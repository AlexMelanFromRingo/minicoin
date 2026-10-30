//! Кошелёк: один ключ, баланс и сборка платежа.
//!
//! Кошелёк не хранит монет, он хранит ключ. Монеты лежат в цепи как
//! выходы, запертые этим ключом. Чтобы узнать баланс, кошелёк спрашивает
//! у узла выходы своего ключа.
//!
//! Упрощение: один ключ на кошелёк, сдача возвращается на тот же адрес.
//! Настоящие кошельки берут новый адрес для каждой сдачи, чтобы платежи
//! было труднее связать между собой.

use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use crate::chain::UtxoEntry;
use crate::consensus::{COIN, COINBASE_MATURITY};
use crate::crypto::{self, PublicKey, Seed};
use crate::net::{self, Message};
use crate::tx::{OutPoint, Transaction, TxIn, TxOut};

/// Через сколько блоков неподтверждённый платёж истечёт.
pub const EXPIRY_WINDOW: u32 = 100;

pub fn create(path: &Path) -> Result<PublicKey, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true); // существующий кошелёк не перезаписываем
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600); // читать ключ может только владелец
    let mut file = options.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => format!("{} уже существует, не перезаписываю", path.display()),
        _ => format!("{}: {e}", path.display()),
    })?;
    let seed = crypto::new_seed();
    file.write_all((crypto::to_hex(&seed) + "\n").as_bytes()).map_err(|e| e.to_string())?;
    Ok(crypto::public_key(&seed))
}

/// Файл кошелька — 32 байта зерна в hex. Не зашифрован: кто прочитал
/// файл, тот владеет монетами.
pub fn load(path: &Path) -> Result<Seed, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    crypto::from_hex(text.trim())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{}: ожидалось 64 hex-символа", path.display()))
}

/// Можно ли потратить выход в блоке `next_height`.
pub fn is_spendable(entry: &UtxoEntry, next_height: u32) -> bool {
    !entry.coinbase || next_height.saturating_sub(entry.height) >= COINBASE_MATURITY
}

/// Собрать и подписать платёж `amount` на `to` с комиссией `fee`.
pub fn build_payment(
    seed: &Seed,
    utxos: &[(OutPoint, UtxoEntry)],
    tip_height: u32,
    to: PublicKey,
    amount: u64,
    fee: u64,
) -> Result<Transaction, String> {
    let next_height = tip_height + 1;
    let need = amount.checked_add(fee).ok_or("слишком большая сумма")?;

    // Выбор монет: крупные первыми. Так входов меньше, а значит меньше
    // размер транзакции и нужная комиссия.
    let mut spendable: Vec<_> = utxos.iter().filter(|(_, e)| is_spendable(e, next_height)).collect();
    spendable.sort_by_key(|(_, e)| std::cmp::Reverse(e.output.amount));

    let mut inputs = Vec::new();
    let mut spent = Vec::new();
    let mut total: u64 = 0;
    for (outpoint, entry) in spendable {
        if total >= need {
            break;
        }
        inputs.push(TxIn { prev: *outpoint, signature: [0; 64] });
        spent.push(entry.output.clone());
        total += entry.output.amount;
    }
    if total < need {
        return Err(format!("недостаточно средств: доступно {}, нужно {}", format_amount(total), format_amount(need)));
    }

    let mut outputs = vec![TxOut { amount, owner: to }];
    let change = total - need;
    if change > 0 {
        outputs.push(TxOut { amount: change, owner: crypto::public_key(seed) });
    }
    let mut tx = Transaction { inputs, outputs, expiry_height: next_height + EXPIRY_WINDOW };
    // Суммы входов подписаны: если узел их занизил, подпись выйдет неверной.
    tx.sign(seed, &spent);
    Ok(tx)
}

/// Комиссия замены по умолчанию: вдвое больше старой, но не меньше, чем
/// требует правило замены (старая + `MIN_FEE_RATE` × размер, см. `mempool`).
pub fn default_bump_fee(old_fee: u64, size: usize) -> u64 {
    old_fee.saturating_mul(2).max(old_fee + crate::mempool::MIN_FEE_RATE * size as u64)
}

/// Замена застрявшего платежа (replace-by-fee): те же входы и тот же
/// получатель, а прибавка к комиссии берётся из сдачи. Получатель получит
/// ровно столько же; если сдачи не хватает, замена невозможна.
///
/// `utxos` — выходы кошелька от узла, включая уже потраченные в мемпуле
/// (среди них — входы `stuck`). `new_fee = None` — комиссия по умолчанию
/// (`default_bump_fee`). Возвращает замену, старую и новую комиссии.
pub fn bump_payment(
    seed: &Seed,
    stuck: &Transaction,
    utxos: &[(OutPoint, UtxoEntry)],
    new_fee: Option<u64>,
) -> Result<(Transaction, u64, u64), String> {
    // Узлу не доверяем. Он мог прислать чужую транзакцию, которая тратит наши
    // выходы на его адрес, или занизить суммы входов, чтобы мы переплатили
    // комиссию. Подпись покрывает все выходы и суммы с владельцами входов
    // (sighash), поэтому переподписываем, только если все подписи сходятся
    // с тем, что прислал узел: значит, это наша транзакция, и суммы входов
    // те самые, что мы подписывали.
    let me = crypto::public_key(seed);
    let mut spent = Vec::new();
    for input in &stuck.inputs {
        let (_, entry) = utxos.iter().find(|(outpoint, _)| *outpoint == input.prev).ok_or_else(|| {
            format!("узел не прислал вход {}:{} — заменять не буду", crypto::to_hex(&input.prev.txid), input.prev.index)
        })?;
        spent.push(entry.output.clone());
    }
    let sighash = stuck.sighash(&spent);
    if stuck.inputs.is_empty() || !stuck.inputs.iter().all(|i| crypto::verify(&me, &sighash, &i.signature)) {
        return Err("подписи не сходятся: узел прислал не ту транзакцию или неверные суммы входов".into());
    }
    // Комиссию считаем сами: суммы входов теперь проверены подписями.
    let input_sum = spent.iter().try_fold(0u64, |sum, o| sum.checked_add(o.amount));
    let old_fee = input_sum
        .zip(stuck.output_sum())
        .and_then(|(inputs, outputs)| inputs.checked_sub(outputs))
        .ok_or("суммы входов и выходов не сходятся")?;
    let new_fee = new_fee.unwrap_or_else(|| default_bump_fee(old_fee, stuck.size()));
    if new_fee <= old_fee {
        return Err(format!("новая комиссия должна быть больше старой ({})", format_amount(old_fee)));
    }
    let mut tx = stuck.clone();
    let extra = new_fee - old_fee;
    let change = match tx.outputs.iter().rposition(|o| o.owner == me) {
        Some(i) if tx.outputs.len() > 1 => i,
        _ => return Err("в транзакции нет сдачи, из которой можно доплатить комиссию".into()),
    };
    match tx.outputs[change].amount {
        amount if amount > extra => tx.outputs[change].amount -= extra,
        // Сдача уходит целиком: выход исчезает, транзакция становится короче.
        amount if amount == extra => {
            tx.outputs.remove(change);
        }
        amount => {
            return Err(format!(
                "сдачи {} не хватает на прибавку к комиссии {}",
                format_amount(amount),
                format_amount(extra)
            ));
        }
    }
    tx.sign(seed, &spent);
    Ok((tx, old_fee, new_fee))
}

/// Запрос к узлу: отправить сообщение и дождаться ответа.
pub fn request(node: &str, message: &Message) -> Result<Message, String> {
    let mut stream = TcpStream::connect(node).map_err(|e| format!("не подключиться к узлу {node}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    net::send(&mut stream, message).map_err(|e| e.to_string())?;
    loop {
        match net::recv(&mut stream).map_err(|e| format!("узел не ответил: {e}"))? {
            // Узел здоровается со всеми, кто подключился. Это не ответ.
            Message::Status { .. } => continue,
            reply => return Ok(reply),
        }
    }
}

pub fn format_amount(units: u64) -> String {
    format!("{}.{:08}", units / COIN, units % COIN)
}

/// "1.5" → 150 000 000 единиц. Без float: деньги не округляют.
pub fn parse_amount(text: &str) -> Result<u64, String> {
    let error = || format!("не сумма: {text}");
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && frac.is_empty()
        || frac.len() > 8
        || !(whole.chars().chain(frac.chars())).all(|c| c.is_ascii_digit())
    {
        return Err(error());
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| error())? };
    let frac: u64 = format!("{frac:0<8}").parse().map_err(|_| error())?;
    whole.checked_mul(COIN).and_then(|w| w.checked_add(frac)).ok_or_else(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(amount: u64, height: u32, coinbase: bool, n: u8) -> (OutPoint, UtxoEntry) {
        let entry = UtxoEntry { output: TxOut { amount, owner: [0; 32] }, height, coinbase };
        (OutPoint { txid: [n; 32], index: 0 }, entry)
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("1.5"), Ok(150_000_000));
        assert_eq!(parse_amount("0.00000001"), Ok(1));
        assert_eq!(parse_amount(".5"), Ok(50_000_000));
        assert_eq!(parse_amount("7"), Ok(700_000_000));
        assert!(parse_amount("1.000000001").is_err());
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("").is_err());
        assert_eq!(format_amount(150_000_001), "1.50000001");
    }

    #[test]
    fn payment_with_change() {
        let seed = crypto::new_seed();
        let utxos = vec![coin(3 * COIN, 1, false, 1), coin(10 * COIN, 1, false, 2)];
        let tx = build_payment(&seed, &utxos, 100, [9; 32], 4 * COIN, 1000).unwrap();
        assert_eq!(tx.inputs.len(), 1, "хватает одной крупной монеты");
        assert_eq!(tx.outputs[0].amount, 4 * COIN);
        assert_eq!(tx.outputs[1].amount, 6 * COIN - 1000);
        assert_eq!(tx.outputs[1].owner, crypto::public_key(&seed));
    }

    #[test]
    fn bump_takes_extra_fee_from_change() {
        let seed = crypto::new_seed();
        let utxos = vec![coin(10 * COIN, 1, false, 1)];
        let stuck = build_payment(&seed, &utxos, 100, [9; 32], 4 * COIN, 200).unwrap();
        let fee = default_bump_fee(200, stuck.size());
        assert_eq!(fee, 400, "удвоение больше минимума 200 + 186 по правилу замены");
        assert_eq!(default_bump_fee(10, stuck.size()), 10 + stuck.size() as u64);

        let (bumped, old_fee, new_fee) = bump_payment(&seed, &stuck, &utxos, None).unwrap();
        assert_eq!((old_fee, new_fee), (200, fee), "старую комиссию кошелёк считает сам");
        assert_eq!(bumped.inputs[0].prev, stuck.inputs[0].prev, "те же входы — иначе это не замена");
        assert_eq!(bumped.outputs[0], stuck.outputs[0], "получатель получает столько же");
        assert_eq!(bumped.outputs[1].amount, stuck.outputs[1].amount - (fee - 200));
        assert_ne!(bumped.inputs[0].signature, stuck.inputs[0].signature, "подпись новая");
        let spent = [utxos[0].1.output.clone()];
        assert!(crypto::verify(&crypto::public_key(&seed), &bumped.sighash(&spent), &bumped.inputs[0].signature));

        assert!(bump_payment(&seed, &stuck, &utxos, Some(100)).is_err());
        assert!(bump_payment(&seed, &stuck, &utxos, Some(7 * COIN)).is_err(), "сдачи не хватает");
        // Вся сдача в комиссию: выход сдачи исчезает.
        let (all_in, _, _) = bump_payment(&seed, &stuck, &utxos, Some(6 * COIN)).unwrap();
        assert_eq!(all_in.outputs.len(), 1);
    }

    #[test]
    fn bump_refuses_transaction_it_did_not_sign() {
        let seed = crypto::new_seed();
        let utxos = vec![coin(10 * COIN, 1, false, 1)];
        let stuck = build_payment(&seed, &utxos, 100, [9; 32], 4 * COIN, 200).unwrap();
        // Узел подменил получателя: наши входы, но деньги — ему.
        let mut forged = stuck.clone();
        forged.outputs[0].owner = [66; 32];
        assert!(bump_payment(&seed, &forged, &utxos, Some(400)).is_err());
        // Чужая транзакция целиком: подписи не нашим ключом.
        let stranger = build_payment(&crypto::new_seed(), &utxos, 100, [9; 32], COIN, 200).unwrap();
        assert!(bump_payment(&seed, &stranger, &utxos, Some(400)).is_err());
        // Узел не показал, что тратит транзакция.
        assert!(bump_payment(&seed, &stuck, &[], Some(400)).unwrap_err().contains("не прислал вход"));
    }

    #[test]
    fn bump_refuses_when_node_lies_about_input_amount() {
        let seed = crypto::new_seed();
        let utxos = vec![coin(10 * COIN, 1, false, 1)];
        let stuck = build_payment(&seed, &utxos, 100, [9; 32], 4 * COIN, 200).unwrap();
        // Узел занизил вход на монету. Поверь кошелёк — он решил бы, что старая
        // комиссия на монету меньше, и переплатил бы. Но подпись не сходится.
        let lied = vec![coin(9 * COIN, 1, false, 1)];
        let err = bump_payment(&seed, &stuck, &lied, None).unwrap_err();
        assert!(err.contains("подписи не сходятся"), "{err}");
        // Чужой владелец входа тоже не проходит.
        let mut foreign = utxos.clone();
        foreign[0].1.output.owner = [7; 32];
        assert!(bump_payment(&seed, &stuck, &foreign, None).is_err());
    }

    #[test]
    fn wallet_file_is_private_and_never_overwritten() {
        let path = std::env::temp_dir().join(format!("minicoin-test-{}.key", std::process::id()));
        let _ = fs::remove_file(&path);
        let key = create(&path).unwrap();
        assert_eq!(crypto::public_key(&load(&path).unwrap()), key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(create(&path).is_err(), "второй create не должен затереть ключ");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn immature_coinbase_is_not_spent() {
        let seed = crypto::new_seed();
        let utxos = vec![coin(50 * COIN, 95, true, 1)];
        assert!(build_payment(&seed, &utxos, 100, [9; 32], COIN, 0).is_err());
        assert!(build_payment(&seed, &utxos, 104, [9; 32], COIN, 0).is_ok());
    }
}
