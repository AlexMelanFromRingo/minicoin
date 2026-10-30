//! Командная строка: узел, кошелёк и разбор блоков.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use minicoin::net::{DEFAULT_PORT, Message};
use minicoin::{address, crypto, explain, node, wallet};

const HELP: &str = "\
minicoin — минимальная, но настоящая криптовалюта

КОШЕЛЁК
  minicoin new-wallet                      создать ключ (файл wallet.key)
  minicoin address                         показать адрес
  minicoin balance                         баланс (спрашивает узел)
  minicoin send <адрес> <сумма> [--fee 0.0001]
  minicoin bump <txid> [--fee сумма]       поднять комиссию застрявшего платежа

УЗЕЛ
  minicoin node [--port 4242] [--peer host:port]... [--mine] [--data data]
               --mine — майнить награду на адрес из кошелька

ОБОЗРЕВАТЕЛЬ
  minicoin info                            сводка узла
  minicoin explain <высота>                побайтовый разбор блока
  minicoin vectors                         тестовые векторы для других реализаций

ОБЩИЕ ОПЦИИ
  --wallet <файл>   файл кошелька (wallet.key)
  --node <адрес>    узел для запросов (127.0.0.1:4242)
";

/// Позиционные аргументы и опции `--имя значение`. `--mine` — флаг без значения.
struct Args {
    positional: Vec<String>,
    options: HashMap<String, Vec<String>>,
}

impl Args {
    fn parse() -> Result<Args, String> {
        let mut positional = Vec::new();
        let mut options: HashMap<String, Vec<String>> = HashMap::new();
        let mut iter = std::env::args().skip(1);
        while let Some(arg) = iter.next() {
            if let Some(name) = arg.strip_prefix("--") {
                let value = if name == "mine" {
                    String::new()
                } else {
                    iter.next().ok_or(format!("у --{name} нет значения"))?
                };
                options.entry(name.to_string()).or_default().push(value);
            } else {
                positional.push(arg);
            }
        }
        Ok(Args { positional, options })
    }

    fn get(&self, name: &str, default: &str) -> String {
        self.options.get(name).and_then(|v| v.last()).cloned().unwrap_or(default.to_string())
    }

    fn has(&self, name: &str) -> bool {
        self.options.contains_key(name)
    }

    fn arg(&self, n: usize, what: &str) -> Result<&str, String> {
        self.positional.get(n).map(String::as_str).ok_or(format!("не указан {what}"))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ошибка: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    let wallet_path = PathBuf::from(args.get("wallet", "wallet.key"));
    let node_addr = args.get("node", &format!("127.0.0.1:{DEFAULT_PORT}"));

    match args.positional.first().map(String::as_str) {
        Some("new-wallet") => {
            let key = wallet::create(&wallet_path)?;
            println!("кошелёк создан: {}", wallet_path.display());
            println!("адрес: {}", address::encode(&key));
        }
        Some("address") => {
            let seed = wallet::load(&wallet_path)?;
            println!("{}", address::encode(&crypto::public_key(&seed)));
        }
        Some("balance") => {
            let owner = crypto::public_key(&wallet::load(&wallet_path)?);
            let Message::Utxos { height, utxos } = wallet::request(&node_addr, &Message::GetUtxos { owner })? else {
                return Err("неожиданный ответ узла".into());
            };
            let (mut spendable, mut immature) = (0, 0);
            for (_, entry) in &utxos {
                if wallet::is_spendable(entry, height + 1) {
                    spendable += entry.output.amount;
                } else {
                    immature += entry.output.amount;
                }
            }
            println!("адрес:     {}", address::encode(&owner));
            println!("доступно:  {}", wallet::format_amount(spendable));
            println!("созревает: {} (награды моложе 10 блоков)", wallet::format_amount(immature));
            println!("выходов:   {} (высота цепи {height})", utxos.len());
        }
        Some("send") => {
            let to = address::decode(args.arg(1, "адрес получателя")?)?;
            let amount = wallet::parse_amount(args.arg(2, "сумма")?)?;
            let fee = wallet::parse_amount(&args.get("fee", "0.0001"))?;
            let seed = wallet::load(&wallet_path)?;
            let owner = crypto::public_key(&seed);
            let Message::Utxos { height, utxos } = wallet::request(&node_addr, &Message::GetUtxos { owner })? else {
                return Err("неожиданный ответ узла".into());
            };
            let tx = wallet::build_payment(&seed, &utxos, height, to, amount, fee)?;
            println!("txid: {}", crypto::to_hex(&tx.txid()));
            match wallet::request(&node_addr, &Message::Tx(tx))? {
                Message::Text(text) => println!("узел: {text}"),
                other => println!("узел: {other:?}"),
            }
        }
        Some("bump") => {
            let txid: [u8; 32] = crypto::from_hex(args.arg(1, "txid")?)
                .and_then(|b| b.try_into().ok())
                .ok_or("txid — 64 hex-символа")?;
            let seed = wallet::load(&wallet_path)?;
            let (old_fee, stuck) = match wallet::request(&node_addr, &Message::GetMempoolTx { txid })? {
                Message::MempoolTx { fee, tx } => (fee, tx),
                Message::Text(text) => return Err(text),
                other => return Err(format!("неожиданный ответ узла: {other:?}")),
            };
            if stuck.txid() != txid {
                return Err("узел прислал не ту транзакцию".into());
            }
            let new_fee = match args.options.get("fee") {
                Some(_) => wallet::parse_amount(&args.get("fee", ""))?,
                None => wallet::default_bump_fee(old_fee, stuck.size()),
            };
            let tx = wallet::bump_payment(&seed, &stuck, old_fee, new_fee)?;
            println!("комиссия: {} → {}", wallet::format_amount(old_fee), wallet::format_amount(new_fee));
            println!("txid: {}", crypto::to_hex(&tx.txid()));
            match wallet::request(&node_addr, &Message::Tx(tx))? {
                Message::Text(text) => println!("узел: {text}"),
                other => println!("узел: {other:?}"),
            }
        }
        Some("node") => {
            let port = args.get("port", &DEFAULT_PORT.to_string()).parse().map_err(|_| "неверный порт")?;
            let mine_to = if args.has("mine") {
                Some(crypto::public_key(&wallet::load(&wallet_path).map_err(|e| {
                    format!("{e}\nдля майнинга нужен кошелёк: minicoin new-wallet --wallet {}", wallet_path.display())
                })?))
            } else {
                None
            };
            let config = node::Config {
                port,
                peers: args.options.get("peer").cloned().unwrap_or_default(),
                data_dir: PathBuf::from(args.get("data", "data")),
                mine_to,
            };
            node::run(config).map_err(|e| e.to_string())?;
        }
        Some("info") => match wallet::request(&node_addr, &Message::GetInfo)? {
            Message::Text(text) => println!("{text}"),
            other => println!("{other:?}"),
        },
        Some("explain") => {
            let height: u32 = args.arg(1, "номер блока")?.parse().map_err(|_| "номер блока — число")?;
            match wallet::request(&node_addr, &Message::GetBlock { height })? {
                Message::Block(block) => print!("{}", explain::explain_block(&block, height)),
                Message::Text(text) => return Err(text),
                other => return Err(format!("неожиданный ответ узла: {other:?}")),
            }
        }
        Some("vectors") => print!("{}", explain::test_vectors()),
        _ => print!("{HELP}"),
    }
    Ok(())
}
