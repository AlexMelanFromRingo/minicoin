//! Побайтовый разбор блока: каждое поле — его байты и смысл.
//!
//! Это та же сериализация, что в `block` и `tx`, только с подписями к
//! каждому полю. Если сложить все hex-строки по порядку, получится
//! ровно `block.to_bytes()` (это проверяет тест).

use crate::address;
use crate::block::{self, Block};
use crate::consensus;
use crate::crypto::{self, to_hex};
use crate::wallet::format_amount;

struct Explainer {
    out: String,
    offset: usize,
    bytes: Vec<u8>,
}

impl Explainer {
    fn section(&mut self, title: &str) {
        self.out.push_str(&format!("\n── {title} ──\n"));
    }

    fn field(&mut self, bytes: &[u8], name: &str, meaning: &str) {
        self.out.push_str(&format!("{:>7}  {name:<14} {}\n", self.offset, to_hex(bytes)));
        if !meaning.is_empty() {
            self.out.push_str(&format!("{:>7}  {:<14} ↳ {meaning}\n", "", ""));
        }
        self.offset += bytes.len();
        self.bytes.extend_from_slice(bytes);
    }

    fn note(&mut self, text: &str) {
        self.out.push_str(&format!("         {text}\n"));
    }
}

pub fn explain_block(block: &Block, height: u32) -> String {
    let mut e = Explainer { out: String::new(), offset: 0, bytes: Vec::new() };
    let h = &block.header;
    let hash = block.hash();
    e.out.push_str(&format!("Блок #{height}  ({} байт)\nхеш {}\n", block.size(), to_hex(&hash)));

    e.section("Заголовок, 88 байт: только он хешируется для PoW");
    e.field(&h.prev_hash, "prev_hash", "хеш предыдущего блока — звено цепи");
    e.field(&h.merkle_root, "merkle_root", "корень дерева Меркла по txid всех транзакций");
    e.field(&h.time.to_le_bytes(), "time", &format!("{} (секунды Unix, little-endian)", h.time));
    e.field(
        &h.difficulty.to_le_bytes(),
        "difficulty",
        &format!("{} — столько хешей в среднем нужно перебрать", h.difficulty),
    );
    e.field(&h.nonce.to_le_bytes(), "nonce", &format!("{} — найдено перебором", h.nonce));
    e.note(&format!("BLAKE3(заголовок) = {}", to_hex(&hash)));
    e.note(&format!("цель = (2²⁵⁶−1)/difficulty = {}", to_hex(&block::target(h.difficulty))));
    let ok = block::meets_difficulty(&hash, h.difficulty);
    e.note(if ok {
        "хеш ≤ цели ✓ работа доказана"
    } else {
        "хеш > цели ✗ (генезис не майнится)"
    });

    e.section("Транзакции");
    e.field(&(block.txs.len() as u32).to_le_bytes(), "tx_count", &format!("{} транзакций", block.txs.len()));

    for (n, tx) in block.txs.iter().enumerate() {
        let kind =
            if tx.is_coinbase() { "coinbase: новые монеты, входов нет" } else { "обычная" };
        e.section(&format!("Транзакция {n} ({kind})"));
        e.field(&(tx.inputs.len() as u16).to_le_bytes(), "input_count", "");
        for (i, input) in tx.inputs.iter().enumerate() {
            e.field(&input.prev.txid, &format!("in[{i}].txid"), "какую транзакцию тратим…");
            e.field(
                &input.prev.index.to_le_bytes(),
                &format!("in[{i}].index"),
                &format!("…и её выход №{}", input.prev.index),
            );
            e.field(&input.signature, &format!("in[{i}].sig"), "Ed25519-подпись владельца выхода под sighash");
        }
        e.field(&(tx.outputs.len() as u16).to_le_bytes(), "output_count", "");
        for (i, output) in tx.outputs.iter().enumerate() {
            e.field(
                &output.amount.to_le_bytes(),
                &format!("out[{i}].amount"),
                &format!("{} монет", format_amount(output.amount)),
            );
            e.field(
                &output.owner,
                &format!("out[{i}].owner"),
                &format!("открытый ключ получателя = {}", address::encode(&output.owner)),
            );
        }
        let expiry = if tx.is_coinbase() {
            format!("{} — высота блока (делает txid уникальным)", tx.expiry_height)
        } else {
            format!("{} — после этой высоты транзакция недействительна", tx.expiry_height)
        };
        e.field(&tx.expiry_height.to_le_bytes(), "expiry_height", &expiry);
        e.note(&format!("txid = BLAKE3(байты транзакции) = {}", to_hex(&tx.txid())));
        if !tx.is_coinbase() {
            e.note(&format!("sighash = BLAKE3(те же байты, подписи заменены нулями) = {}", to_hex(&tx.sighash())));
        }
    }

    if height > 0 {
        e.out.push_str(&format!(
            "\nНаграда за блок на этой высоте: {} монет (+ комиссии)\n",
            format_amount(consensus::block_reward(height))
        ));
    }
    debug_assert_eq!(e.bytes, block.to_bytes());
    debug_assert_eq!(crypto::hash(&e.bytes[..block::HEADER_SIZE]), hash);
    e.out
}

/// Тестовые векторы для других реализаций (`minicoin vectors`).
/// Строки вида `имя = значение`; байты в hex. Ed25519 детерминирована,
/// поэтому подписи тоже воспроизводимы.
pub fn test_vectors() -> String {
    use crate::block::{BlockHeader, merkle_root, target};
    use crate::tx::{OutPoint, Transaction, TxIn, TxOut};

    let mut out = String::new();
    let mut put = |name: &str, value: String| out.push_str(&format!("{name} = {value}\n"));

    let genesis = consensus::genesis_block();
    put("genesis_block", to_hex(&genesis.to_bytes()));
    put("genesis_hash", to_hex(&genesis.hash()));

    let seed = [1u8; 32];
    let key = crypto::public_key(&seed);
    put("seed", to_hex(&seed));
    put("public_key", to_hex(&key));
    put("address", address::encode(&key));
    put("address_of_zero_key", address::encode(&[0; 32]));

    let mut tx = Transaction {
        inputs: vec![TxIn { prev: OutPoint { txid: genesis.txs[0].txid(), index: 0 }, signature: [0; 64] }],
        outputs: vec![
            TxOut { amount: 1_250_000_000, owner: crypto::public_key(&[2; 32]) },
            TxOut { amount: 3_749_990_000, owner: key },
        ],
        expiry_height: 100,
    };
    tx.sign(&seed);
    put("tx", to_hex(&tx.to_bytes()));
    put("tx_sighash", to_hex(&tx.sighash()));
    put("tx_txid", to_hex(&tx.txid()));

    let leaves: Vec<_> = [b"a", b"b", b"c", b"d", b"e"].iter().map(|x| crypto::hash(*x)).collect();
    for n in 1..=5 {
        put(&format!("merkle_{n}"), to_hex(&merkle_root(&leaves[..n])));
    }
    for d in [1, 3, 1 << 20, u64::MAX] {
        put(&format!("target_{d}"), to_hex(&target(d)));
    }
    for (old, span) in [(1 << 20, 200), (1 << 20, 0), (1 << 20, 100), (1 << 20, 10_000), (1000, 333)] {
        put(&format!("retarget_{old}_{span}"), consensus::retarget(old, span).to_string());
    }
    for h in [0, 1, 99_999, 100_000, 6_399_999, 6_400_000] {
        put(&format!("reward_{h}"), consensus::block_reward(h).to_string());
    }

    // Блок 1: coinbase на `key`, время генезис + 10 с, nonce найден перебором.
    let coinbase = Transaction {
        inputs: vec![],
        outputs: vec![TxOut { amount: consensus::block_reward(1), owner: key }],
        expiry_height: 1,
    };
    let mut header = BlockHeader {
        prev_hash: genesis.hash(),
        merkle_root: merkle_root(&[coinbase.txid()]),
        time: consensus::GENESIS_TIME + consensus::BLOCK_TIME,
        difficulty: consensus::INITIAL_DIFFICULTY,
        nonce: 0,
    };
    while !block::meets_difficulty(&header.hash(), header.difficulty) {
        header.nonce += 1;
    }
    let block1 = Block { header, txs: vec![coinbase] };
    put("block1", to_hex(&block1.to_bytes()));
    put("block1_hash", to_hex(&block1.hash()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{OutPoint, Transaction, TxIn, TxOut};

    #[test]
    fn covers_every_byte() {
        let mut block = consensus::genesis_block();
        block.txs.push(Transaction {
            inputs: vec![TxIn { prev: OutPoint { txid: [1; 32], index: 2 }, signature: [3; 64] }],
            outputs: vec![TxOut { amount: 5, owner: [4; 32] }],
            expiry_height: 9,
        });
        // debug_assert внутри сверяет разобранные байты с to_bytes().
        let text = explain_block(&block, 1);
        assert!(text.contains("in[0].sig"));
    }
}
