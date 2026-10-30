//! Параметры сети и правила, которые можно проверить, не зная истории.
//!
//! Всё в этом файле — консенсус: если два узла считают по-разному, сеть
//! расколется. Поэтому только целые числа, никаких float и никакого
//! «примерно».

use std::collections::HashSet;

use crate::block::{self, Block, BlockHeader};
use crate::tx::Transaction;

/// 1 монета = 10⁸ минимальных единиц. Все суммы хранятся в единицах (u64).
pub const COIN: u64 = 100_000_000;

/// Целевой интервал между блоками, секунды. Учебная сеть: побыстрее, чтобы
/// было видно, как она живёт.
pub const BLOCK_TIME: u64 = 10;
/// Как часто пересчитывается сложность, в блоках.
pub const RETARGET_INTERVAL: u32 = 20;
/// Начальная сложность: около миллиона хешей, доли секунды на одном ядре.
/// В тестах — 1, чтобы «майнинг» был мгновенным.
pub const INITIAL_DIFFICULTY: u64 = if cfg!(test) { 1 } else { 1 << 20 };

/// Награда начинается с 50 монет и делится пополам каждые 100 000 блоков.
pub const INITIAL_REWARD: u64 = 50 * COIN;
pub const HALVING_INTERVAL: u32 = 100_000;
/// Всего будет выпущено чуть меньше 50 · 100 000 · 2 = 10 млн монет.
pub const MAX_MONEY: u64 = 10_000_000 * COIN;

/// Награду за блок можно потратить только через 10 блоков: если блок
/// окажется в проигравшей ветке, его награда исчезнет, и вместе с ней
/// исчезли бы все транзакции, которые её успели потратить.
pub const COINBASE_MATURITY: u32 = 10;

pub const MAX_BLOCK_SIZE: usize = 1_000_000;
/// Время блока должно быть больше медианы 11 предыдущих...
pub const MEDIAN_TIME_SPAN: usize = 11;
/// ...и не больше чем на 2 часа впереди часов узла.
pub const MAX_FUTURE_TIME: u64 = 2 * 60 * 60;

/// 2026-10-29 00:00:00 UTC.
pub const GENESIS_TIME: u64 = 1_793_232_000;

pub fn block_reward(height: u32) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 { 0 } else { INITIAL_REWARD >> halvings }
}

/// Новая сложность по времени, за которое добыты последние
/// `RETARGET_INTERVAL` блоков. Блоки шли вдвое быстрее нормы → сложность
/// вдвое выше. Изменение за раз ограничено ×4, чтобы искажённые
/// временные метки не могли резко качнуть сеть.
pub fn retarget(old_difficulty: u64, actual_span: u64) -> u64 {
    let expected = BLOCK_TIME * RETARGET_INTERVAL as u64;
    let span = actual_span.clamp(expected / 4, expected * 4);
    let new = old_difficulty as u128 * expected as u128 / span as u128;
    new.clamp(1, u64::MAX as u128) as u64
}

/// Первый блок зашит в код. Его не проверяют, его просто знают.
/// Coinbase без выходов: монет вне майнинга не существует (премайна нет).
pub fn genesis_block() -> Block {
    let coinbase = Transaction { inputs: vec![], outputs: vec![], expiry_height: 0 };
    let header = BlockHeader {
        prev_hash: [0; 32],
        merkle_root: block::merkle_root(&[coinbase.txid()]),
        time: GENESIS_TIME,
        difficulty: INITIAL_DIFFICULTY,
        nonce: 0,
    };
    Block { header, txs: vec![coinbase] }
}

/// Проверки транзакции, которым не нужна история.
pub fn check_tx_structure(tx: &Transaction) -> Result<(), String> {
    if !tx.is_coinbase() && tx.outputs.is_empty() {
        return Err("транзакция без выходов".into());
    }
    if tx.outputs.iter().any(|o| o.amount == 0) {
        return Err("выход с нулевой суммой".into());
    }
    match tx.output_sum() {
        Some(sum) if sum <= MAX_MONEY => {}
        _ => return Err("сумма выходов больше всех монет в мире".into()),
    }
    let mut seen = HashSet::new();
    if !tx.inputs.iter().all(|i| seen.insert(i.prev)) {
        return Err("один и тот же выход потрачен дважды в одной транзакции".into());
    }
    Ok(())
}

/// Проверки блока, которым не нужна история. Порядок — от дешёвых к
/// дорогим: мусор отсеивается раньше, чем на него тратится время.
pub fn check_block_standalone(block: &Block) -> Result<(), String> {
    if block.size() > MAX_BLOCK_SIZE {
        return Err("блок больше 1 МБ".into());
    }
    if !block::meets_difficulty(&block.hash(), block.header.difficulty) {
        return Err("хеш заголовка выше цели: работа не доказана".into());
    }
    match block.txs.first() {
        Some(tx) if tx.is_coinbase() => {}
        _ => return Err("первая транзакция блока должна быть coinbase".into()),
    }
    if block.txs[1..].iter().any(Transaction::is_coinbase) {
        return Err("coinbase может быть только первой".into());
    }
    for tx in &block.txs {
        check_tx_structure(tx)?;
    }
    let txids: Vec<_> = block.txs.iter().map(Transaction::txid).collect();
    if txids.iter().collect::<HashSet<_>>().len() != txids.len() {
        return Err("в блоке повторяется транзакция".into());
    }
    if block::merkle_root(&txids) != block.header.merkle_root {
        return Err("корень Меркла не совпадает с транзакциями".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_schedule() {
        assert_eq!(block_reward(0), 50 * COIN);
        assert_eq!(block_reward(HALVING_INTERVAL - 1), 50 * COIN);
        assert_eq!(block_reward(HALVING_INTERVAL), 25 * COIN);
        assert_eq!(block_reward(64 * HALVING_INTERVAL), 0);

        let total: u64 = (0..64).map(|i| block_reward(i * HALVING_INTERVAL) * HALVING_INTERVAL as u64).sum();
        assert!(total <= MAX_MONEY);
    }

    #[test]
    fn retarget_follows_block_speed() {
        let expected = BLOCK_TIME * RETARGET_INTERVAL as u64;
        assert_eq!(retarget(1000, expected), 1000);
        assert_eq!(retarget(1000, expected / 2), 2000);
        assert_eq!(retarget(1000, expected * 2), 500);
        // Ограничение ×4 в обе стороны.
        assert_eq!(retarget(1000, 0), 4000);
        assert_eq!(retarget(1000, expected * 100), 250);
        assert_eq!(retarget(1, expected * 100), 1);
    }
}
