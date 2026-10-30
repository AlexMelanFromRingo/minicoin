//! Блок, дерево Меркла и доказательство работы.
//!
//! Блок — это заголовок и список транзакций. Заголовок короткий (88 байт)
//! и через корень Меркла фиксирует все транзакции. Поэтому для
//! доказательства работы (PoW) достаточно хешировать только заголовок.

use crate::codec::{Reader, Writer};
use crate::crypto::{self, Hash};
use crate::tx::Transaction;

pub const HEADER_SIZE: usize = 32 + 32 + 8 + 8 + 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Хеш предыдущего блока. Именно эта ссылка превращает блоки в цепочку:
    /// изменение старого блока меняет его хеш и рвёт все ссылки после него.
    pub prev_hash: Hash,
    /// Корень дерева Меркла по txid всех транзакций блока.
    pub merkle_root: Hash,
    /// Время создания, секунды Unix.
    pub time: u64,
    /// Сложность: сколько хешей в среднем нужно перебрать, чтобы найти
    /// подходящий. Узел проверяет, что она равна ожидаемой (см. `chain`).
    pub difficulty: u64,
    /// Число, которое перебирает майнер.
    pub nonce: u64,
}

impl BlockHeader {
    pub fn write(&self, w: &mut Writer) {
        w.raw(&self.prev_hash);
        w.raw(&self.merkle_root);
        w.u64(self.time);
        w.u64(self.difficulty);
        w.u64(self.nonce);
    }

    pub fn read(r: &mut Reader) -> Result<Self, String> {
        Ok(BlockHeader {
            prev_hash: r.array()?,
            merkle_root: r.array()?,
            time: r.u64()?,
            difficulty: r.u64()?,
            nonce: r.u64()?,
        })
    }

    pub fn hash(&self) -> Hash {
        let mut w = Writer::default();
        self.write(&mut w);
        crypto::hash(&w.bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    /// Первая транзакция всегда coinbase (награда майнеру).
    pub txs: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.header.write(&mut w);
        w.u32(self.txs.len() as u32);
        for tx in &self.txs {
            tx.write_to(&mut w);
        }
        w.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let header = BlockHeader::read(&mut r)?;
        let mut txs = Vec::new();
        for _ in 0..r.u32()? {
            txs.push(Transaction::read(&mut r)?);
        }
        r.finish()?;
        Ok(Block { header, txs })
    }

    pub fn size(&self) -> usize {
        HEADER_SIZE + 4 + self.txs.iter().map(Transaction::size).sum::<usize>()
    }
}

/// Корень дерева Меркла: хешируем txid попарно, пока не останется один.
///
/// ```text
///            root
///          /      \
///       h01        c        ← нечётный узел поднимается как есть
///      /   \       |
///     a     b      c        ← txid
/// ```
///
/// Узел = BLAKE3(0x01 ‖ левый ‖ правый). Префикс 0x01 отличает узел от
/// транзакции: 65 байт не могут быть транзакцией, у неё размер всегда чётный.
/// Нечётный узел не дублируется, как в биткоине: дублирование позволяло
/// построить два разных списка транзакций с одним корнем (CVE-2012-2459).
pub fn merkle_root(txids: &[Hash]) -> Hash {
    if txids.is_empty() {
        return [0; 32];
    }
    let mut level = txids.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => {
                    let mut data = Vec::with_capacity(65);
                    data.push(0x01);
                    data.extend_from_slice(left);
                    data.extend_from_slice(right);
                    crypto::hash(&data)
                }
                [single] => *single,
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

/// Цель: хеш заголовка, прочитанный как 256-битное число (big-endian),
/// должен быть ≤ ⌊(2²⁵⁶ − 1) / difficulty⌋. Хеш непредсказуем, поэтому
/// вероятность попасть под цель равна 1/difficulty, и в среднем нужно
/// `difficulty` попыток. Это и есть «работа».
///
/// Деление 256-битного числа на u64 — обычное деление столбиком по байтам.
pub fn target(difficulty: u64) -> Hash {
    let d = difficulty.max(1) as u128;
    let mut out = [0u8; 32];
    let mut remainder: u128 = 0;
    for byte in out.iter_mut() {
        let current = (remainder << 8) | 0xff;
        *byte = (current / d) as u8;
        remainder = current % d;
    }
    out
}

/// Сравнение массивов байтов в Rust лексикографическое, то есть совпадает
/// со сравнением big-endian чисел.
pub fn meets_difficulty(hash: &Hash, difficulty: u64) -> bool {
    difficulty > 0 && *hash <= target(difficulty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_math() {
        assert_eq!(target(1), [0xff; 32]);
        let t2 = target(2);
        assert_eq!(t2[0], 0x7f);
        assert!(t2[1..].iter().all(|&b| b == 0xff));
        let t256 = target(256);
        assert_eq!(t256[0], 0);
        assert!(t256[1..].iter().all(|&b| b == 0xff));
        assert!(!meets_difficulty(&[0; 32], 0));
    }

    #[test]
    fn merkle_shapes() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(merkle_root(&[a]), a);
        let ab = merkle_root(&[a, b]);
        assert_ne!(ab, merkle_root(&[b, a]));
        // Структура дерева: нечётный `c` поднялся на уровень выше. Подменить
        // пару (a, b) «транзакцией» с txid = ab нельзя: её байты были бы
        // 0x01 ‖ a ‖ b, а это 65 байт, не транзакция.
        assert_eq!(merkle_root(&[a, b, c]), merkle_root(&[ab, c]));
        // Дублирования нет: [a, b, c] и [a, b, c, c] дают разные корни.
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
    }

    #[test]
    fn block_roundtrip() {
        let block = Block {
            header: BlockHeader { prev_hash: [9; 32], merkle_root: [8; 32], time: 1, difficulty: 2, nonce: 3 },
            txs: vec![Transaction { inputs: vec![], outputs: vec![], expiry_height: 0 }],
        };
        let bytes = block.to_bytes();
        assert_eq!(bytes.len(), block.size());
        assert_eq!(Block::from_bytes(&bytes), Ok(block));
    }
}
