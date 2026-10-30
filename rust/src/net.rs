//! Сетевой протокол: сообщения поверх TCP.
//!
//! Кадр сообщения:
//!
//! ```text
//! magic "mini" [4] | тип u8 | длина u32 | полезная нагрузка [длина]
//! ```
//!
//! Магические байты отсекают случайные подключения к чужому порту.
//! Ограничение длины не даёт пиру одним заголовком заставить нас выделить
//! гигабайты памяти.

use std::io::{self, Read, Write};

use crate::block::Block;
use crate::chain::UtxoEntry;
use crate::codec::{Reader, Writer};
use crate::crypto::{Hash, PublicKey};
use crate::tx::{OutPoint, Transaction, TxOut};

pub const MAGIC: [u8; 4] = *b"mini";
pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;
pub const DEFAULT_PORT: u16 = 4242;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// «Вот моя высота и вершина». Шлётся при подключении и после пачки блоков.
    Status {
        height: u32,
        tip: Hash,
    },
    /// «Пришли блоки после первого общего блока из этого локатора».
    GetBlocks {
        locator: Vec<Hash>,
    },
    Block(Block),
    Tx(Transaction),
    /// Запрос кошелька: непотраченные выходы ключа. Выходы, уже потраченные
    /// транзакциями мемпула, узел показывает только с `include_mempool_spent`:
    /// они нужны `bump`, чтобы узнать, что тратит застрявшая транзакция.
    GetUtxos {
        owner: PublicKey,
        include_mempool_spent: bool,
    },
    Utxos {
        height: u32,
        utxos: Vec<(OutPoint, UtxoEntry)>,
    },
    /// Запрос блока основной цепи по высоте (для `explain`).
    GetBlock {
        height: u32,
    },
    GetInfo,
    /// Ответ для человека: результат отправки транзакции, сводка узла, ошибка.
    Text(String),
    /// Запрос кошелька: транзакция из мемпула (чтобы заменить её, см. `bump`).
    GetMempoolTx {
        txid: Hash,
    },
    /// Транзакция из мемпула и её комиссия. Кошелёк этой комиссии не верит и
    /// считает её сам по входам, сверенным с подписями (см. `wallet::bump_payment`).
    MempoolTx {
        fee: u64,
        tx: Transaction,
    },
}

impl Message {
    fn kind(&self) -> u8 {
        match self {
            Message::Status { .. } => 1,
            Message::GetBlocks { .. } => 2,
            Message::Block(_) => 3,
            Message::Tx(_) => 4,
            Message::GetUtxos { .. } => 5,
            Message::Utxos { .. } => 6,
            Message::GetBlock { .. } => 7,
            Message::GetInfo => 8,
            Message::Text(_) => 9,
            Message::GetMempoolTx { .. } => 10,
            Message::MempoolTx { .. } => 11,
        }
    }

    fn payload(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Message::Status { height, tip } => {
                w.u32(*height);
                w.raw(tip);
            }
            Message::GetBlocks { locator } => {
                w.u16(locator.len() as u16);
                locator.iter().for_each(|h| w.raw(h));
            }
            Message::Block(block) => w.raw(&block.to_bytes()),
            Message::Tx(tx) => tx.write_to(&mut w),
            Message::GetUtxos { owner, include_mempool_spent } => {
                w.raw(owner);
                w.u8(*include_mempool_spent as u8);
            }
            Message::Utxos { height, utxos } => {
                w.u32(*height);
                w.u32(utxos.len() as u32);
                for (outpoint, entry) in utxos {
                    w.raw(&outpoint.txid);
                    w.u16(outpoint.index);
                    w.u64(entry.output.amount);
                    w.raw(&entry.output.owner);
                    w.u32(entry.height);
                    w.u8(entry.coinbase as u8);
                }
            }
            Message::GetBlock { height } => w.u32(*height),
            Message::GetInfo => {}
            Message::Text(text) => w.raw(text.as_bytes()),
            Message::GetMempoolTx { txid } => w.raw(txid),
            Message::MempoolTx { fee, tx } => {
                w.u64(*fee);
                tx.write_to(&mut w);
            }
        }
        w.bytes
    }

    fn parse(kind: u8, payload: &[u8]) -> Result<Message, String> {
        let mut r = Reader::new(payload);
        let message = match kind {
            1 => Message::Status { height: r.u32()?, tip: r.array()? },
            2 => {
                let count = r.u16()?;
                Message::GetBlocks { locator: (0..count).map(|_| r.array()).collect::<Result<_, _>>()? }
            }
            3 => return Block::from_bytes(payload).map(Message::Block),
            4 => return Transaction::from_bytes(payload).map(Message::Tx),
            5 => Message::GetUtxos { owner: r.array()?, include_mempool_spent: r.u8()? != 0 },
            6 => {
                let height = r.u32()?;
                let mut utxos = Vec::new();
                for _ in 0..r.u32()? {
                    let outpoint = OutPoint { txid: r.array()?, index: r.u16()? };
                    let output = TxOut { amount: r.u64()?, owner: r.array()? };
                    let entry = UtxoEntry { output, height: r.u32()?, coinbase: r.u8()? != 0 };
                    utxos.push((outpoint, entry));
                }
                Message::Utxos { height, utxos }
            }
            7 => Message::GetBlock { height: r.u32()? },
            8 => Message::GetInfo,
            9 => return String::from_utf8(payload.to_vec()).map(Message::Text).map_err(|_| "не UTF-8".into()),
            10 => Message::GetMempoolTx { txid: r.array()? },
            11 => Message::MempoolTx { fee: r.u64()?, tx: Transaction::read(&mut r)? },
            _ => return Err(format!("неизвестный тип сообщения {kind}")),
        };
        r.finish()?;
        Ok(message)
    }
}

pub fn send(stream: &mut impl Write, message: &Message) -> io::Result<()> {
    let payload = message.payload();
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&MAGIC);
    frame.push(message.kind());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    stream.write_all(&frame)?;
    stream.flush()
}

pub fn recv(stream: &mut impl Read) -> io::Result<Message> {
    let bad = |e: String| io::Error::new(io::ErrorKind::InvalidData, e);
    let mut head = [0u8; 9];
    stream.read_exact(&mut head)?;
    if head[..4] != MAGIC {
        return Err(bad("чужие магические байты".into()));
    }
    let len = u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize;
    if len > MAX_MESSAGE {
        return Err(bad(format!("сообщение слишком большое: {len} байт")));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Message::parse(head[4], &payload).map_err(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus;

    #[test]
    fn messages_roundtrip() {
        let entry = UtxoEntry { output: TxOut { amount: 7, owner: [3; 32] }, height: 9, coinbase: true };
        let messages = vec![
            Message::Status { height: 5, tip: [1; 32] },
            Message::GetBlocks { locator: vec![[1; 32], [2; 32]] },
            Message::Block(consensus::genesis_block()),
            Message::Tx(consensus::genesis_block().txs[0].clone()),
            Message::GetUtxos { owner: [4; 32], include_mempool_spent: true },
            Message::Utxos { height: 3, utxos: vec![(OutPoint { txid: [5; 32], index: 1 }, entry)] },
            Message::GetBlock { height: 2 },
            Message::GetInfo,
            Message::Text("привет".into()),
            Message::GetMempoolTx { txid: [6; 32] },
            Message::MempoolTx { fee: 186, tx: consensus::genesis_block().txs[0].clone() },
        ];
        for message in messages {
            let mut buf = Vec::new();
            send(&mut buf, &message).unwrap();
            assert_eq!(recv(&mut buf.as_slice()).unwrap(), message);
        }
    }

    #[test]
    fn rejects_foreign_magic() {
        let mut buf = Vec::new();
        send(&mut buf, &Message::GetInfo).unwrap();
        buf[0] = b'x';
        assert!(recv(&mut buf.as_slice()).is_err());
    }
}
