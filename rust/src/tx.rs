//! Транзакции и модель UTXO.
//!
//! Монеты существуют только в виде непотраченных выходов (UTXO, Unspent
//! Transaction Output). «Баланса» как числа нигде нет: баланс — это сумма
//! выходов, запертых вашим ключом.
//!
//! Транзакция тратит старые выходы целиком (входы ссылаются на них) и
//! создаёт новые. Разница «входы − выходы» — комиссия майнеру. Если нужно
//! заплатить меньше, чем лежит в выходе, остаток возвращается себе
//! отдельным выходом («сдача»).
//!
//! Выход запирается открытым ключом получателя, а вход отпирает его
//! подписью этим ключом. Скриптового языка нет, это и есть всё условие траты.

use crate::codec::{Reader, Writer};
use crate::crypto::{self, Hash, PublicKey, Seed, Sig};

/// Ссылка на выход: «выход номер `index` транзакции `txid`».
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: Hash,
    pub index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// Какой выход тратим.
    pub prev: OutPoint,
    /// Подпись владельца выхода под `Transaction::sighash`.
    pub signature: Sig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Сумма в минимальных единицах (1 монета = 100 000 000 единиц).
    pub amount: u64,
    /// Кто может потратить этот выход.
    pub owner: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    /// Транзакция действительна только в блоках с высотой ≤ `expiry_height`.
    /// Если её не включили вовремя, она навсегда недействительна, и её входы
    /// можно потратить заново. Так транзакции не зависают в сети навечно.
    /// У coinbase здесь записана высота блока: это делает её txid уникальным.
    pub expiry_height: u32,
}

/// Размер входа и выхода в байтах (см. PROTOCOL.md).
pub const INPUT_SIZE: usize = 32 + 2 + 64;
pub const OUTPUT_SIZE: usize = 8 + 32;

impl Transaction {
    fn write(&self, w: &mut Writer, with_signatures: bool) {
        w.u16(u16::try_from(self.inputs.len()).expect("слишком много входов"));
        for input in &self.inputs {
            w.raw(&input.prev.txid);
            w.u16(input.prev.index);
            // При подписи места подписей заполняются нулями: нельзя подписать
            // байты, в которых уже должна стоять эта самая подпись.
            w.raw(if with_signatures { &input.signature } else { &[0; 64] });
        }
        w.u16(u16::try_from(self.outputs.len()).expect("слишком много выходов"));
        for output in &self.outputs {
            w.u64(output.amount);
            w.raw(&output.owner);
        }
        w.u32(self.expiry_height);
    }

    pub fn write_to(&self, w: &mut Writer) {
        self.write(w, true);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.write(&mut w, true);
        w.bytes
    }

    pub fn read(r: &mut Reader) -> Result<Self, String> {
        let mut inputs = Vec::new();
        for _ in 0..r.u16()? {
            let prev = OutPoint { txid: r.array()?, index: r.u16()? };
            inputs.push(TxIn { prev, signature: r.array()? });
        }
        let mut outputs = Vec::new();
        for _ in 0..r.u16()? {
            outputs.push(TxOut { amount: r.u64()?, owner: r.array()? });
        }
        Ok(Transaction { inputs, outputs, expiry_height: r.u32()? })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let tx = Self::read(&mut r)?;
        r.finish()?;
        Ok(tx)
    }

    /// Идентификатор транзакции — хеш всех её байтов, включая подписи.
    pub fn txid(&self) -> Hash {
        crypto::hash(&self.to_bytes())
    }

    /// То, что подписывают владельцы входов: хеш транзакции с обнулёнными
    /// подписями. Подпись покрывает все входы, все выходы и срок действия,
    /// поэтому изменить в подписанной транзакции ничего нельзя.
    pub fn sighash(&self) -> Hash {
        let mut w = Writer::default();
        self.write(&mut w, false);
        crypto::hash(&w.bytes)
    }

    /// Подписать все входы одним ключом (кошелёк minicoin — один ключ).
    pub fn sign(&mut self, seed: &Seed) {
        let signature = crypto::sign(seed, &self.sighash());
        for input in &mut self.inputs {
            input.signature = signature;
        }
    }

    /// Coinbase — транзакция без входов: монеты, созданные наградой за блок.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    pub fn size(&self) -> usize {
        2 + self.inputs.len() * INPUT_SIZE + 2 + self.outputs.len() * OUTPUT_SIZE + 4
    }

    /// Сумма выходов или `None` при переполнении `u64`.
    pub fn output_sum(&self) -> Option<u64> {
        self.outputs.iter().try_fold(0u64, |sum, o| sum.checked_add(o.amount))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Transaction {
        Transaction {
            inputs: vec![TxIn { prev: OutPoint { txid: [1; 32], index: 3 }, signature: [0; 64] }],
            outputs: vec![TxOut { amount: 5, owner: [2; 32] }],
            expiry_height: 100,
        }
    }

    #[test]
    fn roundtrip_and_size() {
        let tx = sample();
        let bytes = tx.to_bytes();
        assert_eq!(bytes.len(), tx.size());
        assert_eq!(Transaction::from_bytes(&bytes), Ok(tx));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample().to_bytes();
        bytes.push(0);
        assert!(Transaction::from_bytes(&bytes).is_err());
    }

    #[test]
    fn signature_changes_txid_but_not_sighash() {
        let seed = crypto::new_seed();
        let mut tx = sample();
        let (txid, sighash) = (tx.txid(), tx.sighash());
        tx.sign(&seed);
        assert_ne!(tx.txid(), txid);
        assert_eq!(tx.sighash(), sighash);
        assert!(crypto::verify(&crypto::public_key(&seed), &sighash, &tx.inputs[0].signature));
    }
}
