//! Мемпул: проверенные транзакции, которые ждут включения в блок.
//!
//! Мемпул не часть консенсуса. У каждого узла он свой, и правила здесь —
//! «политика узла», а не закон сети. Закон один: транзакция в блоке
//! должна пройти `Chain::check_tx`.
//!
//! Упрощение minicoin: транзакция может тратить только подтверждённые
//! выходы. Цепочек неподтверждённых транзакций нет, поэтому любой набор
//! транзакций из мемпула можно положить в блок в любом порядке.

use std::collections::{HashMap, HashSet};

use crate::chain::Chain;
use crate::crypto::Hash;
use crate::tx::{OutPoint, Transaction};

/// Минимальная комиссия для ретрансляции: единиц за байт. Без неё сеть
/// можно бесплатно завалить мусорными транзакциями.
pub const MIN_FEE_RATE: u64 = 1;

struct Entry {
    tx: Transaction,
    fee: u64,
    size: usize,
}

#[derive(Default)]
pub struct Mempool {
    txs: HashMap<Hash, Entry>,
    /// Какая транзакция мемпула тратит данный выход. Нужно для поиска конфликтов.
    spent_by: HashMap<OutPoint, Hash>,
}

/// Replace-by-fee: можно ли вытеснить из мемпула конфликтующие транзакции
/// (они тратят те же выходы) новой транзакцией.
///
/// Зачем это нужно: отправитель поставил слишком маленькую комиссию,
/// транзакция застряла, и он хочет переотправить те же монеты дороже.
///
/// Чем опасна слишком мягкая политика: каждая замена заново рассылается
/// всей сети. Если менять можно «за копейку», один человек бесплатно
/// загрузит всю сеть бесконечными заменами.
///
/// * `new_fee`, `new_size`     — комиссия и размер в байтах новой транзакции;
/// * `old_fee`, `old_size`     — суммарные комиссия и размер всех вытесняемых.
///
/// Правило из двух условий (суть BIP 125 из Bitcoin Core):
///
/// 1. Замена платит всё, что платили вытесняемые, **плюс** собственную
///    ретрансляцию по минимальной ставке. Старые транзакции уже разошлись
///    по сети бесплатно для отправителя. Если бы замене хватало «на единицу
///    больше», каждая следующая замена снова гоняла бы байты по всем узлам
///    почти даром. Так каждая замена обходится минимум в стоимость новой
///    транзакции.
/// 2. Комиссия **за байт** строго выше. Майнер выбирает транзакции по
///    комиссии за байт (`select`), и замена не должна делать мемпул хуже
///    для него: огромная транзакция с чуть большей суммой, но меньшей
///    ставкой, вытеснила бы выгодную маленькую и задержала бы её.
pub fn should_replace(new_fee: u64, new_size: usize, old_fee: u64, old_size: usize) -> bool {
    let relay_cost = MIN_FEE_RATE * new_size as u64;
    let pays_for_itself = new_fee >= old_fee.saturating_add(relay_cost);
    // new_fee/new_size > old_fee/old_size без дробей, как в `select`.
    let better_rate = new_fee as u128 * old_size as u128 > old_fee as u128 * new_size as u128;
    pays_for_itself && better_rate
}

impl Mempool {
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, txid: &Hash) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn transactions(&self) -> Vec<Transaction> {
        self.txs.values().map(|e| e.tx.clone()).collect()
    }

    /// Транзакция мемпула и её комиссия.
    pub fn get(&self, txid: &Hash) -> Option<(&Transaction, u64)> {
        self.txs.get(txid).map(|e| (&e.tx, e.fee))
    }

    /// Выход уже потрачен какой-то транзакцией мемпула.
    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_by.contains_key(outpoint)
    }

    pub fn add(&mut self, tx: Transaction, chain: &Chain) -> Result<Hash, String> {
        let txid = tx.txid();
        if self.txs.contains_key(&txid) {
            return Err("уже в мемпуле".into());
        }
        let fee = chain.check_tx(&tx, chain.height() + 1)?;
        let size = tx.size();
        let min_fee = size as u64 * MIN_FEE_RATE;
        if fee < min_fee {
            return Err(format!("комиссия {fee} меньше минимальной {min_fee} ({MIN_FEE_RATE} ед/байт)"));
        }

        let conflicts: HashSet<Hash> = tx.inputs.iter().filter_map(|i| self.spent_by.get(&i.prev).copied()).collect();
        if !conflicts.is_empty() {
            let old_fee = conflicts.iter().map(|id| self.txs[id].fee).sum();
            let old_size = conflicts.iter().map(|id| self.txs[id].size).sum();
            if !should_replace(fee, size, old_fee, old_size) {
                return Err("тратит те же выходы, что и транзакция в мемпуле; замена отклонена".into());
            }
            for id in &conflicts {
                self.remove(id);
            }
        }

        for input in &tx.inputs {
            self.spent_by.insert(input.prev, txid);
        }
        self.txs.insert(txid, Entry { tx, fee, size });
        Ok(txid)
    }

    fn remove(&mut self, txid: &Hash) {
        if let Some(entry) = self.txs.remove(txid) {
            for input in &entry.tx.inputs {
                self.spent_by.remove(&input.prev);
            }
        }
    }

    /// После смены вершины цепи проверяем всё заново. Попавшие в блок
    /// транзакции отсеются сами (их входы уже потрачены), так же как
    /// истёкшие и конфликтующие с блоком. `returned` — транзакции из
    /// блоков, отключённых при реорганизации: они снова ждут своей очереди.
    pub fn refresh(&mut self, chain: &Chain, returned: Vec<Transaction>) {
        let pending = returned
            .into_iter()
            .filter(|tx| !tx.is_coinbase())
            .chain(self.txs.drain().map(|(_, e)| e.tx))
            .collect::<Vec<_>>();
        self.spent_by.clear();
        for tx in pending {
            let _ = self.add(tx, chain);
        }
    }

    /// Транзакции для нового блока: самые выгодные (комиссия за байт)
    /// первыми, пока помещаются. Возвращает их и сумму комиссий.
    pub fn select(&self, max_bytes: usize) -> (Vec<Transaction>, u64) {
        let mut entries: Vec<(&Hash, &Entry)> = self.txs.iter().collect();
        // a.fee/a.size > b.fee/b.size ⇔ a.fee·b.size > b.fee·a.size — без дробей.
        entries.sort_by(|(id_a, a), (id_b, b)| {
            (b.fee as u128 * a.size as u128).cmp(&(a.fee as u128 * b.size as u128)).then(id_a.cmp(id_b))
        });
        let (mut txs, mut fees, mut bytes) = (Vec::new(), 0, 0);
        for (_, entry) in entries {
            if bytes + entry.size <= max_bytes {
                bytes += entry.size;
                fees += entry.fee;
                txs.push(entry.tx.clone());
            }
        }
        (txs, fees)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_by_fee_policy() {
        // Та же комиссия — не замена, а спам.
        assert!(!should_replace(1000, 200, 1000, 200));
        // Заметно дороже — замена выгодна.
        assert!(should_replace(5000, 200, 1000, 200));
        // Дешевле — никогда.
        assert!(!should_replace(500, 200, 1000, 200));
        // «На единицу больше» не оплачивает собственную ретрансляцию...
        assert!(!should_replace(1001, 200, 1000, 200));
        // ...а ровно старая комиссия + 1 ед/байт × размер — оплачивает.
        assert!(should_replace(1200, 200, 1000, 200));
        // Больше по сумме, но хуже по ставке (огромная замена) — нет.
        assert!(!should_replace(20_000, 10_000, 1000, 200));
        // Замена нескольких конфликтующих: их комиссии и размеры суммируются.
        assert!(should_replace(3000, 200, 2000, 400));
    }
}
