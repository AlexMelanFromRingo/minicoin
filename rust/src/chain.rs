//! Цепочка блоков и набор UTXO — сердце узла.
//!
//! Узел знает дерево блоков (все ветки, которые ему показали), но
//! «правдой» считает одну: ветку с наибольшей суммарной работой. Набор
//! UTXO всегда соответствует вершине этой ветки.
//!
//! Если другая ветка обгоняет текущую по работе, происходит реорганизация:
//! блоки текущей ветки откатываются до точки расхождения (для этого у
//! каждого блока хранятся undo-данные), затем применяются блоки новой ветки.

use std::collections::{HashMap, HashSet};

use crate::block::Block;
use crate::consensus::{self, COINBASE_MATURITY, MAX_FUTURE_TIME, MEDIAN_TIME_SPAN, RETARGET_INTERVAL};
use crate::crypto::{self, Hash, PublicKey};
use crate::tx::{OutPoint, Transaction, TxOut};

/// Непотраченный выход и то, что о нём нужно помнить для проверки трат.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoEntry {
    pub output: TxOut,
    /// Высота блока, где создан выход (для созревания coinbase).
    pub height: u32,
    pub coinbase: bool,
}

/// Всё, что нужно, чтобы отменить блок: какие выходы он потратил (их надо
/// вернуть) и какие создал (их надо удалить).
#[derive(Default)]
struct BlockUndo {
    spent: Vec<(OutPoint, UtxoEntry)>,
    created: Vec<OutPoint>,
}

pub struct BlockEntry {
    pub block: Block,
    pub height: u32,
    /// Сумма сложностей всех блоков от генезиса до этого включительно.
    pub total_work: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Блок уже известен.
    Duplicate,
    /// Неизвестен родитель: надо догрузить цепочку у того, кто прислал.
    Orphan,
    /// Блок нарушает правила.
    Invalid(String),
}

/// Как изменилась основная цепь после добавления блока.
#[derive(Debug, Default)]
pub struct ChainUpdate {
    /// Подключённые блоки, от старого к новому. Пусто — блок лёг в боковую ветку.
    pub connected: Vec<Hash>,
    /// Отключённые при реорганизации блоки. Их транзакции надо вернуть в мемпул.
    pub disconnected: Vec<Block>,
}

pub struct Chain {
    /// Все известные корректные блоки, включая боковые ветки.
    blocks: HashMap<Hash, BlockEntry>,
    /// Основная цепь: `main[h]` — хеш блока высоты `h`.
    main: Vec<Hash>,
    /// Набор UTXO на вершине основной цепи.
    utxo: HashMap<OutPoint, UtxoEntry>,
    undo: HashMap<Hash, BlockUndo>,
    /// Блоки, которые не удалось подключить. Их потомков не принимаем.
    invalid: HashSet<Hash>,
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Chain {
    pub fn new() -> Self {
        let genesis = consensus::genesis_block();
        let hash = genesis.hash();
        let entry = BlockEntry { total_work: genesis.header.difficulty as u128, block: genesis, height: 0 };
        Chain {
            blocks: HashMap::from([(hash, entry)]),
            main: vec![hash],
            utxo: HashMap::new(),
            undo: HashMap::from([(hash, BlockUndo::default())]),
            invalid: HashSet::new(),
        }
    }

    pub fn height(&self) -> u32 {
        (self.main.len() - 1) as u32
    }

    pub fn tip(&self) -> Hash {
        *self.main.last().expect("генезис есть всегда")
    }

    pub fn get(&self, hash: &Hash) -> Option<&BlockEntry> {
        self.blocks.get(hash)
    }

    pub fn block_at(&self, height: u32) -> Option<&Block> {
        self.main.get(height as usize).map(|hash| &self.blocks[hash].block)
    }

    fn is_on_main(&self, hash: &Hash) -> bool {
        self.blocks.get(hash).is_some_and(|e| self.main.get(e.height as usize) == Some(hash))
    }

    /// Предок блока `hash` на высоте `height` — идём назад по `prev_hash`.
    fn ancestor(&self, mut hash: Hash, height: u32) -> &BlockEntry {
        loop {
            let entry = &self.blocks[&hash];
            if entry.height <= height {
                return entry;
            }
            hash = entry.block.header.prev_hash;
        }
    }

    /// Какую сложность обязан указать блок, идущий после `parent`.
    /// Считается по ветке самого блока, а не по основной цепи.
    pub fn next_difficulty(&self, parent: &Hash) -> u64 {
        let p = &self.blocks[parent];
        let height = p.height + 1;
        if !height.is_multiple_of(RETARGET_INTERVAL) || height <= RETARGET_INTERVAL {
            return p.block.header.difficulty;
        }
        let first = self.ancestor(*parent, p.height - RETARGET_INTERVAL);
        let span = p.block.header.time.saturating_sub(first.block.header.time);
        consensus::retarget(p.block.header.difficulty, span)
    }

    /// Медиана времени последних 11 блоков. Время блока обязано быть больше:
    /// часы майнеров не совпадают, а медиана растёт, даже если кто-то врёт.
    pub fn median_time_past(&self, parent: &Hash) -> u64 {
        let mut times = Vec::new();
        let mut hash = *parent;
        for _ in 0..MEDIAN_TIME_SPAN {
            let entry = &self.blocks[&hash];
            times.push(entry.block.header.time);
            if entry.height == 0 {
                break;
            }
            hash = entry.block.header.prev_hash;
        }
        times.sort_unstable();
        times[times.len() / 2]
    }

    /// Главный вход: принять блок от сети или от своего майнера.
    pub fn add_block(&mut self, block: Block, now: u64) -> Result<ChainUpdate, BlockError> {
        let hash = block.hash();
        if self.blocks.contains_key(&hash) || self.invalid.contains(&hash) {
            return Err(BlockError::Duplicate);
        }
        consensus::check_block_standalone(&block).map_err(BlockError::Invalid)?;

        let prev = block.header.prev_hash;
        if self.invalid.contains(&prev) {
            self.invalid.insert(hash);
            return Err(BlockError::Invalid("родительский блок недействителен".into()));
        }
        let Some(parent) = self.blocks.get(&prev) else {
            return Err(BlockError::Orphan);
        };
        let height = parent.height + 1;
        let total_work = parent.total_work + block.header.difficulty as u128;

        let expected = self.next_difficulty(&prev);
        if block.header.difficulty != expected {
            return Err(BlockError::Invalid(format!(
                "сложность {} вместо положенной {expected}",
                block.header.difficulty
            )));
        }
        if block.header.time <= self.median_time_past(&prev) {
            return Err(BlockError::Invalid("время блока не больше медианы 11 предыдущих".into()));
        }
        if block.header.time > now + MAX_FUTURE_TIME {
            return Err(BlockError::Invalid("блок из будущего".into()));
        }

        // Заголовок в порядке. Блок запоминаем в любом случае: даже если его
        // ветка сейчас легче, завтра она может стать основной.
        self.blocks.insert(hash, BlockEntry { block, height, total_work });

        // Правило выбора цепи: побеждает наибольшая суммарная работа.
        // При равенстве остаёмся на той, что увидели первой.
        if total_work > self.blocks[&self.tip()].total_work {
            self.reorganize(hash).map_err(|error| {
                self.invalid.insert(hash);
                BlockError::Invalid(error)
            })
        } else {
            Ok(ChainUpdate::default())
        }
    }

    /// Сделать `new_tip` вершиной основной цепи.
    fn reorganize(&mut self, new_tip: Hash) -> Result<ChainUpdate, String> {
        // 1. Путь от новой вершины вниз до точки расхождения с основной цепью.
        let mut branch = Vec::new();
        let mut hash = new_tip;
        while !self.is_on_main(&hash) {
            if self.invalid.contains(&hash) {
                return Err("ветка содержит недействительный блок".into());
            }
            branch.push(hash);
            hash = self.blocks[&hash].block.header.prev_hash;
        }
        let fork_point = hash;
        branch.reverse();

        // 2. Откатываем основную цепь до точки расхождения.
        let mut disconnected = Vec::new();
        while self.tip() != fork_point {
            disconnected.push(self.disconnect_tip());
        }

        // 3. Применяем новую ветку. Если какой-то блок в ней плохой —
        //    возвращаем всё как было.
        for (i, hash) in branch.iter().enumerate() {
            if let Err(error) = self.connect(*hash) {
                self.invalid.insert(*hash);
                for _ in 0..i {
                    self.disconnect_tip();
                }
                for block in disconnected.iter().rev() {
                    self.connect(block.hash()).expect("старая цепь была действительна");
                }
                return Err(error);
            }
        }
        Ok(ChainUpdate { connected: branch, disconnected })
    }

    /// Применить блок к UTXO: здесь проверяются все транзакции.
    fn connect(&mut self, hash: Hash) -> Result<(), String> {
        let entry = &self.blocks[&hash];
        let (block, height) = (entry.block.clone(), entry.height);
        let mut undo = BlockUndo::default();
        if let Err(error) = self.apply_block_txs(&block, height, &mut undo) {
            self.rollback(undo);
            return Err(error);
        }
        self.main.push(hash);
        self.undo.insert(hash, undo);
        Ok(())
    }

    fn apply_block_txs(&mut self, block: &Block, height: u32, undo: &mut BlockUndo) -> Result<(), String> {
        let mut fees: u64 = 0;
        // Транзакции применяются по порядку. Поэтому двойная трата внутри
        // блока ловится сама: второй вход не найдёт уже удалённый выход.
        for tx in &block.txs[1..] {
            let fee = self.check_tx(tx, height).map_err(|e| format!("транзакция {}: {e}", short(&tx.txid())))?;
            fees = fees.checked_add(fee).ok_or("переполнение суммы комиссий")?;
            self.apply_tx(tx, height, undo);
        }

        let coinbase = &block.txs[0];
        if coinbase.expiry_height != height {
            return Err("coinbase должна содержать высоту своего блока".into());
        }
        let allowed = consensus::block_reward(height) + fees;
        let paid = coinbase.output_sum().ok_or("переполнение в coinbase")?;
        if paid > allowed {
            return Err(format!("coinbase платит {paid}, а положено не больше {allowed}"));
        }
        self.apply_tx(coinbase, height, undo);
        Ok(())
    }

    /// Проверить обычную транзакцию так, будто она попадёт в блок высоты
    /// `height`. Возвращает комиссию. Это и есть ядро UTXO-модели.
    pub fn check_tx(&self, tx: &Transaction, height: u32) -> Result<u64, String> {
        if tx.is_coinbase() {
            return Err("coinbase вне начала блока".into());
        }
        consensus::check_tx_structure(tx)?;
        if height > tx.expiry_height {
            return Err("срок действия истёк (expiry_height)".into());
        }
        let sighash = tx.sighash();
        let mut input_sum: u64 = 0;
        for input in &tx.inputs {
            let entry = self.utxo.get(&input.prev).ok_or("вход ссылается на несуществующий или потраченный выход")?;
            if entry.coinbase && height.saturating_sub(entry.height) < COINBASE_MATURITY {
                return Err("награда за блок ещё не созрела".into());
            }
            if !crypto::verify(&entry.output.owner, &sighash, &input.signature) {
                return Err("неверная подпись".into());
            }
            input_sum = input_sum.checked_add(entry.output.amount).ok_or("переполнение суммы входов")?;
        }
        let output_sum = tx.output_sum().ok_or("переполнение суммы выходов")?;
        input_sum.checked_sub(output_sum).ok_or_else(|| "выходов больше, чем входов".into())
    }

    fn apply_tx(&mut self, tx: &Transaction, height: u32, undo: &mut BlockUndo) {
        for input in &tx.inputs {
            let spent = self.utxo.remove(&input.prev).expect("проверено в check_tx");
            undo.spent.push((input.prev, spent));
        }
        let txid = tx.txid();
        for (index, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint { txid, index: index as u16 };
            let entry = UtxoEntry { output: output.clone(), height, coinbase: tx.is_coinbase() };
            self.utxo.insert(outpoint, entry);
            undo.created.push(outpoint);
        }
    }

    /// Отмена: сначала вернуть потраченное, потом удалить созданное. Порядок
    /// важен: выход, созданный и потраченный в одном блоке, есть в обоих списках.
    fn rollback(&mut self, undo: BlockUndo) {
        for (outpoint, entry) in undo.spent {
            self.utxo.insert(outpoint, entry);
        }
        for outpoint in undo.created {
            self.utxo.remove(&outpoint);
        }
    }

    fn disconnect_tip(&mut self) -> Block {
        let hash = self.main.pop().expect("генезис не откатывается");
        let undo = self.undo.remove(&hash).expect("undo есть у каждого подключённого блока");
        self.rollback(undo);
        self.blocks[&hash].block.clone()
    }

    /// «Локатор»: хеши нашей цепи — 10 последних, затем с шагом 2, 4, 8…
    /// Пир находит в нём первый общий блок и присылает всё, что после.
    /// Так точка расхождения находится за O(log n) хешей.
    pub fn locator(&self) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut height = self.height() as i64;
        let mut step = 1;
        while height > 0 {
            out.push(self.main[height as usize]);
            if out.len() >= 10 {
                step *= 2;
            }
            height -= step;
        }
        out.push(self.main[0]);
        out
    }

    /// Высота первого блока из локатора, который есть в нашей основной цепи.
    pub fn find_fork(&self, locator: &[Hash]) -> u32 {
        locator.iter().find(|h| self.is_on_main(h)).map_or(0, |h| self.blocks[h].height)
    }

    /// Все непотраченные выходы, запертые ключом `owner`.
    pub fn utxos_of(&self, owner: &PublicKey) -> Vec<(OutPoint, UtxoEntry)> {
        let mut out: Vec<_> =
            self.utxo.iter().filter(|(_, e)| &e.output.owner == owner).map(|(o, e)| (*o, e.clone())).collect();
        out.sort_by_key(|(o, _)| *o);
        out
    }

    pub fn utxo_count(&self) -> usize {
        self.utxo.len()
    }
}

pub fn short(hash: &Hash) -> String {
    crypto::to_hex(&hash[..6])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{self, BlockHeader};
    use crate::consensus::{BLOCK_TIME, block_reward};
    use crate::crypto::Seed;
    use crate::tx::TxIn;

    const NOW: u64 = u64::MAX / 2;

    struct Miner {
        seed: Seed,
        key: PublicKey,
    }

    fn miner() -> Miner {
        let seed = crypto::new_seed();
        Miner { seed, key: crypto::public_key(&seed) }
    }

    /// Собрать и «добыть» блок поверх `parent`. Награда — без комиссий.
    fn make_block(chain: &Chain, parent: Hash, txs: Vec<Transaction>, to: &PublicKey) -> Block {
        let p = chain.get(&parent).unwrap();
        let height = p.height + 1;
        let coinbase = Transaction {
            inputs: vec![],
            outputs: vec![TxOut { amount: block_reward(height), owner: *to }],
            expiry_height: height,
        };
        let mut all = vec![coinbase];
        all.extend(txs);
        let txids: Vec<_> = all.iter().map(Transaction::txid).collect();
        let mut header = BlockHeader {
            prev_hash: parent,
            merkle_root: block::merkle_root(&txids),
            time: p.block.header.time + BLOCK_TIME,
            difficulty: chain.next_difficulty(&parent),
            nonce: 0,
        };
        while !block::meets_difficulty(&header.hash(), header.difficulty) {
            header.nonce += 1;
        }
        Block { header, txs: all }
    }

    fn mine(chain: &mut Chain, txs: Vec<Transaction>, to: &PublicKey) -> Result<ChainUpdate, BlockError> {
        let block = make_block(chain, chain.tip(), txs, to);
        chain.add_block(block, NOW)
    }

    fn pay(from: &Miner, prev: OutPoint, amount: u64, to: &PublicKey) -> Transaction {
        let mut tx = Transaction {
            inputs: vec![TxIn { prev, signature: [0; 64] }],
            outputs: vec![TxOut { amount, owner: *to }],
            expiry_height: 1000,
        };
        tx.sign(&from.seed);
        tx
    }

    /// Цепь, где у `alice` есть одна созревшая награда за блок 1.
    fn chain_with_coins(alice: &Miner) -> (Chain, OutPoint) {
        let mut chain = Chain::new();
        mine(&mut chain, vec![], &alice.key).unwrap();
        let coinbase = OutPoint { txid: chain.block_at(1).unwrap().txs[0].txid(), index: 0 };
        let nobody = [0u8; 32];
        for _ in 0..COINBASE_MATURITY {
            mine(&mut chain, vec![], &nobody).unwrap();
        }
        (chain, coinbase)
    }

    #[test]
    fn payment_moves_coins() {
        let (alice, bob) = (miner(), miner());
        let (mut chain, coin) = chain_with_coins(&alice);
        let tx = pay(&alice, coin, 30 * consensus::COIN, &bob.key);
        mine(&mut chain, vec![tx], &alice.key).unwrap();

        assert_eq!(chain.utxos_of(&bob.key).len(), 1);
        assert_eq!(chain.utxos_of(&bob.key)[0].1.output.amount, 30 * consensus::COIN);
        // Выход потрачен; у alice осталась только новая награда.
        assert!(!chain.utxo.contains_key(&coin));
    }

    #[test]
    fn coinbase_must_mature() {
        let (alice, bob) = (miner(), miner());
        let mut chain = Chain::new();
        mine(&mut chain, vec![], &alice.key).unwrap();
        let coin = OutPoint { txid: chain.block_at(1).unwrap().txs[0].txid(), index: 0 };
        let err = chain.check_tx(&pay(&alice, coin, 1, &bob.key), 2).unwrap_err();
        assert!(err.contains("не созрела"), "{err}");
    }

    #[test]
    fn rejects_invalid_spends() {
        let (alice, bob) = (miner(), miner());
        let (chain, coin) = chain_with_coins(&alice);
        let h = chain.height() + 1;

        // Чужой ключ.
        assert!(chain.check_tx(&pay(&bob, coin, 1, &bob.key), h).unwrap_err().contains("подпись"));
        // Больше, чем есть.
        let too_much = pay(&alice, coin, 51 * consensus::COIN, &bob.key);
        assert!(chain.check_tx(&too_much, h).unwrap_err().contains("выходов больше"));
        // Подпись верная, но транзакцию изменили после подписи.
        let mut tampered = pay(&alice, coin, 1, &bob.key);
        tampered.outputs[0].owner = alice.key;
        assert!(chain.check_tx(&tampered, h).unwrap_err().contains("подпись"));
        // Истёкшая.
        let mut expired = pay(&alice, coin, 1, &bob.key);
        expired.expiry_height = h - 1;
        expired.sign(&alice.seed);
        assert!(chain.check_tx(&expired, h).unwrap_err().contains("срок"));
    }

    #[test]
    fn double_spend_in_one_block_is_rejected() {
        let (alice, bob) = (miner(), miner());
        let (mut chain, coin) = chain_with_coins(&alice);
        let height = chain.height();
        let tx1 = pay(&alice, coin, 10 * consensus::COIN, &bob.key);
        let tx2 = pay(&alice, coin, 20 * consensus::COIN, &bob.key);
        let result = mine(&mut chain, vec![tx1, tx2], &alice.key);
        assert!(matches!(result, Err(BlockError::Invalid(e)) if e.contains("несуществующий")));
        // Состояние не изменилось: частично применённый блок откатился.
        assert_eq!(chain.height(), height);
        assert!(chain.utxo.contains_key(&coin));
        assert!(chain.utxos_of(&bob.key).is_empty());
    }

    #[test]
    fn coinbase_cannot_overpay() {
        let alice = miner();
        let mut chain = Chain::new();
        let mut block = make_block(&chain, chain.tip(), vec![], &alice.key);
        block.txs[0].outputs[0].amount += 1;
        block.header.merkle_root = block::merkle_root(&[block.txs[0].txid()]);
        while !block::meets_difficulty(&block.hash(), block.header.difficulty) {
            block.header.nonce += 1;
        }
        assert!(matches!(chain.add_block(block, NOW), Err(BlockError::Invalid(e)) if e.contains("coinbase платит")));
    }

    #[test]
    fn heavier_branch_wins_and_utxo_follows() {
        let (alice, bob) = (miner(), miner());
        let (mut chain, coin) = chain_with_coins(&alice);
        let fork = chain.tip();

        // Основная цепь: alice платит bob.
        mine(&mut chain, vec![pay(&alice, coin, 5 * consensus::COIN, &bob.key)], &alice.key).unwrap();
        assert_eq!(chain.utxos_of(&bob.key).len(), 1);

        // Соперник строит от `fork` ветку из двух пустых блоков.
        let b1 = make_block(&chain, fork, vec![], &bob.key);
        let b1_hash = b1.hash();
        let update = chain.add_block(b1, NOW).unwrap();
        assert!(update.connected.is_empty(), "равная работа — остаёмся на своей ветке");

        let b2 = make_block(&chain, b1_hash, vec![], &bob.key);
        let update = chain.add_block(b2, NOW).unwrap();
        assert_eq!(update.connected.len(), 2);
        assert_eq!(update.disconnected.len(), 1);

        // Платёж откатился, монета alice снова не потрачена,
        // у bob — только две награды из новой ветки.
        assert!(chain.utxo.contains_key(&coin));
        assert!(chain.utxos_of(&bob.key).iter().all(|(_, e)| e.coinbase));
        // Транзакция из отключённого блока вернётся в мемпул.
        assert_eq!(update.disconnected[0].txs.len(), 2);
    }

    #[test]
    fn invalid_heavier_branch_is_rolled_back() {
        let (alice, bob) = (miner(), miner());
        let (mut chain, coin) = chain_with_coins(&alice);
        let fork = chain.tip();
        mine(&mut chain, vec![], &alice.key).unwrap();
        let tip = chain.tip();

        // Ветка: блок с поддельной подписью, затем ещё один поверх.
        let bad_tx = pay(&bob, coin, 1, &bob.key);
        let b1 = make_block(&chain, fork, vec![bad_tx], &bob.key);
        let b1_hash = b1.hash();
        chain.add_block(b1, NOW).unwrap();
        let b2 = make_block(&chain, b1_hash, vec![], &bob.key);
        assert!(matches!(chain.add_block(b2, NOW), Err(BlockError::Invalid(_))));

        assert_eq!(chain.tip(), tip);
        assert!(chain.utxo.contains_key(&coin));
    }

    #[test]
    fn orphan_and_time_rules() {
        let alice = miner();
        let mut chain = Chain::new();
        let mut orphan = make_block(&chain, chain.tip(), vec![], &alice.key);
        orphan.header.prev_hash = [42; 32];
        while !block::meets_difficulty(&orphan.hash(), orphan.header.difficulty) {
            orphan.header.nonce += 1;
        }
        assert!(matches!(chain.add_block(orphan, NOW), Err(BlockError::Orphan)));

        let mut old = make_block(&chain, chain.tip(), vec![], &alice.key);
        old.header.time = consensus::GENESIS_TIME;
        assert!(matches!(chain.add_block(old, NOW), Err(BlockError::Invalid(e)) if e.contains("медианы")));
    }

    #[test]
    fn locator_finds_fork() {
        let alice = miner();
        let mut a = Chain::new();
        for _ in 0..50 {
            mine(&mut a, vec![], &alice.key).unwrap();
        }
        let locator = a.locator();
        assert_eq!(locator.first(), Some(&a.tip()));
        assert_eq!(locator.last(), Some(&a.main[0]));
        assert!(locator.len() < 20);
        assert_eq!(a.find_fork(&locator), 50);
        assert_eq!(Chain::new().find_fork(&locator), 0);
    }
}
