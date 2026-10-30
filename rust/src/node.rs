//! Узел: цепь + мемпул + сеть + майнер.
//!
//! Устройство нарочно простое: каждое соединение обслуживает свой поток,
//! а всё состояние узла лежит под одним мьютексом. Так легко рассуждать о
//! корректности. Быстродействия это не даёт, но учебной сети оно не нужно.
//!
//! Синхронизация:
//! 1. При подключении стороны обмениваются `Status`.
//! 2. Кто отстал, шлёт `GetBlocks` со своим локатором.
//! 3. Пир отвечает пачкой до 500 блоков и снова `Status`. Если отставание
//!    осталось, шаг 2 повторяется.
//! 4. Новый блок или транзакция, принятые узлом, рассылаются всем пирам.
//!    Новому пиру узел сразу отдаёт свой мемпул.
//!    Блок с неизвестным родителем — повод запросить `GetBlocks`.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::address;
use crate::block::{self, Block, BlockHeader};
use crate::chain::{BlockError, Chain, short};
use crate::consensus::{self, MAX_BLOCK_SIZE};
use crate::crypto::PublicKey;
use crate::mempool::Mempool;
use crate::net::{self, Message};
use crate::tx::{Transaction, TxOut};

const BLOCKS_PER_BATCH: u32 = 500;

pub struct Config {
    pub port: u16,
    pub peers: Vec<String>,
    pub data_dir: PathBuf,
    /// Куда майнить награду. `None` — узел не майнит.
    pub mine_to: Option<PublicKey>,
}

struct State {
    chain: Chain,
    mempool: Mempool,
    /// Все принятые блоки дописываются сюда. При старте узел перечитывает
    /// файл и заново проверяет каждый блок: отдельной базы UTXO нет.
    blocks_file: File,
}

type Conn = Arc<Mutex<TcpStream>>;

struct Node {
    state: Mutex<State>,
    /// Пиры, которым рассылаются новые блоки и транзакции. Кошелёк сюда
    /// не попадает: он не шлёт `Status`, значит он не пир.
    peers: Mutex<HashMap<u64, Conn>>,
    next_id: AtomicU64,
}

/// Что сделать после обработки сообщения (уже без блокировки состояния).
#[derive(Default)]
struct Response {
    reply: Vec<Message>,
    broadcast: Option<Message>,
    disconnect: bool,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("часы до 1970 года").as_secs()
}

macro_rules! log {
    ($($arg:tt)*) => {{
        let t = now();
        println!("[{:02}:{:02}:{:02}] {}", t / 3600 % 24, t / 60 % 60, t % 60, format!($($arg)*));
    }};
}

pub fn run(config: Config) -> io::Result<()> {
    fs::create_dir_all(&config.data_dir)?;
    let path = config.data_dir.join("blocks.dat");
    let chain = load_chain(&path)?;
    log!("цепь загружена: высота {}, вершина {}", chain.height(), short(&chain.tip()));

    let blocks_file = OpenOptions::new().create(true).append(true).open(&path)?;
    let node = Arc::new(Node {
        state: Mutex::new(State { chain, mempool: Mempool::default(), blocks_file }),
        peers: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(0),
    });

    let listener = TcpListener::bind(("0.0.0.0", config.port))?;
    log!("слушаю порт {}", config.port);
    let n = node.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let n = n.clone();
            thread::spawn(move || n.serve(stream));
        }
    });

    // Исходящие соединения переподключаются, если пир пропал.
    for peer in config.peers {
        let n = node.clone();
        thread::spawn(move || {
            loop {
                if let Ok(stream) = TcpStream::connect(&peer) {
                    log!("подключился к {peer}");
                    n.clone().serve(stream);
                    log!("соединение с {peer} закрыто");
                }
                thread::sleep(Duration::from_secs(5));
            }
        });
    }

    if let Some(owner) = config.mine_to {
        log!("майнинг на адрес {}", address::encode(&owner));
        let n = node.clone();
        thread::spawn(move || n.mine(owner));
    }

    loop {
        thread::sleep(Duration::from_secs(30));
        let st = node.state.lock().unwrap();
        let peers = node.peers.lock().unwrap().len();
        log!(
            "высота {} | сложность {} | мемпул {} | UTXO {} | пиров {peers}",
            st.chain.height(),
            st.chain.next_difficulty(&st.chain.tip()),
            st.mempool.len(),
            st.chain.utxo_count()
        );
    }
}

/// Файл блоков: подряд записи `длина u32 | байты блока`.
fn load_chain(path: &PathBuf) -> io::Result<Chain> {
    let mut chain = Chain::new();
    let Ok(mut file) = File::open(path) else {
        return Ok(chain);
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let Some(bytes) = data.get(pos + 4..pos + 4 + len) else { break };
        if let Ok(block) = Block::from_bytes(bytes) {
            let _ = chain.add_block(block, now());
        }
        pos += 4 + len;
    }
    Ok(chain)
}

impl Node {
    fn serve(self: Arc<Self>, stream: TcpStream) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let Ok(writer) = stream.try_clone() else { return };
        let conn: Conn = Arc::new(Mutex::new(writer));
        let status = self.status();
        let _ = net::send(&mut *conn.lock().unwrap(), &status);

        let mut reader = BufReader::new(stream);
        while let Ok(message) = net::recv(&mut reader) {
            // Первый Status — знакомство с новым пиром. Отдаём ему свой мемпул:
            // иначе перезапущенный узел не узнал бы о транзакциях, ждущих блока.
            if matches!(message, Message::Status { .. })
                && self.peers.lock().unwrap().insert(id, conn.clone()).is_none()
            {
                let txs = self.state.lock().unwrap().mempool.transactions();
                for tx in txs {
                    let _ = net::send(&mut *conn.lock().unwrap(), &Message::Tx(tx));
                }
            }
            let response = self.handle(message);
            for reply in &response.reply {
                if net::send(&mut *conn.lock().unwrap(), reply).is_err() {
                    break;
                }
            }
            if let Some(message) = &response.broadcast {
                self.broadcast(message, id);
            }
            if response.disconnect {
                break;
            }
        }
        self.peers.lock().unwrap().remove(&id);
        let _ = conn.lock().unwrap().shutdown(std::net::Shutdown::Both);
    }

    fn broadcast(&self, message: &Message, except: u64) {
        let peers: Vec<(u64, Conn)> = self.peers.lock().unwrap().iter().map(|(id, c)| (*id, c.clone())).collect();
        for (id, conn) in peers {
            if id != except && net::send(&mut *conn.lock().unwrap(), message).is_err() {
                self.peers.lock().unwrap().remove(&id);
            }
        }
    }

    fn status(&self) -> Message {
        let st = self.state.lock().unwrap();
        Message::Status { height: st.chain.height(), tip: st.chain.tip() }
    }

    fn handle(&self, message: Message) -> Response {
        let mut guard = self.state.lock().unwrap();
        let st = &mut *guard;
        let mut response = Response::default();
        match message {
            Message::Status { height, .. } => {
                if height > st.chain.height() {
                    response.reply.push(Message::GetBlocks { locator: st.chain.locator() });
                }
            }
            Message::GetBlocks { locator } => {
                let fork = st.chain.find_fork(&locator);
                let last = st.chain.height().min(fork + BLOCKS_PER_BATCH);
                for height in fork + 1..=last {
                    response.reply.push(Message::Block(st.chain.block_at(height).unwrap().clone()));
                }
                response.reply.push(Message::Status { height: st.chain.height(), tip: st.chain.tip() });
            }
            Message::Block(block) => return accept_block(st, block),
            Message::Tx(tx) => match st.mempool.add(tx.clone(), &st.chain) {
                Ok(txid) => {
                    log!("транзакция {} принята в мемпул", short(&txid));
                    response.reply.push(Message::Text(format!("принята: {}", crate::crypto::to_hex(&txid))));
                    response.broadcast = Some(Message::Tx(tx));
                }
                Err(error) => response.reply.push(Message::Text(format!("отклонена: {error}"))),
            },
            Message::GetUtxos { owner, include_mempool_spent } => {
                // Выходы, уже потраченные транзакциями мемпула, не показываем:
                // иначе кошелёк попытается потратить их второй раз. Их просит
                // только `bump`, чтобы узнать суммы входов застрявшей транзакции.
                let utxos = st
                    .chain
                    .utxos_of(&owner)
                    .into_iter()
                    .filter(|(o, _)| include_mempool_spent || !st.mempool.is_spent(o))
                    .collect();
                response.reply.push(Message::Utxos { height: st.chain.height(), utxos });
            }
            Message::GetBlock { height } => response.reply.push(match st.chain.block_at(height) {
                Some(block) => Message::Block(block.clone()),
                None => Message::Text(format!("блока на высоте {height} нет")),
            }),
            Message::GetInfo => {
                let peers = self.peers.lock().unwrap().len();
                response.reply.push(Message::Text(format!(
                    "высота:      {}\nвершина:     {}\nсложность:   {} (следующего блока)\nмемпул:      {} транзакций\nUTXO:        {}\nпиров:       {peers}",
                    st.chain.height(),
                    crate::crypto::to_hex(&st.chain.tip()),
                    st.chain.next_difficulty(&st.chain.tip()),
                    st.mempool.len(),
                    st.chain.utxo_count(),
                )));
            }
            Message::GetMempoolTx { txid } => response.reply.push(match st.mempool.get(&txid) {
                Some((tx, fee)) => Message::MempoolTx { fee, tx: tx.clone() },
                None => Message::Text("такой транзакции в мемпуле нет (уже в блоке или истекла?)".into()),
            }),
            Message::Utxos { .. } | Message::Text(_) | Message::MempoolTx { .. } => {}
        }
        response
    }

    fn mine(self: Arc<Self>, owner: PublicKey) {
        loop {
            let (mut block, tip) = {
                let st = self.state.lock().unwrap();
                (block_template(&st, owner), st.chain.tip())
            };
            // Перебираем nonce. Раз в 100 000 попыток смотрим, не сменилась ли
            // вершина (тогда наш блок уже бесполезен) и не пора ли обновить
            // шаблон (время и свежие транзакции).
            let started = Instant::now();
            let found = 'search: loop {
                for _ in 0..100_000 {
                    if block::meets_difficulty(&block.header.hash(), block.header.difficulty) {
                        break 'search true;
                    }
                    block.header.nonce += 1;
                }
                if self.state.lock().unwrap().chain.tip() != tip || started.elapsed() > Duration::from_secs(10) {
                    break 'search false;
                }
            };
            if found {
                let response = accept_block(&mut self.state.lock().unwrap(), block);
                if let Some(message) = &response.broadcast {
                    self.broadcast(message, u64::MAX);
                }
            }
        }
    }
}

/// Принять блок (от пира или своего майнера): цепь, файл, мемпул.
fn accept_block(st: &mut State, block: Block) -> Response {
    let mut response = Response::default();
    let hash = block.hash();
    let bytes = block.to_bytes();
    match st.chain.add_block(block.clone(), now()) {
        Ok(update) => {
            let _ = st.blocks_file.write_all(&(bytes.len() as u32).to_le_bytes());
            let _ = st.blocks_file.write_all(&bytes);
            if update.connected.is_empty() {
                log!("блок {} лёг в боковую ветку", short(&hash));
                return response;
            }
            if !update.disconnected.is_empty() {
                log!(
                    "РЕОРГАНИЗАЦИЯ: откачено {} блоков, подключено {}",
                    update.disconnected.len(),
                    update.connected.len()
                );
            }
            let returned = update.disconnected.into_iter().flat_map(|b| b.txs).collect();
            st.mempool.refresh(&st.chain, returned);
            log!("новая вершина: высота {} блок {} ({} транз.)", st.chain.height(), short(&hash), block.txs.len());
            response.broadcast = Some(Message::Block(block));
        }
        Err(BlockError::Duplicate) => {}
        Err(BlockError::Orphan) => response.reply.push(Message::GetBlocks { locator: st.chain.locator() }),
        Err(BlockError::Invalid(error)) => {
            log!("отклонён блок {}: {error}", short(&hash));
            response.disconnect = true;
        }
    }
    response
}

/// Шаблон блока: coinbase с наградой и комиссиями + лучшие транзакции мемпула.
fn block_template(st: &State, owner: PublicKey) -> Block {
    let parent = st.chain.tip();
    let height = st.chain.height() + 1;
    let (txs, fees) = st.mempool.select(MAX_BLOCK_SIZE - 10_000);
    let reward = consensus::block_reward(height) + fees;
    let outputs = if reward > 0 { vec![TxOut { amount: reward, owner }] } else { vec![] };
    let coinbase = Transaction { inputs: vec![], outputs, expiry_height: height };

    let mut all = vec![coinbase];
    all.extend(txs);
    let txids: Vec<_> = all.iter().map(Transaction::txid).collect();
    let header = BlockHeader {
        prev_hash: parent,
        merkle_root: block::merkle_root(&txids),
        time: now().max(st.chain.median_time_past(&parent) + 1),
        difficulty: st.chain.next_difficulty(&parent),
        nonce: 0,
    };
    Block { header, txs: all }
}
