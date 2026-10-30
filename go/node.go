// Узел: цепь + мемпул + сеть + майнер.
//
// Устройство нарочно простое: каждое соединение обслуживает своя горутина,
// а всё состояние узла лежит под одним мьютексом. Так легко рассуждать о
// корректности. Быстродействия это не даёт, но учебной сети оно не нужно.
//
// Синхронизация:
//  1. При подключении стороны обмениваются Status.
//  2. Кто отстал, шлёт GetBlocks со своим локатором.
//  3. Пир отвечает пачкой до 500 блоков и снова Status. Если отставание
//     осталось, шаг 2 повторяется.
//  4. Новый блок или транзакция, принятые узлом, рассылаются всем пирам.
//     Новому пиру узел сразу отдаёт свой мемпул.
//     Блок с неизвестным родителем — повод запросить GetBlocks.
package minicoin

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const blocksPerBatch = 500

// writeTimeout: пир, который не читает, не должен навсегда занять узел.
const writeTimeout = 10 * time.Second

type Config struct {
	Port    uint16
	Peers   []string
	DataDir string
	// Куда майнить награду. nil — узел не майнит.
	MineTo *PublicKey
}

type nodeState struct {
	chain   *Chain
	mempool *Mempool
	// Все принятые блоки дописываются сюда. При старте узел перечитывает
	// файл и заново проверяет каждый блок: отдельной базы UTXO нет.
	blocksFile *os.File
}

// conn — соединение с пиром. Писать в него могут несколько горутин
// (ответы, рассылка, майнер), поэтому запись под своим мьютексом.
type conn struct {
	mu     sync.Mutex
	stream net.Conn
}

func (c *conn) send(message Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.stream.SetWriteDeadline(time.Now().Add(writeTimeout))
	return Send(c.stream, message)
}

type Node struct {
	mu    sync.Mutex
	state nodeState
	// Пиры, которым рассылаются новые блоки и транзакции. Кошелёк сюда
	// не попадает: он не шлёт Status, значит он не пир.
	peersMu sync.Mutex
	peers   map[uint64]*conn
	nextID  atomic.Uint64
}

// response — что сделать после обработки сообщения (уже без блокировки состояния).
type response struct {
	reply      []Message
	broadcast  Message
	disconnect bool
}

func Now() uint64 {
	return uint64(time.Now().Unix())
}

func logf(format string, args ...any) {
	t := Now()
	fmt.Printf("[%02d:%02d:%02d] %s\n", t/3600%24, t/60%60, t%60, fmt.Sprintf(format, args...))
}

func RunNode(config Config) error {
	if err := os.MkdirAll(config.DataDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(config.DataDir, "blocks.dat")
	chain, err := loadChain(path)
	if err != nil {
		return err
	}
	logf("цепь загружена: высота %d, вершина %s", chain.Height(), Short(chain.Tip()))

	blocksFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	node := &Node{
		state: nodeState{chain: chain, mempool: NewMempool(), blocksFile: blocksFile},
		peers: map[uint64]*conn{},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.Port))
	if err != nil {
		return err
	}
	logf("слушаю порт %d", config.Port)
	go func() {
		for {
			stream, err := listener.Accept()
			if err != nil {
				continue
			}
			go node.serve(stream)
		}
	}()

	// Исходящие соединения переподключаются, если пир пропал.
	for _, peer := range config.Peers {
		go func(peer string) {
			for {
				if stream, err := net.Dial("tcp", peer); err == nil {
					logf("подключился к %s", peer)
					node.serve(stream)
					logf("соединение с %s закрыто", peer)
				}
				time.Sleep(5 * time.Second)
			}
		}(peer)
	}

	if config.MineTo != nil {
		logf("майнинг на адрес %s", EncodeAddress(*config.MineTo))
		go node.mine(*config.MineTo)
	}

	for {
		time.Sleep(30 * time.Second)
		node.mu.Lock()
		st := &node.state
		node.peersMu.Lock()
		peers := len(node.peers)
		node.peersMu.Unlock()
		logf("высота %d | сложность %d | мемпул %d | UTXO %d | пиров %d",
			st.chain.Height(), st.chain.NextDifficulty(st.chain.Tip()), st.mempool.Len(), st.chain.UtxoCount(), peers)
		node.mu.Unlock()
	}
}

// loadChain читает файл блоков: подряд записи `длина u32 | байты блока`.
func loadChain(path string) (*Chain, error) {
	chain := NewChain()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return chain, nil
	}
	if err != nil {
		return nil, err
	}
	pos := 0
	for pos+4 <= len(data) {
		length := int(binary.LittleEndian.Uint32(data[pos:]))
		if length > len(data)-pos-4 {
			break // запись оборвана: узел остановили посреди записи
		}
		if block, err := BlockFromBytes(data[pos+4 : pos+4+length]); err == nil {
			_, _ = chain.AddBlock(block, Now())
		}
		pos += 4 + length
	}
	return chain, nil
}

func (n *Node) serve(stream net.Conn) {
	id := n.nextID.Add(1)
	c := &conn{stream: stream}
	_ = c.send(n.status())

	reader := bufio.NewReader(stream)
	for {
		message, err := Recv(reader)
		if err != nil {
			break // обрыв связи или мусор от пира: просто закрываем
		}
		// Первый Status — знакомство с новым пиром. Отдаём ему свой мемпул:
		// иначе перезапущенный узел не узнал бы о транзакциях, ждущих блока.
		if _, ok := message.(Status); ok && n.addPeer(id, c) {
			n.mu.Lock()
			txs := n.state.mempool.Transactions()
			n.mu.Unlock()
			for _, tx := range txs {
				_ = c.send(TxMsg{tx})
			}
		}
		resp := n.handle(message)
		for _, reply := range resp.reply {
			if c.send(reply) != nil {
				break
			}
		}
		if resp.broadcast != nil {
			n.broadcast(resp.broadcast, id)
		}
		if resp.disconnect {
			break
		}
	}
	n.peersMu.Lock()
	delete(n.peers, id)
	n.peersMu.Unlock()
	_ = stream.Close()
}

// addPeer запоминает пира и сообщает, новый ли он.
func (n *Node) addPeer(id uint64, c *conn) bool {
	n.peersMu.Lock()
	defer n.peersMu.Unlock()
	_, known := n.peers[id]
	n.peers[id] = c
	return !known
}

func (n *Node) broadcast(message Message, except uint64) {
	n.peersMu.Lock()
	peers := make(map[uint64]*conn, len(n.peers))
	for id, c := range n.peers {
		peers[id] = c
	}
	n.peersMu.Unlock()
	for id, c := range peers {
		if id != except && c.send(message) != nil {
			n.peersMu.Lock()
			delete(n.peers, id)
			n.peersMu.Unlock()
		}
	}
}

func (n *Node) status() Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	return Status{Height: n.state.chain.Height(), Tip: n.state.chain.Tip()}
}

func (n *Node) handle(message Message) response {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := &n.state
	var resp response
	switch m := message.(type) {
	case Status:
		if m.Height > st.chain.Height() {
			resp.reply = append(resp.reply, GetBlocks{st.chain.Locator()})
		}
	case GetBlocks:
		fork := st.chain.FindFork(m.Locator)
		last := min(st.chain.Height(), fork+blocksPerBatch)
		for height := fork + 1; height <= last; height++ {
			resp.reply = append(resp.reply, BlockMsg{*st.chain.BlockAt(height)})
		}
		resp.reply = append(resp.reply, Status{Height: st.chain.Height(), Tip: st.chain.Tip()})
	case BlockMsg:
		return acceptBlock(st, m.Block)
	case TxMsg:
		txid, err := st.mempool.Add(m.Tx, st.chain)
		if err != nil {
			resp.reply = append(resp.reply, Text{"отклонена: " + err.Error()})
			break
		}
		logf("транзакция %s принята в мемпул", Short(txid))
		resp.reply = append(resp.reply, Text{"принята: " + ToHex(txid[:])})
		resp.broadcast = m
	case GetUtxos:
		// Выходы, уже потраченные транзакциями мемпула, не показываем:
		// иначе кошелёк попытается потратить их второй раз.
		var utxos []Utxo
		for _, u := range st.chain.UtxosOf(m.Owner) {
			if !st.mempool.IsSpent(u.OutPoint) {
				utxos = append(utxos, u)
			}
		}
		resp.reply = append(resp.reply, Utxos{Height: st.chain.Height(), Utxos: utxos})
	case GetBlock:
		if block := st.chain.BlockAt(m.Height); block != nil {
			resp.reply = append(resp.reply, BlockMsg{*block})
		} else {
			resp.reply = append(resp.reply, Text{fmt.Sprintf("блока на высоте %d нет", m.Height)})
		}
	case GetInfo:
		n.peersMu.Lock()
		peers := len(n.peers)
		n.peersMu.Unlock()
		tip := st.chain.Tip()
		resp.reply = append(resp.reply, Text{fmt.Sprintf(
			"высота:      %d\nвершина:     %s\nсложность:   %d (следующего блока)\nмемпул:      %d транзакций\nUTXO:        %d\nпиров:       %d",
			st.chain.Height(), ToHex(tip[:]), st.chain.NextDifficulty(tip), st.mempool.Len(), st.chain.UtxoCount(), peers,
		)})
	case GetMempoolTx:
		if tx, fee, ok := st.mempool.Get(m.Txid); ok {
			resp.reply = append(resp.reply, MempoolTx{Fee: fee, Tx: tx})
		} else {
			resp.reply = append(resp.reply, Text{"такой транзакции в мемпуле нет (уже в блоке или истекла?)"})
		}
	case Utxos, Text, MempoolTx:
	}
	return resp
}

func (n *Node) mine(owner PublicKey) {
	for {
		n.mu.Lock()
		block, tip := blockTemplate(&n.state, owner), n.state.chain.Tip()
		n.mu.Unlock()
		// Перебираем nonce. Раз в 100 000 попыток смотрим, не сменилась ли
		// вершина (тогда наш блок уже бесполезен) и не пора ли обновить
		// шаблон (время и свежие транзакции).
		started := time.Now()
		found := false
		for !found {
			for i := 0; i < 100_000; i++ {
				if MeetsDifficulty(block.Header.Hash(), block.Header.Difficulty) {
					found = true
					break
				}
				block.Header.Nonce++
			}
			if found {
				break
			}
			n.mu.Lock()
			stale := n.state.chain.Tip() != tip
			n.mu.Unlock()
			if stale || time.Since(started) > 10*time.Second {
				break
			}
		}
		if found {
			n.mu.Lock()
			resp := acceptBlock(&n.state, block)
			n.mu.Unlock()
			if resp.broadcast != nil {
				n.broadcast(resp.broadcast, math.MaxUint64)
			}
		}
	}
}

// acceptBlock принимает блок (от пира или своего майнера): цепь, файл, мемпул.
func acceptBlock(st *nodeState, block Block) response {
	var resp response
	hash := block.Hash()
	update, err := st.chain.AddBlock(block, Now())
	switch {
	case err == nil:
	case errors.Is(err, ErrDuplicate):
		return resp
	case errors.Is(err, ErrOrphan):
		resp.reply = append(resp.reply, GetBlocks{st.chain.Locator()})
		return resp
	default:
		logf("отклонён блок %s: %v", Short(hash), err)
		resp.disconnect = true
		return resp
	}

	bytes := block.Bytes()
	record := binary.LittleEndian.AppendUint32(nil, uint32(len(bytes)))
	_, _ = st.blocksFile.Write(append(record, bytes...))
	if len(update.Connected) == 0 {
		logf("блок %s лёг в боковую ветку", Short(hash))
		return resp
	}
	if len(update.Disconnected) > 0 {
		logf("РЕОРГАНИЗАЦИЯ: откачено %d блоков, подключено %d", len(update.Disconnected), len(update.Connected))
	}
	var returned []Transaction
	for _, b := range update.Disconnected {
		returned = append(returned, b.Txs...)
	}
	st.mempool.Refresh(st.chain, returned)
	logf("новая вершина: высота %d блок %s (%d транз.)", st.chain.Height(), Short(hash), len(block.Txs))
	resp.broadcast = BlockMsg{block}
	return resp
}

// blockTemplate — шаблон блока: coinbase с наградой и комиссиями + лучшие транзакции мемпула.
func blockTemplate(st *nodeState, owner PublicKey) Block {
	parent := st.chain.Tip()
	height := st.chain.Height() + 1
	txs, fees := st.mempool.Select(MaxBlockSize - 10_000)
	reward := BlockReward(height) + fees
	var outputs []TxOut
	if reward > 0 {
		outputs = []TxOut{{Amount: reward, Owner: owner}}
	}
	coinbase := Transaction{Outputs: outputs, ExpiryHeight: height}

	all := append([]Transaction{coinbase}, txs...)
	txids := make([]Hash, len(all))
	for i := range all {
		txids[i] = all[i].Txid()
	}
	header := BlockHeader{
		PrevHash:   parent,
		MerkleRoot: MerkleRoot(txids),
		Time:       max(Now(), st.chain.MedianTimePast(parent)+1),
		Difficulty: st.chain.NextDifficulty(parent),
	}
	return Block{Header: header, Txs: all}
}
