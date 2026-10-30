// Цепочка блоков и набор UTXO — сердце узла.
//
// Узел знает дерево блоков (все ветки, которые ему показали), но
// «правдой» считает одну: ветку с наибольшей суммарной работой. Набор
// UTXO всегда соответствует вершине этой ветки.
//
// Если другая ветка обгоняет текущую по работе, происходит реорганизация:
// блоки текущей ветки откатываются до точки расхождения (для этого у
// каждого блока хранятся undo-данные), затем применяются блоки новой ветки.
package minicoin

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"slices"
)

// UtxoEntry — непотраченный выход и то, что о нём нужно помнить для проверки трат.
type UtxoEntry struct {
	Output TxOut
	// Высота блока, где создан выход (для созревания coinbase).
	Height   uint32
	Coinbase bool
}

// Utxo — выход вместе с его адресом (какой транзакции, какой номер).
type Utxo struct {
	OutPoint OutPoint
	Entry    UtxoEntry
}

// blockUndo — всё, что нужно, чтобы отменить блок: какие выходы он
// потратил (их надо вернуть) и какие создал (их надо удалить).
type blockUndo struct {
	spent   []Utxo
	created []OutPoint
}

type BlockEntry struct {
	Block  Block
	Height uint32
	// Сумма сложностей всех блоков от генезиса до этого включительно.
	// В 64 бита она может не поместиться (Rust берёт u128), отсюда big.Int.
	TotalWork *big.Int
}

var (
	// ErrDuplicate — блок уже известен.
	ErrDuplicate = errors.New("блок уже известен")
	// ErrOrphan — неизвестен родитель: надо догрузить цепочку у того, кто прислал.
	ErrOrphan = errors.New("неизвестен родительский блок")
)

// Любая другая ошибка AddBlock означает, что блок нарушает правила.

// ChainUpdate — как изменилась основная цепь после добавления блока.
type ChainUpdate struct {
	// Подключённые блоки, от старого к новому. Пусто — блок лёг в боковую ветку.
	Connected []Hash
	// Отключённые при реорганизации блоки. Их транзакции надо вернуть в мемпул.
	Disconnected []Block
}

type Chain struct {
	// Все известные корректные блоки, включая боковые ветки.
	blocks map[Hash]*BlockEntry
	// Основная цепь: main[h] — хеш блока высоты h.
	main []Hash
	// Набор UTXO на вершине основной цепи.
	utxo map[OutPoint]UtxoEntry
	undo map[Hash]*blockUndo
	// Блоки, которые не удалось подключить. Их потомков не принимаем.
	invalid map[Hash]bool
}

func NewChain() *Chain {
	genesis := GenesisBlock()
	hash := genesis.Hash()
	entry := &BlockEntry{Block: genesis, Height: 0, TotalWork: new(big.Int).SetUint64(genesis.Header.Difficulty)}
	return &Chain{
		blocks:  map[Hash]*BlockEntry{hash: entry},
		main:    []Hash{hash},
		utxo:    map[OutPoint]UtxoEntry{},
		undo:    map[Hash]*blockUndo{hash: {}},
		invalid: map[Hash]bool{},
	}
}

func (c *Chain) Height() uint32 {
	return uint32(len(c.main) - 1)
}

func (c *Chain) Tip() Hash {
	return c.main[len(c.main)-1] // генезис есть всегда
}

func (c *Chain) Get(hash Hash) *BlockEntry {
	return c.blocks[hash]
}

func (c *Chain) BlockAt(height uint32) *Block {
	if uint64(height) >= uint64(len(c.main)) {
		return nil
	}
	return &c.blocks[c.main[height]].Block
}

func (c *Chain) isOnMain(hash Hash) bool {
	entry, ok := c.blocks[hash]
	return ok && int(entry.Height) < len(c.main) && c.main[entry.Height] == hash
}

// ancestor — предок блока hash на высоте height: идём назад по PrevHash.
func (c *Chain) ancestor(hash Hash, height uint32) *BlockEntry {
	for {
		entry := c.blocks[hash]
		if entry.Height <= height {
			return entry
		}
		hash = entry.Block.Header.PrevHash
	}
}

// NextDifficulty — какую сложность обязан указать блок, идущий после parent.
// Считается по ветке самого блока, а не по основной цепи.
func (c *Chain) NextDifficulty(parent Hash) uint64 {
	p := c.blocks[parent]
	height := p.Height + 1
	if height%RetargetInterval != 0 || height <= RetargetInterval {
		return p.Block.Header.Difficulty
	}
	first := c.ancestor(parent, p.Height-RetargetInterval)
	span := satSub64(p.Block.Header.Time, first.Block.Header.Time)
	return Retarget(p.Block.Header.Difficulty, span)
}

// MedianTimePast — медиана времени последних 11 блоков. Время блока обязано
// быть больше: часы майнеров не совпадают, а медиана растёт, даже если кто-то врёт.
func (c *Chain) MedianTimePast(parent Hash) uint64 {
	var times []uint64
	hash := parent
	for i := 0; i < MedianTimeSpan; i++ {
		entry := c.blocks[hash]
		times = append(times, entry.Block.Header.Time)
		if entry.Height == 0 {
			break
		}
		hash = entry.Block.Header.PrevHash
	}
	slices.Sort(times)
	return times[len(times)/2]
}

// AddBlock — главный вход: принять блок от сети или от своего майнера.
func (c *Chain) AddBlock(block Block, now uint64) (ChainUpdate, error) {
	hash := block.Hash()
	if c.blocks[hash] != nil || c.invalid[hash] {
		return ChainUpdate{}, ErrDuplicate
	}
	if err := CheckBlockStandalone(&block); err != nil {
		return ChainUpdate{}, err
	}

	prev := block.Header.PrevHash
	if c.invalid[prev] {
		c.invalid[hash] = true
		return ChainUpdate{}, errors.New("родительский блок недействителен")
	}
	parent := c.blocks[prev]
	if parent == nil {
		return ChainUpdate{}, ErrOrphan
	}
	height := parent.Height + 1
	totalWork := new(big.Int).Add(parent.TotalWork, new(big.Int).SetUint64(block.Header.Difficulty))

	expected := c.NextDifficulty(prev)
	if block.Header.Difficulty != expected {
		return ChainUpdate{}, fmt.Errorf("сложность %d вместо положенной %d", block.Header.Difficulty, expected)
	}
	if block.Header.Time <= c.MedianTimePast(prev) {
		return ChainUpdate{}, errors.New("время блока не больше медианы 11 предыдущих")
	}
	if block.Header.Time > now+MaxFutureTime {
		return ChainUpdate{}, errors.New("блок из будущего")
	}

	// Заголовок в порядке. Блок запоминаем в любом случае: даже если его
	// ветка сейчас легче, завтра она может стать основной.
	c.blocks[hash] = &BlockEntry{Block: block, Height: height, TotalWork: totalWork}

	// Правило выбора цепи: побеждает наибольшая суммарная работа.
	// При равенстве остаёмся на той, что увидели первой.
	if totalWork.Cmp(c.blocks[c.Tip()].TotalWork) > 0 {
		update, err := c.reorganize(hash)
		if err != nil {
			c.invalid[hash] = true
			return ChainUpdate{}, err
		}
		return update, nil
	}
	return ChainUpdate{}, nil
}

// reorganize делает newTip вершиной основной цепи.
func (c *Chain) reorganize(newTip Hash) (ChainUpdate, error) {
	// 1. Путь от новой вершины вниз до точки расхождения с основной цепью.
	var branch []Hash
	hash := newTip
	for !c.isOnMain(hash) {
		if c.invalid[hash] {
			return ChainUpdate{}, errors.New("ветка содержит недействительный блок")
		}
		branch = append(branch, hash)
		hash = c.blocks[hash].Block.Header.PrevHash
	}
	forkPoint := hash
	slices.Reverse(branch)

	// 2. Откатываем основную цепь до точки расхождения.
	var disconnected []Block
	for c.Tip() != forkPoint {
		disconnected = append(disconnected, c.disconnectTip())
	}

	// 3. Применяем новую ветку. Если какой-то блок в ней плохой —
	//    возвращаем всё как было.
	for i, hash := range branch {
		if err := c.connect(hash); err != nil {
			c.invalid[hash] = true
			for j := 0; j < i; j++ {
				c.disconnectTip()
			}
			for j := len(disconnected) - 1; j >= 0; j-- {
				if err := c.connect(disconnected[j].Hash()); err != nil {
					panic("старая цепь была действительна: " + err.Error())
				}
			}
			return ChainUpdate{}, err
		}
	}
	return ChainUpdate{Connected: branch, Disconnected: disconnected}, nil
}

// connect применяет блок к UTXO: здесь проверяются все транзакции.
func (c *Chain) connect(hash Hash) error {
	entry := c.blocks[hash]
	undo := &blockUndo{}
	if err := c.applyBlockTxs(&entry.Block, entry.Height, undo); err != nil {
		c.rollback(undo)
		return err
	}
	c.main = append(c.main, hash)
	c.undo[hash] = undo
	return nil
}

func (c *Chain) applyBlockTxs(block *Block, height uint32, undo *blockUndo) error {
	var fees uint64
	// Транзакции применяются по порядку. Поэтому двойная трата внутри
	// блока ловится сама: второй вход не найдёт уже удалённый выход.
	for i := 1; i < len(block.Txs); i++ {
		tx := &block.Txs[i]
		fee, err := c.CheckTx(tx, height)
		if err != nil {
			txid := tx.Txid()
			return fmt.Errorf("транзакция %s: %w", Short(txid), err)
		}
		var carry uint64
		if fees, carry = bits.Add64(fees, fee, 0); carry != 0 {
			return errors.New("переполнение суммы комиссий")
		}
		c.applyTx(tx, height, undo)
	}

	coinbase := &block.Txs[0]
	if coinbase.ExpiryHeight != height {
		return errors.New("coinbase должна содержать высоту своего блока")
	}
	allowed := BlockReward(height) + fees
	paid, ok := coinbase.OutputSum()
	if !ok {
		return errors.New("переполнение в coinbase")
	}
	if paid > allowed {
		return fmt.Errorf("coinbase платит %d, а положено не больше %d", paid, allowed)
	}
	c.applyTx(coinbase, height, undo)
	return nil
}

// CheckTx проверяет обычную транзакцию так, будто она попадёт в блок высоты
// height. Возвращает комиссию. Это и есть ядро UTXO-модели.
func (c *Chain) CheckTx(tx *Transaction, height uint32) (uint64, error) {
	if tx.IsCoinbase() {
		return 0, errors.New("coinbase вне начала блока")
	}
	if err := CheckTxStructure(tx); err != nil {
		return 0, err
	}
	if height > tx.ExpiryHeight {
		return 0, errors.New("срок действия истёк (expiry_height)")
	}
	sighash := tx.Sighash()
	var inputSum uint64
	for _, input := range tx.Inputs {
		entry, ok := c.utxo[input.Prev]
		if !ok {
			return 0, errors.New("вход ссылается на несуществующий или потраченный выход")
		}
		if entry.Coinbase && satSub32(height, entry.Height) < CoinbaseMaturity {
			return 0, errors.New("награда за блок ещё не созрела")
		}
		if !Verify(entry.Output.Owner, sighash, input.Signature) {
			return 0, errors.New("неверная подпись")
		}
		var carry uint64
		if inputSum, carry = bits.Add64(inputSum, entry.Output.Amount, 0); carry != 0 {
			return 0, errors.New("переполнение суммы входов")
		}
	}
	outputSum, ok := tx.OutputSum()
	if !ok {
		return 0, errors.New("переполнение суммы выходов")
	}
	if inputSum < outputSum {
		return 0, errors.New("выходов больше, чем входов")
	}
	return inputSum - outputSum, nil
}

func (c *Chain) applyTx(tx *Transaction, height uint32, undo *blockUndo) {
	for _, input := range tx.Inputs {
		spent := c.utxo[input.Prev] // есть: проверено в CheckTx
		delete(c.utxo, input.Prev)
		undo.spent = append(undo.spent, Utxo{input.Prev, spent})
	}
	txid := tx.Txid()
	for index, output := range tx.Outputs {
		outpoint := OutPoint{Txid: txid, Index: uint16(index)}
		c.utxo[outpoint] = UtxoEntry{Output: output, Height: height, Coinbase: tx.IsCoinbase()}
		undo.created = append(undo.created, outpoint)
	}
}

// rollback — отмена: сначала вернуть потраченное, потом удалить созданное.
// Порядок важен: выход, созданный и потраченный в одном блоке, есть в обоих списках.
func (c *Chain) rollback(undo *blockUndo) {
	for _, spent := range undo.spent {
		c.utxo[spent.OutPoint] = spent.Entry
	}
	for _, outpoint := range undo.created {
		delete(c.utxo, outpoint)
	}
}

func (c *Chain) disconnectTip() Block {
	hash := c.main[len(c.main)-1] // генезис не откатывается: до него не доходит
	c.main = c.main[:len(c.main)-1]
	c.rollback(c.undo[hash]) // undo есть у каждого подключённого блока
	delete(c.undo, hash)
	return c.blocks[hash].Block
}

// Locator — хеши нашей цепи: 10 последних, затем с шагом 2, 4, 8…
// Пир находит в нём первый общий блок и присылает всё, что после.
// Так точка расхождения находится за O(log n) хешей.
func (c *Chain) Locator() []Hash {
	var out []Hash
	height := int64(c.Height())
	step := int64(1)
	for height > 0 {
		out = append(out, c.main[height])
		if len(out) >= 10 {
			step *= 2
		}
		height -= step
	}
	return append(out, c.main[0])
}

// FindFork — высота первого блока из локатора, который есть в нашей основной цепи.
func (c *Chain) FindFork(locator []Hash) uint32 {
	for _, hash := range locator {
		if c.isOnMain(hash) {
			return c.blocks[hash].Height
		}
	}
	return 0
}

// UtxosOf — все непотраченные выходы, запертые ключом owner.
func (c *Chain) UtxosOf(owner PublicKey) []Utxo {
	var out []Utxo
	for outpoint, entry := range c.utxo {
		if entry.Output.Owner == owner {
			out = append(out, Utxo{outpoint, entry})
		}
	}
	slices.SortFunc(out, func(a, b Utxo) int { return compareOutPoints(a.OutPoint, b.OutPoint) })
	return out
}

func (c *Chain) UtxoCount() int {
	return len(c.utxo)
}

func compareOutPoints(a, b OutPoint) int {
	if order := bytes.Compare(a.Txid[:], b.Txid[:]); order != 0 {
		return order
	}
	return cmp.Compare(a.Index, b.Index)
}

func Short(hash Hash) string {
	return ToHex(hash[:6])
}

// Вычитание с насыщением, как saturating_sub в Rust: меньше нуля не бывает.
func satSub32(a, b uint32) uint32 {
	if a < b {
		return 0
	}
	return a - b
}

func satSub64(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
