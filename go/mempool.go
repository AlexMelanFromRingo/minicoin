// Мемпул: проверенные транзакции, которые ждут включения в блок.
//
// Мемпул не часть консенсуса. У каждого узла он свой, и правила здесь —
// «политика узла», а не закон сети. Закон один: транзакция в блоке
// должна пройти Chain.CheckTx.
//
// Упрощение minicoin: транзакция может тратить только подтверждённые
// выходы. Цепочек неподтверждённых транзакций нет, поэтому любой набор
// транзакций из мемпула можно положить в блок в любом порядке.
package minicoin

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"
)

// MinFeeRate — минимальная комиссия для ретрансляции: единиц за байт. Без
// неё сеть можно бесплатно завалить мусорными транзакциями.
const MinFeeRate uint64 = 1

type mempoolEntry struct {
	tx   Transaction
	fee  uint64
	size int
}

type Mempool struct {
	txs map[Hash]*mempoolEntry
	// Какая транзакция мемпула тратит данный выход. Нужно для поиска конфликтов.
	spentBy map[OutPoint]Hash
}

func NewMempool() *Mempool {
	return &Mempool{txs: map[Hash]*mempoolEntry{}, spentBy: map[OutPoint]Hash{}}
}

// compareProducts сравнивает a1·a2 и b1·b2 без переполнения: произведения
// считаются 128-битными (Rust здесь берёт u128). Так сравниваются ставки
// «комиссия за байт» без дробей: a.fee/a.size > b.fee/b.size ⇔
// a.fee·b.size > b.fee·a.size.
func compareProducts(a1, a2, b1, b2 uint64) int {
	aHi, aLo := bits.Mul64(a1, a2)
	bHi, bLo := bits.Mul64(b1, b2)
	if aHi != bHi {
		return cmp.Compare(aHi, bHi)
	}
	return cmp.Compare(aLo, bLo)
}

// ShouldReplace — replace-by-fee: можно ли вытеснить из мемпула
// конфликтующие транзакции (они тратят те же выходы) новой транзакцией.
//
// Зачем это нужно: отправитель поставил слишком маленькую комиссию,
// транзакция застряла, и он хочет переотправить те же монеты дороже.
//
// Чем опасна слишком мягкая политика: каждая замена заново рассылается
// всей сети. Если менять можно «за копейку», один человек бесплатно
// загрузит всю сеть бесконечными заменами.
//
//   - newFee, newSize — комиссия и размер в байтах новой транзакции;
//   - oldFee, oldSize — суммарные комиссия и размер всех вытесняемых.
//
// Правило из двух условий (суть BIP 125 из Bitcoin Core):
//
//  1. Замена платит всё, что платили вытесняемые, **плюс** собственную
//     ретрансляцию по минимальной ставке. Старые транзакции уже разошлись
//     по сети бесплатно для отправителя. Если бы замене хватало «на единицу
//     больше», каждая следующая замена снова гоняла бы байты по всем узлам
//     почти даром. Так каждая замена обходится минимум в стоимость новой
//     транзакции.
//  2. Комиссия **за байт** строго выше. Майнер выбирает транзакции по
//     комиссии за байт (Select), и замена не должна делать мемпул хуже
//     для него: огромная транзакция с чуть большей суммой, но меньшей
//     ставкой, вытеснила бы выгодную маленькую и задержала бы её.
func ShouldReplace(newFee uint64, newSize int, oldFee uint64, oldSize int) bool {
	relayCost := MinFeeRate * uint64(newSize)
	required, carry := bits.Add64(oldFee, relayCost, 0)
	if carry != 0 {
		required = math.MaxUint64 // насыщение, как saturating_add
	}
	paysForItself := newFee >= required
	betterRate := compareProducts(newFee, uint64(oldSize), oldFee, uint64(newSize)) > 0
	return paysForItself && betterRate
}

func (m *Mempool) Len() int {
	return len(m.txs)
}

func (m *Mempool) Contains(txid Hash) bool {
	return m.txs[txid] != nil
}

func (m *Mempool) Transactions() []Transaction {
	var out []Transaction
	for _, entry := range m.txs {
		out = append(out, entry.tx)
	}
	return out
}

// Get — транзакция мемпула и её комиссия.
func (m *Mempool) Get(txid Hash) (Transaction, uint64, bool) {
	entry := m.txs[txid]
	if entry == nil {
		return Transaction{}, 0, false
	}
	return entry.tx, entry.fee, true
}

// IsSpent: выход уже потрачен какой-то транзакцией мемпула.
func (m *Mempool) IsSpent(outpoint OutPoint) bool {
	_, ok := m.spentBy[outpoint]
	return ok
}

func (m *Mempool) Add(tx Transaction, chain *Chain) (Hash, error) {
	txid := tx.Txid()
	if m.txs[txid] != nil {
		return txid, errors.New("уже в мемпуле")
	}
	fee, err := chain.CheckTx(&tx, chain.Height()+1)
	if err != nil {
		return txid, err
	}
	size := tx.Size()
	minFee := uint64(size) * MinFeeRate
	if fee < minFee {
		return txid, fmt.Errorf("комиссия %d меньше минимальной %d (%d ед/байт)", fee, minFee, MinFeeRate)
	}

	conflicts := map[Hash]bool{}
	for _, input := range tx.Inputs {
		if id, ok := m.spentBy[input.Prev]; ok {
			conflicts[id] = true
		}
	}
	if len(conflicts) > 0 {
		var oldFee uint64
		var oldSize int
		for id := range conflicts {
			oldFee += m.txs[id].fee
			oldSize += m.txs[id].size
		}
		if !ShouldReplace(fee, size, oldFee, oldSize) {
			return txid, errors.New("тратит те же выходы, что и транзакция в мемпуле; замена отклонена")
		}
		for id := range conflicts {
			m.remove(id)
		}
	}

	for _, input := range tx.Inputs {
		m.spentBy[input.Prev] = txid
	}
	m.txs[txid] = &mempoolEntry{tx: tx, fee: fee, size: size}
	return txid, nil
}

func (m *Mempool) remove(txid Hash) {
	if entry := m.txs[txid]; entry != nil {
		delete(m.txs, txid)
		for _, input := range entry.tx.Inputs {
			delete(m.spentBy, input.Prev)
		}
	}
}

// Refresh: после смены вершины цепи проверяем всё заново. Попавшие в блок
// транзакции отсеются сами (их входы уже потрачены), так же как истёкшие
// и конфликтующие с блоком. returned — транзакции из блоков, отключённых
// при реорганизации: они снова ждут своей очереди.
func (m *Mempool) Refresh(chain *Chain, returned []Transaction) {
	var pending []Transaction
	for _, tx := range returned {
		if !tx.IsCoinbase() {
			pending = append(pending, tx)
		}
	}
	for _, entry := range m.txs {
		pending = append(pending, entry.tx)
	}
	m.txs = map[Hash]*mempoolEntry{}
	m.spentBy = map[OutPoint]Hash{}
	for _, tx := range pending {
		_, _ = m.Add(tx, chain)
	}
}

// Select — транзакции для нового блока: самые выгодные (комиссия за байт)
// первыми, пока помещаются. Возвращает их и сумму комиссий.
func (m *Mempool) Select(maxBytes int) ([]Transaction, uint64) {
	type candidate struct {
		txid  Hash
		entry *mempoolEntry
	}
	var entries []candidate
	for txid, entry := range m.txs {
		entries = append(entries, candidate{txid, entry})
	}
	// a.fee/a.size > b.fee/b.size ⇔ a.fee·b.size > b.fee·a.size — без дробей.
	slices.SortFunc(entries, func(a, b candidate) int {
		order := compareProducts(b.entry.fee, uint64(a.entry.size), a.entry.fee, uint64(b.entry.size))
		if order != 0 {
			return order
		}
		return bytes.Compare(a.txid[:], b.txid[:])
	})
	var txs []Transaction
	var fees uint64
	var size int
	for _, c := range entries {
		if size+c.entry.size <= maxBytes {
			size += c.entry.size
			fees += c.entry.fee
			txs = append(txs, c.entry.tx)
		}
	}
	return txs, fees
}
