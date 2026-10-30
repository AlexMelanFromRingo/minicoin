// Параметры сети и правила, которые можно проверить, не зная истории.
//
// Всё в этом файле — консенсус: если два узла считают по-разному, сеть
// расколется. Поэтому только целые числа, никаких float и никакого
// «примерно».
package minicoin

import (
	"errors"
	"math"
	"math/bits"
)

// Coin: 1 монета = 10⁸ минимальных единиц. Все суммы хранятся в единицах (uint64).
const Coin uint64 = 100_000_000

// BlockTime — целевой интервал между блоками, секунды. Учебная сеть:
// побыстрее, чтобы было видно, как она живёт.
const BlockTime uint64 = 10

// RetargetInterval — как часто пересчитывается сложность, в блоках.
const RetargetInterval uint32 = 20

// InitialDifficulty — начальная сложность: около миллиона хешей, доли
// секунды на одном ядре. Переменная, а не константа, только ради тестов:
// они ставят 1, чтобы «майнинг» был мгновенным.
var InitialDifficulty uint64 = 1 << 20

// Награда начинается с 50 монет и делится пополам каждые 100 000 блоков.
const (
	InitialReward   = 50 * Coin
	HalvingInterval = uint32(100_000)
	// Всего будет выпущено чуть меньше 50 · 100 000 · 2 = 10 млн монет.
	MaxMoney = 10_000_000 * Coin
)

// CoinbaseMaturity: награду за блок можно потратить только через 10 блоков:
// если блок окажется в проигравшей ветке, его награда исчезнет, и вместе с
// ней исчезли бы все транзакции, которые её успели потратить.
const CoinbaseMaturity uint32 = 10

const MaxBlockSize = 1_000_000

// Время блока должно быть больше медианы 11 предыдущих...
const MedianTimeSpan = 11

// ...и не больше чем на 2 часа впереди часов узла.
const MaxFutureTime uint64 = 2 * 60 * 60

// GenesisTime — 2026-10-29 00:00:00 UTC.
const GenesisTime uint64 = 1_793_232_000

func BlockReward(height uint32) uint64 {
	halvings := height / HalvingInterval
	if halvings >= 64 {
		return 0
	}
	return InitialReward >> halvings
}

// Retarget — новая сложность по времени, за которое добыты последние
// RetargetInterval блоков. Блоки шли вдвое быстрее нормы → сложность
// вдвое выше. Изменение за раз ограничено ×4, чтобы искажённые временные
// метки не могли резко качнуть сеть.
//
// Произведение old · expected может не поместиться в 64 бита (Rust берёт
// u128), поэтому умножаем и делим 128-битно через math/bits.
func Retarget(oldDifficulty, actualSpan uint64) uint64 {
	expected := BlockTime * uint64(RetargetInterval)
	span := min(max(actualSpan, expected/4), expected*4)
	hi, lo := bits.Mul64(oldDifficulty, expected)
	if hi >= span {
		return math.MaxUint64 // частное не помещается в 64 бита
	}
	quotient, _ := bits.Div64(hi, lo, span)
	return max(quotient, 1)
}

// GenesisBlock: первый блок зашит в код. Его не проверяют, его просто знают.
// Coinbase без выходов: монет вне майнинга не существует (премайна нет).
func GenesisBlock() Block {
	coinbase := Transaction{ExpiryHeight: 0}
	header := BlockHeader{
		MerkleRoot: MerkleRoot([]Hash{coinbase.Txid()}),
		Time:       GenesisTime,
		Difficulty: InitialDifficulty,
	}
	return Block{Header: header, Txs: []Transaction{coinbase}}
}

// CheckTxStructure — проверки транзакции, которым не нужна история.
func CheckTxStructure(tx *Transaction) error {
	if !tx.IsCoinbase() && len(tx.Outputs) == 0 {
		return errors.New("транзакция без выходов")
	}
	for _, output := range tx.Outputs {
		if output.Amount == 0 {
			return errors.New("выход с нулевой суммой")
		}
	}
	if sum, ok := tx.OutputSum(); !ok || sum > MaxMoney {
		return errors.New("сумма выходов больше всех монет в мире")
	}
	seen := make(map[OutPoint]bool)
	for _, input := range tx.Inputs {
		if seen[input.Prev] {
			return errors.New("один и тот же выход потрачен дважды в одной транзакции")
		}
		seen[input.Prev] = true
	}
	return nil
}

// CheckBlockStandalone — проверки блока, которым не нужна история. Порядок —
// от дешёвых к дорогим: мусор отсеивается раньше, чем на него тратится время.
func CheckBlockStandalone(b *Block) error {
	if b.Size() > MaxBlockSize {
		return errors.New("блок больше 1 МБ")
	}
	if !MeetsDifficulty(b.Hash(), b.Header.Difficulty) {
		return errors.New("хеш заголовка выше цели: работа не доказана")
	}
	if len(b.Txs) == 0 || !b.Txs[0].IsCoinbase() {
		return errors.New("первая транзакция блока должна быть coinbase")
	}
	for i := 1; i < len(b.Txs); i++ {
		if b.Txs[i].IsCoinbase() {
			return errors.New("coinbase может быть только первой")
		}
	}
	for i := range b.Txs {
		if err := CheckTxStructure(&b.Txs[i]); err != nil {
			return err
		}
	}
	txids := make([]Hash, len(b.Txs))
	seen := make(map[Hash]bool)
	for i := range b.Txs {
		txids[i] = b.Txs[i].Txid()
		if seen[txids[i]] {
			return errors.New("в блоке повторяется транзакция")
		}
		seen[txids[i]] = true
	}
	if MerkleRoot(txids) != b.Header.MerkleRoot {
		return errors.New("корень Меркла не совпадает с транзакциями")
	}
	return nil
}
