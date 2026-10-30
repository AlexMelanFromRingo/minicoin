// Транзакции и модель UTXO.
//
// Монеты существуют только в виде непотраченных выходов (UTXO, Unspent
// Transaction Output). «Баланса» как числа нигде нет: баланс — это сумма
// выходов, запертых вашим ключом.
//
// Транзакция тратит старые выходы целиком (входы ссылаются на них) и
// создаёт новые. Разница «входы − выходы» — комиссия майнеру. Если нужно
// заплатить меньше, чем лежит в выходе, остаток возвращается себе
// отдельным выходом («сдача»).
//
// Выход запирается открытым ключом получателя, а вход отпирает его
// подписью этим ключом. Скриптового языка нет, это и есть всё условие траты.
package minicoin

import "math/bits"

// OutPoint — ссылка на выход: «выход номер Index транзакции Txid».
type OutPoint struct {
	Txid  Hash
	Index uint16
}

type TxIn struct {
	// Какой выход тратим.
	Prev OutPoint
	// Подпись владельца выхода под Transaction.Sighash.
	Signature Sig
}

type TxOut struct {
	// Сумма в минимальных единицах (1 монета = 100 000 000 единиц).
	Amount uint64
	// Кто может потратить этот выход.
	Owner PublicKey
}

type Transaction struct {
	Inputs  []TxIn
	Outputs []TxOut
	// Транзакция действительна только в блоках с высотой ≤ ExpiryHeight.
	// Если её не включили вовремя, она навсегда недействительна, и её входы
	// можно потратить заново. Так транзакции не зависают в сети навечно.
	// У coinbase здесь записана высота блока: это делает её txid уникальным.
	ExpiryHeight uint32
}

// Размер входа и выхода в байтах (см. PROTOCOL.md).
const (
	InputSize  = 32 + 2 + 64
	OutputSize = 8 + 32
)

func (tx *Transaction) write(w *Writer, withSignatures bool) {
	if len(tx.Inputs) > 0xffff {
		panic("слишком много входов")
	}
	w.U16(uint16(len(tx.Inputs)))
	for _, input := range tx.Inputs {
		w.Raw(input.Prev.Txid[:])
		w.U16(input.Prev.Index)
		// При подписи места подписей заполняются нулями: нельзя подписать
		// байты, в которых уже должна стоять эта самая подпись.
		if withSignatures {
			w.Raw(input.Signature[:])
		} else {
			w.Raw(make([]byte, 64))
		}
	}
	if len(tx.Outputs) > 0xffff {
		panic("слишком много выходов")
	}
	w.U16(uint16(len(tx.Outputs)))
	for _, output := range tx.Outputs {
		w.U64(output.Amount)
		w.Raw(output.Owner[:])
	}
	w.U32(tx.ExpiryHeight)
}

func (tx *Transaction) Encode(w *Writer) {
	tx.write(w, true)
}

func (tx *Transaction) Bytes() []byte {
	var w Writer
	tx.write(&w, true)
	return w.Bytes
}

func ReadTransaction(r *Reader) Transaction {
	var tx Transaction
	count := r.U16()
	for i := uint16(0); i < count && r.Err() == nil; i++ {
		var input TxIn
		r.Array(input.Prev.Txid[:])
		input.Prev.Index = r.U16()
		r.Array(input.Signature[:])
		tx.Inputs = append(tx.Inputs, input)
	}
	count = r.U16()
	for i := uint16(0); i < count && r.Err() == nil; i++ {
		var output TxOut
		output.Amount = r.U64()
		r.Array(output.Owner[:])
		tx.Outputs = append(tx.Outputs, output)
	}
	tx.ExpiryHeight = r.U32()
	return tx
}

func TransactionFromBytes(data []byte) (Transaction, error) {
	r := NewReader(data)
	tx := ReadTransaction(r)
	if err := r.Finish(); err != nil {
		return Transaction{}, err
	}
	return tx, nil
}

// Txid — идентификатор транзакции, хеш всех её байтов, включая подписи.
func (tx *Transaction) Txid() Hash {
	return HashOf(tx.Bytes())
}

// Sighash — то, что подписывают владельцы входов: хеш транзакции с
// обнулёнными подписями, а за ним сумма и владелец каждого тратимого выхода
// (spent[i] — выход, который тратит вход i). Подпись покрывает все входы,
// все выходы и срок действия, поэтому изменить в подписанной транзакции
// ничего нельзя.
//
// Сумм тратимых выходов в байтах транзакции нет: кошелёк узнаёт их у узла.
// Раз они подписаны, узлу не нужно верить. Если он занизил сумму входа,
// кошелёк подпишет не те суммы, и сеть отвергнет подпись, а не заберёт
// разницу в комиссию майнеру (как BIP143 в Bitcoin).
func (tx *Transaction) Sighash(spent []TxOut) Hash {
	if len(spent) != len(tx.Inputs) {
		panic("нужен ровно один тратимый выход на каждый вход")
	}
	var w Writer
	tx.write(&w, false)
	for _, output := range spent {
		w.U64(output.Amount)
		w.Raw(output.Owner[:])
	}
	return HashOf(w.Bytes)
}

// Sign подписывает все входы одним ключом (кошелёк minicoin — один ключ).
// spent — выходы, которые тратят входы, по порядку (см. Sighash).
func (tx *Transaction) Sign(seed Seed, spent []TxOut) {
	signature := Sign(seed, tx.Sighash(spent))
	for i := range tx.Inputs {
		tx.Inputs[i].Signature = signature
	}
}

// IsCoinbase: coinbase — транзакция без входов, монеты, созданные наградой за блок.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 0
}

func (tx *Transaction) Size() int {
	return 2 + len(tx.Inputs)*InputSize + 2 + len(tx.Outputs)*OutputSize + 4
}

// OutputSum — сумма выходов; ok = false при переполнении uint64.
func (tx *Transaction) OutputSum() (sum uint64, ok bool) {
	for _, output := range tx.Outputs {
		var carry uint64
		sum, carry = bits.Add64(sum, output.Amount, 0)
		if carry != 0 {
			return 0, false
		}
	}
	return sum, true
}
