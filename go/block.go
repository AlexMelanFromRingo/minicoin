// Блок, дерево Меркла и доказательство работы.
//
// Блок — это заголовок и список транзакций. Заголовок короткий (88 байт)
// и через корень Меркла фиксирует все транзакции. Поэтому для
// доказательства работы (PoW) достаточно хешировать только заголовок.
package minicoin

import (
	"bytes"
	"math/bits"
)

const HeaderSize = 32 + 32 + 8 + 8 + 8

type BlockHeader struct {
	// Хеш предыдущего блока. Именно эта ссылка превращает блоки в цепочку:
	// изменение старого блока меняет его хеш и рвёт все ссылки после него.
	PrevHash Hash
	// Корень дерева Меркла по txid всех транзакций блока.
	MerkleRoot Hash
	// Время создания, секунды Unix.
	Time uint64
	// Сложность: сколько хешей в среднем нужно перебрать, чтобы найти
	// подходящий. Узел проверяет, что она равна ожидаемой (см. chain.go).
	Difficulty uint64
	// Число, которое перебирает майнер.
	Nonce uint64
}

func (h *BlockHeader) Encode(w *Writer) {
	w.Raw(h.PrevHash[:])
	w.Raw(h.MerkleRoot[:])
	w.U64(h.Time)
	w.U64(h.Difficulty)
	w.U64(h.Nonce)
}

func readBlockHeader(r *Reader) BlockHeader {
	var h BlockHeader
	r.Array(h.PrevHash[:])
	r.Array(h.MerkleRoot[:])
	h.Time = r.U64()
	h.Difficulty = r.U64()
	h.Nonce = r.U64()
	return h
}

func (h *BlockHeader) Hash() Hash {
	var w Writer
	h.Encode(&w)
	return HashOf(w.Bytes)
}

type Block struct {
	Header BlockHeader
	// Первая транзакция всегда coinbase (награда майнеру).
	Txs []Transaction
}

func (b *Block) Hash() Hash {
	return b.Header.Hash()
}

func (b *Block) Bytes() []byte {
	var w Writer
	b.Header.Encode(&w)
	w.U32(uint32(len(b.Txs)))
	for i := range b.Txs {
		b.Txs[i].Encode(&w)
	}
	return w.Bytes
}

func BlockFromBytes(data []byte) (Block, error) {
	r := NewReader(data)
	b := Block{Header: readBlockHeader(r)}
	count := r.U32()
	// Число транзакций прислал пир: память выделяем по мере чтения, а не заранее.
	for i := uint32(0); i < count && r.Err() == nil; i++ {
		b.Txs = append(b.Txs, ReadTransaction(r))
	}
	if err := r.Finish(); err != nil {
		return Block{}, err
	}
	return b, nil
}

func (b *Block) Size() int {
	size := HeaderSize + 4
	for i := range b.Txs {
		size += b.Txs[i].Size()
	}
	return size
}

// MerkleRoot — корень дерева Меркла: хешируем txid попарно, пока не останется один.
//
//	       root
//	     /      \
//	  h01        c        ← нечётный узел поднимается как есть
//	 /   \       |
//	a     b      c        ← txid
//
// Узел = BLAKE3(0x01 ‖ левый ‖ правый). Префикс 0x01 отличает узел от
// транзакции: 65 байт не могут быть транзакцией, у неё размер всегда чётный.
// Нечётный узел не дублируется, как в биткоине: дублирование позволяло
// построить два разных списка транзакций с одним корнем (CVE-2012-2459).
func MerkleRoot(txids []Hash) Hash {
	if len(txids) == 0 {
		return Hash{}
	}
	level := txids
	for len(level) > 1 {
		var next []Hash
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			data := make([]byte, 0, 65)
			data = append(data, 0x01)
			data = append(data, level[i][:]...)
			data = append(data, level[i+1][:]...)
			next = append(next, HashOf(data))
		}
		level = next
	}
	return level[0]
}

// Target — цель: хеш заголовка, прочитанный как 256-битное число
// (big-endian), должен быть ≤ ⌊(2²⁵⁶ − 1) / difficulty⌋. Хеш
// непредсказуем, поэтому вероятность попасть под цель равна 1/difficulty,
// и в среднем нужно difficulty попыток. Это и есть «работа».
//
// Деление 256-битного числа на uint64 — обычное деление столбиком по
// байтам. Остаток меньше делителя, но после сдвига на байт может не
// поместиться в 64 бита, поэтому делим 128-битное число (bits.Div64).
func Target(difficulty uint64) Hash {
	d := max(difficulty, 1)
	var out Hash
	var remainder uint64
	for i := range out {
		hi, lo := remainder>>56, remainder<<8|0xff
		quotient, rem := bits.Div64(hi, lo, d)
		out[i] = byte(quotient)
		remainder = rem
	}
	return out
}

// MeetsDifficulty: bytes.Compare сравнивает лексикографически, то есть
// так же, как big-endian числа.
func MeetsDifficulty(hash Hash, difficulty uint64) bool {
	target := Target(difficulty)
	return difficulty > 0 && bytes.Compare(hash[:], target[:]) <= 0
}
