// Сетевой протокол: сообщения поверх TCP.
//
// Кадр сообщения:
//
//	magic "mini" [4] | тип u8 | длина u32 | полезная нагрузка [длина]
//
// Магические байты отсекают случайные подключения к чужому порту.
// Ограничение длины не даёт пиру одним заголовком заставить нас выделить
// гигабайты памяти.
package minicoin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var Magic = [4]byte{'m', 'i', 'n', 'i'}

const (
	MaxMessage  = 2 * 1024 * 1024
	DefaultPort = 4242
)

// Message — одно из сообщений ниже. Метод kind возвращает его тип в кадре.
type Message interface {
	kind() byte
}

// Status — «вот моя высота и вершина». Шлётся при подключении и после пачки блоков.
type Status struct {
	Height uint32
	Tip    Hash
}

// GetBlocks — «пришли блоки после первого общего блока из этого локатора».
type GetBlocks struct {
	Locator []Hash
}

type BlockMsg struct {
	Block Block
}

type TxMsg struct {
	Tx Transaction
}

// GetUtxos — запрос кошелька: непотраченные выходы ключа. Выходы, уже
// потраченные транзакциями мемпула, узел показывает только с
// IncludeMempoolSpent: они нужны bump, чтобы узнать, что тратит застрявшая
// транзакция.
type GetUtxos struct {
	Owner               PublicKey
	IncludeMempoolSpent bool
}

type Utxos struct {
	Height uint32
	Utxos  []Utxo
}

// GetBlock — запрос блока основной цепи по высоте (для explain).
type GetBlock struct {
	Height uint32
}

type GetInfo struct{}

// Text — ответ для человека: результат отправки транзакции, сводка узла, ошибка.
type Text struct {
	Text string
}

// GetMempoolTx — запрос кошелька: транзакция из мемпула (чтобы заменить её, см. bump).
type GetMempoolTx struct {
	Txid Hash
}

// MempoolTx — транзакция из мемпула и её комиссия. Кошелёк этой комиссии не
// верит и считает её сам по входам, сверенным с подписями (см. BumpPayment).
type MempoolTx struct {
	Fee uint64
	Tx  Transaction
}

func (Status) kind() byte       { return 1 }
func (GetBlocks) kind() byte    { return 2 }
func (BlockMsg) kind() byte     { return 3 }
func (TxMsg) kind() byte        { return 4 }
func (GetUtxos) kind() byte     { return 5 }
func (Utxos) kind() byte        { return 6 }
func (GetBlock) kind() byte     { return 7 }
func (GetInfo) kind() byte      { return 8 }
func (Text) kind() byte         { return 9 }
func (GetMempoolTx) kind() byte { return 10 }
func (MempoolTx) kind() byte    { return 11 }

func payload(message Message) []byte {
	var w Writer
	switch m := message.(type) {
	case Status:
		w.U32(m.Height)
		w.Raw(m.Tip[:])
	case GetBlocks:
		w.U16(uint16(len(m.Locator)))
		for _, hash := range m.Locator {
			w.Raw(hash[:])
		}
	case BlockMsg:
		w.Raw(m.Block.Bytes())
	case TxMsg:
		m.Tx.Encode(&w)
	case GetUtxos:
		w.Raw(m.Owner[:])
		if m.IncludeMempoolSpent {
			w.U8(1)
		} else {
			w.U8(0)
		}
	case Utxos:
		w.U32(m.Height)
		w.U32(uint32(len(m.Utxos)))
		for _, u := range m.Utxos {
			w.Raw(u.OutPoint.Txid[:])
			w.U16(u.OutPoint.Index)
			w.U64(u.Entry.Output.Amount)
			w.Raw(u.Entry.Output.Owner[:])
			w.U32(u.Entry.Height)
			if u.Entry.Coinbase {
				w.U8(1)
			} else {
				w.U8(0)
			}
		}
	case GetBlock:
		w.U32(m.Height)
	case GetInfo:
	case Text:
		w.Raw([]byte(m.Text))
	case GetMempoolTx:
		w.Raw(m.Txid[:])
	case MempoolTx:
		w.U64(m.Fee)
		m.Tx.Encode(&w)
	}
	return w.Bytes
}

func parse(kind byte, data []byte) (Message, error) {
	switch kind {
	case 3:
		block, err := BlockFromBytes(data)
		if err != nil {
			return nil, err
		}
		return BlockMsg{block}, nil
	case 4:
		tx, err := TransactionFromBytes(data)
		if err != nil {
			return nil, err
		}
		return TxMsg{tx}, nil
	case 9:
		if !utf8.Valid(data) {
			return nil, errors.New("не UTF-8")
		}
		return Text{string(data)}, nil
	}
	r := NewReader(data)
	var message Message
	switch kind {
	case 1:
		m := Status{Height: r.U32()}
		r.Array(m.Tip[:])
		message = m
	case 2:
		var m GetBlocks
		count := r.U16()
		for i := uint16(0); i < count && r.Err() == nil; i++ {
			var hash Hash
			r.Array(hash[:])
			m.Locator = append(m.Locator, hash)
		}
		message = m
	case 5:
		var m GetUtxos
		r.Array(m.Owner[:])
		m.IncludeMempoolSpent = r.U8() != 0
		message = m
	case 6:
		m := Utxos{Height: r.U32()}
		count := r.U32()
		for i := uint32(0); i < count && r.Err() == nil; i++ {
			var u Utxo
			r.Array(u.OutPoint.Txid[:])
			u.OutPoint.Index = r.U16()
			u.Entry.Output.Amount = r.U64()
			r.Array(u.Entry.Output.Owner[:])
			u.Entry.Height = r.U32()
			u.Entry.Coinbase = r.U8() != 0
			m.Utxos = append(m.Utxos, u)
		}
		message = m
	case 7:
		message = GetBlock{Height: r.U32()}
	case 8:
		message = GetInfo{}
	case 10:
		var m GetMempoolTx
		r.Array(m.Txid[:])
		message = m
	case 11:
		message = MempoolTx{Fee: r.U64(), Tx: ReadTransaction(r)}
	default:
		return nil, fmt.Errorf("неизвестный тип сообщения %d", kind)
	}
	if err := r.Finish(); err != nil {
		return nil, err
	}
	return message, nil
}

func Send(w io.Writer, message Message) error {
	body := payload(message)
	frame := make([]byte, 0, 9+len(body))
	frame = append(frame, Magic[:]...)
	frame = append(frame, message.kind())
	frame = binary.LittleEndian.AppendUint32(frame, uint32(len(body)))
	frame = append(frame, body...)
	_, err := w.Write(frame)
	return err
}

func Recv(r io.Reader) (Message, error) {
	var head [9]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if [4]byte(head[:4]) != Magic {
		return nil, errors.New("чужие магические байты")
	}
	length := binary.LittleEndian.Uint32(head[5:9])
	if length > MaxMessage {
		return nil, fmt.Errorf("сообщение слишком большое: %d байт", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return parse(head[4], body)
}
