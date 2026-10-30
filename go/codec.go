// Сериализация: как структуры превращаются в байты.
//
// Правило одно: числа пишутся в little-endian фиксированной ширины,
// массивы байтов как есть, перед списком стоит его длина. Библиотек
// здесь нет намеренно: формат байтов — часть протокола. Хеш блока и
// транзакции считается от этих байтов, поэтому все узлы обязаны
// получать их одинаково. Описание формата — в PROTOCOL.md.
package minicoin

import (
	"encoding/binary"
	"errors"
)

type Writer struct {
	Bytes []byte
}

func (w *Writer) U8(value uint8) {
	w.Bytes = append(w.Bytes, value)
}

func (w *Writer) U16(value uint16) {
	w.Bytes = binary.LittleEndian.AppendUint16(w.Bytes, value)
}

func (w *Writer) U32(value uint32) {
	w.Bytes = binary.LittleEndian.AppendUint32(w.Bytes, value)
}

func (w *Writer) U64(value uint64) {
	w.Bytes = binary.LittleEndian.AppendUint64(w.Bytes, value)
}

func (w *Writer) Raw(value []byte) {
	w.Bytes = append(w.Bytes, value...)
}

// Reader читает байты по порядку. Любая нехватка данных — ошибка, а не
// паника: байты приходят из сети, и доверять им нельзя.
//
// Ошибка запоминается: после первой все чтения возвращают нули, а
// вызывающий проверяет Err() один раз в конце. Так код разбора не тонет
// в `if err != nil` после каждого поля.
type Reader struct {
	data []byte
	pos  int
	err  error
}

func NewReader(data []byte) *Reader {
	return &Reader{data: data}
}

func (r *Reader) Err() error {
	return r.err
}

func (r *Reader) Raw(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.data)-r.pos < n {
		r.err = errors.New("неожиданный конец данных")
		return nil
	}
	slice := r.data[r.pos : r.pos+n]
	r.pos += n
	return slice
}

// Array заполняет dst целиком: `r.Array(hash[:])`.
func (r *Reader) Array(dst []byte) {
	copy(dst, r.Raw(len(dst)))
}

func (r *Reader) U8() uint8 {
	if b := r.Raw(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *Reader) U16() uint16 {
	if b := r.Raw(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}

func (r *Reader) U32() uint32 {
	if b := r.Raw(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (r *Reader) U64() uint64 {
	if b := r.Raw(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

// Finish: лишние байты в конце — тоже ошибка: у одного объекта должно
// быть ровно одно байтовое представление.
func (r *Reader) Finish() error {
	if r.err != nil {
		return r.err
	}
	if r.pos != len(r.data) {
		return errors.New("лишние байты в конце")
	}
	return nil
}
