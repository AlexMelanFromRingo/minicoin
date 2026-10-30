package minicoin

import (
	"bytes"
	"testing"
)

func TestNumbersAreLittleEndian(t *testing.T) {
	var w Writer
	w.U16(0x0102)
	w.U32(0x03040506)
	if !bytes.Equal(w.Bytes, []byte{0x02, 0x01, 0x06, 0x05, 0x04, 0x03}) {
		t.Fatalf("байты %x", w.Bytes)
	}

	r := NewReader(w.Bytes)
	if r.U16() != 0x0102 || r.U32() != 0x03040506 {
		t.Fatal("числа прочитаны неверно")
	}
	if r.Finish() != nil {
		t.Fatal("всё прочитано, а Finish недоволен")
	}
	r.U8()
	if r.Err() == nil {
		t.Fatal("чтение за концом данных не дало ошибку")
	}
}
