package minicoin

import (
	"reflect"
	"testing"
)

func filled[T ~[32]byte](b byte) T {
	var out T
	for i := range out {
		out[i] = b
	}
	return out
}

func sampleTx() Transaction {
	return Transaction{
		Inputs:       []TxIn{{Prev: OutPoint{Txid: filled[Hash](1), Index: 3}}},
		Outputs:      []TxOut{{Amount: 5, Owner: filled[PublicKey](2)}},
		ExpiryHeight: 100,
	}
}

func TestTxRoundtripAndSize(t *testing.T) {
	tx := sampleTx()
	data := tx.Bytes()
	if len(data) != tx.Size() {
		t.Fatalf("длина %d, Size %d", len(data), tx.Size())
	}
	parsed, err := TransactionFromBytes(data)
	if err != nil || !reflect.DeepEqual(parsed, tx) {
		t.Fatalf("разбор: %+v, %v", parsed, err)
	}
}

func TestTxRejectsTrailingBytes(t *testing.T) {
	tx := sampleTx()
	if _, err := TransactionFromBytes(append(tx.Bytes(), 0)); err == nil {
		t.Fatal("лишний байт принят")
	}
}

func TestSignatureChangesTxidButNotSighash(t *testing.T) {
	seed := NewSeed()
	tx := sampleTx()
	txid, sighash := tx.Txid(), tx.Sighash()
	tx.Sign(seed)
	if tx.Txid() == txid {
		t.Fatal("подпись не изменила txid")
	}
	if tx.Sighash() != sighash {
		t.Fatal("подпись изменила sighash")
	}
	if !Verify(PublicKeyOf(seed), sighash, tx.Inputs[0].Signature) {
		t.Fatal("подпись не проверяется")
	}
}
