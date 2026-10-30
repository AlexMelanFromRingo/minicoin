package minicoin

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestExplainCoversEveryByte(t *testing.T) {
	block := GenesisBlock()
	var sig Sig
	for i := range sig {
		sig[i] = 3
	}
	block.Txs = append(block.Txs, Transaction{
		Inputs:       []TxIn{{Prev: OutPoint{Txid: filled[Hash](1), Index: 2}, Signature: sig}},
		Outputs:      []TxOut{{Amount: 5, Owner: filled[PublicKey](4)}},
		ExpiryHeight: 9,
	})
	e := explainBlock(&block, 1)
	if !bytes.Equal(e.bytes, block.Bytes()) {
		t.Fatal("разобранные байты не совпадают с Bytes()")
	}
	if HashOf(e.bytes[:HeaderSize]) != block.Hash() {
		t.Fatal("первые 88 байт — заголовок")
	}
	if !strings.Contains(e.out.String(), "in[0].sig") {
		t.Fatal("нет подписи в разборе")
	}
}

// Совместимость с Rust и Python: ../vectors.txt сгенерирован `minicoin vectors`
// на Rust, и Go обязан выдать его байт в байт.
func TestVectorsMatchSharedFile(t *testing.T) {
	want, err := os.ReadFile("../vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := Vectors(); got != string(want) {
		t.Fatalf("векторы расходятся с ../vectors.txt:\n%s", got)
	}
}
