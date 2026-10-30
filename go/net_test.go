package minicoin

import (
	"bytes"
	"reflect"
	"testing"
)

func TestMessagesRoundtrip(t *testing.T) {
	entry := UtxoEntry{Output: TxOut{Amount: 7, Owner: filled[PublicKey](3)}, Height: 9, Coinbase: true}
	genesis := GenesisBlock()
	messages := []Message{
		Status{Height: 5, Tip: filled[Hash](1)},
		GetBlocks{Locator: []Hash{filled[Hash](1), filled[Hash](2)}},
		BlockMsg{genesis},
		TxMsg{genesis.Txs[0]},
		GetUtxos{Owner: filled[PublicKey](4), IncludeMempoolSpent: true},
		Utxos{Height: 3, Utxos: []Utxo{{OutPoint{Txid: filled[Hash](5), Index: 1}, entry}}},
		GetBlock{Height: 2},
		GetInfo{},
		Text{"привет"},
		GetMempoolTx{Txid: filled[Hash](6)},
		MempoolTx{Fee: 186, Tx: genesis.Txs[0]},
	}
	for _, message := range messages {
		var buf bytes.Buffer
		if err := Send(&buf, message); err != nil {
			t.Fatal(err)
		}
		got, err := Recv(&buf)
		if err != nil || !reflect.DeepEqual(got, message) {
			t.Fatalf("%T: получено %+v, %v", message, got, err)
		}
	}
}

func TestRejectsForeignMagic(t *testing.T) {
	var buf bytes.Buffer
	_ = Send(&buf, GetInfo{})
	buf.Bytes()[0] = 'x'
	if _, err := Recv(&buf); err == nil {
		t.Fatal("чужие магические байты приняты")
	}
}
