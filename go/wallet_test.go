package minicoin

import (
	"os"
	"path/filepath"
	"testing"
)

func coin(amount uint64, height uint32, coinbase bool, n byte) Utxo {
	entry := UtxoEntry{Output: TxOut{Amount: amount}, Height: height, Coinbase: coinbase}
	return Utxo{OutPoint{Txid: filled[Hash](n), Index: 0}, entry}
}

func TestAmounts(t *testing.T) {
	good := map[string]uint64{"1.5": 150_000_000, "0.00000001": 1, ".5": 50_000_000, "7": 700_000_000}
	for text, want := range good {
		if got, err := ParseAmount(text); err != nil || got != want {
			t.Errorf("ParseAmount(%q) = %d, %v", text, got, err)
		}
	}
	for _, text := range []string{"1.000000001", "-1", ""} {
		if _, err := ParseAmount(text); err == nil {
			t.Errorf("ParseAmount(%q) принял мусор", text)
		}
	}
	if FormatAmount(150_000_001) != "1.50000001" {
		t.Fatal(FormatAmount(150_000_001))
	}
}

func TestPaymentWithChange(t *testing.T) {
	seed := NewSeed()
	utxos := []Utxo{coin(3*Coin, 1, false, 1), coin(10*Coin, 1, false, 2)}
	tx, err := BuildPayment(seed, utxos, 100, filled[PublicKey](9), 4*Coin, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Inputs) != 1 {
		t.Fatal("хватает одной крупной монеты")
	}
	if tx.Outputs[0].Amount != 4*Coin || tx.Outputs[1].Amount != 6*Coin-1000 || tx.Outputs[1].Owner != PublicKeyOf(seed) {
		t.Fatalf("выходы %+v", tx.Outputs)
	}
}

func TestBumpTakesExtraFeeFromChange(t *testing.T) {
	seed := NewSeed()
	utxos := []Utxo{coin(10*Coin, 1, false, 1)}
	stuck, err := BuildPayment(seed, utxos, 100, filled[PublicKey](9), 4*Coin, 200)
	if err != nil {
		t.Fatal(err)
	}
	fee := DefaultBumpFee(200, stuck.Size())
	if fee != 400 {
		t.Fatalf("удвоение больше минимума 200 + 186 по правилу замены: %d", fee)
	}
	if DefaultBumpFee(10, stuck.Size()) != 10+uint64(stuck.Size()) {
		t.Fatal("минимум по правилу замены")
	}

	bumped, err := BumpPayment(seed, stuck, 200, fee)
	if err != nil {
		t.Fatal(err)
	}
	if bumped.Inputs[0].Prev != stuck.Inputs[0].Prev {
		t.Fatal("те же входы — иначе это не замена")
	}
	if bumped.Outputs[0] != stuck.Outputs[0] {
		t.Fatal("получатель получает столько же")
	}
	if bumped.Outputs[1].Amount != stuck.Outputs[1].Amount-(fee-200) {
		t.Fatal("прибавка к комиссии — из сдачи")
	}
	if bumped.Inputs[0].Signature == stuck.Inputs[0].Signature {
		t.Fatal("подпись новая")
	}

	if _, err := BumpPayment(seed, stuck, 200, 100); err == nil {
		t.Fatal("комиссия меньше старой")
	}
	if _, err := BumpPayment(seed, stuck, 200, 7*Coin); err == nil {
		t.Fatal("сдачи не хватает")
	}
	// Вся сдача в комиссию: выход сдачи исчезает.
	allIn, err := BumpPayment(seed, stuck, 200, 6*Coin)
	if err != nil || len(allIn.Outputs) != 1 {
		t.Fatalf("вся сдача в комиссию: %+v, %v", allIn.Outputs, err)
	}
}

func TestBumpRefusesTransactionItDidNotSign(t *testing.T) {
	seed := NewSeed()
	utxos := []Utxo{coin(10*Coin, 1, false, 1)}
	stuck, _ := BuildPayment(seed, utxos, 100, filled[PublicKey](9), 4*Coin, 200)
	// Узел подменил получателя: наши входы, но деньги — ему.
	forged := stuck
	forged.Outputs = []TxOut{{Amount: stuck.Outputs[0].Amount, Owner: filled[PublicKey](66)}, stuck.Outputs[1]}
	if _, err := BumpPayment(seed, forged, 200, 400); err == nil {
		t.Fatal("переподписана подменённая транзакция")
	}
	// Чужая транзакция целиком: подписи не нашим ключом.
	stranger, _ := BuildPayment(NewSeed(), utxos, 100, filled[PublicKey](9), Coin, 200)
	if _, err := BumpPayment(seed, stranger, 200, 400); err == nil {
		t.Fatal("переподписана чужая транзакция")
	}
}

func TestWalletFileIsPrivateAndNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wallet.key")
	key, err := CreateWallet(path)
	if err != nil {
		t.Fatal(err)
	}
	if seed, err := LoadWallet(path); err != nil || PublicKeyOf(seed) != key {
		t.Fatalf("загружен не тот ключ: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права %o вместо 600", info.Mode().Perm())
	}
	if info.Size() != 65 {
		t.Fatalf("файл — 64 hex-символа и перевод строки, а не %d байт", info.Size())
	}
	if _, err := CreateWallet(path); err == nil {
		t.Fatal("второй CreateWallet не должен затереть ключ")
	}
}

func TestImmatureCoinbaseIsNotSpent(t *testing.T) {
	seed := NewSeed()
	utxos := []Utxo{coin(50*Coin, 95, true, 1)}
	if _, err := BuildPayment(seed, utxos, 100, filled[PublicKey](9), Coin, 0); err == nil {
		t.Fatal("потрачена несозревшая награда")
	}
	if _, err := BuildPayment(seed, utxos, 104, filled[PublicKey](9), Coin, 0); err != nil {
		t.Fatal(err)
	}
}
