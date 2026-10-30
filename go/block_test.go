package minicoin

import (
	"reflect"
	"testing"
)

func TestTargetMath(t *testing.T) {
	if Target(1) != filled[Hash](0xff) {
		t.Fatal("цель при сложности 1 — все единицы")
	}
	want := filled[Hash](0xff)
	want[0] = 0x7f
	if Target(2) != want {
		t.Fatalf("Target(2) = %x", Target(2))
	}
	want[0] = 0
	if Target(256) != want {
		t.Fatalf("Target(256) = %x", Target(256))
	}
	if MeetsDifficulty(Hash{}, 0) {
		t.Fatal("нулевая сложность не бывает выполнена")
	}
}

func TestMerkleShapes(t *testing.T) {
	a, b, c := filled[Hash](1), filled[Hash](2), filled[Hash](3)
	if MerkleRoot([]Hash{a}) != a {
		t.Fatal("корень одного txid — сам txid")
	}
	ab := MerkleRoot([]Hash{a, b})
	if ab == MerkleRoot([]Hash{b, a}) {
		t.Fatal("порядок листьев не важен?")
	}
	// Структура дерева: нечётный c поднялся на уровень выше. Подменить
	// пару (a, b) «транзакцией» с txid = ab нельзя: её байты были бы
	// 0x01 ‖ a ‖ b, а это 65 байт, не транзакция.
	if MerkleRoot([]Hash{a, b, c}) != MerkleRoot([]Hash{ab, c}) {
		t.Fatal("нечётный узел должен подниматься как есть")
	}
	// Дублирования нет: [a, b, c] и [a, b, c, c] дают разные корни.
	if MerkleRoot([]Hash{a, b, c}) == MerkleRoot([]Hash{a, b, c, c}) {
		t.Fatal("нечётный узел продублирован (CVE-2012-2459)")
	}
}

func TestBlockRoundtrip(t *testing.T) {
	block := Block{
		Header: BlockHeader{PrevHash: filled[Hash](9), MerkleRoot: filled[Hash](8), Time: 1, Difficulty: 2, Nonce: 3},
		Txs:    []Transaction{{ExpiryHeight: 0}},
	}
	data := block.Bytes()
	if len(data) != block.Size() {
		t.Fatalf("длина %d, Size %d", len(data), block.Size())
	}
	parsed, err := BlockFromBytes(data)
	if err != nil || !reflect.DeepEqual(parsed, block) {
		t.Fatalf("разбор: %+v, %v", parsed, err)
	}
}
