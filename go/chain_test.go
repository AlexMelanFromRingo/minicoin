package minicoin

import (
	"errors"
	"math"
	"strings"
	"testing"
)

const testNow = math.MaxUint64 / 2

// easyMining: сложность 1 — любой хеш подходит, «майнинг» мгновенный.
// В Rust то же делает cfg!(test) в consensus.rs.
func easyMining(t *testing.T) {
	saved := InitialDifficulty
	InitialDifficulty = 1
	t.Cleanup(func() { InitialDifficulty = saved })
}

type miner struct {
	seed Seed
	key  PublicKey
}

func newMiner() miner {
	seed := NewSeed()
	return miner{seed, PublicKeyOf(seed)}
}

// makeBlock собирает и «добывает» блок поверх parent. Награда — без комиссий.
func makeBlock(chain *Chain, parent Hash, txs []Transaction, to PublicKey) Block {
	p := chain.Get(parent)
	height := p.Height + 1
	coinbase := Transaction{Outputs: []TxOut{{Amount: BlockReward(height), Owner: to}}, ExpiryHeight: height}
	all := append([]Transaction{coinbase}, txs...)
	var txids []Hash
	for i := range all {
		txids = append(txids, all[i].Txid())
	}
	header := BlockHeader{
		PrevHash:   parent,
		MerkleRoot: MerkleRoot(txids),
		Time:       p.Block.Header.Time + BlockTime,
		Difficulty: chain.NextDifficulty(parent),
	}
	for !MeetsDifficulty(header.Hash(), header.Difficulty) {
		header.Nonce++
	}
	return Block{Header: header, Txs: all}
}

func mine(chain *Chain, txs []Transaction, to PublicKey) (ChainUpdate, error) {
	return chain.AddBlock(makeBlock(chain, chain.Tip(), txs, to), testNow)
}

func mustMine(t *testing.T, chain *Chain, txs []Transaction, to PublicKey) ChainUpdate {
	t.Helper()
	update, err := mine(chain, txs, to)
	if err != nil {
		t.Fatalf("блок не принят: %v", err)
	}
	return update
}

func pay(from miner, prev OutPoint, amount uint64, to PublicKey) Transaction {
	tx := Transaction{
		Inputs:       []TxIn{{Prev: prev}},
		Outputs:      []TxOut{{Amount: amount, Owner: to}},
		ExpiryHeight: 1000,
	}
	tx.Sign(from.seed)
	return tx
}

// chainWithCoins — цепь, где у alice есть одна созревшая награда за блок 1.
func chainWithCoins(t *testing.T, alice miner) (*Chain, OutPoint) {
	chain := NewChain()
	mustMine(t, chain, nil, alice.key)
	coinbase := OutPoint{Txid: chain.BlockAt(1).Txs[0].Txid(), Index: 0}
	for i := uint32(0); i < CoinbaseMaturity; i++ {
		mustMine(t, chain, nil, PublicKey{})
	}
	return chain, coinbase
}

// expectInvalid: блок отвергнут как нарушающий правила, и причина содержит want.
func expectInvalid(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || errors.Is(err, ErrDuplicate) || errors.Is(err, ErrOrphan) || !strings.Contains(err.Error(), want) {
		t.Fatalf("ожидалась ошибка правил с %q, получено %v", want, err)
	}
}

func TestPaymentMovesCoins(t *testing.T) {
	easyMining(t)
	alice, bob := newMiner(), newMiner()
	chain, coin := chainWithCoins(t, alice)
	mustMine(t, chain, []Transaction{pay(alice, coin, 30*Coin, bob.key)}, alice.key)

	utxos := chain.UtxosOf(bob.key)
	if len(utxos) != 1 || utxos[0].Entry.Output.Amount != 30*Coin {
		t.Fatalf("у bob %+v", utxos)
	}
	// Выход потрачен; у alice осталась только новая награда.
	if _, ok := chain.utxo[coin]; ok {
		t.Fatal("потраченный выход остался в UTXO")
	}
}

func TestCoinbaseMustMature(t *testing.T) {
	easyMining(t)
	alice, bob := newMiner(), newMiner()
	chain := NewChain()
	mustMine(t, chain, nil, alice.key)
	coin := OutPoint{Txid: chain.BlockAt(1).Txs[0].Txid(), Index: 0}
	tx := pay(alice, coin, 1, bob.key)
	_, err := chain.CheckTx(&tx, 2)
	expectInvalid(t, err, "не созрела")
}

func TestRejectsInvalidSpends(t *testing.T) {
	easyMining(t)
	alice, bob := newMiner(), newMiner()
	chain, coin := chainWithCoins(t, alice)
	h := chain.Height() + 1
	check := func(tx Transaction, want string) {
		t.Helper()
		_, err := chain.CheckTx(&tx, h)
		expectInvalid(t, err, want)
	}

	// Чужой ключ.
	check(pay(bob, coin, 1, bob.key), "подпись")
	// Больше, чем есть.
	check(pay(alice, coin, 51*Coin, bob.key), "выходов больше")
	// Подпись верная, но транзакцию изменили после подписи.
	tampered := pay(alice, coin, 1, bob.key)
	tampered.Outputs[0].Owner = alice.key
	check(tampered, "подпись")
	// Истёкшая.
	expired := pay(alice, coin, 1, bob.key)
	expired.ExpiryHeight = h - 1
	expired.Sign(alice.seed)
	check(expired, "срок")
}

func TestDoubleSpendInOneBlockIsRejected(t *testing.T) {
	easyMining(t)
	alice, bob := newMiner(), newMiner()
	chain, coin := chainWithCoins(t, alice)
	height := chain.Height()
	tx1 := pay(alice, coin, 10*Coin, bob.key)
	tx2 := pay(alice, coin, 20*Coin, bob.key)
	_, err := mine(chain, []Transaction{tx1, tx2}, alice.key)
	expectInvalid(t, err, "несуществующий")
	// Состояние не изменилось: частично применённый блок откатился.
	if chain.Height() != height {
		t.Fatal("высота изменилась")
	}
	if _, ok := chain.utxo[coin]; !ok {
		t.Fatal("выход alice пропал")
	}
	if len(chain.UtxosOf(bob.key)) != 0 {
		t.Fatal("bob получил монеты из отвергнутого блока")
	}
}

func TestCoinbaseCannotOverpay(t *testing.T) {
	easyMining(t)
	alice := newMiner()
	chain := NewChain()
	block := makeBlock(chain, chain.Tip(), nil, alice.key)
	block.Txs[0].Outputs[0].Amount++
	block.Header.MerkleRoot = MerkleRoot([]Hash{block.Txs[0].Txid()})
	for !MeetsDifficulty(block.Hash(), block.Header.Difficulty) {
		block.Header.Nonce++
	}
	_, err := chain.AddBlock(block, testNow)
	expectInvalid(t, err, "coinbase платит")
}

func TestHeavierBranchWinsAndUtxoFollows(t *testing.T) {
	easyMining(t)
	alice, bob := newMiner(), newMiner()
	chain, coin := chainWithCoins(t, alice)
	fork := chain.Tip()

	// Основная цепь: alice платит bob.
	mustMine(t, chain, []Transaction{pay(alice, coin, 5*Coin, bob.key)}, alice.key)
	if len(chain.UtxosOf(bob.key)) != 1 {
		t.Fatal("платёж не дошёл")
	}

	// Соперник строит от fork ветку из двух пустых блоков.
	b1 := makeBlock(chain, fork, nil, bob.key)
	update, err := chain.AddBlock(b1, testNow)
	if err != nil || len(update.Connected) != 0 {
		t.Fatalf("равная работа — остаёмся на своей ветке: %+v, %v", update, err)
	}

	b2 := makeBlock(chain, b1.Hash(), nil, bob.key)
	update, err = chain.AddBlock(b2, testNow)
	if err != nil || len(update.Connected) != 2 || len(update.Disconnected) != 1 {
		t.Fatalf("реорганизация: %d подключено, %d отключено, %v", len(update.Connected), len(update.Disconnected), err)
	}

	// Платёж откатился, монета alice снова не потрачена,
	// у bob — только две награды из новой ветки.
	if _, ok := chain.utxo[coin]; !ok {
		t.Fatal("монета alice не вернулась")
	}
	for _, u := range chain.UtxosOf(bob.key) {
		if !u.Entry.Coinbase {
			t.Fatal("у bob остался выход откаченного платежа")
		}
	}
	// Транзакция из отключённого блока вернётся в мемпул.
	if len(update.Disconnected[0].Txs) != 2 {
		t.Fatal("в отключённом блоке должна быть транзакция платежа")
	}
}

func TestInvalidHeavierBranchIsRolledBack(t *testing.T) {
	easyMining(t)
	alice, bob := newMiner(), newMiner()
	chain, coin := chainWithCoins(t, alice)
	fork := chain.Tip()
	mustMine(t, chain, nil, alice.key)
	tip := chain.Tip()

	// Ветка: блок с поддельной подписью, затем ещё один поверх.
	badTx := pay(bob, coin, 1, bob.key)
	b1 := makeBlock(chain, fork, []Transaction{badTx}, bob.key)
	if _, err := chain.AddBlock(b1, testNow); err != nil {
		t.Fatalf("заголовок b1 в порядке, а блок отвергнут: %v", err)
	}
	b2 := makeBlock(chain, b1.Hash(), nil, bob.key)
	_, err := chain.AddBlock(b2, testNow)
	expectInvalid(t, err, "")

	if chain.Tip() != tip {
		t.Fatal("вершина сменилась на плохую ветку")
	}
	if _, ok := chain.utxo[coin]; !ok {
		t.Fatal("UTXO не вернулись")
	}
}

func TestOrphanAndTimeRules(t *testing.T) {
	easyMining(t)
	alice := newMiner()
	chain := NewChain()
	orphan := makeBlock(chain, chain.Tip(), nil, alice.key)
	orphan.Header.PrevHash = filled[Hash](42)
	for !MeetsDifficulty(orphan.Hash(), orphan.Header.Difficulty) {
		orphan.Header.Nonce++
	}
	if _, err := chain.AddBlock(orphan, testNow); !errors.Is(err, ErrOrphan) {
		t.Fatalf("ожидался сирота, получено %v", err)
	}

	old := makeBlock(chain, chain.Tip(), nil, alice.key)
	old.Header.Time = GenesisTime
	_, err := chain.AddBlock(old, testNow)
	expectInvalid(t, err, "медианы")
}

func TestLocatorFindsFork(t *testing.T) {
	easyMining(t)
	alice := newMiner()
	a := NewChain()
	for i := 0; i < 50; i++ {
		mustMine(t, a, nil, alice.key)
	}
	locator := a.Locator()
	if locator[0] != a.Tip() || locator[len(locator)-1] != a.main[0] {
		t.Fatal("локатор: от вершины до генезиса")
	}
	if len(locator) >= 20 {
		t.Fatalf("локатор слишком длинный: %d", len(locator))
	}
	if a.FindFork(locator) != 50 {
		t.Fatal("своя цепь: общий блок — вершина")
	}
	if NewChain().FindFork(locator) != 0 {
		t.Fatal("пустая цепь: общий блок — генезис")
	}
}
