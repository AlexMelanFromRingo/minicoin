// Побайтовый разбор блока: каждое поле — его байты и смысл.
//
// Это та же сериализация, что в block.go и tx.go, только с подписями к
// каждому полю. Если сложить все hex-строки по порядку, получится
// ровно block.Bytes() (это проверяет тест).
package minicoin

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

type explainer struct {
	out    strings.Builder
	offset int
	bytes  []byte
}

func (e *explainer) section(title string) {
	fmt.Fprintf(&e.out, "\n── %s ──\n", title)
}

func (e *explainer) field(data []byte, name, meaning string) {
	fmt.Fprintf(&e.out, "%7d  %-14s %s\n", e.offset, name, ToHex(data))
	if meaning != "" {
		fmt.Fprintf(&e.out, "%7s  %-14s ↳ %s\n", "", "", meaning)
	}
	e.offset += len(data)
	e.bytes = append(e.bytes, data...)
}

func (e *explainer) note(text string) {
	fmt.Fprintf(&e.out, "         %s\n", text)
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func ExplainBlock(block *Block, height uint32) string {
	return explainBlock(block, height).out.String()
}

func explainBlock(block *Block, height uint32) *explainer {
	e := &explainer{}
	h := &block.Header
	hash := block.Hash()
	fmt.Fprintf(&e.out, "Блок #%d  (%d байт)\nхеш %s\n", height, block.Size(), ToHex(hash[:]))

	e.section("Заголовок, 88 байт: только он хешируется для PoW")
	e.field(h.PrevHash[:], "prev_hash", "хеш предыдущего блока — звено цепи")
	e.field(h.MerkleRoot[:], "merkle_root", "корень дерева Меркла по txid всех транзакций")
	e.field(le64(h.Time), "time", fmt.Sprintf("%d (секунды Unix, little-endian)", h.Time))
	e.field(le64(h.Difficulty), "difficulty", fmt.Sprintf("%d — столько хешей в среднем нужно перебрать", h.Difficulty))
	e.field(le64(h.Nonce), "nonce", fmt.Sprintf("%d — найдено перебором", h.Nonce))
	e.note("BLAKE3(заголовок) = " + ToHex(hash[:]))
	target := Target(h.Difficulty)
	e.note("цель = (2²⁵⁶−1)/difficulty = " + ToHex(target[:]))
	if MeetsDifficulty(hash, h.Difficulty) {
		e.note("хеш ≤ цели ✓ работа доказана")
	} else {
		e.note("хеш > цели ✗ (генезис не майнится)")
	}

	e.section("Транзакции")
	e.field(le32(uint32(len(block.Txs))), "tx_count", fmt.Sprintf("%d транзакций", len(block.Txs)))

	for n := range block.Txs {
		tx := &block.Txs[n]
		kind := "обычная"
		if tx.IsCoinbase() {
			kind = "coinbase: новые монеты, входов нет"
		}
		e.section(fmt.Sprintf("Транзакция %d (%s)", n, kind))
		e.field(le16(uint16(len(tx.Inputs))), "input_count", "")
		for i, input := range tx.Inputs {
			e.field(input.Prev.Txid[:], fmt.Sprintf("in[%d].txid", i), "какую транзакцию тратим…")
			e.field(le16(input.Prev.Index), fmt.Sprintf("in[%d].index", i), fmt.Sprintf("…и её выход №%d", input.Prev.Index))
			e.field(input.Signature[:], fmt.Sprintf("in[%d].sig", i), "Ed25519-подпись владельца выхода под sighash")
		}
		e.field(le16(uint16(len(tx.Outputs))), "output_count", "")
		for i, output := range tx.Outputs {
			e.field(le64(output.Amount), fmt.Sprintf("out[%d].amount", i), FormatAmount(output.Amount)+" монет")
			e.field(output.Owner[:], fmt.Sprintf("out[%d].owner", i), "открытый ключ получателя = "+EncodeAddress(output.Owner))
		}
		expiry := fmt.Sprintf("%d — после этой высоты транзакция недействительна", tx.ExpiryHeight)
		if tx.IsCoinbase() {
			expiry = fmt.Sprintf("%d — высота блока (делает txid уникальным)", tx.ExpiryHeight)
		}
		e.field(le32(tx.ExpiryHeight), "expiry_height", expiry)
		txid := tx.Txid()
		e.note("txid = BLAKE3(байты транзакции) = " + ToHex(txid[:]))
		if !tx.IsCoinbase() {
			sighash := tx.Sighash()
			e.note("sighash = BLAKE3(те же байты, подписи заменены нулями) = " + ToHex(sighash[:]))
		}
	}

	if height > 0 {
		fmt.Fprintf(&e.out, "\nНаграда за блок на этой высоте: %s монет (+ комиссии)\n", FormatAmount(BlockReward(height)))
	}
	return e
}

// Vectors — тестовые векторы для других реализаций (`minicoin vectors`).
// Строки вида `имя = значение`; байты в hex. Ed25519 детерминирована,
// поэтому подписи тоже воспроизводимы.
func Vectors() string {
	var out strings.Builder
	put := func(name, value string) { fmt.Fprintf(&out, "%s = %s\n", name, value) }

	genesis := GenesisBlock()
	genesisHash := genesis.Hash()
	put("genesis_block", ToHex(genesis.Bytes()))
	put("genesis_hash", ToHex(genesisHash[:]))

	var seed Seed
	for i := range seed {
		seed[i] = 1
	}
	key := PublicKeyOf(seed)
	put("seed", ToHex(seed[:]))
	put("public_key", ToHex(key[:]))
	put("address", EncodeAddress(key))
	put("address_of_zero_key", EncodeAddress(PublicKey{}))

	var seed2 Seed
	for i := range seed2 {
		seed2[i] = 2
	}
	tx := Transaction{
		Inputs: []TxIn{{Prev: OutPoint{Txid: genesis.Txs[0].Txid(), Index: 0}}},
		Outputs: []TxOut{
			{Amount: 1_250_000_000, Owner: PublicKeyOf(seed2)},
			{Amount: 3_749_990_000, Owner: key},
		},
		ExpiryHeight: 100,
	}
	tx.Sign(seed)
	sighash, txid := tx.Sighash(), tx.Txid()
	put("tx", ToHex(tx.Bytes()))
	put("tx_sighash", ToHex(sighash[:]))
	put("tx_txid", ToHex(txid[:]))

	var leaves []Hash
	for _, x := range []string{"a", "b", "c", "d", "e"} {
		leaves = append(leaves, HashOf([]byte(x)))
	}
	for n := 1; n <= 5; n++ {
		root := MerkleRoot(leaves[:n])
		put(fmt.Sprintf("merkle_%d", n), ToHex(root[:]))
	}
	for _, d := range []uint64{1, 3, 1 << 20, math.MaxUint64} {
		target := Target(d)
		put(fmt.Sprintf("target_%d", d), ToHex(target[:]))
	}
	for _, c := range [][2]uint64{{1 << 20, 200}, {1 << 20, 0}, {1 << 20, 100}, {1 << 20, 10_000}, {1000, 333}} {
		put(fmt.Sprintf("retarget_%d_%d", c[0], c[1]), fmt.Sprint(Retarget(c[0], c[1])))
	}
	for _, h := range []uint32{0, 1, 99_999, 100_000, 6_399_999, 6_400_000} {
		put(fmt.Sprintf("reward_%d", h), fmt.Sprint(BlockReward(h)))
	}

	// Блок 1: coinbase на key, время генезис + 10 с, nonce найден перебором.
	coinbase := Transaction{Outputs: []TxOut{{Amount: BlockReward(1), Owner: key}}, ExpiryHeight: 1}
	header := BlockHeader{
		PrevHash:   genesisHash,
		MerkleRoot: MerkleRoot([]Hash{coinbase.Txid()}),
		Time:       GenesisTime + BlockTime,
		Difficulty: InitialDifficulty,
	}
	for !MeetsDifficulty(header.Hash(), header.Difficulty) {
		header.Nonce++
	}
	block1 := Block{Header: header, Txs: []Transaction{coinbase}}
	block1Hash := block1.Hash()
	put("block1", ToHex(block1.Bytes()))
	put("block1_hash", ToHex(block1Hash[:]))
	return out.String()
}
