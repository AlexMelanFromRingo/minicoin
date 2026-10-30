// Криптографические примитивы.
//
// Это единственная часть, взятая из библиотек: хеш BLAKE3 и подписи
// Ed25519. Обе — общие стандарты, не привязанные к какой-либо монете.
// Писать свою криптографию нельзя: ошибку в ней не видно, пока ею не
// воспользуется злоумышленник.
package minicoin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"

	"lukechampine.com/blake3"
)

// Hash — 32-байтный хеш BLAKE3. Им идентифицируются блоки и транзакции.
type Hash [32]byte

// PublicKey — открытый ключ Ed25519. Выход транзакции «запирается» именно им.
type PublicKey [32]byte

// Seed — секретное зерно Ed25519: из него однозначно получаются оба ключа.
type Seed [32]byte

// Sig — подпись Ed25519.
type Sig [64]byte

func HashOf(data []byte) Hash {
	return blake3.Sum256(data)
}

// NewSeed — новое случайное зерно из генератора случайных чисел ОС.
func NewSeed() Seed {
	var seed Seed
	if _, err := rand.Read(seed[:]); err != nil {
		panic("ОС не выдала случайные байты")
	}
	return seed
}

func PublicKeyOf(seed Seed) PublicKey {
	private := ed25519.NewKeyFromSeed(seed[:])
	return PublicKey(private[32:])
}

func Sign(seed Seed, message Hash) Sig {
	private := ed25519.NewKeyFromSeed(seed[:])
	return Sig(ed25519.Sign(private, message[:]))
}

// smallOrderY — координаты y восьми точек малого порядка (порядок 1, 2, 4
// и 8), включая неканонические записи p и p+1. Бит знака x не важен,
// поэтому в списке его нет. Тот же список использует libsodium.
var smallOrderY = [7]string{
	"0000000000000000000000000000000000000000000000000000000000000000", // y = 0, порядок 4
	"0100000000000000000000000000000000000000000000000000000000000000", // y = 1, нейтральный элемент
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // порядок 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // порядок 8
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p − 1, порядок 2
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p (то же, что 0)
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1 (то же, что 1)
}

func hasSmallOrder(point []byte) bool {
	y := make([]byte, 32)
	copy(y, point)
	y[31] &= 0x7f
	encoded := hex.EncodeToString(y)
	for _, bad := range smallOrderY {
		if encoded == bad {
			return true
		}
	}
	return false
}

// Verify — строгая проверка, как verify_strict в Rust: неканонические
// подписи и «слабые» ключи отвергаются. Без неё посторонний мог бы чуть
// изменить чужую подпись так, что она осталась бы верной, а хеш транзакции
// (txid) поменялся бы.
//
// ed25519.Verify из стандартной библиотеки сама отвергает S ≥ L, но
// принимает ключ и R малого порядка. С ключом малого порядка подпись
// подходит к любому сообщению, а Rust и Python такие подписи отвергают:
// без этой проверки узлы на Go откололись бы от сети (см. PROTOCOL.md).
func Verify(publicKey PublicKey, message Hash, signature Sig) bool {
	if hasSmallOrder(publicKey[:]) || hasSmallOrder(signature[:32]) {
		return false
	}
	return ed25519.Verify(publicKey[:], message[:], signature[:])
}

func ToHex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func FromHex(text string) ([]byte, bool) {
	bytes, err := hex.DecodeString(text)
	return bytes, err == nil
}
