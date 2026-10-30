package minicoin

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestSignatureRoundtrip(t *testing.T) {
	seed := NewSeed()
	message := HashOf([]byte("hello"))
	sig := Sign(seed, message)
	if !Verify(PublicKeyOf(seed), message, sig) {
		t.Fatal("верная подпись не прошла проверку")
	}
	if Verify(PublicKeyOf(seed), HashOf([]byte("other")), sig) {
		t.Fatal("подпись подошла к другому сообщению")
	}
	if Verify(PublicKeyOf(NewSeed()), message, sig) {
		t.Fatal("подпись подошла к другому ключу")
	}
}

func TestHexRoundtrip(t *testing.T) {
	data := []byte{0, 1, 254, 255}
	if got, ok := FromHex(ToHex(data)); !ok || !bytes.Equal(got, data) {
		t.Fatalf("FromHex(ToHex) = %v, %v", got, ok)
	}
	if _, ok := FromHex("abc"); ok {
		t.Fatal("нечётная длина принята")
	}
	if _, ok := FromHex("zz"); ok {
		t.Fatal("не hex принят")
	}
}

// Пограничные подписи: ключ, сообщение, подпись и ответ ed25519-dalek
// verify_strict (так же отвечает libsodium). Сгенерированы отдельно,
// арифметикой кривой.
var edgeSignatures = []struct {
	name             string
	key, msg, sig    string
	accept, stdlibOK bool
}{
	{"верная", "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", "d049a90bcd7acd3054b4cb73617a6e0b93c0d64fcbedafb4a2fd4427a6bb3193",
		"99b54a6e41328a41d867bd9284015152600766f7435d29268396f514846fab8c10c3bd02c56d0910210a14ff0bdb3f775cff3584006b138a2c15531716138408", true, true},
	{"S + L (неканоническая)", "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", "d049a90bcd7acd3054b4cb73617a6e0b93c0d64fcbedafb4a2fd4427a6bb3193",
		"99b54a6e41328a41d867bd9284015152600766f7435d29268396f514846fab8cfd96b35fdfd01b68f7a60ba2ead41e8c5cff3584006b138a2c15531716138418", false, false},
	{"ключ = нейтральный элемент, подходит к любому сообщению", "0100000000000000000000000000000000000000000000000000000000000000", "d049a90bcd7acd3054b4cb73617a6e0b93c0d64fcbedafb4a2fd4427a6bb3193",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", false, true},
	{"ключ порядка 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "018c267d72f6381a2ec828ada8fb4995323745e5dce6222890ebac36f5323e68",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", false, true},
	{"настоящий ключ, R = нейтральный элемент", "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", "d049a90bcd7acd3054b4cb73617a6e0b93c0d64fcbedafb4a2fd4427a6bb3193",
		"010000000000000000000000000000000000000000000000000000000000000017ed78225bfb76b9322abb498080fc0db65a3cb372220dc6cc191b2c90e9850d", false, true},
	{"нейтральный элемент с битом знака", "0100000000000000000000000000000000000000000000000000000000000080", "d049a90bcd7acd3054b4cb73617a6e0b93c0d64fcbedafb4a2fd4427a6bb3193",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", false, true},
	{"y = p + 1 (нейтральный элемент, неканонически)", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "d049a90bcd7acd3054b4cb73617a6e0b93c0d64fcbedafb4a2fd4427a6bb3193",
		"01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", false, true},
	// Смешанный порядок (aB + T₈) не «слабый»: все три библиотеки проверяют
	// без кофактора, и подпись проходит, только если 8 | k.
	{"смешанный порядок, 8 | k", "9ea3f11f5bd34f0cd7147fd0a436c088f624c6100c1df6a53c0a29e05d60cea0", "ec31682fde561917952ff78a7a8adeffd0febc372dd26871916c46c630381b45",
		"ef4f62f8479733ad879cfaced3c89a9c39dd4fc795ef2efa1c3eafe4d729a08151813d1873602f15c6e9e5d49b25082c83333bc9c44f70e7fe4865fab13f3e00", true, true},
	{"смешанный порядок, 8 ∤ k", "9ea3f11f5bd34f0cd7147fd0a436c088f624c6100c1df6a53c0a29e05d60cea0", "ea29aff4f763a1dbbe46bc514fcb1b30a3242b07a477117fc79e2e476c94e449",
		"ef4f62f8479733ad879cfaced3c89a9c39dd4fc795ef2efa1c3eafe4d729a081cbdd53da75e6cd3ea77458bfcd5bc522f10a0040f0afbf3a4552e778a1a57905", false, false},
}

// Verify обязана отвечать как Rust (verify_strict) и Python (libsodium), а не
// как голая ed25519.Verify, иначе сеть расколется на подписи малого порядка.
func TestVerifyMatchesStrictEd25519(t *testing.T) {
	for _, c := range edgeSignatures {
		key, _ := FromHex(c.key)
		msg, _ := FromHex(c.msg)
		sig, _ := FromHex(c.sig)
		if got := Verify(PublicKey(key), Hash(msg), Sig(sig)); got != c.accept {
			t.Errorf("%s: Verify = %v, ожидалось %v", c.name, got, c.accept)
		}
		if got := ed25519.Verify(key, msg, sig); got != c.stdlibOK {
			t.Errorf("%s: ed25519.Verify = %v, ожидалось %v", c.name, got, c.stdlibOK)
		}
	}
}
