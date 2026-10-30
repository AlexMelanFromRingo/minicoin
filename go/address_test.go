package minicoin

import (
	"strings"
	"testing"
)

func sevens() PublicKey {
	var key PublicKey
	for i := range key {
		key[i] = 7
	}
	return key
}

func TestAddressRoundtrip(t *testing.T) {
	key := sevens()
	address := EncodeAddress(key)
	if !strings.HasPrefix(address, "mc1") || len(address) != 61 {
		t.Fatalf("адрес %q", address)
	}
	for _, text := range []string{address, strings.ToUpper(address)} {
		if got, err := DecodeAddress(text); err != nil || got != key {
			t.Fatalf("DecodeAddress(%q) = %x, %v", text, got, err)
		}
	}
}

func TestAddressDetectsTypo(t *testing.T) {
	chars := []byte(EncodeAddress(sevens()))
	if chars[10] == 'q' {
		chars[10] = 'p'
	} else {
		chars[10] = 'q'
	}
	if _, err := DecodeAddress(string(chars)); err == nil {
		t.Fatal("опечатка не замечена")
	}
}

func TestAddressRejectsForeignPrefix(t *testing.T) {
	address := strings.Replace(EncodeAddress(sevens()), "mc1", "bc1", 1)
	if _, err := DecodeAddress(address); err == nil {
		t.Fatal("чужой префикс принят")
	}
}

// Официальный тестовый вектор Bech32m из BIP 350 (проверка polymod).
func TestBIP350Vector(t *testing.T) {
	s := "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"
	sep := strings.LastIndexByte(s, '1')
	values := hrpExpand(s[:sep])
	for i := sep + 1; i < len(s); i++ {
		values = append(values, byte(strings.IndexByte(charset, s[i])))
	}
	if polymod(values) != bech32mConst {
		t.Fatal("polymod не сошёлся с BIP 350")
	}
}
