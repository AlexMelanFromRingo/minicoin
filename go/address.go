// Адрес: открытый ключ, записанный для людей.
//
// 32 байта ключа кодируются в Bech32m (BIP 350) с префиксом `mc`:
// `mc1` + 52 символа данных + 6 символов контрольной суммы. Контрольная
// сумма гарантированно ловит до 4 опечаток, поэтому деньги не уйдут на
// адрес с ошибкой. Алфавит без символов, которые легко спутать (1, b, i, o).
//
// Bech32m — общий формат, который легко написать самому, поэтому он здесь,
// а не в зависимостях.
package minicoin

import (
	"errors"
	"fmt"
	"strings"
)

const HRP = "mc"
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const bech32mConst uint32 = 0x2bc8_30a3

// polymod: контрольная сумма — остаток от деления многочлена над GF(32).
func polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3}
	chk := uint32(1)
	for _, value := range values {
		top := chk >> 25
		chk = ((chk & 0x1ff_ffff) << 5) ^ uint32(value)
		for i, g := range gen {
			if (top>>i)&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

// hrpExpand: префикс тоже входит в контрольную сумму, адрес чужой сети не пройдёт.
func hrpExpand(hrp string) []byte {
	var out []byte
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// convertBits — перегруппировка битов: из байтов (8 бит) в символы (5 бит) и обратно.
func convertBits(data []byte, from, to uint32, pad bool) ([]byte, bool) {
	var acc, bits uint32
	mask := uint32(1)<<to - 1
	var out []byte
	for _, value := range data {
		if uint32(value)>>from != 0 {
			return nil, false
		}
		acc = ((acc << from) | uint32(value)) & 0xfff
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte((acc>>bits)&mask))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(to-bits))&mask))
		}
	} else if bits >= from || ((acc<<(to-bits))&mask) != 0 {
		return nil, false
	}
	return out, true
}

func EncodeAddress(key PublicKey) string {
	data, _ := convertBits(key[:], 8, 5, true) // байты всегда конвертируются
	values := append(hrpExpand(HRP), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	checksum := polymod(values) ^ bech32mConst

	var out strings.Builder
	out.WriteString(HRP + "1")
	for _, d := range data {
		out.WriteByte(charset[d])
	}
	for i := 0; i < 6; i++ {
		out.WriteByte(charset[(checksum>>(5*(5-i)))&31])
	}
	return out.String()
}

func DecodeAddress(address string) (PublicKey, error) {
	var key PublicKey
	if strings.ToLower(address) != address && strings.ToUpper(address) != address {
		return key, errors.New("в адресе смешаны строчные и заглавные буквы")
	}
	address = strings.ToLower(address)
	sep := strings.LastIndexByte(address, '1')
	if sep < 0 {
		return key, errors.New("в адресе нет разделителя '1'")
	}
	hrp, data := address[:sep], address[sep+1:]
	if hrp != HRP {
		return key, fmt.Errorf("адрес должен начинаться с '%s1'", HRP)
	}
	var values []byte
	for i := 0; i < len(data); i++ {
		p := strings.IndexByte(charset, data[i])
		if p < 0 {
			return key, errors.New("недопустимый символ в адресе")
		}
		values = append(values, byte(p))
	}
	if len(values) < 6 {
		return key, errors.New("адрес слишком короткий")
	}
	if polymod(append(hrpExpand(hrp), values...)) != bech32mConst {
		return key, errors.New("неверная контрольная сумма адреса (опечатка?)")
	}
	bytes, ok := convertBits(values[:len(values)-6], 5, 8, false)
	if !ok {
		return key, errors.New("неверное заполнение битов")
	}
	if len(bytes) != 32 {
		return key, errors.New("адрес должен содержать ровно 32 байта")
	}
	return PublicKey(bytes), nil
}
