//! Адрес: открытый ключ, записанный для людей.
//!
//! 32 байта ключа кодируются в Bech32m (BIP 350) с префиксом `mc`:
//! `mc1` + 52 символа данных + 6 символов контрольной суммы. Контрольная
//! сумма гарантированно ловит до 4 опечаток, поэтому деньги не уйдут на
//! адрес с ошибкой. Алфавит без символов, которые легко спутать (1, b, i, o).
//!
//! Bech32m — общий формат, который легко написать самому, поэтому он здесь,
//! а не в зависимостях.

use crate::crypto::PublicKey;

pub const HRP: &str = "mc";
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Контрольная сумма — остаток от деления многочлена над GF(32).
fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ value as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Префикс тоже входит в контрольную сумму: адрес чужой сети не пройдёт.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    out.push(0);
    out.extend(hrp.bytes().map(|c| c & 31));
    out
}

/// Перегруппировка битов: из байтов (8 бит) в символы (5 бит) и обратно.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        if (value as u32) >> from != 0 {
            return None;
        }
        acc = ((acc << from) | value as u32) & 0xfff;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max) != 0 {
        return None;
    }
    Some(out)
}

pub fn encode(key: &PublicKey) -> String {
    let data = convert_bits(key, 8, 5, true).expect("байты всегда конвертируются");
    let mut values = hrp_expand(HRP);
    values.extend(&data);
    values.extend([0; 6]);
    let checksum = polymod(&values) ^ BECH32M_CONST;

    let mut out = format!("{HRP}1");
    for &d in &data {
        out.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

pub fn decode(address: &str) -> Result<PublicKey, String> {
    if address.to_lowercase() != address && address.to_uppercase() != address {
        return Err("в адресе смешаны строчные и заглавные буквы".into());
    }
    let address = address.to_lowercase();
    let (hrp, data) = address.rsplit_once('1').ok_or("в адресе нет разделителя '1'")?;
    if hrp != HRP {
        return Err(format!("адрес должен начинаться с '{HRP}1'"));
    }
    let values: Vec<u8> = data
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()
        .ok_or("недопустимый символ в адресе")?;
    if values.len() < 6 {
        return Err("адрес слишком короткий".into());
    }
    let mut check = hrp_expand(hrp);
    check.extend(&values);
    if polymod(&check) != BECH32M_CONST {
        return Err("неверная контрольная сумма адреса (опечатка?)".into());
    }
    let bytes = convert_bits(&values[..values.len() - 6], 5, 8, false).ok_or("неверное заполнение битов")?;
    bytes.try_into().map_err(|_| "адрес должен содержать ровно 32 байта".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let address = encode(&key);
        assert!(address.starts_with("mc1"));
        assert_eq!(address.len(), 61);
        assert_eq!(decode(&address), Ok(key));
        assert_eq!(decode(&address.to_uppercase()), Ok(key));
    }

    #[test]
    fn detects_typo() {
        let address = encode(&[7u8; 32]);
        let mut chars: Vec<char> = address.chars().collect();
        chars[10] = if chars[10] == 'q' { 'p' } else { 'q' };
        let typo: String = chars.into_iter().collect();
        assert!(decode(&typo).is_err());
    }

    #[test]
    fn rejects_foreign_prefix() {
        let address = encode(&[7u8; 32]).replacen("mc1", "bc1", 1);
        assert!(decode(&address).is_err());
    }

    /// Официальный тестовый вектор Bech32m из BIP 350 (проверка polymod).
    #[test]
    fn bip350_vector() {
        let s = "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx";
        let (hrp, data) = s.rsplit_once('1').unwrap();
        let mut values = hrp_expand(hrp);
        values.extend(data.bytes().map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8));
        assert_eq!(polymod(&values), BECH32M_CONST);
    }
}
