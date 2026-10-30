//! Криптографические примитивы.
//!
//! Это единственная часть, взятая из библиотек: хеш BLAKE3 и подписи
//! Ed25519. Обе — общие стандарты, не привязанные к какой-либо монете.
//! Писать свою криптографию нельзя: ошибку в ней не видно, пока ею не
//! воспользуется злоумышленник.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// 32-байтный хеш BLAKE3. Им идентифицируются блоки и транзакции.
pub type Hash = [u8; 32];
/// Открытый ключ Ed25519. Выход транзакции «запирается» именно им.
pub type PublicKey = [u8; 32];
/// Секретное зерно Ed25519: из него однозначно получаются оба ключа.
pub type Seed = [u8; 32];
/// Подпись Ed25519.
pub type Sig = [u8; 64];

pub fn hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Новое случайное зерно из генератора случайных чисел операционной системы.
pub fn new_seed() -> Seed {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("ОС не выдала случайные байты");
    seed
}

pub fn public_key(seed: &Seed) -> PublicKey {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn sign(seed: &Seed, message: &Hash) -> Sig {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Строгая проверка: отвергает «слабые» ключи и неканонические подписи.
/// Без неё посторонний мог бы чуть изменить чужую подпись так, что она
/// осталась бы верной, а хеш транзакции (txid) поменялся бы.
pub fn verify(public_key: &PublicKey, message: &Hash, signature: &Sig) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(signature)).is_ok()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    // Только 0-9a-fA-F: from_str_radix сам пропустил бы знак «+» («+f» = 0x0f).
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip() {
        let seed = new_seed();
        let message = hash(b"hello");
        let sig = sign(&seed, &message);
        assert!(verify(&public_key(&seed), &message, &sig));
        assert!(!verify(&public_key(&seed), &hash(b"other"), &sig));
        assert!(!verify(&public_key(&new_seed()), &message, &sig));
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(from_hex(&to_hex(&[0, 1, 254, 255])), Some(vec![0, 1, 254, 255]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("+f+f"), None);
    }
}
