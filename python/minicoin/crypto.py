"""Криптографические примитивы.

Единственная часть, взятая из библиотек: хеш BLAKE3 (пакет blake3) и
подписи Ed25519 (PyNaCl, обёртка над libsodium). Своя криптография —
худшая идея в криптовалюте: ошибку в ней не видно, пока ею не
воспользуется злоумышленник.
"""

import os

from blake3 import blake3
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def hash(data: bytes) -> bytes:  # noqa: A001 — как crypto::hash в Rust
    """32-байтный хеш BLAKE3. Им идентифицируются блоки и транзакции."""
    return blake3(data).digest()


def new_seed() -> bytes:
    """Секретное зерно Ed25519 из генератора случайных чисел ОС."""
    return os.urandom(32)


def public_key(seed: bytes) -> bytes:
    return bytes(SigningKey(seed).verify_key)


def sign(seed: bytes, message: bytes) -> bytes:
    return SigningKey(seed).sign(message).signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Строгая проверка. libsodium, как и verify_strict в Rust, отвергает
    ключи малого порядка и неканонические подписи. Иначе посторонний мог
    бы чуть изменить чужую подпись, сохранив её верной, и txid бы поменялся."""
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
