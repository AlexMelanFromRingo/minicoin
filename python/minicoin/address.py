"""Адрес: открытый ключ, записанный для людей.

32 байта ключа кодируются в Bech32m (BIP 350) с префиксом mc:
mc1 + 52 символа данных + 6 символов контрольной суммы. Контрольная
сумма гарантированно ловит до 4 опечаток.
"""

HRP = "mc"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def polymod(values: list[int]) -> int:
    """Контрольная сумма — остаток от деления многочлена над GF(32)."""
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def hrp_expand(hrp: str) -> list[int]:
    """Префикс тоже входит в контрольную сумму: адрес чужой сети не пройдёт."""
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def convert_bits(data: bytes | list[int], from_bits: int, to_bits: int, pad: bool) -> list[int] | None:
    """Перегруппировка битов: из байтов (8 бит) в символы (5 бит) и обратно."""
    acc = bits = 0
    max_value = (1 << to_bits) - 1
    out = []
    for value in data:
        if value >> from_bits:
            return None
        acc = ((acc << from_bits) | value) & 0xFFF
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & max_value)
    if pad:
        if bits:
            out.append((acc << (to_bits - bits)) & max_value)
    elif bits >= from_bits or (acc << (to_bits - bits)) & max_value:
        return None
    return out


def encode(key: bytes) -> str:
    data = convert_bits(key, 8, 5, True)
    checksum = polymod(hrp_expand(HRP) + data + [0] * 6) ^ BECH32M_CONST
    check = [(checksum >> (5 * (5 - i))) & 31 for i in range(6)]
    return HRP + "1" + "".join(CHARSET[d] for d in data + check)


def decode(address: str) -> bytes:
    """Адрес → 32 байта ключа или ValueError с понятной причиной."""
    if address.lower() != address and address.upper() != address:
        raise ValueError("в адресе смешаны строчные и заглавные буквы")
    address = address.lower()
    hrp, sep, data = address.rpartition("1")
    if not sep:
        raise ValueError("в адресе нет разделителя '1'")
    if hrp != HRP:
        raise ValueError(f"адрес должен начинаться с '{HRP}1'")
    if any(c not in CHARSET for c in data):
        raise ValueError("недопустимый символ в адресе")
    values = [CHARSET.index(c) for c in data]
    if len(values) < 6:
        raise ValueError("адрес слишком короткий")
    if polymod(hrp_expand(hrp) + values) != BECH32M_CONST:
        raise ValueError("неверная контрольная сумма адреса (опечатка?)")
    key = convert_bits(values[:-6], 5, 8, False)
    if key is None:
        raise ValueError("неверное заполнение битов")
    if len(key) != 32:
        raise ValueError("адрес должен содержать ровно 32 байта")
    return bytes(key)
