"""Сериализация: как структуры превращаются в байты.

Правило одно: числа пишутся в little-endian фиксированной ширины,
массивы байтов как есть, перед списком стоит его длина. Хеши блоков и
транзакций считаются от этих байтов, поэтому все узлы обязаны получать
их одинаково. Описание формата — ../PROTOCOL.md.
"""

import struct


class DecodeError(ValueError):
    pass


class Writer:
    def __init__(self) -> None:
        self.bytes = bytearray()

    def u8(self, value: int) -> None:
        self.bytes += struct.pack("<B", value)

    def u16(self, value: int) -> None:
        self.bytes += struct.pack("<H", value)

    def u32(self, value: int) -> None:
        self.bytes += struct.pack("<I", value)

    def u64(self, value: int) -> None:
        self.bytes += struct.pack("<Q", value)

    def raw(self, value: bytes) -> None:
        self.bytes += value


class Reader:
    """Читает байты по порядку. Нехватка данных — исключение DecodeError:
    байты приходят из сети, и доверять им нельзя."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def raw(self, length: int) -> bytes:
        if len(self.data) - self.pos < length:
            raise DecodeError("неожиданный конец данных")
        chunk = self.data[self.pos : self.pos + length]
        self.pos += length
        return bytes(chunk)

    def _unpack(self, fmt: str, size: int) -> int:
        return struct.unpack("<" + fmt, self.raw(size))[0]

    def u8(self) -> int:
        return self._unpack("B", 1)

    def u16(self) -> int:
        return self._unpack("H", 2)

    def u32(self) -> int:
        return self._unpack("I", 4)

    def u64(self) -> int:
        return self._unpack("Q", 8)

    def finish(self) -> None:
        """Лишние байты в конце — тоже ошибка: у объекта ровно одно представление."""
        if self.pos != len(self.data):
            raise DecodeError("лишние байты в конце")
