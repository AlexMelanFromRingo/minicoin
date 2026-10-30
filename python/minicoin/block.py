"""Блок, дерево Меркла и доказательство работы.

Блок — это заголовок и список транзакций. Заголовок короткий (88 байт)
и через корень Меркла фиксирует все транзакции. Поэтому для
доказательства работы (PoW) достаточно хешировать только заголовок.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import crypto
from .codec import Reader, Writer
from .tx import Transaction

HEADER_SIZE = 32 + 32 + 8 + 8 + 8
MAX_HASH = 2**256 - 1


@dataclass
class BlockHeader:
    prev_hash: bytes  # хеш предыдущего блока — звено цепи
    merkle_root: bytes  # корень дерева Меркла по txid всех транзакций
    time: int  # секунды Unix
    difficulty: int  # сколько хешей в среднем нужно перебрать
    nonce: int = 0  # число, которое перебирает майнер

    def write(self, w: Writer) -> None:
        w.raw(self.prev_hash)
        w.raw(self.merkle_root)
        w.u64(self.time)
        w.u64(self.difficulty)
        w.u64(self.nonce)

    def to_bytes(self) -> bytes:
        w = Writer()
        self.write(w)
        return bytes(w.bytes)

    @staticmethod
    def read(r: Reader) -> BlockHeader:
        return BlockHeader(r.raw(32), r.raw(32), r.u64(), r.u64(), r.u64())

    def hash(self) -> bytes:
        return crypto.hash(self.to_bytes())


@dataclass
class Block:
    header: BlockHeader
    txs: list[Transaction] = field(default_factory=list)  # первая — coinbase

    def hash(self) -> bytes:
        return self.header.hash()

    def to_bytes(self) -> bytes:
        w = Writer()
        self.header.write(w)
        w.u32(len(self.txs))
        for tx in self.txs:
            tx.write(w)
        return bytes(w.bytes)

    @staticmethod
    def from_bytes(data: bytes) -> Block:
        r = Reader(data)
        header = BlockHeader.read(r)
        txs = [Transaction.read(r) for _ in range(r.u32())]
        r.finish()
        return Block(header, txs)

    def size(self) -> int:
        return HEADER_SIZE + 4 + sum(tx.size() for tx in self.txs)


def merkle_root(txids: list[bytes]) -> bytes:
    """Корень дерева Меркла: хешируем txid попарно, пока не останется один.

    Узел = BLAKE3(0x01 ‖ левый ‖ правый); нечётный узел поднимается на
    уровень выше без изменений (не дублируется, как в биткоине, —
    дублирование давало два списка транзакций с одним корнем, CVE-2012-2459).
    """
    if not txids:
        return bytes(32)
    level = list(txids)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(crypto.hash(b"\x01" + level[i] + level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def target(difficulty: int) -> bytes:
    """Цель: хеш как 256-битное число должен быть ≤ ⌊(2²⁵⁶−1)/difficulty⌋.
    Вероятность попасть под цель 1/difficulty — это и есть «работа».
    В Python большие числа встроены, деление столбиком писать не нужно."""
    return (MAX_HASH // max(difficulty, 1)).to_bytes(32, "big")


def meets_difficulty(block_hash: bytes, difficulty: int) -> bool:
    return difficulty > 0 and int.from_bytes(block_hash, "big") <= MAX_HASH // difficulty
