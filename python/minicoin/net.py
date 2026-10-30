"""Сетевой протокол: сообщения поверх TCP.

Кадр: magic "mini" [4] | тип u8 | длина u32 | полезная нагрузка [длина].
Магические байты отсекают чужие подключения, ограничение длины не даёт
пиру заставить нас выделить гигабайты памяти.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from .block import Block
from .chain import UtxoEntry
from .codec import DecodeError, Reader, Writer
from .tx import OutPoint, Transaction, TxOut

MAGIC = b"mini"
MAX_MESSAGE = 2 * 1024 * 1024
DEFAULT_PORT = 4242


@dataclass
class Status:  # «вот моя высота и вершина»
    height: int
    tip: bytes


@dataclass
class GetBlocks:  # «пришли блоки после первого общего из локатора»
    locator: list[bytes]


@dataclass
class BlockMsg:
    block: Block


@dataclass
class TxMsg:
    tx: Transaction


@dataclass
class GetUtxos:
    owner: bytes
    # Выходы, уже потраченные транзакциями мемпула, узел показывает только по
    # этому флагу: они нужны bump, чтобы узнать, что тратит застрявшая транзакция.
    include_mempool_spent: bool = False


@dataclass
class Utxos:
    height: int
    utxos: list[tuple[OutPoint, UtxoEntry]] = field(default_factory=list)


@dataclass
class GetBlock:
    height: int


@dataclass
class GetInfo:
    pass


@dataclass
class Text:  # ответ человеку
    text: str


@dataclass
class GetMempoolTx:  # кошелёк: транзакция из мемпула (для замены, см. bump)
    txid: bytes


@dataclass
class MempoolTx:  # транзакция мемпула и её комиссия (кошелёк ей не верит, см. bump)
    fee: int
    tx: Transaction


Message = Status | GetBlocks | BlockMsg | TxMsg | GetUtxos | Utxos | GetBlock | GetInfo | Text | GetMempoolTx | MempoolTx

KINDS = {
    Status: 1, GetBlocks: 2, BlockMsg: 3, TxMsg: 4, GetUtxos: 5, Utxos: 6,
    GetBlock: 7, GetInfo: 8, Text: 9, GetMempoolTx: 10, MempoolTx: 11,
}


def payload(msg: Message) -> bytes:
    w = Writer()
    match msg:
        case Status(height, tip):
            w.u32(height)
            w.raw(tip)
        case GetBlocks(locator):
            w.u16(len(locator))
            for h in locator:
                w.raw(h)
        case BlockMsg(block):
            w.raw(block.to_bytes())
        case TxMsg(tx):
            tx.write(w)
        case GetUtxos(owner, include_mempool_spent):
            w.raw(owner)
            w.u8(int(include_mempool_spent))
        case Utxos(height, utxos):
            w.u32(height)
            w.u32(len(utxos))
            for outpoint, entry in utxos:
                w.raw(outpoint.txid)
                w.u16(outpoint.index)
                w.u64(entry.output.amount)
                w.raw(entry.output.owner)
                w.u32(entry.height)
                w.u8(int(entry.coinbase))
        case GetBlock(height):
            w.u32(height)
        case GetInfo():
            pass
        case Text(text):
            w.raw(text.encode())
        case GetMempoolTx(txid):
            w.raw(txid)
        case MempoolTx(fee, tx):
            w.u64(fee)
            tx.write(w)
    return bytes(w.bytes)


def parse(kind: int, data: bytes) -> Message:
    if kind == 3:
        return BlockMsg(Block.from_bytes(data))
    if kind == 4:
        return TxMsg(Transaction.from_bytes(data))
    if kind == 9:
        return Text(data.decode())
    r = Reader(data)
    if kind == 1:
        msg: Message = Status(r.u32(), r.raw(32))
    elif kind == 2:
        msg = GetBlocks([r.raw(32) for _ in range(r.u16())])
    elif kind == 5:
        msg = GetUtxos(r.raw(32), r.u8() != 0)
    elif kind == 6:
        height = r.u32()
        utxos = []
        for _ in range(r.u32()):
            outpoint = OutPoint(r.raw(32), r.u16())
            output = TxOut(r.u64(), r.raw(32))
            utxos.append((outpoint, UtxoEntry(output, r.u32(), r.u8() != 0)))
        msg = Utxos(height, utxos)
    elif kind == 7:
        msg = GetBlock(r.u32())
    elif kind == 8:
        msg = GetInfo()
    elif kind == 10:
        msg = GetMempoolTx(r.raw(32))
    elif kind == 11:
        msg = MempoolTx(r.u64(), Transaction.read(r))
    else:
        raise DecodeError(f"неизвестный тип сообщения {kind}")
    r.finish()
    return msg


def encode(msg: Message) -> bytes:
    body = payload(msg)
    return MAGIC + struct.pack("<BI", KINDS[type(msg)], len(body)) + body


def send(sock: socket.socket, msg: Message) -> None:
    sock.sendall(encode(msg))


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("соединение закрыто")
        buf += chunk
    return bytes(buf)


def recv(sock: socket.socket) -> Message:
    head = _read_exact(sock, 9)
    if head[:4] != MAGIC:
        raise DecodeError("чужие магические байты")
    kind, length = struct.unpack("<BI", head[4:])
    if length > MAX_MESSAGE:
        raise DecodeError(f"сообщение слишком большое: {length} байт")
    return parse(kind, _read_exact(sock, length))
