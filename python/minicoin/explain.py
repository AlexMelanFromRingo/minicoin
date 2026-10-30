"""Побайтовый разбор блока: каждое поле — его байты и смысл.

Если сложить все hex-строки по порядку, получится ровно block.to_bytes().
"""

from __future__ import annotations

import struct

from . import address, consensus, crypto
from . import block as blk
from .block import Block, BlockHeader
from .tx import OutPoint, Transaction, TxIn, TxOut
from .wallet import format_amount


class Explainer:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.offset = 0
        self.bytes = bytearray()

    def section(self, title: str) -> None:
        self.lines.append(f"\n── {title} ──")

    def field(self, data: bytes, name: str, meaning: str = "") -> None:
        self.lines.append(f"{self.offset:>7}  {name:<14} {data.hex()}")
        if meaning:
            self.lines.append(f"{'':>7}  {'':<14} ↳ {meaning}")
        self.offset += len(data)
        self.bytes += data

    def note(self, text: str) -> None:
        self.lines.append(f"         {text}")


def u16(v: int) -> bytes:
    return struct.pack("<H", v)


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


def u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def explain_block(block: Block, height: int) -> str:
    e = Explainer()
    h = block.header
    block_hash = block.hash()
    e.lines.append(f"Блок #{height}  ({block.size()} байт)\nхеш {block_hash.hex()}")

    e.section("Заголовок, 88 байт: только он хешируется для PoW")
    e.field(h.prev_hash, "prev_hash", "хеш предыдущего блока — звено цепи")
    e.field(h.merkle_root, "merkle_root", "корень дерева Меркла по txid всех транзакций")
    e.field(u64(h.time), "time", f"{h.time} (секунды Unix, little-endian)")
    e.field(u64(h.difficulty), "difficulty", f"{h.difficulty} — столько хешей в среднем нужно перебрать")
    e.field(u64(h.nonce), "nonce", f"{h.nonce} — найдено перебором")
    e.note(f"BLAKE3(заголовок) = {block_hash.hex()}")
    e.note(f"цель = (2²⁵⁶−1)/difficulty = {blk.target(h.difficulty).hex()}")
    ok = blk.meets_difficulty(block_hash, h.difficulty)
    e.note("хеш ≤ цели ✓ работа доказана" if ok else "хеш > цели ✗ (генезис не майнится)")

    e.section("Транзакции")
    e.field(u32(len(block.txs)), "tx_count", f"{len(block.txs)} транзакций")

    for n, tx in enumerate(block.txs):
        kind = "coinbase: новые монеты, входов нет" if tx.is_coinbase() else "обычная"
        e.section(f"Транзакция {n} ({kind})")
        e.field(u16(len(tx.inputs)), "input_count")
        for i, tx_in in enumerate(tx.inputs):
            e.field(tx_in.prev.txid, f"in[{i}].txid", "какую транзакцию тратим…")
            e.field(u16(tx_in.prev.index), f"in[{i}].index", f"…и её выход №{tx_in.prev.index}")
            e.field(tx_in.signature, f"in[{i}].sig", "Ed25519-подпись владельца выхода под sighash")
        e.field(u16(len(tx.outputs)), "output_count")
        for i, out in enumerate(tx.outputs):
            e.field(u64(out.amount), f"out[{i}].amount", f"{format_amount(out.amount)} монет")
            e.field(out.owner, f"out[{i}].owner", f"открытый ключ получателя = {address.encode(out.owner)}")
        if tx.is_coinbase():
            expiry = f"{tx.expiry_height} — высота блока (делает txid уникальным)"
        else:
            expiry = f"{tx.expiry_height} — после этой высоты транзакция недействительна"
        e.field(u32(tx.expiry_height), "expiry_height", expiry)
        e.note(f"txid = BLAKE3(байты транзакции) = {tx.txid().hex()}")
        if not tx.is_coinbase():
            # Тратимых выходов в блоке нет, поэтому значение sighash здесь не посчитать.
            e.note("sighash = BLAKE3(эти байты с нулевыми подписями ‖ сумма и владелец каждого тратимого выхода)")

    if height > 0:
        e.lines.append(
            f"\nНаграда за блок на этой высоте: {format_amount(consensus.block_reward(height))} монет (+ комиссии)"
        )
    assert bytes(e.bytes) == block.to_bytes(), "разбор должен покрыть каждый байт"
    return "\n".join(e.lines) + "\n"


def test_vectors() -> str:
    """Те же векторы, что `minicoin vectors` в Rust-версии."""
    out = []

    def put(name: str, value: str) -> None:
        out.append(f"{name} = {value}")

    genesis = consensus.genesis_block()
    put("genesis_block", genesis.to_bytes().hex())
    put("genesis_hash", genesis.hash().hex())

    seed = bytes([1] * 32)
    key = crypto.public_key(seed)
    put("seed", seed.hex())
    put("public_key", key.hex())
    put("address", address.encode(key))
    put("address_of_zero_key", address.encode(bytes(32)))

    tx = Transaction(
        [TxIn(OutPoint(genesis.txs[0].txid(), 0))],
        [TxOut(1_250_000_000, crypto.public_key(bytes([2] * 32))), TxOut(3_749_990_000, key)],
        100,
    )
    # Вход тратит выход 0 coinbase генезиса как 50 монет на key:
    # выходы 4 999 990 000 + комиссия 10 000 = 5 000 000 000.
    spent = [TxOut(5_000_000_000, key)]
    tx.sign(seed, spent)
    put("tx", tx.to_bytes().hex())
    put("tx_spent_amount", str(spent[0].amount))
    put("tx_sighash", tx.sighash(spent).hex())
    put("tx_txid", tx.txid().hex())

    leaves = [crypto.hash(x) for x in (b"a", b"b", b"c", b"d", b"e")]
    for n in range(1, 6):
        put(f"merkle_{n}", blk.merkle_root(leaves[:n]).hex())
    for d in (1, 3, 1 << 20, 2**64 - 1):
        put(f"target_{d}", blk.target(d).hex())
    for old, span in ((1 << 20, 200), (1 << 20, 0), (1 << 20, 100), (1 << 20, 10_000), (1000, 333)):
        put(f"retarget_{old}_{span}", str(consensus.retarget(old, span)))
    for h in (0, 1, 99_999, 100_000, 6_399_999, 6_400_000):
        put(f"reward_{h}", str(consensus.block_reward(h)))

    coinbase = Transaction([], [TxOut(consensus.block_reward(1), key)], 1)
    header = BlockHeader(
        prev_hash=genesis.hash(),
        merkle_root=blk.merkle_root([coinbase.txid()]),
        time=consensus.GENESIS_TIME + consensus.BLOCK_TIME,
        difficulty=consensus.INITIAL_DIFFICULTY,
    )
    prefix = header.to_bytes()[:80]
    limit = blk.MAX_HASH // header.difficulty
    while int.from_bytes(crypto.hash(prefix + u64(header.nonce)), "big") > limit:
        header.nonce += 1
    block1 = Block(header, [coinbase])
    put("block1", block1.to_bytes().hex())
    put("block1_hash", block1.hash().hex())
    return "\n".join(out) + "\n"
