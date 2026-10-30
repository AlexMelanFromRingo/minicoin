"""Транзакции и модель UTXO.

Монеты существуют только в виде непотраченных выходов (UTXO). «Баланса»
как числа нигде нет: баланс — сумма выходов, запертых вашим ключом.

Транзакция тратит старые выходы целиком (входы ссылаются на них) и
создаёт новые. Разница «входы − выходы» — комиссия майнеру. Остаток
возвращается себе отдельным выходом («сдача»).

Выход запирается открытым ключом получателя, вход отпирает его подписью
этим ключом. Скриптового языка нет, это и есть всё условие траты.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import crypto
from .codec import Reader, Writer

INPUT_SIZE = 32 + 2 + 64
OUTPUT_SIZE = 8 + 32
ZERO_SIG = bytes(64)


@dataclass(frozen=True, order=True)
class OutPoint:
    """Ссылка на выход: «выход номер index транзакции txid»."""

    txid: bytes
    index: int


@dataclass
class TxIn:
    prev: OutPoint
    signature: bytes = ZERO_SIG


@dataclass
class TxOut:
    amount: int  # в единицах: 1 монета = 100 000 000 единиц
    owner: bytes  # кто может потратить этот выход


@dataclass
class Transaction:
    inputs: list[TxIn] = field(default_factory=list)
    outputs: list[TxOut] = field(default_factory=list)
    # Транзакция действительна только в блоках с высотой ≤ expiry_height.
    # Не включили вовремя — она навсегда недействительна, входы свободны.
    # У coinbase здесь высота блока: это делает её txid уникальным.
    expiry_height: int = 0

    def write(self, w: Writer, with_signatures: bool = True) -> None:
        w.u16(len(self.inputs))
        for tx_in in self.inputs:
            w.raw(tx_in.prev.txid)
            w.u16(tx_in.prev.index)
            # При подписи места подписей заполняются нулями: нельзя подписать
            # байты, в которых уже должна стоять эта самая подпись.
            w.raw(tx_in.signature if with_signatures else ZERO_SIG)
        w.u16(len(self.outputs))
        for out in self.outputs:
            w.u64(out.amount)
            w.raw(out.owner)
        w.u32(self.expiry_height)

    def to_bytes(self) -> bytes:
        w = Writer()
        self.write(w)
        return bytes(w.bytes)

    @staticmethod
    def read(r: Reader) -> Transaction:
        inputs = []
        for _ in range(r.u16()):
            prev = OutPoint(r.raw(32), r.u16())
            inputs.append(TxIn(prev, r.raw(64)))
        outputs = [TxOut(r.u64(), r.raw(32)) for _ in range(r.u16())]
        return Transaction(inputs, outputs, r.u32())

    @staticmethod
    def from_bytes(data: bytes) -> Transaction:
        r = Reader(data)
        tx = Transaction.read(r)
        r.finish()
        return tx

    def txid(self) -> bytes:
        """Идентификатор — хеш всех байтов транзакции, включая подписи."""
        return crypto.hash(self.to_bytes())

    def sighash(self) -> bytes:
        """Что подписывают владельцы входов: хеш с обнулёнными подписями.
        Подпись покрывает все входы, выходы и срок действия."""
        w = Writer()
        self.write(w, with_signatures=False)
        return crypto.hash(bytes(w.bytes))

    def sign(self, seed: bytes) -> None:
        """Подписать все входы одним ключом (кошелёк minicoin — один ключ)."""
        signature = crypto.sign(seed, self.sighash())
        for tx_in in self.inputs:
            tx_in.signature = signature

    def is_coinbase(self) -> bool:
        """Coinbase — транзакция без входов: монеты из награды за блок."""
        return not self.inputs

    def size(self) -> int:
        return 2 + len(self.inputs) * INPUT_SIZE + 2 + len(self.outputs) * OUTPUT_SIZE + 4

    def output_sum(self) -> int:
        return sum(out.amount for out in self.outputs)
