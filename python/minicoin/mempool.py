"""Мемпул: проверенные транзакции, которые ждут включения в блок.

Мемпул — не консенсус, а «политика узла»: у каждого узла он свой. Закон
один: транзакция в блоке должна пройти Chain.check_tx.

Упрощение: тратить можно только подтверждённые выходы, поэтому любой набор
транзакций из мемпула можно положить в блок в любом порядке.
"""

from __future__ import annotations

from dataclasses import dataclass

from .chain import Chain
from .consensus import Invalid
from .tx import OutPoint, Transaction

MIN_FEE_RATE = 1  # единиц за байт: без минимума сеть можно бесплатно завалить мусором


@dataclass
class Entry:
    tx: Transaction
    fee: int
    size: int


def should_replace(new_fee: int, new_size: int, old_fee: int, old_size: int) -> bool:
    """Replace-by-fee: вытеснить ли конфликтующие транзакции новой.

    Зачем: отправитель поставил маленькую комиссию, транзакция застряла.
    Чем опасна мягкая политика: каждая замена рассылается всей сети, и
    «замена за копейку» позволяет бесплатно её загрузить.

    Два условия (суть BIP 125), подробно — в rust/src/mempool.rs:
    1. замена платит всё, что платили вытесняемые, плюс свою ретрансляцию;
    2. комиссия за байт строго выше — мемпул не хуже для майнера.
    """
    pays_for_itself = new_fee >= old_fee + MIN_FEE_RATE * new_size
    better_rate = new_fee * old_size > old_fee * new_size  # без дробей, как в select
    return pays_for_itself and better_rate


class Mempool:
    def __init__(self) -> None:
        self.txs: dict[bytes, Entry] = {}
        self.spent_by: dict[OutPoint, bytes] = {}  # какой транзакцией мемпула потрачен выход

    def __len__(self) -> int:
        return len(self.txs)

    def get(self, txid: bytes) -> Entry | None:
        return self.txs.get(txid)

    def is_spent(self, outpoint: OutPoint) -> bool:
        return outpoint in self.spent_by

    def add(self, tx: Transaction, chain: Chain) -> bytes:
        """Принять транзакцию или бросить Invalid с причиной."""
        txid = tx.txid()
        if txid in self.txs:
            raise Invalid("уже в мемпуле")
        fee = chain.check_tx(tx, chain.height() + 1)
        size = tx.size()
        min_fee = size * MIN_FEE_RATE
        if fee < min_fee:
            raise Invalid(f"комиссия {fee} меньше минимальной {min_fee} ({MIN_FEE_RATE} ед/байт)")

        conflicts = {self.spent_by[i.prev] for i in tx.inputs if i.prev in self.spent_by}
        if conflicts:
            old_fee = sum(self.txs[c].fee for c in conflicts)
            old_size = sum(self.txs[c].size for c in conflicts)
            if not should_replace(fee, size, old_fee, old_size):
                raise Invalid("тратит те же выходы, что и транзакция в мемпуле; замена отклонена")
            for c in conflicts:
                self.remove(c)

        for tx_in in tx.inputs:
            self.spent_by[tx_in.prev] = txid
        self.txs[txid] = Entry(tx, fee, size)
        return txid

    def remove(self, txid: bytes) -> None:
        entry = self.txs.pop(txid, None)
        if entry:
            for tx_in in entry.tx.inputs:
                self.spent_by.pop(tx_in.prev, None)

    def refresh(self, chain: Chain, returned: list[Transaction]) -> None:
        """После смены вершины проверяем всё заново: попавшие в блок,
        истёкшие и конфликтующие отсеются сами. returned — транзакции
        из блоков, отключённых при реорганизации."""
        pending = [tx for tx in returned if not tx.is_coinbase()] + [e.tx for e in self.txs.values()]
        self.txs.clear()
        self.spent_by.clear()
        for tx in pending:
            try:
                self.add(tx, chain)
            except Invalid:
                pass

    def select(self, max_bytes: int) -> tuple[list[Transaction], int]:
        """Самые выгодные (комиссия за байт) первыми, пока помещаются.
        Сравнение a.fee/a.size через a.fee·b.size — без дробей, как в Rust."""
        from functools import cmp_to_key

        def by_fee_rate(a: tuple[bytes, Entry], b: tuple[bytes, Entry]) -> int:
            left, right = b[1].fee * a[1].size, a[1].fee * b[1].size
            return (left > right) - (left < right) or (a[0] > b[0]) - (a[0] < b[0])

        txs, fees, used = [], 0, 0
        for _, entry in sorted(self.txs.items(), key=cmp_to_key(by_fee_rate)):
            if used + entry.size <= max_bytes:
                used += entry.size
                fees += entry.fee
                txs.append(entry.tx)
        return txs, fees
