"""Цепочка блоков и набор UTXO — сердце узла.

Узел знает дерево блоков (все ветки, которые ему показали), но «правдой»
считает одну: ветку с наибольшей суммарной работой. Набор UTXO всегда
соответствует вершине этой ветки.

Если другая ветка обгоняет текущую, происходит реорганизация: блоки
откатываются до точки расхождения (по undo-данным), затем применяются
блоки новой ветки.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import consensus, crypto
from .block import Block
from .consensus import Invalid
from .tx import OutPoint, Transaction, TxOut


@dataclass
class UtxoEntry:
    output: TxOut
    height: int  # высота блока, где создан выход (для созревания coinbase)
    coinbase: bool


@dataclass
class BlockUndo:
    """Как отменить блок: что он потратил (вернуть) и что создал (удалить)."""

    spent: list[tuple[OutPoint, UtxoEntry]] = field(default_factory=list)
    created: list[OutPoint] = field(default_factory=list)


@dataclass
class BlockEntry:
    block: Block
    height: int
    total_work: int  # сумма сложностей от генезиса до этого блока


class Duplicate(Exception):
    """Блок уже известен."""


class Orphan(Exception):
    """Неизвестен родитель: надо догрузить цепочку у того, кто прислал."""


@dataclass
class ChainUpdate:
    connected: list[bytes] = field(default_factory=list)  # пусто — боковая ветка
    disconnected: list[Block] = field(default_factory=list)  # их транзакции — назад в мемпул


class Chain:
    def __init__(self) -> None:
        genesis = consensus.genesis_block()
        h = genesis.hash()
        self.blocks: dict[bytes, BlockEntry] = {h: BlockEntry(genesis, 0, genesis.header.difficulty)}
        self.main: list[bytes] = [h]  # main[h] — хеш блока высоты h
        self.utxo: dict[OutPoint, UtxoEntry] = {}
        self.undo: dict[bytes, BlockUndo] = {h: BlockUndo()}
        self.invalid: set[bytes] = set()

    def height(self) -> int:
        return len(self.main) - 1

    def tip(self) -> bytes:
        return self.main[-1]

    def get(self, block_hash: bytes) -> BlockEntry | None:
        return self.blocks.get(block_hash)

    def block_at(self, height: int) -> Block | None:
        if 0 <= height < len(self.main):
            return self.blocks[self.main[height]].block
        return None

    def is_on_main(self, block_hash: bytes) -> bool:
        entry = self.blocks.get(block_hash)
        return entry is not None and entry.height < len(self.main) and self.main[entry.height] == block_hash

    def ancestor(self, block_hash: bytes, height: int) -> BlockEntry:
        """Предок блока на высоте height — идём назад по prev_hash."""
        entry = self.blocks[block_hash]
        while entry.height > height:
            entry = self.blocks[entry.block.header.prev_hash]
        return entry

    def next_difficulty(self, parent: bytes) -> int:
        """Сложность, которую обязан указать блок после parent (по его ветке)."""
        p = self.blocks[parent]
        height = p.height + 1
        if height % consensus.RETARGET_INTERVAL != 0 or height <= consensus.RETARGET_INTERVAL:
            return p.block.header.difficulty
        first = self.ancestor(parent, p.height - consensus.RETARGET_INTERVAL)
        span = max(p.block.header.time - first.block.header.time, 0)
        return consensus.retarget(p.block.header.difficulty, span)

    def median_time_past(self, parent: bytes) -> int:
        """Медиана времени последних 11 блоков: растёт, даже если кто-то врёт."""
        times = []
        entry = self.blocks[parent]
        for _ in range(consensus.MEDIAN_TIME_SPAN):
            times.append(entry.block.header.time)
            if entry.height == 0:
                break
            entry = self.blocks[entry.block.header.prev_hash]
        times.sort()
        return times[len(times) // 2]

    def add_block(self, block: Block, now: int) -> ChainUpdate:
        """Главный вход. Исключения: Duplicate, Orphan, Invalid."""
        h = block.hash()
        if h in self.blocks or h in self.invalid:
            raise Duplicate()
        consensus.check_block_standalone(block)

        prev = block.header.prev_hash
        if prev in self.invalid:
            self.invalid.add(h)
            raise Invalid("родительский блок недействителен")
        parent = self.blocks.get(prev)
        if parent is None:
            raise Orphan()
        height = parent.height + 1
        total_work = parent.total_work + block.header.difficulty

        expected = self.next_difficulty(prev)
        if block.header.difficulty != expected:
            raise Invalid(f"сложность {block.header.difficulty} вместо положенной {expected}")
        if block.header.time <= self.median_time_past(prev):
            raise Invalid("время блока не больше медианы 11 предыдущих")
        if block.header.time > now + consensus.MAX_FUTURE_TIME:
            raise Invalid("блок из будущего")

        # Заголовок в порядке — запоминаем блок, даже если его ветка легче.
        self.blocks[h] = BlockEntry(block, height, total_work)

        # Побеждает наибольшая суммарная работа; при равенстве — первая.
        if total_work > self.blocks[self.tip()].total_work:
            try:
                return self.reorganize(h)
            except Invalid:
                self.invalid.add(h)
                raise
        return ChainUpdate()

    def reorganize(self, new_tip: bytes) -> ChainUpdate:
        # 1. Путь от новой вершины до точки расхождения.
        branch = []
        h = new_tip
        while not self.is_on_main(h):
            if h in self.invalid:
                raise Invalid("ветка содержит недействительный блок")
            branch.append(h)
            h = self.blocks[h].block.header.prev_hash
        fork_point = h
        branch.reverse()

        # 2. Откат основной цепи до точки расхождения.
        disconnected = []
        while self.tip() != fork_point:
            disconnected.append(self.disconnect_tip())

        # 3. Применяем новую ветку; плохой блок — возвращаем всё как было.
        for i, h in enumerate(branch):
            try:
                self.connect(h)
            except Invalid:
                self.invalid.add(h)
                for _ in range(i):
                    self.disconnect_tip()
                for block in reversed(disconnected):
                    self.connect(block.hash())
                raise
        return ChainUpdate(branch, disconnected)

    def connect(self, block_hash: bytes) -> None:
        entry = self.blocks[block_hash]
        undo = BlockUndo()
        try:
            self.apply_block_txs(entry.block, entry.height, undo)
        except Invalid:
            self.rollback(undo)
            raise
        self.main.append(block_hash)
        self.undo[block_hash] = undo

    def apply_block_txs(self, block: Block, height: int, undo: BlockUndo) -> None:
        fees = 0
        # По порядку: двойная трата внутри блока ловится сама.
        for tx in block.txs[1:]:
            try:
                fee = self.check_tx(tx, height)
            except Invalid as e:
                raise Invalid(f"транзакция {short(tx.txid())}: {e}") from None
            fees += fee
            self.apply_tx(tx, height, undo)

        coinbase = block.txs[0]
        if coinbase.expiry_height != height:
            raise Invalid("coinbase должна содержать высоту своего блока")
        allowed = consensus.block_reward(height) + fees
        paid = coinbase.output_sum()
        if paid > allowed:
            raise Invalid(f"coinbase платит {paid}, а положено не больше {allowed}")
        self.apply_tx(coinbase, height, undo)

    def check_tx(self, tx: Transaction, height: int) -> int:
        """Проверить обычную транзакцию для блока высоты height. Возвращает
        комиссию. Это и есть ядро UTXO-модели."""
        if tx.is_coinbase():
            raise Invalid("coinbase вне начала блока")
        consensus.check_tx_structure(tx)
        if height > tx.expiry_height:
            raise Invalid("срок действия истёк (expiry_height)")
        sighash = tx.sighash()
        input_sum = 0
        for tx_in in tx.inputs:
            entry = self.utxo.get(tx_in.prev)
            if entry is None:
                raise Invalid("вход ссылается на несуществующий или потраченный выход")
            if entry.coinbase and height - entry.height < consensus.COINBASE_MATURITY:
                raise Invalid("награда за блок ещё не созрела")
            if not crypto.verify(entry.output.owner, sighash, tx_in.signature):
                raise Invalid("неверная подпись")
            input_sum += entry.output.amount
        if input_sum < tx.output_sum():
            raise Invalid("выходов больше, чем входов")
        return input_sum - tx.output_sum()

    def apply_tx(self, tx: Transaction, height: int, undo: BlockUndo) -> None:
        for tx_in in tx.inputs:
            undo.spent.append((tx_in.prev, self.utxo.pop(tx_in.prev)))
        txid = tx.txid()
        for index, out in enumerate(tx.outputs):
            outpoint = OutPoint(txid, index)
            self.utxo[outpoint] = UtxoEntry(out, height, tx.is_coinbase())
            undo.created.append(outpoint)

    def rollback(self, undo: BlockUndo) -> None:
        """Сначала вернуть потраченное, потом удалить созданное: выход,
        созданный и потраченный в одном блоке, есть в обоих списках."""
        for outpoint, entry in undo.spent:
            self.utxo[outpoint] = entry
        for outpoint in undo.created:
            self.utxo.pop(outpoint, None)

    def disconnect_tip(self) -> Block:
        h = self.main.pop()
        self.rollback(self.undo.pop(h))
        return self.blocks[h].block

    def locator(self) -> list[bytes]:
        """Хеши нашей цепи: 10 последних, затем с шагом 2, 4, 8… и генезис."""
        out = []
        height, step = self.height(), 1
        while height > 0:
            out.append(self.main[height])
            if len(out) >= 10:
                step *= 2
            height -= step
        out.append(self.main[0])
        return out

    def find_fork(self, locator: list[bytes]) -> int:
        for h in locator:
            if self.is_on_main(h):
                return self.blocks[h].height
        return 0

    def utxos_of(self, owner: bytes) -> list[tuple[OutPoint, UtxoEntry]]:
        mine = [(op, e) for op, e in self.utxo.items() if e.output.owner == owner]
        return sorted(mine, key=lambda item: item[0])


def short(block_hash: bytes) -> str:
    return block_hash[:6].hex()
