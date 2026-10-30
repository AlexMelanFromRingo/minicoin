"""Параметры сети и правила, которые можно проверить, не зная истории.

Всё здесь — консенсус: если два узла считают по-разному, сеть расколется.
Поэтому только целые числа (// вместо /), никаких float.
"""

from . import block as blk
from .block import Block, BlockHeader
from .tx import Transaction

COIN = 100_000_000  # 1 монета = 10⁸ минимальных единиц

BLOCK_TIME = 10  # целевой интервал между блоками, секунды
RETARGET_INTERVAL = 20  # пересчёт сложности каждые 20 блоков
INITIAL_DIFFICULTY = 1 << 20  # тесты подменяют на 1

INITIAL_REWARD = 50 * COIN
HALVING_INTERVAL = 100_000
MAX_MONEY = 10_000_000 * COIN

# Награду можно потратить только через 10 блоков: если её блок окажется
# в проигравшей ветке, награда исчезнет вместе со всеми, кто её потратил.
COINBASE_MATURITY = 10

MAX_BLOCK_SIZE = 1_000_000
MEDIAN_TIME_SPAN = 11
MAX_FUTURE_TIME = 2 * 60 * 60

GENESIS_TIME = 1_793_232_000  # 2026-10-29 00:00:00 UTC


def block_reward(height: int) -> int:
    halvings = height // HALVING_INTERVAL
    return 0 if halvings >= 64 else INITIAL_REWARD >> halvings


def retarget(old_difficulty: int, actual_span: int) -> int:
    """Блоки шли вдвое быстрее нормы → сложность вдвое выше.
    Изменение за раз ограничено ×4 в обе стороны."""
    expected = BLOCK_TIME * RETARGET_INTERVAL
    span = min(max(actual_span, expected // 4), expected * 4)
    new = old_difficulty * expected // span
    return min(max(new, 1), 2**64 - 1)


def genesis_block() -> Block:
    """Первый блок зашит в код. Coinbase без выходов: премайна нет."""
    coinbase = Transaction([], [], 0)
    header = BlockHeader(
        prev_hash=bytes(32),
        merkle_root=blk.merkle_root([coinbase.txid()]),
        time=GENESIS_TIME,
        difficulty=INITIAL_DIFFICULTY,
        nonce=0,
    )
    return Block(header, [coinbase])


class Invalid(Exception):
    """Нарушение правил консенсуса."""


def check_tx_structure(tx: Transaction) -> None:
    if not tx.is_coinbase() and not tx.outputs:
        raise Invalid("транзакция без выходов")
    if any(out.amount == 0 for out in tx.outputs):
        raise Invalid("выход с нулевой суммой")
    if tx.output_sum() > MAX_MONEY:
        raise Invalid("сумма выходов больше всех монет в мире")
    prevs = [tx_in.prev for tx_in in tx.inputs]
    if len(set(prevs)) != len(prevs):
        raise Invalid("один и тот же выход потрачен дважды в одной транзакции")


def check_block_standalone(block: Block) -> None:
    """Проверки блока без истории — от дешёвых к дорогим."""
    if block.size() > MAX_BLOCK_SIZE:
        raise Invalid("блок больше 1 МБ")
    if not blk.meets_difficulty(block.hash(), block.header.difficulty):
        raise Invalid("хеш заголовка выше цели: работа не доказана")
    if not block.txs or not block.txs[0].is_coinbase():
        raise Invalid("первая транзакция блока должна быть coinbase")
    if any(tx.is_coinbase() for tx in block.txs[1:]):
        raise Invalid("coinbase может быть только первой")
    for tx in block.txs:
        check_tx_structure(tx)
    txids = [tx.txid() for tx in block.txs]
    if len(set(txids)) != len(txids):
        raise Invalid("в блоке повторяется транзакция")
    if blk.merkle_root(txids) != block.header.merkle_root:
        raise Invalid("корень Меркла не совпадает с транзакциями")
