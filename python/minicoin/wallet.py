"""Кошелёк: один ключ, баланс и сборка платежа.

Кошелёк хранит не монеты, а ключ. Монеты лежат в цепи как выходы,
запертые этим ключом; баланс кошелёк узнаёт у узла.

Упрощение: один ключ на кошелёк, сдача — на тот же адрес. Настоящие
кошельки берут новый адрес для каждой сдачи, чтобы платежи было
труднее связать между собой.
"""

from __future__ import annotations

import os
import re
import socket
from pathlib import Path

from . import crypto, net
from .chain import UtxoEntry
from .consensus import COIN, COINBASE_MATURITY
from .tx import OutPoint, Transaction, TxIn, TxOut

EXPIRY_WINDOW = 100  # через сколько блоков неподтверждённый платёж истечёт


def create(path: Path) -> bytes:
    # O_EXCL: существующий кошелёк не перезаписываем; 0o600: читать ключ может только владелец.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError(f"{path} уже существует, не перезаписываю") from None
    seed = crypto.new_seed()
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    return crypto.public_key(seed)


def load(path: Path) -> bytes:
    """Файл — 32 байта зерна в hex, тот же формат, что у Rust-версии.
    Не зашифрован: кто прочитал файл, тот владеет монетами."""
    text = path.read_text().strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise ValueError(f"{path}: ожидалось 64 hex-символа")
    return bytes.fromhex(text)


def is_spendable(entry: UtxoEntry, next_height: int) -> bool:
    return not entry.coinbase or next_height - entry.height >= COINBASE_MATURITY


def build_payment(
    seed: bytes,
    utxos: list[tuple[OutPoint, UtxoEntry]],
    tip_height: int,
    to: bytes,
    amount: int,
    fee: int,
) -> Transaction:
    next_height = tip_height + 1
    need = amount + fee

    # Выбор монет: крупные первыми — меньше входов, меньше размер и комиссия.
    spendable = sorted(
        (item for item in utxos if is_spendable(item[1], next_height)),
        key=lambda item: item[1].output.amount,
        reverse=True,
    )
    inputs, spent, total = [], [], 0
    for outpoint, entry in spendable:
        if total >= need:
            break
        inputs.append(TxIn(outpoint))
        spent.append(entry.output)
        total += entry.output.amount
    if total < need:
        raise ValueError(f"недостаточно средств: доступно {format_amount(total)}, нужно {format_amount(need)}")

    outputs = [TxOut(amount, to)]
    if total > need:
        outputs.append(TxOut(total - need, crypto.public_key(seed)))
    tx = Transaction(inputs, outputs, next_height + EXPIRY_WINDOW)
    tx.sign(seed, spent)  # суммы входов подписаны: если узел их занизил, подпись выйдет неверной
    return tx


def default_bump_fee(old_fee: int, size: int) -> int:
    """Вдвое больше старой, но не меньше минимума правила замены."""
    from .mempool import MIN_FEE_RATE

    return max(old_fee * 2, old_fee + MIN_FEE_RATE * size)


def bump_payment(
    seed: bytes,
    stuck: Transaction,
    utxos: list[tuple[OutPoint, UtxoEntry]],
    new_fee: int | None = None,
) -> tuple[Transaction, int, int]:
    """Замена застрявшего платежа (replace-by-fee): те же входы и получатель,
    прибавка к комиссии берётся из сдачи.

    utxos — выходы кошелька от узла, включая уже потраченные в мемпуле (среди
    них — входы stuck). new_fee = None — комиссия по умолчанию. Возвращает
    замену, старую и новую комиссии."""
    # Узлу не доверяем. Он мог прислать чужую транзакцию, которая тратит наши
    # выходы на его адрес, или занизить суммы входов, чтобы мы переплатили
    # комиссию. Подпись покрывает все выходы и суммы с владельцами входов
    # (sighash), поэтому переподписываем, только если все подписи сходятся
    # с тем, что прислал узел: значит, это наша транзакция, и суммы входов
    # те самые, что мы подписывали.
    me = crypto.public_key(seed)
    known = dict(utxos)
    spent = []
    for i in stuck.inputs:
        if i.prev not in known:
            raise ValueError(f"узел не прислал вход {i.prev.txid.hex()}:{i.prev.index} — заменять не буду")
        spent.append(known[i.prev].output)
    sighash = stuck.sighash(spent)
    if not stuck.inputs or not all(crypto.verify(me, sighash, i.signature) for i in stuck.inputs):
        raise ValueError("подписи не сходятся: узел прислал не ту транзакцию или неверные суммы входов")
    # Комиссию считаем сами: суммы входов теперь проверены подписями.
    old_fee = sum(out.amount for out in spent) - stuck.output_sum()
    if old_fee < 0:
        raise ValueError("суммы входов и выходов не сходятся")
    if new_fee is None:
        new_fee = default_bump_fee(old_fee, stuck.size())
    if new_fee <= old_fee:
        raise ValueError(f"новая комиссия должна быть больше старой ({format_amount(old_fee)})")
    tx = Transaction([TxIn(i.prev) for i in stuck.inputs], [TxOut(o.amount, o.owner) for o in stuck.outputs], stuck.expiry_height)
    mine = [i for i, out in enumerate(tx.outputs) if out.owner == me]
    if not mine or len(tx.outputs) < 2:
        raise ValueError("в транзакции нет сдачи, из которой можно доплатить комиссию")
    change, extra = mine[-1], new_fee - old_fee
    if tx.outputs[change].amount > extra:
        tx.outputs[change].amount -= extra
    elif tx.outputs[change].amount == extra:
        del tx.outputs[change]  # сдача уходит целиком
    else:
        raise ValueError(
            f"сдачи {format_amount(tx.outputs[change].amount)} не хватает на прибавку к комиссии {format_amount(extra)}"
        )
    tx.sign(seed, spent)
    return tx, old_fee, new_fee


def request(node: str, msg: net.Message) -> net.Message:
    """Отправить запрос узлу и дождаться ответа (приветственный Status пропускаем)."""
    host, _, port = node.rpartition(":")
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        net.send(sock, msg)
        while True:
            reply = net.recv(sock)
            if not isinstance(reply, net.Status):
                return reply


def format_amount(units: int) -> str:
    return f"{units // COIN}.{units % COIN:08d}"


def parse_amount(text: str) -> int:
    """"1.5" → 150 000 000 единиц. Без float: деньги не округляют."""
    # [0-9], а не \d: \d в Python пропускает любые цифры Юникода («١» = 1).
    match = re.fullmatch(r"([0-9]*)(?:\.([0-9]{0,8}))?", text)
    if not match or not (match.group(1) or match.group(2)):
        raise ValueError(f"не сумма: {text}")
    whole = int(match.group(1) or 0)
    frac = int((match.group(2) or "").ljust(8, "0"))
    units = whole * COIN + frac
    if units >= 2**64:
        raise ValueError(f"не сумма: {text}")
    return units
