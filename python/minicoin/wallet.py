"""Кошелёк: один ключ, баланс и сборка платежа.

Кошелёк хранит не монеты, а ключ. Монеты лежат в цепи как выходы,
запертые этим ключом; баланс кошелёк узнаёт у узла.

Упрощение: один ключ на кошелёк, сдача — на тот же адрес. Настоящие
кошельки берут новый адрес для каждой сдачи, чтобы платежи было
труднее связать между собой.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path

from . import crypto, net
from .chain import UtxoEntry
from .consensus import COIN, COINBASE_MATURITY
from .tx import OutPoint, Transaction, TxIn, TxOut

EXPIRY_WINDOW = 100  # через сколько блоков неподтверждённый платёж истечёт


def create(path: Path) -> bytes:
    if path.exists():
        raise ValueError(f"{path} уже существует, не перезаписываю")
    seed = crypto.new_seed()
    path.write_text(seed.hex() + "\n")
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
    inputs, total = [], 0
    for outpoint, entry in spendable:
        if total >= need:
            break
        inputs.append(TxIn(outpoint))
        total += entry.output.amount
    if total < need:
        raise ValueError(f"недостаточно средств: доступно {format_amount(total)}, нужно {format_amount(need)}")

    outputs = [TxOut(amount, to)]
    if total > need:
        outputs.append(TxOut(total - need, crypto.public_key(seed)))
    tx = Transaction(inputs, outputs, next_height + EXPIRY_WINDOW)
    tx.sign(seed)
    return tx


def default_bump_fee(old_fee: int, size: int) -> int:
    """Вдвое больше старой, но не меньше минимума правила замены."""
    from .mempool import MIN_FEE_RATE

    return max(old_fee * 2, old_fee + MIN_FEE_RATE * size)


def bump_payment(seed: bytes, stuck: Transaction, old_fee: int, new_fee: int) -> Transaction:
    """Замена застрявшего платежа (replace-by-fee): те же входы и получатель,
    прибавка к комиссии берётся из сдачи."""
    if new_fee <= old_fee:
        raise ValueError(f"новая комиссия должна быть больше старой ({format_amount(old_fee)})")
    me = crypto.public_key(seed)
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
    tx.sign(seed)
    return tx


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
    match = re.fullmatch(r"(\d*)(?:\.(\d{0,8}))?", text)
    if not match or not (match.group(1) or match.group(2)):
        raise ValueError(f"не сумма: {text}")
    whole = int(match.group(1) or 0)
    frac = int((match.group(2) or "").ljust(8, "0"))
    units = whole * COIN + frac
    if units >= 2**64:
        raise ValueError(f"не сумма: {text}")
    return units
