"""Узел: цепь + мемпул + сеть + майнер.

Устройство как в Rust-версии: поток на соединение, всё состояние под
одной блокировкой. Синхронизация:

1. При подключении стороны обмениваются Status.
2. Кто отстал, шлёт GetBlocks со своим локатором.
3. Пир отвечает пачкой до 500 блоков и снова Status; если отставание
   осталось, шаг 2 повторяется.
4. Новые блоки и транзакции рассылаются всем пирам, новому пиру узел
   сразу отдаёт свой мемпул. Блок с неизвестным
   родителем — повод запросить GetBlocks.
"""

from __future__ import annotations

import itertools
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import address, consensus
from . import block as blk
from .block import Block, BlockHeader
from .chain import Chain, Duplicate, Orphan, short
from .consensus import Invalid
from .mempool import Mempool
from .net import (
    BlockMsg, GetBlock, GetBlocks, GetInfo, GetMempoolTx, GetUtxos, MempoolTx, Message, Status, Text, TxMsg, Utxos,
)
from .tx import Transaction, TxOut
from . import net

BLOCKS_PER_BATCH = 500


def now() -> int:
    return int(time.time())


def log(text: str) -> None:
    print(time.strftime("[%H:%M:%S] ", time.gmtime()) + text, flush=True)


@dataclass
class Response:
    """Что сделать после обработки сообщения (уже без блокировки)."""

    reply: list[Message] = field(default_factory=list)
    broadcast: Message | None = None
    disconnect: bool = False


class Node:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        path = data_dir / "blocks.dat"
        self.chain = load_chain(path)
        self.mempool = Mempool()
        self.blocks_file = open(path, "ab")
        self.lock = threading.Lock()  # защищает chain, mempool, blocks_file
        self.peers: dict[int, socket.socket] = {}  # кому рассылать (прислали Status)
        self.peers_lock = threading.Lock()
        self.send_locks: dict[int, threading.Lock] = {}
        self.ids = itertools.count()

    # ── соединения ──────────────────────────────────────────────

    def serve(self, sock: socket.socket) -> None:
        conn_id = next(self.ids)
        send_lock = threading.Lock()
        self.send_locks[conn_id] = send_lock
        sock.settimeout(None)
        try:
            with self.lock:
                status = Status(self.chain.height(), self.chain.tip())
            with send_lock:
                net.send(sock, status)
            while True:
                msg = net.recv(sock)
                if isinstance(msg, Status):
                    with self.peers_lock:
                        is_new = conn_id not in self.peers
                        self.peers[conn_id] = sock
                    if is_new:  # знакомство: отдаём новому пиру свой мемпул
                        with self.lock:
                            txs = [e.tx for e in self.mempool.txs.values()]
                        with send_lock:
                            for tx in txs:
                                net.send(sock, TxMsg(tx))
                response = self.handle(msg)
                with send_lock:
                    for reply in response.reply:
                        net.send(sock, reply)
                if response.broadcast is not None:
                    self.broadcast(response.broadcast, conn_id)
                if response.disconnect:
                    break
        except (OSError, ValueError):
            pass  # обрыв связи или мусор от пира: просто закрываем
        finally:
            with self.peers_lock:
                self.peers.pop(conn_id, None)
            self.send_locks.pop(conn_id, None)
            sock.close()

    def broadcast(self, msg: Message, except_id: int) -> None:
        with self.peers_lock:
            peers = list(self.peers.items())
        for conn_id, sock in peers:
            if conn_id == except_id:
                continue
            try:
                with self.send_locks.get(conn_id, threading.Lock()):
                    net.send(sock, msg)
            except OSError:
                with self.peers_lock:
                    self.peers.pop(conn_id, None)

    # ── обработка сообщений ─────────────────────────────────────

    def handle(self, msg: Message) -> Response:
        response = Response()
        with self.lock:
            chain = self.chain
            match msg:
                case Status(height, _):
                    if height > chain.height():
                        response.reply.append(GetBlocks(chain.locator()))
                case GetBlocks(locator):
                    fork = chain.find_fork(locator)
                    for height in range(fork + 1, min(chain.height(), fork + BLOCKS_PER_BATCH) + 1):
                        response.reply.append(BlockMsg(chain.block_at(height)))
                    response.reply.append(Status(chain.height(), chain.tip()))
                case BlockMsg(block):
                    return self.accept_block(block)
                case TxMsg(tx):
                    try:
                        txid = self.mempool.add(tx, chain)
                        log(f"транзакция {short(txid)} принята в мемпул")
                        response.reply.append(Text(f"принята: {txid.hex()}"))
                        response.broadcast = TxMsg(tx)
                    except Invalid as e:
                        response.reply.append(Text(f"отклонена: {e}"))
                case GetUtxos(owner, include_mempool_spent):
                    # Потраченные в мемпуле не показываем, иначе кошелёк потратит их снова.
                    # Их просит только bump, чтобы узнать суммы входов застрявшей транзакции.
                    utxos = [
                        (op, e)
                        for op, e in chain.utxos_of(owner)
                        if include_mempool_spent or not self.mempool.is_spent(op)
                    ]
                    response.reply.append(Utxos(chain.height(), utxos))
                case GetBlock(height):
                    found = chain.block_at(height)
                    response.reply.append(BlockMsg(found) if found else Text(f"блока на высоте {height} нет"))
                case GetMempoolTx(txid):
                    entry = self.mempool.get(txid)
                    response.reply.append(
                        MempoolTx(entry.fee, entry.tx)
                        if entry
                        else Text("такой транзакции в мемпуле нет (уже в блоке или истекла?)")
                    )
                case GetInfo():
                    with self.peers_lock:
                        peers = len(self.peers)
                    response.reply.append(
                        Text(
                            f"высота:      {chain.height()}\n"
                            f"вершина:     {chain.tip().hex()}\n"
                            f"сложность:   {chain.next_difficulty(chain.tip())} (следующего блока)\n"
                            f"мемпул:      {len(self.mempool)} транзакций\n"
                            f"UTXO:        {len(chain.utxo)}\n"
                            f"пиров:       {peers}\n"
                            f"реализация:  python"
                        )
                    )
        return response

    def accept_block(self, block: Block) -> Response:
        """Принять блок (от пира или своего майнера). Вызывать под self.lock."""
        response = Response()
        h = block.hash()
        try:
            update = self.chain.add_block(block, now())
        except Duplicate:
            return response
        except Orphan:
            response.reply.append(GetBlocks(self.chain.locator()))
            return response
        except Invalid as e:
            log(f"отклонён блок {short(h)}: {e}")
            response.disconnect = True
            return response

        data = block.to_bytes()
        self.blocks_file.write(struct.pack("<I", len(data)) + data)
        self.blocks_file.flush()
        if not update.connected:
            log(f"блок {short(h)} лёг в боковую ветку")
            return response
        if update.disconnected:
            log(f"РЕОРГАНИЗАЦИЯ: откачено {len(update.disconnected)} блоков, подключено {len(update.connected)}")
        returned = [tx for b in update.disconnected for tx in b.txs]
        self.mempool.refresh(self.chain, returned)
        log(f"новая вершина: высота {self.chain.height()} блок {short(h)} ({len(block.txs)} транз.)")
        response.broadcast = BlockMsg(block)
        return response

    # ── майнер ──────────────────────────────────────────────────

    def block_template(self, owner: bytes) -> Block:
        parent, height = self.chain.tip(), self.chain.height() + 1
        txs, fees = self.mempool.select(consensus.MAX_BLOCK_SIZE - 10_000)
        reward = consensus.block_reward(height) + fees
        outputs = [TxOut(reward, owner)] if reward > 0 else []
        coinbase = Transaction([], outputs, height)
        all_txs = [coinbase] + txs
        header = BlockHeader(
            prev_hash=parent,
            merkle_root=blk.merkle_root([tx.txid() for tx in all_txs]),
            time=max(now(), self.chain.median_time_past(parent) + 1),
            difficulty=self.chain.next_difficulty(parent),
        )
        return Block(header, all_txs)

    def mine(self, owner: bytes) -> None:
        """Перебор nonce. Первые 80 байт заголовка не меняются, поэтому их
        собираем один раз и дописываем только nonce. Python в десятки раз
        медленнее Rust, так что в общей сети этот майнер — скромный участник."""
        from blake3 import blake3

        while True:
            with self.lock:
                block = self.block_template(owner)
                tip = self.chain.tip()
            prefix = block.header.to_bytes()[:80]
            limit = blk.MAX_HASH // block.header.difficulty
            started = time.monotonic()
            found = False
            nonce = 0
            while not found:
                for nonce in range(nonce, nonce + 20_000):
                    if int.from_bytes(blake3(prefix + nonce.to_bytes(8, "little")).digest(), "big") <= limit:
                        found = True
                        break
                else:
                    nonce += 1
                    with self.lock:
                        stale = self.chain.tip() != tip
                    if stale or time.monotonic() - started > 10:
                        break
            if found:
                block.header.nonce = nonce
                with self.lock:
                    response = self.accept_block(block)
                if response.broadcast is not None:
                    self.broadcast(response.broadcast, -1)


def load_chain(path: Path) -> Chain:
    """Файл блоков: записи «длина u32 | байты блока». Каждый блок при
    загрузке проверяется заново — отдельной базы UTXO нет."""
    chain = Chain()
    if not path.exists():
        return chain
    data = path.read_bytes()
    pos = 0
    while pos + 4 <= len(data):
        (length,) = struct.unpack_from("<I", data, pos)
        chunk = data[pos + 4 : pos + 4 + length]
        if len(chunk) < length:
            break
        try:
            chain.add_block(Block.from_bytes(chunk), now())
        except (Duplicate, Orphan, Invalid, ValueError):
            pass
        pos += 4 + length
    return chain


def run(port: int, peers: list[str], data_dir: Path, mine_to: bytes | None) -> None:
    node = Node(data_dir)
    log(f"цепь загружена: высота {node.chain.height()}, вершина {short(node.chain.tip())}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen()
    log(f"слушаю порт {port}")

    def accept_loop() -> None:
        while True:
            sock, _ = server.accept()
            threading.Thread(target=node.serve, args=(sock,), daemon=True).start()

    def connect_loop(peer: str) -> None:
        host, _, peer_port = peer.rpartition(":")
        while True:
            try:
                sock = socket.create_connection((host, int(peer_port)), timeout=5)
                log(f"подключился к {peer}")
                node.serve(sock)
                log(f"соединение с {peer} закрыто")
            except OSError:
                pass
            time.sleep(5)

    threading.Thread(target=accept_loop, daemon=True).start()
    for peer in peers:
        threading.Thread(target=connect_loop, args=(peer,), daemon=True).start()
    if mine_to is not None:
        log(f"майнинг на адрес {address.encode(mine_to)}")
        threading.Thread(target=node.mine, args=(mine_to,), daemon=True).start()

    try:
        while True:
            time.sleep(30)
            with node.lock:
                chain = node.chain
                summary = (
                    f"высота {chain.height()} | сложность {chain.next_difficulty(chain.tip())} | "
                    f"мемпул {len(node.mempool)} | UTXO {len(chain.utxo)}"
                )
            with node.peers_lock:
                log(f"{summary} | пиров {len(node.peers)}")
    except KeyboardInterrupt:
        os._exit(0)
