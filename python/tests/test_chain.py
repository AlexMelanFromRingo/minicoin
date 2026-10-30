"""Те же сценарии, что в rust/src/chain.rs: платежи, двойные траты,
созревание, реорганизация."""

import pytest

from minicoin import block as blk
from minicoin import consensus, crypto
from minicoin.block import Block, BlockHeader
from minicoin.chain import Chain, ChainUpdate, Orphan
from minicoin.consensus import COIN, Invalid
from minicoin.mempool import Mempool
from minicoin.tx import OutPoint, Transaction, TxIn, TxOut

NOW = 2**62


@pytest.fixture(autouse=True)
def easy_mining(monkeypatch):
    """Сложность 1: любой хеш подходит, «майнинг» мгновенный."""
    monkeypatch.setattr(consensus, "INITIAL_DIFFICULTY", 1)


class Miner:
    def __init__(self) -> None:
        self.seed = crypto.new_seed()
        self.key = crypto.public_key(self.seed)


def make_block(chain: Chain, parent: bytes, txs: list[Transaction], to: bytes) -> Block:
    p = chain.get(parent)
    height = p.height + 1
    coinbase = Transaction([], [TxOut(consensus.block_reward(height), to)], height)
    all_txs = [coinbase] + txs
    header = BlockHeader(
        prev_hash=parent,
        merkle_root=blk.merkle_root([tx.txid() for tx in all_txs]),
        time=p.block.header.time + consensus.BLOCK_TIME,
        difficulty=chain.next_difficulty(parent),
    )
    while not blk.meets_difficulty(header.hash(), header.difficulty):
        header.nonce += 1
    return Block(header, all_txs)


def mine(chain: Chain, txs: list[Transaction], to: bytes) -> ChainUpdate:
    return chain.add_block(make_block(chain, chain.tip(), txs, to), NOW)


def reward_of(sender: Miner) -> list[TxOut]:
    """Что тратит sender, по его мнению: монеты в этих тестах — его награда за блок 1."""
    return [TxOut(consensus.block_reward(1), sender.key)]


def pay(sender: Miner, prev: OutPoint, amount: int, to: bytes) -> Transaction:
    tx = Transaction([TxIn(prev)], [TxOut(amount, to)], 1000)
    tx.sign(sender.seed, reward_of(sender))
    return tx


def chain_with_coins(alice: Miner) -> tuple[Chain, OutPoint]:
    chain = Chain()
    mine(chain, [], alice.key)
    coin = OutPoint(chain.block_at(1).txs[0].txid(), 0)
    for _ in range(consensus.COINBASE_MATURITY):
        mine(chain, [], bytes(32))
    return chain, coin


def test_payment_moves_coins():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    mine(chain, [pay(alice, coin, 30 * COIN, bob.key)], alice.key)
    assert [e.output.amount for _, e in chain.utxos_of(bob.key)] == [30 * COIN]
    assert coin not in chain.utxo


def test_coinbase_must_mature():
    alice, bob = Miner(), Miner()
    chain = Chain()
    mine(chain, [], alice.key)
    coin = OutPoint(chain.block_at(1).txs[0].txid(), 0)
    with pytest.raises(Invalid, match="не созрела"):
        chain.check_tx(pay(alice, coin, 1, bob.key), 2)


def test_rejects_invalid_spends():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    h = chain.height() + 1
    with pytest.raises(Invalid, match="подпись"):
        chain.check_tx(pay(bob, coin, 1, bob.key), h)
    with pytest.raises(Invalid, match="выходов больше"):
        chain.check_tx(pay(alice, coin, 51 * COIN, bob.key), h)
    tampered = pay(alice, coin, 1, bob.key)
    tampered.outputs[0].owner = alice.key
    with pytest.raises(Invalid, match="подпись"):
        chain.check_tx(tampered, h)


def test_rejects_signature_over_wrong_amount():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    h = chain.height() + 1
    assert chain.check_tx(pay(alice, coin, COIN, bob.key), h) == consensus.block_reward(1) - COIN
    # Узел соврал кошельку, что вход меньше на монету, и кошелёк подписал
    # эту сумму. Сеть такую подпись отвергает: деньги, которые кошелёк
    # недосчитал, не уйдут майнеру в комиссию.
    tx = pay(alice, coin, COIN, bob.key)
    tx.sign(alice.seed, [TxOut(consensus.block_reward(1) - COIN, alice.key)])
    with pytest.raises(Invalid, match="неверная подпись"):
        chain.check_tx(tx, h)


def test_double_spend_in_one_block_is_rolled_back():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    height = chain.height()
    with pytest.raises(Invalid, match="несуществующий"):
        mine(chain, [pay(alice, coin, 10 * COIN, bob.key), pay(alice, coin, 20 * COIN, bob.key)], alice.key)
    assert chain.height() == height
    assert coin in chain.utxo
    assert chain.utxos_of(bob.key) == []


def test_heavier_branch_wins_and_utxo_follows():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    fork = chain.tip()
    mine(chain, [pay(alice, coin, 5 * COIN, bob.key)], alice.key)

    b1 = make_block(chain, fork, [], bob.key)
    assert chain.add_block(b1, NOW).connected == []
    update = chain.add_block(make_block(chain, b1.hash(), [], bob.key), NOW)
    assert len(update.connected) == 2 and len(update.disconnected) == 1
    assert coin in chain.utxo
    assert all(e.coinbase for _, e in chain.utxos_of(bob.key))


def test_orphan_is_reported():
    alice = Miner()
    chain = Chain()
    orphan = make_block(chain, chain.tip(), [], alice.key)
    orphan.header.prev_hash = bytes([42] * 32)
    with pytest.raises(Orphan):
        chain.add_block(orphan, NOW)


def test_mempool_returns_txs_after_reorg():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    fork = chain.tip()
    tx = pay(alice, coin, 5 * COIN, bob.key)
    mine(chain, [tx], alice.key)

    pool = Mempool()
    b1 = make_block(chain, fork, [], bob.key)
    chain.add_block(b1, NOW)
    update = chain.add_block(make_block(chain, b1.hash(), [], bob.key), NOW)
    pool.refresh(chain, [t for b in update.disconnected for t in b.txs])
    assert len(pool) == 1, "платёж из откаченного блока снова ждёт в мемпуле"


def test_replace_by_fee_policy():
    from minicoin.mempool import should_replace

    assert not should_replace(1000, 200, 1000, 200)  # та же комиссия — спам
    assert should_replace(5000, 200, 1000, 200)
    assert not should_replace(500, 200, 1000, 200)
    assert not should_replace(1001, 200, 1000, 200)  # не оплачивает свою ретрансляцию
    assert should_replace(1200, 200, 1000, 200)
    assert not should_replace(20_000, 10_000, 1000, 200)  # больше сумма, хуже ставка
    assert should_replace(3000, 200, 2000, 400)


def test_mempool_replaces_stuck_payment():
    alice, bob = Miner(), Miner()
    chain, coin = chain_with_coins(alice)
    pool = Mempool()
    reward = consensus.block_reward(1)

    def payment(fee: int) -> Transaction:
        tx = Transaction([TxIn(coin)], [TxOut(10 * COIN, bob.key), TxOut(reward - 10 * COIN - fee, alice.key)], 1000)
        tx.sign(alice.seed, reward_of(alice))
        return tx

    cheap = payment(fee=200)
    pool.add(cheap, chain)
    with pytest.raises(Invalid, match="замена отклонена"):
        pool.add(payment(fee=250), chain)  # +50 не оплачивает 186 байт ретрансляции
    bumped = payment(fee=200 + 186)
    pool.add(bumped, chain)
    assert len(pool) == 1
    txs, fees = pool.select(consensus.MAX_BLOCK_SIZE)
    assert txs == [bumped] and fees == 386
