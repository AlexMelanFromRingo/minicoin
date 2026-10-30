"""Совместимость с Rust-версией: каждое значение из ../vectors.txt
(сгенерированного `minicoin vectors` на Rust) должно воспроизводиться."""

from pathlib import Path

from minicoin import address, consensus, crypto
from minicoin import block as blk
from minicoin.block import Block
from minicoin.explain import test_vectors as generate_vectors
from minicoin.tx import Transaction, TxOut

VECTORS = Path(__file__).resolve().parents[2] / "vectors.txt"


def load() -> dict[str, str]:
    pairs = (line.split(" = ", 1) for line in VECTORS.read_text().splitlines() if line)
    return {k: v for k, v in pairs}


def test_python_generates_identical_vectors():
    assert generate_vectors() == VECTORS.read_text()


def test_parse_rust_bytes():
    v = load()
    genesis = Block.from_bytes(bytes.fromhex(v["genesis_block"]))
    assert genesis == consensus.genesis_block()
    assert genesis.hash().hex() == v["genesis_hash"]

    tx = Transaction.from_bytes(bytes.fromhex(v["tx"]))
    assert tx.txid().hex() == v["tx_txid"]
    spent = [TxOut(int(v["tx_spent_amount"]), bytes.fromhex(v["public_key"]))]
    assert tx.sighash(spent).hex() == v["tx_sighash"]
    assert crypto.verify(bytes.fromhex(v["public_key"]), tx.sighash(spent), tx.inputs[0].signature)

    block1 = Block.from_bytes(bytes.fromhex(v["block1"]))
    assert block1.hash().hex() == v["block1_hash"]
    assert blk.meets_difficulty(block1.hash(), block1.header.difficulty)
    consensus.check_block_standalone(block1)

    assert address.decode(v["address"]).hex() == v["public_key"]
