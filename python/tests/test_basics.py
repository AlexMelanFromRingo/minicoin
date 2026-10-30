import pytest

from minicoin import address, consensus, net
from minicoin import block as blk
from minicoin.chain import UtxoEntry
from minicoin.consensus import COIN
from minicoin.tx import OutPoint, Transaction, TxOut
from minicoin.wallet import format_amount, parse_amount


def test_address_roundtrip_and_typo():
    key = bytes([7] * 32)
    addr = address.encode(key)
    assert addr.startswith("mc1") and len(addr) == 61
    assert address.decode(addr.upper()) == key
    typo = addr[:10] + ("p" if addr[10] == "q" else "q") + addr[11:]
    with pytest.raises(ValueError):
        address.decode(typo)
    with pytest.raises(ValueError):
        address.decode(addr.replace("mc1", "bc1", 1))


def test_amounts():
    assert parse_amount("1.5") == 150_000_000
    assert parse_amount(".5") == 50_000_000
    assert parse_amount("0.00000001") == 1
    for bad in ("1.000000001", "-1", "", "."):
        with pytest.raises(ValueError):
            parse_amount(bad)
    assert format_amount(150_000_001) == "1.50000001"


def test_merkle_has_no_duplication():
    a, b, c = bytes([1] * 32), bytes([2] * 32), bytes([3] * 32)
    assert blk.merkle_root([a]) == a
    assert blk.merkle_root([a, b, c]) != blk.merkle_root([a, b, c, c])


def test_retarget_clamps():
    expected = consensus.BLOCK_TIME * consensus.RETARGET_INTERVAL
    assert consensus.retarget(1000, expected // 2) == 2000
    assert consensus.retarget(1000, 0) == 4000
    assert consensus.retarget(1000, expected * 100) == 250


def test_messages_roundtrip():
    entry = UtxoEntry(TxOut(7, bytes([3] * 32)), 9, True)
    messages = [
        net.Status(5, bytes([1] * 32)),
        net.GetBlocks([bytes([1] * 32), bytes([2] * 32)]),
        net.BlockMsg(consensus.genesis_block()),
        net.TxMsg(Transaction([], [TxOut(5 * COIN, bytes(32))], 3)),
        net.GetUtxos(bytes([4] * 32)),
        net.Utxos(3, [(OutPoint(bytes([5] * 32), 1), entry)]),
        net.GetBlock(2),
        net.GetInfo(),
        net.Text("привет"),
        net.GetMempoolTx(bytes([6] * 32)),
        net.MempoolTx(186, Transaction([], [TxOut(1, bytes(32))], 1)),
    ]
    for msg in messages:
        frame = net.encode(msg)
        assert frame[:4] == b"mini"
        assert net.parse(frame[4], frame[9:]) == msg


def test_bump_takes_extra_fee_from_change():
    from minicoin import crypto
    from minicoin.wallet import build_payment, bump_payment, default_bump_fee

    seed = crypto.new_seed()
    utxos = [(OutPoint(bytes([1] * 32), 0), UtxoEntry(TxOut(10 * COIN, bytes(32)), 1, False))]
    stuck = build_payment(seed, utxos, 100, bytes([9] * 32), 4 * COIN, 200)
    fee = default_bump_fee(200, stuck.size())
    assert fee == 400
    bumped = bump_payment(seed, stuck, 200, fee)
    assert bumped.inputs[0].prev == stuck.inputs[0].prev
    assert bumped.outputs[0] == stuck.outputs[0]
    assert bumped.outputs[1].amount == stuck.outputs[1].amount - 200
    assert bumped.sighash() != stuck.sighash(), "изменилась сдача — значит, нужна новая подпись"
    assert crypto.verify(crypto.public_key(seed), bumped.sighash(), bumped.inputs[0].signature)
    with pytest.raises(ValueError):
        bump_payment(seed, stuck, 200, 7 * COIN)
    assert len(bump_payment(seed, stuck, 200, 6 * COIN).outputs) == 1
