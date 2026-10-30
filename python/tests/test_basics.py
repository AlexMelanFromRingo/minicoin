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
    for bad in ("1.000000001", "-1", "", ".", "١", "1.٥"):
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
        net.GetUtxos(bytes([4] * 32), True),
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


def coin(amount: int) -> tuple[OutPoint, UtxoEntry]:
    return OutPoint(bytes([1] * 32), 0), UtxoEntry(TxOut(amount, bytes(32)), 1, False)


def test_bump_takes_extra_fee_from_change():
    from minicoin import crypto
    from minicoin.wallet import build_payment, bump_payment, default_bump_fee

    seed = crypto.new_seed()
    utxos = [coin(10 * COIN)]
    stuck = build_payment(seed, utxos, 100, bytes([9] * 32), 4 * COIN, 200)
    fee = default_bump_fee(200, stuck.size())
    assert fee == 400
    bumped, old_fee, new_fee = bump_payment(seed, stuck, utxos)
    assert (old_fee, new_fee) == (200, fee), "старую комиссию кошелёк считает сам"
    assert bumped.inputs[0].prev == stuck.inputs[0].prev
    assert bumped.outputs[0] == stuck.outputs[0]
    assert bumped.outputs[1].amount == stuck.outputs[1].amount - 200
    spent = [utxos[0][1].output]
    assert bumped.sighash(spent) != stuck.sighash(spent), "изменилась сдача — значит, нужна новая подпись"
    assert crypto.verify(crypto.public_key(seed), bumped.sighash(spent), bumped.inputs[0].signature)
    with pytest.raises(ValueError):
        bump_payment(seed, stuck, utxos, 100)
    with pytest.raises(ValueError):
        bump_payment(seed, stuck, utxos, 7 * COIN)
    assert len(bump_payment(seed, stuck, utxos, 6 * COIN)[0].outputs) == 1


def test_bump_refuses_transaction_it_did_not_sign():
    from minicoin import crypto
    from minicoin.wallet import build_payment, bump_payment

    seed = crypto.new_seed()
    utxos = [coin(10 * COIN)]
    stuck = build_payment(seed, utxos, 100, bytes([9] * 32), 4 * COIN, 200)
    # Узел подменил получателя: наши входы, но деньги — ему.
    forged = Transaction.from_bytes(stuck.to_bytes())
    forged.outputs[0].owner = bytes([66] * 32)
    with pytest.raises(ValueError):
        bump_payment(seed, forged, utxos, 400)
    # Чужая транзакция целиком: подписи не нашим ключом.
    stranger = build_payment(crypto.new_seed(), utxos, 100, bytes([9] * 32), COIN, 200)
    with pytest.raises(ValueError):
        bump_payment(seed, stranger, utxos, 400)
    # Узел не показал, что тратит транзакция.
    with pytest.raises(ValueError, match="не прислал вход"):
        bump_payment(seed, stuck, [], 400)


def test_bump_refuses_when_node_lies_about_input_amount():
    from minicoin import crypto
    from minicoin.wallet import build_payment, bump_payment

    seed = crypto.new_seed()
    stuck = build_payment(seed, [coin(10 * COIN)], 100, bytes([9] * 32), 4 * COIN, 200)
    # Узел занизил вход на монету. Поверь кошелёк — он решил бы, что старая
    # комиссия на монету меньше, и переплатил бы. Но подпись не сходится.
    with pytest.raises(ValueError, match="подписи не сходятся"):
        bump_payment(seed, stuck, [coin(9 * COIN)])
    # Чужой владелец входа тоже не проходит.
    op, _ = coin(10 * COIN)
    with pytest.raises(ValueError, match="подписи не сходятся"):
        bump_payment(seed, stuck, [(op, UtxoEntry(TxOut(10 * COIN, bytes([7] * 32)), 1, False))])


def test_signature_covers_spent_outputs():
    from minicoin import crypto
    from minicoin.tx import TxIn

    seed = crypto.new_seed()
    key = crypto.public_key(seed)
    tx = Transaction([TxIn(OutPoint(bytes([1] * 32), 3))], [TxOut(5, bytes([2] * 32))], 100)
    txid, sighash = tx.txid(), tx.sighash([TxOut(7, key)])
    tx.sign(seed, [TxOut(7, key)])
    assert tx.txid() != txid and tx.sighash([TxOut(7, key)]) == sighash

    def verify(spent: list[TxOut]) -> bool:
        return crypto.verify(key, tx.sighash(spent), tx.inputs[0].signature)

    assert verify([TxOut(7, key)])
    # Та же транзакция, но узел назвал другую сумму или другого владельца входа.
    assert not verify([TxOut(6, key)]), "сумма подписана"
    assert not verify([TxOut(7, bytes([2] * 32))]), "владелец подписан"


def test_wallet_file_is_private_and_never_overwritten(tmp_path):
    import os
    import stat

    from minicoin import crypto, wallet

    path = tmp_path / "w.key"
    key = wallet.create(path)
    assert crypto.public_key(wallet.load(path)) == key
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ValueError):
        wallet.create(path)
