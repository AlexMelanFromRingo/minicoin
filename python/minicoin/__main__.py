"""Командная строка — те же команды, что у Rust-версии:

    python -m minicoin new-wallet | address | balance | send <адрес> <сумма>
    python -m minicoin node [--port 4242] [--peer host:port]... [--mine]
    python -m minicoin info | explain <высота> | vectors
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import address, crypto, explain, net, node, wallet


def main() -> None:
    parser = argparse.ArgumentParser(prog="minicoin", description="minicoin — минимальная, но настоящая криптовалюта")
    parser.add_argument("--wallet", default="wallet.key", help="файл кошелька")
    parser.add_argument("--node", default=f"127.0.0.1:{net.DEFAULT_PORT}", help="узел для запросов")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("new-wallet", help="создать ключ")
    sub.add_parser("address", help="показать адрес")
    sub.add_parser("balance", help="баланс (спрашивает узел)")
    send = sub.add_parser("send", help="отправить монеты")
    send.add_argument("to")
    send.add_argument("amount")
    send.add_argument("--fee", default="0.0001")
    bump = sub.add_parser("bump", help="поднять комиссию застрявшего платежа")
    bump.add_argument("txid")
    bump.add_argument("--fee", help="новая комиссия (по умолчанию: вдвое больше)")
    run_node = sub.add_parser("node", help="запустить узел")
    run_node.add_argument("--port", type=int, default=net.DEFAULT_PORT)
    run_node.add_argument("--peer", action="append", default=[])
    run_node.add_argument("--mine", action="store_true", help="майнить на адрес из кошелька")
    run_node.add_argument("--data", default="data")
    sub.add_parser("info", help="сводка узла")
    exp = sub.add_parser("explain", help="побайтовый разбор блока")
    exp.add_argument("height", type=int)
    sub.add_parser("vectors", help="тестовые векторы")

    # Опции --wallet/--node допускаются и после команды, как в Rust-версии.
    args, rest = parser.parse_known_args()
    extra = argparse.ArgumentParser(add_help=False)
    extra.add_argument("--wallet")
    extra.add_argument("--node")
    late, unknown = extra.parse_known_args(rest)
    if unknown:
        parser.error(f"неизвестные аргументы: {' '.join(unknown)}")
    wallet_path = Path(late.wallet or args.wallet)
    node_addr = late.node or args.node

    try:
        run(args, wallet_path, node_addr)
    except (ValueError, OSError) as e:
        print(f"ошибка: {e}", file=sys.stderr)
        sys.exit(1)


def run(args: argparse.Namespace, wallet_path: Path, node_addr: str) -> None:
    match args.command:
        case "new-wallet":
            key = wallet.create(wallet_path)
            print(f"кошелёк создан: {wallet_path}")
            print(f"адрес: {address.encode(key)}")
        case "address":
            print(address.encode(crypto.public_key(wallet.load(wallet_path))))
        case "balance":
            owner = crypto.public_key(wallet.load(wallet_path))
            reply = wallet.request(node_addr, net.GetUtxos(owner))
            assert isinstance(reply, net.Utxos), reply
            spendable = sum(e.output.amount for _, e in reply.utxos if wallet.is_spendable(e, reply.height + 1))
            total = sum(e.output.amount for _, e in reply.utxos)
            print(f"адрес:     {address.encode(owner)}")
            print(f"доступно:  {wallet.format_amount(spendable)}")
            print(f"созревает: {wallet.format_amount(total - spendable)} (награды моложе 10 блоков)")
            print(f"выходов:   {len(reply.utxos)} (высота цепи {reply.height})")
        case "send":
            to = address.decode(args.to)
            amount, fee = wallet.parse_amount(args.amount), wallet.parse_amount(args.fee)
            seed = wallet.load(wallet_path)
            reply = wallet.request(node_addr, net.GetUtxos(crypto.public_key(seed)))
            assert isinstance(reply, net.Utxos), reply
            tx = wallet.build_payment(seed, reply.utxos, reply.height, to, amount, fee)
            print(f"txid: {tx.txid().hex()}")
            answer = wallet.request(node_addr, net.TxMsg(tx))
            print(f"узел: {answer.text if isinstance(answer, net.Text) else answer}")
        case "bump":
            seed = wallet.load(wallet_path)
            reply = wallet.request(node_addr, net.GetMempoolTx(bytes.fromhex(args.txid)))
            if isinstance(reply, net.Text):
                raise ValueError(reply.text)
            assert isinstance(reply, net.MempoolTx), reply
            new_fee = wallet.parse_amount(args.fee) if args.fee else wallet.default_bump_fee(reply.fee, reply.tx.size())
            tx = wallet.bump_payment(seed, reply.tx, reply.fee, new_fee)
            print(f"комиссия: {wallet.format_amount(reply.fee)} → {wallet.format_amount(new_fee)}")
            print(f"txid: {tx.txid().hex()}")
            answer = wallet.request(node_addr, net.TxMsg(tx))
            print(f"узел: {answer.text if isinstance(answer, net.Text) else answer}")
        case "node":
            mine_to = crypto.public_key(wallet.load(wallet_path)) if args.mine else None
            node.run(args.port, args.peer, Path(args.data), mine_to)
        case "info":
            answer = wallet.request(node_addr, net.GetInfo())
            print(answer.text if isinstance(answer, net.Text) else answer)
        case "explain":
            answer = wallet.request(node_addr, net.GetBlock(args.height))
            if isinstance(answer, net.Text):
                raise ValueError(answer.text)
            assert isinstance(answer, net.BlockMsg), answer
            print(explain.explain_block(answer.block, args.height), end="")
        case "vectors":
            print(explain.test_vectors(), end="")


if __name__ == "__main__":
    main()
