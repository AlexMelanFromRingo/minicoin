// Командная строка: узел, кошелёк и разбор блоков.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	mc "github.com/AlexMelanFromRingo/minicoin/go"
)

const help = `minicoin — минимальная, но настоящая криптовалюта

КОШЕЛЁК
  minicoin new-wallet                      создать ключ (файл wallet.key)
  minicoin address                         показать адрес
  minicoin balance                         баланс (спрашивает узел)
  minicoin send <адрес> <сумма> [--fee 0.0001]
  minicoin bump <txid> [--fee сумма]       поднять комиссию застрявшего платежа

УЗЕЛ
  minicoin node [--port 4242] [--peer host:port]... [--mine] [--data data]
               --mine — майнить награду на адрес из кошелька

ОБОЗРЕВАТЕЛЬ
  minicoin info                            сводка узла
  minicoin explain <высота>                побайтовый разбор блока
  minicoin vectors                         тестовые векторы для других реализаций

ОБЩИЕ ОПЦИИ
  --wallet <файл>   файл кошелька (wallet.key)
  --node <адрес>    узел для запросов (127.0.0.1:4242)
`

// args — позиционные аргументы и опции `--имя значение`. `--mine` — флаг без значения.
type args struct {
	positional []string
	options    map[string][]string
}

func parseArgs(argv []string) (*args, error) {
	a := &args{options: map[string][]string{}}
	for i := 0; i < len(argv); i++ {
		name, isOption := strings.CutPrefix(argv[i], "--")
		if !isOption {
			a.positional = append(a.positional, argv[i])
			continue
		}
		value := ""
		if name != "mine" {
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("у --%s нет значения", name)
			}
			i++
			value = argv[i]
		}
		a.options[name] = append(a.options[name], value)
	}
	return a, nil
}

func (a *args) get(name, fallback string) string {
	if values := a.options[name]; len(values) > 0 {
		return values[len(values)-1]
	}
	return fallback
}

func (a *args) has(name string) bool {
	_, ok := a.options[name]
	return ok
}

func (a *args) arg(n int, what string) (string, error) {
	if n < len(a.positional) {
		return a.positional[n], nil
	}
	return "", fmt.Errorf("не указан %s", what)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	a, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	walletPath := a.get("wallet", "wallet.key")
	nodeAddr := a.get("node", fmt.Sprintf("127.0.0.1:%d", mc.DefaultPort))

	command := ""
	if len(a.positional) > 0 {
		command = a.positional[0]
	}
	switch command {
	case "new-wallet":
		key, err := mc.CreateWallet(walletPath)
		if err != nil {
			return err
		}
		fmt.Printf("кошелёк создан: %s\n", walletPath)
		fmt.Printf("адрес: %s\n", mc.EncodeAddress(key))
	case "address":
		seed, err := mc.LoadWallet(walletPath)
		if err != nil {
			return err
		}
		fmt.Println(mc.EncodeAddress(mc.PublicKeyOf(seed)))
	case "balance":
		seed, err := mc.LoadWallet(walletPath)
		if err != nil {
			return err
		}
		owner := mc.PublicKeyOf(seed)
		utxos, err := requestUtxos(nodeAddr, mc.GetUtxos{Owner: owner})
		if err != nil {
			return err
		}
		var spendable, immature uint64
		for _, u := range utxos.Utxos {
			if mc.IsSpendable(u.Entry, utxos.Height+1) {
				spendable += u.Entry.Output.Amount
			} else {
				immature += u.Entry.Output.Amount
			}
		}
		fmt.Printf("адрес:     %s\n", mc.EncodeAddress(owner))
		fmt.Printf("доступно:  %s\n", mc.FormatAmount(spendable))
		fmt.Printf("созревает: %s (награды моложе 10 блоков)\n", mc.FormatAmount(immature))
		fmt.Printf("выходов:   %d (высота цепи %d)\n", len(utxos.Utxos), utxos.Height)
	case "send":
		address, err := a.arg(1, "адрес получателя")
		if err != nil {
			return err
		}
		to, err := mc.DecodeAddress(address)
		if err != nil {
			return err
		}
		amountText, err := a.arg(2, "сумма")
		if err != nil {
			return err
		}
		amount, err := mc.ParseAmount(amountText)
		if err != nil {
			return err
		}
		fee, err := mc.ParseAmount(a.get("fee", "0.0001"))
		if err != nil {
			return err
		}
		seed, err := mc.LoadWallet(walletPath)
		if err != nil {
			return err
		}
		utxos, err := requestUtxos(nodeAddr, mc.GetUtxos{Owner: mc.PublicKeyOf(seed)})
		if err != nil {
			return err
		}
		tx, err := mc.BuildPayment(seed, utxos.Utxos, utxos.Height, to, amount, fee)
		if err != nil {
			return err
		}
		txid := tx.Txid()
		fmt.Printf("txid: %s\n", mc.ToHex(txid[:]))
		return submit(nodeAddr, tx)
	case "bump":
		txidText, err := a.arg(1, "txid")
		if err != nil {
			return err
		}
		bytes, ok := mc.FromHex(txidText)
		if !ok || len(bytes) != 32 {
			return errors.New("txid — 64 hex-символа")
		}
		txid := mc.Hash(bytes)
		seed, err := mc.LoadWallet(walletPath)
		if err != nil {
			return err
		}
		reply, err := mc.Request(nodeAddr, mc.GetMempoolTx{Txid: txid})
		if err != nil {
			return err
		}
		// Комиссию из ответа узла не берём: кошелёк посчитает её сам.
		var stuck mc.Transaction
		switch r := reply.(type) {
		case mc.MempoolTx:
			stuck = r.Tx
		case mc.Text:
			return errors.New(r.Text)
		default:
			return fmt.Errorf("неожиданный ответ узла: %+v", r)
		}
		if stuck.Txid() != txid {
			return errors.New("узел прислал не ту транзакцию")
		}
		// Входы застрявшей транзакции уже потрачены в мемпуле, поэтому просим и
		// такие выходы. Суммам узла не верим: BumpPayment сверит их с подписями.
		utxos, err := requestUtxos(nodeAddr, mc.GetUtxos{Owner: mc.PublicKeyOf(seed), IncludeMempoolSpent: true})
		if err != nil {
			return err
		}
		var fee uint64 // 0 — по умолчанию
		if a.has("fee") {
			if fee, err = mc.ParseAmount(a.get("fee", "")); err != nil {
				return err
			}
		}
		tx, oldFee, newFee, err := mc.BumpPayment(seed, stuck, utxos.Utxos, fee)
		if err != nil {
			return err
		}
		fmt.Printf("комиссия: %s → %s\n", mc.FormatAmount(oldFee), mc.FormatAmount(newFee))
		newTxid := tx.Txid()
		fmt.Printf("txid: %s\n", mc.ToHex(newTxid[:]))
		return submit(nodeAddr, tx)
	case "node":
		port, err := strconv.ParseUint(a.get("port", strconv.Itoa(mc.DefaultPort)), 10, 16)
		if err != nil {
			return errors.New("неверный порт")
		}
		var mineTo *mc.PublicKey
		if a.has("mine") {
			seed, err := mc.LoadWallet(walletPath)
			if err != nil {
				return fmt.Errorf("%v\nдля майнинга нужен кошелёк: minicoin new-wallet --wallet %s", err, walletPath)
			}
			key := mc.PublicKeyOf(seed)
			mineTo = &key
		}
		return mc.RunNode(mc.Config{
			Port:    uint16(port),
			Peers:   a.options["peer"],
			DataDir: a.get("data", "data"),
			MineTo:  mineTo,
		})
	case "info":
		reply, err := mc.Request(nodeAddr, mc.GetInfo{})
		if err != nil {
			return err
		}
		if text, ok := reply.(mc.Text); ok {
			fmt.Println(text.Text)
		} else {
			fmt.Printf("%+v\n", reply)
		}
	case "explain":
		heightText, err := a.arg(1, "номер блока")
		if err != nil {
			return err
		}
		height, err := strconv.ParseUint(heightText, 10, 32)
		if err != nil {
			return errors.New("номер блока — число")
		}
		reply, err := mc.Request(nodeAddr, mc.GetBlock{Height: uint32(height)})
		if err != nil {
			return err
		}
		switch r := reply.(type) {
		case mc.BlockMsg:
			fmt.Print(mc.ExplainBlock(&r.Block, uint32(height)))
		case mc.Text:
			return errors.New(r.Text)
		default:
			return fmt.Errorf("неожиданный ответ узла: %+v", r)
		}
	case "vectors":
		fmt.Print(mc.Vectors())
	default:
		fmt.Print(help)
	}
	return nil
}

func requestUtxos(node string, request mc.GetUtxos) (mc.Utxos, error) {
	reply, err := mc.Request(node, request)
	if err != nil {
		return mc.Utxos{}, err
	}
	utxos, ok := reply.(mc.Utxos)
	if !ok {
		return mc.Utxos{}, errors.New("неожиданный ответ узла")
	}
	return utxos, nil
}

// submit отправляет транзакцию узлу и печатает его ответ.
func submit(node string, tx mc.Transaction) error {
	reply, err := mc.Request(node, mc.TxMsg{Tx: tx})
	if err != nil {
		return err
	}
	if text, ok := reply.(mc.Text); ok {
		fmt.Printf("узел: %s\n", text.Text)
	} else {
		fmt.Printf("узел: %+v\n", reply)
	}
	return nil
}
