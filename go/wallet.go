// Кошелёк: один ключ, баланс и сборка платежа.
//
// Кошелёк не хранит монет, он хранит ключ. Монеты лежат в цепи как
// выходы, запертые этим ключом. Чтобы узнать баланс, кошелёк спрашивает
// у узла выходы своего ключа.
//
// Упрощение: один ключ на кошелёк, сдача возвращается на тот же адрес.
// Настоящие кошельки берут новый адрес для каждой сдачи, чтобы платежи
// было труднее связать между собой.
package minicoin

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ExpiryWindow — через сколько блоков неподтверждённый платёж истечёт.
const ExpiryWindow uint32 = 100

// readTimeout: узел, который не отвечает, не должен подвесить кошелёк.
const readTimeout = 10 * time.Second

// pathError: «путь: причина», без имени системного вызова, которое добавляет Go.
func pathError(path string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("%s: %v", path, err)
}

func CreateWallet(path string) (PublicKey, error) {
	// O_EXCL: существующий кошелёк не перезаписываем; 0600: читать ключ может только владелец.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return PublicKey{}, fmt.Errorf("%s уже существует, не перезаписываю", path)
	}
	if err != nil {
		return PublicKey{}, pathError(path, err)
	}
	seed := NewSeed()
	_, err = file.WriteString(ToHex(seed[:]) + "\n")
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return PublicKey{}, pathError(path, err)
	}
	return PublicKeyOf(seed), nil
}

// LoadWallet: файл кошелька — 32 байта зерна в hex. Не зашифрован: кто
// прочитал файл, тот владеет монетами.
func LoadWallet(path string) (Seed, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return Seed{}, pathError(path, err)
	}
	bytes, ok := FromHex(strings.TrimSpace(string(text)))
	if !ok || len(bytes) != 32 {
		return Seed{}, fmt.Errorf("%s: ожидалось 64 hex-символа", path)
	}
	return Seed(bytes), nil
}

// IsSpendable: можно ли потратить выход в блоке nextHeight.
func IsSpendable(entry UtxoEntry, nextHeight uint32) bool {
	return !entry.Coinbase || satSub32(nextHeight, entry.Height) >= CoinbaseMaturity
}

// BuildPayment собирает и подписывает платёж amount на to с комиссией fee.
func BuildPayment(seed Seed, utxos []Utxo, tipHeight uint32, to PublicKey, amount, fee uint64) (Transaction, error) {
	nextHeight := tipHeight + 1
	need := amount + fee
	if need < amount {
		return Transaction{}, errors.New("слишком большая сумма")
	}

	// Выбор монет: крупные первыми. Так входов меньше, а значит меньше
	// размер транзакции и нужная комиссия.
	var spendable []Utxo
	for _, u := range utxos {
		if IsSpendable(u.Entry, nextHeight) {
			spendable = append(spendable, u)
		}
	}
	slices.SortStableFunc(spendable, func(a, b Utxo) int {
		return cmp.Compare(b.Entry.Output.Amount, a.Entry.Output.Amount) // по убыванию
	})

	var inputs []TxIn
	var total uint64
	for _, u := range spendable {
		if total >= need {
			break
		}
		inputs = append(inputs, TxIn{Prev: u.OutPoint})
		total += u.Entry.Output.Amount
	}
	if total < need {
		return Transaction{}, fmt.Errorf("недостаточно средств: доступно %s, нужно %s", FormatAmount(total), FormatAmount(need))
	}

	outputs := []TxOut{{Amount: amount, Owner: to}}
	if change := total - need; change > 0 {
		outputs = append(outputs, TxOut{Amount: change, Owner: PublicKeyOf(seed)})
	}
	tx := Transaction{Inputs: inputs, Outputs: outputs, ExpiryHeight: nextHeight + ExpiryWindow}
	tx.Sign(seed)
	return tx, nil
}

// DefaultBumpFee — комиссия замены по умолчанию: вдвое больше старой, но не
// меньше, чем требует правило замены (старая + MinFeeRate × размер, см. mempool.go).
func DefaultBumpFee(oldFee uint64, size int) uint64 {
	doubled := oldFee * 2
	if oldFee > math.MaxUint64/2 {
		doubled = math.MaxUint64 // насыщение, как saturating_mul
	}
	return max(doubled, oldFee+MinFeeRate*uint64(size))
}

// BumpPayment — замена застрявшего платежа (replace-by-fee): те же входы и
// тот же получатель, а прибавка к комиссии берётся из сдачи. Получатель
// получит ровно столько же; если сдачи не хватает, замена невозможна.
func BumpPayment(seed Seed, stuck Transaction, oldFee, newFee uint64) (Transaction, error) {
	if newFee <= oldFee {
		return Transaction{}, fmt.Errorf("новая комиссия должна быть больше старой (%s)", FormatAmount(oldFee))
	}
	// Узлу не доверяем: он мог прислать чужую транзакцию, которая тратит наши
	// выходы на его адрес. Переподписываем только то, что уже подписали сами:
	// подпись покрывает все выходы (sighash), значит, получатель и суммы те же.
	me := PublicKeyOf(seed)
	sighash := stuck.Sighash()
	signedByMe := len(stuck.Inputs) > 0
	for _, input := range stuck.Inputs {
		signedByMe = signedByMe && Verify(me, sighash, input.Signature)
	}
	if !signedByMe {
		return Transaction{}, errors.New("эту транзакцию подписывал не этот кошелёк — заменять не буду")
	}
	// Копия: срезы входов и выходов не должны делиться со старой транзакцией.
	tx := Transaction{
		Inputs:       slices.Clone(stuck.Inputs),
		Outputs:      slices.Clone(stuck.Outputs),
		ExpiryHeight: stuck.ExpiryHeight,
	}
	extra := newFee - oldFee
	change := -1
	for i, output := range tx.Outputs {
		if output.Owner == me {
			change = i
		}
	}
	if change < 0 || len(tx.Outputs) < 2 {
		return Transaction{}, errors.New("в транзакции нет сдачи, из которой можно доплатить комиссию")
	}
	switch amount := tx.Outputs[change].Amount; {
	case amount > extra:
		tx.Outputs[change].Amount -= extra
	case amount == extra:
		// Сдача уходит целиком: выход исчезает, транзакция становится короче.
		tx.Outputs = slices.Delete(tx.Outputs, change, change+1)
	default:
		return Transaction{}, fmt.Errorf("сдачи %s не хватает на прибавку к комиссии %s", FormatAmount(amount), FormatAmount(extra))
	}
	tx.Sign(seed)
	return tx, nil
}

// Request — запрос к узлу: отправить сообщение и дождаться ответа.
func Request(node string, message Message) (Message, error) {
	stream, err := net.Dial("tcp", node)
	if err != nil {
		return nil, fmt.Errorf("не подключиться к узлу %s: %v", node, err)
	}
	defer stream.Close()
	if err := Send(stream, message); err != nil {
		return nil, err
	}
	for {
		_ = stream.SetReadDeadline(time.Now().Add(readTimeout))
		reply, err := Recv(stream)
		if err != nil {
			return nil, fmt.Errorf("узел не ответил: %v", err)
		}
		// Узел здоровается со всеми, кто подключился. Это не ответ.
		if _, ok := reply.(Status); !ok {
			return reply, nil
		}
	}
}

func FormatAmount(units uint64) string {
	return fmt.Sprintf("%d.%08d", units/Coin, units%Coin)
}

// ParseAmount: "1.5" → 150 000 000 единиц. Без float: деньги не округляют.
func ParseAmount(text string) (uint64, error) {
	bad := fmt.Errorf("не сумма: %s", text)
	whole, frac, _ := strings.Cut(text, ".")
	if whole == "" && frac == "" || len(frac) > 8 || !isDigits(whole) || !isDigits(frac) {
		return 0, bad
	}
	var units uint64
	if whole != "" {
		w, err := strconv.ParseUint(whole, 10, 64)
		if err != nil || w > math.MaxUint64/Coin {
			return 0, bad
		}
		units = w * Coin
	}
	f, _ := strconv.ParseUint(frac+strings.Repeat("0", 8-len(frac)), 10, 64)
	if units+f < units {
		return 0, bad
	}
	return units + f, nil
}

func isDigits(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}
