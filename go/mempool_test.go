package minicoin

import "testing"

func TestReplaceByFeePolicy(t *testing.T) {
	cases := []struct {
		why     string
		newFee  uint64
		newSize int
		oldFee  uint64
		oldSize int
		want    bool
	}{
		{"та же комиссия — не замена, а спам", 1000, 200, 1000, 200, false},
		{"заметно дороже — замена выгодна", 5000, 200, 1000, 200, true},
		{"дешевле — никогда", 500, 200, 1000, 200, false},
		{"«на единицу больше» не оплачивает собственную ретрансляцию", 1001, 200, 1000, 200, false},
		{"ровно старая комиссия + 1 ед/байт × размер — оплачивает", 1200, 200, 1000, 200, true},
		{"больше по сумме, но хуже по ставке (огромная замена)", 20_000, 10_000, 1000, 200, false},
		{"несколько конфликтующих: комиссии и размеры суммируются", 3000, 200, 2000, 400, true},
	}
	for _, c := range cases {
		if got := ShouldReplace(c.newFee, c.newSize, c.oldFee, c.oldSize); got != c.want {
			t.Errorf("%s: ShouldReplace = %v", c.why, got)
		}
	}
}
