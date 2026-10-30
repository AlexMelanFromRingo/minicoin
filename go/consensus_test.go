package minicoin

import "testing"

func TestRewardSchedule(t *testing.T) {
	if BlockReward(0) != 50*Coin || BlockReward(HalvingInterval-1) != 50*Coin {
		t.Fatal("до первого халвинга награда 50 монет")
	}
	if BlockReward(HalvingInterval) != 25*Coin {
		t.Fatal("после халвинга — 25")
	}
	if BlockReward(64*HalvingInterval) != 0 {
		t.Fatal("после 64 халвингов — 0")
	}
	var total uint64
	for i := uint32(0); i < 64; i++ {
		total += BlockReward(i*HalvingInterval) * uint64(HalvingInterval)
	}
	if total > MaxMoney {
		t.Fatalf("всего %d > MaxMoney", total)
	}
}

func TestRetargetFollowsBlockSpeed(t *testing.T) {
	expected := BlockTime * uint64(RetargetInterval)
	cases := []struct{ old, span, want uint64 }{
		{1000, expected, 1000},
		{1000, expected / 2, 2000},
		{1000, expected * 2, 500},
		// Ограничение ×4 в обе стороны.
		{1000, 0, 4000},
		{1000, expected * 100, 250},
		{1, expected * 100, 1},
	}
	for _, c := range cases {
		if got := Retarget(c.old, c.span); got != c.want {
			t.Errorf("Retarget(%d, %d) = %d, ожидалось %d", c.old, c.span, got, c.want)
		}
	}
}
