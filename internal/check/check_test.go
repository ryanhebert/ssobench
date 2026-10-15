package check

import (
	"testing"
	"time"
)

func TestHuman(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second: "45 s", 5 * time.Minute: "5 min", 80 * time.Minute: "1 h 20 min",
		2 * time.Hour: "2 h", 11*time.Hour + 5*time.Minute: "11 h", 47 * time.Hour: "47 h",
		48 * time.Hour: "2 days", 30 * time.Hour: "30 h",
	} {
		if got := Human(d); got != want {
			t.Errorf("Human(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	skew := time.Minute
	for _, c := range []struct {
		name    string
		nb, noa time.Time
		want    Status
	}{
		{"inside", now.Add(-time.Hour), now.Add(time.Hour), Pass},
		{"unbounded", time.Time{}, time.Time{}, Pass},
		{"from the future, within skew", now.Add(30 * time.Second), time.Time{}, Pass},
		{"from the future", now.Add(5 * time.Minute), time.Time{}, Fail},
		{"just expired, within skew", time.Time{}, now.Add(-30 * time.Second), Pass},
		{"expired", time.Time{}, now.Add(-5 * time.Minute), Fail},
	} {
		if got := Window("w", c.nb, c.noa, now, skew); got.Status != c.want || (got.Status == Fail && got.Fix == "") {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

func TestCount(t *testing.T) {
	got := Count([]Result{OK("a", ""), Bad("b", "", "fix"), Meh("c", "", "fix"), Note("d", "")})
	if got.Pass != 1 || got.Fail != 1 || got.Warn != 1 || got.Info != 1 {
		t.Errorf("%+v", got)
	}
	if r := Bad("x", "got", "fix").Mismatch("a", "b"); r.Got != "a" || r.Want != "b" {
		t.Errorf("Mismatch: %+v", r)
	}
	if Rel(time.Unix(100, 0), time.Unix(100, 0)) != "now" || Rel(time.Unix(40, 0), time.Unix(100, 0)) != "1 min ago" {
		t.Error("Rel")
	}
}
