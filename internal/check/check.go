// Package check holds the diagnostic result type shared by the OIDC and SAML
// inspectors.
package check

import (
	"fmt"
	"time"
)

type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	Info Status = "info"
)

// Result is one line in the diagnostics panel. Fix is a plain-English hint
// shown only for warnings and failures.
type Result struct {
	Status Status `json:"Status"`
	Name   string `json:"Name"`
	Detail string `json:"Detail"`
	Fix    string `json:"Fix"`
	// Got and Want, when set, are shown as aligned "Received" and
	// "Expected" lines with the differing part highlighted.
	Got  string `json:"Got"`
	Want string `json:"Want"`
}

// Mismatch returns r with the received and expected values attached.
func (r Result) Mismatch(got, want string) Result {
	r.Got, r.Want = got, want
	return r
}

func OK(name, detail string) Result   { return Result{Status: Pass, Name: name, Detail: detail} }
func Note(name, detail string) Result { return Result{Status: Info, Name: name, Detail: detail} }
func Bad(name, detail, fix string) Result {
	return Result{Status: Fail, Name: name, Detail: detail, Fix: fix}
}
func Meh(name, detail, fix string) Result {
	return Result{Status: Warn, Name: name, Detail: detail, Fix: fix}
}

// Tally counts results by status.
type Tally struct{ Pass, Warn, Fail, Info int }

func Count(rs []Result) Tally {
	var t Tally
	for _, r := range rs {
		switch r.Status {
		case Pass:
			t.Pass++
		case Warn:
			t.Warn++
		case Fail:
			t.Fail++
		case Info:
			t.Info++
		}
	}
	return t
}

// Rel renders t relative to now, e.g. "in 59m0s" or "3s ago".
func Rel(t, now time.Time) string {
	d := t.Sub(now).Round(time.Second)
	switch {
	case d > 0:
		return "in " + Human(d)
	case d < 0:
		return Human(-d) + " ago"
	}
	return "now"
}

// Human writes a duration compactly, as the rest of the UI does: "45 s",
// "5 min", "1 h 20 min", "3 days".
func Human(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 || h >= 10 {
			return fmt.Sprintf("%d h", h)
		}
		return fmt.Sprintf("%d h %d min", h, m)
	}
	if n := int(d.Hours() / 24); n != 1 {
		return fmt.Sprintf("%d days", n)
	}
	return "1 day"
}

// When formats an absolute time with its relative offset.
func When(t, now time.Time) string {
	return fmt.Sprintf("%s (%s)", t.UTC().Format("Jan 2, 15:04:05 UTC"), Rel(t, now))
}

// Window checks a validity window [notBefore, notOnOrAfter) against now with
// the given clock-skew allowance. Zero times are treated as unbounded.
func Window(name string, notBefore, notOnOrAfter, now time.Time, skew time.Duration) Result {
	if !notBefore.IsZero() && now.Add(skew).Before(notBefore) {
		return Bad(name, "not valid until "+When(notBefore, now),
			"It is from the future. The clock on this machine or the identity provider is wrong; sync both with NTP.")
	}
	if !notOnOrAfter.IsZero() && !now.Add(-skew).Before(notOnOrAfter) {
		return Bad(name, "expired "+When(notOnOrAfter, now),
			"It expired before it was checked. Check the clocks, or the lifetime the identity provider gives it.")
	}
	d := "valid"
	if !notBefore.IsZero() {
		d += " from " + When(notBefore, now)
	}
	if !notOnOrAfter.IsZero() {
		d += " until " + When(notOnOrAfter, now)
	}
	return OK(name, d)
}
