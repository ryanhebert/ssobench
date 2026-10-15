package web

import (
	"fmt"
	"log"
	"strings"
	"time"
)

const maxFlows = 50

type Level string

const (
	LInfo  Level = "info"
	LWarn  Level = "warn"
	LError Level = "error"
)

// Event is one step in a sign-in attempt, in the words a person testing SSO
// would use. Secrets are never recorded; tokens are shortened.
type Event struct {
	Time    time.Time     `json:"Time"`
	Offset  time.Duration `json:"Offset"` // since the attempt started
	Level   Level         `json:"Level"`
	Step    string        `json:"Step"`
	Message string        `json:"Message"`
	Took    time.Duration `json:"Took"`
	Detail  string        `json:"Detail"`
}

// Flow is one sign-in attempt, from the button press to the result page.
type Flow struct {
	ID       string    `json:"ID"`
	Kind     string    `json:"Kind"`
	Label    string    `json:"Label"`
	Started  time.Time `json:"Started"`
	ResultID string    `json:"ResultID"`
	Outcome  string    `json:"Outcome"`
	Events   []Event   `json:"Events"`

	Open bool `json:"-"` // display only: expanded in the log view
}

// Tone is how the log colours the flow's outcome: app changes and
// unanswered sign-ins are neutral, not a pass.
func (f Flow) Tone() string {
	switch {
	case f.Kind == "App" || strings.HasSuffix(f.Label, "(settings)") || strings.HasSuffix(f.Label, "(new app)") && f.Outcome == "app created":
		return "neutral"
	case f.Outcome == "":
		return "neutral"
	}
	switch f.Level() {
	case LError:
		return "fail"
	case LWarn:
		return "warn"
	}
	return "pass"
}

// DisplayOutcome is the outcome for the log, with stale sign-ins named.
func (f Flow) DisplayOutcome() string {
	switch {
	case f.Outcome != "":
		return capitalize(f.Outcome)
	case time.Since(f.Started) > 10*time.Minute:
		return "No response yet"
	}
	return "In progress"
}

// Level is the worst event level, for colouring the summary line.
func (f Flow) Level() Level {
	lvl := LInfo
	for _, e := range f.Events {
		if e.Level == LError {
			return LError
		}
		if e.Level == LWarn {
			lvl = LWarn
		}
	}
	return lvl
}

func (s *Server) newFlow(kind, label string) *Flow {
	f := &Flow{ID: randomID(), Kind: kind, Label: label, Started: time.Now()}
	s.mu.Lock()
	s.flows = append([]*Flow{f}, s.flows...)
	if len(s.flows) > maxFlows {
		s.flows = s.flows[:maxFlows]
	}
	s.mu.Unlock()
	return f
}

// event appends to f and echoes a one-line summary to the terminal.
func (s *Server) event(f *Flow, lvl Level, step string, took time.Duration, detail, format string, args ...any) {
	now := time.Now()
	msg := fmt.Sprintf(format, args...)
	s.mu.Lock()
	f.Events = append(f.Events, Event{Time: now, Offset: now.Sub(f.Started), Level: lvl, Step: step, Message: msg, Took: took, Detail: detail})
	s.mu.Unlock()
	if !s.Quiet {
		log.Printf("%s %-4s %s  %-18s %s", now.Format("15:04:05"), f.Kind, f.ID[:6], step, msg)
	}
}

func (s *Server) finish(f *Flow, resultID, outcome string) {
	s.closeFlow(f, resultID, outcome)
	s.saveHistory()
}

// closeFlow records how f ended, without saving: for callers that save
// the history themselves.
func (s *Server) closeFlow(f *Flow, resultID, outcome string) {
	s.mu.Lock()
	f.ResultID, f.Outcome = resultID, outcome
	s.mu.Unlock()
}

// snapshot copies flows under the lock so templates can read them safely.
func (s *Server) snapshot(match func(*Flow) bool) []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Flow
	for _, f := range s.flows {
		if match == nil || match(f) {
			c := *f
			c.Events = append([]Event(nil), f.Events...)
			c.Open = len(out) == 0 // newest expanded, older ones folded
			out = append(out, c)
		}
	}
	return out
}

// Text renders flows as plain text for attaching to a support ticket.
func Text(flows []Flow, version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SSOBench %s log, exported %s\n", version, time.Now().UTC().Format(time.RFC3339))
	for _, f := range flows {
		fmt.Fprintf(&b, "\n=== %s sign-in %s, started %s ===\n", f.Kind, f.Label, f.Started.UTC().Format(time.RFC3339))
		if f.Outcome != "" {
			fmt.Fprintf(&b, "Outcome: %s\n", f.Outcome)
		}
		for _, e := range f.Events {
			took := ""
			if e.Took > 0 {
				took = " (" + e.Took.Round(time.Millisecond).String() + ")"
			}
			fmt.Fprintf(&b, "%s +%-7s %-5s %-20s %s%s\n", e.Time.UTC().Format("15:04:05.000"),
				e.Offset.Round(time.Millisecond), e.Level, e.Step, e.Message, took)
			if e.Detail != "" {
				for _, line := range strings.Split(strings.TrimRight(e.Detail, "\n"), "\n") {
					b.WriteString("        | " + line + "\n")
				}
			}
		}
	}
	return b.String()
}

// shortToken keeps enough of a token to recognize it in other logs.
func shortToken(t string) string {
	if len(t) <= 24 {
		return t
	}
	return fmt.Sprintf("%s…%s (%d chars)", t[:12], t[len(t)-6:], len(t))
}
