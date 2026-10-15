package web

import (
	"sync"

	"github.com/ryanhebert/ssobench/internal/check"
	"time"

	"github.com/ryanhebert/ssobench/internal/oidc"
)

// pendingTimeout is how long a sign-in or sign-out waits for its answer.
const pendingTimeout = 15 * time.Minute

// pendingSet holds requests sent to an identity provider, waiting for the
// answer, by the ID or state that comes back with it. It has its own lock,
// so it can be used with or without s.mu held. Entries expire after
// pendingTimeout.
type pendingSet[T any] struct {
	mu sync.Mutex
	m  map[string]pendingEntry[T]
}

type pendingEntry[T any] struct {
	v  T
	at time.Time
}

// Put stores v under key, and forgets expired entries.
func (p *pendingSet[T]) Put(key string, v T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.m == nil {
		p.m = map[string]pendingEntry[T]{}
	}
	for k, e := range p.m {
		if now.Sub(e.at) > pendingTimeout {
			delete(p.m, k)
		}
	}
	p.m[key] = pendingEntry[T]{v, now}
}

// Take removes and returns the entry for key: each answer is used once.
func (p *pendingSet[T]) Take(key string) (T, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[key]
	delete(p.m, key)
	if ok && time.Since(e.at) > pendingTimeout {
		ok = false
	}
	return e.v, ok
}

// Peek returns the entry for key without removing it.
func (p *pendingSet[T]) Peek(key string) (T, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[key]
	if ok && time.Since(e.at) > pendingTimeout {
		var zero T
		return zero, false
	}
	return e.v, ok
}

// Delete forgets key.
func (p *pendingSet[T]) Delete(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.m, key)
}

// codePending is an authorization code sign-in (OpenID Connect or OAuth
// 2.1) waiting for the browser to come back.
type codePending struct {
	app      *App
	cfg      oidc.Config
	provider *oidc.Provider
	verifier string
	nonce    string
	resource string // OAuth 2.1: the API asked for
	mode     string // OAuth 2.1: the guided check, if any
	via      string
	started  time.Time
	flow     *Flow
}

// unknownState fills res for a callback whose state matches no sign-in
// this tool started, and returns the flow it logged to.
func (s *Server) unknownState(res *Result, kind string, params Section) *Flow {
	f := s.newFlow(kind, "unknown sign-in")
	s.event(f, LError, "Callback", 0, rowsText(params.Rows), "Callback with a state this tool did not issue")
	res.Title = "Unknown sign-in"
	res.Checks = []check.Result{check.Bad("State", "no sign-in in progress with this state",
		"The sign-in took longer than 15 minutes, SSOBench restarted, or the server redirected here without a request from this tool. Start the sign-in from the app's page.")}
	res.All = []Section{params}
	return f
}
