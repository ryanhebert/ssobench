package web

import (
	"sync"
	"sync/atomic"
)

// fileSaver writes one file, in order, and coalesces bursts: callers that
// arrive while a write is running wait for it, and then only one of them
// writes again, with a snapshot that includes all their changes. Every
// caller returns once its changes are on disk.
type fileSaver struct {
	mu      sync.Mutex // held while writing
	pending atomic.Bool
}

func (f *fileSaver) save(write func()) {
	f.pending.Store(true)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending.Swap(false) {
		write()
	}
}

// Flush writes the state and history files, for a clean stop.
func (s *Server) Flush() {
	s.saveState()
	s.saveHistory()
}
