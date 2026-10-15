package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// historyFile keeps results, the log and replay protection across
// restarts, next to the state file. It holds real tokens and assertions, so
// it is written readable by the owner only, like the state file.
// historyVersion is the history file format this version writes.
const historyVersion = 1

type historyFile struct {
	Version int                  `json:"version"`
	Results []*Result            `json:"results"`
	Flows   []*Flow              `json:"flows"`
	Seen    []string             `json:"seen_assertions,omitempty"` // version 1
	SeenTil map[string]time.Time `json:"seen_until,omitempty"`
}

// HistoryPath is where history is kept: beside the state file.
func (s *Server) HistoryPath() string {
	if s.StatePath == "" {
		return ""
	}
	return strings.TrimSuffix(s.StatePath, filepath.Ext(s.StatePath)) + "-history.json"
}

// LoadHistory restores results, the log and seen assertion IDs.
func (s *Server) LoadHistory() error {
	p := s.HistoryPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var h historyFile
	if err := json.Unmarshal(b, &h); err != nil {
		return err
	}
	if h.Version > historyVersion {
		// Saving would drop what this version doesn't know: don't.
		s.historyOff = true
		return fmt.Errorf("%s is from a newer SSOBench (version %d); not loading it, and not saving history this session", p, h.Version)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results, s.flows = h.Results, h.Flows
	for _, id := range h.Seen {
		s.seen[id] = time.Now().Add(seenFallback)
	}
	for id, t := range h.SeenTil {
		s.seen[id] = t
	}
	return nil
}

// saveHistory writes the current history atomically. Failures are logged.
func (s *Server) saveHistory() {
	p := s.HistoryPath()
	if p == "" || s.historyOff {
		return
	}
	s.historySaver.save(func() { s.writeHistory(p) })
}

// writeHistory snapshots results, the log and replay markers under the
// lock, then encodes and writes them without it.
func (s *Server) writeHistory(p string) {
	s.mu.Lock()
	h := historyFile{Version: historyVersion}
	for _, r := range s.results {
		h.Results = append(h.Results, snapshotResult(r))
	}
	for _, f := range s.flows {
		c := *f
		c.Events = append([]Event(nil), f.Events...)
		h.Flows = append(h.Flows, &c)
	}
	h.SeenTil = map[string]time.Time{}
	for id, t := range s.seen {
		h.SeenTil[id] = t
	}
	s.mu.Unlock()
	b, err := json.Marshal(h)
	if err == nil {
		err = writeOwnerOnly(p, b)
	}
	if err != nil {
		s.logf("could not save history to %s: %v", p, err)
	}
}

// writeOwnerOnly replaces path atomically with data, mode 0600.
func writeOwnerOnly(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ssobench-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		_ = os.Chmod(tmp.Name(), 0o600)
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
