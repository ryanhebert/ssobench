package web

import (
	"testing"
	"time"
)

func TestPendingSet(t *testing.T) {
	var p pendingSet[int]
	p.Put("a", 1)
	if v, ok := p.Peek("a"); !ok || v != 1 {
		t.Fatal("peek")
	}
	if v, ok := p.Take("a"); !ok || v != 1 {
		t.Fatal("take")
	}
	if _, ok := p.Take("a"); ok {
		t.Error("taken twice")
	}
	p.Put("old", 2)
	p.m["old"] = pendingEntry[int]{2, time.Now().Add(-pendingTimeout - time.Second)}
	if _, ok := p.Peek("old"); ok {
		t.Error("expired entry returned")
	}
	p.Put("new", 3)
	if _, ok := p.m["old"]; ok {
		t.Error("expired entry not pruned")
	}
}
