package web

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestFileSaverCoalesces(t *testing.T) {
	var f fileSaver
	var writes, value, saved atomic.Int64
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value.Add(1)
			f.save(func() {
				writes.Add(1)
				time.Sleep(time.Millisecond)
				saved.Store(value.Load())
			})
			// Once save returns, this caller's change is written.
			if saved.Load() < 1 {
				t.Error("save returned before writing")
			}
		}()
	}
	wg.Wait()
	if saved.Load() != 50 {
		t.Errorf("last write saw %d of 50 changes", saved.Load())
	}
	if writes.Load() >= 50 {
		t.Logf("no coalescing this run: %d writes", writes.Load())
	}
}

func TestCapBody(t *testing.T) {
	long := strings.Repeat("é", maxProvBody)
	got := capBody(long)
	if len(got) > maxProvBody+40 || !strings.Contains(got, "more bytes not kept") || !strings.HasPrefix(got, "é") {
		t.Errorf("capBody: %d bytes, ends %q", len(got), got[len(got)-30:])
	}
	if capBody("short") != "short" {
		t.Error("short body changed")
	}
}

func TestSCIMReadsDoNotRewriteState(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	path := filepath.Join(t.TempDir(), "state.json")
	ts, admin := newTestServer(t, path)
	id, token := newDirectoryApp(t, admin, ts.URL, ks, nil)
	before, _ := os.Stat(path)
	time.Sleep(20 * time.Millisecond)
	for range 5 {
		scimCall(t, "GET", ts.URL+"/scim/"+id+"/v2/Users", token, "")
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(before.ModTime()) {
		t.Error("SCIM reads rewrote the state file")
	}
	scimCall(t, "POST", ts.URL+"/scim/"+id+"/v2/Users", token, `{"userName":"new@example.com","active":true}`)
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "new@example.com") {
		t.Error("a SCIM change was not saved")
	}
}
