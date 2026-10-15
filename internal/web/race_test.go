package web

import (
	"net/url"
	"sync"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

// Pages render while SCIM deactivates an account, which ends its
// sessions, and new sign-ins open more. Run with -race: pages must only
// ever read snapshots.
func TestPagesRenderDuringProvisioning(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, admin := newTestServer(t, "")
	id, token := newDirectoryApp(t, admin, ts.URL, ks, url.Values{"jit": {"1"}})
	b := browser()
	get(t, b, ts.URL+signInVia(t, b, ts.URL, id, "/a/"+id+"/login", ks, ""))
	_, m := scimCall(t, "GET", ts.URL+"/scim/"+id+"/v2/Users?filter="+url.QueryEscape(`userName eq "bob@example.com"`), token, "")
	uid := m["Resources"].([]any)[0].(map[string]any)["id"].(string)
	set := func(active string) {
		scimCall(t, "PATCH", ts.URL+"/scim/"+id+"/v2/Users/"+uid, token, `{"Operations":[{"op":"replace","path":"active","value":`+active+`}]}`)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, p := range []string{"/", "/apps/" + id, "/apps/" + id + "/users", "/apps/" + id + "/sessions"} {
					get(t, admin, ts.URL+p)
				}
			}
		}()
	}
	for range 6 {
		b := browser()
		get(t, b, ts.URL+signInVia(t, b, ts.URL, id, "/a/"+id+"/login", ks, ""))
		set("false")
		set("true")
	}
	close(stop)
	wg.Wait()
}
