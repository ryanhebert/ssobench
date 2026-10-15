package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestParseExpected(t *testing.T) {
	got := parseExpected("email\n department = Engineering & Ops \n\nEMAIL\n")
	if len(got) != 2 || got[1] != (ExpectedAttr{Name: "department", Value: "Engineering & Ops"}) {
		t.Errorf("%+v", got)
	}
	if s := formatExpected(got); s != "email\ndepartment = Engineering & Ops\n" {
		t.Errorf("%q", s)
	}
}

func TestExpectedAttributes(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})

	// From a result: the attributes it received become the expected ones.
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	rid := loc[strings.LastIndex(loc, "/")+1:]
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "Expect these at every sign-in") {
		t.Fatalf("result lacks Expect these:\n%s", mainOf(page))
	}
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/expected", url.Values{"result": {rid}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expect these: %d", resp.StatusCode)
	}
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/settings"); !strings.Contains(page, "department\n</textarea>") {
		t.Errorf("Settings does not list department:\n%s", mainOf(page))
	}
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "all 1 received") {
		t.Errorf("expected attribute not checked:\n%s", mainOf(page))
	}

	// Missing and different values fail, with what was received.
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"expected": {"department = Sales\nmail"}})
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page := get(t, c, ts.URL+loc)
	if !failed(page) || !strings.Contains(page, "missing mail; department is Engineering &amp; Ops, not Sales") {
		t.Errorf("mismatch not reported:\n%s", mainOf(page))
	}
}
