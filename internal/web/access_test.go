package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

func TestAccessRules(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})

	// No rules: everyone has access, and the tester says so after a sign-in.
	signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/users?view=access"); !strings.Contains(page, "everyone who signs in has access") {
		t.Errorf("access view without rules:\n%s", mainOf(page))
	}

	// A rule bob's attributes don't match: refused, and the tester predicts it.
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/rules", url.Values{"role": {"Admin"}, "source": {"attr"}, "name": {"department"}, "values": {"Finance, Payroll"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add rule: %d", resp.StatusCode)
	}
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/users?view=access"); !strings.Contains(page, "would be refused") || !strings.Contains(page, "department: Engineering &amp; Ops") {
		t.Errorf("tester does not predict the refusal:\n%s", mainOf(page))
	}
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "have access to Payroll") {
		t.Errorf("end user not told they lack access:\n%s", mainOf(page))
	}
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "has no role in Payroll") || !failed(page) {
		t.Error("diagnostics do not fail on access")
	}

	// A second rule that matches gives the role, shown on the welcome screen.
	c.PostForm(ts.URL+"/apps/"+id+"/rules", url.Values{"role": {"Engineer"}, "source": {"attr"}, "name": {"department"}, "values": {"engineering & ops"}})
	loc = signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "Your role: <strong>Engineer</strong>") {
		t.Errorf("welcome screen lacks the role:\n%s", mainOf(page))
	}

	// Removing rules restores open access.
	c.PostForm(ts.URL+"/apps/"+id+"/rules/1/delete", nil)
	c.PostForm(ts.URL+"/apps/"+id+"/rules/1/delete", nil)
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); failed(page) {
		t.Error("sign-in still refused after removing every rule")
	}
}

func TestGroupRuleUsesDirectoryGroups(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id, token := newDirectoryApp(t, c, ts.URL, ks, nil)
	_, m := scimCall(t, "POST", ts.URL+"/scim/"+id+"/v2/Users", token, `{"userName":"bob@example.com","active":true}`)
	scimCall(t, "POST", ts.URL+"/scim/"+id+"/v2/Groups", token, `{"displayName":"Payroll admins","members":[{"value":"`+m["id"].(string)+`"}]}`)
	c.PostForm(ts.URL+"/apps/"+id+"/rules", url.Values{"role": {"Admin"}, "source": {"group"}, "values": {"Payroll admins"}})
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); failed(page) || !strings.Contains(page, "role Admin") {
		t.Errorf("group rule did not grant the role:\n%s", mainOf(page))
	}
}
