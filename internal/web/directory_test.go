package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

// directoryApp creates a SAML app with the user directory on and returns
// its ID and SCIM token.
func newDirectoryApp(t *testing.T, c *http.Client, base string, ks dsig.X509KeyStore, extra url.Values) (string, string) {
	t.Helper()
	id := createApp(t, c, base, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	form := url.Values{"optional": {"1"}, "directory": {"1"}, "match_key": {"nameid"}}
	for k, v := range extra {
		form[k] = v
	}
	resp, err := c.PostForm(base+"/apps/"+id, form)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save settings: %v %d", err, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "SCIM") {
		t.Errorf("turning the directory on should announce the SCIM values under Set up, got %q", loc)
	}
	_, page := get(t, c, base+"/apps/"+id+"/setup")
	m := regexp.MustCompile(`data-copy="([0-9a-f]{48})"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("SCIM token not shown under Set up")
	}
	if !strings.Contains(page, base+"/scim/"+id+"/v2") {
		t.Error("SCIM base URL not shown")
	}
	return id, m[1]
}

func scimCall(t *testing.T, method, u, token, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func TestDirectoryAccountsAtSignIn(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id, _ := newDirectoryApp(t, c, ts.URL, ks, nil)

	// No account: the IdP signs bob in, the app refuses him.
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	_, page := get(t, c, ts.URL+loc)
	if !strings.Contains(page, "you don't have an account in Payroll") {
		t.Errorf("end user not told they have no account:\n%s", mainOf(page))
	}
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page = get(t, c, ts.URL+loc)
	if !strings.Contains(page, "this app has no account for NameID") || !failed(page) {
		t.Error("diagnostics do not fail the Account check")
	}

	if !strings.Contains(page, "No account for bob@example.com") || !strings.Contains(page, "Add bob@example.com to Payroll") {
		t.Error("account-not-found result lacks its headline or one-click add")
	}

	// A near miss is pointed out.
	c.PostForm(ts.URL+"/apps/"+id+"/users", url.Values{"userName": {"bob@corp.example"}})
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page = get(t, c, ts.URL+loc)
	if !strings.Contains(page, "similar identifier") {
		t.Error("near-miss account not explained")
	}

	// Added by hand: signs in, and the welcome screen names the account.
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/users", url.Values{"userName": {"bob@example.com"}, "givenName": {"Bob"}, "familyName": {"Jones"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add user: %d", resp.StatusCode)
	}
	loc = signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	_, page = get(t, c, ts.URL+loc)
	// The account is the email shown on the card, so it isn't repeated.
	if !strings.Contains(page, "Welcome, bob") || strings.Contains(page, "Your account:") {
		t.Errorf("welcome screen after matching the account:\n%s", mainOf(page))
	}

	// Deactivated: refused with its own message.
	_, app := get(t, c, ts.URL+"/apps/"+id+"/users")
	uid := regexp.MustCompile(`/users/([0-9a-f]+)/active`).FindAllStringSubmatch(app, -1)
	if len(uid) != 2 {
		t.Fatalf("want 2 users listed, got %d", len(uid))
	}
	for _, u := range uid {
		c.PostForm(ts.URL+"/apps/"+id+"/users/"+u[1]+"/active", url.Values{"active": {"0"}})
	}
	loc = signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	_, page = get(t, c, ts.URL+loc)
	if !strings.Contains(page, "your account in Payroll is deactivated") {
		t.Errorf("deactivated account not explained:\n%s", mainOf(page))
	}

	// From the diagnostics, one click reactivates and returns to the result.
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page = get(t, c, ts.URL+loc)
	if !strings.Contains(page, "Bob Jones&#39;s account is deactivated") {
		t.Errorf("deactivated headline missing:\n%s", mainOf(page))
	}
	m := regexp.MustCompile(`action="(/apps/[^"]+/active)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no Reactivate button")
	}
	resp, _ = c.PostForm(ts.URL+m[1], url.Values{"active": {"1"}, "back": {loc}})
	if l := resp.Header.Get("Location"); l != loc+"?fixed=reactivated" {
		t.Errorf("reactivate went to %q", l)
	}
}

func TestDirectoryJustInTime(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id, _ := newDirectoryApp(t, c, ts.URL, ks, url.Values{"jit": {"1"}})
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page := get(t, c, ts.URL+loc)
	if !strings.Contains(page, "created just in time") || failed(page) {
		t.Error("just-in-time account not created")
	}
	_, app := get(t, c, ts.URL+"/apps/"+id+"/users")
	if !strings.Contains(app, "Created at sign-in") {
		t.Error("JIT account not listed")
	}
}

func TestSCIMProvisioning(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	state := filepath.Join(t.TempDir(), "state.json")
	ts, c := newTestServer(t, state)
	id, token := newDirectoryApp(t, c, ts.URL, ks, nil)
	base := ts.URL + "/scim/" + id + "/v2"

	if st, _ := scimCall(t, "GET", base+"/Users", "wrong", ""); st != 401 {
		t.Errorf("wrong token: %d, want 401", st)
	}
	if st, m := scimCall(t, "GET", base+"/ServiceProviderConfig", token, ""); st != 200 || m["patch"] == nil {
		t.Errorf("ServiceProviderConfig: %d %v", st, m)
	}

	// The usual IdP sequence: look up, create, then deactivate by PATCH.
	st, m := scimCall(t, "GET", base+"/Users?filter="+url.QueryEscape(`userName eq "bob@example.com"`), token, "")
	if st != 200 || m["totalResults"].(float64) != 0 {
		t.Fatalf("lookup before create: %d %v", st, m)
	}
	st, m = scimCall(t, "POST", base+"/Users", token, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@example.com","name":{"givenName":"Bob","familyName":"Jones"},"emails":[{"value":"bob@example.com","primary":true}],"active":true,"password":"hunter2"}`)
	if st != 201 {
		t.Fatalf("create: %d %v", st, m)
	}
	uid := m["id"].(string)
	if st, _ := scimCall(t, "POST", base+"/Users", token, `{"userName":"BOB@example.com"}`); st != 409 {
		t.Errorf("duplicate create: %d, want 409", st)
	}
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); failed(page) {
		t.Error("provisioned user cannot sign in")
	}

	st, m = scimCall(t, "PATCH", base+"/Users/"+uid, token, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","value":{"active":"False"}}]}`)
	if st != 200 || m["active"] != false {
		t.Fatalf("deactivate: %d %v", st, m)
	}
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "is deactivated") {
		t.Error("deactivated user still signs in")
	}

	// Groups with members.
	st, m = scimCall(t, "POST", base+"/Groups", token, `{"displayName":"Finance","members":[{"value":"`+uid+`"}]}`)
	if st != 201 {
		t.Fatalf("group create: %d %v", st, m)
	}
	gid := m["id"].(string)
	scimCall(t, "PATCH", base+"/Groups/"+gid, token, `{"Operations":[{"op":"remove","path":"members[value eq \"`+uid+`\"]"}]}`)
	if _, m = scimCall(t, "GET", base+"/Groups/"+gid, token, ""); len(m["members"].([]any)) != 0 {
		t.Error("member not removed from group")
	}

	// Activity is listed, the password is not.
	_, page := get(t, c, ts.URL+"/apps/"+id+"/users?view=provisioning")
	for _, want := range []string{"Provisioning", "Created bob@example.com", "Updated bob@example.com (deactivated)", "Rejected: wrong bearer token"} {
		if !strings.Contains(page, want) {
			t.Errorf("app page missing %q", want)
		}
	}
	if strings.Contains(page, "hunter2") {
		t.Error("SCIM password shown in the activity")
	}

	// Users, groups and activity survive a restart; the password was never kept.
	b, _ := os.ReadFile(state)
	if strings.Contains(string(b), "hunter2") {
		t.Error("password written to the state file")
	}
	ts2, c2 := newTestServer(t, state)
	if _, m := scimCall(t, "GET", ts2.URL+"/scim/"+id+"/v2/Users/"+uid, token, ""); m["userName"] != "bob@example.com" {
		t.Errorf("user lost across restart: %v", m)
	}
	if _, page := get(t, c2, ts2.URL+"/apps/"+id+"/users?view=provisioning"); !strings.Contains(page, "Created bob@example.com") {
		t.Error("activity lost across restart")
	}

	if st, _ := scimCall(t, "DELETE", base+"/Users/"+uid, token, ""); st != 204 {
		t.Errorf("delete: %d", st)
	}
	// A new token stops the old one.
	// A new token needs confirming; then the old one stops working.
	if resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/scim-token", nil); !strings.Contains(resp.Header.Get("Location"), "rotate=1") {
		t.Error("token rotated without confirmation")
	}
	if st, _ := scimCall(t, "GET", base+"/Users", token, ""); st != 200 {
		t.Errorf("token stopped working before confirming: %d", st)
	}
	c.PostForm(ts.URL+"/apps/"+id+"/scim-token", url.Values{"confirm": {"1"}})
	if st, _ := scimCall(t, "GET", base+"/Users", token, ""); st != 401 {
		t.Errorf("old token still works after regenerating: %d", st)
	}
}

func TestSCIMOffWithoutDirectory(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	if st, _ := scimCall(t, "GET", ts.URL+"/scim/"+id+"/v2/Users", "", ""); st != 404 {
		t.Errorf("SCIM answered for an app without a directory: %d", st)
	}
	// And sign-ins are not checked against accounts.
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); failed(page) || strings.Contains(page, ">Account<") {
		t.Error("account check ran without a directory")
	}
}

func TestCSVImport(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id, _ := newDirectoryApp(t, c, ts.URL, ks, nil)
	csv := "userName,email,givenName,familyName,active\nbob@example.com,bob@example.com,Bob,Jones,true\namy,amy@example.com,Amy,Lee,false\n"
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/users/import", url.Values{"csv": {csv}})
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "2+new+users") {
		t.Fatalf("import: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, page := get(t, c, ts.URL+"/apps/"+id+"/users")
	if !strings.Contains(page, "Amy Lee") || !strings.Contains(page, "Deactivated") || !strings.Contains(page, "amy, amy@example.com") {
		t.Error("imported users not listed as expected")
	}
	resp, _ = c.PostForm(ts.URL+"/apps/"+id+"/users/import", url.Values{"csv": {"amy,,,,maybe"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad active value accepted: %d", resp.StatusCode)
	}
}

// With a public address for SCIM, Set up and the SCIM responses use it.
func TestSCIMPublicAddress(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id, token := newDirectoryApp(t, c, ts.URL, ks, nil)
	form := url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "optional": {"1"}, "directory": {"1"}, "scim_public": {"https://scim.example.com/path"}}
	resp, _ := c.PostForm(ts.URL+"/apps/"+id, form)
	if body := readBody(resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "with no path") {
		t.Errorf("address with a path: %d", resp.StatusCode)
	}
	form.Set("scim_public", "https://scim.example.com/")
	c.PostForm(ts.URL+"/apps/"+id, form)
	if _, setup := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(setup, "https://scim.example.com/scim/"+id+"/v2") {
		t.Error("Set up does not show the public SCIM URL")
	}
	_, m := scimCall(t, "POST", ts.URL+"/scim/"+id+"/v2/Users", token, `{"userName":"x@example.com"}`)
	if loc, _ := m["meta"].(map[string]any)["location"].(string); !strings.HasPrefix(loc, "https://scim.example.com/scim/") {
		t.Errorf("location %q", loc)
	}
}
