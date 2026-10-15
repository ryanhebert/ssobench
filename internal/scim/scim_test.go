package scim

import (
	"net/url"
	"strings"
	"testing"
)

func TestUsersAndGroups(t *testing.T) {
	d := &Directory{}
	base := "https://sp.example/scim/app/v2"
	res := Users("POST", nil, d, "", []byte(`{"userName":"alice@example.com","name":{"givenName":"Alice"},"emails":[{"value":"alice@example.com"}],"active":true}`), base)
	if res.Status != 201 || !res.Changed || len(d.Users) != 1 {
		t.Fatalf("create: %+v", res)
	}
	alice := d.Users[0]
	if res := Users("POST", nil, d, "", []byte(`{"userName":"ALICE@example.com"}`), base); res.Status != 409 {
		t.Errorf("duplicate userName: %d", res.Status)
	}
	q := url.Values{"filter": {`userName eq "alice@example.com"`}}
	if res := Users("GET", q, d, "", nil, base); res.Status != 200 || res.Body.(map[string]any)["totalResults"] != 1 {
		t.Errorf("filter: %+v", res)
	}
	if res := Users("GET", url.Values{"filter": {`userName sw "a"`}}, d, "", nil, base); res.Status != 400 {
		t.Errorf("unsupported filter: %d", res.Status)
	}
	res = Users("PATCH", nil, d, alice.ID, []byte(`{"Operations":[{"op":"replace","path":"active","value":false}]}`), base)
	if res.Status != 200 || alice.Active || !strings.Contains(res.Summary, "deactivated") {
		t.Errorf("deactivate: %+v active=%v", res, alice.Active)
	}

	res = Groups("POST", nil, d, "", []byte(`{"displayName":"Admins","members":[{"value":"`+alice.ID+`"}]}`), base)
	if res.Status != 201 || len(d.Groups) != 1 || len(d.Groups[0].Members) != 1 {
		t.Fatalf("group: %+v", res)
	}
	if res := Users("DELETE", nil, d, alice.ID, nil, base); res.Status != 204 || len(d.Users) != 0 || len(d.Groups[0].Members) != 0 {
		t.Errorf("delete: %+v users=%d members=%v", res, len(d.Users), d.Groups[0].Members)
	}
	if res := Users("GET", nil, d, "nope", nil, base); res.Status != 404 {
		t.Errorf("unknown id: %d", res.Status)
	}
}

func TestRedactHidesPasswords(t *testing.T) {
	if got := Redact([]byte(`{"userName":"a","password":"hunter2"}`)); got == "" || strings.Contains(got, "hunter2") {
		t.Errorf("password shown: %s", got)
	}
}
