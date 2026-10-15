package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// notPersisted lists App fields, by path, that are deliberately not in the
// state file. Anything else that doesn't survive a save and load is a bug:
// usually a new field added to App but not to savedApp.
var notPersisted = map[string]bool{
	"AppConfig.Legacy": true, // a fixed property of migrated apps; tested in TestV1StateMigratesToLegacyApp
}

// fill sets every exported field reachable from v to a non-zero value.
func fill(v reflect.Value, path string, depth int) {
	if depth > 4 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString("v-" + path)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		if v.Type() == reflect.TypeOf(time.Duration(0)) {
			v.SetInt(int64(time.Second))
		} else {
			v.SetInt(7)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			if f := v.Type().Field(i); f.IsExported() {
				fill(v.Field(i), strings.TrimPrefix(path+"."+f.Name, "."), depth+1)
			}
		}
	case reflect.Pointer:
		if v.Type().Elem().Kind() == reflect.Struct {
			v.Set(reflect.New(v.Type().Elem()))
			fill(v.Elem(), path, depth+1)
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0), path, depth+1)
		v.Set(s)
	}
}

// diff reports exported fields that differ between a and b.
func diff(a, b reflect.Value, path string, out *[]string) {
	if notPersisted[path] {
		return
	}
	if a.Kind() == reflect.Struct && a.Type() != reflect.TypeOf(time.Time{}) {
		for i := 0; i < a.NumField(); i++ {
			if f := a.Type().Field(i); f.IsExported() {
				diff(a.Field(i), b.Field(i), strings.TrimPrefix(path+"."+f.Name, "."), out)
			}
		}
		return
	}
	if !reflect.DeepEqual(a.Interface(), b.Interface()) {
		*out = append(*out, fmt.Sprintf("%s: saved %v, loaded %v", path, a.Interface(), b.Interface()))
	}
}

func TestEveryAppFieldIsSaved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := &App{}
	fill(reflect.ValueOf(want).Elem(), "", 0)
	want.Protocol, want.KeepSecret, want.Legacy = ProtoSAML, true, false
	want.SignKeyPEM, want.SignCertPEM, want.EncKeyPEM, want.EncCertPEM = "", "", "", "" // must be real PEM to load
	s, _ := New("", time.Minute, "test")
	s.Quiet, s.StatePath, s.apps = true, path, []*App{want}
	s.saveState()

	s2, _ := New("", time.Minute, "test")
	s2.Quiet, s2.StatePath = true, path
	if err := s2.LoadState(); err != nil || len(s2.apps) != 1 {
		t.Fatalf("load: %v, %d apps", err, len(s2.apps))
	}
	var problems []string
	diff(reflect.ValueOf(*want), reflect.ValueOf(*s2.apps[0]), "", &problems)
	for _, p := range problems {
		t.Errorf("not saved: %s", p)
	}
}

// The history file keeps its field names: a saved result from before must
// still load.
func TestHistoryFieldNamesAreStable(t *testing.T) {
	r := &Result{}
	fill(reflect.ValueOf(r).Elem(), "", 0)
	b, _ := json.Marshal(r)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, name := range []string{"ID", "AppID", "Checks", "All", "NameID", "SessionIndex", "IDToken", "Ended", "Account", "SessionID", "Auth", "Scopes"} {
		if _, ok := m[name]; !ok {
			t.Errorf("history field %s renamed or missing", name)
		}
	}
}

func TestNewerHistoryFileIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	hist := filepath.Join(dir, "state-history.json")
	os.WriteFile(hist, []byte(`{"version": 9, "results": []}`), 0o600)
	s, _ := New("", time.Minute, "test")
	s.Quiet, s.StatePath = true, state
	if err := s.LoadHistory(); err == nil {
		t.Fatal("newer history file loaded")
	}
	s.saveHistory()
	if b, _ := os.ReadFile(hist); !strings.Contains(string(b), `"version": 9`) {
		t.Error("newer history file overwritten")
	}
}

// testdata/state-v2.json was written by the version before App and
// AppConfig were split, with every field set. Loading and saving it must
// give back exactly the same JSON: existing state files keep everything.
func TestStateFileFormatIsStable(t *testing.T) {
	golden, err := os.ReadFile("testdata/state-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, golden, 0o600)
	s, _ := New("", time.Minute, "test")
	s.Quiet, s.StatePath = true, path
	if err := s.LoadState(); err != nil {
		t.Fatal(err)
	}
	s.saveState()
	again, _ := os.ReadFile(path)
	var a, b any
	json.Unmarshal(golden, &a)
	json.Unmarshal(again, &b)
	if !reflect.DeepEqual(a, b) {
		ga, _ := json.MarshalIndent(a, "", " ")
		gb, _ := json.MarshalIndent(b, "", " ")
		t.Errorf("state file changed on load and save:\nwas %s\nnow %s", ga, gb)
	}
}
