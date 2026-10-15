package web

import "slices"

// Pages render snapshots, never the live App or Result: handlers change
// those under s.mu while a template may be reading. Call these with s.mu
// held.

// snapshotApp copies a, along with the lists and records that handlers
// change in place (accounts, groups, sessions).
func snapshotApp(a *App) *App {
	cp := *a
	cp.Users = make([]*User, len(a.Users))
	for i, u := range a.Users {
		uc := *u
		uc.Emails, uc.Groups = slices.Clone(u.Emails), slices.Clone(u.Groups)
		cp.Users[i] = &uc
	}
	cp.Groups = make([]*Group, len(a.Groups))
	for i, g := range a.Groups {
		gc := *g
		gc.Members = slices.Clone(g.Members)
		cp.Groups[i] = &gc
	}
	cp.Sessions = make([]*Session, len(a.Sessions))
	for i, x := range a.Sessions {
		xc := *x
		cp.Sessions[i] = &xc
	}
	cp.ProvLog = slices.Clone(a.ProvLog)
	cp.AccessRules = slices.Clone(a.AccessRules)
	cp.Expected = slices.Clone(a.Expected)
	cp.AuthnContext = slices.Clone(a.AuthnContext)
	return &cp
}

// snapshotResult copies r. A saved result's lists are not changed after
// it is saved; only flags such as Ended are, so a shallow copy is enough.
func snapshotResult(r *Result) *Result {
	cp := *r
	return &cp
}
