# SSOBench

Self-hosted SAML SP, OpenID Connect RP and OAuth 2.1 client test tool in Go. Single binary, embedded
UI, apps kept in an optional JSON state file. Notes for contributors and coding agents.

## Layout

- `main.go` — CLI (`serve` default, `decode`, `version`), TLS, browser launch.
- `internal/check` — the `Result` type every diagnostic returns (status, detail, fix).
- `internal/oidc` — discovery, PKCE code flow, hand-written JWT/JWKS verification, ID token checks.
- `internal/saml` — metadata parsing, AuthnRequest (Redirect/POST), response inspection and checks.
  Signature verification is the only part delegated to `goxmldsig`.
- `internal/decode` — offline JWT/SAML decoding shared by the CLI and the Decode page.
- `internal/scim` — SCIM 2.0 Users and Groups on a `Directory` value (no HTTP); `internal/web/scim.go` is the endpoint.
- `internal/web` — handlers, per-attempt trace log (`trace.go`), embedded templates/CSS/JS in `assets/`.
  `console.go` is optional console sign-in (password and passkeys, set under Settings); `openPath` lists what stays reachable without it.
- `internal/webauthn` — passkey registration and assertion checks on the standard library (CBOR, COSE ES256/EdDSA/RS256); `webauthntest` is a software authenticator for tests.

## Conventions

- Dependencies: Go standard library plus `goxmldsig` and `etree` only. Adding one needs a reason.
- Every check returns a `check.Result` with a plain-language `Fix` for warnings and failures.
- Checks run on signature-verified content only; unverified data is labelled as such.
- Never log or render the client secret. Tokens in the log go through `shortToken`.
- UI: system fonts, no external assets, CSP `default-src 'self'`. Light and dark themes via CSS tokens
  in `assets/app.css`. Sentence case, no emojis.
- Templates: each page is parsed with `layout.html` in its own set (`web.New`), so `title` blocks do
  not collide.
- Tests: `go test ./...`. `internal/web` has end-to-end SAML and OIDC tests against in-process fakes.

## Architecture notes

- Templates are parsed per page with `layout.html` and `app_parts.html`; register a new page in
  `web.New`. `define` cannot be nested inside `with`.
- Pages render snapshots (`snapshot.go`), never a live `*App` or `*Result`. Change state on the live
  app under `s.mu` (use `s.locked`).
- Persisted app fields live in `AppConfig` with JSON tags: that is the state file format.
  `persist_test.go` and `testdata/state-v2.json` guard it; a format change needs a migration.
- Pending requests use `pendingSet[T]`. Settings are parsed by `parseSettings` (pure), then applied
  with `apply` under the lock. State and history saves coalesce through `fileSaver`.
- SAML signing keys are made per app at first use (`keyFor`) and kept in the state file.
