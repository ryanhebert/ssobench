# Contributing

Bug reports and pull requests are welcome.

## Reporting a problem

Open an issue with what you expected, what happened, and the SSOBench version (`ssobench version`).
If it is about a sign-in, the step-by-step log helps most: open the result, then **Download log**.
The log shortens tokens but still shows names, email addresses and URLs, so remove anything private
before attaching it. Security problems go through [SECURITY.md](SECURITY.md), not an issue.

## Changing the code

You need Go 1.25 or later. The `go` command downloads the exact toolchain pinned in `go.mod`.

```sh
go test -race ./...
gofmt -l .        # should print nothing
go vet ./...
```

CI runs these on Linux, Windows and macOS, plus `govulncheck`.

For a larger change, open an issue first. The main conventions are
below; [AGENTS.md](AGENTS.md), the project notes for contributors and coding assistants, has more.

- Dependencies: the Go standard library plus `goxmldsig` and `etree`. A new one needs a good reason.
- Every check returns a `check.Result`, and every warning or failure carries a plain-language fix.
- Checks run only on signature-verified content.
- Never log or display a client secret or password.
- UI: no external assets (the CSP is `default-src 'self'`), sentence case, light and dark themes.
  Check a UI change at phone width and in both themes.
- Add a test with the change. `internal/web` has end-to-end tests against in-process fake identity
  providers.

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
