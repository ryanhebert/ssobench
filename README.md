# SSOBench

[![Latest release](https://img.shields.io/github/v/release/ryanhebert/ssobench?label=latest)](https://github.com/ryanhebert/ssobench/releases/latest)
[![CI](https://github.com/ryanhebert/ssobench/actions/workflows/ci.yml/badge.svg)](https://github.com/ryanhebert/ssobench/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/ryanhebert/ssobench)](LICENSE)

**See exactly what your identity provider sends, and what is wrong with it.**

When a single sign-on integration fails, the application usually says little more than "sign-in
failed". SSOBench takes the application's place. Register it at your identity provider like any SAML
or OpenID Connect app and sign in. It shows every attribute and claim that arrived, every check that
passed or failed, and how to fix each failure.

I built it because when single sign-on breaks, the people setting it up rarely get to see what their
identity provider actually sent.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/result-dark.png">
  <img alt="A SAML sign-in result: one warning with the fix, then every attribute received" src="docs/images/result-light.png">
</picture>

## What you can do with it

- Prove a new integration works before the real application is ready, or show that a failure isn't
  the application's fault.
- Find out why a sign-in fails: the wrong audience or ACS URL, an expired or rotated certificate, a
  missing attribute, a clock out of sync, a weak algorithm.
- Check an authorization server against OAuth 2.1 (an IETF draft): PKCE required, the implicit and
  password grants refused, and tokens for services through client credentials, checked the way an
  API would check them.
- Test the whole user lifecycle, with SCIM provisioning, roles, sessions and single logout, against
  an app that behaves like a real one.
- Give a test user a realistic sign-in page, and get a reference code back when it fails.
- Attach a step-by-step log of any attempt to a support ticket.

It supports SAML 2.0, OpenID Connect and OAuth 2.1, and runs as a single executable on Windows, macOS
or Linux. Unlike hosted debuggers, it runs on your machine, listening only on `localhost` by default,
so tokens stay there. Unlike a decoder, it acts as the application: it validates signatures,
provisions over SCIM, and keeps sessions and roles.

## Quick start

1. Download the file for your system:

   | System | Download |
   |---|---|
   | Windows | [x64](https://github.com/ryanhebert/ssobench/releases/latest/download/ssobench-windows-amd64.exe), [Arm64](https://github.com/ryanhebert/ssobench/releases/latest/download/ssobench-windows-arm64.exe) |
   | macOS | [Apple silicon](https://github.com/ryanhebert/ssobench/releases/latest/download/ssobench-macos-arm64.tar.gz), [Intel](https://github.com/ryanhebert/ssobench/releases/latest/download/ssobench-macos-amd64.tar.gz) |
   | Linux | [x64](https://github.com/ryanhebert/ssobench/releases/latest/download/ssobench-linux-amd64.tar.gz), [Arm64](https://github.com/ryanhebert/ssobench/releases/latest/download/ssobench-linux-arm64.tar.gz) |

2. Run it. On Windows, open the `.exe`. The binaries are not code-signed yet, so SmartScreen may ask
   you to choose **More info**, then **Run anyway**. On macOS or Linux, extract and start it:

   ```
   tar xzf ssobench-*.tar.gz ssobench && ./ssobench
   ```

   On macOS, a file downloaded in a browser is quarantined. Clear that first:

   ```
   xattr -d com.apple.quarantine ssobench
   ```

3. Your browser opens SSOBench. Choose **New app** and enter your identity provider's metadata URL
   (for SAML) or its issuer and your client ID (for OpenID Connect). Register the values from the
   app's **Set up** tab at your identity provider.

4. Choose **Test sign-in**.

The [guide](docs/guide.md) covers each protocol, user directories and SCIM, sessions, roles, HTTPS,
every option, and running SSOBench as a service. Checksums, software bills of materials and earlier
versions are on the [releases page](https://github.com/ryanhebert/ssobench/releases).

## Security

SSOBench shows tokens and assertions in full, because inspecting them is the point. Run it on your
own machine or a test server, and if other people can reach it, turn on console sign-in (a password
or passkeys) under **Settings**. The [guide](docs/guide.md#security) explains what is stored and
how. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## How it's built

AI coding agents write the code, working from [AGENTS.md](AGENTS.md). I design it, decide what each
check tests and how it explains a failure, set the dependency limits and the tests, and test it with
real sign-ins.

## Contributing

Bug reports, notes on how a particular identity provider behaves, and pull requests are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) and the [roadmap](ROADMAP.md).

## License

Apache License 2.0. See [LICENSE](LICENSE). Third-party licenses are in
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).
