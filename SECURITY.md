# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's
[private vulnerability reporting](https://github.com/ryanhebert/ssobench/security/advisories/new)
for this repository. Do not open a public issue.

Include what you found, how to reproduce it, and the SSOBench version (`ssobench version`). You can
expect an acknowledgement within a week. Fixes are released as a new version, with credit in the
release notes unless you would rather not be named.

## Supported versions

Only the latest release gets security fixes.

## Scope

SSOBench is a test tool. It shows tokens and assertions in full on purpose, and it is meant to run on
your own machine or a test server. In scope, for example:

- a way for another website, or for someone who has not signed in to the console, to read results,
  tokens or secrets, or to change apps or settings;
- a client secret, console password, SCIM bearer token, or a password sent in a SCIM request showing
  up on a page, in the log, or in a file where it should not be;
- a signature, encryption, token or passkey check that accepts something it should reject.

Out of scope:

- what SSOBench shows by design to someone signed in to the console, or to anyone with access to the
  account that runs it;
- running it on a network address with console sign-in off, which it warns about at start.
