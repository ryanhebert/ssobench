# Roadmap

SSOBench aims to test what an identity provider sends to the applications that trust it, over SAML,
OpenID Connect, OAuth and SCIM, and to explain each result in plain language.

## Shipped (v0.1.x)

### SAML

- SP-initiated sign-in with HTTP-Redirect, or HTTP-POST when the identity provider offers only that
- IdP-initiated sign-in, with RelayState shown and a default relay state to test deep links
- Signature verification of the response and the assertion against the metadata certificates
- Checks: status, issuer, destination, recipient, audience, InResponseTo, lifetimes with clock skew,
  replay, SHA-1, certificate expiry, and a certificate rotated since the metadata was loaded (the
  metadata is reloaded automatically)
- Signed AuthnRequests (RSA-SHA256), with a signing key per app published in the SP metadata
- Encrypted assertions: AES-GCM, AES-CBC and Triple DES content, RSA-OAEP and RSA PKCS#1 v1.5 key
  transport, with legacy algorithms flagged
- NameID format, RequestedAuthnContext, ForceAuthn and IsPassive requests, each reported as honored
  or not
- Single logout, SP- and IdP-initiated, signed in both directions, Redirect and POST bindings

### OpenID Connect and OAuth 2.1

- Authorization code flow with PKCE, with or without a client secret
- ID token checks: signature, issuer, audience, `azp`, `exp`, `nbf`, `iat`, nonce, `at_hash`, and
  UserInfo `sub`
- `prompt=login`, `max_age`, `acr_values` and `login_hint`, checked against the tokens
- A scope and claim inspector: scopes requested, granted, and the claims each brought
- RP-initiated and back-channel logout, with logout token validation
- OAuth 2.1 app type: access token validation, refresh token rotation, introspection (RFC 7662),
  client credentials, and probes that PKCE is required and that the implicit grant, and the password
  grant for this client, are refused

### Behaving like an application

- Several apps side by side, each with its own URLs
- A sign-in page and welcome screen per app
- A user directory per app, with matching, just-in-time accounts and CSV import
- A SCIM 2.0 target per app for Users and Groups, with every request logged
- Sessions with lifetimes and idle timeouts, ended by sign-out, logout from the identity provider,
  deactivation or an administrator
- Access rules that give roles from attributes, claims or groups
- Expected attributes, checked at every sign-in

### The tool

- One executable for Windows, Linux and macOS, with apps kept in a state file
- A step-by-step log for every attempt, downloadable as text
- A `decode` command and page for JWTs and SAML messages
- Optional console sign-in with a password or passkeys
- The next free port when 8080 is busy, and HTTPS by default on a network address

## Planned

### SAML

- [ ] Choose the AuthnRequest binding per test (HTTP-Redirect or HTTP-POST)
- [ ] Sign AuthnRequests with RSA-SHA384, RSA-SHA512 or SHA-1, to test which algorithms are accepted
- [ ] Key rollover with two published certificates
- [ ] Several indexed ACS endpoints, requested by URL or index
- [ ] HTTP-Artifact binding probe

### OpenID Connect and OAuth 2.1

- [ ] `response_mode` query, fragment and form_post
- [ ] Refresh token absolute and inactivity lifetimes
- [ ] Client authentication with `client_secret_jwt` and `private_key_jwt`
- [ ] Token revocation (RFC 7009)
- [ ] Front-channel logout
- [ ] Show the remaining lifetime of each token on the result

### Troubleshooting

- [ ] Import a browser trace (HAR or SAML-tracer) and check each message in it
- [ ] Compare two sign-ins side by side

### Later

- [ ] A mock identity provider, for testing applications without a real one
- [ ] A Shared Signals Framework (CAEP and RISC) receiver that shows security events
- [ ] Scoop and winget manifests
