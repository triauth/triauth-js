# Changelog

## [Unreleased]

### Added

- Encrypted responses. Each challenge includes a new P-256 public key (`ek`), and the authenticator encrypts its response to that key with HPKE (RFC 9180). Stage 3 decrypts the response with the private key in the stored `challenge`.
- A `sessionKey` in every `Triauth.authenticate` result. Your application and the authenticator derive it from the encrypted response.
- The `ext.permissions` extension. A sign-in asks with `{permissions:{ping:true, stamp:true}}`, and the result shows the decision in `ext.permissions`.

### Changed

- The default `callbackMethod` is now `GET`.
- Stage 1 returns the `challenge` as `<challenge>.<key>`, which is longer than before.
- Sign-ins need an authenticator that encrypts responses.
- `Triauth.ping`, `Triauth.sign`, `Triauth.stamp` and `Triauth.attest` take the `sessionKey` of a sign-in instead of a `token`.
- Ping and stamp need their permission. Sign and attest need no permission, because the user approves each request.

### Removed

- Mentions of the `privateProfile` extension. The Triauth Authenticator no longer keeps a private profile, and it ignores a request for one.
- The `pingToken`, `signToken`, `stampToken` and `attestToken` extensions.

## [1.0.0-beta.1] - initial public beta

First public beta of the official JavaScript client library for the triauth protocol.
