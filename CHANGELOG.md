# Changelog

## [Unreleased]

### Added

- Encrypted responses. Each challenge includes a new P-256 public key (`ek`), and the authenticator encrypts its response to that key with HPKE (RFC 9180). Stage 3 decrypts the response with the private key in the stored `challenge`.

### Changed

- The default `callbackMethod` is now `GET`.
- Stage 1 returns the `challenge` as `<challenge>.<key>`, which is longer than before.
- Sign-ins need an authenticator that encrypts responses.

### Removed

- Mentions of the `privateProfile` extension. The Triauth Authenticator no longer keeps a private profile, and it ignores a request for one.

## [1.0.0-beta.1] - initial public beta

First public beta of the official JavaScript client library for the triauth protocol.
