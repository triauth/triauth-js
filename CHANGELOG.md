# Changelog

## [Unreleased]

### Added

- `Triauth.validate` validates group names (`groupName`), lookup codes (`lookupCode`), and device tags (`deviceTag`).

### Changed

- Improve handling of unpaired surrogates and prototype-poisoning names in JSON.
- JSON numbers must be safe integers.
- Attestation entry that is `null` is rejected with the error `invalid_attestations` at stage 1.
- Error codes are strings (e.g., `request_denied`) in place of numbers. A validation error also has a `reason` (e.g., `too_long`). See [Error codes](README.md#error-codes).
- `Triauth.whois` rejects a malformed `lookupCode` with the error `invalid_lookup_code`.

## [1.0.0-beta.3] - 2026-10-17

### Added

- Official support for compressed P-256 public keys in `es256` and `webauthn-es256` key records.

### Changed

- An `es256` or `webauthn-es256` key must be a 65-byte uncompressed point or a 33-byte compressed point. The library rejects all other forms, including the hybrid form that some runtimes accept.

## [1.0.0-beta.2] - 2026-10-14

### Added

- Encrypted responses. Every challenge carries a P-256 public key (`ek`), the authenticator encrypts its response to it with HPKE (RFC 9180), and stage 3 decrypts it with the key kept in the stored `challenge`, which stage 1 now returns as `<challenge>.<key>`. Sign-ins need an authenticator that encrypts responses.
- A `sessionKey` in every `Triauth.authenticate` result, derived by both sides from the encrypted response. `Triauth.ping`, `sign`, `stamp` and `attest` take it in place of a `token`, and their requests travel encrypted under it as `skid` and `request`. After a delegated sign-in it starts with the actor's domain, and the requests go to the actor's authenticator.
- The `ext.permissions` extension, `{permissions:{ping:true, stamp:true}}`. Ping and stamp need their permission. Sign and attest need none, because the user approves each request.

### Changed

- The default `callbackMethod` is now `GET`.

### Removed

- The `pingToken`, `signToken`, `stampToken` and `attestToken` extensions, replaced by `ext.permissions`.
- The `privateProfile` extension. The Triauth Authenticator no longer keeps a private profile and ignores a request for one.

## [1.0.0-beta.1] - initial public beta

First public beta of the official JavaScript client library for the triauth protocol.
