---
model: Fable 5.1
model_id: claude-fable-5-1
scope: validate
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Synchronous, network-free format check that fails closed on every guard and shares its grammar with every flow. Two informational findings only.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.validate

## Summary

`Triauth.validate` is a synchronous format check over two inputs, the identifier and the device name. It performs no DNS lookup and keeps no state. It calls the same `Validator.validateIdentifier` and `Validator.validateDeviceName` that stage 1 of every challenge-response flow, the `Identity` constructor, `Signature.generate`, the include parser and the DNS key parser call, so a pre-check with `validate` yields the same accept or reject decision that stage 1 makes before any network I/O, and no flow depends on the caller running it. The accepted grammar is a lowercase ASCII subset with exactly one `@` sign, no Punycode label, no numeric final label and no trailing dot. The lowercase test compares against `toLowerCase()` instead of folding, so the Kelvin sign and the Turkish dotted I are rejected rather than mapped onto ASCII, and Cyrillic look-alikes, zero-width and bidirectional controls, NBSP, C0 controls, DEL and lone surrogates are all rejected. No two accepted spellings resolve to the same identity records, so a validated identifier is safe to use as an account key as it is. Every argument guard fails closed, including own `__proto__` and `constructor` keys from parsed JSON (102) and a typo in the global `Triauth.config` (103). Size limits run before any pattern scan and the patterns are linear on the bounded input, so a 4-million-character input is rejected in well under a millisecond. The README and the JSDoc both state that `{valid: true}` confirms the format only and is not output sanitization. This scope is safe to use in mission-critical production systems. The two findings are informational.

## Findings

### [VALID-001] [info] Error 103 message text differs from the rest of the API and the README error table
**Location:** `src/api/validation.js:97`
**Description:** `validate` reports a configuration override with an unknown or undefined key as `{code: 103, message: 'Unrecognized configuration override'}`. The challenge-response flows, `check`, `whois`, `verify` and the README error-code table all spell the 103 message as `Unrecognized configuration key`, and the table presents the default messages as the basis for custom or localized messages. An integrator that keys a translation or an alert on the message text sees two spellings for one condition. The code is the same everywhere, so there is no security impact. The current spelling is pinned by `test/internals/test_config.js` and `test/fixtures/json/validate.json`.
**Recommendation:** Return the same message text as the rest of the API, `Unrecognized configuration key`, and update the two pinning tests in lockstep.

### [VALID-002] [info] Exotic argument objects make validate throw instead of returning a result
**Location:** `src/api/validation.js:78`
**Description:** `validate` has no exception boundary. The argument guards call `Array.isArray` and `Object.keys` on the caller's object and read its properties, and `Helpers.mergeConfig` copies the override with `Object.assign`. For a revoked Proxy, a Proxy with a throwing `ownKeys` trap, or an object whose `identifier` accessor throws, the exception propagates to the caller instead of a `{valid: false}` result. The async API methods normalize every throw into `{error: {code: 100}}`, so `validate` is the one public method that can throw. No JSON-shaped input reaches this path. `undefined`, `null`, strings, numbers, BigInt, arrays, `String` objects, frozen objects, null-prototype objects and objects with own `__proto__` or `constructor` keys all return a result (verified at `fc20409`). A throw is itself a fail-closed outcome for a request handler, so the exposure is the availability of one request, under objects the caller constructed.
**Recommendation:** State in the JSDoc and the README that `validate` returns a `{valid, errors}` result for plain data objects and throws for accessor or Proxy objects, so the contract is explicit.
