---
model: Fable 5.1
model_id: claude-fable-5-1
scope: validate
lib_version: 1.0.0-beta.2
commit: 7a97e15
reviewed_at: 2026-10-17
status: good-to-go
summary: Synchronous, network-free format check that fails closed on every guard and shares its grammar with every flow. Three informational findings only.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.validate

## Summary

`Triauth.validate` is a synchronous format check over two inputs, the identifier and the device name. It performs no DNS lookup, reads no clock or randomness, keeps no state and writes no log line. It calls the same `Validator.validateIdentifier` and `Validator.validateDeviceName` that stage 1 and stage 3 of every challenge-response flow, the `Identity` constructor behind `check` and `whois`, `Signature.generate`, the signature envelope parser, the include parser, the key-record parser and the groups-record parser call. A pre-check with `validate` therefore predicts the verdict that stage 1 reaches on the identifier before any network I/O, and no flow depends on the caller running it. The accepted identifier grammar is a lowercase ASCII subset with exactly one `@` sign, a name part of at most 63 characters, LDH domain labels of at most 63 characters, no Punycode label, no numeric final label and no trailing dot. The underscore of the `_at` marker is outside both grammars, so no two accepted identifiers address the same identity records, and a validated identifier is safe to use as an account key as it is. The lowercase test compares against `toLowerCase()` instead of folding, so the Kelvin sign and the Turkish dotted I are rejected rather than mapped onto ASCII. Every other non-ASCII character, including Cyrillic look-alikes, zero-width and bidirectional controls, NBSP, BOM, C0 controls, DEL and lone surrogates, fails the ASCII grammar of the name part or of the domain. The argument guards fail closed for every JSON-shaped input, including own `__proto__` and `constructor` keys (102), and a typo or an undefined value in the global `Triauth.config` is reported as 103. Size limits run before any pattern scan and the patterns are linear on the bounded input. The slowest input of accepted length takes about 3 microseconds per call, and an input of 8 million characters is rejected in about 1 microsecond. Each call returns fresh result objects, so a caller cannot alter the messages of a later call. The messages are static table entries that never echo the input. The README and the JSDoc both state that `{valid: true}` confirms the format only and is not output sanitization. The unit tests, the config-guard tests and the JSON conformance suite of this scope pass at 7a97e15. This scope is safe to use in mission-critical production systems. The three findings are informational.

## Findings

### [VALID-001] [info] Error 103 message text differs from the rest of the API and the README error table
**Location:** `src/api/validation.js:97`
**Description:** `validate` reports a configuration override with an unknown or undefined key as `{code: 103, message: 'Unrecognized configuration override'}`. The challenge-response flows, `check`, `whois`, `verify` and the README error-code table all spell the 103 message as `Unrecognized configuration key`, and the table presents the default messages as the basis for custom or localized messages. An integrator that keys a translation or an alert on the message text sees two spellings for one condition. The code is the same everywhere, so there is no security impact. The current spelling is pinned by `test/internals/test_config.js:84` and by the `CONFIG GUARD 103` case of `test/fixtures/json/validate.json` (verified at 7a97e15).
**Recommendation:** Return the same message text as the rest of the API, `Unrecognized configuration key`, and update the two pinning tests in lockstep.

### [VALID-002] [info] Exotic argument objects make validate throw instead of returning a result
**Location:** `src/api/validation.js:78`
**Description:** `validate` has no exception boundary. The argument guards call `Array.isArray` and `Object.keys` on the caller's object and read its properties, and `Helpers.mergeConfig` copies the override with `Object.assign`. For a revoked Proxy, a Proxy with a throwing `ownKeys` trap, or an object whose `identifier` accessor throws, the exception propagates to the caller instead of a `{valid: false}` result. The same holds for the config argument, where a throwing `ownKeys` trap or a throwing accessor on the override propagates. The async API methods normalize every throw into `{error: {code: 100}}`, so `validate` is the one public method that can throw. No JSON-shaped input reaches this path. `undefined`, `null`, strings, numbers, arrays, `String` objects, frozen objects, null-prototype objects such as a query-string parser produces, symbol-keyed objects, objects with own `__proto__` or `constructor` keys and objects with an inherited `identifier` all return a result (verified at 7a97e15). A throw is itself a fail-closed outcome for a request handler, so the exposure is the availability of one request, under objects the caller constructed.
**Recommendation:** State in the JSDoc and the README that `validate` returns a `{valid, errors}` result for plain data objects and throws for accessor or Proxy objects, so the contract is explicit.

### [VALID-003] [info] A config override with an own `__proto__` key passes the 103 guard
**Location:** `src/api/validation.js:94` (the merge is `src/helpers.js:1036`)
**Description:** The guard inspects the merged copy that `Helpers.mergeConfig` builds with `Object.assign`. `Object.assign` writes an own `__proto__` key of the override through the `__proto__` setter that the fresh copy inherits, so the value becomes the prototype of the copy instead of an own key. `Object.keys` on the copy then lists the global keys only, and the guard passes. `Triauth.validate({identifier: 'john@example.com'}, JSON.parse('{"__proto__": {"evil": 1}}'))` returns `{valid: true}`, where every other unknown key, an own `constructor` key included, returns 103 (verified at 7a97e15). The global `Object.prototype` stays untouched, and the copy is local to the call. `validate` reads nothing from the config after the guard, so its result is unaffected. Every known key is an own property of the global config and is copied first, so a prototype injected this way shadows no setting in the methods that do read the config. The override is integrator-supplied input, which the trust model places inside the trusted code. The exposure is one undocumented exception to the rule that an unknown override key is rejected, in the one helper that backs the guard of every public method.
**Recommendation:** Build the merged config with object spread, `{...config, ...overrides}`, which copies an own `__proto__` key as an own data property, so the existing guard reports it as 103 (verified at 7a97e15). Add the case to `test/internals/test_config.js`.
