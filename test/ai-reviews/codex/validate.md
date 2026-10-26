---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: validate
lib_version: 1.0.0-beta.3
commit: e464988
reviewed_at: 2026-10-26
status: warnings
summary: Oversized device tags cause avoidable synchronous memory allocation (VALID-002, medium); the configuration-key rejection bypass persists (VALID-001, low).
settings:
  effort: xhigh
---

# <Model> review — Triauth.validate

## Summary

Within the reviewed `validate` scope, the library is suitable for mission-critical production as a synchronous format checker for size-bounded inputs, provided callers cap untrusted `deviceTag` strings at 242 characters before invoking this version and follow the README's security responsibilities. This assessment does not establish the safety of other APIs and does not depend on beta status. Identifier, device-name, and group-name validators reject oversized strings before grammar scans; lookup codes and device-tag digests enforce their respective alphabets and canonical encodings. However, device tags are tokenized before their size is checked, allowing excessive synchronous allocation (VALID-002, medium). The existing configuration-key rejection bypass remains reproducible (VALID-001, low). As documented, `valid: true` confirms format only; callers must separately establish identity ownership and encode values for their output sinks.

All 14 selected unit tests (13 validation tests and the configuration guard test), 121 validation JSON fixtures, 143 boundary/type/dependency-isolation checks, and 16,384 device-tag canonical-encoding checks against Node's independent Base64URL encoder passed. Separate reproductions confirmed VALID-001 without mutation of global configuration or `Object.prototype`, and measured VALID-002 using delimiter-heavy strings up to 1 MiB. Validation did not invoke the supplied resolver, logger, randomness source, clock, or fetch stubs.

The required source files, reachable helpers, configuration and public entry points, and both required README sections were read. The linked [trust model](https://www.triauth.org/protocol/trust-model) could not be retrieved through the browser tool, and a direct request failed DNS resolution. Consequently, the external trust-model reading required by the guide remains unfulfilled; the security-model assessment is grounded in the local source and README.

## Findings

### [VALID-001] [low] Merging config before checking its keys hides an own `__proto__` property

**Location:** `src/api/validation.js:108`, `src/helpers.js:864`, `src/helpers.js:1046`

**Description:** The configuration whitelist checks the result of `Helpers.mergeConfig(config)`, which uses `Object.assign({}, config, overrides)`. An own, enumerable `__proto__` property from parsed JSON invokes the destination object's inherited prototype setter instead of becoming an own property. Consequently, `Object.keys()` in `hasOnlyKnownProperties()` never sees that unrecognized key, and `validate()` returns success instead of the documented `invalid_config` error. For example:

```javascript
Triauth.validate(
  {identifier: 'alice@example.com'},
  JSON.parse('{"__proto__":{"requireSecur":true}}')
);
// Actual: {valid: true, errors: []}
// Expected: {valid: false, errors: [{code: 'invalid_config', ...}]}
```

This defeats the configuration-key rejection safeguard for JSON-derived overrides and changes the temporary merged object's prototype. The impact in this scope is limited: `validate()` does not subsequently consume that merged configuration. Reproduction confirmed that malformed values for all five supported fields still fail with the same override, and neither `Object.prototype` nor the global configuration is mutated. Ordinary misspelled configuration keys and recognized keys set to `undefined` still return `invalid_config`. An own `__proto__` key in the first, objects argument is correctly rejected with `invalid_arguments`. No authentication or DNSSEC bypass is established by this finding.

**Recommendation:** Check the supplied override's own keys against `KNOWN_CONFIG_KEYS` before merging, while retaining validation of the effective global configuration. Use a merge that preserves `__proto__` as an ordinary own property, such as object spread or a null-prototype destination, so it can be rejected without invoking an inherited setter. Add a regression case using `JSON.parse()` to create an own `__proto__` key and require `invalid_config`; an object-literal `__proto__` initializer would not exercise the same input.

### [VALID-002] [medium] Oversized device tags allocate unbounded arrays before rejection

**Location:** `src/api/validation.js:155`, `src/validator.js:521`, `src/validator.js:542`, `src/protocol.js:54`

**Description:** `validateDeviceTag()` calls `deviceTag.split(':')` without an input-length check or split limit. For a single component, `#isReportedTag()` then calls `component.split('~')` and copies all remaining tokens into the `...rest` array before checking the component's grammar. The current grammar admits at most 242 ASCII characters: two 60-character tags with lookup-code suffixes, two colons, and an identifier of at most 120 bytes. Nevertheless, an arbitrarily long delimiter-heavy string is fully tokenized before rejection:

```javascript
Triauth.validate({deviceTag: '~'.repeat(1024 * 1024)});
// Returns invalid_device_tag, but only after splitting and copying the input.
```

On Node.js v24.13.1, a bounded reproduction using this 1 MiB input measured approximately 46 MiB of additional heap use and 40 ms of synchronous validation time; a 1 MiB colon-only input also allocated approximately 8 MiB. These measurements are runtime-dependent and demonstrate allocation overhead, not a tested process crash. An application that passes attacker-controlled device tags into this advertised fast format checker without a small field-size limit exposes its event loop and heap to avoidable resource exhaustion. Larger or repeated inputs can delay unrelated requests and increase garbage-collection pressure. The risk concerns availability; these inputs still return `valid: false`, and no identity-verification bypass was observed.

**Recommendation:** Reject non-string device tags and strings longer than `2 * (43 + 1 + 16) + 2 + LIMITS.identifierBytesize` before any splitting or decoding. Keep delimiter parsing bounded while continuing to reject extra components. Add regression coverage for the valid 242-character boundary, oversized tags, and long colon/tilde sequences, verifying rejection before tokenization. Until fixed, enforce that field-size cap before calling `validate`, together with application request-size limits.
