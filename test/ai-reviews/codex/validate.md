---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: validate
lib_version: 1.0.0-beta.3
commit: 5c72dcd
reviewed_at: 2026-10-26
status: good-to-go
summary: Format validation has no identified production-blocking issue within this scope; the configuration-key rejection bypass remains (VALID-001, low).
next_id: 3
settings:
  effort: xhigh
---

# <Model> review — Triauth.validate

## Summary

Within the reviewed `validate` scope, the library is suitable for mission-critical production as the documented synchronous format checker, with the README's application security responsibilities observed. This assessment does not establish the safety of other APIs and does not depend on beta status. Identifier, device-name, and group-name validators reject oversized strings before grammar scans; device tags now reject inputs over 242 characters before splitting, resolving the previous allocation finding. Lookup codes enforce their uppercase alphanumeric grammar, and device-tag digests require canonical Base64URL encoding. One low-severity configuration-key rejection bypass remains (VALID-001). As documented, `valid: true` confirms format only; callers must separately establish identity ownership and encode values for their output sinks.

On Node.js v24.13.1, all 15 selected unit tests (14 validation tests and the configuration guard test), 123 validation JSON fixtures, 348 additional boundary/type/configuration/dependency-isolation checks, and 16,384 device-tag canonical-encoding checks against Node's independent Base64URL encoder passed. Instrumented checks confirmed that 8 MiB colon-only and tilde-only device tags never reach `String.prototype.split`, while a valid 242-character composite tag remains accepted. VALID-001 was reproduced without mutation of global configuration or `Object.prototype`; malformed values for all five supported fields still failed. Validation did not invoke the supplied resolver, logger, randomness source, clock, or fetch stubs.

The required source files, reachable helpers, configuration and public entry points, and both required README sections were read. The linked [trust model](https://www.triauth.org/protocol/trust-model) could not be retrieved through the browser tool, including alternate host/trailing-slash attempts; search did not recover its contents, and a direct request failed DNS resolution. Consequently, the external trust-model reading required by the guide remains unfulfilled; the security-model assessment is grounded in the local source and README.

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
