---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: validate
lib_version: 1.0.0-beta.2
commit: 7a97e15
reviewed_at: 2026-10-17
status: good-to-go
summary: VALID-001 remains a low-severity configuration-key rejection bypass; no additional security findings in validate.
settings:
  effort: xhigh
---

# <Model> review — Triauth.validate

## Summary

Within the reviewed `validate` scope, the library is suitable for mission-critical production as a synchronous format checker when callers follow the documented security responsibilities; this assessment does not establish the safety of other APIs and does not depend on beta status. Identifier and device-name checks enforce bounded, lowercase ASCII grammars, reject oversized strings before grammar scans, and perform no DNS requests. `valid: true` confirms format only, as documented; callers must separately establish identity ownership and encode values for their output sinks. The existing low-severity configuration-key rejection bypass, VALID-001, remains reproducible; no additional security findings were identified.

All 14 selected unit tests (13 validation tests and the configuration guard test), 56 validation JSON fixtures, 196,608 character checks, and 95 boundary, type, and dependency-isolation checks passed. A separate reproduction confirmed VALID-001, continued rejection of malformed values, and no mutation of global configuration or `Object.prototype`.

The required source files, reachable helpers, and both required README sections were read. The linked [trust model](https://www.triauth.org/protocol/trust-model) could not be retrieved through the browser tool, and a direct request failed DNS resolution, limiting independent confirmation of that external document.

## Findings

### [VALID-001] [low] Merging config before checking its keys hides an own `__proto__` property

**Location:** `src/api/validation.js:94`, `src/helpers.js:847`, `src/helpers.js:1035`

**Description:** The configuration whitelist checks the result of `Helpers.mergeConfig(config)`, which uses `Object.assign({}, config, overrides)`. An own, enumerable `__proto__` property from parsed JSON invokes the destination object's inherited prototype setter instead of becoming an own property. Consequently, `Object.keys()` in `hasOnlyKnownProperties()` never sees that unrecognized key, and `validate()` returns success instead of the documented error 103. For example:

```javascript
Triauth.validate(
  {identifier: 'alice@example.com'},
  JSON.parse('{"__proto__":{"requireSecur":true}}')
);
// Actual: {valid: true, errors: []}
// Expected: {valid: false, errors: [{code: 103, ...}]}
```

This defeats the configuration-key rejection safeguard for JSON-derived overrides and changes the temporary merged object's prototype. The impact in this scope is limited: `validate()` does not subsequently consume that merged configuration. Reproduction confirmed that malformed identifiers and device names still fail with the same override, and neither `Object.prototype` nor the global configuration is mutated. Ordinary misspelled configuration keys and recognized keys set to `undefined` still return error 103. No authentication or DNSSEC bypass is established by this finding.

**Recommendation:** Check the supplied override's own keys against `KNOWN_CONFIG_KEYS` before merging, while retaining validation of the effective global configuration. Use a merge that preserves `__proto__` as an ordinary own property, such as object spread or a null-prototype destination, so it can be rejected without invoking an inherited setter. Add a regression case using `JSON.parse()` to create an own `__proto__` key and require error 103; an object-literal `__proto__` initializer would not exercise the same input.
