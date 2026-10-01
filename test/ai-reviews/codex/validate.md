---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: validate
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: One low-severity configuration-key rejection bypass; no identifier or device-name format bypass found.
settings:
  effort: xhigh
---

# <Model> review — Triauth.validate

## Summary

Within the reviewed `validate` scope, the library is suitable for mission-critical production as a synchronous format checker when callers follow the documented security responsibilities; this assessment does not establish the safety of the other APIs. Identifier and device-name validation enforce bounded, lowercase ASCII grammars, and oversized strings are rejected before grammar scans; one low-severity configuration-key rejection bypass remains. All 13 validation unit tests, 56 validation JSON fixtures, and 196,638 additional character/type checks passed; a separate reproduction confirmed VALID-001. The required source files, reachable helpers, and both required README sections were read, but the linked [trust model](https://www.triauth.org/protocol/trust-model) could not be retrieved through the browser tool or a direct request, limiting independent confirmation of that external document.

## Findings

### [VALID-001] [low] Merging config before checking its keys hides an own `__proto__` property

**Location:** `src/api/validation.js:94`, `src/helpers.js:776`, `src/helpers.js:964`

**Description:** The configuration whitelist checks the result of `Helpers.mergeConfig(config)`, which uses `Object.assign({}, config, overrides)`. An own, enumerable `__proto__` property from parsed JSON invokes the destination object's inherited prototype setter instead of becoming an own property. Consequently, `Object.keys()` in `hasOnlyKnownProperties()` never sees that unrecognized key, and `validate()` returns success instead of the documented error 103. For example:

```javascript
Triauth.validate(
  {identifier: 'alice@example.com'},
  JSON.parse('{"__proto__":{"requireSecur":true}}')
);
// Actual: {valid: true, errors: []}
// Expected: {valid: false, errors: [{code: 103, ...}]}
```

This defeats the configuration-key rejection safeguard for JSON-derived overrides and changes the temporary merged object's prototype. The impact in this scope is limited: `validate()` does not subsequently consume that merged configuration, the identifier/device-name checks still run, and the reproduction did not mutate `Object.prototype` or the global configuration. No authentication or DNSSEC bypass is established by this finding.

**Recommendation:** Check the supplied override's own keys against `KNOWN_CONFIG_KEYS` before merging, while retaining validation of the effective global configuration. Use a merge that preserves `__proto__` as an ordinary own property, such as object spread or a null-prototype destination, so it can be rejected without invoking an inherited setter. Add a regression case using `JSON.parse()` to create an own `__proto__` key and require error 103; an object-literal `__proto__` initializer would not exercise the same input.
