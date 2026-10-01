---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: sign
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: No security issues found in sign under the documented trust model and application controls.
settings:
  effort: xhigh
---

# <Model> review — Triauth.sign

## Summary

No security issues found in the reviewed `sign` scope; the library is safe to use for this scope in mission-critical production systems when the documented trust assumptions and README controls are satisfied, including `requireSecure: true`, protected session storage, single-use nonces inside messages when replay protection is required, and endpoint rate limiting. Validation passed: 52 targeted unit tests, 217 sign conformance cases, and 21 independent checks covering HMAC binding, attachments, tampering, freshness, replay, DNSSEC enforcement, and delegation. The published trust-model URL was unreachable; its local website source at `../triauth-www/protocol/trust-model.md` (relative to the repository root) was read instead.

## Findings

_No findings._
