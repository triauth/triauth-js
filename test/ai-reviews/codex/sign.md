---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: sign
lib_version: 1.0.0-beta.2
commit: 7a97e15
reviewed_at: 2026-10-17
status: good-to-go
summary: No security findings in sign under the documented trust model and application controls.
settings:
  effort: xhigh
---

# <Model> review — Triauth.sign

## Summary

No security issues found in `sign`; this scope is safe to use in mission-critical production systems when the documented trust assumptions and README controls are met, including `requireSecure: true`, protected session keys and stored challenges, challenge consumption, single-use message nonces where replay protection is required, and endpoint rate limiting. Validation passed: 69 targeted unit tests, 226 sign conformance cases, and 42 independent security checks using freshly generated signing keys to exercise encrypted requests and responses, signer/type/callback binding, attachment substitution, tampering, freshness boundaries, transferable proofs, DNSSEC enforcement, and delegation restrictions. The published trust-model page was unreachable; its local website source at `../triauth-www/protocol/trust-model.md` was read instead.

## Findings

_No findings._
