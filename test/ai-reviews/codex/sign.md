---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: sign
lib_version: 1.0.0-beta.1
commit: 5e18952
reviewed_at: 2026-10-14
status: good-to-go
summary: No security findings in sign under the documented trust model and application controls.
settings:
  effort: xhigh
---

# <Model> review — Triauth.sign

## Summary

No security issues found in `sign`; this scope is safe to use in mission-critical production systems when the documented trust assumptions and README controls are met, including `requireSecure: true`, protected session keys and stored challenges, challenge consumption, single-use message nonces where replay protection is required, and endpoint rate limiting. Validation passed: 69 targeted unit tests, 226 sign conformance cases, and 32 independent security checks covering encrypted requests and responses, signature and attachment binding, tampering, freshness, transferable proofs, DNSSEC enforcement, and delegation. The published trust-model page was unreachable; its local website source at `../triauth-www/protocol/trust-model.md` was read instead.

## Findings

_No findings._
