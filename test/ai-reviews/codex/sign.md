---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: sign
lib_version: 1.0.0-beta.3
commit: e464988
reviewed_at: 2026-10-26
status: good-to-go
summary: No security findings in sign under the documented trust model and application controls.
next_id: 1
settings:
  effort: xhigh
---

# <Model> review — Triauth.sign

## Summary

No security issues found in `sign`; this scope is safe to use in mission-critical production systems when the documented trust assumptions and README controls are met, including `requireSecure: true`, protected session keys and stored challenges, challenge consumption, single-use message nonces where replay protection is required, and endpoint rate limiting. Validation passed: 69 targeted unit tests, 227 sign conformance cases, and 67 independent security checks using fresh ECDSA, Ed25519, and WebAuthn signatures with local DNS fixtures, covering encrypted requests and responses, signer/type/callback binding, attachment substitution, malformed metadata, tampering, freshness boundaries, transferable proofs, DNSSEC enforcement, delegation restrictions, required device keys, and WebAuthn origin/presence/verification checks. The published trust-model page was unreachable; its local website source at `../triauth-www/protocol/trust-model.md` was read instead.

## Findings

_No findings._
