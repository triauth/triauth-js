---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: sign
lib_version: 1.0.0-beta.3
commit: 5c72dcd
reviewed_at: 2026-10-26
status: good-to-go
summary: No security findings in sign; mission-critical use requires the documented trust assumptions and application controls.
next_id: 1
settings:
  effort: xhigh
---

# <Model> review — Triauth.sign

## Summary

No security issues found in `sign`; this scope is safe to use in mission-critical production systems under the documented DNS, private-key, and authenticator-origin trust assumptions and README controls, including `requireSecure: true`, protected session keys and stored challenges, challenge consumption, single-use message nonces when replay protection is required, CSRF protection, application-controlled callback URLs, and endpoint rate limiting. Validation passed: 31 signing unit tests, 228 signing conformance cases, 124 related verification unit tests, and 78 independent checks with fresh ECDSA and Ed25519 keys covering request encryption, response tampering, signer/type/callback binding, attachment substitution, malformed metadata, freshness boundaries, transferable proofs, DNSSEC enforcement, key-use restrictions, and delegation. The published trust-model page was inaccessible; its local website source at `../triauth-www/protocol/trust-model.md` was read instead.

## Findings

_No findings._
