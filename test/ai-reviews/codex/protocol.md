---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: protocol
lib_version: 1.0.0-beta.3
commit: 5c72dcd
reviewed_at: 2026-10-26
status: good-to-go
summary: No actionable protocol vulnerability found under documented security assumptions; 81 adversarial checks passed; external trust-model and live-DNS validation remain incomplete.
next_id: 1
settings:
  effort: xhigh
---

# <Model> review — Triauth.protocol

## Summary

No actionable protocol vulnerability was found in the required sources or traced cipher, API, identity, key-group and delegation paths, assessed against the README's challenge-response flow, relevant API sections, and Best Practices and Security Considerations. Independent of beta status, the reviewed library is safe to use as a component in mission-critical production under that documented model: trusted identity domains, authenticators, resolvers and caches; `requireSecure: true`; confidential, single-use challenges bound to the user's session; protected session keys; application-controlled HTTPS callbacks; stage-1 CSRF protection; rate limiting; and nonce, audience and freshness checks for transferable sign/stamp proofs. Validation passed 545 unit tests, 1,590 JSON conformance cases and 81 independent adversarial checks with fresh P-256, Ed25519 and WebAuthn signatures, encrypted requests/responses and in-memory DNS, covering signed-field integrity, challenge substitution/expiry, session-key agreement, key-group completeness, delegation restrictions, private-mode commitments, DNSSEC enforcement, assertion constraints, attestation provider/binder checks and strict parsing. The unit command exited unsuccessfully at its live-DNS preflight because Cloudflare DoH was unreachable. The required [trust-model page](https://www.triauth.org/protocol/trust-model) was inaccessible through the web tool and a direct request failed DNS resolution; comparison with that external document and live resolver validation remain incomplete.

## Findings

_No findings._
