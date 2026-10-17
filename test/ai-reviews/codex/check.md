---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: check
lib_version: 1.0.0-beta.2
commit: 7a97e15
reviewed_at: 2026-10-17
status: good-to-go
summary: No actionable security findings in check under the documented usage assumptions; external trust-model conformance and live DNS behavior remain unverified.
settings:
  effort: xhigh
---

# <Model> review — Triauth.check

## Summary

No actionable security issues found; within the reviewed `check` scope, the library is suitable for mission-critical production use under the README's documented assumptions: keep the authenticated identifier/deviceTag in a protected session, accept only `valid === true`, enable `requireSecure` where cryptographic DNS integrity is required, trust the configured resolvers/cache, bound re-check intervals, and replace session groups on every successful check. The review traced direct and delegated checks through identifier validation, DNS resolution, private-mode commitments, key/grant tag binding, include policy, DNSSEC enforcement, TTL handling, group refresh, and error propagation; 197 focused unit tests, 91 check fixtures, and 33 additional scenarios covering private delegation, DNSSEC downgrades, missing/duplicate/mismatched commitments, policy and grant changes, resolution failures, missing TTLs, cached group refresh, and actor-key revocation passed. Review limitations: the required [trust-model page](https://www.triauth.org/protocol/trust-model) was inaccessible through the web tool and a direct fetch failed to resolve its hostname; live DNS-zone tests were excluded, so external trust-model conformance and live DNS behavior remain unverified.

## Findings

_No findings._
