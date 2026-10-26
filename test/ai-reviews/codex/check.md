---
model: GPT-6 Astra
model_id: gpt-6-astra
scope: check
lib_version: 1.0.0-beta.3
commit: e464988
reviewed_at: 2026-10-26
status: good-to-go
summary: One low-severity DNS owner-name comparison defect can cause false sign-outs; no authentication or delegation bypass found in check.
settings:
  effort: xhigh
---

# <Model> review — Triauth.check

## Summary

No authentication or delegation bypass was found in the reviewed `check` execution paths. Within this scope, the library is safe to use in mission-critical production systems under the README's documented assumptions: protect the authenticated identifier/deviceTag pair in the session, accept only `valid === true`, require DNSSEC where cryptographic DNS integrity is needed, trust the configured resolvers/cache, bound re-check intervals, and replace session groups after every successful check. CHECK-001 is a low-severity availability limitation: deployments must account for false sign-outs when a DoH response changes DNS owner-name capitalization. This assessment does not certify other API scopes or guarantee uninterrupted authentication availability.

The review traced direct and delegated checks through identifier validation, DNS parsing and caching, private-mode commitments, key/grant tag binding, include policy, DNSSEC enforcement, TTL handling, group refresh, and error propagation. Validation passed: 224 focused unit tests, all 91 `check` JSON fixtures, and 125 additional authentication-to-check scenarios covering direct authentication and every public/private subject/actor combination, key replacement and duplication, grant use/scope changes, delegation-policy revocation, group removal, DNS failures and DNSSEC downgrades, missing TTLs, and missing/duplicate/mismatched commitments. A separate injected-DoH reproduction confirmed CHECK-001 using a deviceTag returned by successful authentication.

Limitations: the required [trust-model page](https://www.triauth.org/protocol/trust-model) was inaccessible through the web tool, and a direct fetch could not resolve its hostname. The live DNS-zone preflight also failed because network access was unavailable; the focused unit run above excluded that suite. External trust-model conformance and live provider behavior remain unverified.

## Findings

### [CHECK-001] [low] Case-sensitive DNS owner matching can falsely sign out valid sessions
**Location:** `src/resolvers/dns_json.js:318`, reached through `src/identity_domain.js:84` and `src/api/authentication.js:349`.

**Description:** The DoH resolver accepts an answer only when `Answer[].name` exactly equals the queried domain, optionally followed by a dot. DNS label comparisons must ignore ASCII letter case, and valid answers may preserve a different capitalization from the query. [RFC 4343, sections 3 and 4](https://www.rfc-editor.org/rfc/rfc4343.html#section-3). Private-mode identity derivation makes this particularly relevant because it emits an uppercase base32 label. An equivalent lowercase answer is discarded, leaving the identity unresolved; `check` then returns `{valid:false, reason:'unresolved'}`, which the documented integration signs out. `requireSecure: true` does not prevent this false negative. In a MultiResolver, one otherwise-successful resolver returning this empty result can also empty the intersection.

Reproduced without live DNS using the existing fixture key and `Triauth.Resolvers.Google` with an injected fetch implementation:

1. Publish a private-mode endpoint and the fixture identity at `_4GIBDU53B3._at.private.triauthdemo.org`, with lookup code `K7QJ3FB9M2WZX0C4`, its matching commitment, and the desktop key. Return `Status: 0`, `AD: true`, and TXT answers with `TTL: 300` and owner names matching the queries.
2. Complete the sealed authentication flow for `john@private.triauthdemo.org`. Pass its returned identifier/deviceTag to `check` with `requireSecure: true`; it returns `valid: true, secure: true`.
3. Change only the DoH answer owner names to their lowercase spellings, retaining the same TXT data, TTL, and AD flag. The next check returns `{valid:false, reason:'unresolved'}` despite no key, commitment, or grant being revoked.

The demonstrated impact is erroneous session termination and possible inability to sign back in through the affected resolver path. It does not demonstrate unauthorized authentication, and current Cloudflare/Google network responses were not tested. Severity is low because this is a resolver interoperability/availability defect without a demonstrated untrusted-party authentication bypass.

**Recommendation:** Type-check answer owner names, compare queried and returned DNS names using ASCII case folding with one optional terminal dot normalized, and continue rejecting genuinely different owner names. Apply normalization only to DNS names; preserve TXT data, lookup codes, and commitment inputs verbatim. Add regression coverage for public and private checks with differently capitalized owner names, including a MultiResolver whose other resolver returns the full matching answer.
