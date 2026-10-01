---
model: Fable 5.1
model_id: claude-fable-5-1
scope: check
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Fail-closed liveness re-check with correct per-identity tag scoping, resolution-level DNSSEC aggregation, and TTL-bounded expiry; only low and info findings remain.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.check

## Summary

`Triauth.check` is a pure DNS liveness re-check. It takes no signature and no user input beyond the stored `identifier` and `deviceTag`, re-resolves the subject (and, for a composite tag, the actor), and answers `valid:true` only when a valid key group with the exact tag digest is still published and, for delegated sessions, the pinned grant tag is still present on the subject and references that actor. Every failure path is fail-closed. The tag lookup is bounded by the resolved identity instance, the `secure` flag is the AND of the endpoint record and every well-formed identity record of both resolutions, `expires` is the minimum TTL across the endpoint record, the grant record, and the key records, and `requireSecure` is enforced on the success path only. The private-mode walk re-derives the identity domain from the lookup code carried in the tag and relies on the `commit` binding, so a wrong or rotated code ends the session rather than resolving a stranger's records. The 91-case conformance suite pins the security-relevant branches, including the sparse key-group gate, tainted-group isolation, scope folding into the grant tag, and the lookup-code grammar.

The library is safe to use in mission-critical production systems for this scope. The findings below are hardening and documentation items. CHECK-001 is the one recommendation to act on: compare the pinned grant's domain with the actor segment before resolving the actor, so a stored tag can never steer the server's DNS resolver at a foreign domain.

## Findings

### [CHECK-001] [low] Actor segment of a composite deviceTag selects foreign DNS targets before the grant's ref is compared
**Location:** `src/api/authentication.js:391-394`, `src/identity_includes.js:217-233`
**Description:** For a composite tag, `check` constructs an `Identity` from the actor identifier found in the tag and hands it to `IdentityIncludes.find`. `find` filters the subject's grants by the pinned tag, then resolves the actor (endpoint record plus identity domain), and only then compares the grant's `ref` with the actor. A grant tag is derivable from public DNS (it is the digest of the published `include` record), so any tag of the form `<published grant tag>:<name>@<any-domain>:<anything>` makes the server issue two DNS queries at `<any-domain>` before the ref mismatch returns `revoked`. Confirmed against an in-memory zone: queries for `attacker.example` and `someone._at.attacker.example` were issued for a tag whose grant references `jane@triauthdemo.org`. The exposure needs a tampered tag store, which the README already tells integrators to avoid (server-side or encrypted cookie session), and stage 1 of the challenge-response methods exposes a comparable lookup surface for arbitrary identifiers. The marginal effect is bounded to outbound DNS lookups chosen by whoever controls the stored tag, so the severity is low.
**Recommendation:** In `IdentityIncludes.find`, drop candidates whose `domainName` differs from the actor identifier's domain before `actorIdentity.resolve()`, and return `null` when none remains. The ref can only match an actor on the grant's own domain (both spellings of a ref carry it), so the pre-filter changes no verdict and removes the foreign lookup entirely. Also list `Triauth.check` in the README rate-limiting bullet, since one call performs up to four DNS resolutions.

### [CHECK-002] [low] deviceTag has no closed grammar: junk suffixes are ignored, the format check runs after DNS I/O, and malformed tags read as revocations
**Location:** `src/api/authentication.js:339-340`, `src/api/authentication.js:378-389`
**Description:** The tag is parsed with two unbounded `split` calls. A direct tag `<digest>~<code>~junk` and `<digest>~not-a-lookup-code` both validate under a public-mode domain, and `<grant>:<actor>:<digest>~<code>~junk` validates on the composite path, because every segment after the first `~` is discarded (confirmed empirically). The composite branch rejects a fourth `:` segment but the `~` separator admits any number of extra fragments, and no segment is checked against the digest alphabet or length. The composite format check itself runs only after the subject identity has been resolved, so a malformed tag still costs two DNS queries and its verdict depends on DNS state (`unresolved` when the subject does not resolve, `revoked` otherwise). Finally, a tag this library can never have minted is reported as `revoked`, while a malformed `identifier` is reported as `{error}`. An integrator treating `{error}` as "retry later" keeps the session on a permanently invalid identifier and ends it on a corrupted tag, which hides storage or integration defects behind revocation. None of this is an authentication bypass: a tag that fails the grammar can only lead to `valid:false`.
**Recommendation:** Validate the tag against a closed grammar before any network I/O: a base64url digest of 43 characters, an optional `~` plus exactly 16 uppercase alphanumerics, and for the composite form a `:`-joined triple whose middle segment passes `validateIdentifier`. Report a grammar failure as `{valid:false, reason:'malformed'}`, the shape `Triauth.verify` already uses, so ports and callers can tell corruption from revocation. Add conformance vectors for the extra-`~` forms so a strict port and this implementation cannot drift.

### [CHECK-003] [info] An empty resolver intersection ends every session of the domain for up to one TTL
**Location:** `src/api/authentication.js:344-349`, `src/resolvers/multi_resolver.js:137-150`
**Description:** `check` maps "no `triauth` record" and "no identity records" to `{valid:false, reason:'unresolved'}`, and the README directs integrators to log the user out on any `valid:false`. Under the default `MultiResolver` a record survives only when every answering resolver carries it, so one resolver's empty or truncated answer is enough to empty the intersection without raising an error, and so is any in-place edit of the apex `triauth` record during the propagation window. The outcome is a domain-wide forced logout rather than a false acceptance, which is the intended fail-closed direction, and the README documents the truncating-relay case and its diagnostic probe. Recorded here because the lever is availability-only and sits outside this scope's code.
**Recommendation:** Keep the fail-closed mapping. Consider surfacing a resolver disagreement about emptiness (some answers non-empty, intersection empty) as a retryable `{error}` instead of `unresolved`, so a single stale negative answer does not end sessions, and keep the `unresolved` verdict for an agreed empty answer.

### [CHECK-004] [info] README result table documents `secure` for the single-identity walk only
**Location:** `README.md:552`
**Description:** The `check` result table states that `secure` is true when DNSSEC protected every record the result depends on, and the synopsis names the endpoint record and the identity answer. For a composite tag the code also folds in the actor's endpoint record and identity answer (`identity.secure && actorIdentity.secure`), which the JSDoc states and the conformance suite pins, but the README section does not.
**Recommendation:** Add the delegated case to the README `secure` row so the three descriptions stay in lockstep.
