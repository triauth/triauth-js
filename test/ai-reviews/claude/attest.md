---
model: Fable 5.1
model_id: claude-fable-5-1
scope: attest
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Bundle verification is sound and fail-closed. One open medium finding (ATTEST-001) - the request cannot require binders, so an unbound attester statement satisfies a person-bound claim by default.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.attest

## Summary

`Triauth.attest` binds every segment of the bundle to the digest of the stored challenge, keeps the user's segment first, pins its identifier and its `via` to the challenge, treats every stated binder as critical, bounds the segment count by the request, gates attester keys on their `use` option, and returns all or nothing. A DNS failure surfaces as a retryable 110 and never as a verdict. The attest unit tests and the attest conformance vectors pass when run through the suite entry (43 and 248 respectively).

The headline concern is a secure-default gap, not a verification defect. The request has no way to require binders, so by default an attestation is satisfied by a provider statement that proves only that someone completed the check for this challenge. The authenticator receives that statement as an opaque string in a URL fragment, so the user can obtain it from any person who completed the provider step with the same parameters. An integrator who gates a person-bound claim (age, identity, residency) on `attested:true` without inspecting `signedMetadata.bind` accepts such a transferred statement. The README documents the inspection. The library does not enforce it (ATTEST-001). The one recommendation to act on is a per-attestation binder requirement in the request, enforced at stage 3.

The library is safe to use in mission-critical production systems. The remaining findings are the host-equality trust anchor without an attester pin (ATTEST-002), operational logs that include the device tag (ATTEST-003), and a documentation gap on delegated ceremonies (ATTEST-004).

## Findings

### [ATTEST-001] [medium] [reviewed] The request cannot require binders, so unbound attester statements satisfy person-bound claims by default
**Location:** `src/api/attestation.js:336-370` (binder check and matching loop), `src/validator.js:189-235` (`validateAttestations`)
**Description:** An attester segment is accepted when it verifies under an identity at the provider host, its `via` is a listed provider URL, and every binder it states equals the user's value. A segment that states no binder passes. Such a segment proves that the provider's check was completed by someone for this challenge digest. It does not prove that the person was the user named in the challenge. The provider learns only its own URL and the digest, and the authenticator receives the provider's statement as an opaque string in the fragment of its own callback URL (`verifyToken` plus `response`). A user can therefore hand the provider link to another person, let that person complete the check, and open the returned link in their own authenticator session. The resulting bundle verifies with `attested:true`. A relying party that gates an age, identity, or residency decision on `attested:true` alone accepts it. The README asks integrators to inspect `attestations.<id>.signedMetadata.bind` after success, and the trust model places that decision with the application. Nothing in the request or the configuration lets the integrator state the requirement up front, so the safe behaviour depends on application code that runs after the library has already reported success. Anonymous attestations remain the right default for claims such as not-a-robot, so the gap is the absence of an opt-in, not the default itself.
**Recommendation:** Let each requested attestation list the binders it requires, for example `attestations.<id>.bind: ['identifier', 'deviceTag']`, validated at stage 1 (229 on an unrecognized name) and baked into the signed challenge. At stage 3, a segment satisfies that attestation only when its `bind` contains every required binder (the equality rule stays as it is), else 401. Document that `deviceTag` is the strong form, because a provider can learn it only by authenticating the user with triauth, while a typed identifier is unverified. Optionally the authenticator forwards the requirement to the provider as a query parameter. This is the one change to make before launch.
> **Human review (triauthor, 2026-10-01):** By design. Attestations are meant to be as anonymous as possible, and with that level of anonymity comes the fact that by default they are bound to neither an identifier nor a device. The binding is the verification provider's decision. A relying party that needs a person-bound claim chooses a provider whose contract states the binding it applies, and the library enforces that every binder the provider states matches the user. Accepted.

### [ATTEST-002] [low] Any identity at the provider host satisfies an attestation, the user included, and the request cannot pin the attester
**Location:** `src/api/attestation.js:352-358`
**Description:** The attester rule compares the domain part of the attester's identifier with the host of its `via`. Every identity published at that host passes, and the default key `use` admits all flows. The conformance suite has self-attestation as a positive case, where the user's own key satisfies a provider URL on the user's domain. A relying party that lists a provider URL on a host that also issues identities to other people (a hosted mail domain, a multi-tenant service) accepts a statement signed by any of those people, including the user being attested. The README tells integrators to compare `attestations.<id>.identifier` with the attester the provider documents, so the mitigation is documented but again runs after success.
**Recommendation:** Allow an optional expected attester per provider URL (for example `providers: [{url, attester}]`, or an `attesters` allowlist per attestation) that stage 3 enforces with 401. As a cheap default hardening, consider refusing a matched segment whose identifier equals the user's identifier or actor, since a user vouching for themselves is never a third-party attestation. That change retires the self-attestation positive vector, which is a founder decision.

### [ATTEST-003] [low] Success and debug logs include the device tag and the full attester result
**Location:** `src/api/attestation.js:359`, `src/api/attestation.js:372`
**Description:** The info-level success line logs `deviceTag`, and the debug line logs the whole matched attester result (keys, binders, metadata). Under `mode=private` the device tag embeds the lookup code, which the README classes as a semi-secret that must not reach third parties. Application logs at info level are routinely shipped to third-party log services. The same success line exists in the authenticate, ping, sign and stamp paths, so the exposure is library-wide. The default console logger emits at error level only, which limits the exposure to integrators who raise the level.
**Recommendation:** Log a digest of the device tag (or omit it) at info level, keep full result objects out of library logs, and state in the Logging section of the README that the logger is a sensitive sink under private mode. Note in the same place that `callbackMethod` GET or HASH puts the response, binders included, into URLs and server logs.

### [ATTEST-004] [low] The result inspection guidance omits `actor`, which identifies who stood in front of the provider
**Location:** `README.md:1060-1063`, `src/api/attestation.js:229-232`
**Description:** The user segment of an attest bundle may be delegated. The actor's device then runs the authenticator session, opens the provider, and completes the check, under a grant the subject published. The result reports this in `actor`, `actorIdentityDomain` and the composite `deviceTag`. Binders do not distinguish the case, because `bind.identifier` targets the subject and `bind.deviceTag` targets the composite tag. The "inspect the result before relying on it" list covers `secure`, `bind` and the attester identifier, but not `actor`. A relying party that follows the list accepts a person-bound attestation completed by the delegate as a statement about the subject.
**Recommendation:** Add `actor` to the inspection list, with the advice to accept a delegated attestation only where the subject's delegate is an acceptable proxy for the claim, and to require `actor === ''` otherwise.
