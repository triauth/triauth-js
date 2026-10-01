---
model: Fable 5.1
model_id: claude-fable-5-1
scope: stamp
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Fail-closed stamp verification with one medium finding. The challenge nonce is not bound to the stamp, so a captured stamp over a fixed message stays redeemable for about 45 seconds.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.stamp

## Summary

`Triauth.stamp` verifies one fresh signature over the challenge message and nothing else. The stage-3 path is strict and fails closed. The envelope grammar is closed, metadata goes through a bounded JSON parser, and the three-state verdict keeps 401 and 402 apart. The flow type, the identifier, the message and the callback base URL are all pinned to the stored challenge. Key use gating excludes keys that are not published for `stamp`, and `requireSecure` turns the DNSSEC flag into a hard gate. The `stamp.json` vectors pin every security property that the code claims, including the replay window.

The headline concern is the replay surface of the design. A stamp does not cover the challenge nonce, so for about 45 seconds a captured stamp verifies against any new stamp challenge for the same identifier, message and base URL. The README documents this and requires a verifier-chosen nonce inside the message. The one recommendation of this review is to bind the nonce at the wire level, which makes stamps single-use by default and keeps `Triauth.verify` portable (STAMP-001). The other open finding is a pre-authorization DNS and crypto cost that the `actor` slot of a response can direct at any domain (STAMP-002). Four informational notes cover device continuity, documentation drift, unauthenticated metadata and log contents.

The library is safe to use in mission-critical production systems. No finding reaches high. Such deployments must put a single-use nonce into every stamped message, pin `via` in third-party verification, and set `requireSecure` where their identities support DNSSEC.

## Findings

### [STAMP-001] [medium] [reviewed] The challenge nonce is not bound to the stamp, so a stamp over a fixed message is replayable for about 45 seconds
**Location:** `src/api/signing.js:102-104`, `src/challenge_response_flow.js:270-287`, `src/response.js:113-141`
**Description:** The signed bytes of a stamp are `stamp;identifier;actor;via;v1;ts;signedMetadata;;msg`. The challenge nonce, `iat` and `cburl` stay outside them, and stage 3 never compares anything in the response with the nonce. Freshness rests on two windows that are measured against the verifier clock and are independent of each other. The challenge `iat` must fall within `stampTimeout` plus 5 s of server drift. The envelope `ts` must lie between 45 s before and 30 s after the verifier clock, which is `stampTimeout` plus the client drift behind and the client drift ahead. A captured stamp therefore verifies against any later stamp challenge for the same identifier, message and callback base URL for up to 45 s after it was minted. The `stamp.json` vectors pin this with the different-nonce, sibling-callback and 45 s replay cases. Stage 1 does not tie the token to the identifier on the server, so an application that takes the identifier from the request lets a caller mint a challenge for the victim's identifier in the caller's own session and redeem a leaked stamp there. The Best Practices heuristic that rejects an `issuedAt` at or below the last `verifiedAt` does not cover this case, because a fresh challenge carries a fresh `issuedAt`. The README documents the property and requires a verifier-chosen nonce inside `message`, and the example follows the rule. The risk remains for integrators who stamp a fixed message, for instance as a session proof or an API credential, and whose responses leave TLS, for example through `callbackMethod` GET, where the stamp lands in URLs, logs and analytics. The impact is identity spoofing at that application. The likelihood is low, which gives medium.
**Recommendation:** Make stamps single-use by default while the wire format is still open. Have the authenticator copy the challenge nonce into the signed metadata, for example as `nonce`, and have stage 3 of `stamp` (and `sign`) require `sig.signedMetadata.nonce === challenge.data.nonce`. `Triauth.verify` ignores the member, so stamps stay portable. A smaller step that needs no authenticator change is to reject a stamp whose `ts` precedes the challenge `iat` by more than `maximalAllowedClientClockDrift`, which trims the window to about 30 s.
> **Human review (triauthor, 2026-10-01):** By design. Stamps are portable proofs, so the challenge nonce stays outside the signed bytes on purpose. Replay protection is a fresh, single-use nonce that the verifier places inside the message, which the README requires and the stamp.json vectors pin together with the 45 s window. Accepted.

### [STAMP-002] [low] The `actor` slot of a response directs DNS resolution and key verification at an arbitrary domain before the subject's grant is checked
**Location:** `src/signature.js:313-357`, `src/identity_includes.js:217-233`, `src/challenge_response_flow.js:285`
**Description:** For a delegated envelope, `Signature.verify` resolves the actor identity first. That reads the endpoint record and the identity records of the actor's domain, at a label derived from the `actorLookupCode` in the signed metadata, and then verifies the crypto signatures against the keys that domain publishes. Only after a key group matches does it resolve the subject and look for a matching include grant. In the stamp flow the subject is pinned to the challenge identifier, but the actor slot is free text under the sender's control. A caller who holds a stamp session can post envelopes that name `anyone@attacker-chosen.example` as the actor. Every such request makes the verifier query that domain through all configured resolvers and verify up to `maxDevices` times `maxKeysPerSignature` signatures against attacker-published keys, and ends in a 401. The work per request is bounded and the README asks for rate limiting of stage 3, so the exposure is cost amplification and an attacker-triggered outbound DNS query, not a bypass. The same ordering lets a stamp whose `via` differs from the challenge callback base reach DNS and crypto before the comparison at `challenge_response_flow.js:285`.
**Recommendation:** Resolve the subject first. Filter its include statements by the actor's domain (every include ref carries it), by the flow in `use`, and by the `via` host in `scope`, and reject without any actor-side DNS when no candidate remains. Pass the expected `via`, the base URL of the challenge `cburl`, into the `Response.verify` constraints so that a mismatch is rejected before resolution.

### [STAMP-003] [info] Stage 3 does not tie the stamp to the device or actor that holds the token
**Location:** `src/challenge_response_flow.js:270-287`, `src/api/signing.js:396-404`, `README.md:1320-1336`
**Description:** A stamp is accepted from any valid device key of the identifier, and from any delegate whose include grant covers `use=stamp` and the callback host. The library cannot see which device holds the `stampToken`, and stage 3 takes no `deviceTag` or `actor` option, so continuity with the session that obtained the token is left to the integrator. The result exposes `deviceTag` and `actor` inside `verificationResult`. The JSDoc asks to store the token next to the `deviceTag`, but neither the JSDoc nor the README says to compare the two at stage 3. An integrator who reads a stamp as proof that the device of this session is still present may accept a stamp from another device of the same user or from a delegate.
**Recommendation:** Accept optional `deviceTag` and `actor` options at stage 3, checked against the verified signature like the optional `identifier` and `callbackUrl`. Say in the stamp section that an integrator compares `verificationResult.deviceTag` with the session's `deviceTag`, and requires `actor === ''` where delegation is not wanted.

### [STAMP-004] [info] The README stamp section omits the replay warning and the session-scoped token guidance that the JSDoc carries
**Location:** `README.md:1314-1336`, `src/api/signing.js:389-404`
**Description:** The JSDoc of `stamp` has a WARNING block that says stamps are not single-use proofs, and two sentences that ask to keep the token in the session that the sign-in created, next to the challenge and the `deviceTag`. The README stamp section has neither. The replay rule appears only in the Best Practices section at the end of the README and in a code comment inside the example. The section also says that a stamp proves that the user "is currently logged in", which reads as a session property, while a stamp proves key possession within a time window.
**Recommendation:** Copy the JSDoc WARNING and the token-storage sentences into the README stamp section, and reword the "currently logged in" sentence.

### [STAMP-005] [info] `unsignedMetadata` on a stamped result is not integrity-protected
**Location:** `src/api/signing.js:148-160`, `src/signature.js:405-406`, `README.md:1606`
**Description:** The unsigned slot of the envelope is outside the signed payload by design, because WebAuthn assertion data travels there. Stage 3 parses it with the bounded JSON parser and copies it verbatim into `verificationResult.unsignedMetadata`. The stamp vectors pin that a response whose unsigned slot was swapped after signing still returns `stamped:true`. The README describes the field but does not say that anyone on the path can set it. An integrator who stores or acts on its content treats attacker-controlled data as part of a verified result.
**Recommendation:** State in the `Triauth.verify` result table and in the stamp section that `unsignedMetadata` is unauthenticated input that must not drive decisions, or drop the field from the stamped result shape. The raw `result` string still carries it for third-party verification.

### [STAMP-006] [info] Info-level logs include the `deviceTag` with its private-mode lookup code
**Location:** `src/api/signing.js:146`, `src/response.js:148`
**Description:** On success, stage 3 logs the identifier and the `deviceTag` at info level, and `Response.verify` logs the whole verification result at debug level. Under `mode=private` the `deviceTag` carries the lookup code as a `~` suffix, and the README lists `deviceTag` and `lookupCode` among the values not to disclose to third parties. The default log level is error, so nothing is emitted unless the integrator raises it, but a raised level with a hosted log service forwards these values.
**Recommendation:** Log the `deviceTag` without its `~lookupCode` suffix, or only at debug level, and mention log handling in the `deviceTag` bullet of Best Practices.
