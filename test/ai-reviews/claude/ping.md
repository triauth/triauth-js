---
model: Fable 5.1
model_id: claude-fable-5-1
scope: ping
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Ping verifies a fresh device signature correctly, no finding above low, the one recommended change is a stage-3 deviceTag pin.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.ping

## Summary

`Triauth.ping` shares the challenge-response engine with `authenticate` and adds the token-gated issue path. Stage 1 validates every input, requires a token, keeps the token secret out of the redirect (only the issuer part and an HMAC over the challenge bytes travel), and never logs the token. Stage 3 requires exactly one signature of type `ping` over the stored challenge, checks the challenge age against the tight 15 s `pingTimeout`, checks the device clock against the 30 s drift allowance, re-reads the keys from DNS on every call, honours the `use=` key option and the `use=`/`scope=` grant options for delegates, binds `via` to the base URL of the challenge's `callbackUrl`, and enforces `requireSecure`. Ping-to-auth and auth-to-ping confusion is blocked on both the challenge `type` and the signed envelope `type`.

The findings are robustness and documentation items. The library accepts a ping from any device or delegate of the identifier because it cannot know which device opened the session, the challenge clock starts before the stage-1 DNS round trip, overlapping key groups can make `deviceTag` depend on DNS answer order, and under `mode=private` the raw response string carries the lookup code. Replay inside the window remains an integrator duty, which the README states.

The method is safe for mission-critical production use when the integrator follows the documented duties (challenge from the server-side session, challenge invalidated on every attempt, result fields compared against the session, stage-1 and stage-3 endpoints rate-limited) and sets `requireSecure` where DNSSEC is mandated. No critical finding.

## Findings

### [PING-001] [low] Stage 3 accepts proof from any device or delegate of the identifier
**Location:** `src/api/authentication.js:602-638`, `src/challenge_response_flow.js:270-300`, README ping section (lines 702 and 732)
**Description:** A ping result is accepted when any valid key group of the identifier signs the challenge, or any delegate under an include grant with `use=ping`. The method takes no session context, so the returned `deviceTag` and `actor` can differ from the values stored at sign-in. The README table states that the `deviceTag` "must be the same" as the one from `authenticate`, while the prose says integrators "can also check" it, so the comparison reads as optional. The signer still needs the identifier's private keys or a published grant, so an outsider cannot extend a session this way. The gap is that a continuous-authentication loop can keep a session alive on proof from a device or delegate other than the one that opened it, which is the opposite of what the method documents.
**Recommendation:** This is the one change this review recommends. Accept an optional stage-3 `deviceTag` option on `ping`, in the way `identifier` and `callbackUrl` are accepted today, and return 401 when the verified `deviceTag` differs. In the README ping section state the comparison of `identifier`, `deviceTag`, and `actor` against the session as a requirement.

### [PING-002] [low] The challenge clock starts before the stage-1 DNS round trip
**Location:** `src/challenge_response_flow.js:132-147`, `src/challenge.js:70`
**Description:** Stage 1 mints the challenge, and its `iat`, before it resolves the endpoint record. With the default MultiResolver that resolution can take up to 8.5 s. Stage 3 requires the `iat` to be no older than `pingTimeout` plus `maximalAllowedServerClockDrift`, 20 s by default. A slow or degraded DNS path therefore consumes part of the ping window before the browser is redirected, and the integrator sees 402 for a user whose device answered promptly. Operators who meet this tend to widen `pingTimeout`, which widens the replay window, instead of removing the cause.
**Recommendation:** Resolve the authentication endpoint first and build the challenge after it resolves, so the `iat` clock starts when the redirect URL is ready. The wire format is unchanged and the frozen-clock vectors keep their output.

### [PING-003] [low] Key-group match order follows the DNS answer order
**Location:** `src/identity_keys.js:249-309`, reached from `src/signature.js:331`
**Description:** `IdentityKeys.verify` returns the first key group whose keys all verify, and it iterates the groups in identity-record order, which is the order of the DNS answer. When two valid groups overlap, for example the same key published under two device names during a rename, a response that carries signatures for both can match either group, so `deviceTag` and `deviceName` vary from call to call. Include grants are tag-sorted for this reason, key groups are not. With the comparison that PING-001 asks for, such a user sees intermittent ping failures.
**Recommendation:** Iterate the key groups in a canonical order, for example sorted by tag as `IdentityIncludes` does, or prefer the group with the most verified keys, so one response always yields one `deviceTag`.

### [PING-004] [low] Under private mode the raw response carries the lookup code
**Location:** `src/signature.js:309-310`, README ping section (`callbackMethod` paragraph) and Best Practices (lines 2044-2046)
**Description:** Under `mode=private` the verifier reads the subject's lookup code, and a delegate's, from the signed metadata of the response envelope. The envelope is base64url, not encrypted, so the raw `response` string is as sensitive as the `lookupCode` and `deviceTag` result fields that the README asks integrators not to disclose. Ping is the high-frequency flow, and the `callbackMethod` extension `GET` places the envelope in the request URL, where access logs, proxies, and browser history keep it. The non-disclosure note covers the result fields only, not the raw response or the callback method.
**Recommendation:** State in the README that the raw `response` carries the lookup code under private mode, advise against `callbackMethod:'GET'` for private-mode identities, and advise against logging raw responses.

### [PING-005] [info] Replay inside the ping window is the integrator's responsibility
**Location:** `src/challenge_response_flow.js:270-300`, `src/response.js:113-127`
**Description:** The library keeps no record of consumed challenges. A captured `(challenge, response)` pair verifies again until the challenge `iat` leaves the window, 20 s by default. The README warning on ping states the single-use rule and the `verifiedAt` watermark technique, and a unit test pins the behaviour. Recorded here so that the reliance is visible and can be accepted.
**Recommendation:** No code change. Keep `pingTimeout` tight and invalidate the stored challenge on every stage-3 call, on success and on failure.

### [PING-006] [info] Stage-1 options are accepted and ignored at stage 3
**Location:** `src/challenge_response_flow.js:72-79`, `src/challenge_response_flow.js:184-193`
**Description:** `token` and `ext` are allow-listed for every stage of the ping flow, but stage 3 reads neither. A call such as `ping({challenge, response, token})` succeeds without any check of the token, which can suggest to an integrator that the token was verified against the response. The method is otherwise strict about unexpected input and returns 102 for it.
**Recommendation:** Return 102 for `token` and `ext` when `challenge` and `response` are present, or state in the docs that stage 3 ignores them.
