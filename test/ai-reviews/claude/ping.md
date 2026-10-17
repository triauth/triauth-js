---
model: Fable 5.1
model_id: claude-fable-5-1
scope: ping
lib_version: 1.0.0-beta.2
commit: 7a97e15
reviewed_at: 2026-10-17
status: good-to-go
summary: Ping verifies a fresh device signature over a sealed request and a sealed response correctly, no finding above low, the one recommended change is a stage-3 deviceTag pin.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.ping

## Summary

`Triauth.ping` shares the challenge-response engine with `authenticate` and adds the session-key path. Stage 1 validates every input, requires a session key, seals the challenge under a request key that HKDF derives from the session key, so the redirect shows only the key id `skid` and ciphertext, and never logs the session key. It mints a fresh P-256 key pair per challenge, publishes the public key in the challenge as `ek`, and returns the private key appended to the stored challenge. Stage 3 opens the response with that key, so a response reads only to the holder of the stored challenge. It requires exactly one signature of type `ping` over the stored challenge string, checks the challenge age against the 15 s `pingTimeout` plus the 5 s server drift allowance, checks the device clock against the 30 s drift allowance, re-reads the keys from DNS on every call, honours the `use=` key option and the `use=`/`scope=` grant options for delegates, binds `via` to the base URL of the challenge's `callbackUrl`, and enforces `requireSecure` at both stages. Ping-to-auth and auth-to-ping confusion is blocked on both the challenge `type` and the signed envelope `type`. The key-verification path also accepts compressed P-256 points from key records. The decoder rejects an x at or above the field prime, rejects a non-residue, takes the parity of y from the prefix, and hands the point to a Web Crypto import that confirms it lies on the curve, so a compressed key verifies exactly like its uncompressed spelling and the ping path gains no new input that it accepts.

The findings are hardening and documentation items. The library accepts a ping from any device or delegate of the identifier because stage 3 carries no session context, the challenge clock starts before the stage-1 DNS round trip, overlapping key groups can make `deviceTag` depend on DNS answer order, and the lookup code of a private-mode identity surfaces in the result and in info-level log lines. Replay inside the window remains an integrator duty, which the README states.

The method is safe for mission-critical production use when the integrator follows the documented duties (challenge from the server-side session, challenge invalidated on every attempt, result fields compared against the session, stage-1 and stage-3 endpoints rate-limited) and sets `requireSecure` where DNSSEC is mandated. No critical finding.

## Findings

### [PING-001] [low] Stage 3 accepts proof from any device or delegate of the identifier
**Location:** `src/api/authentication.js:602-638`, `src/challenge_response_flow.js:300-330`, README ping section (lines 708 and 738)
**Description:** A ping result is accepted when any valid key group of the identifier signs the stored challenge, or any delegate under an include grant with `use=ping` whose `scope` covers the callback host. Stage 3 takes no session context, so the library cannot tell the device that opened the session from any other device of the identifier, and the returned `deviceTag` and `actor` can differ from the values stored at sign-in. The sealed request narrows this in practice. The challenge string travels only inside the sealed request and in the integrator's store, and the authenticator opens the request with the session key of the sign-in device, so a signer on another device also needs the challenge from one of those two places. The README table states that the `deviceTag` "must be the same" as the one from `authenticate`, while the prose says integrators "can also check" it, so the comparison reads as optional. An integrator that skips it runs a continuous-authentication loop on proof that the library never ties to the session's device.
**Recommendation:** This is the one change this review recommends. Accept an optional stage-3 `deviceTag` option on `ping`, in the way `identifier` and `callbackUrl` are accepted today, and return 401 when the verified `deviceTag` differs. The composite tag of a delegated sign-in already names the grant, the actor, and the actor's device, so one pin covers the actor as well. In the README ping section state the comparison of `identifier`, `deviceTag`, and `actor` against the session as a requirement.

### [PING-002] [low] The challenge clock starts before the stage-1 DNS round trip
**Location:** `src/challenge_response_flow.js:138-171`, `src/challenge.js:71`
**Description:** Stage 1 mints the challenge, and its `iat`, before it resolves the authentication endpoint record. With the default MultiResolver that resolution can take up to 8.5 s. Stage 3 requires the `iat` to be no older than `pingTimeout` plus `maximalAllowedServerClockDrift`, 20 s by default. A slow or degraded DNS path therefore consumes part of the ping window before the browser is redirected, and the integrator sees 402 for a user whose device answered promptly. Operators who meet this tend to widen `pingTimeout`, which widens the replay window, instead of removing the cause.
**Recommendation:** Resolve the authentication endpoint first and build the challenge after it resolves, so the `iat` clock starts when the redirect URL is ready. The wire format is unchanged and the frozen-clock vectors keep their output.

### [PING-003] [low] Key-group match order follows the DNS answer order
**Location:** `src/identity_keys.js:249-309`, reached from `src/signature.js:331`
**Description:** `IdentityKeys.verify` returns the first key group whose keys all verify, and it iterates the groups in identity-record order, which is the order of the DNS answer. When two valid groups overlap, for example the same key published under two device names during a rename, a response that carries signatures for both can match either group, so `deviceTag` and `deviceName` vary from call to call. Include grants are tag-sorted for this reason, key groups are not. With the comparison that PING-001 asks for, such a user sees intermittent ping failures.
**Recommendation:** Iterate the key groups in a canonical order, for example sorted by tag as `IdentityIncludes` does, or prefer the group with the most verified keys, so one response always yields one `deviceTag`.

### [PING-004] [info] Under private mode the lookup code surfaces in the result and in info-level logs
**Location:** `src/signature.js:309-310`, `src/api/authentication.js:614`, README Logging (lines 1892-1894) and Best Practices (lines 2041-2043)
**Description:** Under `mode=private` the verifier reads the subject's lookup code, and a delegate's, from the signed metadata of the response envelope. The envelope travels inside the sealed response, so the callback URL, access logs, and browser history show ciphertext that opens only with the decryption key of the stored challenge. The code then surfaces in the `lookupCode` and `deviceTag` result fields, and the success log line at `info` level pairs the identifier with the `deviceTag`, which carries the code as a `~` suffix. Ping is the high-frequency flow, so that pair lands in the log on every ping once an operator raises the log level from the default `error`. The README asks integrators to treat these fields like the identifier, to keep the stored challenge out of URLs and logs, and to review `info` output before forwarding it.
**Recommendation:** No code change. Keep the default `error` log level in production, and treat `info` output as sensitive where private-mode identities sign in.

### [PING-005] [info] Replay inside the ping window is the integrator's responsibility
**Location:** `src/challenge_response_flow.js:300-330`, `src/response.js:113-127`, `test/test_authentication.js:1322-1342`
**Description:** The library keeps no record of consumed challenges. A captured `(challenge, response)` pair verifies again until the challenge `iat` leaves the window, 20 s by default. The sealed request in the browser history can also make the authenticator answer the same challenge again inside that window. The README warning on ping states the single-use rule and the `verifiedAt` watermark technique, and a unit test pins the behaviour. Recorded here so that the reliance is visible and can be accepted.
**Recommendation:** No code change. Keep `pingTimeout` tight and invalidate the stored challenge on every stage-3 call, on success and on failure.

### [PING-006] [info] Stage-1 options are accepted and ignored at stage 3
**Location:** `src/challenge_response_flow.js:78-85`, `src/challenge_response_flow.js:182-248`
**Description:** `sessionKey` and `ext` are allow-listed for every stage of the ping flow, but stage 3 reads neither. A call such as `ping({challenge, response, sessionKey})` succeeds without any check of the session key, which can suggest to an integrator that the response was verified against the session. The method is otherwise strict about unexpected input and returns 102 for it.
**Recommendation:** Return 102 for `sessionKey` and `ext` when `challenge` and `response` are present, or state in the docs that stage 3 ignores them.
