---
model: Fable 5.1
model_id: claude-fable-5-1
scope: ping
lib_version: 1.0.0-beta.3
commit: e464988
reviewed_at: 2026-10-26
status: good-to-go
summary: Ping verifies a fresh device signature over a sealed request and a sealed response correctly, no finding above low, the one recommended change is a stage-3 deviceTag pin.
next_id: 9
settings:
  effort: max
---

# Fable 5.1 review — Triauth.ping

## Summary

`Triauth.ping` shares the challenge-response engine with `authenticate` and adds the session-key path. Stage 1 validates every input, requires a session key, seals the challenge under a request key that HKDF derives from the session key, so the redirect shows only the key id `skid` and ciphertext, and never logs the session key. It mints a fresh P-256 key pair per challenge, publishes the public key in the challenge as `ek`, and returns the private key appended to the stored challenge. Stage 3 opens the response with that key, so a response reads only to the holder of the stored challenge, and only the holder of the session key can seal one, because the challenge with its `ek` travels inside the sealed request. It requires exactly one signature of type `ping` over the stored challenge string, checks the challenge age against the 15 s `pingTimeout` plus the 5 s server drift allowance, checks the device clock against the 30 s drift allowance, re-reads the keys from DNS on every call, honours the `use=` key option and the `use=` and `scope=` grant options for delegates, binds `via` to the base URL of the challenge's `callbackUrl`, pins WebAuthn assertions to the resolved authenticator origin, and enforces `requireSecure` at both stages. Ping-to-auth and auth-to-ping confusion is blocked on both the challenge `type` and the signed envelope `type`. The change since the previous review is the move from numeric to string error codes, which renames the outcomes and alters no check, and the 175-case ping conformance suite pins the behaviour described here.

The findings are hardening and documentation items. The library accepts a ping from any device or delegate of the identifier because stage 3 carries no session context, the challenge clock starts before the stage-1 DNS round trip, overlapping key groups can make `deviceTag` depend on DNS answer order, a failure at the callback is unauthenticated so a sign-out-on-failure policy can be triggered by a third party, and the lookup code of a private-mode identity surfaces in the result and in info-level log lines. Replay inside the window and group refresh remain integrator duties, and the README ping section states neither as plainly as the JSDoc and the `check` section do.

The method is safe for mission-critical production use when the integrator follows the documented duties (challenge from the server-side session, challenge invalidated on every attempt, result fields compared against the session, stage-1 and stage-3 endpoints rate-limited) and sets `requireSecure` where DNSSEC is mandated. No critical finding.

## Findings

### [PING-001] [low] Stage 3 accepts proof from any device or delegate of the identifier
**Location:** `src/api/authentication.js:602-638`, `src/challenge_response_flow.js:300-330`, README ping section (lines 708 and 738)
**Description:** A ping result is accepted when any valid key group of the identifier signs the stored challenge, or any delegate under an include grant with `use=ping` whose `scope` covers the callback host. Stage 3 takes no session context, so the library cannot tell the device that opened the session from any other device of the identifier, and the returned `deviceTag` and `actor` can differ from the values stored at sign-in. The sealed request narrows this in practice. The challenge string travels only inside the sealed request and in the integrator's store, and the authenticator opens the request with the session key that it bound to the sign-in device, so a signer on another device also needs the challenge from one of those two places. The README table states that the `deviceTag` "must be the same" as the one from `authenticate`, while the prose says integrators "can also check" it, so the comparison reads as optional. An integrator that skips it runs a continuous-authentication loop on proof that the library never ties to the session's device.
**Recommendation:** This is the one change this review recommends. Accept an optional stage-3 `deviceTag` option on `ping`, in the way `identifier` and `callbackUrl` are accepted today, and return `verification_failed` when the verified `deviceTag` differs. The composite tag of a delegated sign-in already names the grant, the actor, and the actor's device, so one pin covers the actor as well. In the README ping section state the comparison of `identifier`, `deviceTag`, and `actor` against the session as a requirement.

### [PING-002] [low] The challenge clock starts before the stage-1 DNS round trip
**Location:** `src/challenge_response_flow.js:138-171`, `src/challenge.js:71`
**Description:** Stage 1 mints the challenge, and its `iat`, before it resolves the authentication endpoint record. With the default MultiResolver that resolution can take up to 8.5 s. Stage 3 requires the `iat` to be no older than `pingTimeout` plus `maximalAllowedServerClockDrift`, 20 s by default. A slow or degraded DNS path therefore consumes part of the ping window before the browser is redirected, and the integrator sees `request_expired` for a user whose device answered promptly. Operators who meet this tend to widen `pingTimeout`, which widens the replay window, instead of removing the cause.
**Recommendation:** Resolve the authentication endpoint first and build the challenge after it resolves, so the `iat` clock starts when the redirect URL is ready. The wire format is unchanged and the frozen-clock vectors keep their output.

### [PING-003] [low] Key-group match order follows the DNS answer order
**Location:** `src/identity_keys.js:249-309`, reached from `src/signature.js:331`
**Description:** `IdentityKeys.verify` returns the first key group whose keys all verify, and it iterates the groups in identity-record order, which is the order of the DNS answer. When two valid groups overlap, for example the same key published under two device names during a rename, a response that carries signatures for both can match either group, so `deviceTag` and `deviceName` vary from call to call. Include grants are tag-sorted for this reason (`src/identity_includes.js:196-205`), key groups are not. With the comparison that PING-001 asks for, such a user sees intermittent ping failures.
**Recommendation:** Iterate the key groups in a canonical order, for example sorted by tag as `IdentityIncludes` does, or prefer the group with the most verified keys, so one response always yields one `deviceTag`.

### [PING-004] [info] Under private mode the lookup code surfaces in the result and in info-level logs
**Location:** `src/signature.js:309-310`, `src/api/authentication.js:614`, README Logging (lines 1911-1913) and Best Practices (lines 2060-2062)
**Description:** Under `mode=private` the verifier reads the subject's lookup code, and a delegate's, from the signed metadata of the response envelope. The envelope travels inside the sealed response, so the callback URL, access logs, and browser history show ciphertext that opens only with the decryption key of the stored challenge. The code then surfaces in the `lookupCode` and `deviceTag` result fields, and the success log line at `info` level pairs the identifier with the `deviceTag`, which carries the code as a `~` suffix. Ping is the high-frequency flow, so that pair lands in the log on every ping once an operator raises the log level from the default `error`. The README asks integrators to treat these fields like the identifier, to keep the stored challenge out of URLs and logs, and its Logging warning names device tags with lookup codes among the `info` output to review before forwarding it.
**Recommendation:** No code change. Keep the default `error` log level in production, and treat `info` output as sensitive where private-mode identities sign in.

### [PING-005] [info] Replay inside the ping window is the integrator's responsibility
**Location:** `src/challenge_response_flow.js:300-330`, `src/response.js:113-127`, `test/test_authentication.js:1332-1352`, `src/api/authentication.js:509-512`, README ping section (lines 647-650)
**Description:** The library keeps no record of consumed challenges. A captured `(challenge, response)` pair verifies again until the challenge `iat` leaves the window, 20 s by default. The sealed request in the browser history can also make the authenticator answer the same challenge again inside that window. The JSDoc of `ping` carries a warning block that states the single-use rule for ping, and a unit test pins the behaviour. The README ping section does not repeat that block. Its verify step ends at the optional `identifier` and `callbackUrl` checks, and the single-use rule for ping is left to the generic bullet in Best Practices (lines 2035-2036), which also describes the `verifiedAt` watermark technique. Ping is the high-frequency flow, so the rule matters most where it is not stated. Recorded here so that the reliance is visible and can be accepted.
**Recommendation:** No code change. Add the ping warning block from the JSDoc to the README ping section. Keep `pingTimeout` tight and invalidate the stored challenge on every stage-3 call, on success and on failure.

### [PING-006] [info] Stage-1 options are accepted and ignored at stage 3
**Location:** `src/challenge_response_flow.js:78-85`, `src/challenge_response_flow.js:182-248`
**Description:** `sessionKey` and `ext` are allow-listed for every stage of the ping flow, but stage 3 reads neither. A call such as `ping({challenge, response, sessionKey})` succeeds without any check of the session key, which can suggest to an integrator that the response was verified against the session. The method is otherwise strict about unexpected input and returns `invalid_arguments` for it.
**Recommendation:** Return `invalid_arguments` for `sessionKey` and `ext` when `challenge` and `response` are present, or state in the docs that stage 3 ignores them.

### [PING-007] [low] A failed ping at the callback is unauthenticated, so a sign-out-on-failure policy is a forced sign-out lever
**Location:** `src/challenge_response_flow.js:187-189`, `src/challenge_response_flow.js:194-204`, README Best Practices (lines 2064-2065), README Error codes (line 1755)
**Description:** Only a success result proves anything. The denial sentinel `false` is a plain string that stage 3 maps to `request_denied` before it reads the stored challenge, and any other string that is not a sealed response maps to `invalid_response`. Nobody needs the session key or the stored challenge to produce either. The README tells integrators to count a ping that does not return in time as a failure and to sign the user out, and it describes `request_denied` as a denial by the user or a session key without the permission, so a sign-out on `request_denied` is the natural reading. With the default `GET` callback and the browser default `SameSite=Lax` session cookie, a top-level navigation from any site to the callback URL with `response=false` runs the handler inside the victim's session. The result is a forced sign-out of one user per navigation, not an authentication bypass. The protocol has no signed denial, so the library cannot tell a user's denial from a third party's `false`.
**Recommendation:** No library change. In the README ping section state that a ping failure is not authenticated. Advise integrators to issue a fresh ping after a failed one and to sign the user out only when that ping fails too, and to leave the session unchanged when a callback arrives while no ping is pending.

### [PING-008] [info] Group refresh guidance names only `check`, while a ping-only loop also carries current groups
**Location:** README Best Practices (lines 2067 and 2072-2073), README ping result table (line 736), `src/api/authentication.js:632`
**Description:** The ping result carries the identity's current `groups`, read from the identity records at verification time, the same list that `check` returns. The Best Practices bullet asks integrators to refresh session groups on every `check`, and the README recommends `check` or `ping` for periodic re-verification. An integrator who re-verifies with `ping` alone and reads that bullet literally keeps the groups cached at sign-in, so a membership removal published in DNS does not reach the session until the next sign-in, while key revocation does. The authorization bound that the README promises for `check` is then not met by the ping loop.
**Recommendation:** No code change. Extend the Best Practices bullet to `ping`, and state in the ping result table that `groups` replaces any session-cached list.
