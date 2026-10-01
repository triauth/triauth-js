---
model: Fable 5.1
model_id: claude-fable-5-1
scope: protocol
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Sound, fail-closed protocol core with four low findings and four info notes, none blocking mission-critical use when deployed per the README.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.protocol

## Summary

The protocol core is sound. The signature envelope has a closed grammar. Every slot before the message has a grammar without the `;` delimiter, so one envelope string parses to exactly one set of fields, and a signed payload maps to exactly one tuple of type, identifier, actor, via, version, timestamp, signed metadata, and message. The unsigned metadata slot is the only unsigned field, and the WebAuthn verifier binds its contents through the assertion signature and the challenge digest. Key material comes only from DNS, read through an intersection of independent resolvers. The verifier fails closed on every malformed record, tainted key group, unknown critical option, missing commit record, missing include grant, and unavailable crypto verifier. WebAuthn assertions must match the resolved authenticator origin and must have the user-presence flag set. A delegated signature needs a grant in the subject's own records that covers the actor, the flow, and the service host, and its device tag changes with the grant, the actor's identity domain, and the actor's keys.

The documented limits held up under review. The challenge is not server-signed, and replay protection for `auth` and `ping` rests on the integrator invalidating the stored challenge. `sign` and `stamp` results are transferable within their freshness window, and the `via` check stops their use at another site. DNS integrity for an unsigned zone rests on resolver cross-validation unless `requireSecure` is set. The README states each of these.

No finding is above low. The library is safe for mission-critical production use when it is deployed as the Best Practices section describes. The challenge stays in a server-side store and is invalidated after each attempt, the stage-1 and stage-3 endpoints are rate-limited, and `config.requireSecure` is set to `true` so that an answer without DNSSEC is rejected instead of reported.

The one change to make before launch is PROTO-001. The multi-signature duplicate guard compares segment bytes, and two segments with the same signed content pass it when the unsigned slot differs or when an ECDSA signature is re-encoded with the alternate `s` value. Deduplicate on the signed content instead.

## Findings

### [PROTO-001] [low] Duplicate-segment guard compares bytes, so one key can fill several segments
**Location:** `src/multi_signature.js:77`, `src/verifiers/ecdsa.js:89`
**Description:** `MultiSignature` rejects an envelope only when two of its segments are byte-identical. The signed content of a segment excludes the unsigned metadata slot and the encoding of the crypto signature, so a second segment with the same signed content passes the guard in two ways. The sender can fill the unsigned slot with a value that decodes to `{}`, which the ECDSA and Ed25519 verifiers ignore. Or the sender can replace an ECDSA signature `(r, s)` with `(r, n - s)`, which Web Crypto accepts, as confirmed with the runtime's Web Crypto during this review. The README already says that `minSignatures` counts segments and not signers, and the attestation flow matches one segment per requested attestation, so the practical effect is a guard that is weaker than its comment states. An integrator who keys a replay store on the raw envelope string gets the same two bypasses.
**Recommendation:** Deduplicate on the signed fields of each segment, which are the first seven slots of the envelope, and reject an envelope that repeats them. Optionally reject an ECDSA signature whose `s` value is above half the curve order. State in the README that an envelope string is not a unique identifier of a signature.

### [PROTO-002] [low] Transferable proofs of a private-mode identity disclose its lookup code
**Location:** `src/signature.js:309-310`, README "Best Practices and Security Considerations"
**Description:** Under `mode=private` the verifier derives the identity domain from the lookup code that the envelope states in `signedMetadata.lookupCode`, and from `actorLookupCode` for a delegated signature. `Triauth.verify` has no other way to receive it. A `sign` or `stamp` result is therefore a container for the lookup code, and forwarding the `result` string to a third party for verification gives that party the code. The README asks integrators not to disclose `lookupCode` and `actorLookupCode` to third parties, and does not say that the `result` string of `sign` and `stamp` includes them.
**Recommendation:** Add one sentence to the Best Practices section and to the `sign` and `stamp` sections. A signature made for a private-mode identity includes the lookup code, so share the `result` string only with parties who may look up the identity's records.

### [PROTO-003] [low] A GET callback puts the signed response, with tokens and private profile, into the URL
**Location:** README "Protocol extensions", `src/api/authentication.js:218-246`
**Description:** With `{callbackMethod:'GET'}` the authenticator delivers the response as a URL query parameter. For an `auth` response the signed metadata of the envelope contains the `ext` data that the authenticator returns. This includes the requested `pingToken`, `signToken`, `stampToken`, and `attestToken`, and the `privateProfile` when the user allows it. A query parameter is written to web server access logs, to proxies, and to browser history. The README presents `GET` as suitable for client-side applications and `HASH` as the option for privacy-conscious applications, and does not say what `GET` exposes.
**Recommendation:** State in the Protocol extensions table that a `GET` callback writes the whole response to logs and history, and recommend `POST` or `HASH` when the request asks for tokens or the private profile.

### [PROTO-004] [low] One resolver on the path can deny service for a whole domain
**Location:** `src/resolvers/multi_resolver.js:138-150`, `src/index.js:87-94`
**Description:** The default `MultiResolver` returns the intersection of the answers of every resolver that responded. A single resolver cannot add a record, which is the aim of the design, but a single resolver can remove every record by answering with an empty or a different set. In Node the third resolver is the system resolver over plain UDP. An attacker who can spoof its answers for the identity domain needs no valid record data. The spoof turns `check` into `{valid:false, reason:'unresolved'}` and stage 3 into error 401 for every user of that domain, for as long as it lasts. This is the intended trade of availability for integrity, and it fails closed. The README's resolver guidance covers truncation and DNSSEC support, and not this denial lever.
**Recommendation:** Document that a single disagreeing resolver vetoes an answer. Recommend a local validating resolver such as Unbound, or a DoH-only `MultiResolver`, where the system resolver path crosses an untrusted network. A partial hardening is to count an empty answer as a failure under `maxFailures` when the other resolvers agree on a non-empty answer. This removes the cheapest spoof, and an injected record still needs every answering resolver.

### [PROTO-005] [info] Grant scope matches the host of `via`, not its origin
**Location:** `src/signature.js:351`, `src/identity_includes.js:182-188`
**Description:** A delegated signature is accepted when an include grant of the subject covers the actor, the flow, and the host of the signature's `via`. The match uses the host alone. A grant with `scope=example.com` therefore covers `https://example.com/`, `http://example.com/`, and `https://example.com:8443/`, which are different origins. On a host that serves several tenants on different ports, or over both schemes, the grant is wider than the subject may expect.
**Recommendation:** State the host-level match where the README describes the `scope` option. A later revision of the grant grammar can accept origin-form entries for subjects who need a narrower grant.

### [PROTO-006] [info] Payload reconstruction re-serializes the timestamp slot instead of reusing the wire bytes
**Location:** `src/signature.js:150-163`, `src/signature.js:294-306`
**Description:** The parser accepts a `ts` slot of up to 16 digits and converts it with `parseInt`. The verifier then rebuilds the signed payload from the converted number. Above 2^53 the conversion is lossy, so a wire slot of `9999999999999999` is verified against a 17-digit payload slot of `10000000000000000`, a value that the wire grammar itself refuses, as confirmed during this review. Every freshness window rejects such a timestamp, so there is no practical effect today. The same number is what `signedAt` reports.
**Recommendation:** Keep the wire string of the `ts` slot and use it in the reconstructed payload, or bound the slot to 15 digits so that the number round-trips exactly.

### [PROTO-007] [info] Two cheap rejections run after DNS resolution and signature verification
**Location:** `src/signature.js:155-156`, `src/challenge_response_flow.js:271-285`
**Description:** The `Signature` constructor accepts any number of crypto signature slots that fit in the 16 KB envelope. The `maxKeysPerSignature` cap is applied in `IdentityKeys.verify`, after the signer's identity has been resolved through DNS. In the challenge-response flows the equality of the signature's `via` and the base URL of the challenge's `cburl` is checked in `verifyChallengeResponse`, after DNS resolution and the cryptographic check. A response made for another site therefore costs the verifier a full resolution before it is rejected. The README's rate-limiting advice bounds the effect.
**Recommendation:** Reject more than `maxKeysPerSignature` slots in the `Signature` constructor with error 225. Accept a `via` constraint in `Response.verify`, pass it through to the segment verification, and set it to the base URL of `cburl` in `verifyChallengeResponse`, so that the mismatch is caught before resolution.

### [PROTO-008] [info] The challenge-response flows cannot require a first-party signature
**Location:** `src/challenge_response_flow.js:270-277`, `src/signature.js:343-376`
**Description:** Every flow accepts a delegated signature when the subject's records publish a matching grant. The flows expose no option to refuse delegation, and only `Triauth.verify` accepts an `actor` constraint. The result reports the delegate in `actor`, so an application for which the subject's own approval matters, such as a `sign` of contractual terms, has to check `actor === ''` itself. The grant is the subject's own statement, so accepting it by default is consistent with the trust model.
**Recommendation:** Add a Best Practices note that says to check `actor` when first-party approval is required. A later revision can accept an `actor` constraint on the challenge-response flows.
