---
model: Fable 5.1
model_id: claude-fable-5-1
scope: sign
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Verification logic is sound. The open items are design and documentation matters (replay window, delegation, unsigned metadata), all low.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.sign

## Summary

`Triauth.sign` verifies one device signature over the requested `message` and the signed attachment list, and it ties the result to the challenge identifier, the callback base URL, the key `use` option, and two freshness windows. Envelope parsing is strict, metadata decoding is bounded and canonical, the crypto verifiers fail closed, and the DNSSEC status reaches both the result and the `requireSecure` gate. This review found no defect in the verification logic. The open items are design and documentation matters. The signed payload has no binding to the challenge, so a captured response verifies against any later challenge for the same message within the 30-minute window, as the README states. Delegated signatures and the unsigned metadata slot reach the result without a dedicated note in the `sign` documentation. The library is safe to use in mission-critical production systems when integrators follow the documented practices, in particular a single-use nonce inside `message` wherever a signature authorizes an action. The one recommendation of this review is to bind each `sign` response to its challenge inside the signed metadata and to require that binding at stage 3 (SIGN-001).

## Findings

### [SIGN-001] [low] Stage 3 accepts a replayed response because the signed payload is not bound to the challenge
**Location:** `src/api/signing.js:104`, `src/challenge_response_flow.js:271-286`, `src/response.js:137-138`
**Description:** Stage 3 checks the challenge type, the identifier, the base URL of `cburl` against the envelope `via`, the `msg` string as the signed payload, the attachment list by `name` and `sha256`, the challenge `iat` window, and the signature `ts` window. The challenge `nonce` is not part of the signed payload and is never compared. A `sign` response for one identifier, message, attachment set, and callback base therefore verifies against every other `sign` challenge for the same values while its `ts` stays inside `config.signTimeout` widened by `config.maximalAllowedClientClockDrift` on both sides (30 minutes and 30 seconds by default). The README states this in the `sign` warning and in Best Practices, and it gives the mitigation, a single-use nonce inside `message`. Replay cannot change what was signed, so the impact is limited to integrators who treat `signed:true` as a one-time authorization and reuse the same message text, for example for a payment approval. The `callbackMethod` values `GET` and `HASH` place the response in a URL, which makes a capturable proof easier to obtain from logs and browser history.
**Recommendation:** Bind each response to its challenge inside the signed payload. The authenticator states the challenge `nonce`, or the base64url SHA-256 digest of the challenge string, in `signedMetadata`, for example as `bind.nonce`, and `sign` stage 3 requires the value to equal `challenge.data.nonce`. `Triauth.verify` evaluates the same envelope with the same `message`, so the proof stays portable. Until authenticators send the binding, add a verifier-only check that `sig.signedAt` is not earlier than `challenge.data.iat` minus `config.maximalAllowedClientClockDrift`, so that a response produced before the challenge it is presented with is refused. Keep the README guidance about a nonce inside `message`.

### [SIGN-002] [low] Delegated signatures produce `signed:true` with no stage-3 control and no note in the sign documentation
**Location:** `src/signature.js:343-376`, `src/api/signing.js:148-160`, `README.md:1292-1306`
**Description:** When the envelope has an `actor`, `Signature.verify` accepts the signature if the actor's keys verify and the subject publishes an `include` record for the actor whose `use` covers `sign` and whose `scope` covers the callback host. An `include` record without a `use` option covers every flow (`src/identity_includes.js:98`). The result reports the subject as `identifier` and the delegate in `verificationResult.actor`. `Triauth.sign` offers no option to require the identifier's own keys, and the `sign` section of the README lists `identifier`, `deviceTag`, `secure`, and `expires` as the fields to read from `verificationResult`, without `actor`. An integrator who takes a signature as the subject's personal acceptance of a document may accept a delegate's signature without noticing. The subject authorized the delegation by publishing the record, so this is a defaults and documentation matter, not a bypass.
**Recommendation:** State in the `sign` result table that `verificationResult.actor` is non-empty for a delegated signature and that an integrator who needs the identifier's own keys must check `actor === ''`. Consider a stage-3 option that declares whether delegated signatures are acceptable for this request, so the check does not depend on each integrator reading the nested result.

### [SIGN-003] [low] The unsigned metadata slot is returned verbatim inside `verificationResult`
**Location:** `src/api/signing.js:157`, `src/signature.js:406`
**Description:** The unsigned metadata slot of the envelope is outside the signed payload (`src/signature.js:294-306`), so anyone who relays the response can set it. The `sign` result includes it unchanged as `verificationResult.unsignedMetadata`, next to fields the signature covers. The README `sign` result table describes `verificationResult` as the verified signature and does not single this field out. An integrator who stores or renders fields from `verificationResult` may treat attacker-controlled data as verified. The WebAuthn verifier is the only consumer that validates content from this slot, and it does so by checking the `sig` entries against the signed bytes.
**Recommendation:** State in the `sign` result documentation that `unsignedMetadata` is not covered by the signature and is untrusted input, or omit it from the `sign` result once verification completes. The escape-before-render rule in Best Practices also applies to `signedMetadata` values, which the signer controls.

### [SIGN-004] [info] The attachment proof binds names and digests only
**Location:** `src/api/signing.js:113-144`, `src/validator.js:321-340`
**Description:** Stage 3 confirms that the signed attachment list equals the requested list by `name` and `sha256`, and that a signed `sourceUrl`, when present, equals the requested one. The library never fetches an attachment, so it cannot confirm that the file shown to the user has the digest in the challenge. A `sourceUrl` may be a plain `http://` URL on any host, so the fetched content can be altered in transit. The README states that a verifier must compare the digests with its own copies of the files, and that `sourceUrl` is kept out of the durable proof because it may contain credentials. The challenge itself includes every `sourceUrl` and travels in the redirect URL fragment.
**Recommendation:** Add a sentence to the `sign` section that integrators serve attachments over `https` and keep the original files, since the proof is a statement about digests. Avoid presigned or otherwise secret `sourceUrl` values, as the challenge that includes them reaches the browser.
