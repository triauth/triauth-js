---
model: Fable 5.1
model_id: claude-fable-5-1
scope: whois
lib_version: 1.0.0-beta.1
commit: fc20409
reviewed_at: 2026-10-01
status: good-to-go
summary: Read-only lookup with strict argument checks, fail-closed record parsing, and no lookup-code leakage. Two low findings on the requireSecure exemption and the rate-limit guidance, plus three documentation notes.
settings:
  effort: max
---

# Fable 5.1 review — Triauth.whois

## Summary

`Triauth.whois` is a read-only lookup. It validates its arguments before any DNS traffic (102 for an unknown option key, 103 for an unknown config key, 101 for a missing identifier or a malformed lookup code, 21x for a malformed identifier), resolves the domain's `triauth` record and then the identity records, and returns a deep copy of what it read. The lookup code is consumed only as the HMAC key of the private-mode label derivation. It is never echoed in a result and never logged. Record parsing is linear in the answer size and fails closed per record family, with caps on devices, keys per device, grants, groups, and profile entries. Under private mode the commit record binds an answer to the derivation that was performed, so a wrong code and a label collision both resolve to `status: 0`. A DNS failure surfaces as error 110 instead of a false "does not exist". The `secure` flag is the AND of the endpoint record and every well-formed identity record.

Two low findings remain. `config.requireSecure` has no effect on whois, so a caller who opts in still receives non-DNSSEC results as `status: 1`. The README rate-limit guidance does not cover whois, although whois resolves two caller-chosen domains per call with no token. Three informational notes concern the meaning of `status: 1`, result fields that return DNS text verbatim, and debug logging under private mode.

From the whois perspective the library is safe to use in mission-critical production systems. The low findings are closed by a one-line gate or by documentation, and neither one lets a caller authenticate or act as another identity.

## Findings

### [WHOIS-001] [low] `config.requireSecure` has no effect on whois
**Location:** `src/api/identity.js:194-226` (compare `src/api/authentication.js:418-419` and `src/api/signing.js:725-728`)
**Description:** The status 1 result is assembled from `identity.secure`, and `config.requireSecure` is never consulted. A caller who opts in globally, or per call with `{requireSecure: true}`, still receives `status: 1` with `secure: false` for an answer that was not DNSSEC-validated. A stub-resolver probe confirms this for an unsigned endpoint record and for an unsigned identity answer. `check` and `verify` reject the analogous success result with error 404, so whois is the one DNS-reading method where the opt-in does nothing, and the error 103 guard cannot catch it because the key is recognized. The exposed data is the device list with its key material, the delegation grants, and the group claims. An operator dashboard built on whois shows attacker-published devices or grants from a poisoned unsigned zone with no error, while the operator believes the opt-in protects every result.
**Recommendation:** Call `ChallengeResponseFlow.assertSecure(identity.secure, config)` before the status 1 return, and leave the status 0 and -1 results ungated like the revoked path of check. If the exemption is intended, state it in the `requireSecure` comment in `src/config.js`, in the README default-configuration block, and in the whois JSDoc. Pin the chosen behaviour with a whois.json vector.

### [WHOIS-002] [low] Rate-limit guidance does not cover whois
**Location:** `README.md:2041-2042`, `src/api/identity.js:180-194`
**Description:** One whois call resolves two caller-chosen domains, the identifier's domain and then the identity domain, through every configured resolver. The default MultiResolver sends up to six outbound queries per call, and the answer costs one HMAC plus up to sixty SHA-256 digests for device and grant tags. whois takes an arbitrary identifier and needs no token, no challenge, and no session, so it is the method most likely to sit behind an unauthenticated "look up this address" endpoint. The README bullet on rate limiting covers only stage 1 and stage 3 of the challenge-response flows. With NodeDns in the resolver set, every call also makes the integrator's system resolver query a zone of the attacker's choice, which shows that resolver's egress address to the zone's authoritative server.
**Recommendation:** Extend the bullet to whois and check. Refer to the Caching DNS responses section for repeated lookups of the same identifier.

### [WHOIS-003] [info] `status: 1` means one well-formed record, not a usable identity
**Location:** `src/identity.js:293`, `README.md:748-751`, `README.md:840`
**Description:** `Identity.resolve` reports success when the identity answer contains at least one record that parses as a key followed by a value, whatever the key. A wildcard TXT record such as `*.example.com TXT "hello world"`, or any stray TXT record under the `_at` label, makes every identifier of a public-mode domain report `status: 1` with `devices: []`, `publicProfile: {}`, `groups: []`, and `includes: []`. A stub-resolver probe confirms this. Private mode is not affected because the commit record is required. The README describes `1` as "the identifier exists". An integrator who uses whois to decide whether an address can sign in with Triauth, or to pre-provision an account, reads existence where there is none. Sign-in itself is unaffected because no keys are published.
**Recommendation:** Document that `1` means at least one well-formed identity record is published and that `devices` can be empty, and tell callers to test `devices.length` when they need to know that an identifier can sign in. Alternatively, count only recognized record families toward existence. The vector for an uppercase `NAME` record pins the current rule, so a change needs that vector updated in lockstep.

### [WHOIS-004] [info] Result fields beyond `publicProfile` return DNS text verbatim
**Location:** `src/api/identity.js:186-192`, `src/api/identity.js:206`, `src/api/identity.js:213`, `src/authentication_endpoint.js:146-153`, `src/resolvers/base.js:130`, `README.md:842-848`
**Description:** Three result areas hand DNS text to the caller as published. `authenticationEndpoint.options` is the endpoint record's option map with no schema applied, so unknown keys are retained and their values are bounded only by the size of the TXT answer, because the record parser accepts option values of any length. `devices[].keys[].options` and `includes[].options` keep every `x-` option, whose values may contain the characters `<`, `>`, `"`, `'`, `&`, `/`, and `=`. A stub-resolver probe returns `color: "<b>x</b>"` and a 3000-character value on the endpoint, and `x-note: "<img/src=x/onerror=alert(1)>"` on a device key. The README whois table marks only `publicProfile` as raw text, and the Best Practices bullet mentions device key options but not endpoint options or include options. Only the domain owner can publish these values, so the exposure is a rendering concern for the integrator, not a cross-domain one.
**Recommendation:** Mark `authenticationEndpoint.options`, key `options`, and include `options` as raw text in the whois result table. Optionally bound endpoint option values at the record parser with the 255-byte Normal String limit that `x-` options already get at the schema check, so one record cannot grow a result.

### [WHOIS-005] [info] Debug logging links a private-mode identifier to its derived label
**Location:** `src/identity_domain.js:189`, `src/identity.js:130`, `src/resolvers/base.js:79`, `src/identity_keys.js:152`
**Description:** At the debug level the resolution logs the identifier together with the derived identity domain, for example `Identity domain for identifier "john@example.com" is "_4GIBDU53B3._at.example.com"`, and logs raw key data on a tainting record. The Privacy Considerations section explains that private mode keeps a third party who sees the label from linking it to an identifier without the lookup code. A debug log shipped to a shared log service stores that link for every lookup. The lookup code itself is never logged, and the default logger stays at the error level, so this concerns only integrators who turn debug logging on.
**Recommendation:** State in the Logging section that debug output under private mode identifies users and should stay out of shared log pipelines, or log the derived label without the identifier on that line.
