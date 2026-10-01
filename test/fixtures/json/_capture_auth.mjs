// One-shot capture helper for the Stage 3 "positive" / signed-metadata tests in auth.json,
// plus the security / regression-guard Stage 3 cases at the tail of this script (search "SECURITY").
//
// Stage 3 cases that exercise the SUCCESS body (authenticated:true ...) need a valid ECDSA
// signature, but WebCrypto ECDSA is non-deterministic to MINT (deterministic to VERIFY).
// So we mint the signatures here once, paste the captured `challenge` + `response` pairs
// into auth.json, then RECORD=1 npm run test:json to fill the success expecteds.
//
// Re-run this script whenever:
//   - the signature envelope format changes (segment count, separators, version slot, ...);
//   - the challenge field order changes (the signed payload is the base64url-encoded JSON
//     of the challenge object, so any reordering or new field changes the bytes);
//   - the DNS layout the suite uses for John changes (e.g., a key is added/removed);
//   - the suite-level currentTime/randomSource changes (challenge would no longer match).
//
// Usage:
//   node --experimental-global-webcrypto test/fixtures/json/_capture_auth.mjs
//
// Then copy each printed `RESP_*` block into the corresponding test's `response` arg
// in auth.json, and re-run `RECORD=1 npm run test:json` to populate the success expecteds.
// Confirm `git diff test/fixtures/json/auth.json` matches your intent before committing.

import * as Triauth from '../../../src/index.js';
globalThis.Triauth = Triauth;
import identities from '../identities.json' with { type: 'json' };
// Shared generator plumbing: frozen clock, logger, and the local fixture keypairs (one
// definition keeps every suite's copies in lock-step); this capture works with them
// device-shaped, mirroring identities.json's nesting.
import { T, LOGGER, asDevices, signonly as signonlyKeys, jane as janeKeys, ed25519 as ed25519Keys, PRIVATE } from './_capture_common.mjs';
const DnsResolverStub = (await import('../../stubs/dns_resolver.js')).default;
const SignerStub      = (await import('../../stubs/signer.js')).default;

const john = identities.john;

// signonly: the "key has use=sign in DNS but signs auth" tests.
const signonly = asDevices(signonlyKeys);
// jane: the "cryptographically valid signature for the WRONG identity" test (challenge built
// for john, signed by jane over the same bytes — jane's envelope identifier is itself, her sig
// verifies against her published key, but the signature.verify identifier-constraint catches
// the mismatch against challenge.identifier).
const jane = asDevices(janeKeys);
// ed25519: identity whose key is published with type=ed25519. Ed25519 signing is deterministic —
// re-running this script reproduces a byte-identical RESP_ED25519.
const ed25519 = asDevices(ed25519Keys);

// Must mirror auth.json's `dnsEntries` for John exactly — the published keys here are
// what the runner will look up when verifying the captured signatures.
Triauth.config.resolver = new DnsResolverStub({
  'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
  'john._at.triauthdemo.org': { TXT: [
    'initials JD',
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `key laptop[1/2]:${john.devices[1].keys[0].public}`,
    `key laptop[2/2]:${john.devices[1].keys[1].public}`,
  ]},
  // Signonly identity: device has one key with `use=sign` (NOT `use=auth`). Used to verify
  // that a sign-only key cannot be used for the auth flow — neither when the envelope's
  // type matches the flow (caught by IdentityKeys.verify's mode/use check) nor when it
  // doesn't (caught earlier by signature.verify's type constraint).
  'signonly._at.triauthdemo.org': { TXT: [
    'name Sign Only',
    `key desktop[1/1]:${signonly.devices[0].keys[0].public} use=sign`,
  ]},
  // Jane: ordinary identity used as the "wrong identity" in the cross-identifier mismatch test.
  'jane._at.triauthdemo.org': { TXT: [
    'name Jane Roe',
    'initials JR',
    `key desktop[1/1]:${jane.devices[0].keys[0].public}`,
  ]},
  // Ed25519: identity whose single key is published with type=ed25519.
  'ed25519._at.triauthdemo.org': { TXT: [
    'name Ed25519',
    `key desktop[1/1]:${ed25519.devices[0].keys[0].public} type=ed25519`,
  ]},
});
Triauth.config.logger = LOGGER;

// Freeze the clock at the shared suite T (matches auth.json's suite-level currentTime).
Date.now = () => T;

const identifier  = 'john@triauthdemo.org';
const callbackUrl = 'https://example.com/cb';

// `via` in the signature envelope is checked at src/api/authentication.js against
// `Helpers.getBaseUrl(challenge.data.cburl)` — an exact match against the cburl's BASE URL,
// NOT the full path. For positive tests, we must mint with `via` = the base URL of cburl
// so the verifier's exact-match check passes. (For negative-via tests, deliberately pass
// a different value to force the rejection.)
const via = 'https://example.com/';

// Pre-computed Stage 1 challenge for {identifier:'john@...', callbackUrl, currentTime: T, random: 00..33}.
// Embedded as a literal so this script doesn't depend on the runner producing it for the common case.
// If you change auth.json's currentTime or the random hex used by Stage 1 success tests, recompute.
const challenge = 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2IiLCJ0eXBlIjoiYXV0aCIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoiQUJFaU0wUlZabmVJbWFxN3pOM3Vfd0FSIiwiaWF0IjoxNzc3NDU0Njc1MDAwLCJ2ZXIiOjF9';

// For identities other than John (e.g., signonly), build the challenge via a Stage 1 call with
// the same deterministic random / clock so the resulting challenge is reproducible.
const buildChallenge = async (id) => {
  const bytes = new Uint8Array('00112233445566778899aabbccddeeff00112233'.match(/../g).map(h => parseInt(h, 16)));
  let pos = 0;
  Triauth.config.randomSource = (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = bytes[pos++]; };
  try { return (await Triauth.authenticate({ identifier: id, callbackUrl })).challenge; }
  finally { Triauth.config.randomSource = null; }
};

const sign = (deviceKeys, signedMetadata) => Triauth.Signature.generate(
  SignerStub.signUsingDeviceKeys(deviceKeys),
  'auth', identifier, '', via, challenge,
  signedMetadata,
);

console.log('CHALLENGE:\n' + challenge + '\n');

// --- Plain auth, single-key device (desktop) ------------------------------------------
console.log('RESP_DESKTOP:\n' + await sign(john.devices[0].keys) + '\n');

// --- Plain auth, multi-key device (laptop, 2 keys) ------------------------------------
console.log('RESP_LAPTOP:\n' + await sign(john.devices[1].keys) + '\n');

// --- Desktop + valid signedMetadata.ext -----------------------------------------------
console.log('RESP_DESKTOP_EXT:\n' + await sign(
  john.devices[0].keys,
  { ext: { signToken: true, privateProfile: { initials: 'JD' } } },
) + '\n');

// --- Laptop + valid signedMetadata.ext ------------------------------------------------
console.log('RESP_LAPTOP_EXT:\n' + await sign(
  john.devices[1].keys,
  { ext: { signToken: true, privateProfile: { initials: 'JD' } } },
) + '\n');

// --- Desktop + signedMetadata.ext with non-latin-1 (UTF-8) string values --------------
//     Regression for the btoa-era string codec: metadata chars > U+00FF used to throw at
//     encode (surfacing as 100) and decode as mojibake. Pins the UTF-8 bytes for ports.
console.log('RESP_DESKTOP_UNICODE_EXT:\n' + await sign(
  john.devices[0].keys,
  { ext: { emoji: '🎉', text: 'Привет' } },
) + '\n');

// --- Desktop + INVALID ext (array shape — evil authenticator) -------------------------
//     Verifies the `Validator.validateExt(receivedExt).errors.length === 0` strip-to-{}
//     defense in src/api/authentication.js (~line 189) — auth still succeeds, ext is wiped.
console.log('RESP_DESKTOP_INVALID_EXT:\n' + await sign(
  john.devices[0].keys,
  { ext: ['evil', 'array', 'masquerading', 'as', 'ext'] },
) + '\n');

// --- Desktop + GARBAGE signedMetadata (the WHOLE object is an array, not just .ext) ---
//     Tests the parse-time rejection: Helpers.safeParseJson rejects non-object roots, the
//     Signature constructor catches and re-throws as TriauthError(225). Note that
//     Signature.generate DOES accept an array signedMetadata at sign time — it just
//     JSON.stringify's it as-is into the signed segment.
console.log('RESP_DESKTOP_GARBAGE_SIGNED_METADATA:\n' + await sign(
  john.devices[0].keys,
  ['totally', 'wrong', 'shape', 'for', 'signedMetadata'],
) + '\n');

// --- Desktop + GARBAGE unsignedMetadata (segment is a JSON array, not object) ----------
//     Signature.generate's `unsignedMetadata` parameter goes through `Object.assign({}, x)`,
//     which coerces arrays to objects (loses array-ness). So to mint a signature with
//     array-rooted unsignedMetadata, we generate normally then swap the segment post-hoc.
//     This is exactly what an attacker MITM-ing the envelope would do — unsignedMetadata is
//     outside the signed payload, so the swap doesn't invalidate the crypto signature.
const mintWithGarbageUnsignedMetadata = async (deviceKeys, garbage) => {
  const env = await sign(deviceKeys);  // empty signedMetadata / unsignedMetadata
  const segments = env.slice(1, -1).split(';');
  segments[7] = Triauth.Helpers.stringToBase64Url(JSON.stringify(garbage));  // slot 7 = unsignedMetadata
  return '|' + segments.join(';') + '|';
};
// Same swap, but with caller-supplied raw base64url bytes in slot 6 (for byte-level negatives
// that no JSON.stringify round-trip can produce, e.g. invalid UTF-8).
const mintWithRawUnsignedMetadata = async (deviceKeys, rawB64uSegment) => {
  const env = await sign(deviceKeys);
  const segments = env.slice(1, -1).split(';');
  segments[7] = rawB64uSegment;
  return '|' + segments.join(';') + '|';
};
console.log('RESP_DESKTOP_GARBAGE_UNSIGNED_METADATA:\n' + await mintWithGarbageUnsignedMetadata(
  john.devices[0].keys,
  ['evil', 'array', 'in', 'unsignedMetadata'],
) + '\n');

// --- Signonly: key in DNS has `use=sign` (no auth) -------------------------------------
//     Two variants to pin both guards that block auth:
//       V1 — sign-typed envelope (caller passes |sign;...| to authenticate()).
//            signature.verify's type-constraint fires FIRST (constraints.type 'auth' !=
//            envelope type 'sign'), so the key's use flag is never even consulted.
//            This is the same guard as test #38, but with a more realistic story: the
//            authenticator emitted a sign envelope using a key it IS permitted to sign with.
//       V2 — auth-typed envelope (caller passes |auth;...| to authenticate()).
//            Crypto signature IS valid against the published key over the auth challenge,
//            but IdentityKeys.verify (~src/identity_keys.js:258) sees mode='auth' not in
//            key.options.use='sign' → key skipped → no verified keys → 401.
//            Counterfactual: if the DNS record dropped `use=sign`, default use is
//            'attest,auth,ping,sign,stamp' and this same envelope WOULD authenticate.
const signonlyChallenge = await buildChallenge(signonly.identifier);
console.log('SIGNONLY_CHALLENGE:\n' + signonlyChallenge + '\n');

console.log('RESP_SIGNONLY_SIGN_ENVELOPE:\n' + await Triauth.Signature.generate(
  SignerStub.signUsingDeviceKeys(signonly.devices[0].keys),
  'sign', signonly.identifier, '', via, signonlyChallenge,
) + '\n');

console.log('RESP_SIGNONLY_AUTH_ENVELOPE:\n' + await Triauth.Signature.generate(
  SignerStub.signUsingDeviceKeys(signonly.devices[0].keys),
  'auth', signonly.identifier, '', via, signonlyChallenge,
) + '\n');

// --- Desktop + EVIL signedMetadata: __proto__ pollution attempt ------------------------
//     `Helpers.safeParseJson` defends against this at src/helpers.js:288-296. Crafted via
//     JSON.parse so `__proto__` becomes an own enumerable property (object literals would
//     have triggered the setter and made __proto__ non-own → silently stripped by JSON.stringify).
//     Same uniform 225 outcome as the array-rooted case, exercising a different defense.
console.log('RESP_DESKTOP_EVIL_PROTO_SIGNED_METADATA:\n' + await sign(
  john.devices[0].keys,
  JSON.parse('{"__proto__":{"polluted":"by signedMetadata","isAdmin":true}}'),
) + '\n');

// --- Desktop + EVIL unsignedMetadata: constructor.prototype pollution attempt ----------
//     Hits the second clause of the same defense (constructor + constructor.prototype both
//     as own properties). Note that {constructor: {prototype: ...}} round-trips cleanly via
//     JSON.stringify without needing JSON.parse contortions — `constructor` isn't a setter
//     in object literals.
console.log('RESP_DESKTOP_EVIL_PROTO_UNSIGNED_METADATA:\n' + await mintWithGarbageUnsignedMetadata(
  john.devices[0].keys,
  { constructor: { prototype: { escalated: true, evilFn: 'arbitrary code marker' } } },
) + '\n');

// --- Raw bytes / non-JSON content in metadata slots ------------------------------------
//     A different failure mode from the earlier "wrong-shape JSON" tests: the segment IS
//     valid base64url (passes the Signature constructor's field-level format check), but
//     once decoded to a string it isn't valid JSON at all — JSON.parse throws SyntaxError.
//     This exercises the previously-untested branch where decodeMetadata's *parse* fails
//     (not its post-parse validation); my try/catch in src/signature.js still re-throws as 225.
//
//     Helpers (used here only):
const mintWithRawSignedMetadata = async (deviceKeys, rawB64uSegment) => {
  // Replicate Signature.generate's internal signed-payload layout (src/signature.js:36-48)
  // so we can put arbitrary bytes in the signed-metadata slot without going through
  // encodeMetadata's JSON.stringify. The signature must be real because signedMetadata is
  // inside the signed payload.
  const fields = ['auth', identifier, '', callbackUrl, 'v1', String(Date.now()), rawB64uSegment, '', String(challenge)];
  const signerPayload = fields.join(';');
  const sigs = await SignerStub.signUsingDeviceKeys(deviceKeys)(signerPayload);
  fields[8] = sigs.join(';');
  return '|' + fields.join(';') + '|';
};

// signedMetadata = base64url of "some-random-plain-text-not-json" — JSON.parse throws on the bare word.
console.log('RESP_DESKTOP_RAW_TEXT_SIGNED_METADATA:\n' + await mintWithRawSignedMetadata(
  john.devices[0].keys, 'c29tZS1yYW5kb20tcGxhaW4tdGV4dC1ub3QtanNvbg',
) + '\n');

// signedMetadata = base64url of EF BB BF + {"ext":{"bom":true}} — the decoder must not strip the
// BOM, so this otherwise-valid metadata is rejected at parse time (real signature covers the BOM segment).
console.log('RESP_DESKTOP_BOM_SIGNED_METADATA:\n' + await mintWithRawSignedMetadata(
  john.devices[0].keys, '77u_eyJleHQiOnsiYm9tIjp0cnVlfX0',
) + '\n');

// unsignedMetadata = base64url of raw bytes 0x00..0x0F — control chars, no valid JSON token.
console.log('RESP_DESKTOP_RAW_BINARY_UNSIGNED_METADATA:\n' + await mintWithRawUnsignedMetadata(
  john.devices[0].keys, 'AAECAwQFBgcICQoLDA0ODw',
) + '\n');

// --- Cross-identifier mismatch: jane signs john's challenge ----------------------------
//     Challenge.identifier = 'john@triauthdemo.org' (using the suite's pinned challenge).
//     Envelope is jane-signed: envelope.identifier = 'jane@triauthdemo.org', crypto sig
//     valid against jane's published key over john's challenge bytes. Verification flow:
//       - dispatch passes (no re-provided identifier, so the dispatch-level check is skipped)
//       - response.verify's `constraints.identifier !== challenge.identity.identifier` check
//         is satisfied (both are 'john' — the constraint is built FROM the challenge)
//       - signature.verify then sees envelope.identifier='jane' != constraints.identifier='john'
//         → returns false → propagates as 401
//     Different branch from the existing "re-provided identifier mismatching challenge.identifier"
//     test (which fires at dispatch level when the caller passes their own `identifier` arg).
console.log('RESP_JANE_SIGNS_JOHNS_CHALLENGE:\n' + await Triauth.Signature.generate(
  SignerStub.signUsingDeviceKeys(jane.devices[0].keys),
  'auth', jane.identifier, '', callbackUrl, challenge,
) + '\n');

// --- via mismatch: john signs john's challenge but envelope.via is on a different origin ---
//     Signature is cryptographically valid (john really signed an envelope with that via).
//     But ChallengeResponseFlow.verifyChallengeResponse requires base-equality:
//     `Helpers.getBaseUrl(challenge.data.cburl) === sig.via` — and getBaseUrl('https://example.com/cb')
//     is 'https://example.com/', not 'https://attacker.example/' → 401.
//     Defends against an attacker who controls a different origin's TLS and tries to relay
//     authenticator output back to the legitimate verifier.
console.log('RESP_JOHN_VIA_ATTACKER:\n' + await Triauth.Signature.generate(
  SignerStub.signUsingDeviceKeys(john.devices[0].keys),
  'auth', john.identifier, '', 'https://attacker.example/', challenge,
) + '\n');

// --- safeParseJson limit tests: unsignedMetadata slot (outside signed payload, no new crypto needed) ---
//
//     All variants below produce envelopes with a real ECDSA signature (via mintWithGarbageUnsignedMetadata)
//     but with a slot-6 payload crafted to trigger a specific safeParseJson guard:
//
//       DEEP       — jsonMaxNestingDepth: depth-9 object → check fires at iteration 9 (currentDepth=8 >= 8)
//       LONG_KEY   — jsonMaxKeyLength:   key with 257 chars → key.length > 256 → throw
//       NONASCII   — raw 0xE9 in the key: ill-formed UTF-8, refused at decode → throw
//
//     All surface as error 225 because Signature.decodeMetadata re-throws the decode /
//     safeParseJson Error as TriauthError(225). Confirmed by the try/catch in src/signature.js:116-121.

console.log('RESP_DESKTOP_DEEP_UNSIGNED_METADATA:\n' + await mintWithGarbageUnsignedMetadata(
  john.devices[0].keys,
  // 9 levels: root(1) → a(2) → b(3) → c(4) → d(5) → e(6) → f(7) → g(8) → h→{}(9) → throws
  {a:{b:{c:{d:{e:{f:{g:{h:{}}}}}}}}},
) + '\n');

console.log('RESP_DESKTOP_LONG_KEY_UNSIGNED_METADATA:\n' + await mintWithGarbageUnsignedMetadata(
  john.devices[0].keys,
  {['a'.repeat(257)]: 1},
) + '\n');

// Raw Latin-1 é (0xE9) in the key — {"r<0xE9>sum<0xE9>":1} is ill-formed UTF-8, refused at
// decode and re-thrown as 225.
console.log('RESP_DESKTOP_NONASCII_KEY_UNSIGNED_METADATA:\n' + await mintWithRawUnsignedMetadata(
  john.devices[0].keys,
  'eyJy6XN1bekiOjF9',
) + '\n');

// Raw Latin-1 é (0xE9) inside a string VALUE — {"ext":{"a":"<0xE9>"}} — ill-formed UTF-8 in a
// slot position that has no charset rule of its own; only the decode-time rejection pins it (225).
console.log('RESP_DESKTOP_BADUTF8_VALUE_UNSIGNED_METADATA:\n' + await mintWithRawUnsignedMetadata(
  john.devices[0].keys,
  'eyJleHQiOnsiYSI6IukifX0',
) + '\n');

// {"résumé":1} as proper C3 A9 UTF-8 — decodes fine; the Bounded-JSON ASCII-key rule rejects (225).
console.log('RESP_DESKTOP_EKEY_UNSIGNED_METADATA:\n' + await mintWithRawUnsignedMetadata(
  john.devices[0].keys,
  'eyJyw6lzdW3DqSI6MX0',
) + '\n');

// {"x\ud800y":1} — a lone-surrogate JSON ESCAPE in a key. Every parser behavior converges on
// 225: preserving the escape yields a non-ASCII key, substituting U+FFFD likewise, rejecting it
// fails the parse. No conformance vector requires ACCEPTING a lone-surrogate escape anywhere,
// so a port whose JSON parser rejects them outright stays conformant.
console.log('RESP_DESKTOP_SURROGATE_KEY_UNSIGNED_METADATA:\n' + await mintWithRawUnsignedMetadata(
  john.devices[0].keys,
  'eyJ4XHVkODAweSI6MX0',
) + '\n');

// --- safeParseJson null-node success path: unsignedMetadata = {"ok": null} ---------------
//     typeof null === 'object' → null is pushed to the BFS queue → next iteration hits
//     `if (node === null) continue` → processing skips past it without error.
//     Auth still succeeds because unsignedMetadata is parsed fine (null values are valid),
//     and authenticate() does not surface unsignedMetadata in its result.
console.log('RESP_DESKTOP_NULL_VALUE_UNSIGNED_METADATA:\n' + await mintWithGarbageUnsignedMetadata(
  john.devices[0].keys,
  {ok: null},
) + '\n');

// --- getBaseUrl THEN branch: callbackUrl already ends with '/' ---------------------------
//     getBaseUrl(url) has: `pathname.endsWith('/') ? pathname : pathname.substring(...)`.
//     Existing tests only use callbackUrl='https://example.com/cb' (ELSE branch: strip '/cb').
//     This capture uses callbackUrl='https://example.com/' so pathname='/' already ends with '/',
//     exercising the THEN branch which returns pathname unchanged.
{
  const trailingCallbackUrl = 'https://example.com/';
  const trailingVia = 'https://example.com/';  // getBaseUrl('https://example.com/') = 'https://example.com/'
  const trailingBytes = new Uint8Array('00112233445566778899aabbccddeeff00112233'.match(/../g).map(h => parseInt(h, 16)));
  let tPos = 0;
  Triauth.config.randomSource = (arr) => { for (let i = 0; i < arr.length; i++) arr[i] = trailingBytes[tPos++]; };
  let challengeTrailingSlash;
  try {
    challengeTrailingSlash = (await Triauth.authenticate({ identifier: identifier, callbackUrl: trailingCallbackUrl })).challenge;
  } finally {
    Triauth.config.randomSource = null;
  }
  console.log('CHALLENGE_TRAILING_SLASH:\n' + challengeTrailingSlash + '\n');
  console.log('RESP_DESKTOP_TRAILING_SLASH:\n' + await Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(john.devices[0].keys),
    'auth', identifier, '', trailingVia, challengeTrailingSlash,
  ) + '\n');

  // Nonzero-padding-bits twin for the canonical-decode case: this challenge decodes to 145 bytes, so its
  // final base64url quantum carries 4 padding bits (unlike the main CHALLENGE — 147 bytes, exact
  // quanta, no padding bits to flip). +1 on the last character sets a padding bit: a forgiving
  // decoder yields identical JSON; the strict decoder must reject (223). Pair it with
  // RESP_DESKTOP_TRAILING_SLASH — under a forgiving decoder the flow then dies at 401
  // payload mismatch, because the signature covers the unmutated challenge string.
  const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const tsLastIdx = B64U.indexOf(challengeTrailingSlash.slice(-1));
  if (tsLastIdx % 16 !== 0) throw new Error('CHALLENGE_TRAILING_SLASH no longer ends a 4-padding-bit quantum — pick another base');
  console.log('CH_TRAILING_SLASH_BADBITS (nonzero padding bits):\n'
    + challengeTrailingSlash.slice(0, -1) + B64U[tsLastIdx + 1] + '\n');
}

// --- Ed25519 (key type=ed25519) ---------------------------------------------------------
//     The envelope's crypto signature is Ed25519 over the same payload the ECDSA flow signs
//     (the challenge string). The published key is the 32-byte raw Ed25519 public key.
//     Cross-language guarantee: a port without the ed25519 verifier registered would taint
//     the keyGroup and fail the positive.
{
  const ed25519Challenge = await buildChallenge(ed25519.identifier);
  console.log('ED25519_CHALLENGE:\n' + ed25519Challenge + '\n');

  console.log('RESP_ED25519:\n' + await Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(ed25519.devices[0].keys),
    'auth', ed25519.identifier, '', via, ed25519Challenge,
  ) + '\n');
}

// ============================================================================
// SECURITY / regression-guard Stage 3 cases (auth.json tail).
//
// These pin emergent properties of Triauth.authenticate that the bulk of the suite does not
// isolate and that a refactor — or a port to another language — could silently regress while
// still passing every other test. They reuse John's DNS, clock (T), `identifier`, `via`, the
// canonical `challenge`, and the `sign` helper configured above; only the cases that must vary
// the type / identifier / via / challenge / ts use the small `mintSig` helper below. See the
// matching auth.json test names for the exact property each one guards.
// ============================================================================
console.log('// ---- security / regression-guard cases ----\n');

// base64url(JSON) of a challenge object, built in the SAME canonical field order Challenge.build
// emits ({cburl,[ext],type,identifier,nonce,iat,ver}) so the fixtures read naturally.
const encodeChallenge = (obj) => Triauth.Helpers.stringToBase64Url(JSON.stringify(obj));
const challengeObj = ({cburl, ext, identifier: id = identifier, nonce = 'ABEiM0RVZneImaq7zN3u_wAR'}) =>
  ext === undefined
    ? {cburl, type: 'auth', identifier: id, nonce, iat: T, ver: 1}
    : {cburl, ext, type: 'auth', identifier: id, nonce, iat: T, ver: 1};

// General single-signature mint. (`sign` above is hard-wired to type=auth / john / `via` / the
// canonical `challenge`; the cases below vary the type, identifier, via, challenge, or ts.)
const mintSig = (deviceKeys, type, id, via_, challengeStr, signedMetadata) =>
  Triauth.Signature.generate(SignerStub.signUsingDeviceKeys(deviceKeys), type, id, '', via_, challengeStr, signedMetadata);

// --- [replay] Cross-challenge replay --------------------------------------------------
//     Reuse RESP_DESKTOP (above) as the response and pair it with a SECOND valid challenge that
//     differs ONLY in the nonce. The crypto signature is bound to the exact challenge bytes (the
//     nonce lives inside them), so verification must fail → 401. No new signature is minted; this
//     block only emits the alternate challenge.
console.log('CH_OTHER_NONCE (pair with RESP_DESKTOP):\n'
  + encodeChallenge(challengeObj({cburl: callbackUrl, nonce: 'zZ9OtherNonceReplay0001x'})) + '\n');

// --- [SECURITY] Cross-flow type confusion (ping → auth) -------------------------------
//     A cryptographically VALID ping-typed envelope over the auth challenge bytes. ping and auth
//     both sign the challenge string, so only the envelope `type` slot separates them; the
//     signature.verify type-constraint must reject it (blocks a non-interactive ping being
//     upgraded to a full auth).
console.log('RESP_PING_TYPED_OVER_AUTH:\n' + await mintSig(john.devices[0].keys, 'ping', identifier, via, challenge) + '\n');

// --- [SECURITY] Partial multi-signature for a multi-key device ------------------------
//     John's `laptop` device publishes 2 keys; a valid login must carry a signature from BOTH.
//     Sign with ONLY laptop key #1 (reuses the `sign` helper: type=auth / john / via / challenge).
//     Must fail: every key of a multi-key group is required (AND, not OR).
console.log('RESP_LAPTOP_PARTIAL_ONE_KEY:\n' + await sign([john.devices[1].keys[0]]) + '\n');

// --- [SECURITY] Split key group published only as its final fragment ------------------
//     The test's per-test dnsEntries patch John's identity records to publish ONLY
//     laptop[2/2] — the last fragment of a declared 2-key group. A sparse write to the
//     group's final index makes keys.length equal keyCount, and Object.entries/.every
//     iteration skips array holes, so a length-gated validity check would accept the group
//     and authenticate on ONE signature of a declared 2-key device. The populated-slot
//     count (src/identity_keys.js:153-157) keeps the group invalid → 401.
//     Sign with ONLY laptop key #2 (the published fragment) so the response matches the
//     records exactly as served.
console.log('RESP_LAPTOP_LAST_FRAGMENT_ONLY:\n' + await sign([john.devices[1].keys[1]]) + '\n');

// --- [SECURITY] Unsigned-metadata ext injection --------------------------------------
//     Start from a normal desktop response (empty metadata), then MITM-overwrite slot 6
//     (unsignedMetadata, OUTSIDE the signed payload) with an attacker `ext` — the crypto signature
//     stays valid. authenticate() must still return ext:{}; only signedMetadata.ext is honored.
{
  const env = await sign(john.devices[0].keys);
  const seg = env.slice(1, -1).split(';');
  seg[7] = Triauth.Helpers.stringToBase64Url(JSON.stringify({ ext: { injected: 'attacker' } }));
  console.log('RESP_DESKTOP_UNSIGNED_EXT_INJECTION:\n' + '|' + seg.join(';') + '|' + '\n');
}

// --- [SECURITY] Requested ext is NOT echoed ------------------------------------------
//     The challenge bakes in ext (a stage-1 request — same bytes as the "challenge bakes in the ext
//     object" test), but the signed response carries NO signedMetadata.ext. result.ext must be {}:
//     it reflects what the authenticator SIGNED, never what the integrator requested.
const CH_EXT = encodeChallenge(challengeObj({cburl: callbackUrl, ext: {signToken: true, nested: {foo: 'bar'}}}));
console.log('CH_EXT (ext-bearing challenge):\n' + CH_EXT + '\n');
console.log('RESP_DESKTOP_OVER_EXT_CHALLENGE_NO_SIGNED_EXT:\n' + await mintSig(john.devices[0].keys, 'auth', identifier, via, CH_EXT) + '\n');

// --- [SECURITY] via must EQUAL getBaseUrl(cburl), not merely be a prefix --------------
//     Nested callback path (cburl=https://example.com/app/callback ⇒ getBaseUrl=https://example.com/app/):
//       EXACT  — via=https://example.com/app/  → equal → authenticates (also proves nested cbs work)
//       PARENT — via=https://example.com/       → parent prefix, NOT equal → 401
//     Guards against a port implementing the check as `cburl.startsWith(via)`, under which a
//     root-scoped signature would be accepted for a deeper callback path.
const CH_NESTED = encodeChallenge(challengeObj({cburl: 'https://example.com/app/callback'}));
console.log('CH_NESTED (cburl=https://example.com/app/callback):\n' + CH_NESTED + '\n');
console.log('RESP_NESTED_VIA_EXACT:\n'  + await mintSig(john.devices[0].keys, 'auth', identifier, 'https://example.com/app/', CH_NESTED) + '\n');
console.log('RESP_NESTED_VIA_PARENT:\n' + await mintSig(john.devices[0].keys, 'auth', identifier, via,                       CH_NESTED) + '\n');

// --- [SECURITY] Client-side freshness window (maximalAllowedClientClockDrift = 30s) ----
//     Applied to the signature `ts`, isolated from the server-side iat window: the challenge iat
//     stays at T (in-window); only the signature timestamp moves. (The rest of the suite only ever
//     moves currentTime, which shifts BOTH windows together and lets the iat check mask the ts one.)
//       WITHIN — ts=T+29999 → within drift → authenticates
//       BEYOND — ts=T+30001 → beyond drift → 402 expired
const mintWithTs = async (delta, challengeStr) => {
  Date.now = () => T + delta;       // Signature.generate stamps ts from Date.now()
  try { return await mintSig(john.devices[0].keys, 'auth', identifier, via, challengeStr); }
  finally { Date.now = () => T; }
};
console.log('RESP_TS_WITHIN_CLIENT_DRIFT (ts=T+29999):\n' + await mintWithTs(29999, challenge) + '\n');
console.log('RESP_TS_BEYOND_CLIENT_DRIFT (ts=T+30001):\n' + await mintWithTs(30001, challenge) + '\n');

// --- [Tier-T] Plain-http LAN callback end to end -------------------------------------
//     The full auth flow against a self-hosted callback: cburl http://10.0.0.5:8080/cb,
//     via http://10.0.0.5:8080/ (IPv4-literal host + port). Ed25519 keeps the minted bytes
//     deterministic, so a full regeneration reproduces this response byte-identically.
const CH_ED_LAN = encodeChallenge(challengeObj({cburl: 'http://10.0.0.5:8080/cb', identifier: ed25519.identifier}));
console.log('CH_ED_LAN (cburl=http://10.0.0.5:8080/cb, ed25519):\n' + CH_ED_LAN + '\n');
console.log('RESP_ED_LAN:\n' + await mintSig(ed25519.devices[0].keys, 'auth', ed25519.identifier, 'http://10.0.0.5:8080/', CH_ED_LAN) + '\n');

// --- [SECURITY] Stage 3 re-validates challenge.cburl ---------------------------------
//     A tampered challenge whose cburl embeds userinfo credentials must be rejected even with an
//     otherwise-valid signature. getBaseUrl() strips the credentials (so the via-equality check
//     alone would pass), but the explicit Validator.validateCallbackUrl(challenge.data.cburl) guard
//     fails → 401. A port that trusted the challenge cburl without re-validating it would accept it.
const CH_CREDS = encodeChallenge(challengeObj({cburl: 'https://user:pass@example.com/cb'}));
console.log('CH_CREDS (cburl=https://user:pass@example.com/cb):\n' + CH_CREDS + '\n');
console.log('RESP_CREDS_CBURL:\n' + await mintSig(john.devices[0].keys, 'auth', identifier, via, CH_CREDS) + '\n');

// --- [delegation] jane signs ON BEHALF of john under an include grant ------------------
//     The envelope's actor slot carries jane; verification walks john's include records for a
//     covering grant (patched into the test's dnsEntries) and reports the composite deviceTag.
//     ONE blob serves every delegated auth case (positive, use=/scope= variants, and their 401
//     twins) - the cases differ only in the include record their dnsEntries publish, so a re-mint
//     must be pasted into each of them (grep auth.json for the old blob).
console.log('RESP_DELEGATED:\n' + await Triauth.Signature.generate(
  SignerStub.signUsingDeviceKeys(jane.devices[0].keys),
  'auth', identifier, 'jane@triauthdemo.org', via, challenge,
) + '\n');

// --- [private] mode=private: the identity's lookup code rides signed-metadata -
//     CH_PRIVATE pairs with: RESP_PRIVATE (positive; the result deviceTag gains the ~lookupCode
//     suffix) and RESP_PRIVATE_NOCODE (401 - the identity domain cannot derive without it).
//     RESP_PUBLIC_CODE pairs with the canonical john challenge: a lookupCode member under a
//     public-mode domain is inert, so it authenticates. John's private-mode records live at
//     PRIVATE.john.identityDomain with the `commit` record (see _capture_common.mjs).
const CH_PRIVATE = encodeChallenge(challengeObj({cburl: callbackUrl, identifier: PRIVATE.john.identifier}));
console.log(`CH_PRIVATE (identifier=${PRIVATE.john.identifier}):\n` + CH_PRIVATE + '\n');
console.log('RESP_PRIVATE:\n' + await mintSig(john.devices[0].keys, 'auth', PRIVATE.john.identifier, via, CH_PRIVATE, { lookupCode: PRIVATE.john.lookupCode }) + '\n');
console.log('RESP_PRIVATE_NOCODE:\n' + await mintSig(john.devices[0].keys, 'auth', PRIVATE.john.identifier, via, CH_PRIVATE) + '\n');
console.log('RESP_PUBLIC_CODE:\n' + await sign(john.devices[0].keys, { lookupCode: PRIVATE.john.lookupCode }) + '\n');
