// One-shot generator for the cross-language stamp.json suite.
//
// Like ./_capture_sign.mjs and ./_capture_ping.mjs, the Stage 3 stamp cases that exercise the
// crypto-verified paths (success bodies AND "valid signature, rejected for some OTHER reason"
// negatives) need real ECDSA P-256 signatures. WebCrypto ECDSA is non-deterministic to MINT but
// deterministic to VERIFY, so we mint here once and bake the resulting challenge/response strings
// into stamp.json.
//
// What is signed (same as sign, differs from auth/ping): for `stamp`, the cryptographic signature
// is over the human-readable `msg` string ONLY (not the challenge), and the envelope's
// signedMetadata (slot 5) IS part of the signed payload. UNLIKE sign, stamp carries NO attachments:
//   - Stage 1: passing the `attachments` option to stamp is rejected (102) in onChallenge.
//   - Stage 3: a challenge that carries an `attachments` field is rejected (102) in onResponse.
//   - Stage 3: a response whose signedMetadata contains `attachments` fails verification (401).
// So the canonical stamp signature is minted with an EMPTY signedMetadata ({}), and the
// attachment-rejection negatives are minted with attachments present.
//
// This script assembles and writes the ENTIRE stamp.json file — every test object, with the minted
// challenge/response already inlined — but WITHOUT the `expected` blocks. After running:
//
//   node --experimental-global-webcrypto test/fixtures/json/_capture_stamp.mjs   # (re)write stamp.json structure
//   JSON_SUITE=stamp.json RECORD=1 npm run test:json                             # fill in every `expected`
//   JSON_SUITE=stamp.json npm run test:json                                      # confirm green
//   git diff test/fixtures/json/stamp.json                                       # eyeball before committing
//
// Re-run this script whenever the signature envelope format, the challenge field order, the
// John/signonly/stamponly/jane/webauthn DNS layout, or the suite-level currentTime changes (any of
// these change the signed bytes and invalidate the baked signatures).
//
// Coverage goal: this suite ALONE covers 100% of the code paths reachable through Triauth.stamp
// (verify with `JSON_SUITE=stamp.json npx c8 --include 'src/**' mocha ... test/test_json.js`).
// Everything left uncovered in the stamp-path files is, by construction, NOT reachable through a
// Triauth.stamp call:
//   - the SIGN-only branches in src/api/signing.js: the `validateAttachments` closure body, every
//     `if (type === 'sign')` true-arm in onChallenge/onResponse (setting challenge.data.attachments,
//     validating challenge/response attachments, the whole attachment name+sha256 matching block),
//     the `?? []` response-attachments default, and the `config.signTimeout` arm of the notBefore
//     ternary (stamp always takes the `config.stampTimeout` arm); plus the sign/verify exports;
//   - build-side helpers used to CREATE signatures, never on stamp's verify path: Signature.generate
//     / Signature.encodeMetadata / MultiSignature.generate;
//   - other-API helpers: IdentityKeys.findByTag (Triauth.check) and Validator.validateAttestations
//     (Triauth.attest);
//   - defensive guards that no Triauth.stamp input can trigger: the internally-constructed
//     constraint objects in Response/MultiSignature/Signature.verify are always well-formed; the
//     DNS-record key/option strings are pre-filtered by upstream regexes; AuthenticationEndpoint.urlFor
//     runs only after resolve() succeeds; validateCallbackUrl() itself exercises both getBaseUrl arms; metadata is
//     bounded far under safeParseJson's 256KB limit; Resolvers.Base#resolve is overridden by the stub;
//     TriauthError.process's non-TriauthError branch is unreachable (every stamp throw is a TriauthError);
//   - logger?.() optional-chaining null-arms (the test logger is always present).
// The single stamp-REACHABLE branch this JSON harness cannot exercise is the `expires:undefined`
// arm of MultiSignature.verify's expiry aggregation (src/multi_signature.js): it only happens on a
// successful stamp over a TTL-less DNS record, and a result carrying an `undefined`-valued `expires`
// cannot survive JSON.stringify -> assert.deepStrictEqual round-trip. It is covered by the JS unit
// tests instead (same documented limitation as ping.json/sign.json).

import * as Triauth from '../../../src/index.js';
globalThis.Triauth = Triauth;
import identities from '../identities.json' with { type: 'json' };
// Shared generator plumbing: frozen clock, logger, the local signonly/jane/ed25519 fixture
// identities (one definition keeps every suite's keypairs in lock-step), and the guarded suite
// writer. Flow-specific roles in THIS suite:
//   - signonly (published with use=sign in this suite's dnsEntries): for the STAMP flow a
//     NEGATIVE — `use=sign` does NOT include `stamp`, so john-style crypto would still 401 on
//     the mode/use check. (The mirror image of sign.json, where use=sign is the positive.)
//   - jane: ordinary identity used as the "wrong identity" (jane stamps john's message).
import { T, LOGGER, signonly, jane, ed25519, PRIVATE, writeSuite } from './_capture_common.mjs';
// Minting only needs the private-key signer; no DNS is consulted here (the runner resolves DNS
// from the suite's dnsEntries at verify time).
const SignerStub = (await import('../../stubs/signer.js')).default;

Triauth.config.logger = LOGGER;

// Freeze the clock at the shared suite T. Every challenge iat and every signature ts is minted
// at T, so the signatures land inside stamp's notBefore/notAfter window (notBefore = T - stampTimeout).
Date.now = () => T;

const john = identities.john;
//   - stamponly: publishes JOHN's desktop public key but with use=stamp. The STAMP-flow positive
//     use-restriction: john's private key produces a cryptographically valid signature, and
//     mode='stamp' IS in use='stamp', so the key verifies → stamped:true. (Reuses john's desktop
//     keypair; the DNS record maps the identifier to the published pubkey.) Mirror image of sign's
//     authonly negative.
const STAMPONLY_ID = 'stamponly@triauthdemo.org';

const ID  = 'john@triauthdemo.org';
const CB   = 'https://example.com/cb';        // canonical callbackUrl (has a path segment to strip)
const CB_TRAILING = 'https://example.com/';   // already a base URL (exercises getBaseUrl THEN branch)
// `via` in the envelope is matched at src/api/signing.js against
// Helpers.getBaseUrl(challenge.data.cburl). getBaseUrl('https://example.com/cb') === 'https://example.com/'.
const VIA = 'https://example.com/';
const LAN_CB  = 'http://10.0.0.5:8080/cb';    // plain-http LAN callback: IPv4-literal host + port
const LAN_VIA = 'http://10.0.0.5:8080/';
const NONCE = 'ABEiM0RVZneImaq7zN3u_wAR';     // deterministic nonce for RAND below (kept for readability)
const RAND = '00112233445566778899aabbccddeeff00112233';

// Canonical message that is stamped. All-printable ASCII so it passes Validator.validateMessage.
const MSG = 'example-data-in-textual-format';
const MSG_DIFF = 'A completely different message';   // for the challenge.msg <-> signature binding test

// Attachment fixture, used only to PROVE that stamp rejects attachments (it never reaches the
// sign-style matching). Shape is {name, sourceUrl, sha256} like a sign attachment.
const ATT  = { name: 'License.txt', sourceUrl: 'https://example.com/license.txt', sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee' };

// Build a stamp challenge string with full control over every field. Field order mirrors
// Challenge.build (cburl, [ext], type, identifier, nonce, iat, ver) followed by the msg that _perform's
// onChallenge appends for stamp (NO attachments — that is the whole point of stamp). Stage 3 never
// re-checks the nonce, so a fixed nonce is fine. `attachments` is only ever baked in to drive the
// onResponse 102-rejection negative.
const mkChallenge = ({ cburl = CB, ext, type = 'stamp', identifier = ID, nonce = NONCE, iat = T, ver = 1,
                       msg = MSG, includeMsg = true, attachments, includeAttachments = false } = {}) => {
  const data = {};
  data.cburl = cburl;
  if (ext !== undefined) data.ext = ext;
  data.type = type;
  data.identifier = identifier;
  data.nonce = nonce;
  data.iat = iat;
  data.ver = ver;
  if (includeMsg) data.msg = msg;
  if (includeAttachments) data.attachments = attachments !== undefined ? attachments : [];
  return Triauth.Helpers.stringToBase64Url(JSON.stringify(data));
};

// Standard stamp challenges reused across Stage 3 cases.
const CH           = mkChallenge();                                    // john, cb, msg, no attachments
const CH_TRAILING  = mkChallenge({ cburl: CB_TRAILING });              // john, base-url cb
const CH_SIGNTYPE  = mkChallenge({ type: 'sign' });                    // type mismatch vs stamp flow
const CH_AUTHTYPE  = mkChallenge({ type: 'auth' });                    // type mismatch vs stamp flow
const CH_BADID    = mkChallenge({ identifier: 'no-at-sign.example' });       // valid JSON, malformed identifier → Identity ctor throws → 223
// BOM-prefixed canonical challenge: EF BB BF + the CH bytes. Decodes to valid JSON only if
// the decoder strips the BOM — which it must not (223; canonical-encoding guarantee for ports).
const CH_BOM = Triauth.Helpers.arrayBufferToBase64Url(Uint8Array.from([0xEF, 0xBB, 0xBF, ...Triauth.Helpers.base64UrlToUint8(CH)]));
const CH_BADCBURL  = mkChallenge({ cburl: 'not-a-url' });              // embedded cburl is not a valid URL → onResponse validateCallbackUrl fails → 401
const CH_PAST      = mkChallenge({ iat: 1700000000000 });             // far before notBefore
const CH_FUTURE    = mkChallenge({ iat: 1800000000000 });             // after notAfter (== T)
const CH_JUST_EXP  = mkChallenge({ iat: T - 15e3 - 1 });             // 1ms past stampTimeout (15s) → expired
const CH_60S       = mkChallenge({ iat: T - 60e3 });                  // 60s old: fine for auth (3min), expired for stamp (15s)
const CH_10S       = mkChallenge({ iat: T - 10e3 });                  // 10s old: still inside stamp's 15s window
const CH_IAT_NAN   = mkChallenge({ iat: 'not-a-number' });            // non-numeric iat → Response.verify typeof-guard → 402
const CH_PRIVATE    = mkChallenge({ identifier: PRIVATE.john.identifier });
const CH_SIGNONLY  = mkChallenge({ identifier: signonly.identifier });
const CH_STAMPONLY = mkChallenge({ identifier: STAMPONLY_ID });
const CH_MSG_DIFF  = mkChallenge({ msg: MSG_DIFF });                   // valid msg, but != the stamped message
const CH_NOMSG     = mkChallenge({ includeMsg: false });              // challenge has no msg → onResponse validateMessage(undefined) → 227
const CH_BADMSG    = mkChallenge({ msg: 'bad\nmessage' });            // challenge msg has a control char → 227
const CH_ATT       = mkChallenge({ includeAttachments: true, attachments: [ATT] }); // STAMP-DISTINCT: challenge carries attachments → onResponse 102
const CH_ATT_EMPTY = mkChallenge({ includeAttachments: true, attachments: [] });    // even an EMPTY attachments array is truthy → 102
const CH_ATT_NULL  = mkChallenge({ includeAttachments: true, attachments: null });  // member present with a null value — membership, not truthiness, drives the 102
const CH_WA        = mkChallenge({ identifier: 'webauthn@triauthdemo.org' }); // identity whose key is published as type=webauthn-es256
const CH_ED25519   = mkChallenge({ identifier: ed25519.identifier });         // identity whose key is published as type=ed25519
const CH_ED_LAN    = mkChallenge({ cburl: LAN_CB, identifier: ed25519.identifier }); // LAN callback flow (Ed25519 keeps the minted bytes deterministic)
const CH_WAED      = mkChallenge({ identifier: 'webauthn-ed25519@triauthdemo.org' }); // identity whose key is published as type=webauthn-ed25519

// --- Security-property challenges (replay surface & via binding granularity) ----------
// These pin documented stamp behavior (see the Triauth.stamp WARNING in README.md): the challenge
// nonce is NOT bound to the signature, `via` binds to the callback's base DIRECTORY (not the exact
// URL), and a captured stamp stays replayable for up to stampTimeout + 2*maximalAllowedClientClockDrift.
//
//   - CH_DIFF_NONCE: identical to CH but with a DIFFERENT nonce. Stage 3 never re-checks the nonce
//     and the signature does not cover it, so RESP_DESKTOP (minted for msg=MSG, no challenge) still
//     verifies — the core replay surface.
const CH_DIFF_NONCE = mkChallenge({ nonce: 'a-completely-different-nonce' });
//   - CH_SIBLING_CB: a DIFFERENT callbackUrl that shares the SAME base directory as CB.
//     getBaseUrl('https://example.com/cb') === getBaseUrl('https://example.com/other-endpoint')
//     === 'https://example.com/' === VIA, so the same stamp is accepted at a sibling callback.
const CH_SIBLING_CB = mkChallenge({ cburl: 'https://example.com/other-endpoint' });
//   - CH_REPLAY_45S / CH_REPLAY_OVER: a captured response (envelope ts = T) is replayed against a
//     FRESH challenge whose iat is at the replay moment. The signature ts (T) must stay inside the
//     widened window [now - stampTimeout - drift, now + drift] = [now-45s, now+30s]. At now=T+45000
//     the old ts==T is exactly on the notBefore edge (accepted); at T+45001 it is 1ms outside (402).
const CH_REPLAY_45S  = mkChallenge({ iat: T + 45e3 });
const CH_REPLAY_OVER = mkChallenge({ iat: T + 45e3 + 1 });

// --- signature minting helpers --------------------------------------------------------
// For stamp, the `message` argument to Signature.generate is the human-readable msg (the signed
// payload); signedMetadata is part of the signed payload but for stamp must be empty for success.

const mint = (deviceKeys, opts = {}) => {
  const { type = 'stamp', identifier = ID, via = VIA, message = MSG, signedMetadata = {}, unsignedMetadata = {} } = opts;
  return Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(deviceKeys),
    type, identifier, '', via, message, signedMetadata, unsignedMetadata,
  );
};

// MITM-style swap of slot 7 (unsignedMetadata) after signing — the crypto stays valid because
// unsignedMetadata is the one envelope field outside the signed payload.
const mintUnsignedSwap = async (deviceKeys, garbage, opts = {}) => {
  const env = await mint(deviceKeys, opts);
  const seg = env.slice(1, -1).split(';');
  seg[7] = Triauth.Helpers.stringToBase64Url(JSON.stringify(garbage));
  return '|' + seg.join(';') + '|';
};
const mintRawUnsigned = async (deviceKeys, rawB64uSegment, opts = {}) => {
  const env = await mint(deviceKeys, opts);
  const seg = env.slice(1, -1).split(';');
  seg[7] = rawB64uSegment;
  return '|' + seg.join(';') + '|';
};
// Raw (non-JSON) bytes in the SIGNED metadata slot (6): must re-create the signed payload by hand
// so the real signature covers the raw bytes. (msg lives in slot 8.)
const mintRawSigned = async (deviceKeys, rawB64uSegment, opts = {}) => {
  const { type = 'stamp', identifier = ID, via = VIA, message = MSG } = opts;
  const fields = [type, identifier, '', via, 'v1', String(Date.now()), rawB64uSegment, '', String(message)];
  const sigs = await SignerStub.signUsingDeviceKeys(deviceKeys)(fields.join(';'));
  fields[8] = sigs.join(';');
  return '|' + fields.join(';') + '|';
};

// --- minted responses (Stage 3 with real ECDSA) ---------------------------------------

const RESP_DESKTOP   = await mint(john.devices[0].keys);                                   // john desktop, 1 key, empty signedMetadata
const RESP_LAPTOP    = await mint(john.devices[1].keys);                                   // john laptop, 2 keys
const RESP_LAPTOP_LASTFRAG = await mint([john.devices[1].keys[1]]);                        // laptop key #2 only — pairs with a laptop[2/2]-only DNS patch (sparse final fragment)
// Private mode: the identity's lookup code rides signed-metadata; the DNS carries the commit record.
const RESP_PRIVATE    = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode } });
// A lookupCode member and an attachments member together: the stamp-flow attachments rejection still fires.
const RESP_PRIVATE_ATT = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode, attachments: [] } });
const RESP_STAMPONLY = await mint(john.devices[0].keys, { identifier: STAMPONLY_ID });     // key use=stamp CAN stamp
// Only the FIRST of laptop's two keys signs → the device group can never be fully satisfied
// (key[1] never matches) → exercises IdentityKeys.verify's per-key `break` → 401.
const RESP_LAPTOP_PARTIAL = await mint([john.devices[1].keys[0]]);

// STAMP-DISTINCT attachment negatives (signedMetadata is part of the signed payload, so these carry
// a real signature). A stamp whose response signedMetadata contains attachments fails verification.
const RESP_RESPATT = await mint(john.devices[0].keys, { signedMetadata: { attachments: [ATT] } }); // responseAttachments truthy → 401
const RESP_ED_ATT_NULL = await mint(ed25519.keys, { identifier: ed25519.identifier, signedMetadata: { attachments: null } }); // signedMetadata CARRIES attachments with a null value → 401 (Ed25519 keeps the minted bytes deterministic)
// A stamp whose signedMetadata carries an unrelated (non-attachments) key: stamp does NOT inspect
// it beyond `.attachments`, so it stamps successfully and the metadata is echoed in the result.
const RESP_SIGMETA  = await mint(john.devices[0].keys, { signedMetadata: { note: 'stamp-ignores-non-attachment-metadata' } });

// Valid signatures that still get rejected (the point of each is a NON-crypto rejection):
const RESP_JANE         = await mint(jane.keys, { identifier: jane.identifier });          // jane stamps john's message → wrong identity → 401
const RESP_VIA_ATTACKER = await mint(john.devices[0].keys, { via: 'https://attacker.example/' }); // cburl base != sig.via → 401
const RESP_SIGNONLY     = await mint(signonly.keys, { identifier: signonly.identifier });  // valid crypto, but key use=sign blocks stamp → 401

// 10-min... no — 10-SECOND-old signature is unnecessary: the challenge.iat check and the signature
// ts check are independent, and a fresh (ts=T) signature sits comfortably inside stamp's widened
// signature window [T-45s, T+30s]. So the "10s-old challenge still stamps" success reuses RESP_DESKTOP.

// signedMetadata that decodes to a JSON array → safeParseJson rejects non-object root → 225.
const RESP_GARBAGE_SIGNED = await mint(john.devices[0].keys, { signedMetadata: ['totally', 'wrong', 'shape'] });
const RESP_PROTO_SIGNED   = await mint(john.devices[0].keys, { signedMetadata: JSON.parse('{"__proto__":{"polluted":true,"isAdmin":true}}') });
const RESP_RAWTEXT_SIGNED = await mintRawSigned(john.devices[0].keys, 'c29tZS1yYW5kb20tcGxhaW4tdGV4dC1ub3QtanNvbg'); // "some-random-plain-text-not-json"
const RESP_BOM_SIGNED     = await mintRawSigned(john.devices[0].keys, "77u_eyJleHQiOnsiYm9tIjp0cnVlfX0"); // EF BB BF + {"ext":{"bom":true}} — BOM must not be stripped

// unsignedMetadata safeParseJson limit/poisoning fixtures (real sig, slot-6 MITM swap).
const RESP_GARBAGE_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, ['evil', 'array', 'in', 'unsignedMetadata']);
const RESP_RAWBIN_UNSIGNED  = await mintRawUnsigned(john.devices[0].keys, 'AAECAwQFBgcICQoLDA0ODw'); // raw 0x00..0x0F
const RESP_DEEP_UNSIGNED    = await mintUnsignedSwap(john.devices[0].keys, {a:{b:{c:{d:{e:{f:{g:{h:{}}}}}}}}}); // depth 9 > 8
const RESP_LONGKEY_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, {['a'.repeat(257)]: 1});
const RESP_NONASCII_UNSIGNED= await mintRawUnsigned(john.devices[0].keys, 'eyJy6XN1bekiOjF9'); // {"r<0xE9>sum<0xE9>":1} — raw Latin-1 é: ill-formed UTF-8, refused at decode -> 225
const RESP_BADUTF8_VALUE_UNSIGNED = await mintRawUnsigned(john.devices[0].keys, 'eyJleHQiOnsiYSI6IukifX0'); // {"ext":{"a":"<0xE9>"}} — raw Latin-1 é inside a string VALUE: ill-formed UTF-8, refused at decode -> 225
const RESP_EKEY_UNSIGNED    = await mintRawUnsigned(john.devices[0].keys, 'eyJyw6lzdW3DqSI6MX0'); // {"résumé":1} as proper C3 A9 UTF-8 — decodes fine; the Bounded-JSON ASCII-key rule rejects -> 225
const RESP_SURROGATE_KEY_UNSIGNED = await mintRawUnsigned(john.devices[0].keys, 'eyJ4XHVkODAweSI6MX0'); // {"x\ud800y":1} — a lone-surrogate JSON ESCAPE in a key; every parser behavior converges on 225 (preserve -> non-ASCII key, substitute U+FFFD -> likewise, reject -> parse failure)
const RESP_PROTO_UNSIGNED   = await mintUnsignedSwap(john.devices[0].keys, { constructor: { prototype: { escalated: true, evilFn: 'marker' } } });
const RESP_NULLVALUE_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, {ok: null}); // valid → success

// --- hand-written (no valid crypto needed) responses ----------------------------------
// A bogus stamp envelope that is syntactically valid (passes validateResponse + Signature parse)
// but whose AAAA "signature" can never verify against John's real key → generic 401.
const RESP_BOGUS = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|';
// Well-formed SIGN/AUTH-typed envelopes; the stamp flow's type constraint rejects them before crypto → 401.
const RESP_SIGN_TYPED = '|sign;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|';
const RESP_AUTH_TYPED = '|auth;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|';
// Two stacked stamp segments → exceeds maxSignatures=1 → 401 (both segments parse fine).
const RESP_TWO_SEGMENTS = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;BBBB|';
// 11 crypto signatures inside ONE segment → trips IdentityKeys.verify's maxKeysPerSignature=10 guard.
const RESP_ELEVEN_SIGS = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA;BBBB;CCCC;DDDD;EEEE;FFFF;GGGG;HHHH;IIII;JJJJ;KKKK|';
// 6 signature segments → trips MultiSignature's maxMultiSignatures=5 guard (in the constructor,
// before any segment is parsed) → 225.
const RESP_SIX_SEGMENTS = '|' + Array.from({ length: 6 }, () => 'stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA').join('|') + '|';
// Fresh challenge (iat in window) but the SIGNATURE's own ts is outside the widened window —
// exercises Signature.verify's ts check (returns null), distinct from Response.verify's
// challenge.iat check. Crypto is never reached (the ts check precedes it), so AAAA is fine.
const RESP_TS_PAST   = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1700000000000;;;AAAA|';
const RESP_TS_FUTURE = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1800000000000;;;AAAA|';
// A single-character crypto signature: passes the Signature/IdentityKeys base64url guards (one
// char is "base64url"), but atob() of a 1-char string throws inside the ECDSA verifier's
// base64UrlToUint8 → caught by Ecdsa.verify's try/catch → false → 401. Exercises that catch.
const RESP_ONECHAR_SIG = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;A|';

// --- WebAuthn (type=webauthn-es256) responses -----------------------------------------
// The WebAuthn verifier is reached when the matched device key has type=webauthn-es256. The
// envelope's crypto signature is over (authenticatorData || sha256(clientDataJSON)); the assertion
// (clientDataJSON + authenticatorData) is carried in unsignedMetadata.sig[idx]. The verifier checks
// clientData.challenge === sha256(reconstructed envelope payload), type === 'webauthn.get',
// crossOrigin === false, and origin === <the resolved authentication endpoint origin>. We reuse john's desktop
// P-256 keypair as the underlying WebAuthn key (published under webauthn._at).
const WA_ID = 'webauthn@triauthdemo.org';
const WA_ORIGIN = 'https://auth.triauthdemo.org'; // the RESOLVED authentication-endpoint origin (triauthdemo.org's `triauth` record → auth.triauthdemo.org); the origin the real Authenticator page runs at, NOT the identifier domain
const WA_AUTHDATA = 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAw';                       // realistic authenticatorData
const WA_PAYLOAD = ['stamp', WA_ID, '', VIA, 'v1', String(T), '', '', MSG].join(';');           // exact reconstructed signed payload
const WA_CHAL = await Triauth.Helpers.sha256(WA_PAYLOAD);                                       // expected clientData.challenge

const mkWebAuthn = async ({
  origin = WA_ORIGIN, type = 'webauthn.get', crossOrigin = false,
  challenge = null, clientDataJSON = null, authenticatorData = WA_AUTHDATA,
  sign = true, unsigned = undefined, idx = '0',
} = {}) => {
  const cdj = clientDataJSON !== null ? clientDataJSON
    : JSON.stringify({ type, challenge: challenge ?? WA_CHAL, origin, crossOrigin });

  let cryptoSig = 'AAAA'; // bogus default (negatives that fail before crypto.subtle.verify)
  if (sign) {
    const authBytes = Triauth.Helpers.base64UrlToUint8(authenticatorData);
    const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(cdj)));
    const waPayload = new Uint8Array([...authBytes, ...cdjHash]);
    const key = await crypto.subtle.importKey('jwk', john.devices[0].keys[0].private, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    cryptoSig = Triauth.Helpers.arrayBufferToBase64Url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, waPayload));
  }

  const unsignedMeta = unsigned !== undefined ? unsigned : { sig: { [idx]: { clientDataJSON: cdj, authenticatorData } } };
  const encUnsigned = (unsignedMeta && Object.keys(unsignedMeta).length > 0) ? Triauth.Helpers.stringToBase64Url(JSON.stringify(unsignedMeta)) : '';
  return '|' + ['stamp', WA_ID, '', VIA, 'v1', String(T), '', encUnsigned, cryptoSig].join(';') + '|';
};

const RESP_WA_OK        = await mkWebAuthn();                                                                // valid assertion → success
const RESP_WA_BADSIG    = await mkWebAuthn({ sign: false });                                                 // structure/clientData valid, crypto false → 401
const RESP_WA_NOSIG     = await mkWebAuthn({ sign: false, unsigned: {} });                                   // no sig object
const RESP_WA_NOIDX     = await mkWebAuthn({ sign: false, unsigned: { sig: {} } });                          // no sig[idx]
const RESP_WA_CDJ_NOSTR = await mkWebAuthn({ sign: false, unsigned: { sig: { '0': { clientDataJSON: 123, authenticatorData: WA_AUTHDATA } } } }); // clientDataJSON not a string
const RESP_WA_AD_NOB64  = await mkWebAuthn({ sign: false, unsigned: { sig: { '0': { clientDataJSON: '{}', authenticatorData: '!!!' } } } });      // authenticatorData not base64url
const RESP_WA_BADCHAL   = await mkWebAuthn({ sign: false, challenge: 'A'.repeat(43) });                      // wrong challenge
const RESP_WA_DUPCHAL   = await mkWebAuthn({ sign: false, clientDataJSON: `{"type":"webauthn.get","challenge":"${WA_CHAL}","challenge":"${WA_CHAL}","origin":"${WA_ORIGIN}","crossOrigin":false}` }); // "challenge": twice
const RESP_WA_BADTYPE   = await mkWebAuthn({ sign: false, type: 'webauthn.create' });                        // wrong type
const RESP_WA_CROSSORIG = await mkWebAuthn({ sign: false, crossOrigin: true });                              // crossOrigin true
const RESP_WA_BADORIGIN = await mkWebAuthn({ sign: false, origin: 'https://evil.example' });                 // wrong origin
const RESP_WA_BADJSON   = await mkWebAuthn({ sign: false, clientDataJSON: 'notjson' });                      // clientDataJSON not valid JSON → safeParseJson throws

// Variants of WA_AUTHDATA with a different flags byte (byte 32) and/or truncated length, for the
// UP/UV flag-enforcement tests. The assertion is still genuinely signed over the modified bytes,
// so a rejection can only come from the flag/length checks - not from the crypto verification.
const waAuthData = (flagsByte, length = 37) => {
  const bytes = Triauth.Helpers.base64UrlToUint8(WA_AUTHDATA).slice(0, length);
  if (length > 32) bytes[32] = flagsByte;
  return Triauth.Helpers.arrayBufferToBase64Url(bytes);
};
const RESP_WA_NOUP  = await mkWebAuthn({ authenticatorData: waAuthData(0x00) });     // signed, UP flag cleared → 401
const RESP_WA_SHORT = await mkWebAuthn({ authenticatorData: waAuthData(0x01, 36) }); // signed, 36-byte authenticatorData → 401
const RESP_WA_UPUV  = await mkWebAuthn({ authenticatorData: waAuthData(0x05) });     // signed, UP|UV set → satisfies uv=required

// --- Ed25519 (type=ed25519) and WebAuthn-Ed25519 (type=webauthn-ed25519) responses ----
// Plain Ed25519 mirrors the ECDSA flow exactly (the envelope's crypto signature is Ed25519 over the
// same payload); WebAuthn-Ed25519 mirrors webauthn-es256 with the assertion signed by Ed25519.
const RESP_ED25519_OK    = await mint(ed25519.keys, { identifier: ed25519.identifier });
const RESP_ED_LAN        = await mint(ed25519.keys, { identifier: ed25519.identifier, via: LAN_VIA });
const RESP_ED25519_BOGUS = `|stamp;${ed25519.identifier};;${VIA};v1;${T};;;AAAA|`;       // parses fine, fails Ed25519 crypto → 401

const WAED_ID = 'webauthn-ed25519@triauthdemo.org';
const WAED_PAYLOAD = ['stamp', WAED_ID, '', VIA, 'v1', String(T), '', '', MSG].join(';'); // exact reconstructed signed payload
const WAED_CHAL = await Triauth.Helpers.sha256(WAED_PAYLOAD);                           // expected clientData.challenge

const mkWebAuthnEd25519 = async ({ sign = true } = {}) => {
  const cdj = JSON.stringify({ type: 'webauthn.get', challenge: WAED_CHAL, origin: WA_ORIGIN, crossOrigin: false });

  let cryptoSig = 'AAAA'; // bogus default (negative that fails only at crypto.subtle.verify)
  if (sign) {
    const authBytes = Triauth.Helpers.base64UrlToUint8(WA_AUTHDATA);
    const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(cdj)));
    const waPayload = new Uint8Array([...authBytes, ...cdjHash]);
    const key = await crypto.subtle.importKey('jwk', ed25519.keys[0].private, { name: 'Ed25519' }, false, ['sign']);
    cryptoSig = Triauth.Helpers.arrayBufferToBase64Url(await crypto.subtle.sign({ name: 'Ed25519' }, key, waPayload));
  }

  const encUnsigned = Triauth.Helpers.stringToBase64Url(JSON.stringify({ sig: { '0': { clientDataJSON: cdj, authenticatorData: WA_AUTHDATA } } }));
  return '|' + ['stamp', WAED_ID, '', VIA, 'v1', String(T), '', encUnsigned, cryptoSig].join(';') + '|';
};

const RESP_WAED_OK     = await mkWebAuthnEd25519();              // valid Ed25519-backed assertion → success
const RESP_WAED_BADSIG = await mkWebAuthnEd25519({ sign: false }); // structure/clientData valid, crypto false → 401
// Signature-envelope field-format rejections (Signature constructor → 225). Each isolates one slot.
const RESP_BADVIA      = '|stamp;john@triauthdemo.org;;-;v1;1777454675000;;;AAAA|';                       // via not a URL
const RESP_NONASCII_VIA= '|stamp;john@triauthdemo.org;;https://example.com/é;v1;1777454675000;;;AAAA|';   // via not isNormalString
const RESP_BADTYPE     = '|bogus;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|';    // type not in VALID_TYPES
const RESP_BADID       = '|stamp;not-valid;;https://example.com/;v1;1777454675000;;;AAAA|';               // envelope identifier invalid
const RESP_BADVER      = '|stamp;john@triauthdemo.org;;https://example.com/;v2;1777454675000;;;AAAA|';    // ver != v1
const RESP_BADTS       = '|stamp;john@triauthdemo.org;;https://example.com/;v1;0;;;AAAA|';                // ts fails /^[1-9].../
const RESP_NOSIG       = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;|';        // no crypto signature segment
const RESP_BADSIGB64   = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AA!A|';    // crypto sig not base64url
const RESP_BADSIGMETA  = '|stamp;john@triauthdemo.org;;https://example.com/;v1;1777454675000;!!!;;AAAA|'; // signedMetadata slot not base64url
const RESP_EMPTY_SEGS  = '||||';                                                                         // empty segments → Signature length guard → 225

// --- DNS layout (mirrors sign.json's John/multi/nokeys/signonly/jane/webauthn/private/ambiguous/
//     unconfigured, with stamponly replacing authonly) ----------------------------------
const dnsEntries = {
  'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
  'john._at.triauthdemo.org': { TXT: [
    'initials JD',
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `key laptop[1/2]:${john.devices[1].keys[0].public}`,
    `key laptop[2/2]:${john.devices[1].keys[1].public}`,
  ] },
  'multi._at.triauthdemo.org': { TXT: [
    'name Multi Device',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `key laptop[1/1]:${john.devices[1].keys[0].public}`,
  ] },
  'nokeys._at.triauthdemo.org': { TXT: ['name No Keys', 'initials NK'] },
  'signonly._at.triauthdemo.org': { TXT: [
    'name Sign Only',
    `key desktop[1/1]:${signonly.keys[0].public} use=sign`,
  ] },
  'stamponly._at.triauthdemo.org': { TXT: [
    'name Stamp Only',
    `key desktop[1/1]:${john.devices[0].keys[0].public} use=stamp`,
  ] },
  'jane._at.triauthdemo.org': { TXT: [
    'initials JR',
    'name Jane Roe',
    `key desktop[1/1]:${jane.keys[0].public}`,
  ] },
  'webauthn._at.triauthdemo.org': { TXT: [
    'name WebAuthn',
    `key wa[1/1]:${john.devices[0].keys[0].public} type=webauthn-es256`,
  ] },
  'ed25519._at.triauthdemo.org': { TXT: [
    'name Ed25519',
    `key desktop[1/1]:${ed25519.keys[0].public} type=ed25519`,
  ] },
  'webauthn-ed25519._at.triauthdemo.org': { TXT: [
    'name WebAuthn Ed25519',
    `key wa[1/1]:${ed25519.keys[0].public} type=webauthn-ed25519`,
  ] },
  [PRIVATE.domain]: { TXT: [PRIVATE.endpointRecord] },
  [PRIVATE.john.identityDomain]: { TXT: [
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `commit ${PRIVATE.john.commitment}`,
  ] },
  'ambiguous.example': { TXT: ['triauth a.endpoint.example mode=public', 'triauth b.endpoint.example mode=public'] },
  'unconfigured.example': { TXT: [] },
};

// Per-test DNS patch helpers (shallow-merged over the suite-level entries by the runner).
const johnKeyRecord = (suffix = '', meta) => {
  const rec = `key desktop[1/1]:${john.devices[0].keys[0].public}${suffix}`;
  return { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', meta ? { value: rec, ...meta } : rec] } };
};
// A patch that publishes a john._at record set with a single replacement key record (plus profile).
const johnSingleKey = (keyRecord) => ({ 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', keyRecord] } });
// A patch that republishes the webauthn identity's key record with extra options appended (e.g., ' uv=required').
const waKeyRecord = (suffix = '') => ({ 'webauthn._at.triauthdemo.org': { TXT: ['name WebAuthn', `key wa[1/1]:${john.devices[0].keys[0].public} type=webauthn-es256${suffix}`] } });
// 11 devices: dev01..dev10 (dummy keys) + john's real desktop key. The 11th (desktop) is dropped
// by the maxDevices=10 guard, leaving only unusable dummy groups → 401.
const elevenDevices = { 'john._at.triauthdemo.org': { TXT: [
  'initials JD', 'name John Doe',
  ...Array.from({ length: 10 }, (_, i) => `key dev${String(i + 1).padStart(2, '0')}[1/1]:AAAA`),
  `key desktop[1/1]:${john.devices[0].keys[0].public}`,
] } };

// Shorthands for building test objects (expected is filled by RECORD mode).
const s1 = (name, options, extra = {}) => ({ name, call: 'stamp', args: [options], ...extra });
const s3 = (name, args, extra = {}) => ({ name, call: 'stamp', args: [args], ...extra });

const tests = [
  // ===================================================================================
  // Dispatch & argument-shape guards (flow-level, before Stage 1/3 detection)
  // ===================================================================================
  s3('empty options object returns 101 (matches neither Stage 1 nor Stage 3)', {}),
  s3('STAMP-DISTINCT: null sole arg is normalized to {} by _perform Object.assign → 101 (ping/attest 102 here)', null,
    { _argsOverride: [null] }),
  s3('STAMP-DISTINCT: empty-array sole arg is normalized to {} by _perform Object.assign → 101', null,
    { _argsOverride: [[]] }),
  s1('Stage 1 unrecognized option returns 102', { identifier: ID, callbackUrl: CB, message: MSG, unknownKey: 'x' }),
  s3('Stage 3 unrecognized option returns 102', { challenge: CH, response: RESP_DESKTOP, unknownKey: 1 }),

  // ===================================================================================
  // Stage 1 — identifier validation (210-216)
  // ===================================================================================
  s1('Stage 1 non-string identifier returns 210', { identifier: 123, callbackUrl: CB, message: MSG }),
  s1("Stage 1 identifier with whitespace returns 210 (the /[\\s\\0]/ branch, distinct from non-string 210)",
    { identifier: 'john @triauthdemo.org', callbackUrl: CB, message: MSG }),
  s1('Stage 1 empty-string identifier returns 211', { identifier: '', callbackUrl: CB, message: MSG }),
  s1('Stage 1 too-long identifier returns 212 (byteSize check before username regex)',
    { identifier: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@triauthdemo.org', callbackUrl: CB, message: MSG }),
  s1('Stage 1 uppercase identifier returns 213', { identifier: 'John@triauthdemo.org', callbackUrl: CB, message: MSG }),
  s1('Stage 1 identifier missing @-sign returns 214', { identifier: 'johntriauthdemo.org', callbackUrl: CB, message: MSG }),
  s1('Stage 1 identifier with consecutive dots in username returns 215', { identifier: 'john..doe@triauthdemo.org', callbackUrl: CB, message: MSG }),
  s1('Stage 1 identifier with punycode domain returns 216', { identifier: 'john@xn--example.org', callbackUrl: CB, message: MSG }),
  s1('Stage 1 identifier with an IPv4-literal domain (john@1.2.3.4) returns 216 — a numeric final label is never a domain part', { identifier: 'john@1.2.3.4', callbackUrl: CB, message: MSG }),
  s1('Stage 1 identifier with a 64-character domain label returns 216 — labels are capped at 63 characters (the DNS bound)', { identifier: 'john@' + 'a'.repeat(64) + '.com', callbackUrl: CB, message: MSG }),
  s1('Stage 1 identifier with a single-character final label (john@a.b) returns 216', { identifier: 'john@a.b', callbackUrl: CB, message: MSG }),

  // ===================================================================================
  // Stage 1 — callbackUrl (221) & ext (222) validation
  // ===================================================================================
  s1('Stage 1 non-string callbackUrl returns 221', { identifier: ID, callbackUrl: 123, message: MSG }),
  s1('Stage 1 over-length callbackUrl (>2048 bytes) returns 221',
    { identifier: ID, callbackUrl: 'https://example.com/' + 'a'.repeat(2048), message: MSG }),
  s1('Stage 1 plain-http callbackUrl on a named host (http://example.com/cb) passes URL validation; the tokenless request then returns 226 — an ordering pin: the callbackUrl gate precedes the token gate', { identifier: ID, callbackUrl: 'http://example.com/cb', message: MSG }),
  s1("Stage 1 callbackUrl with punycode domain returns 221", {"identifier":ID,"callbackUrl":"https://xn--mller-kva.de/cb","message":"example-data-in-textual-format"}),
  s1('Stage 1 array-shaped ext returns 222', { identifier: ID, callbackUrl: CB, message: MSG, ext: ['not', 'a', 'plain', 'object'] }),

  // ===================================================================================
  // Stage 1 — token validation (226). STAMP allows token (like ping/attest/sign).
  // ===================================================================================
  s1('Stage 1 too-short token (<16 chars) returns 226', { identifier: ID, callbackUrl: CB, message: MSG, token: 'short' }),
  s1('Stage 1 colon-less token returns 226 (a token is issuer:secret - the issuer may be empty, the colon is structural)', { identifier: ID, callbackUrl: CB, message: MSG, token: 'aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 token with more than one colon returns 226', { identifier: ID, callbackUrl: CB, message: MSG, token: 'issuer.example:aaaaaaaaaaaaaaaa:x' }),
  s1('Stage 1 token with an uppercase issuer returns 226 (the issuer must be a canonical lowercase domain)', { identifier: ID, callbackUrl: CB, message: MSG, token: 'Issuer.Example:aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 token with a non-domain issuer returns 226', { identifier: ID, callbackUrl: CB, message: MSG, token: 'not_a_domain:aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 non-string token returns 226', { identifier: ID, callbackUrl: CB, message: MSG, token: 123 }),
  s1('Stage 1 over-length token (>255 bytes, the Normal-String default byte cap) returns 226', { identifier: ID, callbackUrl: CB, message: MSG, token: 'a'.repeat(257) }),

  // ===================================================================================
  // Stage 1 — message validation (227), STAMP-DISTINCT: validated in _perform's onChallenge
  // (after id/url/ext/token, before DNS). A stamp call MUST carry a printable-ASCII message.
  // ===================================================================================
  s1('Stage 1 omitting message entirely returns 227 (isNormalString(undefined) is false)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 non-string message (number) returns 227', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: 123 }),
  s1('Stage 1 empty-string message returns 227 (isNormalString("") is false)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: '' }),
  s1('Stage 1 message with a newline control char returns 227', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: 'line one\nline two' }),
  s1('Stage 1 over-length message (>2048 bytes) returns 227', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: 'a'.repeat(2050) }),

  // ===================================================================================
  // Stage 1 — STAMP-DISTINCT attachments rejection (102), in onChallenge. Unlike sign,
  // passing attachments to stamp is an error (the message-only flow has no attachments).
  // ===================================================================================
  s1('Stage 1 STAMP-DISTINCT: passing an attachments option returns 102 (Attachments only for sign)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG, attachments: [ATT] }),
  s1('Stage 1 STAMP-DISTINCT: even an EMPTY attachments array is truthy and returns 102', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG, attachments: [] }),
  s1('Stage 1 STAMP-DISTINCT: an attachments member with a null value returns 102 — carrying the member at all is the offense', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG, attachments: null }),

  // ===================================================================================
  // Stage 1 — DNS / configuration (301, 110). Stage 1 resolves the endpoint record only; identity
  // existence and the identity-domain derivation are settled on the signed response at stage 3.
  // ===================================================================================
  s1('Stage 1 domain with no triauth TXT record returns 301', { identifier: 'john@unconfigured.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 endpoint record with an invalid (non-domain) value returns 301 (isDomainName false)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, dnsEntries: { 'triauthdemo.org': { TXT: ['triauth invalid_domain mode=public'] } } }),
  s1('Stage 1 domain with multiple triauth TXT records returns 301 (ambiguous, refuse to choose)', { identifier: 'user@ambiguous.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 unknown identifier under a configured domain still builds a challenge - existence is never probed at issue', { identifier: 'ghost@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 per-test dnsEntries patch can NXDOMAIN a known domain (returns 301)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, dnsEntries: { 'triauthdemo.org': null } }),
  s1('Stage 1 endpoint with an unknown mode still builds a challenge - an unresolvable mode surfaces only once a response is verified', { identifier: 'john@hashed.triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, dnsEntries: { 'hashed.triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=unknownmode'] } } }),
  s1('Stage 1 SERVFAIL on the identifier domain (endpoint lookup) surfaces as 110', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, dnsEntries: { 'triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s1('Stage 1 SERVFAIL on the identity domain (records lookup) still builds a challenge - the identity domain is never queried at issue', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, dnsEntries: { 'john._at.triauthdemo.org': { _error: 'SERVFAIL' } } }),

  // ===================================================================================
  // Stage 1 — success (challenge + stamp.html redirectUrl). All deterministic via fixed nonce + clock.
  // ===================================================================================
  s1('Stage 1 STAMP-DISTINCT: deterministic challenge bakes msg (NO attachments), redirect uses /stamp.html', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1("Stage 1 token produces a redirectUrl with a &token= param carrying the token's public part and the hmac", { identifier: ID, callbackUrl: CB, message: MSG, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 token + ext together: challenge bakes the ext, redirectUrl carries the token and its hmac', { identifier: ID, callbackUrl: CB, message: MSG, token: ':aaaaaaaaaaaaaaaa', ext: { stampToken: true } }, { random: RAND }),
  s1("Stage 1 omitting the token returns 226 - token-gated flows require a token at issue (src/challenge_response_flow.js)", {"identifier":ID,"callbackUrl":CB,"message":"example-data-in-textual-format"}, { random: RAND }),
  s1('Stage 1 endpoint record with a __proto__ option is parsed safely (option dropped) and still builds a challenge', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, dnsEntries: { 'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org __proto__=evil mode=public'] } } }),
  s1('Stage 1 challenge bakes in the ext object', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG, ext: { stampToken: true, nested: { foo: 'bar' } } }, { random: RAND }),
  s1('Stage 1 multi-device identity still builds a challenge', { identifier: 'multi@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 identity with a profile but no key records still builds a challenge (key absence surfaces in Stage 3)', { identifier: 'nokeys@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 PRIVATE: a private-mode endpoint builds a challenge without resolving the identity (no lookup code exists server-side)', { identifier: PRIVATE.john.identifier, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 localhost http callbackUrl is accepted and builds a challenge', { identifier: ID, callbackUrl: 'http://localhost:3000/cb', token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 plain-http callbackUrl on a LAN IPv4-literal host (http://10.0.0.5:8080/cb) builds a challenge — self-hosted deployments run on transport the envelope does not depend on', { identifier: ID, callbackUrl: LAN_CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND }),
  s1('Stage 1 per-test currentTime changes the iat baked into the challenge (nonce unchanged)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', message: MSG }, { random: RAND, currentTime: 1800000000000 }),

  // ===================================================================================
  // Stage 3 — challenge (223) & response (224) validation
  // ===================================================================================
  s3('Stage 3 non-string challenge returns 223', { challenge: 12345, response: RESP_DESKTOP }),
  s3('Stage 3 non-base64url challenge returns 223', { challenge: '!!!not-base64url!!!', response: RESP_DESKTOP }),
  s3('Stage 3 challenge is valid base64url but decodes to non-JSON bytes returns 223 (Challenge.fromString parse path)', { challenge: 'AAEC', response: RESP_DESKTOP }),
  s3('Stage 3 SECURITY: challenge whose decoded bytes are a UTF-8 BOM (EF BB BF) followed by the CANONICAL valid challenge JSON returns 223 — the decoder must not strip the BOM (a second, non-canonical byte encoding of the same challenge must never be accepted; ports must not BOM-sniff when decoding base64url payloads)', { challenge: CH_BOM, response: RESP_DESKTOP }),
  s3('Stage 3 challenge decodes to valid JSON but its identifier member is malformed returns 223 (Identity ctor throws inside Challenge.fromString)', { challenge: CH_BADID, response: RESP_DESKTOP }),
  s3('Stage 3 non-string response returns 224', { challenge: CH, response: 12345 }),
  s3('Stage 3 response without the | envelope delimiters returns 224', { challenge: CH, response: 'no-envelope-delimiters' }),
  s3('Stage 3 short/empty response (length <= 3) returns 224 via the validator length-check', { challenge: CH, response: '' }),
  s3('Stage 3 re-provided malformed identifier returns 210 (the optional Stage-3 identifier validator)', { challenge: CH, response: RESP_DESKTOP, identifier: 'john @triauthdemo.org' }),
  s3('Stage 3 re-provided malformed callbackUrl returns 221 (the optional Stage-3 callbackUrl validator)', { challenge: CH, response: RESP_DESKTOP, callbackUrl: 'https://[::1]/cb' }),
  s3('Stage 3 re-provided callbackUrl that is URL-valid but mismatches challenge.cburl (http://example.com/cb vs https) returns 401 — the equality gate, distinct from the 221 format gate', { challenge: CH, response: RESP_DESKTOP, callbackUrl: 'http://example.com/cb' }),

  // ===================================================================================
  // Stage 3 — dispatch-level constraint checks (401) & denial (403)
  // ===================================================================================
  s3("Stage 3 response equal to the literal 'false' returns 403 (user-denial sentinel)", { challenge: CH, response: 'false' }),
  s3('Stage 3 re-provided identifier mismatching challenge.identifier returns 401', { challenge: CH, response: RESP_DESKTOP, identifier: 'someone-else@triauthdemo.org' }),
  s3('Stage 3 re-provided callbackUrl mismatching challenge.cburl returns 401', { challenge: CH, response: RESP_DESKTOP, callbackUrl: 'https://other-domain.example/' }),
  s3("Stage 3 challenge with type=sign (not 'stamp') returns 401 at the flow type-constraint", { challenge: CH_SIGNTYPE, response: RESP_DESKTOP }),
  s3("Stage 3 challenge with type=auth (not 'stamp') returns 401 at the flow type-constraint", { challenge: CH_AUTHTYPE, response: RESP_DESKTOP }),

  // ===================================================================================
  // Stage 3 — signature-envelope parse failures (225), each isolating one field/slot
  // ===================================================================================
  s3("Stage 3 envelope with a malformed via ('-') is rejected at parse time with 225", { challenge: CH, response: RESP_BADVIA }),
  s3('Stage 3 envelope with a non-ASCII via is rejected at parse time with 225', { challenge: CH, response: RESP_NONASCII_VIA }),
  s3('Stage 3 envelope with an unknown type (not in VALID_TYPES) returns 225', { challenge: CH, response: RESP_BADTYPE }),
  s3('Stage 3 envelope with an invalid identifier returns 225', { challenge: CH, response: RESP_BADID }),
  s3('Stage 3 envelope with ver != v1 returns 225', { challenge: CH, response: RESP_BADVER }),
  s3('Stage 3 envelope with a malformed ts (0) returns 225', { challenge: CH, response: RESP_BADTS }),
  s3('Stage 3 envelope with no crypto signature segment returns 225', { challenge: CH, response: RESP_NOSIG }),
  s3('Stage 3 envelope crypto signature that is not base64url returns 225', { challenge: CH, response: RESP_BADSIGB64 }),
  s3('Stage 3 envelope signedMetadata slot that is not base64url returns 225', { challenge: CH, response: RESP_BADSIGMETA }),
  s3("Stage 3 response '||||' parses into empty segments, each tripping the Signature length guard → 225", { challenge: CH, response: RESP_EMPTY_SEGS }),
  s3('Stage 3 more than 5 signature segments trips the MultiSignature maxMultiSignatures=5 count guard → 225', { challenge: CH, response: RESP_SIX_SEGMENTS }),

  // ===================================================================================
  // Stage 3 — generic verification failures (401)
  // ===================================================================================
  s3('Stage 3 well-formed sign-typed envelope against the stamp flow returns 401 (type constraint, before crypto)', { challenge: CH, response: RESP_SIGN_TYPED }),
  s3('Stage 3 well-formed auth-typed envelope against the stamp flow returns 401', { challenge: CH, response: RESP_AUTH_TYPED }),
  s3('Stage 3 well-formed stamp envelope with bogus crypto bytes returns 401 (generic verification failure)', { challenge: CH, response: RESP_BOGUS }),
  s3('Stage 3 a 1-char crypto signature makes atob throw inside the ECDSA verifier → caught → 401', { challenge: CH, response: RESP_ONECHAR_SIG }),
  s3('Stage 3 two stacked signatures exceed maxSignatures=1 returns 401 (count guard before per-sig verify)', { challenge: CH, response: RESP_TWO_SEGMENTS }),
  s3('Stage 3 a single segment carrying 11 crypto signatures exceeds IdentityKeys maxKeysPerSignature=10 → 401', { challenge: CH, response: RESP_ELEVEN_SIGS }),
  s3('Stage 3 cryptographically valid signature for the WRONG identity (jane stamps john message) returns 401', { challenge: CH, response: RESP_JANE }),
  s3('Stage 3 cryptographically valid signature with envelope.via on a DIFFERENT ORIGIN returns 401 (cburl base != sig.via)', { challenge: CH, response: RESP_VIA_ATTACKER }),
  s3('Stage 3 challenge with a malformed embedded cburl returns 401 (onResponse validateCallbackUrl(cburl) fails)', { challenge: CH_BADCBURL, response: RESP_DESKTOP }),
  s3('Stage 3 STAMP-DISTINCT use mismatch: a stamp-typed envelope from a use=sign key returns 401 (key skipped, no verified keys)', { challenge: CH_SIGNONLY, response: RESP_SIGNONLY }),
  s3('Stage 3 partial multi-key signature (only laptop key 1 of 2 signs) returns 401 (per-key break, group never fully satisfied)', { challenge: CH, response: RESP_LAPTOP_PARTIAL }),
  s3('Stage 3 the signature covers a different message than challenge.msg returns 401 (msg<->signature binding)', { challenge: CH_MSG_DIFF, response: RESP_DESKTOP }),

  // ===================================================================================
  // Stage 3 — STAMP-DISTINCT attachment rejection in onResponse
  // ===================================================================================
  s3('Stage 3 STAMP-DISTINCT: a challenge carrying an attachments field returns 102 (onResponse else-if challengeAttachments)', { challenge: CH_ATT, response: RESP_DESKTOP }),
  s3('Stage 3 STAMP-DISTINCT: even an empty challenge attachments array is truthy → 102', { challenge: CH_ATT_EMPTY, response: RESP_DESKTOP }),
  s3('Stage 3 STAMP-DISTINCT: a challenge carrying attachments with a null value returns 102 — membership, not truthiness', { challenge: CH_ATT_NULL, response: RESP_DESKTOP }),
  s3('Stage 3 STAMP-DISTINCT: a verified stamp whose signedMetadata carries attachments fails with 401 (responseAttachments truthy → false)', { challenge: CH, response: RESP_RESPATT }),
  s3('Stage 3 STAMP-DISTINCT: a verified stamp whose signedMetadata carries attachments with a null value fails with 401 — "carries" is membership, not truthiness', { challenge: CH_ED25519, response: RESP_ED_ATT_NULL }),

  // ===================================================================================
  // Stage 3 — identity / DNS failures during verification (401)
  // ===================================================================================
  s3("Stage 3 envelope.identifier's identity records vanished between stages (NXDOMAIN) returns 401", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': null } }),
  s3("Stage 3 envelope.identifier's authentication endpoint is gone (NXDOMAIN) returns 401", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'triauthdemo.org': null } }),
  s3('Stage 3 DNS SERVFAIL on the authentication endpoint propagates from signature.verify and surfaces as a retryable 110 (not a false 401)', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s3('Stage 3 DNS SERVFAIL on the identity domain propagates from signature.verify and surfaces as a retryable 110 (not a false 401)', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { _error: 'SERVFAIL' } } }),

  // ===================================================================================
  // Stage 3 — IdentityKeys.add / verify branches reached via the stamp verify path (→ 401)
  // ===================================================================================
  s3('Stage 3 identity key with invalid syntax (missing [idx/count]) leaves no usable keyGroup → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key desktop:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 identity key that taints its device group (desktop[2/1]) leaves no valid keyGroup → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key desktop[2/1]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 SECURITY: split key group published only as its final fragment (laptop[2/2] alone, no laptop[1/2]) never validates — a lone write to the group\'s last index already inflates keys.length to keyCount and Object.entries/.every iteration skips array holes, so a length-gated validity check would accept the one-signature response from the published fragment; the populated-slot count (src/identity_keys.js:153-157) keeps the group invalid → 401', { challenge: CH, response: RESP_LAPTOP_LASTFRAG }, { dnsEntries: johnSingleKey(`key laptop[2/2]:${john.devices[1].keys[1].public}`) }),
  s3('Stage 3 leading-zero keyIdx (desktop[01/1]) maps to literal 0, failing the range check and tainting the group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key desktop[01/1]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 leading-zero keyCount (desktop[1/01]) maps to literal 0, failing the range check and tainting the group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key desktop[1/01]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 a doubled key index (two desktop[1/1] records) un-validates the already-valid group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', `key desktop[1/1]:${john.devices[0].keys[0].public}`, `key desktop[1/1]:${john.devices[1].keys[0].public}`] } } }),
  s3('Stage 3 identity key value that is not base64url taints the group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey('key desktop[1/1]:has!bang') }),
  s3('Stage 3 identity key value valid base64url but too short to initialize an ECDSA verifier (AAAA) → 401 (null-verifier continue)', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey('key desktop[1/1]:AAAA') }),
  s3('Stage 3 identity key with a deviceName longer than the record-name regex allows ({1,20}, the 20-byte limit) is dropped → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key abcdefghijklmnopqrstu[1/1]:${john.devices[0].keys[0].public}`) }),
  s3("Stage 3 identity records publishing more than maxDevices=10 devices drop the 11th (john's real key) → 401", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: elevenDevices }),
  s3('Stage 3 identity key with an unknown critical (non x-) option taints its device group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord(' badopt=value') }),
  s3('Stage 3 key record with a negative TTL yields an already-expired keyGroup that is skipped → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord('', { ttl: -2000, dnssec: true }) }),
  s3('Stage 3 TTL-less key record (expires undefined) with bogus crypto → 401 (exercises the expires!==undefined false branch)', { challenge: CH, response: RESP_BOGUS }, { dnsEntries: johnKeyRecord('', { dnssec: true }) }),

  // ===================================================================================
  // Stage 3 — expired / time-window (402). STAMP-DISTINCT: notBefore = now - stampTimeout (15s).
  // ===================================================================================
  s3('Stage 3 challenge iat far before notBefore returns 402', { challenge: CH_PAST, response: RESP_DESKTOP }),
  s3('Stage 3 challenge iat in the future (after notAfter == now) returns 402', { challenge: CH_FUTURE, response: RESP_DESKTOP }),
  s3('Stage 3 STAMP-DISTINCT: a 60s-old challenge (still valid for authenticate, authTimeout 3min) is already expired for stamp (stampTimeout 15s) → 402', { challenge: CH_60S, response: RESP_DESKTOP }),
  // The 402 boundary sits at stampTimeout + maximalAllowedServerClockDrift: a CH_JUST_EXP challenge
  // (1ms past the bare 15s window relative to T) only expires once the clock has also advanced past
  // the 5s server-drift widening, so this test verifies at T + 5s.
  s3('Stage 3 challenge iat 1ms past the 15s stampTimeout + 5s maximalAllowedServerClockDrift returns 402 (boundary)', { challenge: CH_JUST_EXP, response: RESP_DESKTOP }, { currentTime: T + 5e3 }),
  s3('Stage 3 challenge with a non-numeric iat returns 402 (Response.verify typeof-guard)', { challenge: CH_IAT_NAN, response: RESP_DESKTOP }),
  s3('Stage 3 fresh challenge but the SIGNATURE ts is before the widened window → 402 (Signature.verify ts check)', { challenge: CH, response: RESP_TS_PAST }),
  s3('Stage 3 fresh challenge but the SIGNATURE ts is after the widened window → 402', { challenge: CH, response: RESP_TS_FUTURE }),

  // ===================================================================================
  // Stage 3 — metadata parse rejections (225), shared Signature/safeParseJson machinery
  // ===================================================================================
  s3('Stage 3 garbage signedMetadata (decodes to a JSON array) returns 225', { challenge: CH, response: RESP_GARBAGE_SIGNED }),
  s3('Stage 3 __proto__-poisoning signedMetadata is caught by safeParseJson → 225', { challenge: CH, response: RESP_PROTO_SIGNED }),
  s3('Stage 3 signedMetadata that is valid base64url but non-JSON text returns 225', { challenge: CH, response: RESP_RAWTEXT_SIGNED }),
  s3("Stage 3 SECURITY: signedMetadata segment decodes to a UTF-8 BOM (EF BB BF) followed by otherwise-valid ext JSON ({\"ext\":{\"bom\":true}}) — rejected at parse time with 225; the decoder must not strip the BOM, so a non-canonical byte encoding of valid metadata is never accepted (real signature covers the BOM segment)", { challenge: CH, response: RESP_BOM_SIGNED }),
  s3('Stage 3 garbage unsignedMetadata (decodes to a JSON array) returns 225 (real sig, slot MITM-swapped)', { challenge: CH, response: RESP_GARBAGE_UNSIGNED }),
  s3('Stage 3 constructor.prototype-poisoning unsignedMetadata is caught by safeParseJson (second clause) → 225', { challenge: CH, response: RESP_PROTO_UNSIGNED }),
  s3('Stage 3 unsignedMetadata of raw binary bytes (no valid JSON token) returns 225', { challenge: CH, response: RESP_RAWBIN_UNSIGNED }),
  s3('Stage 3 unsignedMetadata nested 9 deep exceeds jsonMaxNestingDepth=8 → 225', { challenge: CH, response: RESP_DEEP_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a 257-char key exceeds jsonMaxKeyLength=256 → 225', { challenge: CH, response: RESP_LONGKEY_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a non-ASCII key returns 225', { challenge: CH, response: RESP_NONASCII_UNSIGNED }),
  s3('Stage 3 SECURITY: unsignedMetadata whose bytes are not well-formed UTF-8 inside a string value returns 225 — payload-slot bytes must be well-formed UTF-8; decoders reject rather than substitute U+FFFD (string values have no charset rule of their own, so only the decode-time rejection pins this)', { challenge: CH, response: RESP_BADUTF8_VALUE_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a non-ASCII key in well-formed UTF-8 ({"résumé":1} as C3 A9 bytes) returns 225 — the Bounded-JSON ASCII-key rule, distinct from the ill-formed-byte rejection', { challenge: CH, response: RESP_EKEY_UNSIGNED }),
  s3('Stage 3 SECURITY: unsignedMetadata whose JSON carries a lone-surrogate escape (\\ud800) in a key returns 225 — parser-independent: a parser that preserves the escape yields a non-ASCII key, one that substitutes U+FFFD likewise, one that rejects it fails the parse; no conformance vector requires accepting a lone-surrogate escape anywhere', { challenge: CH, response: RESP_SURROGATE_KEY_UNSIGNED }),

  // ===================================================================================
  // Stage 3 — WebAuthn verifier backend (key type=webauthn-es256), reached via IdentityKeys.verify.
  // Covers fromPublishableKey (import success + failure) and every structure / clientData guard:
  // the crypto signature is over (authenticatorData || sha256(clientDataJSON)) and the assertion
  // travels in unsignedMetadata.sig[idx].
  // ===================================================================================
  s3('Stage 3 WebAuthn valid assertion (challenge=sha256(payload), webauthn.get, matching origin, crossOrigin=false) stamps successfully', { challenge: CH_WA, response: RESP_WA_OK }),
  s3('Stage 3 WebAuthn structurally valid assertion but a bad ECDSA signature → 401 (crypto.subtle.verify false)', { challenge: CH_WA, response: RESP_WA_BADSIG }),
  s3('Stage 3 WebAuthn unsignedMetadata has no sig object → 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_NOSIG }),
  s3('Stage 3 WebAuthn sig has no entry for the key index → 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_NOIDX }),
  s3('Stage 3 WebAuthn clientDataJSON is not a string → 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_CDJ_NOSTR }),
  s3('Stage 3 WebAuthn authenticatorData is not base64url → 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_AD_NOB64 }),
  s3('Stage 3 WebAuthn clientData.challenge != sha256(payload) → 401', { challenge: CH_WA, response: RESP_WA_BADCHAL }),
  s3('Stage 3 WebAuthn clientDataJSON contains "challenge": more than once → 401 (anti-injection guard)', { challenge: CH_WA, response: RESP_WA_DUPCHAL }),
  s3("Stage 3 WebAuthn clientData.type != 'webauthn.get' → 401", { challenge: CH_WA, response: RESP_WA_BADTYPE }),
  s3('Stage 3 WebAuthn clientData.crossOrigin is not false → 401', { challenge: CH_WA, response: RESP_WA_CROSSORIG }),
  s3('Stage 3 WebAuthn clientData.origin != the authentication endpoint origin → 401', { challenge: CH_WA, response: RESP_WA_BADORIGIN }),
  s3('Stage 3 WebAuthn clientDataJSON is not valid JSON → safeParseJson throws → caught → 401', { challenge: CH_WA, response: RESP_WA_BADJSON }),
  s3('Stage 3 WebAuthn published key value too short to import → fromPublishableKey returns null → 401', { challenge: CH_WA, response: RESP_WA_OK }, { dnsEntries: { 'webauthn._at.triauthdemo.org': { TXT: ['name WebAuthn', 'key wa[1/1]:AAAA type=webauthn-es256'] } } }),

  // ===================================================================================
  // Stage 3 — onResponse message guard (227): the msg is read back FROM the challenge.
  // ===================================================================================
  s3('Stage 3 challenge missing the msg field → 227 (onResponse validateMessage(undefined))', { challenge: CH_NOMSG, response: RESP_DESKTOP }),
  s3('Stage 3 challenge with a control-char msg → 227 (onResponse validateMessage)', { challenge: CH_BADMSG, response: RESP_DESKTOP }),

  // ===================================================================================
  // Stage 3 — SUCCESS (stamped:true). Pins stamp's result shape:
  //   {stamped:true, result, verificationResult:{valid,type:'stamp',identifier,identityDomain,lookupCode,actor,actorIdentityDomain,actorLookupCode,via,ver,ts,
  //    publicProfile,deviceName,deviceTag,keys,secure,expires,signedMetadata,
  //    unsignedMetadata}} — signedMetadata is {} for a plain stamp.
  // ===================================================================================
  s3('Stage 3 valid signature from a single-key device returns stamped:true with one verified key', { challenge: CH, response: RESP_DESKTOP }),
  s3('Stage 3 multi-key device (laptop, 2 keys) stamps successfully with both keys verified', { challenge: CH, response: RESP_LAPTOP }),
  s3('Stage 3 PRIVATE: private-mode identity stamps successfully (lookup code in signed-metadata; the verificationResult deviceTag carries the ~lookupCode suffix)', { challenge: CH_PRIVATE, response: RESP_PRIVATE }),
  s3('Stage 3 PRIVATE STAMP-DISTINCT: a response signed-metadata carrying attachments alongside the lookup code still fails verification -> 401 (the attachments membership rejection is orthogonal to private mode)', { challenge: CH_PRIVATE, response: RESP_PRIVATE_ATT }),
  s3('Stage 3 callbackUrl already ending in / stamps successfully (getBaseUrl THEN branch)', { challenge: CH_TRAILING, response: RESP_DESKTOP }),
  s3('Stage 3 STAMP-DISTINCT: a use=stamp-only key stamps successfully', { challenge: CH_STAMPONLY, response: RESP_STAMPONLY }),
  s3('Stage 3 STAMP-DISTINCT: a stamp whose signedMetadata carries a non-attachment key stamps successfully (metadata echoed, .attachments ignored)', { challenge: CH, response: RESP_SIGMETA }),
  s3('Stage 3 unsignedMetadata with a null value parses fine and stamps successfully', { challenge: CH, response: RESP_NULLVALUE_UNSIGNED }),
  s3('Stage 3 STAMP-DISTINCT: a 10s-old challenge still stamps (inside the 15s stampTimeout window)', { challenge: CH_10S, response: RESP_DESKTOP }),
  s3('Stage 3 key record with dnssec:false stamps successfully but with secure:false', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord('', { ttl: 1800, dnssec: false }) }),
  s3('Stage 3 key record with a custom TTL yields expires = now + ttl*1000', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord('', { ttl: 60, dnssec: true }) }),
  s3('Stage 3 unrecognized identity-record keyword is ignored; stamping still succeeds', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'foo bar', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  // resolveConfig record-sanitization branches: an option value that decodes to a non-normal
  // string, a value that decodes to a non-normal string, and a value with malformed %-encoding
  // (decodeURIComponent throws) are each skipped; the surviving real key still stamps.
  s3('Stage 3 identity records with escape-looking junk in values or options are literal, fit no grammar, and contribute nothing; stamping still succeeds on the surviving key', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'meta x-o=%0A', 'note %0A', 'raw %ZZ', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  s3('Stage 3 x- prefixed key option is allowed through (not in the deviceTag); stamping succeeds with the option visible on the key', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord(' x-tag=custom') }),

  // ===================================================================================
  // Stage 3 — SECURITY PROPERTIES: replay surface & via binding granularity.
  // Regression guards for documented stamp behavior (see the Triauth.stamp WARNING in README.md).
  // These do not add new code branches; they pin the SECURITY CONTRACT so an accidental change to
  // nonce handling, via matching, or the freshness window is caught.
  // ===================================================================================
  // The challenge nonce is NOT bound to the signature: RESP_DESKTOP (minted for msg=MSG with no
  // challenge) verifies against the basic CH and equally against CH_DIFF_NONCE — proving the nonce
  // provides no per-request binding, which is exactly why a captured stamp can be replayed and why
  // relying parties must embed a fresh, single-use nonce INSIDE the message.
  s3('Stage 3 SECURITY: the challenge nonce is NOT bound to the signature — a stamp verifies against a DIFFERENT-nonce challenge with the same msg (the core replay surface; embed a nonce in the message)', { challenge: CH_DIFF_NONCE, response: RESP_DESKTOP }),
  // `via` binds to the callback BASE directory, not the exact URL: the same stamp accepted for CB
  // (https://example.com/cb) is also accepted for a sibling callback (https://example.com/other-endpoint)
  // because both reduce to base https://example.com/ === sig.via.
  s3('Stage 3 SECURITY: via binds to the callback BASE directory, not the exact URL — the same stamp is accepted at a sibling callback sharing the base', { challenge: CH_SIBLING_CB, response: RESP_DESKTOP }),
  // Replay window: a captured response (envelope ts = T) still verifies against a FRESH challenge up
  // to stampTimeout (15s) + 2*maximalAllowedClientClockDrift (2*30s) = 45s after it was minted...
  s3('Stage 3 SECURITY: a captured stamp (envelope ts=T) still verifies against a FRESH challenge 45s later — the replay window boundary (stampTimeout 15s + 2x 30s drift)', { challenge: CH_REPLAY_45S, response: RESP_DESKTOP }, { currentTime: T + 45e3 }),
  // ...and 1ms past that 45s window the same captured stamp is rejected (its ts now falls before the
  // widened notBefore) — confirming the window is bounded and a replay cannot be extended indefinitely.
  s3('Stage 3 SECURITY: 1ms past the 45s replay window the same captured stamp is rejected → 402 (signature ts now before the widened notBefore)', { challenge: CH_REPLAY_OVER, response: RESP_DESKTOP }, { currentTime: T + 45e3 + 1 }),

  // ===================================================================================
  // Back-filled tests that were first added directly to stamp.json (after the clock-drift
  // widening / WebAuthn UP-UV enforcement / dnssec-capping changes shipped) — kept here so
  // a full regeneration reproduces them.
  // ===================================================================================
  s3('Stage 3 SECURITY: endpoint triauth record with dnssec:false caps verificationResult.secure to false even though all key records are DNSSEC-validated', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'triauthdemo.org': { TXT: [{ value: 'triauth auth.triauthdemo.org mode=public', ttl: 1800, dnssec: false }] } } }),
  s3("Stage 3 SECURITY: challenge iat 3s in the FUTURE of the verifying server's clock still stamps — with the 15s stampTimeout and an auto-responding authenticator, stamp is the flow most sensitive to inter-server clock drift", { challenge: CH, response: RESP_DESKTOP }, { currentTime: T - 3e3 }),
  s3('Stage 3 SECURITY: challenge 4.999s past the 15s stampTimeout still stamps — the expiry boundary is widened by maximalAllowedServerClockDrift', { challenge: CH, response: RESP_DESKTOP }, { currentTime: T + 15e3 + 4999 }),
  s3('Stage 3 SECURITY: WebAuthn assertion with the User Present (UP) flag cleared (CTAP-level silent assertion) → 401 even though its ECDSA signature is valid', { challenge: CH_WA, response: RESP_WA_NOUP }),
  s3('Stage 3 SECURITY: WebAuthn authenticatorData shorter than 37 bytes (rpIdHash+flags+signCount) → 401 (length guard)', { challenge: CH_WA, response: RESP_WA_SHORT }),
  s3('Stage 3 SECURITY: uv=required key record rejects an assertion without the User Verified (UV) flag → 401 (UP alone is not enough)', { challenge: CH_WA, response: RESP_WA_OK }, { dnsEntries: waKeyRecord(' uv=required') }),
  s3('Stage 3 uv=required key record accepts an assertion with both UP and UV flags set → stamped:true', { challenge: CH_WA, response: RESP_WA_UPUV }, { dnsEntries: waKeyRecord(' uv=required') }),
  s3('Stage 3 SECURITY: a mistyped uv value (uv=reuired) taints the keyGroup → 401 - fail closed, a typo must not silently drop the user verification requirement', { challenge: CH_WA, response: RESP_WA_OK }, { dnsEntries: waKeyRecord(' uv=reuired') }),

  // ===================================================================================
  // Stage 3 — Ed25519 (type=ed25519) and WebAuthn-Ed25519 (type=webauthn-ed25519) verifier
  // backends, reached via IdentityKeys.verify. Cross-language guarantee: a port without these
  // verifiers registered would taint the keyGroups and fail the positives.
  // ===================================================================================
  s3('Stage 3 Ed25519: valid Ed25519 signature from a type=ed25519 key stamps successfully', { challenge: CH_ED25519, response: RESP_ED25519_OK }),
  s3('Stage 3 Ed25519: full flow against a plain-http LAN callback (cburl http://10.0.0.5:8080/cb, via http://10.0.0.5:8080/) stamps successfully — the envelope binds the via string itself, independent of the transport it names', { challenge: CH_ED_LAN, response: RESP_ED_LAN }),
  s3('Stage 3 Ed25519: bogus signature fails the Ed25519 crypto verification → 401', { challenge: CH_ED25519, response: RESP_ED25519_BOGUS }),
  s3('Stage 3 Ed25519: 65-byte P-256 key material published as type=ed25519 cannot import (raw Ed25519 keys are exactly 32 bytes) → fromPublishableKey null → 401', { challenge: CH_ED25519, response: RESP_ED25519_OK }, { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${john.devices[0].keys[0].public} type=ed25519`] } } }),
  s3('Stage 3 Ed25519 SECURITY: uv=required on a type=ed25519 (non-webauthn) key is unenforceable and taints the keyGroup → 401 — fail closed', { challenge: CH_ED25519, response: RESP_ED25519_OK }, { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${ed25519.keys[0].public} type=ed25519 uv=required`] } } }),
  s3('Stage 3 WebAuthn-Ed25519: valid assertion backed by a type=webauthn-ed25519 key stamps successfully', { challenge: CH_WAED, response: RESP_WAED_OK }),
  s3('Stage 3 WebAuthn-Ed25519: structurally valid assertion with bogus crypto → 401', { challenge: CH_WAED, response: RESP_WAED_BADSIG }),
  // callbackUrl base-directory delimiter guards (";" and "|" are envelope separators).
  s1("Stage 1 SECURITY: callbackUrl with a \";\" in its base directory (https://example.com/a;b/cb) returns 221 — \";\" is the signature envelope field delimiter, so the base URL that becomes the signed via must not contain it; rejecting at validation avoids a silent downstream failure (the authenticator’s Signature.generate refuses such a via)", {"identifier":ID,"callbackUrl":"https://example.com/a;b/cb","message":"example-data-in-textual-format"}),
  s1("Stage 1 SECURITY: callbackUrl with a \"|\" in its base directory (https://example.com/a|b/cb) returns 221 — \"|\" is the signature envelope wrapper/separator; a base URL containing it would corrupt the envelope, so it is rejected at validation rather than failing silently downstream", {"identifier":ID,"callbackUrl":"https://example.com/a|b/cb","message":"example-data-in-textual-format"}),
  s1("Stage 1 callbackUrl with a \";\" in its LAST path segment (https://example.com/cb;sid=1) builds a challenge — the final segment never enters the base URL/via, so the envelope delimiter rule stops at the base span", {"identifier":ID,"callbackUrl":"https://example.com/cb;sid=1","token":":aaaaaaaaaaaaaaaa","message":"example-data-in-textual-format"}, { random: RAND }),
  // PUBLICPROFILE: shape and hardening of the publicProfile surfaced on stamp results
  // (per-test dnsEntries publish the profile records; the envelope is the canonical minted one).
  s3("PUBLICPROFILE: stamp surfaces name/initials and x- extensions; unrecognized keywords (incl. former 'roles'/'title') and over-long x- keys are dropped", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "name John Doe",
          "initials JD",
          "tagline Builder of things",
          "x-team Platform",
          "roles admin",
          "title CTO",
          "future-feature whatever",
          "x-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa dropped",
          "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8"
        ]
      }
    } }),
  s3("PUBLICPROFILE SECURITY: stamp drops a publicProfile keyword that appears more than once (reserved and x-) entirely", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "name First",
          "name Second",
          "initials JD",
          "x-dup one",
          "x-dup two",
          "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8"
        ]
      }
    } }),
  s3("PUBLICPROFILE SECURITY: stamp rejects (does not truncate) a publicProfile value longer than the byte cap", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "initials JD",
          "name aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8"
        ]
      }
    } }),
  s3("PUBLICPROFILE SECURITY: stamp caps the number of distinct x- extensions (only the first publicProfileMaxExtensions are kept)", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "x-f0 v0",
          "x-f1 v1",
          "x-f2 v2",
          "x-f3 v3",
          "x-f4 v4",
          "x-f5 v5",
          "x-f6 v6",
          "x-f7 v7",
          "x-f8 v8",
          "x-f9 v9",
          "x-f10 v10",
          "x-f11 v11",
          "x-f12 v12",
          "x-f13 v13",
          "x-f14 v14",
          "x-f15 v15",
          "x-f16 v16",
          "x-f17 v17",
          "x-f18 v18",
          "x-f19 v19",
          "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8"
        ]
      }
    } }),
  // requireSecure: per-call config; the non-DNSSEC twin patches the key record to dnssec:false.
  s3("requireSecure: stamp stage 3 - DNSSEC-secure result still succeeds when requireSecure:true", { challenge: CH_WA, response: RESP_WA_OK }, { _argsOverride: [{ challenge: CH_WA, response: RESP_WA_OK }, { requireSecure: true }] }),
  s3("SECURITY requireSecure: stamp stage 3 - non-DNSSEC (secure:false) result is rejected with 404", { challenge: CH, response: RESP_DESKTOP }, { _argsOverride: [{ challenge: CH, response: RESP_DESKTOP }, { requireSecure: true }], dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "initials JD",
          "name John Doe",
          {
            "value": "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
            "ttl": 1800,
            "dnssec": false
          }
        ]
      }
    } }),

  // GROUPS: the subject's membership list rides the nested verificationResult
  // (see verify.json for the full battery; this pins the stamp-result plumbing).
  s3("GROUPS: stamp result's nested verificationResult carries the signer's groups, fully qualified and sorted", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "name John Doe",
          "initials JD",
          "groups zeta,admins",
          "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8"
        ]
      }
    } }),
];

// Normalize: a couple of dispatch tests need a non-object sole arg (null / []) that the s3()
// helper can't express through its options object — splice in the override and drop the marker.
for (const t of tests) {
  if (t._argsOverride) { t.args = t._argsOverride; delete t._argsOverride; }
}

const suite = {
  title: 'stamp',
  description:
    'Comprehensive, branch-complete coverage of Triauth.stamp. Stage 1 (request): dispatch/arg guards, ' +
    'identifier/callbackUrl/ext/token validation, the STAMP-DISTINCT message (227) validation done in ' +
    'onChallenge and the STAMP-DISTINCT rejection of any attachments option (102), DNS configuration ' +
    '(301/302) and DNS failure (110), and deterministic challenge + /stamp.html redirect building (msg ' +
    'baked in, NO attachments, plus the token HMAC). Stage 3 (verify): challenge/response validation, ' +
    'dispatch constraints (401/403), signature-envelope parse failures (225), generic verification ' +
    'failures (401), the IdentityKeys add/verify branches (incl. the WebAuthn backend) reached via the ' +
    'verify path, the 15s stampTimeout window (402), metadata parse rejections (225), and the ' +
    'STAMP-DISTINCT attachment rejections — a challenge carrying attachments (102) and a verified stamp ' +
    'whose signedMetadata carries attachments (401) — plus the {stamped:true, result, verificationResult} ' +
    'body with an empty signedMetadata. A final SECURITY-PROPERTIES section pins the documented replay ' +
    'contract: the challenge nonce is NOT bound to the signature (a stamp verifies against a different-nonce ' +
    'challenge), via binds to the callback BASE directory (a sibling callback accepts the same stamp), and a ' +
    'captured stamp stays replayable only within stampTimeout + 2*maximalAllowedClientClockDrift (~45s). For stamp, ' +
    'the crypto signature is over the msg string and ' +
    'signedMetadata is part of the signed payload; crypto-bearing fixtures were minted by ' +
    'test/fixtures/json/_capture_stamp.mjs (WebCrypto ECDSA is non-deterministic to mint, deterministic ' +
    'to verify). A final Ed25519 section covers the type=ed25519 and type=webauthn-ed25519 verifier ' +
    'backends (positives plus crypto/key-material/uv-taint negatives).' +
    ' PRIVATE-mode cases cover stage-1 issue without the existence pre-check, stage-3 verification with the lookup code in signed-metadata (the ~lookupCode-suffixed deviceTag in verificationResult), and the attachments-membership rejection riding alongside a lookup code.',
  dnsEntries,
  currentTime: T,
  tests,
};

writeSuite(new URL('./stamp.json', import.meta.url), suite);
