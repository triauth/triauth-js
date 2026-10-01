// One-shot generator for the cross-language attest.json suite.
//
// Like ./_capture_sign.mjs / ./_capture_stamp.mjs / ./_capture_ping.mjs, the Stage 3 attest cases
// that exercise the crypto-verified paths (success bodies AND "valid signature, rejected for some
// OTHER reason" negatives) need real ECDSA P-256 signatures. WebCrypto ECDSA is non-deterministic
// to MINT but deterministic to VERIFY, so we mint here once and bake the resulting
// challenge/response strings into attest.json.
//
// What is signed (ATTEST-DISTINCT): for `attest`, the cryptographic signature is over the SHA256
// hexdigest (base64url) of the *challenge string itself* — `Helpers.sha256(challenge.challengeString)`
// — NOT the challenge bytes (auth/ping) and NOT a human-readable msg (sign/stamp). Because the
// signed payload is derived from the exact challenge, every minted response is bound to one specific
// challenge string; changing any challenge field (incl. the baked-in `attest` object) invalidates
// the signatures minted against it. Each segment of the multi-signature envelope signs the SAME
// payload.
//
// The other ATTEST-DISTINCT shape is the multi-signature envelope: slot 0 is always the USER's
// signature (`signatures[0]`, the "mainSig"), and slots 1..N are third-party ATTESTER signatures.
// attest's onResponse (src/api/attestation.js) does NOT pass an `identifier`/`via` constraint down
// to Signature.verify — it enforces the `bind` binder object in signedMetadata (identifier/via/
// deviceTag — every member of bind is critical and must match the verified user, on EVERY segment,
// the user's own included), then manually matches each attester segment against the requested
// `providers` and checks the attester identifier's domain equals its `via` hostname. (This is the
// behaviour the identifier-constraint fix enabled — third-party attesters signing under their OWN
// identifier now verify.)
//
// This script assembles and writes the ENTIRE attest.json file — every test object, with the minted
// challenge/response already inlined — but WITHOUT the `expected` blocks. After running:
//
//   node --experimental-global-webcrypto test/fixtures/json/_capture_attest.mjs   # (re)write attest.json structure
//   JSON_SUITE=attest.json RECORD=1 npm run test:json                             # fill in every `expected`
//   JSON_SUITE=attest.json npm run test:json                                      # confirm green
//   git diff test/fixtures/json/attest.json                                       # eyeball before committing
//
// Re-run this script whenever the signature envelope format, the challenge field order, the
// John/jane/attestonly/authonly/webauthn/attester DNS layout, or the suite-level currentTime changes
// (any of these change the signed bytes and invalidate the baked signatures).
//
// Coverage goal: this suite ALONE covers 100% of the code paths reachable through Triauth.attest
// (verify with `JSON_SUITE=attest.json npx c8 --include 'src/**' mocha --node-option=experimental-global-webcrypto
// --require ./test/setup.js test/test_json.js`). Everything left uncovered in the attest-path files
// is, by construction, NOT reachable through a Triauth.attest call:
//   - other public methods: the sign/stamp/auth/ping/check/whois/validate exports and their flow
//     branches (e.g., validateMessage/validateAttachments, IdentityKeys.findByTag);
//   - build-side helpers used to CREATE signatures, never on attest's verify path: Signature.generate
//     / Signature.encodeMetadata / MultiSignature.generate (these mint the fixtures here);
//   - defensive guards that no Triauth.attest input can trigger: the internally-constructed
//     constraint objects in Response/MultiSignature/Signature.verify are always well-formed (the
//     hasOnlyKnownProperties and non-numeric notBefore/notAfter/min/maxSignatures arms); the
//     `minSignatures` under-count arm (a MultiSignature always parses >=1 segment, so length<1 is
//     impossible); the `LIMITS.maxMultiSignatures || 0` right arm (LIMITS is frozen at 5); the
//     `verifyResult.signatures.length > 0` false arm and the matching loop's `attestSig.valid` false
//     arm (a valid verifyResult never carries 0 or invalid signatures); `new URL(attestSig.via)`
//     never throws (via passed validateCallbackUrl at parse time); the DNS-record key/option strings
//     are pre-filtered by upstream regexes; AuthenticationEndpoint.urlFor runs only after resolve()
//     succeeds; validateCallbackUrl() itself exercises both getBaseUrl arms; metadata is bounded far under
//     safeParseJson's 256KB limit; Resolvers.Base#resolve is overridden by the stub;
//     TriauthError.process's non-TriauthError branch is unreachable (every attest throw is a TriauthError);
//   - logger?.() optional-chaining null-arms (the test logger is always present).
// The single attest-REACHABLE branch this JSON harness cannot exercise is the `expires:undefined`
// arm of MultiSignature.verify's expiry aggregation (src/multi_signature.js): it only happens on a
// successful attest over a TTL-less DNS record, and a result carrying an `undefined`-valued `expires`
// cannot survive JSON.stringify -> assert.deepStrictEqual round-trip. It is covered by the JS unit
// tests instead (same documented limitation as ping.json/sign.json/stamp.json).

import * as Triauth from '../../../src/index.js';
globalThis.Triauth = Triauth;
import identities from '../identities.json' with { type: 'json' };
import attesters from '../attesters.json' with { type: 'json' };
// Shared generator plumbing: frozen clock, logger, the local jane/ed25519 fixture identities
// (one definition keeps every suite's keypairs in lock-step), and the guarded suite writer.
import { T, LOGGER, jane, ed25519, PRIVATE, writeSuite } from './_capture_common.mjs';
// Minting only needs the private-key signer; no DNS is consulted here (the runner resolves DNS
// from the suite's dnsEntries at verify time).
const SignerStub = (await import('../../stubs/signer.js')).default;

Triauth.config.logger = LOGGER;

// Freeze the clock at the shared suite T. Every challenge iat and every signature ts is minted at
// T, so the signatures land inside attest's notBefore/notAfter window (notBefore = T - attestTimeout (15min)).
Date.now = () => T;

const b64u = (s) => Triauth.Helpers.stringToBase64Url(s);

const john = identities.john;
// Third-party attesters published under attest.triauthdemo.org (a DIFFERENT domain than the user's).
// Same keypairs as test/fixtures/attesters.json / test_attestation.js so the suites stay in lock-step,
// but here their DNS lives entirely in the stub (no live DNS needed).
const robot = attesters.robot;   // robot-attester@attest.triauthdemo.org, via .../not-a-robot
const age   = attesters.age;     // age-attester@attest.triauthdemo.org,   via .../over-18

// jane (shared fixture identity): ordinary identity used as the "wrong identity".
// ed25519 (shared fixture identity): in THIS suite the same keypair also backs the
// webauthn-ed25519 user and the ed25519-backed third-party attester (twin-style reuse, like
// attestonly/authonly reusing john's key).
const EDATT_ID = 'ed25519-attester@attest.triauthdemo.org';

const ID  = 'john@triauthdemo.org';
const CB   = 'https://example.com/cb';        // canonical callbackUrl (has a path segment to strip)
const CB_TRAILING = 'https://example.com/';   // already a base URL (exercises getBaseUrl THEN branch)
// The user signature's `via` is matched at src/api/attestation.js against
// Helpers.getBaseUrl(challenge.data.cburl). getBaseUrl('https://example.com/cb') === 'https://example.com/'.
const VIA = 'https://example.com/';
const NONCE = 'ABEiM0RVZneImaq7zN3u_wAR';     // deterministic nonce for RAND below (kept for readability)
const RAND = '00112233445566778899aabbccddeeff00112233';

// Attester provider URLs (the `via` an attester signs under). Each via's hostname must equal the
// attester identifier's domain (src/api/attestation.js check 2).
const ROBOT_VIA = robot.via;                                 // https://attest.triauthdemo.org/not-a-robot
const AGE_VIA   = age.via;                                   // https://attest.triauthdemo.org/over-18
const SELF_VIA  = 'https://triauthdemo.org/not-a-robot';     // john self-attesting (hostname == john's domain)

// Requested-attestations objects baked into challenges.
const ATT_ROBOT   = { 'not-a-robot': { label: 'I am not a robot', providers: [ROBOT_VIA] } };
const ATT_SELF    = { 'not-a-robot': { label: 'I am not a robot', providers: [SELF_VIA] } };
const ATT_TWO     = { 'not-a-robot': { label: 'I am not a robot', providers: [ROBOT_VIA] },
                      'over-18':     { label: 'I am over 18',     providers: [AGE_VIA] } };
const ATT_MULTI   = { 'first':  { label: 'first',  providers: [ROBOT_VIA] },
                      'second': { label: 'second', providers: [ROBOT_VIA] } };
const ATT_HOSTMIS = { 'not-a-robot': { label: 'I am not a robot', providers: ['https://example.com/not-a-robot'] } };
const ATT_EMPTY   = {};
const EDCHECK_VIA = 'https://attest.triauthdemo.org/ed25519-check';  // via of the ed25519-backed attester
const ATT_EDCHECK = { 'ed25519-check': { label: 'Verified by an Ed25519 attester', providers: [EDCHECK_VIA] } };

// Build an attest challenge string with full control over every field. Field order mirrors
// Challenge.build (cburl, [ext], type, identifier, nonce, iat, ver) followed by the `attest` object that
// _perform's onChallenge appends for attest. Stage 3 never re-checks the nonce, so a fixed nonce is
// fine. (Because the signed payload is sha256(thisString), every response is minted against the exact
// string this returns — see mintResponse below.)
const mkChallenge = ({ cburl = CB, ext, type = 'attest', identifier = ID, nonce = NONCE, iat = T, ver = 1,
                       attest = ATT_ROBOT, includeAttest = true } = {}) => {
  const data = {};
  data.cburl = cburl;
  if (ext !== undefined) data.ext = ext;
  data.type = type;
  data.identifier = identifier;
  data.nonce = nonce;
  data.iat = iat;
  data.ver = ver;
  if (includeAttest) data.attest = attest;
  return b64u(JSON.stringify(data));
};

// Standard attest challenges reused across Stage 3 cases.
const CH            = mkChallenge();                                   // john, cb, one attestation -> robot
const CH_EMPTY      = mkChallenge({ attest: ATT_EMPTY });              // {} attestations (user sig only)
const CH_SELF       = mkChallenge({ attest: ATT_SELF });              // self-attestation provider
const CH_TWO        = mkChallenge({ attest: ATT_TWO });              // two attestations -> two distinct attesters
const CH_MULTI      = mkChallenge({ attest: ATT_MULTI });            // two attestation IDs, one attester
const CH_TRAILING   = mkChallenge({ cburl: CB_TRAILING });            // cb already a base url
const CH_PRIVATE     = mkChallenge({ identifier: PRIVATE.john.identifier });
const CH_HOSTMIS    = mkChallenge({ attest: ATT_HOSTMIS });          // attester domain != via hostname
const CH_WA         = mkChallenge({ identifier: 'webauthn@triauthdemo.org', attest: ATT_EMPTY });
const CH_AUTHONLY   = mkChallenge({ identifier: 'authonly@triauthdemo.org', attest: ATT_EMPTY });
const CH_ATTESTONLY = mkChallenge({ identifier: 'attestonly@triauthdemo.org', attest: ATT_EMPTY });
const CH_ED25519U   = mkChallenge({ identifier: ed25519.identifier });                              // ed25519 user + the default robot attestation
const CH_EDATT      = mkChallenge({ attest: ATT_EDCHECK });                                  // john user + the ed25519-backed attester
const CH_WAED       = mkChallenge({ identifier: 'webauthn-ed25519@triauthdemo.org', attest: ATT_EMPTY });
const CH_AUTHTYPE   = mkChallenge({ type: 'auth' });                 // type mismatch vs attest flow
const CH_SIGNTYPE   = mkChallenge({ type: 'sign' });                 // type mismatch vs attest flow
const CH_BADID     = mkChallenge({ identifier: 'no-at-sign.example' });    // valid JSON, malformed identifier -> Identity ctor throws -> 223
// BOM-prefixed canonical challenge: EF BB BF + the CH_EMPTY bytes. Decodes to valid JSON only if
// the decoder strips the BOM — which it must not (223; canonical-encoding guarantee for ports).
const CH_BOM = Triauth.Helpers.arrayBufferToBase64Url(Uint8Array.from([0xEF, 0xBB, 0xBF, ...Triauth.Helpers.base64UrlToUint8(CH_EMPTY)]));
const CH_BADCBURL   = mkChallenge({ cburl: 'not-a-url' });           // embedded cburl not a valid URL -> onResponse validateCallbackUrl fails -> 401
const CH_PAST       = mkChallenge({ iat: 1700000000000 });           // far before notBefore
const CH_FUTURE     = mkChallenge({ iat: 1800000000000 });           // after notAfter (== T)
const CH_JUST_EXP   = mkChallenge({ iat: T - (15 * 60e3) - 1 });     // 1ms past attestTimeout (15min) -> expired
const CH_14MIN      = mkChallenge({ iat: T - (14 * 60e3) });         // 14min old: still inside attest's 15min window
const CH_IAT_NAN    = mkChallenge({ iat: 'not-a-number' });          // non-numeric iat -> Response.verify typeof-guard -> 402
const CH_NOATTEST   = mkChallenge({ includeAttest: false });         // challenge has no attest field -> onResponse validateAttestations(undefined) -> 229
const CH_ATTEST_ARR = mkChallenge({ attest: ['not', 'an', 'object'] }); // attest is an array -> onResponse validateAttestations -> 229

// Security/regression challenges. Each differs from CH in exactly ONE field that is part of the
// signed payload (sha256(challengeString)), so a response minted for CH must FAIL against it — pinning
// that the whole challenge (nonce, iat, cburl, attest set) is cryptographically bound, not just
// range/prefix-checked. CH_TWO (defined above) doubles as the "expanded attestation set" challenge.
const CH_DIFF_NONCE = mkChallenge({ nonce: 'DiFfErEnTnOnCe0000000000' });   // differs only in nonce
const CH_DIFF_IAT   = mkChallenge({ iat: T - 60e3 });                       // differs only in iat (still INSIDE the 15min window)
const CH_SIBLING    = mkChallenge({ cburl: 'https://example.com/other' });  // sibling callback: getBaseUrl == VIA, so the via-check would pass
// Relabel: a DIFFERENT attestation id ('is-human') under the SAME provider (robot.via). RESP_OK's
// attester (robot) WOULD satisfy the is-human matching if its crypto verified — so the 401 is purely
// the challenge binding, not the matching loop (proven empirically). A regression that dropped the
// attest map from the signed payload would let this relabel attack succeed; this guard catches it.
const CH_RELABEL    = mkChallenge({ attest: { 'is-human': { label: 'I am human', providers: [ROBOT_VIA] } } });
// attest map carrying a literal __proto__ key (own property via JSON.parse). safeParseJson rejects it
// when Challenge.fromString re-hydrates the challenge in Stage 3 -> 223, before onResponse runs.
const CH_PROTO_ATTEST = mkChallenge({ attest: JSON.parse('{"__proto__":{"label":"evil","providers":["https://triauthdemo.org/evil"]}}') });

// --- signature minting helpers --------------------------------------------------------
// For attest, the `message` argument to Signature.generate is sha256(challengeString); each
// segment (user + attesters) signs the same payload.

const payloadOf = (challengeString) => Triauth.Helpers.sha256(challengeString);

const mintUserSig = (payload, opts = {}) => {
  const { keys = john.devices[0].keys, identifier = ID, actor = '', via = VIA, type = 'attest',
          signedMetadata = {}, unsignedMetadata = {} } = opts;
  return Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(keys), type, identifier, actor, via, payload, signedMetadata, unsignedMetadata);
};

const mintAttesterSig = (payload, { keys, identifier, actor = '', via, type = 'attest', signedMetadata = {} }) =>
  Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(keys), type, identifier, actor, via, payload, signedMetadata);

// Build a full multi-signature response for `challengeString`: a user segment plus zero or more
// attester segments, all signing sha256(challengeString).
const mintResponse = async (challengeString, { user = {}, attesters = [] } = {}) => {
  const payload = await payloadOf(challengeString);
  const segs = [await mintUserSig(payload, user)];
  for (const a of attesters) {
    segs.push(await mintAttesterSig(payload, a));
  }
  return Triauth.MultiSignature.generate(...segs);
};

// MITM-style swap of slot 7 (unsignedMetadata) after signing — the crypto stays valid because
// unsignedMetadata is the one envelope field outside the signed payload.
const mintUnsignedSwap = async (payload, garbage, opts = {}) => {
  const env = await mintUserSig(payload, opts);
  const seg = env.slice(1, -1).split(';');
  seg[7] = b64u(JSON.stringify(garbage));
  return '|' + seg.join(';') + '|';
};
const mintRawUnsigned = async (payload, rawB64uSegment, opts = {}) => {
  const env = await mintUserSig(payload, opts);
  const seg = env.slice(1, -1).split(';');
  seg[7] = rawB64uSegment;
  return '|' + seg.join(';') + '|';
};
// Raw (non-JSON) bytes in the SIGNED metadata slot (6): must re-create the signed payload by hand so
// the real signature covers the raw bytes. (The attest payload lives in slot 8.)
const mintRawSigned = async (payload, rawB64uSegment, opts = {}) => {
  const { keys = john.devices[0].keys, identifier = ID, via = VIA, type = 'attest' } = opts;
  const fields = [type, identifier, '', via, 'v1', String(Date.now()), rawB64uSegment, '', String(payload)];
  const sigs = await SignerStub.signUsingDeviceKeys(keys)(fields.join(';'));
  fields[8] = sigs.join(';');
  return '|' + fields.join(';') + '|';
};

// --- minted responses (Stage 3 with real ECDSA) ---------------------------------------
const payloadCH        = await payloadOf(CH);
const payloadEmpty     = await payloadOf(CH_EMPTY);

// SUCCESS responses
const RESP_OK          = await mintResponse(CH,          { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
const RESP_OK_LAPTOP   = await mintResponse(CH,          { user: { keys: john.devices[1].keys }, attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] }); // 2-key user device
const RESP_EMPTY_OK    = await mintResponse(CH_EMPTY);                                       // user-only, {} attestations
const RESP_EMPTY_LASTFRAG = await mintResponse(CH_EMPTY, { user: { keys: [john.devices[1].keys[1]] } }); // user = laptop key #2 only — pairs with a laptop[2/2]-only DNS patch (sparse final fragment)
const RESP_SELF        = await mintResponse(CH_SELF,     { attesters: [{ keys: john.devices[0].keys, identifier: ID, via: SELF_VIA }] }); // self-attestation
const RESP_TWO         = await mintResponse(CH_TWO,      { attesters: [
                            { keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA },
                            { keys: age.devices[0].keys,   identifier: age.identifier,   via: AGE_VIA } ] });
const RESP_MULTI       = await mintResponse(CH_MULTI,    { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] }); // one attester, two IDs
const RESP_TRAILING    = await mintResponse(CH_TRAILING, { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
const RESP_ATTESTONLY  = await mintResponse(CH_ATTESTONLY, { user: { identifier: 'attestonly@triauthdemo.org' } }); // key use=attest CAN attest
// Private mode: the USER segment carries the subject's lookup code in signed-metadata; the
// attester (a public-mode provider) carries none. The binder's deviceTag binds the RESULT-form Device Tag -
// under private mode that is the `<tag>~<lookupCode>` handle, pinning the lookup-code epoch into the attestation.
const PRIVATE_USER      = { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode } };
const RESP_PRIVATE_OK   = await mintResponse(CH_PRIVATE,  { user: PRIVATE_USER, attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
const RESP_PRIVATE_BIND = await mintResponse(CH_PRIVATE,  { user: PRIVATE_USER, attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA,
                            signedMetadata: { bind: { identifier: PRIVATE.john.identifier, deviceTag: john.devices[0].deviceTag + '~' + PRIVATE.john.lookupCode } } }] });
const RESP_PRIVATE_BIND_UNSALTED = await mintResponse(CH_PRIVATE, { user: PRIVATE_USER, attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA,
                            signedMetadata: { bind: { deviceTag: john.devices[0].deviceTag } } }] });
// The attester's binders live in the `bind` object of its signed metadata, and EVERY member of it
// is critical: the verifier must recognize it and it must match the verified user, so a provider's
// signed statement about whom it verified can never be silently dropped. This one binds all three.
const RESP_BIND_OK     = await mintResponse(CH,          { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA,
                            signedMetadata: { bind: { identifier: ID, via: VIA, deviceTag: john.devices[0].deviceTag } } }] });
// Ed25519 (type=ed25519) success responses — both are mixed-algorithm multisigs:
const RESP_ED25519U    = await mintResponse(CH_ED25519U, { user: { keys: ed25519.keys, identifier: ed25519.identifier },
                            attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] }); // ed25519 USER + es256 attester
const RESP_EDATT       = await mintResponse(CH_EDATT,    { attesters: [{ keys: ed25519.keys, identifier: EDATT_ID, via: EDCHECK_VIA }] }); // es256 user + ed25519 ATTESTER

// ATTEST-DISTINCT negatives (the user sig verifies; the attester match or a mainSig check fails -> 401)
const RESP_MISSING_ATT = await mintResponse(CH);                                            // user-only against a 1-attestation challenge -> unmatched -> 401
const RESP_VIA_NOTPROV = await mintResponse(CH,          { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: AGE_VIA }] }); // attester via not in providers -> 401
const RESP_HOSTMIS     = await mintResponse(CH_HOSTMIS,  { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: 'https://example.com/not-a-robot' }] }); // attester domain != via hostname -> 401
const RESP_ID_MIS      = await mintResponse(CH,          { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { identifier: 'someone-else@example.com' } } }] }); // identifier binder mismatch -> 401
const RESP_VIA_MIS     = await mintResponse(CH,          { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { via: 'https://wrong.example/' } } }] });   // via binder mismatch -> 401
const RESP_TAG_MIS     = await mintResponse(CH,          { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { deviceTag: 'not-the-users-device-tag' } } }] });  // deviceTag binder mismatch -> 401
// Fail-closed binder grammar: an unrecognized binder inside `bind`, a malformed `bind` (empty /
// array / non-string value), or a binder false of the verified user rejects the whole envelope
// (401) — on any segment. Top-level members stay auxiliary: an unrecognized one, regardless of
// name or value, is ignored (the extensibility half of the rule).
const RESP_BIND_UNKNOWN = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { audience: 'https://somewhere.example/' } } }] });
const RESP_BIND_EMPTY   = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: {} } }] });
const RESP_BIND_ARRAY   = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: ['identifier'] } }] });
const RESP_BIND_NONSTR  = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { identifier: 123 } } }] });
const RESP_BIND_MIXED   = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { identifier: ID, via: 'https://wrong.example/' } } }] });
const RESP_BIND_FLAT    = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { sub: 'someone-else@example.com', tag: 'not-the-users-device-tag' } }] });
const RESP_BIND_AUX     = await mintResponse(CH,         { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { issuedFor: 'a future member v1 knows nothing about' } }] });
// `bind` means the same on the USER segment: its binders, when stated, must hold too.
const RESP_BIND_ON_USER     = await mintResponse(CH,     { user: { signedMetadata: { bind: { identifier: ID } } }, attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
const RESP_BIND_ON_USER_MIS = await mintResponse(CH,     { user: { signedMetadata: { bind: { identifier: 'someone-else@example.com' } } }, attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
// A STRAY attester whose binder is false of the user poisons the whole bundle — even though the
// clean robot segment alone satisfies both CH_MULTI attestations (overlapping providers).
const RESP_BIND_STRAY   = await mintResponse(CH_MULTI,   { attesters: [
                            { keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA },
                            { keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA, signedMetadata: { bind: { identifier: 'someone-else@example.com' } } } ] });
const RESP_VIA_ATTACK  = await mintResponse(CH_EMPTY,    { user: { via: 'https://attacker.example/' } }); // mainSig.via != getBaseUrl(cburl) -> 401 (check B, 2nd clause)
const RESP_BADCBURL    = await mintResponse(CH_BADCBURL, { user: { via: VIA } });           // challenge cburl invalid -> 401 (check B, 1st clause)
const RESP_WRONGID     = await mintResponse(CH_EMPTY,    { user: { keys: jane.keys, identifier: jane.identifier } }); // mainSig.identifier != challenge.identifier -> 401 (check A)

// Delegated segments (actor slot set; the delegation walk runs at verify time, driven by per-test include grants):
// jane's key signs the USER segment on john's behalf; and, separately, an ATTESTER segment on robot's behalf.
const RESP_DELEGATED_USER     = await mintResponse(CH, { user: { keys: jane.keys, actor: jane.identifier },
                                                         attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
const RESP_DELEGATED_ATTESTER = await mintResponse(CH, { attesters: [{ keys: jane.keys, identifier: robot.identifier, actor: jane.identifier, via: ROBOT_VIA }] });
const RESP_BADKEY      = await mintResponse(CH_EMPTY,    { user: { keys: jane.keys, identifier: ID } });   // signed with jane's key under john's id -> crypto fails -> 401
const RESP_AUTHONLY    = await mintResponse(CH_AUTHONLY, { user: { identifier: 'authonly@triauthdemo.org' } }); // key use=auth blocks attest -> 401
const RESP_USERTYPE    = await mintResponse(CH_EMPTY,    { user: { type: 'auth' } });        // user segment type=auth != attest constraint -> 401
const RESP_LAPTOP_PART = await mintResponse(CH_EMPTY,    { user: { keys: [john.devices[1].keys[0]] } }); // only laptop key 1 of 2 signs -> group never fully satisfied -> 401

// Security/regression responses (all minted over their challenge's payload, so the ONLY thing wrong
// is the property under test).
// Segment-order: attester in slot 0, user in slot 1. Both verify cryptographically, but mainSig =
// signatures[0] = the attester, whose identifier != challenge.identifier -> 401 (the user-must-be-first invariant).
const RESP_SWAPPED = Triauth.MultiSignature.generate(
  await mintAttesterSig(payloadCH, { keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }),
  await mintUserSig(payloadCH),
);
// Partial: a 2-attestation challenge (not-a-robot -> robot, over-18 -> age) satisfied by ONLY the robot
// attester -> over-18 stays unmatched -> 401 (all-or-nothing).
const RESP_TWO_PARTIAL = await mintResponse(CH_TWO, { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });
// Over-supply: a 1-attestation challenge (maxSignatures = 2) answered with user + TWO attesters (3 sigs)
// -> MultiSignature count guard -> 401 (cannot pad the envelope past requested + 1).
const RESP_OVERSUPPLY = await mintResponse(CH, { attesters: [
  { keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA },
  { keys: age.devices[0].keys,   identifier: age.identifier,   via: AGE_VIA } ] });

// A real user segment (valid crypto over payloadCH) paired with an attester segment carrying bogus
// crypto (a structurally valid attest envelope whose AAAA sig can never verify against robot's key)
// -> the whole multisig fails at the attester segment, before the matching loop -> 401.
const RESP_ATT_BADCRYPTO = (() => {
  const userSeg = RESP_OK.slice(1).split('|')[0];                                  // user segment body (no wrappers)
  const bogusAttester = `attest;${robot.identifier};;${ROBOT_VIA};v1;${T};;;AAAA`;
  return '|' + userSeg + '|' + bogusAttester + '|';
})();

// Window negatives where the failure is the challenge.iat (response not crypto-verified): reuse a
// valid user-only response; Response.verify returns null before constructing the signature.
const RESP_FOR_IAT = RESP_EMPTY_OK;

// Time-window: per-challenge SUCCESS inside the 15min attestTimeout window (sig ts == T).
const RESP_14MIN = await mintResponse(CH_14MIN, { attesters: [{ keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }] });

// metadata parse fixtures on the USER segment, signed over payloadEmpty (CH_EMPTY).
const RESP_GARBAGE_SIGNED   = await mintResponse(CH_EMPTY, { user: { signedMetadata: ['totally', 'wrong', 'shape'] } });
const RESP_PROTO_SIGNED     = await mintResponse(CH_EMPTY, { user: { signedMetadata: JSON.parse('{"__proto__":{"polluted":true,"isAdmin":true}}') } });
const RESP_RAWTEXT_SIGNED   = await mintRawSigned(payloadEmpty, 'c29tZS1yYW5kb20tcGxhaW4tdGV4dC1ub3QtanNvbg'); // "some-random-plain-text-not-json"
const RESP_BOM_SIGNED     = await mintRawSigned(payloadEmpty, "77u_eyJleHQiOnsiYm9tIjp0cnVlfX0"); // EF BB BF + {"ext":{"bom":true}} — BOM must not be stripped
const RESP_GARBAGE_UNSIGNED = await mintUnsignedSwap(payloadEmpty, ['evil', 'array', 'in', 'unsignedMetadata']);
const RESP_PROTO_UNSIGNED   = await mintUnsignedSwap(payloadEmpty, { constructor: { prototype: { escalated: true, evilFn: 'marker' } } });
const RESP_RAWBIN_UNSIGNED  = await mintRawUnsigned(payloadEmpty, 'AAECAwQFBgcICQoLDA0ODw'); // raw 0x00..0x0F
const RESP_DEEP_UNSIGNED    = await mintUnsignedSwap(payloadEmpty, {a:{b:{c:{d:{e:{f:{g:{h:{}}}}}}}}}); // depth 9 > 8
const RESP_LONGKEY_UNSIGNED = await mintUnsignedSwap(payloadEmpty, {['a'.repeat(257)]: 1});
const RESP_NONASCII_UNSIGNED= await mintRawUnsigned(payloadEmpty, 'eyJy6XN1bekiOjF9'); // {"r<0xE9>sum<0xE9>":1} — raw Latin-1 é: ill-formed UTF-8, refused at decode -> 225
const RESP_BADUTF8_VALUE_UNSIGNED = await mintRawUnsigned(payloadEmpty, 'eyJleHQiOnsiYSI6IukifX0'); // {"ext":{"a":"<0xE9>"}} — raw Latin-1 é inside a string VALUE: ill-formed UTF-8, refused at decode -> 225
const RESP_EKEY_UNSIGNED    = await mintRawUnsigned(payloadEmpty, 'eyJyw6lzdW3DqSI6MX0'); // {"résumé":1} as proper C3 A9 UTF-8 — decodes fine; the Bounded-JSON ASCII-key rule rejects -> 225
const RESP_SURROGATE_KEY_UNSIGNED = await mintRawUnsigned(payloadEmpty, 'eyJ4XHVkODAweSI6MX0'); // {"x\ud800y":1} — a lone-surrogate JSON ESCAPE in a key; every parser behavior converges on 225 (preserve -> non-ASCII key, substitute U+FFFD -> likewise, reject -> parse failure)
const RESP_NULLVALUE_UNSIGNED = await mintUnsignedSwap(payloadEmpty, {ok: null}); // valid -> success

// --- hand-written (no valid crypto needed) responses ----------------------------------
// A bogus attest envelope that is syntactically valid (passes validateResponse + Signature parse)
// but whose AAAA "signature" can never verify against John's real key -> generic 401.
const RESP_BOGUS = `|attest;${ID};;${VIA};v1;${T};;;AAAA|`;
// Well-formed SIGN/AUTH-typed envelopes; the attest flow's type constraint rejects them before crypto -> 401.
const RESP_SIGN_TYPED = `|sign;${ID};;${VIA};v1;${T};;;AAAA|`;
const RESP_AUTH_TYPED = `|auth;${ID};;${VIA};v1;${T};;;AAAA|`;
// Three stacked attest segments against an empty-attestation challenge -> exceeds maxSignatures=1 -> 401.
const RESP_EMPTY_TWO = Triauth.MultiSignature.generate(
  await mintUserSig(payloadEmpty),
  await mintAttesterSig(payloadEmpty, { keys: robot.devices[0].keys, identifier: robot.identifier, via: ROBOT_VIA }),
);
// 11 crypto signatures inside ONE segment -> trips IdentityKeys.verify's maxKeysPerSignature=10 guard.
const RESP_ELEVEN_SIGS = `|attest;${ID};;${VIA};v1;${T};;;AAAA;BBBB;CCCC;DDDD;EEEE;FFFF;GGGG;HHHH;IIII;JJJJ;KKKK|`;
// 6 signature segments -> trips MultiSignature's maxMultiSignatures=5 guard (in the constructor) -> 225.
const RESP_SIX_SEGMENTS = '|' + Array.from({ length: 6 }, () => `attest;${ID};;${VIA};v1;${T};;;AAAA`).join('|') + '|';
// Fresh challenge (iat in window) but the SIGNATURE's own ts is outside the widened window -> 402
// (Signature.verify ts check, distinct from Response.verify's challenge.iat check). Crypto unreached.
const RESP_TS_PAST   = `|attest;${ID};;${VIA};v1;1700000000000;;;AAAA|`;
const RESP_TS_FUTURE = `|attest;${ID};;${VIA};v1;1800000000000;;;AAAA|`;
// A single-character crypto signature: passes the base64url guards, but atob() of a 1-char string
// throws inside the ECDSA verifier's base64UrlToUint8 -> caught by Ecdsa.verify's try/catch -> 401.
const RESP_ONECHAR_SIG = `|attest;${ID};;${VIA};v1;${T};;;A|`;
// Signature-envelope field-format rejections (Signature constructor -> 225). Each isolates one slot.
const RESP_BADVIA      = `|attest;${ID};;-;v1;${T};;;AAAA|`;                       // via not a URL
const RESP_NONASCII_VIA= `|attest;${ID};;https://example.com/é;v1;${T};;;AAAA|`;   // via not isNormalString
const RESP_BADTYPE     = `|bogus;${ID};;${VIA};v1;${T};;;AAAA|`;                   // type not in VALID_TYPES
const RESP_BADID       = `|attest;not-valid;;${VIA};v1;${T};;;AAAA|`;              // envelope identifier invalid
const RESP_BADVER      = `|attest;${ID};;${VIA};v2;${T};;;AAAA|`;                 // ver != v1
const RESP_BADTS       = `|attest;${ID};;${VIA};v1;0;;;AAAA|`;                     // ts fails /^[1-9].../
const RESP_NOSIG       = `|attest;${ID};;${VIA};v1;${T};;;|`;                      // no crypto signature segment
const RESP_BADSIGB64   = `|attest;${ID};;${VIA};v1;${T};;;AA!A|`;                  // crypto sig not base64url
const RESP_BADSIGMETA  = `|attest;${ID};;${VIA};v1;${T};!!!;;AAAA|`;               // signedMetadata slot not base64url
const RESP_EMPTY_SEGS  = '||||';                                                 // empty segments -> Signature length guard -> 225

// --- WebAuthn (key type=webauthn-es256) responses -------------------------------------
// Reached when the matched device key has type=webauthn-es256. The envelope's crypto signature is
// over (authenticatorData || sha256(clientDataJSON)); the assertion (clientDataJSON + authenticatorData)
// travels in unsignedMetadata.sig[idx]. The verifier checks clientData.challenge ===
// sha256(reconstructed attest payload), type === 'webauthn.get', crossOrigin === false, and origin ===
// <the resolved authentication endpoint origin>. We reuse john's desktop P-256 keypair as the underlying WebAuthn key.
const WA_ID = 'webauthn@triauthdemo.org';
const WA_ORIGIN = 'https://auth.triauthdemo.org'; // the RESOLVED authentication-endpoint origin (triauthdemo.org's `triauth` record → auth.triauthdemo.org); the origin the real Authenticator page runs at, NOT the identifier domain
const WA_AUTHDATA = 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAw';
const payloadWA = await payloadOf(CH_WA);
const WA_PAYLOAD = ['attest', WA_ID, '', VIA, 'v1', String(T), '', '', payloadWA].join(';'); // exact reconstructed signed payload
const WA_CHAL = await Triauth.Helpers.sha256(WA_PAYLOAD);                                 // expected clientData.challenge

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
  const encUnsigned = (unsignedMeta && Object.keys(unsignedMeta).length > 0) ? b64u(JSON.stringify(unsignedMeta)) : '';
  return '|' + ['attest', WA_ID, '', VIA, 'v1', String(T), '', encUnsigned, cryptoSig].join(';') + '|';
};

const RESP_WA_OK        = await mkWebAuthn();                                                                // valid assertion -> success
const RESP_WA_BADSIG    = await mkWebAuthn({ sign: false });                                                 // structure/clientData valid, crypto false -> 401
const RESP_WA_NOSIG     = await mkWebAuthn({ sign: false, unsigned: {} });                                   // no sig object
const RESP_WA_NOIDX     = await mkWebAuthn({ sign: false, unsigned: { sig: {} } });                          // no sig[idx]
const RESP_WA_CDJ_NOSTR = await mkWebAuthn({ sign: false, unsigned: { sig: { '0': { clientDataJSON: 123, authenticatorData: WA_AUTHDATA } } } }); // clientDataJSON not a string
const RESP_WA_AD_NOB64  = await mkWebAuthn({ sign: false, unsigned: { sig: { '0': { clientDataJSON: '{}', authenticatorData: '!!!' } } } });      // authenticatorData not base64url
const RESP_WA_BADCHAL   = await mkWebAuthn({ sign: false, challenge: 'A'.repeat(43) });                      // wrong challenge
const RESP_WA_DUPCHAL   = await mkWebAuthn({ sign: false, clientDataJSON: `{"type":"webauthn.get","challenge":"${WA_CHAL}","challenge":"${WA_CHAL}","origin":"${WA_ORIGIN}","crossOrigin":false}` }); // "challenge": twice
const RESP_WA_BADTYPE   = await mkWebAuthn({ sign: false, type: 'webauthn.create' });                        // wrong type
const RESP_WA_CROSSORIG = await mkWebAuthn({ sign: false, crossOrigin: true });                              // crossOrigin true
const RESP_WA_BADORIGIN = await mkWebAuthn({ sign: false, origin: 'https://evil.example' });                 // wrong origin
const RESP_WA_BADJSON   = await mkWebAuthn({ sign: false, clientDataJSON: 'notjson' });                      // clientDataJSON not valid JSON -> safeParseJson throws

// Variants of WA_AUTHDATA with a different flags byte (byte 32) and/or truncated length, for the
// UP/UV flag-enforcement tests. The assertion is still genuinely signed over the modified bytes,
// so a rejection can only come from the flag/length checks - not from the crypto verification.
const waAuthData = (flagsByte, length = 37) => {
  const bytes = Triauth.Helpers.base64UrlToUint8(WA_AUTHDATA).slice(0, length);
  if (length > 32) bytes[32] = flagsByte;
  return Triauth.Helpers.arrayBufferToBase64Url(bytes);
};
const RESP_WA_NOUP  = await mkWebAuthn({ authenticatorData: waAuthData(0x00) });     // signed, UP flag cleared -> 401
const RESP_WA_SHORT = await mkWebAuthn({ authenticatorData: waAuthData(0x01, 36) }); // signed, 36-byte authenticatorData -> 401
const RESP_WA_UPUV  = await mkWebAuthn({ authenticatorData: waAuthData(0x05) });     // signed, UP|UV set -> satisfies uv=required
// A patch that republishes the webauthn identity's key record with extra options appended (e.g., ' uv=required').
const waKeyRecord = (suffix = '') => ({ 'webauthn._at.triauthdemo.org': { TXT: ['name WebAuthn', `key wa[1/1]:${john.devices[0].keys[0].public} type=webauthn-es256${suffix}`] } });

// --- WebAuthn-Ed25519 (key type=webauthn-ed25519) responses ---------------------------
// Mirrors webauthn-es256 with the assertion signed by Ed25519.
const WAED_ID = 'webauthn-ed25519@triauthdemo.org';
const payloadWAED = await payloadOf(CH_WAED);
const WAED_PAYLOAD = ['attest', WAED_ID, '', VIA, 'v1', String(T), '', '', payloadWAED].join(';'); // exact reconstructed signed payload
const WAED_CHAL = await Triauth.Helpers.sha256(WAED_PAYLOAD);                                   // expected clientData.challenge

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

  const encUnsigned = b64u(JSON.stringify({ sig: { '0': { clientDataJSON: cdj, authenticatorData: WA_AUTHDATA } } }));
  return '|' + ['attest', WAED_ID, '', VIA, 'v1', String(T), '', encUnsigned, cryptoSig].join(';') + '|';
};

const RESP_WAED_OK     = await mkWebAuthnEd25519();                // valid Ed25519-backed assertion -> success
const RESP_WAED_BADSIG = await mkWebAuthnEd25519({ sign: false }); // structure/clientData valid, crypto false -> 401

// --- DNS layout -----------------------------------------------------------------------
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
  'attestonly._at.triauthdemo.org': { TXT: [
    'name Attest Only',
    `key desktop[1/1]:${john.devices[0].keys[0].public} use=attest`,
  ] },
  'authonly._at.triauthdemo.org': { TXT: [
    'name Auth Only',
    `key desktop[1/1]:${john.devices[0].keys[0].public} use=auth`,
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
  // Third-party attesters, published under a DISTINCT domain (attest.triauthdemo.org).
  'attest.triauthdemo.org': { TXT: ['triauth auth.attest.triauthdemo.org mode=public'] },
  'robot-attester._at.attest.triauthdemo.org': { TXT: [
    'name Robot Checker',
    `key server[1/1]:${robot.devices[0].keys[0].public} use=attest`,
  ] },
  'age-attester._at.attest.triauthdemo.org': { TXT: [
    'name Age Verifier',
    `key server[1/1]:${age.devices[0].keys[0].public} use=attest`,
  ] },
  'ed25519-attester._at.attest.triauthdemo.org': { TXT: [
    'name Ed25519 Checker',
    `key server[1/1]:${ed25519.keys[0].public} use=attest type=ed25519`,
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
// 11 devices: dev01..dev10 (dummy keys) + john's real desktop key. The 11th (desktop) is dropped by
// the maxDevices=10 guard, leaving only unusable dummy groups -> 401.
const elevenDevices = { 'john._at.triauthdemo.org': { TXT: [
  'initials JD', 'name John Doe',
  ...Array.from({ length: 10 }, (_, i) => `key dev${String(i + 1).padStart(2, '0')}[1/1]:AAAA`),
  `key desktop[1/1]:${john.devices[0].keys[0].public}`,
] } };

// Shorthands for building test objects (expected is filled by RECORD mode).
const s1 = (name, options, extra = {}) => ({ name, call: 'attest', args: [options], ...extra });
const s3 = (name, args, extra = {}) => ({ name, call: 'attest', args: [args], ...extra });

const tests = [
  // ===================================================================================
  // Dispatch & argument-shape guards (flow-level, before Stage 1/3 detection)
  // ===================================================================================
  s3('empty options object returns 101 (matches neither Stage 1 nor Stage 3)', {}),
  s3('null sole arg is normalized to {} by attest Object.assign -> 101', null, { _argsOverride: [null] }),
  s3('empty-array sole arg is normalized to {} by attest Object.assign -> 101', null, { _argsOverride: [[]] }),
  s1('Stage 1 unrecognized option returns 102', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, unknownKey: 'x' }),
  s1('Stage 1 ATTEST-DISTINCT: attachments are a sign-only input — supplying them (even empty) to attest is a misplaced input, 102', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: ':aaaaaaaaaaaaaaaa', attachments: [] }),
  s3('Stage 3 unrecognized option returns 102', { challenge: CH, response: RESP_OK, unknownKey: 1 }),

  // ===================================================================================
  // Stage 1 — identifier validation (210-216)
  // ===================================================================================
  s1('Stage 1 non-string identifier returns 210', { identifier: 123, callbackUrl: CB, attestations: ATT_ROBOT }),
  s1("Stage 1 identifier with whitespace returns 210 (the /[\\s\\0]/ branch, distinct from non-string 210)",
    { identifier: 'john @triauthdemo.org', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 empty-string identifier returns 211', { identifier: '', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 too-long identifier returns 212 (byteSize check before username regex)',
    { identifier: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@triauthdemo.org', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 uppercase identifier returns 213', { identifier: 'John@triauthdemo.org', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 identifier missing @-sign returns 214', { identifier: 'johntriauthdemo.org', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 identifier with consecutive dots in username returns 215', { identifier: 'john..doe@triauthdemo.org', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 identifier with punycode domain returns 216', { identifier: 'john@xn--example.org', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 identifier with an IPv4-literal domain (john@1.2.3.4) returns 216 — a numeric final label is never a domain part', { identifier: 'john@1.2.3.4', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 identifier with a 64-character domain label returns 216 — labels are capped at 63 characters (the DNS bound)', { identifier: 'john@' + 'a'.repeat(64) + '.com', callbackUrl: CB, attestations: ATT_ROBOT }),
  s1('Stage 1 identifier with a single-character final label (john@a.b) returns 216', { identifier: 'john@a.b', callbackUrl: CB, attestations: ATT_ROBOT }),

  // ===================================================================================
  // Stage 1 — callbackUrl (221) & ext (222) validation
  // ===================================================================================
  s1('Stage 1 non-string callbackUrl returns 221', { identifier: ID, callbackUrl: 123, attestations: ATT_ROBOT }),
  s1('Stage 1 over-length callbackUrl (>2048 bytes) returns 221',
    { identifier: ID, callbackUrl: 'https://example.com/' + 'a'.repeat(2048), attestations: ATT_ROBOT }),
  s1('Stage 1 plain-http callbackUrl on a named host (http://example.com/cb) passes URL validation; the tokenless request then returns 226 — an ordering pin: the callbackUrl gate precedes the token gate', { identifier: ID, callbackUrl: 'http://example.com/cb', attestations: ATT_ROBOT }),
  s1('Stage 1 plain-http callbackUrl on a LAN IPv4-literal host (http://10.0.0.5:8080/cb) builds a challenge — the callback is transport, while the provider URLs stay on secure origins', { identifier: ID, callbackUrl: 'http://10.0.0.5:8080/cb', token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1("Stage 1 callbackUrl with punycode domain returns 221", {"identifier":ID,"callbackUrl":"https://xn--mller-kva.de/cb","attestations":{"not-a-robot":{"label":"I am not a robot","providers":["https://attest.triauthdemo.org/not-a-robot"]}}}),
  s1('Stage 1 array-shaped ext returns 222', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, ext: ['not', 'a', 'plain', 'object'] }),

  // ===================================================================================
  // Stage 1 — token validation (226). ATTEST allows token (like ping/sign/stamp).
  // ===================================================================================
  s1('Stage 1 too-short token (<16 chars) returns 226', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 'short' }),
  s1('Stage 1 colon-less token returns 226 (a token is issuer:secret - the issuer may be empty, the colon is structural)', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 'aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 token with more than one colon returns 226', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 'issuer.example:aaaaaaaaaaaaaaaa:x' }),
  s1('Stage 1 token with an uppercase issuer returns 226 (the issuer must be a canonical lowercase domain)', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 'Issuer.Example:aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 token with a non-domain issuer returns 226', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 'not_a_domain:aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 non-string token returns 226', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 123 }),
  s1('Stage 1 over-length token (>255 bytes, the Normal-String default byte cap) returns 226', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: 'a'.repeat(257) }),

  // ===================================================================================
  // Stage 1 — ATTEST-DISTINCT attestations validation (229), done in onChallenge (after
  // id/callbackUrl/ext/token, before DNS). Each case isolates one validateAttestations branch.
  // ===================================================================================
  s1('Stage 1 omitting attestations entirely returns 229 (validateAttestations(undefined))', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 null attestations returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: null }),
  s1('Stage 1 string attestations returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: 'nope' }),
  s1('Stage 1 number attestations returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: 123 }),
  s1('Stage 1 array attestations returns 229 (object-but-Array guard)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: [] }),
  // JSON.parse, not an object literal — a literal {__proto__: ...} sets the prototype instead of
  // creating the own key that this case needs. The name would bake into the challenge, which
  // stage-3 safeParseJson categorically refuses — validateAttestations fails fast instead.
  s1('Stage 1 attestation named __proto__ returns 229 — a prototype-poisoning name would bake into a challenge that stage-3 safeParseJson could never verify', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: JSON.parse('{"__proto__":{"label":"I am not a robot","providers":["https://attest.triauthdemo.org/not-a-robot"]}}') }),
  s1('Stage 1 more than maxMultiSignatures-1 (5) attestation IDs returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: {
    a: { label: 'a', providers: [ROBOT_VIA] }, b: { label: 'b', providers: [ROBOT_VIA] }, c: { label: 'c', providers: [ROBOT_VIA] },
    d: { label: 'd', providers: [ROBOT_VIA] }, e: { label: 'e', providers: [ROBOT_VIA] } } }),
  s1('Stage 1 attestation entry that is not an object returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: 'not-an-object' } }),
  s1('Stage 1 attestation entry with an unknown property returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: [ROBOT_VIA], extra: 'x' } } }),
  s1('Stage 1 attestation entry missing label returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { providers: [ROBOT_VIA] } } }),
  s1('Stage 1 attestation entry with empty-string label returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: '', providers: [ROBOT_VIA] } } }),
  s1('Stage 1 attestation entry missing providers returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l' } } }),
  s1('Stage 1 attestation entry with empty providers array returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: [] } } }),
  s1('Stage 1 attestation entry with too many providers (>4) returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: [ROBOT_VIA, ROBOT_VIA, ROBOT_VIA, ROBOT_VIA, ROBOT_VIA] } } }),
  s1('Stage 1 provider URL on plain http returns 229 — providers are verbatim trust anchors and keep the secure-origin rule the callback no longer needs', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['http://insecure.example/p'] } } }),
  s1('Stage 1 provider URL with an IPv4-literal host (https://127.0.0.1/p) returns 229 — the secure-origin rule wants a named host even where the callback grammar admits the dotted quad', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://127.0.0.1/p'] } } }),
  s1('Stage 1 provider URL with a ";" in its path (https://attest.triauthdemo.org/p;v1) returns 229 — a provider URL is embedded whole as the attestation via, so the envelope delimiter is banned in every span of it', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://attest.triauthdemo.org/p;v1'] } } }),
  s1("Stage 1 provider URL with an apostrophe (https://attest.triauthdemo.org/o'brien) returns 229 — the trust-anchor charset stays apostrophe-free even where the callback grammar admits it", { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ["https://attest.triauthdemo.org/o'brien"] } } }),
  s1('Stage 1 provider URL with credentials returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://user:pass@example.com/p'] } } }),
  s1('Stage 1 provider URL with a query string returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://example.com/p?q=1'] } } }),
  s1('Stage 1 provider URL ending in a bare "?" (https://example.com/p?) returns 229 — a canonical URL cannot carry an empty query, and provider URLs allow no query at all', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://example.com/p?'] } } }),
  s1('Stage 1 provider URL with a fragment returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://example.com/p#frag'] } } }),
  s1('Stage 1 provider URL with percent-encoding returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://example.com/p%20space'] } } }),
  s1('Stage 1 provider URL with a punycode domain returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://xn--example.com/p'] } } }),
  s1('Stage 1 provider URL that is unparseable returns 229', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { a: { label: 'l', providers: ['https://'] } } }),
  s1('Stage 1 ATTEST-DISTINCT: a provider URL on localhost (http accepted) is valid and builds a challenge — the secure-origin rule keeps localhost-http for development', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: { 'local-check': { label: 'local check', providers: ['http://localhost:8080/verify'] } } }, { random: RAND }),

  // ===================================================================================
  // Stage 1 — DNS / configuration (301, 110). Stage 1 resolves the endpoint record only; identity
  // existence and the identity-domain derivation are settled on the signed response at stage 3.
  // ===================================================================================
  s1('Stage 1 domain with no triauth TXT record returns 301', { identifier: 'john@unconfigured.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 endpoint record with an invalid (non-domain) value returns 301 (isDomainName false)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, dnsEntries: { 'triauthdemo.org': { TXT: ['triauth invalid_domain mode=public'] } } }),
  s1('Stage 1 domain with multiple triauth TXT records returns 301 (ambiguous, refuse to choose)', { identifier: 'user@ambiguous.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 unknown identifier under a configured domain still builds a challenge - existence is never probed at issue', { identifier: 'ghost@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 per-test dnsEntries patch can NXDOMAIN a known domain (returns 301)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, dnsEntries: { 'triauthdemo.org': null } }),
  s1('Stage 1 endpoint with an unknown mode still builds a challenge - an unresolvable mode surfaces only once a response is verified', { identifier: 'john@hashed.triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, dnsEntries: { 'hashed.triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=unknownmode'] } } }),
  s1('Stage 1 SERVFAIL on the identifier domain (endpoint lookup) surfaces as 110', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, dnsEntries: { 'triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s1('Stage 1 SERVFAIL on the identity domain (records lookup) still builds a challenge - the identity domain is never queried at issue', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, dnsEntries: { 'john._at.triauthdemo.org': { _error: 'SERVFAIL' } } }),

  // ===================================================================================
  // Stage 1 — success (challenge + attest.html redirectUrl). Deterministic via fixed nonce + clock.
  // ===================================================================================
  s1('Stage 1 ATTEST-DISTINCT: deterministic challenge bakes the attestations object, redirect uses /attest.html', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 empty attestations {} is valid and builds a challenge with attest:{}', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_EMPTY }, { random: RAND }),
  s1('Stage 1 multiple attestation IDs are all baked into the challenge', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_TWO }, { random: RAND }),
  s1("Stage 1 token produces a redirectUrl with a &token= param carrying the token's public part and the hmac", { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 token + ext together: challenge bakes the ext, redirectUrl carries the token and its hmac', { identifier: ID, callbackUrl: CB, attestations: ATT_ROBOT, token: ':aaaaaaaaaaaaaaaa', ext: { attestToken: true } }, { random: RAND }),
  s1("Stage 1 omitting the token returns 226 - token-gated flows require a token at issue (src/challenge_response_flow.js)", {"identifier":ID,"callbackUrl":CB,"attestations":{"not-a-robot":{"label":"I am not a robot","providers":["https://attest.triauthdemo.org/not-a-robot"]}}}, { random: RAND }),
  s1('Stage 1 endpoint record with a __proto__ option is parsed safely (option dropped) and still builds a challenge', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, dnsEntries: { 'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org __proto__=evil mode=public'] } } }),
  s1('Stage 1 challenge bakes in the ext object', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT, ext: { attestToken: true, nested: { foo: 'bar' } } }, { random: RAND }),
  s1('Stage 1 multi-device identity still builds a challenge', { identifier: 'multi@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 identity with a profile but no key records still builds a challenge (key absence surfaces in Stage 3)', { identifier: 'nokeys@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 localhost http callbackUrl is accepted (validateCallbackUrl localhost branch)', { identifier: ID, callbackUrl: 'http://localhost:3000/cb', token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND }),
  s1('Stage 1 per-test currentTime changes the iat baked into the challenge (nonce unchanged)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attestations: ATT_ROBOT }, { random: RAND, currentTime: 1800000000000 }),

  // ===================================================================================
  // Stage 3 — challenge (223) & response (224) validation
  // ===================================================================================
  s3('Stage 3 non-string challenge returns 223', { challenge: 12345, response: RESP_OK }),
  s3('Stage 3 non-base64url challenge returns 223', { challenge: '!!!not-base64url!!!', response: RESP_OK }),
  s3('Stage 3 challenge is valid base64url but decodes to non-JSON bytes returns 223 (Challenge.fromString parse path)', { challenge: 'AAEC', response: RESP_OK }),
  s3('Stage 3 SECURITY: challenge whose decoded bytes are a UTF-8 BOM (EF BB BF) followed by the CANONICAL valid challenge JSON returns 223 — the decoder must not strip the BOM (a second, non-canonical byte encoding of the same challenge must never be accepted; ports must not BOM-sniff when decoding base64url payloads)', { challenge: CH_BOM, response: RESP_OK }),
  s3('Stage 3 challenge decodes to valid JSON but its identifier member is malformed returns 223 (Identity ctor throws inside Challenge.fromString)', { challenge: CH_BADID, response: RESP_OK }),
  s3('Stage 3 non-string response returns 224', { challenge: CH, response: 12345 }),
  s3('Stage 3 response without the | envelope delimiters returns 224', { challenge: CH, response: 'no-envelope-delimiters' }),
  s3('Stage 3 short/empty response (length <= 3) returns 224 via the validator length-check', { challenge: CH, response: '' }),
  s3('Stage 3 re-provided malformed identifier returns 210 (the optional Stage-3 identifier validator)', { challenge: CH, response: RESP_OK, identifier: 'john @triauthdemo.org' }),
  s3('Stage 3 re-provided malformed callbackUrl returns 221 (the optional Stage-3 callbackUrl validator)', { challenge: CH, response: RESP_OK, callbackUrl: 'https://[::1]/cb' }),
  s3('Stage 3 re-provided callbackUrl that is URL-valid but mismatches challenge.cburl (http://example.com/cb vs https) returns 401 — the equality gate, distinct from the 221 format gate', { challenge: CH, response: RESP_OK, callbackUrl: 'http://example.com/cb' }),

  // ===================================================================================
  // Stage 3 — ATTEST-DISTINCT challenge.attest re-validation (229) in onResponse
  // ===================================================================================
  s3('Stage 3 challenge missing the attest field returns 229 (onResponse validateAttestations(undefined))', { challenge: CH_NOATTEST, response: RESP_OK }),
  s3('Stage 3 challenge whose attest field is an array returns 229 (onResponse re-validation)', { challenge: CH_ATTEST_ARR, response: RESP_OK }),

  // ===================================================================================
  // Stage 3 — dispatch-level constraint checks (401) & denial (403)
  // ===================================================================================
  s3("Stage 3 response equal to the literal 'false' returns 403 (user-denial sentinel)", { challenge: CH, response: 'false' }),
  s3('Stage 3 re-provided identifier mismatching challenge.identifier returns 401', { challenge: CH, response: RESP_OK, identifier: 'someone-else@triauthdemo.org' }),
  s3('Stage 3 re-provided callbackUrl mismatching challenge.cburl returns 401', { challenge: CH, response: RESP_OK, callbackUrl: 'https://other-domain.example/' }),
  s3("Stage 3 challenge with type=auth (not 'attest') returns 401 at the flow type-constraint", { challenge: CH_AUTHTYPE, response: RESP_EMPTY_OK }),
  s3("Stage 3 challenge with type=sign (not 'attest') returns 401 at the flow type-constraint", { challenge: CH_SIGNTYPE, response: RESP_EMPTY_OK }),

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
  s3("Stage 3 response '||||' parses into empty segments, each tripping the Signature length guard -> 225", { challenge: CH, response: RESP_EMPTY_SEGS }),
  s3('Stage 3 more than 5 signature segments trips the MultiSignature maxMultiSignatures=5 count guard -> 225', { challenge: CH, response: RESP_SIX_SEGMENTS }),

  // ===================================================================================
  // Stage 3 — generic verification failures (401)
  // ===================================================================================
  s3('Stage 3 well-formed sign-typed envelope against the attest flow returns 401 (type constraint, before crypto)', { challenge: CH_EMPTY, response: RESP_SIGN_TYPED }),
  s3('Stage 3 well-formed auth-typed envelope against the attest flow returns 401', { challenge: CH_EMPTY, response: RESP_AUTH_TYPED }),
  s3('Stage 3 well-formed attest envelope with bogus crypto bytes returns 401 (generic verification failure)', { challenge: CH_EMPTY, response: RESP_BOGUS }),
  s3('Stage 3 a 1-char crypto signature makes atob throw inside the ECDSA verifier -> caught -> 401', { challenge: CH_EMPTY, response: RESP_ONECHAR_SIG }),
  s3('Stage 3 two stacked signatures exceed maxSignatures=1 for an empty-attestation challenge -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_TWO }),
  s3('Stage 3 a single segment carrying 11 crypto signatures exceeds IdentityKeys maxKeysPerSignature=10 -> 401', { challenge: CH_EMPTY, response: RESP_ELEVEN_SIGS }),
  s3('Stage 3 user signature for the WRONG identity (jane signs, mainSig.identifier != challenge.identifier) returns 401 (identifier-mismatch guard)', { challenge: CH_EMPTY, response: RESP_WRONGID }),
  s3('Stage 3 user signature under john identifier but signed with jane key returns 401 (crypto fails)', { challenge: CH_EMPTY, response: RESP_BADKEY }),
  s3('Stage 3 user signature with envelope.via on a DIFFERENT ORIGIN returns 401 (getBaseUrl(cburl) != mainSig.via)', { challenge: CH_EMPTY, response: RESP_VIA_ATTACK }),
  s3('Stage 3 challenge with a malformed embedded cburl returns 401 (onResponse validateCallbackUrl(cburl) fails)', { challenge: CH_BADCBURL, response: RESP_BADCBURL }),
  s3('Stage 3 use mismatch: an attest-typed envelope from a use=auth key returns 401 (key skipped, no verified keys)', { challenge: CH_AUTHONLY, response: RESP_AUTHONLY }),
  s3('Stage 3 user envelope type=auth fails the attest type constraint inside Signature.verify -> 401', { challenge: CH_EMPTY, response: RESP_USERTYPE }),
  s3('Stage 3 partial multi-key signature (only laptop key 1 of 2 signs) returns 401 (per-key break, group never fully satisfied)', { challenge: CH_EMPTY, response: RESP_LAPTOP_PART }),

  // ===================================================================================
  // Stage 3 — ATTEST-DISTINCT attester matching (the heart of onResponse) -> 401 unless matched
  // ===================================================================================
  s3('Stage 3 user signs but no attester signature is present -> 401 (requested attestation unmatched)', { challenge: CH, response: RESP_MISSING_ATT }),
  s3('Stage 3 attester via is not in the requested providers list -> 401', { challenge: CH, response: RESP_VIA_NOTPROV }),
  s3("Stage 3 attester identifier's domain != the attester via hostname -> 401", { challenge: CH_HOSTMIS, response: RESP_HOSTMIS }),
  s3('Stage 3 attester bind.identifier present and != user identifier -> 401', { challenge: CH, response: RESP_ID_MIS }),
  s3('Stage 3 attester bind.via present and != user via -> 401', { challenge: CH, response: RESP_VIA_MIS }),
  s3('Stage 3 attester bind.deviceTag present and != user deviceTag -> 401', { challenge: CH, response: RESP_TAG_MIS }),
  s3('SECURITY: attester bind carrying an UNRECOGNIZED binder -> 401 (every member of bind is critical; a constraint the verifier cannot enforce fails the bundle instead of going unread)', { challenge: CH, response: RESP_BIND_UNKNOWN }),
  s3('SECURITY: attester bind present but EMPTY -> 401 (a bind that states nothing is a producer error, not an anonymous attestation)', { challenge: CH, response: RESP_BIND_EMPTY }),
  s3('SECURITY: attester bind is an ARRAY -> 401 (bind must be a non-array object of recognized binders)', { challenge: CH, response: RESP_BIND_ARRAY }),
  s3('SECURITY: attester bind.identifier carrying a NON-STRING value -> 401 (binder values must be strings)', { challenge: CH, response: RESP_BIND_NONSTR }),
  s3('SECURITY: attester bind with one matching and one false binder -> 401 (ALL stated binders must hold, not just some; kills an any-binder-matches implementation)', { challenge: CH, response: RESP_BIND_MIXED }),
  s3('SECURITY: user segment bind.identifier naming someone else -> 401 (bind means the same on every segment; every binder in the envelope must hold)', { challenge: CH, response: RESP_BIND_ON_USER_MIS }),
  s3('SECURITY: STRAY attester with a false binder poisons the bundle -> 401 even though the clean attester alone satisfies both attestations (overlapping providers)', { challenge: CH_MULTI, response: RESP_BIND_STRAY }),
  s3('Stage 3 attester segment with bogus crypto fails the multisig before matching -> 401', { challenge: CH, response: RESP_ATT_BADCRYPTO }),

  // ===================================================================================
  // Stage 3 — SECURITY properties & regression guards (ATTEST-DISTINCT)
  // These exercise cross-challenge / cross-segment scenarios the rest of the suite never does
  // (every other case mints a response against its own challenge). They pin emergent properties of
  // attest's design (the signed payload is sha256(challengeString), so the ENTIRE challenge is bound)
  // and would catch regressions that drop a field from the signed payload, reorder segments, leak
  // partial results, loosen the signature-count bound, or weaken the prototype-pollution defense.
  // ===================================================================================
  // Challenge binding: a response is non-transferable to any other challenge. Each of the next four
  // submits the valid RESP_OK (minted for CH) against a challenge differing in ONE signed field; the
  // user/attester crypto no longer verifies -> 401. (If a refactor signed only a subset of the
  // challenge, these would silently start passing — that is the regression they guard against.)
  s3('SECURITY (nonce binding): RESP_OK does not verify against a challenge differing only in the nonce -> 401', { challenge: CH_DIFF_NONCE, response: RESP_OK }),
  s3('SECURITY (attestation binding / relabel): a response cannot be re-presented against a challenge that RELABELS the attestation (different id, same provider) -> 401 (the attest map is signed; the same attester proof cannot be recontextualized to a different claim — the matching loop alone would otherwise accept it)', { challenge: CH_RELABEL, response: RESP_OK }),
  s3('SECURITY (iat binding): RESP_OK does not verify against a challenge whose iat was shifted within the window -> 401 (NOT 402: iat is signed, not merely range-checked)', { challenge: CH_DIFF_IAT, response: RESP_OK }),
  s3('SECURITY (exact callbackUrl binding): RESP_OK is rejected at a SIBLING callback sharing the same base directory -> 401 (attest binds the full cburl via the signed challenge even though getBaseUrl == mainSig.via; stricter than stamp, whose via binds only the base dir)', { challenge: CH_SIBLING, response: RESP_OK }),
  // Protocol invariant: the user signature must be the first segment.
  s3('SECURITY (segment order): swapping the user and attester segments (attester in slot 0) -> 401 (mainSig is always signatures[0]; its identifier must equal challenge.identifier)', { challenge: CH, response: RESP_SWAPPED }),
  // All-or-nothing: a partially-satisfied multi-attestation request never yields a partial result.
  s3('SECURITY (all-or-nothing): with two distinct attestations requested, satisfying only one of them -> 401 (no partial attested result leaks)', { challenge: CH_TWO, response: RESP_TWO_PARTIAL }),
  // Signature-count bound: cannot pad the envelope with attesters beyond maxSignatures = requested + 1.
  s3('SECURITY (signature-count bound): a 1-attestation challenge answered with user + TWO attesters (3 > maxSignatures=2) -> 401', { challenge: CH, response: RESP_OVERSUPPLY }),
  // Prototype-pollution defense at the challenge-parse boundary.
  s3('SECURITY (prototype-pollution defense): a challenge whose attest map carries a __proto__ key is rejected at parse time -> 223 (safeParseJson blocks it before onResponse)', { challenge: CH_PROTO_ATTEST, response: RESP_OK }),

  // ===================================================================================
  // Stage 3 — identity / DNS failures during verification (401)
  // ===================================================================================
  s3("Stage 3 user identity records vanished between stages (NXDOMAIN) returns 401", { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'john._at.triauthdemo.org': null } }),
  s3("Stage 3 user authentication endpoint is gone (NXDOMAIN) returns 401", { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'triauthdemo.org': null } }),
  s3('Stage 3 DNS SERVFAIL on the authentication endpoint propagates from signature.verify and surfaces as a retryable 110 (not a false 401)', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s3('Stage 3 DNS SERVFAIL on the identity domain propagates from signature.verify and surfaces as a retryable 110 (not a false 401)', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'john._at.triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s3("Stage 3 attester identity records gone (NXDOMAIN) makes the attester segment fail -> 401", { challenge: CH, response: RESP_OK }, { dnsEntries: { 'robot-attester._at.attest.triauthdemo.org': null } }),
  s3("Stage 3 attester authentication endpoint gone (NXDOMAIN) makes the attester segment fail -> 401", { challenge: CH, response: RESP_OK }, { dnsEntries: { 'attest.triauthdemo.org': null } }),

  // ===================================================================================
  // Stage 3 — IdentityKeys.add / verify branches reached via the attest verify path (-> 401)
  // (driven through the USER segment with an empty-attestation challenge + patched john._at records)
  // ===================================================================================
  s3('Stage 3 identity key with invalid syntax (missing [idx/count]) leaves no usable keyGroup -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey(`key desktop:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 identity key that taints its device group (desktop[2/1]) leaves no valid keyGroup -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey(`key desktop[2/1]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 SECURITY: split key group published only as its final fragment (laptop[2/2] alone, no laptop[1/2]) never validates — a lone write to the group\'s last index already inflates keys.length to keyCount and Object.entries/.every iteration skips array holes, so a length-gated validity check would accept the one-signature response from the published fragment; the populated-slot count (src/identity_keys.js:153-157) keeps the group invalid -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_LASTFRAG }, { dnsEntries: johnSingleKey(`key laptop[2/2]:${john.devices[1].keys[1].public}`) }),
  s3('Stage 3 leading-zero keyIdx (desktop[01/1]) maps to literal 0, failing the range check and tainting the group -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey(`key desktop[01/1]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 leading-zero keyCount (desktop[1/01]) maps to literal 0, failing the range check and tainting the group -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey(`key desktop[1/01]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 a doubled key index (two desktop[1/1] records) un-validates the already-valid group -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', `key desktop[1/1]:${john.devices[0].keys[0].public}`, `key desktop[1/1]:${john.devices[1].keys[0].public}`] } } }),
  s3('Stage 3 identity key value that is not base64url taints the group -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey('key desktop[1/1]:has!bang') }),
  s3('Stage 3 identity key value valid base64url but too short to initialize an ECDSA verifier (AAAA) -> 401 (null-verifier continue)', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey('key desktop[1/1]:AAAA') }),
  s3('Stage 3 identity key with a deviceName longer than the record-name regex allows ({1,20}, the 20-byte limit) is dropped -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnSingleKey(`key abcdefghijklmnopqrstu[1/1]:${john.devices[0].keys[0].public}`) }),
  s3("Stage 3 identity records publishing more than maxDevices=10 devices drop the 11th (john's real key) -> 401", { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: elevenDevices }),
  s3('Stage 3 identity key with an unknown critical (non x-) option taints its device group -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnKeyRecord(' badopt=value') }),
  s3('Stage 3 key record with a negative TTL yields an already-expired keyGroup that is skipped -> 401', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnKeyRecord('', { ttl: -2000, dnssec: true }) }),
  s3('Stage 3 TTL-less key record (expires undefined) with bogus crypto -> 401 (exercises the expires!==undefined false branch)', { challenge: CH_EMPTY, response: RESP_BOGUS }, { dnsEntries: johnKeyRecord('', { dnssec: true }) }),

  // ===================================================================================
  // Stage 3 — expired / time-window (402). ATTEST-DISTINCT: notBefore = now - attestTimeout (15min).
  // ===================================================================================
  s3('Stage 3 challenge iat far before notBefore returns 402', { challenge: CH_PAST, response: RESP_FOR_IAT }),
  s3('Stage 3 challenge iat in the future (after notAfter == now) returns 402', { challenge: CH_FUTURE, response: RESP_FOR_IAT }),
  // The 402 boundary sits at attestTimeout + maximalAllowedServerClockDrift: a CH_JUST_EXP challenge
  // (1ms past the bare 15min window relative to T) only expires once the clock has also advanced
  // past the 5s server-drift widening, so this test verifies at T + 5s.
  s3('Stage 3 challenge iat 1ms past the 15min attestTimeout + 5s maximalAllowedServerClockDrift returns 402 (boundary)', { challenge: CH_JUST_EXP, response: RESP_FOR_IAT }, { currentTime: T + 5e3 }),
  s3('Stage 3 challenge with a non-numeric iat returns 402 (Response.verify typeof-guard)', { challenge: CH_IAT_NAN, response: RESP_FOR_IAT }),
  s3('Stage 3 fresh challenge but the SIGNATURE ts is before the widened window -> 402 (Signature.verify ts check)', { challenge: CH, response: RESP_TS_PAST }),
  s3('Stage 3 fresh challenge but the SIGNATURE ts is after the widened window -> 402', { challenge: CH, response: RESP_TS_FUTURE }),

  // ===================================================================================
  // Stage 3 — metadata parse rejections (225), shared Signature/safeParseJson machinery (USER segment)
  // ===================================================================================
  s3('Stage 3 garbage signedMetadata (decodes to a JSON array) returns 225', { challenge: CH_EMPTY, response: RESP_GARBAGE_SIGNED }),
  s3('Stage 3 __proto__-poisoning signedMetadata is caught by safeParseJson -> 225', { challenge: CH_EMPTY, response: RESP_PROTO_SIGNED }),
  s3('Stage 3 signedMetadata that is valid base64url but non-JSON text returns 225', { challenge: CH_EMPTY, response: RESP_RAWTEXT_SIGNED }),
  s3("Stage 3 SECURITY: signedMetadata segment decodes to a UTF-8 BOM (EF BB BF) followed by otherwise-valid ext JSON ({\"ext\":{\"bom\":true}}) — rejected at parse time with 225; the decoder must not strip the BOM, so a non-canonical byte encoding of valid metadata is never accepted (real signature covers the BOM segment)", { challenge: CH_EMPTY, response: RESP_BOM_SIGNED }),
  s3('Stage 3 garbage unsignedMetadata (decodes to a JSON array) returns 225 (real sig, slot MITM-swapped)', { challenge: CH_EMPTY, response: RESP_GARBAGE_UNSIGNED }),
  s3('Stage 3 constructor.prototype-poisoning unsignedMetadata is caught by safeParseJson (second clause) -> 225', { challenge: CH_EMPTY, response: RESP_PROTO_UNSIGNED }),
  s3('Stage 3 unsignedMetadata of raw binary bytes (no valid JSON token) returns 225', { challenge: CH_EMPTY, response: RESP_RAWBIN_UNSIGNED }),
  s3('Stage 3 unsignedMetadata nested 9 deep exceeds jsonMaxNestingDepth=8 -> 225', { challenge: CH_EMPTY, response: RESP_DEEP_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a 257-char key exceeds jsonMaxKeyLength=256 -> 225', { challenge: CH_EMPTY, response: RESP_LONGKEY_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a non-ASCII key returns 225', { challenge: CH_EMPTY, response: RESP_NONASCII_UNSIGNED }),
  s3('Stage 3 SECURITY: unsignedMetadata whose bytes are not well-formed UTF-8 inside a string value returns 225 — payload-slot bytes must be well-formed UTF-8; decoders reject rather than substitute U+FFFD (string values have no charset rule of their own, so only the decode-time rejection pins this)', { challenge: CH_EMPTY, response: RESP_BADUTF8_VALUE_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a non-ASCII key in well-formed UTF-8 ({"résumé":1} as C3 A9 bytes) returns 225 — the Bounded-JSON ASCII-key rule, distinct from the ill-formed-byte rejection', { challenge: CH_EMPTY, response: RESP_EKEY_UNSIGNED }),
  s3('Stage 3 SECURITY: unsignedMetadata whose JSON carries a lone-surrogate escape (\\ud800) in a key returns 225 — parser-independent: a parser that preserves the escape yields a non-ASCII key, one that substitutes U+FFFD likewise, one that rejects it fails the parse; no conformance vector requires accepting a lone-surrogate escape anywhere', { challenge: CH_EMPTY, response: RESP_SURROGATE_KEY_UNSIGNED }),

  // ===================================================================================
  // Stage 3 — WebAuthn verifier backend (key type=webauthn-es256), reached via IdentityKeys.verify.
  // ===================================================================================
  s3('Stage 3 WebAuthn valid assertion (challenge=sha256(payload), webauthn.get, matching origin, crossOrigin=false) attests successfully', { challenge: CH_WA, response: RESP_WA_OK }),
  s3('Stage 3 WebAuthn structurally valid assertion but a bad ECDSA signature -> 401 (crypto.subtle.verify false)', { challenge: CH_WA, response: RESP_WA_BADSIG }),
  s3('Stage 3 WebAuthn unsignedMetadata has no sig object -> 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_NOSIG }),
  s3('Stage 3 WebAuthn sig has no entry for the key index -> 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_NOIDX }),
  s3('Stage 3 WebAuthn clientDataJSON is not a string -> 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_CDJ_NOSTR }),
  s3('Stage 3 WebAuthn authenticatorData is not base64url -> 401 (structure guard)', { challenge: CH_WA, response: RESP_WA_AD_NOB64 }),
  s3('Stage 3 WebAuthn clientData.challenge != sha256(payload) -> 401', { challenge: CH_WA, response: RESP_WA_BADCHAL }),
  s3('Stage 3 WebAuthn clientDataJSON contains "challenge": more than once -> 401 (anti-injection guard)', { challenge: CH_WA, response: RESP_WA_DUPCHAL }),
  s3("Stage 3 WebAuthn clientData.type != 'webauthn.get' -> 401", { challenge: CH_WA, response: RESP_WA_BADTYPE }),
  s3('Stage 3 WebAuthn clientData.crossOrigin is not false -> 401', { challenge: CH_WA, response: RESP_WA_CROSSORIG }),
  s3('Stage 3 WebAuthn clientData.origin != the authentication endpoint origin -> 401', { challenge: CH_WA, response: RESP_WA_BADORIGIN }),
  s3('Stage 3 WebAuthn clientDataJSON is not valid JSON -> safeParseJson throws -> caught -> 401', { challenge: CH_WA, response: RESP_WA_BADJSON }),
  s3('Stage 3 WebAuthn published key value too short to import -> fromPublishableKey returns null -> 401', { challenge: CH_WA, response: RESP_WA_OK }, { dnsEntries: { 'webauthn._at.triauthdemo.org': { TXT: ['name WebAuthn', 'key wa[1/1]:AAAA type=webauthn-es256'] } } }),

  // ===================================================================================
  // Stage 3 — SUCCESS (attested:true). Pins attest's result shape:
  //   {attested:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode,
  //    groups, attestations:{<id>:{...attester sig}}, deviceName, deviceTag, keys}
  // ===================================================================================
  s3('Stage 3 distinct third-party attester verifies under its OWN identifier/domain -> attested:true', { challenge: CH, response: RESP_OK }),
  s3('Stage 3 multi-key user device (laptop, 2 keys) attests successfully with both keys verified', { challenge: CH, response: RESP_OK_LAPTOP }),
  s3('Stage 3 empty attestations {} -> attested:true with attestations:{} (no attester required)', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }),
  s3('Stage 3 self-attestation (attester identifier == user, via hostname == user domain) -> attested:true', { challenge: CH_SELF, response: RESP_SELF }),
  s3('Stage 3 two DISTINCT attesters satisfy two attestations in one envelope -> attested:true', { challenge: CH_TWO, response: RESP_TWO }),
  s3('Stage 3 one attester signature satisfies two attestation IDs (overlapping providers) -> attested:true', { challenge: CH_MULTI, response: RESP_MULTI }),
  s3('Stage 3 attester bind.identifier+bind.via+bind.deviceTag all bind the user -> attested:true', { challenge: CH, response: RESP_BIND_OK }),
  s3('Stage 3 top-level signedMetadata members are auxiliary and ignored regardless of name or value (binders live only in bind) -> attested:true', { challenge: CH, response: RESP_BIND_FLAT }),
  s3('Stage 3 unrecognized non-binder signedMetadata member is tolerated -> attested:true (outside bind, unknown means ignore)', { challenge: CH, response: RESP_BIND_AUX }),
  s3('Stage 3 user segment bind stating its own verified values -> attested:true (bind means the same on every segment)', { challenge: CH, response: RESP_BIND_ON_USER }),
  s3('Stage 3 PRIVATE: private-mode subject attests successfully - the user segment carries the lookup code, the public-mode attester none (per-segment independence)', { challenge: CH_PRIVATE, response: RESP_PRIVATE_OK }),
  s3('Stage 3 PRIVATE: an attester binder binding the result-form deviceTag (<tag>~<lookupCode>) matches and attests successfully - the binder pins the lookup-code epoch', { challenge: CH_PRIVATE, response: RESP_PRIVATE_BIND }),
  s3('Stage 3 PRIVATE SECURITY: an attester binder binding the bare device digest mismatches the suffixed result form -> 401 (the bound value is the result-form handle, not the bare digest)', { challenge: CH_PRIVATE, response: RESP_PRIVATE_BIND_UNSALTED }),
  s3('Stage 3 callbackUrl already ending in / attests successfully (getBaseUrl THEN branch)', { challenge: CH_TRAILING, response: RESP_TRAILING }),
  s3('Stage 3 use=attest-only user key attests successfully', { challenge: CH_ATTESTONLY, response: RESP_ATTESTONLY }),
  s3('Stage 3 unsignedMetadata with a null value parses fine and attests successfully', { challenge: CH_EMPTY, response: RESP_NULLVALUE_UNSIGNED }),
  s3('Stage 3 a 14-min-old challenge still attests (inside the 15min attestTimeout window)', { challenge: CH_14MIN, response: RESP_14MIN }),
  s3('Stage 3 key record with dnssec:false attests successfully but with secure:false', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnKeyRecord('', { ttl: 1800, dnssec: false }) }),
  s3('Stage 3 key record with a custom TTL yields expires = now + ttl*1000', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnKeyRecord('', { ttl: 60, dnssec: true }) }),
  s3('Stage 3 unrecognized identity-record keyword is ignored; attestation still succeeds', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'foo bar', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  s3('Stage 3 identity records with escape-looking junk in values or options are literal, fit no grammar, and contribute nothing; attestation still succeeds on the surviving key', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'meta x-o=%0A', 'note %0A', 'raw %ZZ', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  s3('Stage 3 x- prefixed key option is allowed through (not in the deviceTag); attestation succeeds with the option visible on the key', { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { dnsEntries: johnKeyRecord(' x-tag=custom') }),
  s3('Stage 3 ATTEST-DISTINCT: per-call config attestTimeout:0 takes the `|| 0` arm; an iat==now challenge still attests', { challenge: CH, response: RESP_OK }, { _argsOverride: [{ challenge: CH, response: RESP_OK }, { attestTimeout: 0 }] }),

  // ===================================================================================
  // Back-filled tests that were first added directly to attest.json (after the clock-drift
  // widening / WebAuthn UP-UV enforcement / dnssec-capping changes shipped) — kept here so
  // a full regeneration reproduces them.
  // ===================================================================================
  s3("Stage 3 SECURITY: USER endpoint triauth record with dnssec:false caps top-level secure to false while the attestation's own secure stays true", { challenge: CH, response: RESP_OK }, { dnsEntries: { 'triauthdemo.org': { TXT: [{ value: 'triauth auth.triauthdemo.org mode=public', ttl: 1800, dnssec: false }] } } }),
  s3('Stage 3 SECURITY: ATTESTER endpoint triauth record with dnssec:false caps both the per-attestation secure and the top-level secure to false', { challenge: CH, response: RESP_OK }, { dnsEntries: { 'attest.triauthdemo.org': { TXT: [{ value: 'triauth auth.attest.triauthdemo.org mode=public', ttl: 1800, dnssec: false }] } } }),
  s3('Stage 3 SECURITY: challenge 4.999s past the 15min attestTimeout still attests — the expiry boundary is widened by maximalAllowedServerClockDrift', { challenge: CH, response: RESP_OK }, { currentTime: T + (15 * 60e3) + 4999 }),
  s3('Stage 3 SECURITY: WebAuthn assertion with the User Present (UP) flag cleared (CTAP-level silent assertion) -> 401 even though its ECDSA signature is valid', { challenge: CH_WA, response: RESP_WA_NOUP }),
  s3('Stage 3 SECURITY: WebAuthn authenticatorData shorter than 37 bytes (rpIdHash+flags+signCount) -> 401 (length guard)', { challenge: CH_WA, response: RESP_WA_SHORT }),
  s3('Stage 3 SECURITY: uv=required key record rejects an assertion without the User Verified (UV) flag -> 401 (UP alone is not enough)', { challenge: CH_WA, response: RESP_WA_OK }, { dnsEntries: waKeyRecord(' uv=required') }),
  s3('Stage 3 uv=required key record accepts an assertion with both UP and UV flags set -> attested:true', { challenge: CH_WA, response: RESP_WA_UPUV }, { dnsEntries: waKeyRecord(' uv=required') }),
  s3('Stage 3 SECURITY: a mistyped uv value (uv=reuired) taints the keyGroup -> 401 - fail closed, a typo must not silently drop the user verification requirement', { challenge: CH_WA, response: RESP_WA_OK }, { dnsEntries: waKeyRecord(' uv=reuired') }),

  // ===================================================================================
  // Stage 3 — Ed25519 (type=ed25519) and WebAuthn-Ed25519 (type=webauthn-ed25519) verifier
  // backends, reached via IdentityKeys.verify for both the USER segment and third-party
  // ATTESTER segments. Cross-language guarantee: a port without these verifiers registered
  // would taint the keyGroups and fail the positives.
  // ===================================================================================
  s3('Stage 3 Ed25519: USER with a type=ed25519 key + es256 robot attester attests successfully (mixed-algorithm multisig)', { challenge: CH_ED25519U, response: RESP_ED25519U }),
  s3('Stage 3 Ed25519: THIRD-PARTY ATTESTER backed by a type=ed25519 key attests successfully (es256 user + ed25519 attester)', { challenge: CH_EDATT, response: RESP_EDATT }),
  s3('Stage 3 Ed25519: 65-byte P-256 key material published as the USER\'s type=ed25519 key cannot import (raw Ed25519 keys are exactly 32 bytes) -> fromPublishableKey null -> 401', { challenge: CH_ED25519U, response: RESP_ED25519U }, { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${john.devices[0].keys[0].public} type=ed25519`] } } }),
  s3('Stage 3 Ed25519: 65-byte P-256 key material published as the ATTESTER\'s type=ed25519 key cannot import -> attester unverified -> 401', { challenge: CH_EDATT, response: RESP_EDATT }, { dnsEntries: { 'ed25519-attester._at.attest.triauthdemo.org': { TXT: ['name Ed25519 Checker', `key server[1/1]:${robot.devices[0].keys[0].public} use=attest type=ed25519`] } } }),
  s3('Stage 3 Ed25519 SECURITY: uv=required on a type=ed25519 (non-webauthn) key is unenforceable and taints the keyGroup -> 401 - fail closed', { challenge: CH_ED25519U, response: RESP_ED25519U }, { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${ed25519.keys[0].public} type=ed25519 uv=required`] } } }),
  s3('Stage 3 WebAuthn-Ed25519: valid assertion backed by a type=webauthn-ed25519 user key attests successfully', { challenge: CH_WAED, response: RESP_WAED_OK }),
  s3('Stage 3 WebAuthn-Ed25519: structurally valid assertion with bogus crypto -> 401', { challenge: CH_WAED, response: RESP_WAED_BADSIG }),
  // callbackUrl base-directory delimiter guards (";" and "|" are envelope separators).
  s1("Stage 1 SECURITY: callbackUrl with a \";\" in its base directory (https://example.com/a;b/cb) returns 221 — \";\" is the signature envelope field delimiter, so the base URL that becomes the signed via must not contain it; rejecting at validation avoids a silent downstream failure (the authenticator’s Signature.generate refuses such a via)", {"identifier":ID,"callbackUrl":"https://example.com/a;b/cb","attestations":{"not-a-robot":{"label":"I am not a robot","providers":["https://attest.triauthdemo.org/not-a-robot"]}}}),
  s1("Stage 1 SECURITY: callbackUrl with a \"|\" in its base directory (https://example.com/a|b/cb) returns 221 — \"|\" is the signature envelope wrapper/separator; a base URL containing it would corrupt the envelope, so it is rejected at validation rather than failing silently downstream", {"identifier":ID,"callbackUrl":"https://example.com/a|b/cb","attestations":{"not-a-robot":{"label":"I am not a robot","providers":["https://attest.triauthdemo.org/not-a-robot"]}}}),
  s1("Stage 1 callbackUrl with a \";\" in its LAST path segment (https://example.com/cb;sid=1) builds a challenge — the final segment never enters the base URL/via, so the envelope delimiter rule stops at the base span", {"identifier":ID,"callbackUrl":"https://example.com/cb;sid=1","token":":aaaaaaaaaaaaaaaa","attestations":{"not-a-robot":{"label":"I am not a robot","providers":["https://attest.triauthdemo.org/not-a-robot"]}}}, { random: RAND }),
  // PUBLICPROFILE: shape and hardening of the publicProfile surfaced on attest (the ATTESTER profile) results
  // (per-test dnsEntries publish the profile records; the envelope is the canonical minted one).
  s3("PUBLICPROFILE: attest surfaces the attester's name/initials and x- extensions; unrecognized keywords (incl. former 'roles'/'title') and over-long x- keys are dropped", { challenge: CH, response: RESP_OK }, { dnsEntries: {
      "robot-attester._at.attest.triauthdemo.org": {
        "TXT": [
          "name Robot Checker",
          "initials RC",
          "tagline Always human",
          "x-team Trust",
          "roles admin",
          "title bot",
          "future-feature whatever",
          "x-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa dropped",
          "key server[1/1]:BMR8Ug7qu9HUc9UgY_ADh8giBNmWBbSmGsR6DD6Hg5rpWeyYvu2WlQ43iR_dj0eKN99esQNMe7Gq2u2LBnRejcU use=attest"
        ]
      }
    } }),
  s3("PUBLICPROFILE SECURITY: attest drops an attester publicProfile keyword that appears more than once (reserved and x-) entirely", { challenge: CH, response: RESP_OK }, { dnsEntries: {
      "robot-attester._at.attest.triauthdemo.org": {
        "TXT": [
          "name First",
          "name Second",
          "initials RC",
          "x-dup one",
          "x-dup two",
          "key server[1/1]:BMR8Ug7qu9HUc9UgY_ADh8giBNmWBbSmGsR6DD6Hg5rpWeyYvu2WlQ43iR_dj0eKN99esQNMe7Gq2u2LBnRejcU use=attest"
        ]
      }
    } }),
  s3("PUBLICPROFILE SECURITY: attest rejects (does not truncate) an attester publicProfile value longer than the byte cap", { challenge: CH, response: RESP_OK }, { dnsEntries: {
      "robot-attester._at.attest.triauthdemo.org": {
        "TXT": [
          "initials RC",
          "name aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "key server[1/1]:BMR8Ug7qu9HUc9UgY_ADh8giBNmWBbSmGsR6DD6Hg5rpWeyYvu2WlQ43iR_dj0eKN99esQNMe7Gq2u2LBnRejcU use=attest"
        ]
      }
    } }),
  s3("PUBLICPROFILE SECURITY: attest caps the number of distinct attester x- extensions (only the first publicProfileMaxExtensions are kept)", { challenge: CH, response: RESP_OK }, { dnsEntries: {
      "robot-attester._at.attest.triauthdemo.org": {
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
          "key server[1/1]:BMR8Ug7qu9HUc9UgY_ADh8giBNmWBbSmGsR6DD6Hg5rpWeyYvu2WlQ43iR_dj0eKN99esQNMe7Gq2u2LBnRejcU use=attest"
        ]
      }
    } }),
  // requireSecure: per-call config; the non-DNSSEC twin patches the key record to dnssec:false.
  s3("requireSecure: attest stage 3 - DNSSEC-secure result still succeeds when requireSecure:true", { challenge: CH_WA, response: RESP_WA_OK }, { _argsOverride: [{ challenge: CH_WA, response: RESP_WA_OK }, { requireSecure: true }] }),
  s3("SECURITY requireSecure: attest stage 3 - non-DNSSEC (secure:false) result is rejected with 404", { challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { _argsOverride: [{ challenge: CH_EMPTY, response: RESP_EMPTY_OK }, { requireSecure: true }], dnsEntries: {
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

  // --- delegated segments (include grants) ---------------------------------------------
  s3('Stage 3 delegated USER segment (actor signs under an include grant) attests with the composite deviceTag', { challenge: CH, response: RESP_DELEGATED_USER }, { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD', 'name John Doe',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      `key laptop[1/2]:${john.devices[1].keys[0].public}`,
      `key laptop[2/2]:${john.devices[1].keys[1].public}`,
      'include jane@triauthdemo.org use=attest scope=any',
    ] },
  } }),
  s3('Stage 3 delegated USER segment whose grant publishes no scope option returns 401 - scope is required, and the record is ignored as a whole', { challenge: CH, response: RESP_DELEGATED_USER }, { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD', 'name John Doe',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      `key laptop[1/2]:${john.devices[1].keys[0].public}`,
      `key laptop[2/2]:${john.devices[1].keys[1].public}`,
      'include jane@triauthdemo.org use=attest',
    ] },
  } }),
  s3('Stage 3 SECURITY: a delegated ATTESTER segment never satisfies an attestation (attester statements are first-party) even when the delegation itself verifies -> 401', { challenge: CH, response: RESP_DELEGATED_ATTESTER }, { dnsEntries: {
    'attest.triauthdemo.org': { TXT: ['triauth auth.attest.triauthdemo.org include=triauthdemo.org mode=public'] },
    'robot-attester._at.attest.triauthdemo.org': { TXT: [
      'name Robot Checker',
      `key server[1/1]:${robot.devices[0].keys[0].public} use=attest`,
      'include jane@triauthdemo.org use=attest scope=any',
    ] },
  } }),
  s3('Stage 3 delegated USER segment whose grant is scoped to the service host (use=attest scope=example.com) attests', { challenge: CH, response: RESP_DELEGATED_USER }, { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD', 'name John Doe',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      `key laptop[1/2]:${john.devices[1].keys[0].public}`,
      `key laptop[2/2]:${john.devices[1].keys[1].public}`,
      'include jane@triauthdemo.org use=attest scope=example.com',
    ] },
  } }),
  s3('Stage 3 SECURITY: delegated USER segment whose grant is scoped to a different host (use=attest scope=other.example) returns 401', { challenge: CH, response: RESP_DELEGATED_USER }, { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD', 'name John Doe',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      `key laptop[1/2]:${john.devices[1].keys[0].public}`,
      `key laptop[2/2]:${john.devices[1].keys[1].public}`,
      'include jane@triauthdemo.org use=attest scope=other.example',
    ] },
  } }),

  // GROUPS: two unrelated scopes in one result - the top-level field describes the USER,
  // each attestations.<id>.groups describes that attester's own identity.
  s3("GROUPS: attest carries the user's groups top-level and the attester's own groups inside its attestation - two unrelated scopes", { challenge: CH, response: RESP_OK }, { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD',
      'name John Doe',
      'groups admins,project3',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      `key laptop[1/2]:${john.devices[1].keys[0].public}`,
      `key laptop[2/2]:${john.devices[1].keys[1].public}`,
    ] },
    'robot-attester._at.attest.triauthdemo.org': { TXT: [
      'name Robot Checker',
      'initials RC',
      'groups auditors',
      'key server[1/1]:BMR8Ug7qu9HUc9UgY_ADh8giBNmWBbSmGsR6DD6Hg5rpWeyYvu2WlQ43iR_dj0eKN99esQNMe7Gq2u2LBnRejcU use=attest',
    ] },
  } }),
];

// Normalize: a couple of dispatch/config tests need an args shape the s3() helper can't express
// through its single options object — splice in the override and drop the marker.
for (const t of tests) {
  if (t._argsOverride) { t.args = t._argsOverride; delete t._argsOverride; }
}

const suite = {
  title: 'attest',
  description:
    'Comprehensive, branch-complete coverage of Triauth.attest. Stage 1 (request): dispatch/arg guards, ' +
    'identifier/callbackUrl/ext/token validation, the ATTEST-DISTINCT attestations (229) validation done ' +
    'in onChallenge, DNS configuration (301/302) and DNS failure (110), and deterministic challenge + ' +
    '/attest.html redirect building (with the attestations object baked in, and the token HMAC). Stage 3 ' +
    '(verify): challenge/response validation, the onResponse attest re-validation (229), dispatch ' +
    'constraints (401/403), signature-envelope parse failures (225), generic verification failures (401), ' +
    'the IdentityKeys add/verify branches and WebAuthn verifier reached via the verify path, the 15min ' +
    'attestTimeout window (402), metadata parse rejections (225), and the heart of attest — the ' +
    'multi-signature envelope whose first segment is the user signature and the rest are third-party ' +
    'attester signatures: the bind binder object (identifier/via/deviceTag) is enforced on every ' +
    'segment (every member of bind is critical and must match the verified user; members outside ' +
    'bind are auxiliary and ignored), and attesters are matched against the requested providers ' +
    '(provider membership, attester identifier-domain == via hostname) plus the ' +
    '{attested:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, attestations, deviceName, deviceTag, keys} ' +
    'body. For attest, the crypto signature is over sha256(challengeString) and every segment signs that ' +
    'same payload; crypto-bearing fixtures were minted by test/fixtures/json/_capture_attest.mjs (WebCrypto ' +
    'ECDSA is non-deterministic to mint, deterministic to verify). A final Ed25519 section covers the ' +
    'type=ed25519 and type=webauthn-ed25519 verifier backends for both the user and third-party attester ' +
    'segments, including mixed-algorithm (es256 + ed25519) multisigs.' +
    ' A PRIVATE MODE section covers a private-mode subject with a public-mode attester (per-segment lookup-code independence) and pins that binders bind the result-form deviceTag (a bare-digest deviceTag binder mismatches).',
  dnsEntries,
  currentTime: T,
  tests,
};

writeSuite(new URL('./attest.json', import.meta.url), suite);
