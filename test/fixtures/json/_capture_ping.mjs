// One-shot generator for the cross-language ping.json suite.
//
// Like ./_capture_auth.mjs (the auth.json signer), the Stage 3 ping cases that exercise the
// crypto-verified paths (success bodies AND the "valid signature, rejected for some OTHER
// reason" negatives) need real ECDSA P-256 signatures. WebCrypto ECDSA is non-deterministic
// to MINT but deterministic to VERIFY, so we mint here once and bake the resulting
// challenge/response strings into ping.json.
//
// Unlike _capture_auth.mjs (which only prints blobs for manual paste), this script assembles and
// writes the ENTIRE ping.json file — every test object, with the minted challenge/response
// already inlined — but WITHOUT the `expected` blocks. After running it, populate the
// expecteds with the canonical runner:
//
//   node --experimental-global-webcrypto test/fixtures/json/_capture_ping.mjs   # (re)write ping.json structure
//   RECORD=1 npm run test:json                                                  # fill in every `expected`
//   npm run test:json                                                           # confirm green
//   git diff test/fixtures/json/ping.json                                       # eyeball before committing
//
// Re-run this script whenever the signature envelope format, the challenge field order, the
// John/signonly/jane DNS layout, or the suite-level currentTime changes (any of these change
// the signed bytes and invalidate the baked signatures).

import * as Triauth from '../../../src/index.js';
globalThis.Triauth = Triauth;
import identities from '../identities.json' with { type: 'json' };
// Shared generator plumbing: frozen clock, logger, the local signonly/jane/ed25519 fixture
// identities (single definition keeps every suite's keypairs in lock-step), and the guarded
// suite writer.
import { T, LOGGER, signonly, jane, ed25519, PRIVATE, writeSuite } from './_capture_common.mjs';
// Minting only needs the private-key signer; no DNS is consulted here (the runner resolves DNS
// from the suite's dnsEntries at verify time).
const SignerStub = (await import('../../stubs/signer.js')).default;

Triauth.config.logger = LOGGER;

// Freeze the clock at the shared suite T. Every challenge iat and every signature ts is minted
// at T, so the signatures land inside ping's notBefore/notAfter window (notBefore = T - pingTimeout).
Date.now = () => T;

const john = identities.john;

const ID  = 'john@triauthdemo.org';
const CB   = 'https://example.com/cb';   // canonical callbackUrl (has a path segment to strip)
const CB_TRAILING = 'https://example.com/'; // already a base URL (exercises getBaseUrl THEN branch)
const LAN_CB  = 'http://10.0.0.5:8080/cb'; // plain-http LAN callback: IPv4-literal host + port
const LAN_VIA = 'http://10.0.0.5:8080/';
// `via` in the envelope is matched at src/api/authentication.js against
// Helpers.getBaseUrl(challenge.data.cburl). getBaseUrl('https://example.com/cb') === 'https://example.com/'.
const VIA = 'https://example.com/';
const NONCE = 'ABEiM0RVZneImaq7zN3u_wAR';  // deterministic nonce for RAND below (kept for readability)
const RAND = '00112233445566778899aabbccddeeff00112233';

// Build a ping challenge string with full control over every field. Field order mirrors
// Challenge.build (cburl, [ext], type, identifier, nonce, iat, ver) so the baked strings read like
// real ones; Stage 3 never re-checks the nonce, so a fixed nonce is fine.
const mkChallenge = ({ cburl = CB, ext, type = 'ping', identifier = ID, nonce = NONCE, iat = T, ver = 1 } = {}) => {
  const data = {};
  data.cburl = cburl;
  if (ext !== undefined) data.ext = ext;
  data.type = type;
  data.identifier = identifier;
  data.nonce = nonce;
  data.iat = iat;
  data.ver = ver;
  return Triauth.Helpers.stringToBase64Url(JSON.stringify(data));
};

// Standard ping challenges reused across Stage 3 cases.
const CH          = mkChallenge();                                   // john, cb, fresh
const CH_TRAILING = mkChallenge({ cburl: CB_TRAILING });             // john, base-url cb
const CH_AUTHTYPE = mkChallenge({ type: 'auth' });                   // type mismatch vs ping flow
const CH_PAST     = mkChallenge({ iat: 1700000000000 });             // far before notBefore
const CH_FUTURE   = mkChallenge({ iat: 1800000000000 });             // after notAfter (== T)
const CH_60S      = mkChallenge({ iat: T - 60000 });                 // 60s old: fine for auth (3min), expired for ping (15s)
const CH_PRIVATE   = mkChallenge({ identifier: PRIVATE.john.identifier });
const CH_SIGNONLY = mkChallenge({ identifier: signonly.identifier });
const CH_ED25519  = mkChallenge({ identifier: ed25519.identifier });        // identity whose key is published as type=ed25519
const CH_ED_LAN   = mkChallenge({ cburl: LAN_CB, identifier: ed25519.identifier }); // LAN callback flow (Ed25519 keeps the minted bytes deterministic)
const CH_BADID   = mkChallenge({ identifier: 'no-at-sign.example' });          // valid JSON, malformed identifier → Identity ctor throws → 223
// BOM-prefixed canonical challenge: EF BB BF + the CH bytes. Decodes to valid JSON only if
// the decoder strips the BOM — which it must not (223; canonical-encoding guarantee for ports).
const CH_BOM = Triauth.Helpers.arrayBufferToBase64Url(Uint8Array.from([0xEF, 0xBB, 0xBF, ...Triauth.Helpers.base64UrlToUint8(CH)]));

// --- signature minting helpers --------------------------------------------------------

const mint = (deviceKeys, opts = {}) => {
  const { type = 'ping', identifier = ID, actor = '', via = VIA, challenge = CH, signedMetadata = {}, unsignedMetadata = {} } = opts;
  return Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(deviceKeys),
    type, identifier, actor, via, challenge, signedMetadata, unsignedMetadata,
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
// Raw (non-JSON) bytes in the SIGNED metadata slot (6): must re-create the signed payload by
// hand so the real signature covers the raw bytes.
const mintRawSigned = async (deviceKeys, rawB64uSegment, opts = {}) => {
  const { type = 'ping', identifier = ID, via = VIA, challenge = CH } = opts;
  const fields = [type, identifier, '', via, 'v1', String(Date.now()), rawB64uSegment, '', String(challenge)];
  const sigs = await SignerStub.signUsingDeviceKeys(deviceKeys)(fields.join(';'));
  fields[8] = sigs.join(';');
  return '|' + fields.join(';') + '|';
};

// --- minted responses -----------------------------------------------------------------

const RESP_DESKTOP  = await mint(john.devices[0].keys);                                  // john desktop, 1 key
const RESP_LAPTOP   = await mint(john.devices[1].keys);                                  // john laptop, 2 keys
const RESP_LAPTOP_LASTFRAG = await mint([john.devices[1].keys[1]]);                      // laptop key #2 only — pairs with a laptop[2/2]-only DNS patch (sparse final fragment)
const RESP_TRAILING = await mint(john.devices[0].keys, { challenge: CH_TRAILING });
// Private mode: the identity's lookup code rides signed-metadata; the DNS carries the commit record.
const RESP_PRIVATE   = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, challenge: CH_PRIVATE, signedMetadata: { lookupCode: PRIVATE.john.lookupCode } });

// Valid signatures that still get rejected (the point of each is a NON-crypto rejection):
const RESP_JANE          = await mint(jane.keys, { identifier: jane.identifier });        // jane signs john's challenge

// Delegated ping: jane's key signs ON BEHALF of john (actor slot set). Verifies only when
// john's identity records carry a matching include grant (patched per-test below).
const RESP_DELEGATED     = await mint(jane.keys, { actor: jane.identifier });
const RESP_VIA_ATTACKER  = await mint(john.devices[0].keys, { via: 'https://attacker.example/' });
const RESP_SIGNONLY_PING = await mint(signonly.keys, { identifier: signonly.identifier, challenge: CH_SIGNONLY }); // key use=sign, can't ping

// Ed25519 (type=ed25519): the envelope's crypto signature is Ed25519 over the same payload the
// ECDSA flow signs (the challenge string).
const RESP_ED25519_OK    = await mint(ed25519.keys, { identifier: ed25519.identifier, challenge: CH_ED25519 });
const RESP_ED_LAN        = await mint(ed25519.keys, { identifier: ed25519.identifier, via: LAN_VIA, challenge: CH_ED_LAN });
const RESP_ED25519_BOGUS = `|ping;${ed25519.identifier};;${VIA};v1;${T};;;AAAA|`;        // parses fine, fails Ed25519 crypto → 401

// Time-window negatives carry a real, fresh John signature so the ONLY thing wrong is the
// challenge's iat (proves 402 is about challenge age, not the signature).
const RESP_PAST   = await mint(john.devices[0].keys, { challenge: CH_PAST });
const RESP_FUTURE = await mint(john.devices[0].keys, { challenge: CH_FUTURE });
const RESP_60S    = await mint(john.devices[0].keys, { challenge: CH_60S });

// ext is meaningful only for authenticate(); ping ignores signedMetadata.ext entirely. Minted
// with a populated ext to prove it does NOT leak into the ping result.
const RESP_IGNORED_EXT = await mint(john.devices[0].keys, { signedMetadata: { ext: { pingToken: true, privateProfile: { initials: 'JD' } } } });

// Metadata parse-rejection (225) fixtures — same shared Signature/safeParseJson machinery as auth.
const RESP_GARBAGE_SIGNED   = await mint(john.devices[0].keys, { signedMetadata: ['totally', 'wrong', 'shape'] });
const RESP_PROTO_SIGNED     = await mint(john.devices[0].keys, { signedMetadata: JSON.parse('{"__proto__":{"polluted":true,"isAdmin":true}}') });
const RESP_RAWTEXT_SIGNED   = await mintRawSigned(john.devices[0].keys, 'c29tZS1yYW5kb20tcGxhaW4tdGV4dC1ub3QtanNvbg'); // "some-random-plain-text-not-json"
const RESP_BOM_SIGNED     = await mintRawSigned(john.devices[0].keys, "77u_eyJleHQiOnsiYm9tIjp0cnVlfX0"); // EF BB BF + {"ext":{"bom":true}} — BOM must not be stripped
const RESP_GARBAGE_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, ['evil', 'array', 'in', 'unsignedMetadata']);
const RESP_RAWBIN_UNSIGNED  = await mintRawUnsigned(john.devices[0].keys, 'AAECAwQFBgcICQoLDA0ODw'); // raw 0x00..0x0F
const RESP_DEEP_UNSIGNED    = await mintUnsignedSwap(john.devices[0].keys, {a:{b:{c:{d:{e:{f:{g:{h:{}}}}}}}}}); // depth 9 > 8
const RESP_LONGKEY_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, {['a'.repeat(257)]: 1});
const RESP_NONASCII_UNSIGNED= await mintRawUnsigned(john.devices[0].keys, 'eyJy6XN1bekiOjF9'); // {"r<0xE9>sum<0xE9>":1} — raw Latin-1 é: ill-formed UTF-8, refused at decode -> 225
const RESP_BADUTF8_VALUE_UNSIGNED = await mintRawUnsigned(john.devices[0].keys, 'eyJleHQiOnsiYSI6IukifX0'); // {"ext":{"a":"<0xE9>"}} — raw Latin-1 é inside a string VALUE: ill-formed UTF-8, refused at decode -> 225
const RESP_EKEY_UNSIGNED    = await mintRawUnsigned(john.devices[0].keys, 'eyJyw6lzdW3DqSI6MX0'); // {"résumé":1} as proper C3 A9 UTF-8 — decodes fine; the Bounded-JSON ASCII-key rule rejects -> 225
const RESP_SURROGATE_KEY_UNSIGNED = await mintRawUnsigned(john.devices[0].keys, 'eyJ4XHVkODAweSI6MX0'); // {"x\ud800y":1} — a lone-surrogate JSON ESCAPE in a key; every parser behavior converges on 225 (preserve -> non-ASCII key, substitute U+FFFD -> likewise, reject -> parse failure)
const RESP_PROTO_UNSIGNED   = await mintUnsignedSwap(john.devices[0].keys, { constructor: { prototype: { escalated: true, evilFn: 'marker' } } }); // constructor.prototype clause
const RESP_NULLVALUE_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, {ok: null}); // valid → success

// --- hand-written (no valid crypto needed) responses ----------------------------------
// A bogus ping envelope that is syntactically valid (passes validateResponse + Signature parse)
// but whose AAAA "signature" can never verify against John's real key → generic 401.
const RESP_BOGUS_PING = '|ping;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|';
// A well-formed SIGN-typed envelope; the ping flow's type constraint rejects it before crypto → 401.
const RESP_SIGN_TYPED = '|sign;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|';
// Two stacked ping segments — exceeds maxSignatures=1 → 401 (both segments parse fine).
const RESP_TWO_SEGMENTS = '|ping;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA|ping;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;BBBB|';
// Time-window negatives never reach crypto (Response.verify returns null on the iat check
// before constructing the MultiSignature), so a throwaway envelope with an invalid via='-' is
// fine here — it is never parsed.
const RESP_TIME_PLACEHOLDER = '|ping;john@triauthdemo.org;;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|';
// 11 crypto signatures inside ONE segment → trips IdentityKeys.verify's maxKeysPerSignature=10
// guard (a count check, before any crypto), distinct from the multi-SEGMENT maxSignatures path.
const RESP_ELEVEN_SIGS = '|ping;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA;BBBB;CCCC;DDDD;EEEE;FFFF;GGGG;HHHH;IIII;JJJJ;KKKK|';
// 6 signature segments → trips MultiSignature's maxMultiSignatures=5 count guard, which fires in
// the constructor BEFORE any segment is parsed → 225. The segment bodies are well-formed on
// purpose (to show the rejection is purely about the count).
const RESP_SIX_SEGMENTS = '|' + Array.from({ length: 6 }, () => 'ping;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;AAAA').join('|') + '|';
// Fresh challenge (iat in window) but the SIGNATURE's own ts is outside the widened window —
// exercises Signature.verify's ts check (returns null), distinct from Response.verify's
// challenge.iat check. Crypto is never reached (the ts check precedes it), so AAAA is fine.
const RESP_TS_PAST   = '|ping;john@triauthdemo.org;;https://example.com/;v1;1700000000000;;;AAAA|';
const RESP_TS_FUTURE = '|ping;john@triauthdemo.org;;https://example.com/;v1;1800000000000;;;AAAA|';

// --- DNS layout (mirrors auth.json's John/signonly/jane/private/ambiguous/unconfigured) ----
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
  'jane._at.triauthdemo.org': { TXT: [
    'initials JR',
    'name Jane Roe',
    `key desktop[1/1]:${jane.keys[0].public}`,
  ] },
  'ed25519._at.triauthdemo.org': { TXT: [
    'name Ed25519',
    `key desktop[1/1]:${ed25519.keys[0].public} type=ed25519`,
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
// 11 devices: dev01..dev10 (dummy keys) + john's real desktop key. The 11th (desktop) is dropped
// by the maxDevices=10 guard, leaving only unusable dummy groups → 401.
const elevenDevices = { 'john._at.triauthdemo.org': { TXT: [
  'initials JD', 'name John Doe',
  ...Array.from({ length: 10 }, (_, i) => `key dev${String(i + 1).padStart(2, '0')}[1/1]:AAAA`),
  `key desktop[1/1]:${john.devices[0].keys[0].public}`,
] } };
// John's regular record set plus one include grant record (the default `any` include policy
// admits her without endpoint-record changes).
const johnWithGrant = (grantRecord) => ({ 'john._at.triauthdemo.org': { TXT: [
  'initials JD', 'name John Doe',
  `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  `key laptop[1/2]:${john.devices[1].keys[0].public}`,
  `key laptop[2/2]:${john.devices[1].keys[1].public}`,
  grantRecord,
] } });

// Shorthands for building test objects (expected is filled by RECORD mode).
const s1 = (name, options, extra = {}) => ({ name, call: 'ping', args: [options], ...extra });
const s3 = (name, args, extra = {}) => ({ name, call: 'ping', args: [args], ...extra });

const tests = [
  // ===================================================================================
  // Dispatch & argument-shape guards (flow-level, before Stage 1/3 detection)
  // ===================================================================================
  s3('empty options object returns 101 (matches neither Stage 1 nor Stage 3)', {}),
  s3('null options arg returns 102 — hasOnlyKnownProperties null-guard fires first', null,
    { _argsOverride: [null] }),
  s3('array options arg returns 102 — hasOnlyKnownProperties Array.isArray-guard fires first', null,
    { _argsOverride: [[]] }),
  s1('Stage 1 unrecognized option returns 102', { identifier: ID, callbackUrl: CB, unknownKey: 'x' }),
  s1('Stage 1 PING-DISTINCT: attachments are a sign-only input — supplying them (even empty) to ping is a misplaced input, 102', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', attachments: [] }),
  s3('Stage 3 unrecognized option returns 102 (token IS allow-listed for ping, but unknownKey is not)',
    { challenge: CH, response: RESP_DESKTOP, unknownKey: 1 }),

  // ===================================================================================
  // Stage 1 — identifier validation (210-216)
  // ===================================================================================
  s1('Stage 1 non-string identifier returns 210', { identifier: 123, callbackUrl: CB }),
  s1("Stage 1 identifier with whitespace returns 210 (the /[\\s\\0]/ branch, distinct from non-string 210)",
    { identifier: 'john @triauthdemo.org', callbackUrl: CB }),
  s1('Stage 1 empty-string identifier returns 211', { identifier: '', callbackUrl: CB }),
  s1('Stage 1 too-long identifier returns 212 (byteSize check before username regex)',
    { identifier: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@triauthdemo.org', callbackUrl: CB }),
  s1('Stage 1 uppercase identifier returns 213', { identifier: 'John@triauthdemo.org', callbackUrl: CB }),
  s1('Stage 1 identifier missing @-sign returns 214', { identifier: 'johntriauthdemo.org', callbackUrl: CB }),
  s1('Stage 1 identifier with consecutive dots in username returns 215', { identifier: 'john..doe@triauthdemo.org', callbackUrl: CB }),
  s1('Stage 1 identifier with punycode domain returns 216', { identifier: 'john@xn--example.org', callbackUrl: CB }),
  s1('Stage 1 identifier with an IPv4-literal domain (john@1.2.3.4) returns 216 — a numeric final label is never a domain part', { identifier: 'john@1.2.3.4', callbackUrl: CB }),
  s1('Stage 1 identifier with a 64-character domain label returns 216 — labels are capped at 63 characters (the DNS bound)', { identifier: 'john@' + 'a'.repeat(64) + '.com', callbackUrl: CB }),
  s1('Stage 1 identifier with a single-character final label (john@a.b) returns 216', { identifier: 'john@a.b', callbackUrl: CB }),

  // ===================================================================================
  // Stage 1 — callbackUrl (221) & ext (222) validation
  // ===================================================================================
  s1('Stage 1 non-string callbackUrl returns 221', { identifier: ID, callbackUrl: 123 }),
  s1('Stage 1 over-length callbackUrl (>2048 bytes) returns 221',
    { identifier: ID, callbackUrl: 'https://example.com/' + 'a'.repeat(2048) }),
  s1('Stage 1 plain-http callbackUrl on a named host (http://example.com/cb) passes URL validation; the tokenless request then returns 226 — an ordering pin: the callbackUrl gate precedes the token gate', { identifier: ID, callbackUrl: 'http://example.com/cb' }),
  s1("Stage 1 callbackUrl with punycode domain returns 221", {"identifier":ID,"callbackUrl":"https://xn--mller-kva.de/cb"}),
  s1("Stage 1 callbackUrl with an IPv4-literal host (https://127.0.0.1/cb) passes URL validation — a canonical dotted quad is a grammar host; the tokenless request then returns 226", {"identifier":ID,"callbackUrl":"https://127.0.0.1/cb"}),
  s1("Stage 1 callbackUrl with an IPv6-literal host (https://[::1]/cb) returns 221 — bracketed IPv6 literals are outside the canonical-URL host grammar", {"identifier":ID,"callbackUrl":"https://[::1]/cb"}),
  s1("Stage 1 callbackUrl with an apostrophe in its path (https://example.com/a'b/cb) passes URL validation — \"'\" is RFC 3986 pchar; the tokenless request then returns 226", {"identifier":ID,"callbackUrl":"https://example.com/a'b/cb"}),
  s1('Stage 1 callbackUrl with a leading-zero IPv4 octet (https://1.2.3.04/cb) returns 221 — an IPv4 host has exactly one canonical spelling, the dotted quad without leading zeros', { identifier: ID, callbackUrl: 'https://1.2.3.04/cb' }),
  s1('Stage 1 callbackUrl with an out-of-range IPv4 octet (https://256.1.1.1/cb) returns 221', { identifier: ID, callbackUrl: 'https://256.1.1.1/cb' }),
  s1('Stage 1 callbackUrl with a dword IPv4 spelling (https://2130706433/cb) returns 221', { identifier: ID, callbackUrl: 'https://2130706433/cb' }),
  s1('Stage 1 callbackUrl with a five-octet host (https://1.2.3.4.5/cb) returns 221', { identifier: ID, callbackUrl: 'https://1.2.3.4.5/cb' }),
  s1('Stage 1 array-shaped ext returns 222', { identifier: ID, callbackUrl: CB, ext: ['not', 'a', 'plain', 'object'] }),

  // ===================================================================================
  // Stage 1 — token validation (226). PING-DISTINCT: `token` is allow-listed for ping
  // (authenticate() rejects it with 102), so these reach validateToken.
  // ===================================================================================
  s1('Stage 1 too-short token (<16 chars) returns 226', { identifier: ID, callbackUrl: CB, token: 'short' }),
  s1('Stage 1 non-string token returns 226', { identifier: ID, callbackUrl: CB, token: 123 }),
  s1('Stage 1 over-length token (>255 bytes, the Normal-String default byte cap) returns 226', { identifier: ID, callbackUrl: CB, token: 'a'.repeat(257) }),

  // ===================================================================================
  // Stage 1 — DNS / configuration (301). Stage 1 resolves the endpoint record only; identity
  // existence and the identity-domain derivation are settled on the signed response at stage 3.
  // ===================================================================================
  s1('Stage 1 domain with no triauth TXT record returns 301', { identifier: 'john@unconfigured.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 domain with multiple triauth TXT records returns 301 (ambiguous, refuse to choose)', { identifier: 'user@ambiguous.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 endpoint record without a mode option builds a challenge - the domain runs in private mode by default, and issue reads only the endpoint record', { identifier: 'user@nomode.example', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND, dnsEntries: { 'nomode.example': { TXT: ['triauth auth.nomode.example'] } } }),
  s1('Stage 1 unknown identifier under a configured domain still builds a challenge - existence is never probed at issue', { identifier: 'ghost@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 per-test dnsEntries patch can NXDOMAIN a known domain (returns 301)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND, dnsEntries: { 'triauthdemo.org': null } }),
  s1('Stage 1 endpoint with an unknown mode (mode=unknownmode) still builds a challenge - an unresolvable mode surfaces only once a response is verified', { identifier: 'john@hashed.triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND, dnsEntries: { 'hashed.triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=unknownmode'] } } }),

  // ===================================================================================
  // Stage 1 — success (challenge + redirectUrl). All deterministic via fixed nonce + clock.
  // ===================================================================================
  s1('Stage 1 deterministic challenge + ping.html redirectUrl for a fixed nonce and clock', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1("Stage 1 PING-DISTINCT token produces a redirectUrl with a &token= param carrying the token's public part and the hmac (authenticate() would 102 on token)", { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 token + ext together: challenge bakes the ext, redirectUrl carries the token and its hmac', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', ext: { pingToken: true } }, { random: RAND }),
  s1("Stage 1 omitting the token returns 226 - token-gated flows require a token at issue (src/challenge_response_flow.js)", {"identifier":ID,"callbackUrl":CB}, { random: RAND }),
  s1('Stage 1 localhost http callbackUrl is accepted and builds a challenge', { identifier: ID, callbackUrl: 'http://localhost:3000/cb', token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 plain-http callbackUrl on a LAN IPv4-literal host (http://10.0.0.5:8080/cb) builds a challenge — self-hosted deployments run on transport the envelope does not depend on', { identifier: ID, callbackUrl: LAN_CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 https callbackUrl on a private IPv4-literal host (https://192.168.0.14/cb) builds a challenge', { identifier: ID, callbackUrl: 'https://192.168.0.14/cb', token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 callbackUrl with an explicit port 80 on https (https://example.com:80/cb) builds a challenge — only the scheme default (:443 on https, :80 on http) is non-canonical', { identifier: ID, callbackUrl: 'https://example.com:80/cb', token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1("Stage 1 callbackUrl with \";\" in its query (https://example.com/cb?a=1;b=2) builds a challenge — query and fragment never enter the base URL/via, so the envelope delimiter rule does not reach them", { identifier: ID, callbackUrl: 'https://example.com/cb?a=1;b=2', token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1("Stage 1 callbackUrl with an apostrophe in its query (https://example.com/cb?user=O'Brien) builds a challenge — \"'\" is RFC 3986 pchar", { identifier: ID, callbackUrl: "https://example.com/cb?user=O'Brien", token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 per-test currentTime changes the iat baked into the challenge (nonce unchanged)', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND, currentTime: 1800000000000 }),
  s1('Stage 1 challenge bakes in the ext object', { identifier: ID, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa', ext: { pingToken: true, nested: { foo: 'bar' } } }, { random: RAND }),
  s1('Stage 1 multi-device identity still builds a challenge', { identifier: 'multi@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 identity with a profile but no key records still builds a challenge (key absence surfaces in Stage 3)', { identifier: 'nokeys@triauthdemo.org', callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),

  // ===================================================================================
  // PRIVATE MODE — Stage 1: a server holds no lookup code, so a private-mode identity's
  // records are unreadable at issue. Stage 1 needs none of them: it resolves the endpoint
  // record, builds the challenge, and leaves every identity-level question to Stage 3.
  // ===================================================================================
  s1('Stage 1 PRIVATE: a private-mode endpoint builds a challenge without resolving the identity', { identifier: PRIVATE.john.identifier, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 PRIVATE SECURITY: no identity records published at all still builds a challenge - secrecy means a server cannot pre-confirm existence, so stage 1 never leaks it', { identifier: PRIVATE.john.identifier, callbackUrl: CB, token: ':aaaaaaaaaaaaaaaa' }, { random: RAND, dnsEntries: { [PRIVATE.john.identityDomain]: null } }),
  s1("Stage 1 PRIVATE: an issuer-hinted token is carried through to the private-mode identity's own endpoint (the subject's grants are unreadable without the lookup code; the stage-3 delegated walk enforces them)", { identifier: PRIVATE.john.identifier, callbackUrl: CB, token: 'issuer.example:aaaaaaaaaaaaaaaa' }, { random: RAND }),

  // ===================================================================================
  // Stage 3 — challenge (223) & response (224) validation
  // ===================================================================================
  s3('Stage 3 non-string challenge returns 223', { challenge: 12345, response: RESP_DESKTOP }),
  s3('Stage 3 non-base64url challenge returns 223', { challenge: '!!!not-base64url!!!', response: RESP_DESKTOP }),
  s3('Stage 3 challenge is valid base64url but decodes to non-JSON bytes returns 223 (Challenge.fromString parse path)', { challenge: 'AAEC', response: RESP_DESKTOP }),
  s3('Stage 3 SECURITY: challenge whose decoded bytes are a UTF-8 BOM (EF BB BF) followed by the CANONICAL valid challenge JSON returns 223 — the decoder must not strip the BOM (a second, non-canonical byte encoding of the same challenge must never be accepted; ports must not BOM-sniff when decoding base64url payloads)', { challenge: CH_BOM, response: RESP_DESKTOP }),
  s3('Stage 3 challenge decodes to valid JSON but its identifier member is malformed returns 223 (the Identity constructor throws inside Challenge.fromString, distinct from the non-JSON parse path)', { challenge: CH_BADID, response: RESP_DESKTOP }),
  s3('Stage 3 non-string response returns 224', { challenge: CH, response: 12345 }),
  s3('Stage 3 response without the | envelope delimiters returns 224', { challenge: CH, response: 'no-envelope-delimiters' }),
  s3('Stage 3 short/empty response (length <= 3) returns 224 via the validator length-check', { challenge: CH, response: '' }),
  s3('Stage 3 re-provided malformed identifier returns 210 (the optional Stage-3 identifier validator, distinct from the Stage-1 path)', { challenge: CH, response: RESP_DESKTOP, identifier: 'john @triauthdemo.org' }),
  s3('Stage 3 re-provided malformed callbackUrl returns 221 (the optional Stage-3 callbackUrl validator, distinct from the Stage-1 path)', { challenge: CH, response: RESP_DESKTOP, callbackUrl: 'https://[::1]/cb' }),
  s3('Stage 3 re-provided callbackUrl that is URL-valid but mismatches challenge.cburl (http://example.com/cb vs https) returns 401 — the equality gate, distinct from the 221 format gate', { challenge: CH, response: RESP_DESKTOP, callbackUrl: 'http://example.com/cb' }),

  // ===================================================================================
  // Stage 3 — dispatch-level constraint checks (401) & denial (403)
  // ===================================================================================
  s3("Stage 3 response equal to the literal 'false' returns 403 (user-denial sentinel)", { challenge: CH, response: 'false' }),
  s3('Stage 3 re-provided identifier mismatching challenge.identifier returns 401', { challenge: CH, response: RESP_DESKTOP, identifier: 'someone-else@triauthdemo.org' }),
  s3('Stage 3 re-provided callbackUrl mismatching challenge.cburl returns 401', { challenge: CH, response: RESP_DESKTOP, callbackUrl: 'https://other-domain.example/' }),
  s3("Stage 3 challenge with type=auth (not 'ping') returns 401 at the flow type-constraint", { challenge: CH_AUTHTYPE, response: RESP_DESKTOP }),

  // ===================================================================================
  // Stage 3 — signature envelope parse failures (225)
  // ===================================================================================
  s3("Stage 3 signature envelope with malformed via ('-') is rejected at parse time with 225", { challenge: CH, response: '|ping;john@triauthdemo.org;;-;v1;1777454675000;;;AAAA|' }),
  s3("Stage 3 signature envelope with non-ASCII via is rejected at parse time with 225", { challenge: CH, response: '|ping;john@triauthdemo.org;;https://example.com/é;v1;1777454675000;;;AAAA|' }),
  s3("Stage 3 response '||||' parses into empty segments, each tripping the Signature length guard → 225", { challenge: CH, response: '||||' }),
  s3('Stage 3 more than 5 signature segments trips the MultiSignature maxMultiSignatures=5 count guard → 225 (in the constructor, before any segment is parsed)', { challenge: CH, response: RESP_SIX_SEGMENTS }),

  // ===================================================================================
  // Stage 3 — generic verification failures (401)
  // ===================================================================================
  s3('Stage 3 well-formed sign-typed envelope against the ping flow returns 401 (type constraint, before crypto)', { challenge: CH, response: RESP_SIGN_TYPED }),
  s3('Stage 3 well-formed ping envelope with bogus crypto bytes returns 401 (generic verification failure)', { challenge: CH, response: RESP_BOGUS_PING }),
  s3('Stage 3 two stacked signatures exceed maxSignatures=1 returns 401 (count guard before per-sig verify)', { challenge: CH, response: RESP_TWO_SEGMENTS }),
  s3('Stage 3 cryptographically valid signature for the WRONG identity (jane signs john challenge) returns 401', { challenge: CH, response: RESP_JANE }),
  s3('Stage 3 cryptographically valid signature with envelope.via on a DIFFERENT ORIGIN returns 401 (cburl does not match sig.via)', { challenge: CH, response: RESP_VIA_ATTACKER }),
  s3('Stage 3 ping-typed envelope from a sign-restricted (use=sign) key returns 401 (mode/use check; would ping if use included ping)', { challenge: CH_SIGNONLY, response: RESP_SIGNONLY_PING }),
  s3("Stage 3 envelope.identifier's identity records vanished between stages (NXDOMAIN) returns 401", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': null } }),
  s3("Stage 3 envelope.identifier's authentication endpoint is gone (NXDOMAIN) returns 401", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'triauthdemo.org': null } }),
  s3('Stage 3 DNS SERVFAIL on the authentication endpoint propagates from signature.verify and surfaces as a retryable 110 (not a false 401)', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s3('Stage 3 DNS SERVFAIL on the identity domain propagates from signature.verify and surfaces as a retryable 110 (not a false 401)', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { _error: 'SERVFAIL' } } }),
  s3('Stage 3 identity key with invalid syntax (missing [idx/count]) leaves no usable keyGroup → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', `key desktop:${john.devices[0].keys[0].public}`] } } }),
  s3('Stage 3 identity key that taints its device group (desktop[2/1]) leaves no valid keyGroup → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', `key desktop[2/1]:${john.devices[0].keys[0].public}`] } } }),
  s3('Stage 3 SECURITY: split key group published only as its final fragment (laptop[2/2] alone, no laptop[1/2]) never validates — a lone write to the group\'s last index already inflates keys.length to keyCount and Object.entries/.every iteration skips array holes, so a length-gated validity check would accept the one-signature response from the published fragment; the populated-slot count (src/identity_keys.js:153-157) keeps the group invalid → 401', { challenge: CH, response: RESP_LAPTOP_LASTFRAG }, { dnsEntries: johnSingleKey(`key laptop[2/2]:${john.devices[1].keys[1].public}`) }),
  s3('Stage 3 a single segment carrying 11 crypto signatures exceeds IdentityKeys maxKeysPerSignature=10 → 401 (count guard, distinct from the multi-segment maxSignatures path)', { challenge: CH, response: RESP_ELEVEN_SIGS }),
  s3('Stage 3 identity key value is valid base64url but too short to initialize an ECDSA verifier (AAAA) → 401 (null-verifier continue, no key verified)', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey('key desktop[1/1]:AAAA') }),
  s3('Stage 3 identity key with a deviceName longer than the record-name regex allows ({1,20}, the 20-byte limit) is dropped → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key abcdefghijklmnopqrstu[1/1]:${john.devices[0].keys[0].public}`) }),
  s3("Stage 3 identity records publishing more than maxDevices=10 devices drop the 11th (john's real key) → 401", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: elevenDevices }),
  s3('Stage 3 identity key with an unknown critical (non x-) option taints its device group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord(' badopt=value') }),
  s3('Stage 3 a doubled key index (two desktop[1/1] records) un-validates the already-valid group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', `key desktop[1/1]:${john.devices[0].keys[0].public}`, `key desktop[1/1]:${john.devices[1].keys[0].public}`] } } }),
  s3('Stage 3 leading-zero keyIdx (desktop[01/1]) maps to literal 0, failing the range check and tainting the group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key desktop[01/1]:${john.devices[0].keys[0].public}`) }),
  s3('Stage 3 leading-zero keyCount (desktop[1/01]) maps to literal 0, failing the range check and tainting the group → 401', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnSingleKey(`key desktop[1/01]:${john.devices[0].keys[0].public}`) }),

  // ===================================================================================
  // Stage 3 — expired / time-window (402). PING-DISTINCT: notBefore = now - pingTimeout (15s).
  // ===================================================================================
  s3('Stage 3 challenge iat far before notBefore returns 402', { challenge: CH_PAST, response: RESP_PAST }),
  s3('Stage 3 challenge iat in the future (after notAfter == now) returns 402', { challenge: CH_FUTURE, response: RESP_FUTURE }),
  s3('Stage 3 PING-DISTINCT: a 60s-old challenge (still valid for authenticate, authTimeout 3min) is already expired for ping (pingTimeout 15s) → 402', { challenge: CH_60S, response: RESP_60S }),
  s3('Stage 3 fresh challenge but the SIGNATURE ts is before the widened window → 402 (Signature.verify ts check, distinct from the Response.verify challenge.iat check)', { challenge: CH, response: RESP_TS_PAST }),
  s3('Stage 3 fresh challenge but the SIGNATURE ts is after the widened window → 402', { challenge: CH, response: RESP_TS_FUTURE }),

  // ===================================================================================
  // Stage 3 — metadata parse rejections (225), shared Signature/safeParseJson machinery
  // ===================================================================================
  s3('Stage 3 garbage signedMetadata (decodes to a JSON array) returns 225', { challenge: CH, response: RESP_GARBAGE_SIGNED }),
  s3('Stage 3 __proto__-poisoning signedMetadata is caught by safeParseJson → 225', { challenge: CH, response: RESP_PROTO_SIGNED }),
  s3('Stage 3 constructor.prototype-poisoning unsignedMetadata is caught by safeParseJson (second clause) → 225', { challenge: CH, response: RESP_PROTO_UNSIGNED }),
  s3('Stage 3 signedMetadata that is valid base64url but non-JSON text returns 225', { challenge: CH, response: RESP_RAWTEXT_SIGNED }),
  s3("Stage 3 SECURITY: signedMetadata segment decodes to a UTF-8 BOM (EF BB BF) followed by otherwise-valid ext JSON ({\"ext\":{\"bom\":true}}) — rejected at parse time with 225; the decoder must not strip the BOM, so a non-canonical byte encoding of valid metadata is never accepted (real signature covers the BOM segment)", { challenge: CH, response: RESP_BOM_SIGNED }),
  s3('Stage 3 garbage unsignedMetadata (decodes to a JSON array) returns 225 (real sig, slot MITM-swapped)', { challenge: CH, response: RESP_GARBAGE_UNSIGNED }),
  s3('Stage 3 unsignedMetadata of raw binary bytes (no valid JSON token) returns 225', { challenge: CH, response: RESP_RAWBIN_UNSIGNED }),
  s3('Stage 3 unsignedMetadata nested 9 deep exceeds jsonMaxNestingDepth=8 → 225', { challenge: CH, response: RESP_DEEP_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a 257-char key exceeds jsonMaxKeyLength=256 → 225', { challenge: CH, response: RESP_LONGKEY_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a non-ASCII key returns 225', { challenge: CH, response: RESP_NONASCII_UNSIGNED }),
  s3('Stage 3 SECURITY: unsignedMetadata whose bytes are not well-formed UTF-8 inside a string value returns 225 — payload-slot bytes must be well-formed UTF-8; decoders reject rather than substitute U+FFFD (string values have no charset rule of their own, so only the decode-time rejection pins this)', { challenge: CH, response: RESP_BADUTF8_VALUE_UNSIGNED }),
  s3('Stage 3 unsignedMetadata with a non-ASCII key in well-formed UTF-8 ({"résumé":1} as C3 A9 bytes) returns 225 — the Bounded-JSON ASCII-key rule, distinct from the ill-formed-byte rejection', { challenge: CH, response: RESP_EKEY_UNSIGNED }),
  s3('Stage 3 SECURITY: unsignedMetadata whose JSON carries a lone-surrogate escape (\\ud800) in a key returns 225 — parser-independent: a parser that preserves the escape yields a non-ASCII key, one that substitutes U+FFFD likewise, one that rejects it fails the parse; no conformance vector requires accepting a lone-surrogate escape anywhere', { challenge: CH, response: RESP_SURROGATE_KEY_UNSIGNED }),

  // ===================================================================================
  // Stage 3 — SUCCESS (pinged:true). PING-DISTINCT result shape: {pinged, issuedAt, signedAt,
  // verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, deviceName,
  // deviceTag, keys} — no publicProfile, no ext.
  // ===================================================================================
  s3('Stage 3 valid signature from a single-key device returns pinged:true with one verified key', { challenge: CH, response: RESP_DESKTOP }),
  s3('Stage 3 valid signature from a multi-key device (laptop, 2 keys) returns pinged:true with both keys verified', { challenge: CH, response: RESP_LAPTOP }),
  s3('Stage 3 PRIVATE: private-mode identity pings successfully (lookup code in signed-metadata; deviceTag carries the ~lookupCode suffix)', { challenge: CH_PRIVATE, response: RESP_PRIVATE }),
  s3('Stage 3 PRIVATE SECURITY: a mismatched commit record makes the identity unresolvable -> 401 (the commitment binding gate)', { challenge: CH_PRIVATE, response: RESP_PRIVATE }, { dnsEntries: { [PRIVATE.john.identityDomain]: { TXT: ['name John Doe', `key desktop[1/1]:${john.devices[0].keys[0].public}`, `commit ${PRIVATE.wrongCommitment}`] } } }),
  s3('Stage 3 callbackUrl already ending in / pings successfully (getBaseUrl THEN branch)', { challenge: CH_TRAILING, response: RESP_TRAILING }),
  s3('Stage 3 PING-DISTINCT: signedMetadata.ext is IGNORED by ping (no ext in the result, unlike authenticate)', { challenge: CH, response: RESP_IGNORED_EXT }),
  s3('Stage 3 unsignedMetadata with a null value parses fine and pings successfully', { challenge: CH, response: RESP_NULLVALUE_UNSIGNED }),
  s3('Stage 3 key record with dnssec:false pings successfully but with secure:false', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord('', { ttl: 1800, dnssec: false }) }),
  s3('Stage 3 key record with a custom TTL yields expires = now + ttl*1000', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord('', { ttl: 60, dnssec: true }) }),
  // NOTE: the "TTL-less record → expires:undefined" success path (identity.js ttl-number branch
  // + MultiSignature's no-expiries branch) is reachable via ping but intentionally NOT covered
  // here: a result with an undefined-valued `expires` property cannot survive the JSON round-trip
  // (JSON.stringify drops it, so the replayed assert.deepStrictEqual would fail). It is covered by
  // the JS unit tests in test/test_authentication.js instead.
  s3('Stage 3 unrecognized identity-record keyword is ignored; ping still succeeds', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'foo bar', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  s3('Stage 3 x- prefixed key option is allowed through (not in the deviceTag); ping succeeds with the option visible on the key', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: johnKeyRecord(' x-tag=custom') }),

  // ===================================================================================
  // Back-filled tests that were first added directly to ping.json (after the clock-drift
  // widening / uv fail-closed / dnssec-capping changes shipped) — kept here so a full
  // regeneration reproduces them.
  // ===================================================================================
  s3('Stage 3 SECURITY: endpoint triauth record with dnssec:false caps secure to false even though all key records are DNSSEC-validated', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'triauthdemo.org': { TXT: [{ value: 'triauth auth.triauthdemo.org mode=public', ttl: 1800, dnssec: false }] } } }),
  s3("Stage 3 SECURITY: challenge iat 3s in the FUTURE of the verifying server's clock still pings — with the 15s pingTimeout and an auto-responding authenticator, ping is the flow most sensitive to inter-server clock drift", { challenge: CH, response: RESP_DESKTOP }, { currentTime: T - 3e3 }),
  s3('SECURITY: uv=required on a non-webauthn (es256) key is unenforceable and taints the keyGroup → 401 - fail closed', { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: [
    'initials JD',
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public} uv=required`,
    `key laptop[1/2]:${john.devices[1].keys[0].public}`,
    `key laptop[2/2]:${john.devices[1].keys[1].public}`,
  ] } } }),

  // ===================================================================================
  // Stage 3 — Ed25519 (type=ed25519) verifier backend, reached via IdentityKeys.verify.
  // Cross-language guarantee: a port without the ed25519 verifier registered would taint
  // the keyGroup and fail the positive.
  // ===================================================================================
  s3('Stage 3 Ed25519: valid Ed25519 signature from a type=ed25519 key pings successfully', { challenge: CH_ED25519, response: RESP_ED25519_OK }),
  s3('Stage 3 Ed25519: full flow against a plain-http LAN callback (cburl http://10.0.0.5:8080/cb, via http://10.0.0.5:8080/) pings successfully — the envelope binds the via string itself, independent of the transport it names', { challenge: CH_ED_LAN, response: RESP_ED_LAN }),
  s3('Stage 3 Ed25519: bogus signature fails the Ed25519 crypto verification → 401', { challenge: CH_ED25519, response: RESP_ED25519_BOGUS }),
  s3('Stage 3 Ed25519: 65-byte P-256 key material published as type=ed25519 cannot import (raw Ed25519 keys are exactly 32 bytes) → fromPublishableKey null → 401', { challenge: CH_ED25519, response: RESP_ED25519_OK }, { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${john.devices[0].keys[0].public} type=ed25519`] } } }),
  s3('Stage 3 Ed25519 SECURITY: uv=required on a type=ed25519 (non-webauthn) key is unenforceable and taints the keyGroup → 401 — fail closed', { challenge: CH_ED25519, response: RESP_ED25519_OK }, { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${ed25519.keys[0].public} type=ed25519 uv=required`] } } }),
  // callbackUrl delimiter guards: ";" is banned exactly where it would enter the signed via
  // (the base-URL span); "|" is not a URL character at all.
  s1("Stage 1 SECURITY: callbackUrl with a \";\" in its base directory (https://example.com/a;b/cb) returns 221 — \";\" is the signature envelope field delimiter, and the base URL of the callback becomes the signed via; the base-span check rejects at validation so the authenticator's Signature.generate never has to refuse such a via downstream", {"identifier":ID,"callbackUrl":"https://example.com/a;b/cb"}),
  s1("Stage 1 SECURITY: callbackUrl with a \"|\" in its base directory (https://example.com/a|b/cb) returns 221 — \"|\" is the signature envelope wrapper and not an RFC 3986 URL character, so the grammar rejects it in every span", {"identifier":ID,"callbackUrl":"https://example.com/a|b/cb"}),
  s1("Stage 1 callbackUrl with a \";\" in its LAST path segment (https://example.com/cb;sid=1) builds a challenge — the final segment never enters the base URL/via, so the envelope delimiter rule stops at the base span", {"identifier":ID,"callbackUrl":"https://example.com/cb;sid=1","token":":aaaaaaaaaaaaaaaa"}, { random: RAND }),
  // requireSecure: per-call config; the non-DNSSEC twin patches the key record to dnssec:false.
  s3("requireSecure: ping stage 3 - DNSSEC-secure result still succeeds when requireSecure:true", { challenge: CH, response: RESP_DESKTOP }, { _argsOverride: [{ challenge: CH, response: RESP_DESKTOP }, { requireSecure: true }] }),
  s3("SECURITY requireSecure: ping stage 3 - non-DNSSEC (secure:false) result is rejected with 404", { challenge: CH, response: RESP_DESKTOP }, { _argsOverride: [{ challenge: CH, response: RESP_DESKTOP }, { requireSecure: true }], dnsEntries: {
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

  // --- token structure (issuer:secret) and the redirect's token param -------------------
  // The public part travels verbatim; the secret half only ever keys the HMAC. The redirect
  // always targets the identity's own endpoint - the issuer hint is a value the Authenticator
  // reads, never a routing instruction the Verifier acts on.
  s1('Stage 1 colon-less token returns 226 (a token is issuer:secret - the issuer may be empty, the colon is structural)', { identifier: ID, callbackUrl: CB, token: 'aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 token with more than one colon returns 226', { identifier: ID, callbackUrl: CB, token: 'issuer.example:aaaaaaaaaaaaaaaa:x' }),
  s1('Stage 1 token with an uppercase issuer returns 226 (the issuer must be a canonical lowercase domain)', { identifier: ID, callbackUrl: CB, token: 'Issuer.Example:aaaaaaaaaaaaaaaa' }),
  s1('Stage 1 token with a non-domain issuer returns 226', { identifier: ID, callbackUrl: CB, token: 'not_a_domain:aaaaaaaaaaaaaaaa' }),
  s1("Stage 1 issuer-hinted token puts the issuer in the redirect's token param and keys the hmac with the full token, while the redirect stays on the identity's own endpoint", { identifier: ID, callbackUrl: CB, token: 'issuer.example:aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1('Stage 1 SECURITY: an issuer hint no include grant covers is carried through unchanged - no grant is read at issue, and the secret half never appears in the redirect', { identifier: ID, callbackUrl: CB, token: 'unrelated.example:aaaaaaaaaaaaaaaa' }, { random: RAND }),
  s1("Stage 1 issuer-hinted token whose issuer publishes no triauth endpoint still builds a challenge - the Verifier never resolves the issuer", { identifier: ID, callbackUrl: CB, token: 'noendpoint.example:aaaaaaaaaaaaaaaa' }, { random: RAND, dnsEntries: { 'noendpoint.example': { TXT: [] } } }),

  // --- delegated ping (include grants) ---------------------------------------------------
  s3('Stage 3 delegated response (actor signs under an include grant) verifies with the composite deviceTag', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=any') }),
  s3('Stage 3 delegated response whose grant is limited to the ping flow (use=ping) verifies', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org use=ping scope=any') }),
  s3('Stage 3 delegated response with no include grant in the identity records returns 401', { challenge: CH, response: RESP_DELEGATED }),
  s3('Stage 3 delegated response whose grant does not cover the ping flow (use=sign) returns 401', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org use=sign scope=any') }),
  s3('Stage 3 delegated response whose grant publishes no scope option returns 401 - scope is required, and the record is ignored as a whole', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org') }),
  s3('Stage 3 delegated response whose grant is scoped to the service host (scope=example.com) verifies', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=example.com') }),
  s3('Stage 3 SECURITY: delegated response whose grant is scoped to a different host (scope=other.example) returns 401 - a grant works only at services whose callback host its scope lists', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=other.example') }),
  s3('Stage 3 delegated response whose grant scope lists the service host among others (scope=other.example,example.com) verifies', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=other.example,example.com') }),
  s3('Stage 3 SECURITY: delegated response whose grant carries a scope entry with a port (scope=example.com:8443) returns 401 - a port is never part of a host, so the record is ignored as a whole', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=example.com:8443') }),
  s3('Stage 3 SECURITY: delegated response whose grant lists any beside a host (scope=any,example.com) returns 401 - any is only the sole-entry spelling, so the record is ignored as a whole', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=any,example.com') }),
  s3('Stage 3 envelope with an actor slot that is not an Identifier returns 225', { challenge: CH, response: `|ping;${ID};jane_x@triauthdemo.org;${VIA};v1;${T};;;AAAA|` }),

  // --- stage 3 exact-match re-supply (empty string is a value, not a skip) ---------------
  s3('Stage 3 re-supplied empty-string identifier returns 211 (fail-closed - the empty string is not "not passed")', { challenge: CH, response: RESP_DESKTOP, identifier: '' }),
  s3('Stage 3 re-supplied empty-string callbackUrl returns 221', { challenge: CH, response: RESP_DESKTOP, callbackUrl: '' }),

  // GROUPS: the subject's membership list on ping results (groups appear wherever the identifier does).
  s3("GROUPS: ping surfaces the subject's groups, fully qualified and sorted", { challenge: CH, response: RESP_DESKTOP }, { dnsEntries: { 'john._at.triauthdemo.org': { TXT: [
    'initials JD',
    'name John Doe',
    'groups zeta,admins',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  ] } } }),

  // Delegated secure aggregation: the subject-side term of the two-resolution AND.
  s3('SECURITY: delegated ping with the include record served without DNSSEC -> pinged:true with secure:false - the subject-side resolution degrades the two-resolution AND', { challenge: CH, response: RESP_DELEGATED }, { dnsEntries: johnWithGrant({ value: 'include jane@triauthdemo.org scope=any', ttl: 1800, dnssec: false }) }),
];

// Normalize: a couple of dispatch tests need a non-object sole arg (null / []) that the s3()
// helper can't express through its options object — splice in the override and drop the marker.
for (const t of tests) {
  if (t._argsOverride) { t.args = t._argsOverride; delete t._argsOverride; }
}

const suite = {
  title: 'ping',
  description:
    'Comprehensive coverage of Triauth.ping. Stage 1 (request): dispatch/arg guards, identifier/callbackUrl/ext validation, the ping-only token+HMAC path (authenticate() rejects token with 102), DNS configuration (301), and deterministic challenge + ping.html redirect building. Stage 3 (verify): challenge/response validation, dispatch constraints, signature-envelope parse failures (225), generic verification failures (401), the tighter pingTimeout expiry window (402), and the success body. Pins ping\'s distinct result shape ({pinged, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, deviceName, deviceTag, keys} — no publicProfile, no ext) and that signedMetadata.ext is ignored. Crypto-bearing Stage 3 fixtures were minted by test/fixtures/json/_capture_ping.mjs (WebCrypto ECDSA is non-deterministic to mint, deterministic to verify). A final Ed25519 section covers the type=ed25519 verifier backend (positive plus crypto/key-material/uv-taint negatives).' +
    ' Stage 1 resolves the endpoint record only - identity existence is settled on the signed response, so no stage-1 case yields 302. A PRIVATE MODE section covers mode=private: stage-1 issue over an unreadable identity, stage-3 verification with the lookup code in signed-metadata and the ~lookupCode-suffixed deviceTag, and the commitment-mismatch rejection.',
  dnsEntries,
  currentTime: T,
  tests,
};

writeSuite(new URL('./ping.json', import.meta.url), suite);
