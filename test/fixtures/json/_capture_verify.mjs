// One-shot generator for the cross-language verify.json suite.
//
// Like ./_capture_sign.mjs, the cases that exercise the crypto-verified paths (success bodies AND
// "valid signature, rejected for some OTHER reason" negatives) need real ECDSA P-256 / WebAuthn
// signatures. WebCrypto ECDSA is non-deterministic to MINT but deterministic to VERIFY, so we mint
// here once and bake the resulting signature strings into verify.json.
//
// Triauth.verify(message, signature, constraints?, config?) is the SIMPLEST of the verifying APIs:
// it takes the raw signature envelope directly (no challenge, no Stage-1/Stage-3 dispatch, no
// Response wrapper, no attachment/cburl matching) and runs:
//
//   verify -> new MultiSignature(signature) -> [Signature].verify -> Identity.resolve
//                                                                  -> IdentityKeys.verify -> Verifiers
//
// so this suite drives that whole sub-tree plus verify's own argument guards, its catch routing
// (TriauthError code>=200 -> {verified:true,valid:false}; code 101 -> {error}), and the
// multi-signature SUCCESS path (length>1) that is UNIQUE to verify (sign/stamp pin maxSignatures:1).
// Note: verify applies a secure-by-default single-signature policy — maxSignatures defaults to 1, so a
// multi-segment envelope is rejected (valid:false) unless the caller explicitly raises maxSignatures
// (minSignatures alone does NOT relax it). So every multisig SUCCESS case below passes an explicit
// maxSignatures, and negative cases pin the default rejection.
//
// After running:
//   node --experimental-global-webcrypto test/fixtures/json/_capture_verify.mjs  # (re)write verify.json structure
//   JSON_SUITE=verify.json RECORD=1 npm run test:json                            # fill in every `expected`
//   JSON_SUITE=verify.json npm run test:json                                     # confirm green
//   git diff test/fixtures/json/verify.json                                      # eyeball before committing
//
// Re-run this script whenever the signature envelope format, the John/jane/signonly/webauthn DNS
// layout, or the suite-level currentTime changes (any of these change the signed bytes and
// invalidate the baked signatures).
//
// Coverage goal: this suite ALONE covers 100% of the code paths reachable through Triauth.verify
// (measure with `JSON_SUITE=verify.json npx c8 --include 'src/**' --reporter text \
//   mocha --node-option=experimental-global-webcrypto --require ./test/setup.js test/test_json.js`).
// Everything left uncovered in the verify-path files is, by construction, NOT reachable through a
// Triauth.verify call:
//   - other public methods sharing a file: Triauth.sign / Triauth.stamp (the whole _perform/
//     onChallenge/onResponse machinery and the sign/stamp exports in src/api/signing.js);
//   - the Stage-1/Stage-3 flow modules verify never touches: Challenge, Response,
//     ChallengeResponseFlow, AuthenticationEndpoint.urlFor (urlFor runs only when BUILDING a
//     redirect, never on a verify), Helpers.getBaseUrl / Helpers.randomString;
//   - build-side helpers used to CREATE signatures, never on verify's read path: Signature.generate
//     / Signature.encodeMetadata / Helpers.stringToBase64Url / MultiSignature.generate (all used by
//     THIS script at mint time, never by verify);
//   - other-API helpers: IdentityKeys.findByTag (Triauth.check), and the Validator functions verify
//     never calls at all: validateExt / validateAttestations / validateChallenge / validateResponse
//     / validateMessage / validateAttachments / validateToken. (verify reaches exactly three
//     validators: validateIdentifier + validateCallbackUrl via the Signature ctor on the envelope's
//     identifier/via slots, and validateDeviceName via IdentityKeys.add on the DNS key records);
//   - the validator arms the upstream input shape makes unreachable from verify: validateIdentifier's
//     non-string (slot 1 is always a string) and empty-identifier (short-circuited by the ctor's
//     `this.identifier && ...` guard) arms; the empty-via arm (same short-circuit on slot 3); and
//     validateDeviceName's non-string / empty / whitespace / uppercase
//     / final-charset arms (the key-record regex /[a-z0-9-]{1,16}/ pre-constrains the device name, so
//     only its too-long(>20) arm and the all-valid arm are reachable);
//   - defensive guards no verify input can trigger: verify's `typeof config !== 'object'` arm
//     (config is reassigned to an object on entry); the constraint-whitelist `return false` guards
//     inside MultiSignature.verify / Signature.verify (verify pre-filters constraints to a subset of
//     their whitelists; verify defaults maxSignatures to 1, but MultiSignature.verify deletes
//     minSignatures/maxSignatures before delegating to Signature.verify); Signature.verify's
//     `cryptoSignatures.length>0` guard (the ctor already guarantees >=1); IdentityKeys.verify's
//     non-base64url-signature guard (the Signature ctor already enforces base64url); the
//     Identity ctor's identifier-validation throw (the Signature ctor already rejected any invalid
//     identifier with 225 before Identity is constructed); the hasOnlyKnownProperties
//     `obj[key] !== undefined` arm (JSON args cannot carry `undefined`); IdentityDomain.resolve's
//     immutable-options re-call guard; the createLRUCache set-re-set / eviction / resize arms (the
//     CachingResolver store is never resized or filled to capacity by a verify); Resolvers.Base#resolve (the stub
//     overrides it) and resolveConfig's `!isNormalString(entry.key)` skip (the TXT key is matched by
//     a \w regex); safeParseJson's 256KB limit (a signature is capped at 10KB first);
//     AuthenticationEndpoint.resolve's `candidate.hostname !== value` arm (isDomainName gates it out);
//   - TriauthError.process branches OTHER than the code-101 `else`/warn arm: verify's catch absorbs
//     every code>=200 itself (so process never sees a validation 2xx), and verify never throws a
//     non-TriauthError, so process's 2xx-info and internal-100 arms are not reachable here;
//   - logger?.() optional-chaining NULL arms (test/setup.js installs a stub logger, so the present
//     arm is always taken).
// The single verify-REACHABLE branch this JSON harness cannot exercise is the `expires:undefined`
// success arm (Signature.verify / MultiSignature.verify expiry aggregation over a TTL-less DNS
// record): a result carrying an `undefined`-valued `expires` cannot survive the
// JSON.stringify -> assert.deepStrictEqual round-trip. It is covered by the JS unit tests instead
// (same documented limitation as sign.json / ping.json); the `expires!==undefined` FALSE *branch*
// itself is still exercised below via a TTL-less record paired with bogus crypto (a failure body).

import * as Triauth from '../../../src/index.js';
globalThis.Triauth = Triauth;
import identities from '../identities.json' with { type: 'json' };
// Shared generator plumbing: frozen clock, logger, the local signonly/jane/ed25519 fixture
// identities (one definition keeps every suite's keypairs in lock-step), and the guarded suite
// writer. Flow-specific roles in THIS suite:
//   - signonly (published with use=sign in this suite's dnsEntries): a sign-typed signature
//     verifies (use-match).
//   - jane: an ordinary second identity (its own keypair + DNS) used as the second signer in a
//     multi-signature, and as a standalone success.
import { T, LOGGER, signonly, jane, ed25519, PRIVATE, writeSuite } from './_capture_common.mjs';
// Minting only needs the private-key signer; no DNS is consulted here (the runner resolves DNS
// from the suite's dnsEntries at verify time).
const SignerStub = (await import('../../stubs/signer.js')).default;

Triauth.config.logger = LOGGER;

// Freeze the clock at the shared suite T. Every signature ts is minted at T; DNS TTLs make
// `expires` land at T + ttl*1000. verify applies NO freshness window of its own (the caller
// supplies notBefore/notAfter), so a T-minted signature verifies at time T with no constraints.
Date.now = () => T;

const john = identities.john;

//   - authonly: publishes JOHN's desktop public key but with use=auth. Verifying a sign-typed
//     envelope against it makes mode='sign' fall outside use='auth' -> the key is skipped -> no
//     verified keys -> failure. (Reuses john's desktop keypair under a different identifier.)
const AUTHONLY_ID = 'authonly@triauthdemo.org';
//   - twin: publishes JOHN's desktop public key VERBATIM under a different identifier, with the
//     default use (so mode='sign' is allowed). It isolates the identifier-binding property:
//     relabelling one of john's signatures as `twin` still fails even though twin's published key
//     bytes are identical to john's, proving the identifier is bound by the signed payload, not just
//     "a different key wouldn't match".
const TWIN_ID = 'twin@triauthdemo.org';

const ID  = 'john@triauthdemo.org';
const VIA = 'https://example.com/';

// The message that is signed and later passed to verify. (verify has no validateMessage step; the
// message merely has to be byte-identical to what was signed. Printable ASCII for readability.)
const MSG = 'Please verify this signed statement';
const WRONG_MSG = 'A completely different message';   // for the message<->signature binding test

// --- signature minting helpers (identical in spirit to _capture_sign.mjs) ----------------------

const mint = (deviceKeys, opts = {}) => {
  const { type = 'sign', identifier = ID, actor = '', via = VIA, message = MSG, signedMetadata = {}, unsignedMetadata = {} } = opts;
  return Triauth.Signature.generate(
    SignerStub.signUsingDeviceKeys(deviceKeys),
    type, identifier, actor, via, message, signedMetadata, unsignedMetadata,
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
// Raw (non-JSON) bytes in the SIGNED metadata slot (6): re-create the signed payload by hand so the
// real signature covers the raw bytes (msg lives in slot 8). The Signature ctor rejects it at
// decode time (before any crypto), so this only needs to parse-as-base64url then fail JSON parse.
const mintRawSigned = async (deviceKeys, rawB64uSegment, opts = {}) => {
  const { type = 'sign', identifier = ID, via = VIA, message = MSG } = opts;
  const fields = [type, identifier, '', via, 'v1', String(Date.now()), rawB64uSegment, '', String(message)];
  const sigs = await SignerStub.signUsingDeviceKeys(deviceKeys)(fields.join(';'));
  fields[8] = sigs.join(';');
  return '|' + fields.join(';') + '|';
};

// Replace a single envelope slot of an already-minted signature WITHOUT re-signing, so the real
// crypto signature still covers the ORIGINAL field bytes. Used by the field-binding security guards:
// tampering a SIGNED slot (0=type,1=identifier,2=actor,3=via,5=ts,6=signedMetadata) leaves a structurally
// valid envelope whose crypto no longer matches -> verification must fail. (Slots 4=ver and 7=
// unsignedMetadata are special: ver is structurally pinned to 'v1', and slot 7 is excluded from the
// signed payload, so it is the one slot a tamper does NOT break — already pinned by the slot-7-swap
// successes above.) The new value must itself be well-formed so the Signature ctor reaches crypto
// rather than rejecting the envelope at parse time (225).
const tamperSlot = (env, idx, value) => {
  const seg = env.slice(1, -1).split(';');
  seg[idx] = value;
  return '|' + seg.join(';') + '|';
};

// --- WebAuthn (type=webauthn-es256) ------------------------------------------------------------
// The WebAuthn verifier is reached when the matched device key has type=webauthn-es256. The
// envelope's crypto signature is over (authenticatorData || sha256(clientDataJSON)); the assertion
// (clientDataJSON + authenticatorData) is carried in unsignedMetadata.sig[idx]. The verifier checks
// clientData.challenge === sha256(reconstructed envelope payload), type === 'webauthn.get',
// crossOrigin absent-or-exactly-false, and origin === <the resolved authentication endpoint origin>. We reuse john's desktop
// P-256 keypair as the underlying WebAuthn key (published under webauthn._at).
const WA_ID = 'webauthn@triauthdemo.org';
const WA_ORIGIN = 'https://auth.triauthdemo.org'; // the RESOLVED authentication-endpoint origin (triauthdemo.org's `triauth` record → auth.triauthdemo.org); the origin the real Authenticator page runs at, NOT the identifier domain
const WA_AUTHDATA = 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAw';                       // realistic authenticatorData
const WA_PAYLOAD = ['sign', WA_ID, '', VIA, 'v1', String(T), '', '', MSG].join(';');           // exact reconstructed signed payload
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
  return '|' + ['sign', WA_ID, '', VIA, 'v1', String(T), '', encUnsigned, cryptoSig].join(';') + '|';
};

// --- minted signatures (real ECDSA) ------------------------------------------------------------

const SIG_DESKTOP   = await mint(john.devices[0].keys);                                   // john desktop, 1 key, sign-type
const SIG_LASTFRAG  = await mint([john.devices[1].keys[1]]);                              // laptop key #2 only, sign-type — pairs with a laptop[2/2]-only DNS patch (sparse final fragment)
const SIG_STAMP     = await mint(john.devices[0].keys, { type: 'stamp' });                // stamp-type (mode gating across types)
const SIG_LAPTOP    = await mint(john.devices[1].keys);                                   // john laptop, 2 keys (both verify)
const SIG_LAPTOP_PARTIAL = await mint([john.devices[1].keys[0]]);                         // only laptop key 1 signs -> per-key break
const SIG_HASHED    = await mint(john.devices[0].keys, { identifier: 'john@hashed.triauthdemo.org' });
const SIG_SIGNONLY  = await mint(signonly.keys, { identifier: signonly.identifier });     // key use=sign CAN sign
const SIG_JANE      = await mint(jane.keys, { identifier: jane.identifier });             // second valid identity
// Delegated signature: jane's key signs ON BEHALF of john (actor slot set). Verifies only when
// john's identity records carry a matching include grant (patched per-test).
const SIG_DELEGATED = await mint(jane.keys, { actor: jane.identifier });
const SIG_AUTHONLY  = await mint(john.devices[0].keys, { identifier: AUTHONLY_ID });      // valid crypto, key use=auth blocks sign mode
const SIG_TWIN      = await mint(john.devices[0].keys, { identifier: TWIN_ID });          // genuinely signed AS twin (positive control for the identifier-tamper guard)
const SIG_UNCONF    = await mint(john.devices[0].keys, { identifier: 'john@unconfigured.example' });
const SIG_AMBIG     = await mint(john.devices[0].keys, { identifier: 'user@ambiguous.example' });
const SIG_GHOST     = await mint(john.devices[0].keys, { identifier: 'ghost@triauthdemo.org' });  // no identity records -> resolve false
const SIG_NOKEYS    = await mint(john.devices[0].keys, { identifier: 'nokeys@triauthdemo.org' }); // resolves (profile) but no usable keys
const SIG_SIGNEDMETA = await mint(john.devices[0].keys, { signedMetadata: { ref: 'po-12345', n: 7 } }); // arbitrary signed metadata echoed back
const SIG_LOCALHOST  = await mint(john.devices[0].keys, { via: 'http://localhost:3000/cb' });  // localhost-http via
const SIG_LAN        = await mint(john.devices[0].keys, { via: 'http://10.0.0.5:8080/cb' });   // plain-http LAN via: IPv4-literal host + port

// Private-mode signatures: the lookup code rides signed-metadata (`lookupCode` = the
// subject's, `actorLookupCode` = the actor's), so every variant is its own genuinely-signed
// envelope. john@secret signs with the real john's desktop keys; bot@secret (the delegated actor)
// with jane's keypair as its `worker` device.
const SIG_PRIVATE            = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode } });
const SIG_PRIVATE_NOCODE     = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier });
const SIG_PRIVATE_CODE15     = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode.slice(0, 15) } });
const SIG_PRIVATE_CODE17     = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode + 'A' } });
const SIG_PRIVATE_CODELOWER  = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode.toLowerCase() } });
const SIG_PRIVATE_CODECHARS  = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: 'K7QJ3FB9M2WZX0C!' } });
const SIG_PRIVATE_CODENUM    = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: 42 } });
const SIG_PRIVATE_WRONGCODE  = await mint(john.devices[0].keys, { identifier: PRIVATE.john.identifier, signedMetadata: { lookupCode: PRIVATE.wrongLookupCode } });
const SIG_PUBLIC_WITHCODE    = await mint(john.devices[0].keys, { signedMetadata: { lookupCode: PRIVATE.john.lookupCode } });           // lookupCode under john's public-mode domain
const SIG_ACTORCODE_NOACTOR = await mint(john.devices[0].keys, { signedMetadata: { actorLookupCode: PRIVATE.bot.lookupCode } });       // actorLookupCode on a self-signed envelope
// Delegated inside the private-mode org: bot signs for john; both zones run private mode, so both codes travel.
const SIG_PRIVATE_DELEG              = await mint(jane.keys, { identifier: PRIVATE.john.identifier, actor: PRIVATE.bot.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode, actorLookupCode: PRIVATE.bot.lookupCode } });
const SIG_PRIVATE_DELEG_NOACTORCODE  = await mint(jane.keys, { identifier: PRIVATE.john.identifier, actor: PRIVATE.bot.identifier, signedMetadata: { lookupCode: PRIVATE.john.lookupCode } });
const SIG_PUBLICACTOR_ACTORCODE   = await mint(jane.keys, { actor: jane.identifier, signedMetadata: { actorLookupCode: PRIVATE.bot.lookupCode } }); // actorLookupCode under a public-mode actor

// unsignedMetadata that PARSES fine (null value) -> success, exercising safeParseJson null-node arm.
const SIG_NULLVALUE_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, { ok: null });

// signedMetadata parse rejections (real sig; ctor throws at decode before any crypto) -> 225.
const SIG_GARBAGE_SIGNED = await mint(john.devices[0].keys, { signedMetadata: ['totally', 'wrong', 'shape'] });   // array root
const SIG_PROTO_SIGNED   = await mint(john.devices[0].keys, { signedMetadata: JSON.parse('{"__proto__":{"polluted":true}}') });
const SIG_RAWTEXT_SIGNED = await mintRawSigned(john.devices[0].keys, 'c29tZS1yYW5kb20tcGxhaW4tdGV4dC1ub3QtanNvbg'); // "some-random-plain-text-not-json"
const SIG_BOM_SIGNED     = await mintRawSigned(john.devices[0].keys, "77u_eyJleHQiOnsiYm9tIjp0cnVlfX0"); // EF BB BF + {"ext":{"bom":true}} — BOM must not be stripped

// unsignedMetadata parse rejections (real sig, slot-6 MITM swap) -> 225.
const SIG_GARBAGE_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, ['evil', 'array']);
const SIG_PROTO_UNSIGNED   = await mintUnsignedSwap(john.devices[0].keys, { constructor: { prototype: { escalated: true } } });
const SIG_RAWBIN_UNSIGNED  = await mintRawUnsigned(john.devices[0].keys, 'AAECAwQFBgcICQoLDA0ODw'); // raw 0x00..0x0F (not JSON)
const SIG_DEEP_UNSIGNED    = await mintUnsignedSwap(john.devices[0].keys, {a:{b:{c:{d:{e:{f:{g:{h:{}}}}}}}}}); // depth 9 > 8
const SIG_LONGKEY_UNSIGNED = await mintUnsignedSwap(john.devices[0].keys, {['a'.repeat(257)]: 1});
const SIG_NONASCII_UNSIGNED= await mintRawUnsigned(john.devices[0].keys, 'eyJy6XN1bekiOjF9'); // {"r<0xE9>sum<0xE9>":1} — raw Latin-1 é: ill-formed UTF-8, refused at decode -> malformed
const SIG_BADUTF8_VALUE_UNSIGNED = await mintRawUnsigned(john.devices[0].keys, 'eyJleHQiOnsiYSI6IukifX0'); // {"ext":{"a":"<0xE9>"}} — raw Latin-1 é inside a string VALUE: ill-formed UTF-8, refused at decode -> malformed
const SIG_EKEY_UNSIGNED    = await mintRawUnsigned(john.devices[0].keys, 'eyJyw6lzdW3DqSI6MX0'); // {"résumé":1} as proper C3 A9 UTF-8 — decodes fine; the Bounded-JSON ASCII-key rule rejects -> malformed
const SIG_SURROGATE_KEY_UNSIGNED = await mintRawUnsigned(john.devices[0].keys, 'eyJ4XHVkODAweSI6MX0'); // {"x\ud800y":1} — a lone-surrogate JSON ESCAPE in a key; every parser behavior converges on malformed (preserve -> non-ASCII key, substitute U+FFFD -> likewise, reject -> parse failure)

// WebAuthn assertions.
const SIG_WA_OK        = await mkWebAuthn();                                                                 // valid assertion -> success
const SIG_WA_BADSIG    = await mkWebAuthn({ sign: false });                                                  // structure/clientData valid, crypto false
const SIG_WA_NOSIG     = await mkWebAuthn({ sign: false, unsigned: {} });                                    // no sig object
const SIG_WA_NOIDX     = await mkWebAuthn({ sign: false, unsigned: { sig: {} } });                           // no sig[idx]
const SIG_WA_CDJ_NOSTR = await mkWebAuthn({ sign: false, unsigned: { sig: { '0': { clientDataJSON: 123, authenticatorData: WA_AUTHDATA } } } }); // clientDataJSON not a string
const SIG_WA_AD_NOB64  = await mkWebAuthn({ sign: false, unsigned: { sig: { '0': { clientDataJSON: '{}', authenticatorData: '!!!' } } } });      // authenticatorData not base64url
const SIG_WA_BADCHAL   = await mkWebAuthn({ challenge: 'A'.repeat(43) });                                    // wrong challenge
const SIG_WA_DUPCHAL   = await mkWebAuthn({ clientDataJSON: `{"type":"webauthn.get","challenge":"${WA_CHAL}","challenge":"${WA_CHAL}","origin":"${WA_ORIGIN}","crossOrigin":false}` }); // "challenge": twice
const SIG_WA_BADTYPE   = await mkWebAuthn({ type: 'webauthn.create' });                                      // wrong type
const SIG_WA_CROSSORIG = await mkWebAuthn({ crossOrigin: true });                                            // crossOrigin true
// crossOrigin member ABSENT — optional in WebAuthn, omitted by top-level same-origin clients (notably
// WebKit); really signed, so it must verify end-to-end. (mkWebAuthn's destructuring default would turn
// `crossOrigin: undefined` into false, so the omission is spelled out as raw clientDataJSON.)
const SIG_WA_NOCROSS   = await mkWebAuthn({ clientDataJSON: JSON.stringify({ type: 'webauthn.get', challenge: WA_CHAL, origin: WA_ORIGIN }) });
// crossOrigin present with the STRING "false" — any present value other than exactly false fails the key
// (fail-closed on junk). Really signed: were the gate to pass it, the crypto would verify and the vector
// would flip to valid:true, so the rejection provably comes from the clientData gate.
const SIG_WA_CROSSJUNK = await mkWebAuthn({ crossOrigin: 'false' });
const SIG_WA_BADORIGIN = await mkWebAuthn({ origin: 'https://evil.example' });                               // wrong origin — THE anti-phishing pin, genuinely signed
const SIG_WA_BADJSON   = await mkWebAuthn({ sign: false, clientDataJSON: 'notjson' });                       // clientDataJSON not valid JSON -> safeParseJson throws -> caught

// Variants of WA_AUTHDATA with a different flags byte (byte 32) and/or truncated length, for the
// UP/UV flag-enforcement tests. The assertion is still genuinely signed over the modified bytes,
// so a rejection can only come from the flag/length checks - not from the crypto verification.
const waAuthData = (flagsByte, length = 37) => {
  const bytes = Triauth.Helpers.base64UrlToUint8(WA_AUTHDATA).slice(0, length);
  if (length > 32) bytes[32] = flagsByte;
  return Triauth.Helpers.arrayBufferToBase64Url(bytes);
};
const SIG_WA_NOUP  = await mkWebAuthn({ authenticatorData: waAuthData(0x00) });     // signed, UP flag cleared -> valid:false
const SIG_WA_SHORT = await mkWebAuthn({ authenticatorData: waAuthData(0x01, 36) }); // signed, 36-byte authenticatorData -> valid:false
const SIG_WA_UPUV  = await mkWebAuthn({ authenticatorData: waAuthData(0x05) });     // signed, UP|UV set -> satisfies uv=required
// A patch that republishes the webauthn identity's key record with extra options appended (e.g., ' uv=required').
const waKeyRecord = (suffix = '') => ({ 'webauthn._at.triauthdemo.org': { TXT: ['name WebAuthn', `key wa[1/1]:${john.devices[0].keys[0].public} type=webauthn-es256${suffix}`] } });

// Ed25519 (type=ed25519) and WebAuthn-Ed25519 (type=webauthn-ed25519) signatures. Plain Ed25519
// mirrors the ECDSA flow exactly (the envelope's crypto signature is Ed25519 over the same payload);
// WebAuthn-Ed25519 mirrors webauthn-es256 with the assertion signed by Ed25519.
const SIG_ED25519_OK    = await mint(ed25519.keys, { identifier: ed25519.identifier });
const SIG_ED25519_BOGUS = `|sign;${ed25519.identifier};;${VIA};v1;${T};;;AAAA|`;         // parses fine, fails Ed25519 crypto

const WAED_ID = 'webauthn-ed25519@triauthdemo.org';
const WAED_PAYLOAD = ['sign', WAED_ID, '', VIA, 'v1', String(T), '', '', MSG].join(';'); // exact reconstructed signed payload
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
  return '|' + ['sign', WAED_ID, '', VIA, 'v1', String(T), '', encUnsigned, cryptoSig].join(';') + '|';
};

const SIG_WAED_OK     = await mkWebAuthnEd25519();                // valid Ed25519-backed assertion -> success
const SIG_WAED_BADSIG = await mkWebAuthnEd25519({ sign: false }); // structure/clientData valid, crypto false

// --- multi-signature envelopes (verify-UNIQUE length>1 path) -----------------------------------
const SIG_MULTI         = Triauth.MultiSignature.generate(SIG_DESKTOP, SIG_JANE);   // john + jane over MSG -> multisig success
const SIG_DESKTOP_2     = await mint(john.devices[0].keys);                          // fresh second john signature (distinct bytes - signing is randomized)
const SIG_MULTI_SAME2   = Triauth.MultiSignature.generate(SIG_DESKTOP, SIG_DESKTOP_2); // same signer twice, fresh signatures (used under a dnssec:false patch -> secure:false aggregation)
const SIG_MULTI_DUPED   = Triauth.MultiSignature.generate(SIG_DESKTOP, SIG_DESKTOP);   // byte-identical duplicate segments -> rejected by the MultiSignature ctor (225)
const SIG_MULTI_FIVE    = Triauth.MultiSignature.generate(SIG_DESKTOP, SIG_DESKTOP_2, await mint(john.devices[0].keys), await mint(john.devices[0].keys), await mint(john.devices[0].keys)); // exactly maxMultiSignatures=5 distinct segments
const SIG_MULTI_MIXED   = Triauth.MultiSignature.generate(SIG_DESKTOP, SIG_ED25519_OK); // heterogeneous algorithms: john (es256) + ed25519 signer in one envelope

// --- emergent-security fixtures ----------------------------------------------------------------
// A signed message whose CONTENT is itself a fully-formed fake envelope (different type/identifier/
// via/ts). It must verify and bind to the REAL envelope's fields (sign / john / example.com), proving
// the externally-supplied message is opaque and cannot be smuggled into the parsed envelope slots.
const DELIM_MSG = 'stamp;jane@evil.example;;https://evil.example/;v1;999999999999;;;payload';
const SIG_DELIM_MSG = await mint(john.devices[0].keys, { message: DELIM_MSG });

// Field-binding tampers: each replaces ONE signed slot of john's valid desktop signature with a
// well-formed-but-different value, so the envelope still parses but the crypto no longer matches.
const META_INJECT = Triauth.Helpers.stringToBase64Url(JSON.stringify({ injected: true })); // valid b64url JSON object
const SIG_TAMPER_TYPE   = tamperSlot(SIG_STAMP, 0, 'sign');                     // stamp signature relabelled as an interactive sign
const SIG_TAMPER_ID     = tamperSlot(SIG_DESKTOP, 1, TWIN_ID);                  // john's signature relabelled as twin (identical key bytes)
const SIG_TAMPER_VIA    = tamperSlot(SIG_DESKTOP, 3, 'https://other.example/'); // via swapped to another valid origin
const SIG_TAMPER_TS     = tamperSlot(SIG_DESKTOP, 5, '1777454680000');          // timestamp moved 5s forward
const SIG_TAMPER_SMETA  = tamperSlot(SIG_DESKTOP, 6, META_INJECT);             // forged signedMetadata grafted onto a real signature

// --- hand-written (no valid crypto needed) envelopes -------------------------------------------
const sigBody = `john@triauthdemo.org;;https://example.com/;v1;${T}`;
const SIG_BOGUS      = `|sign;${sigBody};;;AAAA|`;            // well-formed, crypto can never match john's key -> generic failure
const SIG_ONECHAR    = `|sign;${sigBody};;;A|`;              // 1-char crypto sig -> atob throws inside Ecdsa.verify -> caught -> failure
const SIG_ELEVEN     = `|sign;${sigBody};;;AAAA;BBBB;CCCC;DDDD;EEEE;FFFF;GGGG;HHHH;IIII;JJJJ;KKKK|`; // 11 sigs > maxKeysPerSignature=10
const SIG_SIX_SEGS   = '|' + Array.from({ length: 6 }, () => `sign;${sigBody};;;AAAA`).join('|') + '|'; // 6 segments > maxMultiSignatures=5
const SIG_EMPTY_SEGS = '||||';                              // empty segments -> Signature length guard -> 225
const SIG_MULTI_BAD2 = Triauth.MultiSignature.generate(SIG_DESKTOP, SIG_BOGUS);  // seg1 valid (pushed), seg2 fails -> loop returns false

// Length / envelope guards (MultiSignature ctor -> 225)
const SIG_TOO_SHORT  = '|';                                 // length <= 3
const SIG_UNWRAPPED  = 'abcd';                              // does not start/end with '|'
const SIG_OVERSIZED  = '|' + 'a'.repeat(11000) + '|';       // byteSize > signatureBytesize (10KB)

// Signature-envelope field-format rejections (Signature ctor -> 225). Each isolates one slot.
const SIG_BADVIA       = `|sign;john@triauthdemo.org;;-;v1;${T};;;AAAA|`;                       // via not a URL
const SIG_NONASCII_VIA = `|sign;john@triauthdemo.org;;https://example.com/é;v1;${T};;;AAAA|`; // via not isNormalString
const SIG_BADTYPE      = `|bogus;john@triauthdemo.org;;https://example.com/;v1;${T};;;AAAA|`;   // type not in VALID_TYPES
const SIG_BADID        = `|sign;not-valid;;https://example.com/;v1;${T};;;AAAA|`;               // envelope identifier invalid
const SIG_BADVER       = `|sign;john@triauthdemo.org;;https://example.com/;v2;${T};;;AAAA|`;    // ver != v1
const SIG_BADTS        = `|sign;john@triauthdemo.org;;https://example.com/;v1;0;;;AAAA|`;        // ts fails /^[1-9].../
const SIG_NOSIG        = `|sign;john@triauthdemo.org;;https://example.com/;v1;${T};;;|`;        // no crypto signature segment
const SIG_BADSIGB64    = `|sign;john@triauthdemo.org;;https://example.com/;v1;${T};;;AA!A|`;    // crypto sig not base64url
const SIG_BADSIGMETA   = `|sign;john@triauthdemo.org;;https://example.com/;v1;${T};!!!;;AAAA|`; // signedMetadata slot not base64url
const SIG_BADUNSIGNED  = `|sign;john@triauthdemo.org;;https://example.com/;v1;${T};;!!!;AAAA|`; // unsignedMetadata slot not base64url

// Envelope identifier rejections — the Signature ctor runs Validator.validateIdentifier on slot 1,
// so each malformed (but non-empty) identifier exercises one validateIdentifier branch -> 225.
// (210 non-string and 211 empty are NOT reachable here: the slot is always a string, and an empty
//  identifier is short-circuited by the `this.identifier && ...` guard before validateIdentifier.)
const SIG_ID_LONG  = `|sign;${'a'.repeat(240)}@triauthdemo.org;;https://example.com/;v1;${T};;;AAAA|`; // byteSize>identifierBytesize -> 212
const SIG_ID_UPPER = `|sign;John@triauthdemo.org;;https://example.com/;v1;${T};;;AAAA|`;               // uppercase -> 213
const SIG_ID_WS    = `|sign;john doe@triauthdemo.org;;https://example.com/;v1;${T};;;AAAA|`;           // whitespace -> 210 (the /[\s\0]/ arm)
const SIG_ID_USER  = `|sign;jo..hn@triauthdemo.org;;https://example.com/;v1;${T};;;AAAA|`;             // consecutive dots -> 215
const SIG_ID_DOMAIN= `|sign;john@xn--example.org;;https://example.com/;v1;${T};;;AAAA|`;               // punycode domain -> 216

// Envelope `via` handling — the Signature ctor runs Helpers.isCanonicalUrl on slot 3.
// (A non-string / empty via is short-circuited before validateCallbackUrl, so those arms are not
//  reachable from verify; http and IPv4-literal vias parse under the grammar — SIG_LOCALHOST and
//  SIG_LAN above cover the success arms, SIG_VIA_HTTP the parses-then-fails-crypto arm. A via
//  carrying ';' can never arrive: the extra delimiter splits the envelope fields, so such input
//  fails at the field-count layer, not here.)
const SIG_VIA_HTTP = `|sign;john@triauthdemo.org;;http://example.com/;v1;${T};;;AAAA|`;                  // parses fine, bogus crypto -> invalid
const SIG_VIA_IP6  = `|sign;john@triauthdemo.org;;https://[::1]/;v1;${T};;;AAAA|`;                       // bracketed IPv6 literal -> 221
const SIG_VIA_CREDS= `|sign;john@triauthdemo.org;;https://u:p@example.com/;v1;${T};;;AAAA|`;             // userinfo present -> 221
const SIG_VIA_HREF = `|sign;john@triauthdemo.org;;https://example.com;v1;${T};;;AAAA|`;                  // no path (one spelling per resource) -> 221
const SIG_VIA_LONG = `|sign;john@triauthdemo.org;;https://example.com/${'a'.repeat(2048)};v1;${T};;;AAAA|`; // byteSize>urlBytesize(2048) -> 221

// --- DNS layout --------------------------------------------------------------------------------
const dnsEntries = {
  'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
  'john._at.triauthdemo.org': { TXT: [
    'initials JD',
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `key laptop[1/2]:${john.devices[1].keys[0].public}`,
    `key laptop[2/2]:${john.devices[1].keys[1].public}`,
  ] },
  'signonly._at.triauthdemo.org': { TXT: [
    'name Sign Only',
    `key desktop[1/1]:${signonly.keys[0].public} use=sign`,
  ] },
  'authonly._at.triauthdemo.org': { TXT: [
    'name Auth Only',
    `key desktop[1/1]:${john.devices[0].keys[0].public} use=auth`,
  ] },
  'twin._at.triauthdemo.org': { TXT: [
    'name Twin',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,   // john's key bytes, default use -> isolates identifier-binding
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
  'nokeys._at.triauthdemo.org': { TXT: ['name No Keys', 'initials NK'] },
  [PRIVATE.domain]: { TXT: [PRIVATE.endpointRecord] },
  [PRIVATE.john.identityDomain]: { TXT: [
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `commit ${PRIVATE.john.commitment}`,
    `include ${PRIVATE.bot.identifier} scope=any`,    // grant for bot (the default `any` include policy admits it)
  ] },
  [PRIVATE.bot.identityDomain]: { TXT: [
    'name Bot',
    `key worker[1/1]:${jane.keys[0].public}`,
    `commit ${PRIVATE.bot.commitment}`,
  ] },
  'ambiguous.example': { TXT: ['triauth a.endpoint.example mode=public', 'triauth b.endpoint.example mode=public'] },
  'unconfigured.example': { TXT: [] },
};

// Per-test DNS patch helpers (shallow-merged over the suite-level entries by the runner).
const johnKeyRecord = (suffix = '', meta) => {
  const rec = `key desktop[1/1]:${john.devices[0].keys[0].public}${suffix}`;
  return { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', meta ? { value: rec, ...meta } : rec] } };
};
// Publish a john._at record set with a single replacement key record (plus profile).
const johnSingleKey = (keyRecord) => ({ 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', keyRecord] } });
// 11 devices: dev01..dev10 (dummy keys) + john's real desktop key. The 11th (desktop) is dropped by
// the maxDevices=10 guard, leaving only unusable dummy groups -> failure.
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

// john@secret's record set with the trailing records replaced (the commit-record negative variants patch
// the commit record while keeping the key published).
const privateJohnRecords = (...extraRecords) => ({ [PRIVATE.john.identityDomain]: { TXT: [
  'name John Doe',
  `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  ...extraRecords,
] } });

// Shorthand for building a verify test object (expected is filled by RECORD mode).
//   args is the positional [message, signature, constraints?] passed straight to Triauth.verify.
const v = (name, args, extra = {}) => ({ name, call: 'verify', args, ...extra });

const tests = [
  // ===================================================================================
  // Argument-shape guards (101) -> TriauthError(101) -> process -> {error:{code:101}}.
  // (These are the ONLY verify failures that surface as an {error} object; every other
  //  failure below — parse 225 and verification false/null — returns {verified:true,valid:false}.)
  // ===================================================================================
  v('non-string message (number) returns 101', [123, SIG_DESKTOP]),
  v('non-string signature (number) returns 101', [MSG, 123]),
  v('non-object constraints (string) returns 101', [MSG, SIG_DESKTOP, 'not-an-object']),
  v('null constraints returns 101 (hasOnlyKnownProperties null-guard)', [MSG, SIG_DESKTOP, null]),
  v('array constraints returns 101 (hasOnlyKnownProperties Array.isArray-guard)', [MSG, SIG_DESKTOP, []]),
  v('constraints with an unrecognized key returns 101', [MSG, SIG_DESKTOP, { bogus: 1 }]),

  // ===================================================================================
  // MultiSignature / Signature parse failures (TriauthError 225, caught by verify's
  // `code>=200` arm) -> {verified:true, valid:false}. Each isolates one envelope guard.
  // ===================================================================================
  v('signature too short (length <= 3) returns valid:false', [MSG, SIG_TOO_SHORT]),
  v('signature not wrapped in pipes returns valid:false', [MSG, SIG_UNWRAPPED]),
  v('signature exceeding signatureBytesize (>10KB) returns valid:false', [MSG, SIG_OVERSIZED]),
  v('more than 5 segments trips MultiSignature maxMultiSignatures=5 -> valid:false', [MSG, SIG_SIX_SEGS]),
  v("'||||' parses into empty segments, each tripping the Signature length guard -> valid:false", [MSG, SIG_EMPTY_SEGS]),
  v('envelope with a malformed via (\'-\') -> valid:false', [MSG, SIG_BADVIA]),
  v('envelope with a non-ASCII via -> valid:false', [MSG, SIG_NONASCII_VIA]),
  v('envelope with an unknown type (not in VALID_TYPES) -> valid:false', [MSG, SIG_BADTYPE]),
  v('envelope with an invalid identifier -> valid:false', [MSG, SIG_BADID]),
  v('envelope with ver != v1 -> valid:false', [MSG, SIG_BADVER]),
  v('envelope with a malformed ts (0) -> valid:false', [MSG, SIG_BADTS]),
  v('envelope with no crypto signature segment -> valid:false', [MSG, SIG_NOSIG]),
  v('envelope crypto signature that is not base64url -> valid:false', [MSG, SIG_BADSIGB64]),
  v('envelope signedMetadata slot that is not base64url -> valid:false', [MSG, SIG_BADSIGMETA]),
  v('envelope unsignedMetadata slot that is not base64url -> valid:false', [MSG, SIG_BADUNSIGNED]),
  v('signedMetadata decoding to a JSON array -> valid:false (safeParseJson non-object root)', [MSG, SIG_GARBAGE_SIGNED]),
  v('__proto__-poisoning signedMetadata -> valid:false (safeParseJson first clause)', [MSG, SIG_PROTO_SIGNED]),
  v('signedMetadata valid base64url but non-JSON text -> valid:false', [MSG, SIG_RAWTEXT_SIGNED]),
  v("SECURITY: signedMetadata segment decodes to a UTF-8 BOM (EF BB BF) followed by otherwise-valid ext JSON ({\"ext\":{\"bom\":true}}) -> valid:false — the decoder must not strip the BOM, so a non-canonical byte encoding of valid metadata is never accepted (real signature covers the BOM segment)", [MSG, SIG_BOM_SIGNED]),
  v('garbage unsignedMetadata (JSON array) -> valid:false (real sig, slot MITM-swapped)', [MSG, SIG_GARBAGE_UNSIGNED]),
  v('constructor.prototype-poisoning unsignedMetadata -> valid:false (safeParseJson second clause)', [MSG, SIG_PROTO_UNSIGNED]),
  v('unsignedMetadata of raw binary bytes (no valid JSON) -> valid:false', [MSG, SIG_RAWBIN_UNSIGNED]),
  v('unsignedMetadata nested 9 deep exceeds jsonMaxNestingDepth=8 -> valid:false', [MSG, SIG_DEEP_UNSIGNED]),
  v('unsignedMetadata with a 257-char key exceeds jsonMaxKeyLength=256 -> valid:false', [MSG, SIG_LONGKEY_UNSIGNED]),
  v('unsignedMetadata with a non-ASCII key -> valid:false', [MSG, SIG_NONASCII_UNSIGNED]),
  v('SECURITY: unsignedMetadata whose bytes are not well-formed UTF-8 inside a string value -> valid:false — payload-slot bytes must be well-formed UTF-8; decoders reject rather than substitute U+FFFD', [MSG, SIG_BADUTF8_VALUE_UNSIGNED]),
  v('unsignedMetadata with a non-ASCII key in well-formed UTF-8 ({"résumé":1} as C3 A9 bytes) -> valid:false — the Bounded-JSON ASCII-key rule, distinct from the ill-formed-byte rejection', [MSG, SIG_EKEY_UNSIGNED]),
  v('SECURITY: unsignedMetadata whose JSON carries a lone-surrogate escape (\\ud800) in a key -> valid:false — parser-independent (preserve yields a non-ASCII key, substitute U+FFFD likewise, reject fails the parse); no conformance vector requires accepting a lone-surrogate escape anywhere', [MSG, SIG_SURROGATE_KEY_UNSIGNED]),

  // ===================================================================================
  // Envelope identifier / via field validation (Signature ctor -> validateIdentifier /
  // validateCallbackUrl -> 225). Each isolates one validator branch reachable from verify.
  // ===================================================================================
  v('envelope identifier exceeding identifierBytesize (>249) -> valid:false (validateIdentifier 212)', [MSG, SIG_ID_LONG]),
  v('envelope identifier with uppercase -> valid:false (validateIdentifier 213)', [MSG, SIG_ID_UPPER]),
  v('envelope identifier containing whitespace -> valid:false (validateIdentifier 210 /[\\s\\0]/ arm)', [MSG, SIG_ID_WS]),
  v('envelope identifier with consecutive dots in the username -> valid:false (validateIdentifier 215)', [MSG, SIG_ID_USER]),
  v('envelope identifier with a punycode domain -> valid:false (validateIdentifier 216)', [MSG, SIG_ID_DOMAIN]),
  v('envelope via using http on a named host parses under the URL grammar; the bogus signature bytes then fail crypto -> valid:false with reason:invalid (the via format arm no longer rejects http)', [MSG, SIG_VIA_HTTP]),
  v('envelope via with a bracketed IPv6 literal (https://[::1]/) -> valid:false with reason:malformed (IPv6 literals stay outside the URL grammar)', [MSG, SIG_VIA_IP6]),
  v('envelope via carrying userinfo (user:pass@) -> valid:false (validateCallbackUrl credentials arm)', [MSG, SIG_VIA_CREDS]),
  v('envelope via whose URL normalization changes href -> valid:false (validateCallbackUrl href arm)', [MSG, SIG_VIA_HREF]),
  v('envelope via exceeding urlBytesize (>2048) -> valid:false (validateCallbackUrl byteSize arm)', [MSG, SIG_VIA_LONG]),

  // ===================================================================================
  // Constraint-driven failures (Signature.verify) -> {verified:true, valid:false}.
  // type/identifier/ver/via mismatch return false; out-of-window notBefore/notAfter return
  // null; both collapse to valid:false at the verify level.
  // ===================================================================================
  v('constraints.type mismatch (sign signature, {type:stamp}) -> valid:false', [MSG, SIG_DESKTOP, { type: 'stamp' }]),
  v('constraints.identifier mismatch -> valid:false', [MSG, SIG_DESKTOP, { identifier: 'someone-else@triauthdemo.org' }]),
  v('constraints.ver mismatch ({ver:2}) -> valid:false', [MSG, SIG_DESKTOP, { ver: 2 }]),
  v('constraints.via mismatch -> valid:false', [MSG, SIG_DESKTOP, { via: 'https://other.example/' }]),
  v("constraints.actor:'' on a self-signed signature -> valid:true (empty string means self-signed)", [MSG, SIG_DESKTOP, { actor: '' }]),
  v('constraints.actor set (require a delegate) on a self-signed signature -> valid:false', [MSG, SIG_DESKTOP, { actor: 'jane@triauthdemo.org' }]),
  v("constraints.actor:'' (require self-signed) on a delegated signature -> valid:false even with the grant present", [MSG, SIG_DELEGATED, { actor: '' }], { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=any') }),
  v('constraints.actor matching the delegate -> valid:true', [MSG, SIG_DELEGATED, { actor: 'jane@triauthdemo.org' }], { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=any') }),

  // Delegated signatures (include grants)
  v('delegated signature under an include grant -> valid:true with actor and the composite deviceTag', [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=any') }),
  v('delegated signature with no include grant in the identity records -> valid:false', [MSG, SIG_DELEGATED]),
  v('delegated signature whose grant does not cover the sign flow (use=ping) -> valid:false', [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant('include jane@triauthdemo.org use=ping scope=any') }),
  v('delegated signature whose grant covers the sign flow (use=sign,stamp) -> valid:true', [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant('include jane@triauthdemo.org use=sign,stamp scope=any') }),
  v('delegated signature whose grant publishes no scope option -> valid:false - scope is required, and the record is ignored as a whole', [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant('include jane@triauthdemo.org') }),
  v('delegated signature whose grant is scoped to the service host (scope=example.com) -> valid:true', [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=example.com') }),
  v("SECURITY: delegated signature whose grant lists only another host (scope=other.example) -> valid:false - the scope gate reads the envelope's via host", [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=other.example') }),
  v('constraints.notBefore non-numeric (string) -> valid:false (fail-closed)', [MSG, SIG_DESKTOP, { notBefore: 'soon' }]),
  v('constraints.notAfter non-numeric (string) -> valid:false (fail-closed)', [MSG, SIG_DESKTOP, { notAfter: 'later' }]),
  v('constraints.notBefore after the signature ts -> valid:false (Signature.verify null)', [MSG, SIG_DESKTOP, { notBefore: T + 1 }]),
  v('constraints.notAfter before the signature ts -> valid:false (Signature.verify null)', [MSG, SIG_DESKTOP, { notAfter: T - 1 }]),

  // ===================================================================================
  // Generic verification failures -> {verified:true, valid:false}.
  // ===================================================================================
  v('well-formed envelope with bogus crypto bytes -> valid:false', [MSG, SIG_BOGUS]),
  v('a 1-char crypto signature makes atob throw inside the ECDSA verifier -> caught -> valid:false', [MSG, SIG_ONECHAR]),
  v('a single segment carrying 11 crypto signatures exceeds maxKeysPerSignature=10 -> valid:false', [MSG, SIG_ELEVEN]),
  v('verifying against a DIFFERENT message than was signed -> valid:false (message<->signature binding)', [WRONG_MSG, SIG_DESKTOP]),
  v('use mismatch: a sign-typed envelope from a use=auth key -> valid:false (key skipped, no verified keys)', [MSG, SIG_AUTHONLY]),
  v('partial multi-key signature (only laptop key 1 of 2 signs) -> valid:false (per-key break)', [MSG, SIG_LAPTOP_PARTIAL]),

  // ===================================================================================
  // Identity resolution failures during verification.
  // (resolve()==false (NXDOMAIN/unconfigured) -> valid:false; resolve() THROWING (DNS SERVFAIL)
  //  propagates out of signature.verify -> retryable {error:110}.)
  // ===================================================================================
  v("identifier's identity records vanished (NXDOMAIN) -> valid:false", [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': null } }),
  v("identifier's authentication endpoint is gone (NXDOMAIN) -> valid:false", [MSG, SIG_DESKTOP], { dnsEntries: { 'triauthdemo.org': null } }),
  v('DNS SERVFAIL on the authentication endpoint propagates -> retryable {error:110}, not a false valid:false', [MSG, SIG_DESKTOP], { dnsEntries: { 'triauthdemo.org': { _error: 'SERVFAIL' } } }),
  v('DNS SERVFAIL on the identity domain propagates -> retryable {error:110}, not a false valid:false', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { _error: 'SERVFAIL' } } }),
  v('domain not configured for triauth (no triauth TXT) -> valid:false', [MSG, SIG_UNCONF]),
  v('ambiguous endpoint (multiple triauth records) -> valid:false', [MSG, SIG_AMBIG]),
  v('unknown identifier under a configured domain (no identity records) -> valid:false (resolve length>0 false)', [MSG, SIG_GHOST]),
  v('identity resolves (profile only) but has no usable keys -> valid:false (IdentityKeys.verify no groups)', [MSG, SIG_NOKEYS]),
  v('endpoint record with an unknown mode -> IdentityDomain.derive returns null -> valid:false', [MSG, SIG_HASHED], { dnsEntries: { 'hashed.triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=unknownmode'] } } }),
  v('endpoint record with an invalid (non-domain) value -> isDomainName false -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: { 'triauthdemo.org': { TXT: ['triauth invalid_domain mode=public'] } } }),

  // ===================================================================================
  // IdentityKeys.add taint/skip branches reached via the verify path -> valid:false.
  // ===================================================================================
  v('identity key with invalid syntax (missing [idx/count]) leaves no usable keyGroup -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey(`key desktop:${john.devices[0].keys[0].public}`) }),
  v('identity key that taints its device group (desktop[2/1]) -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey(`key desktop[2/1]:${john.devices[0].keys[0].public}`) }),
  v('SECURITY: split key group published only as its final fragment (laptop[2/2] alone, no laptop[1/2]) never validates — a lone write to the group\'s last index already inflates keys.length to keyCount and Object.entries/.every iteration skips array holes, so a length-gated validity check would accept the one-signature response from the published fragment; the populated-slot count (src/identity_keys.js:153-157) keeps the group invalid -> valid:false', [MSG, SIG_LASTFRAG], { dnsEntries: johnSingleKey(`key laptop[2/2]:${john.devices[1].keys[1].public}`) }),
  v('leading-zero keyIdx (desktop[01/1]) maps to literal 0, tainting the group -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey(`key desktop[01/1]:${john.devices[0].keys[0].public}`) }),
  v('leading-zero keyCount (desktop[1/01]) maps to literal 0, tainting the group -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey(`key desktop[1/01]:${john.devices[0].keys[0].public}`) }),
  v('a doubled key index (two desktop[1/1]) un-validates the already-valid group -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', `key desktop[1/1]:${john.devices[0].keys[0].public}`, `key desktop[1/1]:${john.devices[1].keys[0].public}`] } } }),
  v('identity key value that is not base64url taints the group -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey('key desktop[1/1]:has!bang') }),
  v('identity key value valid base64url but too short to initialize an ECDSA verifier (AAAA) -> valid:false (null-verifier continue)', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey('key desktop[1/1]:AAAA') }),
  v('identity key deviceName longer than the record-name regex allows ({1,20}, the 20-byte limit) is dropped -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey(`key abcdefghijklmnopqrstu[1/1]:${john.devices[0].keys[0].public}`) }),
  v("publishing more than maxDevices=10 devices drops the 11th (john's real key) -> valid:false", [MSG, SIG_DESKTOP], { dnsEntries: elevenDevices }),
  v('identity key with an unknown critical (non x-) option taints its device group -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnKeyRecord(' badopt=value') }),
  v('key record with a negative TTL yields an already-expired keyGroup that is skipped -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnKeyRecord('', { ttl: -2000, dnssec: true }) }),
  v('TTL-less key record (expires undefined) with bogus crypto -> valid:false (exercises the expires!==undefined FALSE branch)', [MSG, SIG_BOGUS], { dnsEntries: johnKeyRecord('', { dnssec: true }) }),

  // ===================================================================================
  // WebAuthn verifier backend (key type=webauthn-es256), reached via IdentityKeys.verify.
  // One success + every structure / clientData guard + the import-failure null path.
  // ===================================================================================
  v('WebAuthn structurally valid assertion but a bad ECDSA signature -> valid:false', [MSG, SIG_WA_BADSIG]),
  v('WebAuthn unsignedMetadata has no sig object -> valid:false', [MSG, SIG_WA_NOSIG]),
  v('WebAuthn sig has no entry for the key index -> valid:false', [MSG, SIG_WA_NOIDX]),
  v('WebAuthn clientDataJSON is not a string -> valid:false', [MSG, SIG_WA_CDJ_NOSTR]),
  v('WebAuthn authenticatorData is not base64url -> valid:false', [MSG, SIG_WA_AD_NOB64]),
  v('WebAuthn clientData.challenge != sha256(payload) -> valid:false', [MSG, SIG_WA_BADCHAL]),
  v('WebAuthn clientDataJSON contains "challenge": more than once -> valid:false (anti-injection guard)', [MSG, SIG_WA_DUPCHAL]),
  v("WebAuthn clientData.type != 'webauthn.get' -> valid:false", [MSG, SIG_WA_BADTYPE]),
  v('WebAuthn clientData.crossOrigin is not false -> valid:false', [MSG, SIG_WA_CROSSORIG]),
  v('WebAuthn clientData with the crossOrigin member absent verifies (optional member; top-level same-origin clients, notably WebKit, omit it)', [MSG, SIG_WA_NOCROSS]),
  v('WebAuthn clientData.crossOrigin present with the string "false" -> valid:false (a present member must equal exactly false; junk values fail closed)', [MSG, SIG_WA_CROSSJUNK]),
  v('WebAuthn clientData.origin != the authentication endpoint origin -> valid:false', [MSG, SIG_WA_BADORIGIN]),
  v('WebAuthn clientDataJSON is not valid JSON -> safeParseJson throws -> caught -> valid:false', [MSG, SIG_WA_BADJSON]),
  v('WebAuthn published key too short to import -> fromPublishableKey null -> valid:false', [MSG, SIG_WA_OK], { dnsEntries: { 'webauthn._at.triauthdemo.org': { TXT: ['name WebAuthn', 'key wa[1/1]:AAAA type=webauthn-es256'] } } }),

  // ===================================================================================
  // resolveConfig record-sanitization + ignored keywords (surviving real key still verifies).
  // ===================================================================================
  v('identity records with escape-looking junk in values or options are literal, fit no grammar, and contribute nothing; verification still succeeds on the surviving key', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'meta x-o=%0A', 'note %0A', 'raw %ZZ', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  v('unrecognized identity-record keyword is ignored; verification still succeeds', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: ['initials JD', 'name John Doe', 'foo bar', `key desktop[1/1]:${john.devices[0].keys[0].public}`] } } }),
  v('x- prefixed key option is allowed through (not in the deviceTag); verification succeeds with the option visible on the key', [MSG, SIG_DESKTOP], { dnsEntries: johnKeyRecord(' x-tag=custom') }),
  v('endpoint record with a __proto__ option is parsed safely (option dropped) and still resolves -> success', [MSG, SIG_DESKTOP], { dnsEntries: { 'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org __proto__=evil mode=public'] } } }),

  // ===================================================================================
  // SUCCESS — single signature. verify returns the Signature.verify result:
  //   {valid:true, type, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode,
  //    via, ver, signedAt, verifiedAt, publicProfile, groups, deviceName, deviceTag, keys, secure, expires,
  //    signedMetadata, unsignedMetadata}
  // ===================================================================================
  v('basic single-key (desktop) signature verifies -> verified:true, valid:true', [MSG, SIG_DESKTOP]),
  v('stamp-typed signature verifies (mode gating across types)', [MSG, SIG_STAMP]),
  v('multi-key device (laptop, 2 keys) verifies with both keys verified', [MSG, SIG_LAPTOP]),
  v('localhost http via verifies (result.via keeps the localhost URL)', [MSG, SIG_LOCALHOST]),
  v('plain-http LAN via (http://10.0.0.5:8080/cb, IPv4-literal host + port) verifies — a transferable proof is bound to the via string, not to the transport it names', [MSG, SIG_LAN]),
  v('a use=sign-only key verifies a sign-typed signature (use-match)', [MSG, SIG_SIGNONLY]),
  v('a second independent identity (jane) verifies', [MSG, SIG_JANE]),
  v('signedMetadata object is echoed back verbatim on success', [MSG, SIG_SIGNEDMETA]),
  v('unsignedMetadata with a null value parses fine and verifies (safeParseJson null-node arm)', [MSG, SIG_NULLVALUE_UNSIGNED]),
  v('WebAuthn valid assertion verifies (challenge=sha256(payload), webauthn.get, matching origin, crossOrigin=false)', [MSG, SIG_WA_OK]),
  v('all satisfied constraints {type,identifier,via,ver,notBefore,notAfter} verify -> success', [MSG, SIG_DESKTOP, { type: 'sign', identifier: ID, via: VIA, ver: 1, notBefore: T - 1000, notAfter: T + 1000 }]),
  v('key record with dnssec:false verifies but with secure:false', [MSG, SIG_DESKTOP], { dnsEntries: johnKeyRecord('', { ttl: 1800, dnssec: false }) }),
  v('key record with a custom TTL yields expires = now + ttl*1000', [MSG, SIG_DESKTOP], { dnsEntries: johnKeyRecord('', { ttl: 60, dnssec: true }) }),

  // ===================================================================================
  // SUCCESS — multi-signature (verify-UNIQUE length>1 path). verify returns the multisig
  // envelope {type:'multisig', valid, secure, expires, signatures:[...] } with verified:true.
  // ===================================================================================
  v('two distinct identities (john + jane) over the same message -> multisig success (opted in via maxSignatures; secure aggregate true, expires = min)', [MSG, SIG_MULTI, { maxSignatures: 2 }]),
  v('same-signer-twice multisig (two fresh signatures) under a dnssec:false record -> multisig valid:true with secure:false (every(secure) false arm)', [MSG, SIG_MULTI_SAME2, { maxSignatures: 2 }], { dnsEntries: johnKeyRecord('', { ttl: 1800, dnssec: false }) }),
  v('multisig whose second segment has bogus crypto -> loop returns false -> valid:false (opted in via maxSignatures, so the per-segment loop rejects, not the default-single policy)', [MSG, SIG_MULTI_BAD2, { maxSignatures: 2 }]),

  // ===================================================================================
  // EMERGENT SECURITY PROPERTIES / REGRESSION GUARDS
  // These do NOT chase new branches (coverage is already complete); they pin invariants that a
  // refactor could silently break while keeping 100% branch coverage. Each one would still execute
  // the same lines, so only an output assertion catches the regression.
  // ===================================================================================

  // --- Cryptographic field binding (tamper-evidence) ---------------------------------------------
  // The signed payload is `type;identifier;via;v+ver;ts;signedMetadata;;message`. Take an OTHERWISE
  // VALID signature, change exactly ONE signed slot to a well-formed different value (envelope still
  // parses), and verification MUST flip to valid:false. If a refactor dropped a field from the
  // reconstructed payload, that field would stop being tamper-evident and these guards would fail.
  // (The dual property — that the UNSIGNED metadata slot is NOT bound — is already pinned by the
  // slot-6-swap successes above, e.g. the null-value unsignedMetadata test.)
  v('SECURITY: a stamp signature relabelled type=sign does NOT verify (type is signed; blocks cross-protocol stamp->sign upgrade)', [MSG, SIG_TAMPER_TYPE]),
  v('SECURITY (positive control): a signature genuinely made AS twin verifies, confirming twin resolves and john\'s key is usable under it — so the relabel failure below is the identifier binding, not a resolution miss', [MSG, SIG_TWIN]),
  v("SECURITY: one of john's signatures relabelled identifier=twin does NOT verify, even though twin publishes john's EXACT key bytes (identifier is bound by the crypto, not just by key identity)", [MSG, SIG_TAMPER_ID]),
  v('SECURITY: changing the envelope via to another valid origin does NOT verify (via is signed; blocks relay/origin swap)', [MSG, SIG_TAMPER_VIA]),
  v('SECURITY: moving the envelope ts forward does NOT verify (timestamp is signed; a captured signature cannot be re-stamped fresh to slip a freshness window)', [MSG, SIG_TAMPER_TS]),
  v('SECURITY: grafting forged signedMetadata onto a real signature does NOT verify (signedMetadata is signed and is returned to the caller as trusted data)', [MSG, SIG_TAMPER_SMETA]),

  // --- Message opacity / delimiter-injection resistance -----------------------------------------
  v('SECURITY: a message whose bytes spell a fake "stamp;jane;https://evil/..." envelope still verifies as sign/john/example.com (the external message cannot be smuggled into the parsed envelope fields)', [DELIM_MSG, SIG_DELIM_MSG]),

  // --- WebAuthn assertion is bound to the message -----------------------------------------------
  v('SECURITY: a valid WebAuthn assertion replayed against a DIFFERENT message does NOT verify (clientData.challenge is sha256(payload), so it cannot be lifted onto another message)', [WRONG_MSG, SIG_WA_OK]),

  // --- Freshness-window boundaries are strict (no clock-drift widening) --------------------------
  // verify compares the constraint against ts with NO maximalAllowedClientClockDrift slack (unlike the
  // internal auth/ping/sign/stamp paths). These pin the exact inclusive boundary so an off-by-one
  // (> vs >=) OR an accidental drift-widening is caught: notBefore===ts and notAfter===ts must PASS,
  // while notBefore===ts+1 and notAfter===ts-1 (tested above) must FAIL.
  v('SECURITY: notBefore exactly equal to ts is accepted (inclusive lower bound; fail condition is notBefore > ts)', [MSG, SIG_DESKTOP, { notBefore: T }]),
  v('SECURITY: notAfter exactly equal to ts is accepted (inclusive upper bound; fail condition is notAfter < ts)', [MSG, SIG_DESKTOP, { notAfter: T }]),

  // --- Constraint exactness / non-exposure of internal count constraints ------------------------
  v('SECURITY: an {identifier} constraint is matched EXACTLY against the envelope identifier string, so {identifier:"john@..."} rejects a signature genuinely made AS twin - same key bytes as john, different identifier', [MSG, SIG_TWIN, { identifier: 'john@triauthdemo.org' }]),
  v('maxSignatures:1 rejects a 2-segment multisig envelope -> valid:false (constraint exposed through verify)', [MSG, SIG_MULTI, { maxSignatures: 1 }]),
  v('SECURITY: a multi-signature envelope with NO signature-count constraint is rejected under the default single-signature policy -> valid:false (a relying party checking only valid can never silently receive a {type:multisig} aggregate; raise maxSignatures, which defaults to 1, to verify a multisig)', [MSG, SIG_MULTI]),
  v('maxSignatures:1 accepts a single-signature envelope -> success (pins the flat single-signature result shape)', [MSG, SIG_DESKTOP, { maxSignatures: 1 }]),
  v('minSignatures:2 (with maxSignatures:2) accepts a 2-segment multisig -> multisig success', [MSG, SIG_MULTI, { minSignatures: 2, maxSignatures: 2 }]),
  v('minSignatures:3 (with maxSignatures:5) rejects a 2-segment multisig -> valid:false (below the floor)', [MSG, SIG_MULTI, { minSignatures: 3, maxSignatures: 5 }]),
  v('SECURITY: minSignatures alone does NOT relax the single-signature default - {minSignatures:2} on a 2-segment envelope still rejects because maxSignatures defaults to 1 -> valid:false', [MSG, SIG_MULTI, { minSignatures: 2 }]),
  v('non-numeric maxSignatures is a caller argument error -> {error:101} (rejected before any cryptographic work)', [MSG, SIG_DESKTOP, { maxSignatures: '1' }]),
  v('SECURITY: byte-identical duplicate segments are rejected outright (MultiSignature ctor 225) -> valid:false - a single signature replayed to pad the segment count', [MSG, SIG_MULTI_DUPED]),
  v('SECURITY: minSignatures counts segments, NOT distinct signers - a same-signer-twice envelope (fresh signatures) satisfies minSignatures:2 (with maxSignatures:2); require distinctness via signatures[].identifier/deviceTag', [MSG, SIG_MULTI_SAME2, { minSignatures: 2, maxSignatures: 2 }]),

  // --- Multi-signature fail-safe aggregation ----------------------------------------------------
  v('SECURITY: a multisig over keys with different TTLs reports the EARLIEST (min) expiry, not the latest (john ttl 1800 + jane ttl 60 -> expires = ts + 60000); a regression to max would overstate validity', [MSG, SIG_MULTI, { maxSignatures: 2 }], { dnsEntries: { 'jane._at.triauthdemo.org': { TXT: ['initials JR', 'name Jane Roe', { value: `key desktop[1/1]:${jane.keys[0].public}`, ttl: 60, dnssec: true }] } } }),
  v('SECURITY: exactly maxMultiSignatures=5 valid distinct segments verify (upper boundary accepted; 6 is rejected above) -> multisig success', [MSG, SIG_MULTI_FIVE, { maxSignatures: 5 }]),

  // ===================================================================================
  // Back-filled tests that were first added directly to verify.json (after the WebAuthn
  // UP-UV enforcement / dnssec-capping changes shipped) — kept here so a full regeneration
  // reproduces them.
  // ===================================================================================
  v('SECURITY: endpoint triauth record with dnssec:false caps secure to false even though all key records are DNSSEC-validated', [MSG, SIG_DESKTOP], { dnsEntries: { 'triauthdemo.org': { TXT: [{ value: 'triauth auth.triauthdemo.org mode=public', ttl: 1800, dnssec: false }] } } }),
  v('SECURITY: WebAuthn assertion with the User Present (UP) flag cleared (CTAP-level silent assertion) -> valid:false even though its ECDSA signature is valid', [MSG, SIG_WA_NOUP]),
  v('SECURITY: WebAuthn authenticatorData shorter than 37 bytes (rpIdHash+flags+signCount) -> valid:false (length guard)', [MSG, SIG_WA_SHORT]),
  v('SECURITY: uv=required key record rejects an assertion without the User Verified (UV) flag -> valid:false (UP alone is not enough)', [MSG, SIG_WA_OK], { dnsEntries: waKeyRecord(' uv=required') }),
  v('uv=required key record accepts an assertion with both UP and UV flags set -> valid:true', [MSG, SIG_WA_UPUV], { dnsEntries: waKeyRecord(' uv=required') }),
  v('SECURITY: a mistyped uv value (uv=reuired) taints the keyGroup -> valid:false - fail closed, a typo must not silently drop the user verification requirement', [MSG, SIG_WA_OK], { dnsEntries: waKeyRecord(' uv=reuired') }),

  // ===================================================================================
  // Ed25519 (type=ed25519) and WebAuthn-Ed25519 (type=webauthn-ed25519) verifier backends.
  // Cross-language guarantee: a port without these verifiers registered would taint the
  // keyGroups and fail the positives.
  // ===================================================================================
  v('Ed25519: valid Ed25519 signature from a type=ed25519 key verifies -> valid:true', [MSG, SIG_ED25519_OK]),
  v('Ed25519: bogus signature fails the Ed25519 crypto verification -> valid:false', [MSG, SIG_ED25519_BOGUS]),
  v('Ed25519: 65-byte P-256 key material published as type=ed25519 cannot import (raw Ed25519 keys are exactly 32 bytes) -> fromPublishableKey null -> valid:false', [MSG, SIG_ED25519_OK], { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${john.devices[0].keys[0].public} type=ed25519`] } } }),
  v('Ed25519 SECURITY: uv=required on a type=ed25519 (non-webauthn) key is unenforceable and taints the keyGroup -> valid:false - fail closed', [MSG, SIG_ED25519_OK], { dnsEntries: { 'ed25519._at.triauthdemo.org': { TXT: ['name Ed25519', `key desktop[1/1]:${ed25519.keys[0].public} type=ed25519 uv=required`] } } }),
  v('WebAuthn-Ed25519: valid assertion backed by a type=webauthn-ed25519 key verifies -> valid:true', [MSG, SIG_WAED_OK]),
  v('WebAuthn-Ed25519: structurally valid assertion with bogus crypto -> valid:false', [MSG, SIG_WAED_BADSIG]),
  v('Ed25519 multisig: heterogeneous algorithms (john es256 + ed25519 signer) in one multi-signature envelope -> multisig success', [MSG, SIG_MULTI_MIXED, { maxSignatures: 2 }]),
  // PUBLICPROFILE: shape and hardening of the publicProfile surfaced on verify results
  // (per-test dnsEntries publish the profile records; the envelope is the canonical minted one).
  v("PUBLICPROFILE: verify surfaces name/initials and x- extensions; unrecognized keywords (incl. former 'roles'/'title') and over-long x- keys are dropped", [MSG, SIG_DESKTOP], { dnsEntries: {
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
  v("PUBLICPROFILE SECURITY: verify drops a publicProfile keyword that appears more than once (reserved and x-) entirely", [MSG, SIG_DESKTOP], { dnsEntries: {
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
  v("PUBLICPROFILE SECURITY: verify rejects (does not truncate) a publicProfile value longer than the byte cap", [MSG, SIG_DESKTOP], { dnsEntries: {
      "john._at.triauthdemo.org": {
        "TXT": [
          "initials JD",
          "name aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8"
        ]
      }
    } }),
  v("PUBLICPROFILE SECURITY: verify caps the number of distinct x- extensions (only the first publicProfileMaxExtensions are kept)", [MSG, SIG_DESKTOP], { dnsEntries: {
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
  v('requireSecure: verify - a DNSSEC-secure key chain still verifies when requireSecure:true (config, 4th positional)', [MSG, SIG_DESKTOP, {}, { requireSecure: true }]),
  v('SECURITY requireSecure: verify - a non-DNSSEC (secure:false) key chain is rejected with 404 as {error}, not valid:false', [MSG, SIG_DESKTOP, {}, { requireSecure: true }], { dnsEntries: johnKeyRecord('', { ttl: 1800, dnssec: false }) }),

  // GROUPS: the membership list surfaced on verify results, and the resolution-level secure
  // semantics it rides on (per-test dnsEntries publish the groups records; envelopes are the
  // canonical mints - groups never enter the signed bytes).
  v('GROUPS: verify surfaces the identity\'s groups fully qualified, deduplicated across records, and sorted ascending', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: [
    'initials JD', 'name John Doe',
    'groups zeta,admins',
    'groups admins,project3',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  ] } } }),
  v('GROUPS: an identity publishing no groups records yields groups: [] on the result', [MSG, SIG_DESKTOP]),
  v('GROUPS: a delegated signature carries the SUBJECT\'s groups, never the actor\'s - jane\'s own groups must not leak into a result that speaks for john', [MSG, SIG_DELEGATED], { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD', 'name John Doe',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      'include jane@triauthdemo.org scope=any',
      'groups admins,project3',
    ] },
    'jane._at.triauthdemo.org': { TXT: [
      'initials JR', 'name Jane Roe',
      `key desktop[1/1]:${jane.keys[0].public}`,
      'groups contractors',
    ] },
  } }),
  v('GROUPS: multisig - each segment carries its own signer\'s groups; the aggregate object carries none', [MSG, SIG_MULTI, { maxSignatures: 2 }], { dnsEntries: {
    'john._at.triauthdemo.org': { TXT: [
      'initials JD', 'name John Doe',
      `key desktop[1/1]:${john.devices[0].keys[0].public}`,
      `key laptop[1/2]:${john.devices[1].keys[0].public}`,
      `key laptop[2/2]:${john.devices[1].keys[1].public}`,
      'groups admins',
    ] },
    'jane._at.triauthdemo.org': { TXT: [
      'initials JR', 'name Jane Roe',
      `key desktop[1/1]:${jane.keys[0].public}`,
      'groups reviewers',
    ] },
  } }),
  v('GROUPS SECURITY: a groups record without DNSSEC degrades secure to false - DNSSEC status is resolution-level (full-in or full-out), even though the key records are validated', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: [
    'initials JD', 'name John Doe',
    { value: 'groups admins', ttl: 1800, dnssec: false },
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  ] } } }),
  v('GROUPS SECURITY: a profile record without DNSSEC degrades secure to false - any record of the identity answer participates in the resolution-level status', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: [
    { value: 'name John Doe', ttl: 1800, dnssec: false },
    'initials JD',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  ] } } }),
  v('GROUPS SECURITY: an unrecognized-key record without DNSSEC degrades secure to false - unknown records are ignored for content but remain part of the answer', [MSG, SIG_DESKTOP], { dnsEntries: { 'john._at.triauthdemo.org': { TXT: [
    'initials JD', 'name John Doe',
    { value: 'future-feature whatever', ttl: 1800, dnssec: false },
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
  ] } } }),

  // Delegated secure aggregation: the AND of the two resolutions' Identity secure statuses.
  // One twin per side, so a port omitting either term fails a vector.
  v('SECURITY: delegated verify with the include record served without DNSSEC -> valid:true with secure:false - the subject-side resolution degrades the two-resolution AND', [MSG, SIG_DELEGATED], { dnsEntries: johnWithGrant({ value: 'include jane@triauthdemo.org scope=any', ttl: 1800, dnssec: false }) }),
  v('SECURITY: delegated verify with the actor\'s key record served without DNSSEC -> valid:true with secure:false - the actor-side resolution degrades the two-resolution AND', [MSG, SIG_DELEGATED], { dnsEntries: {
    ...johnWithGrant('include jane@triauthdemo.org scope=any'),
    'jane._at.triauthdemo.org': { TXT: [
      'initials JR', 'name Jane Roe',
      { value: `key desktop[1/1]:${jane.keys[0].public}`, ttl: 1800, dnssec: false },
    ] },
  } }),

  // Literal key data: escapes are ordinary characters everywhere outside profile values.
  v('SECURITY: key data is literal - a percent-escaped spelling of the published key (%42...) is different bytes that never import; the response signed by the real key does not verify -> valid:false', [MSG, SIG_DESKTOP], { dnsEntries: johnSingleKey(`key desktop[1/1]:%42${john.devices[0].keys[0].public.slice(1)}`) }),

  // ===================================================================================
  // PRIVATE MODE (mode=private): the identity domain derives from a
  // per-identity lookup code carried in signed-metadata (`lookupCode` = the subject's,
  // `actorLookupCode` = the actor's), and the records must carry exactly one matching
  // `commit` record. Every binding failure routes through the resolution seam
  // -> valid:false, never a distinct error code. A lookup code is consumed - and reported back
  // on the deviceTag - only where that identity's domain runs mode=private; anywhere else it is an
  // auxiliary signed-metadata member and the envelope's ignore rule for auxiliary members applies to it like any other, which is
  // what lets a signature keep verifying when a domain changes its mode.
  // ===================================================================================
  v('PRIVATE: signature with the identity lookup code in signed-metadata verifies; the deviceTag carries the code as its ~ suffix and identityDomain is the derived-label form', [MSG, SIG_PRIVATE]),
  v('PRIVATE: lookupCode member missing under a private-mode domain -> derivation impossible -> valid:false', [MSG, SIG_PRIVATE_NOCODE]),
  v('PRIVATE: 15-character lookup code (one under the exact 16) -> valid:false', [MSG, SIG_PRIVATE_CODE15]),
  v('PRIVATE: 17-character lookup code (one over the exact 16) -> valid:false', [MSG, SIG_PRIVATE_CODE17]),
  v('PRIVATE: lowercase lookup code -> valid:false (the [A-Z0-9]{16} grammar is strict; no case folding)', [MSG, SIG_PRIVATE_CODELOWER]),
  v('PRIVATE SECURITY: a lowercase lookup code fails BY GRAMMAR, not by resolution outcome - even with records genuinely published (matching commitment included) at the label the lowercase bytes would derive, the code alphabet never widens -> valid:false', [MSG, SIG_PRIVATE_CODELOWER], { dnsEntries: { [PRIVATE.lowercase.identityDomain]: { TXT: [
    'name John Doe',
    `key desktop[1/1]:${john.devices[0].keys[0].public}`,
    `commit ${PRIVATE.lowercase.commitment}`,
  ] } } }),
  v('PRIVATE: lookup code with a character outside [A-Z0-9] -> valid:false', [MSG, SIG_PRIVATE_CODECHARS]),
  v('PRIVATE: non-string lookup code (number) -> valid:false', [MSG, SIG_PRIVATE_CODENUM]),
  v('PRIVATE: well-formed but wrong lookup code derives an unpublished identity domain -> valid:false', [MSG, SIG_PRIVATE_WRONGCODE]),
  v('PRIVATE: a lookupCode member under a public-mode domain is inert -> valid:true with a BARE deviceTag - a domain that runs no private-mode derivation consumes no code and reports none, so the same device is named identically whatever a signature carries (auxiliary members are ignored)', [MSG, SIG_PUBLIC_WITHCODE]),
  v('PRIVATE: an actorLookupCode member on a self-signed (actor-less) envelope is inert -> valid:true - with no actor there is no second identity to resolve, and nothing to report it against', [MSG, SIG_ACTORCODE_NOACTOR]),
  v('PRIVATE SECURITY: commit record missing from the identity records -> valid:false - under a derived private-mode resolution the records exist only through their commitment', [MSG, SIG_PRIVATE], { dnsEntries: privateJohnRecords() }),
  v('PRIVATE SECURITY: commit record value mismatching the derivation -> valid:false', [MSG, SIG_PRIVATE], { dnsEntries: privateJohnRecords(`commit ${PRIVATE.wrongCommitment}`) }),
  v('PRIVATE SECURITY: two commit records - the correct commitment AND a second one - -> valid:false even though one matches; a doubled commitment is the label-merge tripwire, never a valid state', [MSG, SIG_PRIVATE], { dnsEntries: privateJohnRecords(`commit ${PRIVATE.john.commitment}`, `commit ${PRIVATE.wrongCommitment}`) }),
  v('PRIVATE: commit record carrying an unknown critical option -> the record is malformed, leaving the single commit record invalid -> valid:false', [MSG, SIG_PRIVATE], { dnsEntries: privateJohnRecords(`commit ${PRIVATE.john.commitment} evil=1`) }),
  v('PRIVATE: commit record whose value is not a 43-character digest -> malformed record, binding fails -> valid:false', [MSG, SIG_PRIVATE], { dnsEntries: privateJohnRecords('commit tooshort') }),
  v('PRIVATE: commit record served without DNSSEC degrades secure to false while the binding still verifies -> valid:true, secure:false', [MSG, SIG_PRIVATE], { dnsEntries: privateJohnRecords({ value: `commit ${PRIVATE.john.commitment}`, ttl: 1800, dnssec: false }, `include ${PRIVATE.bot.identifier} scope=any`) }),
  v('PRIVATE: delegated signature inside the private-mode org (bot signs for john, both zones in private mode, lookupCode + actorLookupCode in signed-metadata) -> valid:true with both codes suffixed onto the composite deviceTag', [MSG, SIG_PRIVATE_DELEG]),
  v('PRIVATE: delegated signature missing the actorLookupCode while the actor domain runs private mode -> the signer cannot resolve -> valid:false', [MSG, SIG_PRIVATE_DELEG_NOACTORCODE]),
  v('PRIVATE: an actorLookupCode under a public-mode actor is inert -> valid:true with both composite components bare - the code is consumed, and reported, per identity and only where that identity runs mode=private', [MSG, SIG_PUBLICACTOR_ACTORCODE], { dnsEntries: johnWithGrant('include jane@triauthdemo.org scope=any') }),
];

const suite = {
  title: 'verify',
  description:
    'Comprehensive, branch-complete coverage of Triauth.verify(message, signature, constraints?, config?). ' +
    'verify takes a raw signature envelope directly and runs MultiSignature -> Signature -> Identity.resolve ' +
    '-> IdentityKeys.verify -> Verifiers, with no challenge/response, attachment, or callbackUrl machinery. ' +
    'Covered: the argument-shape guards (101) and the DNS-failure path (110) — the only {error} bodies; every other failure is ' +
    '{verified:true,valid:false}; MultiSignature/Signature envelope parse failures and metadata-parse ' +
    'rejections (caught by verify’s code>=200 arm); constraint-driven failures (type/identifier/ver/via ' +
    'mismatch -> false, out-of-window notBefore/notAfter -> null); generic crypto failures (bogus bytes, ' +
    'atob-throw, message<->signature binding, use-mismatch, partial multi-key, too many signatures); identity ' +
    'resolution failures (NXDOMAIN/unconfigured/ambiguous/unknown-identifier/unknown-mode errors -> valid:false; ' +
    'DNS SERVFAIL propagates as a retryable 110); the IdentityKeys add/verify taint & skip branches; the WebAuthn verifier ' +
    '(type=webauthn-es256) success plus every structure/clientData guard and the import-failure path; ' +
    'the Ed25519 (type=ed25519) and WebAuthn-Ed25519 (type=webauthn-ed25519) verifier backends, including ' +
    'a heterogeneous es256+ed25519 multisig; ' +
    'resolveConfig record sanitization; the single-signature SUCCESS body ({valid,type,identifier,identityDomain,lookupCode,actor,' +
    'actorIdentityDomain,actorLookupCode,via,ver,signedAt,verifiedAt,publicProfile,groups,deviceName,deviceTag,keys,secure,expires,signedMetadata,' +
    'unsignedMetadata}); and the verify-UNIQUE multi-signature SUCCESS path (length>1 -> {type:\'multisig\',' +
    'valid,secure,expires,signatures}), which verify accepts only when the caller raises maxSignatures ' +
    '(which defaults to 1) — by default, and when only minSignatures is given, a multi-segment envelope ' +
    'is rejected as valid:false under verify\'s secure-by-default single-signature policy. A final EMERGENT-SECURITY / REGRESSION-GUARD section pins ' +
    'invariants that a refactor could break while keeping 100% branch coverage: cryptographic binding ' +
    'of every signed envelope field (tampering type/identifier/via/ts/signedMetadata on an otherwise-' +
    'valid signature flips valid->false; identifier binding is isolated from key identity via a twin ' +
    'that republishes john\'s exact key); message opacity (a delimiter-laden message cannot be smuggled ' +
    'into the parsed fields); WebAuthn challenge<->message binding; strict (no clock-drift) freshness ' +
    'boundaries at notBefore===ts / notAfter===ts; exact identifier constraint matching; non-exposure of the ' +
    'internal minSignatures/maxSignatures constraints; and multi-signature fail-safe aggregation ' +
    '(earliest expiry wins; the maxMultiSignatures=5 upper boundary is accepted). Crypto-bearing ' +
    'fixtures (ECDSA + WebAuthn) were minted by ' +
    'test/fixtures/json/_capture_verify.mjs (WebCrypto ECDSA is non-deterministic to mint, deterministic to ' +
    'verify). See that script’s header for the exhaustive list of verify-UNREACHABLE branches left ' +
    'uncovered by construction. A GROUPS section pins the membership list surfaced on results ' +
    '(fully-qualified sorted deduplicated names; the subject\'s under delegation; per-segment in ' +
    'multisig with no aggregate-level field) and the resolution-level secure semantics: any ' +
    'non-DNSSEC record of the identity answer - groups, profile, or unrecognized - degrades secure. ' +
    'A PRIVATE MODE section covers mode=private (per-identity lookup code in signed-metadata: ' +
    '`lookupCode` for the subject, `actorLookupCode` for the actor; the exact-16 [A-Z0-9] grammar; ' +
    'the commit record with its exactly-one tripwire and the ~lookupCode deviceTag ' +
    'suffixes, reported from the derivation actually performed; a code is consumed only where its ' +
    'identity runs mode=private and is inert elsewhere; ' +
    'a delegated private-mode org pair verifies with both codes).',
  dnsEntries,
  currentTime: T,
  tests,
};

writeSuite(new URL('./verify.json', import.meta.url), suite);
