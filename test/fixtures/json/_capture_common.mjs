// Shared fixture material for the one-shot suite generators (_capture_*.mjs).
//
// Everything here is deliberately generator-only plumbing: the JSON suites are the
// cross-language interface, and ports neither need nor should
// read this file.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename } from 'node:path';

// Suite-level frozen clock shared by every generator and suite. Every challenge iat and
// every signature ts is minted at T, so signatures land inside each flow's
// notBefore/notAfter window.
export const T = 1777454675000;

// Minimal logger satisfying the `config.logger?.spawn?.(cid) || config.logger` line in the
// API entrypoints; errors stay visible while minting.
export const LOGGER = { debug() {}, info() {}, warn() {}, error: console.error, spawn() { return this; } };

// Locally-generated identities NOT published in real DNS. They live here rather than in
// ../identities.json because that file, with ../dns_records.json, describes the suite's demo zone
// triauthdemo.org — these identifiers only exist inside the suites' dnsEntries.
// One definition keeps every suite's copy of a keypair in lock-step by construction.
//
//   - signonly: key published with use=sign (per-suite dnsEntries) — exercises use-matching.
//   - jane: an ordinary second identity — "wrong identity" / second-signer cases.
//   - ed25519: identity whose key is published with type=ed25519 (32-byte raw Ed25519 public
//     key, base64url). Cross-language guarantee: a port without the ed25519 verifier
//     registered would taint/skip these keys and fail the positives. Unlike WebCrypto ECDSA,
//     Ed25519 signing is deterministic, so re-running a generator reproduces byte-identical
//     envelopes for these cases.
export const signonly = {
  identifier: 'signonly@triauthdemo.org',
  keys: [{
    public:  'BFoRgJA2iCjbm-kRdxhXSuF25IpbYJMQkKb-gq7NB9C3yjYdQxxeVtkmG9k79wOyxzjXpuSJ08E1WKKrr466HWE',
    private: {"kty":"EC","crv":"P-256","d":"3Laqu_Yzg5lupP0TEcAXysZc2tgBJaXNgJWFSR4B5Rg","x":"WhGAkDaIKNub6RF3GFdK4XbkiltgkxCQpv6Crs0H0Lc","y":"yjYdQxxeVtkmG9k79wOyxzjXpuSJ08E1WKKrr466HWE"},
  }],
};
export const jane = {
  identifier: 'jane@triauthdemo.org',
  keys: [{
    public:  'BH0BEkf4wfTawLanz-btFEZQuvAsZF31mZ-mlLslWODUU1g9C68mFNF6FcnX8UiYdFeEDTP_5WoFCVf6EOXaTnE',
    private: {"kty":"EC","crv":"P-256","d":"6Jr-GCjyYQEDzSXu11E0tS8wqCF1xRxX87kg2al8RqY","x":"fQESR_jB9NrAtqfP5u0URlC68CxkXfWZn6aUuyVY4NQ","y":"U1g9C68mFNF6FcnX8UiYdFeEDTP_5WoFCVf6EOXaTnE"},
  }],
};
export const ed25519 = {
  identifier: 'ed25519@triauthdemo.org',
  keys: [{
    public:  'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0',
    private: {"kty":"OKP","crv":"Ed25519","d":"-_UnNRraY7oJRq-G3bKgtnbM9y1AhAoj0zjAYr810yM","x":"Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0"},
  }],
};

// The auth capture works with device-shaped identities (deviceName + keys, mirroring
// identities.json); the other captures use the flat shape above.
export const asDevices = ({ identifier, keys }, deviceName = 'desktop') =>
  ({ identifier, devices: [{ deviceName, keys }] });

// The private-mode fixture domain (mode=private). Two identities under one
// domain: `john` (subject cases; signs with the real john's desktop key from ../identities.json)
// and `bot` (delegated-actor cases; signs with the `jane` keypair above as its `worker` device).
// Lookup codes are fixed literals — the writeSuite drift guard requires deterministic inputs — and
// the derivation literals below follow from them; re-derive with:
//   node --experimental-global-webcrypto --input-type=module -e "
//     import {IdentityDomain} from './src/identity_domain.js'; import {Helpers} from './src/helpers.js';
//     const full = await IdentityDomain.deriveFullLabel('john@private.triauthdemo.org', 'K7QJ3FB9M2WZX0C4');
//     console.log(full.substring(0,10), await Helpers.sha256(full));"
export const PRIVATE = {
  domain: 'private.triauthdemo.org',
  endpointRecord: 'triauth auth.private.triauthdemo.org mode=private',
  john: {
    identifier: 'john@private.triauthdemo.org',
    lookupCode: 'K7QJ3FB9M2WZX0C4',
    identityDomain: '_4GIBDU53B3._at.private.triauthdemo.org',
    commitment: '3Q7YSpb3MLMRaQ20VZBUfoySyM4vQrHMfIIuAxER3_s',
  },
  bot: {
    identifier: 'bot@private.triauthdemo.org',
    lookupCode: 'P2M8XCV4KQ0RZJ5T',
    identityDomain: '_HJINC5QKI5._at.private.triauthdemo.org',
    commitment: 'zhDlBSKImyxtx1GqXmEjAyOyD1IUMXtOBSqGgaPAAxk',
  },
  // john's derivation under this lookup code lands on `_IIBOSRWME5._at.private.triauthdemo.org` —
  // deliberately absent from every dnsEntries, so a wrong code surfaces as an unpublished domain
  wrongLookupCode: 'ZZZZZZZZZZZZZZZZ',
  // a well-formed 43-char digest that matches no fixture derivation (john's commitment under wrongLookupCode)
  wrongCommitment: 'd6aULTkSobj2sWOyq-SPQq403YvOeMaZdmP9GsATkIA',
  // john's derivation under the LOWERCASE spelling of his code: the label those bytes would reach
  // if the [A-Z0-9]{16} grammar ever case-folded, published in one verify vector to prove it does not
  lowercase: {
    identityDomain: '_6DFUEZ2POB._at.private.triauthdemo.org',
    commitment: 'd8Api9OZzCWprcwjTF4Drriuf7DIlcdelWryAZR2hBI',
  },
};

// ---------------------------------------------------------------------------------------
// writeSuite: guarded suite writer.
//
// The shipped .json files accumulate surgical hand-edits between full re-mints (new cases,
// arg adjustments mirroring validation changes). A generator run that does not reflect
// those edits would silently DELETE cases (they simply aren't emitted) or silently REVERT
// same-named args — and RECORD=1 would then happily re-record wrong expecteds under
// unchanged names. Both hazards are invisible in a green test run, so they are blocked
// here, at the only choke point every re-mint passes through.
//
// Comparison is structural (key order in hand-edited JSON differs from generator output)
// and masks base64url runs >= 32 chars with a length-preserving placeholder: WebCrypto
// ECDSA re-mints legitimately change signature bytes on every run (fixed-length raw r||s),
// while any length change still surfaces. Deterministic artifacts (challenge strings,
// Ed25519 envelopes) compare as equal-length masks here; their byte-identity is asserted by
// the re-mint verification gate, not by this guard.
//
// Environment switches:
//   CHECK=1  dry run — print the drift report, write nothing (exit 1 if drift/removals).
//   FORCE=1  write despite removals/drift (after eyeballing the report; the follow-up
//            `git diff` of the suite is the final review).

const B64RUN = /[A-Za-z0-9_-]{32,}/g;
const mask = (v) => {
  if (typeof v === 'string') return v.replace(B64RUN, (m) => 'X'.repeat(m.length));
  if (Array.isArray(v)) return v.map(mask);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = mask(v[k]);
    return out;
  }
  return v;
};
// The guarded surface: everything the runner feeds the call. `expected` is deliberately
// excluded — generators emit tests without it, and RECORD owns it.
const inputsOf = (t) => JSON.stringify(mask({
  call: t.call, args: t.args, dnsEntries: t.dnsEntries, currentTime: t.currentTime, random: t.random,
}));

export function writeSuite(outUrl, suite) {
  const outPath = fileURLToPath(outUrl);
  const file = basename(outPath);
  const check = process.env.CHECK === '1';
  const force = process.env.FORCE === '1';

  const names = suite.tests.map((t) => t.name);
  const dupes = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))];
  if (dupes.length) {
    console.error(`[writeSuite] ${file}: duplicate test names (names are the stable key this guard diffs by):`);
    for (const d of dupes) console.error(`   DUP ${d}`);
    process.exit(1);
  }

  let removed = [], drifted = [], added = [];
  if (existsSync(outPath)) {
    const previous = JSON.parse(readFileSync(outPath, 'utf8'));
    const prev = new Map(previous.tests.map((t) => [t.name, t]));
    const next = new Map(suite.tests.map((t) => [t.name, t]));
    removed = [...prev.keys()].filter((n) => !next.has(n));
    added   = [...next.keys()].filter((n) => !prev.has(n));
    drifted = [...next.keys()].filter((n) => prev.has(n) && inputsOf(prev.get(n)) !== inputsOf(next.get(n)));

    console.log(`[writeSuite] ${file}: existing ${previous.tests.length} tests vs generated ${suite.tests.length}`);
    console.log(`  removed: ${removed.length} | input-drifted: ${drifted.length} | added: ${added.length}`);
    for (const n of removed) console.log(`   REMOVED ${n}`);
    for (const n of drifted) console.log(`   DRIFT   ${n}`);
    for (const n of added)   console.log(`   ADDED   ${n}`);
  } else {
    console.log(`[writeSuite] ${file}: no existing suite — writing fresh`);
  }

  const blocked = (removed.length > 0 || drifted.length > 0) && !force;
  if (check) {
    console.log(`[writeSuite] CHECK=1 — dry run, nothing written${blocked ? ' (would refuse without FORCE=1)' : ' (guard clean)'}`);
    process.exit(blocked ? 1 : 0);
  }
  if (blocked) {
    console.error(`[writeSuite] ${file}: REFUSING to write — removed/drifted cases above would be lost or reverted.`);
    console.error('             Mirror the shipped cases into this generator, or re-run with FORCE=1 to accept.');
    process.exit(1);
  }

  writeFileSync(outPath, JSON.stringify(suite, null, 2) + '\n');
  console.log(`Wrote ${suite.tests.length} tests to ${outPath} (run JSON_SUITE=${file} RECORD=1 npm run test:json to fill expecteds).`);
}
