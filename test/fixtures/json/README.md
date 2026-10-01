# JSON conformance suites — maintainer guide

The `*.json` files in this directory are the protocol's **conformance vectors**: deterministic
inputs (frozen clock, stubbed DNS, optional random-byte stream) with strict-match expected
outputs, run by `test/test_json.js` (`npm run test:json`) and intended to run unchanged against
every port. The consumer-side contract (schema, execution semantics a port must reproduce) is
carried by the JSON files themselves — they are the interface; nothing else in this
directory concerns ports. The runner's header comment (`test/test_json.js`) documents the schema in full.

## Provenance: how each suite is maintained

| Suite | Source of truth | Crypto fixtures |
|---|---|---|
| `attest`, `ping`, `sign`, `stamp`, `verify` | **Generator-minted**: `_capture_<flow>.mjs` assembles and writes the whole file | minted by the generator |
| `auth` | **Hand-maintained** structure; `_capture_auth.mjs` prints labeled envelope blobs to paste into it | paste-assisted |
| `whois`, `check`, `validate` | **Hand-maintained** (no crypto needed) | — |

Shared generator plumbing (frozen clock `T`, logger, the local `signonly`/`jane`/`ed25519`
keypairs, the guarded writer) lives in `_capture_common.mjs`. The per-suite `dnsEntries` blocks
and mint helpers are deliberately per-generator — they differ by flow.

## The three workflows

### 1. Full re-mint (envelope format, challenge fields, DNS layout, or clock changed)

```
node --experimental-global-webcrypto test/fixtures/json/_capture_<flow>.mjs
JSON_SUITE=<flow>.json RECORD=1 npm run test:json     # fill in every `expected`
JSON_SUITE=<flow>.json npm run test:json              # confirm green
git diff test/fixtures/json/<flow>.json               # eyeball before committing
```

The writer compares the generated suite against the shipped file and **refuses to write** when
it would drop cases or silently change same-named inputs (see "The guard" below). WebCrypto
ECDSA uses a random `k`, so every re-mint changes every ECDSA/WebAuthn signature byte — the
diff is large but the deterministic parts (challenge strings, Ed25519 envelopes, expecteds
modulo echoed envelopes) must survive byte-identically.

New cases go **into the generator**, never directly into a minted `.json` — a direct edit
survives only until the next re-mint reverts it (the guard turns that silent revert into a
loud refusal, but the fix is the same: mirror into the generator).

### 2. Surgical edit (inputs change, `expected` stays the same)

For a limits/input adjustment that keeps the same outcome: run a small script that
`JSON.parse`s the suite, mutates only the target fields, and writes
`JSON.stringify(data, null, 2) + '\n'` back — the diff is just the changed values. Mirror the
same change into the generator (the guard enforces this at the next mint). `validate.json` is
hand-formatted (compact one-line args): edit it as **raw text** to preserve its formatting.

### 3. Surgical RECORD (`expected` changes, signed bytes don't)

For a result-shape change (renamed/added result fields): run
`JSON_SUITE=<flow>.json RECORD=1 npm run test:json` **without** re-running the generator.
RECORD rewrites only the `expected` blocks and leaves every `args` byte identical — no
signature churn. Then mirror any new-field expectations into the generator comments if they
document result shapes.

## The guard (`writeSuite` in `_capture_common.mjs`)

Every generator writes through `writeSuite`, which diffs the generated suite against the
shipped file by test name:

- **removed** names (shipped case the generator no longer emits) → refuse;
- **input drift** on same-named cases (`args`/`dnsEntries`/`currentTime`/`random`, compared
  structurally with base64url runs ≥ 32 chars masked length-preservingly, so fresh ECDSA mints
  compare equal) → refuse — this catches the silent-revert hazard;
- **added** names → informational;
- duplicate test names → always refuse (names are the stable key the guard diffs by).

Switches: `CHECK=1` dry-runs (report only, exit 1 on drift), `FORCE=1` writes despite the
report — only after eyeballing it; the `git diff` of the suite is the final review.

## Gotchas

- **Always pass `JSON_SUITE=` together with `RECORD=1`.** RECORD rewrites every *touched* suite
  with canonical `JSON.stringify(…, null, 2)` formatting; a bare `RECORD=1` run that touches
  `validate.json` destroys its hand formatting.
- **Determinism map**: challenges (fixed nonce + frozen clock) and Ed25519 signatures re-mint
  byte-identically; ECDSA (incl. WebAuthn assertions) re-mints differently every run. `sign`
  and `stamp` expecteds echo the full response envelope in `expected.result`, so those blocks
  legitimately change on re-mint; `ping`/`attest`/`verify` expecteds carry only stable
  base64url (public keys, deviceTag).
- **DNS stub defaults**: a bare-string TXT record means `{value, ttl: 1800, dnssec: true}`.
  Non-DNSSEC cases (e.g. the `requireSecure` twins) use the object form with `dnssec: false`.
- **Token gating**: `ping`/`sign`/`stamp`/`attest` require a `token` at Stage 1 *before*
  message/attachment/DNS work — every Stage-1 case that must get past the token check carries
  `token: ':aaaaaaaaaaaaaaaa'` (the `issuer:secret` form with an empty issuer); cases pinning
  earlier validation errors (dispatch, identifier, callbackUrl, ext, invalid-token 226) stay
  tokenless.
- **Per-suite coverage**: `JSON_SUITE=<flow>.json npm run coverage:json` measures one suite in
  isolation. Each minted suite alone covers 100% of the paths reachable through its
  `Triauth.<flow>` call; each generator's header inventories the branches that are
  unreachable-by-construction.
- **Local identities** (`signonly`, `jane`, `ed25519`) exist only inside the suites'
  `dnsEntries`: `../identities.json` and `../dns_records.json` describe the suite's demo zone
  `triauthdemo.org` (see `../README.md`), and an identity that is not part of that zone does not
  belong in them.
