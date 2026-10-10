// Cross-language JSON-driven test runner.
//
// Each JSON suite describes deterministic input (DNS records, a fixed clock, an optional
// byte stream for randomness) and a list of API calls with strict-match expected results.
// The same fixtures are intended to be run against future ports of the library
// (Python, Go, ...) so protocol behavior stays uniform across implementations.
//
// Schema:
//   {
//     "title":       string,
//     "description": string,
//     "dnsEntries":  { "<domain>": null | { "<TYPE>": [string | {value, ttl, dnssec}, ...] } | { "_error": "<message>" } },
//     "currentTime": number,    // ms since epoch — suite-level default
//     "tests": [
//       {
//         "name":        string,
//         "call":        "<TriauthMethod>",
//         "args":        [...positional],
//         "currentTime": number,   // OPTIONAL — overrides the suite-level currentTime
//         "dnsEntries":  { ... },  // OPTIONAL — shallow-merged on top of the suite-level dnsEntries
//         "random":      "<lowercase hex>",   // OPTIONAL bytes consumed by randomSource
//         "expected":    {...}                // may be omitted in RECORD mode
//       }
//     ]
//   }
//
// Rules:
//   - dnsEntries[domain] === null is observationally equivalent to omitting the key
//     (both yield [] from the stub, matching real resolver NXDOMAIN behavior — see
//     src/resolvers/node_dns.js:82 and src/resolvers/dns_json.js:128). The null form is
//     kept as an expressive hint for readers.
//   - dnsEntries[domain] === { "_error": "..." } makes the stub reject that domain's DNS
//     query, simulating a SERVFAIL or network error. resolveConfig (src/resolvers/base.js)
//     catches the rejection and throws TriauthError(110), which propagates through the
//     resolve() catch blocks in AuthenticationEndpoint and IdentityDomain.
//   - Per-test dnsEntries is a per-domain shallow merge over the suite-level entries:
//     keys present in the test patch override completely (use null to "remove" / NXDOMAIN
//     a domain that was set at the suite level), keys absent inherit unchanged.
//   - Per-test currentTime, when set, overrides the suite-level value for that test only.
//     Time stays frozen for the entire test (no wall-clock progression).
//   - args is always an array (spread into the call). whois({identifier: "foo"}) → args: [{"identifier": "foo"}].
//   - random is a lowercase hex string of bytes. The runner installs a deterministic
//     Triauth.config.randomSource that returns these bytes in order; tests not consuming
//     randomness omit the field.
//   - expected is matched with assert.deepStrictEqual.
//   - A successful stage-1 result ({challenge, redirectUrl}) is masked before matching, because stage 1 mints a fresh
//     key pair for every challenge. The stored challenge is `<c>.<decryptionKey>`, and `<c>` carries `"ek":"<87 chars>"`.
//     The runner checks that a value sealed to `ek` opens with the decryption key, replaces the decryption key with
//     `DK`, base64url-decodes `<c>`, replaces the `ek` value with `EK` in the JSON text, and re-encodes it, in
//     `challenge` and in the `redirectUrl` fragment. When the fragment has `token=<issuer>:<hmac>`, the runner checks
//     that `hmac` is the base64url HMAC-SHA256 of the bytes of `<c>`, keyed by the UTF-8 of the `token` argument, and
//     replaces it with `HMAC`. Ports apply the same rule.
//
// Record mode:
//   Run with RECORD=1 (e.g., `RECORD=1 npm run test:json`) to capture actual output and
//   rewrite the JSON file. Missing or mismatching expected blocks are filled/replaced.
//   Normal runs are read-only. Node-only (no fs in browser).

import whoisSuite from './fixtures/json/whois.json' with { type: 'json' };
import authSuite from './fixtures/json/auth.json' with { type: 'json' };
import pingSuite from './fixtures/json/ping.json' with { type: 'json' };
import checkSuite from './fixtures/json/check.json' with { type: 'json' };
import signSuite from './fixtures/json/sign.json' with { type: 'json' };
import stampSuite from './fixtures/json/stamp.json' with { type: 'json' };
import verifySuite from './fixtures/json/verify.json' with { type: 'json' };
import attestSuite from './fixtures/json/attest.json' with { type: 'json' };
import validateSuite from './fixtures/json/validate.json' with { type: 'json' };
import DnsResolverStub from './stubs/dns_resolver.js';

const RECORDING = typeof process !== 'undefined' && !!process.env?.RECORD;

// Optional single-suite filter (e.g., `JSON_SUITE=sign.json npm run test:json`) used to run or
// measure coverage of one suite in isolation. Unset runs every suite.
const ONLY = typeof process !== 'undefined' ? process.env?.JSON_SUITE : undefined;

const SUITES = [
  { file: 'whois.json', data: whoisSuite },
  { file: 'auth.json',  data: authSuite  },
  { file: 'ping.json',  data: pingSuite  },
  { file: 'check.json', data: checkSuite },
  { file: 'sign.json',  data: signSuite  },
  { file: 'stamp.json', data: stampSuite },
  { file: 'verify.json', data: verifySuite },
  { file: 'attest.json', data: attestSuite },
  { file: 'validate.json', data: validateSuite }
].filter((s) => !ONLY || s.file === ONLY);

// Resolve each suite's absolute path so RECORD mode can write it back.
for (const s of SUITES) {
  s.path = new URL(`./fixtures/json/${s.file}`, import.meta.url).pathname;
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`Invalid hex string: ${JSON.stringify(hex)} (must be lowercase, even length)`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function makeRandomSource(hex, testName) {
  const bytes = hexToBytes(hex);
  let pos = 0;
  return function (arr) {
    if (pos + arr.length > bytes.length) {
      const need = arr.length;
      const have = bytes.length - pos;
      throw new Error(
        `Random byte stream exhausted (test "${testName}"): needed ${need} bytes, ${have} remaining`
      );
    }
    for (let i = 0; i < arr.length; i++) {
      arr[i] = bytes[pos++];
    }
    return arr;
  };
}

// Stage 1 mints a fresh key pair for every challenge, so a stage-1 result carries random values: the `ek` inside the
// challenge, the decryption key after the challenge's `.`, and the token HMAC over the challenge. The runner checks
// each one, then puts a fixed placeholder in its place (EK, DK, HMAC) before comparing.
async function maskStage1(result, options) {
  if (!result || typeof result.challenge !== 'string' || typeof result.redirectUrl !== 'string') {
    return result;
  }

  const [challenge, decryptionKey] = result.challenge.split('.');
  const json = Triauth.Helpers.base64UrlToString(challenge);
  const ek = (json.match(/"ek":"([A-Za-z0-9_-]{87})"/) || [])[1];
  assert(ek && json.split('"ek":').length === 2, 'a stage-1 challenge carries exactly one ek');

  // The key pair works: a probe sealed to ek opens with the decryption key
  const probe = await Triauth.ResponseCipher.seal(ek, 'probe');
  assert.equal(await Triauth.ResponseCipher.open(ek, decryptionKey, probe), 'probe');

  const masked = Triauth.Helpers.stringToBase64Url(json.replace(`"ek":"${ek}"`, '"ek":"EK"'));
  let redirectUrl = result.redirectUrl.replace(`challenge=${challenge}`, `challenge=${masked}`);

  // The token HMAC binds the challenge to the token holder
  const tokenParam = (redirectUrl.match(/[#?&]token=([^&]*)/) || [])[1];
  if (tokenParam !== undefined) {
    const [issuer, hmac] = tokenParam.split(':');
    const hmacKey = Triauth.Helpers.stringToUtf8Bytes(options.token);
    const expectedHmac = Triauth.Helpers.arrayBufferToBase64Url(await Triauth.Helpers.hmacSha256(hmacKey, Triauth.Helpers.base64UrlToUint8(challenge)));
    assert.equal(hmac, expectedHmac, 'the token HMAC covers the challenge');
    redirectUrl = redirectUrl.replace(`token=${tokenParam}`, `token=${issuer}:HMAC`);
  }

  return {...result, challenge: masked + '.DK', redirectUrl};
}

function isDeepEqual(a, b) {
  try {
    assert.deepStrictEqual(a, b);
    return true;
  } catch {
    return false;
  }
}

for (const suite of SUITES) {
  const { file, data, path } = suite;

  describe(data.title || file, function () {
    let suiteTouched = false;

    for (const t of data.tests) {
      it(t.name, async function () {
        const fn = Triauth[t.call];
        if (typeof fn !== 'function') {
          throw new Error(`Unknown Triauth method: ${t.call}`);
        }
        if (!Array.isArray(t.args)) {
          throw new Error(`Test "${t.name}": args must be an array`);
        }

        const effectiveTime = 'currentTime' in t ? t.currentTime : data.currentTime;
        const effectiveDns  = Object.assign({}, data.dnsEntries, t.dnsEntries);
        const randomSource  = t.random ? makeRandomSource(t.random, t.name) : null;

        const savedNow      = Date.now;
        const savedResolver = Triauth.config.resolver;
        const savedRandom   = Triauth.config.randomSource;

        Date.now                    = () => effectiveTime;
        Triauth.config.resolver     = new DnsResolverStub(effectiveDns);
        Triauth.config.randomSource = randomSource;

        try {
          const result = await maskStage1(await fn(...t.args), t.args[0]);
          if (RECORDING) {
            if (!('expected' in t) || !isDeepEqual(result, t.expected)) {
              t.expected = result;
              suiteTouched = true;
            }
          } else {
            assert.deepStrictEqual(result, t.expected);
          }
        } finally {
          Date.now                    = savedNow;
          Triauth.config.resolver     = savedResolver;
          Triauth.config.randomSource = savedRandom;
        }
      });
    }

    after(async function () {
      if (RECORDING && suiteTouched) {
        const fs = await import('node:fs');
        fs.writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
      }
    });
  });
}
