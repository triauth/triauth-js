# Test fixtures

The JSON conformance suites under `json/` have their own [maintainer guide](json/README.md). This page covers `dns_test_zone.json`, the one fixture that is backed by live DNS.

## The live DNS test zone

`dns_test_zone.json` is the published content of `dns-test.triauthdemo.org`, a Cloudflare-hosted subtree signed through the DS record of `triauthdemo.org`. `test/internals/test_resolvers_zone.js` runs every concrete resolver against each name in the file and compares the answers with the fixture. The resolvers are Cloudflare, Google and DnsSb over HTTPS, node:dns, and the default composition of Cloudflare, Google and node:dns that the library installs. Each entry says what it exercises in its `exercises` field.

### What a run needs

- Network access. Without it, set `TRIAUTH_SKIP_ZONE_TESTS=1`. The suite then reports one skipped entry with that reason, which is the only way to leave it out.
- The zone at the fixture's version. The apex carries a `zone-version N` record, and the preflight fails once, with the reason, when the published version differs from `version` in the file.
- A system resolver that delivers large answers in full. The `big` name publishes 40 records, about 4.7 KB, so the answer has to arrive over TCP, and node:dns depends on the resolver path of the machine for that. Check it before a run:

  ```sh
  node -e "require('node:dns').resolveTxt('big.dns-test.triauthdemo.org',(e,r)=>console.log(e?e.code:r.length+' of 40'))"
  ```

  Anything other than `40 of 40` fails the preflight, and every node:dns-bearing cell of `big`, with one message that names the cause. Point the machine at a full recursive resolver, for example 9.9.9.9 or 1.1.1.1, or a local Unbound. The user-mode networking proxy of QEMU (10.0.2.3) delivers 20 of the 40 records. The Azure-provided resolver (168.63.129.16) behind GitHub's hosted runners delivers 8, now and then without the truncation flag, which is why the workflows point the runners at public resolvers first (`.github/actions/full-resolver`).

### Publishing a change to the zone

1. Edit `dns_test_zone.json` and raise `version` together with the `zone-version` record of the apex.
2. Publish every entry of `names` under its key, with the records of `records`, the TTL of `defaults.ttl` unless the entry has its own `ttl`, in the signed zone. The `*.wild` entry is a wildcard, and its `query` field names the name the tests ask for. `alias` is a CNAME to `plain`. The `_comment` field at the top of the file describes how the logical TXT strings relate to their published form.
3. Wait for the old answers to expire. A name that was unpublished before stays negatively cached for up to 1800 s.
4. Run `npm test -- --grep "DNS test zone"`.

The `external` entries are names outside the zone, `nxdomain.dns-test.invalid`, `dnssec-failed.org` and `github.com`, and are never published by us. An `optional` entry goes pending with a warning when the external name no longer behaves as sampled.
