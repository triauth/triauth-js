import zone from '../fixtures/dns_test_zone.json' with { type: 'json' };
import { isNode, itNode } from '../env.js';

// The concrete resolvers against real answers

const ENTRIES = { ...zone.names, ...zone.external };
const EXTERNAL = new Set(Object.keys(zone.external));

// Fresh instances per test: the Cloudflare/DnsSb constructors set their TXT flags on the options
// object they receive, so no two resolvers may share one. Retry/timeout settings are the fleet's.
const dohOptions = () => ({ retries: 1, timeout: 4e3 });

// The composition src/index.js installs by default. Under `npm test` Triauth.config.resolver is the
// fixture zone, so the shipped fleet is rebuilt here to be exercised against real answers.
const makeDefaultComposition = () => new Triauth.Resolvers.MultiResolver([
  new Triauth.Resolvers.Cloudflare(dohOptions()),
  new Triauth.Resolvers.Google(dohOptions()),
  new Triauth.Resolvers.NodeDns({ timeout: 4e3 })
], { maxFailures: 1, timeout: 8.5e3 });

const MATRIX = [
  { label: 'Cloudflare', kind: 'doh',   make: () => new Triauth.Resolvers.Cloudflare(dohOptions()) },
  { label: 'Google',     kind: 'doh',   make: () => new Triauth.Resolvers.Google(dohOptions()) },
  { label: 'DnsSb',      kind: 'doh',   make: () => new Triauth.Resolvers.DnsSb(dohOptions()) },
  { label: 'NodeDns',    kind: 'node',  make: () => new Triauth.Resolvers.NodeDns({ timeout: 2e3, tries: 2 }), nodeOnly: true },
  { label: 'MultiResolver (default composition)', kind: 'multi', make: makeDefaultComposition }
];

const it_ = (r) => (r.nodeOnly ? itNode : it);
const queryName = (name, entry) => entry.query ?? name;
const values = (records) => records.map((r) => r.value).sort();
const stripDot = (v) => v.replace(/\.$/, '');
const plain = (options) => Object.assign({}, options);
const sortedConfig = (entries) => entries
  .map(({ key, value, options }) => ({ key, value, options: plain(options) }))
  .sort((a, b) => (a.key + a.value).localeCompare(b.key + b.value));

// One expectation per (resolver kind, entry): {mode:'values', values} | {mode:'min', min} |
// {mode:'reject'} | {mode:'reject-or-resolve'}. Unless the fixture says otherwise, a name resolves
// to its published TXT strings, and a name with no TXT resolves to nothing.
const expectationFor = (kind, entry, spec = entry.expect?.[kind]) => {
  if (typeof spec === 'string') return { mode: spec };
  if (spec?.valuesOf) return { mode: 'values', values: ENTRIES[spec.valuesOf].records.TXT };
  if (spec?.values) return { mode: 'values', values: spec.values };
  if (spec?.minRecords) return { mode: 'min', min: spec.minRecords };
  return { mode: 'values', values: entry.records?.TXT ?? [] };
};

const summary = (exp) => ({
  values: exp.values?.length ? `the ${exp.values.length} published value(s)` : 'an empty answer',
  min: `at least ${exp.min} record(s)`,
  reject: 'a rejection',
  'reject-or-resolve': 'a rejection, or records the system resolver vouches for'
}[exp.mode]);

// Per-record shape by resolver kind: DoH answers carry a TTL within the published bound and the
// response-level AD bit; node:dns carries neither.
const assertShape = (kind, records, name, entry) => {
  const ttlMax = entry.ttl ?? (EXTERNAL.has(name) ? null : zone.defaults.ttl);
  const dnssec = entry.dnssec ?? zone.defaults.dnssec;
  for (const record of records) {
    if (kind === 'node') {
      assert.strictEqual(record.ttl, undefined, `${name}: node:dns reports no TTL`);
      assert.strictEqual(record.dnssec, undefined, `${name}: node:dns reports no DNSSEC status`);
    } else {
      assert(Number.isInteger(record.ttl) && record.ttl > 0 && (ttlMax === null || record.ttl <= ttlMax),
        `${name}: ttl ${record.ttl} must lie in (0, ${ttlMax ?? '∞'}]`);
      assert.strictEqual(record.dnssec, dnssec, `${name}: dnssec must be ${dnssec} ("${record.value}")`);
    }
  }
};

// Settles a resolution into {records} | {error}, retrying a rejection once - one slow provider
// must not fail a cell whose expectation is an answer.
const settle = async (query) => {
  try { return { records: await query() }; } catch (first) {
    try { return { records: await query() }; } catch (error) { return { error, first }; }
  }
};

// A system resolver that cannot deliver a large RRset in full (some NAT resolvers cap the answer
// even over TCP) is an environment limit, not a resolver bug: node:dns then returns a subset and
// the default composition's intersection shrinks with it. Detected from the node:dns outcome alone.
const truncatedBy = (entry, nodeOutcome) => {
  const published = entry.records?.TXT?.length ?? 0;
  const got = nodeOutcome?.records?.length;
  return entry.large && isNode && got > 0 && got < published ? `${got}/${published}` : null;
};

// The cell: mocha context is `this` (function-style tests) so optional samples can go pending.
function assertCell(kind, outcome, name, entry, exp, valueOf = (v) => v) {
  if (exp.mode === 'reject') {
    assert(outcome.error !== undefined, `${name}: expected a rejection, got ${JSON.stringify(outcome.records)}`);
    return;
  }
  if (exp.mode === 'reject-or-resolve') {
    if (outcome.records) assertShape(kind, outcome.records, name, entry);
    return;
  }
  assert(outcome.records !== undefined, `${name}: expected records, got rejection ${String(outcome.error?.message ?? outcome.error)}`);
  const records = outcome.records;
  if (entry.optional) {
    const signedAfterAll = kind !== 'node' && records.some((r) => r.dnssec !== (entry.dnssec ?? zone.defaults.dnssec));
    if (records.length === 0 || signedAfterAll) {
      console.warn(`[zone] optional sample ${name} ${records.length === 0 ? 'answers nothing' : 'no longer matches its DNSSEC expectation'} - pick another sample`);
      return this.skip();
    }
  }
  if (exp.mode === 'min') assert(records.length >= exp.min, `${name}: expected at least ${exp.min} record(s), got ${records.length}`);
  else assert.deepStrictEqual(records.map((r) => valueOf(r.value)).sort(), [...exp.values].sort(), `${name}: value set`);
  assertShape(kind, records, name, entry);
}

export default function() { describe(`DNS test zone (${zone.zone}, published)`, function () {
  this.timeout(20000);
  this.slow(5000);

  if (typeof process !== 'undefined' && process.env?.TRIAUTH_SKIP_ZONE_TESTS) {
    it.skip('skipped by TRIAUTH_SKIP_ZONE_TESTS - offline development');
    return;
  }

  // Fail fast, once, with the reason: an unreachable, unpublished, stale or unsigned zone would
  // otherwise surface as a hundred individual failures.
  before('zone preflight', async function () {
    this.timeout(15000);
    const probe = async (Resolver) => {
      try { return { records: await new Resolver({ retries: 2, timeout: 4e3 }).resolve(zone.zone, 'TXT') }; }
      catch (error) { return { error }; }
    };
    const apex = zone.names[zone.zone].records.TXT;
    const marker = apex.find((v) => v.startsWith('zone-version '));
    const cloudflare = await probe(Triauth.Resolvers.Cloudflare);
    if (cloudflare.error) {
      throw new Error(`${zone.zone} is unreachable through Cloudflare DoH (${cloudflare.error?.message ?? cloudflare.error}) - the zone tests need network access`);
    }
    if (!cloudflare.records.some((r) => r.value === apex[0])) {
      throw new Error(`${zone.zone} publishes no "${apex[0]}" record: the zone is unpublished, or negatively cached for up to 1800 s after publishing. Publish the records listed in test/fixtures/dns_test_zone.json (see test/fixtures/README.md)`);
    }
    const published = cloudflare.records.find((r) => r.value.startsWith('zone-version '))?.value;
    if (published !== marker) {
      throw new Error(`${zone.zone} publishes "${published}" while the fixture is at version ${zone.version}: republish the zone from test/fixtures/dns_test_zone.json`);
    }
    if (!cloudflare.records.every((r) => r.dnssec === true)) {
      const google = await probe(Triauth.Resolvers.Google);
      if (google.records?.every((r) => r.dnssec === true)) {
        console.warn(`[zone] Cloudflare DoH does not validate ${zone.zone} while Google does - 1.1.1.1 has not picked up the DS yet (up to an hour per PoP); dnssec assertions fail until it does`);
      } else {
        throw new Error(`${zone.zone} is not DNSSEC-validated by Cloudflare or Google DoH - is the DS record for triauthdemo.org at the registrar?`);
      }
    }
  });

  for (const [name, entry] of Object.entries(ENTRIES)) {
    const query = queryName(name, entry);

    describe(`${query} - ${entry.exercises}`, function () {
      // One round trip per resolver, all in flight together; the cells assert on the outcomes.
      const txt = {};
      const config = {};
      const typed = {};
      const wantsConfig = entry.config || entry.expect?.resolveConfig;

      before(async function () {
        this.timeout(20000);
        await Promise.all(MATRIX.map(async (r) => {
          txt[r.label] = await settle(() => r.make().resolve(query, 'TXT'));
          if (wantsConfig && (r.kind !== 'node' || entry.config)) {
            config[r.label] = await settle(() => r.make().resolveConfig(query));
          }
          for (const type of Object.keys(entry.queries ?? {})) {
            (typed[type] ??= {})[r.label] = await settle(() => r.make().resolve(query, type));
          }
        }));
      });

      for (const r of MATRIX) {
        const exp = expectationFor(r.kind, entry);
        it_(r)(`${r.label} resolves TXT to ${summary(exp)}`, function () {
          const truncated = r.kind !== 'doh' && truncatedBy(entry, txt['NodeDns']);
          if (truncated) {
            console.warn(`[zone] the system resolver delivers ${truncated} records of ${query}: node:dns and the default composition are pending here`);
            return this.skip();
          }
          assertCell.call(this, r.kind, txt[r.label], query, entry, exp);
        });
      }

      if (entry.config) {
        for (const r of MATRIX) {
          it_(r)(`${r.label} resolveConfig parses the records as published`, function () {
            const outcome = config[r.label];
            assert(outcome.records !== undefined, `${query}: resolveConfig rejected with ${String(outcome.error?.message ?? outcome.error)}`);
            assert.deepStrictEqual(sortedConfig(outcome.records), sortedConfig(entry.config));
            assertShape(r.kind, outcome.records, query, entry);
          });
        }
      }

      if (entry.expect?.resolveConfig) {
        for (const r of MATRIX.filter((r) => r.kind !== 'node')) {
          it(`${r.label} resolveConfig surfaces the failure as error ${entry.expect.resolveConfig}`, function () {
            const { error } = config[r.label];
            assert(error instanceof Triauth.Error && error.code === entry.expect.resolveConfig,
              `${query}: expected Triauth.Error ${entry.expect.resolveConfig}, got ${String(error?.message ?? error)}`);
          });
        }
      }

      for (const [type, spec] of Object.entries(entry.queries ?? {})) {
        for (const r of MATRIX) {
          const exp = expectationFor(r.kind, entry, spec[r.kind]);
          it_(r)(`${r.label} resolves ${type} to ${summary(exp)}`, function () {
            assertCell.call(this, r.kind, typed[type][r.label], query, entry, exp, stripDot);
          });
        }
      }
    });
  }

  describe('the default composition, cross-checked', function () {
    const setName = `set.${zone.zone}`;
    const bigName = `big.${zone.zone}`;

    it('keeps every record of an RRset the three members agree on (intersection loses nothing)', async function () {
      const records = await makeDefaultComposition().resolve(setName, 'TXT');
      assert.deepStrictEqual(values(records), [...ENTRIES[setName].records.TXT].sort());
      const big = await makeDefaultComposition().resolve(bigName, 'TXT');
      const published = ENTRIES[bigName].records.TXT.length;
      if (big.length < published && isNode) {
        const truncated = truncatedBy(ENTRIES[bigName], await settle(() => new Triauth.Resolvers.NodeDns({ timeout: 2e3, tries: 2 }).resolve(bigName, 'TXT')));
        if (truncated) {
          console.warn(`[zone] the system resolver delivers ${truncated} records of ${bigName}: the composition check is pending here`);
          return this.skip();
        }
      }
      assert.equal(big.length, published);
    });

    it('reports dnssec:true from the validating members alone, node:dns abstaining', async function () {
      const records = await makeDefaultComposition().resolve(`plain.${zone.zone}`, 'TXT');
      assert.equal(records.length, 1);
      assert.strictEqual(records[0].dnssec, true);
      assert(records[0].ttl > 0 && records[0].ttl <= zone.defaults.ttl);
    });

    it('rejects a broken DNSSEC chain with the members\' reasons', async function () {
      await assert.rejects(makeDefaultComposition().resolve('dnssec-failed.org', 'TXT'));
      await assert.rejects(makeDefaultComposition().resolveConfig('dnssec-failed.org'),
        (error) => error instanceof Triauth.Error && error.code === 110);
    });
  });

  describe('Triauth.Resolvers.CachingResolver over the default composition', function () {
    this.timeout(30000);

    // Counts what reaches the network; the cache must answer the second query by itself.
    class Counting extends Triauth.Resolvers.Base {
      constructor(inner) { super(); this.inner = inner; this.calls = 0; }
      resolve(...args) { this.calls++; return this.inner.resolve(...args); }
    }

    it('serves the second query from the cache with the remaining TTL, and bypasses it on request', async function () {
      const name = `plain.${zone.zone}`;
      const upstream = new Counting(makeDefaultComposition());
      const cache = new Triauth.Resolvers.CachingResolver(upstream);

      let first = await cache.resolve(name, 'TXT');
      // A record about to expire would leave nothing to serve; take a fresh one instead.
      if (Math.min(...first.map((r) => r.ttl)) < 5) {
        await new Promise((resolve) => setTimeout(resolve, 6000));
        first = await cache.resolve(name, 'TXT');
      }
      const calls = upstream.calls;

      const second = await cache.resolve(name, 'TXT');
      assert.equal(upstream.calls, calls, 'the second query never reaches the network');
      assert.deepStrictEqual(values(second), values(first));
      assert.strictEqual(second[0].dnssec, first[0].dnssec);
      assert(second[0].ttl <= first[0].ttl, 'a cached answer carries the remaining TTL');

      await cache.resolve(name, 'TXT', { cache: false });
      assert.equal(upstream.calls, calls + 1, 'cache:false goes to the network');
    });
  });

}); }
