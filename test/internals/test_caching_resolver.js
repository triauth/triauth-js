// A counting inner resolver: tracks upstream calls, supports per-test record changes,
// injected failures, and a settle delay (for the coalescing tests).
class CountingResolverStub extends Triauth.Resolvers.Base {

  constructor(domainRecords = {}) {
    super();
    this.domainRecords = domainRecords;
    this.calls = 0;
    this.error = null;
    this.delay = 0;
  }

  resolve(domainName, type) {
    this.calls++;

    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (this.error) {
          return reject(this.error);
        }
        // Hand out fresh record objects, like real resolvers do
        resolve(((this.domainRecords[domainName] || {})[type] || []).map((r) => ({...r})));
      }, this.delay);
    });
  }
}

export default function() { describe('Triauth.Resolvers.CachingResolver', () => {

  const REAL_NOW = Date.now;
  let now;

  const makeRecords = () => ({'cache.test': {'TXT': [{value: 'key AAAA', ttl: 60, dnssec: true}]}});

  beforeEach(() => {
    now = REAL_NOW();
    Date.now = () => now;
  });

  afterEach(() => {
    Date.now = REAL_NOW;
  });

  it('serves repeated queries from the cache within the TTL', async () => {
    const inner = new CountingResolverStub(makeRecords());
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    let records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1);
    assert.equal(records[0].value, 'key AAAA');
    assert.equal(records[0].ttl, 60);
    assert.equal(records[0].dnssec, true);

    now += 30 * 1000;
    records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1, 'second query must be served from the cache');
    assert.equal(records[0].value, 'key AAAA');
    assert.equal(records[0].dnssec, true);
  });

  it('serves cached records with the remaining, not the original, TTL', async () => {
    const inner = new CountingResolverStub(makeRecords());
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    await resolver.resolve('cache.test', 'TXT');

    now += 25 * 1000;
    const records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1);
    assert.equal(records[0].ttl, 35, 'cached record must report the remaining TTL');
  });

  it('re-queries once the record TTL has passed', async () => {
    const inner = new CountingResolverStub(makeRecords());
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    await resolver.resolve('cache.test', 'TXT');

    now += 60 * 1000;
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2, 'expired cache entries must not be served');
  });

  it('caps the cache lifetime at maxTtl', async () => {
    const inner = new CountingResolverStub({'cache.test': {'TXT': [{value: 'key AAAA', ttl: 3600, dnssec: true}]}});
    const resolver = new Triauth.Resolvers.CachingResolver(inner, {maxTtl: 10});

    await resolver.resolve('cache.test', 'TXT');

    now += 9 * 1000;
    const records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1);
    assert.equal(records[0].ttl, 3591, 'the record TTL itself is not capped, only the cache lifetime');

    now += 1 * 1000;
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2, 'entries must not be served from the cache for longer than maxTtl');
  });

  it('uses the shortest TTL across records as the cache lifetime', async () => {
    const inner = new CountingResolverStub({'cache.test': {'TXT': [
      {value: 'key AAAA', ttl: 60, dnssec: true},
      {value: 'key BBBB', ttl: 5, dnssec: true}
    ]}});
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    await resolver.resolve('cache.test', 'TXT');

    now += 4 * 1000;
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1);

    now += 1 * 1000;
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2);
  });

  it('does not cache answers with ttl:0 records, and caches nothing when maxTtl is 0', async () => {
    let inner = new CountingResolverStub({'cache.test': {'TXT': [{value: 'key AAAA', ttl: 0, dnssec: true}]}});
    let resolver = new Triauth.Resolvers.CachingResolver(inner);

    await resolver.resolve('cache.test', 'TXT');
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2, 'ttl:0 means "do not cache"');

    inner = new CountingResolverStub(makeRecords());
    resolver = new Triauth.Resolvers.CachingResolver(inner, {maxTtl: 0});

    await resolver.resolve('cache.test', 'TXT');
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2, 'maxTtl:0 must disable caching');
  });

  it('does not cache records that carry no TTL by default', async () => {
    const inner = new CountingResolverStub({'cache.test': {'TXT': [{value: 'key AAAA', ttl: undefined, dnssec: undefined}]}});
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    await resolver.resolve('cache.test', 'TXT');
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2);
  });

  it('caches TTL-less records for defaultTtl seconds when configured, keeping their TTL undefined', async () => {
    const inner = new CountingResolverStub({'cache.test': {'TXT': [{value: 'key AAAA', ttl: undefined, dnssec: undefined}]}});
    const resolver = new Triauth.Resolvers.CachingResolver(inner, {defaultTtl: 30});

    await resolver.resolve('cache.test', 'TXT');

    now += 29 * 1000;
    const records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1);
    assert.equal(records[0].ttl, undefined, 'a TTL the origin did not provide must not be invented');
    assert.equal(records[0].dnssec, undefined);

    now += 1 * 1000;
    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2);
  });

  it('does not cache empty answers by default', async () => {
    const inner = new CountingResolverStub({});
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    assert.deepEqual(await resolver.resolve('missing.test', 'TXT'), []);
    assert.deepEqual(await resolver.resolve('missing.test', 'TXT'), []);
    assert.equal(inner.calls, 2);
  });

  it('caches empty answers for negativeTtl seconds when configured', async () => {
    const inner = new CountingResolverStub({});
    const resolver = new Triauth.Resolvers.CachingResolver(inner, {negativeTtl: 5});

    assert.deepEqual(await resolver.resolve('missing.test', 'TXT'), []);
    assert.deepEqual(await resolver.resolve('missing.test', 'TXT'), []);
    assert.equal(inner.calls, 1);

    now += 5 * 1000;
    await resolver.resolve('missing.test', 'TXT');
    assert.equal(inner.calls, 2);
  });

  it('never caches failed resolutions', async () => {
    const inner = new CountingResolverStub(makeRecords());
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    inner.error = new Error('resolution failed');
    await assert.rejects(resolver.resolve('cache.test', 'TXT'), /resolution failed/);
    assert.equal(inner.calls, 1);

    inner.error = null;
    const records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2, 'the failure must not have been cached');
    assert.equal(records[0].value, 'key AAAA');

    await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2, 'the subsequent success must have been cached');
  });

  it('bypasses the cache entirely (no read, no write) when called with cache:false', async () => {
    const inner = new CountingResolverStub({'cache.test': {'TXT': [{value: 'key OLD', ttl: 60, dnssec: true}]}});
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    await resolver.resolve('cache.test', 'TXT'); // populates the cache with 'key OLD'
    inner.domainRecords['cache.test']['TXT'] = [{value: 'key NEW', ttl: 60, dnssec: true}];

    const fresh = await resolver.resolve('cache.test', 'TXT', {cache: false});
    assert.equal(inner.calls, 2, 'cache:false must not read from the cache');
    assert.equal(fresh[0].value, 'key NEW');

    const cached = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 2);
    assert.equal(cached[0].value, 'key OLD', 'cache:false must not write to the cache');
  });

  it('keys the cache by record type and domain name, case-insensitively for the type', async () => {
    const inner = new CountingResolverStub({
      'a.test': {'TXT': [{value: 'key AAAA', ttl: 60, dnssec: true}], 'A': [{value: '192.0.2.1', ttl: 60, dnssec: true}]},
      'b.test': {'TXT': [{value: 'key BBBB', ttl: 60, dnssec: true}]}
    });
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    assert.equal((await resolver.resolve('a.test', 'TXT'))[0].value, 'key AAAA');
    assert.equal((await resolver.resolve('a.test', 'A'))[0].value, '192.0.2.1');
    assert.equal((await resolver.resolve('b.test', 'TXT'))[0].value, 'key BBBB');
    assert.equal(inner.calls, 3, 'different domains/types must not collide in the cache');

    assert.equal((await resolver.resolve('a.test', 'txt'))[0].value, 'key AAAA');
    assert.equal((await resolver.resolve('a.test', 'A'))[0].value, '192.0.2.1');
    assert.equal((await resolver.resolve('b.test', 'TXT'))[0].value, 'key BBBB');
    assert.equal(inner.calls, 3, 'repeated queries (incl. differently-cased types) must be served from the cache');
  });

  it('coalesces concurrent queries for the same records into a single upstream query', async () => {
    const inner = new CountingResolverStub(makeRecords());
    inner.delay = 20;
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    const [r1, r2] = await Promise.all([
      resolver.resolve('cache.test', 'TXT'),
      resolver.resolve('cache.test', 'TXT')
    ]);

    assert.equal(inner.calls, 1, 'concurrent queries must share a single upstream call');
    assert.equal(r1[0].value, 'key AAAA');
    assert.equal(r2[0].value, 'key AAAA');
    assert.notEqual(r1[0], r2[0], 'each caller must get its own copy of the records');
  });

  it('shares a coalesced failure with all waiting callers, without caching it', async () => {
    const inner = new CountingResolverStub(makeRecords());
    inner.delay = 20;
    inner.error = new Error('resolution failed');
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    const settled = await Promise.allSettled([
      resolver.resolve('cache.test', 'TXT'),
      resolver.resolve('cache.test', 'TXT')
    ]);

    assert.equal(inner.calls, 1);
    assert.equal(settled[0].status, 'rejected');
    assert.equal(settled[1].status, 'rejected');

    inner.error = null;
    assert.equal((await resolver.resolve('cache.test', 'TXT'))[0].value, 'key AAAA');
    assert.equal(inner.calls, 2);
  });

  it('does not coalesce queries that carry an abort signal', async () => {
    const inner = new CountingResolverStub(makeRecords());
    inner.delay = 20;
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    await Promise.all([
      resolver.resolve('cache.test', 'TXT', {signal: new AbortController().signal}),
      resolver.resolve('cache.test', 'TXT', {signal: new AbortController().signal})
    ]);

    assert.equal(inner.calls, 2, 'signal-carrying callers must each get their own upstream query');
  });

  it('is immune to mutations of the records it returned', async () => {
    const inner = new CountingResolverStub(makeRecords());
    const resolver = new Triauth.Resolvers.CachingResolver(inner);

    // Mutate the freshly resolved answer, the way an enclosing MultiResolver would
    const fresh = await resolver.resolve('cache.test', 'TXT');
    fresh[0].value = 'key EVIL';
    fresh[0].ttl = 1;
    fresh[0].dnssec = false;

    const cached = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1);
    assert.equal(cached[0].value, 'key AAAA');
    assert.equal(cached[0].ttl, 60);
    assert.equal(cached[0].dnssec, true);

    // Mutating a cache-hit answer must not corrupt the cache either
    cached[0].dnssec = false;
    assert.equal((await resolver.resolve('cache.test', 'TXT'))[0].dnssec, true);
  });

  it('supports a custom asynchronous store with serialization (e.g., Redis-like)', async () => {
    const backing = new Map();
    const ops = [];
    const store = {
      get: async (key) => { ops.push(['get', key]); return backing.has(key) ? JSON.parse(backing.get(key)) : null; },
      set: async (key, value) => { ops.push(['set', key]); backing.set(key, JSON.stringify(value)); }
    };

    const inner = new CountingResolverStub(makeRecords());
    const resolver = new Triauth.Resolvers.CachingResolver(inner, {store});

    await resolver.resolve('cache.test', 'TXT');

    now += 10 * 1000;
    const records = await resolver.resolve('cache.test', 'TXT');
    assert.equal(inner.calls, 1, 'the answer must survive the store serialization round-trip');
    assert.equal(records[0].value, 'key AAAA');
    assert.equal(records[0].ttl, 50);
    assert.equal(records[0].dnssec, true);

    assert.deepEqual(ops, [['get', 'TXT:cache.test'], ['set', 'TXT:cache.test'], ['get', 'TXT:cache.test']]);
  });

  it('fails open (to a fresh resolution) when the store fails or returns garbage', async () => {
    const inner = new CountingResolverStub(makeRecords());

    // A store that always throws
    let resolver = new Triauth.Resolvers.CachingResolver(inner, {store: {
      get: () => { throw new Error('store read failed'); },
      set: () => { throw new Error('store write failed'); }
    }});

    assert.equal((await resolver.resolve('cache.test', 'TXT'))[0].value, 'key AAAA');
    assert.equal((await resolver.resolve('cache.test', 'TXT'))[0].value, 'key AAAA');
    assert.equal(inner.calls, 2, 'a failing store must not break resolution');

    // A store that returns malformed entries
    for (const garbage of ['garbage', {}, {records: [], storedAt: 'x', expiresAt: 'y'}, 42]) {
      inner.calls = 0;
      resolver = new Triauth.Resolvers.CachingResolver(inner, {store: {get: () => garbage, set: () => {}}});

      assert.equal((await resolver.resolve('cache.test', 'TXT'))[0].value, 'key AAAA');
      assert.equal(inner.calls, 1, `a malformed cache entry (${JSON.stringify(garbage)}) must be treated as a miss`);
    }
  });

  it('integrates with resolveConfig and the recommended MultiResolver composition', async () => {
    const innerA = new CountingResolverStub({'config.test': {'TXT': [{value: 'key AAAA opt=1', ttl: 20, dnssec: true}]}});
    const innerB = new CountingResolverStub({'config.test': {'TXT': [{value: 'key AAAA opt=1', ttl: 10, dnssec: true}]}});

    const resolver = new Triauth.Resolvers.CachingResolver(
      new Triauth.Resolvers.MultiResolver([innerA, innerB], {maxFailures: 0})
    );

    let entries = await resolver.resolveConfig('config.test');
    assert.equal(entries.length, 1);
    assert.equal(entries[0].key, 'key');
    assert.equal(entries[0].value, 'AAAA');
    assert.equal(entries[0].options['opt'], '1');
    assert.equal(entries[0].ttl, 10);
    assert.equal(entries[0].dnssec, true);

    now += 5 * 1000;
    entries = await resolver.resolveConfig('config.test');
    assert.equal(innerA.calls, 1);
    assert.equal(innerB.calls, 1, 'one cache hit must save the queries to all wrapped providers');
    assert.equal(entries[0].ttl, 5, 'remaining TTL must propagate through resolveConfig');
  });

}); }
