import DnsResolverStub from '../stubs/dns_resolver.js';

const ACTOR_KEY = 'BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8';

// A resolver stub serving one actor identity, used by the find() tests below.
const actorResolver = () => new DnsResolverStub({
  'actor.example': { TXT: ['triauth auth.actor.example mode=public'] },
  'actor._at.actor.example': { TXT: [`key server[1/1]:${ACTOR_KEY}`] },
});

const ANY = { includePolicy: ['any'] };

// Every grant publishes a scope; `anyScope` spells the sole-entry form that covers every service host.
const anyScope = (options = {}) => ({ scope: 'any', ...options });

export default function() { describe('Triauth.IdentityIncludes', () => {

  describe('Triauth.IdentityIncludes.parsePolicy', () => {
    it('defaults an unpublished include option to any', () => {
      assert.deepEqual(Triauth.IdentityIncludes.parsePolicy(undefined), ['any']);
    });

    it('splits and lowercases the published option', () => {
      assert.deepEqual(Triauth.IdentityIncludes.parsePolicy('LOCAL,Partner.Example'), ['local', 'partner.example']);
      assert.deepEqual(Triauth.IdentityIncludes.parsePolicy('any'), ['any']);
      assert.deepEqual(Triauth.IdentityIncludes.parsePolicy('none'), ['none']);
    });
  });

  describe('Triauth.IdentityIncludes.add', () => {

    describe('include policy', () => {
      it('accepts any ref under a sole any policy', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@other.example', anyScope(), ANY), true);
      });

      it('rejects every ref when the policy is absent (fail closed)', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@other.example', anyScope()), false);
        assert.equal(inc.includes.length, 0);
      });

      it('none rejects every ref and dominates any combination', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@other.example', anyScope(), { includePolicy: ['none'] }), false);
        assert.equal(await inc.add('a@other.example', anyScope(), { includePolicy: ['none', 'any'] }), false);
        assert.equal(await inc.add('a@other.example', anyScope(), { includePolicy: ['none', 'other.example'] }), false);
      });

      it('local admits only refs on localDomainName', async () => {
        const inc = new Triauth.IdentityIncludes();
        const meta = { includePolicy: ['local'], localDomainName: 'subject.example' };
        assert.equal(await inc.add('a@subject.example', anyScope(), meta), true);
        assert.equal(await inc.add('a@other.example', anyScope(), meta), false);
      });

      it('domain entries act as an exact allowlist', async () => {
        const inc = new Triauth.IdentityIncludes();
        const meta = { includePolicy: ['local', 'partner.example'], localDomainName: 'subject.example' };
        assert.equal(await inc.add('a@partner.example', anyScope(), meta), true);
        assert.equal(await inc.add('a@sub.partner.example', anyScope(), meta), false);
      });

      it('any is honored only as the sole policy entry', async () => {
        const inc = new Triauth.IdentityIncludes();
        const meta = { includePolicy: ['any', 'partner.example'], localDomainName: 'subject.example' };
        assert.equal(await inc.add('a@partner.example', anyScope(), meta), true);
        assert.equal(await inc.add('a@other.example', anyScope(), meta), false);
      });
    });

    describe('ref forms', () => {
      it('accepts identifier refs, lowercasing them', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('Actor@Example.com', anyScope(), ANY), true);
        assert.equal(inc.includes[0].ref, 'actor@example.com');
        assert.equal(inc.includes[0].domainName, 'example.com');
      });

      it('accepts identity-domain refs, public and private (leading underscore) forms', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('actor._at.corp.example', anyScope(), ANY), true);
        assert.equal(await inc.add('_4GIBDU53B3._at.private.corp.example', anyScope(), ANY), true);
        assert.equal(inc.includes[1].ref, '_4gibdu53b3._at.private.corp.example');
        assert.equal(inc.includes[1].domainName, 'private.corp.example');
      });

      it('rejects refs with interior underscores, doubled ._at. markers, or no marker at all', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('_a_l_i_c_e._at.corp.example', anyScope(), ANY), false);
        assert.equal(await inc.add('actor._at.corp._at.example.com', anyScope(), ANY), false);
        assert.equal(await inc.add('corp.example', anyScope(), ANY), false);
        assert.equal(inc.includes.length, 0);
      });
    });

    describe('options', () => {
      it('defaults an absent use option to every flow', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', anyScope(), ANY), true);
        assert.equal(inc.includes[0].options.use, 'attest,auth,ping,sign,stamp');
      });

      it('rejects an explicitly empty or invalid use option (fail closed, no default substitution)', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', anyScope({ use: '' }), ANY), false);
        assert.equal(await inc.add('a@x.example', anyScope({ use: 'bogus' }), ANY), false);
        assert.equal(inc.includes.length, 0);
      });

      it('rejects unknown critical options and keeps x- experimental ones', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', anyScope({ evil: '1' }), ANY), false);
        assert.equal(await inc.add('a@x.example', anyScope({ 'x-note': 'hello' }), ANY), true);
      });

      it('does not mutate the caller-supplied options object', async () => {
        const inc = new Triauth.IdentityIncludes();
        const options = anyScope();
        await inc.add('a@x.example', options, ANY);
        assert.deepEqual(options, { scope: 'any' });
      });
    });

    describe('the scope option', () => {
      it('accepts a host allowlist, storing the published spelling in options and the parsed form beside it', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', { scope: 'svc.example' }, ANY), true);
        assert.equal(inc.includes[0].options.scope, 'svc.example');
        assert.deepEqual(inc.includes[0].scope, ['svc.example']);
        assert.deepEqual(inc.includes[0].use, ['attest', 'auth', 'ping', 'sign', 'stamp']);
      });

      it('ignores a record publishing no scope option (fail closed, no default)', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', {}, ANY), false);
        assert.equal(await inc.add('a@x.example', { use: 'sign' }, ANY), false);
        assert.equal(inc.includes.length, 0);
      });

      it('accepts any as the sole entry: options keep the literal spelling and the parsed scope is null (every service host)', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', { scope: 'any' }, ANY), true);
        assert.equal(inc.includes[0].options.scope, 'any');
        assert.strictEqual(inc.includes[0].scope, null);
      });

      it('accepts multi-entry lists with duplicates, IPv4 quads, and single-label hosts', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', { scope: 'a.example,b.example,a.example' }, ANY), true);
        assert.deepEqual(inc.includes[0].scope, ['a.example', 'b.example', 'a.example']);
        assert.equal(await inc.add('b@x.example', { scope: '10.0.0.5,localhost' }, ANY), true);
      });

      it('rejects the record whenever any entry is not a canonical callback host (fail closed, never repaired)', async () => {
        const inc = new Triauth.IdentityIncludes();
        for (const scope of [
          '',                        // empty value - like an empty use, never defaulted
          'SVC.Example',             // hosts are lowercase
          'ANY',                     // values are literal and case-sensitive - the sole-entry keyword included
          'Any',
          'svc.example:8443',        // a port is not part of a host - scope matching is port-blind
          'xn--mller-kva.de',        // no Punycode labels, valid encodings included
          'bad.123',                 // a numeric final label is never a named host
          '0x7f.0.0.1',              // exotic IPv4 spellings match no production
          'svc.example,',            // an empty list slot
          ',svc.example',
          'svc.example,|garbage|',   // one bad entry drops the whole record
          'svc.example/path',        // a path is not a host
          'a..b'
        ]) {
          assert.equal(await inc.add('a@x.example', { scope }, ANY), false, `scope=${scope}`);
        }
        assert.equal(inc.includes.length, 0);
      });

      it('rejects a non-string scope value', async () => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('a@x.example', { scope: 42 }, ANY), false);
        assert.equal(await inc.add('a@x.example', { scope: ['svc.example'] }, ANY), false);
      });

      it('rejects none anywhere and any beside other entries - any is only the sole-entry spelling', async () => {
        const inc = new Triauth.IdentityIncludes();
        for (const scope of ['none', 'any,svc.example', 'svc.example,any', 'none,svc.example', 'any,none', 'any,any']) {
          assert.equal(await inc.add('a@x.example', { scope }, ANY), false, `scope=${scope}`);
        }
        assert.equal(inc.includes.length, 0);
      });
    });

    describe('grant tags', () => {
      const tagFor = async (options) => {
        const inc = new Triauth.IdentityIncludes();
        assert.equal(await inc.add('actor@x.example', options, ANY), true);
        return inc.includes[0].tag;
      };

      it('derives a stable 43-character tag from the ref and critical options only', async () => {
        const a = new Triauth.IdentityIncludes();
        const b = new Triauth.IdentityIncludes();
        await a.add('actor@x.example', anyScope({ use: 'sign' }), ANY);
        await b.add('actor@x.example', anyScope({ use: 'sign', 'x-note': 'ignored' }), ANY);
        assert.equal(a.includes[0].tag.length, 43);
        assert.equal(a.includes[0].tag, b.includes[0].tag);

        const c = new Triauth.IdentityIncludes();
        await c.add('actor@x.example', anyScope({ use: 'auth' }), ANY);
        assert.notEqual(a.includes[0].tag, c.includes[0].tag);
      });

      it('folds the published scope into the tag - scope=any and a host list never share a tag', async () => {
        const unrestricted = await tagFor({ use: 'sign', scope: 'any' });
        const scoped = await tagFor({ use: 'sign', scope: 'svc.example' });
        assert.notEqual(unrestricted, scoped);
        assert.notEqual(scoped, await tagFor({ use: 'sign', scope: 'other.example' }));
        assert.equal(scoped, await tagFor({ use: 'sign', scope: 'svc.example' }));
      });

      it('hashes the literal scope=any pair into the grant tag preimage', async () => {
        assert.equal(
          await tagFor({ use: 'sign', scope: 'any' }),
          await Triauth.Helpers.sha256('\x01actor@x.example\x02scope=any\x1Euse=sign')
        );
      });
    });

    describe('the maxIncludes cap', () => {
      it('accepts LIMITS.maxIncludes grants and skips (only) the excess, without paying their hash', async () => {
        const inc = new Triauth.IdentityIncludes();
        for (let i = 0; i < Triauth.LIMITS.maxIncludes; i++) {
          assert.equal(await inc.add(`a${i}@x.example`, anyScope(), ANY), true);
        }
        assert.equal(inc.includes.length, Triauth.LIMITS.maxIncludes);

        let digests = 0;
        const realDigest = crypto.subtle.digest.bind(crypto.subtle);
        crypto.subtle.digest = (...args) => { digests++; return realDigest(...args); };
        try {
          assert.equal(await inc.add('overflow@x.example', anyScope(), ANY), false);
        } finally {
          crypto.subtle.digest = realDigest;
        }
        assert.equal(digests, 0, 'the over-cap record must be skipped before its tag is hashed');
        assert.equal(inc.includes.length, Triauth.LIMITS.maxIncludes, 'accepted grants stay usable');
      });
    });
  });

  describe('Triauth.IdentityIncludes.list', () => {
    it('returns the include statements ordered by tag, whatever the publication order', async () => {
      const inc = new Triauth.IdentityIncludes();
      await inc.add('c@x.example', anyScope(), ANY);
      await inc.add('a@x.example', anyScope({ use: 'sign' }), ANY);
      await inc.add('b._at.x.example', anyScope(), ANY);

      const listed = inc.list();
      assert.equal(listed.length, 3);
      assert.deepEqual(listed.map((i) => i.tag), listed.map((i) => i.tag).slice().sort());
      assert.deepEqual(listed.map((i) => i.ref).slice().sort(), ['a@x.example', 'b._at.x.example', 'c@x.example']);
    });

    it('returns an empty array when the identity publishes no grants', () => {
      assert.deepEqual(new Triauth.IdentityIncludes().list(), []);
    });

    it('returns a copy - reordering it leaves the canonical order intact', async () => {
      const inc = new Triauth.IdentityIncludes();
      await inc.add('a@x.example', anyScope(), ANY);
      await inc.add('b@x.example', anyScope(), ANY);

      const canonical = inc.list().map((i) => i.tag);
      inc.list().reverse();
      assert.deepEqual(inc.list().map((i) => i.tag), canonical);
    });
  });

  describe('Triauth.IdentityIncludes.find', () => {
    const grantedInc = async (use) => {
      const inc = new Triauth.IdentityIncludes();
      await inc.add('actor@actor.example', anyScope(use ? { use } : {}), ANY);
      return inc;
    };
    const actorIdentity = () => new Triauth.Identity('actor@actor.example', {}, { resolver: actorResolver() });

    it('returns the matching include statement for a granted mode', async () => {
      const inc = await grantedInc('sign');
      const match = await inc.find(actorIdentity(), null, 'sign');
      assert.equal(match?.ref, 'actor@actor.example');
    });

    it('returns null when the mode is not granted, and skips the use check for a null mode (liveness)', async () => {
      const inc = await grantedInc('sign');
      assert.equal(await inc.find(actorIdentity(), null, 'auth'), null);
      assert.notEqual(await inc.find(actorIdentity(), null, null), null);
    });

    it('pins the grant when includeTag is given: matching tag found, unknown tag null', async () => {
      const inc = await grantedInc('sign');
      const tag = inc.includes[0].tag;
      assert.notEqual(await inc.find(actorIdentity(), tag, 'sign'), null);
      assert.equal(await inc.find(actorIdentity(), 'A'.repeat(43), 'sign'), null);
    });

    it('selects deterministically among multiple covering grants: the lexicographically least tag wins, whatever the add order', async () => {
      const grants = [{ use: 'sign' }, { use: 'sign,stamp' }, {}].map((options) => anyScope(options));
      const tagOf = async (ordering) => {
        const inc = new Triauth.IdentityIncludes();
        for (const options of ordering) assert.equal(await inc.add('actor@actor.example', options, ANY), true);
        return (await inc.find(actorIdentity(), null, 'sign')).tag;
      };

      const picked = await tagOf(grants);
      assert.equal(picked, await tagOf([...grants].reverse()));

      const inc = new Triauth.IdentityIncludes();
      for (const options of grants) await inc.add('actor@actor.example', options, ANY);
      assert.equal(picked, inc.includes.map((i) => i.tag).sort()[0]);
    });

    it('returns false when the actor identity cannot be resolved (distinct from a revoked grant)', async () => {
      const inc = new Triauth.IdentityIncludes();
      await inc.add('ghost@dead.example', anyScope(), ANY);
      const ghost = new Triauth.Identity('ghost@dead.example', {}, { resolver: new DnsResolverStub({}) });
      assert.equal(await inc.find(ghost, null, 'auth'), false);
    });

    it('gates on the service host: a scoped grant matches its listed hosts exactly, and a null host skips the check (liveness)', async () => {
      const inc = new Triauth.IdentityIncludes();
      await inc.add('actor@actor.example', { scope: 'svc.example,alt.example' }, ANY);
      assert.notEqual(await inc.find(actorIdentity(), null, 'auth', 'svc.example'), null);
      assert.notEqual(await inc.find(actorIdentity(), null, 'auth', 'alt.example'), null);
      assert.equal(await inc.find(actorIdentity(), null, 'auth', 'sub.svc.example'), null, 'subdomains do not inherit');
      assert.equal(await inc.find(actorIdentity(), null, 'auth', 'other.example'), null);
      assert.notEqual(await inc.find(actorIdentity(), null, 'auth', null), null);
      assert.notEqual(await inc.find(actorIdentity(), null, 'auth'), null);
    });

    it('a scope=any grant covers every service host', async () => {
      const inc = await grantedInc('sign');
      assert.notEqual(await inc.find(actorIdentity(), null, 'sign', 'anywhere.example'), null);
      assert.notEqual(await inc.find(actorIdentity(), null, 'sign', '10.0.0.5'), null);
    });

    it('scope filters the covering set before the deterministic least-tag pick', async () => {
      const mk = async (ordering) => {
        const inc = new Triauth.IdentityIncludes();
        for (const options of ordering) assert.equal(await inc.add('actor@actor.example', options, ANY), true);
        return inc;
      };
      const grants = [{ scope: 'svc.example' }, { scope: 'any' }];
      const incA = await mk(grants);
      const incB = await mk([...grants].reverse());

      // At a host both grants cover, the least tag wins, whatever the add order
      const atSvcA = await incA.find(actorIdentity(), null, 'auth', 'svc.example');
      const atSvcB = await incB.find(actorIdentity(), null, 'auth', 'svc.example');
      assert.equal(atSvcA.tag, atSvcB.tag);
      assert.equal(atSvcA.tag, incA.includes.map((i) => i.tag).sort()[0]);

      // At a host outside the scoped grant's list, only the scope=any grant covers
      const atOther = await incA.find(actorIdentity(), null, 'auth', 'other.example');
      assert.equal(atOther.options.scope, 'any');
    });
  });
}); }
