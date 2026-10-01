import identifiersFixture from './fixtures/identifiers.json' with { type: 'json' };
import DnsResolverStub from './stubs/dns_resolver.js';
import { LIMITS } from '../src/protocol.js';

describe('Identity API', () => {

  describe('Triauth.Identity.resolve (private mode)', () => {

    // The lookup code is a construction-time property of the Identity: it selects the identity
    // domain the records are read from, and the commit record makes those records exist only through the
    // commitment over the derivation actually performed.
    const LOOKUP_CODE = 'K7QJ3FB9M2WZX0C4';
    const IDENTITY_DOMAIN = '_4GIBDU53B3._at.private.triauthdemo.org';
    const COMMITMENT = '3Q7YSpb3MLMRaQ20VZBUfoySyM4vQrHMfIIuAxER3_s';

    const privateResolver = (records) => new DnsResolverStub({
      'private.triauthdemo.org': { TXT: ['triauth auth.private.triauthdemo.org mode=private'] },
      [IDENTITY_DOMAIN]: { TXT: records },
    });

    const records = ['name John Doe', `commit ${COMMITMENT}`];

    it('resolves through the lookup code, and reports the derived identity domain', async () => {
      const identity = new Triauth.Identity('john@private.triauthdemo.org', { lookupCode: LOOKUP_CODE }, { resolver: privateResolver(records) });

      assert.equal(await identity.resolve(), true);
      assert.equal(identity.identityDomain.domainName, IDENTITY_DOMAIN);
      assert.equal(identity.publicProfile.name, 'John Doe');
    });

    it('never resolves without a lookup code - no identity domain can be derived', async () => {
      const identity = new Triauth.Identity('john@private.triauthdemo.org', {}, { resolver: privateResolver(records) });

      assert.equal(await identity.resolve(), false);
      assert.equal(identity.identityDomain.domainName, null);
    });

    it('never resolves when the commit record does not bind the derivation performed', async () => {
      for (const commitRecords of [
        [],                                                       // commitment absent
        [`commit ${'A'.repeat(43)}`],                             // commitment mismatched
        [`commit ${COMMITMENT} evil=1`],                          // unknown critical option - malformed record
        [`commit ${COMMITMENT}`, `commit ${'A'.repeat(43)}`],     // doubled - the label-merge tripwire
      ]) {
        const identity = new Triauth.Identity('john@private.triauthdemo.org', { lookupCode: LOOKUP_CODE },
          { resolver: privateResolver(['name John Doe', ...commitRecords]) });

        assert.equal(await identity.resolve(), false, JSON.stringify(commitRecords));
      }
    });

  });

  describe('Triauth.whois', () => {

    it('returns correct identity details for valid identifiers', async () => {
      const whoisResult = await Triauth.whois({identifier: 'john@triauthdemo.org'});
      assert.equal(whoisResult?.status, 1);

      const publicProfile = whoisResult.publicProfile;
      return assert.equal(publicProfile.name, 'John Doe');
    });

    it('works with utf-8 encoded identity details', async () => {
      const whoisResult = (await Triauth.whois({identifier: 'frederic@triauthdemo.org'}));
      return assert.equal(whoisResult.publicProfile.name, 'Frédéric Łukasiewicz');
    });

    it('returns {status:0} for missing identifiers under domains configured for triauth', async () => {
      const identifiers = ['missing-identifier@triauthdemo.org'];
      for (const identifier of identifiers) {
        const whoisRes = (await Triauth.whois({identifier}));
        assert.equal(whoisRes?.status, 0);
      }
    });

    it('returns {error} for invalid identifiers', async () => {
      const {invalidIdentifiers, emptyIdentifiers} = identifiersFixture;
      const results = [];
      for (const invalidIdentifier in invalidIdentifiers) {
        const errorMsg = invalidIdentifiers[invalidIdentifier];
        const whoisRes = (await Triauth.whois({identifier: invalidIdentifier}));
        results.push(assert(whoisRes.error));
      }
      return results;
    });

    it('returns {error} upon resolver failure', async () => {
      const identifiers = ['a@dnssec-failed.org'];
      for (const identifier of identifiers) {
        const whoisRes = (await Triauth.whois({identifier}));
        assert.equal(whoisRes.error.code, 110);
      }
    });

    it('returns {status:-1} if domain does not exist or is not configured for triauth', async () => {
      const identifiers = ['john@example.com', 'john@e.com'];
      for (const identifier of identifiers) {
        const whoisRes = (await Triauth.whois({identifier}));
        assert.equal(whoisRes?.status, -1);
      }
    });

    it('status-1 result includes identityDomain, authenticationEndpoint, and well-formed devices array', async () => {
      const whoisRes = await Triauth.whois({identifier: 'john@triauthdemo.org'});
      assert.equal(whoisRes.status, 1);

      assert(typeof whoisRes.identityDomain === 'string' && whoisRes.identityDomain.length > 0);

      assert(typeof whoisRes.authenticationEndpoint === 'object');
      assert(typeof whoisRes.authenticationEndpoint.url === 'string' && whoisRes.authenticationEndpoint.url.length > 0);
      assert(typeof whoisRes.authenticationEndpoint.options === 'object');
      assert(typeof whoisRes.authenticationEndpoint.secure === 'boolean');

      assert(typeof whoisRes.secure === 'boolean', 'the resolution-level DNSSEC status is a top-level flag');

      assert(Array.isArray(whoisRes.devices) && whoisRes.devices.length > 0);
      for (const device of whoisRes.devices) {
        assert(typeof device.deviceName === 'string' && device.deviceName.length > 0);
        assert(typeof device.deviceTag === 'string' && device.deviceTag.length > 0);
        assert(Array.isArray(device.keys) && device.keys.length > 0);
        assert(typeof device.keys[0].value === 'string');
        assert(typeof device.keys[0].options === 'object');
      }
    });

    it('status-0 result includes authenticationEndpoint and identityDomain', async () => {
      const whoisRes = await Triauth.whois({identifier: 'missing-identifier@triauthdemo.org'});
      assert.equal(whoisRes.status, 0);

      assert(typeof whoisRes.identityDomain === 'string' && whoisRes.identityDomain.length > 0);
      assert(typeof whoisRes.authenticationEndpoint === 'object');
      assert(typeof whoisRes.authenticationEndpoint.url === 'string' && whoisRes.authenticationEndpoint.url.length > 0);
      assert(typeof whoisRes.authenticationEndpoint.options === 'object');
      assert(typeof whoisRes.authenticationEndpoint.secure === 'boolean');
    });

    it('ignores DNS identity records with unrecognized keywords', async () => {
      // Identity records may legitimately carry keywords the library doesn't know about
      // (forward compatibility). They should be silently dropped during resolution
      // and not contaminate publicProfile or device keys.
      const dnsRecords = {
        'example.org': {
          TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]
        },
        'unknown._at.example.org': {
          TXT: [
            {value: 'name Forward Compat',                                                                            ttl: 1800, dnssec: true},
            {value: 'initials FC',                                                                                    ttl: 1800, dnssec: true},
            {value: 'tagline Builder of things',                                                                      ttl: 1800, dnssec: true},
            {value: 'x-acme-team Platform',                                                                           ttl: 1800, dnssec: true},
            {value: 'x-acme-long ' + 'a'.repeat(300),                                                                 ttl: 1800, dnssec: true},
            {value: 'future-feature some-future-value',                                                               ttl: 1800, dnssec: true},
            {value: 'foo bar',                                                                                        ttl: 1800, dnssec: true},
            {value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true}
          ]
        }
      };
      const resolver = new DnsResolverStub(dnsRecords);

      // Capture debug output to assert the "Ignoring unrecognized identity record"
      // line fires for the unknown keywords.
      const debugMessages = [];
      const captureLogger = {
        debug: (msg) => debugMessages.push(msg),
        info:  () => {}, warn: () => {}, error: () => {},
        spawn() { return captureLogger; }
      };

      const whoisRes = await Triauth.whois({identifier: 'unknown@example.org'}, {resolver, logger: captureLogger});

      assert.equal(whoisRes.status, 1);
      assert.equal(whoisRes.publicProfile.name, 'Forward Compat');
      assert.equal(whoisRes.publicProfile.initials, 'FC');
      assert(!('tagline' in whoisRes.publicProfile), 'tagline is no longer a recognized publicProfile keyword (dropped like other unrecognized keywords)');
      // `x-` prefixed keywords are passed through verbatim...
      assert.equal(whoisRes.publicProfile['x-acme-team'], 'Platform');
      // ...but an over-length value (> publicProfileMaxValueBytesize) is rejected, not truncated.
      assert(!('x-acme-long' in whoisRes.publicProfile), 'over-length extension values must be rejected');
      assert(!('future-feature' in whoisRes.publicProfile), 'unknown keywords must not leak into publicProfile');
      assert(!('foo' in whoisRes.publicProfile));
      assert(Array.isArray(whoisRes.devices) && whoisRes.devices.length > 0);
      assert(debugMessages.includes('Ignoring unrecognized identity record'), 'expected the "Ignoring unrecognized identity record" debug line to fire');
    });

    it('caps the number of distinct `x-` extensions but never drops reserved keywords', async () => {
      // A domain could publish an unbounded number of `x-` extension records; only the first
      // LIMITS.publicProfileMaxExtensions distinct ones are kept. Reserved keywords live in a
      // separate, bounded allowlist and must survive regardless of record order or extension flood.
      const overLimit = LIMITS.publicProfileMaxExtensions + 5;
      const extensionRecords = Array.from({length: overLimit}, (_, i) => ({
        value: `x-f${i} v${i}`, ttl: 1800, dnssec: true
      }));

      const dnsRecords = {
        'example.org': {TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]},
        'flood._at.example.org': {
          TXT: [
            ...extensionRecords,
            // reserved keyword declared AFTER the extension flood - must still be kept
            {value: 'name Flooded User', ttl: 1800, dnssec: true},
            {value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true}
          ]
        }
      };
      const resolver = new DnsResolverStub(dnsRecords);

      const debugMessages = [];
      const captureLogger = {
        debug: (msg) => debugMessages.push(msg),
        info: () => {}, warn: () => {}, error: () => {},
        spawn() { return captureLogger; }
      };

      const whoisRes = await Triauth.whois({identifier: 'flood@example.org'}, {resolver, logger: captureLogger});

      const extensionKeys = Object.keys(whoisRes.publicProfile).filter(k => k.startsWith('x-'));
      assert.equal(extensionKeys.length, LIMITS.publicProfileMaxExtensions, 'extensions must be capped');
      assert.equal(whoisRes.publicProfile.name, 'Flooded User', 'reserved keyword must survive the extension flood');
      assert(debugMessages.includes('Ignoring publicProfile extension over the limit'), 'expected the over-limit debug line to fire');
    });

    it('drops a publicProfile keyword entirely when it appears more than once', async () => {
      // Doubled keywords are ambiguous, so both the reserved and the `x-` variants are dropped
      // entirely rather than guessing first- or last-wins.
      const dnsRecords = {
        'example.org': {TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]},
        'dup._at.example.org': {
          TXT: [
            {value: 'name First',     ttl: 1800, dnssec: true},
            {value: 'name Second',    ttl: 1800, dnssec: true},
            {value: 'initials OK',    ttl: 1800, dnssec: true},
            {value: 'x-dup one',      ttl: 1800, dnssec: true},
            {value: 'x-dup two',      ttl: 1800, dnssec: true},
            {value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true}
          ]
        }
      };
      const resolver = new DnsResolverStub(dnsRecords);

      const debugMessages = [];
      const captureLogger = {
        debug: (msg) => debugMessages.push(msg),
        info: () => {}, warn: () => {}, error: () => {},
        spawn() { return captureLogger; }
      };

      const whoisRes = await Triauth.whois({identifier: 'dup@example.org'}, {resolver, logger: captureLogger});

      assert(!('name' in whoisRes.publicProfile), 'a doubled reserved keyword must be dropped entirely');
      assert(!('x-dup' in whoisRes.publicProfile), 'a doubled extension keyword must be dropped entirely');
      assert.equal(whoisRes.publicProfile.initials, 'OK', 'non-doubled keywords are unaffected');
      assert(debugMessages.includes('Ignoring doubled publicProfile entry'), 'expected the doubled-entry debug line to fire');
    });

    it('reports resolution-level secure:false when the triauth configuration record is not DNSSEC protected', async () => {
      const keyRecord = 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8';

      for (const [endpointDnssec, expectedSecure] of [[true, true], [false, false]]) {
        const resolver = new DnsResolverStub({
          'example.org': {
            TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: endpointDnssec}]
          },
          'john._at.example.org': {
            TXT: [{value: keyRecord, ttl: 1800, dnssec: true}]
          }
        });

        const whoisRes = await Triauth.whois({identifier: 'john@example.org'}, {resolver});

        assert.equal(whoisRes.status, 1);
        assert.equal(whoisRes.devices.length, 1);
        assert.equal(whoisRes.secure, expectedSecure, `endpoint dnssec:${endpointDnssec} must yield secure:${expectedSecure}`);
      }
    });

    describe('include records', () => {
      const keyRecord = {value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true};

      // Resolves team@example.org against a zone with the given endpoint record and
      // extra identity records, and returns the include statements it ends up with.
      const resolvedIncludes = async (endpointRecord, identityRecords) => {
        const resolver = new DnsResolverStub({
          'example.org': {TXT: [{value: endpointRecord, ttl: 1800, dnssec: true}]},
          'team._at.example.org': {TXT: [keyRecord, ...identityRecords]}
        });
        const identity = new Triauth.Identity('team@example.org', {}, {resolver});
        assert.equal(await identity.resolve(), true);
        return identity.includes.includes;
      };

      it("gates include records through the endpoint record's include option (default: any)", async () => {
        const records = [
          {value: 'include mate@example.org use=sign scope=any', ttl: 1800, dnssec: true},
          {value: 'include ext@other.example scope=any',         ttl: 1800, dnssec: true}
        ];

        const admitted = await resolvedIncludes('triauth local-auth.example.org mode=public', records);
        assert.deepEqual(admitted.map((i) => i.ref).sort(), ['ext@other.example', 'mate@example.org'], 'the default policy admits local and foreign refs alike');
        assert.equal(admitted.find((i) => i.ref === 'mate@example.org').options.use, 'sign', 'record options must reach the include statement');

        assert.equal((await resolvedIncludes('triauth local-auth.example.org include=none mode=public', records)).length, 0);
        assert.deepEqual(
          (await resolvedIncludes('triauth local-auth.example.org include=local mode=public', records)).map((i) => i.ref),
          ['mate@example.org'], 'include=local admits (only) refs on the identity domain');
        assert.deepEqual(
          (await resolvedIncludes('triauth local-auth.example.org include=other.example mode=public', records)).map((i) => i.ref),
          ['ext@other.example'], 'an allowlisted domain admits (only) its refs');
      });

      it('carries per-record freshness: expires from the TTL (absent TTL: undefined, never NaN)', async () => {
        const includes = await resolvedIncludes('triauth local-auth.example.org include=any mode=public', [
          {value: 'include mate@example.org scope=any', ttl: 1800, dnssec: true},
          {value: 'include peer@other.example scope=any',          dnssec: false}
        ]);

        const mate = includes.find((i) => i.ref === 'mate@example.org');
        const peer = includes.find((i) => i.ref === 'peer@other.example');
        assert(Number.isFinite(mate.expires) && mate.expires > Date.now(), 'a TTL yields a finite future expires');
        assert.strictEqual(peer.expires, undefined, 'a record without a TTL yields no expires');
      });
    });

    describe('groups records', () => {
      const keyRecord = {value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true};
      const rec = (value) => ({value, ttl: 1800, dnssec: true});

      // Resolves team@example.org against a zone carrying the given extra identity records and
      // returns the whois result together with the captured debug lines.
      const resolvedWhois = async (identityRecords) => {
        const resolver = new DnsResolverStub({
          'example.org': {TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]},
          'team._at.example.org': {TXT: [keyRecord, ...identityRecords]}
        });
        const debugMessages = [];
        const captureLogger = {
          debug: (msg) => debugMessages.push(msg),
          info: () => {}, warn: () => {}, error: () => {},
          spawn() { return captureLogger; }
        };
        const whoisRes = await Triauth.whois({identifier: 'team@example.org'}, {resolver, logger: captureLogger});
        assert.equal(whoisRes.status, 1);
        return {whoisRes, debugMessages};
      };

      it('surfaces groups as fully-qualified names - union across records, deduplicated, sorted ascending', async () => {
        const {whoisRes} = await resolvedWhois([
          rec('groups zeta,admins'),
          rec('groups admins,project3')
        ]);
        assert.deepStrictEqual(whoisRes.groups, ['admins@example.org', 'project3@example.org', 'zeta@example.org']);
      });

      it('yields the same list regardless of DNS answer order', async () => {
        const a = await resolvedWhois([rec('groups zeta'), rec('groups admins')]);
        const b = await resolvedWhois([rec('groups admins'), rec('groups zeta')]);
        assert.deepStrictEqual(a.whoisRes.groups, b.whoisRes.groups);
      });

      it('lowercases the record value before validation - names surface normalized', async () => {
        const {whoisRes} = await resolvedWhois([rec('groups Admins,PROJECT3')]);
        assert.deepStrictEqual(whoisRes.groups, ['admins@example.org', 'project3@example.org']);
      });

      it('an empty element (trailing comma) voids the whole record - siblings stay effective', async () => {
        const {whoisRes, debugMessages} = await resolvedWhois([
          rec('groups admins,'),
          rec('groups project3')
        ]);
        assert.deepStrictEqual(whoisRes.groups, ['project3@example.org']);
        assert(debugMessages.includes('Ignoring groups record with a malformed group name'), 'expected the malformed-name debug line to fire');
      });

      it('one grammar-invalid element voids the whole record - never repaired to the valid subset', async () => {
        const {whoisRes} = await resolvedWhois([rec('groups good,-bad,alsogood')]);
        assert.deepStrictEqual(whoisRes.groups, []);
      });

      it('rejects names outside the device-name grammar (dots, underscores, hyphen placement, spaces)', async () => {
        for (const value of ['groups a.b', 'groups under_score', 'groups -lead', 'groups trail-', 'groups dou--ble', 'groups two words', 'groups ,']) {
          const {whoisRes} = await resolvedWhois([rec(value)]);
          assert.deepStrictEqual(whoisRes.groups, [], `${JSON.stringify(value)} must void the record`);
        }
      });

      it('enforces the 20-byte name cap - a boundary-length name passes, one byte over voids the record', async () => {
        const ok = 'a'.repeat(20);
        const over = 'a'.repeat(21);
        assert.deepStrictEqual((await resolvedWhois([rec(`groups ${ok}`)])).whoisRes.groups, [`${ok}@example.org`]);
        assert.deepStrictEqual((await resolvedWhois([rec(`groups ${over}`)])).whoisRes.groups, []);
      });

      it('a groups record carrying any critical option is ignored as a whole; x- options are inert', async () => {
        const {whoisRes, debugMessages} = await resolvedWhois([
          rec('groups admins use=auth'),
          rec('groups project3 x-note=hi')
        ]);
        assert.deepStrictEqual(whoisRes.groups, ['project3@example.org']);
        assert(debugMessages.includes('Ignoring groups record due to unrecognized options'), 'expected the unrecognized-options debug line to fire');
      });

      it('caps distinct names at LIMITS.maxGroups in processing order; duplicates never consume the cap', async () => {
        const first = Array.from({length: LIMITS.maxGroups - 5}, (_, i) => `g${String(i).padStart(3, '0')}`);
        const second = ['g000', ...Array.from({length: 10}, (_, i) => `h${String(i).padStart(2, '0')}`)];
        const {whoisRes, debugMessages} = await resolvedWhois([
          rec('groups ' + first.join(',')),
          rec('groups ' + second.join(','))
        ]);
        assert.equal(whoisRes.groups.length, LIMITS.maxGroups);
        assert(whoisRes.groups.includes('h04@example.org'), 'the final distinct name under the cap must be kept (the duplicate before it consumed no budget)');
        assert(!whoisRes.groups.includes('h05@example.org'), 'names beyond the cap must be dropped');
        assert(debugMessages.includes('Ignoring groups and further group records over the limit'), 'expected the one-time over-limit summary to fire');
      });

      it('a groups record is recognized - it does not fire the unrecognized-identity-record debug line', async () => {
        const {debugMessages} = await resolvedWhois([rec('groups admins')]);
        assert(!debugMessages.includes('Ignoring unrecognized identity record'));
      });

      it('an identity without groups records yields groups: []', async () => {
        const {whoisRes} = await resolvedWhois([]);
        assert.deepStrictEqual(whoisRes.groups, []);
      });

      it('coexists with keys, includes, and profile records without cross-interference', async () => {
        const {whoisRes} = await resolvedWhois([
          rec('name Team Account'),
          rec('include mate@example.org use=sign scope=any'),
          rec('groups admins')
        ]);
        assert.deepStrictEqual(whoisRes.groups, ['admins@example.org']);
        assert.equal(whoisRes.publicProfile.name, 'Team Account');
        assert.equal(whoisRes.includes.length, 1);
        assert.equal(whoisRes.devices.length, 1);
      });

      it('SECURITY: any non-DNSSEC identity record degrades the resolution-level secure - DNSSEC is full-in or full-out', async () => {
        // The groups, profile, and even unrecognized-key variants all degrade the resolution,
        // and whois surfaces the same resolution-level flag the verification flows report.
        for (const insecureRecord of ['groups admins', 'name Team Account', 'future-key whatever']) {
          const resolver = new DnsResolverStub({
            'example.org': {TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]},
            'team._at.example.org': {TXT: [keyRecord, {value: insecureRecord, ttl: 1800, dnssec: false}]}
          });
          const whoisRes = await Triauth.whois({identifier: 'team@example.org'}, {resolver});
          const checkRes = await Triauth.check({identifier: 'team@example.org', deviceTag: whoisRes.devices[0].deviceTag}, {resolver});
          assert.equal(checkRes.valid, true);
          assert.equal(checkRes.secure, false, `a non-DNSSEC "${insecureRecord}" record must degrade the resolution-level secure`);
          assert.equal(whoisRes.secure, false, 'whois surfaces the same resolution-level status');
        }

        // The all-validated contrast: the same zone with every record DNSSEC-validated is secure
        const resolver = new DnsResolverStub({
          'example.org': {TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]},
          'team._at.example.org': {TXT: [keyRecord, rec('groups admins')]}
        });
        const whoisRes = await Triauth.whois({identifier: 'team@example.org'}, {resolver});
        const checkRes = await Triauth.check({identifier: 'team@example.org', deviceTag: whoisRes.devices[0].deviceTag}, {resolver});
        assert.equal(whoisRes.secure, true);
        assert.equal(checkRes.secure, true);
        assert.deepStrictEqual(checkRes.groups, ['admins@example.org'], 'check carries the identity\'s current groups');
      });
    });

  });
});
