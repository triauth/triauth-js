import DnsResolverStub from '../stubs/dns_resolver.js';
import dnsRecords from '../fixtures/dns_records.json' with { type: 'json' };

export default function() { describe('Triauth.IdentityDomain', () => {

  describe('Triauth.IdentityDomain.derive', () => {

    it('returns null for an unknown mode', async () => {
      const result = await Triauth.IdentityDomain.derive('john@example.com', {mode: 'future-mode'});
      assert.strictEqual(result, null);
    });

    it('returns null without a mode, lookup code or not - the default mode is applied by Identity before derivation', async () => {
      assert.strictEqual(await Triauth.IdentityDomain.derive('john@example.com', {}), null);
      assert.strictEqual(await Triauth.IdentityDomain.derive('john@private.triauthdemo.org', {lookupCode: 'K7QJ3FB9M2WZX0C4'}), null);
    });

    it('returns the identity domain with no full label in public mode (nothing is derived)', async () => {
      assert.deepStrictEqual(
        await Triauth.IdentityDomain.derive('john@example.com', {mode: 'public'}),
        {domainName: 'john._at.example.com'}
      );
    });

  });

  describe('Triauth.IdentityDomain private-mode derivation (known answers)', () => {

    const IDENTIFIER  = 'john@private.triauthdemo.org';
    const LOOKUP_CODE = 'K7QJ3FB9M2WZX0C4';
    const FULL_LABEL  = '4GIBDU53B3KGFSZUD5KRVUGITFQ2QAN2C55FNXO25S53WGT6CK6A';
    const DOMAIN_NAME = '_4GIBDU53B3._at.private.triauthdemo.org';
    const COMMITMENT  = '3Q7YSpb3MLMRaQ20VZBUfoySyM4vQrHMfIIuAxER3_s';

    it('derives the full 52-char base32 string: the HMAC-SHA-256 of the identifier, keyed by the lookup code', async () => {
      assert.strictEqual(await Triauth.IdentityDomain.deriveFullLabel(IDENTIFIER, LOOKUP_CODE), FULL_LABEL);
      // The derivation is the plain keyed MAC, reproducible with any HMAC implementation
      const mac = await Triauth.Helpers.hmacSha256(Triauth.Helpers.stringToUtf8Bytes(LOOKUP_CODE), Triauth.Helpers.stringToUtf8Bytes(IDENTIFIER));
      assert.strictEqual(Triauth.Helpers.uInt8ArrayToBase32(mac), FULL_LABEL);
    });

    it('derives the identity domain: a leading underscore, the first 10 characters of the full label, and the ._at. marker', async () => {
      assert.deepStrictEqual(
        await Triauth.IdentityDomain.derive(IDENTIFIER, {mode: 'private', lookupCode: LOOKUP_CODE}),
        {domainName: DOMAIN_NAME, fullLabel: FULL_LABEL}
      );
      assert.strictEqual(DOMAIN_NAME, '_' + FULL_LABEL.substring(0, 10) + '._at.private.triauthdemo.org');
    });

    it('keeps the label length fixed - a published len option is an unknown option key, retained and inert', async () => {
      for (const len of ['1', '3', '16', '0', 'banana']) {
        assert.strictEqual(
          (await Triauth.IdentityDomain.derive(IDENTIFIER, {mode: 'private', len, lookupCode: LOOKUP_CODE})).domainName,
          DOMAIN_NAME, len
        );
      }
    });

    it('lands on an unrelated label under every other lookup code - the label carries no trace of the code', async () => {
      const other = await Triauth.IdentityDomain.derive(IDENTIFIER, {mode: 'private', lookupCode: 'ZZZZZZZZZZZZZZZZ'});
      assert.strictEqual(other.domainName, '_IIBOSRWME5._at.private.triauthdemo.org');
      assert.notStrictEqual(other.fullLabel, FULL_LABEL);
    });

    it('returns null when the lookup code is missing or malformed (fail closed, never repaired)', async () => {
      for (const lookupCode of [undefined, null, 42, 'K7QJ3FB9M2WZX0C', 'K7QJ3FB9M2WZX0C44', 'k7qj3fb9m2wzx0c4', 'K7QJ3FB9M2WZX0C-']) {
        assert.strictEqual(
          await Triauth.IdentityDomain.derive(IDENTIFIER, {mode: 'private', lookupCode}),
          null, JSON.stringify(lookupCode)
        );
      }
    });

    it('a lookup code is inert under every other mode - only mode=private consumes one', async () => {
      assert.deepStrictEqual(
        await Triauth.IdentityDomain.derive(IDENTIFIER, {mode: 'public', lookupCode: LOOKUP_CODE}),
        {domainName: 'john._at.private.triauthdemo.org'}
      );
      assert.strictEqual(
        await Triauth.IdentityDomain.derive(IDENTIFIER, {mode: 'future-mode', lookupCode: LOOKUP_CODE}),
        null
      );
    });

    it('resolve() exposes the commitment over the untruncated label', async () => {
      const stub = new DnsResolverStub({[DOMAIN_NAME]: {TXT: ['name John Doe']}});
      const id = new Triauth.IdentityDomain(IDENTIFIER, {resolver: stub});
      assert.strictEqual(await id.setOptions({mode: 'private', lookupCode: LOOKUP_CODE}).resolve(), true);
      assert.strictEqual(id.expectedCommitment, COMMITMENT);
      assert.strictEqual(await Triauth.Helpers.sha256(FULL_LABEL), COMMITMENT);
    });

    it('resolve() returns false without a mode, even with a lookup code - nothing is derived and nothing is expected', async () => {
      const stub = new DnsResolverStub({[DOMAIN_NAME]: {TXT: ['name John Doe']}});
      const id = new Triauth.IdentityDomain(IDENTIFIER, {resolver: stub});
      assert.strictEqual(await id.setOptions({lookupCode: LOOKUP_CODE}).resolve(), false);
      assert.strictEqual(id.domainName, null);
      assert.strictEqual(id.expectedCommitment, null);
    });

    it('resolve() leaves the expected binding null outside private mode', async () => {
      const stub = new DnsResolverStub(dnsRecords);
      const id = new Triauth.IdentityDomain('john@triauthdemo.org', {resolver: stub});
      await id.setOptions({mode: 'public'}).resolve();
      assert.strictEqual(id.expectedCommitment, null);
    });

    it('resolve() returns false, without querying DNS, when the lookup code is missing', async () => {
      let queried = false;
      const stub = {resolveConfig: async () => { queried = true; return []; }};
      const id = new Triauth.IdentityDomain(IDENTIFIER, {resolver: stub});
      assert.strictEqual(await id.setOptions({mode: 'private'}).resolve(), false);
      assert.strictEqual(id.resolved, false);
      assert.strictEqual(id.domainName, null);
      assert.strictEqual(queried, false);
    });

  });

  describe('Triauth.IdentityDomain.resolve', () => {

    it('returns false when the derived domain name is null (unknown mode)', async () => {
      const stub = new DnsResolverStub(dnsRecords);
      const id = new Triauth.IdentityDomain('john@example.com', {resolver: stub});
      const result = await id.setOptions({mode: 'future-mode'}).resolve();
      assert.strictEqual(result, false);
      assert.strictEqual(id.resolved, false);
    });

    it('throws when the options were never set - there is no derivation to resolve', async () => {
      const id = new Triauth.IdentityDomain('john@triauthdemo.org', {resolver: new DnsResolverStub(dnsRecords)});

      await assert.rejects(() => id.resolve(), /options not set/);
    });

  });

  describe('Triauth.IdentityDomain.setOptions', () => {

    it('returns the instance, so the call chains straight into resolve()', async () => {
      const id = new Triauth.IdentityDomain('john@example.com', {resolver: new DnsResolverStub(dnsRecords)});

      assert.strictEqual(id.setOptions({mode: 'public'}), id);
      assert.deepStrictEqual(id.options, {mode: 'public'});
      assert.strictEqual(await id.resolve(), true);
    });

    it('sets the options once - a second call is a caller error, not a re-derivation', () => {
      const id = new Triauth.IdentityDomain('john@example.com');
      id.setOptions({mode: 'public'});

      // Even the identical derivation is refused: the memoized answer is already spoken for
      assert.throws(() => id.setOptions({mode: 'private'}), /already set/);
      assert.throws(() => id.setOptions({mode: 'public'}), /already set/);
      assert.deepStrictEqual(id.options, {mode: 'public'});
    });

  });

}); }
