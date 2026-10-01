import DnsResolverStub from '../stubs/dns_resolver.js';

export default function() { describe('Triauth.AuthenticationEndpoint', () => {

  it('returns false and sets host to null when multiple triauth records are published', async () => {
    const stub = new DnsResolverStub({
      'multi.example.com': {TXT: ['triauth auth1.example.com mode=public', 'triauth auth2.example.com mode=public']}
    });
    const ae = new Triauth.AuthenticationEndpoint('multi.example.com', {resolver: stub});
    const result = await ae.resolve();
    assert.strictEqual(result, false);
    assert.strictEqual(ae.host, null);
    assert.strictEqual(ae.secure, undefined);
  });

  it('SECURITY: refuses to choose among multiple triauth records even when only one of them carries a mode', async () => {
    const stub = new DnsResolverStub({
      'multi.example.com': {TXT: ['triauth auth1.example.com', 'triauth auth2.example.com mode=public']}
    });
    const ae = new Triauth.AuthenticationEndpoint('multi.example.com', {resolver: stub});
    assert.strictEqual(await ae.resolve(), false);
    assert.strictEqual(ae.host, null);
  });

  it('fills the defaults into the options - mode=private and include=any - so they report what the verifier uses', async () => {
    const stub = new DnsResolverStub({
      'example.com': {TXT: [{value: 'triauth auth.example.com', ttl: 1800, dnssec: true}]}
    });
    const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
    assert.strictEqual(await ae.resolve(), true);
    assert.strictEqual(ae.host, 'auth.example.com');
    // options is a null-prototype object; compare a copy (a failing deepStrictEqual on the raw object aborts mocha)
    assert.deepStrictEqual({...ae.options}, {mode: 'private', include: 'any'});
    assert.strictEqual(ae.secure, true);
  });

  it('keeps a published include policy and fills only the absent defaults', async () => {
    const stub = new DnsResolverStub({
      'example.com': {TXT: ['triauth auth.example.com include=local']}
    });
    const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
    assert.strictEqual(await ae.resolve(), true);
    assert.deepStrictEqual({...ae.options}, {include: 'local', mode: 'private'});
  });

  it('resolves under any mode value and reports it verbatim - the vocabulary is enforced at identity-domain derivation, not here', async () => {
    for (const mode of ['banana', 'Public', 'PRIVATE', 'public,private']) {
      const stub = new DnsResolverStub({
        'example.com': {TXT: [`triauth auth.example.com mode=${mode}`]}
      });
      const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
      assert.strictEqual(await ae.resolve(), true, `mode=${mode}`);
      assert.strictEqual(ae.host, 'auth.example.com', `mode=${mode}`);
      assert.strictEqual(ae.options.mode, mode, `mode=${mode}`);
    }
  });

  it('resolves under each registered mode and exposes it in options', async () => {
    for (const mode of ['public', 'private']) {
      const stub = new DnsResolverStub({
        'example.com': {TXT: [`triauth auth.example.com mode=${mode}`]}
      });
      const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
      assert.strictEqual(await ae.resolve(), true, `mode=${mode}`);
      assert.strictEqual(ae.host, 'auth.example.com');
      assert.strictEqual(ae.options.mode, mode);
    }
  });

  it('sets secure:true when the triauth record was DNSSEC validated', async () => {
    const stub = new DnsResolverStub({
      'example.com': {TXT: [{value: 'triauth auth.example.com mode=public', ttl: 1800, dnssec: true}]}
    });
    const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
    assert.strictEqual(await ae.resolve(), true);
    assert.strictEqual(ae.host, 'auth.example.com');
    assert.strictEqual(ae.secure, true);
  });

  it('records the triauth record\'s expiry from its TTL, and none without a TTL', async () => {
    const withTtl = new Triauth.AuthenticationEndpoint('example.com', {resolver: new DnsResolverStub({
      'example.com': {TXT: [{value: 'triauth auth.example.com mode=public', ttl: 60, dnssec: true}]}
    })});
    const before = Date.now();
    assert.strictEqual(await withTtl.resolve(), true);
    assert(withTtl.expires >= before + 60_000 && withTtl.expires <= Date.now() + 60_000, 'expires is the resolution time plus the TTL');

    const withoutTtl = new Triauth.AuthenticationEndpoint('example.com', {resolver: new DnsResolverStub({
      'example.com': {TXT: [{value: 'triauth auth.example.com mode=public', dnssec: true}]}
    })});
    assert.strictEqual(await withoutTtl.resolve(), true);
    assert.strictEqual(withoutTtl.expires, undefined);
  });

  it('urlFor builds the redirect from the bare host', async () => {
    const stub = new DnsResolverStub({
      'example.com': {TXT: ['triauth Auth.Example.COM mode=public']}
    });
    const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
    assert.strictEqual(await ae.resolve(), true);
    assert.strictEqual(ae.host, 'auth.example.com'); // lowercased for use

    assert.strictEqual(ae.urlFor(null), 'https://auth.example.com/'); // the bare endpoint URL
    assert.strictEqual(ae.urlFor('auth', {challenge: 'abc-123_XYZ'}), 'https://auth.example.com/auth.html#?challenge=abc-123_XYZ');
    assert.strictEqual(ae.urlFor('sign', {challenge: 'abc', hmac: 'def'}), 'https://auth.example.com/sign.html#?challenge=abc&hmac=def');
  });

  it('sets secure:false when the triauth record was not DNSSEC validated', async () => {
    for (const dnssec of [false, undefined]) {
      const stub = new DnsResolverStub({
        'example.com': {TXT: [{value: 'triauth auth.example.com mode=public', ttl: 1800, dnssec}]}
      });
      const ae = new Triauth.AuthenticationEndpoint('example.com', {resolver: stub});
      assert.strictEqual(await ae.resolve(), true);
      assert.strictEqual(ae.secure, false, `dnssec:${dnssec} must map to secure:false`);
    }
  });

}); }
