import SignerStub from '../stubs/signer.js';
import identities from '../fixtures/identities.json' with { type: 'json' };
import dnsRecords from '../fixtures/dns_records.json' with { type: 'json' };
import DnsResolverStub from '../stubs/dns_resolver.js';

export default function() { describe('Triauth.Signature', () => {
  const dnsResolver = new DnsResolverStub(dnsRecords);
  const identityFixture = identities['john'];
  const via = 'https://example.com/';
  const message = 'internal-signature-test';

  it('returns a string being a valid signature', async () => {

    const identityFixture = identities['john'];
    const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
    const testMessages = ['Test', '', "\x00 \u0000 \n \r \u{1F4A9} \u202E ' \"", ";\n;;\n"];
    const testMetadata = [null, {}]

    for(const message of testMessages) {
      const signature = await Triauth.Signature.generate(async (payload) => await signerStub.sign(payload), 'auth', identityFixture.identifier, '', 'https://example.com/', message);

      assert.equal(typeof signature, 'string', 'Signature must be a string');
      assert.equal(signature[0], '|', 'Signatures must start with |')
      assert.equal(signature[signature.length - 1], '|', 'Signatures must end with |')

      const verifyResult = await (new Triauth.Signature(signature, {resolver:dnsResolver})).verify(message);

      assert.equal(verifyResult.valid, true, 'Verification result should have verified set to true for valid signatures');
    }
  });

  describe('Triauth.Signature.verify constraint enforcement', () => {

    const identityFixture = identities['john'];
    const message = 'constraint-test-message';
    const via = 'https://example.com/';

    // Helper: build a fresh valid signature object bound to the stub resolver
    const buildSignature = async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const sig = await Triauth.Signature.generate(
        async (payload) => signerStub.sign(payload),
        'auth',
        identityFixture.identifier, '',
        via,
        message
      );
      return new Triauth.Signature(sig, {resolver: dnsResolver});
    };

    it('returns null (not false) when notBefore is past the signature ts (fix #5)', async () => {
      const sigObj = await buildSignature();
      const ts = sigObj.ts;

      const res = await sigObj.verify(message, {notBefore: ts + 1000});
      assert.strictEqual(res, null, 'notBefore in the future of ts must return null so callers can surface "expired"');
    });

    it('returns null (not false) when notAfter is before the signature ts (fix #5)', async () => {
      const sigObj = await buildSignature();
      const ts = sigObj.ts;

      const res = await sigObj.verify(message, {notAfter: ts - 1000});
      assert.strictEqual(res, null, 'notAfter in the past of ts must return null so callers can surface "expired"');
    });

    it('fails closed (returns false) when notBefore is non-numeric (fix #6)', async () => {
      const sigObj = await buildSignature();

      const res = await sigObj.verify(message, {notBefore: 'not-a-number'});
      assert.strictEqual(res, false, 'non-numeric notBefore must fail closed, not silently disable the check');
    });

    it('fails closed (returns false) when notAfter is NaN (fix #6)', async () => {
      const sigObj = await buildSignature();

      const res = await sigObj.verify(message, {notAfter: NaN});
      assert.strictEqual(res, false, 'NaN notAfter must fail closed, not silently disable the check');
    });

    it('returns false on type constraint mismatch', async () => {
      const sigObj = await buildSignature();

      const res = await sigObj.verify(message, {type: 'sign'});
      assert.strictEqual(res, false);
    });

    it('returns false on identifier constraint mismatch', async () => {
      const sigObj = await buildSignature();

      const res = await sigObj.verify(message, {identifier: 'other-user@triauthdemo.org'});
      assert.strictEqual(res, false);
    });

    it('returns false on via constraint mismatch', async () => {
      const sigObj = await buildSignature();

      const res = await sigObj.verify(message, {via: 'https://other-domain.com/'});
      assert.strictEqual(res, false);
    });

    it("enforces the actor constraint in both directions ('' = require self-signed)", async () => {
      const selfSigned = await buildSignature();
      assert.strictEqual(await selfSigned.verify(message, {actor: 'delegate@example.com'}), false,
        'requiring a delegate must reject a self-signed signature');

      const res = await (await buildSignature()).verify(message, {actor: ''});
      assert.equal(res.valid, true, "actor:'' must accept a self-signed signature");
      assert.strictEqual(res.actor, '');

      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const delegated = await Triauth.Signature.generate(
        async (payload) => signerStub.sign(payload), 'auth', identityFixture.identifier, 'delegate@example.com', via, message
      );
      const delegatedObj = new Triauth.Signature(delegated, {resolver: dnsResolver});
      assert.strictEqual(await delegatedObj.verify(message, {actor: ''}), false,
        'requiring self-signed must reject a delegated signature');
    });

    it('returns false on an unrecognized constraint key', async () => {
      const sigObj = await buildSignature();

      const res = await sigObj.verify(message, {unknownConstraint: 'foo'});
      assert.strictEqual(res, false, 'unrecognized constraint keys must surface as a failure, not silently pass');
    });
  });

  describe('Triauth.Signature.generate', () => {

    it('returns false for an unrecognized type', async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const result = await Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'invalid-type', identityFixture.identifier, '', via, message
      );
      assert.strictEqual(result, false);
    });

    it('returns false when via contains a semicolon - the envelope layer refuses the payload delimiter on its own authority (the URL grammar allows a final-segment ";")', async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const result = await Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'auth', identityFixture.identifier, '', 'https://x.com/;evil', message
      );
      assert.strictEqual(result, false);
    });

    it('returns false when via contains a pipe (envelope wrapper char) - fails closed instead of emitting a corrupt envelope', async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const result = await Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'auth', identityFixture.identifier, '', 'https://x.com/a|b/', message
      );
      assert.strictEqual(result, false);
    });

    it("accepts only '' or a valid identifier in the actor slot", async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const generate = (actor) => Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'auth', identityFixture.identifier, actor, via, message
      );

      for (const bad of [null, undefined, 'Actor@Example.com', 'actor_x@example.com', 'not an identifier']) {
        assert.strictEqual(await generate(bad), false, JSON.stringify(bad));
      }

      for (const [actor, label] of [['', 'self-signed'], ['actor@example.com', 'delegated']]) {
        const envelope = await generate(actor);
        const slots = envelope.slice(1, -1).split(';');
        assert.equal(slots.length, 9, `${label}: nine envelope slots`);
        assert.equal(slots[2], actor, `${label}: actor slot carries the input verbatim`);
      }
    });

  });

  describe('Triauth.Signature constructor', () => {

    it('throws (code 225) when raw data contains extra pipe delimiters', () => {
      assert.throws(() => new Triauth.Signature('|a|b|'), (err) => err.code === 225);
    });

  });

  describe('Triauth.Signature.verify additional branches', () => {

    it('returns false when cryptoSignatures is empty (defensive guard)', async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const sig = await Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'auth', identityFixture.identifier, '', via, message
      );
      const sigObj = new Triauth.Signature(sig, {resolver: dnsResolver});
      sigObj.cryptoSignatures = [];
      const result = await sigObj.verify(message);
      assert.strictEqual(result, false);
    });

    it('rejects with TriauthError 110 when DNS resolution throws (propagated, not swallowed into false)', async () => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[0].keys[0].private);
      const sig = await Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'auth', 'a@dnssec-failed.org', '', via, message
      );
      // No custom resolver: the suite's zone resolver publishes dnssec-failed.org as a resolution
      // failure, exactly as a validating resolver reports it. The rejection must propagate so API
      // methods can surface a retryable {error:110} instead of a false "signature invalid" verdict.
      const sigObj = new Triauth.Signature(sig);
      await assert.rejects(sigObj.verify(message), (err) => err instanceof Triauth.Error && err.code === 110);
    });

  });

  describe('Triauth.MultiSignature.verify constraint enforcement', () => {

    const buildSig = async (device = 0) => {
      const signerStub = await SignerStub.fromJWK(identityFixture.devices[device].keys[0].private);
      return Triauth.Signature.generate(
        async (p) => signerStub.sign(p), 'auth', identityFixture.identifier, '', via, message
      );
    };

    it('returns false when signature count is below minSignatures', async () => {
      const sig = await buildSig();
      const ms = new Triauth.MultiSignature(Triauth.MultiSignature.generate(sig), {resolver: dnsResolver});
      assert.strictEqual(await ms.verify(message, {minSignatures: 2}), false);
    });

    it('returns false when signature count exceeds maxSignatures', async () => {
      const sig1 = await buildSig();
      const sig2 = await buildSig(1);
      const ms = new Triauth.MultiSignature(Triauth.MultiSignature.generate(sig1, sig2), {resolver: dnsResolver});
      assert.strictEqual(await ms.verify(message, {maxSignatures: 1}), false);
    });

    it('fails closed (returns false) when a signature-count bound is non-numeric', async () => {
      // The primitive defends itself even though Triauth.verify now rejects non-numeric bounds with 101
      // before delegating here; Response.verify (the challenge-response flows) reaches this guard directly.
      const sig = await buildSig();
      const ms = new Triauth.MultiSignature(Triauth.MultiSignature.generate(sig), {resolver: dnsResolver});
      assert.strictEqual(await ms.verify(message, {maxSignatures: '1'}), false);
    });

    it('rejects byte-identical duplicate segments at parse time (225), while distinct segments of the same identity parse fine', async () => {
      const sig = await buildSig();

      // A single signature replayed to pad the segment count is never legitimate
      assert.throws(
        () => new Triauth.MultiSignature(Triauth.MultiSignature.generate(sig, sig), {resolver: dnsResolver}),
        (err) => err instanceof Triauth.Error && err.code === 225
      );

      // Two signatures by two devices of the same identity differ in bytes on every runtime and parse fine
      const sig2 = await buildSig(1);
      const ms = new Triauth.MultiSignature(Triauth.MultiSignature.generate(sig, sig2), {resolver: dnsResolver});
      assert.strictEqual(ms.signatures.length, 2);
    });

  });

}); }
