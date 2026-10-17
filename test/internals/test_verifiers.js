export default function() { describe('Verifiers', () => {

  describe('Triauth.Verifiers.Base', () => {

    // Triauth.Verifiers.Base carries the contract that every verifier implements, and no
    // implementation of its own: a registered class that leaves either member unimplemented
    // names itself in the error, rather than failing as a missing property at the call site.

    it('rejects the abstract fromPublishableKey - a subclass must implement it', async () => {
      await assert.rejects(
        Triauth.Verifiers.Base.fromPublishableKey('BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8'),
        /Triauth\.Verifiers\.Base\.fromPublishableKey is abstract and must be implemented by a subclass/
      );
    });

    it('rejects the abstract verify - a subclass must implement it', async () => {
      await assert.rejects(
        new Triauth.Verifiers.Base().verify('message', 'signature', {}, {}),
        /Triauth\.Verifiers\.Base#verify is abstract and must be implemented by a subclass/
      );
    });

  });

  describe('P-256 key forms (Ecdsa, WebAuthnEs256)', () => {

    // An ES256 key record carries the uncompressed (0x04) or the compressed (0x02/0x03) point.
    // Triauth.Helpers.decodeP256PublicKey decodes both on every runtime, so no form depends on
    // what the Web Crypto implementation imports. The hybrid form (0x06/0x07) never imports,
    // also where Web Crypto would accept it (Node.js does).

    const message = 'triauth P-256 key forms';
    const b64u = (bytes) => Triauth.Helpers.arrayBufferToBase64Url(bytes);

    // One key pair of each y parity, with its signature over `message`
    const keyPairs = async () => {
      const byParity = new Map();
      for (let i = 0; byParity.size < 2 && i < 64; i++) {
        const keyPair = await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
        const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
        const signature = await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, keyPair.privateKey, Triauth.Helpers.stringToUtf8Bytes(message));
        byParity.set(raw[64] & 1, {raw, signature: b64u(signature)});
      }
      assert.equal(byParity.size, 2);
      return [...byParity.values()];
    };

    it('Ecdsa builds a verifier from the compressed key of either prefix, and it verifies the signatures of the key', async () => {
      for (const {raw, signature} of await keyPairs()) {
        const compressed = Uint8Array.from([0x02 | (raw[64] & 1), ...raw.subarray(1, 33)]);
        const verifier = await Triauth.Verifiers.Ecdsa.fromPublishableKey(b64u(compressed));

        assert.ok(verifier instanceof Triauth.Verifiers.Ecdsa);
        assert.equal(await verifier.verify(message, signature, {}, {}), true);

        // The other prefix names the negated point, a different key
        const negated = Uint8Array.from([compressed[0] ^ 1, ...compressed.subarray(1)]);
        assert.equal(await (await Triauth.Verifiers.Ecdsa.fromPublishableKey(b64u(negated))).verify(message, signature, {}, {}), false);
      }
    });

    it('WebAuthnEs256 builds a verifier from the compressed key of either prefix', async () => {
      for (const {raw} of await keyPairs()) {
        const compressed = Uint8Array.from([0x02 | (raw[64] & 1), ...raw.subarray(1, 33)]);
        assert.ok(await Triauth.Verifiers.WebAuthnEs256.fromPublishableKey(b64u(compressed)) instanceof Triauth.Verifiers.WebAuthnEs256);
      }
    });

    it('Ecdsa and WebAuthnEs256 resolve to null for the hybrid form of a valid key', async () => {
      for (const {raw} of await keyPairs()) {
        const hybrid = Uint8Array.from([0x06 | (raw[64] & 1), ...raw.subarray(1)]);
        assert.equal(await Triauth.Verifiers.Ecdsa.fromPublishableKey(b64u(hybrid)), null);
        assert.equal(await Triauth.Verifiers.WebAuthnEs256.fromPublishableKey(b64u(hybrid)), null);
      }
    });

  });

}); }
