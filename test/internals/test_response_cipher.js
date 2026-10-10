// RFC 9180, appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode, sequence number 0
const VECTOR = {
  info: '4f6465206f6e2061204772656369616e2055726e',
  pkEm: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
  skEm: '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
  pkRm: '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
  skRm: 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
  pt: '4265617574792069732074727574682c20747275746820626561757479',
  aad: '436f756e742d30',
  ct: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'
};

const P256 = {name: 'ECDH', namedCurve: 'P-256'};
const ENVELOPE = '|auth;john@triauthdemo.org;;https://example.com/;v1;1787224766683;;;S8lEY3KOYs9gsSpCJ8YnbnKHVCJcT0dXRREZCAgfIR_3dqkW3S9eUcfQZc6q2HD2sy56LwndOoSbcGyO2ZbUnw|';

const hexToBytes = (hex) => Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const b64u = (bytes) => Triauth.Helpers.arrayBufferToBase64Url(bytes);

// A P-256 key pair from the vector's raw keys, as Web Crypto imports it
const vectorKeys = async (pkHex, skHex, usages = ['deriveBits']) => {
  const pk = hexToBytes(pkHex);
  const jwk = {kty: 'EC', crv: 'P-256', x: b64u(pk.subarray(1, 33)), y: b64u(pk.subarray(33)), d: b64u(hexToBytes(skHex))};
  return {
    privateKey: await crypto.subtle.importKey('jwk', jwk, P256, false, usages),
    publicKey: await crypto.subtle.importKey('raw', pk, P256, true, [])
  };
};

// Replaces one base64url character at the given index with a different one
const flip = (string, index) => string.slice(0, index) + (string[index] === 'A' ? 'B' : 'A') + string.slice(index + 1);

const rejects = async (promise) => {
  try {
    await promise;
  } catch {
    return true;
  }
  return false;
};

export default function() { describe('Triauth.ResponseCipher', () => {

  it('reproduces the RFC 9180 A.3.1 encapsulated key and ciphertext', async () => {
    const ephemeral = await vectorKeys(VECTOR.pkEm, VECTOR.skEm);
    const {enc, ct} = await Triauth.ResponseCipher.sealBase(hexToBytes(VECTOR.pkRm), hexToBytes(VECTOR.info), hexToBytes(VECTOR.aad), hexToBytes(VECTOR.pt), ephemeral);

    assert.equal(bytesToHex(enc), VECTOR.pkEm);
    assert.equal(bytesToHex(ct), VECTOR.ct);
  });

  it('opens the RFC 9180 A.3.1 ciphertext with the recipient key', async () => {
    const recipient = await vectorKeys(VECTOR.pkRm, VECTOR.skRm);
    const pt = await Triauth.ResponseCipher.openBase(hexToBytes(VECTOR.pkEm), recipient.privateKey, hexToBytes(VECTOR.pkRm), hexToBytes(VECTOR.info), hexToBytes(VECTOR.aad), hexToBytes(VECTOR.ct));

    assert.equal(bytesToHex(pt), VECTOR.pt);
  });

  it('mints key pairs in the wire format: an 87-character uncompressed point and a 43-character scalar', async () => {
    const {encryptionKey, decryptionKey} = await Triauth.ResponseCipher.generateKeyPair();

    assert.match(encryptionKey, /^[A-Za-z0-9_-]{87}$/);
    assert.equal(Triauth.Helpers.base64UrlToUint8(encryptionKey)[0], 0x04);
    assert.match(decryptionKey, /^[A-Za-z0-9_-]{43}$/);
  });

  it('seals a response that opens with the key pair, as `<enc>.<ciphertext>`', async () => {
    const {encryptionKey, decryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const sealed = await Triauth.ResponseCipher.seal(encryptionKey, ENVELOPE);

    assert.match(sealed, /^[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{22,}$/);
    assert(!sealed.includes('john'), 'the sealed response does not show the identifier');
    assert.equal(await Triauth.ResponseCipher.open(encryptionKey, decryptionKey, sealed), ENVELOPE);
  });

  it('round-trips UTF-8 beyond Latin-1', async () => {
    const {encryptionKey, decryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const text = '|auth;Привет \u{1F389}|';

    assert.equal(await Triauth.ResponseCipher.open(encryptionKey, decryptionKey, await Triauth.ResponseCipher.seal(encryptionKey, text)), text);
  });

  it('uses a fresh ephemeral key for every seal', async () => {
    const {encryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const first = await Triauth.ResponseCipher.seal(encryptionKey, ENVELOPE);
    const second = await Triauth.ResponseCipher.seal(encryptionKey, ENVELOPE);

    assert.notEqual(first.split('.')[0], second.split('.')[0]);
    assert.notEqual(first, second);
  });

  it('refuses a ciphertext or encapsulated key that was changed in transit', async () => {
    const {encryptionKey, decryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const sealed = await Triauth.ResponseCipher.seal(encryptionKey, ENVELOPE);

    assert(await rejects(Triauth.ResponseCipher.open(encryptionKey, decryptionKey, flip(sealed, sealed.length - 5))), 'tampered ciphertext');
    assert(await rejects(Triauth.ResponseCipher.open(encryptionKey, decryptionKey, flip(sealed, 40))), 'tampered encapsulated key');
  });

  it('refuses a response sealed to another key pair', async () => {
    const intended = await Triauth.ResponseCipher.generateKeyPair();
    const other = await Triauth.ResponseCipher.generateKeyPair();
    const sealed = await Triauth.ResponseCipher.seal(intended.encryptionKey, ENVELOPE);

    assert(await rejects(Triauth.ResponseCipher.open(other.encryptionKey, other.decryptionKey, sealed)));
    assert(await rejects(Triauth.ResponseCipher.open(intended.encryptionKey, other.decryptionKey, sealed)));
  });

  it('refuses a malformed sealed response', async () => {
    const {encryptionKey, decryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const sealed = await Triauth.ResponseCipher.seal(encryptionKey, ENVELOPE);
    const [enc, ct] = sealed.split('.');

    for (const malformed of [ENVELOPE, enc, enc + '.', '.' + ct, sealed + '.' + ct, '', 'false', 123]) {
      assert(await rejects(Triauth.ResponseCipher.open(encryptionKey, decryptionKey, malformed)), String(malformed).slice(0, 20));
    }
  });

  it('refuses to seal to an encryption key that is not an uncompressed P-256 point', async () => {
    const {encryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const point = Triauth.Helpers.base64UrlToUint8(encryptionKey);
    const compressed = b64u(Uint8Array.of(0x02 + (point[64] & 1), ...point.subarray(1, 33)));
    const offCurve = b64u(Uint8Array.of(0x04, ...new Uint8Array(64).fill(1)));

    for (const invalid of [compressed, offCurve, encryptionKey.slice(0, -2), '']) {
      assert(await rejects(Triauth.ResponseCipher.seal(invalid, ENVELOPE)), invalid.slice(0, 12));
    }
  });

  it('validates the sealed form and its length before any crypto (224)', async () => {
    const {encryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    const sealed = await Triauth.ResponseCipher.seal(encryptionKey, ENVELOPE);
    const [enc] = sealed.split('.');

    assert.equal(Triauth.Validator.validateSealedResponse(sealed).valid, true);

    for (const invalid of [ENVELOPE, enc, enc + '.' + 'A'.repeat(21), sealed + '.x', 'A'.repeat(86) + '.' + 'A'.repeat(22), enc + '.' + 'A'.repeat(30000), null, 123]) {
      const result = Triauth.Validator.validateSealedResponse(invalid);
      assert.equal(result.valid, false, String(invalid).slice(0, 20));
      assert.equal(result.errors[0].code, 224);
    }
  });

}); }
