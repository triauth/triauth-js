// A fixed session key, and a challenge sealed under it once, so that the derivation of the request key stays the same
const VECTOR = {
  sessionKey: '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8',
  skid: 'wzI1sz3n1R4biw4FL_VJ3Q',
  challenge: 'eyJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyJ9',
  sealed: 'P2Ba7MARsXQZNhKC.QPOC3-Co8j1POUCTnc-nRsvppsBp8f1i6vJU-NnjzLHkF9mX2O3jV93_WU2IXjT6ha8AX1q75oAQmaDTZUZ-kuJrwg'
};

const OTHER_KEY = 'A'.repeat(43);

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

export default function() { describe('Triauth.RequestCipher', () => {

  it('opens the fixed vector, and computes its skid', async () => {
    assert.equal(await Triauth.RequestCipher.open(VECTOR.sessionKey, VECTOR.sealed), VECTOR.challenge);
    assert.equal(await Triauth.RequestCipher.skid(VECTOR.sessionKey), VECTOR.skid);
  });

  it('seals a challenge that opens under the same session key, as `<iv>.<ciphertext>`', async () => {
    const sealed = await Triauth.RequestCipher.seal(VECTOR.sessionKey, VECTOR.challenge);

    assert.match(sealed, /^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/);
    assert.equal(await Triauth.RequestCipher.open(VECTOR.sessionKey, sealed), VECTOR.challenge);
  });

  it('uses a fresh IV for every seal', async () => {
    const first = await Triauth.RequestCipher.seal(VECTOR.sessionKey, VECTOR.challenge);
    const second = await Triauth.RequestCipher.seal(VECTOR.sessionKey, VECTOR.challenge);

    assert.notEqual(first.split('.')[0], second.split('.')[0]);
  });

  it('refuses a request that was changed in transit, or sealed under another session key', async () => {
    assert(await rejects(Triauth.RequestCipher.open(VECTOR.sessionKey, flip(VECTOR.sealed, 3))), 'changed IV');
    assert(await rejects(Triauth.RequestCipher.open(VECTOR.sessionKey, flip(VECTOR.sealed, VECTOR.sealed.length - 3))), 'changed ciphertext');
    assert(await rejects(Triauth.RequestCipher.open(OTHER_KEY, VECTOR.sealed)), 'another session key');
  });

  it('refuses a malformed sealed request', async () => {
    const [iv, ct] = VECTOR.sealed.split('.');

    for (const malformed of ['', iv, iv + '.', '.' + ct, VECTOR.sealed + '.x', iv.slice(1) + '.' + ct, 123]) {
      assert(await rejects(Triauth.RequestCipher.open(VECTOR.sessionKey, malformed)), String(malformed).slice(0, 20));
    }
  });

  it('gives a different skid for a different session key', async () => {
    const skid = await Triauth.RequestCipher.skid(OTHER_KEY);

    assert.match(skid, /^[A-Za-z0-9_-]{22}$/);
    assert.notEqual(skid, VECTOR.skid);
  });

}); }
