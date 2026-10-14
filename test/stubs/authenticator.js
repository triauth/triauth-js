// Plays the Triauth Authenticator's part of the challenge-response flow in tests. The authenticator receives only the
// public part of the challenge that stage 1 returns, and it seals the response to that challenge's `ek`.
class AuthenticatorStub {

  // A session key as `Triauth.authenticate` returns it, for the flows that follow a sign-in
  static SESSION_KEY = '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8';

  // The challenge as the authenticator receives it: the stored challenge before its `.` and decryption key
  static publicChallenge(storedChallenge) {
    return storedChallenge.split('.')[0];
  }

  // A stored challenge re-encoded from edited challenge data, with the decryption key of the original kept
  static reencode(storedChallenge, data) {
    const decryptionKey = storedChallenge.split('.')[1];
    return Triauth.Helpers.stringToBase64Url(JSON.stringify(data)) + (decryptionKey === undefined ? '' : '.' + decryptionKey);
  }

  // A stored challenge for hand-built challenge data: the data gets a fresh `ek`, and the stored form keeps its key
  static async store(data) {
    const {encryptionKey, decryptionKey} = await Triauth.ResponseCipher.generateKeyPair();
    return Triauth.Helpers.stringToBase64Url(JSON.stringify({...data, ek: encryptionKey})) + '.' + decryptionKey;
  }

  // The response as the authenticator sends it, sealed to the challenge's `ek`. A `false` denial, a non-string
  // envelope, a challenge that does not decode, or a challenge without `ek` (which the authenticator refuses) passes
  // the envelope through unchanged, so tests can show that stage 3 refuses it.
  static async seal(storedChallenge, envelope) {
    if (typeof storedChallenge !== 'string' || typeof envelope !== 'string' || envelope === 'false') {
      return envelope;
    }

    let ek;
    try {
      ek = Triauth.Challenge.fromString(AuthenticatorStub.publicChallenge(storedChallenge)).data.ek;
    } catch {
      return envelope;
    }

    return ek === undefined ? envelope : (await Triauth.ResponseCipher.seal(ek, envelope)).sealedResponse;
  }
}

export default AuthenticatorStub;
