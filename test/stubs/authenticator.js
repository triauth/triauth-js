// Plays the Triauth Authenticator's part of the challenge-response flow in tests. The authenticator receives only the
// public part of the challenge that stage 1 returns, and it seals the response when that challenge carries an `ek`.
class AuthenticatorStub {

  // The challenge as the authenticator receives it: the stored challenge before its `.` and decryption key
  static publicChallenge(storedChallenge) {
    return storedChallenge.split('.')[0];
  }

  // A stored challenge re-encoded from edited challenge data, with the decryption key of the original kept
  static reencode(storedChallenge, data) {
    const decryptionKey = storedChallenge.split('.')[1];
    return Triauth.Helpers.stringToBase64Url(JSON.stringify(data)) + (decryptionKey === undefined ? '' : '.' + decryptionKey);
  }

  // The response as the authenticator sends it: sealed to the challenge's `ek` when it has one. A `false` denial, a
  // non-string envelope, or a challenge that does not decode passes the envelope through unchanged.
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

    return ek === undefined ? envelope : Triauth.ResponseCipher.seal(ek, envelope);
  }
}

export default AuthenticatorStub;
