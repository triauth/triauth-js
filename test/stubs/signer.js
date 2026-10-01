class Signer {

  // Derives the Web Crypto import parameters from the JWK itself,
  // so that both EC (P-256) and OKP (Ed25519) fixture keys can be used.
  static algorithmForJWK(jwkPrivateKey) {
    if (jwkPrivateKey.kty === 'OKP' && jwkPrivateKey.crv === 'Ed25519') {
      return {name: 'Ed25519'};
    }
    return {name: 'ECDSA', namedCurve: 'P-256', hash: {name: 'SHA-256'}};
  }

  static async fromJWK(jwkPrivateKeys, options=undefined) {
    jwkPrivateKeys = jwkPrivateKeys instanceof Array ? jwkPrivateKeys : [jwkPrivateKeys];
    const privateCryptoKeys = [];

    for (const jwkPrivateKey of jwkPrivateKeys) {
      const algorithm = options || Signer.algorithmForJWK(jwkPrivateKey);
      const cryptoKey = await crypto.subtle.importKey('jwk', jwkPrivateKey, algorithm, true, ['sign']);
      privateCryptoKeys.push(cryptoKey);
    }

    return new Signer(privateCryptoKeys);
  }

  static async fromDeviceKeys(keys) {
    return Signer.fromJWK(keys.map((k) => k.private));
  }

  static signUsingDeviceKeys(keys) {

    return async (payload) => {
      const signer = await Signer.fromDeviceKeys(keys);
      return signer.sign(payload);
    }
  }

  constructor(privateCryptoKeys) {
    this.privateCryptoKeys = privateCryptoKeys;
  }

  async sign(message) {
    const data = new TextEncoder().encode(message);

    const signatures = [];

    for (const privateKey of this.privateCryptoKeys) {
      const algorithm = privateKey.algorithm.name === 'Ed25519'
        ? {name: 'Ed25519'}
        : {name: 'ECDSA', namedCurve: 'P-256', hash: {name: 'SHA-256'}};

      const cryptoSig = await crypto.subtle.sign(
        algorithm,
        privateKey,
        data
      );

      signatures.push(Triauth.Helpers.arrayBufferToBase64Url(cryptoSig));
    }

    return signatures;
  }

}

export default Signer;
