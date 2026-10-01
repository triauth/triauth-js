/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { Base } from './base.js';
import { register } from './registry.js';
import { Helpers } from '../helpers.js';

/**
 * The base abstract verifier for WebAuthn signatures.
 *
 * Performs the WebAuthn-level assertion validation.
 * Subclasses must define concrete importAlgorithm, verifyAlgorithm, and register themselves (e.g., as `webauthn-es256`).
 *
 * @class
 * @memberof Triauth.Verifiers
 */
export class WebAuthn extends Base {

  // The Web Crypto parameters used to import the publishable key and to verify
  // assertion signatures. Concrete subclasses MUST override these to bind a
  // credential algorithm; left null, the verifier fails closed.

  /** @type {AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm | null} */
  static importAlgorithm = null;

  /** @type {AlgorithmIdentifier | RsaPssParams | EcdsaParams | null} */
  static verifyAlgorithm = null;

  /**
   * Constructs a new instance of verifier for the given public crypto key and options.
   *
   * @param publicKey {CryptoKey} - A public key in form of CryptoKey object.
   * @param [options={}] {object} - Key options as read from the DNS record that contained the publicKey.
   *        Supports `uv: 'required'` - assertions are then accepted only with the User Verified (UV) flag set
   *        (i.e., the authenticator checked PIN/biometrics).
   * @param [context={}] {{idx?: number, mode?: string, webAuthnOrigin?: string}} -
   *        Per-verification context. `idx` (key's index in its keyGroup) selects which `unsignedData.sig[idx]` entry to verify against;
   *        `webAuthnOrigin`, if set, is enforced against `clientData.origin`. Stored on `this.context`.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   */
  constructor(publicKey, options = {}, context = {}, config = {}) {
    super();

    this.publicKey = publicKey;
    this.options = options;
    this.context = context;
    this.config = Helpers.mergeConfig(config);
  }

  /**
   * Builds an instance of the Verifier from the raw key information read from the DNS.
   *
   * @param rawPublicKey {string} - A key as published in the DNS record.
   * @param [options={}] {object} - Key options as read from the DNS record that contained the rawPublicKey.
   * @param [context={}] {{idx?: number, mode?: string, webAuthnOrigin?: string}} -
   *        Per-verification context. `idx` (key's index in its keyGroup) selects which `unsignedData.sig[idx]` entry to verify against;
   *        `webAuthnOrigin`, if set, is enforced against `clientData.origin`. Stored on `this.context`.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   *
   * @returns {Promise<WebAuthn|null>} A promise that resolves to the instance of this verifier, or null if key is invalid or other problem occurred.
   */
  static async fromPublishableKey(rawPublicKey, options = {}, context = {}, config = {}) {
    config = Helpers.mergeConfig(config);

    const importAlgorithm = this.importAlgorithm;
    if (!importAlgorithm) {
      config.logger?.debug?.('WebAuthn is an algorithm-agnostic base verifier - use a concrete subclass (e.g., WebAuthnEs256)');
      return null;
    }

    try {
      const publicKey = (await crypto.subtle.importKey('raw', /** @type {BufferSource} */ (Helpers.base64UrlToUint8(rawPublicKey)), importAlgorithm, true, ['verify']));

      return new this(publicKey, options, context, config);

    } catch (err) {
      config.logger?.debug?.(err);
      return null;
    }
  }

  /**
   * Verifies that a given signature matches the verifier's public key and the given message.
   *
   * @param message {string} - The message that was signed; its SHA-256 digest must match `clientData.challenge`.
   * @param signatureBase64Url {string} - Base64Url encoded signature over `(authenticatorData || sha256(clientDataJSON))`.
   * @param signedData {object} - Signature envelope's signedMetadata. Unused by this verifier.
   * @param unsignedData {{sig: Object<number, {clientDataJSON: string, authenticatorData: string}>}} -
   *        Signature envelope's unsignedMetadata. Must contain `sig[idx]` for this key's index (set on `this.context.idx`),
   *        carrying the original `clientDataJSON` (string) and `authenticatorData` (base64url, minimum 37 bytes,
   *        with the User Present flag set - silent CTAP-level assertions are rejected).
   *
   * @returns {Promise<boolean>} A promise that resolves to true or false basing on the verification result.
   */
  async verify(message, signatureBase64Url, signedData, unsignedData) {
    try {
      /** @type {AlgorithmIdentifier | RsaPssParams | EcdsaParams | null} */
      const verifyAlgorithm = (/** @type {*} */ (this.constructor)).verifyAlgorithm;
      if (!verifyAlgorithm) {
        this.config.logger?.debug?.('WebAuthn is an algorithm-agnostic base verifier - use a concrete subclass (e.g., WebAuthnEs256)');
        return false;
      }

      const idx = this.context.idx;
      const expectedChallenge = await Helpers.sha256(message);
      const expectedOrigin = this.context.webAuthnOrigin;

      // SECURITY NOTE: `unsignedData` is NOT covered by the triauth envelope's signature, but:
      //   - clientData.challenge is checked to be the expectedChallenge
      //   - (authenticatorData + sha256(clientDataJSON)) is covered by the WebAuthn-signed payload
      if (
        typeof unsignedData !== 'object' ||
        typeof unsignedData.sig !== 'object' ||
        typeof unsignedData.sig[idx] !== 'object' ||
        typeof unsignedData.sig[idx].clientDataJSON !== 'string' ||
        !Helpers.isBase64UrlString(unsignedData.sig[idx].authenticatorData)
      ) {
        return false;
      }

      const { authenticatorData, clientDataJSON } = unsignedData.sig[idx];

      // Verify clientData structure, including that the clientData.challenge is an SHA-256 digest of the message
      const clientData = Helpers.safeParseJson(clientDataJSON);
      if(
        clientData.challenge !== expectedChallenge ||               // <--- challenge MUST MATCH --- !!!
        clientDataJSON.match(/"challenge":/g).length !== 1 ||       // Ensure that "challenge" key appears exactly once in the clientDataJSON, as an extra safety precaution
        clientData.type !== 'webauthn.get' ||                       // type should always be 'webauthn.get'
        (clientData.crossOrigin !== false && clientData.crossOrigin !== undefined) || // if present, must be exactly false (a cross-origin <iframe> assertion carries true); the member is optional and absent means top-level same-origin (WebKit omits it)
        (expectedOrigin && clientData.origin !== expectedOrigin)    // origin, if available from context, must match
      ) {
        return false;
      }

      // Parse the authenticatorData: 32-byte rpIdHash, 1 flags byte, 4-byte signCount (37 bytes minimum)
      const authenticatorDataBytes = Helpers.base64UrlToUint8(authenticatorData);
      if (authenticatorDataBytes.length < 37) {
        this.config.logger?.debug?.('WebAuthn assertion rejected - authenticatorData shorter than 37 bytes');
        return false;
      }

      // Require the User Present (UP) flag, as the W3C Web Authentication specification mandates for assertions.
      // Browser-mediated assertions always carry UP=1 (the client performs a presence test before
      // returning one); its absence indicates a CTAP-level "silent" assertion (options.up=false),
      // e.g., minted by malware with direct access to a connected authenticator.
      //
      // The rpIdHash (bytes 0-31) is intentionally NOT checked: the public key is pinned in the
      // DNS identity records and a WebAuthn credential only ever signs under its own rpId, so
      // there is no cross-RP credential confusion to prevent; the phishing angle is covered by
      // the clientData.origin check above. The signCount (bytes 33-36) is not checked either:
      // clone detection requires server-side state that this stateless verifier does not have
      // (and modern passkeys report a constant 0).
      if ((authenticatorDataBytes[32] & 0x01) !== 0x01) {
        this.config.logger?.debug?.('WebAuthn assertion rejected - User Present (UP) flag not set');
        return false;
      }

      // When the key record demands user verification (`uv=required`), also require the
      // User Verified (UV) flag - i.e., the authenticator must have checked PIN/biometrics.
      // Key records carrying any other `uv` value never reach this point - they taint their
      // whole keyGroup during Triauth.IdentityKeys#add (fail closed, never silently weaker).
      if (this.options.uv === 'required' && (authenticatorDataBytes[32] & 0x04) !== 0x04) {
        this.config.logger?.debug?.('WebAuthn assertion rejected - User Verified (UV) flag required by key options but not set');
        return false;
      }

      // Reconstruct the payload that was signed by webauthn
      const clientDataHash = await crypto.subtle.digest(
        'SHA-256',
        /** @type {BufferSource} */ (Helpers.stringToUtf8Bytes(clientDataJSON))
      );

      const webAuthnPayload = new Uint8Array([
        ...new Uint8Array(authenticatorDataBytes),
        ...new Uint8Array(clientDataHash)
      ]);

      // Convert the signature being verified back to UInt8Array for crypto.verify
      const signature = Helpers.base64UrlToUint8(signatureBase64Url);

      // Verify the digital signature (may raise an exception if arguments are invalid)
      return await crypto.subtle.verify(
        verifyAlgorithm,
        this.publicKey,
        /** @type {BufferSource} */ (signature),
        webAuthnPayload
      );

    } catch (err) {
      this.config.logger?.debug?.(err);
      return false;
    }
  }

}

/**
 * A verifier for WebAuthn signatures backed by ECDSA P-256 (ES256) credentials.
 *
 * Shares all WebAuthn assertion validation with the WebAuthn base class; this subclass
 * only binds the ES256 credential algorithm.
 *
 * @class
 * @memberof Triauth.Verifiers
 *
 */
export class WebAuthnEs256 extends WebAuthn {

  static importAlgorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  static verifyAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };

}

/**
 * A verifier for WebAuthn signatures backed by Ed25519 (EdDSA over Curve25519) credentials.
 *
 * Shares all WebAuthn assertion validation with the WebAuthn base class; this subclass
 * only binds the Ed25519 credential algorithm. Like the plain Ed25519 verifier, it requires
 * Ed25519 support in the runtime's Web Crypto API (Node.js 18.4+; Safari 17+, Firefox 130+,
 * Chrome/Edge 137+) - on runtimes without it, `fromPublishableKey` resolves to null and the
 * keyGroup fails verification (fail closed).
 *
 * @class
 * @memberof Triauth.Verifiers
 *
 */
export class WebAuthnEd25519 extends WebAuthn {

  static importAlgorithm = { name: 'Ed25519' };
  static verifyAlgorithm = { name: 'Ed25519' };

}

register('webauthn-es256', WebAuthnEs256);
register('webauthn-ed25519', WebAuthnEd25519);
