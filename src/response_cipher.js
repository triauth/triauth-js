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

import { Helpers } from './helpers.js';

const P256 = { name: 'ECDH', namedCurve: 'P-256' };
const EMPTY = new Uint8Array(0);

// The version label at the start of every labeled HKDF input (RFC 9180, section 4)
const HPKE_V1 = Helpers.stringToUtf8Bytes('HPKE-v1');

// The suite identifiers of the labeled HKDF steps, with the IDs from RFC 9180, section 7. KEM_ID is "KEM" and the KEM
// ID 0x0010 for DHKEM(P-256, HKDF-SHA256), as in RFC 9180, section 4.1. SUITE_ID is "HPKE", the same KEM ID, the KDF ID
// 0x0001 for HKDF-SHA256 and the AEAD ID 0x0001 for AES-128-GCM, as in RFC 9180, section 5.1.
const KEM_ID = Uint8Array.of(0x4b, 0x45, 0x4d, 0x00, 0x10);
const SUITE_ID = Uint8Array.of(0x48, 0x50, 0x4b, 0x45, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01);

// The `info` of the key schedule (RFC 9180, section 5.1). It binds every sealed response to this protocol and version,
// so a response sealed for another application or version does not open.
const INFO = Helpers.stringToUtf8Bytes('triauth/response/v1');

/**
 * Seals and opens the responses of the challenge-response flows, so that a response travels only as ciphertext.
 *
 * The construction is HPKE, Hybrid Public Key Encryption (RFC 9180, https://www.rfc-editor.org/rfc/rfc9180). HPKE
 * encrypts a message to a public key in three steps. The sender makes a one-time key pair and runs ECDH with the
 * recipient's public key to get a shared secret. HKDF derives an AES key and a nonce from that secret. AES-GCM encrypts
 * the message and adds a tag that detects any change. The sender's one-time public key (`enc`) goes with the
 * ciphertext. With it, the recipient runs ECDH with its private key and derives the same AES key.
 *
 * This class uses the DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM suite in base mode, single shot. Base
 * mode has no pre-shared key and does not authenticate the sender. The signatures inside the response do that. Single
 * shot means that each key schedule encrypts one message.
 *
 * The client application mints a fresh key pair for every challenge. The challenge contains the public key as `ek`,
 * and the private key stays with the stored challenge. The Triauth Authenticator seals the response to `ek`, so only
 * the holder of the stored challenge can open it.
 *
 * A sealed response is `<enc>.<ciphertext>`, both base64url.
 *
 * @class
 * @memberof Triauth
 */
export class ResponseCipher {

  /**
   * Mints a fresh key pair for one challenge.
   *
   * @returns {Promise<{encryptionKey: string, decryptionKey: string}>} `encryptionKey` is the public key for the
   *          challenge's `ek`, an uncompressed P-256 point in 87 base64url characters. `decryptionKey` is the private
   *          scalar in 43 base64url characters, which stays with the stored challenge.
   */
  static async generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(P256, true, ['deriveBits']);

    return {
      encryptionKey: Helpers.arrayBufferToBase64Url(await crypto.subtle.exportKey('raw', keyPair.publicKey)),
      decryptionKey: (await crypto.subtle.exportKey('jwk', keyPair.privateKey)).d
    };
  }

  /**
   * Seals a response envelope to the challenge's encryption key. This is the authenticator's side. Every call makes a
   * new one-time key pair, so the same envelope seals to different bytes each time.
   *
   * @param encryptionKey {string} - the challenge's `ek`.
   * @param response {string} - the response envelope (`|...|`).
   *
   * @returns {Promise<string>} the sealed response, `<enc>.<ciphertext>`.
   *
   * @throws {Error} when the encryption key is not a P-256 point.
   */
  static async seal(encryptionKey, response) {
    const {enc, ct} = await this.sealBase(Helpers.base64UrlToUint8(encryptionKey), INFO, EMPTY, Helpers.stringToUtf8Bytes(response));
    return Helpers.arrayBufferToBase64Url(enc) + '.' + Helpers.arrayBufferToBase64Url(ct);
  }

  /**
   * Opens a sealed response with the key pair of its challenge. This is the client application's side.
   *
   * @param encryptionKey {string} - the challenge's `ek`.
   * @param decryptionKey {string} - the private scalar kept with the stored challenge.
   * @param sealedResponse {string} - the sealed response, `<enc>.<ciphertext>`.
   *
   * @returns {Promise<string>} the response envelope.
   *
   * @throws {Error} when the sealed response is malformed, or was not sealed to this key pair.
   */
  static async open(encryptionKey, decryptionKey, sealedResponse) {
    const [enc, ct, rest] = String(sealedResponse).split('.');

    if (rest !== undefined || !enc || !ct) {
      throw new TypeError('Malformed sealed response');
    }

    const pkRm = Helpers.base64UrlToUint8(encryptionKey);
    const skR = await crypto.subtle.importKey('jwk', {
      kty: 'EC', crv: 'P-256', d: decryptionKey,
      x: Helpers.arrayBufferToBase64Url(pkRm.subarray(1, 33)),
      y: Helpers.arrayBufferToBase64Url(pkRm.subarray(33, 65))
    }, P256, false, ['deriveBits']);

    const pt = await this.openBase(Helpers.base64UrlToUint8(enc), skR, pkRm, INFO, EMPTY, Helpers.base64UrlToUint8(ct));
    return Helpers.utf8BytesToString(pt);
  }

  /**
   * HPKE single-shot seal in base mode (RFC 9180, section 6.1). Encap makes the one-time key pair and the shared
   * secret (RFC 9180, section 4.1). The key schedule derives the AES key and nonce (RFC 9180, section 5.1). AES-GCM
   * then encrypts the plaintext.
   *
   * @param pkRm {Uint8Array} - the recipient's public key, an uncompressed P-256 point.
   * @param info {Uint8Array} - the application context.
   * @param aad {Uint8Array} - the associated data, authenticated but not encrypted.
   * @param pt {Uint8Array} - the plaintext.
   * @param [ephemeral=null] {?CryptoKeyPair} - a fixed sender key pair, only for known-answer tests such as the
   *   RFC 9180 test vector A.3.1. Reusing it for the same recipient repeats the AES key and nonce, which breaks AES-GCM.
   *
   * @returns {Promise<{enc: Uint8Array, ct: Uint8Array}>} the encapsulated key (the sender's one-time public key) and
   *          the ciphertext with its 16-byte tag.
   */
  static async sealBase(pkRm, info, aad, pt, ephemeral = null) {
    ephemeral ??= await crypto.subtle.generateKey(P256, true, ['deriveBits']);

    const enc = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
    const {key, nonce} = await this.#keySchedule(await this.#ecdh(ephemeral.privateKey, pkRm), enc, pkRm, info);
    const ct = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv: /** @type {BufferSource} */ (nonce), additionalData: /** @type {BufferSource} */ (aad)},
      key, /** @type {BufferSource} */ (pt)
    );

    return {enc, ct: new Uint8Array(ct)};
  }

  /**
   * HPKE single-shot open in base mode (RFC 9180, section 6.1). Decap recovers the shared secret from `enc` and the
   * recipient's private key (RFC 9180, section 4.1). The key schedule derives the same AES key and nonce (RFC 9180,
   * section 5.1). AES-GCM then decrypts the ciphertext and checks its tag.
   *
   * @param enc {Uint8Array} - the encapsulated key, the sender's one-time public key.
   * @param skR {CryptoKey} - the recipient's private key.
   * @param pkRm {Uint8Array} - the recipient's public key, an uncompressed P-256 point.
   * @param info {Uint8Array} - the application context.
   * @param aad {Uint8Array} - the associated data.
   * @param ct {Uint8Array} - the ciphertext with its tag.
   *
   * @returns {Promise<Uint8Array>} the plaintext.
   *
   * @throws {Error} when the ciphertext does not authenticate under this key pair.
   */
  static async openBase(enc, skR, pkRm, info, aad, ct) {
    const {key, nonce} = await this.#keySchedule(await this.#ecdh(skR, enc), enc, pkRm, info);
    const pt = await crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: /** @type {BufferSource} */ (nonce), additionalData: /** @type {BufferSource} */ (aad)},
      key, /** @type {BufferSource} */ (ct)
    );

    return new Uint8Array(pt);
  }

  /**
   * P-256 Diffie-Hellman, the DH() function of the DHKEM (RFC 9180, section 4.1). Its result is the x-coordinate of
   * the shared point, 32 bytes. The public key must be an uncompressed point (RFC 9180, section 7.1.1). The Web Crypto
   * import rejects a point that is not on the curve, as RFC 9180, section 7.1.4 requires.
   *
   * @param privateKey {CryptoKey} - this side's private key, the sender's one-time key or the recipient's key.
   * @param publicKeyBytes {Uint8Array} - the other side's public key, an uncompressed P-256 point of 65 bytes.
   *
   * @returns {Promise<Uint8Array>} the 32-byte Diffie-Hellman shared secret.
   *
   * @throws {Error} when the public key is not an uncompressed point on the P-256 curve.
   */
  static async #ecdh(privateKey, publicKeyBytes) {
    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04) {
      throw new TypeError('Invalid public key');
    }

    const publicKey = await crypto.subtle.importKey('raw', /** @type {BufferSource} */ (publicKeyBytes), P256, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({name: 'ECDH', public: publicKey}, privateKey, 256));
  }

  /**
   * Derives the AES key and nonce for one message. ExtractAndExpand derives the KEM shared secret from the DH result
   * and both public keys (RFC 9180, section 4.1). KeySchedule then derives the key and the base nonce for base mode,
   * with an empty pre-shared key (RFC 9180, section 5.1). One message per context means sequence number 0, so the
   * nonce is the base nonce itself (RFC 9180, section 5.2).
   *
   * @param dh {Uint8Array} - the 32-byte Diffie-Hellman shared secret.
   * @param enc {Uint8Array} - the sender's one-time public key.
   * @param pkRm {Uint8Array} - the recipient's public key, an uncompressed P-256 point.
   * @param info {Uint8Array} - the application context.
   *
   * @returns {Promise<{key: CryptoKey, nonce: Uint8Array}>} the AES-128-GCM key and the 12-byte nonce.
   */
  static async #keySchedule(dh, enc, pkRm, info) {
    const sharedSecret = await this.#hkdf(KEM_ID, EMPTY, 'eae_prk', dh, 'shared_secret', this.#concat(enc, pkRm), 32);
    // mode_base (0x00), then the hashes of the empty PSK ID and of info
    const context = this.#concat(Uint8Array.of(0x00), await this.#extract('psk_id_hash', EMPTY), await this.#extract('info_hash', info));
    const key = await this.#hkdf(SUITE_ID, sharedSecret, 'secret', EMPTY, 'key', context, 16);

    return {
      key: await crypto.subtle.importKey('raw', /** @type {BufferSource} */ (key), 'AES-GCM', false, ['encrypt', 'decrypt']),
      nonce: await this.#hkdf(SUITE_ID, sharedSecret, 'secret', EMPTY, 'base_nonce', context, 12)
    };
  }

  /**
   * LabeledExtract followed by LabeledExpand (RFC 9180, section 4). Web Crypto's HKDF runs Extract and then Expand
   * (RFC 5869), so one call does both. The labeled inputs start with "HPKE-v1", the suite ID and the step's label.
   * This keeps every derived value apart from the others.
   *
   * @param suiteId {Uint8Array} - KEM_ID for the DHKEM step, SUITE_ID for the key schedule.
   * @param salt {Uint8Array} - the Extract salt. An empty salt acts as 32 zero bytes (RFC 5869, section 2.2).
   * @param extractLabel {string} - the LabeledExtract label, such as `eae_prk`.
   * @param ikm {Uint8Array} - the input keying material.
   * @param expandLabel {string} - the LabeledExpand label, such as `shared_secret`.
   * @param info {Uint8Array} - the LabeledExpand context.
   * @param length {number} - the output length in bytes, below 256.
   *
   * @returns {Promise<Uint8Array>} the derived bytes.
   */
  static async #hkdf(suiteId, salt, extractLabel, ikm, expandLabel, info, length) {
    const labeledIkm = this.#concat(HPKE_V1, suiteId, Helpers.stringToUtf8Bytes(extractLabel), ikm);
    const labeledInfo = this.#concat(Uint8Array.of(0x00, length), HPKE_V1, suiteId, Helpers.stringToUtf8Bytes(expandLabel), info);
    const hkdfKey = await crypto.subtle.importKey('raw', /** @type {BufferSource} */ (labeledIkm), 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      {name: 'HKDF', hash: 'SHA-256', salt: /** @type {BufferSource} */ (salt), info: /** @type {BufferSource} */ (labeledInfo)},
      hkdfKey, length * 8
    );

    return new Uint8Array(bits);
  }

  /**
   * LabeledExtract with an empty salt (RFC 9180, section 4), for `psk_id_hash` and `info_hash`. RFC 5869 sets a
   * missing salt to 32 zero bytes for SHA-256. HMAC under 32 zero bytes gives the same result as HMAC under an empty
   * key, which Web Crypto refuses.
   *
   * @param label {string} - the label, `psk_id_hash` or `info_hash`.
   * @param ikm {Uint8Array} - the input keying material.
   *
   * @returns {Promise<Uint8Array>} the 32-byte pseudorandom key.
   */
  static async #extract(label, ikm) {
    return Helpers.hmacSha256(new Uint8Array(32), this.#concat(HPKE_V1, SUITE_ID, Helpers.stringToUtf8Bytes(label), ikm));
  }

  /**
   * Joins byte strings in order, the concat() of RFC 9180.
   *
   * @param parts {...Uint8Array} - the byte strings.
   *
   * @returns {Uint8Array} the joined bytes.
   */
  static #concat(...parts) {
    const rv = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;

    for (const part of parts) {
      rv.set(part, offset);
      offset += part.length;
    }

    return rv;
  }
}
