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

// The HKDF `info` of the request key
const REQUEST_KEY_INFO = Helpers.stringToUtf8Bytes('triauth/request/v1');

/**
 * Seals and opens the requests that follow a sign-in (ping, sign, stamp and attest), so that the redirect URL and
 * the browser history show no identifier and no message.
 *
 * The client application seals the challenge with AES-128-GCM, under a request key that HKDF-SHA256 (RFC 5869)
 * derives from the session key of the sign-in. The request also contains `skid`, a short hash of the session key,
 * so that the authenticator can find the key. Only the client application and the authenticator know the session
 * key, so a request that opens also proves where it comes from.
 *
 * A sealed request is `<iv>.<ciphertext>`, both base64url. The plaintext is the JSON of the challenge.
 *
 * @class
 * @memberof Triauth
 */
export class RequestCipher {

  /**
   * Computes the session key ID, which the request contains readable so that the authenticator can find the key.
   * It is the first 16 bytes of the SHA-256 of the 32 bytes of the session key.
   *
   * @param sessionKey {string} - the session key, 43 base64url characters, without the domain of a delegated key.
   *
   * @returns {Promise<string>} the session key ID, 22 base64url characters.
   */
  static async skid(sessionKey) {
    const digest = await crypto.subtle.digest('SHA-256', /** @type {BufferSource} */ (Helpers.base64UrlToUint8(sessionKey)));
    return Helpers.arrayBufferToBase64Url(new Uint8Array(digest).subarray(0, 16));
  }

  /**
   * Seals a challenge under the session key. This is the client application's side.
   *
   * @param sessionKey {string} - the session key, 43 base64url characters, without the domain of a delegated key.
   * @param challenge {string} - the challenge, base64url.
   *
   * @returns {Promise<string>} the sealed request, `<iv>.<ciphertext>`.
   */
  static async seal(sessionKey, challenge) {
    // The IV comes from Web Crypto and never from `randomSource`. A repeated IV under one key breaks AES-GCM.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv}, await this.#requestKey(sessionKey, 'encrypt'), /** @type {BufferSource} */ (Helpers.base64UrlToUint8(challenge))
    );

    return Helpers.arrayBufferToBase64Url(iv) + '.' + Helpers.arrayBufferToBase64Url(ct);
  }

  /**
   * Opens a sealed request with the session key. This is the authenticator's side.
   *
   * @param sessionKey {string} - the session key, 43 base64url characters, without the domain of a delegated key.
   * @param sealedRequest {string} - the sealed request, `<iv>.<ciphertext>`.
   *
   * @returns {Promise<string>} the challenge, base64url.
   *
   * @throws {Error} when the sealed request is malformed, or does not open under this session key.
   */
  static async open(sessionKey, sealedRequest) {
    const [iv, ct, rest] = String(sealedRequest).split('.');

    if (rest !== undefined || iv?.length !== 16 || !ct) {
      throw new TypeError('Malformed sealed request');
    }

    const pt = await crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: /** @type {BufferSource} */ (Helpers.base64UrlToUint8(iv))},
      await this.#requestKey(sessionKey, 'decrypt'), /** @type {BufferSource} */ (Helpers.base64UrlToUint8(ct))
    );

    return Helpers.arrayBufferToBase64Url(new Uint8Array(pt));
  }

  /**
   * Derives the AES-128-GCM request key from the session key with HKDF-SHA256 (RFC 5869). The empty salt acts as 32
   * zero bytes, and the info label keeps this key apart from any other key of the session.
   *
   * @param sessionKey {string} - the session key, 43 base64url characters.
   * @param usage {KeyUsage} - `encrypt` or `decrypt`.
   *
   * @returns {Promise<CryptoKey>} the request key.
   */
  static async #requestKey(sessionKey, usage) {
    const ikm = await crypto.subtle.importKey('raw', /** @type {BufferSource} */ (Helpers.base64UrlToUint8(sessionKey)), 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      {name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: /** @type {BufferSource} */ (REQUEST_KEY_INFO)},
      ikm, {name: 'AES-GCM', length: 128}, false, [usage]
    );
  }
}
