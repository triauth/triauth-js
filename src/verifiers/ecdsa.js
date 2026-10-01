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
 * The verifier for ECDSA signatures (P-256 curve with SHA-256).
 * This is the default verifier in triauth.
 *
 * @class
 * @memberof Triauth.Verifiers
 */
export class Ecdsa extends Base {

  /**
   * Constructs a new instance of ECDSA verifier for the given public crypto key and options.
   *
   * @param publicKey {CryptoKey} - A public key in form of CryptoKey object.
   * @param [options={}] {object} - Key options as read from the DNS record that contained the publicKey.
   * @param [context={}] {object} - Per-verification context. Unused by this verifier.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   */
  // eslint-disable-next-line no-unused-vars
  constructor(publicKey, options = {}, context = {}, config = {}) {
    super();

    this.publicKey = publicKey;
    this.config = Helpers.mergeConfig(config);
  }

  /**
   * Builds an instance of the Verifier from the raw key information read from the DNS.
   *
   * @param rawPublicKey {string} - A key as published in the DNS record.
   * @param [options={}] {object} - Key options as read from the DNS record that contained the rawPublicKey.
   * @param [context={}] {object} - Per-verification context. Unused by this verifier.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   *
   * @returns {Promise<Ecdsa|null>} A promise that resolves to the instance of this verifier, or null if key is invalid or other problem occurred.
   */
  static async fromPublishableKey(rawPublicKey, options = {}, context = {}, config = {}) {
    config = Helpers.mergeConfig(config);

    try {
      const publicKey = (await crypto.subtle.importKey('raw', /** @type {BufferSource} */ (Helpers.base64UrlToUint8(rawPublicKey)), {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256'
      }, true, ['verify']));
      return new this(publicKey, options, context, config);
    } catch (err) {
      config.logger?.debug?.(err);
      return null;
    }
  }

  /**
   * Verifies that a given signature matches the verifier's public key and the given message.
   *
   * @param message {string} - The message to verify against.
   * @param signatureBase64Url {string} - Base64Url encoded signature.
   * @param signedData {object} - Signature envelope's signedMetadata. Unused by this verifier.
   * @param unsignedData {object} - Signature envelope's unsignedMetadata. Unused by this verifier.
   *
   * @returns {Promise<boolean>} A promise that resolves to true or false basing on the verification result.
   */
  // eslint-disable-next-line no-unused-vars
  async verify(message, signatureBase64Url, signedData, unsignedData) {
    try {
      const data = Helpers.stringToUtf8Bytes(message);
      const signature = Helpers.base64UrlToUint8(signatureBase64Url);
      return await crypto.subtle.verify({
        name: 'ECDSA',
        hash: 'SHA-256'
      }, this.publicKey, /** @type {BufferSource} */ (signature), /** @type {BufferSource} */ (data));
    } catch (err) {
      this.config.logger?.debug?.(err);
      return false;
    }
  }

}

register('es256', Ecdsa);
