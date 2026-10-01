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

/**
 * The base abstract class from which all Verifiers inherit common functions.
 *
 * @class
 * @memberof Triauth.Verifiers
 */
export class Base {

  /**
   * Constructs a verifier for a public key as it is published in an identity record.
   *
   * This is the abstract contract that concrete verifiers (e.g., Ecdsa, Ed25519, WebAuthn) implement.
   *
   * @param rawPublicKey {string} - The publishable key material, as read from the identity record.
   * @param [options={}] {object} - Key options as read from the DNS record that carried the key (e.g., `use`, `uv`).
   * @param [context={}] {object} - Per-verification context threaded through from `Triauth.IdentityKeys#verify`
   *                                (e.g., `idx`, `mode`, `webAuthnOrigin`).
   * @param [config={}] {object}  - Optional overrides for the global Triauth.config settings
   *
   * @returns {Promise<Base|null>} A promise that resolves to a verifier instance, or to null when the key
   *          material cannot be imported. A key whose verifier cannot be constructed is skipped, never trusted.
   */
  // eslint-disable-next-line no-unused-vars
  static async fromPublishableKey(rawPublicKey, options = {}, context = {}, config = {}) {
    throw new Error('Triauth.Verifiers.Base.fromPublishableKey is abstract and must be implemented by a subclass');
  }

  /**
   * Verifies that a given signature matches the verifier's public key and the given message.
   *
   * This is the abstract contract that concrete verifiers (e.g., Ecdsa, Ed25519, WebAuthn) implement.
   *
   * @param message {string} - The message to verify against.
   * @param signatureBase64Url {string} - Base64Url encoded signature.
   * @param signedData {object} - Signature envelope's signedMetadata.
   * @param unsignedData {object} - Signature envelope's unsignedMetadata.
   *
   * @returns {Promise<boolean>} A promise that resolves to true or false basing on the verification result.
   */
  // eslint-disable-next-line no-unused-vars
  async verify(message, signatureBase64Url, signedData, unsignedData) {
    throw new Error('Triauth.Verifiers.Base#verify is abstract and must be implemented by a subclass');
  }

}
