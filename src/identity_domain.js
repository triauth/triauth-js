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
import { AT_MARKER, PRIVATE_LABEL_LENGTH } from './protocol.js';

/**
 * Derives a domain name under which identity records are stored, and reads the identity records from DNS
 * (e.g., `john._at.triauthdemo.org` for `mode=public` domains or `_AXD3AKE8EX._at.triauthdemo.org` for `mode=private` domains).
 *
 * Objects of this class start in unresolved state, and need to be resolved with a call to resolve() that queries the DNS.
 *
 * @class
 * @memberof Triauth
 */
export class IdentityDomain {

  /**
   * Memoizes the resolution, so that concurrent and repeated `resolve()` calls share a single
   * DNS round trip. A rejection is memoized too, and is replayed to every later caller.
   * @type {?Promise<boolean>}
   */
  #resolvePromise = null;

  /**
   * Returns the full derived label of a private-mode identity: the base32 encoding of the HMAC-SHA-256
   * of the identifier, keyed by the identity's lookup code.
   *
   * The identifier needs to be in downcase, as results of this function are case-sensitive.
   *
   * @param identifier {string} - the identifier to derive from
   * @param lookupCode {string} - the identity's lookup code, the HMAC key
   * @returns {Promise<string>} A promise that resolves to the 52-character base32 string whose first PRIVATE_LABEL_LENGTH characters form the label of the identity domain, e.g., '4GIBDU53B3KGFSZUD5KRVUGITFQ2QAN2C55FNXO25S53WGT6CK6A'
   */
  static async deriveFullLabel(identifier, lookupCode) {
    return Helpers.uInt8ArrayToBase32(
      await Helpers.hmacSha256(Helpers.stringToUtf8Bytes(lookupCode), Helpers.stringToUtf8Bytes(identifier))
    );
  }

  /**
   * Derives a domain name under which identity records are being kept for the passed identifier.
   * Expects a pre-validated identifier (see Triauth.Validator.validateIdentifier).
   *
   * @param identifier {string} - a pre-validated user identifier
   * @param [options={}] {object} - options as read from the DNS TXT record specifying the authentication endpoint (`mode`), plus the identity's `lookupCode` under `mode=private`
   * @returns {Promise<null|{domainName:string, fullLabel?:string}>} A promise that resolves to the domain name (carrying the untruncated label under `mode=private`), or null when no domain name can be derived (an unknown mode, or a missing/malformed lookup code under `mode=private`)
   */
  static async derive(identifier, options = {}) {

    // Extract the original domain name from the identifier
    const identifierDomain = identifier.split('@')[1];

    // The mode decides the way identity domain is derived
    const mode = options.mode;

    if (mode === 'public') {
      return { domainName: identifier.replace('@', AT_MARKER) };
    }

    if (mode === 'private') {
      if (!Helpers.isLookupCode(options.lookupCode)) {
        return null;
      }

      // HMAC the identifier under the lookup code, base32 encode, and keep the fixed-length label
      const fullLabel = await IdentityDomain.deriveFullLabel(identifier, options.lookupCode);

      return {domainName: '_' + fullLabel.substring(0, PRIVATE_LABEL_LENGTH) + AT_MARKER + identifierDomain, fullLabel};
    }

    // If an unknown mode is set, return `null`
    return null;
  }

  /**
   * Constructs a new instance of IdentityDomain basing on the identifier.
   *
   * Objects of this class start in an un-resolved state, and a call to the resolve() that
   * performs the DNS resolution needs to be made before most of the other methods can be used.
   *
   * @param identifier {string} - The identifier for which identity domain is constructed.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   */
  constructor(identifier, config={}) {
    this.config = Helpers.mergeConfig(config);

    this.identifier = identifier;

    /**
     * The resolution options, as fixed by `setOptions(...)`; `undefined` until then.
     * @type {(object|undefined)}
     */
    this.options = undefined;

    /**
     * The domain name the identity records are published under, derived from the identifier and the
     * resolution mode. `null` until resolved.
     * @type {?string}
     */
    this.domainName = null;

    /**
     * The identity records as read from the DNS, in `Triauth.Resolvers.Base#resolveConfig` form.
     * `null` until resolved.
     * @type {?Array<{key: string, value: string, options: object, ttl: (number|undefined), dnssec: (boolean|undefined)}>}
     */
    this.identityRecords = null;

    /**
     * The lookup code that addressed the records in private mode. `null` in every other mode.
     * @type {?string}
     */
    this.lookupCode = null;

    /**
     * The commitment a private-mode record set must carry to be accepted - the digest of the derived
     * full label. `null` in every other mode.
     * @type {?string}
     */
    this.expectedCommitment = null;

    /**
     * Whether the identity domain resolved successfully; `undefined` until resolve() has run.
     * @type {(boolean|undefined)}
     */
    this.resolved = undefined;
  }

  /**
   * Sets the options for future `resolve` calls.
   * May be called only once.
   *
   * @param options {object} - Options read from the authentication endpoint DNS record (e.g., `{mode: 'public'|'private'}`), plus the identity's `lookupCode` where its mode consumes one.
   *
   * @returns {IdentityDomain} this instance, so the call chains straight into resolve().
   *
   * @throws {Error} when the options have already been set.
   */
  setOptions(options) {
    if (this.options) {
      throw new Error('Options of a Triauth.IdentityDomain are already set');
    }

    this.options = options;

    return this;
  }

  /**
   * Resolves the identity domain by deriving the domain name from the identifier
   * (using the authentication endpoint options) and querying the DNS for its identity records.
   * Sets the `domainName` and `identityRecords` properties accordingly.
   *
   * Set resolution options with `setOptions(...)` prior to the call.
   *
   * The result is memoized, and subsequent calls to `resolve` do not perform DNS lookups.
   * Rejections are currently memoized too.
   *
   * @returns {Promise<boolean>} A promise that resolves to true when identity records have been fetched, false when the domain name could not be derived.
   *
   * @throws {Error} when the resolution options have not been set yet - call `setOptions(...)` first.
   */
  async resolve() {

    if (!this.options) {
      throw new Error('Triauth.IdentityDomain options not set');
    }

    // Memoize the returned promise so that multiple and/or concurrent calls return the same status.
    return (this.#resolvePromise ||= (async () => {
      try {
        const derived = await IdentityDomain.derive(this.identifier, this.options);
        this.config.logger?.debug?.(`Identity domain for identifier "${this.identifier}" is "${derived?.domainName}"`);

        // A derivation that cannot be performed leaves the identity without an identity domain,
        // which is like an identity that publishes no records.
        if (!derived) {
          this.resolved = false;
          return this.resolved;
        }

        const {domainName, fullLabel} = derived;

        if (this.options.mode === 'private') {
          this.lookupCode = this.options.lookupCode;
          this.expectedCommitment = await Helpers.sha256(fullLabel);
        }

        this.domainName = domainName;
        this.identityRecords = await this.config.resolver.resolveConfig(domainName, this.config);

        this.resolved = true;
        return this.resolved;

      } catch(err) {
        this.config.logger?.debug?.(err);

        this.resolved = false;
        throw err;
      }
    })());
  }

}
