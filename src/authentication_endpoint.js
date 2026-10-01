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
import { DEFAULT_MODE, DEFAULT_INCLUDE } from './protocol.js';

/**
 * Holds information about authentication endpoint for a given domain.
 *
 * Authentication endpoint is the URL under which Triauth Authenticator application, for the given identifier and its domain,
 * is available and can be communicated with.
 *
 * Objects of this class start in unresolved state, and need to be resolved with a call to resolve() that queries the DNS.
 *
 * @class
 * @memberof Triauth
 */
export class AuthenticationEndpoint {

  /**
   * Memoizes the resolution, so that concurrent and repeated `resolve()` calls share a single
   * DNS round trip. A rejection is memoized too, and is replayed to every later caller.
   * @type {?Promise<boolean>}
   */
  #resolvePromise = null;

  /**
   * Constructs a new instance of AuthenticationEndpoint basing on the domain name extracted form the identifier.
   *
   * Objects of this class start in an un-resolved state, and a call to the resolve() that
   * performs the DNS resolution needs to be made before most of the other methods can be used.
   *
   * @param domainName {string} - The domain name for which authentication endpoint shall be resolved.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings.
   */
  constructor(domainName, config={}) {
    this.domainName = domainName;
    this.config = Helpers.mergeConfig(config);

    /**
     * The endpoint's lowercase host — the value of the domain's `triauth` DNS record.
     * `null` until resolved.
     * @type {?string}
     */
    this.host = null;

    /**
     * The options as read from the `triauth` DNS record, with defaults filed in if missing.
     * Empty until resolved.
     * @type {object}
     */
    this.options = Object.create(null);

    /**
     * Whether the DNS record defining this authentication endpoint was protected by DNSSEC.
     * `true` only when the resolver reported a validated (AD) response for the matched `triauth` record;
     * `false` when it was not validated or the resolver did not report DNSSEC status;
     * `undefined` until resolved.
     * @type {(boolean|undefined)}
     */
    this.secure = undefined;

    /**
     * Expiry of the resolved `triauth` record: the resolution time plus its TTL, in milliseconds;
     * `undefined` when the record carried no TTL. Every expiry reported for an identity is bounded by it.
     * @type {(number|undefined)}
     */
    this.expires = undefined;

    this.resolved = undefined;
  }

  /**
   * Returns the URL of the authentication endpoint, with the passed action and parameters included.
   *
   * With an action, it is the final URL to which the user's web browser should be redirected in the challenge-response flow.
   * The params are passed inside the URL fragment identifier for privacy reasons.
   *
   * @param action {?string} - An action verb used to construct the URL - e.g., 'auth', 'sign', etc., or null for the bare endpoint URL.
   * @param params {object} - Parameters that should be included in the URL, ignored when action is null.
   *
   * @returns {string} an url of authentication endpoint with the given action and parameters.
   *
   * @throws {Error} when the endpoint has not been resolved yet - call `resolve()` first.
   */
  urlFor(action, params) {
    if (!this.resolved) {
      throw new Error('Unresolved AuthenticationEndpoint');
    }

    if (action === null) {
      return `https://${this.host}/`;
    }

    // Parameter values are base64url by the time they get here
    const pairs = Object.entries(params).map(([key, value]) => `${key}=${value}`);

    return `https://${this.host}/${action}.html#?${pairs.join('&')}`;
  }

  /**
   * Resolves the authentication endpoint for the domain by querying the DNS,
   * and sets the `host`, `options`, and `secure` properties accordingly basing on the DNS response.
   *
   * The result is memoized, and subsequent calls to `resolve` do not perform DNS lookups.
   * Rejections are currently memoized too.
   *
   * @returns {Promise<boolean>} a promise that resolves to true if the URL of authentication endpoint has been resolved, false otherwise.
   */
  async resolve() {

    // Memoize the returned promise so that multiple and/or concurrent calls return the same status.
    return (this.#resolvePromise ||= (async () => {
      try {
        this.config.logger?.debug?.(`Resolving Triauth.AuthenticationEndpoint for domain ${this.domainName}`);

        const domainConfig = await this.config.resolver.resolveConfig(this.domainName, this.config);

        for (const entry of domainConfig) {
          if (entry.key === 'triauth' && Helpers.isDomainName(entry.value)) {
            if (this.host) {
              // Multiple triauth records published — refuse to choose
              this.config.logger?.warn?.('Multiple triauth records found; refusing to choose', {domainName:this.domainName});
              this.host = null;
              this.options = Object.create(null);
              this.secure = undefined;
              this.expires = undefined;
              break;
            }

            this.host = entry.value.toLowerCase();
            this.options = entry.options;
            this.secure = !!entry.dnssec;
            this.expires = Number.isInteger(entry.ttl) ? Date.now() + entry.ttl * 1000 : undefined;

            // Set defaults
            this.options.mode ??= DEFAULT_MODE;
            this.options.include ??= DEFAULT_INCLUDE;
          }
        }

        this.config.logger?.debug?.(`Triauth.AuthenticationEndpoint for domain ${this.domainName} is ${this.host}`);

        this.resolved = !!this.host;
        return this.resolved;

      } catch (err) {
        this.config.logger?.debug?.(err);

        this.resolved = false;
        throw err;
      }
    })());
  }

}
