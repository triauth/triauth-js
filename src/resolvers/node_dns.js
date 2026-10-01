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
import { Helpers } from '../helpers.js';

/**
 * A DNS resolver that uses the Node.js 'dns' built-in standard library to perform queries.
 * This resolver works only with Node.js, and in web-browser based environment will always fail/reject.
 *
 * @class
 * @memberof Triauth.Resolvers
 *
 * @see Documentation - {@link https://nodejs.org/api/dns.html}
 */
export class NodeDns extends Base {

  /**
   * @param [options={}] {object}
   * @param [options.tries] {number}        - How many times each name server is tried before the query fails
   *                                          (`ARES_OPT_TRIES`; this works differently than `retries` in DnsJson). Defaults to 3.
   * @param [options.timeout] {number}      - How long to wait (ms) for a single try before it counts as failed.
   *                                          Defaults to null, which leaves the c-ares default in place.
   * @param [options.signal] {AbortSignal}  - An optional AbortSignal that cancels an in-flight query.
   */
  constructor(options = {}) {
    super();
    this.options = options;
    this.dns = null;
  }

  async #loadDns() {
    if (this.dns || typeof window !== 'undefined') {
      return this.dns;
    }
    try {
      const mod = await import('node:dns');
      this.dns = mod.default ?? mod;
    } catch {
      this.dns = null;
    }
    return this.dns;
  }

  /**
   * Queries the DNS for resource records of a given type that are stored under a given domain name,
   * through the Node.js `node:dns` resolver.
   *
   * @param domain {string} - A domain name to query the DNS for.
   * @param type {string}   - A type of DNS resource record to look for; only 'TXT' is supported.
   * @param [options={}] {object} - Per-call overrides for the resolver options passed to the constructor.
   * @param [config={}] {object}  - Optional overrides for the global Triauth.config settings.
   *
   * @returns {Promise.<Array.<{value:string, ttl:(number|undefined), dnssec:(boolean|undefined)}>>}
   *          A promise that resolves to the array of retrieved DNS resource records in {value, ttl, dnssec}
   *          format. `node:dns` reports neither a TTL nor a DNSSEC status, so both are always undefined, and
   *          a record whose bytes are not well-formed UTF-8 is left out of the answer. A missing name
   *          (NXDOMAIN/ENOTFOUND) and a name with no records of this type (ENODATA) both resolve to an empty
   *          array. It rejects in web browsers, for a non-TXT query type, and upon any other resolver error.
   */
  resolve(domain, type, options={}, config={}) {
    config = Helpers.mergeConfig(config);

    options = Object.assign({
      tries: 3, // this works differently than "retries" in dns_json - @see ARES_OPT_TRIES on https://manpages.ubuntu.com/manpages/oracular/en/man3/ares_init_options.3.html
      timeout: null,
      signal: null
    }, this.options, options);

    return new Promise((resolve, reject) => {

      if (typeof window !== 'undefined') {
        return reject('NodeDns resolver is unavailable in web browsers');
      }

      if (type !== 'TXT') {
        return reject('Non TXT queries are not supported yet for this resolver');
      }

      this.#loadDns().then((dns) => {
        if (!dns) {
          return reject('node:dns resolver is not available');
        }

        // @see https://nodejs.org/dist/latest-v20.x/docs/api/dns.html#resolveroptions
        // @see https://manpages.ubuntu.com/manpages/oracular/en/man3/ares_init_options.3.html
        const resolver = new dns.Resolver({
          timeout: options.timeout || -1,
          tries: options.tries || 3
        });

        const onAbort = () => resolver.cancel();
        if (options.signal) {
          options.signal.addEventListener('abort', onAbort);
        }

        return resolver.resolveTxt(domain, (err, records) => {
          if (options.signal) {
            options.signal.removeEventListener('abort', onAbort);
          }

          if (err) {
            // A missing name (NXDOMAIN/ENOTFOUND) and a name with no records of this type (ENODATA)
            // are both empty answers - same as the DoH resolvers report them; other errors propagate
            return (err.code === 'ENOTFOUND' || err.code === 'ENODATA') ? resolve([]) : reject(err);
          }

          return resolve(records.flatMap((r) => {
            // A TXT record's character-strings concatenate in order with no separator;
            // node:dns delivers them as an array of chunk strings, one char per octet.
            const raw = r.join('');

            let val;
            try {
              val = Helpers.utf8BytesToString(Uint8Array.from(raw, c => c.charCodeAt(0) & 0xff));
            } catch (err) {
              config.logger?.debug?.(err);
              // A record whose bytes are not well-formed UTF-8 is ignored as a whole
              return [];
            }

            return [{
              value: val,
              ttl: undefined,
              dnssec: undefined
            }];
          }));
        });
      }).catch(reject);
    });
  }
}
