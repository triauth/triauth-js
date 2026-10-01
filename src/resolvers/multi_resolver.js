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
 * A multi-resolver that takes an array of resolvers, and returns an intersection of DNS resource record values
 * as returned by each of the listed resolvers. This allows responses from multiple independent DNS resolver service
 * providers to be cross-validated against each other, helping to protect from BGP poisoning, rogue providers and provider-specific attacks.
 *
 * The TTL of each record is calculated as a minimal TTL returned by the resolvers.
 * The dnssec property for returned record is set to true only when at least one resolver has set it to 'true' and no resolvers have set it to 'false'.
 * The aggregation is independent of resolver order: resolvers that report no DNSSEC status (undefined) express no opinion,
 * and the property remains undefined when no resolver reports an explicit status.
 *
 * @class
 * @memberof Triauth.Resolvers
 */
export class MultiResolver extends Base {

  /**
   * @param resolvers {Array} - An array of resolver objects (descendants of Triauth.Resolvers.Base).
   * @param [options={}] {Object}          - The options listed below are consumed at this layer; any other entries
   *                                         are forwarded to each sub-resolver's resolve() call.
   * @param [options.maxFailures] {number} - The maximal number of resolvers that are allowed to fail for the resolution to still successfully complete.
   * @param [options.timeout] {number}     - How long to wait (ms) before aborting the multi-resolver call with a timeout error.
   *                                          Requires the runtime to provide `AbortController`; where it does not (e.g. nginx/njs),
   *                                          the option is ignored and each sub-resolver's own timeout behavior applies instead.
   */
  constructor(resolvers, options = {}) {
    super();
    this.resolvers = resolvers;
    this.options = options;
  }

  /**
   * Queries every configured resolver for the given records, and returns the intersection of their answers.
   *
   * A record is returned only when every resolver that answered carries it. Its `ttl` is the lowest one
   * reported for it, and its `dnssec` follows the aggregation described in the class documentation above.
   *
   * @param domain {string} - A domain name to query the DNS for.
   * @param type {string}   - A type of DNS resource record to look for (e.g., 'TXT', 'A').
   * @param [options={}] {object} - Per-call overrides for the resolver options passed to the constructor.
   *                                `maxFailures` and `timeout` are consumed at this layer; every other entry
   *                                fans out to each sub-resolver's resolve() call.
   * @param [config={}] {object}  - Optional overrides for the global Triauth.config settings.
   *
   * @returns {Promise.<Array.<{value:string, ttl:(number|undefined), dnssec:(boolean|undefined)}>>}
   *          A promise that resolves to the array of retrieved DNS resource records in {value, ttl, dnssec} format.
   *          It rejects with an Array of the sub-resolver errors once more than `options.maxFailures` of them fail
   *          or none of them answers, and with an Error once `options.timeout` elapses.
   */
  resolve(domain, type, options={}, config={}) {
    config = Helpers.mergeConfig(config);
    options = Object.assign({}, this.options, options);

    return new Promise((multiResolve, multiReject) => {
      const results = [];

      // Handle timeouts, but allow for platforms with owne fetch and without AbortController
      const abortController = typeof AbortController !== 'undefined' ? new AbortController() : null;
      let timeoutHandle = null;
      if (abortController) {
        abortController.signal.addEventListener('abort', () => multiReject(new Error('MultiResolver timeout')));
        if (options.timeout) {
          timeoutHandle = setTimeout(
            () => abortController.abort(new Error('MultiResolver timeout')),
            options.timeout
          );
        }
      }

      // maxFailures and timeout are consumed at this layer; every other option fans out
      // to the sub-resolvers, with the shared abort signal replacing any caller-provided one
      /** @type {Object.<string, any>} */
      const childOptions = Object.assign({}, options);
      delete childOptions.maxFailures;
      delete childOptions.timeout;
      if (abortController) {
        childOptions.signal = abortController.signal;
      } else {
        delete childOptions.signal;
      }

      this.resolvers.forEach((resolver) => {
        results.push(new Promise((resolve, reject) => {
          config.logger?.debug?.(`[DNS] Querying resolver ${resolver.constructor.name} for ${type} records of ${domain}`);
          const ts = Helpers.now();

          resolver.resolve(domain, type, childOptions, config).then(
            (res) => { config.logger?.debug?.(`[DNS] Resolved ${Object.keys(res).length} record(s) with ${resolver.constructor.name} in ${Math.round(Helpers.now() - ts)}ms`, {res}); return res; },
            (err) => { config.logger?.debug?.(`[DNS] Failed resolution with ${resolver.constructor.name} in ${Math.round(Helpers.now() - ts)}ms`, {cause:err}); throw err; }
          ).then(resolve, reject);
        }));
      });

      return Promise.allSettled(results).then((values) => {
        if (timeoutHandle !== null) {
          clearTimeout(timeoutHandle);
        }

        const failedResolutions = values.filter((v) => {
          return v.status !== 'fulfilled';
        });

        const fulfilledResolutions = values.filter((v) => {
          return v.status === 'fulfilled';
        });

        // Enforce the maxFailures limit from options
        if (failedResolutions.length > (options.maxFailures || 0) || fulfilledResolutions.length <= 0) {
          return multiReject(failedResolutions.map((fr) => {
            return fr.reason;
          }));
        }

        // Start with the first result, and limit/modify it basing on other
        let retval = fulfilledResolutions[0].value;

        // Remove entries which values are not present in responses of _all_ fulfilled resolvers
        for (const v of fulfilledResolutions) {
          retval = retval.filter((record) => {
            const rv = v.value.map((e) => {
              return e.value;
            }).indexOf(record.value) >= 0;

            if (!rv) {
              config.logger?.debug?.('[DNS] Ignoring DNS record for which non-matching responses were received', {record});
            }

            return rv;
          });
        }

        // Modify dnssec and ttl properties
        retval.forEach(function(e) {
          // Track explicit per-record dnssec reports across all fulfilled resolvers
          let sawTrue = false;
          let sawFalse = false;

          for (const v of fulfilledResolutions) {
            for (const r of v.value) {
              if (r.value === e.value) {

                // Any defined non-true report counts as an explicit veto
                if (r.dnssec === true) {
                  sawTrue = true;
                } else if (r.dnssec !== undefined) {
                  sawFalse = true;
                }

                // e.ttl and/or r.ttl may be undefined; ?? keeps a TTL of 0 in the min-aggregation
                if (r.ttl < (e.ttl ?? Infinity)) {
                  e.ttl = r.ttl
                }

              }
            }
          }

          // dnssec is true only when at least one resolver explicitly reported true and
          // none reported false; it stays undefined when no resolver expressed an opinion.
          e.dnssec = sawFalse ? false : (sawTrue ? true : undefined);
        });

        return multiResolve(retval);
      });
    });
  }

}
