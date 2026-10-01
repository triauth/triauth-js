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

import { TriauthError } from '../error.js';
import { Helpers } from '../helpers.js';

/**
 * A base class from which other DNS resolvers inherit common functions.
 * Subclasses are expected to implement `resolve(domainName, type, options = {}, config = {})`.
 *
 * @class
 * @memberof Triauth.Resolvers
 */
export class Base {

  /**
   * Queries the DNS for resource records of a given type that are stored under a given domain name.
   *
   * This is the abstract contract that concrete subclasses (e.g., DnsJson, NodeDns, MultiResolver) implement.
   *
   * @param domainName {string} - A domain name to query the DNS for.
   * @param type {string}       - A type of DNS resource record to look for (e.g., 'TXT', 'A').
   * @param [options={}] {object} - Per-call overrides for the resolver options passed to the constructor.
   * @param [config={}] {object}  - Optional overrides for the global Triauth.config settings.
   *
   * @returns {Promise.<Array.<{value:string, ttl:(number|undefined), dnssec:(boolean|undefined)}>>}
   *          A promise that resolves to the array of retrieved DNS resource records in {value, ttl, dnssec} format.
   *
   * @throws {Error} always - this method is abstract and carries no implementation of its own.
   */
  // eslint-disable-next-line no-unused-vars
  async resolve(domainName, type, options = {}, config = {}) {
    throw new Error('Triauth.Resolvers.Base#resolve is abstract and must be implemented by a subclass');
  }

  /**
   * Returns configuration entries that are stored as DNS TXT records under a given domain name.
   * Each configuration entry consist of a key, optional value, and any number of options.
   *
   * Options are the maximal trailing run of whole whitespace-separated `key=value` tokens;
   * the text before that run is the entry's value, kept verbatim — `=`-containing text outside
   * the trailing run is ordinary value text and needs no escaping. Option values and the value
   * are percent-decoded; a record violating these rules is ignored as a whole.
   *
   * @example
   *
   * // Given the following DNS TXT record of an example.com domain:
   * // `example.com IN TXT "app triauth-authenticator style=dark logo=none"`
   * await resolveConfig('example.com');
   * => [{key:"app", value:"triauth-authenticator", options:{style:"dark", logo:"none"}, ttl:60, dnssec:false}]
   *
   * @param domainName {string}  - a domain name for/of which configuration should be read from the DNS
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   *
   * @returns {Promise.<Array.<{key:string, value:string, options:object, ttl:(number|undefined), dnssec:(boolean|undefined)}>>}
   *          A promise that resolves to the array of configuration entries/objects, as read from DNS, each in form of {key, value, options, ttl, dnssec}.
   *
   * @throws {TriauthError} code 110 when the underlying DNS query fails - intentionally propagated so that
   *                        API methods report a retryable error instead of treating the name as unconfigured.
   */
  async resolveConfig(domainName, config={}) {
    config = Helpers.mergeConfig(config);

    config.logger?.debug?.(`[DNS] Querying DNS for config records of ${domainName}`);

    let txtRecords,
        rv = [];

    try {
      txtRecords = await this.resolve(domainName, 'TXT', {}, config);

    } catch (err) {
      config.logger?.debug?.(`DNS name resolution failed for ${domainName}`, {cause:err});
      throw new TriauthError(110, 'DNS resolution failed, try again later');
    }

    // A record is its key, a blank run, and a rest with no line terminator. An option is a whole
    // whitespace-separated key=value token, so `a+b=c` never yields one. The `\S` stops the blank
    // run and the rest from trading characters, so the parse stays linear in the record size.
    const recordRegexp = /^([\w_-]+)\s+(\S.*)$/;
    const optionTokenRegexp = /^([\w_\-[\].@]+)=(\S+)$/;

    txtRecords.forEach((record) => {
      let md;

      try {

        if ((md = record.value.match(recordRegexp))) {
          const entry = {key: md[1], value: '', options: Object.create(null), ttl: record.ttl, dnssec: record.dnssec};

          if (!Helpers.isNormalString(entry.key, 255)) {
            return;
          }

          // Split once, keeping the blank runs (odd indexes) so the value is reassembled verbatim.
          // The option run is the maximal suffix of option tokens, collected right-to-left.
          const parts = md[2].trimEnd().split(/(\s+)/);
          const optionMatches = [];
          let i = parts.length - 1,
              optionMd;
          while (i >= 0 && (optionMd = parts[i].match(optionTokenRegexp))) {
            optionMatches.push(optionMd);
            i -= 2;
          }
          entry.value = i < 0 ? '' : parts.slice(0, i + 1).join('');
          optionMatches.reverse();

          // Process the run left to right; a repeated option key takes its last occurrence.
          // Option values are consumed as published - no percent-decoding at this layer: options are
          // machine vocabularies (and enter tag preimages), so their bytes stay those of the zone file.
          for (const m of optionMatches) {
            const optionKey = m[1];
            const optionValue = m[2];

            if (!(Helpers.isNormalString(optionKey, 255) && Helpers.isNormalString(optionValue, null))) {
              return;
            }

            // Protect against JS specific prototype poisoning attacks
            if (optionKey !== '__proto__' && optionKey !== 'constructor' && optionKey !== 'prototype') {
              entry.options[optionKey] = optionValue;
            }
          }

          // The text before the option run is the value. An options-only record has none and is ignored below.
          entry.value = entry.value.trim();

          if (!Helpers.isNormalString(entry.value, null)) {
            return;
          }

          return rv.push(entry);
        }
      } catch (err) {
        config.logger?.debug?.(err);
        // continue regardless of error
      }

    });

    config.logger?.debug?.(`[DNS] Parsed ${rv.length} DNS config record(s) from ${domainName}`);

    return rv;
  }

}
