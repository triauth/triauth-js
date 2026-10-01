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
import { LIMITS } from '../protocol.js';

/**
 * A base class for DNS resolvers based on JSON API for DNS over HTTPS (DoH).
 *
 * It provides a basic implementation of the `resolve` method that uses the JSON API endpoint URL which is expected
 * to be set by child classes through the `super(endpointUrl, options={})` call in their respective constructors.
 *
 * @class
 * @memberof Triauth.Resolvers
 *
 * @see A comprehensive list of public DoH servers is available on
 *      {@link https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers}.
 *      Some of them may offer JSON API that allows cross-origin requests.
 */
export class DnsJson extends Base {

  /**
   * @param url {string}                              - A base URL of the DoH API endpoint
   * @param [options={}] {object}
   * @param [options.skipPadding] {boolean}           - Set to true if you want to omit using random padding in the fetch url.
   *                                                    Random padding helps to prevent side-channel privacy attacks based on statistical analysis of the HTTPS payload.
   * @param [options.retries] {number}                - How many times to retry if name resolution fails. Defaults to 0.
   * @param [options.retryDelay] {number}             - If failure may be recoverable with time, how long to wait between retries in ms. Defaults to 150.
   * @param [options.timeout] {number}                - How long to wait before aborting the HTTP fetch request. Defaults to null.
   *                                                    Requires the runtime to provide `AbortController`; where it does not (e.g. nginx/njs),
   *                                                    the fetch implementation's own timeout applies instead.
   * @param [options.signal] {AbortSignal}            - An optional AbortSignal that can be used to abort HTTP fetch requests (requires `AbortController`).
   * @param [options.fetch] {Function}                - A fetch implementation to use instead of the global `fetch`. Lets constrained runtimes
   *                                                    inject their own client (e.g. `ngx.fetch` under nginx/njs). Defaults to the global `fetch`.
   * @param [options.normalizeTxtRecords] {boolean}   - Set to true to convert presentation-form TXT data — each 255-octet character-string wrapped
   *                                                    in double-quotes, e.g. `"part1" "part2"` — into the record's logical content: the character-string
   *                                                    contents concatenated in order with no separator (some DoH providers return presentation form).
   * @param [options.decodeTxtRecords] {boolean}      - Set to true to decode RFC 1035 presentation-format escapes in TXT records - `\NNN` (exactly three
   *                                                    decimal digits) into that octet, `\X` into X literally — and reinterpret the result as utf-8
   *                                                    (some DoH providers escape non-printable ASCII). A record carrying a malformed escape
   *                                                    (`\NNN` above 255, fewer than three digits, a bare trailing backslash) is ignored as a whole.
   */
  constructor(url, options = {}) {
    super();
    this.url = url;
    this.options = options;
  }

  /**
   * Converts a TXT record's presentation form into its logical content.
   *
   * DoH JSON providers that emit presentation form wrap each 255-octet character-string in
   * double-quotes and separate consecutive strings with whitespace (`"part1" "part2"`),
   * escaping a literal quote as `\"` and a literal backslash as `\\` inside a string.
   * The record's logical content is the in-order, no-separator concatenation of the
   * character-string contents. Because `\"`, `\\` and decimal `\NNN` escapes all live at the
   * same level of the presentation grammar, they must be decoded in a single pass: with
   * `keepEscapes` set, `\"` and `\\` sequences are kept verbatim in the output (they still
   * delimit correctly) so that the decodeTxtRecords stage decodes every escape at once;
   * without it, they decode to their literal characters here.
   *
   * Data that does not start with a double-quote is already logical content and is returned
   * unchanged. Data that starts like presentation form but does not parse as a sequence of
   * quoted strings (e.g., an unterminated quote) is returned unchanged, so downstream record
   * parsing rejects it instead of consuming a half-normalized value.
   *
   * @param data {string} - The `Answer[].data` field of a TXT answer.
   * @param [keepEscapes=false] {boolean} - Set to true to keep `\"`/`\\` escape sequences verbatim
   *                                        in the output, for a subsequent single-pass escape decode.
   * @returns {string} The logical record content.
   */
  static normalizeTxtData(data, keepEscapes = false) {
    if (data.length < 2 || data[0] !== '"') {
      return data;
    }

    let content = '';
    let i = 0;

    while (i < data.length) {
      // Each pass consumes one double-quoted character-string, then any inter-string whitespace
      if (data[i] !== '"') {
        return data;
      }
      i++;

      for (; i < data.length && data[i] !== '"'; i++) {
        if (data[i] === '\\' && (data[i + 1] === '"' || data[i + 1] === '\\')) {
          content += keepEscapes ? data[i] + data[i + 1] : data[i + 1];
          i++;
        } else {
          content += data[i];
        }
      }

      if (i >= data.length) {
        return data;
      }
      i++;

      while (i < data.length && (data[i] === ' ' || data[i] === '\t')) {
        i++;
      }
    }

    return content;
  }

  /**
   * Queries the DNS for resource records of a given type that are stored under a given domainName.
   *
   * @param domainName {string}   - A domain name to query the DNS for. For example "example.com".
   * @param type {string}         - A type of DNS resource record to look for. For example "TXT", or "A".
   * @param [options={}] {object} - Overrides for the options passed to the constructor that will be effective during this function call.
   * @param [config={}] {object}  - Optional overrides for the global Triauth.config settings
   *
   * @returns {Promise.<Array.<{value:string, ttl:(number|undefined), dnssec:(boolean|undefined)}>>} A promise that resolves to the array of retrieved DNS resource records in {value, ttl, dnssec} format;
   *          `ttl` and `dnssec` carry the provider's `TTL` and `AD` fields, and stay undefined where the provider omits them.
   */
  resolve(domainName, type, options={}, config={}) {
    config = Helpers.mergeConfig(config);

    options = Object.assign({
      retries: 0,
      retryDelay: 150,
      skipPadding: false,
      timeout: null,
      signal: null,
      fetch: null
    }, this.options, options);

    // Ensure type is upper-case
    type = String(type).toUpperCase();

    return new Promise((resolve, reject) => {
      // Browsers and Node expose a global `fetch`; constrained runtimes may inject one through options.fetch.
      const fetchImpl = options.fetch || (typeof fetch !== 'undefined' ? fetch : undefined);
      if (typeof fetchImpl !== 'function') {
        return reject(new Error('No fetch implementation available; pass options.fetch'));
      }

      let fetchUrl = `${this.url}?name=${encodeURIComponent(domainName)}&type=${encodeURIComponent(type)}`;

      // Use random padding to limit the scope for side-channel privacy attacks that use the packet sizes of HTTPS GET requests.
      // Uses crypto.getRandomValues so the padding cannot be predicted from a known-plaintext leak.
      if (!options.skipPadding) {
        const chars = 'abcdefghijklmnopqrstuvwxyz';
        fetchUrl += "&random_padding=";
        const needed = (50 - (fetchUrl.length % 50)) % 50;
        if (needed > 0) {
          const rnd = new Uint8Array(needed);
          crypto.getRandomValues(rnd);
          for (let i = 0; i < needed; i++) {
            fetchUrl += chars[rnd[i] % chars.length];
          }
        }
      }

      // Prepare fetch abort controller for timeout support and abort signal propagation
      // but only if the runtime implements AbortController (e.g., runtimes with custom fetch implementations may be missing it)
      const abortController = typeof AbortController !== 'undefined' ? new AbortController() : null;

      let timeoutHandle = null;
      if (abortController && options.timeout) {
        timeoutHandle = setTimeout(() => {
          abortController.abort(new Error('Resolver timeout'));
        }, options.timeout);
      }

      const onAbort = () => abortController.abort(new Error('Abort signal received'));
      if (abortController && options.signal) {
        options.signal.addEventListener('abort', onAbort);
      }

      const cleanup = () => {
        if (timeoutHandle !== null) {
          clearTimeout(timeoutHandle);
          timeoutHandle = null;
        }
        if (abortController && options.signal) {
          options.signal.removeEventListener('abort', onAbort);
        }
      };

      const fetchOptions = { headers: { 'Accept': 'application/dns-json' } };
      if (abortController) {
        fetchOptions.signal = abortController.signal;
      }

      return fetchImpl(fetchUrl, fetchOptions).then(async (response) => {
        // cleanup() is intentionally deferred to the `finally` below so the
        // per-request timeout stays armed across the entire body read,
        // bounding slow-body delivery (server sends headers fast, then dribbles bytes).
        try {
          if (!response.ok) {
            throw new Error(`DoH request failed with HTTP ${response.status}`);
          }

          // Bail early when the server *declares* an over-limit body.
          const declared = parseInt(response.headers.get('content-length'), 10);
          if (Number.isFinite(declared) && declared > LIMITS.jsonMaxBytesize) {
            abortController?.abort(new Error('DoH response exceeds size limit'));
            throw new Error('DoH response exceeds size limit (Content-Length)');
          }

          // Prefer incremental streaming when supported; fall back to .text() if not
          if (response.body && typeof response.body.getReader === 'function') {
            const reader = response.body.getReader();
            const chunks = [];
            let received = 0;

            try {
              for (;;) {
                const { value, done } = await reader.read();
                if (done) break;

                // Check BEFORE accumulating the over-limit chunk so we never hold it.
                if (received + value.byteLength > LIMITS.jsonMaxBytesize) {
                  abortController?.abort(new Error('DoH response exceeds size limit'));
                  throw new Error('DoH response exceeds size limit');
                }

                received += value.byteLength;
                chunks.push(value);
              }
            } finally {
              try { reader.releaseLock(); } catch { /* reader may already be errored */ }
            }

            // Assemble and decode once — multi-byte sequences may span chunk boundaries.
            // Strict: a body that is not well-formed UTF-8 rejects the whole response
            // (propagates to the retry/reject path below, like any transport failure).
            const bytes = new Uint8Array(received);
            let offset = 0;
            for (const chunk of chunks) {
              bytes.set(chunk, offset);
              offset += chunk.byteLength;
            }

            return Helpers.utf8BytesToString(bytes);

          } else if (typeof response.text === 'function') {
            const text = await response.text();
            if (Helpers.byteSize(text) > LIMITS.jsonMaxBytesize) {
              throw new Error('DoH response exceeds size limit');
            }
            return text;

          } else {
            throw new Error('DoH response has no readable body');
          }

        } finally {
          cleanup();
        }

      }).then(async(text) => {
        let json;
        try {
          json = Helpers.safeParseJson(text);
        } catch (err) {
          return reject(err);
        }

        // Check for error response status code(s), and act appropriately
        // @see DNS status codes - http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

        // for NXDOMAIN return empty array
        if (json['Status'] === 3) {
          return resolve([]);

        // for other errors, retry and if still error, fail
        } else if (json['Status'] !== 0) {
          if (options.retries <= 0) {
            return reject(new Error(`DoH response carries DNS status ${json['Status']}`));

          } else {
            options.retries -= 1;

            if (options.retryDelay) {
              await new Promise((resolve) => {
                return setTimeout(resolve, options.retryDelay);
              });
            }

            return this.resolve(domainName, type, options, config).then(resolve, reject);
          }
        }

        // The status code is 0 - all fine, continue to extract and parse the answer
        const retval = [];
        const dnsRecordTypes = {
          'TXT': 16,
          'A': 1,
          'AAAA': 28,
          'CNAME': 5
        }

        for (const a of (json['Answer'] || [])) {

          // Ensure the response is for the correct domain
          if (a['name'] !== domainName && a['name'] !== domainName + '.') {
            continue;
          }

          // Ensure the response has the requested record type
          if (dnsRecordTypes[type.toUpperCase()] !== a['type']) {
            continue;
          }

          // Ensure the response has fields of expected types
          if (
            typeof a['data'] !== 'string' ||
            (!Number.isInteger(a['TTL']) || a['TTL'] < 0) ||
            typeof json['AD'] !== 'boolean'
          ) {
            continue;
          }

          // Convert presentation-form TXT data into the record's logical content if normalizeTxtRecords is set;
          // when the decode stage below will run, escapes stay verbatim so it can decode them in one pass
          if (a['type'] === 16 && options.normalizeTxtRecords) {
            a['data'] = DnsJson.normalizeTxtData(a['data'], options.decodeTxtRecords);
          }

          // Decode escaped chars: one left-to-right pass over the RFC 1035 escape grammar —
          // `\DDD` (exactly three digits, one octet) yields that byte, `\X` yields X literally,
          // and anything else (`\DDD` above 255, fewer than three digits, a bare trailing
          // backslash) rejects the record as a whole rather than guessing
          if (a['type'] === 16 && options.decodeTxtRecords) {
            try {
              const bytes = a['data'].replace(/\\(\d{3})|\\(\D)?/g, (m, ddd, ch) => {
                if (ddd !== undefined) {
                  const code = parseInt(ddd, 10);
                  if (code > 255) {
                    throw new Error('Invalid \\DDD escape in a TXT record');
                  }
                  return String.fromCharCode(code);
                }
                if (ch === undefined) {
                  throw new Error('Truncated escape in a TXT record');
                }
                return ch;
              });
              // One-char-per-octet contract: a char above U+00FF is not an octet, so it rejects
              // the record rather than wrapping mod-256 into an unrelated byte
              a['data'] = Helpers.utf8BytesToString(Uint8Array.from(bytes, (c) => {
                const byte = c.charCodeAt(0);
                if (byte > 255) {
                  throw new Error('Non-octet character in a TXT record escape decode');
                }
                return byte;
              }));
            } catch (err) {
              config.logger?.debug?.(`DNS TXT record could not be decoded`, {cause:err});
              continue;
            }
          }

          retval.push({value: a['data'], ttl: a['TTL'], dnssec: json['AD']});
        }

        return resolve(retval);

      }).catch((err) => {
        cleanup();
        config.logger?.debug?.(err);

        if (options.signal?.aborted || options.retries <= 0) {
          return reject(err);

        } else {
          options.retries -= 1;

          return this.resolve(domainName, type, options, config).then(resolve, reject);
        }

      });
    });
  }

}
