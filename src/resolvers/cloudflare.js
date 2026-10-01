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

import { DnsJson } from './dns_json.js';

/**
 * A DNS resolver that uses the Cloudflare DoH JSON API endpoint
 *
 * @class
 * @memberof Triauth.Resolvers
 *
 * @see Documentation - {@link https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/}
 * @see Privacy Policy - {@link https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/}
 * @see Terms Of Service - {@link https://developers.cloudflare.com/1.1.1.1/terms-of-use/}
 */
export class Cloudflare extends DnsJson {

  /**
   * @param [options={}] {object} - Resolver options, as documented on `Triauth.Resolvers.DnsJson`.
   *                                `normalizeTxtRecords` and `decodeTxtRecords` are always set to true
   *                                for this endpoint, overriding whatever the caller passes.
   */
  constructor(options = {}) {
    options.normalizeTxtRecords = true; // Cloudflare returns TXT records in presentation form: each character-string double-quoted, e.g. "part1" "part2"
    options.decodeTxtRecords = true; // Cloudflare escapes non-printable ASCII characters into \\[decimal] form (RFC 1035 presentation format) instead of utf-8 encoding them
    super('https://cloudflare-dns.com/dns-query', options);
  }

}
