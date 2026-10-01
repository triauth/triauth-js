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
 * A DNS resolver that uses the Google Public DNS DoH JSON API endpoint
 *
 * @class
 * @memberof Triauth.Resolvers
 *
 * @see Documentation - {@link https://developers.google.com/speed/public-dns/docs/doh/json}
 * @see Privacy Policy - {@link https://developers.google.com/speed/public-dns/privacy}
 * @see Terms Of Service - {@link https://developers.google.com/speed/public-dns/terms}
 */
export class Google extends DnsJson {

  /**
   * @param [options={}] {object} - Resolver options, as documented on `Triauth.Resolvers.DnsJson`.
   */
  constructor(options = {}) {
    // Google returns TXT data as logical record content: character-strings arrive already
    // concatenated with no separator and without surrounding quotes, so neither
    // normalizeTxtRecords nor decodeTxtRecords is needed.
    super('https://dns.google/resolve', options);
  }

}
