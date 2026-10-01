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
 * Methods related to identity that are a part of the official triauth-js API.
 *
 * @namespace Identity
 * @memberof Triauth.Api
 */

import { KNOWN_CONFIG_KEYS } from '../config.js';
import { Helpers } from '../helpers.js';
import { TriauthError } from '../error.js';
import { Identity } from '../identity.js';

/**
 * The whois method can be used to check if a given personal identifier exists, and obtain public details stored in its identity records.
 * For domains operating in `mode=private`, the `lookupCode` is required to look up the identity records.
 *
 * Upon call, it returns an object with a `status` property of:
 * `-1` if domain does not exist or is not configured for triauth,
 * `0` if domain is configured but identifier does not exist or could not be located (e.g., a missing or wrong `lookupCode` under `mode=private`),
 * and `1` if identifier exists.
 * On error, it returns an `{error: {code, message}}` object instead (with no `status`).
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let whoisResult = await Triauth.whois({identifier});
 * let whoisResult = await Triauth.whois({identifier, lookupCode}); // for an identity under a mode=private domain
 * // returns {error: {code: number, message: string}} upon error
 * // returns {status:1, identifier, authenticationEndpoint:{…}, identityDomain, secure, publicProfile:{…}, groups:[…], devices:[…], includes:[…]} if identifier exists
 * // returns {status:0, identifier, authenticationEndpoint:{…}, identityDomain} if domain is configured for triauth but the identifier does not exist or, for mode=private domains, a missing or wrong lookupCode was supplied
 * // returns {status:-1, identifier} if domain is not configured for triauth
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.whois({identifier: 'john@triauthdemo.org'});
 * //
 * // {
 * //   "status": 1,
 * //   "identifier": "john@triauthdemo.org",
 * //   "authenticationEndpoint": {
 * //     "url": "https://auth.triauthdemo.org/",
 * //     "options": {
 * //       "mode": "public",
 * //       "include": "any"
 * //     },
 * //     "secure": true
 * //   },
 * //   "identityDomain": "john._at.triauthdemo.org",
 * //   "secure": true,
 * //   "publicProfile": {
 * //     "initials": "JD",
 * //     "name": "John Doe"
 * //   },
 * //   "groups": [],
 * //   "devices": [
 * //     {
 * //       "deviceName": "laptop",
 * //       "deviceTag": "5I4NnX-4lW3gdTqGW3zKpLsLR9oRiWip8zp6mqQgkL4",
 * //       "keys": [
 * //         {
 * //           "value": "BCkB_Cr-7pvY1Y2buYRksJPb09Tqld7M3SDII36cp_C7k08NPTWvbj0p14oMBGDGbGZ1qLkfnJSARBbAj1sA0fs",
 * //           "options": {
 * //             "type": "es256",
 * //             "use": "attest,auth,ping,sign,stamp"
 * //           }
 * //         },
 * //         {
 * //           "value": "BLglw14iw47KUztRHdeKNfBBBMf5P4SsZg9O9za44mO2BceHZlcQwFmtO1crjVNnwwZszqtMhErs3divGeQrQI4",
 * //           "options": {
 * //             "type": "es256",
 * //             "use": "attest,auth,ping,sign,stamp"
 * //           }
 * //         }
 * //       ]
 * //     },
 * //     {
 * //       "deviceName": "desktop",
 * //       "deviceTag": "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
 * //       "keys": [
 * //         {
 * //           "value": "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
 * //           "options": {
 * //             "type": "es256",
 * //             "use": "attest,auth,ping,sign,stamp"
 * //           }
 * //         }
 * //       ]
 * //     }
 * //   ],
 * //   "includes": []
 * // }
 * //
 * ```
 *
 * The `includes` array lists the identity's published `include` statements, e.g.:
 *
 * ```javascript
 * // "includes": [
 * //   {
 * //     "ref": "jane@triauthdemo.org",
 * //     "options": {"use": "sign", "scope": "any"},
 * //     "tag": "LJwdl7N9xsSO4LV6T3gmmxVk_eXLyS58jw7czzooByw"
 * //   }
 * // ]
 * ```
 *
 * @param options {object} - whois lookup options
 * @param options.identifier {string} - the identifier to look up
 * @param [options.lookupCode] {string} - the identity's lookup code (used when domain is in private mode)
 * @param [config={}] {object} - optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {error: {code: number, message: string}}
 *   | {identifier: string, status: -1}
 *   | {identifier: string, status: 0, authenticationEndpoint: {url: string, options: object, secure: boolean}, identityDomain: string|null}
 *   | {identifier: string, status: 1, authenticationEndpoint: {url: string, options: object, secure: boolean}, identityDomain: string, secure: boolean, publicProfile: object, groups: Array<string>, devices: Array<{deviceName: string, deviceTag: string, keys: Array<{value: string, options: object}>}>, includes: Array<{ref: string, options: object, tag: string}>}
 * >} A promise that resolves into one of the following:
 * - `{error: {code, message}}` — the arguments were rejected (101 a missing `identifier` or a malformed `lookupCode`, 102 an unrecognized option key — a bare identifier string or a config object in the options position included, 103 an unrecognized config key, 21x an invalid identifier) or the DNS resolution failed (110).
 * - `{identifier, status: -1}` — the identity domain does not exist or is not configured for triauth (no `authenticationEndpoint` could be resolved).
 * - `{identifier, status: 0, authenticationEndpoint, identityDomain}` — the domain is triauth-configured but no identity records exist for this identifier. Under `mode=private` this is also the answer when the call carries no `lookupCode` (then `identityDomain` is `null`, as no identity domain could be derived) or a wrong one (a malformed `lookupCode` is instead rejected with error 101).
 * - `{identifier, status: 1, authenticationEndpoint, identityDomain, secure, publicProfile, groups, devices, includes}` — the identifier was fully resolved. The `secure` flag is resolution-level: true only when DNSSEC was reported for the domain's `triauth` configuration record and for every well-formed record of the identity answer (DNSSEC validates answers, not individual records, so one flag describes the identity answer; `authenticationEndpoint.secure` isolates the endpoint record's own status). The `groups` array lists the identity's fully-qualified group-membership claims (sorted, deduplicated; e.g., `['admins@triauthdemo.org']`). Each entry in `devices` carries:
 *   - `deviceName` {string} — a user given name of the device,
 *   - `deviceTag` {string} — a unique tag identifying the device by its associated public keys,
 *   - `keys` {Array<{value, options}>} — the device's individual published keys.
 *
 *   Each entry in `includes` (ordered by `tag`) carries:
 *   - `ref` {string} — the delegate the grant covers, as published (lowercased): either an identifier (`jane@example.com`) or an identity domain (`jane._at.example.com`),
 *   - `options` {object} — the grant's options: `use` lists the flows the grant covers (all five when unpublished) and `scope` the service hosts it works at (`any` = every host, or a comma-separated host list),
 *   - `tag` {string} — the grant digest that appears as the first segment of a delegated result's composite `deviceTag`.
 */
export const whois = async function(options, config = {}) {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  config.logger?.info?.('Processing Triauth.whois');
  const ts = Helpers.now();

  try {
    // Ensure only recognized options are present to help avoid misspellings
    if (!Helpers.hasOnlyKnownProperties(options, ['identifier', 'lookupCode'])) {
      throw new TriauthError(102, 'Unrecognized function argument');
    }

    // Reject config carrying unknown keys
    if (!Helpers.hasOnlyKnownProperties(config, KNOWN_CONFIG_KEYS)) {
      throw new TriauthError(103, 'Unrecognized configuration key');
    }

    const {identifier, lookupCode} = options;

    if (typeof identifier !== 'string' || (lookupCode !== undefined && !Helpers.isLookupCode(lookupCode))) {
      throw new TriauthError(101, 'Invalid or missing function arguments');
    }

    const retval = {status:null, identifier};

    const identity = new Identity(identifier, {lookupCode}, config);

    if (!(await identity.authenticationEndpoint.resolve())) {
      return Helpers.clone(Object.assign(retval, {
        status: -1
      }));
    }

    Object.assign(retval, {
      authenticationEndpoint: {
        url: identity.authenticationEndpoint.urlFor(null),
        options: identity.authenticationEndpoint.options,
        secure: identity.authenticationEndpoint.secure === true
      }
    });

    if (!(await identity.resolve())) {
      return Helpers.clone(Object.assign(retval, {
        status: 0,
        identityDomain: identity.identityDomain.domainName
      }));
    }

    const devices = [];
    for (const deviceName in identity.keys.keyGroups) {
      const keyGroup = identity.keys.keyGroups[deviceName];
      if (keyGroup.valid) {
        // only expose white-listed properties
        const keys = keyGroup.keys.map((key) => ({value:key.value, options:key.options}));

        devices.push({deviceName: deviceName, deviceTag: keyGroup.tag, keys: keys});
      }
    }

    // only expose white-listed properties of the include statements (grants) admitted under the domain's include policy
    const includes = identity.includes.list().map((incl) => ({ref: incl.ref, options: incl.options, tag: incl.tag}));

    return Helpers.clone(Object.assign(retval, {
      status: 1,

      identityDomain: identity.identityDomain.domainName,
      secure: identity.secure,

      publicProfile: identity.publicProfile,
      groups: identity.groups,

      devices,
      includes
    }));

  } catch (err) {
    return TriauthError.process(err, config);

  } finally {
    config.logger?.info?.('Completed in ' + Math.round(Helpers.now() - ts) + 'ms');

  }
};
