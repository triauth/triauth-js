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

import { TriauthError } from './error.js';
import { Validator } from './validator.js';
import { AuthenticationEndpoint } from './authentication_endpoint.js';
import { IdentityDomain } from './identity_domain.js';
import { IdentityKeys } from './identity_keys.js';
import { LIMITS } from './protocol.js';
import {Helpers} from "./helpers.js";
import {IdentityIncludes} from "./identity_includes.js";

/**
 * Represents an entity that is identified by the provided `identifier`.
 *
 * Objects of this class start in unresolved state, and need to be resolved with a call to resolve() that queries the DNS.
 *
 * @class
 * @memberof Triauth
 */
export class Identity {

  /**
   * A regexp for the reserved keywords that may appear in the identity records (DNS TXT records)
   * and are recognized and returned as a part of publicProfile.
   * @type {RegExp}
   */
  #PUBLIC_PROFILE_KEYWORDS = /^(name|initials)$/;

  /**
   * Memoizes the resolution, so that concurrent and repeated `resolve()` calls share a single
   * DNS round trip. A rejection is memoized too, and is replayed to every later caller.
   * @type {?Promise<boolean>}
   */
  #resolvePromise = null;

  /**
   * Constructs a new instance of Identity for the given identifier.
   *
   * Objects of this class start in an un-resolved state, and a call to the resolve() method that
   * performs the DNS resolution needs to be made before most of the other methods can be used.
   *
   * @param identifier {string} - Identifier (e.g., `john@triauthdemo.org`) for which the Identity object is constructed.
   * @param [options={}] {object} - Resolution options.
   * @param [options.lookupCode] {string} - The lookup code that addresses the identity records - required in private mode.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   *
   * @throws {TriauthError} carrying the first validation error when the identifier is malformed.
   */
  constructor(identifier, options={}, config={}) {
    this.identifier = identifier;
    this.options = options;
    this.config = Helpers.mergeConfig(config);

    // Ensure received identifier is valid
    const validationResult = Validator.validateIdentifier(this.identifier);
    if (!validationResult.valid) {
      throw new TriauthError(validationResult.errors[0].code, validationResult.errors[0].message);
    }

    /**
     * The public profile entries published in the identity records (e.g., `name`, `initials`, and
     * any `x-` prefixed key); a null value marks a key that is published but carries no value.
     * Populated by resolve().
     * @type {Object<string, ?string>}
     */
    this.publicProfile = {};

    /**
     * Fully-qualified group names this identity claims membership in (e.g., ['admins@triauthdemo.org']);
     * deduplicated and sorted, populated by resolve()
     * @type {string[]}
     */
    this.groups = [];

    this.domainName = this.identifier.split('@')[1];

    this.authenticationEndpoint = new AuthenticationEndpoint(this.domainName, this.config);
    this.identityDomain = new IdentityDomain(this.identifier, this.config);

    /** The public keys published for this identity, grouped by device. Populated by resolve(). */
    this.keys = new IdentityKeys(this.config);

    /** The delegation grants published for this identity. Populated by resolve(). */
    this.includes = new IdentityIncludes(this.config);

    /**
     * Whether the identity resolved successfully; `undefined` until resolve() has run.
     * @type {(boolean|undefined)}
     */
    this.resolved = undefined;

    /**
     * Whether the whole identity resolution - the endpoint record and every identity record - was
     * DNSSEC-validated; computed by resolve().
     * @type {boolean}
     */
    this.secure = false;
  }

  /**
   * Resolves the identity by querying the DNS.
   * Identities must have at least one identity record present to be successfully resolved.
   *
   * The result is memoized, and subsequent calls to the `resolve` function do not perform DNS lookups.
   * Rejections are currently memoized too.
   *
   * @returns {Promise<boolean>} A promise that resolves to true if the identity has been resolved, false otherwise.
   */
  async resolve() {

    // Memoize the returned promise so that multiple and/or concurrent calls return the same status.
    return (this.#resolvePromise ||= (async () => {
      try {
        this.config.logger?.debug?.(`Resolving Triauth.Identity for identifier ${this.identifier}`);

        // Resolve the authenticationEndpoint to read triauth configuration, and then the identityDomain
        //
        // This will query the DNS for TXT records stored under the domain name of the identifier, looking for a TXT record starting with 'triauth' keyword.
        // We start with this, to make sure domain is configured for triauth, and to get the mode in which identity domains should be derived from identifiers (e.g., public or private).
        //
        // Next, resolve the identity domain, using the options as read from the DNS TXT record defining the authentication endpoint, to obtain its identityRecords.
        // This will query the DNS for TXT records stored at the domain name that is derived from the user's identifier (e.g., 'john._at.triauthdemo.org' (public mode), or '_4GIBDU53B3._at.private.triauthdemo.org' (private mode)).
        if (
          !await this.authenticationEndpoint.resolve() ||
          !await this.identityDomain.setOptions({
            mode: this.authenticationEndpoint.options.mode,
            lookupCode: this.options.lookupCode
          }).resolve()
        ) {
          this.resolved = false;
          return this.resolved;
        }

        const identityRecords = this.identityDomain.identityRecords;

        // The endpoint record is a dependency of key discovery (its options select the identity domain
        // the keys are read from), so keys can only be as secure as the endpoint record itself.
        const endpointSecure = this.authenticationEndpoint.secure === true;
        const includePolicy = IdentityIncludes.parsePolicy(this.authenticationEndpoint.options['include']);

        let publicProfileExtensionCount = 0;
        const publicProfile = {}; // local copy, until object is resolved
        const groups = new Set(); // local set of bare group names; qualified and assigned once resolved
        let identitySecure = endpointSecure; // identity can be only as secure as the endpoint answer
        let commitment = null; // the `commit` record value, if present

        for (const entry of identityRecords) {

          identitySecure &&= !!entry.dnssec;

          // DNS-derived freshness of this record: fresh until its TTL runs out
          const expires = (Number.isInteger(entry.ttl) ? Date.now() + entry.ttl * 1000 : undefined);

          // Profile values are the only record values that are percent-decoded
          const profileValue = (entry.key.match(this.#PUBLIC_PROFILE_KEYWORDS) || entry.key.startsWith('x-'))
            ? Helpers.percentDecode(entry.value)
            : null;

          // `key` record - add to this.keys (IdentityKeys)
          if (entry.key === 'key') {
            await this.keys.add(entry.value, entry.options, {expires});

          // `include` record - add to this.includes (IdentityIncludes)
          } else if (entry.key === 'include') {
            await this.includes.add(entry.value, entry.options, {expires, includePolicy, localDomainName: this.domainName});

          // `groups` record - a comma-separated list of group names this identity claims membership in, later scoped to the identifier's domain
          } else if (entry.key === 'groups' && groups.size < LIMITS.maxGroups) {

            // No critical options are defined, so any critical option means the record is ignored ('x-' options are inert)
            if (!Helpers.verifyOptionsSchema(entry.options, {})) {
              this.config.logger?.debug?.('Ignoring groups record due to unrecognized options', {identifier:this.identifier});
              continue;
            }

            // Group names follow the device-name grammar; a record with any malformed name is ignored as a whole, never repaired.
            const names = Helpers.asciiLowercase(entry.value).split(',');
            if (!names.every((name) => Validator.validateDeviceName(name).valid)) {
              this.config.logger?.debug?.('Ignoring groups record with a malformed group name', {identifier:this.identifier});
              continue;
            }

            for (const name of names) {
              if (groups.has(name)){ continue; } // duplicates never consume the cap
              if (groups.size >= LIMITS.maxGroups) {
                this.config.logger?.debug?.('Ignoring groups and further group records over the limit', {limit:LIMITS.maxGroups});
                break;
              }
              groups.add(name);
            }

          // `commit` record - the commitment binding these records to the identity's derivation (its lookup code)
          } else if (entry.key === 'commit') {

            // No critical options are defined; the value is a 43-character base64url digest
            if (
              commitment === null &&
              Helpers.verifyOptionsSchema(entry.options, {}) &&
              Helpers.isBase64UrlString(entry.value)
            ) {
              commitment = entry.value;

            } else {
              commitment = false;
              this.config.logger?.debug?.('Ignoring malformed or duplicated commit record(s)', {identifier:this.identifier});

            }

          // publicProfile record - value is exposed raw, so it's the responsibility of API callers to escape it before rendering
          } else if (
            entry.key.match(this.#PUBLIC_PROFILE_KEYWORDS) &&
            profileValue !== null &&
            Helpers.isNormalString(profileValue, LIMITS.publicProfileMaxValueBytesize)
          ) {

            // Do not allow doubled keywords - drop the whole entry from publicProfile
            if (Object.hasOwn(publicProfile, entry.key)) {
              publicProfile[entry.key] = null;
              this.config.logger?.debug?.('Ignoring doubled publicProfile entry', {keyword:entry.key, identifier:this.identifier});
              continue;
            }

            publicProfile[entry.key] = profileValue;

          // Public profile extension / experimental keyword(s) in `x-` namespace
          // - 'x-' namespace is open-ended, with a cap on the number of distinct extensions kept
          // - similar as with recognized publicProfile entries - keys and values exposed raw, so must be escaped by callers before rendering
          } else if (
            entry.key.startsWith('x-') &&
            Helpers.isNormalString(entry.key, LIMITS.publicProfileMaxKeyBytesize) &&
            profileValue !== null &&
            Helpers.isNormalString(profileValue, LIMITS.publicProfileMaxValueBytesize)
          ) {

            // Do not allow doubled keywords - drop the whole entry from publicProfile
            if (Object.hasOwn(publicProfile, entry.key)) {
              publicProfile[entry.key] = null;
              this.config.logger?.debug?.('Ignoring doubled publicProfile entry', {keyword:entry.key, identifier:this.identifier});
              continue;
            }

            if (publicProfileExtensionCount < LIMITS.publicProfileMaxExtensions) {
              publicProfile[entry.key] = profileValue;
              publicProfileExtensionCount++;

            } else {
              this.config.logger?.debug?.('Ignoring publicProfile extension over the limit', {keyword:entry.key, identifier:this.identifier});
            }

          } else {
            this.config.logger?.debug?.('Ignoring unrecognized identity record', {keyword:entry.key, identifier:this.identifier, domainName:this.identityDomain.domainName});

          }
        }

        // When 'private' mode is set for the domain, identityRecords must carry a valid/matching 'commit ...' entry, for the identity to be resolved.
        // The value of `commit ...` entry is supposed to be base64url(SHA-256(<untruncated base32 label>))
        if (
          this.identityDomain.expectedCommitment !== null &&
          commitment !== this.identityDomain.expectedCommitment
        ) {
          this.config.logger?.info?.('Commit record missing, mismatched, or duplicated - identity unresolved', {identifier:this.identifier});
          this.resolved = false;
          return this.resolved;
        }

        // Remove 'null' records from local publicProfile and assign to this.publicProfile
        this.publicProfile = Object.fromEntries(Object.entries(publicProfile).filter(([, v]) => v !== null));

        // Sorted (DNS answer order is not stable) and qualified with the identifier's domain
        this.groups = [...groups].sort().map((name) => `${name}@${this.domainName}`);

        this.secure = identitySecure;

        this.config.logger?.debug?.(`Parsed identity records for ${this.identifier} - ${this.keys.count} devices, ${Object.keys(this.publicProfile).length} profile entries, ${this.groups.length} groups`);

        this.resolved = identityRecords.length > 0;
        return this.resolved;

      } catch (err) {
        this.config.logger?.debug?.(err);

        this.resolved = false;
        throw err;
      }
    })());
  }

}
