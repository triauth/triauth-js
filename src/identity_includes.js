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
import { Validator } from './validator.js';
import { FLOWS, FLOWS_USE_REGEXP, SCOPE_ANY, SCOPE_NONE, AT_MARKER, LIMITS, DEFAULT_INCLUDE } from './protocol.js';

/**
 * Holds information about include statements for identifier, as extracted from identity records.
 *
 * @class
 * @memberof Triauth
 */
export class IdentityIncludes {

  /**
   * Constructs an empty include-statement list.
   *
   * @param [config={}] {object} - optional overrides for the global Triauth.config settings.
   */
  constructor(config = {}) {
    this.config = Helpers.mergeConfig(config);

    // Holds entries in form of {ref, options, use, scope, domainName, tag, expires}
    this.includes = [];
    this.sorted = false;
  }

  /**
   * Parses the endpoint record's `include` option into the include policy list.
   *
   * @param [rawOption] {string} - the `include` option value as published; undefined defaults to `any`.
   *
   * @returns {Array<string>} the policy entries (`none`|`any`|`local`|allowlisted domain names), lowercased.
   */
  static parsePolicy(rawOption) {
    return rawOption !== undefined ? Helpers.asciiLowercase(rawOption).split(',') : [DEFAULT_INCLUDE];
  }

  /**
   * Adds an include statement to the list of includes
   *
   * @param value {string} - the ref of the include as visible in the identity record - either the actor's
   *        identifier (e.g., 'actor@triauthdemo.org') or its identity domain (e.g., 'actor._at.triauthdemo.org')
   * @param [options={}] {object} - the include options as specified in the identity record
   * @param [metadata={}] {object} - the resolve-layer context for the include record ({expires, includePolicy, localDomainName});
   *        `includePolicy` is the endpoint record's `include` option as a list of policies: `none` rejects every include (and dominates any combination),
   *        `any` as the sole entry allows all refs, `local` allows refs on `localDomainName`, and any other entry allowlists that exact domain;
   *        when absent it defaults to `['none']` (every include is ignored)
   * @returns {Promise<boolean>} true when the include was successfully added, false when it was ignored (e.g., unrecognized ref or options, or the `LIMITS.maxIncludes` cap was exceeded)
   */
  async add(value, options = {}, metadata = {}) {
    // Work on a private copy of `options`
    options = Object.assign({}, options);

    // Normalize value to downcase
    value = Helpers.asciiLowercase(String(value));   // ASCII-only: a non-ASCII uppercase letter must fail the ref grammar, not fold into it

    // The value must be either an identifier (`actor@example.org`) or a lowercase identity domain (`actor._at.example.org`, `_4gibdu58b3._at.example.org`)
    // The separator (`@` or AT_MARKER) tells the two spellings apart,
    const separator =
      Validator.validateIdentifier(value).valid ? '@' :
      Helpers.isDomainName(value.replace(/^_/,'').replace(AT_MARKER, '.')) && value.split(AT_MARKER).length === 2 ? AT_MARKER :
      null;

    if (!separator) {
      this.config.logger?.debug?.('Ignoring include due to unrecognized ref');
      return false;
    }

    // Parse options

    // All non-x- prefixed options are critical, and unknown critical options MUST cause include to be ignored.
    // `scope` is required and names the service hosts the grant works at: the sole entry `any` (every host),
    // or a comma-separated allowlist of hostnames. `any` beside other entries and `none` are not valid.
    const optionsSchema = {
      use: [FLOWS_USE_REGEXP],
      scope: [(scope) => scope === SCOPE_ANY || scope.split(',').every((host) =>
        host !== SCOPE_ANY && host !== SCOPE_NONE && Helpers.urlHost('https://' + host + '/') === host)]
    };

    // Set defaults
    options['use'] ??= FLOWS.join(',');

    // `scope` has no safe default
    if (options['scope'] === undefined) {
      this.config.logger?.debug?.('Ignoring include without a scope option', {ref: value});
      return false;
    }

    // Validate options
    if (!Helpers.verifyOptionsSchema(options, optionsSchema)) {
      return false;
    }

    // Extract domainName from the ref
    const domainName = value.split(separator).slice(1).join(separator);

    // Double check that we have extracted non-empty domainName - should be unreachable under normal conditions
    if (!domainName) {
      return false;
    }

    // Check the include policy (the endpoint record's `include` option), as passed from the resolve layer
    const includePolicy = metadata.includePolicy ?? ['none'];
    if (
      includePolicy.includes('none') ||
      !(
        (includePolicy.length === 1 && includePolicy[0] === 'any') ||
        (includePolicy.includes('local') && domainName === metadata.localDomainName) ||
        includePolicy.includes(domainName)
      )
    ) {
      this.config.logger?.debug?.('Ignoring include due to policy', {ref: value, includePolicy});
      return false;
    }

    // Enforce the include count cap - includes beyond it are ignored
    if (this.includes.length >= LIMITS.maxIncludes) {
      this.config.logger?.debug?.('Ignoring include - too many include statements');
      return false;
    }

    // A stable tag of this grant (its ref and critical options), so the grant's presence can later be re-checked from the tag alone
    const tag = await Helpers.sha256(
      '\x01' + value + '\x02' +
        Object.entries(options).filter(([k]) => !(k[0] === 'x' && k[1] === '-')).map(([k,v]) => k + '=' + v).sort().join('\x1E')
    );

    // At this point the `include` has been validated, so we can add it to the list and continue
    this.includes.push({
      ref: value,
      options,                              // the published spelling - the tag preimage and whois read this
      use: options['use'].split(','),       // parsed once for matching
      scope: options['scope'] === SCOPE_ANY ? null : options['scope'].split(','),  // null = every service host
      domainName,
      tag,
      expires: metadata.expires
    });

    this.sorted = false;

    return true;
  }

  /**
   * Lists the include statements in their canonical (tag-sorted) order.
   *
   * @returns {Array<{ref: string, options: object, use: Array<string>, scope: (Array<string>|null), domainName: string, tag: string, expires: (number|undefined)}>} the include statements (`scope` is `null` for a `scope=any` grant, which covers every service host); an empty array when the identity publishes none.
   */
  list() {
    this.#sort();
    return this.includes.slice();
  }

  /**
   * Checks if the include statement references the given actor (by identifier or identity domain), allows the
   * given mode/use, and covers the given service host with its `scope`.
   *
   * @param includeStatement {object} - the include statement to check.
   * @param actorIdentity {import('./identity.js').Identity} - the resolved actor identity to match against.
   * @param mode {?string} - the flow the include must allow; `null` skips the use check.
   * @param host {?string} - the service host the include must cover; `null` skips the scope check.
   *
   * @returns {boolean} true when the include statement covers the actor, the mode, and the host.
   */
  #checkMatch(includeStatement, actorIdentity, mode, host) {
    return (
      (includeStatement.ref === actorIdentity.identifier || includeStatement.ref === actorIdentity.identityDomain.domainName.toLowerCase()) &&
      (mode === null || includeStatement.use.includes(mode)) &&
      (host === null || includeStatement.scope === null || includeStatement.scope.includes(host))
    )
  }

  /**
   * Sorts the include statements by their `tag` values (idempotent).
   *
   * The scan order matters as DNS may return the records in any order, and without the sort the code
   * could pick different includes (with different tags - which end up in deviceTag) on each API method call.
   */
  #sort() {
    if (!this.sorted) {
      this.includes.sort((a, b) => {
        const x = a['tag'], y = b['tag'];
        return x < y ? -1 : x > y ? 1 : 0;
      });
    }

    this.sorted = true;
  }

  /**
   * Finds an include statement that grants the given actor the given mode, resolving the actor's identity in the process.
   *
   * @param actorIdentity {import('./identity.js').Identity} - the actor (delegate) to match include statements against.
   * @param [includeTag=null] {?string} - when given, only the include statement with this tag is considered.
   * @param [mode='auth'] {?string} - the flow that the include must allow; `null` skips the use check.
   * @param [host=null] {?string} - the service host that the include's `scope` must cover; `null` skips the scope check.
   *
   * @returns {Promise<object|null|false>} the matching include statement, `null` when none matches (revoked), or `false` when the actor's identity could not be resolved.
   */
  async find(actorIdentity, includeTag=null, mode='auth', host=null) {
    this.#sort();
    const candidates = includeTag != null ? this.includes.filter((incl) => incl.tag === includeTag) : this.includes;

    if (candidates.length === 0) {
      this.config.logger?.debug?.('IdentityIncludes.find failed - include statement revoked', {includeTag});
      return null;
    }

    await actorIdentity.resolve();
    if (!actorIdentity.resolved) {
      this.config.logger?.debug?.('IdentityIncludes.find failed - failed to resolve actor', {actorIdentifier: actorIdentity.identifier});
      return false;
    }

    return candidates.find((incl) => this.#checkMatch(incl, actorIdentity, mode, host)) ?? null;
  }

}
