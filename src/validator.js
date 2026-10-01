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
import { LIMITS, DELIMITER } from './protocol.js';

/**
 * A collection of helper methods dedicated for data validation.
 *
 * These validation methods are not meant to be bullet-proof, and API method calls should return correct results even
 * if invalid or dangerous data for some reason passes the validation.
 *
 * @class
 * @memberof Triauth
 */
export class Validator {

  static #ERRORS = {
    210: 'Identifier is invalid',
    211: 'Identifier must not be empty',
    212: 'Identifier is too long',
    213: 'Identifier must be provided in lowercase',
    214: 'Identifier must include one @ sign',
    215: 'Identifier contains invalid username',
    216: 'Identifier contains invalid domain name',
    221: 'Invalid callbackUrl',
    222: 'Invalid ext',
    223: 'Invalid challenge',
    224: 'Invalid response',
    225: 'Invalid signature',
    226: 'Invalid token',
    227: 'Invalid message',
    228: 'Invalid attachments',
    229: 'Invalid attestations',
    260: 'Device name is invalid',
    261: 'Device name must not be empty',
    262: 'Device name is too long',
    263: 'Device name must be provided in lowercase',
    264: 'Device name must include only letters, numbers, and hyphens'
  };

  static #expandResult(errors) {
    // expand errors
    errors = errors.map((errno) => {
      return {
        code: errno,
        message: this.#ERRORS[errno]
      };
    });

    return {
      valid: errors.length === 0,
      errors
    };
  };

  /**
   * Validates the provided personal identifier's format, and returns human-friendly error messages if problems are found.
   *
   * @param identifier {String} - Identifier that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateIdentifier(identifier) {
    if (typeof identifier !== 'string') {
      return this.#expandResult([210]); // 'Identifier is invalid'
    }

    if (identifier.length <= 0) {
      return this.#expandResult([211]); // 'Identifier must not be empty'
    }

    if (identifier.length > LIMITS.identifierBytesize || Helpers.byteSize(identifier) > LIMITS.identifierBytesize) {
      return this.#expandResult([212]); // 'Identifier is too long'
    }

    // identifiers must not contain any whitespace characters and/or NULL
    if (identifier.match(/[\s\0]/g)) {
      return this.#expandResult([210]); // 'Identifier is invalid'
    }

    if (identifier !== identifier.toLowerCase()) {
      return this.#expandResult([213]); // Identifier must be provided in lowercase
    }

    if ((identifier.match(/@/g) || []).length !== 1) {
      return this.#expandResult([214]); // 'Identifier must include one @ sign'
    }

    const [username, domain] = identifier.split('@');
    const errors = [];

    if (
      // Username may be composed only of ASCII letters, numbers, dot and hyphen signs, must start with a letter or a digit,
      // and must be no longer than 63 chars (DNS label limit),
      !username.match(/^[a-z0-9][a-z0-9.-]{0,62}$/) ||

      // consecutive dots and/or hyphens are not allowed,
      username.match(/[.-][.-]/i) ||

      // and it must not end with a dot or hyphen.
      username.match(/[.-]$/i)
    ) {
      errors.push(215); // 'Invalid username'
    }

    if (
      !Helpers.isDomainName(domain)
    ) {
      errors.push(216); // 'Invalid domain name',
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the provided callback URL's format, and returns human-friendly error messages if problems are found.
   *
   * @param callbackUrl {String} - Callback URL that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateCallbackUrl(callbackUrl) {
    const errors = [];

    // A callback URL is any canonical URL — http or https, named or IPv4-literal host — whose
    // base URL is free of the signature-envelope delimiter ';'
    const base = Helpers.getBaseUrl(callbackUrl);
    if (base === false || base.includes(DELIMITER)) {
      errors.push(221);
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the optional `ext` property for {@link Triauth.authenticate} — both as supplied in stage 1 and as received back in stage 3.
   *
   * `ext` must be a plain object whose values are strings, numbers, booleans, or plain objects one level deep (no arrays, no deeper nesting).
   * Keys must additionally be ASCII-only — `Helpers.safeParseJson` rejects non-ASCII property names when the ext round-trips back in stage 3 —
   * and never one of the prototype-poisoning names (`__proto__`, `constructor`, `prototype`)
   *
   * @param ext {object} - Ext object that should be validated.
   * @param [depth=0] {number} - Nesting depth of the object being validated: 0 for the `ext` object itself,
   *                             1 for the single level of nested plain objects that `ext` values may contain.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateExt(ext, depth=0) {
    const errors = [];

    if (
      !ext ||
      !(typeof ext === 'object' && !Array.isArray(ext) && Object.keys(ext).every((k) => Helpers.isNormalString(k, LIMITS.jsonMaxKeyLength) && !/[^\x20-\x7E]/.test(k) && ['__proto__', 'constructor', 'prototype'].indexOf(k) < 0) && Object.values(ext).every((e) => typeof e === 'string' || typeof e === 'number' || typeof e === 'boolean' || (depth === 0 && this.validateExt(e, depth + 1).errors.length === 0))) ||
      Helpers.byteSize(JSON.stringify(ext)) > LIMITS.extBytesize
    ) {
      errors.push(222);
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the `attestations` option for {@link Triauth.attest}, applied both when building the challenge (stage 1) and verifying the response (stage 3).
   *
   * `attestations` must be a plain object keyed by attestation name, where each value is `{label: string, providers: string[]}`.
   * An empty object `{}` is valid; passing it will produce `{attested: true, attestations: {}}` from stage 3.
   * An attestation name is never one of the prototype-poisoning keys (`__proto__`, `constructor`, `prototype`).
   *
   * @param attestations {Object} - Attestations object that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateAttestations(attestations) {
    const errors = [];

    if (
      !attestations ||
      !(typeof attestations === 'object' && !Array.isArray(attestations)) ||
      !(Object.keys(attestations).every((k) => Helpers.isNormalString(k) && ['__proto__', 'constructor', 'prototype'].indexOf(k) < 0))
      ) {
      return this.#expandResult([229]);
    }

    // The multi-signature envelope holds at most maxMultiSignatures entries (1 user + N attesters),
    // so requesting more than (maxMultiSignatures - 1) attestations creates a request that can never be satisfied.
    if (Object.keys(attestations).length > LIMITS.maxMultiSignatures - 1) {
      return this.#expandResult([229]);
    }

    for (const entry of Object.values(attestations)) {
      if(
        !(typeof entry === 'object' && !Array.isArray(entry)) ||
        !(Object.keys(entry).every((k) => ['label', 'providers'].indexOf(k) >= 0)) ||
        !(Helpers.isNormalString(entry.label)) ||
        !(
          Array.isArray(entry.providers) &&
          entry.providers.length > 0 && entry.providers.length <= LIMITS.maxMultiSignatures - 1 &&
          entry.providers.every((pUrl) => Helpers.isSecureUrl(pUrl))
        )
      ) {
        errors.push(229);

      } else {
        for (const providerUrl of entry.providers) {
          // Beyond being canonical on a secure origin, a provider URL is displayed verbatim in
          // the authenticator UI and embedded whole as the `via` field of the attestation
          // segment, so it must carry no query, no fragment, no percent-escapes, no envelope
          // delimiter ';', and no apostrophe. In a canonical URL, '?' and '#' can appear only
          // as the query/fragment introducers and '%' only in an escape — one charset test
          // covers every excluded character.
          if (/[?#%;']/.test(providerUrl)) {
            errors.push(229);
          }
        }
      }
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the challenge string returned from stage 1 of an authentication flow, before passing it to stage 3.
   *
   * The challenge must be a non-empty base64url-encoded string within the allowed byte size.
   *
   * @param challenge {String} - Challenge string that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateChallenge(challenge) {
    const errors = [];

    if (
      typeof challenge !== 'string' ||
      challenge.length <= 0 ||
      challenge.length > LIMITS.challengeBytesize ||
      Helpers.byteSize(challenge) > LIMITS.challengeBytesize ||
      !Helpers.isBase64UrlString(challenge)
    ) {
      errors.push(223);
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the response string returned by the authenticator in stage 3 of an authentication flow.
   *
   * The response must be a pipe-delimited string of the form `|...|`, within the allowed byte size.
   *
   * @param response {String} - Response string that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateResponse(response) {
    const errors = [];

    if (
      typeof response !== 'string' ||
      response.length <= 3 ||
      (response[0] !== '|' || response[response.length - 1] !== '|') ||
      response.length > LIMITS.signatureBytesize ||
      Helpers.byteSize(response) > LIMITS.signatureBytesize
    ) {
      errors.push(224);
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the message string to be signed or stamped in a {@link Triauth.sign} or {@link Triauth.stamp} flow.
   *
   * @param message {String} - Message that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateMessage(message) {
    const errors = [];

    if (!Helpers.isNormalString(message, LIMITS.messageBytesize)) {
      errors.push(227);
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the `attachments` array for a {@link Triauth.sign} flow.
   *
   * Each attachment must be a plain object with `name` (string) and `sha256` (64-character lowercase hex string),
   * plus a `sourceUrl` (a canonical URL). Names must be unique within the array.
   *
   * `sourceUrl` is only needed when building the challenge (stage 1), so the authenticator knows where to fetch
   * the file to hash. It is intentionally NOT required on the signed response (stage 3): the durable proof binds
   * only `name`+`sha256`, and keeping `sourceUrl` out of the signed payload avoids embedding fetch URLs (which may
   * carry presigned credentials) in a portable, third-party-verifiable signature. Pass `requireSourceUrl = false`
   * to validate a response's attachments, where `sourceUrl` may be omitted (but is held to the same rule if present).
   *
   * @param attachments {Array<{name: string, sourceUrl?: string, sha256: string}>} - Attachments array that should be validated.
   * @param [requireSourceUrl=true] {boolean} - Whether a valid `sourceUrl` is mandatory on every entry.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateAttachments(attachments, requireSourceUrl = true) {
    const errors = [];
    const seenNames = Object.create(null);

    if (
      !Array.isArray(attachments) ||
      attachments.length > LIMITS.attachmentsCount ||
      !attachments.every((f) =>
        Helpers.hasOnlyKnownProperties(f, ['name', 'sourceUrl', 'sha256']) &&
        Helpers.isNormalString(f.name, 255) &&
        ((!requireSourceUrl && f.sourceUrl === undefined) || Helpers.isCanonicalUrl(f.sourceUrl)) &&
        (typeof f.sha256 === 'string' && /^[0-9a-f]{64}$/.test(f.sha256)) &&
        (!seenNames[f.name] && (seenNames[f.name] = true))
      )
    ) {
      errors.push(228);
    }

    return this.#expandResult(errors);
  }

  /**
   * The binder names a signature may state inside its signed-metadata `bind` object: the verified
   * fields the signature is bound to. Each names a field of the verified user signature and must
   * equal it (see {@link Triauth.attest}).
   *
   * @type {Array<string>}
   */
  static BINDER_NAMES = ['identifier', 'via', 'deviceTag'];

  /**
   * Validates a signature segment's signed metadata against the binder grammar.
   *
   * A signature states what it is bound to in the `bind` object, and **every member of `bind` is
   * critical**: a verifier must recognize it and it must match, so a constraint the producer signed
   * can never be dropped without a trace. Members outside `bind` stay auxiliary and tolerant
   * (an unrecognized one is ignored), so a compatible revision may still add signed metadata.
   *
   * @param signedMetadata {object} - The signed metadata of a signature segment.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   *          Invalid (225) when `bind` is present but is not an object of at least one recognized
   *          binder with a string value.
   */
  static validateBinders(signedMetadata) {
    if (Object.keys(signedMetadata).indexOf('bind') < 0) {
      return this.#expandResult([]); // a signature that binds nothing is valid - attesters attest anonymously
    }

    const bind = signedMetadata.bind;
    const binders = (bind && typeof bind === 'object' && !Array.isArray(bind)) ? Object.keys(bind) : null;

    if (
      !binders ||
      binders.length < 1 ||
      !binders.every((binder) => this.BINDER_NAMES.indexOf(binder) >= 0 && typeof bind[binder] === 'string')
    ) {
      return this.#expandResult([225]);
    }

    return this.#expandResult([]);
  }

  /**
   * Validates the `token` that gates stage 1 of {@link Triauth.ping}, {@link Triauth.sign}, {@link Triauth.stamp}, and {@link Triauth.attest}.
   *
   * A token has the form `issuer:secret` — an issuer prefix that is either empty (the identifier's own domain) or the
   * lowercase domain name whose endpoint record names the authenticator that minted the token, a single `:`, and a
   * secret of at least 16 characters. The whole token keys the HMAC that binds the challenge to the token holder,
   * and must be a normal string within the allowed byte size.
   *
   * @param token {String} - Token that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateToken(token) {
    const errors = [];

    if (
      typeof token !== 'string' ||
      !Helpers.isNormalString(token)
    ) {
      return this.#expandResult([226]);
    }

    // Validate token structure
    const [tokenDomainName, tokenSecret, rest] = token.split(':');

    if (
      (tokenDomainName && !Helpers.isDomainName(tokenDomainName)) ||
      tokenDomainName.toLowerCase() !== tokenDomainName ||
      (tokenSecret || '').length < 16 ||
      rest !== undefined
    ) {
      errors.push(226);
    }

    return this.#expandResult(errors);
  }

  /**
   * Validates the provided device name's format, and returns human-friendly error messages if problems are found.
   *
   * Device names must be lowercase and composed of letters, numbers, and single hyphens between alphanumerics
   * (no leading, trailing, or consecutive hyphens), within the allowed byte size.
   *
   * @param deviceName {String} - Device name that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: number, message: string}>}}
   */
  static validateDeviceName(deviceName) {
    const errors = [];

    if (typeof deviceName !== 'string') {
      return this.#expandResult([260]); // 'Device name is invalid'
    }

    if (deviceName.length <= 0) {
      errors.push(261); // 'Device name must not be empty'
    }

    if (deviceName.length > LIMITS.deviceNameBytesize || Helpers.byteSize(deviceName) > LIMITS.deviceNameBytesize) {
      return this.#expandResult([262]); // 'Device name is too long'
    }

    // deviceName must not contain any whitespace characters and/or NULL
    if (deviceName.match(/[\s\0]/g)) {
      errors.push(260); // 'Device name is invalid'
    }

    if (deviceName !== deviceName.toLowerCase()) {
      errors.push(263); // Device name must be provided in lowercase
    }

    // Lowercase alphanumerics joined by single hyphens: the name must start and end on an alphanumeric
    // and carry no consecutive hyphens.
    if (!deviceName.match(/^[a-z0-9]+(-[a-z0-9]+)*$/)) {
      errors.push(264);
    }

    return this.#expandResult(errors);
  }
}
