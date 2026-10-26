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

// The longest well-formed session key, `<domain>:<key>` with a domain of at most LIMITS.domainNameBytesize
// bytes and a 43-character key, and the longest well-formed device tag, `<grantTag>:<actorIdentifier>:<actorDeviceTag>`
// with two tag components of 43 + 1 + 16 characters around an identifier of at most LIMITS.identifierBytesize bytes.
// The validators compare the length against these caps ahead of any split, so the cost of a rejection does not
// grow with the input.
const SESSION_KEY_MAX_LENGTH = LIMITS.domainNameBytesize + 1 + 43;
const DEVICE_TAG_MAX_LENGTH = 2 * (43 + 1 + 16) + 2 + LIMITS.identifierBytesize;

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

  /**
   * The message of every validation error, by error code and reason. Each code names the invalid field,
   * and each reason names the rule that the field breaks.
   */
  static #ERRORS = {
    invalid_identifier: {
      invalid: 'Identifier is invalid',
      empty: 'Identifier must not be empty',
      too_long: 'Identifier is too long',
      not_lowercase: 'Identifier must be provided in lowercase',
      invalid_format: 'Identifier must include one @ sign',
      invalid_username: 'Identifier contains invalid username',
      invalid_domain: 'Identifier contains invalid domain name'
    },
    invalid_callback_url: {invalid: 'Invalid callbackUrl'},
    invalid_ext: {invalid: 'Invalid ext'},
    invalid_challenge: {invalid: 'Invalid challenge'},
    invalid_response: {invalid: 'Invalid response'},
    invalid_signature: {invalid: 'Invalid signature'},
    invalid_session_key: {invalid: 'Invalid session key'},
    invalid_message: {invalid: 'Invalid message'},
    invalid_attachments: {invalid: 'Invalid attachments'},
    invalid_attestations: {invalid: 'Invalid attestations'},
    invalid_lookup_code: {invalid: 'Invalid lookup code'},
    invalid_device_tag: {invalid: 'Invalid device tag'},
    invalid_device_name: {
      invalid: 'Device name is invalid',
      empty: 'Device name must not be empty',
      too_long: 'Device name is too long',
      not_lowercase: 'Device name must be provided in lowercase',
      invalid_characters: 'Device name must include only letters, numbers, and hyphens'
    },
    invalid_group_name: {
      invalid: 'Group name is invalid',
      empty: 'Group name must not be empty',
      too_long: 'Group name is too long',
      not_lowercase: 'Group name must be provided in lowercase',
      invalid_characters: 'Group name must include only letters, numbers, and hyphens'
    }
  };

  /**
   * Builds a validation result from the reasons found for one field.
   *
   * @param code {string} - The error code of the field (e.g., `invalid_identifier`).
   * @param reasons {Array<string>} - The reasons found, empty when the field is valid.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static #expandResult(code, reasons) {
    return {
      valid: reasons.length === 0,
      errors: reasons.map((reason) => ({code, reason, message: this.#ERRORS[code][reason]}))
    };
  }

  /**
   * Validates the provided personal identifier's format, and returns human-friendly error messages if problems are found.
   *
   * @param identifier {String} - Identifier that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateIdentifier(identifier) {
    if (typeof identifier !== 'string') {
      return this.#expandResult('invalid_identifier', ['invalid']);
    }

    if (identifier.length <= 0) {
      return this.#expandResult('invalid_identifier', ['empty']);
    }

    if (identifier.length > LIMITS.identifierBytesize || Helpers.byteSize(identifier) > LIMITS.identifierBytesize) {
      return this.#expandResult('invalid_identifier', ['too_long']);
    }

    // identifiers must not contain any whitespace characters and/or NULL
    if (identifier.match(/[\s\0]/g)) {
      return this.#expandResult('invalid_identifier', ['invalid']);
    }

    if (identifier !== identifier.toLowerCase()) {
      return this.#expandResult('invalid_identifier', ['not_lowercase']);
    }

    if ((identifier.match(/@/g) || []).length !== 1) {
      return this.#expandResult('invalid_identifier', ['invalid_format']);
    }

    const [username, domain] = identifier.split('@');
    const reasons = [];

    if (
      // Username may be composed only of ASCII letters, numbers, dot and hyphen signs, must start with a letter or a digit,
      // and must be no longer than 63 chars (DNS label limit),
      !username.match(/^[a-z0-9][a-z0-9.-]{0,62}$/) ||

      // consecutive dots and/or hyphens are not allowed,
      username.match(/[.-][.-]/i) ||

      // and it must not end with a dot or hyphen.
      username.match(/[.-]$/i)
    ) {
      reasons.push('invalid_username');
    }

    if (
      !Helpers.isDomainName(domain)
    ) {
      reasons.push('invalid_domain');
    }

    return this.#expandResult('invalid_identifier', reasons);
  }

  /**
   * Validates the provided callback URL's format, and returns human-friendly error messages if problems are found.
   *
   * @param callbackUrl {String} - Callback URL that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateCallbackUrl(callbackUrl) {
    const reasons = [];

    // A callback URL is any canonical URL — http or https, named or IPv4-literal host — whose
    // base URL is free of the signature-envelope delimiter ';'
    const base = Helpers.getBaseUrl(callbackUrl);
    if (base === false || base.includes(DELIMITER)) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_callback_url', reasons);
  }

  /**
   * Validates the optional `ext` property for {@link Triauth.authenticate} — both as supplied in stage 1 and as received back in stage 3.
   *
   * `ext` must be a plain object whose values are strings, whole numbers, booleans, or plain objects one level deep (no arrays, no deeper nesting).
   * A string value carries no unpaired surrogate and a number is a whole number of magnitude at most 2^53 - 1, the rules that
   * `Helpers.safeParseJson` applies to every JSON value when the ext comes back in stage 3.
   * Keys must additionally be ASCII-only — `Helpers.safeParseJson` rejects non-ASCII property names when the ext round-trips back in stage 3 —
   * and never one of the prototype-poisoning names (`__proto__`, `constructor`, `prototype`)
   *
   * @param ext {object} - Ext object that should be validated.
   * @param [depth=0] {number} - Nesting depth of the object being validated: 0 for the `ext` object itself,
   *                             1 for the single level of nested plain objects that `ext` values may contain.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateExt(ext, depth=0) {
    const reasons = [];

    if (
      !ext ||
      !(typeof ext === 'object' && !Array.isArray(ext) && Object.keys(ext).every((k) => Helpers.isNormalString(k, LIMITS.jsonMaxKeyLength) && !/[^\x20-\x7E]/.test(k) && ['__proto__', 'constructor', 'prototype'].indexOf(k) < 0) && Object.values(ext).every((e) => (typeof e === 'string' && Helpers.isWellFormedString(e)) || Number.isSafeInteger(e) || typeof e === 'boolean' || (depth === 0 && this.validateExt(e, depth + 1).errors.length === 0))) ||
      Helpers.byteSize(JSON.stringify(ext)) > LIMITS.extBytesize
    ) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_ext', reasons);
  }

  /**
   * Validates the `attestations` option for {@link Triauth.attest}, applied both when building the challenge (stage 1) and verifying the response (stage 3).
   *
   * `attestations` must be a plain object keyed by attestation name, where each value is `{label: string, providers: string[]}`.
   * An empty object `{}` is valid; passing it will produce `{attested: true, attestations: {}}` from stage 3.
   * An attestation name is printable ASCII, as it becomes a property name of the challenge that `Helpers.safeParseJson` admits only in ASCII in stage 3,
   * and never one of the prototype-poisoning keys (`__proto__`, `constructor`, `prototype`).
   *
   * @param attestations {Object} - Attestations object that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateAttestations(attestations) {
    const reasons = [];

    if (
      !attestations ||
      !(typeof attestations === 'object' && !Array.isArray(attestations)) ||
      !(Object.keys(attestations).every((k) => Helpers.isNormalString(k) && !/[^\x20-\x7E]/.test(k) && ['__proto__', 'constructor', 'prototype'].indexOf(k) < 0))
      ) {
      return this.#expandResult('invalid_attestations', ['invalid']);
    }

    // The multi-signature envelope holds at most maxMultiSignatures entries (1 user + N attesters),
    // so requesting more than (maxMultiSignatures - 1) attestations creates a request that can never be satisfied.
    if (Object.keys(attestations).length > LIMITS.maxMultiSignatures - 1) {
      return this.#expandResult('invalid_attestations', ['invalid']);
    }

    for (const entry of Object.values(attestations)) {
      if(
        !(entry !== null && typeof entry === 'object' && !Array.isArray(entry)) ||
        !(Object.keys(entry).every((k) => ['label', 'providers'].indexOf(k) >= 0)) ||
        !(Helpers.isNormalString(entry.label)) ||
        !(
          Array.isArray(entry.providers) &&
          entry.providers.length > 0 && entry.providers.length <= LIMITS.maxMultiSignatures - 1 &&
          entry.providers.every((pUrl) => Helpers.isSecureUrl(pUrl))
        )
      ) {
        reasons.push('invalid');

      } else {
        for (const providerUrl of entry.providers) {
          // Beyond being canonical on a secure origin, a provider URL is displayed verbatim in
          // the authenticator UI and embedded whole as the `via` field of the attestation
          // segment, so it must carry no query, no fragment, no percent-escapes, no envelope
          // delimiter ';', and no apostrophe. In a canonical URL, '?' and '#' can appear only
          // as the query/fragment introducers and '%' only in an escape — one charset test
          // covers every excluded character.
          if (/[?#%;']/.test(providerUrl)) {
            reasons.push('invalid');
          }
        }
      }
    }

    return this.#expandResult('invalid_attestations', reasons);
  }

  /**
   * Validates the challenge string returned from stage 1 of an authentication flow, before passing it to stage 3.
   *
   * The challenge must be a non-empty base64url-encoded string within the allowed byte size.
   *
   * @param challenge {String} - Challenge string that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateChallenge(challenge) {
    const reasons = [];

    if (
      typeof challenge !== 'string' ||
      challenge.length <= 0 ||
      challenge.length > LIMITS.challengeBytesize ||
      Helpers.byteSize(challenge) > LIMITS.challengeBytesize ||
      !Helpers.isBase64UrlString(challenge)
    ) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_challenge', reasons);
  }

  /**
   * Validates the response string returned by the authenticator in stage 3 of an authentication flow.
   *
   * The response must be a pipe-delimited string of the form `|...|`, within the allowed byte size.
   *
   * @param response {String} - Response string that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateResponse(response) {
    const reasons = [];

    if (
      typeof response !== 'string' ||
      response.length <= 3 ||
      (response[0] !== '|' || response[response.length - 1] !== '|') ||
      response.length > LIMITS.signatureBytesize ||
      Helpers.byteSize(response) > LIMITS.signatureBytesize
    ) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_response', reasons);
  }

  /**
   * Validates the sealed response received in stage 3 of an authentication flow, before it is opened.
   *
   * A sealed response is `<enc>.<ciphertext>`, both base64url: an 87-character encapsulated key, and a ciphertext of
   * at least the 16-byte authentication tag, bounded by the sealed size of the largest response envelope.
   *
   * @param response {String} - Sealed response that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateSealedResponse(response) {
    const reasons = [];
    const maxLength = 87 + 1 + Math.ceil((LIMITS.signatureBytesize + 16) * 4 / 3);

    if (
      typeof response !== 'string' ||
      response.length > maxLength ||
      !/^[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{22,}$/.test(response)
    ) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_response', reasons);
  }

  /**
   * Validates the message string to be signed or stamped in a {@link Triauth.sign} or {@link Triauth.stamp} flow.
   *
   * @param message {String} - Message that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateMessage(message) {
    const reasons = [];

    if (!Helpers.isNormalString(message, LIMITS.messageBytesize)) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_message', reasons);
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
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateAttachments(attachments, requireSourceUrl = true) {
    const reasons = [];
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
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_attachments', reasons);
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
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   *          Invalid (`invalid_signature`) when `bind` is present but is not an object of at least one recognized
   *          binder with a string value.
   */
  static validateBinders(signedMetadata) {
    if (Object.keys(signedMetadata).indexOf('bind') < 0) {
      return this.#expandResult('invalid_signature', []); // a signature that binds nothing is valid - attesters attest anonymously
    }

    const bind = signedMetadata.bind;
    const binders = (bind && typeof bind === 'object' && !Array.isArray(bind)) ? Object.keys(bind) : null;

    if (
      !binders ||
      binders.length < 1 ||
      !binders.every((binder) => this.BINDER_NAMES.indexOf(binder) >= 0 && typeof bind[binder] === 'string')
    ) {
      return this.#expandResult('invalid_signature', ['invalid']);
    }

    return this.#expandResult('invalid_signature', []);
  }

  /**
   * Validates the `sessionKey` that gates stage 1 of {@link Triauth.ping}, {@link Triauth.sign}, {@link Triauth.stamp}, and {@link Triauth.attest}.
   *
   * A session key is the `sessionKey` of a {@link Triauth.authenticate} result, 32 bytes in 43 base64url characters.
   * After a delegated sign-in it is `<domain>:<key>`, with the lowercase domain name of the actor.
   *
   * @param sessionKey {String} - Session key that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateSessionKey(sessionKey) {
    const parts = typeof sessionKey === 'string' && sessionKey.length <= SESSION_KEY_MAX_LENGTH ? sessionKey.split(':') : [];
    const [domain, key] = parts.length === 2 ? parts : [null, parts[0]];

    if (
      parts.length < 1 || parts.length > 2 ||
      (domain !== null && !(Helpers.isDomainName(domain) && domain === domain.toLowerCase())) ||
      key.length !== 43 || !Helpers.isBase64UrlString(key)
    ) {
      return this.#expandResult('invalid_session_key', ['invalid']);
    }

    // The canonical base64url of 32 bytes has no data in the unused bits of its last character
    try {
      Helpers.base64UrlToUint8(key);
    } catch {
      return this.#expandResult('invalid_session_key', ['invalid']);
    }

    return this.#expandResult('invalid_session_key', []);
  }

  /**
   * Validates the provided device name's format, and returns human-friendly error messages if problems are found.
   *
   * Device names must be lowercase and composed of letters, numbers, and single hyphens between alphanumerics
   * (no leading, trailing, or consecutive hyphens), within the allowed byte size.
   *
   * @param deviceName {String} - Device name that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateDeviceName(deviceName) {
    return this.#expandResult('invalid_device_name', this.#nameErrors(deviceName));
  }

  /**
   * Validates the provided group name's format, and returns human-friendly error messages if problems are found.
   *
   * Group names follow the device-name grammar: lowercase letters, numbers, and single hyphens between alphanumerics
   * (no leading, trailing, or consecutive hyphens), within the allowed byte size. The name is the bare name as published
   * in a `groups` record (e.g., `admins`), not the fully-qualified form found in results (e.g., `admins@example.com`).
   *
   * @param groupName {String} - Group name that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateGroupName(groupName) {
    return this.#expandResult('invalid_group_name', this.#nameErrors(groupName));
  }

  /**
   * Validates the provided lookup code's format.
   *
   * A lookup code is exactly 16 uppercase letters and digits (e.g., `K7QJ3FB9M2WZX0C4`). It addresses the records
   * of an identity under a `mode=private` domain.
   *
   * @param lookupCode {String} - Lookup code that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateLookupCode(lookupCode) {
    const reasons = [];

    if (!Helpers.isLookupCode(lookupCode)) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_lookup_code', reasons);
  }

  /**
   * Validates the provided device tag's format.
   *
   * A device tag is the `deviceTag` of a result: a 43-character base64url digest (e.g., `3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ`),
   * suffixed with `~` and a lookup code under a `mode=private` domain. After a delegated sign-in it is
   * `<grantTag>:<actorIdentifier>:<actorDeviceTag>`, and each of its two tags may carry such a suffix.
   *
   * @param deviceTag {String} - Device tag that should be validated.
   *
   * @returns {{valid: boolean, errors: Array<{code: string, reason: string, message: string}>}}
   */
  static validateDeviceTag(deviceTag) {
    const reasons = [];
    const parts = typeof deviceTag === 'string' && deviceTag.length <= DEVICE_TAG_MAX_LENGTH ? deviceTag.split(':') : [];

    if (
      !(parts.length === 1 && this.#isReportedTag(parts[0])) &&
      !(parts.length === 3 && this.#isReportedTag(parts[0]) && this.validateIdentifier(parts[1]).valid && this.#isReportedTag(parts[2]))
    ) {
      reasons.push('invalid');
    }

    return this.#expandResult('invalid_device_tag', reasons);
  }

  /**
   * Checks one tag component of a device tag: a 43-character base64url digest, optionally suffixed with `~` and a lookup code.
   *
   * @param component {string} - Tag component that should be checked.
   *
   * @returns {boolean} true when the component is a well-formed tag
   */
  static #isReportedTag(component) {
    const [tag, lookupCode, ...rest] = component.split('~');

    if (rest.length > 0 || tag.length !== 43 || (lookupCode !== undefined && !Helpers.isLookupCode(lookupCode))) {
      return false;
    }

    // The canonical base64url of a 32-byte digest has no data in the unused bits of its last character
    try {
      Helpers.base64UrlToUint8(tag);
    } catch {
      return false;
    }

    return true;
  }

  /**
   * Checks a name against the device-name grammar, shared by device names and group names.
   *
   * @param name {*} - Name that should be validated.
   *
   * @returns {Array<string>} The reasons found, empty when the name is valid.
   */
  static #nameErrors(name) {
    const reasons = [];

    if (typeof name !== 'string') {
      return ['invalid'];
    }

    if (name.length <= 0) {
      reasons.push('empty');
    }

    if (name.length > LIMITS.deviceNameBytesize || Helpers.byteSize(name) > LIMITS.deviceNameBytesize) {
      return ['too_long'];
    }

    // The name must not contain any whitespace characters and/or NULL
    if (name.match(/[\s\0]/g)) {
      reasons.push('invalid');
    }

    if (name !== name.toLowerCase()) {
      reasons.push('not_lowercase');
    }

    // Lowercase alphanumerics joined by single hyphens: the name must start and end on an alphanumeric
    // and carry no consecutive hyphens.
    if (!name.match(/^[a-z0-9]+(-[a-z0-9]+)*$/)) {
      reasons.push('invalid_characters');
    }

    return reasons;
  }
}
