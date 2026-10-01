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
import { Helpers } from './helpers.js';
import { LIMITS, WRAPPER } from './protocol.js';
import { Signature } from './signature.js';

/**
 * A multi-signature envelope, which is one or more `Triauth.Signature` segments joined and wrapped by the `|` character.
 *
 * @class
 * @memberof Triauth
 */
export class MultiSignature {

  /**
   * Concatenates individual signature envelopes into one multi-signature envelope.
   *
   * @param signatures {...string} - Individual `Triauth.Signature` envelopes, each wrapped in `|`.
   *
   * @returns {string} the multi-signature envelope carrying the given signatures, in the given order.
   */
  static generate(...signatures) {
    return WRAPPER + signatures.map((s) => s.slice(1,-1)).join(WRAPPER) + WRAPPER;
  }

  /**
   * Parses a multi-signature envelope into the individual `Triauth.Signature` segments it carries.
   *
   * @param rawData {string} - A multi-signature envelope: one or more signature segments wrapped in,
   *                           and delimited by, the `|` character.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   *
   * @throws {TriauthError} code 225 when the envelope is not a string, is not `|`-wrapped, exceeds
   *                        `LIMITS.signatureBytesize`, carries more than `LIMITS.maxMultiSignatures`
   *                        segments, or repeats a byte-identical segment.
   */
  constructor(rawData, config={}) {
    this.config = Helpers.mergeConfig(config);

    // Check the basic sanity and format of received arguments
    if (
      typeof rawData !== 'string' ||
      rawData.length <= 3 ||
      (rawData[0] !== WRAPPER || rawData[rawData.length - 1] !== WRAPPER) ||
      Helpers.byteSize(rawData) > LIMITS.signatureBytesize
    ) {
      throw new TriauthError(225, 'Invalid signature');
    }

    this.rawData = rawData;

    const segments = rawData.slice(1,-1).split(WRAPPER);

    const {maxMultiSignatures} = LIMITS;
    if (segments.length < 1 || segments.length > maxMultiSignatures) {
      throw new TriauthError(225, 'Invalid signature');
    }

    // Do not allow byte-identical duplicate segments
    if (new Set(segments).size !== segments.length) {
      throw new TriauthError(225, 'Invalid signature');
    }

    // Extract and parse signature segments
    this.signatures = segments.map( (sig) => new Signature(WRAPPER + sig + WRAPPER, config) );
  }

  /**
   * Verifies that the signature is valid for the given message.
   *
   * @param message {string}                      - Message, should be the same as originally signed.
   * @param [constraints={}] {object}             - Optional constraints that the signature must satisfy:
   * @param [constraints.type] {string}           - If given, passed through to each contributing `Signature.verify` for type matching.
   * @param [constraints.identifier] {string}     - If given, must match the identifier for which it was created.
   * @param [constraints.actor] {string}          - If given, passed through to each contributing `Signature.verify` for actor matching ('' = no actor).
   * @param [constraints.ver] {number}            - If given, passed through to each contributing `Signature.verify` for version matching.
   * @param [constraints.via] {string}            - If given, passed through to each contributing `Signature.verify` for client URL matching.
   * @param [constraints.notBefore] {number}      - If given, must be a timestamp after which the signature was created.
   * @param [constraints.notAfter] {number}       - If given, must be a timestamp before which the signature was created.
   * @param [constraints.minSignatures] {number}  - If given, the multi-signature envelope must contain at least this many signatures.
   * @param [constraints.maxSignatures] {number}  - If given, the multi-signature envelope must contain at most this many signatures.
   *
   * @returns {Promise<{type: 'multisig', valid: boolean, secure: (boolean|undefined), expires: (number|undefined), verifiedAt: (number|undefined), signatures: Array<object>}|false|null>}
   *          A promise that resolves to:
   *          - `false` upon failed verification,
   *          - `null` upon time-related constraint failure (so callers can distinguish "expired" from generic failure),
   *          - or an object with:
   *            `type` - always the literal `'multisig'`,
   *            `valid` - `true` when every contributing signature verified,
   *            `secure` - `true` only when every contributing signature's identity was DNSSEC-validated; `undefined` when there are no results to aggregate,
   *            `expires` - the earliest defined per-signature expiry (ms timestamp), or `undefined` if none of the contributing key groups had a TTL,
   *            `verifiedAt` - the latest (max) per-signature verification timestamp (ms) - when the whole envelope finished verifying; `undefined` when there are no results to aggregate,
   *            `signatures` - array of per-signature verification results (see `Triauth.Signature#verify` for each entry's shape).
   */
  async verify(message, constraints = {}) {
    const verificationResults = [];

    constraints = Object.assign({}, constraints);

    if (
      !Helpers.hasOnlyKnownProperties(constraints, [
        'minSignatures', 'maxSignatures', // enforced by this method
        'type', 'identifier', 'actor', 'ver', 'via', 'notBefore', 'notAfter' // enforced by Triauth.Signature.verify
      ], false)
    ) {
      this.config.logger?.error?.('Unrecognized constraint');
      return false;
    }

    // Fail if signature count constraints are provided in a non-numeric form
    if (
      (constraints.minSignatures != null && (typeof constraints.minSignatures !== 'number' || Number.isNaN(constraints.minSignatures))) ||
      (constraints.maxSignatures != null && (typeof constraints.maxSignatures !== 'number' || Number.isNaN(constraints.maxSignatures)))
    ) {
      this.config.logger?.error?.('Invalid minSignatures/maxSignatures constraint');
      return false;
    }

    if (constraints.minSignatures != null && this.signatures.length < constraints.minSignatures) {
      return false;
    }
    delete constraints.minSignatures;

    if (constraints.maxSignatures != null && this.signatures.length > constraints.maxSignatures) {
      return false;
    }
    delete constraints.maxSignatures;

    for (const signature of this.signatures) {
      const sigVerRes = await signature.verify(message, constraints);

      if (!sigVerRes || !sigVerRes.valid) {
        return sigVerRes === null ? null : false;
      }

      verificationResults.push(sigVerRes);
    }

    const valid = verificationResults.length > 0 && verificationResults.every((r) => r && r.valid);
    const secure = verificationResults.length > 0 ? verificationResults.every((r) => r && r.secure) : undefined;

    // Combine expiries by taking the earliest defined value. An `undefined` expires on any single
    // result means "no expiry constraint from this key" and should not poison the min.
    // When no result carries an expiry, the combined expires is undefined.
    const expiriesWithValues = verificationResults.map((r) => r && r.expires).filter((e) => typeof e === 'number');
    const expires = expiriesWithValues.length > 0 ? Math.min(...expiriesWithValues) : undefined;

    // Combine per-signature verification timestamps by taking the LATEST: the whole envelope is only
    // fully verified once its slowest signature (e.g., one whose identity DNS blocked) has confirmed.
    // Mirrors the expires filter above so a stray undefined cannot turn Math.max into NaN.
    const verifiedAtValues = verificationResults.map((r) => r && r.verifiedAt).filter((v) => typeof v === 'number');
    const verifiedAt = verifiedAtValues.length > 0 ? Math.max(...verifiedAtValues) : undefined;

    return {
      type: 'multisig',
      valid,
      secure,
      expires,
      verifiedAt,
      signatures: verificationResults
    }
  }

}
