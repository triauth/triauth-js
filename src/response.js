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
import { MultiSignature } from './multi_signature.js';

/**
 * Represents an authentication response that is sent from Triauth Authenticator back to the client application,
 * typically in a response to the previously sent Triauth.Challenge.
 *
 * @class
 * @memberof Triauth
 */
export class Response {

  /**
   * Constructs a new instance of Response around a response received from the Triauth Authenticator.
   *
   * @param responseString {string} - The received response - a triauth multi-signature envelope. It is
   *                                  parsed and validated by `verify`, not by this constructor.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   */
  constructor(responseString, config={}) {
    this.config = Helpers.mergeConfig(config);
    this.responseString = responseString; // responseString is a triauth signature (string)
  }

  /**
   * Verifies that the signatures provided as a part of this authentication response are valid for the given challenge.
   *
   * @param type {string} - Expected type of the response, one of 'attest', 'auth', 'ping', 'sign', 'stamp'.
   * @param signedPayload {string} - The exact string that the cryptographic signature is verified against.
   *                                For 'auth' and 'ping' this is the serialized challenge string; for 'sign'
   *                                and 'stamp' it is the human-readable `msg`; for 'attest' it is the
   *                                base64url-encoded SHA-256 digest of the challenge string. Callers must
   *                                pass it explicitly — there is no implicit default.
   * @param challenge {import('./challenge.js').Challenge} - The Challenge originally built and sent to the Triauth Authenticator.
   *                                Used only for constraint checks (identifier match, `iat` bounds); it is
   *                                not the cryptographic input to verification.
   * @param [constraints={}] {object}             - Optional constraints that the response must satisfy:
   * @param [constraints.identifier] {string}     - If given, must match the identifier embedded in the challenge.
   * @param [constraints.notBefore] {number}      - If given, the challenge `iat` must be >= this timestamp.
   * @param [constraints.notAfter] {number}       - If given, the challenge `iat` must be <= this timestamp.
   * @param [constraints.minSignatures] {number}  - If given, the multi-signature envelope must contain at least this many signatures.
   * @param [constraints.maxSignatures] {number}  - If given, the multi-signature envelope must contain at most this many signatures.
   *
   * @returns {Promise<
   *     {type: string, valid: boolean, secure: boolean, expires: (number|undefined), verifiedAt: (number|undefined), signatures: Array<object>}
   *   | null
   *   | false
   * >}
   *          A promise that resolves to:
   *          - `null` when a time-related constraint fails (signal to surface as "expired" to the user),
   *          - `false` when any other verification fails,
   *          - or an object with: `valid:true`, the `type` of the envelope ('multisig'), a `secure` flag
   *            (true only when DNSSEC was validated for every contributing signature's identity),
   *            an `expires` timestamp (the earliest defined per-signature expiry, or undefined if none of
   *            the contributing key groups had a TTL), a `verifiedAt` timestamp (the latest per-signature
   *            verification time - when the whole envelope finished verifying), and a `signatures` array of
   *            per-signature results (each carrying its own `identifier`, `identityDomain`, `lookupCode`, `actor`, `actorIdentityDomain`, `actorLookupCode`, `publicProfile`,
   *            `groups`, `keys`, `deviceName`, `deviceTag`, `signedAt`, `verifiedAt`, `signedMetadata`, `unsignedMetadata`).
   */
  async verify(type, signedPayload, challenge, constraints = {}) {


    ////
    // Constraints - Verify constraints in relation to the restored authentication request
    //
    // The challenge `iat` was minted by the integrator's own infrastructure, but not necessarily
    // by this host - under load balancing, stage 1 and stage 3 may land on different servers with
    // imperfectly synchronized clocks. The `iat` bounds are therefore widened by the (small)
    // `maximalAllowedServerClockDrift`, while signature timestamps minted on the end-user's device
    // get the (larger) `maximalAllowedClientClockDrift` below.

    if (!Helpers.hasOnlyKnownProperties(constraints, ['identifier', 'notBefore', 'notAfter', 'minSignatures', 'maxSignatures'])) {
      this.config.logger?.error?.('Unrecognized constraint');
      return false;
    }

    if (
      constraints.identifier != null &&
      challenge.identity.identifier !== constraints.identifier
    ) {
      this.config.logger?.debug?.('constraints.identifier not satisfied');
      return false;
    }

    // Fail closed if time bounds are provided in a non-numeric form rather than silently
    // coercing to NaN (which would compare as false and bypass the window check).
    if (
      (constraints.notBefore != null && (typeof constraints.notBefore !== 'number' || Number.isNaN(constraints.notBefore))) ||
      (constraints.notAfter != null && (typeof constraints.notAfter !== 'number' || Number.isNaN(constraints.notAfter)))
    ) {
      this.config.logger?.error?.('Invalid notBefore/notAfter constraint');
      return false;
    }

    if (
      constraints.notBefore != null &&
      (typeof challenge.data.iat !== 'number' || challenge.data.iat < constraints.notBefore - this.config.maximalAllowedServerClockDrift)
    ) {
      this.config.logger?.debug?.('constraints.notBefore not satisfied');
      return null;
    }

    if (
      constraints.notAfter != null &&
      (typeof challenge.data.iat !== 'number' || challenge.data.iat > constraints.notAfter + this.config.maximalAllowedServerClockDrift)
    ) {
      this.config.logger?.debug?.('constraints.notAfter not satisfied');
      return null;
    }

    ////
    // Signature - Verify the triauth signature passed in response

    const signature = new MultiSignature(this.responseString, this.config);

    const retval = await signature.verify(signedPayload, {
      type,
      identifier: constraints.identifier,
      notBefore: constraints.notBefore != null ? constraints.notBefore - this.config.maximalAllowedClientClockDrift : undefined,
      notAfter: constraints.notAfter != null ? constraints.notAfter + this.config.maximalAllowedClientClockDrift : undefined,
      minSignatures: constraints.minSignatures,
      maxSignatures: constraints.maxSignatures
    });

    if (!retval || !retval.valid) {
      this.config.logger?.debug?.('Triauth.Response.verify failed');
      return retval === null ? null : false;
    }

    this.config.logger?.debug?.('Triauth.Response.verify successful', {retval});

    return retval;
  }

}
