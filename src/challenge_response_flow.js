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
import { Validator } from './validator.js';
import { Identity } from './identity.js';
import { Challenge } from './challenge.js';
import { Response } from './response.js';
import { KNOWN_CONFIG_KEYS } from './config.js';

/**
 * Internal helper that implements the shared 3-step challenge-response flow used by
 * some of the top-level API methods (e.g., `authenticate`).
 *
 * Each API method delegates to `perform()` with a flow `type` and a pair of callbacks
 * (`onChallenge`, `onResponse`) carrying the per-flow logic.
 *
 * @class
 * @memberof Triauth
 */
export class ChallengeResponseFlow {

  /**
   * Executes one stage of the challenge-response flow:
   *  - **Stage 1** (when `identifier`+`callbackUrl` are given, `challenge`/`response` are not): builds a challenge,
   *    invokes `onChallenge` to let the caller mutate `challenge.data`, then returns `{challenge, redirectUrl}`.
   *  - **Stage 3** (when `challenge`+`response` are given): parses both, sanity-checks them against optional
   *    `identifier`/`callbackUrl` constraints, then invokes `onResponse` for per-flow verification.
   *
   * @param type {string} - Flow type: `'auth'`, `'ping'`, `'attest'`, `'sign'`, or `'stamp'`.
   * @param [options={}] {object} - User-facing options. Stage 1 expects `{identifier, callbackUrl, ext?, token?}`
   *                                 (`token` is required for every flow except `'auth'`, where it is rejected). Stage 3 expects
   *                                 `{challenge, response, identifier?, callbackUrl?}` (the optional ones, if
   *                                 provided, are additionally checked against the values embedded in the challenge).
   * @param [callbacks] {{onChallenge: function, onResponse: function}} -
   *        `onChallenge({challenge})` runs after the `Triauth.Challenge` is built (stage 1), giving the caller
   *        a chance to populate `challenge.data` (e.g., `msg`, `attest`, `attachments`).
   *        `onResponse({challenge, response})` performs verification (stage 3); must return the per-flow
   *        success object, `null` for expired-style failures, or `false` for generic verification failures.
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings.
   *
   * @returns {Promise<{challenge: string, redirectUrl: string}|{error: {code: number, message: string}}|*>}
   *          A promise resolving to `{challenge, redirectUrl}` (stage 1), whatever `onResponse` returned
   *          (stage 3 success), or `{error:{code,message}}` if any error was caught. When
   *          `config.requireSecure` is set, a stage-3 result that is not DNSSEC-secure is rejected with
   *          `{error:{code:404,…}}` instead of being returned (see `assertSecure`).
   */
  static async perform(type, options={}, callbacks={onChallenge:null, onResponse:null}, config={}) {
    config.logger?.info?.('Processing Triauth.' + type);
    const ts = Helpers.now();

    try {

      // Ensure only recognized options are present to help avoid misspellings.
      // `token` is only meaningful for token-bearing flows (ping/attest/sign/stamp), not for auth.
      const allowedOptions = ['identifier', 'callbackUrl', 'challenge', 'response', 'ext'];
      if (type !== 'auth') {
        allowedOptions.push('token');
      }

      if (!Helpers.hasOnlyKnownProperties(options, allowedOptions)) {
        throw new TriauthError(102, 'Unrecognized function argument');
      }

      // Reject config overrides carrying unknown keys (typos that would otherwise be silently ignored,
      // sometimes weakening security - e.g. a misspelled `requireSecure`). We validate the MERGED config,
      // so a stray key is caught whether it came from this call's override or a global Triauth.config
      if (!Helpers.hasOnlyKnownProperties(config, KNOWN_CONFIG_KEYS)) {
        throw new TriauthError(103, 'Unrecognized configuration key');
      }

      // Read supported options
      const identifier = options.identifier;
      const callbackUrl = options.callbackUrl;
      const challenge = options.challenge;
      const response = options.response;
      const ext = options.ext;
      const token = options.token;

      // Stage 1 - identifier, callbackUrl, and ext (optional) are provided, and we need to build and return a challenge and redirectUrl
      if (
        identifier != null &&
        callbackUrl != null &&
        (challenge == null && response == null)
      ) {
        const validationError = (
          Validator.validateIdentifier(identifier).errors[0] ||
          Validator.validateCallbackUrl(callbackUrl).errors[0] ||
          (ext != null && Validator.validateExt(ext).errors[0]) ||
          (token != null && Validator.validateToken(token).errors[0])
        );

        if (validationError) {
          throw new TriauthError(validationError.code, validationError.message);
        }

        // Token-gated flows (every flow except `auth`) require a token at issue
        if (type !== 'auth' && token == null) {
          throw new TriauthError(226, 'Invalid token');
        }

        config.logger?.info?.('Request parameters:', {identifier, callbackUrl, ext});

        const identity = new Identity(identifier, {}, config);

        // Prepare options for the authentication request
        const challengeOptions = {};

        challengeOptions.cburl = callbackUrl;

        if (ext != null) {
          challengeOptions.ext = ext;
        }

        // Build the authentication request for the given identity with the given options - `callbackUrl` and `ext`.
        const challengeObj = Challenge.build(type, identity, challengeOptions, config);
        await callbacks.onChallenge({challenge: challengeObj});
        const challengeString = challengeObj.toString();

        // Fail early if the just-built challenge is not itself a valid challenge
        const challengeError = Validator.validateChallenge(challengeString).errors[0];
        if (challengeError) {
          throw new TriauthError(challengeError.code, challengeError.message);
        }

        const authenticationEndpoint = identity.authenticationEndpoint;

        // Check if authentication endpoint has been configured for the given identifier's domain name
        if (!(await authenticationEndpoint.resolve())) {
          throw new TriauthError(301, 'Domain is not configured for triauth');
        }

        // Enforce config.requireSecure if set
        ChallengeResponseFlow.assertSecure(authenticationEndpoint.secure, config);

        const redirectUrlParams = {challenge:challengeString};

        // Include the pre-validated token in the request parameters if present
        if (token) {
          const [tokenPublicPart] = token.split(':');

          const challengeHMAC = Helpers.arrayBufferToBase64Url(
            await Helpers.hmacSha256(Helpers.stringToUtf8Bytes(token), Helpers.base64UrlToUint8(challengeString))
          );

          redirectUrlParams.token = tokenPublicPart + ':' + challengeHMAC;
        }

        const redirectUrl = authenticationEndpoint.urlFor(type, redirectUrlParams);
        const redirectUrlString = redirectUrl.toString();

        // Return the challenge that the client should remember, and a redirectUrl to which the user's web browser should be redirected.
        return Helpers.clone({
          challenge: challengeString,
          redirectUrl: redirectUrlString
        });

      // Stage 3 - both challenge and response are provided, and we need to verify them against each other and return the result.
      } else if (
        challenge != null &&
        response != null
      ) {

        if (response === 'false') {
          throw new TriauthError(403, 'Request has been denied');
        }

        const validationError = (
          Validator.validateChallenge(challenge).errors[0] ||
          Validator.validateResponse(response).errors[0] ||
          (identifier != null && Validator.validateIdentifier(identifier).errors[0]) ||
          (callbackUrl != null && Validator.validateCallbackUrl(callbackUrl).errors[0])
        );

        if (validationError) {
          throw new TriauthError(validationError.code, validationError.message);
        }

        config.logger?.info?.('Verifying response with constraints', {type, identifier, callbackUrl});

        // Parse the received response (string) into the Triauth.Response object.
        let challengeObj, responseObj;

        try {
          challengeObj = Challenge.fromString(options.challenge, config);
        } catch (err) {
          throw new TriauthError(223, 'Invalid challenge', {cause:err});
        }

        responseObj = new Response(response, config);

        // Make sure the challenge's type matches the flow type, and (if again passed in options)
        // that the identifier and/or callbackUrl matches the one embedded in the challenge.
        if (
          challengeObj.data.type !== type ||
          (identifier != null && challengeObj.identity.identifier !== identifier) ||
          (callbackUrl != null && challengeObj.data.cburl !== callbackUrl)
        ) {
          throw new TriauthError(401, 'Your identity could not be verified');
        }

        const retval = await callbacks.onResponse({challenge:challengeObj, response:responseObj});

        if (retval) {
          // Enforce config.requireSecure if set
          ChallengeResponseFlow.assertSecure(retval.secure ?? retval.verificationResult?.secure, config);
          return retval;

        } else if (retval === null) {
          throw new TriauthError(402, 'Authentication request has expired, please try again');

        } else {
          throw new TriauthError(401, 'Your identity could not be verified');

        }

      // Fail when the given function arguments do not match to any of stages.
      } else {
        throw new TriauthError(101, 'Invalid or missing function arguments - expected either {identifier,callbackUrl,ext,...} or {challenge,response,identifier?,callbackUrl?}');

      }

    } catch (err) {
      return TriauthError.process(err, config);


    } finally {
      config.logger?.info?.('Completed in ' + Math.round(Helpers.now() - ts) + 'ms');

    }

  }

  /**
   * Verifies a single-signature challenge response and enforces the success invariant shared by the
   * `auth`, `ping`, `sign`, and `stamp` flows: the envelope must carry exactly one signature, that
   * signature must be valid and backed by at least one key, its identifier must match the one bound
   * in the challenge, and the challenge's `cburl` must be a valid callback URL whose base URL equals
   * the signature's `via`. (The multi-signature `attest` flow has a different shape - 1 user + N
   * attester signatures - and intentionally does NOT use this helper.)
   *
   * @param type {string} - flow type ('auth'|'ping'|'sign'|'stamp'), passed through to Response.verify.
   * @param signedPayload {string} - the exact bytes the signature is verified against (the serialized
   *        challenge for auth/ping; the human-readable `msg` for sign/stamp).
   * @param challenge {Challenge} - the re-hydrated challenge.
   * @param response {Response} - the parsed response envelope.
   * @param timeout {number} - the flow's freshness window (e.g., `config.authTimeout`), subtracted from now.
   * @param config {object} - effective config (with an already-spawned logger).
   *
   * @returns {Promise<{sig: object, verifyResult: object}|null|false>} On success, the verified first
   *          signature plus the full multi-signature result (callers read `secure`/`expires` from the
   *          latter); `null` on a time/expiry failure; `false` on any other verification failure.
   */
  static async verifyChallengeResponse(type, signedPayload, challenge, response, timeout, config) {
    const verifyResult = await response.verify(type, signedPayload, challenge, {
      identifier: challenge.identity.identifier,
      notBefore: Date.now() - (timeout || 0),
      notAfter: Date.now(),
      minSignatures: 1,
      maxSignatures: 1
    });

    const sig = verifyResult && verifyResult.signatures[0];

    if (
      verifyResult && verifyResult.valid && verifyResult.signatures.length === 1 &&
      sig && sig.valid && sig.keys.length > 0 &&
      sig.identifier === challenge.identity.identifier &&
      Validator.validateCallbackUrl(challenge.data.cburl).valid && Helpers.getBaseUrl(challenge.data.cburl) === sig.via
    ) {
      return {sig, verifyResult};

    // For time constraints verification failure, signal "expired" (caller surfaces 402).
    } else if (verifyResult === null) {
      config.logger?.info?.('Verification failed - request expired', {identifier:challenge.identity.identifier, iat:parseInt(challenge.data.iat, 10)});
      return null;

    // For other falsy signature verification results, signal a generic failure (caller surfaces 401).
    } else {
      config.logger?.info?.('Verification failed', {identifier:challenge.identity.identifier});
      return false;

    }
  }

  /**
   * Enforces the optional `config.requireSecure` policy: when the caller has opted in, an
   * otherwise-valid result whose DNS chain was not reported DNSSEC-validated (`secure !== true`)
   * is rejected.
   *
   * @param secure {boolean|undefined} - the aggregate DNSSEC-validation flag of the result.
   * @param config {object} - effective config; `requireSecure` (default false) toggles enforcement.
   * @throws {TriauthError} 404 when `config.requireSecure` is set and `secure` is not strictly `true`.
   */
  static assertSecure(secure, config) {
    if (config.requireSecure && secure !== true) {
      throw new TriauthError(404, 'Your domain does not support DNSSEC, which is required to continue.');
    }
  }

}
