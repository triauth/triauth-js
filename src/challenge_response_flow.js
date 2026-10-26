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
import { ResponseCipher } from './response_cipher.js';
import { RequestCipher } from './request_cipher.js';
import { AuthenticationEndpoint } from './authentication_endpoint.js';
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
   *  - **Stage 1** (when `identifier`+`callbackUrl` are given, `challenge`/`response` are not): builds a challenge
   *    that carries a fresh encryption key (`ek`), invokes `onChallenge` to let the caller mutate `challenge.data`,
   *    then returns `{challenge, redirectUrl}`. The returned `challenge` is `<challenge>.<decryptionKey>`.
   *  - **Stage 3** (when `challenge`+`response` are given): parses both, opens the sealed response with the
   *    decryption key of the stored challenge, sanity-checks them against optional `identifier`/`callbackUrl`
   *    constraints, then invokes `onResponse` for per-flow verification.
   *
   * @param type {string} - Flow type: `'auth'`, `'ping'`, `'attest'`, `'sign'`, or `'stamp'`.
   * @param [options={}] {object} - User-facing options. Stage 1 expects `{identifier, callbackUrl, ext?, sessionKey?}`
   *                                 plus the flow's own options (`sessionKey` is required for every flow except `'auth'`,
   *                                 where it is rejected). Stage 3 expects `{challenge, response, identifier?, callbackUrl?}`
   *                                 (the optional ones, if provided, are additionally checked against the values embedded
   *                                 in the challenge) and rejects every other option as unrecognized.
   * @param [callbacks] {{onChallenge: function, onResponse: function}} -
   *        `onChallenge({challenge})` runs after the `Triauth.Challenge` is built (stage 1), giving the caller
   *        a chance to populate `challenge.data` (e.g., `msg`, `attest`, `attachments`).
   *        `onResponse({challenge, response, sessionKey})` performs verification (stage 3); must return the per-flow
   *        success object, `null` for expired-style failures, or `false` for generic verification failures.
   *        `sessionKey` is the session key from opening the sealed response (see `ResponseCipher.open`).
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings.
   * @param [flowOptions=[]] {Array<string>} - Names of the flow's own stage-1 options (e.g., `message`), which `onChallenge`
   *                                           reads from `options` and which stage 3 rejects like any unrecognized option.
   *
   * @returns {Promise<{challenge: string, redirectUrl: string}|{error: {code: string, reason?: string, message: string}}|*>}
   *          A promise resolving to `{challenge, redirectUrl}` (stage 1), whatever `onResponse` returned
   *          (stage 3 success), or `{error:{code,message}}` if any error was caught. When
   *          `config.requireSecure` is set, a stage-3 result that is not DNSSEC-secure is rejected with
   *          `{error:{code:'dnssec_required',…}}` instead of being returned (see `assertSecure`).
   */
  static async perform(type, options={}, callbacks={onChallenge:null, onResponse:null}, config={}, flowOptions=[]) {
    config.logger?.info?.('Processing Triauth.' + type);
    const ts = Helpers.now();

    try {

      // Ensure only recognized options are present to help avoid misspellings. Stage 3 reads the challenge and the
      // response, and cross-checks an identifier and a callbackUrl against the challenge. Every other option shapes
      // the challenge at stage 1: `ext`, the flow's own options, and `sessionKey` for the flows that follow a sign-in
      // (ping/attest/sign/stamp), not for auth.
      const stage3 = options !== null && typeof options === 'object' && options.challenge != null && options.response != null;
      const allowedOptions = stage3
        ? ['challenge', 'response', 'identifier', 'callbackUrl']
        : ['identifier', 'callbackUrl', 'challenge', 'response', 'ext', ...flowOptions, ...(type !== 'auth' ? ['sessionKey'] : [])];

      if (!Helpers.hasOnlyKnownProperties(options, allowedOptions)) {
        throw new TriauthError({code: 'invalid_arguments', message: 'Unrecognized function argument'});
      }

      // Reject config overrides carrying unknown keys (typos that would otherwise be silently ignored,
      // sometimes weakening security - e.g. a misspelled `requireSecure`). We validate the MERGED config,
      // so a stray key is caught whether it came from this call's override or a global Triauth.config
      if (!Helpers.hasOnlyKnownProperties(config, KNOWN_CONFIG_KEYS)) {
        throw new TriauthError({code: 'invalid_config', message: 'Unrecognized configuration key'});
      }

      // Read supported options
      const identifier = options.identifier;
      const callbackUrl = options.callbackUrl;
      const challenge = options.challenge;
      const response = options.response;
      const ext = options.ext;
      const sessionKey = options.sessionKey;

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
          (sessionKey != null && Validator.validateSessionKey(sessionKey).errors[0])
        );

        if (validationError) {
          throw new TriauthError(validationError);
        }

        // Every flow that follows a sign-in (all but `auth`) requires the session key of that sign-in
        if (type !== 'auth' && sessionKey == null) {
          throw new TriauthError({code: 'invalid_session_key', reason: 'invalid', message: 'Invalid session key'});
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

        // The authenticator seals the response to `ek`. The decryption key stays with the stored challenge.
        const {encryptionKey, decryptionKey} = await ResponseCipher.generateKeyPair();
        challengeObj.data.ek = encryptionKey;

        await callbacks.onChallenge({challenge: challengeObj});
        const challengeString = challengeObj.toString();

        // Fail early if the just-built challenge is not itself a valid challenge
        const challengeError = Validator.validateChallenge(challengeString).errors[0];
        if (challengeError) {
          throw new TriauthError(challengeError);
        }

        // A delegated session key is `<domain>:<key>`, and its session is at the authenticator of that domain
        const [sessionKeyDomain, sessionKeySecret] = sessionKey?.includes(':') ? sessionKey.split(':') : ['', sessionKey];
        const authenticationEndpoint = sessionKeyDomain ? new AuthenticationEndpoint(sessionKeyDomain, config) : identity.authenticationEndpoint;

        // Check if authentication endpoint has been configured for the domain name
        if (!(await authenticationEndpoint.resolve())) {
          throw new TriauthError({code: 'domain_not_configured', message: 'Domain is not configured for triauth'});
        }

        // Enforce config.requireSecure if set
        ChallengeResponseFlow.assertSecure(authenticationEndpoint.secure, config);

        // A request that follows a sign-in travels sealed under the session key, with `skid` to find the key.
        // A sign-in has no session key yet, so its challenge travels readable.
        const redirectUrlParams = sessionKey
          ? {skid: await RequestCipher.skid(sessionKeySecret), request: await RequestCipher.seal(sessionKeySecret, challengeString)}
          : {challenge: challengeString};

        const redirectUrl = authenticationEndpoint.urlFor(type, redirectUrlParams);
        const redirectUrlString = redirectUrl.toString();

        // Return the challenge that the client should remember (with the key that opens the response), and a redirectUrl
        // to which the user's web browser should be redirected.
        return Helpers.clone({
          challenge: challengeString + '.' + decryptionKey,
          redirectUrl: redirectUrlString
        });

      // Stage 3 - both challenge and response are provided, and we need to verify them against each other and return the result.
      } else if (
        challenge != null &&
        response != null
      ) {

        if (response === 'false') {
          throw new TriauthError({code: 'request_denied', message: 'Request has been denied'});
        }

        // The stored challenge is `<challenge>.<decryptionKey>`, and the response is sealed to the challenge's `ek`
        const [challengeString, decryptionKey, rest] = typeof challenge === 'string' ? challenge.split('.') : [];

        const validationError = (
          Validator.validateChallenge(challengeString).errors[0] ||
          ((rest !== undefined || !Helpers.isBase64UrlString(decryptionKey) || decryptionKey.length !== 43) && {code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge'}) ||
          Validator.validateSealedResponse(response).errors[0] ||
          (identifier != null && Validator.validateIdentifier(identifier).errors[0]) ||
          (callbackUrl != null && Validator.validateCallbackUrl(callbackUrl).errors[0])
        );

        if (validationError) {
          throw new TriauthError(validationError);
        }

        config.logger?.info?.('Verifying response with constraints', {type, identifier, callbackUrl});

        // Parse the received response (string) into the Triauth.Response object.
        let challengeObj, responseObj;

        try {
          challengeObj = Challenge.fromString(challengeString, config);
        } catch (err) {
          throw new TriauthError({code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge'}, {cause:err});
        }

        // Every challenge carries the encryption key that its response is sealed to
        const encryptionKey = challengeObj.data.ek;
        if (!Helpers.isBase64UrlString(encryptionKey) || encryptionKey.length !== 87) {
          throw new TriauthError({code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge'});
        }

        let envelope, sessionKey;

        try {
          ({response: envelope, sessionKey} = await ResponseCipher.open(encryptionKey, decryptionKey, response));
        } catch (err) {
          throw new TriauthError({code: 'invalid_response', reason: 'invalid', message: 'Invalid response'}, {cause:err});
        }

        const responseError = Validator.validateResponse(envelope).errors[0];
        if (responseError) {
          throw new TriauthError(responseError);
        }

        responseObj = new Response(envelope, config);

        // Make sure the challenge's type matches the flow type, and (if again passed in options)
        // that the identifier and/or callbackUrl matches the one embedded in the challenge.
        if (
          challengeObj.data.type !== type ||
          (identifier != null && challengeObj.identity.identifier !== identifier) ||
          (callbackUrl != null && challengeObj.data.cburl !== callbackUrl)
        ) {
          throw new TriauthError({code: 'verification_failed', message: 'Your identity could not be verified'});
        }

        const retval = await callbacks.onResponse({challenge:challengeObj, response:responseObj, sessionKey});

        if (retval) {
          // Enforce config.requireSecure if set
          ChallengeResponseFlow.assertSecure(retval.secure ?? retval.verificationResult?.secure, config);
          return retval;

        } else if (retval === null) {
          throw new TriauthError({code: 'request_expired', message: 'Authentication request has expired, please try again'});

        } else {
          throw new TriauthError({code: 'verification_failed', message: 'Your identity could not be verified'});

        }

      // Fail when the given function arguments do not match to any of stages.
      } else {
        throw new TriauthError({code: 'invalid_arguments', message: 'Invalid or missing function arguments - expected either {identifier,callbackUrl,ext,...} or {challenge,response,identifier?,callbackUrl?}'});

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

    // For time constraints verification failure, signal "expired" (caller surfaces request_expired).
    } else if (verifyResult === null) {
      config.logger?.info?.('Verification failed - request expired', {identifier:challenge.identity.identifier, iat:parseInt(challenge.data.iat, 10)});
      return null;

    // For other falsy signature verification results, signal a generic failure (caller surfaces verification_failed).
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
   * @throws {TriauthError} `dnssec_required` when `config.requireSecure` is set and `secure` is not strictly `true`.
   */
  static assertSecure(secure, config) {
    if (config.requireSecure && secure !== true) {
      throw new TriauthError({code: 'dnssec_required', message: 'Your domain does not support DNSSEC, which is required to continue.'});
    }
  }

}
