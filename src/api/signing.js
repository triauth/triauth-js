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
 * Methods related to signing and signature verification that are a part of the official triauth-js API.
 *
 * @namespace Signing
 * @memberof Triauth.Api
 */

import { KNOWN_CONFIG_KEYS } from '../config.js';
import { TriauthError } from '../error.js';
import { Helpers } from '../helpers.js';
import { Validator } from '../validator.js';
import { ChallengeResponseFlow } from '../challenge_response_flow.js';
import { MultiSignature } from '../multi_signature.js';

/**
 * Shared implementation for `Triauth.sign` and `Triauth.stamp`.
 * Embeds `message` (and, for `sign`, optional `attachments`) into the challenge,
 * then verifies the response is a single fresh signature over the same `message`
 * with matching attachments. Attachments are rejected for `stamp`.
 * Freshness is bounded by `config.signTimeout` or `config.stampTimeout`.
 *
 * @private
 * @param type {'sign'|'stamp'}
 * @param [options={}] {object} - same shape as the corresponding public `sign`/`stamp` method
 * @param [config={}] {object} - optional overrides for the global `Triauth.config` settings
 * @returns {Promise<object>} same return shape as the corresponding public method
 */
const _perform = async(type, options = {}, config = {}) => {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  options = Object.assign({}, options);

  const messageOption = options.message;
  delete options.message;

  const attachmentsProvided = 'attachments' in options;
  const attachmentsOption = options.attachments;
  delete options.attachments;

  const validateMessage = (message) => {
    const validationError = Validator.validateMessage(message).errors[0];

    if (validationError) {
      throw new TriauthError(validationError.code, validationError.message);
    }
  }

  const validateAttachments = (attachments, requireSourceUrl = true) => {
    const validationError = Validator.validateAttachments(attachments, requireSourceUrl).errors[0];

    if (validationError) {
      throw new TriauthError(validationError.code, validationError.message);
    }
  }

  const onChallenge = async ({challenge}) => {
    validateMessage(messageOption);
    challenge.data.msg = messageOption;

    if (type === 'sign') {
      validateAttachments(attachmentsOption ?? []);
      challenge.data.attachments = attachmentsOption ?? [];

    } else if (attachmentsProvided) {
      throw new TriauthError(102, 'Attachments option may only be used with Triauth.sign function');
    }
  };

  const onResponse = async ({challenge, response}) => {
    const message = challenge.data.msg;
    validateMessage(message);

    const challengeAttachments = challenge.data.attachments;

    if (type === 'sign') {
      validateAttachments(challengeAttachments);

    } else if ('attachments' in challenge.data) {
      throw new TriauthError(102, 'Attachments option may only be used with Triauth.sign function');

    }

    // Sign/stamp signatures cover the `msg` (plus the identity header and `ts`), but NOT the
    // challenge nonce/iat/cburl. This makes stamps portable across verifiers (within the `ts` window).
    const result = await ChallengeResponseFlow.verifyChallengeResponse(type, message, challenge, response, (type === 'sign' ? config.signTimeout : config.stampTimeout), config);

    // Propagate the failure signals unchanged: null -> 402 (expired), false -> 401 (invalid).
    if (!result) {
      return result;
    }

    const {sig, verifyResult} = result;

    const responseAttachments = (type === 'sign' ? (sig.signedMetadata.attachments ?? []) : sig.signedMetadata.attachments);

    if (type === 'sign') {
      // `sourceUrl` is optional on the signed response - the proof binds only name+sha256, and the
      // authenticator should not embed fetch URLs (which may carry credentials) in a portable signature.
      validateAttachments(responseAttachments, false);

    } else if ('attachments' in sig.signedMetadata) {
      config.logger?.info?.('Verification failed - stamp response signed-metadata carries attachments', {identifier:sig.identifier});
      return false;

    }

    if (type === 'sign') {
      // Attachments are matched by name+sha256. `sourceUrl` is optional but if present must match too.
      const attachmentsMatch = (ca, ra) => (
        ca.name === ra.name &&
        ca.sha256 && ca.sha256 === ra.sha256 &&
        (ra.sourceUrl === undefined || ra.sourceUrl === ca.sourceUrl)
      );

      const attachmentsVerifyResult = (
        challengeAttachments.length === responseAttachments.length &&
        challengeAttachments.every( (ca) => responseAttachments.find( (ra) => attachmentsMatch(ca, ra) ) ) &&
        responseAttachments.every( (ra) => challengeAttachments.find( (ca) => attachmentsMatch(ca, ra) ) )
      )

      if (!attachmentsVerifyResult) {
        config.logger?.info?.('Verification failed - not all attachments have been signed', {identifier:sig.identifier});
        return false;
      }
    }

    config.logger?.info?.('Verification successful', {identifier:sig.identifier, deviceTag:sig.deviceTag});

    const retval = {};
    const verb = type + 'ed';
    retval[verb] = true;

    Object.assign(retval, {
      result: response.responseString,
      issuedAt: challenge.data.iat,
      signedAt: sig.signedAt,
      verifiedAt: verifyResult.verifiedAt,
      verificationResult: verifyResult.signatures[0]
    });

    return Helpers.clone(retval);
  };

  return ChallengeResponseFlow.perform(type, options, {onChallenge, onResponse}, config);
};

/**
 * The `sign` method may be used to obtain an interactive signature of a given `message` and optional `attachments` from the user with a given `identifier`.
 * Interactive signatures require interaction from the user, like reviewing the message and clicking on the 'Sign' button in the Triauth Authenticator.
 * Signatures generated by the `sign` function may be later verified by any party using the `Triauth.verify` method, and may act as an independent proof that e.g.,
 * user has accepted certain terms or documents.
 *
 * > [!WARNING]
 * > A `sign` result is a transferable proof, not a single-use act. The cryptographic signature covers
 * > the `message` (and any `attachments`) together with the signature's own `type`, `identifier`, `via`,
 * > and timestamp — but **not** the challenge nonce, which is never bound to the signature and is not
 * > re-checked during verification. A `sign` response therefore re-verifies against any freshly minted
 * > `sign` challenge for the same `(identifier, message, callbackUrl-base)` while its timestamp is within
 * > `config.signTimeout` (30 minutes by default, widened by `config.maximalAllowedClientClockDrift`), and
 * > the raw `result` is independently verifiable via `Triauth.verify` until the signer's DNS keys rotate.
 * > Relying parties that need single-use / replay protection must embed a fresh, verifier-chosen nonce
 * > inside the `message` itself and reject reused nonces.
 *
 * > [!NOTE]
 * > **To use this function you must request and obtain a special `signToken`**<br/>
 * > To do so, provide the `ext:{signToken:true}` parameter to the `Triauth.authenticate` function during the initial call (i.e., when building the challenge),
 * > and, given that the user agrees and/or authenticator supports it, in the authentication result you will receive `ext.signToken` property (string).
 * > You should keep the `signToken` value private, and pass it as a `token` parameter in the initial call to the `sign` method.
 * > The token is issued by the authenticator on the device that signed in, and only that device honors it.
 * > A user with several devices holds a different token on each.
 * >
 * > Also, the `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
 * > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
 * > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
 *
 * The signing is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
 *
 * **1. Request**
 *
 * At first, you need to call the `Triauth.sign` method with the `identifier` option set to the user provided personal identifier (lowercase string),
 * a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
 * a `message` (string) option set to a human-readable text message to be signed,
 * an optional `attachments` (array) option listing additional file attachments to be covered by the signature,
 * a `token` (string) option set to the `signToken` previously obtained via `ext.signToken` from a `Triauth.authenticate` call,
 * and an optional `ext` option (object) listing the [protocol extensions](#protocol-extensions) that you wish to use.
 *
 * > [!NOTE]
 * > The `message` may consist of letters and digits from any language, space, and a fixed set of punctuation, and is limited to 2 KB.
 * > Emojis, newlines, tabs, and other whitespace or control characters are not allowed - the same rule as for `Triauth.stamp`.
 *
 * The `attachments` option, if present, should be an array (of at most 10 entries) with information on additional file attachments that need to be downloaded and covered by the signature.
 * Each entry in the `attachments` array should be in the form of `{name, sourceUrl, sha256}`, where `name` is a unique attachment's file name, `sourceUrl` is the URL from which the attachment can be downloaded, and `sha256` is a SHA256 hexdigest of the attachment file content.
 *
 * > [!TIP]
 * > The server from which attachment is served must respond with `Access-Control-Allow-Origin: *` HTTP header to allow Triauth Authenticator to download it.
 * > Additionally, only selected file formats and extensions are supported (`.txt`, `.pdf`, `.json`, `.xml`, `.png`, `.doc`, `.xls`, and a few others).
 * > For file formats other than `txt` and `pdf`, the file name must end with the appropriate extension (e.g., `.doc`).
 *
 * > [!TIP]
 * > You can get a SHA256 hexdigest of a content of a given `sourceUrl` with the following snippet:<br/>
 * > ```javascript
 * > await fetch(sourceUrl).then(r => r.arrayBuffer()).then(b => crypto.subtle.digest('SHA-256', b)).then(h => Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join(''));
 * > ```
 *
 *
 * In return, you will receive an object with the `challenge` (string) and `redirectUrl` (string).
 * You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let result = await Triauth.sign({identifier, callbackUrl, message, attachments, token, ext});
 * // returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
 * // returns {error} on error
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.sign(
 *   {
 *     identifier: 'john@triauthdemo.org',
 *     callbackUrl: 'https://example.com/triauth-callback',
 *     message: 'To continue, please read and accept the attached License',
 *     attachments: [
 *       {
 *         name: 'License',
 *         sourceUrl: 'https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/text/AGPL-3.0-or-later.txt',
 *         sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
 *       }
 *     ],
 *     token: ':icP7sOAmpY_W1ODqjLgG6y-G'
 *   }
 * );
 * // {
 * //   "challenge": "eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzaWduIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJLRXZCSVBLZFRLX1JNYldFUkZVVFpBcUkiLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwibXNnIjoiVG8gY29udGludWUsIHBsZWFzZSByZWFkIGFuZCBhY2NlcHQgdGhlIGF0dGFjaGVkIExpY2Vuc2UiLCJhdHRhY2htZW50cyI6W3sibmFtZSI6IkxpY2Vuc2UiLCJzb3VyY2VVcmwiOiJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc3BkeC9saWNlbnNlLWxpc3QtZGF0YS9yZWZzL2hlYWRzL21haW4vdGV4dC9BR1BMLTMuMC1vci1sYXRlci50eHQiLCJzaGEyNTYiOiJkOGE2Y2MzMWFiYzE2YjY3NDhjN2EyMWYyMTYxMWY1YTFlYzMzZjY3ZDIyY2EyM2Q3ZGExYzE5Yjk1NDk2YmVlIn1dfQ",
 * //   "redirectUrl": "https://auth.triauthdemo.org/sign.html#?challenge=eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzaWduIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJLRXZCSVBLZFRLX1JNYldFUkZVVFpBcUkiLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwibXNnIjoiVG8gY29udGludWUsIHBsZWFzZSByZWFkIGFuZCBhY2NlcHQgdGhlIGF0dGFjaGVkIExpY2Vuc2UiLCJhdHRhY2htZW50cyI6W3sibmFtZSI6IkxpY2Vuc2UiLCJzb3VyY2VVcmwiOiJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc3BkeC9saWNlbnNlLWxpc3QtZGF0YS9yZWZzL2hlYWRzL21haW4vdGV4dC9BR1BMLTMuMC1vci1sYXRlci50eHQiLCJzaGEyNTYiOiJkOGE2Y2MzMWFiYzE2YjY3NDhjN2EyMWYyMTYxMWY1YTFlYzMzZjY3ZDIyY2EyM2Q3ZGExYzE5Yjk1NDk2YmVlIn1dfQ&token=:rZCy5mqxuP2Oru3AWovmMd7ym4oqyx7sBV033WcLlNk"
 * // }
 * ```
 *
 * **2. Redirect**
 *
 * Once the user's web browser is redirected to the `redirectUrl`, they will be taken to the Triauth Authenticator web application,
 * where they will be presented with the message, and have an opportunity to view and/or download attachments.
 *
 * If the user declines the signing request, the Triauth Authenticator sends `false` as the `response`, which `Triauth.sign` reports as error 403.
 *
 * **3. Verify**
 *
 * After the user approves the signing request, the Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP POST method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/POST), and passes a signature in the `response` form parameter.
 * The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
 *
 * Once you extract the `response` (string), you should pass it to the `Triauth.sign` function together with the previously stored `challenge` (string) to obtain signing result.
 * If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let signingResult = await Triauth.sign({challenge, response});
 * // returns {signed:true, result, issuedAt, signedAt, verifiedAt, verificationResult} upon success
 * // returns {error:{code, message}} upon failure
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.sign(
 *   {
 *    challenge:'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzaWduIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJLRXZCSVBLZFRLX1JNYldFUkZVVFpBcUkiLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwibXNnIjoiVG8gY29udGludWUsIHBsZWFzZSByZWFkIGFuZCBhY2NlcHQgdGhlIGF0dGFjaGVkIExpY2Vuc2UiLCJhdHRhY2htZW50cyI6W3sibmFtZSI6IkxpY2Vuc2UiLCJzb3VyY2VVcmwiOiJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc3BkeC9saWNlbnNlLWxpc3QtZGF0YS9yZWZzL2hlYWRzL21haW4vdGV4dC9BR1BMLTMuMC1vci1sYXRlci50eHQiLCJzaGEyNTYiOiJkOGE2Y2MzMWFiYzE2YjY3NDhjN2EyMWYyMTYxMWY1YTFlYzMzZjY3ZDIyY2EyM2Q3ZGExYzE5Yjk1NDk2YmVlIn1dfQ',
 *    response:'|sign;john@triauthdemo.org;;https://example.com/;v1;1787224774435;eyJhdHRhY2htZW50cyI6W3sibmFtZSI6IkxpY2Vuc2UiLCJzaGEyNTYiOiJkOGE2Y2MzMWFiYzE2YjY3NDhjN2EyMWYyMTYxMWY1YTFlYzMzZjY3ZDIyY2EyM2Q3ZGExYzE5Yjk1NDk2YmVlIn1dfQ;;pj0gdEVQ3JBYh08jknFpY45WX462AUb1z78mINHewl1NXWzU5_g9ibD3-ffbdH9SIGtQTtcHQrsa3Ivt1wg1sg|'
 *   }
 * );
 * //
 * // {
 * //   "signed": true,
 * //   "result": "|sign;john@triauthdemo.org;;https://example.com/;v1;1787224774435;eyJhdHRhY2htZW50cyI6W3sibmFtZSI6IkxpY2Vuc2UiLCJzaGEyNTYiOiJkOGE2Y2MzMWFiYzE2YjY3NDhjN2EyMWYyMTYxMWY1YTFlYzMzZjY3ZDIyY2EyM2Q3ZGExYzE5Yjk1NDk2YmVlIn1dfQ;;pj0gdEVQ3JBYh08jknFpY45WX462AUb1z78mINHewl1NXWzU5_g9ibD3-ffbdH9SIGtQTtcHQrsa3Ivt1wg1sg|",
 * //   "issuedAt": 1787224748449,
 * //   "signedAt": 1787224774435,
 * //   "verifiedAt": 1787224774536,
 * //   "verificationResult": {
 * //     "valid": true,
 * //     "type": "sign",
 * //     "identifier": "john@triauthdemo.org",
 * //     "identityDomain": "john._at.triauthdemo.org",
 * //     "lookupCode": "",
 * //     "actor": "",
 * //     "actorIdentityDomain": "",
 * //     "actorLookupCode": "",
 * //     "via": "https://example.com/",
 * //     "ver": 1,
 * //     "signedAt": 1787224774435,
 * //     "verifiedAt": 1787224774536,
 * //     "publicProfile": {
 * //       "initials": "JD",
 * //       "name": "John Doe"
 * //     },
 * //     "groups": [],
 * //     "deviceName": "desktop",
 * //     "deviceTag": "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
 * //     "keys": [
 * //       {
 * //         "value": "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
 * //         "options": {
 * //           "type": "es256",
 * //           "use": "attest,auth,ping,sign,stamp"
 * //         },
 * //         "verified": true,
 * //         "skipped": false
 * //       }
 * //     ],
 * //     "secure": true,
 * //     "expires": 1787226574536,
 * //     "signedMetadata": {
 * //       "attachments": [
 * //         {
 * //           "name": "License",
 * //           "sha256": "d8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee"
 * //         }
 * //       ]
 * //     },
 * //     "unsignedMetadata": {}
 * //   }
 * // }
 * //
 * ```
 *
 * > [!IMPORTANT]
 * > Upon successful signing, the result object will have the `signed` property set to `true`, and the raw signature (string) available in the `result` property.
 * > This signature may also be verified by third parties using the `Triauth.verify` method.
 * >
 * > Upon failed signing, the `signed` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
 *
 * > [!NOTE]
 * > An attachment is bound to the signature by its `name` and `sha256` only. The `sourceUrl` is used at request time to fetch the file, but is optional in the signed response. If a response does sign a `sourceUrl`, it must match the one requested in the challenge.
 *
 * @param [options={}] {object}
 *
 * @param [options.identifier] {string} - (stage 1) the user provided identifier
 * @param [options.callbackUrl] {string} - (stage 1) an application provided URL to which the user's web browser should be redirected with the response
 * @param [options.message] {string} - (stage 1) a human-readable text message to be signed
 * @param [options.attachments] {Array<{name: string, sourceUrl: string, sha256: string}>} - (stage 1) optional list of at most 10 attachments to be covered by the signature; `name` must be unique within the list and `sha256` a lowercase hex digest
 * @param [options.token] {string} - (stage 1, required) the `signToken` previously obtained via `ext.signToken` from a `Triauth.authenticate` call; a stage-1 request without it returns error 226
 * @param [options.ext] {object} - (stage 1) an optional object of protocol extensions to use (e.g., `{callbackMethod:'GET'}`)
 *
 * @param [options.challenge] {string} - (stage 3) a challenge as it was returned by the method after stage 1 call
 * @param [options.response] {string} - (stage 3) a received response, by default delivered as a `response` form parameter of a POST to the `callbackUrl` (overridable via the `callbackMethod` extension)
 *
 * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {challenge: string, redirectUrl: string}
 *   | {signed: true, result: string, issuedAt: number, signedAt: number, verifiedAt: number, verificationResult: object}
 *   | {error: {code: number, message: string}}
 * >}
 */
export const sign = async(options = {}, config = {}) => {
  return _perform('sign', options, config);
};

/**
 * The `stamp` method may be used to automatically obtain a signature of a given `message` made on behalf of the user with a given `identifier`.
 * Stamps do not typically require any interaction from the user, and may be later verified by any party using the `Triauth.verify` method.
 * They can be used e.g., to prove to other websites that the user is logged in to your website, to authenticate third-party API requests,
 * or in [Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to prove the identities of communicating parties for E2E encryption.
 *
 * > [!WARNING]
 * > Stamps are not single-use proofs. The cryptographic signature covers the `message` together
 * > with the stamp's `type`, `identifier`, `via`, and timestamp — but **not** the challenge nonce,
 * > which is never bound to the signature. A stamp over a fixed `message` thus re-verifies against
 * > any challenge that reuses that `message`, within the `ts` freshness window. Relying parties that
 * > need replay protection must include a fresh, verifier-chosen nonce inside `message` itself.
 *
 * > [!NOTE]
 * > **To use this function you must request and obtain a special `stampToken`**<br/>
 * > To do so, provide the `ext:{stampToken:true}` parameter to the `Triauth.authenticate` function during the initial call (i.e., when building the challenge),
 * > and, given that the user agrees and/or authenticator supports it, in the authentication result you will receive `ext.stampToken` property (string).
 * > You should keep the `stampToken` value private, and pass it as a `token` parameter in the initial call to the `stamp` method.
 * > The token is issued by the authenticator on the device that signed in, and only that device honors it.
 * > The authenticator keeps its copy in that browser's storage, and the next sign-in on that device, approved or denied, replaces or removes it.
 * > Store the token in the session that the sign-in created, next to the `challenge` and `deviceTag`, not on the user's account, and pass that session's token.
 * > A user with several devices holds a different token on each.
 * >
 * > Also, the `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
 * > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
 * > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
 *
 * The stamping is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
 *
 * **1. Request**
 *
 * At first, you need to call the `Triauth.stamp` method with the `identifier` option set to the user provided personal identifier (lowercase string),
 * a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
 * a `message` (string) option set to a text message to be stamped,
 * a `token` (string) option set to the `stampToken` previously obtained via `ext.stampToken` from a `Triauth.authenticate` call,
 * and an optional `ext` option (object) listing the [protocol extensions](#protocol-extensions) that you wish to use.
 *
 * > [!NOTE]
 * > The `message` may consist of letters and digits from any language, space, and a fixed set of punctuation, and is limited to 2 KB.
 * > Emojis, newlines, tabs, and other whitespace or control characters are not allowed.
 * > To stamp binary data or multi-line content (e.g., a public key, a pretty-printed JSON object, a PEM blob),
 * > base64- or hex-encode it before passing it as `message`.
 *
 * In return, you will receive an object with the `challenge` (string) and `redirectUrl` (string).
 * You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let result = await Triauth.stamp({identifier, callbackUrl, message, token, ext});
 * // returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
 * // returns {error} on error
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.stamp(
 *   {
 *     identifier:'john@triauthdemo.org',
 *     callbackUrl:'https://example.com/triauth-callback',
 *     message: 'login-nonce:4f2d9c715b6e4a3c', // a fresh, single-use nonce from your server, when the stamp gates anything
 *     token:':uXyqjnczCcq1xStskY7xN6-Q'
 *   }
 * );
 * //
 * // {
 * //   challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzdGFtcCIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoic1ZoVXRZOXQzMEVDQjJUR0t2WTktZXpBIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsIm1zZyI6ImxvZ2luLW5vbmNlOjRmMmQ5YzcxNWI2ZTRhM2MifQ',
 * //   redirectUrl: 'https://auth.triauthdemo.org/stamp.html#?challenge=eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzdGFtcCIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoic1ZoVXRZOXQzMEVDQjJUR0t2WTktZXpBIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsIm1zZyI6ImxvZ2luLW5vbmNlOjRmMmQ5YzcxNWI2ZTRhM2MifQ&token=:dIsLLvqBmQO_DS2o_HhLM5LRJk8hHdbr938NmJnif64'
 * // }
 * //
 * ```
 *
 * **2. Redirect**
 *
 * Once the user's web browser is redirected to the `redirectUrl`, and assuming that the `token` is valid, the Triauth Authenticator web application will immediately respond with the stamp to the `callbackUrl`.
 *
 * **3. Verify**
 *
 * The Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP POST method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/POST), and passes a stamp in the `response` form parameter.
 * The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
 *
 * Once you extract the `response` (string), you should pass it to the `Triauth.stamp` function together with the previously stored `challenge` (string) to obtain stamping result.
 * If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let stampingResult = await Triauth.stamp({challenge, response});
 * // returns {stamped:true, result, issuedAt, signedAt, verifiedAt, verificationResult} upon success
 * // returns {error:{code, message}} upon failure
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.stamp(
 *   {
 *    challenge:'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzdGFtcCIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoic1ZoVXRZOXQzMEVDQjJUR0t2WTktZXpBIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsIm1zZyI6ImxvZ2luLW5vbmNlOjRmMmQ5YzcxNWI2ZTRhM2MifQ',
 *    response:'|stamp;john@triauthdemo.org;;https://example.com/;v1;1787224751380;;;0lWRFGKZsAC18au2DqtYEavf7zXDkCQH0fTOqwB2QeWsKhSkm29NY0mz1r6VckOVL2utg3wp1QMnySEO56zupg|'
 *   }
 * );
 *
 * //
 * // {
 * //   "stamped": true,
 * //   "result": "|stamp;john@triauthdemo.org;;https://example.com/;v1;1787224751380;;;0lWRFGKZsAC18au2DqtYEavf7zXDkCQH0fTOqwB2QeWsKhSkm29NY0mz1r6VckOVL2utg3wp1QMnySEO56zupg|",
 * //   "issuedAt": 1787224748449,
 * //   "signedAt": 1787224751380,
 * //   "verifiedAt": 1787224751481,
 * //   "verificationResult": {
 * //     "valid": true,
 * //     "type": "stamp",
 * //     "identifier": "john@triauthdemo.org",
 * //     "identityDomain": "john._at.triauthdemo.org",
 * //     "lookupCode": "",
 * //     "actor": "",
 * //     "actorIdentityDomain": "",
 * //     "actorLookupCode": "",
 * //     "via": "https://example.com/",
 * //     "ver": 1,
 * //     "signedAt": 1787224751380,
 * //     "verifiedAt": 1787224751481,
 * //     "publicProfile": {
 * //       "initials": "JD",
 * //       "name": "John Doe"
 * //     },
 * //     "groups": [],
 * //     "deviceName": "desktop",
 * //     "deviceTag": "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
 * //     "keys": [
 * //       {
 * //         "value": "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
 * //         "options": {
 * //           "type": "es256",
 * //           "use": "attest,auth,ping,sign,stamp"
 * //         },
 * //         "verified": true,
 * //         "skipped": false
 * //       }
 * //     ],
 * //     "secure": true,
 * //     "expires": 1787226551481,
 * //     "signedMetadata": {},
 * //     "unsignedMetadata": {}
 * //   }
 * // }
 * //
 * ```
 *
 * > [!IMPORTANT]
 * > Upon successful stamping, the result object will have the `stamped` property set to `true`, and the stamp (string) available in the `result` property.
 * > This stamp may also be verified by third parties using the `Triauth.verify` method.
 * >
 * > Upon failed stamping, the `stamped` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
 *
 * @param [options={}] {object}
 *
 * @param [options.identifier] {string} - (stage 1) the user provided identifier
 * @param [options.callbackUrl] {string} - (stage 1) an application provided URL to which the user's web browser should be redirected with the response
 * @param [options.message] {string} - (stage 1) a text message to be stamped
 * @param [options.token] {string} - (stage 1, required) the `stampToken` previously obtained via `ext.stampToken` from a `Triauth.authenticate` call; a stage-1 request without it returns error 226
 * @param [options.ext] {object} - (stage 1) an optional object of protocol extensions to use (e.g., `{callbackMethod:'GET'}`)
 *
 * @param [options.challenge] {string} - (stage 3) a challenge as it was returned by the method after stage 1 call
 * @param [options.response] {string} - (stage 3) a received response, by default delivered as a `response` form parameter of a POST to the `callbackUrl` (overridable via the `callbackMethod` extension)
 *
 * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {challenge: string, redirectUrl: string}
 *   | {stamped: true, result: string, issuedAt: number, signedAt: number, verifiedAt: number, verificationResult: object}
 *   | {error: {code: number, message: string}}
 * >}
 */
export const stamp = async(options = {}, config = {}) => {
  return _perform('stamp', options, config);
};

/**
 * The verify method verifies triauth signatures and stamps.
 * For the verification to succeed, the public keys associated with the device that made the signature/stamp need to be still present in the DNS.
 *
 * > [!TIP]
 * > For signatures that need to be verifiable even after the respective device keys are removed from the DNS,
 * > consider using a DNS History Service.
 *
 * > [!TIP]
 * > All responses in triauth's 3-step challenge-response protocol are triauth signatures, and to some extent can also be verified later with this method.
 * > But never use this method in place of the original (i.e., never use `Triauth.verify(challenge, response)` in place of `Triauth.authenticate({challenge, response})` or any other such method),
 * > as it may report `{valid:true}`, even when important constraints are not met (e.g., the authentication request has timed out).
 *
 * > [!IMPORTANT]
 * > By default `Triauth.verify` accepts only a **single-signature** envelope (`maxSignatures` defaults to 1).
 * > To verify a multi-signature envelope (e.g. an attestation bundle), raise `maxSignatures` to the number of
 * > segments you expect; otherwise a multi-segment envelope is reported as `{valid:false, reason:'declined'}`.
 *
 * Synopsis:
 *
 * ```javascript
 * let verificationResult = await Triauth.verify(message, signature);
 * // returns {valid:true, type, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, via, ver, signedAt, verifiedAt, publicProfile, groups, deviceName, deviceTag, keys, secure, expires, signedMetadata, unsignedMetadata} if signature has been successfully verified
 * // returns {valid:true, type:'multisig', secure, expires, verifiedAt, signatures} when a multi-signature was verified, the signatures array carries the individual verification results
 * // returns {valid:false, reason} when the envelope was evaluated and not accepted; reason is one of 'malformed' (unparseable envelope), 'invalid' (bad crypto, an unresolvable signer, or an identifier/actor/type/ver/via mismatch), 'expired' (signature timestamp outside notBefore/notAfter), or 'declined' (segment count outside minSignatures/maxSignatures)
 * // returns {error} when the signature could not be evaluated at all (e.g. bad arguments, DNS failure, or a requireSecure veto)
 *
 * ```
 *
 * > [!IMPORTANT]
 * > Accept a signature only when `valid === true`. Treat every other result as not verified. The `reason` string on a `{valid:false}` result is diagnostic only (for logging / UX / retry classification) - never use it as an accept/reject signal.
 * > If you raise `maxSignatures`, expect that you may get `type:'multisig'` back without a top-level `identifier` set.
 *
 * Example:
 *
 * ```javascript
 * await Triauth.verify(
 *   'login-nonce:4f2d9c715b6e4a3c',
 *   '|stamp;john@triauthdemo.org;;https://example.com/;v1;1787224751380;;;0lWRFGKZsAC18au2DqtYEavf7zXDkCQH0fTOqwB2QeWsKhSkm29NY0mz1r6VckOVL2utg3wp1QMnySEO56zupg|'
 * );
 * //
 * // {
 * //   "valid": true,
 * //   "type": "stamp",
 * //   "identifier": "john@triauthdemo.org",
 * //   "identityDomain": "john._at.triauthdemo.org",
 * //   "lookupCode": "",
 * //   "actor": "",
 * //   "actorIdentityDomain": "",
 * //   "actorLookupCode": "",
 * //   "via": "https://example.com/",
 * //   "ver": 1,
 * //   "signedAt": 1787224751380,
 * //   "verifiedAt": 1787224808550,
 * //   "publicProfile": {
 * //     "initials": "JD",
 * //     "name": "John Doe"
 * //   },
 * //   "groups": [],
 * //   "deviceName": "desktop",
 * //   "deviceTag": "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
 * //   "keys": [
 * //     {
 * //       "value": "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
 * //       "options": {
 * //         "type": "es256",
 * //         "use": "attest,auth,ping,sign,stamp"
 * //       },
 * //       "verified": true,
 * //       "skipped": false
 * //     }
 * //   ],
 * //   "secure": true,
 * //   "expires": 1787226608550,
 * //   "signedMetadata": {},
 * //   "unsignedMetadata": {}
 * // }
 * //
 * ```
 *
 * @param message {string} - A message that was signed
 * @param signature {string} - The received signature of the message
 * @param [constraints={}] {object} - Optional additional constraints that should be verified prior to calling the time-taking internal crypto functions
 * @param [constraints.identifier] {string} - identifier on behalf of which the signature was generated
 * @param [constraints.actor] {string} - the actor (delegate) whose keys made the signature on behalf of the `identifier`; `''` requires a non-delegated signature
 * @param [constraints.ver] {number} - the triauth signature envelope version to require
 * @param [constraints.type] {string} - the type of signature to require — one of 'attest'|'auth'|'ping'|'sign'|'stamp'. Pin this to the expected signature type when possible.
 * @param [constraints.via] {string} - the base URL (e.g., https://example.com/) of the client application the signature was issued to (the base URL of its `callbackUrl`). Pin it when possible. Otherwise a signature requested by another application verifies just as well.
 * @param [constraints.notBefore] {number} - a Unix timestamp in milliseconds (a non-number is rejected with error 101). If the timestamp encoded in the signature is earlier than this value, the result is `{valid:false, reason:'expired'}`. Note: unlike the internal verify path used by `authenticate`/`ping`/`sign`/`stamp`, `Triauth.verify` does **not** widen this bound by `config.maximalAllowedClientClockDrift` - the comparison is strict.
 * @param [constraints.notAfter] {number} - a Unix timestamp in milliseconds (a non-number is rejected with error 101). If the timestamp encoded in the signature is greater than this value, the result is `{valid:false, reason:'expired'}`. Note: strict comparison; no clock-drift slack is applied (see `notBefore`).
 * @param [constraints.minSignatures] {number} - the minimum number of signature segments the (multi-)signature envelope must contain. A count below this is a signature-count policy decline, reported as `{valid:false, reason:'declined'}`. Note: this counts segments, NOT distinct signers - the same identity may legitimately contribute multiple (e.g., per-device) signatures; to require distinct signers, additionally check `signatures[].identifier` and/or `signatures[].deviceTag` in the result. Because `maxSignatures` defaults to 1, requiring more than one signature means you must also raise `maxSignatures`.
 * @param [constraints.maxSignatures] {number} - the maximum number of signature segments the (multi-)signature envelope may contain. **Defaults to 1** (secure-by-default): when omitted, `Triauth.verify` accepts only a single signature, so a multi-segment envelope is reported as `{valid:false, reason:'declined'}`. To verify a multi-signature envelope, pass an explicit `maxSignatures` (>= the number of segments you expect). The default of 1 also pins the result to the flat single-signature shape and bounds the per-segment DNS resolution work for untrusted input.
 * @param [config={}] {object} - optional overrides for the global Triauth.config settings. When `config.requireSecure` is set, an otherwise-valid signature whose DNS chain was not reported DNSSEC-validated (`secure !== true`) is rejected with error 404 (surfaced as `{error}`).
 *
 * @returns {Promise<
 *     {valid: true, type: string, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, via: string, ver: number, signedAt: number, verifiedAt: number, publicProfile: object, groups: Array<string>, deviceName: string, deviceTag: string, keys: Array<object>, secure: boolean, expires: (number|undefined), signedMetadata: object, unsignedMetadata: object}
 *   | {valid: true, type: 'multisig', secure: boolean, expires: (number|undefined), verifiedAt: number, signatures: Array<object>}
 *   | {valid: false, reason: 'malformed'|'invalid'|'expired'|'declined'}
 *   | {error: {code: number, message: string}}
 * >}
 */
export const verify = async function(message, signature, constraints = {}, config = {}) {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  config.logger?.info?.('Processing Triauth.verify');
  const ts = Helpers.now();

  try {
    // Check the sanity of received arguments
    if (
      (typeof message !== 'string' || typeof signature !== 'string' || typeof constraints !== 'object' || typeof config !== 'object') ||
      (!Helpers.hasOnlyKnownProperties(constraints, ['identifier', 'actor', 'ver', 'type', 'via', 'notBefore', 'notAfter', 'minSignatures', 'maxSignatures']))
    ){
      throw new TriauthError(101, 'Invalid arguments');
    }

    // Reject config overrides carrying unknown keys
    if (!Helpers.hasOnlyKnownProperties(config, KNOWN_CONFIG_KEYS)) {
      throw new TriauthError(103, 'Unrecognized configuration key');
    }

    // Signature-count bounds, when provided, must be numbers
    if (
      (constraints.minSignatures != null && (typeof constraints.minSignatures !== 'number' || Number.isNaN(constraints.minSignatures))) ||
      (constraints.maxSignatures != null && (typeof constraints.maxSignatures !== 'number' || Number.isNaN(constraints.maxSignatures)))
    ) {
      throw new TriauthError(101, 'Invalid arguments');
    }

    // Secure-by-default: when the caller does not specify maxSignatures, it defaults to 1, so an
    // un-opted-in multi-signature envelope is declined below.
    if (constraints.maxSignatures == null) {
      constraints = Object.assign({}, constraints, { maxSignatures: 1 });
    }

    const sig = new MultiSignature(signature, config);

    // A signature-count policy mismatch means we DECLINE cryptographic verification and report `{valid:false, reason:'declined'}`
    const segCount = sig.signatures.length;
    const { minSignatures, maxSignatures } = constraints;
    if (
      (maxSignatures != null && segCount > maxSignatures) ||
      (minSignatures != null && segCount < minSignatures)
    ) {
      config.logger?.info?.('Verification declined - signature count outside minSignatures/maxSignatures policy', {segCount, minSignatures, maxSignatures});
      return { valid: false, reason: 'declined' };
    }

    const verifyResult = await sig.verify(message, constraints);

    if (!verifyResult || !verifyResult.valid) {
      config.logger?.info?.('Verification failed');

      // `null` => time-related failure ("expired"); `false` (or a defensive object with valid:false)
      // => any other failure ("invalid"). Preserves the 3-state verdict the lower layers compute.
      return { valid: false, reason: verifyResult === null ? 'expired' : 'invalid' };
    }

    // Enforce config.requireSecure (mirrors the challenge-response flows and Triauth.check): an
    // otherwise-valid envelope whose DNS chain was not reported DNSSEC-validated is rejected with
    // error 404, surfaced as {error} via the catch below.
    ChallengeResponseFlow.assertSecure(verifyResult.secure, config);

    config.logger?.info?.('Verification successful');

    const retval = Helpers.clone(verifyResult.signatures.length > 1 ? verifyResult : verifyResult.signatures[0]);

    return retval;

  } catch (err) {

    // A 2xx validation/parse error means the envelope could not be parsed into a well-formed
    // signature - a definitive negative verdict reported as {valid:false, reason:'malformed'}. Other
    // TriauthErrors (e.g. 404 from requireSecure, or a 110 DNS failure) surface as {error}.
    if (
      err instanceof TriauthError && err.code >= 200 && err.code < 300
    ) {
      return { valid: false, reason: 'malformed' };
    }

    return TriauthError.process(err, config);

  } finally {
    config.logger?.info?.('Completed in ' + Math.round(Helpers.now() - ts) + 'ms');

  }
};
