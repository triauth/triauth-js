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
 * Methods related to attestations that are a part of the official triauth-js API.
 *
 * @namespace Attestation
 * @memberof Triauth.Api
 */

import { TriauthError } from '../error.js';
import { Helpers } from '../helpers.js';
import { Validator } from '../validator.js';
import { LIMITS } from '../protocol.js';
import { ChallengeResponseFlow } from '../challenge_response_flow.js';

/**
 * The `attest` method may be used to obtain third-party verified attestations related to the given user's `identifier`.
 * You can request attestations of almost anything, like the user age, not-a-robot status, location, role, etc., given that there is a verification provider that provides such attestation.
 *
 * Each attestation consists of a `label` (string) that is displayed to the user (e.g., 'I am not a robot'),
 * and `providers` (array of `https://` URL strings), from which the user can select the desired verification provider.
 * Once the user clicks 'verify' button for the given attestation, they are taken to the selected verification provider URL.
 * It is then the job of verification provider to verify that the user meets the certain criteria (e.g., as read from the URL),
 * and respond with a digital signature. Such signature(s) are embedded in the final response that you receive,
 * and are verified during the stage '3. Verify' call of `Triauth.attest`.
 *
 * > [!IMPORTANT]
 * > **You choose which providers to trust, and the provider defines what the attestation means.**<br/>
 * > `Triauth.attest` only verifies that a signature came from an identity at the host of one of the `providers` you listed. It does not interpret what that provider actually checked.
 *
 * > [!NOTE]
 * > **Attestations in triauth may be anonymous.**<br/>
 * > By default, verification providers receive only the user-selected verification provider URL, and the domain name of user's authentication endpoint (e.g., `auth.triauth.org`).
 * > They can later ask the user for their full identifier if needed and set a constraint that the attestation is valid only for the given identifier.
 *
 * > [!NOTE]
 * > **Binders: what an attestation is tied to.**<br/>
 * > A verification provider that learns the user states it in the `bind` object of its signature's signed metadata:
 * > `identifier` (the user's identifier), `via` (the client application), and `deviceTag` (the device that completed the ceremony).
 * > Every member of `bind` is critical, on every signature of the response: an unrecognized binder — or one that does not equal the verified user's value — fails the attestation (401),
 * > so a provider's signed statement can never be silently ignored. Members of the signed metadata outside `bind` are auxiliary, and unrecognized ones are ignored.
 * > An attester that binds nothing attests anonymously (the default); the binders it did state are surfaced under `attestations.<id>.signedMetadata.bind`, so you can require their presence.
 *
 * > [!NOTE]
 * > **To use this function you must request and obtain a special `attestToken`**<br/>
 * > To do so, provide the `ext:{attestToken:true}` parameter to the `Triauth.authenticate` function during the initial call (i.e., when building the challenge),
 * > and, given that the user agrees and/or authenticator supports it, in the authentication result you will receive `ext.attestToken` property (string).
 * > You should keep the `attestToken` value private, and pass it as a `token` parameter in the initial call to the `attest` method.
 * > The token is issued by the authenticator on the device that signed in, and only that device honors it.
 * > A user with several devices holds a different token on each.
 * >
 * > Also, the `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
 * > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
 * > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
 *
 * The attestations are based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
 *
 * **1. Request**
 *
 * At first, you need to call the `Triauth.attest` method with the `identifier` option set to the user provided personal identifier (lowercase string),
 * a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
 * an `attestations` option (object) whose keys are caller-chosen attestation IDs and whose values consist of a `label` (string) and `providers` (array of `https://` URL strings),
 * a `token` (string) option set to the `attestToken` previously obtained via `ext.attestToken` from a `Triauth.authenticate` call,
 * and an optional `ext` option (object) listing the [protocol extensions](#protocol-extensions) that you wish to use.
 *
 * In return, you will receive an object with the `challenge` (string) and `redirectUrl` (string).
 * You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let result = await Triauth.attest({identifier, callbackUrl, attestations, token, ext});
 * // returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
 * // returns {error} on error
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.attest(
 *   {
 *     identifier: 'john@triauthdemo.org',
 *     callbackUrl: 'https://example.com/triauth-callback',
 *     attestations: {
 *       'not-a-robot': {
 *         label: 'I am not a robot',
 *         providers: [
 *           'https://attest.triauthdemo.org/not-a-robot',
 *           'https://other-provider.example.com/i-am/not-a-robot'
 *         ]
 *       }
 *     },
 *     token: ':tgX6ZXfNi3xwzSwuennigDoA'
 *   }
 * );
 * // {challenge: 'eyJjYn…JdfX19', redirectUrl: 'https://auth.triauthdemo.org/attest.html#?challenge=eyJjYn…JdfX19&token=:WE4zaN5WA_NuHX1BW4wBidu_Sef2aqkzA-gOxlyLmeE'}
 * ```
 *
 * **2. Redirect**
 *
 * Once the user's web browser is redirected to the `redirectUrl`, they will be taken to the Triauth Authenticator web application, where they will be presented with the requested attestations.
 * For each attestation, your `label` is shown in the UI, together with a select field listing `providers`, and a 'Verify' button, allowing the user to select the desired provider and complete the attestation.
 *
 * > [!TIP]
 * > The URLs of verification providers are shown in the UI, so keep them short and human-friendly.
 *
 * If the user declines the request, the Triauth Authenticator sends `false` as the `response`, which `Triauth.attest` reports as error 403.
 *
 * **3. Verify**
 *
 * The Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP POST method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/POST), and passes the attestation in the `response` form parameter.
 * The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
 *
 * Once you extract the `response` (string), you should pass it to the `Triauth.attest` function together with the previously stored `challenge` (string) to obtain attestation result.
 * If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let attestResult = await Triauth.attest({challenge, response});
 * // returns {attested:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, attestations, deviceName, deviceTag, keys} upon success
 * // returns {error:{code, message}} upon failure
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.attest(
 *   {
 *    challenge:'eyJjYn…JdfX19',
 *    response:'|attest;john@triauthdemo.org;;https://example.com/;v1;1787224773556;;;MsVdr13VwgivjiTRnp78ncX2skDvZf5MdWLqXTXrMmo0VUtmn6R7gx1qJVhLJGYojMh9C4Lj2b_wxtbFlaZltg|attest;robot-attester@attest.triauthdemo.org;;https://attest.triauthdemo.org/not-a-robot;v1;1787224768930;;;AvbmMJwAcE0B_EaBv0EdMAcBAwJVY0BpN1MOmARhc_LdS6QsQzgwSNUaahjL_UyA8qXoiEqqtDXrlkG_1fWBpg|'
 *   }
 * );
 *
 * //
 * // {
 * //   "attested": true,
 * //   "issuedAt": 1787224748449,
 * //   "signedAt": 1787224773556,
 * //   "verifiedAt": 1787224773991,
 * //   "expires": 1787226573991,
 * //   "secure": true,
 * //   "identifier": "john@triauthdemo.org",
 * //   "identityDomain": "john._at.triauthdemo.org",
 * //   "lookupCode": "",
 * //   "actor": "",
 * //   "actorIdentityDomain": "",
 * //   "actorLookupCode": "",
 * //   "groups": [],
 * //   "attestations": {
 * //     "not-a-robot": {
 * //       "valid": true,
 * //       "type": "attest",
 * //       "identifier": "robot-attester@attest.triauthdemo.org",
 * //       "identityDomain": "robot-attester._at.attest.triauthdemo.org",
 * //       "lookupCode": "",
 * //       "actor": "",
 * //       "actorIdentityDomain": "",
 * //       "actorLookupCode": "",
 * //       "via": "https://attest.triauthdemo.org/not-a-robot",
 * //       "ver": 1,
 * //       "signedAt": 1787224768930,
 * //       "verifiedAt": 1787224773991,
 * //       "publicProfile": {
 * //         "name": "Robot Checker"
 * //       },
 * //       "groups": [],
 * //       "deviceName": "server",
 * //       "deviceTag": "NOtejuAqKHSdgvKVpw57cU_Qipj6UKcz2nNiugx0l8g",
 * //       "keys": [
 * //         {
 * //           "value": "BMR8Ug7qu9HUc9UgY_ADh8giBNmWBbSmGsR6DD6Hg5rpWeyYvu2WlQ43iR_dj0eKN99esQNMe7Gq2u2LBnRejcU",
 * //           "options": {
 * //             "use": "attest",
 * //             "type": "es256"
 * //           },
 * //           "verified": true,
 * //           "skipped": false
 * //         }
 * //       ],
 * //       "secure": true,
 * //       "expires": 1787226573991,
 * //       "signedMetadata": {},
 * //       "unsignedMetadata": {}
 * //     }
 * //   },
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
 * //   ]
 * // }
 * //
 * ```
 *
 * > [!IMPORTANT]
 * > Upon successful attestation, the result object will have the `attested` property set to `true`.
 * >
 * > Upon failed attestation, the `attested` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
 *
 * When `attested` is `true`, inspect the result before relying on it:
 * - Check `secure`. It is `true` only when DNSSEC protected every DNS record of every identity involved in verification (the user's and every attester's, including each domain's `triauth` configuration record). When it is `false`, some of the public keys read from DNS were not cryptographically protected.
 * - For attestations that must be tied to this specific user, confirm that the per-attestation `attestations.<id>.signedMetadata.bind` carries the binding you expect (the `identifier`/`deviceTag`).
 * - Compare `attestations.<id>.identifier` with the attester the provider documents when the provider's host also issues identities to others.
 *
 * @param options {object}
 *
 * @param [options.identifier] {string} - (stage 1) the user provided identifier
 * @param [options.callbackUrl] {string} - (stage 1) an application provided URL to which the user's web browser should be redirected with the response
 * @param [options.attestations] {object} - (stage 1) an object whose keys are caller-chosen attestation IDs and whose values are `{label, providers}` objects describing each requested attestation; at most 4 attestations, each listing at most 4 `https://` provider URLs (error 229 otherwise)
 * @param [options.token] {string} - (stage 1, required) the `attestToken` previously obtained via `ext.attestToken` from a `Triauth.authenticate` call; a stage-1 request without it returns error 226
 * @param [options.ext] {object} - (stage 1) an optional object of protocol extensions to use (e.g., `{callbackMethod:'GET'}`)
 *
 * @param [options.challenge] {string} - (stage 3) a challenge as it was returned by the method after stage 1 call
 * @param [options.response] {string} - (stage 3) a received response, by default delivered as a `response` form parameter of a POST to the `callbackUrl` (overridable via the `callbackMethod` extension)
 *
 * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {challenge: string, redirectUrl: string}
 *   | {attested: true, issuedAt: number, signedAt: number, verifiedAt: number, expires: (number|undefined), secure: boolean, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, groups: Array<string>, attestations: object, deviceName: string, deviceTag: string, keys: Array<object>}
 *   | {error: {code: number, message: string}}
 * >} A promise that resolves to one of the following:
 * - `{challenge: string, redirectUrl: string}`: Returned during stage 1 when a challenge is generated. The `challenge` should be stored and the user should be redirected to the `redirectUrl`.
 * - `{attested: true, issuedAt: number, signedAt: number, verifiedAt: number, expires?: number, secure: boolean, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, groups: Array<string>, attestations: object, deviceName: string, deviceTag: string, keys: Array<object>}`: Returned during stage 3 upon successful attestation. Includes:
 *   - `attested` (true): Indicates the attestation request was fully satisfied (user signature plus every requested attester signature verified).
 *   - `issuedAt` (number): Unix timestamp on **your** server's clock at which you issued the challenge in stage 1 — the start of the flow's timeline.
 *   - `signedAt` (number): Unix timestamp on the **user's device** clock at which the user signed the request (the user's `mainSig`). Verified to fall within the freshness window, but device-asserted — do not treat it as a trusted wall clock; prefer `issuedAt`/`verifiedAt` for authoritative timing. Each attester's own signing time is on its `attestations.<id>.signedAt`.
 *   - `verifiedAt` (number): Unix timestamp on **your** server's clock at which the whole bundle finished verifying — the latest (max) across the user's and every attester's signature confirmation.
 *   - `expires` (number, optional): Unix timestamp at which the overall verification expires — the earliest expiry across all signing identities; `undefined` when none of the DNS records involved carried a TTL, in which case apply your own re-check interval.
 *   - `secure` (boolean): True only when, for every identity involved (the user's and every attester's), DNSSEC was reported for the domain's `triauth` configuration record and for every well-formed record of the identity answer; a single non-validated identity record anywhere degrades it.
 *   - `identifier` (string): The user's identifier (from the user's `mainSig`).
 *   - `identityDomain` (string): The DNS domain under which the user's identity records are stored (the user's own, for a delegated ceremony).
 *   - `lookupCode` (string): The lookup code the user identity's domain derivation consumed (under `mode=private`); `''` where none was. Each `attestations.<id>.lookupCode` names the attester's own likewise.
 *   - `actor` (string): The identifier of the delegate whose keys signed the user's `mainSig` (delegated ceremony), or `''` when the user's own keys signed it. Attester signatures are always first-party (their own `actor` is `''`).
 *   - `actorIdentityDomain` (string): For a delegated ceremony, the DNS domain under which the delegate's identity records are stored — the records the signing keys were read from; `''` when the user's own keys signed it (and always `''` on attester entries).
 *   - `actorLookupCode` (string): The lookup code the delegate's domain derivation consumed; `''` where none was (and always `''` on attester entries - their statements are first-party).
 *   - `groups` (array): The user's fully-qualified group-membership claims (sorted, deduplicated; `[]` when none are published). This top-level field describes the user, while each `attestations.<id>.groups` describes that attester's own identity.
 *   - `attestations` (object): A map keyed by the caller-chosen attestation ID, whose values are the per-attester signature objects (same shape as `Triauth.Signature#verify` returns: `{valid, type:'attest', identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, via, ver, signedAt, verifiedAt, publicProfile, groups, deviceName, deviceTag, keys, secure, expires, signedMetadata, unsignedMetadata}`).
 *   - `deviceName` (string): User-given, public name of the device that signed the request.
 *   - `deviceTag` (string): Unique identifier of the device (and, for a delegated ceremony, the delegation) that signed the request, in the same form `Triauth.authenticate` reports it.
 *   - `keys` (array): Public keys considered and/or used to verify the user's signature.
 * - `{error: {code: number, message: string}}`: Returned during stage 1 or stage 3 when attestation fails, includes an error object with code and message.
 */
export const attest = async(options, config = {}) => {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  options = Object.assign({}, options);
  const attestationsOption = options.attestations;
  delete options.attestations;

  const validateAttestations = (attestations) => {
    const validationError = Validator.validateAttestations(attestations).errors[0];

    if (validationError) {
      throw new TriauthError(validationError.code, validationError.message);
    }
  }

  const onChallenge = async ({challenge}) => {
    validateAttestations(attestationsOption);
    challenge.data.attest = attestationsOption;
  };

  const onResponse = async ({challenge, response}) => {
    const attestations = challenge.data.attest;
    validateAttestations(attestations);

    // For attestations the signature is verified against the SHA256 of challengeString
    const signedPayload = await Helpers.sha256(challenge.challengeString);

    const verifyResult = (await response.verify('attest', signedPayload, challenge, {
      notBefore: Date.now() - (config.attestTimeout || 0),
      notAfter: Date.now(),
      minSignatures: 1,
      maxSignatures: Math.min(Object.keys(attestations).length + 1, LIMITS.maxMultiSignatures || 0)
    }));

    if (verifyResult?.valid && verifyResult.signatures.length > 0) {

      // Protocol invariant: the user's signature is always the first element of the
      // multi-signature envelope; the remaining entries are attester signatures.
      const mainSig = verifyResult.signatures[0];

      if (challenge.identity.identifier !== mainSig.identifier) {
        config.logger?.debug?.('Verification failed - identifier mismatch', {expectedIdentifier:challenge.identity.identifier, receivedIdentifier:mainSig.identifier});
        return false;
      }

      if (
        !Validator.validateCallbackUrl(challenge.data.cburl).valid ||
        Helpers.getBaseUrl(challenge.data.cburl) !== mainSig.via
      ) {
        config.logger?.debug?.('Verification failed - via prefix mismatch', {cburl:challenge.data.cburl, via:mainSig.via});
        return false;
      }

      // What a binder must equal, by name: the verified user signature's own fields.
      const binderTargets = {
        identifier: mainSig.identifier,  // the user the attestation is bound to
        via: mainSig.via,                // the client application the user signed for
        deviceTag: mainSig.deviceTag     // the device that completed the ceremony
      };

      // Verify binders - a verifier's statement about WHOM it verified
      // An envelope carrying a false or unrecognized binding is malformed as a whole.
      for (const sig of verifyResult.signatures) {
        if (
          !Validator.validateBinders(sig.signedMetadata).valid ||
          !Object.entries(sig.signedMetadata.bind || {}).every(([binder, value]) => value === binderTargets[binder])
        ) {
          config.logger?.debug?.('Verification failed - invalid or mismatched binders', {identifier:sig.identifier, signedMetadata:sig.signedMetadata});
          return false;
        }
      }

      const attestationsResult = {};

      // Note: a single attestSig can satisfy multiple requested attestation IDs if their providers` lists overlap
      for (const [attestId, {providers}] of Object.entries(attestations)) {
        let matched = false;

        for (const attestSig of verifyResult.signatures.slice(1)) {
          if (
            attestSig.valid &&
            attestSig.actor === '' && // attester statements must be self-signed
            providers.indexOf(attestSig.via) >= 0 &&
            attestSig.identifier.replace(/.+@/, '') === Helpers.urlHost(attestSig.via)
          ) {
            config.logger?.debug?.('Attestation matched', {attestId, attestSig});
            attestationsResult[attestId] = Object.assign({}, attestSig);
            matched = true;
            break;
          }
        }

        if (!matched) {
          config.logger?.info?.('Verification failed - missing or unverified attestation', {attestId});
          return false;
        }
      }

      config.logger?.info?.('Verification successful', {identifier:mainSig.identifier, deviceTag:mainSig.deviceTag, attestations:Object.keys(attestationsResult)});

      return Helpers.clone({
        attested: true,

        issuedAt: challenge.data.iat,
        signedAt: mainSig.signedAt,
        verifiedAt: verifyResult.verifiedAt,

        expires: verifyResult.expires,
        secure: verifyResult.secure,

        identifier: mainSig.identifier,
        identityDomain: mainSig.identityDomain,
        lookupCode: mainSig.lookupCode,
        actor: mainSig.actor,
        actorIdentityDomain: mainSig.actorIdentityDomain,
        actorLookupCode: mainSig.actorLookupCode,
        groups: mainSig.groups,

        attestations: attestationsResult,

        deviceName: mainSig.deviceName,
        deviceTag: mainSig.deviceTag,
        keys: mainSig.keys
      });

    } else if (verifyResult === null) {
      config.logger?.info?.('Verification failed - request expired', {identifier:challenge.identity.identifier, iat:parseInt(challenge.data.iat, 10)});
      return null;

    } else {
      config.logger?.info?.('Verification failed', {identifier:challenge.identity.identifier});
      return false;

    }
  };

  return ChallengeResponseFlow.perform('attest', options, {onChallenge, onResponse}, config);
};
