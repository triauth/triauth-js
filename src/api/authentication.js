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
 * Methods related to authentication that are a part of the official triauth-js API.
 *
 * @namespace Authentication
 * @memberof Triauth.Api
 */

import { KNOWN_CONFIG_KEYS } from '../config.js';
import { TriauthError } from '../error.js';
import { Helpers } from '../helpers.js';
import { Validator } from '../validator.js';
import { Identity } from '../identity.js';
import { ChallengeResponseFlow } from '../challenge_response_flow.js';

/**
 * The authenticate method performs a challenge-response authentication based on the triauth protocol.
 * Successful authentication confirms that the user is in control of the provided identifier, and may be e.g., logged in to your website with it.
 *
 * The authentication is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
 *
 * **1. Request**
 *
 * At first, you need to call the `Triauth.authenticate` method with the `identifier` option set to the user provided personal identifier (lowercase string),
 * a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
 * and an optional `ext` option (object) listing the [protocol extensions](#protocol-extensions) that you wish to use.
 *
 * In return, you will receive an object with the `challenge` (string) and `redirectUrl` (string).
 * You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let result = await Triauth.authenticate({identifier, callbackUrl, ext?});
 * // returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
 * // returns {error:{code, message}} when the input is invalid, DNS resolution fails, or the domain is not configured for triauth
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.authenticate(
 *   {
 *     identifier: 'john@triauthdemo.org',
 *     callbackUrl: 'https://example.com/triauth-callback'
 *   }
 * );
 * // {
 * //   challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJhdXRoIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJTSWRJaXZRRTVJbkhHQmFUWGhDb0UxMG8iLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MX0',
 * //   redirectUrl: 'https://auth.triauthdemo.org/auth.html#?challenge=eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJhdXRoIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJTSWRJaXZRRTVJbkhHQmFUWGhDb0UxMG8iLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MX0'
 * // }
 * ```
 *
 * **2. Redirect**
 *
 * Once the user's web browser is redirected to the `redirectUrl`, they will be taken to the Triauth Authenticator web application, where they can approve or reject the authentication request.
 *
 * If the user approves the authentication request, Triauth Authenticator signs the challenge using one or more private keys that are available to it, and for which matching public keys may be obtained from the identity records, associated with the user's `identifier`, stored in the DNS.
 * It then redirects the web browser to the `callbackUrl`, by default using a `HTTP GET` method, and passes the signature, together with optional additional data, inside the `response` URL parameter.
 *
 * If the user declines the authentication request, the Triauth Authenticator sends `false` as the `response`, which `Triauth.authenticate` reports as error 403.
 *
 * **3. Verify**
 *
 * After the user approves the authentication request, Triauth Authenticator redirects the web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes a response in the `response` URL parameter.
 * The callback method that is used to pass the response to the client application can be configured with [callbackMethod extension](#protocol-extensions).
 *
 * Once you extract the `response` (string), you should pass it to the `Triauth.authenticate` function together with the previously stored `challenge` (string) to obtain authentication result.
 * If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`.
 *
 * > [!WARNING]
 * > **Invalidate the challenge after every authentication attempt.**
 * > Upon authentication attempt, remove, invalidate, or forget the associated `challenge` that was stored in the user's session or your local database,
 * > so that it cannot be re-used in replay attacks.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let authenticationResult = await Triauth.authenticate({challenge, response});
 * // returns {authenticated:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, publicProfile, groups, keys, deviceName, deviceTag, ext} upon successful authentication
 * // returns {error:{code, message}} upon failed authentication
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.authenticate(
 *   {
 *    challenge:'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJhdXRoIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJTSWRJaXZRRTVJbkhHQmFUWGhDb0UxMG8iLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MX0',
 *    response:'|auth;john@triauthdemo.org;;https://example.com/;v1;1787224766683;;;S8lEY3KOYs9gsSpCJ8YnbnKHVCJcT0dXRREZCAgfIR_3dqkW3S9eUcfQZc6q2HD2sy56LwndOoSbcGyO2ZbUnw|'
 *   }
 * );
 * //
 * // {
 * //   "authenticated": true,
 * //   "issuedAt": 1787224748449,
 * //   "signedAt": 1787224766683,
 * //   "verifiedAt": 1787224766784,
 * //   "expires": 1787226566784,
 * //   "secure": true,
 * //   "identifier": "john@triauthdemo.org",
 * //   "identityDomain": "john._at.triauthdemo.org",
 * //   "lookupCode": "",
 * //   "actor": "",
 * //   "actorIdentityDomain": "",
 * //   "actorLookupCode": "",
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
 * //   "ext": {}
 * // }
 * //
 * ```
 *
 * > [!IMPORTANT]
 * > Upon successful authentication, the authentication result object will have the `authenticated` property set to `true`, and the authenticated personal identifier available in the `identifier` property.
 * >
 * > Upon failed authentication, the `authenticated` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
 *
 * @see Documentation and usage examples on GitHub - {@link https://github.com/triauth/triauth-js#user-content-triauth-authenticate}
 *
 * @param options {object}
 *
 * @param [options.identifier] {string} - (stage 1) the user provided identifier that is being authenticated
 * @param [options.callbackUrl] {string} - (stage 1) an application provided URL to which the user's web browser should be redirected with the response
 * @param [options.ext] {object} - (stage 1) an optional object of protocol extensions to use (e.g., `{signToken:true}`)
 *
 * @param [options.challenge] {string} - (stage 3) a challenge as it was returned by the method after stage 1 call
 * @param [options.response] {string} - (stage 3) a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension)
 *
 * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {challenge: string, redirectUrl: string}
 *   | {authenticated: true, issuedAt: number, signedAt: number, verifiedAt: number, expires: (number|undefined), secure: boolean, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, publicProfile: object, groups: Array<string>, deviceName: string, deviceTag: string, keys: Array<object>, ext: object}
 *   | {error: {code: number, message: string}}
 * >} A promise that resolves to one of the following:
 * - `{challenge: string, redirectUrl: string}`: Returned during stage 1 when a challenge is generated. The `challenge` should be stored and the user should be redirected to the `redirectUrl`.
 * - `{authenticated: true, issuedAt: number, signedAt: number, verifiedAt: number, expires?: number, secure: boolean, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, publicProfile: object, groups: Array<string>, deviceName: string, deviceTag: string, keys: Array<object>, ext: object}`: Returned during stage 3 upon successful authentication. Includes:
 *   - `authenticated` (true): Indicates authentication was successful.
 *   - `issuedAt` (number): Unix timestamp on **your** server's clock at which you issued the challenge in stage 1 — the start of the flow's timeline.
 *   - `signedAt` (number): Unix timestamp on the **user's device** clock at which the authenticator signed the response. Verified to fall within the freshness window, but device-asserted — do not treat it as a trusted wall clock; prefer `issuedAt`/`verifiedAt` for authoritative timing.
 *   - `verifiedAt` (number): Unix timestamp on **your** server's clock at which this library confirmed the signature — the authoritative "when did this happen" anchor.
 *   - `expires` (number, optional): Unix timestamp at which the DNS records backing the verified keys expire (the earliest TTL expiry) and re-verification via `Triauth.check`/`Triauth.ping` is due. This is **not** a hard session lifetime: it is a hint for when to re-check, not a license to keep a session open without re-checking — a long DNS TTL otherwise delays the effect of a key revocation by the full TTL. May be `undefined` when DNS records carry no TTL (e.g., under the NodeDns resolver); in that case apply your own minimum/maximum re-check interval. Do not perform arithmetic against it without first handling the `undefined` case.
 *   - `secure` (boolean): Indicates whether DNSSEC was used for strong cryptographic integrity. `true` only when the domain's `triauth` configuration record and every well-formed record of the identity answer (for delegated authentication, of both the subject's and the delegate's answers) were DNSSEC-validated; a single non-validated identity record degrades it.
 *   - `identifier` (string): The authenticated user's identifier.
 *   - `identityDomain` (string): The domain name under which identity records are stored for this identifier (the subject's, for delegated authentication).
 *   - `lookupCode` (string): The lookup code the identifier's domain derivation consumed (under `mode=private` the identity records live at a code-derived label); `''` where none was. The same semi-secret that suffixes the `deviceTag` - handle it identically; it feeds `Triauth.whois({identifier, lookupCode})`.
 *   - `actor` (string): For delegated authentication (an `include` identity record granting a delegate the right to act on behalf of the identifier), the identifier of the delegate that actually performed the authentication; `''` for direct authentication (the user's own keys).
 *   - `actorIdentityDomain` (string): For delegated authentication, the domain name under which the delegate's identity records are stored — the records the signing keys were read from; `''` for direct authentication.
 *   - `actorLookupCode` (string): The lookup code the delegate's domain derivation consumed; `''` where none was, and always `''` for direct authentication.
 *   - `publicProfile` (object): Public details of the authenticated identity as read from identity records (e.g., 'name' and/or 'initials').
 *   - `groups` (array): Fully-qualified group names the identity's records claim membership in (e.g., `['admins@triauthdemo.org']`), sorted and deduplicated; `[]` when none are published. The claim is made by the identity's DNS zone — treat it as authoritative only where that zone's operator is the authorization authority, compare entries only against other group names (never against identifiers), and escape before rendering. For delegated authentication these are the subject's groups, never the delegate's.
 *   - `deviceName` (string): User-given, public name of the device that was used for authentication, as read from the DNS key records (e.g., `"mylaptop"`).
 *   - `deviceTag` (string): Unique identifier of the device (and, for delegated authentication, the delegation) used; under `mode=private` it also carries the lookup code. Store it verbatim and pass it to `Triauth.check`.
 *   - `keys` (array): Public keys that were considered and/or used during verification.
 *   - `ext` (object): Data returned by the authenticator application for the requested protocol extensions. Always present - `{}` when no extension data was returned (a malformed `ext` is discarded with a logged warning and also yields `{}`).
 * - `{error: {code: number, message: string}}`: Returned during stage 1 or stage 3 when authentication fails, includes an error object with code and message.
 */
export const authenticate = async(options, config = {}) => {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  // No challenge processing needed here
  const onChallenge = async () => {};

  const onResponse = async ({challenge, response}) => {

    // Verify the response against the challenge
    const result = await ChallengeResponseFlow.verifyChallengeResponse('auth', challenge.challengeString, challenge, response, config.authTimeout, config);

    // Propagate the failure signals unchanged: null -> 402 (expired), false -> 401 (invalid).
    if (!result) {
      return result;
    }

    const {sig, verifyResult} = result;

    config.logger?.info?.('Verification successful', {identifier:sig.identifier, deviceTag:sig.deviceTag});

    const receivedExt = sig.signedMetadata?.ext;
    const receivedExtValid = receivedExt && Validator.validateExt(receivedExt).errors.length === 0;

    // Auxiliary data tolerance: a malformed `ext` does NOT block authentication (a buggy or
    // forward-incompatible authenticator must not lock the user out). Coerce to {} silently
    // for the caller, but log a warning so operators that care can plug a custom logger.
    if (receivedExt && !receivedExtValid) {
      config.logger?.warn?.('Discarding malformed signedMetadata.ext', {identifier:sig.identifier, deviceTag:sig.deviceTag});
    }

    return Helpers.clone({
      authenticated: true,
      issuedAt: challenge.data.iat,
      signedAt: sig.signedAt,
      verifiedAt: verifyResult.verifiedAt,
      expires: verifyResult.expires,
      secure: verifyResult.secure,
      identifier: sig.identifier,
      identityDomain: sig.identityDomain,
      lookupCode: sig.lookupCode,
      actor: sig.actor,
      actorIdentityDomain: sig.actorIdentityDomain,
      actorLookupCode: sig.actorLookupCode,
      publicProfile: sig.publicProfile,
      groups: sig.groups,
      deviceName: sig.deviceName,
      deviceTag: sig.deviceTag,
      keys: sig.keys,
      ext: receivedExtValid ? receivedExt : {}
    });
  };

  return ChallengeResponseFlow.perform('auth', options, {onChallenge, onResponse}, config);
};

/**
 * The check method verifies that the user's public keys and delegation associated with the given `deviceTag` are still present and unchanged in the Domain Name System (DNS), and that the user may remain authenticated.
 * It also returns the user's current group memberships, allowing the application to detect membership changes.
 *
 * A key may be removed from the DNS by the user or their organization when, for example, an associated device is stolen, decommissioned, or the user leaves the organization.
 * Similarly, a delegation may be revoked when the user no longer allows a particular actor to act on their behalf.
 * Group membership changes may affect the user's access to your application features or resources.
 *
 * This method may be periodically called with the `identifier` and `deviceTag` as returned by the `Triauth.authenticate` method.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let checkResult = await Triauth.check({identifier, deviceTag});
 * // returns {valid:true, secure, expires, groups} keys are still present in the DNS; `expires` (when a number) is the unix timestamp until which the check method need not be called again; `expires` may be undefined when DNS records carry no TTL (e.g., under the NodeDns resolver) - in that case apply your own minimum re-check interval; `groups` is the identity's current membership list - replace any session-cached groups with it on every check
 * // returns {valid:false, reason} when the device may no longer remain authenticated and should be logged out; reason is 'revoked' (the device's keys are no longer published) or 'unresolved' (the identity itself no longer resolves)
 * // returns {error} when status cannot be determined at the moment due to some error
 *
 * ```
 *
 * > [!IMPORTANT]
 * > Accept only when `valid === true` (the device keys are still present). The `reason` on a `{valid:false}` result is diagnostic only - both `'revoked'` and `'unresolved'` mean the user should be logged out.
 *
 * Example:
 *
 * ```javascript
 * await Triauth.check(
 *   {
 *     identifier: "john@triauthdemo.org",
 *     deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ"
 *   }
 * );
 * //
 * // {
 * //   "valid": true,
 * //   "secure": true,
 * //   "expires": 1737547197157,
 * //   "groups": []
 * // }
 * //
 * ```
 *
 * @param options {object}
 * @param options.identifier {string} - identifier to be verified
 * @param options.deviceTag {string} - the `deviceTag` as returned by a challenge-response method's result
 * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {valid: true, secure: boolean, expires: (number|undefined), groups: Array<string>}
 *   | {valid: false, reason: 'revoked'|'unresolved'}
 *   | {error: {code: number, message: string}}
 * >} A promise that resolves to one of the following:
 * - `{valid: true, secure: boolean, expires?: number, groups: Array<string>}`: Indicates that the user may remain authenticated. The `secure` property is `true` only when the domain's `triauth` configuration record and every well-formed record of the identity answer (for composite device tags, of both identities' answers) were DNSSEC-validated. The `expires` property, when a number, is the Unix timestamp until which the `check` method need not be called again; it is `undefined` when the DNS records carry no TTL (e.g., under the NodeDns resolver) - in that case apply your own minimum re-check interval. The `groups` property carries the identity's **current** fully-qualified group names — replace any session-cached groups with this list on every check, so membership changes take effect within the same bound as key revocation.
 * - `{valid: false, reason: 'revoked'|'unresolved'}`: Indicates that the device may no longer remain authenticated and should be logged out (call `Triauth.authenticate` again to re-authenticate). The `reason` is diagnostic only: `'revoked'` - the device's keys are no longer published in the DNS; `'unresolved'` - the identity itself (or, for a delegated `deviceTag`, the actor's identity) no longer resolves (e.g., the domain is no longer configured for triauth, or has no identity records).
 * - `{error: {code: number, message:string}}`: Indicates that there was some problem, and the status cannot be determined at the moment, including an `error` message with more details.
 */
export const check = async (options, config = {}) => {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  config.logger?.info?.('Processing Triauth.check');
  const ts = Helpers.now();

  try {

    // Ensure only recognized options are present to help avoid misspellings.
    if (!Helpers.hasOnlyKnownProperties(options, ['identifier', 'deviceTag'])) {
      throw new TriauthError(102, 'Unrecognized function argument');
    }

    // Reject config overrides carrying unknown keys
    if (!Helpers.hasOnlyKnownProperties(config, KNOWN_CONFIG_KEYS)) {
      throw new TriauthError(103, 'Unrecognized configuration key');
    }

    const identifier = options.identifier;
    const deviceTag = options.deviceTag;

    config.logger?.info?.('Request parameters:', {identifier, deviceTag});

    if (typeof identifier !== 'string' || typeof deviceTag !== 'string') {
      throw new TriauthError(101, 'Invalid or missing function arguments');
    }

    // Parse the composite deviceTag
    const parts = deviceTag.split(':');
    const [subjectComponent, subjectLookupCode] = parts[0].split('~');

    const identity = new Identity(identifier, {lookupCode:subjectLookupCode}, config);

    await identity.resolve();

    if (!identity.resolved) {
      config.logger?.debug?.('Check failed', {reason: 'unresolved', identifier, deviceTag});
      return { valid: false, reason: 'unresolved' };
    }

    // There are two types of deviceTags:
    // - 'direct' ones that directly match the user's device (keyGroup),
    // - 'delegated' ones that were produced by delegated authentication (when `include` was followed), that have ':' in them

    let secure = null;
    let expires = null;

    // 'direct' deviceTags don't have ':'
    if (parts.length === 1) {

      // Attempt direct match to one of keyGroup tags
      const keyGroup = identity.keys.findByTag(subjectComponent);

      if (!keyGroup) {
        config.logger?.debug?.('Check failed - deviceTag revoked', {identifier, deviceTag});
        return { valid: false, reason: 'revoked' };
      }

      secure = identity.secure;
      expires = Helpers.earliest(identity.authenticationEndpoint.expires, keyGroup.expires);

    // 'delegated' deviceTag
    } else {

      // Decompose the deviceTag for delegated/actor flows into the `include` statement tag, actor's identifier,
      // and actor's device tag; the device component resolves in the actor's zone, so it carries the actor's salt
      const includeTag = subjectComponent;
      const [, actorIdentifier, actorDeviceTagComponent, rest] = parts;
      const [actorDeviceTag, actorLookupCode] = (actorDeviceTagComponent ?? '').split('~');

      // Validate the device tag format - return {valid: false} as with any other invalid deviceTag
      if (
        !includeTag ||
        !Validator.validateIdentifier(actorIdentifier).valid ||
        !actorDeviceTag ||
        rest !== undefined
      ) {
        return { valid: false, reason: 'revoked' };
      }

      const actorIdentity = new Identity(actorIdentifier, {lookupCode:actorLookupCode}, config);

      // Verify that there is a matching include statement
      const includeStatement = await identity.includes.find(actorIdentity, includeTag, null);

      if (!includeStatement) {
        config.logger?.debug?.('Check failed - include statement unresolved or revoked', {identifier, deviceTag, includeTag});
        return { valid: false, reason: includeStatement === false ? 'unresolved' : 'revoked' };
      }

      // Finally, ensure that the actor's deviceTag matches one of actor's keyGroups
      const actorKeyGroup = actorIdentity.keys.findByTag(actorDeviceTag);

      if (!actorKeyGroup) {
        config.logger?.debug?.('Check failed - actor deviceTag revoked', {actorIdentifier, actorDeviceTag});
        return { valid: false, reason: 'revoked' };
      }

      secure = identity.secure && actorIdentity.secure;
      expires = Helpers.earliest(
        Helpers.earliest(identity.authenticationEndpoint.expires, includeStatement.expires),
        Helpers.earliest(actorIdentity.authenticationEndpoint.expires, actorKeyGroup.expires)
      );
    }

    config.logger?.debug?.('Check successful', {identifier, deviceTag});

    // Enforce config.requireSecure. valid:false (revoked) path stays not gated by design
    ChallengeResponseFlow.assertSecure(secure, config);

    return Helpers.clone({
      valid: true,
      secure,
      expires,
      groups: identity.groups
    });

  } catch (err) {
    return TriauthError.process(err, config);

  } finally {
    config.logger?.info?.('Completed in ' + Math.round(Helpers.now() - ts) + 'ms');

  }
};

/**
 * The `ping` method may be used to re-authenticate the user in background, by obtaining a fresh proof that the user still has access to cryptographic keys.
 * While the `Triauth.check` method ensures only that the keys and the optional delegation used for authentication were not changed or removed from DNS,
 * `Triauth.ping` goes a step further, and requires a fresh, valid signature.
 *
 * Pings typically do not require any interaction from the user, and may be used as one of the signals in Continuous Authentication schemes.
 *
 * > [!NOTE]
 * > **To use this function you must request and obtain a special `pingToken`**<br/>
 * > To do so, provide the `ext:{pingToken:true}` parameter to the `Triauth.authenticate` function during the initial call (i.e., when building the challenge),
 * > and in the authentication result you will receive `ext.pingToken` property (string).
 * > You should keep the `pingToken` value private, and pass it as a `token` parameter in the initial call to the `ping` method.
 * > The token is issued by the authenticator on the device that signed in, and only that device honors it.
 * > A user with several devices holds a different token on each.
 * >
 * > Also, the `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
 * > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
 * > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
 *
 * The ping is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
 *
 * **1. Request**
 *
 * At first, you need to call the `Triauth.ping` method with the `identifier` option set to the user provided personal identifier (lowercase string),
 * a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
 * a `token` (string) option set to the `pingToken` previously obtained via `ext.pingToken` from a `Triauth.authenticate` call,
 * and an optional `ext` option (object) listing the [protocol extensions](#protocol-extensions) that you wish to use.
 *
 * In return, you will receive an object with the `challenge` (string) and `redirectUrl` (string).
 * You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let result = await Triauth.ping({identifier, callbackUrl, token, ext});
 * // returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
 * // returns {error} on error
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 *
 * await Triauth.ping(
 *   {
 *     identifier:'john@triauthdemo.org',
 *     callbackUrl:'https://example.com/callback',
 *     token:':SvUj6xL4PhtYnNEboKbJ85WW'
 *   }
 * );
 * //
 * // {
 * //   challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FsbGJhY2siLCJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoicWFvU1JnZlVnREpwZG5LX1FnQTd4SG9ZIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjF9',
 * //   redirectUrl: 'https://auth.triauthdemo.org/ping.html#?challenge=eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FsbGJhY2siLCJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoicWFvU1JnZlVnREpwZG5LX1FnQTd4SG9ZIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjF9&token=:DFB4aHZqJ6zpbq8QVqQfTM4rsCkuCuyBqokCaImZelE'
 * // }
 * //
 * ```
 *
 * **2. Redirect**
 *
 * Once the user's web browser is redirected to the `redirectUrl`, and assuming that the `token` is valid, the Triauth Authenticator web application will immediately respond to the `callbackUrl`.
 *
 * **3. Verify**
 *
 * The Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes a fresh signature in the `response` URL parameter.
 * The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
 *
 * Once you extract the `response` (string), you should pass it to the `Triauth.ping` function together with the previously stored `challenge` (string) to obtain ping result.
 * If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`.
 *
 * > [!WARNING]
 * > **Invalidate the challenge after every ping attempt.**
 * > Only ever pass a `challenge` that your application generated and stored server-side (e.g., in the user's session or your database) - never one taken from user-controlled input.
 * > Upon every ping attempt, make sure to remove or invalidate that stored `challenge`, so that a captured `(challenge, response)` pair cannot be re-used in replay attacks within the `pingTimeout` freshness window. This matters especially for ping, which is meant for frequent, unattended background / Continuous Authentication use.
 *
 * Synopsis:
 *
 * ```javascript
 *
 * let pingResult = await Triauth.ping({challenge, response});
 * // returns {pinged:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, deviceName, deviceTag, keys} upon success
 * // returns {error:{code, message}} upon error
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * await Triauth.ping(
 *   {
 *    challenge:'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FsbGJhY2siLCJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoicWFvU1JnZlVnREpwZG5LX1FnQTd4SG9ZIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjF9',
 *    response:'|ping;john@triauthdemo.org;;https://example.com/;v1;1787224751161;;;KalL2ivLz--0voQXL-jBp58650Hj1PIUpe8W4Nfps0HnRdlXMFu6wDUCssE_dr6_BrKRtT508BRXe3228yiA_A|'
 *   }
 * );
 *
 * //
 * // {
 * //   "pinged": true,
 * //   "issuedAt": 1787224748449,
 * //   "signedAt": 1787224751161,
 * //   "verifiedAt": 1787224751262,
 * //   "expires": 1787226551262,
 * //   "secure": true,
 * //   "identifier": "john@triauthdemo.org",
 * //   "identityDomain": "john._at.triauthdemo.org",
 * //   "lookupCode": "",
 * //   "actor": "",
 * //   "actorIdentityDomain": "",
 * //   "actorLookupCode": "",
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
 * //   ]
 * // }
 * //
 * ```
 *
 * > [!IMPORTANT]
 * > Upon successful pinging, the result object will have the `pinged` property set to `true`.
 * > You can also check that the returned `identifier`, `deviceTag`, and `secure` values match your expectations.
 * > Note that `expires` may be undefined or arbitrarily low - apply your own minimum re-ping interval, as described for `Triauth.authenticate`.
 * >
 * > Upon failed pinging, the `pinged` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
 *
 * > [!NOTE]
 * > Users may configure a different set of cryptographic keys (that still belongs to the same device) for the purpose of responding to ping requests.
 * > You can assume that the `deviceTag` in `ping` result should be the same as in the original `Triauth.authenticate` response, but the combination of verified/skipped keys may differ.
 *
 * @param options {object}
 *
 * @param [options.identifier] {string} - (stage 1) the user provided identifier
 * @param [options.callbackUrl] {string} - (stage 1) an application provided URL to which the user's web browser should be redirected with the response
 * @param [options.token] {string} - (stage 1, required) the `pingToken` previously obtained via `ext.pingToken` from a `Triauth.authenticate` call; a stage-1 request without it returns error 226
 * @param [options.ext] {object} - (stage 1) an optional object of protocol extensions to use (e.g., `{callbackMethod:'GET'}`)
 *
 * @param [options.challenge] {string} - (stage 3) a challenge as it was returned by the method after stage 1 call
 * @param [options.response] {string} - (stage 3) a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension)
 *
 * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
 *
 * @returns {Promise<
 *     {challenge: string, redirectUrl: string}
 *   | {pinged: true, issuedAt: number, signedAt: number, verifiedAt: number, expires: (number|undefined), secure: boolean, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, groups: Array<string>, deviceName: string, deviceTag: string, keys: Array<object>}
 *   | {error: {code: number, message: string}}
 * >}
 */
export const ping = async(options, config = {}) => {
  config = Helpers.mergeConfig(config);
  config.logger = config.logger?.spawn?.(config.cid) || config.logger;

  // No challenge processing needed here
  const onChallenge = async () => {};

  const onResponse = async ({challenge, response}) => {

    // Verify the response against the challenge
    const result = await ChallengeResponseFlow.verifyChallengeResponse('ping', challenge.challengeString, challenge, response, config.pingTimeout, config);

    // Propagate the failure signals unchanged: null -> 402 (expired), false -> 401 (invalid).
    if (!result) {
      return result;
    }

    const {sig, verifyResult} = result;

    config.logger?.info?.('Verification successful', {identifier:sig.identifier, deviceTag:sig.deviceTag});

    return Helpers.clone({
      pinged: true,

      issuedAt: challenge.data.iat,
      signedAt: sig.signedAt,
      verifiedAt: verifyResult.verifiedAt,

      expires: verifyResult.expires,
      secure: verifyResult.secure,

      identifier: sig.identifier,
      identityDomain: sig.identityDomain,
      lookupCode: sig.lookupCode,
      actor: sig.actor,
      actorIdentityDomain: sig.actorIdentityDomain,
      actorLookupCode: sig.actorLookupCode,
      groups: sig.groups,

      deviceName: sig.deviceName,
      deviceTag: sig.deviceTag,
      keys: sig.keys
    });
  };

  return ChallengeResponseFlow.perform('ping', options, {onChallenge, onResponse}, config);
};
