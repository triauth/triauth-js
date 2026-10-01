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
import { Identity } from './identity.js';
import { VERSION } from './protocol.js';

/**
 * Represents an authentication request (challenge) that is sent from client application to the Triauth Authenticator.
 *
 * @class
 * @memberof Triauth
 */
export class Challenge {

  /**
   * Recreates the Challenge from the given challenge.
   *
   * @param challengeString {string} - a challenge, typically as stored during the stage 1 of challenge-response flow.
   * @param [config={}] {object} - optional overrides for the global Triauth.config settings
   *
   * @returns {Challenge}
   * @throws {Error} upon problems with deserialization of the challenge or the format of personal identifier encoded within
   */
  static fromString(challengeString, config={}) {
    const decodedChallenge = Helpers.base64UrlToString(challengeString);
    const challengeData = Helpers.safeParseJson(decodedChallenge);
    const identity = new Identity(challengeData.identifier, {}, config);

    const retval = new Challenge(identity, challengeData, config);
    retval.challengeString = challengeString;

    return retval;
  }

  /**
   * Builds a new Challenge and populates the required request data fields with the default values,
   * unless a value for them was provided through the data argument.
   *
   * @param type {string} - the type of request associated with this challenge, e.g., 'auth', 'sign', etc.
   * @param identity {Identity} - identity for which the authentication request is being built.
   * @param data {Object} - data to include in the authentication request, may override the defaults
   * @param [config={}] {object} - optional overrides for the global Triauth.config settings
   *
   * @returns {Challenge}
   */
  static build(type, identity, data, config = {}) {
    config = Helpers.mergeConfig(config);

    // Populate the data fields that must be present in the triauth authentication request with default values
    data = Object.assign({}, data, {
      type,
      identifier: identity.identifier, // the Identifier the request is addressed to
      nonce: Helpers.randomString(24, config), // cryptographic nonce
      iat: Date.now(), // timestamp of when authentication request was created
      ver: VERSION
    })

    return new Challenge(identity, data, config);
  }

  /**
   * Constructs a new instance of Challenge for the given identity and challenge data.
   *
   * Use the `build` factory to mint a fresh challenge, or `fromString` to re-hydrate a serialized
   * one; this constructor stores what it is given and validates nothing on its own.
   *
   * @param identity {Identity} - The Identity the challenge is addressed to.
   * @param [data={}] {object} - The challenge's wire fields - `type`, `identifier`, `nonce`, `iat` and
   *                             `ver`, plus any per-flow additions such as `msg`, `attest` or `attachments`.
   * @param [config={}] {object} - optional overrides for the global Triauth.config settings
   */
  constructor(identity, data = {}, config = {}) {
    this.identity = identity;
    this.data = data;
    this.config = Helpers.mergeConfig(config);

    // Populated by Challenge.fromString when re-hydrating a serialized challenge; left undefined
    // for freshly built challenges (use toString() to serialize on demand).
    /** @type {string|undefined} */
    this.challengeString = undefined;
  }

  /**
   * Serializes this authentication request into a string that may be used as a challenge.
   *
   * @returns {string} a challenge which can be included in the redirect URL
   */
  toString() {
    const challengeJson = JSON.stringify(this.data);
    return Helpers.stringToBase64Url(challengeJson);
  }

}
