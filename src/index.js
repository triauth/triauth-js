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
 * Entry point of triauth-js, assembling the `Triauth` namespace.
 *
 * Example use:
 *
 * ```js
 * import * as Triauth from 'triauth'
 * import { authenticate, Resolvers } from 'triauth'
 * ```
 *
 * @namespace Triauth
 *
 * @borrows Triauth.Api.Authentication.authenticate as authenticate
 * @borrows Triauth.Api.Authentication.check as check
 * @borrows Triauth.Api.Authentication.ping as ping
 * @borrows Triauth.Api.Attestation.attest as attest
 * @borrows Triauth.Api.Identity.whois as whois
 * @borrows Triauth.Api.Signing.sign as sign
 * @borrows Triauth.Api.Signing.stamp as stamp
 * @borrows Triauth.Api.Signing.verify as verify
 * @borrows Triauth.Api.Validation.validate as validate
 */

import { config } from './config.js';
import { Logger } from './logger.js';
import * as Api from './api/index.js';
import * as Resolvers from './resolvers/index.js';

// Top-level classes and namespaces
export { Helpers } from './helpers.js';
export { Logger } from './logger.js';
export { Validator } from './validator.js';
export { TriauthError as Error } from './error.js';
export { Identity } from './identity.js';
export { IdentityKeys } from './identity_keys.js';
export { IdentityIncludes } from './identity_includes.js';
export { IdentityDomain } from './identity_domain.js';
export { AuthenticationEndpoint } from './authentication_endpoint.js';
export { Challenge } from './challenge.js';
export { Response } from './response.js';
export { Signature } from './signature.js';
export { MultiSignature } from './multi_signature.js';
export { ChallengeResponseFlow } from './challenge_response_flow.js';
export { config } from './config.js';
export { LIMITS } from './protocol.js';

export * as Resolvers from './resolvers/index.js';
export * as Verifiers from './verifiers/index.js';
export * as Api from './api/index.js';

// Top-level API method aliases
export const authenticate = Api.Authentication.authenticate;
export const check        = Api.Authentication.check;
export const ping         = Api.Authentication.ping;
export const attest       = Api.Attestation.attest;
export const whois        = Api.Identity.whois;
export const validate     = Api.Validation.validate;
export const sign         = Api.Signing.sign;
export const stamp        = Api.Signing.stamp;
export const verify       = Api.Signing.verify;

// Initialize defaults that depend on constructed instances

config.logger ??= new Logger(console, {
  logLevel: 'error',
  prefix: '[triauth]'
});

config.resolver ??= new Resolvers.MultiResolver(
  [
    new Resolvers.Cloudflare({retries: 1, timeout: 4e3}),
    new Resolvers.Google({retries: 1, timeout: 4e3}),
    new Resolvers.NodeDns({timeout: 4e3})
  ],
  {maxFailures: 1, timeout: 8.5e3}
);

// Web browser specific - dispatch a `triauth:ready` event when loaded
if (typeof window !== 'undefined') {
  const readyEvent = new CustomEvent('triauth:ready');
  window.dispatchEvent(readyEvent);
}
