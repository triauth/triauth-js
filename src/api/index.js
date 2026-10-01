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
 * The API namespace holds methods that are a part of the official triauth-js API.
 *
 * Every API method is also aliased at the top level, so `Triauth.Api.Authentication.authenticate` and
 * `Triauth.authenticate` are the same function.
 *
 * @namespace Api
 * @memberof Triauth
 */

export * as Authentication from './authentication.js';
export * as Attestation from './attestation.js';
export * as Identity from './identity.js';
export * as Signing from './signing.js';
export * as Validation from './validation.js';
