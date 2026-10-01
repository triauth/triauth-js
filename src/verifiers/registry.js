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
 * @file
 * Holds information about registered digital signature verifiers.
 * Each public key stored in the identity records in the DNS may be associated with a type of verifier that is to be used with it (e.g., `type=es256`).
 */

const _verifiers = {};

/**
 * Registers a verifier class that should be used for keys of the given type.
 *
 * @param type {string} - the type of key, e.g., 'es256'
 * @param verifierClass {Function} - a class descending from `Triauth.Verifiers.Base` that should handle the keys of given type
 */
export function register(type, verifierClass) {
  _verifiers[type] = verifierClass;
}

/**
 * Returns a verifier registered for the given key type.
 *
 * @param type {string} - the type of the key for which verifier is being looked for
 * @returns {*} A class that descends from `Triauth.Verifiers.Base` (with a static `fromPublishableKey` factory) that is responsible for handling given keys, or undefined if not found.
 */
export function get(type) {
  return _verifiers[type];
}

/**
 * Returns a list of registered verifier's types
 *
 * @returns {string[]}
 */
export function list() {
  return Object.keys(_verifiers);
}
