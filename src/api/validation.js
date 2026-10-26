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
 * Methods related to validation of various objects related to the triauth protocol
 *
 * @namespace Validation
 * @memberof Triauth.Api
 */

import { KNOWN_CONFIG_KEYS } from '../config.js';
import { Helpers } from '../helpers.js';
import { Validator } from '../validator.js';

/**
 * The validate method can be used to perform a basic format validation on the given objects.
 * It is fast, synchronous, and does not perform any DNS requests.
 *
 * Currently, it supports validation of personal identifiers (`identifier`), device names (`deviceName`),
 * group names (`groupName`, the bare name as published in a `groups` record, e.g., `admins`),
 * lookup codes (`lookupCode`, the 16-character code of an identity under a `mode=private` domain),
 * and device tags (`deviceTag`, as reported in results and passed to {@link Triauth.check}).
 * At least one of the supported objects must be provided, and unrecognized (e.g., misspelled)
 * keys are rejected, so that nothing silently passes as valid without being validated.
 *
 * Synopsis:
 *
 * ```javascript
 * let validationResult = Triauth.validate({identifier?, deviceName?, groupName?, lookupCode?, deviceTag?});
 * // returns {valid:true, errors:[]} if all the objects passed validation
 * // returns {valid:false, errors:[{code:..., reason:..., message:...}, ...]} if at least one the objects failed validation
 * // returns {valid:false, errors:[{code:'invalid_arguments', ...}]} when objects is empty or not an object, contains an unrecognized key, or an undefined value
 * // returns {valid:false, errors:[{code:'invalid_config', ...}]} when config contains an unrecognized key or a key set to undefined
 *
 * ```
 *
 * Example:
 *
 * ```javascript
 * Triauth.validate({identifier: 'john@triauthdemo.org'});
 * // {valid: true, errors: []}
 *
 * Triauth.validate({identifier: 'john'});
 * // {valid: false, errors: [{code: 'invalid_identifier', reason: 'invalid_format', message: 'Identifier must include one @ sign'}]}
 *
 * Triauth.validate({groupName: 'admins@example.com'});
 * // {valid: false, errors: [{code: 'invalid_group_name', reason: 'invalid_characters', message: 'Group name must include only letters, numbers, and hyphens'}]}
 *
 * Triauth.validate({lookupCode: 'k7qj3fb9m2wzx0c4'});
 * // {valid: false, errors: [{code: 'invalid_lookup_code', reason: 'invalid', message: 'Invalid lookup code'}]}
 *
 * Triauth.validate({deviceTag: '3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ~K7QJ3FB9M2WZX0C4'});
 * // {valid: true, errors: []}
 * ```
 *
 * > [!NOTE]
 * > `{valid: true}` confirms the *format* only - it is not input sanitization.
 * > Callers must still encode or escape the value for whatever sink it flows into (SQL, shell, file paths, HTML, log lines).
 *
 * @param objects {object} - one or more objects to validate
 * @param [objects.identifier] {string} - an identifier to validate
 * @param [objects.deviceName] {string} - a deviceName to validate
 * @param [objects.groupName] {string} - a bare group name to validate (e.g., `admins`)
 * @param [objects.lookupCode] {string} - a lookup code to validate (e.g., `K7QJ3FB9M2WZX0C4`)
 * @param [objects.deviceTag] {string} - a device tag to validate, plain or composite (e.g., `3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ`)
 * @param [config={}] {object} - optional overrides for the global Triauth.config settings; unrecognized keys are rejected (`invalid_config`)
 *
 * @returns {{valid: boolean, errors: Array<{code: string, reason?: string, message: string}>}}
 *                                          An object with valid property containing the validation result,
 *                                          and the errors property containing an array of errors (if any),
 *                                          in the {code, reason?, message} format.
 */
export const validate = function(objects, config = {}) {

  // `objects` must be a plain object with at least one supported entry,
  // so that e.g. validate(null) or validate({}) cannot pass as valid.
  if (!objects || typeof objects !== 'object' || Array.isArray(objects) || Object.keys(objects).length === 0) {
    return {
      valid: false,
      errors: [{code: 'invalid_arguments', message: 'Invalid or missing function arguments'}]
    };
  }

  // Ensure only recognized objects with defined values are present to help avoid misspellings.
  if (!Helpers.hasOnlyKnownProperties(objects, ['identifier', 'deviceName', 'groupName', 'lookupCode', 'deviceTag'])) {
    return {
      valid: false,
      errors: [{code: 'invalid_arguments', message: 'Unrecognized function argument'}]
    };
  }

  // Reject config overrides carrying unknown keys
  if (!Helpers.hasOnlyKnownProperties(Helpers.mergeConfig(config), KNOWN_CONFIG_KEYS)) {
    return {
      valid: false,
      errors: [{code: 'invalid_config', message: 'Unrecognized configuration key'}]
    };
  }

  const retval = {
    valid: true,
    errors: []
  };

  const keys = Object.keys(objects);

  if (keys.indexOf('identifier') >= 0){
    let vr = Validator.validateIdentifier(objects['identifier']);
    if (!vr.valid) {
      retval.valid = false;
      retval.errors = retval.errors.concat(vr.errors);
    }
  }

  if (keys.indexOf('deviceName') >= 0){
    let vr = Validator.validateDeviceName(objects['deviceName']);
    if (!vr.valid) {
      retval.valid = false;
      retval.errors = retval.errors.concat(vr.errors);
    }
  }

  if (keys.indexOf('groupName') >= 0){
    let vr = Validator.validateGroupName(objects['groupName']);
    if (!vr.valid) {
      retval.valid = false;
      retval.errors = retval.errors.concat(vr.errors);
    }
  }

  if (keys.indexOf('lookupCode') >= 0){
    let vr = Validator.validateLookupCode(objects['lookupCode']);
    if (!vr.valid) {
      retval.valid = false;
      retval.errors = retval.errors.concat(vr.errors);
    }
  }

  if (keys.indexOf('deviceTag') >= 0){
    let vr = Validator.validateDeviceTag(objects['deviceTag']);
    if (!vr.valid) {
      retval.valid = false;
      retval.errors = retval.errors.concat(vr.errors);
    }
  }

  return retval;
};
