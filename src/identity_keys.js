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
import { Validator } from './validator.js';
import { LIMITS, FLOWS, FLOWS_USE_REGEXP } from './protocol.js';
import * as Verifiers from './verifiers/index.js';

/**
 * Holds information about devices and their public keys that belong to the identifier, as extracted from identity records.
 *
 * @class
 * @memberof Triauth
 */
export class IdentityKeys {

  /**
   * Constructs a new, empty instance of IdentityKeys; key groups are populated through `add`.
   *
   * @param [config={}] {object} - Optional overrides for the global Triauth.config settings
   */
  constructor(config = {}) {
    this.config = Helpers.mergeConfig(config);

    /**
     * The key groups (devices) published for the identity, keyed by device name.
     * Only groups marked `valid:true` can be used; a tainted group can never become valid.
     * @type {Object<string, {keyCount: number, keys: Array<{value: string, options: object}>, expires?: number, tainted?: boolean, valid?: boolean, tag?: string}>}
     */
    this.keyGroups = Object.create(null);

    /**
     * The total number of valid key groups (devices).
     * @type {number}
     */
    this.count = 0;
  }

  /**
   * Adds a key to the correct group of identity keys
   *
   * @param keyData {string} - the value of the key as visible in the identity record that includes the prefix with device name and key index
   * @param [options={}] {object} - the key options as specified in the identity record; recognized critical options are
   *        `type` (a registered verifier type), `use` (comma-separated list of allowed modes),
   *        and `uv=required` (demand user verification; valid only on `webauthn-*` typed keys) - any other non-`x-` option or value taints the keyGroup
   * @param [keyMetadata={}] {object} - the metadata about the key record, as passed from the DNS resolver
   * @returns {Promise<boolean>} true when key was successfully added, false if there are problems with the key structure (e.g., invalid group index)
   */
  async add(keyData, options = {}, keyMetadata = {}) {
    // Work on a private copy of `options`
    options = Object.assign({}, options);

    const matchData = keyData.match(/^(?<deviceName>[a-z0-9-]{1,20})\[(?<keyIdx>[0-9]{1,6})\/(?<keyCount>[0-9]{1,6})\]:(?<keyVal>\S+)$/);

    if (!matchData) {
      this.config.logger?.debug?.('Ignoring key due to unrecognized syntax');
      return false;
    }

    // At this point we know that deviceName conforms to the required syntax, but everything else needs additional validation.
    // We intentionally let through things like non-base64-url keyVals, as when invalid, they should taint the whole keyGroup.

    const deviceName = matchData.groups.deviceName;

    // Map leading-zero forms (e.g., "01") to literal 0 so they fail the downstream range check
    // and taint the whole keyGroup, rather than being silently skipped at the regex stage.
    // Skipping would leave the device's other published keys potentially usable, which we don't
    // want when any single record on that device looks malformed.
    const keyIdx = matchData.groups.keyIdx[0] === '0' ? 0 : parseInt(matchData.groups.keyIdx, 10);
    const keyCount = matchData.groups.keyCount[0] === '0' ? 0 : parseInt(matchData.groups.keyCount, 10);
    const keyVal = matchData.groups.keyVal;

    const {maxDevices, maxKeysPerDevice} = LIMITS;

    // Make sure device name conforms to the requirements
    if (!Validator.validateDeviceName(deviceName).valid) {
      this.config.logger?.debug?.(`Ignoring key due to invalid device name`);
      return false;
    }

    // Make sure we are under the maxDevices limit which is the same as the number of defined keyGroups
    if (!this.keyGroups[deviceName] && Object.keys(this.keyGroups).length >= maxDevices) {
      this.config.logger?.debug?.(`Too many devices defined, ignoring key for device ${deviceName}`);
      return false;
    }

    // Pre-initialize the entry with defaults
    this.keyGroups[deviceName] ||= {keyCount, keys: [], expires: undefined};

    const keyGroup = this.keyGroups[deviceName];

    // Parse options

    // All non-x- prefixed options are critical, and unknown critical options MUST taint the keyGroup
    const optionsSchema = {
      type: Verifiers.list(),
      use: [FLOWS_USE_REGEXP],
      uv: ['required']
    };

    // Set defaults
    options['type'] ??= 'es256';
    options['use'] ??= FLOWS.join(',');

    // Validate options
    let optionsTainted = !Helpers.verifyOptionsSchema(options, optionsSchema);

    // The `uv` (user verification) constraint can only be proven by WebAuthn-backed keys - on any
    // other key type the requirement would be silently unenforceable, so it taints the keyGroup instead.
    if (options['uv'] !== undefined && !/^webauthn-/.test(options['type'])) {
      optionsTainted = true;
    }

    // Catch edge cases, mark keyGroups as tainted, and return false
    if (
      keyGroup.tainted ||
      optionsTainted ||                                   // options are tainted (invalid options)
      (keyCount < 1 || keyCount > maxKeysPerDevice) ||    // there are too many keys per device/keyGroup
      (keyIdx < 1 || keyIdx > keyCount) ||                // key index is mangled - e.g., [6/5]
      keyGroup.keyCount !== keyCount ||                   // number of keys in the group is not consistent across all keys (e.g., laptop[1/10], and then laptop[2/5])
      keyGroup.keys[keyIdx - 1] ||                        // key entry with the given index is doubled (e.g., laptop[1/2]:aaa, laptop[1/2]:bbb)
      keyVal.length > 1024 ||                             // key value must be of sane length
      !Helpers.isBase64UrlString(keyVal)                  // key value must be base64URL encoded
    ) {

      // Mark the keyGroup as tainted, so that it cannot become valid
      keyGroup.tainted = true;

      // If for some reason the keyGroup has been previously marked as valid and counted in, un-validate it
      if (keyGroup.valid) {
        keyGroup.valid = false;
        delete keyGroup.tag;
        this.count -= 1;
      }

      // Return false to let the caller know that the key was not added
      this.config.logger?.debug?.('Key failed validation and tainted all keys for device', {keyData, deviceName});
      return false;
    }

    // At this point key has been validated, so we can continue

    // Store the key in the keyGroup at the appropriate index
    keyGroup.keys[keyIdx - 1] = {
      value: keyVal,
      options
    };

    // The group expiry timestamp is calculated as min of expiry timestamps of individual keys
    // If no key in keyGroup has expires set, the keyGroup.expires stays undefined
    if (keyMetadata.expires && keyMetadata.expires < (keyGroup.expires || Infinity)) {
      keyGroup.expires = keyMetadata.expires;
    }

    const populatedKeyCount = Object.keys(keyGroup.keys).length;

    // If we have all keys from the group, and it was not tainted, we can mark it as valid and calculate its tag
    // The tag takes into account only options that do not start with 'x-'
    if (!keyGroup.tainted && keyGroup.keyCount === populatedKeyCount && populatedKeyCount > 0) {
      keyGroup.valid = true;
      keyGroup.tag = (
        await Helpers.sha256(
          '\x01' + deviceName + '\x1E' + keyGroup.keyCount + '\x02' +
          Object.entries(keyGroup.keys).map(([idx,key]) => [
            idx,
            key.value,
            ...Object.entries(key.options).filter(([k]) => !(k[0] === 'x' && k[1] === '-')).map(([k,v]) => k + '=' + v).sort()
          ].join('\x1E')).join('\x1D')
        )
      );
      this.count += 1;
    }

    return true;
  }

  /**
   * Finds a key group that matches the given tag.
   *
   * @param tag {string} - The device tag to look for, as carried by a signature envelope.
   *
   * @returns {{keyCount: number, keys: Array<{value: string, options: object}>, expires?: number, tainted?: boolean, valid?: boolean, tag?: string}|null}
   *          the matching key group, or null when no valid group carries that tag
   */
  findByTag(tag) {
    for (const keyGroup of Object.values(this.keyGroups)) {
      if (keyGroup.valid && keyGroup.tag === tag) {
        return keyGroup;
      }
    }

    return null;
  }

  /**
   * Verifies that the given signatures are valid for the given message and given key use constraint -
   * i.e., that they were made using private keys for which a matching set of public keys are present
   * in one key group of this identity keys, and such keys are marked for such use.
   *
   * Signatures are verified using verifiers defined under the Triauth.Verifiers namespace, that may be specific
   * for each of the identity keys (as loaded from the DNS), and specified in the key's "type" option. For example,
   * for the identity key visible in DNS as "key BHA...QPDR type=ecdsa", an "ECDSA" - Triauth.Verifiers.Ecdsa verifier will be used.
   *
   * Signatures must match all keys in a key group for the verification to be successful.
   *
   * @param message {string} - The message (envelope payload) for which the signatures are verified.
   * @param signatures {Array<string>} - Crypto signatures (base64url) to attempt to verify against the key group's keys.
   * @param context {{mode: string, webAuthnOrigin: (string|undefined)}} -
   *        Verification context. `mode` (typically the signature type — `auth`/`sign`/`stamp`/`ping`/`attest`) gates which keys are considered via their `use=` option.
   *        Additional fields (e.g., `webAuthnOrigin`) are threaded through to crypto verifiers.
   * @param [signedData={}] {object} - The signature envelope's `signedMetadata`. Threaded to crypto verifiers but not consumed here.
   * @param [unsignedData={}] {object} - The signature envelope's `unsignedMetadata`. Threaded to crypto verifiers (e.g., WebAuthn reads `sig[idx]` from it).
   * @returns {Promise<{valid: true, keys: *, name: string, tag: string, expires: number}|false>}
   *          Returns a promise that resolves to a {valid, keys, name, tag, expires} object when signatures have matched a keys group, false otherwise.
   */
  async verify(message, signatures, context, signedData={}, unsignedData={}) {
    const {mode} = context;

    // this.config.logger?.debug?.('Triauth.IdentityKeys.verify', {message, signatures, context, signedData, unsignedData});

    // Make sure we do not have too many signatures to verify
    const {maxKeysPerSignature} = LIMITS;
    if (signatures.length > maxKeysPerSignature) {
      this.config.logger?.debug?.(`Too many signatures to verify - got ${signatures.length} with a limit of ${maxKeysPerSignature}`);
      return false;
    }

    if (signatures.some((s) => !Helpers.isBase64UrlString(s))) {
      this.config.logger?.debug?.(`Non base64-url encoded signature detected`);
      return false;
    }

    // Attempt to verify each of keyGroups/devices, stop at and return the first matching/verified one
    for (const [name, keyGroup] of Object.entries(this.keyGroups)) {

      // Only take into account key groups that are considered valid, and have not expired.
      // Allow a grace window (the client clock drift allowance doubles as a generous upper bound for
      // in-call processing time) in expiry calculation, so that DNS key records with TTL=0 may still validate.
      if (
        keyGroup.valid !== true ||
        (keyGroup.expires !== undefined && keyGroup.expires + this.config.maximalAllowedClientClockDrift < Date.now())
      ) {
        continue;
      }

      // Prepare a working copy of keys, and add the verified property
      const keys = keyGroup.keys.map((key) => ({value:key.value, options:key.options, verified:false, skipped:false}));

      // Go through each key and each signature looking for a match
      // This by its own has O(n^2) complexity, but should be fine, since the number of keys and signatures is limited.
      for (const [idx, key] of Object.entries(keys)) {

        // Only take into account keys with matching use mode (auth, sign, stamp).
        const use = key.options.use?.split(',');
        if (mode && use && use.indexOf(mode) < 0) {
          key.skipped = true;
          continue;
        }

        // Get the correct crypto verifier for the given key type
        const verifierContext = Object.assign({idx}, context);
        const verifier = await Verifiers.get(key.options.type)?.fromPublishableKey(key.value, key.options, verifierContext);
        if (!verifier) {
          this.config.logger?.debug?.('Could not initialize verifier for key', {key});
          continue;
        }

        // Delegate signature verification to the crypto verifier
        for (const signature of signatures) {
          key.verified ||= await verifier?.verify(message, signature, signedData, unsignedData);
        }

        // If the required key did not match any of the signatures, skip other keys from the keyGroup
        if (key.verified !== true) {
          break;
        }
      }

      const keyGroupKeysMatch = keys.every(k => k.verified === true || k.skipped === true);
      const verifiedKeys = keys.filter(k => k.verified === true);

      if (keys.length > 0 && verifiedKeys.length > 0 && keyGroupKeysMatch) {
        this.config.logger?.debug?.(`Successful verification for deviceName ${name}`, {deviceName:name, keys});
        return {
          valid: true,
          keys,
          name,
          tag: keyGroup.tag,
          expires: keyGroup.expires
        };
      } else {
        this.config.logger?.debug?.(`Failed verification for deviceName ${name}`, {deviceName:name, keys});
      }
    }

    return false;
  }

}
