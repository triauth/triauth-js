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
 * Constants as defined by the triauth protocol.
 */

// Protocol version, and its token form used in the signature envelope's version slot
export const VERSION = 1;
export const VERSION_TOKEN = 'v' + VERSION;

// Signature envelope wrapper and field delimiter characters
export const WRAPPER = '|';
export const DELIMITER = ';';

// The marker that replaces '@' when deriving an identity domain from an identifier
export const AT_MARKER = '._at.';

// The default mode= and include= for domains that do not specify ones
export const DEFAULT_MODE = 'private';
export const DEFAULT_INCLUDE = 'any';

// Private-mode identity domains label length
export const PRIVATE_LABEL_LENGTH = 10;

// The challenge-response flows: signature envelope `type` slots and key/include `use=` options
export const FLOWS = Object.freeze(['attest', 'auth', 'ping', 'sign', 'stamp']);
export const FLOWS_USE_REGEXP = new RegExp(`^(${FLOWS.join('|')})(,(${FLOWS.join('|')})){0,${FLOWS.length - 1}}$`);

// The `include` record's `scope=` reserved values
export const SCOPE_ANY = 'any';
export const SCOPE_NONE = 'none';

/**
 * Shared validation/parsing limits.
 */
export const LIMITS = Object.freeze({
  identifierBytesize: 120,       // the maximal bytesize of a triauth identifier (`username@domain`)
  domainNameBytesize: 253,       // the maximal bytesize of a DNS name (RFC 1035), bounding every host and domain name read from the wire
  urlBytesize: 2048,             // the maximal bytesize of URLs (e.g., callbackUrl, attachment's sourceUrl, etc.)
  challengeBytesize: 16 * 1024,  // the maximal bytesize of a base64url-encoded challenge string
  signatureBytesize: 16 * 1024,  // the maximal bytesize of a Signature/MultiSignature envelope, also bounds the `response` string returned by the authenticator
  extBytesize: 4 * 1024,         // the maximal bytesize of the JSON-serialized `ext` protocol-extensions object
  messageBytesize: 2 * 1024,     // the maximal bytesize of a message to be signed or stamped
  attachmentsCount: 10,          // the maximal number of attachments accepted by Triauth.sign
  deviceNameBytesize: 20,        // the maximal bytesize of a device name, as visible in the identity records in DNS
  maxDevices: 10,                // the maximal number of devices per user, as visible in the identity records in DNS
  maxKeysPerDevice: 5,           // the maximal number of keys associated with a single device, as visible in the identity records in DNS
  maxIncludes: 50,               // the maximal number of include statements per user, as visible in the identity records in DNS
  maxGroups: 200,                // the maximal number of group names per user, as visible in the identity records in DNS
  maxKeysPerSignature: 10,       // the maximal number of keys that may be used in a single Signature, defaults to 2 * maxKeysPerDevice (to allow for key rotation)
  maxMultiSignatures: 5,         // the maximal number of individual Signatures inside MultiSignature (multi-signatures are typically used for attestations)
  jsonMaxBytesize: 256 * 1024,   // the maximal allowable bytesize of JSON string that is considered safe for parsing
  jsonMaxNestingDepth: 8,        // the maximal nesting depth of objects in JSON strings (root counts as depth 1, so `{}` is depth 1)
  jsonMaxKeyLength: 255,         // the maximal length of a single object key in JSON strings
  publicProfileMaxKeyBytesize: 64,    // per-key bytesize cap for publicProfile fields read from DNS, so a domain cannot bloat results
  publicProfileMaxValueBytesize: 255, // per-value bytesize cap for publicProfile fields read from DNS, so a domain cannot bloat results
  publicProfileMaxExtensions: 16      // max number of distinct `x-` extension fields kept in publicProfile (reserved keywords are not counted)
});
