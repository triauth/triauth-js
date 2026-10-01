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

import { TriauthError } from './error.js';
import { Helpers } from './helpers.js';
import { Validator } from './validator.js';
import { LIMITS, FLOWS, WRAPPER, DELIMITER, VERSION_TOKEN } from './protocol.js';
import { Identity } from './identity.js';

/**
 * A single triauth signature envelope, that carries structured information about the signer, and other data,
 * along with the plain cryptographic signatures.
 *
 * Wire format: `|type;identifier;actor;via;v1;ts;signedMetadata;unsignedMetadata;cryptoSignature(s)|`
 *
 * @class
 * @memberof Triauth
 */
export class Signature {

  /**
   * Generates a signature envelope by signing the payload with the provided cryptoSigner.
   *
   * @param cryptoSigner {function} - an async callback that receives the payload string (and a mutable unsignedMetadata reference) and returns one or more base64url crypto signatures.
   * @param type {string} - the flow type of the signature ('attest'|'auth'|'ping'|'sign'|'stamp').
   * @param identifier {string} - the identifier (the subject) the signature is made for.
   * @param actor {string} - the identifier of the delegate whose keys sign on behalf of the `identifier`, or `''` for a non-delegated signature.
   * @param via {string} - the base URL of the client application the signature is produced for.
   * @param message {string} - the message to sign.
   * @param [signedMetadata={}] {object} - additional data embedded under the crypto signatures.
   * @param [unsignedMetadata={}] {object} - additional data embedded outside the signed payload (the cryptoSigner may populate it).
   * @param [config={}] {object} - optional overrides for the global Triauth.config settings.
   *
   * @returns {Promise<string|false>} the signature envelope, or false when the passed values fail validation.
   */
  static async generate(cryptoSigner, type, identifier, actor, via, message, signedMetadata={}, unsignedMetadata={}, config={}) {
    config = Helpers.mergeConfig(config);

    config.logger?.debug?.('Generating signature', {type, identifier, actor, via, message, signedMetadata, unsignedMetadata});

    if (
      !(type && FLOWS.indexOf(type) >= 0) ||
      !(Validator.validateIdentifier(identifier).valid) ||
      !(actor === '' || Validator.validateIdentifier(actor).valid) ||
      !(Helpers.isCanonicalUrl(via) && via.indexOf(DELIMITER) === -1 && via.indexOf(WRAPPER) === -1)
    ) {
      return false;
    }

    const envelopeFields = [
      type,
      identifier,
      actor,
      via,
      VERSION_TOKEN,
      Date.now(),
      signedMetadata && Object.keys(signedMetadata).length > 0 ? this.encodeMetadata(signedMetadata) : '',
      '',
      String(message)
    ];

    // Prepare the payload that is to be signed by cryptoSigner
    const signerPayload = envelopeFields.join(DELIMITER);

    // Make a copy of received unsignedMetadata that can be safely modified in-place by cryptoSigner
    const unsignedMetadataRef = Object.assign({}, unsignedMetadata);

    // Let the cryptoSigner sign the payload, and populate the unsignedMetadataRef if needed
    config.logger?.debug?.('Generating signature for payload', {signerPayload, unsignedMetadataRef});
    const cryptoSignatures = await cryptoSigner(signerPayload, unsignedMetadataRef);

    // Replace the original message with cryptoSignatures in envelopeFields
    envelopeFields[8] = cryptoSignatures instanceof Array ? cryptoSignatures.join(DELIMITER) : String(cryptoSignatures);

    // Populate the unsignedMetadata in envelopeFields now (after signing)
    envelopeFields[7] = Object.keys(unsignedMetadataRef).length > 0 ? this.encodeMetadata(unsignedMetadataRef) : '';

    // Construct the envelope of Signature by joining the items with ';' and wrapping everything in '|'
    return WRAPPER + envelopeFields.join(DELIMITER) + WRAPPER;
  }

  /**
   * Parses a raw signature envelope string.
   *
   * @param rawData {string} - the wrapped signature envelope.
   * @param [config={}] {object} - optional overrides for the global Triauth.config settings.
   *
   * @throws {TriauthError} code 225 when the envelope or any of its fields is malformed.
   */
  constructor(rawData, config={}) {
    this.config = Helpers.mergeConfig(config);

    // Pre-check the basic sanity and format of received arguments
    if (
      typeof rawData !== 'string' ||
      rawData.length <= 3 ||
      (rawData[0] !== WRAPPER || rawData[rawData.length - 1] !== WRAPPER) ||
      Helpers.byteSize(rawData) > LIMITS.signatureBytesize ||
      rawData.split(WRAPPER).length  !== 3
    ) {
      throw new TriauthError(225, 'Invalid signature');
    }

    /** The wrapped signature envelope this instance was parsed from. */
    this.rawData = rawData;

    // Extract information from the signature segment's envelope
    const envelope = this.rawData.slice(1,-1).split(DELIMITER);

    /** The flow the signature was made for - one of `attest`, `auth`, `ping`, `sign`, `stamp`. */
    this.type = envelope.shift();
    /** The identifier of the account the signature speaks for. */
    this.identifier = envelope.shift();
    /** The delegated actor that produced the signature, or `''` when the account signed for itself. */
    this.actor = envelope.shift();
    /** The canonical URL of the client application the signature was issued to. */
    this.via = envelope.shift();
    /** The protocol version token as published (e.g., `v1`); re-parsed into its integer below. */
    this.ver = envelope.shift();
    /** The signing timestamp as published; re-parsed into an integer (ms) below. */
    this.ts = envelope.shift();
    /** The signed metadata slot, base64url as carried on the wire, or `''` when the envelope carries none. */
    this.encodedSignedMetadata = envelope.shift();
    /** The unsigned metadata slot, base64url as carried on the wire, or `''` when the envelope carries none. */
    this.encodedUnsignedMetadata = envelope.shift();
    /** The envelope's crypto signatures (base64url), one per key in the signing key group. */
    this.cryptoSignatures = envelope.slice();

    // Check the format of data extracted from the envelope
    if (
      !(this.type && FLOWS.indexOf(this.type) >= 0) ||
      !(this.identifier && Validator.validateIdentifier(this.identifier).valid) ||
      !(this.actor === '' || Validator.validateIdentifier(this.actor).valid) ||
      !(this.via && Helpers.isCanonicalUrl(this.via)) ||
      !(this.ver && this.ver.match(/^v[1-9][0-9]{0,15}$/)) ||
      !(this.ver === VERSION_TOKEN) ||
      !(this.ts && this.ts.match(/^[1-9][0-9]{0,15}$/)) ||
      !(this.encodedSignedMetadata === '' || Helpers.isBase64UrlString(this.encodedSignedMetadata)) ||
      !(this.encodedUnsignedMetadata === '' || Helpers.isBase64UrlString(this.encodedUnsignedMetadata)) ||
      this.cryptoSignatures.length < 1 || // there must be at least one crypto signature
      this.cryptoSignatures.some((cs) => cs.length < 1 || !Helpers.isBase64UrlString(cs))
    ) {
      throw new TriauthError(225, 'Invalid signature');
    }

    // Parse the numeric properties from envelope - they have been pre-checked with regexp
    this.ver = parseInt(this.ver.substring(1), 10);
    this.ts = parseInt(this.ts, 10);

    // De-serialize metadata back to JS objects
    try {
      /** The decoded metadata covered by the crypto signatures; `{}` when the envelope carries none. */
      this.signedMetadata   = this.encodedSignedMetadata   ? this.decodeMetadata(this.encodedSignedMetadata)   : {};
      /** The decoded metadata NOT covered by the crypto signatures; `{}` when the envelope carries none. */
      this.unsignedMetadata = this.encodedUnsignedMetadata ? this.decodeMetadata(this.encodedUnsignedMetadata) : {};
    } catch (err) {
      throw new TriauthError(225, 'Invalid signature', {cause: err});
    }
  }

  /**
   * Extracts object from encodedMetadata
   *
   * Triauth signature's envelope may contain additional information,
   * which can be either covered by the signatures (signedMetadata), or not (unsignedMetadata).
   *
   * @param encodedMetadata {string}  - A base64url encoded, JSON serialized object
   *
   * @returns {{}|any} restored object
   */
  decodeMetadata(encodedMetadata) {
    return Helpers.safeParseJson(
      Helpers.base64UrlToString(encodedMetadata)
    );
  }

  /**
   * Encodes an object into the encodedMetadata form carried by a signature envelope.
   *
   * The inverse of `decodeMetadata`.
   *
   * @param metadata {object} - An object to be carried in the envelope's signedMetadata or unsignedMetadata slot
   *
   * @returns {string} a base64url encoded, JSON serialized representation of the object
   */
  static encodeMetadata(metadata) {
    return Helpers.stringToBase64Url(JSON.stringify(metadata));
  }

  /**
   * Verifies that the signature segment is valid.
   *
   * @param message {string}                      - Message, should be the same as originally signed.
   * @param [constraints={}] {object}             - Optional constraints that the signature must satisfy:
   * @param [constraints.type] {string}           - If given, must match the signature's `type` slot ('attest'|'auth'|'ping'|'sign'|'stamp').
   * @param [constraints.identifier] {string}     - If given, must match the identifier for which it was created.
   * @param [constraints.actor] {string}          - If given, must match the signature's `actor` slot — the delegate whose keys made the signature on behalf of the `identifier`; `''` requires a non-delegated signature.
   * @param [constraints.ver] {number}            - If given, must match the signature's protocol version.
   * @param [constraints.via] {string}            - If given, must match the URL of the client application that requested the signature.
   * @param [constraints.notBefore] {number}      - If given, must be a timestamp after which the signature was created.
   * @param [constraints.notAfter] {number}       - If given, must be a timestamp before which the signature was created.
   *
   * @returns {Promise<{valid: true, type: string, identifier: string, identityDomain: string, lookupCode: string, actor: string, actorIdentityDomain: string, actorLookupCode: string, via: string, ver: number, signedAt: number, verifiedAt: number, publicProfile: object, groups: Array<string>, deviceName: string, deviceTag: string, keys: Array<object>, secure: boolean, expires: (number|undefined), signedMetadata: object, unsignedMetadata: object}|false|null>}
   *          A promise that resolves to false upon failed verification, null upon time constraints failure, or to an object with the following properties:
   *          valid - set to true
   *          type - a type of signature that was verified
   *          identifier - the identifier for which the signature was made (the subject),
   *          identityDomain - the domain name under which the identifier's identity records are stored (the subject's, for delegated signatures; for a direct signature, the records the signing keys were read from),
   *          lookupCode - the lookup code the subject identity's domain derivation consumed (under `mode=private` its records live at a code-derived label), or `''` where no code was consumed - the same code the deviceTag carries as a `~` suffix,
   *          actor - the identifier of the delegate whose keys made the signature on behalf of the identifier, or `''` when the signature was made with the identifier's own keys,
   *          actorIdentityDomain - the domain name under which the actor's identity records are stored — the records the signing keys of a delegated signature were read from — or `''` when the signature was made with the identifier's own keys,
   *          actorLookupCode - the lookup code the actor's domain derivation consumed, or `''` where none was (an actor domain not running private mode, or a signature under the identifier's own keys),
   *          via - the URL of the client application that requested the signature,
   *          ver - the version slot of the signature envelope,
   *          signedAt - the device-asserted timestamp at which the signature was made (the envelope `ts` slot; the user's device clock, only proven to fall within the freshness window),
   *          verifiedAt - this host's wall-clock timestamp at which the signature's crypto was confirmed,
   *          publicProfile - a public profile of identifier as read from the DNS records,
   *          groups - fully-qualified group names the identifier's identity records claim membership in (e.g., ['admins@triauthdemo.org']), sorted and deduplicated; for delegated signatures these are the subject's groups, never the actor's,
   *          keys - an array of public keys, read from identity records, that were used for verification,
   *          deviceName - a user-given name of the device that was used for signing (the actor's device for delegated signatures),
   *          deviceTag - a string identifying the device; for delegated signatures the composite `<includeTag>:<actorIdentifier>:<actorDeviceTag>`, covering the grant (`include` statement) as well; under private mode a tag component carries the lookupCode as a `~<lookupCode>` suffix (`<deviceTag>~<lookupCode>` direct, `<includeTag>~<lookupCode>:<actor>:<deviceTag>` and/or `...:<deviceTag>~<actorLookupCode>` delegated),
   *          secure - a boolean, true only when DNSSEC was reported for the domain's triauth endpoint record and for every well-formed record of the signer's identity answer — and for delegated signatures, of the subject's too; a single non-validated identity record degrades it,
   *          expires - a timestamp when dns records from which keys were extracted expire (calculated from TTL values in DNS response; undefined when none carried a TTL),
   *          signedMetadata - an object, containing any additional data that is covered by the embedded crypto signatures,
   *          unsignedMetadata - an object, containing data that for various reasons was not covered by the embedded crypto signatures, but may be needed to verify it
   *
   * @throws {TriauthError} code 110 when DNS resolution of the signer's identity fails - intentionally propagated so that API methods report a retryable error instead of a false "signature invalid" verdict
   */
  async verify(message, constraints = {}) {

    // Verify constraints to avoid bugs stemming from misspelling of keys in constraints object
    if (!Helpers.hasOnlyKnownProperties(constraints, ['type', 'identifier', 'actor', 'ver', 'via', 'notBefore', 'notAfter'], false)) {
      this.config.logger?.error?.('Unrecognized constraint');
      return false;
    }

    // Make sure that we actually have signatures to verify
    if (!(this.cryptoSignatures.length > 0)) {
      return false;
    }

    // Fail closed if time bounds are provided in a non-numeric form rather than silently
    // coercing to NaN (which would compare as false and bypass the window check).
    if (
      (constraints.notBefore != null && (typeof constraints.notBefore !== 'number' || Number.isNaN(constraints.notBefore))) ||
      (constraints.notAfter != null && (typeof constraints.notAfter !== 'number' || Number.isNaN(constraints.notAfter)))
    ) {
      this.config.logger?.error?.('Invalid notBefore/notAfter constraint');
      return false;
    }

    // 3-state return contract (shared by Signature/MultiSignature/Response.verify and relied on by
    // every API method to choose between a 402 "expired" and a 401 "invalid"):
    //   - a result object => success
    //   - `null`          => time-related failure ("expired")
    //   - `false`         => any other failure ("invalid")
    // `null` and `false` are deliberately distinct and must stay distinct as the value propagates up.
    if (
      (constraints.notBefore != null && constraints.notBefore > this.ts) ||
      (constraints.notAfter != null && constraints.notAfter < this.ts)
    ) {
      return null;
    }

    // All other constraint mismatches are generic failures.
    if (
      (constraints.type != null && constraints.type !== this.type) ||
      (constraints.identifier != null && constraints.identifier !== this.identifier) ||
      (constraints.actor != null && constraints.actor !== this.actor) ||
      (constraints.ver != null && constraints.ver !== this.ver) ||
      (constraints.via != null && constraints.via !== this.via)
    ) {
      return false;
    }

    // Re-construct the envelope (payload) against which the signature will be verified.
    // envelopeFields[7] (the unsignedMetadata slot) is intentionally empty in the signed payload:
    // it is the ONE field of the envelope that is NOT cryptographically signed.
    const envelopeFields = [
      this.type,
      this.identifier,
      this.actor || '',
      this.via,
      'v' + this.ver,
      this.ts,
      this.encodedSignedMetadata || '',
      '',
      String(message)
    ];

    const payload = envelopeFields.join(DELIMITER);

    // Extract lookup codes that may be needed for mode == 'private' domains
    const subjectLookupCode = Helpers.isLookupCode(this.signedMetadata.lookupCode) ? this.signedMetadata.lookupCode : null;
    const actorLookupCode = Helpers.isLookupCode(this.signedMetadata.actorLookupCode) ? this.signedMetadata.actorLookupCode : null;

    // Build the identity object for the identifier as embedded in the signature
    const subjectIdentity = new Identity(this.identifier, { lookupCode: subjectLookupCode }, this.config);
    const actorIdentity = this.actor ? new Identity(this.actor, { lookupCode: actorLookupCode }, this.config) : null;
    const signerIdentity = (actorIdentity || subjectIdentity);

    // Attempt to resolve identity records of the identifier. A definitive negative (domain not
    // configured for triauth, or no identity records published) fails the verification. A thrown
    // resolution error (e.g., TriauthError 110 on DNS failure) intentionally propagates instead.
    if (!(await signerIdentity.resolve())) {
      this.config.logger?.debug?.('Identifier does not exist or is not configured for triauth');
      return false;
    }

    // Prepare a context for this check
    const context = {
      mode: this.type,                                                         // signature type ('auth'|'sign'|'stamp'|'ping'|'attest') — enforces the key's "use" option
      webAuthnOrigin: 'https://' + signerIdentity.authenticationEndpoint.host  // for WebAuthn verifications - clientData.origin must equal the RESOLVED authentication endpoint origin (the host the Authenticator is actually served from, e.g. https://auth.example.com), NOT the identifier's domain; the endpoint record grammar fixes the endpoint scheme to https with no port, so the origin is exactly this concatenation
    };

    const kvResult = await signerIdentity.keys.verify(payload, this.cryptoSignatures, context, this.signedMetadata, this.unsignedMetadata);
    if (!kvResult || kvResult.valid !== true) {
      return false;
    }

    let deviceTag = kvResult.tag;
    let secure = signerIdentity.secure;                    // DNSSEC status is resolution-level - any non-validated identity record degrades it
    let expires = Helpers.earliest(signerIdentity.authenticationEndpoint.expires, kvResult.expires);  // the endpoint record selects the keys, so it bounds their freshness

    // For delegated signatures (with actor set), now make sure that the proper include is present in the main identity records
    // (covering the actor, the flow, and - through its `scope` - the service the signature was made via),
    // and update the `secure`, `expires`, and `deviceTag` with information from it.
    if (actorIdentity) {

      // Resolve the main identity for which the signature was made
      if (!(await subjectIdentity.resolve())) {
        this.config.logger?.debug?.('Main identifier does not exist or is not configured for triauth');
        return false;
      }

      const includeStatement = await subjectIdentity.includes.find(actorIdentity, null, this.type, /** @type {string} */ (Helpers.urlHost(this.via)));

      // Make sure the include statement is present
      if (!includeStatement) {
        this.config.logger?.debug?.('No matching include statements found for this actor');
        return false;
      }

      // Device tag for delegated signatures is the ':' joined: include record tag, actor identifier, and actor's deviceTag,
      // e.g., '5I4NnX-4lW3gdTqGW3zKpLsLR9oRiWip8zp6mqQgkL4:actor@triauthdemo.org:3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ'.
      // We need all of this so that deviceTag is guaranteed to change when:
      // - any significant changes to the `include` statement were made (e.g., change in `use` or `scope`),
      // - any significant changes to actor's identity domain configuration (e.g., a lookup code rotation) were made,
      // - and any changes to actor's device keys were made.
      // Also, the full actor's identifier in the deviceTag allows for simpler 'Triauth.check' code.
      const subjectLookupCode = subjectIdentity.identityDomain.lookupCode;
      const actorLookupCode = actorIdentity.identityDomain.lookupCode;

      deviceTag =
        includeStatement.tag + (subjectLookupCode ? '~' + subjectLookupCode : '')
        + ':' + actorIdentity.identifier + ':'
        + deviceTag + (actorLookupCode ? '~' + actorLookupCode : '');

      secure = secure && subjectIdentity.secure;
      expires = Helpers.earliest(expires, Helpers.earliest(subjectIdentity.authenticationEndpoint.expires, includeStatement.expires));

    } else if (subjectIdentity.identityDomain.lookupCode) {
      deviceTag = deviceTag + '~' + subjectIdentity.identityDomain.lookupCode;

    }

    // Wall-clock instant at which this signature was confirmed
    const verifiedAt = Date.now();

    return {
      valid: true,
      type: this.type,
      identifier: subjectIdentity.identifier,
      identityDomain: subjectIdentity.identityDomain.domainName,
      lookupCode: subjectIdentity.identityDomain.lookupCode || '',
      actor: actorIdentity ? actorIdentity.identifier : '',
      actorIdentityDomain: actorIdentity ? actorIdentity.identityDomain.domainName : '',
      actorLookupCode: actorIdentity ? (actorIdentity.identityDomain.lookupCode || '') : '',
      via: this.via,
      ver: this.ver,
      signedAt: this.ts,
      verifiedAt,
      publicProfile: subjectIdentity.publicProfile,
      groups: subjectIdentity.groups,
      deviceName: kvResult.name,
      deviceTag,
      keys: kvResult.keys,
      secure,
      expires,
      signedMetadata: this.signedMetadata,
      unsignedMetadata: this.unsignedMetadata
    };
  }
}
