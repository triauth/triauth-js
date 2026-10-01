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

import { LIMITS } from './protocol.js';
import { config } from './config.js';

/**
 * Static helpers shared across the library.
 *
 * @class
 * @memberof Triauth
 */
export class Helpers {
  static #BASE64URL_REGEXP = /^[A-Za-z0-9\-_]+$/;
  static #BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  static #BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static #BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  static #BASE64URL_VALUES = (() => {
    const values = new Uint8Array(123); // indexed by char code; 'z' (the highest) is 122
    for (let i = 0; i < 64; i++) {
      values[Helpers.#BASE64URL_ALPHABET.charCodeAt(i)] = i;
    }
    return values;
  })();
  static #DOMAIN_NAME_REGEXP = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i
  static #XN_LABEL_REGEXP = /(^xn--)|(\.xn--)/i;                                // a Punycode (xn--) label, leading or after a dot
  static #URL_HOST_LABEL_REGEXP = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;     // one lowercase LDH host label, 1-63 chars, no edge hyphens
  static #URL_NUMERIC_LABEL_REGEXP = /^(?:[0-9]+|0x[0-9a-f]*)$/i;               // an all-digits or 0x-hex label, an IPv4 notation when final
  static #URL_IPV4_QUAD_REGEXP = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/; // a canonical dotted-quad IPv4 host: four decimal octets 0-255, no leading zeros
  static #URL_DOT_SEGMENT_REGEXP = /^(?:\.|%2e){1,2}$/i;                        // a "." or ".." path segment, %2e spellings included
  static #URL_PATH_REGEXP = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$/;               // RFC 3986 pchar + "/" ("%" is a plain char here; "|" is not a URL character)
  static #URL_QUERY_REGEXP = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]+$/;             // the path characters + "?" also the fragment charset
  static #NORMAL_STRING_REGEXP = /^[\p{L}\p{N} ~!@#$%^&*()_\-+={}[\]|\\:;"'<,>.?/]+$/u; // the Unicode property escape \p{L} matches any kind of letter from any language, \p{N} any number.
  static #UNPAIRED_SURROGATE_REGEXP = /\p{Cs}/u;                                // matches only UNPAIRED surrogates - the strings UTF-8 cannot encode.
  static #LOOKUP_CODE_REGEXP = /^[A-Z0-9]{16}$/;

  // eslint-disable-next-line no-restricted-globals
  static #ENCODER = new TextEncoder();

  // eslint-disable-next-line no-restricted-globals
  static #DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

  /**
   * Returns the current time in milliseconds, for duration measurements.
   *
   * Monotonic (`performance.now`) whenever the runtime provides it, wall-clock
   * (`Date.now`) otherwise.
   *
   * @returns {number} a millisecond timestamp.
   */
  static now() {
    return globalThis.performance?.now?.() ?? Date.now();
  }

  /**
   * Returns the earlier of two timestamps, tolerating either being null/undefined.
   *
   * @param a {?number} - a timestamp, or null/undefined.
   * @param b {?number} - a timestamp, or null/undefined.
   *
   * @returns {?number} the earlier of the two, or whichever one is set.
   */
  static earliest(a,b) {
    return (a != null && b != null) ? (a < b ? a : b) : (a ?? b);
  }

  /**
   * Verifies DNS record options against a schema of allowed critical options and values.
   *
   * Non-`x-` prefixed options are critical: each must be whitelisted in the schema and match one of its
   * allowed values (strings, regexps, or predicate functions returning exactly `true`). `x-` prefixed
   * options are experimental and pass as long as they are normal strings.
   *
   * @param options {object} - the options as parsed from a DNS record.
   * @param optionsSchema {object} - a map of option keys to arrays of allowed values (strings, regexps, or predicates).
   *
   * @returns {boolean} true when every option is acceptable, false otherwise.
   */
  static verifyOptionsSchema(options, optionsSchema) {
    for (const [optionKey, optionVal] of Object.entries(options)) {
      // whitelisted critical options and values
      if (
        typeof optionVal === 'string' &&
        Object.hasOwn(optionsSchema, optionKey) &&
        optionsSchema[optionKey].findIndex(
          (v) => (typeof v === 'string' && optionVal === v) || (v.constructor.name === 'RegExp' && optionVal.match(v)) || (typeof v === 'function' && v(optionVal) === true)
        ) >= 0
      ) {
        continue;

      // experimental options prefixed with 'x-' are allowed as long as they are generally sane
      } else if (
        Helpers.isNormalString(optionKey) &&
        Helpers.isNormalString(optionVal) &&
        optionKey[0] === 'x' &&
        optionKey[1] === '-'
      ) {
        continue;

      // unknown or invalid critical option - reject
      } else {
        return false;

      }
    }

    return true;
  }

  /**
   * Returns a deep copy of the given JSON-shaped value (API results, parsed records).
   *
   * Uses the runtime's `structuredClone` when present, and an equivalent JSON
   * round-trip otherwise.
   *
   * @param value {*} - A JSON-shaped value to copy.
   *
   * @returns {*} a deep copy sharing no mutable state with the input.
   */
  static clone(value) {
    if (typeof globalThis.structuredClone === 'function') {
      return structuredClone(value);
    }
    return value === undefined ? value : JSON.parse(JSON.stringify(value));
  }

  /**
   * Encodes a given byte array into a Base32 encoded string.
   *
   * @param b {Uint8Array} - A byte array containing the message to be encoded as a base32 string.
   *
   * @returns {string} base32 representation of the given byte array
   */
  static uInt8ArrayToBase32(b) {
    const alphabet = this.#BASE32_ALPHABET;
    const bytes = b;

    let bits = 0;
    let value = 0;
    let rv = "";

    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;

      // 5-bits per character in base32
      while (bits >= 5) {
        rv += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    // anything that's left needs to be also encoded
    if (bits > 0) {
      rv += alphabet[(value << (5 - bits)) & 31];
    }

    return rv;
  }

  /**
   * Encodes a given byte array buffer into a Base64 encoded string.
   *
   * @param b {ArrayBuffer|Uint8Array} - An array buffer (or Uint8Array view) that contains the message (bytes) to be encoded as base64 string.
   *
   * @returns {string} base64 representation of the given array buffer
   */
  static arrayBufferToBase64(b) {
    const alphabet = this.#BASE64_ALPHABET;
    const bytes = new Uint8Array(b);

    let rv = '';

    // 3 bytes make 4 characters; a final partial group is '='-padded
    for (let i = 0; i < bytes.length; i += 3) {
      const b0 = bytes[i];
      const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;

      rv += alphabet[b0 >> 2];
      rv += alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
      rv += i + 1 < bytes.length ? alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
      rv += i + 2 < bytes.length ? alphabet[b2 & 0x3f] : '=';
    }

    return rv;
  }

  /**
   * Encodes a given byte array buffer into a Base64URL encoded string.
   *
   * @param b {ArrayBuffer|Uint8Array} - An array buffer (or Uint8Array view) that contains the message (bytes) to be encoded as base64url string.
   *
   * @returns {string} base64url representation of the given array buffer
   */
  static arrayBufferToBase64Url(b) {
    const rv = this.arrayBufferToBase64(b);
    return rv.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Converts the passed base64url encoded string into an Uint8Array of its individual bytes.
   *
   * @param s {string} - A base64url encoded string.
   *
   * @returns {Uint8Array} an array with byte values representing the characters of passed string.
   *
   * @throws {TypeError} when the string is not base64url, or is a non-canonical encoding
   *                     (an impossible length, or payload in the final character's unused bits).
   */
  static base64UrlToUint8(s) {
    // Canonical decode: only the padding-free base64url alphabet, only
    // possible lengths, and no payload in the final character's unused bits —
    // every byte sequence has exactly one accepted encoding.
    if (typeof s !== 'string' || s.length % 4 === 1 || !/^[A-Za-z0-9\-_]*$/.test(s)) {
      throw new TypeError('Invalid base64url input');
    }

    const values = Helpers.#BASE64URL_VALUES;
    const rv = new Uint8Array(Math.floor(s.length * 3 / 4));

    let bits = 0;
    let value = 0;
    let index = 0;

    for (let i = 0; i < s.length; i++) {
      value = (value << 6) | values[s.charCodeAt(i)];
      bits += 6;

      // 8 accumulated bits form a byte
      if (bits >= 8) {
        bits -= 8;
        rv[index++] = (value >>> bits) & 0xff;
      }
    }

    // Trailing bits of a final partial group must be zero, or the same bytes
    // would have more than one encoding.
    if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) {
      throw new TypeError('Non-canonical base64url input');
    }

    return rv;
  }

  /**
   * Encodes the passed string into base64url encoding of its UTF-8 bytes.
   *
   * Any well-formed string is encodable (emojis, non-latin scripts, etc.). Throws a TypeError
   * on an unpaired surrogate — ill-formed UTF-16 has no UTF-8 encoding. Unreachable through
   * the protocol surface: every internal call site encodes JSON.stringify output, which
   * escapes unpaired surrogates.
   *
   * @param s {string} - A string to encode.
   *
   * @returns {string} encoded string.
   */
  static stringToBase64Url(s) {
    return this.arrayBufferToBase64Url(this.stringToUtf8Bytes(s));
  }

  /**
   * Decodes the passed base64url encoded string, interpreting the decoded bytes as UTF-8.
   *
   * Throws a TypeError on malformed base64url input and on bytes that are not well-formed
   * UTF-8. A leading byte-order mark is preserved, not stripped: U+FEFF stays byte-visible,
   * so every byte sequence has exactly one decoded spelling.
   *
   * @param s {string} - A string to decode.
   *
   * @returns {string} decoded string.
   */
  static base64UrlToString(s) {
    return this.utf8BytesToString(this.base64UrlToUint8(s));
  }

  /**
   * Encodes the passed string into its UTF-8 bytes.
   *
   * Throws a TypeError on an unpaired surrogate — ill-formed UTF-16 has no UTF-8 encoding,
   * and substituting U+FFFD would let two distinct strings share one byte encoding (the
   * platform encoder substitutes, so the well-formedness gate lives here).
   *
   * @param s {string} - A string to encode. Anything else throws.
   *
   * @returns {Uint8Array} the UTF-8 bytes of the string.
   *
   * @throws {TypeError} when the value is not a string, or the string carries an unpaired surrogate.
   */
  static stringToUtf8Bytes(s) {
    if (typeof s !== 'string') {
      throw new TypeError('stringToUtf8Bytes expects a string');
    }
    if (Helpers.#UNPAIRED_SURROGATE_REGEXP.test(s)) {
      throw new TypeError('Unpaired surrogate');
    }

    return this.#ENCODER.encode(s);
  }

  /**
   * Decodes the passed UTF-8 bytes into a string.
   *
   * Strict: throws a TypeError on any ill-formed sequence — overlong encodings, encoded
   * surrogates, code points above U+10FFFF, truncated or stray continuation bytes. A leading
   * byte-order mark is preserved, not stripped.
   *
   * Backed by the runtime's TextDecoder in fatal mode. The strict-decode contract itself is
   * pinned by the conformance vectors, so ports use their own stdlib's strict decoder.
   *
   * @param bytes {Uint8Array} - The UTF-8 bytes to decode. Anything else throws.
   *
   * @returns {string} the decoded string.
   *
   * @throws {TypeError} when the value is not a Uint8Array, or the bytes are not well-formed UTF-8.
   */
  static utf8BytesToString(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('utf8BytesToString expects a Uint8Array');
    }

    try {
      return this.#DECODER.decode(bytes);
    } catch {
      throw new TypeError('Ill-formed UTF-8 bytes');
    }
  }

  /**
   * Lowercases only the ASCII letters `A`-`Z` of the passed string, applying no other case mapping.
   *
   * Wire values that are "lowercased" before an ASCII grammar must use this instead of
   * String#toLowerCase(): the full Unicode case mapping would fold characters such as
   * U+212A KELVIN SIGN into ASCII (`k`), silently widening the wire alphabet in a way
   * other implementations (ASCII tolower) would not reproduce.
   *
   * @param string {string} - A string to map.
   *
   * @returns {string} the string with `A`-`Z` mapped to `a`-`z` and every other character intact.
   */
  static asciiLowercase(string) {
    return string.replace(/[A-Z]/g, (c) => c.toLowerCase());
  }

  /**
   * Percent-decodes the passed string into utf-8.
   *
   * @param string {string} - A string to decode.
   *
   * @returns {string|null} the decoded string, or null when an escape is malformed (a `%` not
   *          followed by two hexadecimal digits) or decodes to ill-formed UTF-8.
   */
  static percentDecode(string) {
    try {
      return decodeURIComponent(string);
    } catch {
      return null;
    }
  }

  /**
   * Checks that the passed string does not contain fancy utf-8 characters such as emojis, right-to-left encoding, etc.
   *
   * This is useful in validation of user-provided identifiers and/or other strings that may be displayed in the UI.
   *
   * @param string {string} - A string to check.
   * @param [bytesizeLimit=255] {number|null} - The size limit for the string (counted in bytes). Null for unbound.
   *
   * @returns {boolean} true if string contains only 'normal' characters, false otherwise.
   */
  static isNormalString(string, bytesizeLimit=255) {
    // Ensure that we are dealing with a string
    if (typeof string !== 'string') {
      return false;
    }

    // If bytesizeLimit is set, enforce it
    if (bytesizeLimit && this.byteSize(string) > bytesizeLimit) {
      return false;
    }

    return this.#NORMAL_STRING_REGEXP.test(string);
  }

  /**
   * Checks whether any label of the given hostname (or domain name) is in Punycode form.
   *
   * Punycode/IDN labels [RFC 3492] are blocked throughout the protocol, in identifiers, URLs,
   * and endpoint hosts alike, to keep look-alike "homograph" domains out of everything a user
   * may be shown.
   *
   * @param string {string} - A hostname or domain name to check.
   *
   * @returns {boolean} true if the string carries an `xn--` label, false otherwise.
   */
  static hasPunycodeLabel(string) {
    return typeof string === 'string' && this.#XN_LABEL_REGEXP.test(string);
  }

  /**
   * Parses an absolute http(s) URL given in its canonical spelling, and returns its components.
   *
   * This is a small subset of RFC 3986 admitting exactly one spelling per resource.
   * Owning it makes the accepted set identical on every engine (cross-engine URL parser
   * differentials are a classic source of origin confusion).
   *
   * The grammar:
   *   - scheme: the literal `https://` or `http://`,
   *   - host: dot-separated lowercase LDH labels (letters/digits/hyphens, 1–63 chars, no
   *     leading/trailing hyphen, no empty labels) whose final label is not numeric (all digits,
   *     or `0x` + hex digits) — or a canonical dotted-quad IPv4 literal (four decimal octets
   *     0–255, no leading zeros). Every other IPv4 spelling (hex, octal, dword, short forms)
   *     matches neither production; `[` is not in the grammar, so IPv6 literals are out as well,
   *   - port: optional; 1–65535 with no leading zeros, never the scheme's default,
   *   - userinfo: none (`@` cannot appear before the path),
   *   - path: required and absolute; characters from the RFC 3986 `pchar` set plus `/` and `%`
   *     (`|` is not an RFC 3986 URL character and never appears); no `.`/`..` segments in any
   *     spelling (`%2e` forms included),
   *   - query and fragment: optional and non-empty, over the path characters plus `?`.
   *
   * `%` is a plain character at this layer; the policy wrapper below rejects malformed escapes
   * before parsing. This parser is reachable only through that wrapper, so grammar and policy
   * always travel together.
   *
   * @param string {string} - The URL string to parse.
   *
   * @returns {?Readonly<{scheme: string, host: string, port: string, path: string,
   *   query: ?string, fragment: ?string, origin: string, base: string}>} The URL's components
   *   (frozen), or null when the string is not a canonical URL. `port` is `''` and
   *   `query`/`fragment` are null when absent; `origin` carries no trailing slash; `base` is the
   *   origin plus the path up to and including its last `/`.
   */
  static #parseCanonicalUrl(string) {
    if (typeof string !== 'string') {
      return null;
    }

    // Scheme — the lowercase spelling only
    let scheme;
    if (string.startsWith('https://')) {
      scheme = 'https';
    } else if (string.startsWith('http://')) {
      scheme = 'http';
    } else {
      return null;
    }

    let tail = string.slice(scheme.length + 3);

    // The authority runs up to the first '/', '?' or '#'
    const authorityEnd = tail.search(/[/?#]/);
    const authority = authorityEnd < 0 ? tail : tail.slice(0, authorityEnd);
    tail = authorityEnd < 0 ? '' : tail.slice(authorityEnd);

    if (authority === '' || authority.includes('@')) {
      return null;
    }

    // Optional port
    let host = authority;
    let port = '';
    const portAt = authority.lastIndexOf(':');
    if (portAt >= 0) {
      port = authority.slice(portAt + 1);
      host = authority.slice(0, portAt);
      if (
        !/^[1-9][0-9]{0,4}$/.test(port) || // 1-65535: no leading zeros, and port 0 is not a destination
        Number(port) > 65535 ||
        port === (scheme === 'https' ? '443' : '80') // an explicit default port is not canonical
      ) {
        return null;
      }
    }

    // Host — a named host (LDH labels, non-numeric final label) or a canonical dotted-quad
    // IPv4 literal; every exotic IPv4 spelling matches neither production
    const labels = host.split('.');
    if (
      !Helpers.#URL_IPV4_QUAD_REGEXP.test(host) &&
      (
        !labels.every((label) => Helpers.#URL_HOST_LABEL_REGEXP.test(label)) ||
        Helpers.#URL_NUMERIC_LABEL_REGEXP.test(labels[labels.length - 1])
      )
    ) {
      return null;
    }

    // Fragment and query — split off in that order, so neither can hide in the other
    let fragment = null;
    const fragmentAt = tail.indexOf('#');
    if (fragmentAt >= 0) {
      fragment = tail.slice(fragmentAt + 1);
      tail = tail.slice(0, fragmentAt);
      if (!Helpers.#URL_QUERY_REGEXP.test(fragment)) {
        return null;
      }
    }

    let query = null;
    const queryAt = tail.indexOf('?');
    if (queryAt >= 0) {
      query = tail.slice(queryAt + 1);
      tail = tail.slice(0, queryAt);
      if (!Helpers.#URL_QUERY_REGEXP.test(query)) {
        return null;
      }
    }

    // Path — what remains
    const path = tail;
    if (
      path[0] !== '/' ||
      !Helpers.#URL_PATH_REGEXP.test(path) ||
      path.split('/').some((segment) => Helpers.#URL_DOT_SEGMENT_REGEXP.test(segment))
    ) {
      return null;
    }

    const origin = `${scheme}://${host}${port ? `:${port}` : ''}`;
    const base = origin + path.slice(0, path.lastIndexOf('/') + 1);

    return Object.freeze({ scheme, host, port, path, query, fragment, origin, base });
  }

  /**
   * Checks that the passed string is a canonical, safe-to-display URL.
   *
   * A string passes only when it is:
   *   - non-empty and within `LIMITS.urlBytesize`,
   *   - printable ASCII only (no spaces or control characters),
   *   - free of malformed `%`-escapes (every `%` is followed by two hex digits),
   *   - a canonical `http` or `https` URL per the closed grammar (a lowercase LDH host with a
   *     non-numeric final label, or a canonical dotted-quad IPv4 literal — no other IP spelling,
   *     no IPv6; optional non-default port; absolute path; optional query and fragment; no
   *     userinfo; the RFC 3986 `pchar` charset, which has no `|`; no `.`/`..`/`%2e` path
   *     segments), and
   *   - free of Punycode/IDN `xn--` labels (homograph look-alikes).
   *
   * Used to validate caller-supplied URLs that are later embedded in signatures or shown to the
   * user: the `callbackUrl` (whose base-URL span carries the extra `;` rule at the validator) and
   * attachment `sourceUrl`s. URLs that act as verbatim trust anchors — attestation provider URLs —
   * use the narrower {@link Triauth.Helpers.isSecureUrl} instead.
   *
   * @param string {string} - A string to check.
   *
   * @returns {boolean} true if the string is a canonical URL meeting all the above constraints, false otherwise.
   */
  static isCanonicalUrl(string) {
    return this.#canonicalUrl(string) !== null;
  }

  /**
   * Checks that the passed string is a canonical URL (see {@link Triauth.Helpers.isCanonicalUrl})
   * on a secure origin: an `https` URL with a named (non-IP-literal) host — or, for local
   * development, an `http` URL on the literal host `localhost`.
   *
   * This is the acceptance rule for URLs used verbatim as trust anchors: attestation provider
   * URLs, which are displayed to the user as the trust decision and embedded whole as the
   * attestation Segment's `via`. Callback URLs take the wider {@link Triauth.Helpers.isCanonicalUrl}
   * instead — only their base URL enters the envelope, under its own delimiter rule.
   *
   * Every string this accepts is also accepted by `isCanonicalUrl`: both are views over the same
   * parse, so the two accept-sets cannot diverge.
   *
   * @param string {string} - A string to check.
   *
   * @returns {boolean} true if the string is a canonical URL on a secure origin, false otherwise.
   */
  static isSecureUrl(string) {
    const url = this.#canonicalUrl(string);

    return url !== null &&
      !this.#URL_IPV4_QUAD_REGEXP.test(url.host) &&
      (url.scheme === 'https' || url.host === 'localhost');
  }

  /**
   * The single accept-set behind every canonical-URL helper: the closed grammar of
   * {@link Triauth.Helpers.#parseCanonicalUrl} plus the protocol policy — size cap, printable
   * ASCII, well-formed `%`-escapes, and no Punycode label.
   *
   * `isCanonicalUrl`, `isSecureUrl`, `getBaseUrl`, and `urlHost` are all views over this one
   * function (`isSecureUrl` a narrowing one), so no URL can ever pass one of them while failing
   * another's underlying parse.
   *
   * @param string {string} - A string to check and parse.
   *
   * @returns {?Readonly<{scheme: string, host: string, port: string, path: string,
   *   query: ?string, fragment: ?string, origin: string, base: string}>} The parsed components,
   *   or null when the string is not a canonical URL under the full protocol rules.
   */
  static #canonicalUrl(string) {
    // Ensure that we are dealing with a string
    if (typeof string !== 'string') {
      return null;
    }

    // Ensure size limits
    if (string.length === 0 || this.byteSize(string) > LIMITS.urlBytesize) {
      return null;
    }

    // ASCII only
    if (!/^[\x21-\x7E]+$/.test(string)) {
      return null;
    }

    // Reject malformed percent escapes.
    if (/%(?![0-9A-Fa-f]{2})/.test(string)) {
      return null;
    }

    // The string must be a canonical URL per the closed grammar
    const url = this.#parseCanonicalUrl(string);
    if (!url) {
      return null;
    }

    // Block Punycode/IDN homographs (RFC 3492)
    if (this.hasPunycodeLabel(url.host)) {
      return null;
    }

    return url;
  }

  /**
   * Checks that the passed string uses only characters from base64URL alphabet.
   *
   * This method is intended for quick validation and is not bullet-proof - e.g., may not check that the string is properly base64URL encoded.
   *
   * @param string {string} - A string to check.
   *
   * @returns {boolean} true if string contains only base64url characters, false otherwise.
   */
  static isBase64UrlString(string) {
    return typeof string === 'string' && this.#BASE64URL_REGEXP.test(string);
  }

  /**
   * Checks that the passed string is a valid domain name.
   *
   * Accepts case-insensitive LDH domain names of at least two labels. Labels in Punycode form
   * (`xn--`) are rejected (homograph look-alikes), and so is a numeric final label (all digits,
   * or `0x` + hex digits) — real TLDs are never numeric, and this keeps every IPv4 spelling,
   * exotic notations included, from ever being taken for a domain name.
   *
   * This method is intended for quick validation and is not bullet-proof - e.g., exotic domain names may not be recognized
   *
   * @param string {string} - A string to check.
   *
   * @returns {boolean} true if string is a domain name, false otherwise.
   */
  static isDomainName(string) {
    return typeof string === 'string' &&
      this.byteSize(string) <= LIMITS.domainNameBytesize &&
      this.#DOMAIN_NAME_REGEXP.test(string) &&
      !this.hasPunycodeLabel(string) &&
      !this.#URL_NUMERIC_LABEL_REGEXP.test(string.slice(string.lastIndexOf('.') + 1));
  }

  /**
   * Returns the base URL of the given canonical URL string: its origin plus the path up to and
   * including the last `/`, with query and fragment removed.
   *
   * For example, `https://example.com/foo/bar` returns `https://example.com/foo/`, while
   * `https://example.com/foo/` returns `https://example.com/foo/` unchanged.
   *
   * The base URL is what the authenticator signs into the `via` field of a signature envelope,
   * so this accepts only canonical URLs (see {@link Triauth.Helpers.isCanonicalUrl}) — for
   * anything else it returns `false` rather than a normalized guess.
   *
   * @param url {string} - A canonical URL string to process.
   *
   * @returns {string|false} The base URL with a trailing slash, or `false` if the input is not a canonical URL.
   */
  static getBaseUrl(url) {
    return this.#canonicalUrl(url)?.base ?? false;
  }

  /**
   * Returns the host (without the port) of the given canonical URL string.
   *
   * @param url {string} - A canonical URL string to process.
   *
   * @returns {string|false} The lowercase hostname, or `false` if the input is not a canonical URL.
   */
  static urlHost(url) {
    return this.#canonicalUrl(url)?.host ?? false;
  }

  /**
   * Calculates the SHA-256 digest of the passed string.
   *
   * @param message {string} - A message whose SHA-256 digest should be calculated.
   * @returns {Promise<string>} a promise that resolves to the sha256 of the given message.
   */
  static async sha256(message) {
    const data = this.stringToUtf8Bytes(message);

    const hash = (await crypto.subtle.digest('SHA-256', /** @type {BufferSource} */ (data)));
    return this.arrayBufferToBase64Url(hash);
  }

  /**
   * Computes the HMAC-SHA-256 of a message under a key.
   *
   * Keys the private-mode identity-domain derivation (`Triauth.IdentityDomain.deriveFullLabel`) and
   * binds the redirect token of the challenge-response flows to the challenge.
   *
   * @param key {Uint8Array} - The key bytes.
   * @param message {Uint8Array} - The message bytes.
   * @returns {Promise<Uint8Array>} a promise that resolves to the 32-byte MAC.
   */
  static async hmacSha256(key, message) {
    const hmacKey = await crypto.subtle.importKey(
      'raw', /** @type {BufferSource} */ (key),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );

    return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, /** @type {BufferSource} */ (message)));
  }

  /**
   * Generates a random string of the given length using the base64 url alphabet.
   *
   * The underlying byte source is the effective config's `randomSource` when set, otherwise
   * `crypto.getRandomValues`. See `Triauth.config.randomSource` for details on overriding
   * the entropy source.
   *
   * @param len {Number} - The character length of the returned string.
   * @param [config] {object} - The effective config whose `randomSource` supplies the bytes;
   *                            defaults to the global `Triauth.config`.
   * @returns {string} a random string of the given length
   */
  static randomString(len, {randomSource} = config) {
    // base64url packs 3 random bytes into 4 chars (0.75 bytes/char), so `len` chars need
    // ceil(len * 0.75) bytes; the +1 covers the partial final group and guarantees the encoded
    // string is at least `len` chars before the substring trim. Every returned char is therefore
    // backed by fresh random bytes (no padding/repetition is introduced by the trim).
    const array = new Uint8Array(Math.ceil(len * 0.75) + 1);
    const source = randomSource || ((arr) => crypto.getRandomValues(arr));
    source(array);
    return Helpers.arrayBufferToBase64Url(array).substring(0, len);
  }

  /**
   * Verifies that the passed object has only properties that are on the passed whitelist.
   *
   * This method helps to ensure that the user-passed arguments were not misspelled or come from untrusted sources.
   * It also helps to recognize that an argument was passed from the user in the subsequent code, by enforcing (in strict
   * mode) that only non-undefined values may be set by the user.
   *
   * @param obj {Object} - An object which properties should be checked.
   * @param whitelist {ReadonlyArray<string>} - An array of allowed properties (whitelist).
   * @param [strict=true] {boolean} - When true (default), a whitelisted key whose value is `undefined` is rejected; use this at
   *   trust boundaries (user-facing options/constraints) to force callers to omit a value rather than pass `undefined`.
   *
   * @returns {boolean} true if object contains only properties from the whitelist, false otherwise
   */
  static hasOnlyKnownProperties(obj, whitelist, strict = true) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return false;
    }

    const objKeys = Object.keys(obj);
    return objKeys.every(key => whitelist.includes(key) && (!strict || obj[key] !== undefined));
  }

  /**
   * Returns the number of bytes it takes to store the given string in UTF-8.
   *
   * This method is helpful when validating untrusted input, as simply checking .length
   * may be not enough for utf-8 encoded strings.
   *
   * @param str {string} - A string for which its underlying bytesize should be calculated.
   *
   * @returns {number} The number of bytes.
   */
  static byteSize(str) {
    let size = 0;

    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);

      if (c < 0x80) {
        size += 1;
      } else if (c < 0x800) {
        size += 2;
      } else if (c >= 0xD800 && c < 0xDC00 && str.charCodeAt(i + 1) >= 0xDC00 && str.charCodeAt(i + 1) <= 0xDFFF) {
        size += 4;
        i++;
      } else {
        size += 3;
      }
    }

    return size;
  }

  /**
   * Parses the provided json text source and returns original object.
   *
   * This method is a wrapper around the native JSON parser with some added security-focused validations and limits:
   *   - accepts only source strings smaller than 256KB,
   *   - ensures that the JSON encoded structure is an 'object',
   *   - protects against prototype poisoning attacks,
   *   - blocks non-ascii characters in property names,
   *   - allows a maximal object nesting depth of 8 levels (the root object counts as depth 1),
   *   - maximal key length of 256 characters.
   *
   * @param source {string} - A source string that contains json encoded data.
   *
   * @returns {Object} deserialized object
   */
  static safeParseJson(source) {
    const err = new Error('JSON validation error');

    // Pre-validate that source is a string not larger than 256KB
    if (
      typeof source !== 'string' ||
      Helpers.byteSize(source) > LIMITS.jsonMaxBytesize
    ) {
      throw err;
    }

    const jsonObject = JSON.parse(source);

    // We always expect to see JSON encoded objects ({}) at root level.
    if (jsonObject === null || typeof jsonObject !== 'object' || Array.isArray(jsonObject)) {
      throw err;
    }

    const {
      jsonMaxNestingDepth,
      jsonMaxKeyLength
    } = LIMITS;

    // Keep track of nesting depth, capped at jsonMaxNestingDepth
    let currentDepth = 0;

    let queue = [jsonObject];

    while (queue.length) {

      if (jsonMaxNestingDepth && currentDepth >= jsonMaxNestingDepth) {
        throw err;
      }
      currentDepth += 1;

      let nodes = queue;
      queue = [];

      for (const node of nodes) {

        if (node === undefined || node === null) {
          continue;
        }

        // Defend against prototype poisoning
        if (
          Object.prototype.hasOwnProperty.call(node, '__proto__') ||
          (
            Object.prototype.hasOwnProperty.call(node, 'constructor') &&
            Object.prototype.hasOwnProperty.call(node.constructor, 'prototype')
          )
        ) {
          throw err;
        }

        for (const key in node) {

          // Limit the maximal length of a key
          if (key.length > jsonMaxKeyLength){
            throw err;
          }

          // Do not accept non-ascii keys
          // eslint-disable-next-line no-control-regex
          if (/[^\x00-\x7F]/.test(key)){
            throw err;
          }

          if (typeof node[key] === 'object') {
            queue.push(node[key]);
          }
        }
      }
    }

    return jsonObject;
  }

  /**
   * Builds a minimal in-memory LRU cache - the default answer store of `Triauth.Resolvers.CachingResolver`.
   *
   * The returned object's `get` and `set` methods are async (return Promises) so a caller can swap in
   * a custom remote cache without changing the call sites.
   *
   * @param [size=1024] {number} - Maximum number of entries. Defaults to 1024.
   *
   * @returns {{get: (function(string): Promise<*|null>), set: (function(string, *): Promise<void>), resize: (function(number): void)}}
   *          An LRU cache exposing `get(key)`, `set(key, value)`, and `resize(newSize)`.
   */
  static createLRUCache(size = 1024) {
    const cache = new Map();

    return {
      get: async (key) => {
        if (!cache.has(key)) return null;
        const val = cache.get(key);
        cache.delete(key);
        cache.set(key, val);
        return val;
      },
      set: async (key, val) => {
        if (cache.has(key)) cache.delete(key);
        else if (cache.size >= size) cache.delete(cache.keys().next().value);
        cache.set(key, val);
      },
      resize: newSize => {
        size = newSize;
        while (cache.size > size) cache.delete(cache.keys().next().value);
      }
    };
  }

  /**
   * Checks whether the given value is a well-formed lookup code - the 16-character token that
   * addresses an identity's records in the DNS when resolving in private mode.
   *
   * @param val {*} - A value to check; anything that is not a string is reported as not a lookup code.
   *
   * @returns {boolean} true when the value is a string of exactly 16 uppercase letters and digits
   */
  static isLookupCode(val) {
    return !!(typeof val === 'string' && val.match(this.#LOOKUP_CODE_REGEXP));
  }

  /**
   * Returns the effective settings for one call or instance: the global `Triauth.config`
   * with the given per-call overrides merged over it. The global object is read at call
   * time, so runtime mutations of `Triauth.config` are picked up.
   *
   * @param [overrides={}] {object} - Per-call overrides for the global Triauth.config settings.
   *
   * @returns {typeof config} the merged settings
   */
  static mergeConfig(overrides = {}) {
    return Object.assign({}, config, overrides);
  }
}
