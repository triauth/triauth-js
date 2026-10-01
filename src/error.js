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

// The issue tracker to which internal errors should be reported
const ISSUES_URL = 'https://github.com/triauth/triauth-js/issues';

/**
 * The base error type used throughout triauth-js, carrying a numeric `code`, `message`, and `data`.
 *
 * @class
 * @memberof Triauth
 */
export class TriauthError extends Error {
  /**
   * @param code {number}                  - Numeric error code consulted by `TriauthError.process` to shape the response.
   * @param message {string}               - Human-readable error message.
   * @param [data={}] {{cause?: *, [k: string]: *}} - Optional metadata; `cause` (if present) is forwarded to the `Error` constructor and stripped from `this.data`.
   */
  constructor(code, message, data = {}) {
    super(message, {cause: data.cause});

    this.name = this.constructor.name;

    this.code = code;
    this.message = message;

    this.data = Object.assign({}, data);
    delete this.data.cause;

    this.ts = new Date();
  }

  /**
   * Normalizes any thrown value into the `{error: {code, message}}` shape returned by Triauth API methods,
   * and logs it via `config.logger`. Validation errors (code 200–299) are logged at `info`; other
   * `TriauthError`s at `warn`. Anything else is an internal error (code 100) logged at `error`
   * with the original error as `cause`.
   *
   * @param err {*} - The thrown value (typically a `TriauthError`, but anything is accepted).
   * @param config {object} - Effective per-call config; only `config.logger` is consulted here.
   *
   * @returns {{error: {code: number, message: string}}}
   */
  static process(err, config) {
    if (err instanceof TriauthError) {

      // Validation errors are logged with info severity
      if (err.code >= 200 && err.code < 300) {
        config.logger?.info?.(`Validation error - ${err.message} (${err.code})`, {cause:err});
      } else {
        config.logger?.warn?.(`${err.message} (${err.code})`, {cause:err});
      }

      return {
        error: {
          code: err.code,
          message: err.message
        }
      };

    } else {
      config.logger?.error?.(
        `Internal error (100): this is a defect in triauth-js - please report it at ${ISSUES_URL} together with the stack trace`,
        {cause: err}
      );

      return {
        error: {
          code: 100,
          message: 'Internal error'
        }
      };

    }
  }

}
