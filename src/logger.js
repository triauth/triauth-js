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
 * An implementation of simple logger that is set as the default value for `Triauth.config.logger` with output to the console.
 *
 * @class
 * @memberof Triauth
 */
export class Logger {

  /**
   *
   * @param [output=null] {object} - An object to which log messages will be sent, that should implement {debug, info, warn, error} functions, just like the native `console`.
   * @param [options={}] {object} - Additional configurations options. Defaults to {}.
   * @param [options.logLevel='warn'] {string} - A minimal level of messages that get logged to output. One of `debug`, `info`, `warn`, `error`. Defaults to 'warn'.
   * @param [options.prefix='[triauth]'] {string} - A prefix to use when logging messages. Defaults to '[triauth]'.
   * @param [options.cid=undefined] {string|false|null|undefined} - A correlation/context identifier shown in the [cid:...] tag, to identify log lines belonging to a single API call. A nullish value leaves the tag empty here; `false` explicitly suppresses it. (The `spawn` factory resolves nullish into an auto-generated id.)
   */
  constructor(output = null, options = {}) {
    this.output = output;
    this.logLevel = options.logLevel || 'warn';
    this.prefix = options.prefix || '[triauth]';
    this.cid = options.cid;
  }

  /**
   * Returns a child logger for a single API call, resolving the correlation id (`cid`):
   *   - nullish (null/undefined): "autofill" - inherit this logger's `cid` or mint a fresh one.
   *   - `false`: explicit opt-out - stored as-is and suppressed by `#formatMessage` (no `[cid:...]` tag).
   *   - string: used verbatim as the correlation id.
   *
   * @param [cid] {string|false|null|undefined} - explicit id, `false` to opt out, or nullish to autofill.
   * @returns {Logger}
   */
  spawn(cid) {
    return new Logger(this.output, {
      logLevel: this.logLevel,
      prefix: this.prefix,
      cid: cid == null ? this.cid || this.#generateCid() : cid,
    });
  }

  /**
   * Logs a message at the `debug` level, when the logger's `logLevel` admits it.
   *
   * @param args {...*} - Values to log. Passed through verbatim to the output's `debug` function,
   *                      behind the logger's prefix, correlation id (when set), and level tag.
   */
  debug(...args) {
    if (['debug'].indexOf(this.logLevel) >= 0) {
      this.output?.debug(...this.#formatMessage('debug', args));
    }
  }

  /**
   * Logs a message at the `info` level, when the logger's `logLevel` admits it.
   *
   * @param args {...*} - Values to log. Passed through verbatim to the output's `info` function,
   *                      behind the logger's prefix, correlation id (when set), and level tag.
   */
  info(...args) {
    if (['debug', 'info'].indexOf(this.logLevel) >= 0) {
      this.output?.info(...this.#formatMessage('info', args));
    }
  }

  /**
   * Logs a message at the `warn` level, when the logger's `logLevel` admits it.
   *
   * @param args {...*} - Values to log. Passed through verbatim to the output's `warn` function,
   *                      behind the logger's prefix, correlation id (when set), and level tag.
   */
  warn(...args) {
    if (['debug', 'info', 'warn'].indexOf(this.logLevel) >= 0) {
      this.output?.warn(...this.#formatMessage('warn', args));
    }
  }

  /**
   * Logs a message at the `error` level, when the logger's `logLevel` admits it.
   *
   * @param args {...*} - Values to log. Passed through verbatim to the output's `error` function,
   *                      behind the logger's prefix, correlation id (when set), and level tag.
   */
  error(...args) {
    if (['debug', 'info', 'warn', 'error'].indexOf(this.logLevel) >= 0) {
      this.output?.error(...this.#formatMessage('error', args));
    }
  }

  #formatMessage(logLevel, args) {
    const parts = [this.prefix];

    if (this.cid) {
      parts.push(`[cid:${this.cid}]`);
    }

    parts.push(`[${logLevel}]`);

    return [...parts, ...args];
  }

  #generateCid() {
    return Math.random().toString(36).slice(2, 10);
  }
}
