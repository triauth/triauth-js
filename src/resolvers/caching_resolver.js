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

import { Base } from './base.js';
import { Helpers } from '../helpers.js';

/**
 * A caching resolver that wraps another resolver (a descendant of Triauth.Resolvers.Base) and caches its
 * answers at the application level, so that repeated queries for the same DNS records are served from the
 * cache instead of the network.
 *
 * @example
 * Triauth.config.resolver = new Triauth.Resolvers.CachingResolver(Triauth.config.resolver)
 *
 * @class
 * @memberof Triauth.Resolvers
 */
export class CachingResolver extends Base {

  /**
   * @param resolver {Base} - The resolver (a descendant of Triauth.Resolvers.Base) whose answers should be cached.
   * @param [options={}] {object}
   * @param [options.store] {object}       - The cache store to use, fixed at construction time. May be anything that implements
   *                                         `get(key)` and `set(key, value)` methods (synchronous or promise-returning); stored values
   *                                         are JSON-serializable and must survive the store's serialization round-trip.
   *                                         Defaults to an in-process `Triauth.Helpers.createLRUCache(1000)`.
   *                                         SECURITY: the store becomes part of your trusted computing base — anyone able to write to it
   *                                         can inject DNS records (i.e., public keys). When using a shared store such as Redis,
   *                                         restrict write access accordingly.
   * @param [options.maxTtl] {number}      - The maximal time (in seconds) an answer may be served from the cache, regardless of the TTLs
   *                                         carried by its records. Bounds the worst-case revocation latency added on top of regular
   *                                         DNS caching. Defaults to 300. Set to 0 to disable caching.
   * @param [options.defaultTtl] {number}  - The cache lifetime (in seconds) for answers whose records carry no TTL (e.g., from the
   *                                         NodeDns resolver). Defaults to 0 (such answers are not cached).
   * @param [options.negativeTtl] {number} - The cache lifetime (in seconds) for empty answers (no records found).
   *                                         Defaults to 0 (empty answers are not cached).
   */
  constructor(resolver, options = {}) {
    super();
    this.resolver = resolver;
    this.options = options;
    this.store = options.store || Helpers.createLRUCache(1000);
    this.pending = new Map();
  }

  /**
   * Queries the cache for resource records of a given type that are stored under a given domainName,
   * falling back to (and caching the answer of) the wrapped resolver on a cache miss.
   *
   * @param domainName {string} - A domain name to query the DNS for. For example "example.com".
   * @param type {string}       - A type of DNS resource record to look for. For example "TXT", or "A".
   * @param [options={}] {object} - Per-call overrides for the options passed to the constructor (except `store`).
   *                                Additionally, `cache` may be set to `false` to fully bypass the cache for this
   *                                call (no read, no write). All options are also forwarded to the wrapped resolver.
   * @param [config={}] {object}  - Optional overrides for the global Triauth.config settings.
   *
   * @returns {Promise.<Array.<{value:string, ttl:(number|undefined), dnssec:(boolean|undefined)}>>} A promise that resolves to the array of retrieved DNS resource records in {value, ttl, dnssec} format.
   */
  async resolve(domainName, type, options = {}, config = {}) {
    config = Helpers.mergeConfig(config);

    options = Object.assign({
      maxTtl: 300,
      defaultTtl: 0,
      negativeTtl: 0
    }, this.options, options);

    // Ensure type is upper-case, so that cache keys are consistent across differently-cased queries
    type = String(type).toUpperCase();

    if (options.cache === false) {
      return this.resolver.resolve(domainName, type, options, config);
    }

    const key = `${type}:${domainName}`;

    // The cache must fail open (to a fresh resolution): a failing store is treated as a cache miss
    let entry = null;
    try {
      entry = await this.store.get(key);
    } catch (err) {
      config.logger?.debug?.(`[DNS] Cache read failed for ${type} records of ${domainName}`, {cause: err});
    }

    const now = Date.now();
    if (entry && Array.isArray(entry.records) && typeof entry.storedAt === 'number' && typeof entry.expiresAt === 'number' && now < entry.expiresAt) {
      config.logger?.debug?.(`[DNS] Cache hit for ${type} records of ${domainName}`);

      // Serve records with the remaining — not the original — TTL, so that TTL-derived
      // values downstream (e.g., the `expires` timestamps) stay honest
      const elapsed = (now - entry.storedAt) / 1000;

      return entry.records.map((record) => ({
        value: record.value,
        ttl: typeof record.ttl === 'number' ? Math.max(0, Math.ceil(record.ttl - elapsed)) : undefined,
        dnssec: record.dnssec
      }));
    }

    // Coalesce concurrent cache misses for the same key into a single upstream query.
    // Callers with an abort signal always get their own upstream query, so that one
    // caller's abort cannot reject a resolution shared with the others.
    let lookup = options.signal ? null : this.pending.get(key);

    if (lookup) {
      config.logger?.debug?.(`[DNS] Joining the in-flight query for ${type} records of ${domainName}`);

    } else {
      lookup = this.#lookup(key, domainName, type, options, config);

      if (!options.signal) {
        this.pending.set(key, lookup);
        const cleanup = () => this.pending.delete(key);
        lookup.then(cleanup, cleanup);
      }
    }

    // Each caller gets its own copy of the answer, so that downstream in-place record
    // mutations (e.g., by an enclosing MultiResolver) cannot leak across callers
    return lookup.then(CachingResolver.#copyRecords);
  }

  /**
   * Resolves through the wrapped resolver and caches the answer for min(shortest record TTL, maxTtl) seconds.
   * Rejections are propagated and never cached.
   */
  async #lookup(key, domainName, type, options, config) {
    const records = await this.resolver.resolve(domainName, type, options, config);

    let lifetime; // for how long (in seconds) the answer may be served from the cache

    if (records.length === 0) {
      lifetime = options.negativeTtl;

    } else {
      lifetime = options.maxTtl;

      for (const record of records) {
        lifetime = Math.min(lifetime, typeof record.ttl === 'number' ? record.ttl : options.defaultTtl);
      }
    }

    if (lifetime > 0) {
      const storedAt = Date.now();

      try {
        // A copy is stored, so that callers mutating the returned records cannot corrupt the cache
        await this.store.set(key, {records: CachingResolver.#copyRecords(records), storedAt, expiresAt: storedAt + lifetime * 1000});
        config.logger?.debug?.(`[DNS] Cached ${records.length} ${type} record(s) of ${domainName} for ${lifetime}s`);

      } catch (err) {
        config.logger?.debug?.(`[DNS] Cache write failed for ${type} records of ${domainName}`, {cause: err});
      }
    }

    return records;
  }

  static #copyRecords(records) {
    return records.map((record) => ({value: record.value, ttl: record.ttl, dnssec: record.dnssec}));
  }

}
