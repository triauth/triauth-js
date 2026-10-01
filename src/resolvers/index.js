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
 * The namespace for DNS resolvers.
 *
 * @namespace Resolvers
 * @memberof Triauth
 */
export { Base } from './base.js';
export { DnsJson } from './dns_json.js';
export { MultiResolver } from './multi_resolver.js';
export { CachingResolver } from './caching_resolver.js';
export { Cloudflare } from './cloudflare.js';
export { Google } from './google.js';
export { NodeDns } from './node_dns.js';
export { DnsSb } from './dns_sb.js';
