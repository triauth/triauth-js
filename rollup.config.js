import { readFileSync, writeFileSync, cpSync, watch } from 'node:fs';
import { resolve } from 'node:path';
import MagicString from 'magic-string';
import terser from '@rollup/plugin-terser';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

const banner = `/*!
 * triauth-js v${pkg.version}
 *
 * See https://www.triauth.org/ and https://github.com/triauth/triauth-js/ for more details.
 *
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
 */`;

// Drop the per-module SPDX banner at transform time from src/ files, so each distributed
// artifact carries exactly one license comment; magic-string keeps the sourcemaps faithful.
const stripSourceLicense = {
  name: 'strip-source-license',
  transform(code, id) {
    if (!/[\\/]src[\\/]/.test(id)) return null;
    const match = /^\/\*![\s\S]*?\*\/\r?\n+/.exec(code);
    if (!match) return null;
    const s = new MagicString(code);
    s.remove(0, match[0].length);
    return { code: s.toString(), map: s.generateMap({ hires: true }) };
  },
};

// `node:dns` is loaded lazily by NodeDns inside a `typeof window === 'undefined'` guard, and
// only on Node. Marking it external keeps the import out of the browser UMD bundle. Rollup's
// UMD wrapper will pass `undefined` for it when the browser entry runs, which is fine because
// the guarded code path never executes there.
const external = (id) => id === 'node:dns' || id === 'dns';

// Playground: Set the custom data from build env variables
const escapeAttr = (value) => value
  .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const injectPlaygroundData = () => {
  const file = 'dist/index.html';
  const html = readFileSync(file, 'utf8')
    .replace('__TERMS_OF_SERVICE_URL__', () => escapeAttr(process.env['TERMS_OF_SERVICE_URL'] ||''))
    .replace('__PRIVACY_POLICY_URL__',   () => escapeAttr(process.env['PRIVACY_POLICY_URL'] || ''));
  writeFileSync(file, html);
};

// Copies playground/, test/, and package.json into dist/ on every successful build.
// Uses Node stdlib's `fs.cpSync` and `fs.watch` (no third-party dep).
//
// Two trigger paths:
//   1. `writeBundle` — fires whenever rollup writes a bundle (initial build,
//      JS source change in watch mode, etc.). Keeps the existing behaviour.
//   2. `fs.watch` on playground/, test/, package.json — only registered once, in
//      watch mode, so that editing static assets directly (e.g. a tweak in
//      playground/index.html) re-copies them into dist/ without
//      needing to restart `npm run dev` or touch a JS source file. The
//      browser still needs a manual page reload.
//
// fs.watch can fire multiple events for a single save (especially on Linux),
// so the copy is debounced through a short timer.
const doCopyAll = () => {
  cpSync('playground', 'dist', { recursive: true });
  injectPlaygroundData();
  // dist/test/test.js is testConfig's bundle output - keep the unbundled entry out of the copy.
  // test/ai-reviews/ holds review documents for the repository, not playground content.
  const skip = [resolve('test/test.js'), resolve('test/ai-reviews')];
  cpSync('test', 'dist/test', { recursive: true, filter: (src) => !skip.includes(resolve(src)) });
  cpSync('package.json', 'dist/package.json');
};

let staticWatchersStarted = false;
let copyTimer = null;
const scheduleCopy = () => {
  clearTimeout(copyTimer);
  copyTimer = setTimeout(doCopyAll, 50);
};

const copyStaticAssets = {
  name: 'copy-static-assets',
  buildStart() {
    if (this.meta.watchMode && !staticWatchersStarted) {
      staticWatchersStarted = true;
      try {
        watch('playground',    { recursive: true }, scheduleCopy);
        watch('test',          { recursive: true }, scheduleCopy);
        watch('package.json',                       scheduleCopy);
      } catch (err) {
        this.warn('Could not start docs/test watcher (' + err.message + '). Static assets will only be copied on JS rebuilds.');
      }
    }
  },
  writeBundle: doCopyAll,
};

// Minified twins of the browser-facing builds, for CDN delivery
const minify = () => terser({ format: { comments: /^!/ } });

const mainConfig = {
  input: 'src/index.js',
  external,

  output: [
    {
      file: 'dist/triauth.mjs',
      format: 'es',
      banner,
      sourcemap: true,
    },
    {
      file: 'dist/triauth.cjs',
      format: 'cjs',
      banner,
      sourcemap: true,
      exports: 'named',
    },
    {
      file: 'dist/triauth.js',
      format: 'umd',
      name: 'Triauth',
      banner,
      sourcemap: true,
      // Map external node:dns to a globally undefined name in the UMD wrapper so the bundle
      // loads cleanly in browsers (the guarded code path will not call into it).
      globals: { 'node:dns': 'undefined', 'dns': 'undefined' },
    },
    {
      file: 'dist/triauth.min.mjs',
      format: 'es',
      banner,
      sourcemap: true,
      plugins: [minify()],
    },
    {
      file: 'dist/triauth.min.js',
      format: 'umd',
      name: 'Triauth',
      banner,
      sourcemap: true,
      // Same external mapping as the readable UMD build above.
      globals: { 'node:dns': 'undefined', 'dns': 'undefined' },
      plugins: [minify()],
    },
  ],

  plugins: [stripSourceLicense, copyStaticAssets],
};

// .json imports are emitted through JSON.parse (Node's JSON-module path): object-literal
// codegen would turn an own `__proto__` fixture key into a [[Prototype]] assignment.
const jsonAsParsed = {
  name: 'json-as-parsed',
  transform(code, id) {
    if (!id.endsWith('.json')) return null;
    JSON.parse(code); // malformed fixtures fail the build with the file id attached
    return { code: `export default JSON.parse(${JSON.stringify(code)});`, map: { mappings: '' } };
  },
};

// Browser test bundle: takes test/test.js (ES modules importing fixtures + stubs + sub-tests)
// and produces a single dist/test/test.js that the harness loads via <script src="test.js">
// (resolved relative to /test/index.html, so the request hits /test/test.js).
//
// Output path is intentionally INSIDE dist/test/ so it overwrites the unbundled source that
// the copyStaticAssets plugin places there. Rollup processes array configs in order, and
// copyStaticAssets runs in the first config's writeBundle hook before this one builds, so
// the bundled file wins.
//
// `Triauth` is referenced as a runtime global - the harness loads /triauth.js (UMD) first,
// which attaches window.Triauth before test.js runs.
const testConfig = {
  input: 'test/test.js',
  external: (id) => id.startsWith('node:'),

  output: {
    file: 'dist/test/test.js',
    format: 'iife',
    name: 'TriauthTests',
    sourcemap: false,
    // 'auto' silences the "Mixing named and default exports" warning for the tests, which
    // don't actually export anything - they just run on load.
    exports: 'auto',
  },

  plugins: [
    stripSourceLicense,
    jsonAsParsed,
  ],
};

export default [mainConfig, testConfig];
