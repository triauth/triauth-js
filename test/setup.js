import * as Triauth from '../src/index.js';
import assert from 'node:assert';

globalThis.Triauth = Triauth;
globalThis.assert = assert;

const noop = () => {};
const makeStubLogger = () => ({
  debug: noop, info: noop, warn: noop, error: noop,
  // `spawn` returns a fresh child logger so that the
  // `config.logger?.spawn?.(config.cid) || config.logger` line in every API
  // entrypoint hits the truthy branch under tests.
  spawn: () => makeStubLogger()
});
Triauth.config.logger = makeStubLogger();
