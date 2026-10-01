export default function() { describe('Triauth.Helpers', () => {

  describe('safeParseJson', () => {

    it('limits the bytesize of a string to parse', () => {
      const limit = Triauth.LIMITS.jsonMaxBytesize;
      let jsonString, jsonResult;

      jsonString = '{"a":"' + 'A'.repeat(limit - 8) + '"}';
      jsonResult = Triauth.Helpers.safeParseJson(jsonString);
      assert.equal(typeof jsonResult, 'object');

      try {
        jsonString = '{"a":"' + 'A'.repeat(limit - 7) + '"}';
        jsonResult = Triauth.Helpers.safeParseJson(jsonString);
        assert(false);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        } else {
          assert(true);
        }
      }
    });

    it('only allows objects to be encoded (no arrays)', () => {
      let jsonResult = Triauth.Helpers.safeParseJson('{}');
      assert.equal(typeof jsonResult, 'object');

      for (const str of ['[]', '"string"', '11', '3.14', 'true', 'false', 'null']) {
        try {
          Triauth.Helpers.safeParseJson(str);
          assert(false);
        } catch (err) {
          if (err?.name === 'AssertionError') {
            throw err;
          } else {
            assert(true);
          }
        }
      }
    });

    it('throws on attempted JS prototype poisoning', () => {
      for (const str of ['{"__proto__": {"isAdmin": true}}', '{"constructor": {"prototype": {"isAdmin": true}}}', '{"a":{"constructor": {"prototype": {"isAdmin": true}}}}']) {
        try {
          Triauth.Helpers.safeParseJson(str);
          assert(false);
        } catch (err) {
          if (err?.name === 'AssertionError') {
            throw err;
          } else {
            assert(true);
          }
        }
      }
    });

    it('only allows ASCII non-control keys with limited length', () => {
      const limit = Triauth.LIMITS.jsonMaxKeyLength;
      for (const str of ['{"Ą":"A"}', '{"lorem\nipsum":"dolor sit"}', '{"' + 'A'.repeat(limit+1) + '":"A"}']) {
        try {
          Triauth.Helpers.safeParseJson(str);
          assert(false);
        } catch (err) {
          if (err?.name === 'AssertionError') {
            throw err;
          } else {
            assert(true);
          }
        }
      }
    });

    it('limits the nesting level', () => {
      const limit = Triauth.LIMITS.jsonMaxNestingDepth;
      let obj = {};
      let root = obj;

      // Build a chain whose total nesting depth equals the limit (root counts as depth 1, so we
      // add limit-1 children below root). This is the maximum allowed depth and should be accepted.
      for (let i = 0; i < limit - 1; i++) {
        obj[i] = {};
        obj = obj[i];
      }

      let jsonResult = Triauth.Helpers.safeParseJson(JSON.stringify(root));
      assert.equal(typeof jsonResult, 'object');

      // Adding one more nested object pushes the depth past the limit — should be rejected.
      obj['z'] = {};

      try {
        Triauth.Helpers.safeParseJson(JSON.stringify(root));
        assert(false);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        } else {
          assert(true);
        }
      }
    });

    it('accepts wide objects and arrays as member counts are bounded by the bytesize cap', () => {
      const jsonVals = [];
      for (let i = 0; i < 2000; i++) {
        jsonVals.push('"' + String(i) + '":"A"');
      }

      const wideObject = Triauth.Helpers.safeParseJson('{' + jsonVals.join(',') + '}');
      assert.equal(Object.keys(wideObject).length, 2000);

      const wideArray = Triauth.Helpers.safeParseJson('{"list":[' + Array.from({length: 2000}, (_, i) => i).join(',') + ']}');
      assert.equal(wideArray.list.length, 2000);
    });

  });

  describe('stringToBase64Url / base64UrlToString', () => {

    it('round-trips strings from any script (UTF-8)', () => {
      const samples = [
        '{"a":1}',
        'café',
        'Привет мир',
        '日本語のテスト',
        'zażółć gęślą jaźń',
        'ok \u{1F389}',
        'mixed: é Привет 日本語 \u{1F680}\u{1F389}'
      ];

      for (const s of samples) {
        assert.equal(Triauth.Helpers.base64UrlToString(Triauth.Helpers.stringToBase64Url(s)), s, s);
      }
    });

    it('encodes the UTF-8 bytes of the string (exact encodings)', () => {
      // ASCII payloads must stay bit-identical to the historical encoding — recorded
      // challenges/signatures in test/fixtures/json/*.json depend on this.
      assert.equal(Triauth.Helpers.stringToBase64Url('{"a":1}'), 'eyJhIjoxfQ');

      // 'é' must encode as its UTF-8 bytes C3 A9, not the latin-1 byte E9 ('6Q') that the
      // old btoa()-based implementation produced.
      assert.equal(Triauth.Helpers.stringToBase64Url('é'), 'w6k');
      assert.equal(Triauth.Helpers.base64UrlToString('w6k'), 'é');
    });

    it('throws on byte sequences that are not well-formed UTF-8', () => {
      // '6Q' is the latin-1 (pre-UTF-8) encoding of 'é' — the lone byte E9 is ill-formed
      // UTF-8. Rejecting (never substituting U+FFFD) keeps exactly one byte spelling per
      // string; callers map the TypeError to 223 (challenge) / 225 (metadata) on the wire.
      try {
        Triauth.Helpers.base64UrlToString('6Q');
        assert(false);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        }
        assert.equal(err.name, 'TypeError');
      }
    });

    it('does not strip a UTF-8 BOM, so a BOM-prefixed JSON payload stays rejected', () => {
      // '77u_eyJhIjoxfQ' is EF BB BF + '{"a":1}'. The BOM bytes are well-formed UTF-8, so
      // the decoder returns them as U+FEFF — byte-visible, never sniffed away. A decoder
      // that stripped it would accept a second, non-canonical byte encoding of the same
      // JSON past safeParseJson.
      const decoded = Triauth.Helpers.base64UrlToString('77u_eyJhIjoxfQ');
      assert.equal(decoded, '\uFEFF{"a":1}');

      try {
        Triauth.Helpers.safeParseJson(decoded);
        assert(false);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        } else {
          assert(true);
        }
      }
    });

    it('still throws on malformed base64url input', () => {
      try {
        Triauth.Helpers.base64UrlToString('A'); // length ≡ 1 (mod 4) is never valid base64
        assert(false);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        } else {
          assert(true);
        }
      }
    });

    it('throws on unpaired surrogates when encoding', () => {
      // Ill-formed UTF-16 has no UTF-8 encoding. Unreachable from the public API (both call
      // sites encode JSON.stringify output, which escapes unpaired surrogates as \udXXX).
      try {
        Triauth.Helpers.stringToBase64Url('\uD800');
        assert(false);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        }
        assert.equal(err.name, 'TypeError');
      }
    });

  });

  describe('stringToUtf8Bytes / utf8BytesToString / byteSize', () => {

    const decodeThrows = (bytes, label) => {
      try {
        Triauth.Helpers.utf8BytesToString(Uint8Array.from(bytes));
        assert(false, `expected a throw: ${label}`);
      } catch (err) {
        if (err?.name === 'AssertionError') {
          throw err;
        }
        assert.equal(err.name, 'TypeError', label);
      }
    };

    it('rejects every class of ill-formed UTF-8 sequence', () => {
      // Overlong encodings — a shorter spelling of the same code point exists
      decodeThrows([0xC0, 0x80], 'overlong NUL (C0 80)');
      decodeThrows([0xC1, 0xBF], 'overlong (C1 BF)');
      decodeThrows([0xE0, 0x80, 0xAF], 'overlong (E0 80 AF)');
      decodeThrows([0xF0, 0x80, 0x80, 0x8F], 'overlong (F0 80 80 8F)');

      // The UTF-16 surrogate range U+D800-U+DFFF has no UTF-8 encoding
      decodeThrows([0xED, 0xA0, 0x80], 'encoded surrogate U+D800 (ED A0 80)');
      decodeThrows([0xED, 0xBF, 0xBF], 'encoded surrogate U+DFFF (ED BF BF)');

      // Above U+10FFFF
      decodeThrows([0xF4, 0x90, 0x80, 0x80], 'U+110000 (F4 90 80 80)');
      decodeThrows([0xF5, 0x80, 0x80, 0x80], 'lead byte F5');
      decodeThrows([0xFF], 'lead byte FF');

      // Truncated and stray sequences
      decodeThrows([0xE9], 'lone latin-1 high byte (E9)');
      decodeThrows([0xC3], 'truncated 2-byte sequence');
      decodeThrows([0xE2, 0x82], 'truncated 3-byte sequence');
      decodeThrows([0xF0, 0x9F, 0x92], 'truncated 4-byte sequence');
      decodeThrows([0x80], 'stray continuation byte');
      decodeThrows([0xC3, 0x28], 'lead followed by a non-continuation byte');
    });

    it('decodes the full well-formed range, boundaries included', () => {
      const cases = [
        [[], ''],
        [[0x00], '\u0000'],
        [[0x0A, 0x7F], '\n\u007F'],
        [[0xC2, 0x80], '\u0080'],
        [[0xDF, 0xBF], '\u07FF'],
        [[0xE0, 0xA0, 0x80], '\u0800'],
        [[0xED, 0x9F, 0xBF], '\uD7FF'],           // last code point below the surrogate gap
        [[0xEE, 0x80, 0x80], '\uE000'],           // first code point above it
        [[0xEF, 0xBF, 0xBD], '\uFFFD'],           // a literal replacement character is well-formed
        [[0xEF, 0xBB, 0xBF, 0x61], '\uFEFFa'],    // BOM kept byte-visible, not stripped
        [[0xF0, 0x90, 0x80, 0x80], '\u{10000}'],
        [[0xF4, 0x8F, 0xBF, 0xBF], '\u{10FFFF}'],
      ];

      for (const [bytes, expected] of cases) {
        assert.equal(Triauth.Helpers.utf8BytesToString(Uint8Array.from(bytes)), expected, bytes.join(','));
      }
    });

    it('encodes each UTF-8 length class byte-exactly and round-trips', () => {
      const cases = [
        ['', []],
        ['A', [0x41]],
        ['é', [0xC3, 0xA9]],
        ['€', [0xE2, 0x82, 0xAC]],
        ['\u{1F389}', [0xF0, 0x9F, 0x8E, 0x89]],
      ];

      for (const [s, bytes] of cases) {
        assert.deepEqual(Array.from(Triauth.Helpers.stringToUtf8Bytes(s)), bytes, JSON.stringify(s));
        assert.equal(Triauth.Helpers.utf8BytesToString(Triauth.Helpers.stringToUtf8Bytes(s)), s);
      }
    });

    it('rejects unpaired surrogates when encoding', () => {
      for (const s of ['\uD800', '\uDC00', 'a\uD800z', '\uD800\uD800', 'tail\uDBFF']) {
        try {
          Triauth.Helpers.stringToUtf8Bytes(s);
          assert(false, JSON.stringify(s));
        } catch (err) {
          if (err?.name === 'AssertionError') {
            throw err;
          }
          assert.equal(err.name, 'TypeError', JSON.stringify(s));
        }
      }
    });

    it('byteSize counts UTF-8 bytes without ever throwing', () => {
      assert.equal(Triauth.Helpers.byteSize(''), 0);
      assert.equal(Triauth.Helpers.byteSize('abc'), 3);
      assert.equal(Triauth.Helpers.byteSize('é'), 2);
      assert.equal(Triauth.Helpers.byteSize('€'), 3);
      assert.equal(Triauth.Helpers.byteSize('\u{1F389}'), 4);
      assert.equal(Triauth.Helpers.byteSize('𐀀'), 4); // a valid pair is one 4-byte code point

      // An unpaired surrogate counts as 3 bytes (the length of its U+FFFD substitute), so
      // limit checks stay meaningful even for strings the strict codec refuses to encode.
      assert.equal(Triauth.Helpers.byteSize('\uD800'), 3);
      assert.equal(Triauth.Helpers.byteSize('a\uDC00b'), 5);
    });

    it('agrees with the platform codecs across a randomized corpus (differential oracle)', () => {
      const oracleEncoder = new TextEncoder();
      const oracleDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

      // Deterministic Park-Miller LCG so any failure reproduces exactly
      let state = 0xC0FFEE;
      const rand = (n) => {
        state = (state * 48271) % 2147483647;
        return state % n;
      };

      const randomWellFormed = () => {
        let s = '';
        const len = rand(64);
        for (let i = 0; i < len; i++) {
          const bucket = rand(4);
          let cp;
          if (bucket === 0) {
            cp = rand(0x80);                                            // ASCII
          } else if (bucket === 1) {
            cp = 0x80 + rand(0x800 - 0x80);                             // 2-byte
          } else if (bucket === 2) {
            do { cp = 0x800 + rand(0x10000 - 0x800); } while (cp >= 0xD800 && cp <= 0xDFFF); // 3-byte
          } else {
            cp = 0x10000 + rand(0x110000 - 0x10000);                    // astral (4-byte)
          }
          s += String.fromCodePoint(cp);
        }
        return s;
      };

      for (let round = 0; round < 300; round++) {
        const s = randomWellFormed();
        const encoded = Triauth.Helpers.stringToUtf8Bytes(s);

        assert.deepEqual(Array.from(encoded), Array.from(oracleEncoder.encode(s)), JSON.stringify(s));
        assert.equal(Triauth.Helpers.utf8BytesToString(encoded), oracleDecoder.decode(encoded), JSON.stringify(s));
        assert.equal(Triauth.Helpers.byteSize(s), encoded.length, JSON.stringify(s));

        // Mutate one byte: both codecs must agree — same decoded string, or both reject
        if (encoded.length > 0) {
          const mutated = Uint8Array.from(encoded);
          mutated[rand(mutated.length)] = rand(256);

          let ours = null;
          let oracle = null;
          try { ours = Triauth.Helpers.utf8BytesToString(mutated); } catch { /* rejection recorded as null */ }
          try { oracle = oracleDecoder.decode(mutated); } catch { /* rejection recorded as null */ }

          assert.equal(ours, oracle, `bytes: ${Array.from(mutated).join(',')}`);
        }
      }
    });

  });

  describe('Triauth.Helpers.verifyOptionsSchema', () => {
    const schema = {use: [/^(auth|sign)$/], mode: ['public', 'private']};

    it('accepts whitelisted critical options by exact string or regexp match', () => {
      assert.equal(Triauth.Helpers.verifyOptionsSchema({}, schema), true);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({use: 'auth', mode: 'private'}, schema), true);
    });

    it('rejects unknown critical options and non-matching values', () => {
      assert.equal(Triauth.Helpers.verifyOptionsSchema({unknown: '1'}, schema), false);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({use: 'bogus'}, schema), false);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({mode: ''}, schema), false);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({use: 42}, schema), false);
    });

    it('passes x- experimental options as long as they are normal strings', () => {
      assert.equal(Triauth.Helpers.verifyOptionsSchema({'x-lab': 'on'}, schema), true);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({'x-lab': 'a\x00b'}, schema), false);
    });

    it('accepts predicate values on an exactly-true return, rejecting anything else', () => {
      const predicated = {list: [(v) => v.split(',').every((entry) => entry.length > 0)]};
      assert.equal(Triauth.Helpers.verifyOptionsSchema({list: 'a,b'}, predicated), true);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({list: 'a,'}, predicated), false);

      // A truthy-but-not-true return does not accept
      assert.equal(Triauth.Helpers.verifyOptionsSchema({list: 'x'}, {list: [(v) => v.length]}), false);

      // Non-string values never reach the predicate (this one would throw on 42)
      assert.equal(Triauth.Helpers.verifyOptionsSchema({list: 42}, {list: [(v) => v.startsWith('a')]}), false);
    });

    it('matches each option against its full allowed-value list: strings, regexps, and predicates compose', () => {
      const mixed = {v: ['literal', /^regexp$/, (x) => x === 'predicate']};
      assert.equal(Triauth.Helpers.verifyOptionsSchema({v: 'literal'}, mixed), true);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({v: 'regexp'}, mixed), true);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({v: 'predicate'}, mixed), true);
      assert.equal(Triauth.Helpers.verifyOptionsSchema({v: 'other'}, mixed), false);
    });
  });

  describe('randomString', () => {

    it('draws bytes from the passed config.randomSource, defaulting to the global config', () => {
      // A per-call effective config with a deterministic byte stream must shape the output
      const zeroes = (arr) => arr.fill(0);
      assert.equal(Triauth.Helpers.randomString(24, {randomSource: zeroes}), 'A'.repeat(24));

      // Without the argument, the global Triauth.config.randomSource applies
      const saved = Triauth.config.randomSource;
      try {
        Triauth.config.randomSource = (arr) => arr.fill(0xff);
        assert.equal(Triauth.Helpers.randomString(4), '____');
      } finally {
        Triauth.config.randomSource = saved;
      }
    });

    it('threads a per-call config.randomSource into the challenge nonce (Challenge.build)', () => {
      const identity = new Triauth.Identity('john@triauthdemo.org');
      const challenge = Triauth.Challenge.build('auth', identity, {}, {randomSource: (arr) => arr.fill(0)});

      assert.equal(challenge.data.nonce, 'A'.repeat(24));
    });
  });
}); }
