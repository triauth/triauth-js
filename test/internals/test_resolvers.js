import DnsResolverStub from '../stubs/dns_resolver.js';

import { itNode } from '../env.js';

// Response-shaped stub over the text() fallback path, one JSON payload per call.
const textResponse = (payload) => ({
  ok: true, status: 200,
  headers: { get: () => null },
  text: () => Promise.resolve(JSON.stringify(payload)),
  body: null
});

export default function() { describe('DNS Resolvers', () => {

  describe('Triauth.Resolvers.Base.resolve', () => {

    it('rejects as abstract - a subclass must implement it', async () => {
      await assert.rejects(
        new Triauth.Resolvers.Base().resolve('example.com', 'TXT'),
        /Triauth\.Resolvers\.Base#resolve is abstract and must be implemented by a subclass/
      );
    });

  });

  describe('Triauth.Resolvers.Base.resolveConfig', () => {

    it('correctly parses configuration from DNS TXT records', async () => {
      const dnsResolver = new DnsResolverStub(
        {'config.test': {'TXT':
              [
                {value: 'config-key config-value config-option-key[1]=config-option-value-1 config-option-key[2]=config-option-value-2', ttl: 0, dnssec: false},
                {value: 'key BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 0, dnssec: false},
                {value: 'utf-8 %5EA%C4%84%5E opt=Z%3D%C5%BB', ttl: 0, dnssec: false},
                {value: 'uri-malformed %5EA%C4%84%5', ttl: 0, dnssec: false},
              ]
          }}
      );

      const records = await dnsResolver.resolveConfig('config.test');

      assert.equal(records[0].key, 'config-key');
      assert.equal(records[0].value, 'config-value');
      assert.equal(Object.keys(records[0].options).length, 2);
      assert.equal(records[0].options['config-option-key[1]'], 'config-option-value-1');
      assert.equal(records[0].options['config-option-key[2]'], 'config-option-value-2');

      assert.equal(records[1].key, 'key');
      assert.equal(records[1].value, 'BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8');

      // Values and option values are consumed as published - the record layer never percent-decodes
      assert.equal(records[2].key, 'utf-8');
      assert.equal(records[2].value, '%5EA%C4%84%5E');
      assert.equal(records[2].options['opt'], 'Z%3D%C5%BB');

      // A '%' is an ordinary character at this layer, so a lone trailing '%' parses fine too
      assert.equal(records[3].key, 'uri-malformed');
      assert.equal(records[3].value, '%5EA%C4%84%5');
    });

    it('extracts options only from the trailing run of whole tokens', async () => {
      const dnsResolver = new DnsResolverStub(
        {'config.test': {'TXT':
              [
                {value: 'name John x-a=1 Doe', ttl: 0, dnssec: false},                  // mid-record option-shaped token is value text
                {value: 'name price a+b=c', ttl: 0, dnssec: false},                     // '=' inside a non-option token never yields a sub-token option
                {value: 'name John x-a=1 x-b=2', ttl: 0, dnssec: false},                // multi-option trailing run
                {value: 'name John x-a=1 x-a=2', ttl: 0, dnssec: false},                // repeated key within the run: last occurrence wins
                {value: 'name x-a=1', ttl: 0, dnssec: false},                           // options-only record has an empty value and is ignored
                {value: 'triauth mode=private auth.example.com', ttl: 0, dnssec: false}, // leading option-shaped token is value text
                {value: 'name John x-a%3D1', ttl: 0, dnssec: false},                    // %3D keeps an option-shaped final token inside the value
              ]
          }}
      );

      const records = await dnsResolver.resolveConfig('config.test');

      assert.equal(records.length, 6);

      assert.equal(records[0].value, 'John x-a=1 Doe');
      assert.equal(Object.keys(records[0].options).length, 0);

      assert.equal(records[1].value, 'price a+b=c');
      assert.equal(Object.keys(records[1].options).length, 0);

      assert.equal(records[2].value, 'John');
      assert.equal(Object.keys(records[2].options).length, 2);
      assert.equal(records[2].options['x-a'], '1');
      assert.equal(records[2].options['x-b'], '2');

      assert.equal(records[3].value, 'John');
      assert.equal(Object.keys(records[3].options).length, 1);
      assert.equal(records[3].options['x-a'], '2');

      assert.equal(records[4].key, 'triauth');
      assert.equal(records[4].value, 'mode=private auth.example.com');
      assert.equal(Object.keys(records[4].options).length, 0);

      // %3D is literal at this layer; the token still has no '=' so it never parses as an option
      assert.equal(records[5].value, 'John x-a%3D1');
      assert.equal(Object.keys(records[5].options).length, 0);
    });

    it('discards reserved option keys while keeping the record and its remaining options', async () => {
      const dnsResolver = new DnsResolverStub(
        {'config.test': {'TXT':
              [
                {value: 'name John __proto__=evil', ttl: 0, dnssec: false},
                {value: 'name John constructor=evil', ttl: 0, dnssec: false},
                {value: 'name John prototype=evil', ttl: 0, dnssec: false},
                {value: 'name John __proto__=evil x-a=1', ttl: 0, dnssec: false}, // sibling options in the same run survive
              ]
          }}
      );

      const records = await dnsResolver.resolveConfig('config.test');

      assert.equal(records.length, 4);

      for (const record of records) {
        assert.equal(record.value, 'John');

        // The bag inherits nothing an attacker-controlled key could reach or shadow;
        // direct reads double as tripwires (on an ordinary object, ['__proto__'] and
        // ['constructor'] resolve through the prototype chain to non-undefined values).
        assert.equal(Object.getPrototypeOf(record.options), null);
        assert.equal(record.options['__proto__'], undefined);
        assert.equal(record.options['constructor'], undefined);
        assert.equal(record.options['prototype'], undefined);
      }

      assert.equal(Object.keys(records[0].options).length, 0);
      assert.equal(Object.keys(records[1].options).length, 0);
      assert.equal(Object.keys(records[2].options).length, 0);

      assert.equal(Object.keys(records[3].options).length, 1);
      assert.equal(records[3].options['x-a'], '1');
    });

    it('keeps the value verbatim between the key and the option run', async () => {
      const dnsResolver = new DnsResolverStub(
        {'config.test': {'TXT':
              [
                'name John   Doe Jr x-a=1',    // inner blank runs of the value survive as published
                'name John  x-a=1 \t x-b=2  ', // blank runs around the options are separators only
                'name John  ',                 // trailing blanks are not part of the value
                'name x-a=1 x-b=2',            // a run of options with no value in front is ignored
              ]
          }}
      );

      const records = await dnsResolver.resolveConfig('config.test');

      assert.equal(records.length, 3);

      assert.equal(records[0].value, 'John   Doe Jr');
      assert.deepEqual(Object.entries(records[0].options), [['x-a', '1']]);

      assert.equal(records[1].value, 'John');
      assert.deepEqual(Object.entries(records[1].options), [['x-a', '1'], ['x-b', '2']]);

      assert.equal(records[2].value, 'John');
      assert.equal(Object.keys(records[2].options).length, 0);
    });

    it('ignores a record whose text spans a line, while other blanks separate tokens', async () => {
      const dnsResolver = new DnsResolverStub(
        {'config.test': {'TXT':
              [
                'name John\nx-a=1',
                'name John x-a=1\n',
                'name John\r',
                'name John\tx-a=1',
              ]
          }}
      );

      const records = await dnsResolver.resolveConfig('config.test');

      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'John');
      assert.deepEqual(Object.entries(records[0].options), [['x-a', '1']]);
    });

    it('parses a DNS-sized record in time linear to its size', async () => {
      // A TXT record tops out at 64 KB. Each parses in a few milliseconds, so the budget is generous.
      const dnsResolver = new DnsResolverStub(
        {'config.test': {'TXT':
              [
                'name x' + ' a=b'.repeat(16000),     // the longest option run that fits a record
                'name' + ' ab'.repeat(16000),        // as many value tokens
                'name' + ' '.repeat(32000) + 'x\n',  // a blank run that ends in a line terminator
              ]
          }}
      );

      const started = performance.now();
      const records = await dnsResolver.resolveConfig('config.test');
      const elapsed = performance.now() - started;

      assert.equal(records.length, 2);

      assert.equal(records[0].value, 'x');
      assert.deepEqual(Object.entries(records[0].options), [['a', 'b']]);

      assert.equal(records[1].value, 'ab' + ' ab'.repeat(15999));
      assert.equal(Object.keys(records[1].options).length, 0);

      assert(elapsed < 500, `parsing three 64 KB records took ${Math.round(elapsed)}ms`);
    });

  });

  describe('Triauth.Resolvers.MultiResolver', async () => {

    it('correctly resolves', async () => {
      const multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:20, dnssec:true}, {value:'key BBBB', ttl:20, dnssec:true}, {value:'key CCCC', ttl:20, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key BBBB', ttl:10, dnssec:false}, {value:'key AAAA', ttl:10, dnssec:false}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:undefined, dnssec:undefined}, {value:'key CCCC', ttl:undefined, dnssec:undefined}]}})
      ], {maxFailures:0});

      const records = await multiResolver.resolveConfig('config.test');

      assert.equal(records.length, 1);
      assert.equal(records[0].key, 'key');
      assert.equal(records[0].value, 'AAAA');
      assert.equal(records[0].ttl, 10);
      assert.equal(records[0].dnssec, false);
    });

    it('correctly sets the dnssec flag', async () => {
      let multiResolver, records;

      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:false}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}})
      ], {maxFailures:0});

      records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].dnssec, false, 'when any resolver returns false, dnssec must be false');

      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}})
      ], {maxFailures:0});

      records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].dnssec, true, 'undefined value should not affect computed dnssec status');

      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}}),
      ], {maxFailures:0});

      records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].dnssec, undefined, 'should be undefined when all resolvers return undefined dnssec')
    });

    it('computes the dnssec flag independently of resolver order', async () => {
      let multiResolver, records;

      // A no-opinion resolver listed first must not mask explicit true reports from later resolvers
      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}})
      ], {maxFailures:0});

      records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].dnssec, true, 'explicit true reports determine the flag even when the first resolver has no opinion');

      // An explicit false vetoes from any position in the fleet
      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:undefined}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:false}]}})
      ], {maxFailures:0});

      records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].dnssec, false, 'an explicit false vetoes regardless of resolver order');
    });

    it('keeps a TTL of 0 in the min-aggregation, independently of resolver order', async () => {
      // TTL 0 means immediate expiry (e.g., revocation); it must win the min
      // against larger TTLs from other resolvers, from any position in the fleet
      let multiResolver, records;

      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:0, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:300, dnssec:true}]}})
      ], {maxFailures:0});

      records = await multiResolver.resolve('config.test', 'TXT');

      assert.strictEqual(records[0].ttl, 0, 'a TTL of 0 reported first must not be overwritten by a larger TTL');

      multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:300, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:0, dnssec:true}]}})
      ], {maxFailures:0});

      records = await multiResolver.resolve('config.test', 'TXT');

      assert.strictEqual(records[0].ttl, 0, 'a TTL of 0 reported later must win the min against a larger TTL');
    });

    // Records the options each sub-resolver receives, for fan-out and signal-propagation assertions.
    class OptionsCapturingStub extends DnsResolverStub {
      resolve(domainName, type, options = {}) {
        this.sawSignalKey = 'signal' in options;
        this.sawOptions = Object.assign({}, options);
        return super.resolve(domainName, type, options);
      }
    }

    it('fans out per-call and constructor options to sub-resolvers, keeping its own consumed keys', async () => {
      const stub = new OptionsCapturingStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}});
      const multiResolver = new Triauth.Resolvers.MultiResolver([stub], {maxFailures:0, skipPadding:true});

      const records = await multiResolver.resolve('config.test', 'TXT', {retries:2, normalizeTxtRecords:true, timeout:5000});

      assert.equal(records[0].value, 'key AAAA');
      assert.equal(stub.sawOptions.retries, 2, 'per-call sub-resolver options must cross the fan-out boundary');
      assert.equal(stub.sawOptions.normalizeTxtRecords, true, 'per-call TXT flags must cross the fan-out boundary');
      assert.equal(stub.sawOptions.skipPadding, true, 'constructor-level options fan out through the merge');
      assert.equal('maxFailures' in stub.sawOptions, false, 'maxFailures is consumed at the MultiResolver layer');
      assert.equal('timeout' in stub.sawOptions, false, 'timeout is consumed at the MultiResolver layer');
    });

    it('attaches an abort signal to sub-resolvers when AbortController is available', async () => {
      const stub = new OptionsCapturingStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}});
      const multiResolver = new Triauth.Resolvers.MultiResolver([stub], {maxFailures:0});

      const records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].value, 'AAAA');
      assert.strictEqual(stub.sawSignalKey, true, 'an AbortSignal should be attached when AbortController is available');
    });

    it('tolerates sub-resolver failures within the maxFailures budget', async () => {
      const multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{_error: 'boom'}})
      ], {maxFailures:1});

      const records = await multiResolver.resolveConfig('config.test');

      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'AAAA');
    });

    it('rejects when failures exceed maxFailures', async () => {
      const multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}}),
        new DnsResolverStub({'config.test':{_error: 'boom'}})
      ], {maxFailures:0});

      await assert.rejects(
        multiResolver.resolve('config.test', 'TXT'),
        (reasons) => Array.isArray(reasons) && reasons.length === 1 && /boom/.test(reasons[0].message)
      );
    });

    it('rejects when every resolver fails, regardless of the maxFailures budget', async () => {
      const multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{_error: 'boom one'}}),
        new DnsResolverStub({'config.test':{_error: 'boom two'}})
      ], {maxFailures:5});

      await assert.rejects(
        multiResolver.resolve('config.test', 'TXT'),
        (reasons) => Array.isArray(reasons) && reasons.length === 2
      );
    });

    it('rejects with a timeout when resolvers stall (AbortController present)', async () => {
      // A stub that never settles: no timers involved, so mocha exits cleanly.
      const stalling = new DnsResolverStub();
      stalling.resolve = () => new Promise(() => {});

      const multiResolver = new Triauth.Resolvers.MultiResolver([stalling], {maxFailures:0, timeout:50});

      await assert.rejects(multiResolver.resolve('config.test', 'TXT'), /MultiResolver timeout/);
    });

    it('clears the timeout when resolution completes in time', async () => {
      const multiResolver = new Triauth.Resolvers.MultiResolver([
        new DnsResolverStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}})
      ], {maxFailures:0, timeout:5000});

      const records = await multiResolver.resolveConfig('config.test');

      assert.equal(records[0].value, 'AAAA');
    });

    describe('without AbortController', () => {

      // Simulates a runtime that lacks AbortController (e.g. nginx/njs): resolution must
      // proceed, options.timeout is ignored, and no signal may reach the sub-resolvers.

      let originalAbortController;
      beforeEach(() => { originalAbortController = globalThis.AbortController; });
      afterEach(() => { globalThis.AbortController = originalAbortController; });

      it('resolves and passes no signal key to sub-resolvers', async () => {
        globalThis.AbortController = undefined;       // the runtime lacks it

        const stub = new OptionsCapturingStub({'config.test':{'TXT':[{value:'key AAAA', ttl:10, dnssec:true}]}});
        // timeout is set on purpose: it must be ignored without AbortController
        const multiResolver = new Triauth.Resolvers.MultiResolver([stub], {maxFailures:0, timeout:1000});

        const records = await multiResolver.resolveConfig('config.test');

        assert.equal(records.length, 1);
        assert.equal(records[0].value, 'AAAA');
        assert.strictEqual(stub.sawSignalKey, false, 'no AbortSignal should be attached when AbortController is unavailable');
      });

    });

  });

  describe('TXT character-string concatenation', () => {

    // A TXT record's RDATA is one or more 255-octet character-strings whose contents concatenate
    // in order with no separator. Each resolver path delivers that logical content.

    let originalFetch;
    beforeEach(() => { originalFetch = globalThis.fetch; });
    afterEach(() => { globalThis.fetch = originalFetch; });

    // Response-shaped stub whose body streams one JSON payload.
    const stubJsonFetch = (payload) => () => {
      const bytes = new TextEncoder().encode(JSON.stringify(payload));
      let sent = false;
      return Promise.resolve({
        ok: true, status: 200,
        headers: { get: () => null },
        body: new ReadableStream({
          pull(c) {
            if (sent) { c.close(); return; }
            sent = true;
            c.enqueue(bytes);
          }
        }, {highWaterMark: 0})
      });
    };

    // Response-shaped stub streaming raw bytes, chunkSize bytes at a time.
    const stubBytesFetch = (bytes, chunkSize = bytes.length) => () => {
      let offset = 0;
      return Promise.resolve({
        ok: true, status: 200,
        headers: { get: () => null },
        body: new ReadableStream({
          pull(c) {
            if (offset >= bytes.length) { c.close(); return; }
            c.enqueue(bytes.slice(offset, offset + chunkSize));
            offset += chunkSize;
          }
        }, {highWaterMark: 0})
      });
    };

    itNode('NodeDns joins a multi-chunk TXT answer with no separator', async () => {
      const nodeDns = new Triauth.Resolvers.NodeDns();

      // node:dns delivers each TXT answer as an array of character-string chunks
      nodeDns.dns = {
        Resolver: class {
          constructor() {}
          cancel() {}
          resolveTxt(domain, cb) { cb(null, [['key part1', 'part2'], ['single']]); }
        }
      };

      const records = await nodeDns.resolve('config.test', 'TXT');

      assert.equal(records.length, 2);
      assert.equal(records[0].value, 'key part1part2');
      assert.equal(records[1].value, 'single');
    });

    itNode('NodeDns resolves an empty answer for NXDOMAIN and NODATA alike, and propagates other errors', async () => {
      const nodeDns = new Triauth.Resolvers.NodeDns();

      const stubDnsError = (code) => ({
        Resolver: class {
          constructor() {}
          cancel() {}
          resolveTxt(domain, cb) { const e = new Error(`queryTxt ${code}`); e.code = code; cb(e); }
        }
      });

      // A missing name and a name with no TXT records are both empty answers,
      // matching how the DoH resolvers report the same DNS states
      nodeDns.dns = stubDnsError('ENOTFOUND');
      assert.deepEqual(await nodeDns.resolve('config.test', 'TXT'), []);

      nodeDns.dns = stubDnsError('ENODATA');
      assert.deepEqual(await nodeDns.resolve('config.test', 'TXT'), []);

      nodeDns.dns = stubDnsError('ETIMEOUT');
      await assert.rejects(nodeDns.resolve('config.test', 'TXT'), (err) => err.code === 'ETIMEOUT');
    });

    itNode('NodeDns rejects instead of hanging when the resolver cannot be constructed (e.g., out-of-range options)', async () => {
      const nodeDns = new Triauth.Resolvers.NodeDns();

      nodeDns.dns = {
        Resolver: class {
          constructor() { throw new Error('ERR_OUT_OF_RANGE'); }
        }
      };

      await assert.rejects(nodeDns.resolve('config.test', 'TXT'), /ERR_OUT_OF_RANGE/);
    });

    it('DnsJson.normalizeTxtData concatenates presentation-form character-strings', () => {
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"abc" "def"'), 'abcdef');
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"abc"'), 'abc');
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"a" "b" "c"'), 'abc');
    });

    it('DnsJson.normalizeTxtData decodes escaped quotes and backslashes as literals', () => {
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"a\\"b" "c\\\\d"'), 'a"bc\\d');
    });

    it('DnsJson.normalizeTxtData keeps escapes verbatim with keepEscapes, for the single-pass decode stage', () => {
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"a\\"b" "c\\\\d"', true), 'a\\"bc\\\\d');
    });

    it('DnsJson.normalizeTxtData returns logical-form and malformed data unchanged', () => {
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('key plain-value'), 'key plain-value');
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"unterminated'), '"unterminated');
      assert.equal(Triauth.Resolvers.DnsJson.normalizeTxtData('"a"x"b"'), '"a"x"b"');
    });

    it('Cloudflare yields concatenated content for presentation-form answers, with decimal escapes decoding to utf-8', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          { name: 'config.test', type: 16, TTL: 30, data: '"key part1" "part2"' },
          // a decimal escape pair (RFC 1035 presentation format; Ą = bytes 196 132) split across
          // the character-string boundary decodes after concatenation
          { name: 'config.test', type: 16, TTL: 30, data: '"utf-8 A\\196" "\\132B"' }
        ]
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records[0].value, 'key part1part2');
      assert.equal(records[1].value, 'utf-8 AĄB');
    });

    it('DnsSb yields concatenated content for presentation-form answers', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          { name: 'config.test', type: 16, TTL: 30, data: '"key part1" "part2"' }
        ]
      });

      const resolver = new Triauth.Resolvers.DnsSb({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records[0].value, 'key part1part2');
    });

    it('Google passes logical-form answers through unchanged', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          { name: 'config.test', type: 16, TTL: 30, data: 'key part1part2' }
        ]
      });

      const resolver = new Triauth.Resolvers.Google({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records[0].value, 'key part1part2');
    });

    it('DnsJson resolves a large RRset (150 answers)', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: Array.from({ length: 150 }, (_, i) => ({ name: 'config.test', type: 16, TTL: 30, data: `key device${i}[1/1]:value${i}` }))
      });

      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', {skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records.length, 150);
      assert.equal(records[149].value, 'key device149[1/1]:value149');
    });

    it('DnsJson honors per-call normalizeTxtRecords/decodeTxtRecords overrides in both directions', async () => {
      const payload = {
        Status: 0, AD: true,
        Answer: [
          { name: 'config.test', type: 16, TTL: 30, data: '"key A\\196" "\\132B"' }
        ]
      };

      // Flags absent at construction, enabled per-call: presentation form normalizes and decodes
      globalThis.fetch = stubJsonFetch(payload);
      const bare = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', {skipPadding: true, retries: 0});
      let records = await bare.resolve('config.test', 'TXT', {normalizeTxtRecords: true, decodeTxtRecords: true});
      assert.equal(records[0].value, 'key AĄB');

      // Flags set at construction (Cloudflare), disabled per-call: data passes through verbatim
      globalThis.fetch = stubJsonFetch(payload);
      const cloudflare = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      records = await cloudflare.resolve('config.test', 'TXT', {normalizeTxtRecords: false, decodeTxtRecords: false});
      assert.equal(records[0].value, '"key A\\196" "\\132B"');
    });

    it('Cloudflare decodes same-level presentation escapes in one pass (escaped backslash before digits stays literal)', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          // logical content `literal \123`: presentation escapes the backslash as \\ ,
          // which must not merge with the digits into a \DDD escape
          { name: 'config.test', type: 16, TTL: 30, data: '"literal \\\\123"' },
          { name: 'config.test', type: 16, TTL: 30, data: '"say \\"hi\\""' }
        ]
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records[0].value, 'literal \\123');
      assert.equal(records[1].value, 'say "hi"');
    });

    it('Cloudflare skips records with malformed decimal escapes instead of guessing, keeping siblings', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          // \321 would wrap to 65 ('A') under a mod-256 reading; the record rejects instead
          { name: 'config.test', type: 16, TTL: 30, data: '"over \\321"' },
          // a \DDD escape is exactly three digits; shorter runs reject
          { name: 'config.test', type: 16, TTL: 30, data: '"short \\04"' },
          { name: 'config.test', type: 16, TTL: 30, data: '"key good"' }
        ]
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'key good');
    });

    it('Cloudflare skips a record carrying raw non-octet characters under the escape contract, keeping siblings', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          // decodeTxtRecords means one-char-per-octet content (printable ASCII + \DDD escapes);
          // raw Ą (U+0104) would wrap mod-256 to the control char U+0004 — the record rejects instead
          { name: 'config.test', type: 16, TTL: 30, data: '"ZoĄ \\196\\132"' },
          { name: 'config.test', type: 16, TTL: 30, data: '"key good"' }
        ]
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'key good');
    });

    it('Cloudflare skips a record whose decimal escapes decode to ill-formed UTF-8, keeping its siblings', async () => {
      globalThis.fetch = stubJsonFetch({
        Status: 0, AD: true,
        Answer: [
          // \233 is the lone latin-1 'é' octet (0xE9) — not well-formed UTF-8 on its own,
          // so the record is ignored as a whole (a record value must be well-formed UTF-8)
          { name: 'config.test', type: 16, TTL: 30, data: '"bad \\233"' },
          { name: 'config.test', type: 16, TTL: 30, data: '"key good"' }
        ]
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'key good');
    });

    itNode('NodeDns reinterprets one-char-per-octet chunks as UTF-8, dropping records with ill-formed bytes', async () => {
      const nodeDns = new Triauth.Resolvers.NodeDns();

      nodeDns.dns = {
        Resolver: class {
          constructor() {}
          cancel() {}
          // C3 A9 split across the character-string boundary is UTF-8 'é' after concatenation;
          // the record carrying a lone E9 octet is not well-formed UTF-8
          resolveTxt(domain, cb) { cb(null, [['name Zo\xC3', '\xA9'], ['name Zo\xE9']]); }
        }
      };

      const records = await nodeDns.resolve('config.test', 'TXT');

      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'name Zoé');
    });

    it('DnsJson rejects a response body that is not well-formed UTF-8', async () => {
      // A valid JSON skeleton with a raw 0xE9 octet inside a string value — the body is
      // refused as a whole (a transport-level failure, like a bad status code)
      const head = new TextEncoder().encode('{"Status":0,"AD":true,"Answer":[{"name":"config.test","type":16,"TTL":30,"data":"key ');
      const tail = new TextEncoder().encode('"}]}');
      globalThis.fetch = stubBytesFetch(Uint8Array.from([...head, 0xE9, ...tail]));

      const resolver = new Triauth.Resolvers.Google({skipPadding: true, retries: 0});

      await assert.rejects(resolver.resolve('config.test', 'TXT'));
    });

    it('DnsJson decodes multi-byte characters split across stream chunks', async () => {
      const payload = JSON.stringify({
        Status: 0, AD: true,
        Answer: [{ name: 'config.test', type: 16, TTL: 30, data: 'key Zoé' }]
      });

      // One byte per chunk, so the é's C3 A9 pair always spans a chunk boundary
      globalThis.fetch = stubBytesFetch(new TextEncoder().encode(payload), 1);

      const resolver = new Triauth.Resolvers.Google({skipPadding: true, retries: 0});
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records[0].value, 'key Zoé');
    });

  });

  describe('Triauth.Resolvers.DnsJson retry behavior', () => {

    it('treats an abort from the caller signal as terminal', async () => {
      let calls = 0;
      // First attempt hangs until its per-request signal aborts; any retry would succeed.
      const fetchStub = (url, opts) => {
        calls += 1;
        if (calls === 1) {
          return new Promise((_, rej) => opts.signal.addEventListener('abort', () =>
            rej(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }))));
        }
        return Promise.resolve(textResponse({ Status: 0, AD: true, Answer: [{ name: 'config.test', type: 16, TTL: 30, data: 'key AAAA' }] }));
      };

      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', { skipPadding: true });
      const abortController = new AbortController();
      const pending = resolver.resolve('config.test', 'TXT', { signal: abortController.signal, retries: 2, fetch: fetchStub });

      abortController.abort();

      await assert.rejects(pending, (err) => err.name === 'AbortError');
      assert.equal(calls, 1, 'an aborted resolution must not spend its retry budget');
    });

    it('carries the per-call config across a DNS-status retry (the retried attempt still logs)', async () => {
      let calls = 0;
      const fetchStub = () => {
        calls += 1;
        return Promise.resolve(calls === 1
          ? textResponse({ Status: 2 })  // SERVFAIL — triggers the status-retry path
          : textResponse({ Status: 0, AD: true, Answer: [
              { name: 'config.test', type: 16, TTL: 30, data: 'bad \\999' },  // invalid \DDD escape — logged and skipped
              { name: 'config.test', type: 16, TTL: 30, data: 'key good' }
            ] }));
      };

      const logs = [];
      const logger = { debug: (msg) => logs.push(String(msg)) };

      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', { skipPadding: true });
      const records = await resolver.resolve('config.test', 'TXT',
        { retries: 1, retryDelay: 0, decodeTxtRecords: true, fetch: fetchStub }, { logger });

      assert.equal(calls, 2);
      assert.equal(records.length, 1);
      assert.equal(records[0].value, 'key good');
      assert(logs.some((m) => m.includes('DNS TXT record could not be decoded')),
        'the retried attempt must log through the caller-provided config');
    });

    it('rejects an exhausted DNS-status retry with a real Error naming the status', async () => {
      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', { skipPadding: true });

      await assert.rejects(
        resolver.resolve('config.test', 'TXT', { retries: 0, fetch: () => Promise.resolve(textResponse({ Status: 2 })) }),
        (err) => err instanceof Error && /DNS status 2/.test(err.message)
      );
    });
  });

  describe('Triauth.Resolvers.DnsJson answer filters and transport retries', () => {

    // Answer shapes a real zone never produces: the per-answer filters and the transport-error
    // retry are pinned here, while the published test zone covers what real providers return.
    const answering = (payload) => new Triauth.Resolvers.DnsJson('https://doh.test/dns-query',
      { skipPadding: true, fetch: () => Promise.resolve(textResponse(payload)) });

    it('keeps only well-formed answers for the queried name and type', async () => {
      const records = await answering({ Status: 0, AD: true, Answer: [
        { name: 'config.test',  type: 5,  TTL: 30,  data: 'target.test.' },  // a CNAME entry at the queried name: wrong type
        { name: 'target.test',  type: 16, TTL: 30,  data: 'key target' },    // the alias target's own TXT: wrong name
        { name: 'config.test.', type: 16, TTL: 30,  data: 'key absolute' },  // the queried name in absolute form: kept
        { name: 'config.test',  type: 16, TTL: 30,  data: 42 },              // data must be a string
        { name: 'config.test',  type: 16, TTL: -1,  data: 'key negative' },  // TTL must be a non-negative integer
        { name: 'config.test',  type: 16, TTL: 1.5, data: 'key fraction' },
        { name: 'config.test',  type: 16, TTL: 30,  data: 'key good' }
      ] }).resolve('config.test', 'TXT');

      assert.deepStrictEqual(records.map((r) => r.value).sort(), ['key absolute', 'key good']);
    });

    it('drops every answer of a response whose AD flag is not a boolean', async () => {
      const records = await answering({ Status: 0, AD: 'true', Answer: [
        { name: 'config.test', type: 16, TTL: 30, data: 'key good' }
      ] }).resolve('config.test', 'TXT');

      assert.deepStrictEqual(records, []);
    });

    it('resolves an empty answer for NXDOMAIN (Status 3) without spending retries', async () => {
      let calls = 0;
      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', {
        skipPadding: true, fetch: () => { calls += 1; return Promise.resolve(textResponse({ Status: 3 })); }
      });

      assert.deepStrictEqual(await resolver.resolve('missing.test', 'TXT', { retries: 2 }), []);
      assert.equal(calls, 1);
    });

    it('retries a transport failure once and resolves on the next attempt', async () => {
      let calls = 0;
      const fetchStub = () => {
        calls += 1;
        return calls === 1
          ? Promise.reject(new TypeError('fetch failed'))
          : Promise.resolve(textResponse({ Status: 0, AD: true, Answer: [{ name: 'config.test', type: 16, TTL: 30, data: 'key good' }] }));
      };
      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', { skipPadding: true });

      const records = await resolver.resolve('config.test', 'TXT', { retries: 1, retryDelay: 0, fetch: fetchStub });
      assert.equal(records[0].value, 'key good');
      assert.equal(calls, 2);
    });

    it('rejects a transport failure outright once no retry is left', async () => {
      let calls = 0;
      const resolver = new Triauth.Resolvers.DnsJson('https://doh.test/dns-query', { skipPadding: true });

      await assert.rejects(
        resolver.resolve('config.test', 'TXT', { retries: 0, fetch: () => { calls += 1; return Promise.reject(new TypeError('fetch failed')); } }),
        (err) => err instanceof TypeError && err.message === 'fetch failed'
      );
      assert.equal(calls, 1);
    });

    itNode('NodeDns cancels the in-flight query on abort, and detaches its listener once the query settles', async () => {
      // A hand-rolled signal records what the adapter attaches and detaches; `fire()` plays the abort.
      const signal = () => ({
        handlers: [],
        addEventListener(type, fn) { this.handlers.push(fn); },
        removeEventListener(type, fn) { this.handlers = this.handlers.filter((h) => h !== fn); },
        fire() { for (const fn of this.handlers) fn(); }
      });
      const nodeDns = new Triauth.Resolvers.NodeDns();
      nodeDns.dns = {
        Resolver: class {
          constructor() { this.parked = null; }
          cancel() { this.parked?.(Object.assign(new Error('queryTxt ECANCELLED'), { code: 'ECANCELLED' })); }
          resolveTxt(domain, cb) {
            if (domain === 'parked.test') { this.parked = cb; return; }   // never answers on its own
            cb(null, [['key ok']]);
          }
        }
      };

      const aborting = signal();
      const pending = nodeDns.resolve('parked.test', 'TXT', { signal: aborting });
      await new Promise((resolve) => setTimeout(resolve, 0));   // the adapter loads node:dns before it listens
      assert.equal(aborting.handlers.length, 1, 'the adapter listens for abort while the query is in flight');
      aborting.fire();
      await assert.rejects(pending, (err) => err.code === 'ECANCELLED');
      assert.equal(aborting.handlers.length, 0, 'the listener is detached once the query settles');

      const answered = signal();
      const records = await nodeDns.resolve('answered.test', 'TXT', { signal: answered });
      assert.equal(records[0].value, 'key ok');
      assert.equal(answered.handlers.length, 0, 'a settled query leaves no listener behind');
    });

  });

  describe('Triauth.Resolvers.DnsJson body limits', () => {

    const LIMIT = 256 * 1024;
    const CHUNK = 64 * 1024;

    let originalFetch;

    beforeEach(() => { originalFetch = globalThis.fetch; });
    afterEach(() => { globalThis.fetch = originalFetch; });

    // Build a Response-shaped object whose body stream errors when the request signal aborts.
    // This mirrors real-fetch behavior so the resolver's reader.read() actually rejects on abort.
    // highWaterMark:0 suppresses the speculative pull that would otherwise fire at construction
    // time — we want `pull` invocations to track consumer demand only.
    const makeStubFetch = ({status, contentLength, streamSource}) => (url, opts) => {
      let streamController;
      const body = new ReadableStream({
        start(c) { streamController = c; },
        pull(c) { streamSource(c); }
      }, {highWaterMark: 0});
      opts?.signal?.addEventListener('abort', () => {
        try { streamController.error(opts.signal.reason || new Error('aborted')); } catch { /* already errored */ }
      });
      return Promise.resolve({
        ok: status >= 200 && status < 300,
        status,
        headers: { get: (name) => name.toLowerCase() === 'content-length' ? contentLength : null },
        body
      });
    };

    it('rejects without reading body when Content-Length declares over-limit size', async () => {
      let pulls = 0;
      globalThis.fetch = makeStubFetch({
        status: 200,
        contentLength: String(LIMIT + 1024),
        streamSource: () => { pulls++; }
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      await assert.rejects(resolver.resolve('example.com', 'TXT'));
      assert.strictEqual(pulls, 0, 'body must not be pulled when Content-Length exceeds limit');
    });

    it('aborts the request when streamed bytes exceed the size limit', async () => {
      let bytesEnqueued = 0;
      let signalSeen = null;
      globalThis.fetch = (url, opts) => {
        signalSeen = opts.signal;
        let streamController;
        const body = new ReadableStream({
          start(c) { streamController = c; },
          pull(c) {
            bytesEnqueued += CHUNK;
            c.enqueue(new Uint8Array(CHUNK));
          }
        }, {highWaterMark: 0});
        opts.signal?.addEventListener('abort', () => {
          try { streamController.error(opts.signal.reason); } catch { /* */ }
        });
        return Promise.resolve({
          ok: true, status: 200,
          headers: {get: () => null},
          body
        });
      };

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const start = Date.now();
      await assert.rejects(resolver.resolve('example.com', 'TXT'));
      const elapsed = Date.now() - start;

      assert.ok(elapsed < 5000, `expected fast abort, took ${elapsed}ms`);
      assert.ok(signalSeen?.aborted, 'request signal should be aborted');
      // Resolver accepts up to 4 x 64KB = 256KB (= LIMIT, not >), then rejects the 5th chunk.
      // Allow some slack in case the stream pull is called speculatively beyond what's read.
      assert.ok(bytesEnqueued <= LIMIT + 2 * CHUNK,
        `bytes enqueued (${bytesEnqueued}) exceeded LIMIT + 2*CHUNK (${LIMIT + 2 * CHUNK})`);
    });

    it('rejects non-2xx responses before reading the body', async () => {
      let pulls = 0;
      globalThis.fetch = makeStubFetch({
        status: 500,
        contentLength: null,
        streamSource: () => { pulls++; }
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      await assert.rejects(
        resolver.resolve('example.com', 'TXT'),
        (err) => /500/.test(String(err?.message ?? err))
      );
      assert.strictEqual(pulls, 0, 'body must not be pulled when status is non-2xx');
    });

    it('respects options.timeout when the body is slow (timeout stays armed past headers)', async () => {
      globalThis.fetch = makeStubFetch({
        status: 200,
        contentLength: null,
        streamSource: () => { /* never enqueue: server sent headers then went silent */ }
      });

      const resolver = new Triauth.Resolvers.Cloudflare({skipPadding: true, retries: 0});
      const start = Date.now();
      await assert.rejects(resolver.resolve('example.com', 'TXT', {timeout: 100}));
      const elapsed = Date.now() - start;

      assert.ok(elapsed >= 90, `expected to wait for timeout, only took ${elapsed}ms`);
      assert.ok(elapsed < 1000, `timeout should fire within ~100ms, took ${elapsed}ms`);
    });

  });

  describe('Triauth.Resolvers.DnsJson constrained fetch (injected client, no AbortController/stream)', () => {

    // Simulates a runtime where fetch is injected (not a global), the response
    // exposes only text() (no ReadableStream body), and AbortController is absent.

    let originalFetch, originalAbortController;
    beforeEach(() => {
      originalFetch = globalThis.fetch;
      originalAbortController = globalThis.AbortController;
    });
    afterEach(() => {
      globalThis.fetch = originalFetch;
      globalThis.AbortController = originalAbortController;
    });

    // A text()-only Response
    const textOnlyResponse = (payload, { status = 200, contentLength = null } = {}) => ({
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name) => name.toLowerCase() === 'content-length' ? contentLength : null },
      text: () => Promise.resolve(typeof payload === 'string' ? payload : JSON.stringify(payload))
    });

    it('resolves through an injected fetch with a text()-only response and no AbortController', async () => {
      globalThis.AbortController = undefined;         // the runtime lacks it
      globalThis.fetch = () => { throw new Error('global fetch must not be used'); };

      let sawUrl = null, sawHadSignalKey = true;
      const injectedFetch = (url, opts) => {
        sawUrl = url;
        sawHadSignalKey = 'signal' in opts;           // must be omitted entirely, not set to undefined
        return Promise.resolve(textOnlyResponse({
          Status: 0, AD: true,
          Answer: [{ name: 'config.test', type: 16, TTL: 30, data: '"key part1" "part2"' }]
        }));
      };

      const resolver = new Triauth.Resolvers.Cloudflare({ skipPadding: true, retries: 0, fetch: injectedFetch });
      const records = await resolver.resolve('config.test', 'TXT');

      assert.equal(records[0].value, 'key part1part2');
      assert.equal(records[0].dnssec, true);
      assert.ok(sawUrl.startsWith('https://cloudflare-dns.com/dns-query?name=config.test'));
      assert.strictEqual(sawHadSignalKey, false, 'no AbortSignal should be attached when AbortController is unavailable');
    });

    it('enforces the size cap on the text() fallback path', async () => {
      globalThis.AbortController = undefined;
      const huge = 'x'.repeat(256 * 1024 + 1);
      const injectedFetch = () => Promise.resolve(textOnlyResponse(`{"padding":"${huge}"}`));

      const resolver = new Triauth.Resolvers.Cloudflare({ skipPadding: true, retries: 0, fetch: injectedFetch });
      await assert.rejects(resolver.resolve('example.com', 'TXT'), /size limit/);
    });

    it('honors the Content-Length pre-check without an AbortController', async () => {
      globalThis.AbortController = undefined;
      let textRead = false;
      const injectedFetch = () => Promise.resolve({
        ok: true, status: 200,
        headers: { get: (name) => name.toLowerCase() === 'content-length' ? String(256 * 1024 + 1024) : null },
        text: () => { textRead = true; return Promise.resolve('{}'); }
      });
      const resolver = new Triauth.Resolvers.Cloudflare({ skipPadding: true, retries: 0, fetch: injectedFetch });
      await assert.rejects(resolver.resolve('example.com', 'TXT'), /Content-Length/);
      assert.strictEqual(textRead, false, 'body must not be read when Content-Length exceeds the limit');
    });

    it('rejects when no fetch implementation is available', async () => {
      globalThis.fetch = undefined;
      const resolver = new Triauth.Resolvers.Cloudflare({ skipPadding: true, retries: 0 });
      await assert.rejects(resolver.resolve('example.com', 'TXT'), /No fetch implementation/);
    });

  });

}); }
