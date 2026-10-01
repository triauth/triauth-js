import { KNOWN_CONFIG_KEYS } from '../../src/config.js';

export default function() { describe('Config override guard (103)', () => {

  // Every config-consuming public method runs the same guard. The challenge-response methods
  // (authenticate/ping/attest/sign/stamp) share it via ChallengeResponseFlow.perform; check/verify/whois
  // each carry their own. validate is intentionally excluded - it ignores config entirely.
  const opts = { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.org/cb' };
  const callWith = (config) => Promise.all([
    Triauth.authenticate(opts, config),
    Triauth.ping(opts, config),
    Triauth.attest(opts, config),
    Triauth.sign(opts, config),
    Triauth.stamp(opts, config),
    Triauth.check({ identifier: 'john@triauthdemo.org', deviceTag: 'tag' }, config),
    Triauth.verify('message', 'signature', {}, config),
    Triauth.whois({ identifier: 'john@triauthdemo.org' }, config),
  ]);

  it('KNOWN_CONFIG_KEYS is a frozen snapshot of the declared keys, and cid defaults to null', () => {
    assert.ok(Object.isFrozen(KNOWN_CONFIG_KEYS), 'snapshot must be frozen');
    assert.ok(KNOWN_CONFIG_KEYS.includes('cid'));
    assert.ok(KNOWN_CONFIG_KEYS.includes('requireSecure'));
    assert.deepEqual([...KNOWN_CONFIG_KEYS].sort(), Object.keys(Triauth.config).sort());
    assert.strictEqual(Triauth.config.cid, null);
  });

  it('rejects a per-call override carrying an unknown key (103) on every config-consuming method', async () => {
    // `requireSecur` is a misspelling of `requireSecure` - without the guard it would be silently
    // ignored, leaving the caller believing DNSSEC was required when it was not.
    for (const r of await callWith({ requireSecur: true })) {
      assert.strictEqual(r.error?.code, 103);
      assert.strictEqual(r.error?.message, 'Unrecognized configuration key');
    }
  });

  it('rejects a known key explicitly set to undefined (103), which would otherwise clobber its default', async () => {
    // requireSecure:undefined would disable the DNSSEC requirement; a drift set to undefined would
    // poison the freshness arithmetic with NaN. The strict guard refuses both - pass a value or omit.
    assert.strictEqual((await Triauth.verify('m', 's', {}, { requireSecure: undefined })).error?.code, 103);
    assert.strictEqual((await Triauth.whois({ identifier: 'john@triauthdemo.org' }, { maximalAllowedClientClockDrift: undefined })).error?.code, 103);
  });

  it('accepts a valid override (no 103 - processing continues to its normal result)', async () => {
    // verify is network-free, so this exercises the guard's accept path without DNS.
    const r = await Triauth.verify('m', 's', {}, { requireSecure: true, maximalAllowedClientClockDrift: 1000 });
    assert.notStrictEqual(r.error?.code, 103);
  });

  it('treats cid well: null / false / a string pass, undefined is rejected (103)', async () => {
    assert.notStrictEqual((await Triauth.verify('m', 's', {}, { cid: null })).error?.code, 103);
    assert.notStrictEqual((await Triauth.verify('m', 's', {}, { cid: false })).error?.code, 103);
    assert.notStrictEqual((await Triauth.verify('m', 's', {}, { cid: 'corr-123' })).error?.code, 103);
    assert.strictEqual((await Triauth.verify('m', 's', {}, { cid: undefined })).error?.code, 103);
  });

  it('catches a typo introduced via global Triauth.config mutation, then recovers once cleaned up', async () => {
    // Validating the *merged* config means a stray global key is caught on the very next call,
    // even with no per-call override at all.
    assert.ok(!('requireSecur' in Triauth.config));
    Triauth.config.requireSecur = true;
    try {
      const r = await Triauth.verify('m', 's', {});
      assert.strictEqual(r.error?.code, 103);
    } finally {
      delete Triauth.config.requireSecur;
    }
    assert.notStrictEqual((await Triauth.verify('m', 's', {})).error?.code, 103);
  });

  it('honors a logger override', async () => {
    const r1 = await Triauth.verify('m', 's', {}, { logger: null });
    assert.notStrictEqual(r1.error?.code, 103);

    const custom = { debug() {}, info() {}, warn() {}, error() {} };
    const r2 = await Triauth.verify('m', 's', {}, { logger: custom });
    assert.notStrictEqual(r2.error?.code, 103);
  });

  it('validate carries the same config override guard', () => {
    // unknown key -> 103
    const bad = Triauth.validate({ identifier: 'john@triauthdemo.org' }, { requireSecur: true });
    assert.strictEqual(bad.valid, false);
    assert.ok(bad.errors.some((e) => e.code === 103 && e.message === 'Unrecognized configuration override'));

    // strict: a known key set to undefined is rejected too (JSON suites can't express undefined, so it lives here)
    const undef = Triauth.validate({ identifier: 'john@triauthdemo.org' }, { requireSecure: undefined });
    assert.strictEqual(undef.valid, false);
    assert.ok(undef.errors.some((e) => e.code === 103));

    // a valid override is accepted and object validation proceeds normally
    assert.strictEqual(Triauth.validate({ identifier: 'john@triauthdemo.org' }, { requireSecure: true }).valid, true);

    // the objects guard still takes precedence over the config guard
    assert.strictEqual(Triauth.validate({ bogus: 1 }, { requireSecur: true }).errors[0].code, 102);
  });

}); }
