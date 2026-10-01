export default function() { describe('Triauth.Logger', () => {

  it('Logs only messages with urgency equal or above to the set logLevel', async () => {
    let messages = [];

    const log = (...args) => messages.push(args);

    const logger = new Triauth.Logger({
      debug: log,
      info: log,
      warn: log,
      error: log
    });

    for(let i = 0; i < 4; i++) {
      logger.logLevel = ['debug', 'info', 'warn', 'error'][i];

      for(let j = 0; j < 4; j++) {
        logger[
          ['debug', 'info', 'warn', 'error'][j]
        ](j);
      }

    }

    assert.deepEqual(
      messages.map( (e) => e[2]),
      [0, 1, 2, 3, 1, 2, 3, 2, 3, 3]
    );
  });

  // Returns the `[cid:...]` segment of a single warn line, or null when the logger emits no cid tag.
  const cidTagOf = (logger) => {
    const captured = [];
    const out = { debug() {}, info() {}, warn: (...a) => captured.push(a), error() {} };
    logger.output = out;
    logger.logLevel = 'warn';
    logger.warn('x');
    return captured[0].find((p) => typeof p === 'string' && p.startsWith('[cid:')) || null;
  };

  it('spawn resolves cid: nullish autofills, false opts out, a string is used verbatim', () => {
    const base = new Triauth.Logger(null, { prefix: '[t]' });

    // nullish (null/undefined) -> a fresh id is minted
    assert.match(cidTagOf(base.spawn(null)), /^\[cid:.+\]$/);
    assert.match(cidTagOf(base.spawn(undefined)), /^\[cid:.+\]$/);

    // false -> explicit opt-out, no tag at all
    assert.strictEqual(cidTagOf(base.spawn(false)), null);

    // string -> used exactly
    assert.strictEqual(cidTagOf(base.spawn('corr-123')), '[cid:corr-123]');
  });

  it('spawn inherits the parent cid when its argument is nullish', () => {
    const base = new Triauth.Logger(null, { prefix: '[t]', cid: 'parent' });
    assert.strictEqual(cidTagOf(base.spawn(null)), '[cid:parent]');
  });

}); }
