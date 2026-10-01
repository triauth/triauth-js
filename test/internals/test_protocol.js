import { FLOWS, FLOWS_USE_REGEXP, SCOPE_ANY, SCOPE_NONE, VERSION, VERSION_TOKEN, WRAPPER, DELIMITER, AT_MARKER,
         PRIVATE_LABEL_LENGTH, LIMITS } from '../../src/protocol.js';

export default function() { describe('protocol.js constants', () => {

  it('pins the envelope vocabulary', () => {
    assert.equal(VERSION, 1);
    assert.equal(VERSION_TOKEN, 'v1');
    assert.equal(WRAPPER, '|');
    assert.equal(DELIMITER, ';');
    assert.equal(AT_MARKER, '._at.');
  });

  it('pins the private-mode label length', () => {
    assert.equal(PRIVATE_LABEL_LENGTH, 10);
  });

  it('pins the scope keywords: any (the sole-entry spelling covering every service host) and none (reserved, never valid)', () => {
    assert.equal(SCOPE_ANY, 'any');
    assert.equal(SCOPE_NONE, 'none');
  });

  it('keeps FLOWS sorted and frozen', () => {
    assert.deepEqual([...FLOWS], ['attest', 'auth', 'ping', 'sign', 'stamp']);
    assert(Object.isFrozen(FLOWS));
  });

  describe('FLOWS_USE_REGEXP', () => {
    it('accepts single flows and comma-joined flow lists', () => {
      for (const flow of FLOWS) assert(FLOWS_USE_REGEXP.test(flow), flow);
      assert(FLOWS_USE_REGEXP.test('auth,sign'));
      assert(FLOWS_USE_REGEXP.test(FLOWS.join(',')));
    });

    it('rejects the empty string, unknown flows, and malformed lists', () => {
      for (const bad of ['', 'bogus', 'auth,', ',auth', 'auth,,sign', 'auth sign', 'AUTH', 'auth,bogus']) {
        assert(!FLOWS_USE_REGEXP.test(bad), JSON.stringify(bad));
      }
    });
  });
}); }
