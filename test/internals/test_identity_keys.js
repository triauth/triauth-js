import identities from '../fixtures/identities.json' with { type: 'json' };
import SignerStub from '../stubs/signer.js';

export default function() { describe('Triauth.IdentityKeys', () => {
  describe('Triauth.IdentityKeys.add', async () => {
    const keyVal = 'BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8';

    it('accepts valid keys', async () => {
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`desktop[1/1]:${keyVal}`), true);

      assert.equal(await ik.add(`laptop[1/2]:${keyVal}`), true);
      assert.equal(await ik.add(`laptop[2/2]:${keyVal}`), true);

      assert.equal(ik.count, 2);
      for (const keyGroup of Object.values(ik.keyGroups)) {
        assert.equal(keyGroup.valid, true);
        assert(!keyGroup.tainted);
        assert.equal(typeof keyGroup.tag, 'string');
      }
    });

    it('does not mutate the caller-supplied options object (works on a private copy)', async () => {
      const ik = new Triauth.IdentityKeys();
      const options = {}; // no type/use given - add() fills the defaults internally

      assert.equal(await ik.add(`desktop[1/1]:${keyVal}`, options), true);

      // The caller's object must be left untouched (defaults are applied to a private copy)...
      assert.deepEqual(options, {});

      // ...while the stored keyGroup key carries the defaulted copy, which is NOT the same reference.
      assert.deepEqual(ik.keyGroups.desktop.keys[0].options, { type: 'es256', use: 'attest,auth,ping,sign,stamp' });
      assert.notStrictEqual(ik.keyGroups.desktop.keys[0].options, options);
    });

    it('does not accept keys with unknown syntax', async () => {
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`lap_top[1/1]:${keyVal}`), false);

      assert.equal(Object.keys(ik.keyGroups).length, 0);
    });

    it('rejects device names longer than the record-name regex / device-name limit allows ({1,20})', async () => {
      const ik = new Triauth.IdentityKeys();

      // 21-char name exceeds the add() regex ({1,20}) — and the 20-byte device-name limit — so it is rejected outright
      assert.equal(await ik.add(`aaaaaaaaaaaaaaaaaaaaa[1/1]:${keyVal}`), false);
      assert.equal(Object.keys(ik.keyGroups).length, 0);
    });

    it('does not accept keys with obviously invalid position and/or count and taints the whole keyGroup', async () => {
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`laptop1[1/0]:${keyVal}`), false);
      assert.equal(await ik.add(`laptop2[0/2]:${keyVal}`), false);
      assert.equal(await ik.add(`laptop3[2/02]:${keyVal}`), false);
      assert.equal(await ik.add(`laptop4[2/1]:${keyVal}`), false);

      assert.equal(Object.keys(ik.keyGroups).length, 4);
      assert.equal(ik.count, 0, 'no valid keyGroups should be present');
      for (const key of Object.values(ik.keyGroups)) {
        assert(!key.valid);
        assert.equal(key.tainted, true);
      }
    });

    it('observes the maxKeysPerDevice limit', async () => {
      const ik = new Triauth.IdentityKeys();
      const maxKeysPerDevice = Triauth.LIMITS.maxKeysPerDevice;

      assert.equal(await ik.add(`desktop[${maxKeysPerDevice}/${maxKeysPerDevice}]:${keyVal}`), true);
      assert.equal(await ik.add(`laptop[${maxKeysPerDevice + 1}/${maxKeysPerDevice + 1}]:${keyVal}`), false);
    });

    it('observes the maxDevices limit', async () => {
      const ik = new Triauth.IdentityKeys();
      const maxDevices = Triauth.LIMITS.maxDevices;

      for (let i=0; i<maxDevices; i++) {
        assert.equal(await ik.add(`device${i}[1/1]:${keyVal}`), true);
      }

      assert.equal(await ik.add(`device[1/1]:${keyVal}`), false);
    });

    it('does not accept keys when keyCount is not consistent and taints the whole keyGroup', async () => {
      const ik = new Triauth.IdentityKeys();
      const keysCount = 3;

      for (let i=1; i <= keysCount - 1; i++) {
        assert.equal(await ik.add(`device[${i}/${keysCount}]:${keyVal}`), true);
      }

      assert.equal(await ik.add(`device[${keysCount}/${keysCount -1}]:${keyVal}`), false, 'key with incosistent keyCount should not be accepted');

      assert(!ik.keyGroups['device'].valid, 'keyGroup should not be valid');
      assert.equal(ik.keyGroups['device'].tainted, true, 'keyGroup should be tainted');

      assert.equal(await ik.add(`device[${keysCount}/${keysCount}]:${keyVal}`), false, 'should not be possible to add keys to a tainted group');
      assert(!ik.keyGroups['device'].valid, 'keyGroup should remain not valid');
    });

    it('does not accept keys at duplicated positions and taints the whole keyGroup', async () => {
      const ik = new Triauth.IdentityKeys();
      const keysCount = 2;

      for (let i=1; i<=keysCount; i++) {
        assert.equal(await ik.add(`device[${i}/${keysCount}]:${keyVal}`), true);
      }

      assert(ik.keyGroups['device'].valid, 'keyGroup should be valid at this point, before a conflicting key is added');
      assert.equal(ik.count, 1);

      assert.equal(await ik.add(`device[1/${keysCount}]:${keyVal}`), false, 'key at colliding index should not be accepted');

      assert(!ik.keyGroups['device'].valid, 'keyGroup should be invalidated upon collision');
      assert.equal(ik.keyGroups['device'].tainted, true);
      assert.equal(ik.count, 0);
    });

    it('does not mark sparse keyGroups valid before every declared key slot is populated', async () => {
      const ik = new Triauth.IdentityKeys();
      const keysCount = 3;

      assert.equal(await ik.add(`device[3/${keysCount}]:${keyVal}`), true);
      assert.equal(ik.keyGroups['device'].keys.length, keysCount);
      assert.equal(Object.keys(ik.keyGroups['device'].keys).length, 1);
      assert(!ik.keyGroups['device'].valid);
      assert.equal(ik.count, 0);

      assert.equal(await ik.add(`device[1/${keysCount}]:${keyVal}`), true);
      assert.equal(Object.keys(ik.keyGroups['device'].keys).length, 2);
      assert(!ik.keyGroups['device'].valid);
      assert.equal(ik.count, 0);

      assert.equal(await ik.add(`device[2/${keysCount}]:${keyVal}`), true);
      assert.equal(Object.keys(ik.keyGroups['device'].keys).length, keysCount);
      assert.equal(ik.keyGroups['device'].valid, true);
      assert.equal(ik.count, 1);
    });

    it('correctly maintains the expires status', async () => {
      const ik = new Triauth.IdentityKeys();
      const keyCount = 3;

      assert.equal(await ik.add(`device[1/3]:${keyVal}`, {}, {expires:10}), true);
      assert.equal(await ik.add(`device[2/3]:${keyVal}`, {}, {expires:5}), true);
      assert.equal(await ik.add(`device[3/3]:${keyVal}`, {}, {expires:12}), true);

      assert(ik.keyGroups['device'].valid);
      assert.equal(ik.keyGroups['device'].expires, 5);
    });

    it('keyGroup.expires stays undefined when no key in the group has a TTL (keyMetadata.expires is undefined)', async () => {
      // Exercises the identity.js path where `typeof entry.ttl !== 'number'` → expires=undefined,
      // and the identity_keys.js path where `if (keyMetadata.expires && ...)` is false → keyGroup.expires stays undefined.
      // JSON.stringify drops undefined, so this branch cannot be covered by the JSON test framework.
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`device[1/2]:${keyVal}`, {}, {secure: true}), true);
      assert.equal(await ik.add(`device[2/2]:${keyVal}`, {}, {secure: true}), true);

      assert(ik.keyGroups['device'].valid);
      assert.equal(ik.keyGroups['device'].expires, undefined);
      assert(Object.prototype.hasOwnProperty.call(ik.keyGroups['device'], 'expires'));
    });

    it('does not accept non base64-url key values and taints the whole keyGroup', async () => {
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`device[1/2]:${keyVal}`), true);

      assert.equal(await ik.add(`device[2/2]:${'@' + keyVal}`), false);
      assert.equal(ik.keyGroups['device'].tainted, true);
      assert.equal(ik.count, 0);
    });

    it('does not accept unknown values for known key options and taints the whole group', async () => {
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`device[1/2]:${keyVal}`, {type:'es256'}), true);
      assert.equal(await ik.add(`device[2/2]:${keyVal}`, {type:'-----'}), false);

      assert(!ik.keyGroups['device'].valid);
      assert.equal(ik.keyGroups['device'].tainted, true);
      assert.equal(ik.count, 0);
    });

    it('skips over unknown x- experimental options for future compatibility', async () => {
      const ik = new Triauth.IdentityKeys();

      assert.equal(await ik.add(`device[1/2]:${keyVal}`, {type:'es256'}), true);
      assert.equal(await ik.add(`device[2/2]:${keyVal}`, {'x-futureoption':'-----'}), true);

      assert(ik.keyGroups['device'].valid);
      assert(!ik.keyGroups['device'].tainted);
      assert.equal(ik.count, 1);
    });
  });

  describe('Triauth.IdentityKeys.verify', async () => {

    const forEachDevice = async (identities, callback) => {
      for (const identity of Object.values(identities)) {
        for (const device of identity.devices) {
          const identityKeys = new Triauth.IdentityKeys();
          const message = 'Lorem ipsum dolor';

          const signatures = [];
          for (const keyPair of device.keys) {
            const signerStub = await SignerStub.fromJWK(keyPair.private);
            const signature = await signerStub.sign(message);
            signatures.push(signature[0]);

            const keyIdx = signatures.length;
            const keyCount = device.keys.length;

            assert.equal(await identityKeys.add(`${device.deviceName}[${keyIdx}/${keyCount}]:${keyPair.public}`), true);
          }

          await callback({identity, device, identityKeys, message, signatures});
        }
      }
    }

    it('verifies valid signatures', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        assert.equal(identityKeys.keyGroups[device.deviceName].valid, true);

        const verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});

        assert.equal(verifyResult.name, device.deviceName);
        assert.equal(verifyResult.tag, device.deviceTag);
      });
    });

    it('observes the maxKeysPerSignature limit', async () => {
      const maxSignatures = Triauth.LIMITS.maxKeysPerSignature;

      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        assert.equal(identityKeys.keyGroups[device.deviceName].valid, true);

        const limitLeft = maxSignatures - signatures.length;

        for (let i=0; i < limitLeft; i++ ) {
          signatures.push(signatures[0]);
          const verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});

          assert.equal(verifyResult.name, device.deviceName);
          assert.equal(verifyResult.tag, device.deviceTag);
        }

        signatures.push(signatures[0]);
        const verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});

        assert(!verifyResult);
      });
    });

    it('expects strictly only base64Url encoded signatures', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        signatures.push('@');

        const verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});

        assert(!verifyResult);
      });
    });

    it('does not verify mangled keys', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        identityKeys.keyGroups[device.deviceName].keys[0].value += 'a';

        const verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});

        assert(!verifyResult);
      });
    });

    it('does not verify mangled signatures', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        signatures[0] += 'a';

        const verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});

        assert(!verifyResult);
      });
    });

    it('does not take into account non-valid keyGroups', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;

        identityKeys.keyGroups[device.deviceName].valid = false;
        let verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});
        assert(!verifyResult);

        identityKeys.keyGroups[device.deviceName].valid = null;
        verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});
        assert(!verifyResult);
      });
    });

    it('propagates expires:undefined to the verify result when no key has a TTL', async () => {
      // Exercises the `expires: keyGroup.expires` return at identity_keys.js:300
      // when keyGroup.expires was never set (all keys added without a TTL).
      // JSON.stringify drops `undefined` values, so this branch cannot be reached via the JSON test framework.
      const ik = new Triauth.IdentityKeys();
      const message = 'Lorem ipsum dolor';

      const identity = Object.values(identities)[0];
      const device = identity.devices[0];
      const signatures = [];

      for (const [idx, keyPair] of device.keys.entries()) {
        const keyIdx = idx + 1;
        const keyCount = device.keys.length;
        const signerStub = await SignerStub.fromJWK(keyPair.private);
        const signature = await signerStub.sign(message);
        signatures.push(signature[0]);
        // Pass keyMetadata without 'expires' — simulates a DNS record without a TTL
        assert.equal(await ik.add(`${device.deviceName}[${keyIdx}/${keyCount}]:${keyPair.public}`, {}, {secure: true}), true);
      }

      assert.equal(ik.keyGroups[device.deviceName].expires, undefined);

      const verifyResult = await ik.verify(message, signatures, {mode: 'auth'});
      assert(verifyResult, 'verify must succeed');
      assert(Object.prototype.hasOwnProperty.call(verifyResult, 'expires'), 'expires must be an own property of the result');
      assert.equal(verifyResult.expires, undefined, 'expires must be undefined when no key had a TTL');
    });

    // @todo - check
    it('verifies keyGroups within the clock-drift grace window after their expires has passed', async () => {
      // The in-call expiry check allows a grace window equal to `maximalAllowedClientClockDrift` after
      // `expires` so that DNS records published with TTL=0 (whose `expires` equals the resolution
      // moment) still verify within the same call. KeyGroups older than that grace are skipped —
      // protecting against external misuse where an Identity is held across calls.
      // The DNS-published expiry value itself is propagated to the caller unchanged.
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        const drift = Triauth.config.maximalAllowedClientClockDrift;

        // TTL=0 case — expires equals "now" at resolution; well within the drift grace.
        identityKeys.keyGroups[device.deviceName].expires = Date.now();
        let verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});
        assert(verifyResult, 'TTL=0 records (expires == Date.now()) must verify within the drift grace');
        assert.equal(verifyResult.name, device.deviceName);

        // expires slightly in the past, but still within the drift grace — verifies; original value propagated.
        const expiresInPast = Date.now() - 1;
        identityKeys.keyGroups[device.deviceName].expires = expiresInPast;
        verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});
        assert(verifyResult, 'expires within the drift grace must NOT block in-call verification');
        assert.equal(verifyResult.expires, expiresInPast, 'the original expires value is propagated to the result');

        // expires older than the drift grace — keyGroup is skipped.
        identityKeys.keyGroups[device.deviceName].expires = Date.now() - drift - 1000;
        verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});
        assert(!verifyResult, 'expires older than maximalAllowedClientClockDrift must skip the keyGroup');
      });
    });

    it('does not verify keys of unrecognized type', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;

        identityKeys.keyGroups[device.deviceName].keys[0].options.type = 'unrecognized-type';

        let verifyResult = await identityKeys.verify(message, signatures, {mode: 'auth'});
        assert(!verifyResult);
      });
    });

    it('correctly verifies the use option', async () => {
      await forEachDevice(identities, async (opts) => {
        const {device, identityKeys, message, signatures} = opts;
        const keysCount = identityKeys.keyGroups[device.deviceName].keys.length;
        let verifyResult;

        identityKeys.keyGroups[device.deviceName].keys[0].options.use = 'auth';

        verifyResult = await identityKeys.verify(message, signatures, {mode:'auth'});
        assert(verifyResult);

        verifyResult = await identityKeys.verify(message, signatures, {mode:'sign'});
        assert(keysCount > 1 ? verifyResult : !verifyResult);

        verifyResult = await identityKeys.verify(message, signatures, {mode:'stamp'});
        assert(keysCount > 1 ? verifyResult : !verifyResult);

        verifyResult = await identityKeys.verify(message, signatures, {mode:'missing'});
        assert(!verifyResult);


        identityKeys.keyGroups[device.deviceName].keys[0].options.use = 'auth,sign';

        verifyResult = await identityKeys.verify(message, signatures, {mode:'auth'});
        assert(verifyResult);

        verifyResult = await identityKeys.verify(message, signatures, {mode:'sign'});
        assert(verifyResult);

        verifyResult = await identityKeys.verify(message, signatures, {mode:'stamp'});
        assert(keysCount > 1 ? verifyResult : !verifyResult);

        verifyResult = await identityKeys.verify(message, signatures, {mode:'missing'});
        assert(!verifyResult);
      });
    });

    it('validates webauthn signatures', async () => {
      // Real browser-recorded assertion. The payload is opaque bytes at this layer (WebAuthn
      // checks clientData.challenge === sha256(payload), never parses it), so the recorded
      // challenge blob must stay byte-exact regardless of the current challenge JSON shape.
      // @todo: Update the challenge here to match the currently used structure
      const fixture = {
        "identifier": "john@triauthdemo.org",
        "callbackUrl": "-",
        "publishableKey": "BLz4Aq2-83mwY130EohDzyiC9kBabbb92CaiRHVoEJGrV-vT2N1F-yRqSReT_ixAzti8ZBX6q5ISEHBStcISrAM",
        "challenge": "eyJjYnVybCI6Ii0iLCJzdWIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoiY0dOcE0xLTQyRWY3MVNXbWozX1NCekpUIiwiaWF0IjoxNzcyNzk4ODg1MDUyLCJ2ZXIiOjF9",
        "clientDataJSON": "{\"type\":\"webauthn.get\",\"challenge\":\"K5Y3CSaQpudj72n_Uz-ZxvyVBVygyh0yEp4fguKmhjY\",\"origin\":\"http://localhost:8080\",\"crossOrigin\":false}",
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAw",
        "signature": "0UKhAqv1LVGwJU6slDq-vungPeOQlj1sdHkF0Yh7w33r8X6SqjKS_kq-CcSqGWPRZWkgK_vobcHSlkWC0PPO-Q"
      };

      let {
        identifier,
        callbackUrl,
        publishableKey,
        challenge,
        clientDataJSON,
        authenticatorData,
        signature
      } = fixture;

      const unsignedData = {'sig':{'0':{clientDataJSON, authenticatorData}}};

      const ik = new Triauth.IdentityKeys('john@triauthdemo.org');
      const keyAddResult = await ik.add(`device[1/1]:${publishableKey}`, {type:'webauthn-es256'});

      assert.equal(keyAddResult, true);
      assert(ik.keyGroups['device'].valid);
      assert.equal(ik.count, 1);

      let verifyResult = await ik.verify(challenge, [signature], {mode:'auth'}, {}, unsignedData);

      assert.equal(!!verifyResult, true);
      assert.equal(verifyResult.name, 'device');
      assert.equal(verifyResult.keys[0].verified, true);
      assert.equal(verifyResult.keys[0].skipped, false);

      verifyResult = await ik.verify(challenge + 'z', [signature], 'auth', {}, unsignedData);
      assert.equal(verifyResult, false, 'should not verify non-matching challanges');

      verifyResult = await ik.verify(challenge, [signature+'a'], 'auth', {}, unsignedData);
      assert.equal(verifyResult, false, 'should not verify non-matching signatures');
    });

    it('rejects webauthn assertions without the User Present (UP) flag or with truncated authenticatorData', async () => {
      const johnKey = identities['john'].devices[0].keys[0];
      const message = 'up-flag-test-message';

      // Mint a fresh, correctly signed assertion with the given flags byte (and optional truncation),
      // so that a rejection can only come from the flags/length checks - not from the crypto verification.
      const mkAssertion = async (flagsByte, length = 37) => {
        const authData = new Uint8Array(37);
        authData.fill(0xAA, 0, 32); // arbitrary rpIdHash (not checked - the key is pinned in DNS)
        authData[32] = flagsByte;   // bytes 33-36 (signCount) left as 0
        const trimmed = authData.slice(0, length);

        const clientDataJSON = JSON.stringify({
          type: 'webauthn.get',
          challenge: await Triauth.Helpers.sha256(message),
          origin: 'https://triauthdemo.org',
          crossOrigin: false
        });

        const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientDataJSON)));
        const payload = new Uint8Array([...trimmed, ...cdjHash]);
        const privateKey = await crypto.subtle.importKey('jwk', johnKey.private, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
        const signature = Triauth.Helpers.arrayBufferToBase64Url(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, privateKey, payload));

        return {signature, unsignedData: {sig: {'0': {clientDataJSON, authenticatorData: Triauth.Helpers.arrayBufferToBase64Url(trimmed)}}}};
      };

      const ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {type: 'webauthn-es256'}), true);

      // Controls: UP=1 verifies, with or without UV
      let {signature, unsignedData} = await mkAssertion(0x01);
      assert(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), 'UP=1 assertion must verify');

      ({signature, unsignedData} = await mkAssertion(0x05));
      assert(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), 'UP=1|UV=1 assertion must verify');

      // UP=0 - a CTAP-level "silent" assertion is rejected even though correctly signed
      ({signature, unsignedData} = await mkAssertion(0x00));
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'UP=0 (silent) assertion must be rejected');

      // UV without UP - still rejected (user presence is the mandated baseline)
      ({signature, unsignedData} = await mkAssertion(0x04));
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'UV=1 without UP must be rejected');

      // authenticatorData shorter than 37 bytes (rpIdHash + flags + signCount) - rejected by the length guard
      ({signature, unsignedData} = await mkAssertion(0x01, 36));
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'authenticatorData < 37 bytes must be rejected');
    });

    it('validates the uv option fail-closed and enforces the User Verified (UV) flag for uv=required keys', async () => {
      const johnKey = identities['john'].devices[0].keys[0];
      const message = 'uv-option-test-message';

      const mkAssertion = async (flagsByte) => {
        const authData = new Uint8Array(37);
        authData.fill(0xAA, 0, 32);
        authData[32] = flagsByte;

        const clientDataJSON = JSON.stringify({
          type: 'webauthn.get',
          challenge: await Triauth.Helpers.sha256(message),
          origin: 'https://triauthdemo.org',
          crossOrigin: false
        });

        const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientDataJSON)));
        const payload = new Uint8Array([...authData, ...cdjHash]);
        const privateKey = await crypto.subtle.importKey('jwk', johnKey.private, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
        const signature = Triauth.Helpers.arrayBufferToBase64Url(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, privateKey, payload));

        return {signature, unsignedData: {sig: {'0': {clientDataJSON, authenticatorData: Triauth.Helpers.arrayBufferToBase64Url(authData)}}}};
      };

      // uv accepts only the literal 'required' - any other value taints the keyGroup (fail closed,
      // a typo must not silently drop the user verification requirement)
      let ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {type: 'webauthn-es256', uv: 'reuired'}), false, 'a mistyped uv value must not be accepted');
      assert.equal(ik.keyGroups['device'].tainted, true, 'a mistyped uv value must taint the keyGroup');

      // uv on a non-webauthn key is unenforceable - taints as well
      ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {uv: 'required'}), false, 'uv=required on a non-webauthn (default es256) key must not be accepted');
      assert.equal(ik.keyGroups['device'].tainted, true, 'uv=required on a non-webauthn key must taint the keyGroup');

      ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {type: 'ed25519', uv: 'required'}), false, 'uv=required on an ed25519 key must not be accepted');
      assert.equal(ik.keyGroups['device'].tainted, true, 'uv=required on an ed25519 key must taint the keyGroup');

      // uv=required on a webauthn key is valid; assertions verify only with the UV flag set
      ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {type: 'webauthn-es256', uv: 'required'}), true);
      assert.equal(ik.keyGroups['device'].valid, true);

      let {signature, unsignedData} = await mkAssertion(0x05); // UP|UV
      assert(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), 'UP=1|UV=1 assertion must verify for a uv=required key');

      ({signature, unsignedData} = await mkAssertion(0x01));   // UP only
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'UV=0 assertion must be rejected for a uv=required key');
    });

    it('rejects webauthn clientDataJSON carrying a lone surrogate - the encoder refuses it and the refusal is absorbed to false', async () => {
      const johnKey = identities['john'].devices[0].keys[0];
      const message = 'lone-surrogate-test-message';

      const authData = new Uint8Array(37);
      authData.fill(0xAA, 0, 32);
      authData[32] = 0x01; // UP set - every gate before the hash step passes

      // A JSON "\ud800" escape survives JSON.parse as an actual unpaired surrogate inside the
      // clientDataJSON string (attacker-reachable: unsignedMetadata sits outside the signed
      // payload). Such a string has no UTF-8 bytes, so no authenticator can ever have signed it.
      const loneSurrogate = String.fromCharCode(0xD800);
      const clientDataJSON = '{"type":"webauthn.get","challenge":"' + await Triauth.Helpers.sha256(message)
        + '","origin":"https://triauthdemo.org","crossOrigin":false,"x":"' + loneSurrogate + '"}';

      // Sign the U+FFFD-substituted spelling - the bytes a lossy encoder would hash. This pins
      // that not even a signature over the substitute verifies: the encoder refuses the string
      // outright instead of aliasing it onto substituted bytes.
      const substituted = clientDataJSON.replace(loneSurrogate, String.fromCharCode(0xFFFD));
      const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(substituted)));
      const payload = new Uint8Array([...authData, ...cdjHash]);
      const privateKey = await crypto.subtle.importKey('jwk', johnKey.private, {name: 'ECDSA', namedCurve: 'P-256'}, false, ['sign']);
      const signature = Triauth.Helpers.arrayBufferToBase64Url(await crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, privateKey, payload));

      const unsignedData = {sig: {'0': {clientDataJSON, authenticatorData: Triauth.Helpers.arrayBufferToBase64Url(authData)}}};

      const ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {type: 'webauthn-es256'}), true);

      // Resolves to false - the refusal never escapes the verifier as a throw
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false);
    });

    // A fixed OKP/Ed25519 fixture pair; `public` is the 32-byte raw public key (base64url) as published in DNS
    const ed25519Key = {
      public: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0',
      private: {kty: 'OKP', crv: 'Ed25519', d: '-_UnNRraY7oJRq-G3bKgtnbM9y1AhAoj0zjAYr810yM', x: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0'}
    };

    it('validates ed25519 signatures', async () => {
      const message = 'ed25519-test-message';

      const ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${ed25519Key.public}`, {type: 'ed25519'}), true);
      assert.equal(ik.keyGroups['device'].valid, true);
      assert.equal(ik.count, 1);

      const signerStub = await SignerStub.fromJWK(ed25519Key.private);
      const [signature] = await signerStub.sign(message);

      let verifyResult = await ik.verify(message, [signature], {mode: 'auth'});
      assert.equal(!!verifyResult, true);
      assert.equal(verifyResult.name, 'device');
      assert.equal(verifyResult.keys[0].verified, true);
      assert.equal(verifyResult.keys[0].skipped, false);

      verifyResult = await ik.verify(message + 'z', [signature], {mode: 'auth'});
      assert.equal(verifyResult, false, 'should not verify non-matching messages');

      verifyResult = await ik.verify(message, [signature + 'a'], {mode: 'auth'});
      assert.equal(verifyResult, false, 'should not verify mangled signatures');
    });

    it('verifies mixed-type keyGroups (es256 + ed25519)', async () => {
      const johnKey = identities['john'].devices[0].keys[0];
      const message = 'mixed-keygroup-test-message';

      const ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/2]:${johnKey.public}`, {type: 'es256'}), true);
      assert.equal(await ik.add(`device[2/2]:${ed25519Key.public}`, {type: 'ed25519'}), true);
      assert.equal(ik.keyGroups['device'].valid, true);

      const [es256Signature] = await (await SignerStub.fromJWK(johnKey.private)).sign(message);
      const [ed25519Signature] = await (await SignerStub.fromJWK(ed25519Key.private)).sign(message);

      let verifyResult = await ik.verify(message, [es256Signature, ed25519Signature], {mode: 'auth'});
      assert(verifyResult, 'a mixed group must verify when signatures for all keys are present');
      assert.equal(verifyResult.keys[0].verified, true);
      assert.equal(verifyResult.keys[1].verified, true);

      verifyResult = await ik.verify(message, [es256Signature], {mode: 'auth'});
      assert.equal(verifyResult, false, 'a missing ed25519 signature must fail the whole group');

      verifyResult = await ik.verify(message, [ed25519Signature], {mode: 'auth'});
      assert.equal(verifyResult, false, 'a missing es256 signature must fail the whole group');
    });

    it('does not verify es256 key material published as type=ed25519', async () => {
      const johnKey = identities['john'].devices[0].keys[0];
      const message = 'wrong-key-material-test-message';

      const ik = new Triauth.IdentityKeys();
      // The 65-byte P-256 key passes add() (key length is not type-checked there) ...
      assert.equal(await ik.add(`device[1/1]:${johnKey.public}`, {type: 'ed25519'}), true);
      assert.equal(ik.keyGroups['device'].valid, true);

      // ... but the raw Ed25519 import requires exactly 32 bytes, so no verifier can be
      // built for the key, and verification must fail without throwing
      const [signature] = await (await SignerStub.fromJWK(johnKey.private)).sign(message);
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}), false);
    });

    it('ed25519 verifier returns false (not throws) on malformed verify() input', async () => {
      const verifier = await Triauth.Verifiers.Ed25519.fromPublishableKey(ed25519Key.public);
      assert(verifier, 'verifier must be built from a valid 32-byte raw public key');

      assert.equal(await verifier.verify('some-message', null), false, 'a non-string signature must yield false, not an exception');
    });

    it('the WebAuthn base verifier is algorithm-agnostic and fails closed when used directly', async () => {
      const johnKey = identities['john'].devices[0].keys[0];

      // No credential algorithm bound on the base class - fromPublishableKey must resolve to null...
      assert.equal(await Triauth.Verifiers.WebAuthn.fromPublishableKey(johnKey.public), null);

      // ...and a directly-constructed instance must fail verification, not throw
      const es256Verifier = await Triauth.Verifiers.WebAuthnEs256.fromPublishableKey(johnKey.public);
      assert(es256Verifier, 'the concrete ES256 subclass must build fine from the same key');
      const baseVerifier = new Triauth.Verifiers.WebAuthn(es256Verifier.publicKey);
      assert.equal(await baseVerifier.verify('some-message', 'AAAA', {}, {}), false);
    });

    it('validates webauthn-ed25519 signatures (incl. uv=required UV-flag enforcement)', async () => {
      const message = 'webauthn-ed25519-test-message';

      // Mint a fresh, correctly Ed25519-signed assertion with the given flags byte, so that a
      // rejection can only come from the WebAuthn-level checks - not from the crypto verification.
      const mkAssertion = async (flagsByte) => {
        const authData = new Uint8Array(37);
        authData.fill(0xAA, 0, 32); // arbitrary rpIdHash (not checked - the key is pinned in DNS)
        authData[32] = flagsByte;   // bytes 33-36 (signCount) left as 0

        const clientDataJSON = JSON.stringify({
          type: 'webauthn.get',
          challenge: await Triauth.Helpers.sha256(message),
          origin: 'https://triauthdemo.org',
          crossOrigin: false
        });

        const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientDataJSON)));
        const payload = new Uint8Array([...authData, ...cdjHash]);
        const privateKey = await crypto.subtle.importKey('jwk', ed25519Key.private, {name: 'Ed25519'}, false, ['sign']);
        const signature = Triauth.Helpers.arrayBufferToBase64Url(await crypto.subtle.sign({name: 'Ed25519'}, privateKey, payload));

        return {signature, unsignedData: {sig: {'0': {clientDataJSON, authenticatorData: Triauth.Helpers.arrayBufferToBase64Url(authData)}}}};
      };

      // A UP=1 assertion backed by the ed25519 key verifies
      let ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${ed25519Key.public}`, {type: 'webauthn-ed25519'}), true);
      assert.equal(ik.keyGroups['device'].valid, true);

      let {signature, unsignedData} = await mkAssertion(0x01);
      const verifyResult = await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData);
      assert(verifyResult, 'UP=1 webauthn-ed25519 assertion must verify');
      assert.equal(verifyResult.keys[0].verified, true);

      assert.equal(await ik.verify(message + 'z', [signature], {mode: 'auth'}, {}, unsignedData), false, 'non-matching message must not verify');
      assert.equal(await ik.verify(message, [signature.slice(0, -2) + 'qq'], {mode: 'auth'}, {}, unsignedData), false, 'mangled signature must not verify');

      // UP=0 (CTAP-level silent assertion) is rejected by the inherited WebAuthn-level check
      ({signature, unsignedData} = await mkAssertion(0x00));
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'UP=0 (silent) assertion must be rejected');

      // es256 (65-byte) key material on a webauthn-ed25519 record cannot build a verifier - fail closed
      const johnKey = identities['john'].devices[0].keys[0];
      const ikWrong = new Triauth.IdentityKeys();
      assert.equal(await ikWrong.add(`device[1/1]:${johnKey.public}`, {type: 'webauthn-ed25519'}), true);
      ({signature, unsignedData} = await mkAssertion(0x01));
      assert.equal(await ikWrong.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'es256 key material must not verify as webauthn-ed25519');

      // uv=required is valid on webauthn-ed25519 (a webauthn-* type) and enforces the UV flag
      ik = new Triauth.IdentityKeys();
      assert.equal(await ik.add(`device[1/1]:${ed25519Key.public}`, {type: 'webauthn-ed25519', uv: 'required'}), true);
      assert.equal(ik.keyGroups['device'].valid, true);

      ({signature, unsignedData} = await mkAssertion(0x05)); // UP|UV
      assert(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), 'UP=1|UV=1 assertion must verify for a uv=required webauthn-ed25519 key');

      ({signature, unsignedData} = await mkAssertion(0x01)); // UP only
      assert.equal(await ik.verify(message, [signature], {mode: 'auth'}, {}, unsignedData), false, 'UV=0 assertion must be rejected for a uv=required webauthn-ed25519 key');
    });

  });

}); }
