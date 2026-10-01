import SignerStub from './stubs/signer.js';
import DnsResolverStub from './stubs/dns_resolver.js';
import identities from './fixtures/identities.json' with { type: 'json' };
import identifiersFixture from './fixtures/identifiers.json' with { type: 'json' };

describe('Authentication API', () => {

  describe('Triauth.authenticate', () => {

    it('does not accept unrecognized options', async () => {
      const authRes = (await Triauth.authenticate({
        identifier: 'john@triauthdemo.org',
        callbackUrl: 'https://example.com/',
        unknownKey: 123
      }));

      assert(!authRes.authenticated);
      assert.equal(authRes.error.code, 102);
    });

    describe('accepts identifier and callbackUrl to produce challenge and redirectUrl', () => {

      const identifier = 'john@triauthdemo.org';
      const callbackUrl = 'http://localhost/';

      it('returns challenge and a correct redirectUrl for valid identifiers', async () => {
        const authRes = (await Triauth.authenticate({
          identifier: 'john@triauthdemo.org',
          callbackUrl: 'https://example.com/'
        }));
        assert(authRes.challenge);
        assert(authRes.redirectUrl);
      });

      it('encodes the identifier and callbackUrl in the challenge', async () => {
        const authRes = (await Triauth.authenticate({identifier, callbackUrl}));
        const challengeRequest = Triauth.Challenge.fromString(authRes.challenge);

        assert.equal(challengeRequest.data.identifier, identifier);
        assert.equal(challengeRequest.data.cburl, callbackUrl);
      });

      it('accepts optional ext hash and encodes it in the challenge', async () => {
        const authRes = (await Triauth.authenticate({identifier, callbackUrl, ext:{'signToken':true}}));
        const challengeRequest = Triauth.Challenge.fromString(authRes.challenge);

        assert.equal(challengeRequest.data.ext?.signToken, true);
      });

      it('accepts ext values with non-latin-1 characters and encodes them in the challenge', async () => {
        // Regression: btoa()-based encoding used to throw on chars > U+00FF and surface as 100 Internal error
        const ext = {note: 'Привет \u{1F389}'};
        const authRes = (await Triauth.authenticate({identifier, callbackUrl, ext}));

        assert(!authRes.error, JSON.stringify(authRes.error));
        const challengeRequest = Triauth.Challenge.fromString(authRes.challenge);
        assert.equal(challengeRequest.data.ext?.note, ext.note);
      });

      it('returns {error:{code:222}} for ext with non-ASCII keys', async () => {
        // safeParseJson rejects non-ASCII property names at stage 3, so validateExt must fail fast
        const authRes = (await Triauth.authenticate({identifier, callbackUrl, ext:{'ключ':'value'}}));

        assert(!authRes.authenticated);
        assert.equal(authRes.error.code, 222);
      });

      it('carries the documented manifest extension shape verbatim', async () => {
        // The README's extension table: the registered manifest shape must pass the ext grammar
        const manifest = {name: 'Fabulous Example', startUrl: 'https://example.com/', iconUrl: 'https://example.com/icon.png'};
        const authRes = (await Triauth.authenticate({identifier, callbackUrl, ext: {manifest}}));

        assert(!authRes.error, JSON.stringify(authRes.error));
        const challengeRequest = Triauth.Challenge.fromString(authRes.challenge);
        assert.deepStrictEqual(challengeRequest.data.ext?.manifest, manifest);
      });

      it('generates random and unique challenges for each call', async () => {
        const challenges = [];

        for (let i = 1; i <= 3; i++) {
          challenges.push((await Triauth.authenticate({identifier, callbackUrl})).challenge);
        }
        const uniqueChallenges = [...new Set(challenges)];

        assert.equal(uniqueChallenges.length, challenges.length);
      });

      it('returns validation error for invalid identifiers', async () => {
        const {invalidIdentifiers, emptyIdentifiers} = identifiersFixture;
        invalidIdentifiers[123] = 'non-string type';

        for (const invalidIdentifier in invalidIdentifiers) {
          const authRes = (await Triauth.authenticate({
            identifier: invalidIdentifier,
            callbackUrl: '-'
          }));
          assert(!authRes?.authenticated, invalidIdentifier);
          assert(authRes.error.code >= 210, invalidIdentifier);
          assert(authRes.error.code < 220, invalidIdentifier);
        }
      });

      it('returns validation error for invalid callbackUrls', async () => {
        const invalidUrls = ['=', '', 'http://localhost/' + 'a'.repeat(2048)];

        for (const invalidUrl of invalidUrls) {
          const authRes = (await Triauth.authenticate({
            identifier: 'john@triauthdemo.org',
            callbackUrl: invalidUrl
          }));
          assert(!authRes?.authenticated);
          assert(authRes.error.code >= 200);
          assert(authRes.error.code < 300);
        }
      });

      it('returns 301 for a domain that is not configured for triauth', async () => {
        const authRes = (await Triauth.authenticate({
          identifier: 'john@example.com',
          callbackUrl: 'https://example.com/'
        }));

        assert(!authRes?.authenticated);
        assert.equal(authRes.error.code, 301);
      });

      it('builds a challenge for an unknown identifier under a configured domain - existence is settled at stage 3, never probed at issue', async () => {
        const authRes = (await Triauth.authenticate({
          identifier: 'non-existing@triauthdemo.org',
          callbackUrl: 'https://example.com/'
        }));

        assert(!authRes.error);
        assert(authRes.challenge);
        assert(authRes.redirectUrl.startsWith('https://'));
      });

      it('returns DNS error for DNSSEC failed domains', async () => {
        const authRes = await Triauth.authenticate({identifier:'a@dnssec-failed.org', callbackUrl:'https://example.com/'});

        assert(!authRes?.authenticated);
        assert(authRes.error);
        assert.equal(authRes.error.code, 110);
      });

      it('rejects the `token` option for the auth flow (only allowed for ping/attest/sign/stamp)', async () => {
        const authRes = await Triauth.authenticate({
          identifier: 'john@triauthdemo.org',
          callbackUrl: 'https://example.com/',
          token: 'some-token-value'
        });

        assert(!authRes.authenticated);
        assert.equal(authRes.error.code, 102, '`token` for auth must surface as Unrecognized function argument');
      });
    });

    describe('accepts challenge and response to produce authentication result', () => {

      it('correctly sets the authenticated status', async () => {
        for (const identity of Object.values(identities)) {
          const challenge = (await Triauth.authenticate({identifier:identity.identifier, callbackUrl:'https://example.com/'})).challenge;

          for (const device of identity.devices) {

            const signature = await Triauth.Signature.generate(
              SignerStub.signUsingDeviceKeys(device.keys),
              'auth',
              identity.identifier, '',
              'https://example.com/',
              challenge
              );

            // Valid signatures should authenticate
            let authRes = (await Triauth.authenticate({challenge, response:signature}));

            assert.equal(authRes.authenticated, true);

            assert.equal(authRes.secure, true);
            assert(authRes.expires > Date.now());
            assert.equal(authRes.identifier, identity.identifier);
            assert.equal(authRes.identityDomain, identity.identityDomain);
            assert.equal(authRes.actor, '');
            assert.equal(authRes.actorIdentityDomain, '');
            assert.equal(authRes.lookupCode, '', 'a public-mode identity consumes no lookup code');
            assert.equal(authRes.actorLookupCode, '');
            assert.deepEqual(authRes.publicProfile, identity.publicProfile);

            assert.equal(authRes.keys.length, device.keys.length);
            assert.equal(authRes.keys.every((k) => k.verified), true);

            assert.equal(authRes.deviceName, device.deviceName);
            // assert.equal(authRes.deviceTag, device.deviceTag);
            assert.equal(typeof authRes.ext, 'object');

            // Milestone timeline: issued (stage 1) <= signed (stage 2) <= verified (stage 3), all numbers.
            assert.equal(typeof authRes.issuedAt, 'number');
            assert.equal(typeof authRes.signedAt, 'number');
            assert.equal(typeof authRes.verifiedAt, 'number');
            assert(authRes.issuedAt <= authRes.signedAt && authRes.signedAt <= authRes.verifiedAt);

            // Invalid signature should not authenticate
            authRes = (await Triauth.authenticate({challenge, response:signature.replace('@', '@a')}));
            assert(!authRes.authenticated, 'invalid signatures must not be authenticated');
            assert(!authRes.identifier);
          }
        }
      });

      it('correctly sets the ext property', async () => {
        const signedData = {'ext':{'key':'value', 'nested-object':{'a':'b'}}};
        const unsignedData = {'a':'b'};

        for (const identity of Object.values(identities)) {
          const challenge = (await Triauth.authenticate({identifier:identity.identifier, callbackUrl:'https://example.com/'})).challenge;

          for (const device of identity.devices) {
            const response = await Triauth.Signature.generate(
              SignerStub.signUsingDeviceKeys(device.keys),
              'auth',
              identity.identifier, '',
              'https://example.com/',
              challenge,
              signedData,
              unsignedData
            );

            const authRes = (await Triauth.authenticate({challenge, response}));

            assert.equal(authRes.authenticated, true);
            assert.equal(authRes.identifier, identity.identifier);
            assert.equal(authRes.deviceName, device.deviceName);

            assert.deepEqual(authRes.ext, signedData.ext);
          }
        }
      });

      it('round-trips ext values with non-latin-1 characters', async () => {
        // Regression: stage 1 used to fail with 100 (btoa throw) and stage 3 decoded UTF-8 as mojibake (atob)
        const signedData = {'ext':{'emoji':'\u{1F389}\u{1F680}', 'cyrillic':'тест'}};

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.authenticate({identifier:identity.identifier, callbackUrl:'https://example.com/', ext:{note:'Привет \u{1F389}'}})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          'https://example.com/',
          challenge,
          signedData
        );

        const authRes = (await Triauth.authenticate({challenge, response}));

        assert.equal(authRes.authenticated, true);
        assert.deepEqual(authRes.ext, signedData.ext);
      });

      it('caps secure at the DNSSEC status of the triauth configuration record', async () => {
        // The endpoint record selects the identity domain the keys are read from (mode/len options),
        // so even DNSSEC-validated key records must not yield secure:true when the endpoint
        // record itself was not validated.
        const identity = identities['john'];
        const device = identity.devices[0];

        const keyRecords = device.keys.map((key, idx) => ({
          value: `key ${device.deviceName}[${idx + 1}/${device.keys.length}]:${key.public} type=es256`,
          ttl: 1800,
          dnssec: true
        }));

        for (const [endpointDnssec, expectedSecure] of [[true, true], [false, false], [undefined, false]]) {
          const resolver = new DnsResolverStub({
            'triauthdemo.org': {TXT: [{value: 'triauth auth.triauthdemo.org mode=public', ttl: 1800, dnssec: endpointDnssec}]},
            'john._at.triauthdemo.org': {TXT: keyRecords}
          });

          const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl: 'https://example.com/'}, {resolver})).challenge;
          const response = await Triauth.Signature.generate(
            SignerStub.signUsingDeviceKeys(device.keys),
            'auth',
            identity.identifier, '',
            'https://example.com/',
            challenge
          );

          const authRes = await Triauth.authenticate({challenge, response}, {resolver});

          assert.equal(authRes.authenticated, true, `authentication must succeed for endpoint dnssec:${endpointDnssec}`);
          assert.equal(authRes.secure, expectedSecure, `endpoint dnssec:${endpointDnssec} must yield secure:${expectedSecure}`);
        }
      });

      it('rejects an otherwise-valid auth with error 404 when config.requireSecure is set and the result is not DNSSEC-secure', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const keyRecords = (dnssec) => device.keys.map((key, idx) => ({
          value: `key ${device.deviceName}[${idx + 1}/${device.keys.length}]:${key.public} type=es256`,
          ttl: 1800,
          dnssec
        }));

        for (const secure of [true, false]) {
          const resolver = new DnsResolverStub({
            'triauthdemo.org': {TXT: ['triauth auth.triauthdemo.org mode=public']},
            'john._at.triauthdemo.org': {TXT: keyRecords(secure)}
          });

          const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl: 'https://example.com/'}, {resolver})).challenge;
          const response = await Triauth.Signature.generate(
            SignerStub.signUsingDeviceKeys(device.keys),
            'auth',
            identity.identifier, '',
            'https://example.com/',
            challenge
          );

          // Default (requireSecure off): authenticates regardless of `secure`.
          const authDefault = await Triauth.authenticate({challenge, response}, {resolver});
          assert.equal(authDefault.authenticated, true, `default config must authenticate (secure:${secure})`);
          assert.equal(authDefault.secure, secure);

          // requireSecure on: a DNSSEC-secure result still authenticates; a non-secure one is rejected with 404.
          const authStrict = await Triauth.authenticate({challenge, response}, {resolver, requireSecure: true});
          if (secure) {
            assert.equal(authStrict.authenticated, true, 'DNSSEC-secure result must still authenticate under requireSecure');
            assert.equal(authStrict.secure, true);
          } else {
            assert(!authStrict.authenticated, 'non-DNSSEC result must not authenticate under requireSecure');
            assert.equal(authStrict.error.code, 404);
            assert.equal(authStrict.error.message, 'Your domain does not support DNSSEC, which is required to continue.');
          }
        }
      });

      it('authenticates with ed25519 keys (type=ed25519 key records)', async () => {
        // A fixed OKP/Ed25519 fixture pair; `public` is the 32-byte raw public key (base64url) as published in DNS
        const ed25519Key = {
          public: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0',
          private: {kty: 'OKP', crv: 'Ed25519', d: '-_UnNRraY7oJRq-G3bKgtnbM9y1AhAoj0zjAYr810yM', x: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0'}
        };

        const identifier = 'john@triauthdemo.org';
        const callbackUrl = 'https://example.com/';

        const resolver = new DnsResolverStub({
          'triauthdemo.org': {TXT: ['triauth auth.triauthdemo.org mode=public']},
          'john._at.triauthdemo.org': {TXT: [`key device[1/1]:${ed25519Key.public} type=ed25519`]}
        });

        const challenge = (await Triauth.authenticate({identifier, callbackUrl}, {resolver})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys([ed25519Key]),
          'auth',
          identifier, '',
          callbackUrl,
          challenge
        );

        const authRes = await Triauth.authenticate({challenge, response}, {resolver});

        assert.equal(authRes.authenticated, true, 'authentication backed by an ed25519 key must succeed');
        assert.equal(authRes.identifier, identifier);
        assert.equal(authRes.keys[0].options.type, 'ed25519');
        assert.equal(authRes.keys[0].verified, true);
      });

      it('verifies identifier, if passed, is the same as in challenge', async () => {

        const identifier = identities['john'].identifier;

        const challenge = (await Triauth.authenticate({identifier, callbackUrl:'https://example.com/'})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(identities['john'].devices[0].keys),
          'auth',
          identifier, '',
          'https://example.com/',
          challenge
        );

        let authRes = (await Triauth.authenticate({identifier, challenge, response}));
        assert.equal(authRes.authenticated, true);

        authRes = (await Triauth.authenticate({identifier:'other-user@example.com', challenge, response}));
        assert(!authRes?.authenticated);
      });

      it('does not authenticate challenges with invalid or unresolvable identifier', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.authenticate({identifier:identity.identifier, callbackUrl:'https://example.com/'})).challenge;
        const decodedChallenge = JSON.parse(Triauth.Helpers.base64UrlToString(challenge));

        assert.equal(decodedChallenge.identifier, identity.identifier);

        // first identifier is valid (to check if this test is working correctly), the rest not
        for (const identifier of [identity.identifier, 'john@domain.invalid', 'john@triauth.org', 'not-existing@triauthdemo.org', '!', '']) {
          decodedChallenge.identifier = identifier;
          const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(decodedChallenge));

          const response = await Triauth.Signature.generate(
            SignerStub.signUsingDeviceKeys(device.keys),
            'auth',
            identifier, '',
            'https://example.com/',
            challenge
          );

          let authRes = (await Triauth.authenticate({challenge:modifiedChallenge, response}));

          assert.equal(!!authRes?.authenticated, identifier === identity.identifier);
        }
      });

      it('does not authenticate expired challenges', async () => {
        // challenge with iat set far in the past; built dynamically
        const challenge = Triauth.Helpers.stringToBase64Url(JSON.stringify({
          type: 'auth',
          identifier: 'john@triauthdemo.org',
          nonce: 'wtr6JVXFUZJBJULti3aYZo5A',
          iat: 1737711045465,
          ver: 1
        }));

        const authRes = (await Triauth.authenticate({
          challenge,
          response: '|auth;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'
        }));

        assert.equal(!!authRes?.authenticated, false);
        assert.equal(authRes.error.code, 402);
      });

      it('does not authenticate challenges with issued at (iat) in future', async () => {
        // challenge with iat set far in the future; built dynamically
        const challenge = Triauth.Helpers.stringToBase64Url(JSON.stringify({
          type: 'auth',
          identifier: 'john@triauthdemo.org',
          nonce: 'wtr6JVXFUZJBJULti3aYZo5A',
          iat: 99999999999999,
          ver: 1
        }));

        const authRes = (await Triauth.authenticate({
          challenge,
          response: '|auth;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'
        }));

        assert.equal(!!authRes?.authenticated, false);
        assert.equal(authRes.error.code, 402);
      });

      it('does not authenticate invalid challenges', (done) => {
        const promises = [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].map((invalidChallenge) => {
          return Triauth.authenticate({
            challenge: invalidChallenge,
            response: '|auth;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'
          }).then((authRes) => assert(authRes.authenticated === false)).catch(() => assert(false));
        });

        Promise.allSettled(promises).then(() => done());
      });

      it('does not authenticate invalid responses', (done) => {
        const promises = [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].map(async function(invalidResponse) {
          return (await Triauth.authenticate({
            challenge: 'eyJzdWIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoid3RyNkpWWEZVWkpCSlVMdGkzYVlabzVBIiwiaWF0IjoxNzM3NzExMDQ1NDY1LCJ2ZXIiOjF9',
            response: invalidResponse
          })).then((authRes) => assert(authRes.authenticated === false)).catch(() => assert(false));
        });

        Promise.allSettled(promises).then(() => done());
      });

      it('rejects challenges whose embedded `type` does not match the auth flow', async () => {
        // An attacker who substitutes the challenge's `type` field with another flow's value
        // must be rejected at Stage 3 with 401 before any DNS or signature work.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const buildRes = await Triauth.authenticate({identifier: identity.identifier, callbackUrl});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.type = 'sign';  // tamper
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          callbackUrl,
          modifiedChallenge
        );

        const authRes = await Triauth.authenticate({challenge: modifiedChallenge, response});
        assert(!authRes.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it('rejects responses whose envelope `type` does not match the auth flow', async () => {
        // Even if the challenge says `auth`, a signature minted with envelope type='sign'
        // must be rejected by the signature.verify type constraint.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',  // <-- envelope type mismatched with the flow
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        const authRes = await Triauth.authenticate({challenge, response});
        assert(!authRes.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it('verifies callbackUrl, if passed, is the same as in challenge', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        // Matching callbackUrl — succeeds
        let authRes = await Triauth.authenticate({challenge, response, callbackUrl});
        assert.equal(authRes.authenticated, true);

        // Mismatching callbackUrl — fails with 401
        authRes = await Triauth.authenticate({challenge, response, callbackUrl: 'https://other-domain.com/'});
        assert(!authRes.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it('rejects responses whose signed `via` is not a prefix of the challenge `cburl`', async () => {
        // Defense-in-depth (S2): under a non-DNSSEC domain, attacker-controlled keys could sign
        // with a misaligned `via`. Even though the signature is cryptographically valid against
        // the attacker's published key, the via/cburl mismatch must reject the auth.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/triauth-callback';

        const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl})).challenge;

        // Sanity: a via that is a proper prefix of cburl authenticates
        let response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          'https://example.com/',
          challenge
        );
        let authRes = await Triauth.authenticate({challenge, response});
        assert.equal(authRes.authenticated, true, 'via prefixing cburl must authenticate');

        // A via on a different domain must fail
        response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          'https://attacker.example/',
          challenge
        );
        authRes = await Triauth.authenticate({challenge, response});
        assert(!authRes.authenticated, 'via not a prefix of cburl must NOT authenticate');
      });

      it('honors per-call authTimeout override (config #1)', async () => {
        // Default 3-minute window should reject an iat just outside it; a widened per-call
        // authTimeout override should accept the same iat.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';
        const defaultTimeout = Triauth.config.authTimeout;

        const buildRes = await Triauth.authenticate({identifier: identity.identifier, callbackUrl});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        // Move iat 10 seconds past the default window
        challengeObj.data.iat = Date.now() - (defaultTimeout + 10e3);
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          callbackUrl,
          modifiedChallenge
        );

        // Default config — should fail with 402 (expired)
        let authRes = await Triauth.authenticate({challenge: modifiedChallenge, response});
        assert(!authRes.authenticated, 'default authTimeout must reject iat outside window');
        assert.equal(authRes.error.code, 402);

        // Override widens the window — should succeed
        authRes = await Triauth.authenticate(
          {challenge: modifiedChallenge, response},
          {authTimeout: defaultTimeout * 2 + 60e3}
        );
        assert.equal(authRes.authenticated, true, 'per-call authTimeout override must accept iat within widened window');
      });

      it('does NOT prevent in-window replay (caller is responsible for invalidating challenges)', async () => {
        // The library deliberately does not track consumed challenges; replay protection is the
        // caller's responsibility (see README). This test documents that contract — if it ever
        // changes (e.g., internal tracking is added), the contract change must be deliberate.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        const first = await Triauth.authenticate({challenge, response});
        assert.equal(first.authenticated, true);

        const second = await Triauth.authenticate({challenge, response});
        assert.equal(second.authenticated, true, 'library does not track consumed challenges — caller must');
      });

      it('still authenticates when unsignedMetadata is tampered with after signing', async () => {
        // The unsignedMetadata slot in the signature envelope is intentionally NOT covered by the
        // crypto signature. Verifiers that consume unsignedMetadata must independently bind the
        // consumed fields (see WebAuthn). For ECDSA auth, no field is consumed from unsignedMetadata,
        // so tampering must not affect the outcome.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.authenticate({identifier: identity.identifier, callbackUrl})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        // Inject a tampered unsignedMetadata segment into the wire envelope
        const segments = response.slice(1, -1).split(';');
        // segments[7] is the unsignedMetadata slot
        segments[7] = Triauth.Helpers.stringToBase64Url(JSON.stringify({tampered: 'evilValue'}));
        const tamperedResponse = '|' + segments.join(';') + '|';

        const authRes = await Triauth.authenticate({challenge, response: tamperedResponse});
        assert.equal(authRes.authenticated, true, 'tampered unsignedMetadata must NOT invalidate ECDSA auth');
      });
    });

    describe('delegated authentication (include grants)', () => {

      const subjectDevice = identities['john'].devices[0]; // the subject's own device key
      const actorDevice   = identities['john'].devices[1]; // a second fixture keypair, serving as the actor's device
      const callbackUrl = 'https://example.com/';

      const resolver = (includeRecords) => new DnsResolverStub({
        'example.org': {TXT: [{value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true}]},
        'john._at.example.org': {TXT: [
          {value: `key desktop[1/1]:${subjectDevice.keys[0].public}`, ttl: 1800, dnssec: true},
          ...includeRecords
        ]},
        'issuer.example': {TXT: [{value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true}]},
        'actor._at.issuer.example': {TXT: [
          {value: `key remote[1/2]:${actorDevice.keys[0].public}`, ttl: 1800, dnssec: true},
          {value: `key remote[2/2]:${actorDevice.keys[1].public}`, ttl: 1800, dnssec: true}
        ]}
      });

      // Runs the full flow with the actor's keys signing on behalf of john@example.org
      const delegatedAuth = async (includeRecords, cburl = callbackUrl) => {
        const config = {resolver: resolver(includeRecords)};
        const challenge = (await Triauth.authenticate({identifier: 'john@example.org', callbackUrl: cburl}, config)).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(actorDevice.keys),
          'auth',
          'john@example.org', 'actor@issuer.example',
          cburl,
          challenge
        );
        return {config, authRes: await Triauth.authenticate({challenge, response}, config)};
      };

      it('authenticates the subject through a granted actor, with the composite deviceTag', async () => {
        const includeRecord = {value: 'include actor@issuer.example scope=any', ttl: 900, dnssec: true};
        const {config, authRes} = await delegatedAuth([includeRecord]);

        assert.equal(authRes.authenticated, true);
        assert.equal(authRes.identifier, 'john@example.org');
        assert.equal(authRes.actor, 'actor@issuer.example');
        assert.equal(authRes.identityDomain, 'john._at.example.org');
        assert.equal(authRes.actorIdentityDomain, 'actor._at.issuer.example', "the actor's identity domain names the records the signing keys were read from");
        assert.equal(authRes.lookupCode, '', 'public-mode identities consume no lookup code');
        assert.equal(authRes.actorLookupCode, '');
        assert.equal(authRes.deviceName, 'remote', 'device fields must describe the actor device that signed');
        assert.equal(authRes.secure, true);

        const [includeTag, actorIdentifier, actorDeviceTag] = authRes.deviceTag.split(':');
        assert.equal(actorIdentifier, 'actor@issuer.example');
        assert.match(actorDeviceTag, /^[A-Za-z0-9_-]{43}$/);

        const subject = new Triauth.Identity('john@example.org', {}, config);
        await subject.resolve();
        assert.equal(includeTag, subject.includes.includes[0].tag, 'the deviceTag must pin the exact grant');

        // The include record's 900s TTL is shorter than the key records' - earliest wins
        assert(authRes.expires > Date.now() + 800_000 && authRes.expires <= Date.now() + 900_000);
      });

      it("carries the subject's groups on the result, never the actor's", async () => {
        const config = {resolver: new DnsResolverStub({
          'example.org': {TXT: [{value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true}]},
          'john._at.example.org': {TXT: [
            {value: `key desktop[1/1]:${subjectDevice.keys[0].public}`, ttl: 1800, dnssec: true},
            {value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: true},
            {value: 'groups admins,project3', ttl: 1800, dnssec: true}
          ]},
          'issuer.example': {TXT: [{value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true}]},
          'actor._at.issuer.example': {TXT: [
            {value: `key remote[1/2]:${actorDevice.keys[0].public}`, ttl: 1800, dnssec: true},
            {value: `key remote[2/2]:${actorDevice.keys[1].public}`, ttl: 1800, dnssec: true},
            {value: 'groups contractors', ttl: 1800, dnssec: true}
          ]}
        })};

        const challenge = (await Triauth.authenticate({identifier: 'john@example.org', callbackUrl}, config)).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(actorDevice.keys),
          'auth',
          'john@example.org', 'actor@issuer.example',
          callbackUrl,
          challenge
        );
        const authRes = await Triauth.authenticate({challenge, response}, config);

        assert.equal(authRes.authenticated, true);
        assert.deepStrictEqual(authRes.groups, ['admins@example.org', 'project3@example.org'], "the subject's groups, qualified with the subject's domain - the actor's own groups must not leak in");
      });

      it('caps secure at the DNSSEC status of the include record', async () => {
        const {authRes} = await delegatedAuth([{value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: false}]);

        assert.equal(authRes.authenticated, true);
        assert.equal(authRes.secure, false);
      });

      it('bounds expires by the subject endpoint record TTL when it is the shortest-lived record', async () => {
        const config = {resolver: new DnsResolverStub({
          'example.org': {TXT: [{value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 60, dnssec: true}]},
          'john._at.example.org': {TXT: [
            {value: `key desktop[1/1]:${subjectDevice.keys[0].public}`, ttl: 1800, dnssec: true},
            {value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: true}
          ]},
          'issuer.example': {TXT: [{value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true}]},
          'actor._at.issuer.example': {TXT: [
            {value: `key remote[1/2]:${actorDevice.keys[0].public}`, ttl: 1800, dnssec: true},
            {value: `key remote[2/2]:${actorDevice.keys[1].public}`, ttl: 1800, dnssec: true}
          ]}
        })};
        const challenge = (await Triauth.authenticate({identifier: 'john@example.org', callbackUrl}, config)).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(actorDevice.keys), 'auth', 'john@example.org', 'actor@issuer.example', callbackUrl, challenge);
        const before = Date.now();
        const authRes = await Triauth.authenticate({challenge, response}, config);

        assert.equal(authRes.authenticated, true);
        assert(authRes.expires >= before + 60_000 && authRes.expires <= Date.now() + 60_000, 'the subject endpoint record expires first');
      });

      it('rejects (401) a delegated response with no include grant for the actor', async () => {
        const {authRes} = await delegatedAuth([]);

        assert(!authRes?.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it("rejects (401) a delegated response whose grant does not cover the auth flow (use=sign)", async () => {
        const {authRes} = await delegatedAuth([{value: 'include actor@issuer.example use=sign scope=any', ttl: 1800, dnssec: true}]);

        assert(!authRes?.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it('rejects (401) a delegated response whose grant publishes no scope option - the record is ignored as a whole', async () => {
        const {authRes} = await delegatedAuth([{value: 'include actor@issuer.example', ttl: 1800, dnssec: true}]);

        assert(!authRes?.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it('authenticates through a grant scoped to the service host (scope=example.com)', async () => {
        const {authRes} = await delegatedAuth([{value: 'include actor@issuer.example scope=example.com', ttl: 1800, dnssec: true}]);

        assert.equal(authRes.authenticated, true);
        assert.equal(authRes.actor, 'actor@issuer.example');
      });

      it('SECURITY: rejects (401) a delegated response whose grant is scoped to a different host (scope=other.example)', async () => {
        const {authRes} = await delegatedAuth([{value: 'include actor@issuer.example scope=other.example', ttl: 1800, dnssec: true}]);

        assert(!authRes?.authenticated);
        assert.equal(authRes.error.code, 401);
      });

      it('matches scope on the bare host: an IPv4 callback on a non-default port is covered by its quad entry', async () => {
        const {authRes} = await delegatedAuth(
          [{value: 'include actor@issuer.example scope=10.0.0.5', ttl: 1800, dnssec: true}],
          'http://10.0.0.5:8080/'
        );

        assert.equal(authRes.authenticated, true);
        assert.equal(authRes.actor, 'actor@issuer.example');
      });

      it('authenticates through a scope=any grant at any callback host - an IPv4 callback on a non-default port included', async () => {
        const {authRes} = await delegatedAuth(
          [{value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: true}],
          'http://10.0.0.5:8080/'
        );

        assert.equal(authRes.authenticated, true);
        assert.equal(authRes.actor, 'actor@issuer.example');
      });

      it('SECURITY: rejects (401) when the grant lists any beside a host (scope=example.com,any) - any is only the sole-entry spelling, so the record is ignored as a whole', async () => {
        const {authRes} = await delegatedAuth([{value: 'include actor@issuer.example scope=example.com,any', ttl: 1800, dnssec: true}]);

        assert(!authRes?.authenticated);
        assert.equal(authRes.error.code, 401);
      });
    });
  });

  describe('Triauth.ping', () => {

    describe('accepts identifier, callbackUrl, and token to produce challenge and redirectUrl', () => {

      const identifier = 'john@triauthdemo.org';
      const callbackUrl = 'https://example.com/';
      const token = ':' + 'a'.repeat(16);

      it('returns challenge and a correct redirectUrl for valid identifiers', async () => {
        const pingRes = (await Triauth.ping({identifier, callbackUrl, token}));
        assert(typeof pingRes.challenge === 'string' && pingRes.challenge.length > 0);
        assert(typeof pingRes.redirectUrl === 'string' && pingRes.redirectUrl.length > 0);
      });

      it('includes the token and its hmac in redirectUrl when token is provided', async () => {
        const pingRes = (await Triauth.ping({identifier, callbackUrl, token}));
        assert(pingRes.redirectUrl.indexOf('token=') >= 0);
        assert(pingRes.redirectUrl.indexOf('hmac=') < 0);
      });

      it('rejects a token-less request with 226 - ping is a token-gated flow', async () => {
        const pingRes = (await Triauth.ping({identifier, callbackUrl}));
        assert.equal(pingRes?.error?.code, 226);
      });

      it('encodes type, identifier and callbackUrl in the challenge', async () => {
        const pingRes = (await Triauth.ping({identifier, callbackUrl, token}));
        const challengeRequest = Triauth.Challenge.fromString(pingRes.challenge);

        assert.equal(challengeRequest.data.type, 'ping');
        assert.equal(challengeRequest.data.identifier, identifier);
        assert.equal(challengeRequest.data.cburl, callbackUrl);
        assert.equal(challengeRequest.data.ver, 1);
      });

      it('accepts optional ext hash and encodes it in the challenge', async () => {
        const pingRes = (await Triauth.ping({identifier, callbackUrl, token, ext:{'foo':'bar'}}));
        const challengeRequest = Triauth.Challenge.fromString(pingRes.challenge);

        assert.equal(challengeRequest.data.ext?.foo, 'bar');
      });

      it('generates random and unique challenges for each call', async () => {
        const challenges = [];

        for (let i = 1; i <= 3; i++) {
          challenges.push((await Triauth.ping({identifier, callbackUrl, token})).challenge);
        }

        assert.equal((new Set(challenges)).size, challenges.length);
      });

      it('returns validation error for invalid identifiers', async () => {
        const {invalidIdentifiers} = identifiersFixture;
        for (const invalidIdentifier in invalidIdentifiers) {
          const pingRes = (await Triauth.ping({identifier: invalidIdentifier, callbackUrl, token}));
          assert(!pingRes?.pinged, invalidIdentifier);
          assert(pingRes.error.code >= 210 && pingRes.error.code < 220, invalidIdentifier);
        }
      });

      it('returns validation error for invalid callbackUrls', async () => {
        const invalidUrls = ['=', '', 'https://[::1]/' + 'a'.repeat(1100)];

        for (const invalidUrl of invalidUrls) {
          const pingRes = (await Triauth.ping({identifier, callbackUrl: invalidUrl, token}));
          assert(!pingRes?.pinged);
          assert.equal(pingRes.error.code, 221);
        }
      });

      it('returns {error:{code:102}} for unrecognized options', async () => {
        const pingRes = (await Triauth.ping({identifier, callbackUrl, token, unknownKey: 1}));
        assert(!pingRes?.pinged);
        assert.equal(pingRes.error.code, 102);
      });

      it('returns {error:{code:226}} for invalid tokens', async () => {
        const invalidTokens = ['short', 123, '', 'a'.repeat(257)];
        for (const invalidToken of invalidTokens) {
          const pingRes = (await Triauth.ping({identifier, callbackUrl, token: invalidToken}));
          assert(!pingRes?.pinged);
          assert.equal(pingRes.error.code, 226);
        }
      });

      it('returns {error:{code:222}} for malformed ext', async () => {
        const invalidExts = [[], {a:{b:{c:1}}}, {x:'y'.repeat(4096)}];
        for (const invalidExt of invalidExts) {
          const pingRes = (await Triauth.ping({identifier, callbackUrl, token, ext: invalidExt}));
          assert(!pingRes?.pinged);
          assert.equal(pingRes.error.code, 222);
        }
      });
    });

    describe('token pass-through and hmac keying', () => {

      // The redirectUrl carries the token's public part verbatim, with the HMAC appended after a
      // ':' separator. The HMAC is keyed by the full `public:secret` token string, exactly as the
      // issuing endpoint handed it out - the secret half never travels.
      const expectedHmac = async (token, challenge) => {
        const key = await crypto.subtle.importKey(
          'raw', Triauth.Helpers.stringToUtf8Bytes(token), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']
        );
        return Triauth.Helpers.arrayBufferToBase64Url(
          await crypto.subtle.sign('HMAC', key, Triauth.Helpers.base64UrlToUint8(challenge))
        );
      };

      const keyRecord = {value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true};
      const resolver = (grant = 'include actor@issuer.example scope=any') => new DnsResolverStub({
        'example.org':           {TXT: [{value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true}]},
        'john._at.example.org':  {TXT: [keyRecord, {value: grant, ttl: 1800, dnssec: true}]},
        'issuer.example':        {TXT: [{value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true}]}
      });
      const callbackUrl = 'https://example.com/';

      const tokenParam = (redirectUrl) => redirectUrl.match(/[#&?]token=([^&]*)/)[1];

      it('keys the redirectUrl hmac with the whole token, leading colon included', async () => {
        const token = ':' + 'a'.repeat(16);
        const pingRes = await Triauth.ping({identifier: 'john@example.org', callbackUrl, token}, {resolver: resolver()});

        assert(pingRes.redirectUrl.startsWith('https://local-auth.example.org/ping.html#?'));
        assert.equal(tokenParam(pingRes.redirectUrl), ':' + await expectedHmac(token, pingRes.challenge));
      });

      it("carries an issuer-hinted token's public part through to the identity's own endpoint", async () => {
        const token = 'issuer.example:' + 'a'.repeat(16);
        const pingRes = await Triauth.ping({identifier: 'john@example.org', callbackUrl, token}, {resolver: resolver()});

        assert(pingRes.redirectUrl.startsWith('https://local-auth.example.org/ping.html#?'),
          'the redirect always targets the identity\'s endpoint; the issuer hint travels in the token');
        assert.equal(tokenParam(pingRes.redirectUrl), 'issuer.example:' + await expectedHmac(token, pingRes.challenge));
      });

      it('carries an issuer hint no include grant covers, unchanged - the grant is enforced on the signed response, not at issue', async () => {
        const token = 'unrelated.example:' + 'a'.repeat(16);
        const pingRes = await Triauth.ping({identifier: 'john@example.org', callbackUrl, token}, {resolver: resolver()});

        assert(!pingRes.error);
        assert.equal(tokenParam(pingRes.redirectUrl).split(':')[0], 'unrelated.example');
      });

      it('rejects (226) a token with no secret part - the grammar keeps a secret behind every public part', async () => {
        const pingRes = await Triauth.ping({identifier: 'john@example.org', callbackUrl, token: 'issuer.example'}, {resolver: resolver()});

        assert(!pingRes?.pinged);
        assert.equal(pingRes.error.code, 226);
      });
    });

    describe('accepts challenge and response to produce ping result', () => {

      it('correctly sets the pinged status', async () => {
        const callbackUrl = 'https://example.com/';
        for (const identity of Object.values(identities)) {
          const challenge = (await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl})).challenge;

          for (const device of identity.devices) {
            const tsBefore = Date.now();
            const response = await Triauth.Signature.generate(
              SignerStub.signUsingDeviceKeys(device.keys),
              'ping',
              identity.identifier, '',
              callbackUrl,
              challenge
            );

            const pingRes = (await Triauth.ping({challenge, response}));
            const tsAfter = Date.now();

            assert.equal(pingRes.pinged, true);
            assert.equal(pingRes.identifier, identity.identifier);
            assert.equal(pingRes.identityDomain, identity.identityDomain);
            assert.equal(pingRes.actorIdentityDomain, '');
            assert.equal(pingRes.lookupCode, '');
            assert.equal(pingRes.actorLookupCode, '');
            assert.equal(pingRes.deviceName, device.deviceName);
            assert.equal(pingRes.secure, true);
            assert(pingRes.expires > Date.now());
            assert.equal(pingRes.keys.length, device.keys.length);
            assert.equal(pingRes.keys.every((k) => k.verified), true);
            assert(pingRes.signedAt >= tsBefore && pingRes.signedAt <= tsAfter);
            assert(typeof pingRes.issuedAt === 'number' && pingRes.issuedAt <= pingRes.signedAt);
            assert(pingRes.verifiedAt >= tsBefore && pingRes.verifiedAt <= tsAfter);
            assert(pingRes.signedAt <= pingRes.verifiedAt);

            // Invalid signature must not ping
            const pingResInvalid = (await Triauth.ping({challenge, response: response.replace('@', '@a')}));
            assert(!pingResInvalid.pinged);
          }
        }
      });

      it('does not ping expired challenges', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const buildRes = await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.iat = Date.now() - (Triauth.config.pingTimeout + 10e3);
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          callbackUrl,
          modifiedChallenge
        );

        const pingRes = await Triauth.ping({challenge: modifiedChallenge, response});
        assert(!pingRes.pinged);
        assert.equal(pingRes.error.code, 402);
      });

      it('does not ping challenges with issued at (iat) in future', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const buildRes = await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.iat = 99999999999999;
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          callbackUrl,
          modifiedChallenge
        );

        const pingRes = await Triauth.ping({challenge: modifiedChallenge, response});
        assert(!pingRes.pinged);
        assert.equal(pingRes.error.code, 402);
      });

      it('rejects responses whose envelope `type` is not `ping`', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'auth',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        const pingRes = await Triauth.ping({challenge, response});
        assert(!pingRes.pinged);
        assert(pingRes.error);
      });

      it('rejects challenges whose embedded `type` does not match the ping flow', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const buildRes = await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.type = 'auth';
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          callbackUrl,
          modifiedChallenge
        );

        const pingRes = await Triauth.ping({challenge: modifiedChallenge, response});
        assert(!pingRes.pinged);
        assert.equal(pingRes.error.code, 401);
      });

      it('verifies identifier, if passed, is the same as in challenge', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        let pingRes = await Triauth.ping({identifier: identity.identifier, challenge, response});
        assert.equal(pingRes.pinged, true);

        pingRes = await Triauth.ping({identifier: 'other-user@example.com', challenge, response});
        assert(!pingRes.pinged);
        assert.equal(pingRes.error.code, 401);
      });

      it('verifies callbackUrl, if passed, is the same as in challenge', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        let pingRes = await Triauth.ping({challenge, response, callbackUrl});
        assert.equal(pingRes.pinged, true);

        pingRes = await Triauth.ping({challenge, response, callbackUrl: 'https://other-domain.com/'});
        assert(!pingRes.pinged);
        assert.equal(pingRes.error.code, 401);
      });

      it('rejects responses whose signed `via` is not a prefix of the challenge `cburl`', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/triauth-callback';

        const challenge = (await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          'https://attacker.example/',
          challenge
        );

        const pingRes = await Triauth.ping({challenge, response});
        assert(!pingRes.pinged);
      });

      it('does NOT prevent in-window replay (caller is responsible for invalidating challenges)', async () => {
        // Mirrors the equivalent contract test for Triauth.authenticate.
        const identity = identities['john'];
        const device = identity.devices[0];
        const callbackUrl = 'https://example.com/';

        const challenge = (await Triauth.ping({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'ping',
          identity.identifier, '',
          callbackUrl,
          challenge
        );

        const first = await Triauth.ping({challenge, response});
        assert.equal(first.pinged, true);

        const second = await Triauth.ping({challenge, response});
        assert.equal(second.pinged, true, 'library does not track consumed challenges — caller must');
      });

      it('does not ping invalid challenges', (done) => {
        const promises = [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].map((invalidChallenge) => {
          return Triauth.ping({
            challenge: invalidChallenge,
            response: '|ping;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'
          }).then((pingRes) => assert(!pingRes?.pinged)).catch(() => assert(false));
        });

        Promise.allSettled(promises).then(() => done());
      });

      it('does not ping invalid responses', (done) => {
        const promises = [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].map(async function(invalidResponse) {
          return (await Triauth.ping({
            challenge: 'eyJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoid3RyNkpWWEZVWkpCSlVMdGkzYVlabzVBIiwiaWF0IjoxNzM3NzExMDQ1NDY1LCJ2ZXIiOjF9',
            response: invalidResponse
          })).then((pingRes) => assert(!pingRes?.pinged)).catch(() => assert(false));
        });

        Promise.allSettled(promises).then(() => done());
      });
    });
  });

  describe('Triauth.check', () => {

    it('returns {valid:true} for a valid device tag', async () => {
      const identity = identities['john'];
      const checkResult = (await Triauth.check({identifier: identity.identifier, deviceTag: identity.devices[0].deviceTag}));

      assert.equal(checkResult.valid, true);
      assert(!('checked' in checkResult));
    });

    it("carries the identity's current groups and reflects membership changes on re-check", async () => {
      const zone = (groupsRecords) => new DnsResolverStub({
        'example.org': {TXT: [{value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true}]},
        'member._at.example.org': {TXT: [
          {value: `key desktop[1/1]:${identities['john'].devices[0].keys[0].public}`, ttl: 1800, dnssec: true},
          ...groupsRecords.map((value) => ({value, ttl: 1800, dnssec: true}))
        ]}
      });

      const deviceTag = (await Triauth.whois({identifier: 'member@example.org'}, {resolver: zone([])})).devices[0].deviceTag;

      const before = await Triauth.check({identifier: 'member@example.org', deviceTag}, {resolver: zone(['groups admins,project3'])});
      assert.equal(before.valid, true);
      assert.deepStrictEqual(before.groups, ['admins@example.org', 'project3@example.org']);

      // The org removes one membership - the next periodic check returns the fresh list for the same device
      const after = await Triauth.check({identifier: 'member@example.org', deviceTag}, {resolver: zone(['groups project3'])});
      assert.equal(after.valid, true);
      assert.deepStrictEqual(after.groups, ['project3@example.org'], 'session-cached groups must be replaced with this fresh list');

      // Failure shapes stay groups-free
      const revoked = await Triauth.check({identifier: 'member@example.org', deviceTag: 'not-a-real-tag'}, {resolver: zone([])});
      assert.equal(revoked.valid, false);
      assert(!('groups' in revoked));
    });

    it('returns {valid:false, reason:\'revoked\'} for invalid or missing device tags', async () => {
      const checkResult = (await Triauth.check({identifier: 'john@triauthdemo.org', deviceTag: 'invalid-tag'}));

      assert.equal(checkResult.valid, false);
      assert.equal(checkResult.reason, 'revoked');
    });

    it('returns {valid:false, reason:\'unresolved\'} for identifiers with no identity records', async () => {
      const {invalidIdentifiers, emptyIdentifiers} = identifiersFixture;

      for (const emptyIdentifier of emptyIdentifiers) {
        const checkResult = (await Triauth.check({identifier: emptyIdentifier, deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk'}));

        assert.equal(checkResult.valid, false);
        assert.equal(checkResult.reason, 'unresolved');
      }
    });

    it('returns {error:{code, message} for invalid identifiers', async () => {
      const {invalidIdentifiers, emptyIdentifiers} = identifiersFixture;

      for (const invalidIdentifier in invalidIdentifiers) {
        const checkResult = (await Triauth.check({identifier: invalidIdentifier, deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk'}));

        assert(!Object.keys(checkResult).includes('checked'));
        assert(!Object.keys(checkResult).includes('valid'));
        assert(checkResult.error);
      }
    });

    it('returns {error:{code:101}} for invalid arguments', async () => {
      const checkResult = (await Triauth.check({identifier: {}, deviceTag: {}}));

      assert(!Object.keys(checkResult).includes('checked'));
      assert(!Object.keys(checkResult).includes('valid'));
      assert.equal(checkResult.error.code, 101);
    });

    it('returns {error:{code:102}} for unrecognized arguments', async () => {
      const checkResult = (await Triauth.check({identifier: 'john@triauthdemo.org', deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk', unknown: 'value'}));

      assert(!Object.keys(checkResult).includes('checked'));
      assert(!Object.keys(checkResult).includes('valid'));
      assert.equal(checkResult.error.code, 102);
    });

    it('returns {error:{code:110}} for DNSSEC-failed domains', async () => {
      const checkResult = await Triauth.check({identifier: 'a@dnssec-failed.org', deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk'});
      assert.equal(checkResult.error.code, 110);
    });

    it('includes secure (boolean) and expires (future timestamp) in a valid check result', async () => {
      const identity = identities['john'];
      const checkResult = await Triauth.check({identifier: identity.identifier, deviceTag: identity.devices[0].deviceTag});

      assert.equal(checkResult.valid, true);
      assert(!('checked' in checkResult));
      assert.equal(typeof checkResult.secure, 'boolean');
      assert(typeof checkResult.expires === 'number' && checkResult.expires > Date.now());
    });

    it('bounds expires by the endpoint record TTL when it is shorter than the key records\'', async () => {
      const identity = identities['john'];
      const resolver = new DnsResolverStub({
        'triauthdemo.org': {TXT: [{value: 'triauth auth.triauthdemo.org mode=public', ttl: 60, dnssec: true}]},
        'john._at.triauthdemo.org': {TXT: [{value: `key desktop[1/1]:${identity.devices[0].keys[0].public}`, ttl: 86400, dnssec: true}]}
      });
      const before = Date.now();
      const checkResult = await Triauth.check({identifier: identity.identifier, deviceTag: identity.devices[0].deviceTag}, {resolver});

      assert.equal(checkResult.valid, true);
      assert(checkResult.expires >= before + 60_000 && checkResult.expires <= Date.now() + 60_000, 'the endpoint record expires first');
    });

    it('bounds a composite tag\'s expires by the actor endpoint record TTL', async () => {
      const subjectDevice = identities['john'].devices[0];
      const actorDevice = identities['john'].devices[1];
      const resolver = new DnsResolverStub({
        'example.org': {TXT: [{value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 86400, dnssec: true}]},
        'john._at.example.org': {TXT: [
          {value: `key desktop[1/1]:${subjectDevice.keys[0].public}`, ttl: 86400, dnssec: true},
          {value: 'include actor@issuer.example scope=any', ttl: 86400, dnssec: true}
        ]},
        'issuer.example': {TXT: [{value: 'triauth remote-auth.issuer.example mode=public', ttl: 60, dnssec: true}]},
        'actor._at.issuer.example': {TXT: [{value: `key remote[1/1]:${actorDevice.keys[0].public}`, ttl: 86400, dnssec: true}]}
      });
      const subject = await Triauth.whois({identifier: 'john@example.org'}, {resolver});
      const actor = await Triauth.whois({identifier: 'actor@issuer.example'}, {resolver});
      const deviceTag = `${subject.includes[0].tag}:actor@issuer.example:${actor.devices[0].deviceTag}`;
      const before = Date.now();
      const checkResult = await Triauth.check({identifier: 'john@example.org', deviceTag}, {resolver});

      assert.equal(checkResult.valid, true);
      assert(checkResult.expires >= before + 60_000 && checkResult.expires <= Date.now() + 60_000, 'the actor endpoint record expires first');
    });

    describe('delegated deviceTags (composite includeTag:actor:actorDeviceTag)', () => {

      const subjectDevice = identities['john'].devices[0];
      const actorDevice   = identities['john'].devices[1];

      const zones = ({includeRecords, actorZones = true}) => new DnsResolverStub({
        'example.org': {TXT: [{value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true}]},
        'john._at.example.org': {TXT: [
          {value: `key desktop[1/1]:${subjectDevice.keys[0].public}`, ttl: 1800, dnssec: true},
          ...includeRecords
        ]},
        ...(actorZones ? {
          'issuer.example': {TXT: [{value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true}]},
          'actor._at.issuer.example': {TXT: [{value: `key remote[1/1]:${actorDevice.keys[0].public}`, ttl: 1800, dnssec: true}]}
        } : {})
      });

      const grant = {value: 'include actor@issuer.example use=sign scope=any', ttl: 1800, dnssec: true};

      // The composite deviceTag as a delegated authentication would have produced it
      const mintedDeviceTag = async (resolver) => {
        const subject = new Triauth.Identity('john@example.org', {}, {resolver});
        const actor = new Triauth.Identity('actor@issuer.example', {}, {resolver});
        await Promise.all([subject.resolve(), actor.resolve()]);
        return `${subject.includes.includes[0].tag}:actor@issuer.example:${Object.values(actor.keys.keyGroups)[0].tag}`;
      };

      it('is a liveness check: a grant stays valid for its whole lifetime regardless of its use option', async () => {
        const resolver = zones({includeRecords: [grant]});
        const deviceTag = await mintedDeviceTag(resolver);

        // The grant covers only `sign`, yet check (which carries no flow) accepts it
        const checkResult = await Triauth.check({identifier: 'john@example.org', deviceTag}, {resolver: zones({includeRecords: [grant]})});
        assert.equal(checkResult.valid, true);
        assert.equal(typeof checkResult.secure, 'boolean');
        assert(typeof checkResult.expires === 'number' && checkResult.expires > Date.now());
      });

      it('reports revoked when the include record is gone, or when the pinned grant/actor device no longer matches', async () => {
        const deviceTag = await mintedDeviceTag(zones({includeRecords: [grant]}));

        const gone = await Triauth.check({identifier: 'john@example.org', deviceTag}, {resolver: zones({includeRecords: []})});
        assert.deepEqual(gone, {valid: false, reason: 'revoked'});

        const [, actorIdentifier, actorDeviceTag] = deviceTag.split(':');
        const otherGrant = await Triauth.check(
          {identifier: 'john@example.org', deviceTag: `${'A'.repeat(43)}:${actorIdentifier}:${actorDeviceTag}`},
          {resolver: zones({includeRecords: [grant]})}
        );
        assert.deepEqual(otherGrant, {valid: false, reason: 'revoked'});

        const otherDevice = await Triauth.check(
          {identifier: 'john@example.org', deviceTag: deviceTag.replace(/[^:]+$/, 'B'.repeat(43))},
          {resolver: zones({includeRecords: [grant]})}
        );
        assert.deepEqual(otherDevice, {valid: false, reason: 'revoked'});
      });

      it('reports unresolved when the actor identity cannot be resolved (distinct from revocation)', async () => {
        const deviceTag = await mintedDeviceTag(zones({includeRecords: [grant]}));

        const checkResult = await Triauth.check(
          {identifier: 'john@example.org', deviceTag},
          {resolver: zones({includeRecords: [grant], actorZones: false})}
        );
        assert.deepEqual(checkResult, {valid: false, reason: 'unresolved'});
      });

      it('is scope-blind: a grant scoped to another service stays valid - check carries no flow and no callback URL', async () => {
        const scopedGrant = {value: 'include actor@issuer.example use=sign scope=other.example', ttl: 1800, dnssec: true};
        const deviceTag = await mintedDeviceTag(zones({includeRecords: [scopedGrant]}));

        const checkResult = await Triauth.check({identifier: 'john@example.org', deviceTag}, {resolver: zones({includeRecords: [scopedGrant]})});
        assert.equal(checkResult.valid, true);
      });

      it('SECURITY: reports revoked for a deviceTag pinned to the scope=any grant when the published grant carries a host list - scope folds into the grant tag', async () => {
        const deviceTag = await mintedDeviceTag(zones({includeRecords: [grant]}));
        const scopedGrant = {value: 'include actor@issuer.example use=sign scope=example.com', ttl: 1800, dnssec: true};

        const checkResult = await Triauth.check({identifier: 'john@example.org', deviceTag}, {resolver: zones({includeRecords: [scopedGrant]})});
        assert.deepEqual(checkResult, {valid: false, reason: 'revoked'});
      });

      it('SECURITY: reports revoked for a deviceTag pinned to the scope=any grant when the published grant lacks scope - the record is ignored as a whole', async () => {
        const deviceTag = await mintedDeviceTag(zones({includeRecords: [grant]}));
        const scopelessRecord = {value: 'include actor@issuer.example use=sign', ttl: 1800, dnssec: true};

        const checkResult = await Triauth.check({identifier: 'john@example.org', deviceTag}, {resolver: zones({includeRecords: [scopelessRecord]})});
        assert.deepEqual(checkResult, {valid: false, reason: 'revoked'});
      });

      it('reports revoked for malformed composite deviceTags', async () => {
        const resolver = () => zones({includeRecords: [grant]});
        const tag = 'C'.repeat(43);

        for (const malformed of [
          `${tag}:${tag}`,                                  // two segments
          `${tag}:actor@issuer.example:${tag}:${tag}`,      // four segments
          `${tag}:Actor@Issuer.example:${tag}`,             // non-lowercase actor identifier
          `:actor@issuer.example:${tag}`,                   // empty include tag
          `${tag}:actor@issuer.example:`                    // empty actor device tag
        ]) {
          const checkResult = await Triauth.check({identifier: 'john@example.org', deviceTag: malformed}, {resolver: resolver()});
          assert.deepEqual(checkResult, {valid: false, reason: 'revoked'}, malformed);
        }
      });
    });

    it('returns error 404 when config.requireSecure is set and the device keys are not DNSSEC-secure', async () => {
      const identity = identities['john'];
      const device = identity.devices[0];

      const keyRecords = (dnssec) => device.keys.map((key, idx) => ({
        value: `key ${device.deviceName}[${idx + 1}/${device.keys.length}]:${key.public} type=es256`,
        ttl: 1800,
        dnssec
      }));

      for (const secure of [true, false]) {
        const resolver = new DnsResolverStub({
          'triauthdemo.org': {TXT: ['triauth auth.triauthdemo.org mode=public']},
          'john._at.triauthdemo.org': {TXT: keyRecords(secure)}
        });

        // Default (requireSecure off): valid regardless of `secure`.
        const def = await Triauth.check({identifier: identity.identifier, deviceTag: device.deviceTag}, {resolver});
        assert.equal(def.valid, true);
        assert(!('checked' in def));
        assert.equal(def.secure, secure);

        // requireSecure on: DNSSEC-secure keys stay valid; non-secure keys are rejected with 404.
        const strict = await Triauth.check({identifier: identity.identifier, deviceTag: device.deviceTag}, {resolver, requireSecure: true});
        if (secure) {
          assert.equal(strict.valid, true);
          assert.equal(strict.secure, true);
        } else {
          assert(!('valid' in strict), 'non-DNSSEC check must not return a valid verdict under requireSecure');
          assert.equal(strict.error.code, 404);
          assert.equal(strict.error.message, 'Your domain does not support DNSSEC, which is required to continue.');
        }
      }
    });

    it('does not gate the revoked (valid:false) path on requireSecure', async () => {
      // Keys exist but the queried deviceTag does not match -> {valid:false}; requireSecure must not turn this into 404.
      const identity = identities['john'];
      const device = identity.devices[0];
      const resolver = new DnsResolverStub({
        'triauthdemo.org': {TXT: ['triauth auth.triauthdemo.org mode=public']},
        'john._at.triauthdemo.org': {TXT: device.keys.map((key, idx) => `key ${device.deviceName}[${idx + 1}/${device.keys.length}]:${key.public} type=es256`)}
      });

      const res = await Triauth.check({identifier: identity.identifier, deviceTag: 'nonexistent-device-tag'}, {resolver, requireSecure: true});
      assert.equal(res.valid, false);
      assert.equal(res.reason, 'revoked');
      assert(!res.error, 'revoked path must not surface an error under requireSecure');
    });

  });
});
