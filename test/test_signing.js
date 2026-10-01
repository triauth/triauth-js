import SignerStub from './stubs/signer.js';
import DnsResolverStub from './stubs/dns_resolver.js';
import identities from './fixtures/identities.json' with { type: 'json' };
import identifiersFixture from './fixtures/identifiers.json' with { type: 'json' };

describe('Signing API', () => {

  describe('Triauth.sign', () => {

    it('builds a challenge for an identifier that publishes no records - existence is settled at stage 3', async () => {
      const signRes = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier:'john-missing@triauthdemo.org', callbackUrl:'http://localhost/', message:'Test'}));

      assert(!signRes.error);
      assert(signRes.challenge);
    });

    describe('accepts identifier, callbackUrl, message, and token to produce challenge and redirectUrl', () => {

      const identifier = 'john@triauthdemo.org';
      const callbackUrl = 'https://example.com/';
      const message = 'Please sign this';
      const token = ':' + 'a'.repeat(16);
      const attachments = [{
        name: 'License.txt',
        sourceUrl: 'https://example.com/license.txt',
        sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
      }];

      it('returns challenge and a correct redirectUrl for valid input', async () => {
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token}));
        assert(typeof signRes.challenge === 'string' && signRes.challenge.length > 0);
        assert(typeof signRes.redirectUrl === 'string' && signRes.redirectUrl.length > 0);
      });

      it('encodes type, identifier, callbackUrl, and message in the challenge', async () => {
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token}));
        const challengeRequest = Triauth.Challenge.fromString(signRes.challenge);

        assert.equal(challengeRequest.data.type, 'sign');
        assert.equal(challengeRequest.data.identifier, identifier);
        assert.equal(challengeRequest.data.cburl, callbackUrl);
        assert.equal(challengeRequest.data.msg, message);
        assert.equal(challengeRequest.data.ver, 1);
      });

      it('encodes a message with non-latin-1 characters in the challenge', async () => {
        // Regression: btoa()-based encoding used to throw on chars > U+00FF and surface as 100 Internal error
        const message = 'Привет, мир';
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token}));

        assert(!signRes.error, JSON.stringify(signRes.error));
        const challengeRequest = Triauth.Challenge.fromString(signRes.challenge);
        assert.equal(challengeRequest.data.msg, message);
      });

      it('includes the token and its hmac in redirectUrl when token is provided', async () => {
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token}));
        assert(signRes.redirectUrl.indexOf('token=') >= 0);
        assert(signRes.redirectUrl.indexOf('hmac=') < 0);
      });

      it('rejects a token-less request with 226 - sign is a token-gated flow', async () => {
        const signRes = (await Triauth.sign({identifier, callbackUrl, message}));
        assert.equal(signRes?.error?.code, 226);
      });

      it('accepts optional attachments and encodes them in the challenge', async () => {
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token, attachments}));
        const challengeRequest = Triauth.Challenge.fromString(signRes.challenge);

        assert.deepEqual(challengeRequest.data.attachments, attachments);
      });

      it('generates random and unique challenges for each call', async () => {
        const challenges = [];

        for (let i = 1; i <= 3; i++) {
          challenges.push((await Triauth.sign({identifier, callbackUrl, message, token})).challenge);
        }

        assert.equal((new Set(challenges)).size, challenges.length);
      });

      it('returns {error:{code:227}} for invalid messages', async () => {
        const invalidMessages = [123, null, '', 'has \n newline', 'has \x00 NUL', 'a'.repeat(2050)];
        for (const invalidMessage of invalidMessages) {
          const signRes = (await Triauth.sign({identifier, callbackUrl, message: invalidMessage, token}));
          assert(!signRes?.signed);
          assert.equal(signRes.error.code, 227);
        }
      });

      it('accepts messages up to messageBytesize (regression: must not be capped at the 255-byte isNormalString default)', async () => {
        // messageBytesize is 2048; isNormalString's default cap must not silently shadow it.
        for (const n of [256, 1024, 2048]) {
          const signRes = (await Triauth.sign({identifier, callbackUrl, message: 'a'.repeat(n), token}));
          assert(signRes?.challenge, `a ${n}-byte message must be accepted`);
          assert(!signRes.error, `a ${n}-byte message must not be rejected`);
        }
      });

      it('returns {error:{code:228}} for malformed attachments', async () => {
        const base = attachments[0];
        const invalidAttachmentSets = [
          'not-an-array',
          [{name: base.name, sourceUrl: base.sourceUrl}],                                    // missing sha256
          [{name: base.name, sourceUrl: base.sourceUrl, sha256: 'not-hex'}],                 // malformed sha256
          [{name: base.name, sourceUrl: 'https://[::1]/file.txt', sha256: base.sha256}],           // IPv6-literal host (out of grammar)
          [{name: base.name, sourceUrl: 'https://user:pass@example.com/file', sha256: base.sha256}], // credentials
          [base, base],                                                                       // duplicate name
          [{name: base.name, sourceUrl: base.sourceUrl, sha256: base.sha256, extra: 'x'}]    // extra property
        ];
        for (const invalidAttachments of invalidAttachmentSets) {
          const signRes = (await Triauth.sign({identifier, callbackUrl, message, token, attachments: invalidAttachments}));
          assert(!signRes?.signed);
          assert.equal(signRes.error.code, 228);
        }
      });

      it('returns {error:{code:228}} for more than attachmentsCount (10) attachments, while accepting exactly 10', async () => {
        // The explicit count cap (LIMITS.attachmentsCount = 10) is a gate distinct from the
        // challengeBytesize byte cap exercised below: these entries are tiny, so the 11th must
        // surface as 228 (too many), not 223 (too big).
        const make = (n) => Array.from({length: n}, (_, i) => ({
          name: `file-${i}`,
          sourceUrl: `https://example.com/f${i}.txt`,
          sha256: '0'.repeat(64)
        }));

        const tenRes = (await Triauth.sign({identifier, callbackUrl, message, token, attachments: make(10)}));
        assert(tenRes?.challenge, 'exactly 10 attachments must be accepted');
        assert(!tenRes.error, 'exactly 10 attachments must not be rejected');

        const elevenRes = (await Triauth.sign({identifier, callbackUrl, message, token, attachments: make(11)}));
        assert(!elevenRes?.signed);
        assert.equal(elevenRes.error.code, 228);
      });

      it('returns {error:{code:223}} when the assembled challenge exceeds challengeBytesize (fails early, before DNS)', async () => {
        // Every input is individually valid, but enough max-length attachment sourceUrls push the
        // serialized challenge past LIMITS.challengeBytesize — the stage-1 guard surfaces this as 223.
        const bigAttachments = Array.from({length: 8}, (_, i) => ({
          name: `file-${i}`,
          sourceUrl: 'https://example.com/' + 'a'.repeat(2000),
          sha256: '0'.repeat(64)
        }));
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token, attachments: bigAttachments}));
        assert(!signRes?.signed);
        assert.equal(signRes.error.code, 223);
      });

      it('returns validation error for invalid identifiers', async () => {
        const {invalidIdentifiers} = identifiersFixture;
        for (const invalidIdentifier in invalidIdentifiers) {
          const signRes = (await Triauth.sign({identifier: invalidIdentifier, callbackUrl, message, token}));
          assert(!signRes?.signed, invalidIdentifier);
          assert(signRes.error.code >= 210 && signRes.error.code < 220, invalidIdentifier);
        }
      });

      it('returns {error:{code:221}} for invalid callbackUrls', async () => {
        const invalidUrls = ['=', '', 'https://[::1]/' + 'a'.repeat(1100)];

        for (const invalidUrl of invalidUrls) {
          const signRes = (await Triauth.sign({identifier, callbackUrl: invalidUrl, message, token}));
          assert(!signRes?.signed);
          assert.equal(signRes.error.code, 221);
        }
      });

      it('returns {error:{code:102}} for unrecognized options', async () => {
        const signRes = (await Triauth.sign({identifier, callbackUrl, message, token, unknownKey: 1}));
        assert(!signRes?.signed);
        assert.equal(signRes.error.code, 102);
      });

      it('returns {error:{code:226}} for invalid tokens', async () => {
        const invalidTokens = ['short', 123, '', 'a'.repeat(257)];
        for (const invalidToken of invalidTokens) {
          const signRes = (await Triauth.sign({identifier, callbackUrl, message, token: invalidToken}));
          assert(!signRes?.signed);
          assert.equal(signRes.error.code, 226);
        }
      });
    });

    describe('accepts challenge and response to produce signing result', () => {

      it('correctly sets the signed status (no attachments)', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Please sign this';

        for (const identity of Object.values(identities)) {
          const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;

          for (const device of identity.devices) {
            const response = await Triauth.Signature.generate(
              SignerStub.signUsingDeviceKeys(device.keys),
              'sign',
              identity.identifier, '',
              callbackUrl,
              message
            );

            const signRes = (await Triauth.sign({challenge, response}));

            assert.equal(signRes.signed, true);
            assert(typeof signRes.result === 'string' && signRes.result.startsWith('|') && signRes.result.endsWith('|'));
            assert.equal(signRes.verificationResult.valid, true);
            assert.equal(signRes.verificationResult.type, 'sign');
            assert.equal(signRes.verificationResult.identifier, identity.identifier);
            assert.equal(signRes.verificationResult.via, callbackUrl);
            assert.equal(signRes.verificationResult.deviceName, device.deviceName);
          }
        }
      });

      it('correctly handles signatures with attachments', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Sign with attachment';
        const attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message, attachments})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message,
          {attachments}
        );

        const signRes = (await Triauth.sign({challenge, response}));
        assert.equal(signRes.signed, true);
        assert.deepEqual(signRes.verificationResult.signedMetadata.attachments, attachments);

        // Milestone timeline at the top level; top-level signedAt mirrors the nested verificationResult.
        assert(signRes.issuedAt <= signRes.signedAt && signRes.signedAt <= signRes.verifiedAt);
        assert.equal(signRes.signedAt, signRes.verificationResult.signedAt);
      });

      it('produced signature is independently verifiable with Triauth.verify', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Independently verifiable';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const signRes = await Triauth.sign({challenge, response});
        assert.equal(signRes.signed, true);

        const verifyRes = await Triauth.verify(message, signRes.result);
        assert.equal(verifyRes.valid, true);
        assert.equal(verifyRes.type, 'sign');
        assert.equal(verifyRes.identifier, identity.identifier);

        const verifyTampered = await Triauth.verify(message + ' (tampered)', signRes.result);
        assert.equal(verifyTampered.valid, false);
      });

      it('honors config.requireSecure: a non-DNSSEC signature is rejected with error 404', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'requireSecure check';

        const identity = identities['john'];
        const device = identity.devices[0];

        const signature = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

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

          // Default (requireSecure off): verifies regardless of `secure`.
          const verifyDefault = await Triauth.verify(message, signature, {}, {resolver});
          assert.equal(verifyDefault.valid, true, `default config must verify (secure:${secure})`);
          assert.equal(verifyDefault.secure, secure);

          // requireSecure on: a DNSSEC-secure signature still verifies; a non-secure one is rejected with 404.
          const verifyStrict = await Triauth.verify(message, signature, {}, {resolver, requireSecure: true});
          if (secure) {
            assert.equal(verifyStrict.valid, true, 'DNSSEC-secure signature must still verify under requireSecure');
            assert.equal(verifyStrict.secure, true);
          } else {
            assert.notEqual(verifyStrict.valid, true, 'non-DNSSEC signature must not verify under requireSecure');
            assert.equal(verifyStrict.error.code, 404);
          }
        }
      });

      it('rejects response with attachments when challenge requested none', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'No attachments expected';
        const sneakyAttachments = [{
          name: 'sneaky.txt',
          sourceUrl: 'https://example.com/sneaky.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message,
          {attachments: sneakyAttachments}
        );

        const signRes = (await Triauth.sign({challenge, response}));
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('rejects response missing attachments when challenge requested some', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Attachments expected';
        const attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message, attachments})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const signRes = (await Triauth.sign({challenge, response}));
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('rejects response with attachment sha256 differing from challenge', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Mismatched sha';
        const attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message, attachments})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message,
          {attachments: [{name: 'License.txt', sourceUrl: attachments[0].sourceUrl, sha256: '0'.repeat(64)}]}
        );

        const signRes = (await Triauth.sign({challenge, response}));
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('rejects response with mismatched attachment name', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Mismatched name';
        const attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message, attachments})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message,
          {attachments: [{name: 'Other.txt', sourceUrl: attachments[0].sourceUrl, sha256: attachments[0].sha256}]}
        );

        const signRes = (await Triauth.sign({challenge, response}));
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('rejects mismatched embedded challenge `type`', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Type tamper';

        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.type = 'stamp';
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const signRes = (await Triauth.sign({challenge: modifiedChallenge, response}));
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('rejects mismatched envelope `type`', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Envelope tamper';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const signRes = (await Triauth.sign({challenge, response}));
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('verifies identifier, if passed, is the same as in challenge', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Cross-check identifier';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        let signRes = await Triauth.sign({identifier: identity.identifier, challenge, response});
        assert.equal(signRes.signed, true);

        signRes = await Triauth.sign({identifier: 'other-user@example.com', challenge, response});
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('verifies callbackUrl, if passed, is the same as in challenge', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Cross-check callbackUrl';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        let signRes = await Triauth.sign({challenge, response, callbackUrl});
        assert.equal(signRes.signed, true);

        signRes = await Triauth.sign({challenge, response, callbackUrl: 'https://other-domain.com/'});
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 401);
      });

      it('honors per-call signTimeout override', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'Timeout override';
        const defaultTimeout = Triauth.config.signTimeout;

        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.sign({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.iat = Date.now() - (defaultTimeout + 10e3);
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        let signRes = await Triauth.sign({challenge: modifiedChallenge, response});
        assert(!signRes.signed);
        assert.equal(signRes.error.code, 402);

        signRes = await Triauth.sign(
          {challenge: modifiedChallenge, response},
          {signTimeout: defaultTimeout * 2 + 60e3}
        );
        assert.equal(signRes.signed, true);
      });

      it('does not sign invalid challenges or responses', (done) => {
        const validChallenge = 'eyJ0eXBlIjoic2lnbiIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoid3RyNkpWWEZVWkpCSlVMdGkzYVlabzVBIiwiaWF0IjoxNzM3NzExMDQ1NDY1LCJ2ZXIiOjF9';
        const validResponse = '|sign;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|';
        const promises = [];

        for (const invalidChallenge of [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ']) {
          promises.push(
            Triauth.sign({challenge: invalidChallenge, response: validResponse}).then((r) => assert(!r?.signed)).catch(() => assert(false))
          );
        }
        for (const invalidResponse of [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ']) {
          promises.push(
            Triauth.sign({challenge: validChallenge, response: invalidResponse}).then((r) => assert(!r?.signed)).catch(() => assert(false))
          );
        }

        Promise.allSettled(promises).then(() => done());
      });
    });

  });

  describe('Triauth.stamp', () => {

    describe('accepts identifier, callbackUrl, message, and token to produce challenge and redirectUrl', () => {

      const identifier = 'john@triauthdemo.org';
      const callbackUrl = 'https://example.com/';
      const message = 'example-data-in-textual-format';
      const token = ':' + 'a'.repeat(16);

      it('returns challenge and a correct redirectUrl for valid input', async () => {
        const stampRes = (await Triauth.stamp({identifier, callbackUrl, message, token}));
        assert(typeof stampRes.challenge === 'string' && stampRes.challenge.length > 0);
        assert(typeof stampRes.redirectUrl === 'string' && stampRes.redirectUrl.length > 0);
      });

      it('encodes type, identifier, callbackUrl, and message in the challenge', async () => {
        const stampRes = (await Triauth.stamp({identifier, callbackUrl, message, token}));
        const challengeRequest = Triauth.Challenge.fromString(stampRes.challenge);

        assert.equal(challengeRequest.data.type, 'stamp');
        assert.equal(challengeRequest.data.identifier, identifier);
        assert.equal(challengeRequest.data.cburl, callbackUrl);
        assert.equal(challengeRequest.data.msg, message);
      });

      it('includes the token and its hmac in redirectUrl when token is provided', async () => {
        const stampRes = (await Triauth.stamp({identifier, callbackUrl, message, token}));
        assert(stampRes.redirectUrl.indexOf('token=') >= 0);
        assert(stampRes.redirectUrl.indexOf('hmac=') < 0);
      });

      it('rejects a token-less request with 226 - stamp is a token-gated flow', async () => {
        const stampRes = (await Triauth.stamp({identifier, callbackUrl, message}));
        assert.equal(stampRes?.error?.code, 226);
      });

      it('rejects the attachments option even when otherwise valid', async () => {
        const attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];
        const stampRes = (await Triauth.stamp({identifier, callbackUrl, message, token, attachments}));
        assert(!stampRes?.stamped);
        assert.equal(stampRes.error.code, 102);
      });

      it('returns {error:{code:227}} for invalid messages', async () => {
        const invalidMessages = [123, null, '', 'has \n newline', 'a'.repeat(2050)];
        for (const invalidMessage of invalidMessages) {
          const stampRes = (await Triauth.stamp({identifier, callbackUrl, message: invalidMessage, token}));
          assert(!stampRes?.stamped);
          assert.equal(stampRes.error.code, 227);
        }
      });

      it('returns {error:{code:226}} for invalid tokens', async () => {
        const invalidTokens = ['short', 123, '', 'a'.repeat(257)];
        for (const invalidToken of invalidTokens) {
          const stampRes = (await Triauth.stamp({identifier, callbackUrl, message, token: invalidToken}));
          assert(!stampRes?.stamped);
          assert.equal(stampRes.error.code, 226);
        }
      });

      it('returns {error:{code:102}} for unrecognized options', async () => {
        const stampRes = (await Triauth.stamp({identifier, callbackUrl, message, token, unknownKey: 1}));
        assert(!stampRes?.stamped);
        assert.equal(stampRes.error.code, 102);
      });
    });

    describe('accepts challenge and response to produce stamping result', () => {

      it('correctly sets the stamped status', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'example-data-in-textual-format';

        for (const identity of Object.values(identities)) {
          const challenge = (await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;

          for (const device of identity.devices) {
            const response = await Triauth.Signature.generate(
              SignerStub.signUsingDeviceKeys(device.keys),
              'stamp',
              identity.identifier, '',
              callbackUrl,
              message
            );

            const stampRes = (await Triauth.stamp({challenge, response}));

            assert.equal(stampRes.stamped, true);
            assert(typeof stampRes.result === 'string' && stampRes.result.startsWith('|') && stampRes.result.endsWith('|'));
            assert.equal(stampRes.verificationResult.valid, true);
            assert.equal(stampRes.verificationResult.type, 'stamp');
            assert.equal(stampRes.verificationResult.identifier, identity.identifier);
            assert.equal(stampRes.verificationResult.via, callbackUrl);
            assert.equal(stampRes.verificationResult.deviceName, device.deviceName);
            assert.equal(stampRes.verificationResult.secure, true);

            assert(stampRes.issuedAt <= stampRes.signedAt && stampRes.signedAt <= stampRes.verifiedAt);
            assert.equal(stampRes.signedAt, stampRes.verificationResult.signedAt);
          }
        }
      });

      it('produced stamp is independently verifiable with Triauth.verify', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'example-data-in-textual-format';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const stampRes = await Triauth.stamp({challenge, response});
        assert.equal(stampRes.stamped, true);

        const verifyRes = await Triauth.verify(message, stampRes.result);
        assert.equal(verifyRes.valid, true);
        assert.equal(verifyRes.type, 'stamp');
        assert.equal(verifyRes.identifier, identity.identifier);
      });

      it('rejects stamp response that carries signedMetadata.attachments', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'stamp with attachments not allowed';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message,
          {attachments: [{name: 'sneaky.txt', sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'}]}
        );

        const stampRes = (await Triauth.stamp({challenge, response}));
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 401);
      });

      it('rejects responses whose envelope `type` is `sign`', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'envelope mismatch';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'sign',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const stampRes = (await Triauth.stamp({challenge, response}));
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 401);
      });

      it('rejects challenges whose embedded `type` was tampered to `sign`', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'embedded mismatch';

        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.type = 'sign';
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const stampRes = (await Triauth.stamp({challenge: modifiedChallenge, response}));
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 401);
      });

      it('does not stamp expired challenges', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'expired';

        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.iat = Date.now() - (Triauth.config.stampTimeout + 10e3);
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const stampRes = await Triauth.stamp({challenge: modifiedChallenge, response});
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 402);
      });

      it('verifies identifier, if passed, is the same as in challenge', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'cross-check identifier';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        let stampRes = await Triauth.stamp({identifier: identity.identifier, challenge, response});
        assert.equal(stampRes.stamped, true);

        stampRes = await Triauth.stamp({identifier: 'other-user@example.com', challenge, response});
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 401);
      });

      it('verifies callbackUrl, if passed, is the same as in challenge', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'cross-check callbackUrl';

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message})).challenge;
        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        let stampRes = await Triauth.stamp({challenge, response, callbackUrl});
        assert.equal(stampRes.stamped, true);

        stampRes = await Triauth.stamp({challenge, response, callbackUrl: 'https://other-domain.com/'});
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 401);
      });

      it('rejects stamp challenge that has attachments injected into challenge.data', async () => {
        const callbackUrl = 'https://example.com/';
        const message = 'tampered-challenge-test';

        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.stamp({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, message});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.attachments = [{
          name: 'sneaky.txt',
          sourceUrl: 'https://example.com/sneaky.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }];
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'stamp',
          identity.identifier, '',
          callbackUrl,
          message
        );

        const stampRes = await Triauth.stamp({challenge: modifiedChallenge, response});
        assert(!stampRes.stamped);
        assert.equal(stampRes.error.code, 102);
      });
    });
  });

  describe('Triauth.verify', () => {
    const message = 'Test';
    const v1Signature = '|stamp;john@triauthdemo.org;;http://localhost:8080/playground/;v1;1778004366970;;;_KUn9Z_qAp_MmSfYx2tIHIdeBWnumtVH8K053Tpxch7dbAwgrh8GysgxVPrUhJco9HJnFA3j-_T5mf5PEXANOw|';

    it('is able to verify v1 signatures', async () => {
      const verifyRes = (await Triauth.verify(message, v1Signature));

      assert.equal(verifyRes.valid, true);
      assert.equal(verifyRes.type, 'stamp');
      assert.equal(verifyRes.identifier, 'john@triauthdemo.org');
      assert.equal(verifyRes.via, 'http://localhost:8080/playground/');
      assert.equal(verifyRes.ver, 1);
      assert.equal(verifyRes.signedAt, 1778004366970);
      assert(typeof verifyRes.verifiedAt === 'number' && verifyRes.verifiedAt >= verifyRes.signedAt);
      assert(!('issuedAt' in verifyRes)); // verify has no challenge, so no issuedAt milestone
    });

    it('returns {valid:false} when signature is invalid or does not meet the constraints', async () => {
      let verifyRes;

      // A valid signature acts as a baseline for next tests
      const validMessage = message + '';
      const validSignature = v1Signature + '';

      verifyRes = (await Triauth.verify(validMessage, validSignature));
      assert.equal(verifyRes.valid, true); // baseline

      // A modified message should not validate
      verifyRes = (await Triauth.verify(validMessage + ' ', validSignature));
      assert.equal(verifyRes.valid, false);

      // A modified signature should not validate
      verifyRes = (await Triauth.verify(validMessage, validSignature.replace('E', 'A')));
      assert.equal(verifyRes.valid, false);

      // A signature with invalid syntax should not validate
      const invalidSignatures = [validSignature.replace('@', '-'), '', "\n", ' ', '//'];
      for (const invalidSignature of invalidSignatures) {
        verifyRes = (await Triauth.verify(validMessage, invalidSignature));
        assert.equal(verifyRes.valid, false);
        assert.equal(verifyRes.reason, 'malformed');
        assert.ok(!('verified' in verifyRes));
      }

      // Constraints should be taken into account
      verifyRes = (await Triauth.verify(validMessage, validSignature, {identifier:'john@triauthdemo.org'}));
      assert.equal(verifyRes.valid, true);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {identifier:'-'}));
      assert.equal(verifyRes.valid, false);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {ver:1}));
      assert.equal(verifyRes.valid, true);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {ver:2}));
      assert.equal(verifyRes.valid, false);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {type:'stamp'}));
      assert.equal(verifyRes.valid, true);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {type:'sign'}));
      assert.equal(verifyRes.valid, false);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {notBefore:1778004366970}));
      assert.equal(verifyRes.valid, true);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {notBefore:1778004366970 + 1}));
      assert.equal(verifyRes.valid, false);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {notAfter:1778004366970}));
      assert.equal(verifyRes.valid, true);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {notAfter:1778004366970 - 1}));
      assert.equal(verifyRes.valid, false);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {via:'http://localhost:8080/playground/'}));
      assert.equal(verifyRes.valid, true);

      verifyRes = (await Triauth.verify(validMessage, validSignature, {via:'-'}));
      assert.equal(verifyRes.valid, false);
    });

    it('returns {valid:false} when identity does not exist', async () => {
      let verifyRes;

      verifyRes = (await Triauth.verify('Lorem ipsum', '|john@example.invalid;v1;sig;-;1772111038143;kZkVpe-QzTIdn9IyjqDI9ram8AJblrg5AW7T1lo6Xoeiah1NgiUEQPQ3JZyDv8YhoHPkWgV0Qeb7vjW9BB6a4g|'));
      assert.equal(verifyRes.valid, false, 'Valid should be null for identifiers using unconfigured domains');

      verifyRes = (await Triauth.verify('Lorem ipsum', '|not-existing@triauthdemo.org;v1;sig;-;1772111038143;kZkVpe-QzTIdn9IyjqDI9ram8AJblrg5AW7T1lo6Xoeiah1NgiUEQPQ3JZyDv8YhoHPkWgV0Qeb7vjW9BB6a4g|'));
      assert.equal(verifyRes.valid, false, 'Valid should be null for identifiers with no identity records in the DNS');

      verifyRes = (await Triauth.verify('Dolor sit', [1]));
      assert.equal(verifyRes.valid, undefined, 'Valid should be undefined when invalid arguments are passed to the function');
      assert.equal(verifyRes.error.code, 101);
    });

    it('returns a multi-signature envelope when the input has more than one signature', async () => {
      // The verify implementation returns the verifyResult itself (with `type:'multisig'`
      // and a `signatures` array) only when signatures.length > 1; for a single signature
      // it returns that signature's shape directly. Build a 2-signature envelope so the
      // multi-signature branch in src/api/signing.js:verify is exercised. Verifying a
      // multi-signature requires opting in with maxSignatures (>= the segment count); by
      // default verify rejects multi-signature envelopes (covered by the test below).
      const identity = identities['john'];
      const device = identity.devices[0];
      const via = 'https://example.com/';
      const message = 'multi-sig-verify-test';

      const sigA = await Triauth.Signature.generate(
        SignerStub.signUsingDeviceKeys(device.keys),
        'stamp',
        identity.identifier, '',
        via,
        message
      );
      const sigB = await Triauth.Signature.generate(
        SignerStub.signUsingDeviceKeys(device.keys),
        'stamp',
        identity.identifier, '',
        via,
        message
      );
      const multiSig = Triauth.MultiSignature.generate(sigA, sigB);

      const verifyRes = await Triauth.verify(message, multiSig, {maxSignatures: 2});

      assert.equal(verifyRes.valid, true);
      assert.ok(!('verified' in verifyRes));
      assert.equal(verifyRes.type, 'multisig');
      assert(Array.isArray(verifyRes.signatures));
      assert.equal(verifyRes.signatures.length, 2);
      assert(verifyRes.signatures.every((s) => s.valid && s.type === 'stamp' && s.identifier === identity.identifier));
    });

    it('declines an out-of-policy signature count with {valid:false, reason:\'declined\'}', async () => {
      // A signature-count policy mismatch is reported as {valid:false, reason:'declined'} - no cryptographic verification
      const identity = identities['john'];
      const device = identity.devices[0];
      const via = 'https://example.com/';
      const message = 'multi-sig-default-reject-test';

      const sigA = await Triauth.Signature.generate(SignerStub.signUsingDeviceKeys(device.keys), 'stamp', identity.identifier, '', via, message);
      const sigB = await Triauth.Signature.generate(SignerStub.signUsingDeviceKeys(device.keys), 'stamp', identity.identifier, '', via, message);
      const multiSig = Triauth.MultiSignature.generate(sigA, sigB);

      // Default maxSignatures:1, 2-segment envelope -> declined under the count policy.
      const verifyRes = await Triauth.verify(message, multiSig);
      assert.equal(verifyRes.valid, false);
      assert.equal(verifyRes.reason, 'declined');
      assert.notEqual(verifyRes.type, 'multisig');

      // minSignatures alone does not raise the default cap, so it is still declined.
      const minOnly = await Triauth.verify(message, multiSig, {minSignatures: 2});
      assert.equal(minOnly.valid, false);
      assert.equal(minOnly.reason, 'declined');

      // Explicit maxSignatures below the segment count -> also a count-policy decline.
      const overMax = await Triauth.verify(message, multiSig, {maxSignatures: 1});
      assert.equal(overMax.valid, false);
      assert.equal(overMax.reason, 'declined');

      // minSignatures floor not met (even with a sufficient maxSignatures) -> count-policy decline.
      const underMin = await Triauth.verify(message, multiSig, {minSignatures: 3, maxSignatures: 5});
      assert.equal(underMin.valid, false);
      assert.equal(underMin.reason, 'declined');

      // An explicit maxSignatures:0 is a real (zero) bound, not "unset": every envelope has >=1 segment,
      // so it is a count-policy decline -> {valid:false, reason:'declined'} (regression guard for the falsy-0 bug).
      const zeroMax = await Triauth.verify(message, multiSig, {maxSignatures: 0});
      assert.equal(zeroMax.valid, false);
      assert.equal(zeroMax.reason, 'declined');

      // A malformed (non-numeric or NaN) bound is a caller argument error -> {error:{code:101}}, surfaced
      // before any cryptographic work (louder than silently failing the signature closed).
      const nonNumeric = await Triauth.verify(message, multiSig, {maxSignatures: '1'});
      assert.equal(nonNumeric.error.code, 101);
      const nanBound = await Triauth.verify(message, multiSig, {minSignatures: NaN});
      assert.equal(nanBound.error.code, 101);

      // Raising maxSignatures to the segment count is what enables multi-signature verification.
      const optedIn = await Triauth.verify(message, multiSig, {maxSignatures: 2});
      assert.equal(optedIn.valid, true);
      assert.ok(!('verified' in optedIn));
      assert.equal(optedIn.type, 'multisig');
    });

  });
});
