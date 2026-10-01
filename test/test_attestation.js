import SignerStub from './stubs/signer.js';
import identities from './fixtures/identities.json' with { type: 'json' };
import attesters from './fixtures/attesters.json' with { type: 'json' };
import identifiersFixture from './fixtures/identifiers.json' with { type: 'json' };

describe('Attestation API', () => {

  describe('Triauth.attest', () => {

    describe('accepts identifier, callbackUrl, attestations, and token to produce challenge and redirectUrl', () => {

      const identifier = 'john@triauthdemo.org';
      const callbackUrl = 'https://example.com/';
      const token = ':' + 'a'.repeat(16);
      const attestations = {
        'not-a-robot': {
          label: 'I am not a robot',
          providers: ['https://triauthdemo.org/not-a-robot']
        }
      };

      it('returns challenge and a correct redirectUrl for valid input', async () => {
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations, token}));
        assert(typeof attestRes.challenge === 'string' && attestRes.challenge.length > 0);
        assert(typeof attestRes.redirectUrl === 'string' && attestRes.redirectUrl.length > 0);
      });

      it('encodes type, identifier, callbackUrl, and attestations in the challenge', async () => {
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations, token}));
        const challengeRequest = Triauth.Challenge.fromString(attestRes.challenge);

        assert.equal(challengeRequest.data.type, 'attest');
        assert.equal(challengeRequest.data.identifier, identifier);
        assert.equal(challengeRequest.data.cburl, callbackUrl);
        assert.deepEqual(challengeRequest.data.attest, attestations);
      });

      it('includes the token and its hmac in redirectUrl when token is provided', async () => {
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations, token}));
        assert(attestRes.redirectUrl.indexOf('token=') >= 0);
        assert(attestRes.redirectUrl.indexOf('hmac=') < 0);
      });

      it('rejects a token-less request with 226 - attest is a token-gated flow', async () => {
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations}));
        assert.equal(attestRes?.error?.code, 226);
      });

      it('returns validation error for invalid identifiers', async () => {
        const {invalidIdentifiers} = identifiersFixture;
        for (const invalidIdentifier in invalidIdentifiers) {
          const attestRes = (await Triauth.attest({identifier: invalidIdentifier, callbackUrl, attestations, token}));
          assert(!attestRes?.attested, invalidIdentifier);
          assert(attestRes.error.code >= 210 && attestRes.error.code < 220, invalidIdentifier);
        }
      });

      it('returns {error:{code:221}} for invalid callbackUrls', async () => {
        const invalidUrls = ['=', '', 'https://[::1]/' + 'a'.repeat(1100)];

        for (const invalidUrl of invalidUrls) {
          const attestRes = (await Triauth.attest({identifier, callbackUrl: invalidUrl, attestations, token}));
          assert(!attestRes?.attested);
          assert.equal(attestRes.error.code, 221);
        }
      });

      it('returns {error:{code:102}} for unrecognized options', async () => {
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations, token, unknownKey: 1}));
        assert(!attestRes?.attested);
        assert.equal(attestRes.error.code, 102);
      });

      it('returns {error:{code:226}} for invalid tokens', async () => {
        const invalidTokens = ['short', 123, '', 'a'.repeat(257)];
        for (const invalidToken of invalidTokens) {
          const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations, token: invalidToken}));
          assert(!attestRes?.attested);
          assert.equal(attestRes.error.code, 226);
        }
      });

      it('returns {error:{code:229}} when attestations option is null or non-object', async () => {
        for (const invalidAttestations of [null, 'string', 123, []]) {
          const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations: invalidAttestations, token}));
          assert(!attestRes?.attested);
          assert.equal(attestRes.error.code, 229);
        }
      });

      it('returns {error:{code:229}} when an entry has an unknown property', async () => {
        const bad = {'not-a-robot': {label: 'I am not a robot', providers: ['https://triauthdemo.org/p'], extra: 'x'}};
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations: bad, token}));
        assert(!attestRes?.attested);
        assert.equal(attestRes.error.code, 229);
      });

      it('returns {error:{code:229}} when an entry is missing label or providers', async () => {
        const sets = [
          {'a': {providers: ['https://triauthdemo.org/p']}},                          // missing label
          {'a': {label: '', providers: ['https://triauthdemo.org/p']}},               // empty label
          {'a': {label: 'lbl'}},                                                       // missing providers
          {'a': {label: 'lbl', providers: []}}                                         // empty providers
        ];
        for (const bad of sets) {
          const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations: bad, token}));
          assert(!attestRes?.attested);
          assert.equal(attestRes.error.code, 229);
        }
      });

      it('returns {error:{code:229}} when providers list is too long', async () => {
        const tooMany = Array.from({length: Triauth.LIMITS.maxMultiSignatures}, (_, i) => `https://triauthdemo.org/p${i}`);
        const bad = {'a': {label: 'lbl', providers: tooMany}};
        const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations: bad, token}));
        assert(!attestRes?.attested);
        assert.equal(attestRes.error.code, 229);
      });

      it('returns {error:{code:229}} for malformed provider URLs', async () => {
        const sets = [
          'http://insecure.example/p',
          'https://user:pass@example.com/p',
          'https://example.com/p?q=1',
          'https://example.com/p#frag',
          'https://example.com/p%20space',
          'https://xn--example.com/p'
        ];
        for (const badUrl of sets) {
          const bad = {'a': {label: 'lbl', providers: [badUrl]}};
          const attestRes = (await Triauth.attest({identifier, callbackUrl, attestations: bad, token}));
          assert(!attestRes?.attested, badUrl);
          assert.equal(attestRes.error.code, 229, badUrl);
        }
      });
    });

    describe('accepts challenge and response to produce attestation result', () => {

      const callbackUrl = 'https://example.com/';
      const attesterVia = 'https://triauthdemo.org/not-a-robot';
      const attestations = {
        'not-a-robot': {
          label: 'I am not a robot',
          providers: [attesterVia]
        }
      };

      const buildResponse = async (identity, device, challenge, {
        userVia = callbackUrl,
        attesterIdentifier = identity.identifier,
        attesterViaOverride = attesterVia,
        userType = 'attest',
        attesterType = 'attest',
        attesterSignedMetadata = {},
        omitAttester = false
      } = {}) => {
        const overrideMessage = await Triauth.Helpers.sha256(challenge);

        const userSig = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          userType,
          identity.identifier, '',
          userVia,
          overrideMessage
        );

        if (omitAttester) {
          return Triauth.MultiSignature.generate(userSig);
        }

        const attesterSig = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          attesterType,
          attesterIdentifier, '',
          attesterViaOverride,
          overrideMessage,
          attesterSignedMetadata
        );

        return Triauth.MultiSignature.generate(userSig, attesterSig);
      };

      it('correctly sets the attested status (self-attestation)', async () => {
        for (const identity of Object.values(identities)) {
          // The attester via hostname must equal the attester identifier's domain (see
          // src/api/attestation.js:275), so for self-attestation the via uses the user's domain.
          const domain = identity.identifier.split('@')[1];
          const perIdentityVia = `https://${domain}/not-a-robot`;
          const perIdentityAttestations = {
            'not-a-robot': {label: 'I am not a robot', providers: [perIdentityVia]}
          };

          const buildRes = await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations: perIdentityAttestations});
          const challenge = buildRes.challenge;

          for (const device of identity.devices) {
            const response = await buildResponse(identity, device, challenge, {attesterViaOverride: perIdentityVia});

            const attestRes = (await Triauth.attest({challenge, response}));

            assert.equal(attestRes.attested, true);
            assert.equal(attestRes.secure, true);
            assert.equal(attestRes.identifier, identity.identifier);
            assert.equal(attestRes.identityDomain, identity.identityDomain);
            assert.equal(attestRes.actorIdentityDomain, '');
            assert.equal(attestRes.lookupCode, '');
            assert.equal(attestRes.actorLookupCode, '');
            assert.equal(attestRes.deviceName, device.deviceName);
            assert(attestRes.expires > Date.now());
            assert.equal(attestRes.keys.length, device.keys.length);
            assert.equal(attestRes.keys.every((k) => k.verified), true);

            const att = attestRes.attestations['not-a-robot'];
            assert.equal(att.valid, true);
            assert.equal(att.type, 'attest');
            assert.equal(att.identifier, identity.identifier);
            assert.equal(att.via, perIdentityVia);

            // Top-level milestone timeline (signedAt = user's mainSig); nested attester carries its own.
            assert(attestRes.issuedAt <= attestRes.signedAt && attestRes.signedAt <= attestRes.verifiedAt);
            assert(typeof att.signedAt === 'number' && typeof att.verifiedAt === 'number');
            // top-level verifiedAt is the max across all signatures (user + attesters)
            assert(attestRes.verifiedAt >= att.verifiedAt);
          }
        }
      });

      it('allows one attester signature to satisfy multiple attestation IDs', async () => {
        const multiAttestations = {
          'first': {label: 'first', providers: [attesterVia]},
          'second': {label: 'second', providers: [attesterVia]}
        };

        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations: multiAttestations})).challenge;
        const response = await buildResponse(identity, device, challenge);

        const attestRes = (await Triauth.attest({challenge, response}));
        assert.equal(attestRes.attested, true);
        assert.equal(attestRes.attestations.first.valid, true);
        assert.equal(attestRes.attestations.second.valid, true);
      });

      it('accepts attester bind.identifier and bind.via that match the user', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {
          attesterSignedMetadata: {bind: {identifier: identity.identifier, via: callbackUrl}}
        });

        const attestRes = (await Triauth.attest({challenge, response}));
        assert.equal(attestRes.attested, true);
      });

      it('rejects when attester signature is missing entirely', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {omitAttester: true});

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects when attester `via` is not in the requested providers list', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {
          attesterViaOverride: 'https://triauthdemo.org/some-other-attestation'
        });

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it("rejects when attester identifier's domain does not match the attester via hostname", async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        // provider list contains a via under example.com but the attester signs with
        // identifier=john@triauthdemo.org → triauthdemo.org !== example.com → check 2 fails.
        const customAttestations = {
          'not-a-robot': {
            label: 'I am not a robot',
            providers: ['https://example.com/not-a-robot']
          }
        };

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations: customAttestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {
          attesterViaOverride: 'https://example.com/not-a-robot'
        });

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects when attester signature is cryptographically invalid', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const goodResponse = await buildResponse(identity, device, challenge);

        // Flip a character in the attester segment (after the first '|...|' which is the user sig)
        const firstPipe = goodResponse.indexOf('|', 1);
        const secondPipe = goodResponse.indexOf('|', firstPipe + 1);
        const attesterPart = goodResponse.slice(secondPipe);
        // tamper - replace a base64url character inside the attester segment
        const tamperedAttester = attesterPart.replace(/A/, 'B').replace(/^([^B]+)$/, attesterPart.slice(0, -10) + 'AAAAAAAAA' + attesterPart.slice(-1));
        const badResponse = goodResponse.slice(0, secondPipe) + tamperedAttester;

        const attestRes = (await Triauth.attest({challenge, response: badResponse}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects when attester bind.identifier is present and differs from the user identifier', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {
          attesterSignedMetadata: {bind: {identifier: 'someone-else@example.com'}}
        });

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects when attester bind.via is present and differs from the user via', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {
          attesterSignedMetadata: {bind: {via: 'https://wrong.example/'}}
        });

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects challenges whose embedded `type` does not match the attest flow', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.type = 'auth';
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await buildResponse(identity, device, modifiedChallenge);

        const attestRes = (await Triauth.attest({challenge: modifiedChallenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects responses whose envelope `type` is not `attest`', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {userType: 'auth'});

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('rejects when user signature `via` is not a prefix of challenge `cburl`', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const response = await buildResponse(identity, device, challenge, {userVia: 'https://attacker.example/'});

        const attestRes = (await Triauth.attest({challenge, response}));
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('does not attest expired challenges', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];

        const buildRes = await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.iat = Date.now() - (Triauth.config.attestTimeout + 10e3);
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await buildResponse(identity, device, modifiedChallenge);

        const attestRes = await Triauth.attest({challenge: modifiedChallenge, response});
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 402);
      });

      it('honors per-call attestTimeout override', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        const defaultTimeout = Triauth.config.attestTimeout;

        const buildRes = await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations});
        const challengeObj = Triauth.Challenge.fromString(buildRes.challenge);
        challengeObj.data.iat = Date.now() - (defaultTimeout + 10e3);
        const modifiedChallenge = Triauth.Helpers.stringToBase64Url(JSON.stringify(challengeObj.data));

        const response = await buildResponse(identity, device, modifiedChallenge);

        let attestRes = await Triauth.attest({challenge: modifiedChallenge, response});
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 402);

        attestRes = await Triauth.attest(
          {challenge: modifiedChallenge, response},
          {attestTimeout: defaultTimeout * 2 + 60e3}
        );
        assert.equal(attestRes.attested, true);
      });

      it('rejects when the first signature identifier differs from the challenge identity (identifier mismatch guard)', async () => {
        const identity = identities['john'];
        const device = identity.devices[0];
        // The user slot is signed by another identity under its own records: the crypto verifies,
        // and only the identifier comparison against the challenge fails
        const other = attesters['robot'];

        const challenge = (await Triauth.attest({token:':aaaaaaaaaaaaaaaa', identifier: identity.identifier, callbackUrl, attestations})).challenge;
        const signedPayload = await Triauth.Helpers.sha256(challenge);

        const userSig = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(other.devices[0].keys),
          'attest',
          other.identifier, '',
          callbackUrl,
          signedPayload
        );

        const attesterSig = await Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(device.keys),
          'attest',
          identity.identifier, '',
          attesterVia,
          signedPayload
        );

        const response = Triauth.MultiSignature.generate(userSig, attesterSig);
        const attestRes = await Triauth.attest({challenge, response});
        assert(!attestRes.attested);
        assert.equal(attestRes.error.code, 401);
      });

      it('does not attest invalid challenges or responses', (done) => {
        const validChallenge = 'eyJ0eXBlIjoiYXR0ZXN0IiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJ3dHI2SlZYRlVaSkJKVUx0aTNhWVpvNUEiLCJpYXQiOjE3Mzc3MTEwNDU0NjUsInZlciI6MX0';
        const validResponse = '|attest;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|';
        const promises = [];

        for (const invalidChallenge of [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ']) {
          promises.push(
            Triauth.attest({challenge: invalidChallenge, response: validResponse}).then((r) => assert(!r?.attested)).catch(() => assert(false))
          );
        }
        for (const invalidResponse of [void 0, null, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ']) {
          promises.push(
            Triauth.attest({challenge: validChallenge, response: invalidResponse}).then((r) => assert(!r?.attested)).catch(() => assert(false))
          );
        }

        Promise.allSettled(promises).then(() => done());
      });
    });

    describe('third-party attestation with a distinct attester identity', function () {

      const john = identities['john'];
      const robot = attesters['robot'];
      const age = attesters['age'];
      const callbackUrl = 'https://example.com/';
      const userVia = 'https://example.com/'; // Helpers.getBaseUrl(callbackUrl)

      const mkSig = async (challenge, keys, identifier, via, signedMetadata = {}) =>
        Triauth.Signature.generate(
          SignerStub.signUsingDeviceKeys(keys), 'attest', identifier, '', via,
          await Triauth.Helpers.sha256(challenge), signedMetadata);

      const userSig = (challenge, via = userVia) => mkSig(challenge, john.devices[0].keys, john.identifier, via);
      const attesterSig = (challenge, attester, { via, signedMetadata = {} } = {}) =>
        mkSig(challenge, attester.devices[0].keys, attester.identifier, via ?? attester.via, signedMetadata);
      const buildChallenge = (attns) =>
        Triauth.attest({token:':aaaaaaaaaaaaaaaa',  identifier: john.identifier, callbackUrl, attestations: attns }).then((r) => r.challenge);

      const robotAttestations = { 'not-a-robot': { label: 'I am not a robot', providers: [robot.via] } };

      it('verifies an attester signing under its OWN distinct identifier and identity domain', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(await userSig(challenge), await attesterSig(challenge, robot));

        const res = await Triauth.attest({ challenge, response });

        assert.equal(res.attested, true);
        assert.equal(res.identifier, john.identifier);

        const att = res.attestations['not-a-robot'];
        assert.equal(att.valid, true);
        assert.equal(att.type, 'attest');
        assert.equal(att.identifier, robot.identifier);                  // distinct from the user
        assert.notEqual(att.identifier, john.identifier);
        assert.equal(att.via, robot.via);
        assert.equal(att.identityDomain, robot.identityDomain);
        assert.equal(att.actorIdentityDomain, '', 'attester statements are first-party');
        assert.equal(att.lookupCode, '');
        assert.equal(att.actorLookupCode, '');
      });

      it('verifies two DISTINCT attesters satisfying two attestations in one envelope', async () => {
        const attns = {
          'not-a-robot': { label: 'I am not a robot', providers: [robot.via] },
          'over-18':     { label: 'I am over 18',     providers: [age.via] }
        };
        const challenge = await buildChallenge(attns);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot),
          await attesterSig(challenge, age)
        );

        const res = await Triauth.attest({ challenge, response });

        assert.equal(res.attested, true);
        assert.equal(res.attestations['not-a-robot'].identifier, robot.identifier);
        assert.equal(res.attestations['over-18'].identifier, age.identifier);
      });

      it('accepts a distinct attester whose bind.identifier, bind.via, and bind.deviceTag all bind the user', async () => {
        // Learn the user main-sig deviceTag from a plain attestation (avoids hard-coding it).
        const ch0 = await buildChallenge(robotAttestations);
        const base = await Triauth.attest({ challenge: ch0, response: Triauth.MultiSignature.generate(await userSig(ch0), await attesterSig(ch0, robot)) });
        const userTag = base.deviceTag;

        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { identifier: john.identifier, via: userVia, deviceTag: userTag } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert.equal(res.attested, true);
      });

      it('rejects a distinct attester whose bind.deviceTag does NOT match the user deviceTag', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { deviceTag: 'not-the-users-device-tag' } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('rejects a distinct attester whose bind.identifier is present and differs from the user identifier', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { identifier: 'someone-else@example.com' } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('rejects a distinct attester whose bind.via is present and differs from the user via', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { via: 'https://wrong.example/' } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('SECURITY: rejects a distinct attester carrying an UNRECOGNIZED binder inside bind - every member of bind is critical, so a constraint the verifier cannot enforce fails the bundle instead of going unread', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { audience: 'https://somewhere.example/' } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('SECURITY: rejects a malformed bind (empty, an array, or a non-object) - a bind that states nothing is a producer error, not an anonymous attestation', async () => {
        for (const bind of [{}, 'identifier', ['identifier'], null]) {
          const challenge = await buildChallenge(robotAttestations);
          const response = Triauth.MultiSignature.generate(
            await userSig(challenge),
            await attesterSig(challenge, robot, { signedMetadata: { bind } })
          );

          const res = await Triauth.attest({ challenge, response });
          assert(!res.attested, JSON.stringify(bind));
          assert.equal(res.error.code, 401, JSON.stringify(bind));
        }
      });

      it('SECURITY: rejects a bind with one matching and one false binder - ALL stated binders must hold, not just some', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { identifier: john.identifier, via: 'https://wrong.example/' } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('SECURITY: rejects a distinct attester whose bind carries a non-string binder value', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot, { signedMetadata: { bind: { identifier: 123 } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('tolerates unrecognized signedMetadata members outside bind - binders live only in bind, so top-level members (any name, any value) are auxiliary and ignored', async () => {
        for (const signedMetadata of [
          { identifier: john.identifier },
          { sub: 'someone-else@example.com' },
          { tag: 'not-the-users-device-tag' },
          { issuedFor: 'a future member v1 knows nothing about' }
        ]) {
          const challenge = await buildChallenge(robotAttestations);
          const response = Triauth.MultiSignature.generate(
            await userSig(challenge),
            await attesterSig(challenge, robot, { signedMetadata })
          );

          const res = await Triauth.attest({ challenge, response });
          assert.equal(res.attested, true, JSON.stringify(signedMetadata));
        }
      });

      it('accepts a user segment whose bind states its own verified values - bind means the same on every segment of the envelope', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await mkSig(challenge, john.devices[0].keys, john.identifier, userVia, { bind: { identifier: john.identifier, via: userVia } }),
          await attesterSig(challenge, robot)
        );

        const res = await Triauth.attest({ challenge, response });
        assert.equal(res.attested, true);
      });

      it('SECURITY: rejects a user segment whose bind.identifier names someone else - every binder in the envelope must hold', async () => {
        const challenge = await buildChallenge(robotAttestations);
        const response = Triauth.MultiSignature.generate(
          await mkSig(challenge, john.devices[0].keys, john.identifier, userVia, { bind: { identifier: 'someone-else@example.com' } }),
          await attesterSig(challenge, robot)
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });

      it('SECURITY: rejects an envelope carrying a STRAY attester whose binder is false of the user - a false signed binding poisons the whole bundle, even when every requested attestation is satisfied by another segment', async () => {
        const attns = {
          'not-a-robot':   { label: 'I am not a robot',   providers: [robot.via] },
          'still-not-one': { label: 'I am still not one', providers: [robot.via] }
        };
        const challenge = await buildChallenge(attns);
        const response = Triauth.MultiSignature.generate(
          await userSig(challenge),
          await attesterSig(challenge, robot),  // satisfies both attestations (their provider lists overlap)
          await attesterSig(challenge, robot, { signedMetadata: { bind: { identifier: 'someone-else@example.com' } } })
        );

        const res = await Triauth.attest({ challenge, response });
        assert(!res.attested);
        assert.equal(res.error.code, 401);
      });
    });
  });
});
