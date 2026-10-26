import identifiersFixture from './fixtures/identifiers.json' with { type: 'json' };

describe('Validation API', () => {

  describe('Triauth.validate', () => {

    it('returns {valid:false, errors} for invalid identifiers', async () => {
      const {invalidIdentifiers} = identifiersFixture;
      const results = [];
      for (const invalidIdentifier in invalidIdentifiers) {
        const errorMsg = invalidIdentifiers[invalidIdentifier];
        const validationRes = (await Triauth.validate({identifier:invalidIdentifier}));
        results.push(assert.equal(validationRes.valid, false));
        results.push(assert(validationRes.errors.length > 0));
      }
      return results;
    });

    it('returns {valid:true} and no errors for valid identifiers', async () => {
      const {validIdentifiers} = identifiersFixture;
      const results = [];
      for (const identifier of validIdentifiers) {
        const validationRes = (await Triauth.validate({identifier}));
        results.push(assert.equal(validationRes.valid, true));
        results.push(assert.equal(validationRes.errors.length, 0));
      }
    });

    it('returns {valid:false, errors} for invalid device names', async () => {
      const invalidDeviceNames = ['a@a', '', 'Device', 'device_12', 'my device', ' device', 'device ', 'thisdevicenameistoolong', '-pc', 'pc-', 'my--pc', '--pc--', 'xn--pc']
      for (const deviceName of invalidDeviceNames) {
        const validationRes = await Triauth.validate({deviceName});
        assert.equal(validationRes.valid, false);
        assert(validationRes.errors.length > 0);
      }
    });

    it('returns {valid:true} and no errors for valid device names', async () => {
      const validDeviceNames = ['laptop', 'laptop-12', 'my-pc-2']
      for (const deviceName of validDeviceNames) {
        const validationRes = await Triauth.validate({deviceName});
        assert.equal(validationRes.valid, true);
        assert.equal(validationRes.errors.length, 0);
      }
    });

    it('rejects an oversized identifier or device name on size alone, before any grammar scan', () => {
      const deviceName = Triauth.validate({deviceName: 'a-'.repeat(4_000_000) + 'a'});
      assert.deepEqual(deviceName.errors.map((e) => [e.code, e.reason]), [['invalid_device_name', 'too_long']]);

      const identifier = Triauth.validate({identifier: 'a-'.repeat(4_000_000) + 'a@example.com'});
      assert.deepEqual(identifier.errors.map((e) => [e.code, e.reason]), [['invalid_identifier', 'too_long']]);
    });

    it('rejects an oversized device tag on length alone, ahead of the split', () => {
      const started = Date.now();

      for (const deviceTag of [':'.repeat(8 * 1024 * 1024), '~'.repeat(8 * 1024 * 1024), 'A'.repeat(243)]) {
        const result = Triauth.validate({deviceTag});
        assert.deepEqual(result.errors.map((e) => [e.code, e.reason]), [['invalid_device_tag', 'invalid']]);
      }

      // Splitting 16 MiB of delimiters takes hundreds of milliseconds and allocates millions of array entries
      assert(Date.now() - started < 200, 'an oversized device tag is rejected ahead of any split');
    });

    it('returns {valid:false, errors:[{code:invalid_arguments}]} for an empty object (nothing to validate)', () => {
      const result = Triauth.validate({});
      assert.equal(result.valid, false);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0].code, 'invalid_arguments');
    });

    it('returns {valid:false, errors:[{code:invalid_arguments}]} when objects is missing or not a plain object', () => {
      for (const objects of [undefined, null, 'john@example.com', 42, true, ['john@example.com']]) {
        const result = Triauth.validate(objects);
        assert.equal(result.valid, false);
        assert.equal(result.errors.length, 1);
        assert.equal(result.errors[0].code, 'invalid_arguments');
      }
    });

    it('returns {valid:false, errors:[{code:invalid_arguments}]} for misspelled or unrecognized keys', () => {
      const misspelled = [
        {identifer: 'john@example.com'},
        {Identifier: 'john@example.com'},
        {devicename: 'laptop'},
        {identifier: 'john@example.com', extra: true}
      ];
      for (const objects of misspelled) {
        const result = Triauth.validate(objects);
        assert.equal(result.valid, false);
        assert.equal(result.errors.length, 1);
        assert.equal(result.errors[0].code, 'invalid_arguments');
      }
    });

    it('returns {valid:false, errors:[{code:invalid_arguments}]} for undefined values', () => {
      const result = Triauth.validate({identifier: undefined});
      assert.equal(result.valid, false);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0].code, 'invalid_arguments');
    });

    it('returns {valid:false, errors} for null and empty values', () => {
      for (const objects of [{identifier: null}, {identifier: ''}, {deviceName: null}, {deviceName: ''}]) {
        const result = Triauth.validate(objects);
        assert.equal(result.valid, false);
        assert(result.errors.length > 0);
        assert(result.errors.every((e) => e.reason !== undefined), 'null/empty values should fail with field validation errors');
      }
    });

    it('returns {valid:true} when both identifier and deviceName are valid', () => {
      const result = Triauth.validate({identifier: 'john@example.com', deviceName: 'laptop'});
      assert.equal(result.valid, true);
      assert.equal(result.errors.length, 0);
    });

    it('accumulates errors from both identifier and deviceName when both are invalid', () => {
      const result = Triauth.validate({identifier: 'bad-no-at-sign', deviceName: 'BAD DEVICE'});
      assert.equal(result.valid, false);
      assert(result.errors.length >= 2, 'should have at least one error per invalid field');
    });

    it('returns {valid:false} with only deviceName errors when identifier is valid', () => {
      const result = Triauth.validate({identifier: 'john@example.com', deviceName: 'BAD DEVICE'});
      assert.equal(result.valid, false);
      assert(result.errors.length > 0);
      assert(result.errors.every((e) => e.code === 'invalid_device_name'), 'errors should be deviceName errors only');
    });

  });
});
