export default function() { describe('Verifiers', () => {

  describe('Triauth.Verifiers.Base', () => {

    // Triauth.Verifiers.Base carries the contract that every verifier implements, and no
    // implementation of its own: a registered class that leaves either member unimplemented
    // names itself in the error, rather than failing as a missing property at the call site.

    it('rejects the abstract fromPublishableKey - a subclass must implement it', async () => {
      await assert.rejects(
        Triauth.Verifiers.Base.fromPublishableKey('BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8'),
        /Triauth\.Verifiers\.Base\.fromPublishableKey is abstract and must be implemented by a subclass/
      );
    });

    it('rejects the abstract verify - a subclass must implement it', async () => {
      await assert.rejects(
        new Triauth.Verifiers.Base().verify('message', 'signature', {}, {}),
        /Triauth\.Verifiers\.Base#verify is abstract and must be implemented by a subclass/
      );
    });

  });

}); }
