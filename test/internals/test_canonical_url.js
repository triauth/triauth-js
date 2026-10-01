export default function() { describe('Triauth.Helpers (canonical URLs)', () => {

  // The one accepted spelling of each resource — every entry must pass isCanonicalUrl.
  const CANONICAL = [
    'https://example.com/',
    'https://example.com/cb',
    'https://example.com/app/callback',
    'https://example.com/license.txt',
    'https://example.org/cb',
    'https://other-domain.com/',
    'https://attest.triauthdemo.org/not-a-robot',
    'https://triauthdemo.org/p',
    'http://localhost/',
    'http://localhost:3000/cb',
    'http://localhost:8080/verify',
    'http://localhost:8080/playground/',
    'http://example.com/cb',
    'http://intranet.corp.example/wiki',
    'https://intranet/',
    'https://a.b/',
    'https://1.example.com/',
    'https://a.com:8443/x',
    'https://a.com:80/x',
    'http://a.com:443/x',
    'https://127.0.0.1/',
    'http://192.168.0.14/cb',
    'http://10.0.0.5:8080/cb',
    'https://100.64.7.13:8443/login',
    'https://a.com//double//slash',
    'https://a.com/f%2Fx',
    'https://a.com/%41bc',
    'https://a.com/~tilde/*star/(par)en/pl+us/co:lon/at@sign/eq=uals/do$llar/am&p/co,mma/ex!cl',
    'https://example.com/cb;sid=1',
    'https://example.com/a;b/cb',
    "https://x.com/a'b",
    'https://a.com/?q;x',
    "https://a.com/?q'x",
    'https://example.com/cb?a=1;b=2',
    'https://a.com/#f;x',
    "https://a.com/#f'x",
    'https://example.com/cb?a=b&c=d',
    'https://example.com/cb?X-Amz-Signature=abc',
    'https://example.com/cb#frag',
    'https://example.com/cb?x=1#y',
    'https://example.com/cb#f?x',
    'https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/text/AGPL-3.0-or-later.txt',
    'https://example.com/' + 'a'.repeat(2028) // exactly LIMITS.urlBytesize (2048) bytes
  ];

  // Non-canonical or out-of-grammar spellings — every entry must be rejected.
  const REJECTED = {
    'scheme': [
      'HTTPS://example.com/', 'Https://example.com/', 'HTTP://example.com/', 'ftp://example.com/',
      'wss://example.com/', 'example.com/', '//example.com/', 'https:/example.com/'
    ],
    'host': [
      'https://A.COM/', 'https://Example.com/', 'https://a.com./', 'https://.a.com/', 'https://a..com/',
      'https://_x.a.com/', 'https://-a-.com/', 'https://a-.com/', 'https://-a.com/',
      'https://' + 'a'.repeat(64) + '.com/', 'https://', 'https:///', 'https://:8080/'
    ],
    // an IPv4 host has exactly one grammar spelling — the dotted quad; every other notation is out
    'exotic-ip-spellings': [
      'https://[::1]/', 'https://0x7f.0x1/', 'https://1.2.3.04/', 'https://example.12/',
      'https://2130706433/', 'https://0177.0.0.1/', 'https://a.0x/', 'https://256.1.1.1/',
      'https://1.2.3/', 'https://1.2.3.4.5/', 'https://0x7f.0x0.0x0.0x1/', 'https://010.0.0.1/'
    ],
    'punycode': [
      'https://xn--mller-kva.de/cb', 'https://a.xn--p1ai/', 'https://XN--mller-kva.de/'
    ],
    'port': [
      'https://a.com:443/', 'http://localhost:80/', 'https://a.com:08080/', 'https://a.com:65536/',
      'https://a.com:/', 'https://a.com:8_0/', 'https://a.com:0/'
    ],
    'userinfo': [
      'https://user:pass@example.com/p', 'https://user@example.com/', 'https://@example.com/'
    ],
    // characters outside the RFC 3986 pchar set — the envelope wrapper '|' among them
    'charset': [
      'https://a.com/a|b', 'https://example.com/a|b/cb', 'https://a.com/a[b]c', 'https://a.com/{x}',
      'https://a.com/a\\b', 'https://a.com/a^b', 'https://a.com/a`b', 'https://a.com/"x"',
      'https://a.com/<y>', 'https://a.com/?q|x', 'https://a.com/?q[x]', 'https://a.com/#f|x',
      'https://a.com/#f#g'
    ],
    'dot-segments': [
      'https://a.com/./b', 'https://a.com/../b', 'https://a.com/a/..', 'https://a.com/%2e/b',
      'https://a.com/a/%2e%2E/b', 'https://a.com/.%2E/b', 'https://a.com/%2E%2e/'
    ],
    'structure': [
      'https://example.com', 'https://example.com?x=1', 'https://example.com#f',
      'https://a.com/?', 'https://a.com/#', 'https://a.com/?#'
    ],
    'encoding-and-size': [
      'https://a.com/%zz', 'https://a.com/%2', 'https://a.com/100%', 'https://a.com/é',
      'https://müller.de/', 'https://a.com/a b', 'https://a.com/a\tb', '',
      'https://example.com/' + 'a'.repeat(2029) // one byte over LIMITS.urlBytesize
    ]
  };

  describe('isCanonicalUrl', () => {

    it('accepts the canonical spelling of http(s) URLs, named and IPv4-literal hosts alike', () => {
      for (const url of CANONICAL) {
        assert.equal(Triauth.Helpers.isCanonicalUrl(url), true, url);
      }
    });

    for (const [rule, urls] of Object.entries(REJECTED)) {
      it(`rejects out-of-grammar spellings: ${rule}`, () => {
        for (const url of urls) {
          assert.equal(Triauth.Helpers.isCanonicalUrl(url), false, url);
        }
      });
    }

    it('rejects non-string input', () => {
      for (const value of [123, null, undefined, {}, ['https://example.com/'], true]) {
        assert.equal(Triauth.Helpers.isCanonicalUrl(value), false, String(value));
      }
    });

  });

  describe('isSecureUrl', () => {

    // Secure-origin URLs: https on a named host, or http on the literal localhost. This is the
    // acceptance rule for verbatim trust anchors (attestation provider URLs).
    const SECURE = [
      'https://example.com/', 'https://attest.triauthdemo.org/not-a-robot', 'https://triauthdemo.org/p',
      'https://a.com:8443/x', 'https://intranet/', 'http://localhost/', 'http://localhost:8080/verify'
    ];

    // Canonical, but not secure-origin: http off localhost, or an IP-literal host on any scheme.
    const CANONICAL_NOT_SECURE = [
      'http://example.com/cb', 'http://intranet.corp.example/wiki', 'http://192.168.0.14/cb',
      'http://10.0.0.5:8080/cb', 'https://127.0.0.1/', 'https://100.64.7.13:8443/login'
    ];

    it('accepts canonical https URLs on named hosts, and http on the literal localhost', () => {
      for (const url of SECURE) {
        assert.equal(Triauth.Helpers.isSecureUrl(url), true, url);
      }
    });

    it('rejects canonical URLs that are http off localhost or carry an IP-literal host', () => {
      for (const url of CANONICAL_NOT_SECURE) {
        assert.equal(Triauth.Helpers.isSecureUrl(url), false, url);
        assert.equal(Triauth.Helpers.isCanonicalUrl(url), true, `still canonical: ${url}`);
      }
    });

    it('is a strict narrowing of isCanonicalUrl: never accepts what the grammar rejects', () => {
      for (const url of [...CANONICAL, ...Object.values(REJECTED).flat(), 42, null, undefined, '']) {
        if (Triauth.Helpers.isSecureUrl(url)) {
          assert.equal(Triauth.Helpers.isCanonicalUrl(url), true, String(url).slice(0, 60));
        }
      }
    });

  });

  describe('getBaseUrl', () => {

    it('returns the origin plus the path through the last "/"', () => {
      const cases = [
        ['https://example.com/cb', 'https://example.com/'],
        ['https://example.com/', 'https://example.com/'],
        ['https://example.com/app/callback', 'https://example.com/app/'],
        ['https://example.com/app/', 'https://example.com/app/'],
        ['http://localhost:3000/cb', 'http://localhost:3000/'],
        ['http://10.0.0.5:8080/cb', 'http://10.0.0.5:8080/'],
        ['https://a.com:8443/x/y/z', 'https://a.com:8443/x/y/'],
        ['https://a.com/x/y/z?q=1#f', 'https://a.com/x/y/'],
        ['https://example.com/cb;sid=1', 'https://example.com/'],
        // the helper is a pure view: a ';' in the base span parses fine here, and it is the
        // callbackUrl validator that refuses to let such a base become a `via`
        ['https://example.com/a;b/cb', 'https://example.com/a;b/']
      ];
      for (const [url, base] of cases) {
        assert.equal(Triauth.Helpers.getBaseUrl(url), base, url);
      }
    });

    it('returns false for anything that is not a canonical URL — the policy checks included', () => {
      for (const url of [
        'not-a-url', 'https://u:p@a.com/x', 'https://A.COM/x', 'https://example.com', 'https://a.com/a|b/cb', 42, null,
        // policy-layer rejects share the same accept-set as isCanonicalUrl (no grammar-only backdoor)
        'https://xn--mller-kva.de/x', 'https://a.com/%zz/x', 'https://0x7f.0x1/x', 'https://example.com/' + 'a'.repeat(2029)
      ]) {
        assert.equal(Triauth.Helpers.getBaseUrl(url), false, String(url).slice(0, 60));
      }
    });

  });

  describe('urlHost', () => {

    it('returns the port-free lowercase host of a canonical URL', () => {
      const cases = [
        ['https://attest.triauthdemo.org/over-18', 'attest.triauthdemo.org'],
        ['http://localhost:8080/verify', 'localhost'],
        ['https://a.com:8443/x', 'a.com'],
        ['https://127.0.0.1/', '127.0.0.1'],
        ['http://10.0.0.5:8080/cb', '10.0.0.5']
      ];
      for (const [url, host] of cases) {
        assert.equal(Triauth.Helpers.urlHost(url), host, url);
      }
    });

    it('returns false for anything that is not a canonical URL — the policy checks included', () => {
      for (const url of ['https://2130706433/', 'nope', '', null, 'https://xn--mller-kva.de/x', 'https://a.com/%zz/x']) {
        assert.equal(Triauth.Helpers.urlHost(url), false, String(url));
      }
    });

  });

  describe('hasPunycodeLabel', () => {

    it('flags xn-- labels in any position, case-insensitively', () => {
      for (const host of ['xn--mller-kva.de', 'a.xn--p1ai', 'XN--mller-kva.de', 'a.XN--p1ai.com']) {
        assert.equal(Triauth.Helpers.hasPunycodeLabel(host), true, host);
      }
      for (const host of ['example.com', 'axn--b.com', 'xn.example.com', 42, null]) {
        assert.equal(Triauth.Helpers.hasPunycodeLabel(host), false, String(host));
      }
    });

  });

  describe('isDomainName', () => {

    it('accepts LDH domain names of at least two labels, case-insensitively', () => {
      for (const domain of ['example.com', 'auth.example.com', 'AUTH.Uppercase.Example', '1.example.com', 'a-b.example.co']) {
        assert.equal(Triauth.Helpers.isDomainName(domain), true, domain);
      }
    });

    it('rejects punycode labels and numeric final labels (IPv4 spellings)', () => {
      for (const domain of ['xn--mller-kva.de', 'a.xn--p1ai', 'a.example.12', '0x7f.0x1', 'a.0x7F', 'example.0x', 'localhost', 'a.com.', 'port.example:8443']) {
        assert.equal(Triauth.Helpers.isDomainName(domain), false, domain);
      }
    });

    it('bounds a name at 253 bytes, the DNS maximum', () => {
      const labels = 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(63) + '.';
      assert.equal(Triauth.Helpers.isDomainName(labels + 'd'.repeat(61)), true, '253 bytes');
      assert.equal(Triauth.Helpers.isDomainName(labels + 'd'.repeat(62)), false, '254 bytes');
    });

  });

  // The closed grammar must never be the looser side of a parser differential: everything it
  // accepts must also survive a WHATWG-URL round-trip canonicality check (re-serialization
  // equality), and on that accepted set both parsers must extract identical components. Runs
  // against the runtime's own URL implementation — Node and browsers each cross-check it.
  describe('grammar vs WHATWG URL (differential)', () => {

    const whatwgIsCanonicalUrl = (string) => {
      if (typeof string !== 'string') { return false; }
      if (string.length === 0 || Triauth.Helpers.byteSize(string) > Triauth.LIMITS.urlBytesize) { return false; }
      if (!/^[\x21-\x7E]+$/.test(string)) { return false; }
      if (/%(?![0-9A-Fa-f]{2})/.test(string)) { return false; }
      try {
        const url = new URL(string);
        if (/(^xn--)|(\.xn--)/i.test(url.hostname)) { return false; }
        return (
          !url.username && !url.password &&
          // WHATWG percent-encodes "'" in http(s) queries (its special-query set); the closed
          // grammar keeps the RFC 3986 pchar set, where "'" is legal — accept exactly that one
          // spelling difference and no other.
          (url.href === string || url.href === string.replace(/'/g, '%27'))
        );
      } catch {
        return false;
      }
    };

    const whatwgGetBaseUrl = (string) => {
      try {
        const url = new URL(string);
        const pathname = url.pathname;
        url.pathname = pathname.endsWith('/') ? pathname : pathname.substring(0, pathname.lastIndexOf('/') + 1);
        url.username = '';
        url.password = '';
        url.hash = '';
        url.search = '';
        return url.href;
      } catch {
        return false;
      }
    };

    const corpus = [
      ...CANONICAL,
      ...Object.values(REJECTED).flat(),
      // WHATWG-canonical strings deliberately outside the closed grammar
      'https://a.com/a|b', 'https://a.com/a[b]c', 'https://a.com/?q|pipe', 'https://a.com/?q^caret',
      'https://a.com/?q{cur}', 'https://a.com/?q`tick', 'https://a.com/?q\\back', 'https://a.com/#f|pipe',
      'https://a.com/#f\\back', 'https://a.com/#f^caret', 'https://a.com./',
      'https://_x.a.com/', 'https://-a-.com/', 'https://a.com/?', 'https://a.com/#',
      // and assorted hostile spellings
      'https://a.com\\b/', 'https://a.com/%2e%2e/%2e%2e/etc', 'https://0x7f.1/', 'https://a.com:0443/',
      'http://LOCALHOST/', 'http://localhost./', 'https://a.com/..%2f..', 'https://e.com/?\'or 1=1--'
    ];

    it('never accepts a string the WHATWG round-trip check rejects', () => {
      for (const s of corpus) {
        if (Triauth.Helpers.isCanonicalUrl(s)) {
          assert.equal(whatwgIsCanonicalUrl(s), true, `accepted, but WHATWG-non-canonical: ${s}`);
        }
      }
    });

    it('extracts the same base URL and host as WHATWG parsing on every accepted URL', () => {
      for (const s of corpus) {
        if (Triauth.Helpers.isCanonicalUrl(s)) {
          assert.equal(Triauth.Helpers.getBaseUrl(s), whatwgGetBaseUrl(s), `base of ${s}`);
          assert.equal(Triauth.Helpers.urlHost(s), new URL(s).hostname, `host of ${s}`);
        }
      }
    });

    it('exposes one accept-set: getBaseUrl and urlHost succeed exactly when isCanonicalUrl accepts', () => {
      for (const s of corpus) {
        const canonical = Triauth.Helpers.isCanonicalUrl(s);
        assert.equal(Triauth.Helpers.getBaseUrl(s) !== false, canonical, `getBaseUrl vs isCanonicalUrl on ${String(s).slice(0, 60)}`);
        assert.equal(Triauth.Helpers.urlHost(s) !== false, canonical, `urlHost vs isCanonicalUrl on ${String(s).slice(0, 60)}`);
      }
    });

  });

}); }
