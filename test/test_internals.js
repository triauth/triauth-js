import resolvers from './internals/test_resolvers.js';
import resolversZone from './internals/test_resolvers_zone.js';
import verifiers from './internals/test_verifiers.js';
import cachingResolver from './internals/test_caching_resolver.js';
import identityKeys from './internals/test_identity_keys.js';
import identityIncludes from './internals/test_identity_includes.js';
import logger from './internals/test_logger.js';
import helpers from './internals/test_helpers.js';
import canonicalUrl from './internals/test_canonical_url.js';
import signature from './internals/test_signature.js';
import identityDomain from './internals/test_identity_domain.js';
import authenticationEndpoint from './internals/test_authentication_endpoint.js';
import config from './internals/test_config.js';
import protocol from './internals/test_protocol.js';

// Wrapping the calls under a single 'Internals' label
describe('Internals', () => {
  resolvers();
  resolversZone();
  verifiers();
  cachingResolver();
  identityKeys();
  identityIncludes();
  logger();
  helpers();
  canonicalUrl();
  signature();
  identityDomain();
  authenticationEndpoint();
  config();
  protocol();
});
