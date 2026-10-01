import DnsResolverStub from './dns_resolver.js';
import dnsRecords from '../fixtures/dns_records.json' with { type: 'json' };

// The suite's DNS served from the fixture
export const zoneResolver = new DnsResolverStub(dnsRecords);
export { dnsRecords };

Triauth.config.resolver = zoneResolver;
