class DnsResolverStub extends Triauth.Resolvers.Base {

  constructor(domainRecords = {}, options = {}, config = {}) {
    super();
    this.domainRecords = domainRecords;
    this.options = options;
    this.config = Object.assign({}, Triauth.config, config);
  }

  resolve(domainName, type, options = {}) {
    const records = this.domainRecords[domainName];

    return new Promise( (resolve, reject) => {
      if (records?._error) {
        return reject(new Error(records._error));
      }
      let retval = (records || {})[type] || [];
      retval = retval.map((record) => typeof record === 'string' ? {'value':record, 'ttl':1800, 'dnssec':true} : record);
      resolve(retval);
    });
  }
}

export default DnsResolverStub;
