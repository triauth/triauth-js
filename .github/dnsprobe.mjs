// Raw DNS probe: asks the system resolver (or a given server) for a TXT RRset over UDP (with and
// without EDNS) and over TCP, several times, and prints the answer count and the TC flag of each
// reply. Node only. Usage: node dnsprobe.mjs [name] [server] [rounds]
import dgram from 'node:dgram';
import net from 'node:net';
import dns from 'node:dns';

const name = process.argv[2] ?? 'big.dns-test.triauthdemo.org';
const servers = process.argv[3] ? [process.argv[3]] : dns.getServers().filter((s) => !s.includes(':') || s.startsWith('['));
const rounds = Number(process.argv[4] ?? 10);

const qname = Buffer.concat([...name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')])), Buffer.from([0])]);
const query = (id, edns) => {
  const h = Buffer.alloc(12); h.writeUInt16BE(id, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4); h.writeUInt16BE(edns ? 1 : 0, 10);
  const q = Buffer.concat([qname, Buffer.from([0, 16, 0, 1])]);
  const opt = edns ? Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]) : Buffer.alloc(0); // OPT, udp size 1232
  return Buffer.concat([h, q, opt]);
};
const summarize = (buf, took) => {
  if (!buf) return `no reply (${took}ms)`;
  const flags = buf.readUInt16BE(2);
  return `rcode=${flags & 0xf} TC=${(flags & 0x200) ? 1 : 0} answers=${buf.readUInt16BE(6)} bytes=${buf.length} (${took}ms)`;
};
const udp = (server, edns) => new Promise((resolve) => {
  const sock = dgram.createSocket('udp4'); const t0 = Date.now(); const id = Math.floor(Math.random() * 65536);
  const timer = setTimeout(() => { sock.close(); resolve(summarize(null, Date.now() - t0)); }, 3000);
  sock.on('message', (msg) => { clearTimeout(timer); sock.close(); resolve(summarize(msg, Date.now() - t0)); });
  sock.send(query(id, edns), 53, server);
});
const tcp = (server, edns) => new Promise((resolve) => {
  const t0 = Date.now(); const id = Math.floor(Math.random() * 65536); let buf = Buffer.alloc(0);
  const sock = net.connect(53, server, () => { const q = query(id, edns); const len = Buffer.alloc(2); len.writeUInt16BE(q.length, 0); sock.write(Buffer.concat([len, q])); });
  const done = (msg) => { sock.destroy(); resolve(summarize(msg, Date.now() - t0)); };
  sock.setTimeout(3000, () => done(null)); sock.on('error', (e) => resolve(`error ${e.code} (${Date.now() - t0}ms)`));
  sock.on('data', (d) => { buf = Buffer.concat([buf, d]); if (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) done(buf.subarray(2, 2 + buf.readUInt16BE(0))); });
});

console.log(`node ${process.version} ${process.platform}, servers ${JSON.stringify(dns.getServers())}, probing ${servers.join(', ')} for TXT ${name}`);
for (const server of servers) {
  for (let i = 1; i <= rounds; i++) {
    const [u, ue, t] = await Promise.all([udp(server, false), udp(server, true), tcp(server, false)]);
    console.log(`${server} #${i}  UDP/plain ${u}  |  UDP/EDNS1232 ${ue}  |  TCP ${t}`);
  }
  const r = new dns.Resolver(); r.setServers([server]);
  const counts = await Promise.all(Array.from({ length: rounds }, () => new Promise((res) => r.resolveTxt(name, (e, recs) => res(e ? e.code : recs.length)))));
  console.log(`${server} node:dns resolveTxt x${rounds}: ${counts.join(' ')}`);
}
