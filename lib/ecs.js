'use strict';

// EDNS Client Subnet wire helpers — v1.2.0
// Only IPv4 ECS is supported; the relay's fixed subnet is an IPv4 CIDR.

function buildEcsData(cidr) {
  const parts = String(cidr).split('/');
  if (parts.length !== 2) throw new Error('expected an IPv4 CIDR like 221.176.1.0/24');
  const [addr, prefixRaw] = parts;
  const octets = addr.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    throw new Error('invalid IPv4 address');
  }
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error('invalid prefix length');
  }
  const bytes = Math.ceil(prefix / 8);
  const data = Buffer.alloc(4 + bytes);
  data.writeUInt16BE(1, 0); // family: IPv4
  data[2] = prefix; // source prefix length
  data[3] = 0; // scope prefix length, always 0 in a query
  for (let i = 0; i < bytes; i++) data[4 + i] = octets[i] || 0;
  const remainder = prefix % 8;
  if (remainder && bytes > 0) data[4 + bytes - 1] &= (0xff << (8 - remainder)) & 0xff;
  return data;
}

function skipName(buf, offset) {
  let off = offset;
  while (true) {
    if (off >= buf.length) throw new Error('truncated name');
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length) throw new Error('truncated pointer');
      return off + 2;
    }
    if ((len & 0xc0) !== 0) throw new Error('bad label');
    off += 1 + len;
  }
}

function skipRecord(buf, offset) {
  const nameEnd = skipName(buf, offset);
  if (nameEnd + 10 > buf.length) throw new Error('truncated record');
  const rdlength = buf.readUInt16BE(nameEnd + 8);
  const end = nameEnd + 10 + rdlength;
  if (end > buf.length) throw new Error('truncated rdata');
  return end;
}

function parseOptions(rdata) {
  const options = [];
  let off = 0;
  while (off + 4 <= rdata.length) {
    const code = rdata.readUInt16BE(off);
    const len = rdata.readUInt16BE(off + 2);
    const end = off + 4 + len;
    if (end > rdata.length) break;
    options.push({ code, data: rdata.subarray(off + 4, end) });
    off = end;
  }
  return options;
}

function buildOpt(original, ecs) {
  const payloadSize = original ? original.udpSize : 1232;
  const ttl = original ? original.ttl : 0;
  const options = original ? original.options.filter((option) => option.code !== 8) : [];
  options.push({ code: 8, data: ecs });
  const rdata = Buffer.concat(
    options.map((option) => {
      const head = Buffer.alloc(4);
      head.writeUInt16BE(option.code, 0);
      head.writeUInt16BE(option.data.length, 2);
      return Buffer.concat([head, option.data]);
    }),
  );
  const head = Buffer.alloc(11);
  head[0] = 0; // root name
  head.writeUInt16BE(41, 1); // OPT
  head.writeUInt16BE(payloadSize, 3);
  head.writeUInt32BE(ttl, 5);
  head.writeUInt16BE(rdata.length, 9);
  return Buffer.concat([head, rdata]);
}

function injectEcs(query, ecs) {
  if (query.length < 12) throw new Error('truncated header');
  const qd = query.readUInt16BE(4);
  const an = query.readUInt16BE(6);
  const ns = query.readUInt16BE(8);
  const ar = query.readUInt16BE(10);

  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = skipName(query, off);
    off += 4;
    if (off > query.length) throw new Error('truncated question');
  }
  for (let i = 0; i < an + ns; i++) off = skipRecord(query, off);
  const additionalStart = off;

  let originalOpt = null;
  const preserved = [];
  for (let i = 0; i < ar; i++) {
    const start = off;
    const nameEnd = skipName(query, off);
    if (nameEnd + 10 > query.length) throw new Error('truncated additional record');
    const type = query.readUInt16BE(nameEnd);
    const end = skipRecord(query, start);
    if (type === 41) {
      if (!originalOpt) {
        const udpSize = query.readUInt16BE(nameEnd + 2);
        const ttl = query.readUInt32BE(nameEnd + 4);
        const rdlength = query.readUInt16BE(nameEnd + 8);
        const rdata = query.subarray(nameEnd + 10, nameEnd + 10 + rdlength);
        originalOpt = { udpSize, ttl, options: parseOptions(rdata) };
      }
    } else {
      preserved.push(query.subarray(start, end));
    }
    off = end;
  }

  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(preserved.length + 1, 10);
  const body = query.subarray(12, additionalStart);
  return Buffer.concat([header, body, ...preserved, buildOpt(originalOpt, ecs)]);
}

module.exports = { buildEcsData, injectEcs };
