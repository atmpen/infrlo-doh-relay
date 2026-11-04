// Smoke tests for the DoH relay. Hermetic: a local HTTP mock plays the upstream,
// so `npm test` does not need outbound DNS or internet access.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import http2 from 'node:http2';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ecs from '../lib/ecs.js';

const { buildEcsData, injectEcs } = ecs;
const here = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(here, '..', 'server.js');
const ANSWER_IP = '203.0.113.7';
const TEST_TOKEN = 'smoke-test-token';
const TEST_SUFFIX = 'weduolijia';

function buildQuery(name, type = 1) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const labels = name.split('.').filter(Boolean);
  const qname = [];
  for (const label of labels) qname.push(Buffer.from([label.length]), Buffer.from(label));
  qname.push(Buffer.from([0]));
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, ...qname, tail]);
}

function buildAnswer(query, ip = ANSWER_IP, idOffset = 0) {
  const id = Buffer.from(query.subarray(0, 2));
  if (idOffset) id.writeUInt16BE((id.readUInt16BE(0) + idOffset) & 0xffff, 0);
  const header = Buffer.concat([
    id,
    Buffer.from([0x81, 0x80]), // QR=1, RD=1, RA=1, rcode=0
    Buffer.from([0x00, 0x01]), // qdcount
    Buffer.from([0x00, 0x01]), // ancount
    Buffer.from([0x00, 0x00]), // nscount
    Buffer.from([0x00, 0x00]), // arcount
  ]);
  let off = 12;
  while (query[off] !== 0) off += query[off] + 1;
  const question = query.subarray(12, off + 5);
  const answer = Buffer.concat([
    Buffer.from([0xc0, 0x0c]), // pointer to qname
    Buffer.from([0x00, 0x01, 0x00, 0x01]), // type A, class IN
    Buffer.from([0x00, 0x00, 0x00, 0x3c]), // ttl 60
    Buffer.from([0x00, 0x04]),
    Buffer.from(ip.split('.').map(Number)),
  ]);
  return Buffer.concat([header, question, answer]);
}

function startMock({ idOffset = 0, ip = ANSWER_IP, delayMs = 0 } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      let query;
      if (req.method === 'GET') {
        const url = new URL(req.url, 'http://localhost');
        query = Buffer.from(url.searchParams.get('dns') || '', 'base64url');
      } else {
        query = Buffer.concat(chunks);
      }
      requests.push({
        method: req.method,
        contentLength: req.headers['content-length'],
        contentType: req.headers['content-type'],
        query: Buffer.from(query),
      });
      const respond = () => {
        if (res.writableEnded || res.destroyed) return;
        const answer = buildAnswer(query, ip, idOffset);
        res.writeHead(200, {
          'content-type': 'application/dns-message',
          'content-length': answer.length,
        });
        res.end(answer);
      };
      if (delayMs) setTimeout(respond, delayMs).unref();
      else respond();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port, requests });
    });
  });
}

function startH2Mock() {
  const server = http2.createServer();
  server.on('stream', (stream) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => {
      const query = Buffer.concat(chunks);
      const answer = buildAnswer(query, ANSWER_IP, 0);
      stream.respond({
        ':status': 200,
        'content-type': 'application/dns-message',
        'content-length': answer.length,
      });
      stream.end(answer);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port });
    });
  });
}

function skipName(buf, off) {
  while (true) {
    const len = buf[off];
    if (len === undefined) throw new Error('truncated name');
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;
    off += 1 + len;
  }
}

function parseOpt(query) {
  const qd = query.readUInt16BE(4);
  const an = query.readUInt16BE(6);
  const ns = query.readUInt16BE(8);
  const ar = query.readUInt16BE(10);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = skipName(query, off);
    off += 4;
  }
  for (let i = 0; i < an + ns; i++) {
    off = skipName(query, off);
    const rdlen = query.readUInt16BE(off + 8);
    off += 10 + rdlen;
  }
  for (let i = 0; i < ar; i++) {
    off = skipName(query, off);
    const type = query.readUInt16BE(off);
    const udpSize = query.readUInt16BE(off + 2);
    const ttl = query.readUInt32BE(off + 4);
    const rdlen = query.readUInt16BE(off + 8);
    const rdata = query.subarray(off + 10, off + 10 + rdlen);
    if (type === 41) return { udpSize, ttl, rdata };
    off += 10 + rdlen;
  }
  return null;
}

function findEcs(query) {
  const opt = parseOpt(query);
  if (!opt) return null;
  let off = 0;
  while (off + 4 <= opt.rdata.length) {
    const code = opt.rdata.readUInt16BE(off);
    const len = opt.rdata.readUInt16BE(off + 2);
    const data = opt.rdata.subarray(off + 4, off + 4 + len);
    if (code === 8 && data.length >= 4) {
      return {
        family: data.readUInt16BE(0),
        source: data[2],
        scope: data[3],
        address: [...data.subarray(4)],
      };
    }
    off += 4 + len;
  }
  return null;
}

function buildQueryWithOpt(name, ecsCidr, doBit = true) {
  const query = buildQuery(name);
  query.writeUInt16BE(1, 10);
  const ecsData = buildEcsData(ecsCidr);
  const rdata = Buffer.alloc(4 + ecsData.length);
  rdata.writeUInt16BE(8, 0);
  rdata.writeUInt16BE(ecsData.length, 2);
  ecsData.copy(rdata, 4);
  const head = Buffer.alloc(11);
  head[0] = 0;
  head.writeUInt16BE(41, 1);
  head.writeUInt16BE(1232, 3);
  head.writeUInt32BE(doBit ? 0x8000 : 0, 5);
  head.writeUInt16BE(rdata.length, 9);
  return Buffer.concat([query, head, rdata]);
}

async function closedPort() {
  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function startRelay(env = {}) {
  const child = spawn(process.execPath, [serverPath], {
    env: { ...process.env, PORT: '0', DOH_TOKEN: TEST_TOKEN, DOH_SUFFIX: TEST_SUFFIX, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });

  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('relay start timeout: ' + output)), 5000);
    const check = () => {
      const match = output.match(/listening on 0\.0\.0\.0:(\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    };
    child.stdout.on('data', check);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`relay exited ${code}: ${output}`));
    });
  });
  return { child, base: `http://127.0.0.1:${port}` };
}

async function stopRelay(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([once(child, 'exit'), new Promise((resolve) => setTimeout(resolve, 2000))]);
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
}

function dohPost(base, query, headers = {}) {
  return fetch(`${base}/${TEST_TOKEN}/${TEST_SUFFIX}`, {
    method: 'POST',
    headers: { 'content-type': 'application/dns-message', ...headers },
    body: query,
  });
}

function assertAnswer(buffer, query) {
  assert.ok(buffer.length >= 12, 'response is a DNS message');
  assert.equal(buffer.readUInt16BE(0), query.readUInt16BE(0), 'id matches');
  assert.equal(buffer[3] & 0x0f, 0, 'rcode is NOERROR');
  assert.equal(buffer.readUInt16BE(6), 1, 'one answer');
  assert.equal(buffer.subarray(-4).join('.'), ANSWER_IP, 'answer is the mock A record');
}

const mock = await startMock();
const badMock = await startMock({ idOffset: 1 });
const mockUpstream = `http://127.0.0.1:${mock.port}/dns-query`;

after(() => {
  mock.server.closeAllConnections?.();
  badMock.server.closeAllConnections?.();
  mock.server.close();
  badMock.server.close();
});

test('health endpoint reports the version', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const response = await fetch(relay.base + '/health');
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.status, 'ok');
    assert.equal(body.version, '1.4.0');
    assert.equal(body.ecs, '111.8.1.0/24');
    assert.equal(body.auth, true);
    assert.equal(body.suffix, TEST_SUFFIX);
  } finally {
    await stopRelay(relay.child);
  }
});

test('POST DoH query returns the upstream answer', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const query = buildQuery('example.com');
    const response = await dohPost(relay.base, query);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'application/dns-message');
    assertAnswer(Buffer.from(await response.arrayBuffer()), query);
    // Cloudflare rejects a chunked POST, so the relay must send a length.
    const received = mock.requests.at(-1);
    assert.equal(received.contentLength, String(received.query.length));
  } finally {
    await stopRelay(relay.child);
  }
});

test('GET DoH query returns the upstream answer', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const query = buildQuery('example.com');
    const response = await fetch(
      `${relay.base}/${TEST_TOKEN}/${TEST_SUFFIX}?dns=` + query.toString('base64url'),
    );
    assert.equal(response.status, 200);
    assertAnswer(Buffer.from(await response.arrayBuffer()), query);
  } finally {
    await stopRelay(relay.child);
  }
});

test('rejects a non-DNS content type', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const response = await fetch(`${relay.base}/${TEST_TOKEN}/${TEST_SUFFIX}`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'not dns',
    });
    assert.equal(response.status, 415);
  } finally {
    await stopRelay(relay.child);
  }
});

test('rejects a GET without the dns parameter', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const response = await fetch(`${relay.base}/${TEST_TOKEN}/${TEST_SUFFIX}`);
    assert.equal(response.status, 400);
  } finally {
    await stopRelay(relay.child);
  }
});

test('unknown paths are 404', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    assert.equal((await fetch(relay.base + '/not-dns')).status, 404);
    assert.equal((await fetch(`${relay.base}/${TEST_TOKEN}/dns-query`)).status, 404);
  } finally {
    await stopRelay(relay.child);
  }
});

test('token auth is required before the DoH path', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream, DOH_TOKEN: 'secret' });
  try {
    const query = buildQuery('example.com');
    const wrongToken = await fetch(`${relay.base}/wrong/${TEST_SUFFIX}`, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
    });
    assert.equal(wrongToken.status, 401);

    const good = await fetch(`${relay.base}/secret/${TEST_SUFFIX}`, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
    });
    assert.equal(good.status, 200);
    assertAnswer(Buffer.from(await good.arrayBuffer()), query);

    const getGood = await fetch(
      `${relay.base}/secret/${TEST_SUFFIX}?dns=` + query.toString('base64url'),
    );
    assert.equal(getGood.status, 200);

    const oldPath = await fetch(`${relay.base}/secret/dns-query`, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
    });
    assert.equal(oldPath.status, 404);
  } finally {
    await stopRelay(relay.child);
  }
});

test('falls over to the next upstream', async () => {
  const deadPort = await closedPort();
  const relay = await startRelay({
    DOH_UPSTREAMS: `http://127.0.0.1:${deadPort}/dns-query,${mockUpstream}`,
  });
  try {
    const query = buildQuery('example.com');
    const response = await dohPost(relay.base, query);
    assert.equal(response.status, 200);
    assertAnswer(Buffer.from(await response.arrayBuffer()), query);
  } finally {
    await stopRelay(relay.child);
  }
});

test('rejects an answer with a mismatched DNS id', async () => {
  const relay = await startRelay({
    DOH_UPSTREAMS: `http://127.0.0.1:${badMock.port}/dns-query`,
  });
  try {
    const response = await dohPost(relay.base, buildQuery('example.com'));
    assert.equal(response.status, 502);
  } finally {
    await stopRelay(relay.child);
  }
});

test('injectEcs replaces an existing ECS and keeps the DO bit', () => {
  const original = buildQueryWithOpt('example.com', '8.8.8.0/24', true);
  const injected = injectEcs(original, buildEcsData('221.176.1.0/24'));
  const opt = parseOpt(injected);
  assert.equal(opt.ttl & 0x8000, 0x8000, 'DO bit preserved');
  assert.deepEqual(findEcs(injected), {
    family: 1,
    source: 24,
    scope: 0,
    address: [221, 176, 1],
  });
  assert.equal(injected.readUInt16BE(10), 1, 'one additional record');

  let count = 0;
  let off = 0;
  while (off + 4 <= opt.rdata.length) {
    const code = opt.rdata.readUInt16BE(off);
    const len = opt.rdata.readUInt16BE(off + 2);
    if (code === 8) count += 1;
    off += 4 + len;
  }
  assert.equal(count, 1, 'the old ECS option is gone');
});

test('relay injects the configured ECS into the upstream query', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream, DOH_ECS: '221.176.1.0/24' });
  try {
    const query = buildQuery('example.com');
    const response = await dohPost(relay.base, query);
    assert.equal(response.status, 200);
    const received = mock.requests.at(-1).query;
    assert.deepEqual(findEcs(received), {
      family: 1,
      source: 24,
      scope: 0,
      address: [221, 176, 1],
    });
    assert.equal(received.readUInt16BE(10), 1);
  } finally {
    await stopRelay(relay.child);
  }
});

test('DOH_ECS=off leaves the query untouched', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream, DOH_ECS: 'off' });
  try {
    const query = buildQuery('example.com');
    const response = await dohPost(relay.base, query);
    assert.equal(response.status, 200);
    const received = mock.requests.at(-1).query;
    assert.equal(findEcs(received), null);
    assert.equal(received.readUInt16BE(10), 0);
  } finally {
    await stopRelay(relay.child);
  }
});

test('uses HTTP/2 for http2:// upstreams', async () => {
  const h2mock = await startH2Mock();
  const relay = await startRelay({
    DOH_UPSTREAMS: `http2://127.0.0.1:${h2mock.port}/dns-query`,
  });
  try {
    const query = buildQuery('example.com');
    const response = await dohPost(relay.base, query);
    assert.equal(response.status, 200);
    assertAnswer(Buffer.from(await response.arrayBuffer()), query);
  } finally {
    await stopRelay(relay.child);
    h2mock.server.close();
  }
});

test('races upstreams and returns the first useful answer', async () => {
  const fast = await startMock({ ip: '203.0.113.7' });
  const slow = await startMock({ ip: '203.0.113.8', delayMs: 600 });
  const relay = await startRelay({
    DOH_UPSTREAMS: `http://127.0.0.1:${slow.port}/dns-query,http://127.0.0.1:${fast.port}/dns-query`,
    DOH_ECS: 'off',
  });
  try {
    const query = buildQuery('example.com');
    const started = Date.now();
    const response = await dohPost(relay.base, query);
    const elapsed = Date.now() - started;
    assert.equal(response.status, 200);
    const buffer = Buffer.from(await response.arrayBuffer());
    assert.equal(buffer.subarray(-4).join('.'), '203.0.113.7');
    assert.ok(elapsed < 600, `fast upstream should win (${elapsed}ms)`);
  } finally {
    await stopRelay(relay.child);
    fast.server.closeAllConnections?.();
    slow.server.closeAllConnections?.();
    fast.server.close();
    slow.server.close();
  }
});

test('rate limits one client after the configured budget', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream, RATE_LIMIT_PER_MIN: '2' });
  try {
    const query = buildQuery('example.com');
    assert.equal((await dohPost(relay.base, query)).status, 200);
    assert.equal((await dohPost(relay.base, query)).status, 200);
    const limited = await dohPost(relay.base, query);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '60');
  } finally {
    await stopRelay(relay.child);
  }
});
