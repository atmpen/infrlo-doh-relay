// Smoke tests for the DoH relay. Hermetic: a local HTTP mock plays the upstream,
// so `npm test` does not need outbound DNS or internet access.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverPath = path.join(here, '..', 'server.js');
const ANSWER_IP = '203.0.113.7';

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

function startMock({ idOffset = 0 } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push({
      method: req.method,
      contentLength: req.headers['content-length'],
      contentType: req.headers['content-type'],
    });
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
      const answer = buildAnswer(query, ANSWER_IP, idOffset);
      res.writeHead(200, {
        'content-type': 'application/dns-message',
        'content-length': answer.length,
      });
      res.end(answer);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port, requests });
    });
  });
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
    env: { ...process.env, PORT: '0', ...env },
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
  return fetch(base + '/dns-query', {
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
    assert.equal(body.version, '1.1.1');
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
    assert.equal(mock.requests.at(-1).contentLength, String(query.length));
  } finally {
    await stopRelay(relay.child);
  }
});

test('GET DoH query returns the upstream answer', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const query = buildQuery('example.com');
    const response = await fetch(relay.base + '/dns-query?dns=' + query.toString('base64url'));
    assert.equal(response.status, 200);
    assertAnswer(Buffer.from(await response.arrayBuffer()), query);
  } finally {
    await stopRelay(relay.child);
  }
});

test('rejects a non-DNS content type', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const response = await fetch(relay.base + '/dns-query', {
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
    const response = await fetch(relay.base + '/dns-query');
    assert.equal(response.status, 400);
  } finally {
    await stopRelay(relay.child);
  }
});

test('unknown paths are 404', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream });
  try {
    const response = await fetch(relay.base + '/not-dns');
    assert.equal(response.status, 404);
  } finally {
    await stopRelay(relay.child);
  }
});

test('token auth accepts query and path forms', async () => {
  const relay = await startRelay({ DOH_UPSTREAMS: mockUpstream, DOH_TOKEN: 'secret' });
  try {
    const query = buildQuery('example.com');
    assert.equal((await dohPost(relay.base, query)).status, 401);
    assert.equal((await dohPost(relay.base, query, { 'x-token': 'wrong' })).status, 401);

    const viaQuery = await fetch(relay.base + '/dns-query?token=secret', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
    });
    assert.equal(viaQuery.status, 200);
    assertAnswer(Buffer.from(await viaQuery.arrayBuffer()), query);

    const viaPath = await fetch(relay.base + '/dns-query/secret', {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
    });
    assert.equal(viaPath.status, 200);
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
