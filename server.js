'use strict';

// Infrlo DoH relay — v1.2.0
// RFC 8484 DNS-over-HTTPS relay. Infrlo expects the app on 0.0.0.0:5000.
// Dependency-free on purpose: the platform only needs `node server.js`.

const http = require('node:http');
const http2 = require('node:http2');
const crypto = require('node:crypto');
const { buildEcsData, injectEcs } = require('./lib/ecs');

const VERSION = '1.2.0';
const PORT = process.env.PORT === undefined || process.env.PORT === ''
  ? 5000
  : Number(process.env.PORT);
// Order matters only until the first success; the winning upstream is remembered.
const UPSTREAMS = (process.env.DOH_UPSTREAMS ||
  'https://unfiltered.adguard-dns.com/dns-query,https://dns11.quad9.net/dns-query,https://dns.google/dns-query')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const DOH_TOKEN = (process.env.DOH_TOKEN || '').trim();
// RATE_LIMIT_PER_MIN=0 disables the limiter; unset means 600/min per IP.
const RATE_LIMIT_PER_MIN = process.env.RATE_LIMIT_PER_MIN === undefined
  ? 600
  : Math.max(0, Number(process.env.RATE_LIMIT_PER_MIN) || 0);
const UPSTREAM_TIMEOUT_MS = Math.max(500, Number(process.env.UPSTREAM_TIMEOUT_MS) || 3000);
const MAX_BODY = 65535;
// Default ECS is a China Mobile /24 (AS9808, Beijing). DOH_ECS=off disables it.
const ECS_CIDR = process.env.DOH_ECS === undefined ? '221.176.1.0/24' : process.env.DOH_ECS.trim();
let ECS_DATA = null;
if (ECS_CIDR && !/^(off|none|0)$/i.test(ECS_CIDR)) {
  try {
    ECS_DATA = buildEcsData(ECS_CIDR);
  } catch (err) {
    console.error(`invalid DOH_ECS (${ECS_CIDR}): ${err.message}; ECS disabled`);
  }
}

let preferredUpstream = 0;
const rateBuckets = new Map();
const sessions = new Map();

function orderedUpstreams() {
  const first = UPSTREAMS[preferredUpstream] || UPSTREAMS[0];
  return [first, ...UPSTREAMS.filter((url) => url !== first)];
}

function isValidAnswer(data, queryId) {
  return (
    data.length >= 12 &&
    (data[2] & 0x80) !== 0 && // QR bit: this is a response
    data.readUInt16BE(0) === queryId
  );
}

function getSession(url) {
  const key = url.protocol + '//' + url.host;
  let session = sessions.get(key);
  if (session && !session.closed && !session.destroyed) return session;
  const origin = url.protocol === 'http2:' ? `http://${url.host}` : `https://${url.host}`;
  const options = url.protocol === 'http2:' ? {} : { servername: url.hostname };
  session = http2.connect(origin, options);
  const drop = () => {
    if (sessions.get(key) === session) sessions.delete(key);
  };
  session.on('close', drop);
  session.on('error', drop);
  session.on('goaway', drop);
  sessions.set(key, session);
  return session;
}

function relayOnceH1(url, method, queryString, body, cb) {
  let done = false;
  let timer;
  const finish = (err, status, data) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    cb(err, status, data);
  };

  const req = http.request(
    {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + (queryString ? '?' + queryString : ''),
      method,
      headers: {
        accept: 'application/dns-message',
        'user-agent': `infrlo-doh-relay/${VERSION}`,
        // Cloudflare rejects a chunked POST, so send an explicit length.
        ...(method === 'POST'
          ? { 'content-type': 'application/dns-message', 'content-length': body ? body.length : 0 }
          : {}),
      },
    },
    (upstream) => {
      const chunks = [];
      let size = 0;
      upstream.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          req.destroy(new Error('upstream body too large'));
          return;
        }
        chunks.push(chunk);
      });
      upstream.on('end', () => finish(null, upstream.statusCode, Buffer.concat(chunks)));
    },
  );

  timer = setTimeout(() => {
    req.destroy(new Error('upstream timeout'));
    finish(new Error('upstream timeout'));
  }, UPSTREAM_TIMEOUT_MS);

  req.on('timeout', () => req.destroy(new Error('upstream timeout')));
  req.on('error', (err) => finish(err));
  if (body) req.write(body);
  req.end();
}

function relayOnceH2(url, method, queryString, body, cb) {
  let done = false;
  let timer;
  let req;
  let status = null;
  const chunks = [];
  let size = 0;
  const finish = (err, statusCode, data) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    cb(err, statusCode, data);
  };

  try {
    const session = getSession(url);
    const headers = {
      ':method': method,
      ':path': url.pathname + (queryString ? '?' + queryString : ''),
      ':authority': url.host,
      accept: 'application/dns-message',
      'user-agent': `infrlo-doh-relay/${VERSION}`,
    };
    if (method === 'POST') {
      headers['content-type'] = 'application/dns-message';
      headers['content-length'] = body ? body.length : 0;
    }
    req = session.request(headers);
  } catch (err) {
    return cb(err);
  }

  req.on('response', (responseHeaders) => {
    status = responseHeaders[':status'];
  });
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY) {
      try {
        req.close(http2.constants.NGHTTP2_CANCEL);
      } catch {}
      finish(new Error('upstream body too large'));
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => finish(null, status, Buffer.concat(chunks)));
  req.on('error', (err) => finish(err));

  timer = setTimeout(() => {
    try {
      req.close(http2.constants.NGHTTP2_CANCEL);
    } catch {}
    finish(new Error('upstream timeout'));
  }, UPSTREAM_TIMEOUT_MS);

  if (body) req.write(body);
  req.end();
}

function relayOnce(url, method, queryString, body, cb) {
  if (url.protocol === 'http:') return relayOnceH1(url, method, queryString, body, cb);
  return relayOnceH2(url, method, queryString, body, cb);
}

function relay(method, queryString, body, queryId, cb) {
  const upstreams = orderedUpstreams();
  const attempt = (index) => {
    if (index >= upstreams.length) return cb(new Error('all upstreams failed'));
    const upstream = upstreams[index];
    let url;
    try {
      url = new URL(upstream);
    } catch {
      return attempt(index + 1);
    }
    relayOnce(url, method, queryString, body, (err, status, data) => {
      if (!err && status >= 200 && status < 300 && isValidAnswer(data, queryId)) {
        const preferred = UPSTREAMS.indexOf(upstream);
        if (preferred >= 0) preferredUpstream = preferred;
        return cb(null, data, upstream);
      }
      attempt(index + 1);
    });
  };
  attempt(0);
}

function send(res, status, body, type, extraHeaders = {}) {
  if (res.writableEnded || res.destroyed) return;
  res.writeHead(status, {
    'content-type': type || 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function rateLimited(ip) {
  if (!RATE_LIMIT_PER_MIN) return false;
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now >= bucket.reset) {
    bucket = { count: 0, reset: now + 60000 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT_PER_MIN;
}

function tokenMatches(candidate) {
  if (!DOH_TOKEN) return true;
  const given = Buffer.from(String(candidate || ''));
  const expected = Buffer.from(DOH_TOKEN);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

function readBody(req, cb) {
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  req.on('data', (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY) {
      tooLarge = true;
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => cb(tooLarge ? new Error('request body too large') : null, Buffer.concat(chunks)));
  req.on('error', (err) => cb(err));
}

function applyEcs(query) {
  if (!ECS_DATA) return query;
  try {
    return injectEcs(query, ECS_DATA);
  } catch {
    return query;
  }
}

function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const started = Date.now();
  // Never log a path token: /dns-query/<token> is the private form.
  const displayPath = url.pathname.startsWith('/dns-query/') ? '/dns-query/[redacted]' : url.pathname;

  if (url.pathname === '/' || url.pathname === '/health') {
    return send(
      res,
      200,
      JSON.stringify({
        status: 'ok',
        version: VERSION,
        uptime: Math.round(process.uptime()),
        upstreams: UPSTREAMS.length,
        auth: Boolean(DOH_TOKEN),
        ecs: ECS_DATA ? ECS_CIDR : 'off',
      }),
      'application/json; charset=utf-8',
    );
  }

  let isDohPath = url.pathname === '/dns-query' || url.pathname === '/dns-query/';
  let token = url.searchParams.get('token');
  if (!isDohPath && url.pathname.startsWith('/dns-query/')) {
    isDohPath = true;
    try {
      token = decodeURIComponent(url.pathname.slice('/dns-query/'.length));
    } catch {
      return send(res, 400, 'bad token encoding\n');
    }
  }
  if (!isDohPath) return send(res, 404, 'not found\n');

  // Limit before auth so a token guesser cannot brute-force at full speed.
  if (rateLimited(clientIp(req))) {
    return send(res, 429, 'rate limited\n', 'text/plain; charset=utf-8', { 'retry-after': '60' });
  }
  if (!tokenMatches(token)) return send(res, 401, 'unauthorized\n');

  const log = (status, extra = '') => {
    console.log(`${req.method} ${displayPath} ${status} ${Date.now() - started}ms${extra}`);
  };

  const reply = (err, data, upstream) => {
    if (err) {
      log(502, ` (${err.message})`);
      return send(res, 502, 'upstream error\n');
    }
    log(200, upstream ? ` via ${new URL(upstream).hostname}` : '');
    send(res, 200, data, 'application/dns-message');
  };

  if (req.method === 'GET') {
    const dns = url.searchParams.get('dns');
    if (!dns) {
      log(400);
      return send(res, 400, 'missing dns parameter\n');
    }
    const original = Buffer.from(dns, 'base64url');
    if (original.length < 12) {
      log(400);
      return send(res, 400, 'bad dns message\n');
    }
    const query = applyEcs(original);
    return relay('GET', 'dns=' + query.toString('base64url'), null, query.readUInt16BE(0), reply);
  }

  if (req.method === 'POST') {
    const type = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/dns-message') {
      log(415);
      return send(res, 415, 'expected application/dns-message\n');
    }
    return readBody(req, (err, body) => {
      if (err) {
        log(400);
        return send(res, 400, 'bad request body\n');
      }
      if (body.length < 12) {
        log(400);
        return send(res, 400, 'bad dns message\n');
      }
      const query = applyEcs(body);
      relay('POST', '', query, query.readUInt16BE(0), reply);
    });
  }

  log(405);
  send(res, 405, 'method not allowed\n');
}

const server = http.createServer((req, res) => {
  try {
    handle(req, res);
  } catch (err) {
    console.error('request handler error:', err.message);
    if (!res.headersSent) send(res, 500, 'internal error\n');
    else res.destroy();
  }
});

server.requestTimeout = 15000;
server.headersTimeout = 16000;
server.keepAliveTimeout = 65000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateBuckets) {
    if (now >= bucket.reset) rateBuckets.delete(ip);
  }
}, 60000).unref();

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    for (const session of sessions.values()) {
      try {
        session.close();
      } catch {}
    }
    server.close(() => process.exit(0));
    setTimeout(() => {
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      process.exit(0);
    }, 5000).unref();
  });
}

server.listen(PORT, '0.0.0.0', () => {
  const address = server.address();
  const actualPort = address && typeof address === 'object' ? address.port : PORT;
  console.log(`infrlo-doh-relay v${VERSION} listening on 0.0.0.0:${actualPort}`);
  console.log(`upstreams: ${UPSTREAMS.join(', ')}`);
  console.log(`ecs: ${ECS_DATA ? ECS_CIDR : 'off'}`);
  if (DOH_TOKEN) console.log('token auth: enabled');
  if (RATE_LIMIT_PER_MIN) console.log(`rate limit: ${RATE_LIMIT_PER_MIN}/min per IP`);
});
