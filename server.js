'use strict';

// Infrlo DoH relay — v1.0.1
// RFC 8484 DNS-over-HTTPS relay. Infrlo expects the app on 0.0.0.0:5000.
// Kept dependency-free on purpose: no npm install step on the platform.

const http = require('node:http');
const https = require('node:https');

const VERSION = '1.0.1';
const PORT = Number(process.env.PORT || 5000);
// DOH_UPSTREAMS lets a deployment override the defaults without a rebuild.
const UPSTREAMS = (process.env.DOH_UPSTREAMS ||
  'https://cloudflare-dns.com/dns-query,https://dns.google/dns-query')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const MAX_BODY = 65535;
const UPSTREAM_TIMEOUT = 10000;

function relayOnce(base, method, queryString, body, cb) {
  const url = new URL(base);
  let done = false;
  let timer;
  const finish = (err, status, data) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    cb(err, status, data);
  };

  const req = https.request(
    {
      hostname: url.hostname,
      port: 443,
      path: url.pathname + (queryString ? '?' + queryString : ''),
      method,
      headers: {
        'content-type': 'application/dns-message',
        accept: 'application/dns-message',
        'user-agent': `infrlo-doh-relay/${VERSION}`,
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

  // A hard timer covers DNS lookup and connect, which socket timeouts miss.
  timer = setTimeout(() => {
    req.destroy(new Error('upstream timeout'));
    finish(new Error('upstream timeout'));
  }, UPSTREAM_TIMEOUT);

  req.on('timeout', () => req.destroy(new Error('upstream timeout')));
  req.on('error', (err) => finish(err));
  if (body) req.write(body);
  req.end();
}

// Try each upstream in order; an HTTP error status is not a valid DNS answer.
function relay(method, queryString, body, cb, index = 0) {
  if (index >= UPSTREAMS.length) return cb(new Error('all upstreams failed'));
  relayOnce(UPSTREAMS[index], method, queryString, body, (err, status, data) => {
    if (!err && status >= 200 && status < 300 && data.length >= 12) return cb(null, data);
    relay(method, queryString, body, cb, index + 1);
  });
}

function send(res, status, body, type) {
  res.writeHead(status, {
    'content-type': type || 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const started = Date.now();

  if (url.pathname === '/' || url.pathname === '/health') {
    return send(res, 200, `infrlo-doh-relay v${VERSION}\n`);
  }

  if (url.pathname !== '/dns-query') {
    return send(res, 404, 'not found\n');
  }

  const reply = (err, data) => {
    if (err) {
      console.log(`${req.method} ${url.pathname} 502 ${Date.now() - started}ms ${err.message}`);
      return send(res, 502, 'upstream error\n');
    }
    console.log(`${req.method} ${url.pathname} 200 ${Date.now() - started}ms ${data.length}b`);
    send(res, 200, data, 'application/dns-message');
  };

  if (req.method === 'GET') {
    const dns = url.searchParams.get('dns');
    if (!dns) return send(res, 400, 'missing dns parameter\n');
    return relay('GET', 'dns=' + encodeURIComponent(dns), null, reply);
  }

  if (req.method === 'POST') {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (body.length < 12) return send(res, 400, 'bad dns message\n');
      relay('POST', '', body, reply);
    });
    return;
  }

  send(res, 405, 'method not allowed\n');
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`infrlo-doh-relay v${VERSION} listening on 0.0.0.0:${PORT}`);
  console.log(`upstreams: ${UPSTREAMS.join(', ')}`);
});
