# infrlo-doh-relay

v1.5.0 — a dependency-free [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) DNS-over-HTTPS relay, made for [Infrlo](https://infrlo.com/).

It accepts DoH queries on `/<DOH_TOKEN>/weduolijia`, injects a fixed EDNS Client Subnet (ECS) into every upstream query, forwards the DNS wire message over HTTP/2, and returns the answer unchanged. The root URL serves a live status dashboard. No cache, no query logging, no npm dependencies.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/<DOH_TOKEN>/weduolijia` | DoH query body (`content-type: application/dns-message`) |
| `GET` | `/<DOH_TOKEN>/weduolijia?dns=<base64url>` | DoH query in the URL |
| `GET` | `/` | Live status dashboard (public, token never shown) |
| `GET` | `/api/status` | JSON consumed by the dashboard (public) |
| `GET` | `/health` | Minimal JSON for monitoring (public) |

The token is a path segment and is checked **before** rate limiting, DNS parsing, ECS injection, or any upstream request. There is no `/dns-query` alias; the suffix is controlled by `DOH_SUFFIX` and defaults to `weduolijia`.

The server listens on `0.0.0.0:5000` (`PORT` overrides), which is what Infrlo expects.

## Web UI

Open `https://<your-app-domain>/` to see the dashboard:

- Version, uptime, Node runtime, memory
- DoH request count, success rate, auth failures, rate-limit hits
- Fixed ECS and rate limit
- Per-upstream attempts, wins, errors, last RTT and last rcode

It refreshes every 5 seconds and is served by the same process. The dashboard and `/api/status` are public, but neither contains `DOH_TOKEN`; the endpoint is shown as `/<token>/weduolijia`.

## Deploy on Infrlo

In the Infrlo dashboard, **Deploy → From Public URL** and use:

| Field | Value |
| --- | --- |
| Repository URL | `https://github.com/weduolijia/infrlo-doh-relay` |
| Branch | `main` |
| Build command | `npm install` |
| Run command | `sh start.sh` |

Set `DOH_TOKEN` to your secret in the environment variables section. **The relay refuses to start without it** — this is deliberate, so it cannot accidentally run as an open resolver.

Then open `https://<your-app-domain>/health`; it should return JSON with `"version":"1.5.0"`.

The `Dockerfile` is included for platforms that build images directly. It pins Node 20 and runs as the non-root `node` user.

### CA bundle and startup script

`start.sh` exports the Mozilla CA bundle before starting the relay:

- `SSL_CERT_FILE=$DIR/certs/cacert.pem`
- `NODE_EXTRA_CA_CERTS=$DIR/certs/cacert.pem`

`certs/cacert.pem` is the Mozilla root bundle from <https://curl.se/ca/cacert.pem> (extracted 2026-10-20, 118 certificates). This is the trust store for the relay's outbound HTTPS requests to Quad9 and Google. If the Infrlo run command is `node server.js`, the script is skipped; use `sh start.sh` instead. The Dockerfile bakes the same environment into the image.

### Environment variables

| Name | Default | Meaning |
| --- | --- | --- |
| `DOH_TOKEN` | **required** | Secret path segment. The DoH URL is `/<DOH_TOKEN>/<DOH_SUFFIX>`. Never commit it to the repo. |
| `DOH_SUFFIX` | `weduolijia` | Last path segment; must be a single path segment. |
| `DOH_ECS` | `111.8.1.0/24` | Fixed IPv4 ECS injected into every upstream query (Hunan Mobile, Changsha). `off` disables injection and passes the client's own ECS through. |
| `DOH_UPSTREAMS` | Quad9 dns11, Google | Comma-separated DoH URLs; all queried in parallel. |
| `RATE_LIMIT_PER_MIN` | `600` | Per-IP requests per minute. `0` disables the limiter. |
| `UPSTREAM_TIMEOUT_MS` | `3000` | Per-upstream timeout before trying the next one. |

Use a URL-safe token (letters, digits, `-`, `_`). If it contains characters that are special in a URL, percent-encode them in the path.

## Upstreams and ECS behavior

Default set: **Quad9 dns11 + Google**, raced in parallel over HTTP/2.

| Upstream | URL | ECS behavior (tested 2026-11-03) |
| --- | --- | --- |
| Quad9 dns11 | `https://dns11.quad9.net/dns-query` | Accepts and uses ECS; usually does not echo the option. Returns mainland China Mobile addresses for Hunan/Beijing ECS. Requires HTTP/2. |
| Google Public DNS | `https://dns.google/dns-query` | Google documents ECS support, but this network cannot reach Google; verify after deployment. |

AdGuard unfiltered is no longer a default. It echoes ECS with `scope=24`, but for several mainland domains it returned Hong Kong CDN addresses even with a mainland ECS; add it via `DOH_UPSTREAMS` only if you prefer its non-filtering behavior over China routing.

Racing optimizes latency, not ECS quality: whichever upstream answers first wins. If Google answers first without honoring ECS, the result may not be a Hunan Mobile address. For consistent ECS results, set `DOH_UPSTREAMS` to Quad9 dns11 only.

The default ECS is `111.8.1.0/24` (Hunan Mobile, Changsha, AS56047). Change it with `DOH_ECS`, for example `221.176.1.0/24` (Beijing Mobile) or `120.196.1.0/24` (Shanghai Mobile). Use `DOH_ECS=off` if you want the client's own ECS to pass through untouched.

The relay replaces any ECS the client sent; it does not merge options. Other EDNS options (including the DNSSEC DO bit) are preserved.

## Use with mihomo

```yaml
dns:
  enable: true
  nameserver:
    - https://<your-app-domain>/<DOH_TOKEN>/weduolijia
```

The relay is stateless, so it can also be used by any other RFC 8484 client.

## Test it

```bash
# health
curl -sS https://<your-app-domain>/health

# a real query: example.com A, base64url-encoded wire message
curl -sS 'https://<your-app-domain>/<DOH_TOKEN>/weduolijia?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' -o answer.bin
```

`answer.bin` is a raw DNS response. To check it without extra tools:

```bash
node -e "console.log(require('fs').readFileSync('answer.bin').toString('hex'))"
```

## Run and test locally

```bash
DOH_TOKEN=dev-token sh start.sh   # listens on 127.0.0.1:5000
npm test                         # hermetic tests; local HTTP/1.1 and HTTP/2 mocks play the upstream
```

The tests do not need internet access. The relay accepts `http://` and `http2://` upstreams only for local testing; production upstreams should be `https://`.

## Notes

- The relay does not cache. DNS caching stays with the client, which is what you want for a resolver path.
- Request logs contain method, path, status and latency only. The token path segment is logged as `[redacted]`; query names are never logged.
- All configured upstreams are raced in parallel. The first useful answer (NOERROR or NXDOMAIN) wins; the losing requests are canceled. SERVFAIL, REFUSED, and FORMERR responses are kept only as a fallback when no upstream produces a useful answer.
- The upstream answer must echo the query ID and have the QR bit set; otherwise it is ignored by the race.
- HTTPS upstreams use HTTP/2. Quad9 rejects HTTP/1.1 with 505, which is why HTTP/2 is not optional here.
