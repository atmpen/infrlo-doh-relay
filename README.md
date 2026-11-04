# infrlo-doh-relay

v1.8.0 — a dependency-free [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) DNS-over-HTTPS relay, made for [Infrlo](https://infrlo.com/).

It accepts DoH queries on `/<DOH_TOKEN>/weduolijia`, applies the configured ECS policy (inject a fixed subnet, or pass the client's own ECS through), forwards the DNS wire message over HTTP/2, and returns the answer unchanged. The root URL serves a live status dashboard. No cache, no query logging, no npm dependencies.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/<DOH_TOKEN>/weduolijia` | DoH query body (`content-type: application/dns-message`) |
| `GET` | `/<DOH_TOKEN>/weduolijia?dns=<base64url>` | DoH query in the URL |
| `GET` | `/` | Status page HTML with a password gate (public HTML, data locked) |
| `POST` | `/api/unlock` | Exchange the homepage password for a session cookie |
| `GET` | `/api/status` | Dashboard JSON (session cookie required) |
| `POST` | `/api/reveal` | Validate the DoH token (session cookie required) |
| `POST` | `/api/config/ecs` | Switch ECS mode and change the custom subnet (session cookie required) |
| `POST` | `/api/lock` | Clear the session |
| `GET` | `/health` | Minimal JSON for monitoring (public) |

The token is a path segment and is checked **before** rate limiting, DNS parsing, ECS injection, or any upstream request. There is no `/dns-query` alias; the suffix is controlled by `DOH_SUFFIX` and defaults to `weduolijia`.

The server listens on `0.0.0.0:5000` (`PORT` overrides), which is what Infrlo expects.

## Web UI

Open `https://<your-app-domain>/`. The page is in Chinese and starts with a password gate:

- `WEB_PASSWORD` (defaults to `DOH_TOKEN`) unlocks the dashboard for 12 hours with an HttpOnly, SameSite=Strict session cookie.
- The dashboard shows version, uptime, Node runtime, memory, DoH request/success counters, ECS, rate limit, and per-upstream attempts/wins/errors/last RTT/last rcode.
- The DNS endpoint is displayed with the token masked: `https://<app-domain>/••••••••/weduolijia`.
- Clicking 复制 opens a DoH token prompt. The server validates the token; on success the browser copies the full URL to the clipboard, on failure it shows a warning.
- The ECS card shows either the injected subnet or 透传, with an 编辑 button. The editor has a mode selector:
  - 自定义 ECS — inject the IPv4 CIDR shown in the input (for example `111.8.1.0/24`). The relay replaces any ECS the client sent.
  - 透传客户端 ECS — do not inject anything; a client-supplied ECS reaches the upstream unchanged, and a query without ECS stays without one.

  The change applies to subsequent queries immediately. When `ECS_FILE` is writable, it is persisted there and takes precedence over `DOH_ECS`/`ECS_MODE` on restart.
- A dark/light theme toggle is persisted in `localStorage`; 锁定 clears the session.

`/api/status`, `/api/reveal`, and `/api/config/ecs` require the session cookie; `/api/reveal` additionally requires the correct DoH token. `/health` stays public for monitoring and contains no secrets.

## Deploy on Infrlo

In the Infrlo dashboard, **Deploy → From Public URL** and use:

| Field | Value |
| --- | --- |
| Repository URL | `https://github.com/weduolijia/infrlo-doh-relay` |
| Branch | `main` |
| Build command | `npm install` |
| Run command | `sh start.sh` |

Set `DOH_TOKEN` to your secret in the environment variables section. **The relay refuses to start without it** — this is deliberate, so it cannot accidentally run as an open resolver. Optionally set `WEB_PASSWORD` to use a different password for the dashboard; if omitted, the homepage password is the DoH token.

Then open `https://<your-app-domain>/health`; it should return JSON with `"version":"1.8.0"`.

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
| `WEB_PASSWORD` | `DOH_TOKEN` | Homepage password. Set a separate value if the dashboard password should differ from the DoH token. |
| `DOH_SUFFIX` | `weduolijia` | Last path segment; must be a single path segment. |
| `ECS_MODE` | `custom` | `custom` injects `DOH_ECS`; `passthrough` forwards the client's own ECS untouched. |
| `DOH_ECS` | `111.8.1.0/24` | IPv4 ECS used in `custom` mode (Hunan Mobile, Changsha). The legacy value `off` selects `passthrough`. The dashboard can override both at runtime. |
| `ECS_FILE` | `data/ecs.txt` | File written by the dashboard's ECS editor as `{"mode":"custom","ecs":"…"}`. When present and readable, it takes precedence over `ECS_MODE`/`DOH_ECS` on restart. Legacy plain-text files (`<cidr>` or `off`) are still accepted. Set it to an empty string to disable persistence. |
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

The default ECS is `111.8.1.0/24` (Hunan Mobile, Changsha, AS56047). Change it with `DOH_ECS`, for example `221.176.1.0/24` (Beijing Mobile) or `120.196.1.0/24` (Shanghai Mobile). Set `ECS_MODE=passthrough` (or the legacy `DOH_ECS=off`) to forward the client's own ECS untouched.

In `custom` mode the relay replaces any ECS the client sent and preserves other EDNS options (including the DNSSEC DO bit). In `passthrough` mode the query is forwarded exactly as received.

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
