# infrlo-doh-relay

v1.2.0 — a dependency-free [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) DNS-over-HTTPS relay, made for [Infrlo](https://infrlo.com/).

It accepts DoH queries on `/dns-query`, injects a fixed EDNS Client Subnet (ECS) into every upstream query, forwards the DNS wire message over HTTP/2, and returns the answer unchanged. No cache, no query logging, no npm dependencies.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/dns-query` | DoH query body (`content-type: application/dns-message`) |
| `GET` | `/dns-query?dns=<base64url>` | DoH query in the URL |
| `POST` | `/dns-query/<token>` | Same as above, token in the path (when `DOH_TOKEN` is set) |
| `GET` | `/health` | Version, uptime, upstream count, auth and ECS state |

The server listens on `0.0.0.0:5000` (`PORT` overrides), which is what Infrlo expects.

## Deploy on Infrlo

In the Infrlo dashboard, **Deploy → From Public URL** and use:

| Field | Value |
| --- | --- |
| Repository URL | `https://github.com/weduolijia/infrlo-doh-relay` |
| Branch | `main` |
| Build command | `npm install` |
| Run command | `node server.js` |

Then open `https://<your-app-domain>/health`; it should return JSON with `"version":"1.2.0"`.

The `Dockerfile` is included for platforms that build images directly. It pins Node 20 and runs as the non-root `node` user.

### Environment variables

Set these in the Infrlo deploy form (or the app's environment settings) if available:

| Name | Default | Meaning |
| --- | --- | --- |
| `DOH_TOKEN` | empty | When set, `/dns-query` requires `?token=<value>` or `/dns-query/<value>`. Use this for a private endpoint. |
| `DOH_ECS` | `221.176.1.0/24` | Fixed IPv4 ECS injected into every upstream query. `off` disables injection and passes the client's own ECS through. |
| `DOH_UPSTREAMS` | AdGuard unfiltered, Quad9 dns11, Google | Comma-separated DoH URLs, tried in order. The first success becomes preferred. |
| `RATE_LIMIT_PER_MIN` | `600` | Per-IP requests per minute. `0` disables the limiter. |
| `UPSTREAM_TIMEOUT_MS` | `3000` | Per-upstream timeout before trying the next one. |

Without `DOH_TOKEN`, anyone who knows the URL can use the relay. Set a token if the app domain will be shared.

## Upstreams and ECS behavior

Default order: **AdGuard unfiltered → Quad9 dns11 → Google**. All three are queried over HTTP/2.

| Upstream | URL | ECS behavior (tested 2026-11-03) |
| --- | --- | --- |
| AdGuard non-filtering | `https://unfiltered.adguard-dns.com/dns-query` | Accepts and uses ECS; echoes the option with `scope=24`. Answers change with the subnet. |
| Quad9 dns11 | `https://dns11.quad9.net/dns-query` | Accepts and uses ECS; usually does not echo the option. Answers change with the subnet. Requires HTTP/2. |
| Google Public DNS | `https://dns.google/dns-query` | Google documents ECS support, but this network cannot reach Google; verify after deployment. |

The default ECS is `221.176.1.0/24` (China Mobile, Beijing, AS9808). Change it to another China Mobile segment with `DOH_ECS`, for example `120.196.1.0/24` (China Mobile Shanghai). Use `DOH_ECS=off` if you want the client's own ECS to pass through untouched.

The relay replaces any ECS the client sent; it does not merge options. Other EDNS options (including the DNSSEC DO bit) are preserved.

## Use with mihomo

```yaml
dns:
  enable: true
  nameserver:
    - https://<your-app-domain>/dns-query
    # with DOH_TOKEN set:
    # - https://<your-app-domain>/dns-query?token=<DOH_TOKEN>
```

The relay is stateless, so it can also be used by any other RFC 8484 client.

## Test it

```bash
# health
curl -sS https://<your-app-domain>/health

# a real query: example.com A, base64url-encoded wire message
curl -sS 'https://<your-app-domain>/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE' -o answer.bin
```

`answer.bin` is a raw DNS response. To check it without extra tools:

```bash
node -e "console.log(require('fs').readFileSync('answer.bin').toString('hex'))"
```

## Run and test locally

```bash
npm start        # listens on 127.0.0.1:5000
npm test         # hermetic tests; local HTTP/1.1 and HTTP/2 mocks play the upstream
```

The tests do not need internet access. The relay accepts `http://` and `http2://` upstreams only for local testing; production upstreams should be `https://`.

## Notes

- The relay does not cache. DNS caching stays with the client, which is what you want for a resolver path.
- Request logs contain method, path, status and latency only. Query names and tokens are never logged.
- The upstream answer must echo the query ID and have the QR bit set; otherwise the next upstream is tried.
- A successful upstream becomes the preferred one for the next request, so a healthy resolver is not re-probed on every query.
- HTTPS upstreams use HTTP/2. Quad9 rejects HTTP/1.1 with 505, which is why HTTP/2 is not optional here.
