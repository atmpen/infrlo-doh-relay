# infrlo-doh-relay

v1.1.1 — a dependency-free [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) DNS-over-HTTPS relay, made for [Infrlo](https://infrlo.com/).

It accepts DoH queries on `/dns-query`, forwards the raw DNS wire message to an upstream DoH resolver, and returns the answer unchanged. No cache, no query logging, no npm dependencies.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/dns-query` | DoH query body (`content-type: application/dns-message`) |
| `GET` | `/dns-query?dns=<base64url>` | DoH query in the URL |
| `POST` | `/dns-query/<token>` | Same as above, token in the path (when `DOH_TOKEN` is set) |
| `GET` | `/health` | Version, uptime, upstream count, whether auth is on |

The server listens on `0.0.0.0:5000` (`PORT` overrides), which is what Infrlo expects.

## Deploy on Infrlo

In the Infrlo dashboard, **Deploy → From Public URL** and use:

| Field | Value |
| --- | --- |
| Repository URL | `https://github.com/weduolijia/infrlo-doh-relay` |
| Branch | `main` |
| Build command | `npm install` |
| Run command | `node server.js` |

Then open `https://<your-app-domain>/health`; it should return JSON with `"version":"1.1.1"`.

The `Dockerfile` is included for platforms that build images directly. It pins Node 20 and runs as the non-root `node` user.

### Optional environment variables

Set these in the Infrlo deploy form (or the app's environment settings) if available:

| Name | Default | Meaning |
| --- | --- | --- |
| `DOH_TOKEN` | empty | When set, `/dns-query` requires `?token=<value>` or `/dns-query/<value>`. Use this for a private endpoint. |
| `DOH_UPSTREAMS` | Cloudflare, Google | Comma-separated DoH URLs, tried in order. |
| `RATE_LIMIT_PER_MIN` | `600` | Per-IP requests per minute. `0` disables the limiter. |
| `UPSTREAM_TIMEOUT_MS` | `5000` | Per-upstream timeout before trying the next one. |

Without `DOH_TOKEN`, anyone who knows the URL can use the relay. Set a token if the app domain will be shared.

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
npm test         # hermetic tests; a local mock plays the upstream
```

The tests use a local HTTP mock upstream, so they do not need internet access. The relay accepts `http://` upstreams only for local testing; production upstreams should be `https://`.

## Notes

- The relay does not cache. DNS caching stays with the client, which is what you want for a resolver path.
- Request logs contain method, path, status and latency only. Query names and tokens are never logged.
- The upstream answer must echo the query ID and have the QR bit set; otherwise the next upstream is tried.
- A successful upstream becomes the preferred one for the next request, so a healthy resolver is not re-probed on every query.
