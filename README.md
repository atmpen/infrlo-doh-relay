# infrlo-doh-relay

v1.0.1 — minimal RFC 8484 DNS-over-HTTPS relay for Infrlo.

- Listens on `0.0.0.0:5000` (`PORT` overrides).
- `GET /dns-query?dns=<base64url>` and `POST /dns-query` (`application/dns-message`).
- Upstreams in order: Cloudflare DoH, then Google DoH.
- `GET /health` returns the version.

Deploy on Infrlo from this GitHub repo; the Dockerfile pins the runtime.
