# certs

`cacert.pem` is the Mozilla CA root bundle from <https://curl.se/ca/cacert.pem>.

- Extracted: 2026-10-20
- Certificates: 118
- Used by `start.sh` via `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`

Refresh it with:

```bash
curl -sS https://curl.se/ca/cacert.pem -o certs/cacert.pem
```