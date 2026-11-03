#!/bin/sh
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Mozilla CA bundle for outbound TLS trust (AdGuard/Quad9/Google).
if [ -f "$DIR/certs/cacert.pem" ]; then
  export SSL_CERT_FILE="$DIR/certs/cacert.pem"
  export NODE_EXTRA_CA_CERTS="$DIR/certs/cacert.pem"
fi

exec node server.js