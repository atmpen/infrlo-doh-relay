FROM node:20-alpine

LABEL org.opencontainers.image.title="infrlo-doh-relay" \
      org.opencontainers.image.version="1.9.0"

WORKDIR /app
COPY --chown=node:node package.json server.js ./
COPY --chown=node:node lib ./lib
COPY --chown=node:node public ./public
COPY --chown=node:node certs ./certs
COPY --chown=node:node start.sh ./

ENV PORT=5000 \
    SSL_CERT_FILE=/app/certs/cacert.pem \
    NODE_EXTRA_CA_CERTS=/app/certs/cacert.pem
EXPOSE 5000
USER node

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:5000/health >/dev/null || exit 1

CMD ["sh", "start.sh"]
