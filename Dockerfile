FROM node:20-alpine

LABEL org.opencontainers.image.title="infrlo-doh-relay" \
      org.opencontainers.image.version="1.3.0"

WORKDIR /app
COPY --chown=node:node package.json server.js ./
COPY --chown=node:node lib ./lib

ENV PORT=5000
EXPOSE 5000
USER node

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:5000/health >/dev/null || exit 1

CMD ["node", "server.js"]
