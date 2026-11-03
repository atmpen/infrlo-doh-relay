FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
ENV PORT=5000
EXPOSE 5000
CMD ["node", "server.js"]
