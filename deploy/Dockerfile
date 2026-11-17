# The Keykin box as a container. Built from the repo root:
#   docker build -f deploy/Dockerfile -t keykin-box .
FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY box ./box
COPY src ./src
COPY frost-wasm ./frost-wasm
COPY vendor ./vendor
COPY login ./login
ENV KEYKIN_DIR=/data KEYKIN_ADDR=0.0.0.0 KEYKIN_PORT=7460
USER 1000:1000
EXPOSE 7460
CMD ["node", "box/server.ts"]
