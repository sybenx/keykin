# Keykin Login as a container: the public door and the account page. It holds no piece and no admin code.
# Built from the repo root:
#   docker build -f deploy/Dockerfile.login -t keykin-login .
FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY login ./login
ENV KEYKIN_LOGIN_ADDR=0.0.0.0 KEYKIN_LOGIN_PORT=7470
USER 1000:1000
EXPOSE 7470
CMD ["node", "login/server.ts"]
