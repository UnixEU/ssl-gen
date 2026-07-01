FROM node:22-alpine

RUN apk add --no-cache openssl

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY server.js ./
COPY lib ./lib
COPY public ./public
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENV PROJECT_ROOT=/project
ENV WEBUI_INTERNAL_PORT=8443

EXPOSE 8443

ENTRYPOINT ["/entrypoint.sh"]