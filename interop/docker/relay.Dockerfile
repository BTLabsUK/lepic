# The public Epicbox relay (EpicCash/epic-epicbox-docker): its Node.js server and its epicboxlib
# signature checker. Same runtime as the relay's own Dockerfile; the checker is compiled by
# build.sh so its build cache stays in interop/.work.
# debian:bookworm-slim, pinned by digest.
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        ca-certificates \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY package.json package-lock.json app_mongo.js ./
COPY default_config.json ./config.json
RUN npm ci --omit=dev --no-audit --no-fund

# Upstream listens on every interface; here the relay shares one network namespace with the
# wallets, so loopback is enough. The grep fails the build if upstream changes the line.
RUN sed -i "s|server.listen(config.localepicboxserviceport);|server.listen(config.localepicboxserviceport, '127.0.0.1');|" app_mongo.js \
    && grep -q "server.listen(config.localepicboxserviceport, '127.0.0.1');" app_mongo.js

COPY --from=bin epicboxlib ./epicboxlib

RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin relay
USER relay

CMD ["node", "app_mongo.js"]
