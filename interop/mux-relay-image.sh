#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the Epicmail relay image the acceptance stack uses with --mux-relay and writes its config:
#
#   mux-relay-image.sh <relay source dir> <image tag> <config file to write>
#
# The relay's own Dockerfile is a static musl build for x86_64. This builds it for the machine's own
# architecture instead (aarch64 on an Apple-silicon Mac) by changing the cargo target in a copy of the
# Dockerfile; the relay's sources and Dockerfile are not touched. The binary goes into a Debian image,
# because the stack's health check needs bash and the acceptance steps read the relay's SQLite store
# with sqlite3 (read-only) and its metrics page with bash. Then run.sh reads
#   ACCEPTANCE_MUX_RELAY_IMAGE=<image tag> ACCEPTANCE_MUX_RELAY_CONFIG=<config file>
set -euo pipefail

src="${1:?usage: mux-relay-image.sh <relay source dir> <image tag> <config file>}"
tag="${2:?image tag}"
config="${3:?config file}"

case "$(uname -m)" in
    arm64 | aarch64) arch=aarch64 ;;
    *) arch=x86_64 ;;
esac

sed "s/x86_64-unknown-linux-musl/${arch}-unknown-linux-musl/g" "${src}/Dockerfile" |
    docker build --quiet -t "${tag}-bin" -f - "${src}" >/dev/null
docker build --quiet -t "${tag}" - >/dev/null <<DOCKER
FROM ${tag}-bin AS bin
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends sqlite3 >/dev/null \\
    && rm -rf /var/lib/apt/lists/*
COPY --from=bin /usr/local/bin/epicmail /usr/local/bin/mux-relay
RUN mkdir /data && chown 65532:65532 /data
USER 65532:65532
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/mux-relay"]
DOCKER

mkdir -p "$(dirname "${config}")"
cat >"${config}" <<'TOML'
[server]
listen = "127.0.0.1:3423"
domain = "localhost"
port = 3423

[store]
path = "/data/epicmail.db"

[federation]
enabled = false

[log.file]
enabled = false
TOML
