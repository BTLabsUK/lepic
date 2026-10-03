# One image for the node, the miner, both reference wallets and lepic. The binaries come from
# build.sh, compiled on the same Debian release as this base.
# debian:bookworm-slim, pinned by digest.
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        libncursesw6 \
        libsqlite3-0 \
        libssl3 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY epic epic-wallet lepic miner /usr/local/bin/
COPY foundation_floonet.json /usr/share/epic/foundation_floonet.json
COPY --from=scripts node.sh wallet.sh /usr/local/bin/
COPY --from=scripts ew.sh /usr/local/bin/ew
RUN chmod 0755 /usr/local/bin/node.sh /usr/local/bin/wallet.sh /usr/local/bin/ew

# Named volumes take the owner of the directory they are mounted on from the image, so the
# mount points exist here, owned by the user every service runs as.
RUN useradd --uid 10001 --user-group --home-dir /data --no-create-home --shell /usr/sbin/nologin interop \
    && mkdir -p /data/node /node /exchange \
    && chown interop:interop /data /data/node /node /exchange
USER interop

# epic-wallet prints its tables only to a terminal it can describe.
ENV HOME=/data TERM=xterm-256color
WORKDIR /data
