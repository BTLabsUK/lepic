# One image for the node proxy, the live miner, both reference wallets and lepic; no node runs
# locally. The binaries come from build.sh, compiled on the same Debian release as this base.
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
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY epic-wallet lepic miner /usr/local/bin/
COPY --from=scripts wallet.sh node-proxy.py /usr/local/bin/
COPY --from=scripts ew.sh /usr/local/bin/ew
RUN chmod 0755 /usr/local/bin/wallet.sh /usr/local/bin/node-proxy.py /usr/local/bin/ew

# compose.yaml runs every service as the invoking user, so the bind-mounted wallet directories
# stay theirs; this user is the image's own default.
RUN useradd --uid 10001 --user-group --home-dir /data --no-create-home --shell /usr/sbin/nologin live \
    && mkdir -p /data /exchange \
    && chown live:live /data /exchange
USER live

# epic-wallet prints its tables only to a terminal it can describe.
ENV HOME=/data TERM=xterm-256color
WORKDIR /data
