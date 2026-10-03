# One image for the node, the miner, both reference wallets and lepic. The binaries come from
# build.sh, compiled on the same Debian release as this base.
FROM debian:bookworm-slim

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

# epic-wallet prints its tables only to a terminal it can describe.
ENV HOME=/data TERM=xterm-256color
WORKDIR /data
