# tcpdump for the interop gate's frame capture: it shares the node's network namespace and writes
# what crosses loopback on the relay and HTTP listener ports to /capture. The binary gets
# cap_net_raw as a file capability, so it runs as a plain user.
# debian:bookworm-slim, pinned by digest, as the runtime image.
FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        libcap2-bin \
        tcpdump \
    && setcap cap_net_raw=eip "$(command -v tcpdump)" \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --user-group --home-dir /capture --no-create-home --shell /usr/sbin/nologin capture \
    && mkdir -p /capture \
    && chown capture:capture /capture
USER capture
WORKDIR /capture
