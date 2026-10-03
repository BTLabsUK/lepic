# Compiles the reference node, the reference wallet, the relay's signature checker and lepic.
# Sources, CARGO_HOME and target directories are bind-mounted from interop/.work, so the image
# holds only toolchains and system packages, and build caches stay on the host.
# rust:1.89.0-bookworm, pinned by digest. build.sh checks the tag against REFERENCE_RUST.
FROM rust:1.89.0-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff

ARG LEPIC_RUST=1.99.0

# The node and wallet build RandomX and secp256k1-zkp from C and C++, and bindgen needs libclang.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        clang \
        cmake \
        libclang-dev \
        libncursesw5-dev \
        libssl-dev \
        llvm-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Clippy and rustfmt check the interop miner, which builds with the reference toolchain.
RUN rustup component add clippy rustfmt \
    && rustup toolchain install "${LEPIC_RUST}" --profile minimal \
    && chmod -R a+rwX "${RUSTUP_HOME}"

ENV CARGO_HOME=/work/cargo

# build.sh runs every container as the invoking user; nothing needs root after this point.
USER 65534:65534
