# Compiles the reference node, the reference wallet, the relay's signature checker and lepic.
# Sources, CARGO_HOME and target directories are bind-mounted from interop/.work, so the image
# holds only toolchains and system packages, and build caches stay on the host.
ARG REFERENCE_RUST=1.89.0
FROM rust:${REFERENCE_RUST}-bookworm

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
