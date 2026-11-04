#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds what the live floonet stack runs. ../build.sh compiles the pinned reference wallet, the
# relay's checker and lepic (and the reference node, which the live stack does not run); this
# script adds the live miner and stages the binaries the runtime image copies in
# ../.work/live/bin. Rerunning it is incremental.
set -euo pipefail

live_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
interop_dir="$(cd "${live_dir}/.." && pwd)"
repo_dir="$(cd "${interop_dir}/.." && pwd)"
work_dir="${interop_dir}/.work"
# shellcheck source=../pins.env
source "${interop_dir}/pins.env"

# The same tag ../build.sh computes, so both use one builder image.
builder_image="lepic-interop-builder:$({
    cat "${interop_dir}/docker/builder.Dockerfile"
    echo "${REFERENCE_RUST} ${NODE_RUST} ${LEPIC_RUST}"
} | sha256sum | cut -c1-12)"

log() { printf '[live-build] %s\n' "$*" >&2; }

miner_cargo() {
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/work/home \
        -e RUSTUP_TOOLCHAIN="${NODE_RUST}" \
        -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
        -e CARGO_TARGET_DIR=/work/target/live-miner \
        -e CARGO_TERM_COLOR=never \
        -v "${work_dir}:/work" \
        -v "${repo_dir}:/repo:ro" \
        -w /repo/interop/live/miner \
        "${builder_image}" \
        cargo "$@"
}

"${interop_dir}/build.sh"

log "checking and compiling the live miner"
miner_cargo fmt --check
miner_cargo clippy --release --locked -- -D warnings
miner_cargo build --release --locked

bin="${work_dir}/live/bin"
mkdir -p "${bin}"
for file in epic-wallet lepic; do
    install -m 0755 "${work_dir}/bin/${file}" "${bin}/${file}"
done
install -m 0755 "${work_dir}/target/live-miner/release/lepic-live-miner" "${bin}/miner"
log "binaries are in ${bin}"
