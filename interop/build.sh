#!/usr/bin/env bash
# Fetches the pinned upstream sources and compiles every binary the interop stack runs:
# the reference node, the reference wallet, the relay's signature checker, the interop miner
# and lepic. Everything it writes goes under interop/.work. Rerunning it is incremental.
set -euo pipefail

interop_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${interop_dir}/.." && pwd)"
work_dir="${interop_dir}/.work"
# shellcheck source=pins.env
source "${interop_dir}/pins.env"

# The tag changes with the Dockerfile and the toolchains, so a change rebuilds the image.
builder_image="lepic-interop-builder:$({
    cat "${interop_dir}/docker/builder.Dockerfile"
    echo "${REFERENCE_RUST} ${LEPIC_RUST}"
} | sha256sum | cut -c1-12)"
jobs="${CARGO_BUILD_JOBS:-4}"

log() { printf '[build] %s\n' "$*" >&2; }

# Clones one commit into a directory, or checks that an existing clone is at that commit.
fetch_commit() {
    local url="$1" commit="$2" dir="$3"
    if [[ ! -d "${dir}/.git" ]]; then
        log "fetching ${url} at ${commit}"
        git init -q "${dir}"
        git -C "${dir}" remote add origin "${url}"
    fi
    if [[ "$(git -C "${dir}" rev-parse -q --verify HEAD 2>/dev/null)" != "${commit}" ]]; then
        git -C "${dir}" fetch -q --depth 1 origin "${commit}"
        git -C "${dir}" -c advice.detachedHead=false checkout -q --force "${commit}"
    fi
    local head
    head="$(git -C "${dir}" rev-parse HEAD)"
    if [[ "${head}" != "${commit}" ]]; then
        log "${dir} is at ${head}, expected ${commit}"
        exit 1
    fi
}

fetch_sources() {
    mkdir -p "${work_dir}/src"
    fetch_commit "${EPIC_REPO}" "${EPIC_COMMIT}" "${work_dir}/src/epic"
    fetch_commit "${EPIC_WALLET_REPO}" "${EPIC_WALLET_COMMIT}" "${work_dir}/src/epic-wallet"
    fetch_commit "${EPICBOX_REPO}" "${EPICBOX_COMMIT}" "${work_dir}/src/epic-epicbox-docker"

    # The relay records the epic-wallet commit its checker links against as a submodule.
    local relay="${work_dir}/src/epic-epicbox-docker"
    local sub_path=epicboxlib_source/epic-wallet
    local sub_commit sub_url
    sub_commit="$(git -C "${relay}" ls-tree HEAD "${sub_path}" | awk '{print $3}')"
    sub_url="$(git -C "${relay}" config -f .gitmodules "submodule.${sub_path}.url")"
    fetch_commit "${sub_url}" "${sub_commit}" "${relay}/${sub_path}"
}

build_builder_image() {
    # The base image is pinned by digest, so its tag must name the reference toolchain.
    if ! grep -q "^FROM rust:${REFERENCE_RUST}-bookworm@sha256:" "${interop_dir}/docker/builder.Dockerfile"; then
        log "builder.Dockerfile does not build on rust:${REFERENCE_RUST}-bookworm"
        exit 1
    fi
    if docker image inspect "${builder_image}" >/dev/null 2>&1; then
        return
    fi
    log "building ${builder_image}"
    docker build -q \
        --build-arg "LEPIC_RUST=${LEPIC_RUST}" \
        -t "${builder_image}" \
        -f "${interop_dir}/docker/builder.Dockerfile" \
        "${interop_dir}/docker" >/dev/null
}

# Runs one cargo command in the builder container as the invoking user.
cargo_in_builder() {
    local toolchain="$1" source_dir="$2" target="$3"
    shift 3
    mkdir -p "${work_dir}/cargo" "${work_dir}/target/${target}" "${work_dir}/home"
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/work/home \
        -e RUSTUP_TOOLCHAIN="${toolchain}" \
        -e CARGO_BUILD_JOBS="${jobs}" \
        -e CARGO_TARGET_DIR="/work/target/${target}" \
        -e CARGO_TERM_COLOR=never \
        -v "${work_dir}:/work" \
        -v "${repo_dir}:/repo:ro" \
        -w "${source_dir}" \
        "${builder_image}" \
        cargo "$@"
}

# Compiles a pinned upstream binary once. Its build directory is deleted afterwards: the
# binary never changes for a pinned commit, and the directory is several gigabytes.
build_pinned() {
    local name="$1" source_dir="$2" commit="$3" binary="$4"
    local stamp="${work_dir}/bin/${binary}.commit"
    if [[ -x "${work_dir}/bin/${binary}" && "$(cat "${stamp}" 2>/dev/null)" == "${commit}" ]]; then
        return
    fi
    log "compiling ${name}"
    cargo_in_builder "${REFERENCE_RUST}" "${source_dir}" "${binary}" build --release --locked
    install -m 0755 "${work_dir}/target/${binary}/release/${binary}" "${work_dir}/bin/${binary}"
    echo "${commit}" >"${stamp}"
    rm -rf "${work_dir}/target/${binary}"
}

build_binaries() {
    mkdir -p "${work_dir}/bin"
    build_pinned "epic ${EPIC_TAG}" /work/src/epic "${EPIC_COMMIT}" epic
    build_pinned "epic-wallet ${EPIC_WALLET_TAG}" /work/src/epic-wallet "${EPIC_WALLET_COMMIT}" epic-wallet
    build_pinned "the relay's epicboxlib" /work/src/epic-epicbox-docker/epicboxlib_source \
        "${EPICBOX_COMMIT}" epicboxlib
    install -m 0644 "${work_dir}/src/epic/debian/foundation_floonet.json" \
        "${work_dir}/bin/foundation_floonet.json"

    log "checking and compiling the interop miner"
    cargo_in_builder "${REFERENCE_RUST}" /repo/interop/miner miner fmt --check
    cargo_in_builder "${REFERENCE_RUST}" /repo/interop/miner miner \
        clippy --release --locked -- -D warnings
    cargo_in_builder "${REFERENCE_RUST}" /repo/interop/miner miner build --release --locked
    install -m 0755 "${work_dir}/target/miner/release/lepic-interop-miner" "${work_dir}/bin/miner"

    log "compiling lepic"
    cargo_in_builder "${LEPIC_RUST}" /repo lepic build --release --locked -p lepic-cli --bin lepic
    install -m 0755 "${work_dir}/target/lepic/release/lepic" "${work_dir}/bin/lepic"
}

main() {
    fetch_sources
    build_builder_image
    build_binaries
    log "binaries are in ${work_dir}/bin"
}

main "$@"
