#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fetches the pinned upstream sources and compiles every binary the interop stack runs:
# the reference node, the reference wallet, the legacy wallet, the relay's signature checker, the interop miner
# and lepic (with and without the floonet harness).
#
# Every binary is built once and kept in a cache shared by all checkouts of this machine, keyed by what it is built
# from: a pinned upstream binary by its commit and toolchain, the miner by its sources, lepic by the content of the
# files it compiles. A checkout that asks for a binary already in the cache copies it into interop/.work/bin and
# compiles nothing. The cache lives in LEPIC_BUILD_CACHE (default ~/.cache/lepic-build); it holds
#   store/<key>/    finished binaries, one directory per key
#   work/           the pinned sources, the Cargo home and the cargo target directories the builder container mounts
#   locks/          one lock per build target, so two checkouts never compile the same thing twice
#
#   ./build.sh            build what the cache lacks, copy everything into .work/bin
#   ./build.sh --status   list the cache entries and what this checkout would use
#   ./build.sh --no-lepic build only what the stack runs (interop/on-mac.sh: the host builds lepic itself)
#   ./build.sh --prune    drop old entries (LEPIC_BUILD_KEEP newest per kind, default 3) and stale staging directories
set -euo pipefail
shopt -s nullglob

interop_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${interop_dir}/.." && pwd)"
work_dir="${interop_dir}/.work"
cache_root="${LEPIC_BUILD_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/lepic-build}"
store_dir="${cache_root}/store"
shared_work="${cache_root}/work"
lock_dir="${cache_root}/locks"
keep="${LEPIC_BUILD_KEEP:-3}"
# A cargo target directory that grows past this is deleted before its next build, so stale artefacts of old commits
# cannot fill the disk.
target_max_gb="${LEPIC_BUILD_TARGET_MAX_GB:-20}"
# shellcheck source=pins.env
source "${interop_dir}/pins.env"
# shellcheck source=portable.sh
source "${interop_dir}/portable.sh"

# The tag changes with the Dockerfile and the toolchains, so a change rebuilds the image.
builder_image="lepic-interop-builder:$({
    cat "${interop_dir}/docker/builder.Dockerfile"
    echo "${REFERENCE_RUST} ${NODE_RUST} ${LEPIC_RUST}"
} | "${SHA256[@]}" | cut -c1-12)"
builder_tag="${builder_image##*:}"
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

# Clones the relay's sources and the submodule its signature checker links against. The directory is named by the
# commit, so checkouts on different pins never fight over one clone.
relay_src_dir() { echo "${shared_work}/src/epic-epicbox-docker-${EPICBOX_COMMIT:0:12}"; }

fetch_relay_source() {
    local relay
    relay="$(relay_src_dir)"
    mkdir -p "${shared_work}/src"
    fetch_commit "${EPICBOX_REPO}" "${EPICBOX_COMMIT}" "${relay}"
    # The relay records the epic-wallet commit its checker links against as a submodule.
    local sub_path=epicboxlib_source/epic-wallet
    local sub_commit sub_url
    sub_commit="$(git -C "${relay}" ls-tree HEAD "${sub_path}" | awk '{print $3}')"
    sub_url="$(git -C "${relay}" config -f .gitmodules "submodule.${sub_path}.url")"
    fetch_commit "${sub_url}" "${sub_commit}" "${relay}/${sub_path}"
}

# Fetches the sources of one pinned upstream binary and prints its directory name under work/src.
fetch_pinned_source() {
    local name="$1" url="$2" commit="$3"
    mkdir -p "${shared_work}/src"
    fetch_commit "${url}" "${commit}" "${shared_work}/src/${name}-${commit:0:12}"
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
        --build-arg "NODE_RUST=${NODE_RUST}" \
        --build-arg "LEPIC_RUST=${LEPIC_RUST}" \
        -t "${builder_image}" \
        -f "${interop_dir}/docker/builder.Dockerfile" \
        "${interop_dir}/docker" >/dev/null
}

# Runs one cargo command in the builder container as the invoking user.
cargo_in_builder() {
    local toolchain="$1" source_dir="$2" target="$3"
    shift 3
    mkdir -p "${shared_work}/cargo" "${shared_work}/target/${target}" "${shared_work}/home"
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/work/home \
        -e RUSTUP_TOOLCHAIN="${toolchain}" \
        -e CARGO_BUILD_JOBS="${jobs}" \
        -e CARGO_TARGET_DIR="/work/target/${target}" \
        -e CARGO_TERM_COLOR=never \
        -v "${shared_work}:/work" \
        -v "${repo_dir}:/repo:ro" \
        -w "${source_dir}" \
        "${builder_image}" \
        cargo "$@"
}

# Deletes a cargo target directory that has grown past the limit.
cap_target() {
    local dir="${shared_work}/target/$1" kb
    [[ -d "${dir}" ]] || return 0
    kb="$(du -sk "${dir}" | awk '{print $1}')"
    if ((kb > target_max_gb * 1024 * 1024)); then
        log "target/$1 is $((kb / 1024 / 1024)) GB, over ${target_max_gb} GB: starting it again"
        rm -rf "${dir}"
    fi
}

# --- the store ---------------------------------------------------------------------------------------------------

entry_dir() { echo "${store_dir}/$1"; }
have_entry() { [[ -f "$(entry_dir "$1")/.complete" ]]; }

# Marks an entry as used now, so --prune keeps the ones in use.
touch_entry() { touch "$(entry_dir "$1")/.complete"; }

# Runs a command with the lock of one build target held.
with_lock() {
    local name="$1"
    shift
    mkdir -p "${lock_dir}"
    lock_run "${lock_dir}/${name}.lock" "$@"
}

# publish_entry KEY STAGE: a finished staging directory becomes the entry, in one rename.
publish_entry() {
    local key="$1" stage="$2" final
    final="$(entry_dir "${key}")"
    touch "${stage}/.complete"
    rm -rf "${final}"
    mv "${stage}" "${final}"
}

new_stage() {
    local stage="${store_dir}/.stage-$1.$$"
    rm -rf "${stage}"
    mkdir -p "${stage}"
    echo "${stage}"
}

# --- the entries --------------------------------------------------------------------------------------------------

# A pinned upstream binary, compiled once with the toolchain its source pins. Its build directory is deleted
# afterwards: the binary never changes for a pinned commit, and the directory is several gigabytes.
_build_pinned() {
    local key="$1" label="$2" toolchain="$3" name="$4" url="$5" commit="$6" binary="$7" built="$8" subdir="$9"
    if have_entry "${key}"; then
        return
    fi
    build_builder_image
    local source_dir=/work/src/${name}-${commit:0:12}
    if [[ "${name}" == epic-epicbox-docker ]]; then
        fetch_relay_source
    else
        fetch_pinned_source "${name}" "${url}" "${commit}"
    fi
    log "compiling ${label}"
    cargo_in_builder "${toolchain}" "${source_dir}${subdir}" "${binary}" build --release --locked
    local stage
    stage="$(new_stage "${key}")"
    install -m 0755 "${shared_work}/target/${binary}/release/${built}" "${stage}/${binary}"
    if [[ "${binary}" == epic ]]; then
        install -m 0644 "${shared_work}/src/${name}-${commit:0:12}/debian/foundation_floonet.json" \
            "${stage}/foundation_floonet.json"
    fi
    publish_entry "${key}" "${stage}"
    rm -rf "${shared_work}/target/${binary}"
}

ensure_pinned() {
    local label="$1" toolchain="$2" name="$3" url="$4" commit="$5" binary="$6" built="${7:-$6}" subdir="${8:-}"
    local key="${binary}-${commit:0:12}-${builder_tag}"
    if ! have_entry "${key}"; then
        with_lock "target-${binary}" _build_pinned "${key}" "${label}" "${toolchain}" "${name}" "${url}" "${commit}" \
            "${binary}" "${built}" "${subdir}"
    fi
    touch_entry "${key}"
    use_entry "${key}" "${binary}"
    [[ "${binary}" != epic ]] || use_entry "${key}" foundation_floonet.json
}

# Copies one file of an entry into .work/bin, unless it is already there unchanged.
use_entry() {
    local key="$1" file="$2" from to
    from="$(entry_dir "${key}")/${file}"
    to="${work_dir}/bin/${file}"
    mkdir -p "${work_dir}/bin"
    if ! cmp -s "${from}" "${to}" 2>/dev/null; then
        cp --reflink=auto -f "${from}" "${to}.tmp.$$"
        mv -f "${to}.tmp.$$" "${to}"
    fi
}

# The miner is checked (fmt, clippy) and compiled by the node's toolchain. Its key is the content of its own sources.
miner_key() {
    local h
    h="$(cd "${interop_dir}/miner" && git ls-files -z --cached --others --exclude-standard . |
        xargs -0 "${SHA256[@]}" | "${SHA256[@]}" | cut -c1-12)"
    echo "miner-${h}-${builder_tag}"
}

_build_miner() {
    local key="$1"
    if have_entry "${key}"; then
        return
    fi
    build_builder_image
    log "checking and compiling the interop miner"
    cargo_in_builder "${NODE_RUST}" /repo/interop/miner miner fmt --check
    cargo_in_builder "${NODE_RUST}" /repo/interop/miner miner \
        clippy --release --locked -- -D warnings
    cargo_in_builder "${NODE_RUST}" /repo/interop/miner miner build --release --locked
    local stage
    stage="$(new_stage "${key}")"
    install -m 0755 "${shared_work}/target/miner/release/lepic-interop-miner" "${stage}/miner"
    publish_entry "${key}" "${stage}"
}

# The files the lepic binary is compiled from: the whole tree, less what only tests, CI, docs and the interop rig
# touch. The three documents the code includes with include_str! stay in. A listed file that is gone is skipped.
lepic_input_hash() {
    (
        cd "${repo_dir}"
        {
            git ls-files -z --cached --others --exclude-standard -- . \
                ':!interop' ':!.github' ':!.gitlab' ':!.githooks' ':!fuzz' ':!conformance' ':!console' \
                ':!docs' ':!*.md'
            printf 'docs/api/openapi.json\0'
        } |
            while IFS= read -r -d '' f; do [[ -f "${f}" ]] && printf '%s\0' "${f}"; done |
            xargs -0 "${SHA256[@]}" | "${SHA256[@]}" | cut -c1-12
    )
}

# $1 is the entry name (lepic or lepic-floonet), the rest the cargo arguments.
_build_lepic() {
    local key="$1" name="$2" source_hash="$3"
    shift 3
    if have_entry "${key}"; then
        return
    fi
    build_builder_image
    cap_target "${name}"
    log "compiling ${name} (cache miss ${key}; sources ${source_hash})"
    cargo_in_builder "${LEPIC_RUST}" /repo "${name}" build --release --locked -p lepic-cli --bin lepic "$@"
    local stage
    stage="$(new_stage "${key}")"
    install -m 0755 "${shared_work}/target/${name}/release/lepic" "${stage}/${name}"
    publish_entry "${key}" "${stage}"
}

ensure_lepic() {
    local name="$1" source_hash="$2"
    shift 2
    local key="${name}-${source_hash}-${builder_tag}"
    if ! have_entry "${key}"; then
        with_lock "target-${name}" _build_lepic "${key}" "${name}" "${source_hash}" "$@"
    fi
    touch_entry "${key}"
    use_entry "${key}" "${name}"
}

build_binaries() {
    ensure_pinned "epic ${EPIC_TAG}" "${NODE_RUST}" epic "${EPIC_REPO}" "${EPIC_COMMIT}" epic
    ensure_pinned "epic-wallet ${EPIC_WALLET_TAG}" "${REFERENCE_RUST}" epic-wallet "${EPIC_WALLET_REPO}" \
        "${EPIC_WALLET_COMMIT}" epic-wallet
    ensure_pinned "epic-wallet ${EPIC_WALLET_LEGACY_TAG} (legacy peer)" "${REFERENCE_RUST}" epic-wallet-legacy \
        "${EPIC_WALLET_REPO}" "${EPIC_WALLET_LEGACY_COMMIT}" epic-wallet-legacy epic-wallet
    ensure_pinned "the relay's epicboxlib" "${REFERENCE_RUST}" epic-epicbox-docker "${EPICBOX_REPO}" \
        "${EPICBOX_COMMIT}" epicboxlib epicboxlib /epicboxlib_source

    local key
    key="$(miner_key)"
    if ! have_entry "${key}"; then
        with_lock target-miner _build_miner "${key}"
    fi
    touch_entry "${key}"
    use_entry "${key}" miner

    # --no-lepic: for a machine whose host is not Linux, where the lepic under test is built natively.
    [[ "${with_lepic}" == true ]] || return 0
    local source_hash
    source_hash="$(lepic_input_hash)"
    ensure_lepic lepic "${source_hash}"
    # The floonet suites (e2e, live) run a build whose process host is on floonet.
    ensure_lepic lepic-floonet "${source_hash}" --features floonet-harness
}

# The relay's source tree is the build context of the relay image. Every checkout points at the shared clone.
link_relay_source() {
    local relay link="${work_dir}/src/epic-epicbox-docker"
    with_lock "relay-src" fetch_relay_source
    relay="$(relay_src_dir)"
    mkdir -p "${work_dir}/src"
    if [[ -L "${link}" ]]; then
        [[ "$(readlink "${link}")" == "${relay}" ]] || ln -sfn "${relay}" "${link}"
    else
        # A clone left by an earlier build.sh in this checkout: the shared one replaces it.
        rm -rf "${link}"
        ln -s "${relay}" "${link}"
    fi
}

prune_group() {
    # Keeps the newest ${keep} entries whose name starts with the prefix and ends with the builder tag of any toolchain.
    local prefix="$1" entry n=0
    while IFS= read -r entry; do
        n=$((n + 1))
        if ((n > keep)); then
            log "dropping ${entry##*/}"
            rm -rf "${entry}"
        fi
    done < <(
        for d in "${store_dir}/${prefix}"-*; do
            if [[ -f "${d}/.complete" ]]; then
                printf '%s %s\n' "$(file_mtime "${d}/.complete")" "${d}"
            fi
        done | sort -rn | awk '{print $2}'
    )
}

prune() {
    [[ -d "${store_dir}" ]] || return 0
    local group
    for group in epic epic-wallet epic-wallet-legacy epicboxlib miner lepic lepic-floonet; do
        prune_group "${group}"
    done
    # Staging directories of builds that died (more than a day old, and not this process's).
    find "${store_dir}" -maxdepth 1 -name '.stage-*' -mmin +1440 -type d -exec rm -rf {} +
}

status() {
    echo "cache: ${cache_root}"
    du -sh "${store_dir}" "${shared_work}" 2>/dev/null || true
    local d
    for d in "${store_dir}"/*/; do
        if [[ -f "${d}.complete" ]]; then
            printf '%s  %s\n' "$(fmt_epoch "$(file_mtime "${d}.complete")")" "$(basename "${d}")"
        fi
    done | sort
    echo "this checkout wants: lepic-$(lepic_input_hash)-${builder_tag}, $(miner_key)"
}

with_lepic=true

main() {
    case "${1:-}" in
        --status) status; return ;;
        --prune) prune; return ;;
        --no-lepic) with_lepic=false ;;
        '') ;;
        *) log "usage: build.sh [--status|--prune|--no-lepic]"; exit 2 ;;
    esac
    mkdir -p "${store_dir}" "${work_dir}/bin"
    build_binaries
    link_relay_source
    prune
    log "binaries are in ${work_dir}/bin"
}

main "$@"
