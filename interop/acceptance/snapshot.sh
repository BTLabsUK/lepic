# SPDX-License-Identifier: Apache-2.0
# The funded chain, saved. Mining a private chain to coinbase maturity and funding the peer wallet takes
# minutes and gives the same result every run, so run.sh does it once per stack version: it saves the node's
# chain and both wallets after funding (the node-data, funder-data and peer-data volumes) and every later run
# restores them into its fresh volumes. A run stays hermetic: it works on its own copy of the volumes, which
# `dc down -v` deletes, and the saved files are never written to.
#
# A snapshot is keyed by what produced it: the pinned node, wallet and miner binaries, the pins, the scripts that
# configure the node and the wallets, the compose file, ../lib.sh and the funding logic (fund_stack in steps.sh).
# Change any of them and the next run builds a new snapshot. lepic is not part of the key: it is not in the chain.
#
# Snapshots live in <build cache>/snapshots (LEPIC_BUILD_CACHE, default ~/.cache/lepic-build), the newest
# SNAPSHOT_KEEP of them. run.sh --from-genesis ignores them; run.sh --rebuild-snapshot replaces the current one.
# shellcheck shell=bash disable=SC2154,SC2016 # ACCEPTANCE_DIR, RUN_LOG and EXCHANGE_DIR come from run.sh

SNAPSHOT_VOLUMES=(node-data funder-data peer-data)
SNAPSHOT_KEEP="${SNAPSHOT_KEEP:-2}"
# The runtime image has tar; it runs as root so the files keep their owner (uid 10001).
SNAPSHOT_IMAGE=lepic-acceptance-runtime:local

snapshot_root() { echo "${LEPIC_BUILD_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/lepic-build}/snapshots"; }

# Prints the key, or nothing when the binaries are not built.
snapshot_key() {
    local interop="${ACCEPTANCE_DIR}/.." bin="${ACCEPTANCE_DIR}/../.work/bin"
    {
        (cd "${bin}" && "${SHA256[@]}" epic epic-wallet miner foundation_floonet.json)
        cat "${interop}/pins.env" "${interop}/docker/node.sh" "${interop}/docker/wallet.sh" "${interop}/docker/ew.sh" \
            "${interop}/docker/runtime.Dockerfile" "${interop}/lib.sh" "${ACCEPTANCE_DIR}/compose.yaml" \
            "${ACCEPTANCE_DIR}/snapshot.sh"
        sed -n '/^fund_stack() {/,/^}/p' "${ACCEPTANCE_DIR}/steps.sh"
    } 2>/dev/null | "${SHA256[@]}" | cut -c1-12
}

snapshot_dir() { echo "$(snapshot_root)/acceptance-$1"; }
snapshot_have() { [[ -f "$(snapshot_dir "$1")/.complete" ]]; }

# The tip height of the running node.
snapshot_node_height() {
    dc exec -T node sh -c 'curl -s -u "epic:$(cat /data/node/.api_secret)" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_status\",\"params\":[]}" http://127.0.0.1:23413/v2/owner' |
        jq -r '.result.Ok.tip.height'
}

# Saves the volumes of the running, funded stack under the key. Stops the stack; the caller removes it.
snapshot_save() {
    local key="$1" height stage final volume
    height="$(snapshot_node_height)"
    final="$(snapshot_dir "${key}")"
    stage="${final}.stage.$$"
    mkdir -p "$(snapshot_root)"
    rm -rf "${stage}"
    mkdir -p "${stage}"
    # A stopped stack has no writer: the node and the wallets flush their databases on a clean stop.
    dc stop -t 60 >>"${RUN_LOG}" 2>&1 || return 1
    for volume in "${SNAPSHOT_VOLUMES[@]}"; do
        docker run --rm --user 0 --entrypoint tar -v "lepic-acceptance_${volume}:/v:ro" "${SNAPSHOT_IMAGE}" \
            -C /v --numeric-owner -cf - . 2>>"${RUN_LOG}" | gzip -1 >"${stage}/${volume}.tar.gz" || return 1
    done
    jq -n --arg key "${key}" --arg height "${height}" --arg at "$(date -u +%FT%TZ)" \
        '{key: $key, height: ($height | tonumber), saved_at: $at}' >"${stage}/meta.json"
    touch "${stage}/.complete"
    rm -rf "${final}"
    mv "${stage}" "${final}"
    log "saved the funded chain (height ${height}) as snapshot ${key}"
    snapshot_prune "${key}"
}

# Fills the stack's freshly created, still empty volumes from a snapshot. Containers exist, none runs.
snapshot_restore() {
    local key="$1" dir volume
    dir="$(snapshot_dir "${key}")"
    for volume in "${SNAPSHOT_VOLUMES[@]}"; do
        gzip -dc "${dir}/${volume}.tar.gz" |
            docker run -i --rm --user 0 --entrypoint tar -v "lepic-acceptance_${volume}:/v" "${SNAPSHOT_IMAGE}" \
                -C /v --numeric-owner -xf - 2>>"${RUN_LOG}" || return 1
    done
    touch "${dir}/.complete"
    log "restored the funded chain from snapshot ${key} (height $(jq -r .height "${dir}/meta.json"))"
}

# Keeps the newest SNAPSHOT_KEEP snapshots, and never the one named.
snapshot_prune() {
    local keep_key="$1" dir n=0
    while IFS= read -r dir; do
        n=$((n + 1))
        if ((n > SNAPSHOT_KEEP)) && [[ "${dir}" != "$(snapshot_dir "${keep_key}")" ]]; then
            log "dropping old snapshot ${dir##*/}"
            rm -rf "${dir}"
        fi
    done < <(
        for dir in "$(snapshot_root)"/acceptance-*; do
            if [[ -f "${dir}/.complete" ]]; then
                printf '%s %s\n' "$(file_mtime "${dir}/.complete")" "${dir}"
            fi
        done | sort -rn | awk '{print $2}'
    )
}
