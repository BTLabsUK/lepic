#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs every Epicbox and file interop scenario between lepic and the epic-wallet release pinned in pins.env on a fresh
# local stack and prints a pass or fail table. Exits 0 only when every scenario passed.
#
#   ./run.sh            build what changed, start a clean stack, run, tear it down
#   ./run.sh --keep     leave the stack running afterwards for inspection
#   ./run.sh --no-build skip build.sh and use the binaries already in .work/bin
#
# PEER_WALLET=legacy runs the legacy scenarios instead: the peer is the previous classic wallet
# (EPIC_WALLET_LEGACY_TAG in pins.env) and the funder stays on the pinned release.
#
# SCENARIO_FILTER=<extended regex> runs only the scenarios whose names match it (setup always
# runs). The scenarios share one chain and balances, so a subset is a check, not the full run. A
# filter that matches no scenario fails the run.
#
# INTEROP_CAPTURE=1 also records every frame on the relay and HTTP listener ports and copies the
# recording, the slate files and the peer's seed file to <log dir>/capture (see gate.sh).
# INTEROP_LOG_DIR names the log dir; results.tsv in it lists each step and its result.
set -euo pipefail

INTEROP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${INTEROP_DIR}/lib.sh"
# shellcheck source=scenarios.sh
source "${INTEROP_DIR}/scenarios.sh"

keep=false
build=true
for arg in "$@"; do
    case "${arg}" in
        --keep) keep=true ;;
        --no-build) build=false ;;
        *) echo "unknown option ${arg}" >&2; exit 2 ;;
    esac
done
hold_stack lepic-interop

case "${PEER_WALLET:-pinned}" in
    pinned) PEER_WALLET_BIN=epic-wallet ;;
    legacy) PEER_WALLET_BIN=epic-wallet-legacy; SCENARIOS=("${LEGACY_SCENARIOS[@]}") ;;
    *) echo "PEER_WALLET must be pinned or legacy" >&2; exit 2 ;;
esac
export PEER_WALLET_BIN
if [[ "${INTEROP_CAPTURE:-0}" == 1 ]]; then
    export COMPOSE_PROFILES=capture
fi

log_dir="${INTEROP_LOG_DIR:-${INTEROP_DIR}/.work/logs/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "${log_dir}"
RUN_LOG="${log_dir}/run.log"
: >"${RUN_LOG}"

teardown() {
    dc logs --no-color --timestamps >"${log_dir}/compose.log" 2>&1 || true
    if [[ "${keep}" == false ]]; then
        dc down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap teardown EXIT

if [[ "${build}" == true ]]; then
    log "building binaries (incremental; the first build takes a while)"
    "${INTEROP_DIR}/build.sh" >>"${RUN_LOG}" 2>&1
fi

log "starting a clean stack"
{
    dc down -v --remove-orphans
    dc build
    dc up --no-start
} >>"${RUN_LOG}" 2>&1
if [[ "$(docker network inspect lepic-interop_interop --format '{{.Internal}}')" != true ]]; then
    log "the interop network has a route out; refusing to start"
    exit 1
fi
dc up -d --wait --wait-timeout 300 >>"${RUN_LOG}" 2>&1

names=()
results=()
times=()
details=()
failed=0

run_step() {
    local name="$1" function="$2" started=${SECONDS} result
    log "${name}"
    DETAIL=""
    if "${function}"; then result=PASS; else result=FAIL; failed=$((failed + 1)); fi
    names+=("${name}")
    results+=("${result}")
    times+=("$((SECONDS - started))s")
    details+=("${DETAIL}")
    log "${result}: ${DETAIL}"
}

run_step "setup and funding" setup
if [[ "${results[0]}" == PASS ]]; then
    for entry in "${SCENARIOS[@]}"; do
        [[ "${entry%%:*}" =~ ${SCENARIO_FILTER:-.} ]] || continue
        run_step "${entry%%:*}" "${entry#*:}"
    done
fi
peer_listen_stop >/dev/null 2>&1 || true
lepic_http_listen_stop >/dev/null 2>&1 || true
if [[ "${INTEROP_CAPTURE:-0}" == 1 ]] && ! capture_collect "${log_dir}/capture" >>"${RUN_LOG}" 2>&1; then
    log "collecting the capture failed"
    failed=$((failed + 1))
fi

printf '\n%-34s %-6s %6s  %s\n' "Scenario" "Result" "Time" "Detail"
printf '%-34s %-6s %6s  %s\n' "--------" "------" "----" "------"
for i in "${!names[@]}"; do
    printf '%-34s %-6s %6s  %s\n' "${names[i]}" "${results[i]}" "${times[i]}" "${details[i]}"
done
printf '\nLogs: %s\n' "${log_dir}"

: >"${log_dir}/results.tsv"
for i in "${!names[@]}"; do
    printf '%s\t%s\n' "${names[i]}" "${results[i]}" >>"${log_dir}/results.tsv"
done
ran=$((${#names[@]} - 1))
printf 'Scenarios run: %d\n' "${ran}"
if [[ -n "${SCENARIO_FILTER:-}" && "${results[0]}" == PASS ]] && ((ran == 0)); then
    log "SCENARIO_FILTER matched no scenario: ${SCENARIO_FILTER}"
    exit 1
fi

if ((failed > 0)); then
    exit 1
fi
