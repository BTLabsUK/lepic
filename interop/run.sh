#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs every Epicbox and file interop scenario between lepic and epic-wallet v4.0.2 on a fresh
# local stack and prints a pass or fail table. Exits 0 only when every scenario passed.
#
#   ./run.sh            build what changed, start a clean stack, run, tear it down
#   ./run.sh --keep     leave the stack running afterwards for inspection
#   ./run.sh --no-build skip build.sh and use the binaries already in .work/bin
#
# SCENARIO_FILTER=<extended regex> runs only the scenarios whose names match it (setup always
# runs). The scenarios share one chain and balances, so a subset is a check, not the full run.
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

log_dir="${INTEROP_DIR}/.work/logs/$(date -u +%Y%m%dT%H%M%SZ)"
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

printf '\n%-34s %-6s %6s  %s\n' "Scenario" "Result" "Time" "Detail"
printf '%-34s %-6s %6s  %s\n' "--------" "------" "----" "------"
for i in "${!names[@]}"; do
    printf '%-34s %-6s %6s  %s\n' "${names[i]}" "${results[i]}" "${times[i]}" "${details[i]}"
done
printf '\nLogs: %s\n' "${log_dir}"

if ((failed > 0)); then
    exit 1
fi
