#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# CLI acceptance: drives the installed `lepic` binary through every command against the local
# interop stack (relay, reference node v4.1.0 on a test-mode chain, epic-wallet v4.1.0), in both
# directions over Epicbox and slate files, and prints a pass or fail table. Exits 0 only when
# every step passed. Each run starts from a clean state: a new chain, new wallets and a new
# lepic home under .work/state.
#
#   ./run.sh                  build, install lepic with `cargo xtask install`, run, tear down
#   ./run.sh --keep           leave the stack running afterwards
#   ./run.sh --no-build       use the binaries already built and the lepic already installed
#   ./run.sh --lepic <path>   test this lepic binary instead of the installed one
#   ./run.sh --stack-only     start a clean stack, fund nothing, print where it listens and
#                             keep it, and the stack lock, until stopped; ./chain.sh drives it
#   ./run.sh --probes         run the relay and epic-wallet probes of probes.sh instead of the
#                             steps
set -euo pipefail

ACCEPTANCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${ACCEPTANCE_DIR}/../.." && pwd)"
# ../lib.sh drives the compose file in INTEROP_DIR; here that is this directory's.
INTEROP_DIR="${ACCEPTANCE_DIR}"
# shellcheck source=../lib.sh
source "${ACCEPTANCE_DIR}/../lib.sh"
# shellcheck source=steps.sh
source "${ACCEPTANCE_DIR}/steps.sh"

keep=false
build=true
stack_only=false
setup_step=step_setup
LEPIC_BIN=""
while (($# > 0)); do
    case "$1" in
        --keep) keep=true ;;
        --probes)
            # shellcheck source=probes.sh
            source "${ACCEPTANCE_DIR}/probes.sh"
            setup_step=step_probe_setup
            STEPS=("${PROBE_STEPS[@]}")
            ;;
        --stack-only) stack_only=true ;;
        --no-build) build=false ;;
        --lepic)
            LEPIC_BIN="${2:?--lepic needs a path}"
            shift
            ;;
        *)
            echo "unknown option $1" >&2
            exit 2
            ;;
    esac
    shift
done
hold_stack lepic-acceptance

WORK_DIR="${ACCEPTANCE_DIR}/.work"
STATE_DIR="${WORK_DIR}/state"
EXCHANGE_DIR="${WORK_DIR}/exchange"
log_dir="${WORK_DIR}/logs/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${log_dir}"
RUN_LOG="${log_dir}/run.log"
: >"${RUN_LOG}"

teardown() {
    dc logs --no-color --timestamps >"${log_dir}/compose.log" 2>&1 || true
    if [[ "${keep}" == false ]]; then
        dc down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}

port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

log "stopping any earlier acceptance stack"
dc down -v --remove-orphans >>"${RUN_LOG}" 2>&1 || true
for port in "${NODE_PORT}" "${RELAY_PORT}"; do
    if port_in_use "${port}"; then
        log "127.0.0.1:${port} is in use; the stack publishes the node and relay there"
        exit 1
    fi
done
trap teardown EXIT

if [[ "${build}" == true ]]; then
    log "building the stack's binaries (incremental; the first build takes a while)"
    "${ACCEPTANCE_DIR}/../build.sh" >>"${RUN_LOG}" 2>&1
    if [[ "${stack_only}" == false ]]; then
        log "installing lepic with cargo xtask install"
        (cd "${REPO_DIR}" && cargo xtask install) >>"${RUN_LOG}" 2>&1
    fi
fi
if [[ "${stack_only}" == false ]]; then
    if [[ -z "${LEPIC_BIN}" ]]; then
        LEPIC_BIN="$(type -P lepic || true)"
        [[ -n "${LEPIC_BIN}" ]] || LEPIC_BIN="${HOME}/.local/bin/lepic"
    fi
    [[ -x "${LEPIC_BIN}" ]] || {
        log "no lepic binary at ${LEPIC_BIN}"
        exit 1
    }
    log "testing $("${LEPIC_BIN}" --version) at ${LEPIC_BIN}"
fi

log "starting a clean stack"
rm -rf "${STATE_DIR}" "${EXCHANGE_DIR}"
mkdir -p "${STATE_DIR}" "${EXCHANGE_DIR}"
# The wallet containers run as their own uid and write slate files here, and the host's lepic
# answers them. Sticky, so neither side can remove or replace the other's files.
chmod 1777 "${EXCHANGE_DIR}"
{
    dc build
    dc up --no-start
} >>"${RUN_LOG}" 2>&1
if [[ "$(docker network inspect lepic-acceptance_internal --format '{{.Internal}}')" != true ]]; then
    log "the acceptance network has a route out; refusing to start"
    exit 1
fi
dc up -d --wait --wait-timeout 300 >>"${RUN_LOG}" 2>&1

if [[ "${stack_only}" == true ]]; then
    (umask 077 && dc exec -T node cat /data/node/.foreign_api_secret >"${STATE_DIR}/foreign_api_secret")
    "${ACCEPTANCE_DIR}/chain.sh" env
    log "stack up; the miner adds a block every few seconds. Stop with Ctrl-C."
    sleeper=""
    trap '[[ -z "${sleeper}" ]] || kill "${sleeper}" 2>/dev/null; exit 0' INT TERM
    # The lock and the EXIT trap's teardown last as long as this wait. The sleep gets no copy
    # of the lock, so the lock ends with this script.
    while :; do
        if [[ -n "${STACK_LOCK_FD:-}" ]]; then
            sleep 3600 {STACK_LOCK_FD}>&- &
        else
            sleep 3600 &
        fi
        sleeper=$!
        wait "${sleeper}"
    done
fi

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

run_step "setup and funding" "${setup_step}"
if [[ "${results[0]}" == PASS ]]; then
    for entry in "${STEPS[@]}"; do
        run_step "${entry%%:*}" "${entry#*:}"
    done
fi
peer_listen_stop >/dev/null 2>&1 || true

# The table goes to stdout and into the log directory, so a run can be checked afterwards.
{
    printf 'lepic: %s at %s\n' "$("${LEPIC_BIN}" --version)" "${LEPIC_BIN}"
    printf 'tree: %s\n' "$(git -C "${REPO_DIR}" describe --always --dirty 2>/dev/null || echo unknown)"
    printf '\n%-40s %-6s %6s  %s\n' "Step" "Result" "Time" "Detail"
    printf '%-40s %-6s %6s  %s\n' "----" "------" "----" "------"
    for i in "${!names[@]}"; do
        printf '%-40s %-6s %6s  %s\n' "${names[i]}" "${results[i]}" "${times[i]}" "${details[i]}"
    done
    printf '\n%d of %d steps passed\n' "$((${#names[@]} - failed))" "${#names[@]}"
} | tee "${log_dir}/results.txt"
printf '\nLogs: %s\n' "${log_dir}"

if ((failed > 0)); then
    exit 1
fi
