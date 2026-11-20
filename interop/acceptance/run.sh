#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# CLI acceptance: drives the installed `lepic` binary through every command against the local
# interop stack (relay, reference node v4.1.2 on a test-mode chain, epic-wallet v4.1.0), in both
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
#   ./run.sh --trust          run the stock-queue and relay checks of trust.sh instead
#   ./run.sh --from-genesis   mine and fund from a new chain, ignoring the saved funded chain
#   ./run.sh --rebuild-snapshot  mine and fund again and replace the saved funded chain
#
# The steps start from a saved funded chain (snapshot.sh): the first run of a stack version mines
# and funds and saves the node and wallet volumes, later runs restore them into their own fresh
# volumes. --probes, --trust and --stack-only always start from genesis.
#
# The relay is the Epicmail mailbox, the one we ship, built from its sources by ../mux-relay-image.sh
# (ACCEPTANCE_MUX_RELAY_SRC names a checkout; ACCEPTANCE_MUX_RELAY_IMAGE with
# ACCEPTANCE_MUX_RELAY_CONFIG name one built outside). The full step set runs on it. The checks of
# the relay's store go through the adapter in steps.sh (relay_messages_for, relay_unmade_for,
# relay_posts_total), which reads Epicmail's SQLite file read-only.
#
#   ./run.sh --stock-relay    the opt-in lane: the stock Node relay and its MongoDB, and only the
#                             Legacy Epicbox address and stock-wallet steps (STOCK_STEPS in steps.sh).
#                             Run it rarely: it checks what public stock relays still carry.
#
# --probes, --trust and --stack-only test the stock relay itself and always use it.
#
# ACCEPTANCE_ONLY=<name>[,<name>...] runs setup and only the steps whose function names are listed
# (list step_wallet_init, step_receive_by_file and step_fund_payer first: the steps need funds), for
# developing a step.
#
# ACCEPTANCE_NODE_PORT=<port> publishes the node API on that loopback port in place of 43413. The
# relay stays on 3423, because Epicbox addresses name it.
set -euo pipefail

ACCEPTANCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${ACCEPTANCE_DIR}/../.." && pwd)"
# ../lib.sh drives the compose file in INTEROP_DIR; here that is this directory's.
INTEROP_DIR="${ACCEPTANCE_DIR}"
# shellcheck source=../lib.sh
source "${ACCEPTANCE_DIR}/../lib.sh"
# shellcheck source=steps.sh
source "${ACCEPTANCE_DIR}/steps.sh"
# shellcheck source=../portable.sh
source "${ACCEPTANCE_DIR}/../portable.sh"
# shellcheck source=snapshot.sh
source "${ACCEPTANCE_DIR}/snapshot.sh"

# The relay of the stack. Default: the Epicmail mailbox, built by ../mux-relay-image.sh from the
# relay's sources (ACCEPTANCE_MUX_RELAY_SRC, then LEPIC_MUX_RELAY_SRC, then tools/lepic.sh's
# cache); the image and its config can be given as ACCEPTANCE_MUX_RELAY_IMAGE and
# ACCEPTANCE_MUX_RELAY_CONFIG instead. --stock-relay (below) starts the stock Node relay.
RELAY_MODE=epicmail
keep=false
build=true
stack_only=false
from_genesis=false
rebuild_snapshot=false
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
        --trust)
            # shellcheck source=probes.sh
            source "${ACCEPTANCE_DIR}/probes.sh"
            # shellcheck source=trust.sh
            source "${ACCEPTANCE_DIR}/trust.sh"
            setup_step=step_trust_setup
            STEPS=("${TRUST_STEPS[@]}")
            ;;
        --stock-relay) RELAY_MODE=stock ;;
        --stack-only) stack_only=true ;;
        --from-genesis) from_genesis=true ;;
        --rebuild-snapshot) rebuild_snapshot=true ;;
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

# The probes and trust checks and a bare stack test the stock relay itself, so they run on it.
if [[ "${setup_step}" != step_setup || "${stack_only}" == true ]]; then
    RELAY_MODE=stock
fi
STEPS_ALL=("${STEPS[@]}")
if [[ "${RELAY_MODE}" == epicmail ]]; then
    if [[ -z "${ACCEPTANCE_MUX_RELAY_IMAGE:-}" ]]; then
        relay_src="${ACCEPTANCE_MUX_RELAY_SRC:-${LEPIC_MUX_RELAY_SRC:-${HOME}/.cache/wfe-lepic/mux-relay/src}}"
        [[ -f "${relay_src}/Dockerfile" ]] || {
            echo "no Epicmail sources at ${relay_src}: set ACCEPTANCE_MUX_RELAY_SRC to a checkout of the" >&2
            echo "relay, or ACCEPTANCE_MUX_RELAY_IMAGE and ACCEPTANCE_MUX_RELAY_CONFIG, or run with" >&2
            echo "--stock-relay (tools/lepic.sh smoke fetches the sources itself)" >&2
            exit 2
        }
        ACCEPTANCE_MUX_RELAY_IMAGE=lepic-acceptance-mux-relay:local
        ACCEPTANCE_MUX_RELAY_CONFIG="${ACCEPTANCE_DIR}/.work/relay.toml"
        NEED_RELAY_IMAGE="${relay_src}"
    fi
    : "${ACCEPTANCE_MUX_RELAY_CONFIG:?ACCEPTANCE_MUX_RELAY_IMAGE is set, so the config is needed}"
    # compose.mux.yaml names the local tag only, so a given image is tagged with it.
    if [[ "${ACCEPTANCE_MUX_RELAY_IMAGE}" != lepic-acceptance-mux-relay:local ]]; then
        docker tag "${ACCEPTANCE_MUX_RELAY_IMAGE}" lepic-acceptance-mux-relay:local
    fi
    export ACCEPTANCE_MUX_RELAY_IMAGE ACCEPTANCE_MUX_RELAY_CONFIG
    export COMPOSE_OVERRIDE="${ACCEPTANCE_DIR}/compose.mux.yaml"
fi
if [[ "${RELAY_MODE}" == stock && "${setup_step}" == step_setup ]]; then
    STEPS=()
    for entry in "${STEPS_ALL[@]}"; do
        [[ " ${STOCK_STEPS[*]} " == *" ${entry#*:} "* ]] && STEPS+=("${entry}")
    done
fi

# Every entry is "display name:function", the name without a colon, and an ACCEPTANCE_ONLY name
# is a function of some entry. A filter that matches nothing must not start the stack.
only_count=0
if [[ "${stack_only}" == false ]]; then
    valid=()
    for entry in "${STEPS[@]}"; do
        if [[ "${entry//[^:]/}" != ":" ]]; then
            echo "step entry needs exactly one colon, between name and function: ${entry}" >&2
            exit 2
        fi
        valid+=("${entry#*:}")
    done
    if [[ -n "${ACCEPTANCE_ONLY:-}" ]]; then
        IFS=, read -r -a only_names <<<"${ACCEPTANCE_ONLY}"
        only_count=${#only_names[@]}
        unknown=()
        for name in "${only_names[@]}"; do
            [[ " ${valid[*]} " == *" ${name} "* ]] || unknown+=("${name}")
        done
        if ((${#unknown[@]} > 0)); then
            echo "ACCEPTANCE_ONLY names no step: ${unknown[*]}" >&2
            echo "valid names: ${valid[*]}" >&2
            exit 2
        fi
    fi
fi
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

if [[ -n "${NEED_RELAY_IMAGE:-}" ]]; then
    log "building the Epicmail relay image from ${NEED_RELAY_IMAGE}"
    "${ACCEPTANCE_DIR}/../mux-relay-image.sh" "${NEED_RELAY_IMAGE}" "${ACCEPTANCE_MUX_RELAY_IMAGE}" \
        "${ACCEPTANCE_MUX_RELAY_CONFIG}" >>"${RUN_LOG}" 2>&1
fi

# Brings up a stack with empty volumes: the containers are created, the node's and wallets' volumes empty.
create_stack() {
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
}

start_stack() { dc up -d --wait --wait-timeout 300 >>"${RUN_LOG}" 2>&1; }

STACK_FUNDED=false
chain_key=""
if [[ "${setup_step}" == step_setup && "${stack_only}" == false && "${from_genesis}" == false ]]; then
    chain_key="$(snapshot_key)"
fi
create_stack
if [[ -n "${chain_key}" ]]; then
    if [[ "${rebuild_snapshot}" == true ]] || ! snapshot_have "${chain_key}"; then
        log "no saved funded chain for this stack version (${chain_key}); mining and funding it once"
        start_stack
        if fund_stack && snapshot_save "${chain_key}"; then
            dc down -v --remove-orphans >>"${RUN_LOG}" 2>&1
            create_stack
        else
            log "could not build the snapshot; running from genesis"
            chain_key=""
            dc down -v --remove-orphans >>"${RUN_LOG}" 2>&1
            create_stack
        fi
    fi
    if [[ -n "${chain_key}" ]]; then
        snapshot_restore "${chain_key}"
        STACK_FUNDED=true
    fi
fi
start_stack

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
    steps_run=0
    for entry in "${STEPS[@]}"; do
        if [[ -n "${ACCEPTANCE_ONLY:-}" && ",${ACCEPTANCE_ONLY}," != *",${entry#*:},"* ]]; then
            continue
        fi
        run_step "${entry%%:*}" "${entry#*:}"
        steps_run=$((steps_run + 1))
    done
    if [[ -n "${ACCEPTANCE_ONLY:-}" && "${steps_run}" != "${only_count}" ]]; then
        log "ACCEPTANCE_ONLY listed ${only_count} steps and ${steps_run} ran"
        failed=$((failed + 1))
    fi
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
    printf '\n%d of %d steps passed (relay: %s)\n' \
        "$((${#names[@]} - failed))" "${#names[@]}" "${RELAY_MODE}"
} | tee "${log_dir}/results.txt"
printf '\nLogs: %s\n' "${log_dir}"

if ((failed > 0)); then
    exit 1
fi
