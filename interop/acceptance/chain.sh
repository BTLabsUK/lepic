#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Drives the stack `run.sh --stack-only` keeps running, for tests of a lepic outside the stack,
# such as the Flutter binding (BTLabs-EPIC/lepic-flutter). It takes no lock: the run.sh
# holding the stack holds it.
#
#   ./chain.sh env                    the node URL, its API secret file, the relay and the
#                                     slate exchange directory, as KEY=value lines
#   ./chain.sh height                 the node's tip height
#   ./chain.sh mine <blocks>          waits until the miner added that many blocks
#   ./chain.sh fund <address> <epic>  the funder sends that amount to an Epicbox address; the
#                                     receiving wallet must drain or listen to answer it
#   ./chain.sh receive <slate file>   the funder answers an S1 file in the exchange directory,
#                                     writing <file>.response next to it
set -euo pipefail

ACCEPTANCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEROP_DIR="${ACCEPTANCE_DIR}"
# shellcheck source=../lib.sh
source "${ACCEPTANCE_DIR}/../lib.sh"
# shellcheck source=steps.sh
source "${ACCEPTANCE_DIR}/steps.sh"

WORK_DIR="${ACCEPTANCE_DIR}/.work"
STATE_DIR="${WORK_DIR}/state"
EXCHANGE_DIR="${WORK_DIR}/exchange"
SECRET_FILE="${STATE_DIR}/foreign_api_secret"
RUN_LOG="${WORK_DIR}/chain.log"

usage() {
    sed -n '2,13s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

require_stack() {
    if [[ -z "$(dc ps -q --status running funder 2>/dev/null)" || ! -s "${SECRET_FILE}" ]]; then
        log "the acceptance stack is not running; start it with interop/acceptance/run.sh --stack-only"
        exit 1
    fi
}

node_height() {
    curl -sf -u "epic:$(cat "${SECRET_FILE}")" \
        -d '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":[]}' \
        "http://127.0.0.1:${NODE_PORT}/v2/foreign" | jq -er .result.Ok.height
}

height_at_least() { (($(node_height) >= $1)); }

print_env() {
    printf 'LEPIC_INTEROP_NODE_URL=http://127.0.0.1:%s\n' "${NODE_PORT}"
    printf 'LEPIC_INTEROP_NODE_API_SECRET_FILE=%s\n' "${SECRET_FILE}"
    printf 'LEPIC_INTEROP_EPICBOX_DOMAIN=localhost\n'
    printf 'LEPIC_INTEROP_EPICBOX_PORT=%s\n' "${RELAY_PORT}"
    printf 'LEPIC_INTEROP_EXCHANGE_DIR=%s\n' "${EXCHANGE_DIR}"
}

mine() {
    local blocks="${1:?mine needs a block count}"
    [[ "${blocks}" =~ ^[0-9]+$ ]] || usage
    local target=$(($(node_height) + blocks))
    # Two to four seconds a block; a minute of slack for a slow start.
    wait_until "height ${target}" $((blocks * 6 + 60)) height_at_least "${target}"
    node_height
}

fund() {
    local address="${1:?fund needs an address}" amount="${2:?fund needs an amount}"
    log "waiting for spendable funds in the funder wallet"
    wait_until "funder funds" 300 ew_spendable_at_least funder $(($(to_units "${amount}") + UNIT))
    # The funder finalizes and posts when the answer reaches its listener.
    ew_listening funder || ew_listen_start funder
    ew funder send -m epicbox -d "${address}" -c 1 -s smallest "${amount}" >>"${RUN_LOG}"
}

receive() {
    local file="${1:?receive needs a slate file}"
    local name
    name="$(basename "${file}")"
    [[ -f "${EXCHANGE_DIR}/${name}" ]] || {
        log "${name} is not in ${EXCHANGE_DIR}"
        exit 1
    }
    ew funder receive -i "/exchange/${name}" >>"${RUN_LOG}"
}

(($# > 0)) || usage
command="$1"
shift
require_stack
case "${command}" in
    env) print_env ;;
    height) node_height ;;
    mine) mine "$@" ;;
    fund) fund "$@" ;;
    receive) receive "$@" ;;
    *) usage ;;
esac
