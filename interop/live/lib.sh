# Helpers for the live floonet test. Sourced by run.sh after ../lib.sh, whose generic helpers
# (dc, lepic, ew, to_units, wait_until, balances, ew_tx_confirmed, drain_until) it reuses with
# INTEROP_DIR pointing at this directory.
# shellcheck shell=bash

# Public read-only floonet API, used for the tip and kernel lookups only. Calls are at least
# PUBLIC_MIN_GAP seconds apart and each is recorded in PUBLIC_LOG (set by run.sh), which also
# carries the spacing across the subshells that command substitution creates.
LIVE_PUBLIC_API="${LIVE_PUBLIC_API:-https://floo-node.btlabs.uk}"
PUBLIC_MIN_GAP=10

public_get() {
    local last wait
    last="$(tail -n 1 "${PUBLIC_LOG}" 2>/dev/null | cut -d' ' -f1)"
    wait=$((${last:-0} + PUBLIC_MIN_GAP - $(date +%s)))
    if ((wait > 0)); then sleep "${wait}"; fi
    echo "$(date +%s) GET $1" >>"${PUBLIC_LOG}"
    curl -fsS -m 20 "${LIVE_PUBLIC_API}$1" 2>>"${RUN_LOG}"
}

public_calls() { wc -l <"${PUBLIC_LOG}" 2>/dev/null || echo 0; }

# GET on the local node's v1 API, from inside the stack's network namespace.
node_get() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T node sh -c 'curl -fsS -u "epic:$(cat /data/node/.api_secret)" "http://127.0.0.1:13413$1"' \
        sh "$1" 2>>"${RUN_LOG}"
}

local_height() { node_get /v1/chain | jq -r .height; }

public_height() { public_get /v1/chain | jq -r .height; }

# Waits until the local node has a peer and has caught up with the public tip.
wait_synced() {
    local timeout="$1"
    local deadline=$((SECONDS + timeout)) public height
    public="$(public_height)" || return 1
    while :; do
        height="$(local_height)" || height=0
        if ((height >= public)); then
            log "local node at ${height}, public tip ${public}"
            return 0
        fi
        if ((SECONDS >= deadline)); then
            log "local node at ${height} after ${timeout}s, public tip ${public}"
            return 1
        fi
        sleep 15
    done
}

miner_running() { [[ -n "$(dc --profile mining ps -q miner 2>/dev/null)" ]]; }

miner_start() {
    miner_running && return 0
    log "mining started at height $(local_height)"
    dc --profile mining up -d miner >>"${RUN_LOG}" 2>&1
}

miner_stop() {
    miner_running || return 0
    dc --profile mining stop miner >>"${RUN_LOG}" 2>&1
    log "mining stopped at height $(local_height)"
}

# Mines only while a check is pending: starts the miner, waits for the check, stops the miner.
mine_until() {
    local what="$1" timeout="$2" status=0
    shift 2
    miner_start || return 1
    wait_until "${what}" "${timeout}" "$@" || status=$?
    miner_stop
    return "${status}"
}

# The kernel excess epic-wallet recorded for a slate, as hex.
ew_tx_kernel() {
    ew "$1" txs -t "$2" | grep -oE '\b0[89][0-9a-f]{64}\b' | head -n 1
}

# Height of the block holding a kernel, as the local or the public node reports it.
local_kernel_height() { node_get "/v1/chain/kernels/$1" | jq -r .height; }

public_kernel_height() { public_get "/v1/chain/kernels/$1" | jq -r '.height // empty'; }

public_has_kernel() { [[ -n "$(public_kernel_height "$1")" ]]; }

wallet_log_lines() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T peer sh -c 'grep -c "Starting epicbox listener" /data/.epic/floo/epic-wallet.log 2>/dev/null || true'
}

listener_started_after() { (($(wallet_log_lines) > $1)); }

# Starts epic-wallet's Epicbox listener in the peer container and waits until it subscribed.
listen_start() {
    listen_stop
    local before
    before="$(wallet_log_lines)"
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -d peer sh -c 'echo $$ >/data/listen.pid; exec ew listen -m epicbox >>/data/listen.log 2>&1'
    wait_until "the peer listener" 60 listener_started_after "${before}" || return 1
    # The subscription follows the log line.
    sleep 3
}

listen_stop() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T peer sh -c '
        [ -f /data/listen.pid ] || exit 0
        pid="$(cat /data/listen.pid)"
        kill "${pid}" 2>/dev/null || true
        while kill -0 "${pid}" 2>/dev/null; do sleep 0.2; done
        rm -f /data/listen.pid'
}
