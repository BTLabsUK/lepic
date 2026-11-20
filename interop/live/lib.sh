# SPDX-License-Identifier: Apache-2.0
# Helpers for the live floonet test. Sourced by run.sh after ../lib.sh, whose generic helpers
# (dc, lepic, ew, to_units, balances, ew_tx_confirmed, drain_until) it reuses with INTEROP_DIR
# pointing at this directory.
# shellcheck shell=bash

# Every wallet command refreshes against the public node, so checks that poll wallets wait
# POLL_INTERVAL seconds between attempts instead of ../lib.sh's two.
POLL_INTERVAL="${LIVE_POLL_INTERVAL:-15}"

# Runs a check every POLL_INTERVAL seconds until it succeeds or `timeout` seconds pass.
poll_until() {
    local what="$1" timeout="$2"
    shift 2
    local deadline=$((SECONDS + timeout))
    until "$@"; do
        if ((SECONDS >= deadline)); then
            log "timed out after ${timeout}s waiting for ${what}"
            return 1
        fi
        sleep "${POLL_INTERVAL}"
    done
}

# A read on the public node's foreign API, the one part of its API it serves without a secret.
# Calls are at least PUBLIC_MIN_GAP seconds apart and each is recorded in PUBLIC_LOG (set by
# run.sh), which also carries the spacing across the subshells that command substitution
# creates. A 429 answer is retried after a growing pause. $1 is the method, $2 its params.
PUBLIC_MIN_GAP=5

public_get() {
    local last wait attempt=1 pause=10 status body
    body="$(jq -cn --arg method "$1" --argjson params "${2:-[]}" \
        '{jsonrpc: "2.0", id: 1, method: $method, params: $params}')"
    while :; do
        last="$(tail -n 1 "${PUBLIC_LOG}" 2>/dev/null | cut -d' ' -f1)"
        wait=$((${last:-0} + PUBLIC_MIN_GAP - $(date +%s)))
        if ((wait > 0)); then sleep "${wait}"; fi
        echo "$(date +%s) POST $1" >>"${PUBLIC_LOG}"
        status="$(curl -sS -m 20 -o "${PUBLIC_LOG}.body" -w '%{http_code}' \
            -H 'Content-Type: application/json' -d "${body}" \
            "${LIVE_NODE_URL}/v2/foreign" 2>>"${RUN_LOG}")" || status=000
        if [[ "${status}" == 429 && attempt -lt 6 ]]; then
            log "public node rate limited ${1}; retrying in ${pause}s"
            sleep "${pause}"
            pause=$((pause * 2))
            attempt=$((attempt + 1))
            continue
        fi
        [[ "${status}" == 200 ]] || { printf 'POST %s: HTTP %s\n' "$1" "${status}" >>"${RUN_LOG}"; return 1; }
        cat "${PUBLIC_LOG}.body"
        return 0
    done
}

public_calls() { wc -l <"${PUBLIC_LOG}" 2>/dev/null || echo 0; }

public_height() { public_get get_tip | jq -r '.result.Ok.height'; }

# Height of the block holding a kernel, as the public node reports it.
public_kernel_height() {
    public_get get_kernel "$(jq -cn --arg excess "$1" '[$excess, null, null]')" |
        jq -r '.result.Ok.height // empty'
}

public_has_kernel() { [[ -n "$(public_kernel_height "$1")" ]]; }

miner_running() { [[ -n "$(dc --profile mining ps -q miner 2>/dev/null)" ]]; }

miner_start() {
    miner_running && return 0
    log "mining started at height $(public_height)"
    # Only the miner: a plain `up` could rebuild and recreate the proxy and the funder mid-run.
    dc --profile mining up -d --no-deps --no-build miner >>"${RUN_LOG}" 2>&1
}

miner_stop() {
    miner_running || return 0
    dc --profile mining stop miner >>"${RUN_LOG}" 2>&1
    log "mining stopped at height $(public_height)"
}

# Mines only while a check is pending: starts the miner, waits for the check, stops the miner.
mine_until() {
    local what="$1" timeout="$2" status=0
    shift 2
    miner_start || return 1
    poll_until "${what}" "${timeout}" "$@" || status=$?
    miner_stop
    return "${status}"
}

# The kernel excess epic-wallet recorded for a slate, as hex.
ew_tx_kernel() {
    ew "$1" txs -t "$2" | grep -oE '\b0[89][0-9a-f]{64}\b' | head -n 1
}

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
