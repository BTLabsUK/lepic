# Helpers the scenarios use to drive the interop stack. Sourced by run.sh.
# shellcheck shell=bash

# Wallet amounts are compared in the smallest unit (1e-8 EPIC) as integers.
UNIT=100000000

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

dc() { docker compose --project-directory "${INTEROP_DIR}" -f "${INTEROP_DIR}/compose.yaml" "$@"; }

# lepic with JSON output; logs go to the run log, and so does a failure's exit status.
lepic() {
    local status=0
    dc exec -T lepic lepic "$@" 2>>"${RUN_LOG}" || status=$?
    ((status == 0)) || printf 'lepic %s exited %d\n' "$*" "${status}" >>"${RUN_LOG}"
    return "${status}"
}

# epic-wallet in the funder or peer container, colour codes stripped.
ew() {
    local wallet="$1" status
    shift
    dc exec -T "${wallet}" ew "$@" 2>>"${RUN_LOG}" | sed 's/\x1b\[[0-9;]*[mK]//g; s/\x1b[()][A-Z0-9]//g'
    status="${PIPESTATUS[0]}"
    ((status == 0)) || printf 'epic-wallet (%s) %s exited %d\n' "${wallet}" "$*" "${status}" >>"${RUN_LOG}"
    return "${status}"
}

# "12.34000000" or "12.34" -> 1234000000
to_units() {
    local text="$1" whole frac
    whole="${text%%.*}"
    frac=""
    [[ "${text}" == *.* ]] && frac="${text#*.}"
    frac="${frac}00000000"
    frac="${frac:0:8}"
    echo $((10#${whole} * UNIT + 10#${frac}))
}

# Runs a check every 2 seconds until it succeeds or `timeout` seconds pass.
wait_until() {
    local what="$1" timeout="$2"
    shift 2
    local deadline=$((SECONDS + timeout))
    until "$@"; do
        if ((SECONDS >= deadline)); then
            log "timed out after ${timeout}s waiting for ${what}"
            return 1
        fi
        sleep 2
    done
}

tip_height() { lepic node status | jq -r .height; }

# Refreshes lepic against the node and prints one balance field in units.
lepic_balance() {
    local field="$1" value
    value="$(lepic wallet info | jq -r ".accounts[0].${field}")"
    to_units "${value}"
}

lepic_tx_state() { lepic tx show "$1" | jq -r .state; }

lepic_tx_count() { lepic tx list | jq '.transactions | length'; }

# The lepic transaction with this slate id, as `tx list` shows it.
lepic_tx_by_slate() { lepic tx list | jq -c --arg id "$1" '.transactions[] | select(.slate_id == $id)'; }

lepic_tx_confirmed() {
    lepic wallet info >/dev/null
    [[ "$(lepic_tx_state "$1")" == confirmed ]]
}

lepic_spendable_at_least() { (($(lepic_balance spendable) >= $1)); }

ew_spendable() {
    local value
    value="$(ew "$1" info | awk -F'|' '/Currently Spendable/ {gsub(/ /, "", $2); print $2}')"
    to_units "${value:-0}"
}

ew_spendable_at_least() { (($(ew_spendable "$1") >= $2)); }

# Prints the `txs` row of the transaction with this slate id.
ew_tx_row() { ew "$1" txs | grep -F -- "$2" | head -n 1; }

ew_tx_known() { [[ -n "$(ew_tx_row "$1" "$2")" ]]; }

ew_tx_confirmed() { ew_tx_row "$1" "$2" | awk '{for (i = 1; i <= NF; i++) if ($i == "true") found = 1} END {exit !found}'; }

ew_address() {
    ew "$1" address | awk '/^Epicbox address/ {getline; getline; print; exit}'
}

# Moves funds from the funder to `wallet` through slate files, the way epic-wallet users fund
# each other offline, and waits until the transaction is mined. Funding transactions go one at a
# time so each send sees the outputs the previous one spent as spent.
fund_by_file() {
    local wallet="$1" amount="$2" name="$3"
    local slate="/exchange/${name}.slate" slate_id
    ew funder send -m file -d "${slate}" -c 1 -s smallest "${amount}" >>"${RUN_LOG}" || return 1
    slate_id="$(dc exec -T funder cat "${slate}" | jq -r .id)"
    if [[ "${wallet}" == lepic ]]; then
        lepic tx receive "${slate}" >>"${RUN_LOG}" || return 1
    else
        ew "${wallet}" receive -i "${slate}" >>"${RUN_LOG}" || return 1
    fi
    ew funder finalize -i "${slate}.response" >>"${RUN_LOG}" || return 1
    wait_until "funding ${name} mined" 120 ew_tx_confirmed funder "${slate_id}"
}

listener_starts() { dc exec -T peer sh -c 'grep -c "Starting epicbox listener" /data/.epic/user/epic-wallet.log 2>/dev/null || true'; }

# Starts epic-wallet's Epicbox listener in the peer container and waits until it subscribed.
peer_listen_start() {
    peer_listen_stop
    local before
    before="$(listener_starts)"
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -d peer sh -c 'echo $$ >/data/listen.pid; exec ew listen -m epicbox >>/data/listen.log 2>&1'
    wait_until "the peer listener" 30 listener_started_after "${before}" || return 1
    # The subscription follows the log line.
    sleep 2
}

listener_started_after() { (($(listener_starts) > $1)); }

peer_listen_stop() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T peer sh -c '
        [ -f /data/listen.pid ] || exit 0
        pid="$(cat /data/listen.pid)"
        kill "${pid}" 2>/dev/null || true
        while kill -0 "${pid}" 2>/dev/null; do sleep 0.2; done
        rm -f /data/listen.pid'
}

# Drains lepic's Epicbox inbox until a jq expression over the summed counters (by default the
# counter `name`) reaches `want`, then prints the summed counters as JSON.
drain_until() {
    local name="$1" want="$2" timeout="$3" expression="${4:-.$1}"
    local deadline=$((SECONDS + timeout))
    local total='{"received":0,"finalized":0,"repeated":0,"rejected":0,"held":0}'
    while :; do
        local report
        report="$(lepic epicbox drain)" || return 1
        total="$(jq -c -n --argjson a "${total}" --argjson b "${report}" \
            '$a | with_entries(.value += ($b[.key] // 0))')"
        if (($(jq -r "${expression}" <<<"${total}") >= want)); then
            echo "${total}"
            return 0
        fi
        if ((SECONDS >= deadline)); then
            log "drain did not reach ${name} >= ${want} in ${timeout}s: ${total}"
            echo "${total}"
            return 1
        fi
        sleep 3
    done
}

relay_healthy() {
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$(dc ps -q epicbox)")" == healthy ]]
}

# Restarts only the relay container. `up` would also recreate the node, whose network namespace
# every other service shares.
restart_relay() {
    dc restart epicbox >/dev/null 2>&1 || return 1
    wait_until "the relay" 60 relay_healthy
}

mongo_eval() {
    dc exec -T mongodb mongosh --quiet -u root -p rootpass --authenticationDatabase admin epicbox \
        --eval "$1"
}
