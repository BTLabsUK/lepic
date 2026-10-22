# Helpers the scenarios use to drive the interop stack. Sourced by run.sh.
# shellcheck shell=bash

# Wallet amounts are compared in the smallest unit (1e-8 EPIC) as integers.
UNIT=100000000

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

dc() { docker compose --project-directory "${INTEROP_DIR}" -f "${INTEROP_DIR}/compose.yaml" "$@"; }

# Allows one run of compose project $1 at a time on this host. Every worktree's copy of a stack
# shares its project name and ports, so a second run's start or teardown removes the first run's
# containers. The lock is released when the script exits.
hold_stack() {
    local lock="${TMPDIR:-/tmp}/$1.lock"
    if ! command -v flock >/dev/null; then
        log "flock not found; a concurrent $1 run would not be noticed"
        return 0
    fi
    exec {STACK_LOCK_FD}<>"${lock}"
    if ! flock -n "${STACK_LOCK_FD}"; then
        log "another $1 run is active on this host (lock ${lock}); wait for it to end"
        exit 1
    fi
}

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

# Pays an invoice slate file from the epic-wallet in `wallet`. Its `pay` asks for the invoice
# amount on a prompt that needs a terminal, so it runs under `script` and the amount is typed in.
ew_pay() {
    local wallet="$1" amount="$2" status
    shift 2
    local command
    command="ew pay $(printf '%q ' "$@")"
    printf '%s\n' "${amount}" |
        dc exec -T "${wallet}" timeout 120 script -qec "${command}" /dev/null >>"${RUN_LOG}" 2>&1
    status="${PIPESTATUS[1]}"
    ((status == 0)) || printf 'epic-wallet (%s) pay %s exited %d\n' "${wallet}" "$*" "${status}" >>"${RUN_LOG}"
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

listener_starts() { dc exec -T "$1" sh -c 'grep -c "Starting epicbox listener" /data/.epic/user/epic-wallet.log 2>/dev/null || true'; }

# Starts epic-wallet's Epicbox listener in the funder or peer container and waits until it
# subscribed.
ew_listen_start() {
    local wallet="$1"
    ew_listen_stop "${wallet}"
    local before
    before="$(listener_starts "${wallet}")"
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -d "${wallet}" sh -c 'echo $$ >/data/listen.pid; exec ew listen -m epicbox >>/data/listen.log 2>&1'
    wait_until "the ${wallet} listener" 30 listener_started_after "${wallet}" "${before}" || return 1
    # The subscription follows the log line.
    sleep 2
}

listener_started_after() { (($(listener_starts "$1") > $2)); }

ew_listen_stop() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T "$1" sh -c '
        [ -f /data/listen.pid ] || exit 0
        pid="$(cat /data/listen.pid)"
        kill "${pid}" 2>/dev/null || true
        while kill -0 "${pid}" 2>/dev/null; do sleep 0.2; done
        rm -f /data/listen.pid'
}

# True while the Epicbox listener ew_listen_start started in that container runs.
ew_listening() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T "$1" sh -c '[ -f /data/listen.pid ] && kill -0 "$(cat /data/listen.pid)" 2>/dev/null'
}

# Ports of the HTTP listeners the HTTP scenarios start. The funder's foreign API holds 23415 and
# the miner's stratum server 23416 in the shared namespace.
PEER_HTTP_PORT=23500
LEPIC_HTTP_PORT=23510

http_port_open() { dc exec -T "$1" curl -s -o /dev/null "http://127.0.0.1:$2/v2/foreign"; }

# Starts `epic-wallet listen -m http` in the peer container and waits until the port answers. It
# shares the pid file of the Epicbox listener, so ew_listen_stop stops either.
peer_http_listen_start() {
    ew_listen_stop peer
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -d peer sh -c "echo \$\$ >/data/listen.pid; exec ew listen -m http -n -l ${PEER_HTTP_PORT} >>/data/listen.log 2>&1"
    wait_until "the peer http listener" 30 http_port_open peer "${PEER_HTTP_PORT}"
}

# Starts `lepic http listen` in the lepic container and waits until the port answers.
lepic_http_listen_start() {
    lepic_http_listen_stop >/dev/null
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -d lepic sh -c "rm -f /data/http.log; echo \$\$ >/data/http.pid; exec lepic http listen --port ${LEPIC_HTTP_PORT} >/data/http.log 2>&1"
    wait_until "the lepic http listener" 30 http_port_open lepic "${LEPIC_HTTP_PORT}"
}

# Interrupts the lepic listener as Ctrl-C would and prints its report (the last log line).
lepic_http_listen_stop() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T lepic sh -c '
        [ -f /data/http.pid ] || exit 0
        pid="$(cat /data/http.pid)"
        kill -INT "${pid}" 2>/dev/null || true
        n=0
        while kill -0 "${pid}" 2>/dev/null && [ "${n}" -lt 100 ]; do sleep 0.2; n=$((n + 1)); done
        rm -f /data/http.pid
        tail -n 1 /data/http.log'
}

peer_listen_start() { ew_listen_start peer; }

peer_listen_stop() { ew_listen_stop peer; }

# Drains lepic's Epicbox inbox until a jq expression over the summed counters (by default the
# counter `name`) reaches `want`, then prints the summed counters as JSON.
drain_until() {
    local name="$1" want="$2" timeout="$3" expression="${4:-.$1}"
    local deadline=$((SECONDS + timeout))
    local total='{"received":0,"finalized":0,"repeated":0,"rejected":0,"held":0,"parked":0,"bounced":0,"dropped":0,"notices":0}'
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
