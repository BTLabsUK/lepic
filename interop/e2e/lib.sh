# SPDX-License-Identifier: Apache-2.0
# Helpers the end-to-end cases use: named wallets on floonet, background listeners, funding from
# a bank wallet, block waits and assertions. Sourced by run.sh after ../lib.sh.
# shellcheck shell=bash

# Where the warm state lives: wallets, config, password file, the bank. Outside the repository so
# a run keeps its wallets and funds for the next one.
E2E_STATE="${LEPIC_E2E_STATE:-${HOME}/epic-build/epic1-suite/state}"
E2E_NODE="${LEPIC_E2E_NODE:-https://floo-node.btlabs.uk}"
E2E_RELAY="${LEPIC_E2E_RELAY:-epicbox.btlabs.uk}"
# A second relay for links that name more than one, and for relay moves.
E2E_RELAY2="${LEPIC_E2E_RELAY2:-epicbox.stackwallet.com}"
# Confirmations a send needs on its inputs. The miner runs while cases run, so one is enough.
E2E_MINCONF="${LEPIC_E2E_MINCONF:-1}"
# The QA funder and the lock that serialises its use across parallel runs.
E2E_FUNDER="${LEPIC_E2E_FUNDER:-${HOME}/epic/qa-funder/fund.sh}"
E2E_FUNDER_LOCK="${HOME}/.cache/lepic-e2e-funder.lock"
# A file a host's mining guard reads before it lets a miner start. When set, the runner writes it
# for the miner's lifetime and removes it after; unset, it writes nothing.
E2E_MINER_ALLOW="${LEPIC_E2E_MINER_ALLOW:-}"
E2E_TOR_DIR="${LEPIC_E2E_TOR_DIR:-${HOME}/.cache/wfe-linux-build/work/tor-bundle}"
# Wallet names start with this, so the test database and the state directory show what they are.
E2E_PREFIX="e1s"

# Background processes this run started: pid -> log prefix, stopped by e2e_cleanup.
declare -gA E2E_BG=()

e2e_init_state() {
    mkdir -p "${E2E_STATE}/wallets" "${E2E_STATE}/home" "${E2E_STATE}/files"
    chmod 700 "${E2E_STATE}"
    if [[ ! -s "${E2E_STATE}/pw" ]]; then
        (umask 077 && printf 'e1s-suite-%s\n' "$(head -c 9 /dev/urandom | base64 | tr -d '/+=')" >"${E2E_STATE}/pw")
    fi
    cat >"${E2E_STATE}/config.toml" <<EOF
network = "floonet"
node_url = "${E2E_NODE}"
epicbox_relay = "${E2E_RELAY}"
password_file = "${E2E_STATE}/pw"
EOF
    # The servers list the CLI writes on first use; kept here so ~/.lepic is never read.
    [[ -s "${E2E_STATE}/settings.toml" ]] || cp "${LEPIC_E2E_SETTINGS:-${HOME}/.lepic/settings.toml}" "${E2E_STATE}/settings.toml"
}

wdir() { echo "${E2E_STATE}/wallets/$1"; }

# Extra config for one wallet: a file wallets/<name>.toml replaces the shared config when present.
wconfig() {
    local own="${E2E_STATE}/wallets/$1.toml"
    if [[ -f "${own}" ]]; then echo "${own}"; else echo "${E2E_STATE}/config.toml"; fi
}

# Writes a per-wallet config: the shared one plus the given lines (key = value).
wconfig_set() {
    local name="$1"
    shift
    {
        cat "${E2E_STATE}/config.toml"
        printf '%s\n' "$@"
    } >"${E2E_STATE}/wallets/${name}.toml"
}

wconfig_reset() { rm -f "${E2E_STATE}/wallets/$1.toml"; }

lepic_env() {
    local name="$1"
    shift
    env -i PATH="${PATH}" HOME="${E2E_STATE}/home" LEPIC_CONFIG="$(wconfig "${name}")" \
        LEPIC_SETTINGS="${E2E_STATE}/settings.toml" LEPIC_PASSWORD_FILE="${E2E_STATE}/pw" \
        "${LEPIC_BIN}" --network floonet --data-dir "$(wdir "${name}")" "$@"
}

# `w <wallet> <args>`: lepic on that wallet with JSON output. stdout is the JSON; stderr goes to
# the run log, and a failure's exit status and error are logged with the command.
w() {
    local name="$1" status=0 err="${CASE_DIR:-${RUN_DIR}}/last.err"
    shift
    lepic_env "${name}" --output json "$@" 2>"${err}" || status=$?
    if ((status != 0)); then
        printf '[%s] %s: lepic %s exited %d\n' "$(date -u +%H:%M:%S)" "${name}" "$*" "${status}" >>"${RUN_LOG}"
        cat "${err}" >>"${RUN_LOG}"
    fi
    return "${status}"
}

# `wx <status> <wallet> <args>`: the command must exit with exactly that status. Its JSON error is
# left in LAST_JSON.
wx() {
    local want="$1" name="$2" got=0
    shift 2
    LAST_JSON="$(lepic_env "${name}" --output json "$@" 2>"${CASE_DIR:-${RUN_DIR}}/last.err")" || got=$?
    LAST_ERR="$(cat "${CASE_DIR:-${RUN_DIR}}/last.err")"
    if ((got != want)); then
        printf '[%s] %s: lepic %s exited %d, wanted %d\n%s\n%s\n' "$(date -u +%H:%M:%S)" "${name}" "$*" \
            "${got}" "${want}" "${LAST_JSON}" "${LAST_ERR}" >>"${RUN_LOG}"
        fail "lepic $* exited ${got}, wanted ${want}: $(tail -c 300 <<<"${LAST_ERR}${LAST_JSON}")"
    fi
}

# Starts lepic in the background on a wallet; prints nothing, sets BG_PID and BG_LOG.
wbg() {
    local name="$1" tag="$2"
    shift 2
    BG_LOG="${CASE_DIR:-${RUN_DIR}}/${name}.${tag}"
    # The child keeps no copy of this run's lock descriptors, so a listener never holds a lock.
    (
        for fd in /proc/${BASHPID}/fd/*; do
            fd="${fd##*/}"
            ((fd > 2)) && eval "exec ${fd}>&-" 2>/dev/null
        done
        exec env -i PATH="${PATH}" HOME="${E2E_STATE}/home" LEPIC_CONFIG="$(wconfig "${name}")" \
            LEPIC_SETTINGS="${E2E_STATE}/settings.toml" LEPIC_PASSWORD_FILE="${E2E_STATE}/pw" \
            "${LEPIC_BIN}" --network floonet --data-dir "$(wdir "${name}")" --log-level info "$@"
    ) >"${BG_LOG}.out" 2>"${BG_LOG}.err" </dev/null &
    BG_PID=$!
    E2E_BG[${BG_PID}]="${BG_LOG}"
}

wstop() {
    local pid="$1"
    [[ -n "${pid}" ]] || return 0
    kill -INT "${pid}" 2>/dev/null || true
    local deadline=$((SECONDS + 20))
    while kill -0 "${pid}" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.3; done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    unset "E2E_BG[${pid}]"
}

e2e_cleanup() {
    local pid
    for pid in "${!E2E_BG[@]}"; do wstop "${pid}"; done
}

# Listens on Epicbox in the background until wstop; waits for the relay connection.
epicbox_listen() {
    wbg "$1" epicbox epicbox listen
    EPICBOX_PID=${BG_PID}
    wait_until "$1 connected to the relay" 40 grep -q "connected to the relay" "${BG_LOG}.err"
}

# HTTP listener on a free loopback port; sets HTTP_PID, HTTP_PORT and HTTP_URL.
http_listen() {
    local name="$1"
    shift
    wbg "${name}" http http listen --port 0 "$@"
    HTTP_PID=${BG_PID}
    wait_until "${name} http listener" 20 grep -q 'Listening for payments over HTTP on port' "${BG_LOG}.err" || return 1
    HTTP_PORT="$(sed -n 's/.*on port \([0-9]*\).*/\1/p' "${BG_LOG}.err" | head -n 1)"
    HTTP_URL="http://127.0.0.1:${HTTP_PORT}"
}

# Creates a wallet when it does not exist yet and records it in the test database.
ensure_wallet() {
    local name="$1" words="${2:-12}"
    if [[ ! -d "$(wdir "${name}")" ]]; then
        local out
        out="$(w "${name}" wallet init --words "${words}")" || return 1
        (umask 077 && printf '%s\n' "${out}" >"${E2E_STATE}/wallets/${name}.init.json")
        testdb_wallet "${name}" "$(jq -r .recovery_phrase <<<"${out}")"
    fi
}

# The phrase goes in the environment and the password is read from its file, so neither is in
# any process's argument list.
testdb_wallet() {
    local name="$1" phrase="$2" address
    address="$(w "${name}" wallet address | jq -r '.address // .epicbox // empty' 2>/dev/null || true)"
    E2E_TESTDB_PHRASE="${phrase}" python3 - "${name}" "${E2E_STATE}/pw" "${address}" <<'PY' >>"${RUN_LOG}" 2>&1 || true
import sys, os
sys.path.insert(0, os.path.expanduser("~/wallet-for-epic/tools/rellib/testdb"))
from client import emit
name, password_file, address = sys.argv[1:4]
phrase = os.environ.pop("E2E_TESTDB_PHRASE")
with open(password_file, encoding="utf-8") as f:
    password = f.read().rstrip("\n")
emit("wallet.put", name=name, role="qa", platform="linux-cli", phrase=phrase, password=password,
     note="epic1 e2e suite (interop/e2e), floonet", origin="lepic interop/e2e", state="active")
if address:
    emit("wallet.address", name=name, role="qa", kind="epicbox", address=address)
PY
}

balance() { w "$1" wallet info | jq -r ".accounts[0].${2:-spendable}"; }
balance_units() {
    local b
    b="$(balance "$1" "${2:-spendable}")" || return 1
    [[ "${b}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
    to_units "${b}"
}
# Units a send with --min-confirmations E2E_MINCONF can spend: the wallet's own spendable figure
# waits for 6 confirmations, which on a slow floonet is minutes more than the suite's sends need.
usable_units() {
    w "$1" wallet info >/dev/null || return 1
    w "$1" wallet outputs | jq -r --argjson c "${E2E_MINCONF}" '
        [.outputs[] | select((.category == "spendable" or .category == "awaiting_confirmation")
            and .confirmations >= $c) | .value | split(".") | (.[0] | tonumber) * 100000000
            + ((.[1] // "0") + "00000000" | .[0:8] | tonumber)] | add // 0'
}
spendable_at_least() {
    local have
    have="$(usable_units "$1")" || return 1
    [[ "${have}" =~ ^[0-9]+$ ]] || return 1
    ((have >= $2))
}
tip() { w "${E2E_PREFIX}-bank" node status 2>/dev/null | jq -r .height; }

# Funds a wallet from the bank until it holds `amount` spendable in at least `outputs` outputs of
# its own, each send a separate output. The bank is refilled from the QA funder when it runs low.
ensure_funds() {
    local name="$1" amount="$2" outputs="${3:-2}" want have per i sent=0 target_pid target_url out
    want="$(to_units "${amount}")"
    have="$(usable_units "${name}")" || return 1
    ((have >= want)) && return 0
    per=$(((want - have) / outputs + UNIT / 10))
    log "funding ${name} with ${outputs} x $(from_units "${per}") from the bank"
    exec {bank_fd}>>"${E2E_STATE}/bank.lock"
    flock "${bank_fd}"
    http_listen "${name}" || { exec {bank_fd}>&-; return 1; }
    # A bank refill starts its own listener, which replaces HTTP_PID and HTTP_URL.
    target_pid="${HTTP_PID}"
    target_url="${HTTP_URL}"
    for ((i = 0; i < outputs; i++)); do
        bank_ready "$(((per + UNIT / 10)))" || break
        out="$(w "${E2E_PREFIX}-bank" tx send --to "${target_url}" --min-confirmations "${E2E_MINCONF}" \
            --change-outputs 3 "$(from_units "${per}")")" || { bank_cancel_failed "${out}"; break; }
        sent=$((sent + 1))
    done
    wstop "${target_pid}"
    exec {bank_fd}>&-
    ((sent > 0)) || { log "the bank sent nothing to ${name}"; return 1; }
    wait_until "${name} funds confirmed" 180 spendable_at_least "${name}" "${want}"
}

# A bank send that failed after it stored its transaction holds its inputs until cancelled.
bank_cancel_failed() {
    local id
    # With --output json the error is the JSON on stdout.
    id="$(jq -r '.error.tx_id // empty' <<<"$1" 2>/dev/null)"
    [[ -n "${id}" ]] || return 0
    log "cancelling the bank's failed send ${id}"
    w "${E2E_PREFIX}-bank" tx cancel "${id}" >/dev/null || true
}

# Waits for the bank to have `units` spendable; refills it from the QA funder below the floor.
bank_ready() {
    local units="$1" bank="${E2E_PREFIX}-bank" total
    spendable_at_least "${bank}" "${units}" && return 0
    # Change waiting for its confirmation counts in the total, under whichever field holds it.
    total="$(balance_units "${bank}" total)" || return 1
    if ((total < units + UNIT)); then
        log "the bank is low; refilling it from the QA funder"
        fund_bank "${LEPIC_E2E_BANK_REFILL:-30}" || return 1
        wait_until "bank refill confirmed" 300 spendable_at_least "${bank}" "${units}"
        return
    fi
    wait_until "bank change confirmed" 180 spendable_at_least "${bank}" "${units}"
}

# One QA funder send to the bank over HTTP. The funder needs 10 confirmations on its change, so
# calls are serialised by a host-wide lock and the miner must be running between them.
fund_bank() {
    local amount="$1" bank="${E2E_PREFIX}-bank" status=1 attempt out
    exec {fund_fd}>>"${E2E_FUNDER_LOCK}"
    flock "${fund_fd}"
    http_listen "${bank}" || { exec {fund_fd}>&-; return 1; }
    out="${CASE_DIR:-${RUN_DIR}}/fund.out"
    # The funder's own change needs 10 confirmations; until then it reports no funds.
    for ((attempt = 1; attempt <= 15; attempt++)); do
        status=0
        "${E2E_FUNDER}" "${HTTP_URL}" "${amount}" >"${out}" 2>&1 || status=$?
        cat "${out}" >>"${RUN_LOG}"
        ((status == 0)) && break
        grep -q 'Not enough funds' "${out}" || break
        log "the QA funder's change is not yet confirmed; trying again (${attempt})"
        sleep 20
    done
    wstop "${HTTP_PID}"
    exec {fund_fd}>&-
    ((status == 0)) || { log "fund.sh failed (${status}); see ${RUN_LOG}"; return 1; }
    printf '%s fund_bank %s\n' "$(date -u +%FT%TZ)" "${amount}" >>"${E2E_STATE}/funding.log"
}

# The miner moves blocks only; its rewards go to the node's own wallet, never to a test wallet.
# Runs share it: each registers its pid under miner.users, the first starts it and the last one
# out stops it.
MINER_STARTED=false
miner_start() {
    [[ "${E2E_MINE:-true}" == true ]] || return 0
    local users="${E2E_STATE}/miner.users" allow="${E2E_MINER_ALLOW}"
    mkdir -p "${users}"
    exec {miner_fd}>>"${E2E_STATE}/miner.lock"
    flock "${miner_fd}"
    : >"${users}/$$"
    MINER_STARTED=true
    MINER_T0=${SECONDS}
    if pm2 pid floo-miner 2>/dev/null | grep -Eq '^[1-9]'; then
        log "floo-miner already running; sharing it"
    else
        if [[ -n "${allow}" && ! -f "${allow}" ]]; then
            mkdir -p "$(dirname "${allow}")"
            printf '{"until": "%s", "reason": "LEPIC epic1 e2e suite: confirm test transactions (interop/e2e)", "by": "interop/e2e"}\n' \
                "$(date -d '+5 hours' --iso-8601=seconds)" >"${allow}"
        fi
        if (cd "${HOME}/epic/floo-miner" && pm2 start ecosystem.config.cjs) >>"${RUN_LOG}" 2>&1; then
            log "floo-miner started"
        else
            log "the miner did not start; blocks will not move"
        fi
    fi
    exec {miner_fd}>&-
}

# The miner binary pm2 runs. `pm2 delete` can leave it behind: it holds its RandomX dataset and
# keeps mining. miner_reap ends what is left: TERM, then KILL after 10 s.
MINER_BIN="${HOME}/epic/floo-miner/bin/epic-miner.real"
miner_reap() {
    local i
    pgrep -f "${MINER_BIN}" >/dev/null || return 0
    pkill -TERM -f "${MINER_BIN}" || true
    for ((i = 0; i < 20; i++)); do
        pgrep -f "${MINER_BIN}" >/dev/null || return 0
        sleep 0.5
    done
    pkill -KILL -f "${MINER_BIN}" || true
    sleep 1
}

miner_stop() {
    [[ "${MINER_STARTED}" == true ]] || return 0
    local users="${E2E_STATE}/miner.users" f others=0 allow="${E2E_MINER_ALLOW}"
    exec {miner_fd}>>"${E2E_STATE}/miner.lock"
    flock "${miner_fd}"
    rm -f "${users}/$$"
    for f in "${users}"/*; do
        [[ -e "${f}" ]] || continue
        if kill -0 "${f##*/}" 2>/dev/null; then others=$((others + 1)); else rm -f "${f}"; fi
    done
    if ((others == 0)); then
        pm2 delete floo-miner >>"${RUN_LOG}" 2>&1 || true
        miner_reap
        [[ -z "${allow}" ]] || { grep -q '"by": "interop/e2e"' "${allow}" 2>/dev/null && rm -f "${allow}"; }
        if pgrep -f "${MINER_BIN}" >/dev/null; then
            log "epic-miner.real is still running after the stop; see ps aux | grep epic-miner.real"
        else
            log "floo-miner stopped"
        fi
    else
        log "floo-miner left running for ${others} other run(s)"
    fi
    exec {miner_fd}>&-
    MINER_STARTED=false
    local spent=$((SECONDS - MINER_T0))
    printf '%s run %s held the miner %ss\n' "$(date -u +%FT%TZ)" "$$" "${spent}" >>"${E2E_STATE}/miner.log"
}

# Blocks: waits until the tip is `n` past where it is now.
wait_blocks() {
    local n="${1:-1}" start
    start="$(tip)"
    wait_until "${n} blocks past ${start}" $((60 + n * 30)) tip_above $((start + n - 1))
}
tip_above() { (($(tip) > $1)); }

# Transactions -------------------------------------------------------------------------------

tx_by_slate() { w "$1" tx list | jq -c --arg id "$2" '[.transactions[] | select(.slate_id == $id)] | first // empty'; }
tx_state() { w "$1" tx show "$2" | jq -r .state; }
tx_state_is() { [[ "$(tx_state "$1" "$2")" == "$3" ]]; }
slate_state_is() { [[ "$(tx_by_slate "$1" "$2" | jq -r '.state // empty')" == "$3" ]]; }
slate_state_in() {
    local s
    s="$(tx_by_slate "$1" "$2" | jq -r '.state // empty')"
    [[ " $3 " == *" ${s} "* ]]
}

# Assertions: each sets DETAIL and fails.
fail() {
    DETAIL="$*"
    printf '%s' "$*" >"${CASE_DIR:-${RUN_DIR}}/detail.txt"
    return 1
}
# A passing case's detail: what it saw (a time, a height, a count).
note() {
    DETAIL="$*"
    printf '%s' "$*" >"${CASE_DIR:-${RUN_DIR}}/detail.txt"
}
expect_eq() { [[ "$1" == "$2" ]] || fail "${3:-value}: got '$1', wanted '$2'"; }
expect_match() { [[ "$1" =~ $2 ]] || fail "${3:-value}: '$1' does not match /$2/"; }
expect_json() {
    local json="$1" filter="$2" what="${3:-$2}"
    jq -e "${filter}" >/dev/null <<<"${json}" || fail "${what}: $(head -c 300 <<<"${json}")"
}
