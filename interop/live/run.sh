#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live floonet smoke test between lepic and epic-wallet v4.0.2, over slate files and over a local
# Epicbox relay, on the public floonet chain. Opt-in: does nothing unless LEPIC_LIVE_TESTS=1.
#
#   LEPIC_LIVE_TESTS=1 ./run.sh             build what changed, start the stack, fund, test
#   LEPIC_LIVE_TESTS=1 ./run.sh --no-build  reuse the images and binaries already built
#   LEPIC_LIVE_TESTS=1 ./run.sh --down      stop the stack afterwards
#   LEPIC_LIVE_TESTS=1 ./run.sh --mine-funds  fund the funder by mining coinbase, not from
#                                             LEPIC_LIVE_FUNDER
#
# No node runs locally: both wallets and the miner use the public floonet node's foreign API
# (LIVE_NODE_URL), and the stack stays up by default so the wallets stay usable by hand.
#
# The funder wallet is topped up from an outside floonet wallet, LEPIC_LIVE_FUNDER (see the
# README). It mines its own coinbase only with --mine-funds, without that command, or when that
# wallet holds too little. Mining otherwise happens only while funding transactions confirm and
# while each test transaction waits for its block. Prints a table with every kernel excess
# and the height the public floonet node reports for it. Exits 0 only when every step passed.
set -euo pipefail

LIVE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${LEPIC_LIVE_TESTS:-}" != 1 ]]; then
    echo "live floonet test skipped: set LEPIC_LIVE_TESTS=1 to run it" >&2
    exit 0
fi

down=false
build=true
mine_funds=false
for arg in "$@"; do
    case "${arg}" in
        --down) down=true ;;
        --no-build) build=false ;;
        --mine-funds) mine_funds=true ;;
        *) echo "unknown option ${arg}" >&2; exit 2 ;;
    esac
done

# ../lib.sh drives the compose project in INTEROP_DIR; here that is this directory's stack.
INTEROP_DIR="${LIVE_DIR}"
# shellcheck source=../lib.sh
source "${LIVE_DIR}/../lib.sh"
# shellcheck source=lib.sh
source "${LIVE_DIR}/lib.sh"
hold_stack lepic-live

LIVE_INTEROP_DIR="$(cd "${LIVE_DIR}/.." && pwd)"
LIVE_UID="$(id -u)"
LIVE_GID="$(id -g)"
# The floonet node every wallet and the miner use, through its foreign API.
LIVE_NODE_URL="${LIVE_NODE_URL:-https://floo-node.btlabs.uk}"
export LIVE_INTEROP_DIR LIVE_UID LIVE_GID LIVE_NODE_URL
# Compose reads .env from this directory, so `docker compose` here works by hand as well.
printf 'LIVE_INTEROP_DIR=%s\nLIVE_UID=%s\nLIVE_GID=%s\nLIVE_NODE_URL=%s\n' \
    "${LIVE_INTEROP_DIR}" "${LIVE_UID}" "${LIVE_GID}" "${LIVE_NODE_URL}" >"${LIVE_DIR}/.env"

# Each wallet is topped up with this many funding outputs of this size when its spendable
# balance is below the minimum, which leaves room for several test transactions.
FUND_OUTPUTS="${LIVE_FUND_OUTPUTS:-3}"
FUND_AMOUNT="${LIVE_FUND_AMOUNT:-5}"
FUND_MINIMUM=$((${LIVE_FUND_MINIMUM:-8} * UNIT))
# A confirmation wait covers many blocks of slack.
CONFIRM_TIMEOUT="${LIVE_CONFIRM_TIMEOUT:-1800}"
# A command that pays floonet EPIC: `<command> <http-url> <amount>` sends, `<command> info` prints
# an epic-wallet info table. The QA funder's fund.sh by default, when it is there; set it empty
# to mine instead.
if [[ -z "${LEPIC_LIVE_FUNDER+set}" && -x "${HOME}/epic/qa-funder/fund.sh" ]]; then
    LEPIC_LIVE_FUNDER="${HOME}/epic/qa-funder/fund.sh"
fi
LEPIC_LIVE_FUNDER="${LEPIC_LIVE_FUNDER:-}"
# The funder's foreign listener, which the outside wallet pays over HTTP.
FUNDER_URL="http://127.0.0.1:33415"

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
log_dir="${LIVE_INTEROP_DIR}/.work/live/logs/${run_id}"
mkdir -p "${log_dir}" "${LIVE_DIR}"/data/{funder,peer,lepic,exchange} "${LIVE_INTEROP_DIR}/.work/live/proxy"
PROXY_STATS="${LIVE_INTEROP_DIR}/.work/live/proxy/calls.json"
RUN_LOG="${log_dir}/run.log"
PUBLIC_LOG="${log_dir}/public-calls.log"
: >"${RUN_LOG}"
: >"${PUBLIC_LOG}"

teardown() {
    miner_stop >/dev/null 2>&1 || true
    listen_stop >/dev/null 2>&1 || true
    dc --profile mining logs --no-color --timestamps >"${log_dir}/compose.log" 2>&1 || true
    if [[ "${down}" == true ]]; then
        # Without -v: the wallets are bind mounts and stay; only containers go.
        dc --profile mining down --remove-orphans >/dev/null 2>&1 || true
    fi
}
# The exit status is the last line of every run's output, whatever ended it.
finish() {
    local status=$?
    teardown
    printf 'exit status: %d\n' "${status}"
}
trap finish EXIT

log "floonet node ${LIVE_NODE_URL} through the proxy; lepic node ${LEPIC_TEST_NODE_URL:-the proxy}," \
    "relay ${LEPIC_TEST_RELAY:-ws://localhost:33423}"

if [[ "${build}" == true ]]; then
    log "building binaries (incremental; the first build takes a while)"
    "${LIVE_DIR}/build.sh" >>"${RUN_LOG}" 2>&1
fi

log "starting the stack"
{
    dc build
    dc up -d --wait --wait-timeout 300
} >>"${RUN_LOG}" 2>&1

# The proxy counts every request it sends upstream since it started; the run reports the change.
proxy_count() { jq -r ".${1}" "${PROXY_STATS}" 2>/dev/null || echo 0; }
proxy_total_before="$(proxy_count total)"
proxy_limited_before="$(proxy_count rate_limited)"

names=()
results=()
times=()
details=()
kernels=()
failed=0
DETAIL=""
KERNEL=""

run_step() {
    local name="$1" function="$2" started=${SECONDS} result
    log "${name}"
    DETAIL=""
    KERNEL=""
    if "${function}"; then result=PASS; else result=FAIL; failed=$((failed + 1)); fi
    names+=("${name}")
    results+=("${result}")
    times+=("$((SECONDS - started))s")
    details+=("${DETAIL}")
    kernels+=("${KERNEL:--}")
    log "${result}: ${DETAIL}"
}

fail() {
    DETAIL="$*"
    return 1
}

LEPIC_ADDRESS=""
PEER_ADDRESS=""

step_node() {
    local height
    height="$(public_height)" || fail "the floonet node does not answer" || return 1
    DETAIL="floonet node at height ${height}"
}

lepic_wallet_exists() { [[ -n "$(ls -A "${LIVE_DIR}/data/lepic/lepic" 2>/dev/null)" ]]; }

step_wallets() {
    if ! lepic_wallet_exists; then
        log "creating the lepic floonet wallet"
        # The output carries the recovery phrase; only the network is read from it.
        lepic wallet init | jq -e '.network == "floonet"' >/dev/null ||
            fail "lepic wallet init failed" || return 1
    fi
    LEPIC_ADDRESS="$(lepic wallet address | jq -r .address)"
    local peer
    peer="$(ew_address peer)"
    [[ -n "${peer}" ]] || fail "no epic-wallet address" || return 1
    PEER_ADDRESS="${peer%%:*}:33423"
    log "lepic ${LEPIC_ADDRESS}, epic-wallet ${PEER_ADDRESS}"
    DETAIL="lepic ${LEPIC_ADDRESS%%@*}, epic-wallet ${PEER_ADDRESS%%@*}"
}

# Funder -> wallet through slate files; waits until the funder sees it confirmed. The miner is
# already running.
fund_one() {
    local wallet="$1" name="$2"
    local slate="/exchange/${name}.slate" slate_id
    ew funder send -m file -d "${slate}" -c 1 -s smallest "${FUND_AMOUNT}" >>"${RUN_LOG}" || return 1
    slate_id="$(jq -r .id "${LIVE_DIR}/data/exchange/${name}.slate")"
    if [[ "${wallet}" == lepic ]]; then
        lepic tx receive "${slate}" >>"${RUN_LOG}" || return 1
    else
        ew "${wallet}" receive -i "${slate}" >>"${RUN_LOG}" || return 1
    fi
    ew funder finalize -i "${slate}.response" >>"${RUN_LOG}" || return 1
    poll_until "funding ${name} confirmed" "${CONFIRM_TIMEOUT}" ew_tx_confirmed funder "${slate_id}"
}

lepic_spendable() { lepic_balance spendable; }

# Spendable units of the outside funding wallet, from its info table; 0 when it does not answer.
outside_spendable() {
    local value
    value="$("${LEPIC_LIVE_FUNDER}" info 2>>"${RUN_LOG}" |
        awk -F'|' '/Currently Spendable/ {gsub(/ /, "", $2); print $2}')" || true
    to_units "${value:-0}"
}

# Gets the funder `units` spendable at one confirmation: paid by LEPIC_LIVE_FUNDER over HTTP when
# that wallet holds enough, or mined as coinbase (30 blocks to mature) otherwise.
top_up_funder() {
    local units="$1" has amount
    if [[ "${mine_funds}" == false && -n "${LEPIC_LIVE_FUNDER}" ]]; then
        has="$(outside_spendable)"
        # A margin of one EPIC for the payment's own fee.
        if ((has >= units + UNIT)); then
            amount="$(jq -n "${units} / ${UNIT}")"
            log "paying the funder ${amount} EPIC from ${LEPIC_LIVE_FUNDER}"
            "${LEPIC_LIVE_FUNDER}" "${FUNDER_URL}" "${amount}" >>"${RUN_LOG}" 2>&1 ||
                fail "${LEPIC_LIVE_FUNDER} did not pay the funder" || return 1
            mine_until "the funder's payment confirmed" "${CONFIRM_TIMEOUT}" \
                ew_spendable_at_least funder "${units}" 1 ||
                fail "the payment to the funder did not confirm" || return 1
            return 0
        fi
        log "${LEPIC_LIVE_FUNDER} holds $(jq -n "${has} / ${UNIT}") EPIC, too little; mining instead"
    fi
    miner_start || fail "the miner did not start" || return 1
    log "waiting for ${units} units of mature coinbase in the funder"
    poll_until "funder funds" 7200 ew_spendable_at_least funder "${units}" 1 ||
        fail "the funder did not get mature coinbase" || return 1
}

lepic_spendable_now() { (($(lepic_spendable) >= $1)); }

step_funding() {
    local lepic_has peer_has need=0 n
    lepic_has="$(lepic_spendable)"
    peer_has="$(ew_spendable peer)"
    ((lepic_has < FUND_MINIMUM)) && need=$((need + FUND_OUTPUTS))
    ((peer_has < FUND_MINIMUM)) && need=$((need + FUND_OUTPUTS))
    if ((need == 0)); then
        DETAIL="already funded: lepic $(jq -n "${lepic_has} / ${UNIT}") EPIC, epic-wallet $(jq -n "${peer_has} / ${UNIT}") EPIC spendable"
        return 0
    fi
    local funder_need=$(((need * FUND_AMOUNT + 1) * UNIT))
    if ! ew_spendable_at_least funder "${funder_need}" 1; then
        top_up_funder "${funder_need}" || return 1
    fi
    miner_start || fail "the miner did not start" || return 1
    if ((lepic_has < FUND_MINIMUM)); then
        for ((n = 1; n <= FUND_OUTPUTS; n++)); do
            fund_one lepic "${run_id}-lepic-${n}" || fail "funding lepic failed" || return 1
        done
    fi
    if ((peer_has < FUND_MINIMUM)); then
        for ((n = 1; n <= FUND_OUTPUTS; n++)); do
            fund_one peer "${run_id}-peer-${n}" || fail "funding epic-wallet failed" || return 1
        done
    fi
    poll_until "lepic funded" "${CONFIRM_TIMEOUT}" lepic_spendable_now "${FUND_MINIMUM}" ||
        fail "lepic funds did not confirm" || return 1
    poll_until "peer funded" "${CONFIRM_TIMEOUT}" ew_spendable_at_least peer "${FUND_MINIMUM}" ||
        fail "epic-wallet funds did not confirm" || return 1
    miner_stop
    DETAIL="funded at height $(public_height): lepic $(jq -n "$(lepic_spendable) / ${UNIT}") EPIC, epic-wallet $(jq -n "$(ew_spendable peer) / ${UNIT}") EPIC spendable"
}

both_confirmed() { lepic_tx_confirmed "$1" && ew_tx_confirmed peer "$2"; }

lepic_total_is() { (($(lepic_balance total) == $1)); }

# Mines until both wallets confirm the transaction, then checks lepic's balance, and that the
# kernel epic-wallet recorded is in a block of the floonet chain. Sets DETAIL and KERNEL.
settle() {
    local tx_id="$1" slate_id="$2" expected="$3"
    mine_until "tx ${tx_id} confirmed on both sides" "${CONFIRM_TIMEOUT}" both_confirmed "${tx_id}" "${slate_id}" ||
        fail "slate ${slate_id} not confirmed: lepic $(lepic_tx_state "${tx_id}")" || return 1
    poll_until "lepic total" 120 lepic_total_is "${expected}" ||
        fail "lepic total is $(lepic_balance total), expected ${expected}" || return 1
    local kernel height
    kernel="$(ew_tx_kernel peer "${slate_id}")"
    [[ -n "${kernel}" ]] || fail "epic-wallet recorded no kernel for ${slate_id}" || return 1
    KERNEL="${kernel}"
    height="$(public_kernel_height "${kernel}")"
    [[ -n "${height}" ]] || fail "the floonet node has no kernel ${kernel}" || return 1
    DETAIL="slate ${slate_id} confirmed on both sides, kernel in block ${height}"
}

scenario_lepic_sends_file() {
    local amount=1 name="${run_id}-lepic-to-peer" before sent tx_id slate_id fee
    before="$(lepic_balance total)"
    sent="$(lepic tx send "${amount}" --to-file "/exchange/${name}.slate" \
        --min-confirmations 1 --selection smallest)" || fail "lepic send failed" || return 1
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    ew peer receive -i "/exchange/${name}.slate" >>"${RUN_LOG}" || fail "epic-wallet receive failed" || return 1
    lepic tx finalize "/exchange/${name}.slate.response" >>"${RUN_LOG}" || fail "lepic finalize failed" || return 1
    settle "${tx_id}" "${slate_id}" $((before - $(to_units "${amount}") - fee))
}

scenario_peer_sends_file() {
    local amount=1.25 name="${run_id}-peer-to-lepic" before slate_id tx_id
    before="$(lepic_balance total)"
    ew peer send -m file -d "/exchange/${name}.slate" -c 1 -s smallest "${amount}" >>"${RUN_LOG}" ||
        fail "epic-wallet send failed" || return 1
    slate_id="$(jq -r .id "${LIVE_DIR}/data/exchange/${name}.slate")"
    lepic tx receive "/exchange/${name}.slate" >>"${RUN_LOG}" || fail "lepic receive failed" || return 1
    ew peer finalize -i "/exchange/${name}.slate.response" >>"${RUN_LOG}" || fail "epic-wallet finalize failed" || return 1
    tx_id="$(lepic_tx_by_slate "${slate_id}" | jq -r .tx_id)"
    [[ -n "${tx_id}" ]] || fail "lepic has no transaction for ${slate_id}" || return 1
    settle "${tx_id}" "${slate_id}" $((before + $(to_units "${amount}")))
}

scenario_lepic_sends_epicbox() {
    local amount=1.5 before sent tx_id slate_id fee summary
    listen_start || fail "epic-wallet listener did not start" || return 1
    before="$(lepic_balance total)"
    sent="$(lepic tx send "${amount}" --to "${PEER_ADDRESS}" \
        --min-confirmations 1 --selection smallest)" || fail "lepic send failed" || return 1
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    summary="$(drain_until finalized 1 300)" || fail "lepic finalized nothing: ${summary}" || return 1
    listen_stop
    settle "${tx_id}" "${slate_id}" $((before - $(to_units "${amount}") - fee))
}

scenario_peer_sends_epicbox() {
    local amount=1.75 before last summary tx tx_id slate_id
    listen_start || fail "epic-wallet listener did not start" || return 1
    before="$(lepic_balance total)"
    last="$(lepic tx list | jq '[.transactions[].tx_id] | max // 0')"
    ew peer send -m epicbox -d "${LEPIC_ADDRESS}" -c 1 -s smallest "${amount}" >>"${RUN_LOG}" ||
        fail "epic-wallet send failed" || return 1
    summary="$(drain_until received 1 300)" || fail "lepic received nothing: ${summary}" || return 1
    tx="$(lepic tx list | jq -c --argjson after "${last}" \
        '[.transactions[] | select(.tx_id > $after and .direction == "incoming")]')"
    [[ "$(jq length <<<"${tx}")" == 1 ]] || fail "expected one new incoming tx, got: ${tx}" || return 1
    tx_id="$(jq -r '.[0].tx_id' <<<"${tx}")"
    slate_id="$(jq -r '.[0].slate_id' <<<"${tx}")"
    # epic-wallet's listener finalizes and posts once lepic's reply arrives, so it keeps running
    # until the transaction is settled.
    settle "${tx_id}" "${slate_id}" $((before + $(to_units "${amount}")))
    local status=$?
    listen_stop
    return "${status}"
}

run_step "floonet node" step_node
[[ "${results[0]}" == PASS ]] && run_step "wallets" step_wallets
[[ "${results[-1]}" == PASS ]] && run_step "funding" step_funding
if [[ "${results[-1]}" == PASS ]]; then
    run_step "lepic sends to epic-wallet, file" scenario_lepic_sends_file
    run_step "epic-wallet sends to lepic, file" scenario_peer_sends_file
    run_step "lepic sends to epic-wallet, epicbox" scenario_lepic_sends_epicbox
    run_step "epic-wallet sends to lepic, epicbox" scenario_peer_sends_epicbox
fi

printf '\n%-38s %-6s %6s  %-66s  %s\n' "Step" "Result" "Time" "Kernel excess" "Detail"
printf '%-38s %-6s %6s  %-66s  %s\n' "----" "------" "----" "-------------" "------"
for i in "${!names[@]}"; do
    printf '%-38s %-6s %6s  %-66s  %s\n' "${names[i]}" "${results[i]}" "${times[i]}" "${kernels[i]}" "${details[i]}"
done
proxy_calls=$(($(proxy_count total) - proxy_total_before))
proxy_limited=$(($(proxy_count rate_limited) - proxy_limited_before))
own_calls="$(public_calls)"
printf '\nPublic node calls: %d in total (%d through the proxy for lepic, epic-wallet and the miner,\n' \
    "$((proxy_calls + own_calls))" "${proxy_calls}"
printf '%d by run.sh); the proxy got %d answers of 429; run time %dm%02ds. Logs: %s\n' \
    "${own_calls}" "${proxy_limited}" "$((SECONDS / 60))" "$((SECONDS % 60))" "${log_dir}"
cp "${PROXY_STATS}" "${log_dir}/proxy-calls.json" 2>/dev/null || true

if ((failed > 0)); then
    exit 1
fi
