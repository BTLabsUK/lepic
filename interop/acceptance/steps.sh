# SPDX-License-Identifier: Apache-2.0
# The steps run.sh runs, in order, against the host's lepic. Sourced by run.sh after ../lib.sh,
# whose `lepic` helper drives a container; the one here replaces it with the binary under test.
#
# Each step sets DETAIL to one line and returns 0 when every check held. They share one chain
# and one set of wallets, and EXPECTED_TOTAL tracks what lepic's balance must be after each, so
# a lost or doubled effect anywhere shows up as a wrong balance.
# shellcheck shell=bash disable=SC2034 # DETAIL and STEPS are read by run.sh

# The gateway publishes the node API and the relay on these loopback ports.
NODE_PORT=43413
RELAY_PORT=3423

LEPIC_PASSWORD_VALUE="acceptance password"
DETAIL=""
EXPECTED_TOTAL=0
RECOVERY_PHRASE=""
LEPIC_ADDRESS=""
PEER_ADDRESS=""
PEER_KEY=""
EPICBOX_SEND_TX=""

fail() {
    DETAIL="$*"
    return 1
}

# Runs a command with only what a fresh login shell would give lepic: PATH, a home of its own
# and the acceptance config file. Nothing from the invoking shell's LEPIC_* variables leaks in.
lepic_env() {
    env -i PATH="${PATH}" HOME="${STATE_DIR}/home" LEPIC_CONFIG="${STATE_DIR}/config.toml" \
        LEPIC_PASSWORD="${LEPIC_PASSWORD_VALUE}" "$@"
}

# The lepic under test, with JSON output. Its stderr goes to the run log, and so do a failure's
# exit status and its JSON error document, which a caller's pipe would otherwise swallow.
lepic() {
    local status=0 output
    output="$(lepic_env "${LEPIC_BIN}" --output json "$@" </dev/null 2>>"${RUN_LOG}")" || status=$?
    if ((status != 0)); then
        printf 'lepic %s exited %d: %s\n' "$*" "${status}" "${output}" >>"${RUN_LOG}"
    fi
    [[ -z "${output}" ]] || printf '%s\n' "${output}"
    return "${status}"
}

# The exit code of a lepic command, its output discarded.
lepic_status() {
    local status=0
    lepic "$@" >/dev/null || status=$?
    echo "${status}"
}

lepic_total_is() { (($(lepic_balance total) == $1)); }

lepic_locked() { to_units "$(lepic wallet info | jq -r '.accounts[0].locked')"; }

check_lepic_total() {
    wait_until "lepic total ${EXPECTED_TOTAL}" 60 lepic_total_is "${EXPECTED_TOTAL}" ||
        fail "lepic total is $(lepic_balance total), expected ${EXPECTED_TOTAL}"
}

lepic_last_tx_id() { lepic tx list | jq '[.transactions[].tx_id] | max // 0'; }

lepic_incoming_after() {
    lepic tx list | jq -c --argjson after "$1" \
        '.transactions[] | select(.tx_id > $after and .direction == "incoming")'
}

# Waits until a lepic transaction and the epic-wallet record of the same slate are confirmed.
confirm_both() {
    local tx_id="$1" slate_id="$2" wallet="${3:-peer}"
    wait_until "lepic tx ${tx_id} confirmed" 180 lepic_tx_confirmed "${tx_id}" ||
        fail "lepic tx ${tx_id} is $(lepic_tx_state "${tx_id}"), not confirmed" || return 1
    wait_until "${wallet} tx ${slate_id} confirmed" 120 ew_tx_confirmed "${wallet}" "${slate_id}" ||
        fail "epic-wallet (${wallet}) did not confirm ${slate_id}"
}

# The slate file lepic wrote is in the V3 shape with header 3/3 (ADR 0015), with a TTL when
# `ttl` is "ttl".
lepic_file_is_v3() {
    local path="$1" ttl="${2:-}"
    jq -e --arg ttl "${ttl}" '
        .version_info.version == 3 and .version_info.orig_version == 3
        and has("ttl_cutoff_height") and has("payment_proof")
        and (($ttl != "ttl") or (.ttl_cutoff_height != null))' "${path}" >/dev/null
}

block_header_version() { jq -r .version_info.block_header_version "$1"; }

relay_messages_for() { mongo_eval "print(db.slates.countDocuments({queue: '$1'}))"; }

relay_messages_above() { (($(relay_messages_for "$1") > $2)); }

# epic-wallet sends to lepic through a slate file and finalizes lepic's V3 reply. Prints the
# lepic receive report.
ew_sends_file_to_lepic() {
    local wallet="$1" amount="$2" name="$3"
    local slate="${EXCHANGE_DIR}/${name}.slate"
    ew "${wallet}" send -m file -d "/exchange/${name}.slate" -c 1 -s smallest "${amount}" >>"${RUN_LOG}" ||
        fail "epic-wallet send to ${name} failed" || return 1
    local received
    received="$(lepic tx receive "${slate}")" || fail "lepic could not receive ${name}" || return 1
    local reply
    reply="$(jq -r .reply_file <<<"${received}")"
    [[ "${reply}" == "${slate}.response" ]] || fail "reply went to ${reply}" || return 1
    lepic_file_is_v3 "${reply}" || fail "lepic's S2 is not V3 at 3/3" || return 1
    [[ "$(block_header_version "${reply}")" == "$(block_header_version "${slate}")" ]] ||
        fail "lepic's S2 changed the block header version" || return 1
    ew "${wallet}" finalize -i "/exchange/${name}.slate.response" >>"${RUN_LOG}" ||
        fail "epic-wallet could not finalize lepic's V3 S2" || return 1
    echo "${received}"
}

step_setup() {
    dc exec -T node cat /data/node/.foreign_api_secret >"${STATE_DIR}/foreign_api_secret" ||
        fail "could not read the node api secret" || return 1
    chmod 600 "${STATE_DIR}/foreign_api_secret"
    cat >"${STATE_DIR}/config.toml" <<EOF
# The local chain is usernet, where epic-wallet derives mainnet Epicbox addresses.
network = mainnet
data_dir = "lepic"
node_url = "http://127.0.0.1:${NODE_PORT}"
node_api_secret_file = "foreign_api_secret"
epicbox_relay = "ws://localhost:${RELAY_PORT}"
EOF
    mkdir -p "${STATE_DIR}/home"

    local peer
    peer="$(ew_address peer)"
    [[ -n "${peer}" ]] || fail "no epic-wallet address" || return 1
    # epic-wallet leaves the relay port out of the address it prints.
    PEER_ADDRESS="${peer%%:*}:${RELAY_PORT}"
    PEER_KEY="${PEER_ADDRESS%%@*}"

    log "waiting for mature coinbase in the funder wallet"
    wait_until "funder funds" 300 ew_spendable_at_least funder $((150 * UNIT)) ||
        fail "the funder wallet was not funded by mining" || return 1
    log "funding epic-wallet's peer wallet"
    local n slate_id
    for n in 1 2 3; do
        ew funder send -m file -d "/exchange/peer-${n}.slate" -c 1 -s smallest 20 >>"${RUN_LOG}" ||
            fail "funding the peer failed" || return 1
        slate_id="$(jq -r .id "${EXCHANGE_DIR}/peer-${n}.slate")"
        ew peer receive -i "/exchange/peer-${n}.slate" >>"${RUN_LOG}" || fail "peer receive failed" || return 1
        ew funder finalize -i "/exchange/peer-${n}.slate.response" >>"${RUN_LOG}" ||
            fail "funder finalize failed" || return 1
        wait_until "peer funding ${n} mined" 120 ew_tx_confirmed funder "${slate_id}" ||
            fail "peer funding ${n} was not mined" || return 1
    done
    wait_until "peer funded" 180 ew_spendable_at_least peer $((60 * UNIT)) ||
        fail "epic-wallet funds did not confirm" || return 1
    DETAIL="stack up, peer funded at height $(lepic node status | jq -r .height)"
}

step_node_status() {
    local status
    status="$(lepic node status)" || fail "node status failed" || return 1
    jq -e '.node_version == "4.1.0" and .height > 0' <<<"${status}" >/dev/null ||
        fail "unexpected node status: ${status}" || return 1
    local human
    human="$(lepic_env "${LEPIC_BIN}" node status 2>>"${RUN_LOG}")" || fail "human node status failed" || return 1
    grep -q '^Height ' <<<"${human}" || fail "human node status has no height: ${human}" || return 1
    DETAIL="node 4.1.0 at height $(jq -r .height <<<"${status}") through 127.0.0.1:${NODE_PORT}"
}

step_wallet_init() {
    local created
    created="$(lepic wallet init --words 12)" || fail "wallet init failed" || return 1
    RECOVERY_PHRASE="$(jq -r .recovery_phrase <<<"${created}")"
    [[ "$(wc -w <<<"${RECOVERY_PHRASE}")" -eq 12 ]] || fail "recovery phrase is not 12 words" || return 1
    [[ "$(jq -r .data_dir <<<"${created}")" == "${STATE_DIR}/lepic" ]] ||
        fail "wallet created in $(jq -r .data_dir <<<"${created}")" || return 1
    [[ "$(stat -c %a "${STATE_DIR}/lepic")" == 700 ]] || fail "data directory is not private" || return 1
    [[ "$(lepic_status wallet init)" -eq 5 ]] || fail "a second init was not refused with 5" || return 1
    DETAIL="12-word wallet in .work/state/lepic, mode 700; second init refused"
}

step_address_and_status() {
    LEPIC_ADDRESS="$(lepic wallet address | jq -r .address)" || fail "wallet address failed" || return 1
    [[ "${LEPIC_ADDRESS}" == *"@localhost:${RELAY_PORT}" ]] || fail "address ${LEPIC_ADDRESS}" || return 1
    local status
    status="$(lepic epicbox status)" || fail "epicbox status failed" || return 1
    jq -e --arg address "${LEPIC_ADDRESS}" --arg relay "ws://localhost:${RELAY_PORT}" \
        '.address == $address and .relay == $relay and .pending_deliveries == 0' <<<"${status}" >/dev/null ||
        fail "unexpected epicbox status: ${status}" || return 1
    [[ "$(lepic_balance total)" -eq 0 ]] || fail "a new wallet has funds" || return 1
    DETAIL="${LEPIC_ADDRESS}"
}

step_receive_by_file() {
    local received tx_id slate_id n
    for n in 1 2; do
        received="$(ew_sends_file_to_lepic funder 25 "lepic-${n}")" || return 1
        tx_id="$(jq -r .tx_id <<<"${received}")"
        slate_id="$(jq -r .slate_id <<<"${received}")"
        confirm_both "${tx_id}" "${slate_id}" funder || return 1
    done
    EXPECTED_TOTAL=$((50 * UNIT))
    check_lepic_total || return 1
    wait_until "lepic spendable" 180 lepic_spendable_at_least "${EXPECTED_TOTAL}" ||
        fail "lepic funds did not become spendable" || return 1
    DETAIL="two V2 S1 files from epic-wallet answered in V3; 50 EPIC spendable"
}

# The message table of one epic-wallet transaction. epic-wallet prints it only to a terminal, so
# `txs` runs under `script`.
ew_tx_messages() {
    local wallet="$1" slate_id="$2"
    dc exec -T "${wallet}" timeout 60 script -qec "ew txs -t ${slate_id}" /dev/null </dev/null 2>>"${RUN_LOG}" |
        sed 's/\x1b\[[0-9;]*[mK]//g; s/\x1b[()][A-Z0-9]//g'
}

lepic_tx_has_message() {
    local tx_id="$1" role="$2" text="$3"
    lepic tx show "${tx_id}" |
        jq -e --arg role "${role}" --arg text "${text}" \
            'any(.messages[]; .role == $role and .text == $text)' >/dev/null
}

step_send_over_epicbox() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local sent tx_id slate_id fee summary
    sent="$(lepic tx send 1.5 --to "${PEER_ADDRESS}" -m "acceptance")" || fail "lepic send failed" || return 1
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    EPICBOX_SEND_TX="${tx_id}"
    summary="$(drain_until finalized 1 120)" || fail "lepic finalized nothing: ${summary}" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    # lepic's S1 carried the marker; the stock reply did not, so the stock wallet is recorded
    # as another wallet and is sent no notice.
    [[ "$(unmade_for "${PEER_KEY}")" == 0 ]] || fail "a message for the stock wallet is unacknowledged" || return 1
    [[ "$(lepic_peer_support "${PEER_KEY}")" == no-invoices ]] || fail "lepic did not record the stock answer" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 1.5) - fee))
    check_lepic_total || return 1
    local messages
    messages="$(ew_tx_messages peer "${slate_id}")"
    printf 'epic-wallet (peer) txs -t %s:\n%s\n' "${slate_id}" "${messages}" >>"${RUN_LOG}"
    # The sender's row of the message table: participant 0, the text, then its public key.
    grep -Eq '^ *0 +acceptance +0[23][0-9a-f]{64} ' <<<"${messages}" || fail "epic-wallet txs shows no lepic message: ${messages}" || return 1
    lepic_tx_has_message "${tx_id}" sender acceptance || fail "lepic tx show has no own message" || return 1
    DETAIL="S1 by relay, S2 drained and finalized; ${slate_id} confirmed; message shown by epic-wallet txs"
}

step_listen_receives_over_epicbox() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local last before
    last="$(lepic_last_tx_id)"
    before="$(relay_messages_for "${PEER_KEY}")"
    # Started without the lepic_env function, so $! is lepic itself (env execs it) and the
    # Ctrl-C below reaches lepic rather than a subshell, which ignores it.
    env -i PATH="${PATH}" HOME="${STATE_DIR}/home" LEPIC_CONFIG="${STATE_DIR}/config.toml" \
        LEPIC_PASSWORD="${LEPIC_PASSWORD_VALUE}" "${LEPIC_BIN}" epicbox listen \
        >"${STATE_DIR}/listen.out" 2>"${STATE_DIR}/listen.err" </dev/null &
    local listen_pid=$!
    wait_until "lepic listening" 30 grep -q "connected to the relay" "${STATE_DIR}/listen.err" ||
        { kill -INT "${listen_pid}" 2>/dev/null; fail "listen did not report the connection"; } || return 1
    wait_until "peer spendable" 180 ew_spendable_at_least peer $((3 * UNIT)) ||
        { kill -INT "${listen_pid}"; fail "epic-wallet has no spendable funds"; } || return 1
    ew peer send -m epicbox -d "${LEPIC_ADDRESS}" -c 1 -s smallest -g "from epic-wallet" 2.25 >>"${RUN_LOG}" ||
        { kill -INT "${listen_pid}"; fail "epic-wallet send failed"; } || return 1
    wait_until "lepic's S2 on the relay" 60 relay_messages_above "${PEER_KEY}" "${before}"
    local answered=$?
    kill -INT "${listen_pid}"
    local status=0
    wait "${listen_pid}" || status=$?
    cat "${STATE_DIR}/listen.err" >>"${RUN_LOG}"
    ((answered == 0)) || fail "listen did not answer the S1" || return 1
    ((status == 0)) || fail "listen exited ${status} on Ctrl-C" || return 1
    grep -q '^Received 1, ' "${STATE_DIR}/listen.out" ||
        fail "listen summary: $(cat "${STATE_DIR}/listen.out")" || return 1
    local tx
    tx="$(lepic_incoming_after "${last}")"
    [[ -n "${tx}" && "$(wc -l <<<"${tx}")" -eq 1 ]] || fail "expected one new incoming tx: ${tx}" || return 1
    [[ "$(jq -r .amount_credited <<<"${tx}")" == 2.25000000 ]] || fail "credited amount wrong: ${tx}" || return 1
    lepic_tx_has_message "$(jq -r .tx_id <<<"${tx}")" sender "from epic-wallet" ||
        fail "lepic tx show lacks epic-wallet's message: $(lepic tx show "$(jq -r .tx_id <<<"${tx}")")" || return 1
    confirm_both "$(jq -r .tx_id <<<"${tx}")" "$(jq -r .slate_id <<<"${tx}")" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 2.25)))
    check_lepic_total || return 1
    DETAIL="listen answered epic-wallet's S1 and stopped on Ctrl-C with exit 0; its message shown by tx show"
}

step_send_by_file() {
    peer_listen_stop
    local slate="${EXCHANGE_DIR}/lepic-sends.slate"
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(to_units 2.2)" ||
        fail "lepic has no spendable funds" || return 1
    local sent
    sent="$(lepic tx send 1.1 --to-file "${slate}" --ttl-blocks 60)" || fail "lepic send failed" || return 1
    lepic_file_is_v3 "${slate}" ttl || fail "lepic's S1 is not V3 at 3/3 with a TTL" || return 1
    ew peer receive -i /exchange/lepic-sends.slate >>"${RUN_LOG}" || fail "epic-wallet refused lepic's V3 S1" || return 1
    local finalized
    finalized="$(lepic tx finalize "${slate}.response")" || fail "lepic could not finalize the S2" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    jq -e --arg id "${slate_id}" '.slate_id == $id and .state == "posted"' <<<"${finalized}" >/dev/null ||
        fail "finalize report: ${finalized}" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 1.1) - fee))
    check_lepic_total || return 1
    DETAIL="V3 S1 with TTL read by epic-wallet; ${slate_id} confirmed"
}

step_invoice_epic_wallet() {
    peer_listen_stop
    local slate="${EXCHANGE_DIR}/lepic-invoices.slate"
    wait_until "peer spendable" 180 ew_spendable_at_least peer "$(to_units 1.8)" ||
        fail "epic-wallet has no spendable funds" || return 1
    local issued
    issued="$(lepic invoice issue 0.8 --to-file "${slate}")" || fail "lepic invoice issue failed" || return 1
    lepic_file_is_v3 "${slate}" || fail "lepic's I1 is not V3 at 3/3" || return 1
    ew_pay peer 0.8 -i /exchange/lepic-invoices.slate -d /exchange/lepic-invoices.slate.response -c 1 -s smallest ||
        fail "epic-wallet could not pay lepic's V3 I1" || return 1
    local finalized tx_id slate_id
    finalized="$(lepic tx finalize "${slate}.response")" || fail "lepic could not finalize the I2" || return 1
    tx_id="$(jq -r .tx_id <<<"${issued}")"
    slate_id="$(jq -r .slate_id <<<"${issued}")"
    [[ "$(jq -r .slate_id <<<"${finalized}")" == "${slate_id}" ]] || fail "finalized another slate" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 0.8)))
    check_lepic_total || return 1
    DETAIL="V3 I1 paid by epic-wallet, finalized by lepic; ${slate_id} confirmed"
}

step_pay_epic_wallet_invoice() {
    peer_listen_stop
    local slate="${EXCHANGE_DIR}/peer-invoices.slate"
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(to_units 1.7)" ||
        fail "lepic has no spendable funds" || return 1
    ew peer invoice -d /exchange/peer-invoices.slate 0.7 >>"${RUN_LOG}" || fail "epic-wallet invoice failed" || return 1
    [[ "$(lepic_status invoice pay "${slate}" 0.6)" -eq 7 ]] || fail "a wrong amount was not refused with 7" || return 1
    [[ ! -e "${slate}.response" ]] || fail "a refused payment wrote a reply" || return 1
    local paid
    paid="$(lepic invoice pay "${slate}" 0.7 --ttl-blocks 60)" || fail "lepic could not pay the I1" || return 1
    lepic_file_is_v3 "${slate}.response" ttl || fail "lepic's I2 is not V3 at 3/3 with a TTL" || return 1
    ew peer finalize -i /exchange/peer-invoices.slate.response >>"${RUN_LOG}" ||
        fail "epic-wallet could not finalize lepic's V3 I2" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${paid}")"
    slate_id="$(jq -r .slate_id <<<"${paid}")"
    fee="$(to_units "$(jq -r .fee <<<"${paid}")")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 0.7) - fee))
    check_lepic_total || return 1
    DETAIL="wrong amount refused; I2 with TTL finalized by epic-wallet; ${slate_id} confirmed"
}

step_resend_after_failed_delivery() {
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(to_units 1.4)" ||
        fail "lepic has no spendable funds" || return 1
    local status=0
    lepic tx send 0.4 --to-file "${STATE_DIR}/missing/undelivered.slate" >/dev/null || status=$?
    ((status == 11)) || fail "a send to an unwritable file exited ${status}, not 11" || return 1
    local tx_id
    tx_id="$(lepic tx list | jq -r '[.transactions[] | select(.state == "sent")][0].tx_id')"
    [[ "${tx_id}" =~ ^[0-9]+$ ]] || fail "no stored send after the failed delivery" || return 1
    (($(lepic_locked) > 0)) || fail "the undelivered send locked nothing" || return 1
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local resent
    resent="$(lepic tx resend "${tx_id}" --to "${PEER_ADDRESS}")" || fail "tx resend failed" || return 1
    jq -e --arg tx "${tx_id}" '(.tx_id | tostring) == $tx and .transport == "epicbox"' <<<"${resent}" >/dev/null ||
        fail "resend report: ${resent}" || return 1
    local summary slate_id fee
    summary="$(drain_until finalized 1 120)" || fail "lepic finalized nothing: ${summary}" || return 1
    slate_id="$(lepic tx show "${tx_id}" | jq -r .slate_id)"
    fee="$(to_units "$(lepic tx show "${tx_id}" | jq -r .fee)")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 0.4) - fee))
    check_lepic_total || return 1
    [[ "$(lepic_status tx resend "${tx_id}" --to "${PEER_ADDRESS}")" -eq 7 ]] ||
        fail "resending a confirmed transaction was not refused with 7" || return 1
    DETAIL="send exited 11 with inputs locked; tx resend over the relay confirmed it"
}

step_cancel() {
    peer_listen_stop
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(to_units 1.2)" ||
        fail "lepic has no spendable funds" || return 1
    local sent tx_id
    sent="$(lepic tx send 0.2 --to-file "${EXCHANGE_DIR}/cancelled.slate")" || fail "lepic send failed" || return 1
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    (($(lepic_locked) > 0)) || fail "the send locked nothing" || return 1
    [[ "$(lepic tx cancel "${tx_id}" | jq -r .state)" == cancelled ]] || fail "tx cancel failed" || return 1
    [[ "$(lepic_tx_state "${tx_id}")" == cancelled ]] || fail "tx ${tx_id} is not cancelled" || return 1
    (($(lepic_locked) == 0)) || fail "cancel left funds locked" || return 1
    check_lepic_total || return 1
    DETAIL="tx ${tx_id} cancelled, nothing locked"
}

step_list_show_post() {
    local list
    list="$(lepic tx list)" || fail "tx list failed" || return 1
    local count
    count="$(jq '.transactions | length' <<<"${list}")"
    ((count == 9)) || fail "tx list has ${count} transactions, expected 9" || return 1
    local shown
    shown="$(lepic tx show "${EPICBOX_SEND_TX}")" || fail "tx show failed" || return 1
    jq -e '.state == "confirmed" and .transport == "epicbox" and (.stages | index("S1")) and (.stages | index("S3"))' \
        <<<"${shown}" >/dev/null || fail "tx show: ${shown}" || return 1
    [[ "$(lepic_status tx post "${EPICBOX_SEND_TX}")" -eq 7 ]] ||
        fail "posting a confirmed transaction was not refused with 7" || return 1
    [[ "$(lepic_status tx show 999)" -eq 6 ]] || fail "an unknown tx was not 6" || return 1
    local human
    human="$(lepic_env "${LEPIC_BIN}" tx list 2>>"${RUN_LOG}")" || fail "human tx list failed" || return 1
    grep -q '^ *ID  DIR .*AMOUNT .*FEE .*TRANSPORT' <<<"${human}" || fail "human tx list header: ${human}" || return 1
    DETAIL="9 transactions listed; S1 and S3 stored; confirmed post refused"
}

step_errors() {
    local status=0
    env -i PATH="${PATH}" HOME="${STATE_DIR}/home" LEPIC_CONFIG="${STATE_DIR}/config.toml" \
        LEPIC_PASSWORD="wrong password" "${LEPIC_BIN}" wallet info >/dev/null 2>>"${RUN_LOG}" || status=$?
    ((status == 4)) || fail "a wrong password exited ${status}, not 4" || return 1
    local before
    before="$(lepic_last_tx_id)"
    [[ "$(lepic_status tx send 1 --to "${PEER_KEY:1}@localhost:${RELAY_PORT}")" -eq 2 ]] ||
        fail "a mistyped address was not refused with 2" || return 1
    [[ "$(lepic_last_tx_id)" == "${before}" ]] || fail "a mistyped address stored a transaction" || return 1
    [[ "$(lepic_status tx send 1000 --to "${PEER_ADDRESS}")" -eq 8 ]] || fail "overspending was not 8" || return 1
    local human
    human="$(lepic_env "${LEPIC_BIN}" --data-dir "${STATE_DIR}/none" wallet info 2>&1 </dev/null)" && status=0 || status=$?
    ((status == 5)) || fail "a missing wallet exited ${status}, not 5" || return 1
    grep -q '^hint: no mainnet wallet in ' <<<"${human}" || fail "no hint for a missing wallet: ${human}" || return 1
    status=0
    env -i PATH="${PATH}" HOME="${STATE_DIR}/home" LEPIC_CONFIG="${STATE_DIR}/config.toml" \
        LEPIC_PASSWORD="${LEPIC_PASSWORD_VALUE}" LEPIC_NODE_URL=http://127.0.0.1:9 \
        "${LEPIC_BIN}" wallet info >/dev/null 2>>"${RUN_LOG}" || status=$?
    ((status == 9)) || fail "an unreachable node exited ${status}, not 9" || return 1
    DETAIL="wrong password 4, bad address 2 and nothing stored, overspend 8, no wallet 5 with hint, no node 9"
}

# A directory key for the listing step: the generator point, a valid compressed key.
LISTING_DKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Drains lepic's listing address of LISTING_DKEY until a counter reaches a value, as
# drain_until does for the wallet's own address.
listing_drain_until() {
    local name="$1" want="$2" timeout="$3"
    local deadline=$((SECONDS + timeout))
    local total='{"received":0,"finalized":0,"repeated":0,"rejected":0,"held":0,"dropped":0,"notices":0}'
    while :; do
        local report
        report="$(lepic epicbox drain --listing "${LISTING_DKEY}")" || return 1
        total="$(jq -c -n --argjson a "${total}" --argjson b "${report}" \
            '$a | with_entries(.value += ($b[.key] // 0))')"
        if (($(jq -r ".${name}" <<<"${total}") >= want)); then
            echo "${total}"
            return 0
        fi
        if ((SECONDS >= deadline)); then
            echo "${total}"
            return 1
        fi
        sleep 2
    done
}

# The ed25519 key of an onion v3 address, in hex: the first 32 of its base32 bytes.
onion_key_hex() {
    python3 -c 'import base64,sys; a=sys.argv[1].split(".")[0].upper(); print(base64.b32decode(a)[:32].hex())' "$1"
}

# epic-wallet pays lepic's listing address over Epicbox: a listing drain on its own connection
# answers from the listing, the record names the listing, the payments address is untouched,
# and a stock S1 sent with a proof request arrives as V2 without it. The funds count toward the total the later restore must find.
step_listing_receives_over_epicbox() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local listing
    listing="$(lepic epicbox status --listing "${LISTING_DKEY}" | jq -r .address)" ||
        fail "lepic gave no listing address" || return 1
    [[ "${listing%%@*}" != "${LEPIC_ADDRESS%%@*}" ]] || fail "the listing is the payments address" || return 1
    local main_before
    main_before="$(relay_messages_for "${LEPIC_ADDRESS%%@*}")"
    wait_until "peer spendable" 180 ew_spendable_at_least peer $((3 * UNIT)) ||
        fail "epic-wallet has no spendable funds" || return 1
    local last
    last="$(lepic_last_tx_id)"
    ew peer send -m epicbox -d "${listing}" -c 1 -s smallest 1.1 >>"${RUN_LOG}" ||
        { fail "epic-wallet send to the listing failed"; } || return 1
    local summary
    summary="$(listing_drain_until received 1 120)" ||
        { fail "the listing drain received nothing: ${summary}"; } || return 1
    local tx tx_id slate_id
    tx="$(lepic_incoming_after "${last}")"
    [[ -n "${tx}" && "$(wc -l <<<"${tx}")" -eq 1 ]] || fail "expected one new incoming tx: ${tx}" || return 1
    tx_id="$(jq -r .tx_id <<<"${tx}")"
    slate_id="$(jq -r .slate_id <<<"${tx}")"
    lepic tx show "${tx_id}" | jq -e --arg dkey "${LISTING_DKEY}" \
        '.receive_listing.dkey == $dkey and .receive_listing.generation == 0' >/dev/null ||
        { fail "tx show does not name the listing: $(lepic tx show "${tx_id}")"; } || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 1.1)))

    # epic-wallet's Epicbox S1 is V2, which has no payment proof field: a proof asked of the
    # listing never reaches it, the payment arrives as an ordinary one and is answered from the
    # listing. Refusing a proof request at a listing is covered by the engine tests.
    local onion proof_key
    onion="$(lepic tor address | jq -r .onion)" || fail "lepic gave no onion address" || return 1
    proof_key="$(onion_key_hex "${onion}")"
    last="$(lepic_last_tx_id)"
    ew peer send -m epicbox -d "${listing}" -c 1 -s smallest -y -z "${proof_key}" 1.2 >>"${RUN_LOG}" ||
        fail "epic-wallet send with a proof request failed" || return 1
    summary="$(listing_drain_until received 1 120)" ||
        fail "the listing drain received nothing: ${summary}" || return 1
    tx="$(lepic_incoming_after "${last}")"
    tx_id="$(jq -r .tx_id <<<"${tx}")"
    slate_id="$(jq -r .slate_id <<<"${tx}")"
    lepic tx show "${tx_id}" | jq -e '.receive_listing != null' >/dev/null ||
        fail "the second listing payment does not name the listing" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 1.2)))

    # Nothing of it reached the payments address: its queue is unchanged and a drain of it
    # takes nothing.
    [[ "$(relay_messages_for "${LEPIC_ADDRESS%%@*}")" == "${main_before}" ]] ||
        fail "the payments address queue changed" || return 1
    jq -e '.received == 0 and .rejected == 0' <<<"$(lepic epicbox drain)" >/dev/null ||
        fail "the payments drain took listing traffic" || return 1
    check_lepic_total || return 1
    DETAIL="listing paid by epic-wallet and answered from it, tx ${tx_id} names the listing and confirmed; a V2 S1 sent with -y came without a proof and was received there too; payments address untouched"
}

step_restore() {
    local restored status=0
    restored="$(printf '%s\n' "${RECOVERY_PHRASE}" | lepic_env "${LEPIC_BIN}" \
        --data-dir "${STATE_DIR}/restored" wallet restore 2>"${STATE_DIR}/restore.err")" || status=$?
    cat "${STATE_DIR}/restore.err" >>"${RUN_LOG}"
    ((status == 0)) || fail "wallet restore exited ${status}" || return 1
    grep -q '^Scanned heights 0 to ' <<<"${restored}" || fail "restore report: ${restored}" || return 1
    grep -q '^scanned to height ' "${STATE_DIR}/restore.err" || fail "restore printed no progress" || return 1
    local total
    total="$(lepic --data-dir "${STATE_DIR}/restored" wallet info | jq -r '.accounts[0].total')"
    (($(to_units "${total}") == EXPECTED_TOTAL)) ||
        fail "restored total ${total}, expected ${EXPECTED_TOTAL} units" || return 1
    DETAIL="restored from the phrase with progress; total ${total} matches"
}

unscanned() { lepic --data-dir "${STATE_DIR}/unscanned" "$@"; }

unscanned_total() { to_units "$(unscanned wallet info | jq -r '.accounts[0].total')"; }

unscanned_tx_confirmed() {
    unscanned wallet info >/dev/null
    [[ "$(unscanned tx show "$1" | jq -r .state)" == confirmed ]]
}

# A wallet restored with --no-scan refuses to receive until `wallet scan` has scanned the chain
# from genesis; then it holds what lepic holds and receives from epic-wallet.
step_scan_after_restore_without_scan() {
    local restored status=0
    restored="$(printf '%s\n' "${RECOVERY_PHRASE}" | lepic_env "${LEPIC_BIN}" --output json \
        --data-dir "${STATE_DIR}/unscanned" wallet restore --no-scan 2>>"${RUN_LOG}")" || status=$?
    ((status == 0)) || fail "wallet restore --no-scan exited ${status}" || return 1
    jq -e '.scan == null' <<<"${restored}" >/dev/null || fail "restore report: ${restored}" || return 1
    local slate="${EXCHANGE_DIR}/unscanned.slate"
    ew funder send -m file -d /exchange/unscanned.slate -c 1 -s smallest 1.25 >>"${RUN_LOG}" ||
        fail "epic-wallet send to the unscanned wallet failed" || return 1
    status="$(unscanned_status tx receive "${slate}")"
    ((status == 5)) || fail "a receive before the scan exited ${status}, not 5" || return 1
    [[ ! -e "${slate}.response" ]] || fail "a refused receive wrote a reply" || return 1
    local scanned
    scanned="$(unscanned wallet scan)" || fail "wallet scan failed" || return 1
    jq -e '.start_height == 0 and .found > 0 and .restored == .found and .resumed == false' \
        <<<"${scanned}" >/dev/null || fail "scan report: ${scanned}" || return 1
    (($(unscanned_total) == EXPECTED_TOTAL)) ||
        fail "scanned total $(unscanned_total), expected ${EXPECTED_TOTAL} units" || return 1
    local received tx_id
    received="$(unscanned tx receive "${slate}")" || fail "the receive after the scan failed" || return 1
    ew funder finalize -i /exchange/unscanned.slate.response >>"${RUN_LOG}" ||
        fail "epic-wallet could not finalize the reply" || return 1
    tx_id="$(jq -r .tx_id <<<"${received}")"
    wait_until "unscanned tx ${tx_id} confirmed" 180 unscanned_tx_confirmed "${tx_id}" ||
        fail "the receive after the scan did not confirm" || return 1
    (($(unscanned_total) == EXPECTED_TOTAL + $(to_units 1.25))) ||
        fail "total after the receive $(unscanned_total) units" || return 1
    DETAIL="--no-scan restore refused tx receive with 5; wallet scan found $(jq -r .found <<<"${scanned}") outputs, total matched, then received 1.25"
}

unscanned_status() {
    local status=0
    unscanned "$@" >/dev/null || status=$?
    echo "${status}"
}

step_import_seed() {
    peer_listen_stop
    dc exec -T peer cat /data/.epic/user/wallet_data/wallet.seed >"${STATE_DIR}/peer.seed" ||
        fail "could not copy the peer's wallet.seed" || return 1
    local status=0
    printf 'peer-password\n' | lepic_env "${LEPIC_BIN}" --output json --data-dir "${STATE_DIR}/imported" \
        wallet import-seed "${STATE_DIR}/peer.seed" >>"${RUN_LOG}" 2>&1 || status=$?
    ((status == 0)) || fail "wallet import-seed exited ${status}" || return 1
    local imported peer_total
    imported="$(to_units "$(lepic --data-dir "${STATE_DIR}/imported" wallet info | jq -r '.accounts[0].total')")"
    peer_total="$(ew peer info | awk -F'|' '/Confirmed Total/ {gsub(/ /, "", $2); print $2}')"
    ((imported == $(to_units "${peer_total}"))) ||
        fail "imported total ${imported}, epic-wallet says ${peer_total}" || return 1
    DETAIL="epic-wallet's wallet.seed imported; total ${peer_total} matches epic-wallet"
}

# A second lepic wallet, the payer of the service's invoices over Epicbox. Its data directory is
# its own, and so is its lock, so it runs beside the service's.
payer() { lepic --data-dir "${STATE_DIR}/payer" "$@"; }

payer_status() {
    local status=0
    payer "$@" >/dev/null || status=$?
    echo "${status}"
}

payer_balance() { to_units "$(payer wallet info | jq -r ".accounts[0].$1")"; }

payer_spendable_at_least() { (($(payer_balance spendable) >= $1)); }

payer_tx_confirmed() {
    payer wallet info >/dev/null
    [[ "$(payer tx show "$1" | jq -r .state)" == confirmed ]]
}

# Messages for `key` the relay holds that nobody acknowledged.
unmade_for() { mongo_eval "print(db.slates.countDocuments({queue: '$1', made: false}))"; }

# What lepic learned about the peer with this Epicbox key from its messages, through
# `epicbox peer` (the store keeps it sealed): `no-invoices`, `lepic`, or nothing.
lepic_peer_support() {
    local view
    view="$(lepic epicbox peer "$1@localhost:${RELAY_PORT}")" || return 1
    case "$(jq -r .capability <<<"${view}")" in
        lepic) echo lepic ;;
        no_invoices) echo no-invoices ;;
        *) echo "" ;;
    esac
}

step_fund_payer() {
    payer wallet init --words 12 >/dev/null || fail "the payer's wallet init failed" || return 1
    local slate="${EXCHANGE_DIR}/payer.slate"
    ew funder send -m file -d /exchange/payer.slate -c 1 -s smallest 3 >>"${RUN_LOG}" ||
        fail "epic-wallet send to the payer failed" || return 1
    local received tx_id
    received="$(payer tx receive "${slate}")" || fail "the payer could not receive" || return 1
    ew funder finalize -i /exchange/payer.slate.response >>"${RUN_LOG}" ||
        fail "epic-wallet could not finalize the payer's reply" || return 1
    tx_id="$(jq -r .tx_id <<<"${received}")"
    wait_until "payer tx ${tx_id} confirmed" 180 payer_tx_confirmed "${tx_id}" ||
        fail "the payer's funding did not confirm" || return 1
    wait_until "payer spendable" 180 payer_spendable_at_least "$(to_units 3)" ||
        fail "the payer's funds did not become spendable" || return 1
    DETAIL="a second lepic wallet holds 3 EPIC, spendable"
}

# A service issues an invoice over Epicbox to a payer that allowed it; the payer answers once and
# never finalizes, and hears from the service that the payment was posted.
# Collects the contact mailboxes of `who` (lepic or payer) until a jq test over the collect
# report and the wallet holds, for at most `timeout` seconds.
collect_until() {
    local who="$1" timeout="$2" check="$3"
    local deadline=$((SECONDS + timeout))
    while :; do
        "${who}" contact collect >/dev/null || return 1
        eval "${check}" && return 0
        ((SECONDS < deadline)) || return 1
        sleep 2
    done
}

payer_contact_invoices() { payer contact invoices | jq '.invoices | length'; }

# The payer's `contact collect` with human output, which shows each notice it took on stderr;
# true when one of them matches `pattern`.
payer_collect_shows() {
    local pattern="$1" out="${STATE_DIR}/payer-collect.out" err="${STATE_DIR}/payer-collect.err"
    lepic_env "${LEPIC_BIN}" --data-dir "${STATE_DIR}/payer" contact collect \
        >"${out}" 2>"${err}" </dev/null || return 1
    cat "${out}" "${err}" >>"${RUN_LOG}"
    grep -q -- "${pattern}" "${err}"
}

# Invoices go between paired contacts: the service pairs with the payer by invite, the payer
# checks the words and allows its invoices, the service invoices it through the contact
# mailboxes, the payer pays once with the amount typed again, and the service finalizes and
# posts; the payer never finalizes and hears that it was posted.
step_invoice_lepic_over_epicbox() {
    local invite link service_side accepted payer_side
    invite="$(lepic contact invite --name Service)" || fail "contact invite failed" || return 1
    link="$(jq -r .link <<<"${invite}")"
    service_side="$(jq -r .contact_id <<<"${invite}")"
    accepted="$(payer contact accept "${link}" --name Payer)" || fail "contact accept failed" || return 1
    jq -e '.posted' <<<"${accepted}" >/dev/null || fail "the reply was not posted: ${accepted}" || return 1
    payer_side="$(jq -r .contact_id <<<"${accepted}")"
    collect_until lepic 60 '[[ "$(lepic contact list | jq -r --arg id "${service_side}" ".contacts[] | select(.contact_id == \$id) | .state")" == paired ]]' ||
        fail "the service never paired: $(lepic contact list)" || return 1
    collect_until payer 60 '[[ "$(payer contact list | jq -r --arg id "${payer_side}" ".contacts[] | select(.contact_id == \$id) | .state")" == paired ]]' ||
        fail "the payer never paired: $(payer contact list)" || return 1
    local words_service words_payer
    words_service="$(lepic contact list | jq -c --arg id "${service_side}" '.contacts[] | select(.contact_id == $id) | .sas')"
    words_payer="$(payer contact list | jq -c --arg id "${payer_side}" '.contacts[] | select(.contact_id == $id) | .sas')"
    [[ -n "${words_service}" && "${words_service}" == "${words_payer}" ]] ||
        fail "the two sides show different words: ${words_service} ${words_payer}" || return 1
    lepic contact sas "${service_side}" match >/dev/null || fail "the service's words check failed" || return 1
    payer contact sas "${payer_side}" match >/dev/null || fail "the payer's words check failed" || return 1
    payer contact allow-invoices "${payer_side}" on >/dev/null || fail "allow-invoices failed" || return 1

    local issued tx_id slate_id
    issued="$(lepic contact invoice "${service_side}" 0.6 --reference order-1)" ||
        fail "contact invoice failed" || return 1
    tx_id="$(jq -r .tx_id <<<"${issued}")"
    slate_id="$(jq -r .slate_id <<<"${issued}")"
    lepic contact collect >/dev/null || fail "the service's collect failed" || return 1
    collect_until payer 60 '(($(payer_contact_invoices) >= 1))' ||
        fail "the payer parked no invoice: $(payer contact invoices)" || return 1
    local listed
    listed="$(payer contact invoices)"
    jq -e --arg id "${slate_id}" --arg from "${payer_side}" '.invoices | length == 1
        and .[0].slate_id == $id and .[0].amount == "0.60000000" and .[0].contact_id == $from
        and .[0].reference == "order-1" and .[0].verified' <<<"${listed}" >/dev/null ||
        fail "contact invoices: ${listed}" || return 1

    local paid payment_tx fee
    paid="$(payer contact pay-invoice "${slate_id}" 0.6)" || fail "the payer could not pay the invoice" || return 1
    payment_tx="$(jq -r .tx_id <<<"${paid}")"
    fee="$(to_units "$(jq -r .fee <<<"${paid}")")"
    [[ "$(payer_status contact pay-invoice "${slate_id}" 0.6)" != 0 ]] ||
        fail "the invoice was paid twice" || return 1
    payer contact collect >/dev/null || fail "the payer's collect failed" || return 1

    collect_until lepic 120 '[[ "$(lepic_tx_state "${tx_id}")" == posted || "$(lepic_tx_state "${tx_id}")" == confirmed ]]' ||
        fail "the service did not post: tx ${tx_id} is $(lepic_tx_state "${tx_id}")" || return 1
    wait_until "the posted notice" 60 payer_collect_shows "invoice ${slate_id} posted by the issuer" ||
        fail "the payer heard no posted notice: $(cat "${STATE_DIR}/payer-collect.out" "${STATE_DIR}/payer-collect.err")" ||
        return 1
    [[ "$(payer_contact_invoices)" == 0 ]] || fail "the paid invoice is still parked" || return 1

    wait_until "lepic tx ${tx_id} confirmed" 180 lepic_tx_confirmed "${tx_id}" ||
        fail "the service's tx ${tx_id} is $(lepic_tx_state "${tx_id}"), not confirmed" || return 1
    wait_until "payer tx ${payment_tx} confirmed" 180 payer_tx_confirmed "${payment_tx}" ||
        fail "the payer's tx ${payment_tx} did not confirm" || return 1
    local excess
    excess="$(lepic tx show "${tx_id}" | jq -r .kernel_excess)"
    [[ -n "${excess}" && "${excess}" == "$(payer tx show "${payment_tx}" | jq -r .kernel_excess)" ]] ||
        fail "service and payer disagree on the kernel" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 0.6)))
    check_lepic_total || return 1
    (($(payer_balance total) == $(to_units 3) - $(to_units 0.6) - fee)) ||
        fail "payer total $(payer_balance total) units after paying" || return 1
    DETAIL="paired by invite, words matched, invoices allowed; I1 through the mailboxes paid once, finalized and posted by the service; payer heard posted; ${slate_id} confirmed"
}

# lepic sends to the second lepic wallet over Epicbox while that wallet listens. Both slates
# carry the marker, so after the push the sender tells the receiver, which shows the payment as
# reported posted within seconds and long before the chain confirms it.
step_send_to_lepic_over_epicbox() {
    local payer_address
    payer_address="$(payer wallet address | jq -r .address)" || fail "payer wallet address failed" || return 1
    # Started without the lepic_env function, so $! is lepic itself and the Ctrl-C reaches it.
    env -i PATH="${PATH}" HOME="${STATE_DIR}/home" LEPIC_CONFIG="${STATE_DIR}/config.toml" \
        LEPIC_PASSWORD="${LEPIC_PASSWORD_VALUE}" "${LEPIC_BIN}" --data-dir "${STATE_DIR}/payer" \
        epicbox listen >"${STATE_DIR}/payer-listen.out" 2>"${STATE_DIR}/payer-listen.err" </dev/null &
    local listen_pid=$!
    wait_until "the payer listening" 30 grep -q "connected to the relay" "${STATE_DIR}/payer-listen.err" ||
        { kill -INT "${listen_pid}" 2>/dev/null; fail "the payer's listen did not connect"; } || return 1
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(to_units 0.5)" ||
        { kill -INT "${listen_pid}"; fail "lepic has no spendable funds"; } || return 1
    local sent tx_id slate_id fee summary
    sent="$(lepic tx send 0.4 --to "${payer_address}")" ||
        { kill -INT "${listen_pid}"; fail "lepic send to the payer failed"; } || return 1
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    summary="$(drain_until finalized 1 120)" ||
        { kill -INT "${listen_pid}"; fail "lepic finalized nothing: ${summary}"; } || return 1
    local posted_at="${EPOCHREALTIME}"
    wait_until "the payer's posted report" 30 grep -q "payment ${slate_id} reported posted by its sender" \
        "${STATE_DIR}/payer-listen.err"
    local reported=$? reported_at="${EPOCHREALTIME}"
    # The listen holds the payer's data directory; `tx show` reads the store without a refresh,
    # so the payment still waits for the chain after it stopped.
    kill -INT "${listen_pid}"
    wait "${listen_pid}" || true
    cat "${STATE_DIR}/payer-listen.err" >>"${RUN_LOG}"
    ((reported == 0)) || fail "the payer heard nothing: $(tail -5 "${STATE_DIR}/payer-listen.err")" || return 1
    local payer_tx shown
    payer_tx="$(payer tx list | jq -r --arg id "${slate_id}" '.transactions[] | select(.slate_id == $id) | .tx_id')"
    shown="$(payer tx show "${payer_tx}")"
    jq -e '.state == "received" and (.sender_reported_posted_at | type) == "string"' <<<"${shown}" >/dev/null ||
        fail "payer tx show: ${shown}" || return 1
    [[ "$(lepic_peer_support "$(payer wallet address | jq -r .address | cut -d@ -f1)")" == lepic ]] ||
        fail "lepic did not record the payer as running lepic" || return 1
    local seconds
    seconds="$(python3 -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):.1f}")' "${posted_at}" "${reported_at}")"

    wait_until "lepic tx ${tx_id} confirmed" 180 lepic_tx_confirmed "${tx_id}" ||
        fail "lepic tx ${tx_id} is $(lepic_tx_state "${tx_id}"), not confirmed" || return 1
    wait_until "payer tx ${payer_tx} confirmed" 180 payer_tx_confirmed "${payer_tx}" ||
        fail "the payer's tx ${payer_tx} did not confirm" || return 1
    [[ "$(payer tx show "${payer_tx}" | jq -r '.sender_reported_posted_at // "none"')" == none ]] ||
        fail "the report is still shown after confirmation" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 0.4) - fee))
    check_lepic_total || return 1
    DETAIL="S1 and S2 marked; the listening receiver reported ${slate_id} posted ${seconds}s after the sender's drain returned; confirmed"
}

# A stock epic-wallet listener sends an invoice straight back; lepic counts it as bounced,
# records that the peer does not pay invoices, and sends it no notice. The listener keeps
# acknowledging: a payment after the bounce goes through.
step_stock_listener_bounces_invoice() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local issued tx_id slate_id summary
    issued="$(lepic invoice issue 0.5 --to "${PEER_ADDRESS}")" || fail "lepic invoice issue to epic-wallet failed" || return 1
    tx_id="$(jq -r .tx_id <<<"${issued}")"
    slate_id="$(jq -r .slate_id <<<"${issued}")"
    summary="$(drain_until bounced 1 120)" || fail "no bounce came back: ${summary}" || return 1
    jq -e '.bounced == 1 and .finalized == 0' <<<"${summary}" >/dev/null || fail "drain: ${summary}" || return 1
    [[ "$(unmade_for "${PEER_KEY}")" == 0 ]] || fail "the stock listener left the I1 unacknowledged" || return 1
    ! ew_tx_known peer "${slate_id}" || fail "epic-wallet recorded the invoice" || return 1
    local support
    support="$(lepic_peer_support "${PEER_KEY}")" || fail "lepic's store was not found" || return 1
    [[ "${support}" == no-invoices ]] || fail "lepic recorded the peer as '${support}'" || return 1

    local before
    before="$(relay_messages_for "${PEER_KEY}")"
    [[ "$(lepic tx cancel "${tx_id}" | jq -r .state)" == cancelled ]] || fail "cancelling the invoice failed" || return 1
    sleep 3
    [[ "$(relay_messages_for "${PEER_KEY}")" == "${before}" ]] ||
        fail "lepic sent the stock wallet something on cancel" || return 1

    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(to_units 0.4)" ||
        fail "lepic has no spendable funds" || return 1
    local sent send_tx send_slate fee
    sent="$(lepic tx send 0.3 --to "${PEER_ADDRESS}")" || fail "lepic send after the bounce failed" || return 1
    send_tx="$(jq -r .tx_id <<<"${sent}")"
    send_slate="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    summary="$(drain_until finalized 1 120)" || fail "epic-wallet stopped answering after the bounce: ${summary}" || return 1
    confirm_both "${send_tx}" "${send_slate}" || return 1
    [[ "$(unmade_for "${PEER_KEY}")" == 0 ]] || fail "the stock listener left a message unacknowledged" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 0.3) - fee))
    check_lepic_total || return 1
    peer_listen_stop
    DETAIL="I1 ${slate_id} bounced and acknowledged, peer recorded no-invoices, no notice on cancel; later S1 confirmed"
}

STEPS=(
    "node status:step_node_status"
    "wallet init:step_wallet_init"
    "wallet address, epicbox status:step_address_and_status"
    "epic-wallet sends to lepic by file:step_receive_by_file"
    "lepic sends to epic-wallet by epicbox:step_send_over_epicbox"
    "epic-wallet sends to lepic by epicbox:step_listen_receives_over_epicbox"
    "lepic sends to epic-wallet by file:step_send_by_file"
    "lepic invoices epic-wallet by file:step_invoice_epic_wallet"
    "epic-wallet invoices lepic by file:step_pay_epic_wallet_invoice"
    "failed delivery, then tx resend:step_resend_after_failed_delivery"
    "tx cancel:step_cancel"
    "tx list, tx show, tx post:step_list_show_post"
    "errors and exit codes:step_errors"
    "epic-wallet pays a lepic listing by epicbox:step_listing_receives_over_epicbox"
    "wallet restore:step_restore"
    "restore --no-scan, then wallet scan:step_scan_after_restore_without_scan"
    "wallet import-seed:step_import_seed"
    "a second lepic wallet funded by file:step_fund_payer"
    "lepic invoices lepic by epicbox:step_invoice_lepic_over_epicbox"
    "lepic sends to lepic by epicbox, posted notice:step_send_to_lepic_over_epicbox"
    "epic-wallet bounces an epicbox invoice:step_stock_listener_bounces_invoice"
)
