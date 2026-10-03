# The setup and the scenarios run.sh runs, in order. Sourced by run.sh.
#
# Each scenario sets DETAIL to one line and returns 0 when every check held. They share one
# chain and one pair of wallets, and EXPECTED_TOTAL tracks what lepic's balance must be after
# each of them, so a lost or doubled effect anywhere shows up as a wrong balance.
# shellcheck shell=bash disable=SC2034 # DETAIL and SCENARIOS are read by run.sh

DETAIL=""
EXPECTED_TOTAL=0
PEER_ADDRESS=""
LEPIC_ADDRESS=""
LEPIC_KEY=""
# Redelivered copies lepic has acknowledged, by stage; they are queued again with the rest.
COPIES_S1=0
COPIES_S2=0

fail() {
    DETAIL="$*"
    return 1
}

# Messages the relay holds for lepic that lepic has not acknowledged yet.
relay_pending_for_lepic() {
    mongo_eval "print(db.slates.countDocuments({queue: '${LEPIC_KEY}', made: false}))"
}

relay_holds_for_lepic() { (($(relay_pending_for_lepic) >= $1)); }

lepic_total_is() { (($(lepic_balance total) == $1)); }

check_lepic_total() {
    wait_until "lepic total ${EXPECTED_TOTAL}" 60 lepic_total_is "${EXPECTED_TOTAL}" ||
        fail "lepic total is $(lepic_balance total), expected ${EXPECTED_TOTAL}"
}

# Highest local transaction id, 0 when there is none.
lepic_last_tx_id() { lepic tx list | jq '[.transactions[].tx_id] | max // 0'; }

# Incoming lepic transactions newer than `after`, one compact JSON object per line.
lepic_incoming_after() {
    lepic tx list | jq -c --argjson after "$1" \
        '.transactions[] | select(.tx_id > $after and .direction == "incoming")'
}

# Waits until a lepic transaction and the peer's record of the same slate are confirmed.
confirm_both() {
    local tx_id="$1" slate_id="$2"
    wait_until "lepic tx ${tx_id} confirmed" 180 lepic_tx_confirmed "${tx_id}" ||
        fail "lepic tx ${tx_id} is $(lepic_tx_state "${tx_id}"), not confirmed" || return 1
    wait_until "peer tx ${slate_id} confirmed" 120 ew_tx_confirmed peer "${slate_id}" ||
        fail "epic-wallet did not confirm ${slate_id}"
}

# Sends from lepic to the peer over Epicbox; prints the send report.
lepic_send_to_peer() {
    local amount="$1"
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(($(to_units "${amount}") + UNIT))" ||
        return 1
    lepic tx send "${amount}" --to "${PEER_ADDRESS}"
}

peer_send_to_lepic() {
    local amount="$1"
    wait_until "peer spendable" 180 ew_spendable_at_least peer "$(($(to_units "${amount}") + UNIT))" ||
        return 1
    ew peer send -m epicbox -d "${LEPIC_ADDRESS}" -c 1 -s smallest "${amount}" >>"${RUN_LOG}"
}

setup() {
    log "creating the lepic wallet"
    lepic wallet init | jq -e '.network == "mainnet"' >/dev/null || fail "lepic wallet init failed" || return 1
    LEPIC_ADDRESS="$(lepic wallet address | jq -r .address)"
    LEPIC_KEY="${LEPIC_ADDRESS%%@*}"
    local peer
    peer="$(ew_address peer)"
    [[ -n "${peer}" ]] || fail "no epic-wallet address" || return 1
    PEER_ADDRESS="${peer%%:*}:3423"
    log "lepic ${LEPIC_ADDRESS}, epic-wallet ${PEER_ADDRESS}"

    log "waiting for mature coinbase in the funder wallet"
    wait_until "funder funds" 300 ew_spendable_at_least funder $((150 * UNIT)) ||
        fail "the funder wallet was not funded by mining" || return 1

    log "funding both wallets through slate files"
    local n
    for n in 1 2; do
        fund_by_file lepic 20 "lepic-${n}" || fail "funding lepic failed" || return 1
    done
    for n in 1 2 3; do
        fund_by_file peer 20 "peer-${n}" || fail "funding epic-wallet failed" || return 1
    done
    EXPECTED_TOTAL=$((40 * UNIT))
    wait_until "lepic funded" 180 lepic_spendable_at_least "${EXPECTED_TOTAL}" ||
        fail "lepic funds did not confirm" || return 1
    wait_until "peer funded" 180 ew_spendable_at_least peer $((60 * UNIT)) ||
        fail "epic-wallet funds did not confirm" || return 1
    DETAIL="lepic and epic-wallet funded at height $(tip_height)"
}

scenario_lepic_sends() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local sent
    sent="$(lepic_send_to_peer 1.5)" || fail "lepic send failed" || return 1
    local tx_id slate_id fee summary
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    summary="$(drain_until finalized 1 120)" || fail "lepic finalized nothing: ${summary}" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 1.5) - fee))
    check_lepic_total || return 1
    DETAIL="slate ${slate_id} confirmed on both sides"
}

scenario_epic_wallet_sends() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local last
    last="$(lepic_last_tx_id)"
    peer_send_to_lepic 2.25 || fail "epic-wallet send failed" || return 1
    local summary
    summary="$(drain_until received 1 120)" || fail "lepic received nothing: ${summary}" || return 1
    local tx
    tx="$(lepic_incoming_after "${last}")"
    [[ "$(wc -l <<<"${tx}")" -eq 1 && -n "${tx}" ]] || fail "expected one new incoming tx, got: ${tx}" || return 1
    [[ "$(jq -r .amount_credited <<<"${tx}")" == 2.25000000 ]] || fail "credited amount wrong: ${tx}" || return 1
    local tx_id slate_id
    tx_id="$(jq -r .tx_id <<<"${tx}")"
    slate_id="$(jq -r .slate_id <<<"${tx}")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 2.25)))
    check_lepic_total || return 1
    DETAIL="slate ${slate_id} confirmed on both sides"
}

scenario_relay_restart() {
    peer_listen_stop
    local sent
    sent="$(lepic_send_to_peer 1)" || fail "lepic send failed" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"

    log "restarting the relay with S1 stored for epic-wallet"
    restart_relay || fail "relay did not come back" || return 1
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    wait_until "epic-wallet received S1" 120 ew_tx_known peer "${slate_id}" ||
        fail "epic-wallet never received S1 after the restart" || return 1
    wait_until "S2 stored for lepic" 60 relay_holds_for_lepic 1 ||
        fail "the relay holds no S2 for lepic" || return 1
    peer_listen_stop

    log "restarting the relay with S2 stored for lepic"
    restart_relay || fail "relay did not come back" || return 1
    local summary
    summary="$(drain_until finalized 1 120)" || fail "lepic finalized nothing: ${summary}" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 1) - fee))
    check_lepic_total || return 1
    DETAIL="two relay restarts; slate ${slate_id} confirmed on both sides"
}

scenario_offline_then_drain() {
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    local last
    last="$(lepic_last_tx_id)"
    peer_send_to_lepic 0.5 || fail "first epic-wallet send failed" || return 1
    peer_send_to_lepic 0.75 || fail "second epic-wallet send failed" || return 1
    wait_until "two slates stored for lepic" 60 relay_holds_for_lepic 2 ||
        fail "the relay does not hold both slates" || return 1

    local report
    report="$(lepic epicbox drain)" || fail "drain failed" || return 1
    [[ "$(jq -r .received <<<"${report}")" -eq 2 ]] ||
        fail "one drain should receive both slates: ${report}" || return 1
    local txs
    txs="$(lepic_incoming_after "${last}")"
    [[ "$(wc -l <<<"${txs}")" -eq 2 ]] || fail "expected two new incoming txs: ${txs}" || return 1
    local tx
    while read -r tx; do
        confirm_both "$(jq -r .tx_id <<<"${tx}")" "$(jq -r .slate_id <<<"${tx}")" || return 1
    done <<<"${txs}"
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 0.5) + $(to_units 0.75)))
    check_lepic_total || return 1
    DETAIL="one drain received both slates sent while lepic was offline"
}

# Queues again, under a new relay message id, the `limit` messages lepic acknowledged most
# recently (all of them when `limit` is 0), so only (slate id, stage) can tell the copies apart
# from new messages. Prints how many it queued.
redeliver_to_lepic() {
    mongo_eval "
        const done = db.slates.find({queue: '${LEPIC_KEY}', made: true})
            .sort({createdat: -1}).limit($1).toArray();
        done.forEach(d => {
            delete d._id;
            d.made = false;
            d.messageid = d.messageid + 'dup' + Date.now();
            d.createdat = new Date();
            db.slates.insertOne(d);
        });
        print(done.length);"
}

# Every counter of a drain report except `field` is zero, and `field` is `want`.
report_counts_only() {
    local report="$1" field="$2" want="$3" name
    for name in received finalized repeated rejected held; do
        local expected=0
        [[ "${name}" == "${field}" ]] && expected="${want}"
        [[ "$(jq -r ".${name}" <<<"${report}")" -eq "${expected}" ]] || return 1
    done
}

scenario_duplicate_open() {
    peer_listen_stop
    local last count_before report
    last="$(lepic_last_tx_id)"
    peer_send_to_lepic 0.4 || fail "epic-wallet send failed" || return 1
    wait_until "S1 stored for lepic" 60 relay_holds_for_lepic 1 || fail "the relay holds no S1" || return 1
    report="$(lepic epicbox drain)" || fail "drain failed" || return 1
    report_counts_only "${report}" received 1 || fail "S1 not received once: ${report}" || return 1
    local incoming
    incoming="$(lepic_incoming_after "${last}")"
    count_before="$(lepic_tx_count)"

    [[ "$(redeliver_to_lepic 1)" -eq 1 ]] || fail "could not redeliver S1" || return 1
    report="$(lepic epicbox drain)" || fail "drain failed" || return 1
    report_counts_only "${report}" repeated 1 || fail "redelivered S1 not counted repeated: ${report}" || return 1
    COPIES_S1=$((COPIES_S1 + 1))

    local sent
    sent="$(lepic_send_to_peer 0.6)" || fail "lepic send failed" || return 1
    peer_listen_start || fail "epic-wallet listener did not start" || return 1
    wait_until "S2 stored for lepic" 120 relay_holds_for_lepic 1 || fail "the relay holds no S2" || return 1
    report="$(lepic epicbox drain)" || fail "drain failed" || return 1
    report_counts_only "${report}" finalized 1 || fail "S2 not finalized once: ${report}" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"

    # Drain refreshes nothing, so the transaction is still open when the copy arrives.
    [[ "$(redeliver_to_lepic 1)" -eq 1 ]] || fail "could not redeliver S2" || return 1
    report="$(lepic epicbox drain)" || fail "drain failed" || return 1
    report_counts_only "${report}" repeated 1 || fail "redelivered S2 not counted repeated: ${report}" || return 1
    COPIES_S2=$((COPIES_S2 + 1))
    [[ "$(lepic_tx_state "${tx_id}")" == posted ]] || fail "tx ${tx_id} is not posted" || return 1
    [[ "$(lepic_tx_count)" -eq $((count_before + 1)) ]] || fail "redeliveries created transactions" || return 1

    confirm_both "$(jq -r .tx_id <<<"${incoming}")" "$(jq -r .slate_id <<<"${incoming}")" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 0.4) - $(to_units 0.6) - fee))
    check_lepic_total || return 1
    DETAIL="redelivered S1 and S2 of open transactions counted repeated, no effect"
}

# Epicbox transactions of lepic in one direction.
lepic_epicbox_txs() {
    lepic tx list | jq --arg dir "$1" '[.transactions[] | select(.transport == "epicbox" and .direction == $dir)] | length'
}

scenario_duplicate_settled() {
    local count_before copies
    count_before="$(lepic_tx_count)"
    # Every S1 lepic acknowledged started an incoming transaction, every S2 completed an outgoing
    # one, and all of them are confirmed by now.
    local s1 s2
    s1=$(($(lepic_epicbox_txs incoming) + COPIES_S1))
    s2=$(($(lepic_epicbox_txs outgoing) + COPIES_S2))
    copies="$(redeliver_to_lepic 0)"
    ((copies == s1 + s2)) || fail "redelivered ${copies} messages, expected ${s1} S1 and ${s2} S2" || return 1

    local summary
    summary="$(drain_until handled "${copies}" 60 '.repeated + .rejected')" ||
        fail "redeliveries not all settled: ${summary}" || return 1
    # A copy of an S2 whose transaction is confirmed is counted rejected, not repeated: a known
    # lepic-wallet defect recorded in the V-02 claim's Found section, to be fixed in its own task.
    # Require `repeated` for all copies once it is.
    [[ "$(jq -r .repeated <<<"${summary}")" -eq "${s1}" && "$(jq -r .rejected <<<"${summary}")" -eq "${s2}" ]] ||
        fail "expected ${s1} repeated S1 and ${s2} rejected S2 copies: ${summary}" || return 1
    local field
    for field in received finalized held; do
        [[ "$(jq -r ".${field}" <<<"${summary}")" -eq 0 ]] ||
            fail "a redelivery counted as ${field}: ${summary}" || return 1
    done
    [[ "$(relay_pending_for_lepic)" -eq 0 ]] || fail "redeliveries left unacknowledged on the relay" || return 1
    [[ "$(lepic_tx_count)" -eq "${count_before}" ]] || fail "redeliveries created transactions" || return 1
    check_lepic_total || return 1
    DETAIL="${s1} S1 copies repeated, ${s2} S2 copies of confirmed txs rejected, no effect"
}

SCENARIOS=(
    "lepic sends to epic-wallet:scenario_lepic_sends"
    "epic-wallet sends to lepic:scenario_epic_wallet_sends"
    "relay restart mid-transaction:scenario_relay_restart"
    "lepic offline, then one drain:scenario_offline_then_drain"
    "duplicates of open transactions:scenario_duplicate_open"
    "duplicates of settled slates:scenario_duplicate_settled"
)
