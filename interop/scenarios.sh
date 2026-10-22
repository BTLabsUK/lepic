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
    [[ "$(jq -r .repeated <<<"${summary}")" -eq "${copies}" ]] ||
        fail "expected all ${copies} copies repeated: ${summary}" || return 1
    local field
    for field in received finalized rejected held; do
        [[ "$(jq -r ".${field}" <<<"${summary}")" -eq 0 ]] ||
            fail "a redelivery counted as ${field}: ${summary}" || return 1
    done
    [[ "$(relay_pending_for_lepic)" -eq 0 ]] || fail "redeliveries left unacknowledged on the relay" || return 1
    [[ "$(lepic_tx_count)" -eq "${count_before}" ]] || fail "redeliveries created transactions" || return 1
    check_lepic_total || return 1
    DETAIL="${s1} S1 and ${s2} S2 copies of confirmed txs repeated, no effect"
}

# The slate file lepic wrote at `path` is in the V3 shape with header 3/3 (ADR 0015), and carries
# a TTL when `ttl` is "ttl".
lepic_file_is_v3() {
    local path="$1" ttl="${2:-}"
    dc exec -T lepic cat "${path}" | jq -e --arg ttl "${ttl}" '
        .version_info.version == 3 and .version_info.orig_version == 3
        and has("ttl_cutoff_height") and has("payment_proof")
        and (($ttl != "ttl") or (.ttl_cutoff_height != null))' >/dev/null
}

# The block header version a slate file carries.
file_block_header_version() { dc exec -T lepic cat "$1" | jq -r .version_info.block_header_version; }

# lepic writes S1 with a TTL to a file, epic-wallet answers it, lepic finalizes and posts.
scenario_file_lepic_sends() {
    peer_listen_stop
    local slate=/exchange/file-lepic-sends.slate
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(($(to_units 1.1) + UNIT))" ||
        fail "lepic has no spendable funds" || return 1
    local sent
    sent="$(lepic tx send 1.1 --to-file "${slate}" --ttl-blocks 60)" || fail "lepic send failed" || return 1
    lepic_file_is_v3 "${slate}" ttl || fail "lepic's S1 is not V3 at 3/3 with a TTL" || return 1
    ew peer receive -i "${slate}" >>"${RUN_LOG}" || fail "epic-wallet refused lepic's V3 S1" || return 1
    local finalized
    finalized="$(lepic tx finalize "${slate}.response")" || fail "lepic could not finalize the S2" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    [[ "$(jq -r .slate_id <<<"${finalized}")" == "${slate_id}" ]] || fail "finalized another slate: ${finalized}" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 1.1) - fee))
    check_lepic_total || return 1
    DETAIL="V3 S1 with TTL read by epic-wallet; slate ${slate_id} confirmed on both sides"
}

# epic-wallet writes S1 (V2 at 2/2), lepic answers in V3 at 3/3, epic-wallet finalizes and posts.
scenario_file_epic_wallet_sends() {
    peer_listen_stop
    local slate=/exchange/file-epic-wallet-sends.slate
    wait_until "peer spendable" 180 ew_spendable_at_least peer "$(($(to_units 1.2) + UNIT))" ||
        fail "epic-wallet has no spendable funds" || return 1
    ew peer send -m file -d "${slate}" -c 1 -s smallest 1.2 >>"${RUN_LOG}" || fail "epic-wallet send failed" || return 1
    local received
    received="$(lepic tx receive "${slate}")" || fail "lepic could not receive the S1" || return 1
    local reply
    reply="$(jq -r .reply_file <<<"${received}")"
    lepic_file_is_v3 "${reply}" || fail "lepic's S2 is not V3 at 3/3" || return 1
    [[ "$(file_block_header_version "${reply}")" == "$(file_block_header_version "${slate}")" ]] ||
        fail "lepic's S2 changed the block header version" || return 1
    ew peer finalize -i "${reply}" >>"${RUN_LOG}" || fail "epic-wallet could not finalize lepic's V3 S2" || return 1
    local tx_id slate_id
    tx_id="$(jq -r .tx_id <<<"${received}")"
    slate_id="$(jq -r .slate_id <<<"${received}")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 1.2)))
    check_lepic_total || return 1
    DETAIL="V3 S2 finalized by epic-wallet; slate ${slate_id} confirmed on both sides"
}

# lepic issues I1 to a file, epic-wallet pays it, lepic finalizes and posts.
scenario_file_lepic_invoices() {
    peer_listen_stop
    local slate=/exchange/file-lepic-invoices.slate
    wait_until "peer spendable" 180 ew_spendable_at_least peer "$(($(to_units 0.8) + UNIT))" ||
        fail "epic-wallet has no spendable funds" || return 1
    local issued
    issued="$(lepic invoice issue 0.8 --to-file "${slate}")" || fail "lepic invoice issue failed" || return 1
    lepic_file_is_v3 "${slate}" || fail "lepic's I1 is not V3 at 3/3" || return 1
    ew_pay peer "$(jq -r .amount <<<"${issued}")" -i "${slate}" -d "${slate}.response" -c 1 -s smallest ||
        fail "epic-wallet could not pay lepic's V3 I1" || return 1
    local finalized
    finalized="$(lepic tx finalize "${slate}.response")" || fail "lepic could not finalize the I2" || return 1
    local tx_id slate_id
    tx_id="$(jq -r .tx_id <<<"${issued}")"
    slate_id="$(jq -r .slate_id <<<"${issued}")"
    [[ "$(jq -r .slate_id <<<"${finalized}")" == "${slate_id}" ]] || fail "finalized another slate: ${finalized}" || return 1
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 0.8)))
    check_lepic_total || return 1
    DETAIL="V3 I1 paid by epic-wallet; slate ${slate_id} confirmed on both sides"
}

# epic-wallet issues I1 (V2 at 2/2), lepic pays with a TTL in V3 at 3/3, epic-wallet finalizes.
scenario_file_epic_wallet_invoices() {
    peer_listen_stop
    local slate=/exchange/file-epic-wallet-invoices.slate
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(($(to_units 0.7) + UNIT))" ||
        fail "lepic has no spendable funds" || return 1
    ew peer invoice -d "${slate}" 0.7 >>"${RUN_LOG}" || fail "epic-wallet invoice failed" || return 1
    local paid
    paid="$(lepic invoice pay "${slate}" 0.7 --ttl-blocks 60)" || fail "lepic could not pay the I1" || return 1
    local reply
    reply="$(jq -r .reply_file <<<"${paid}")"
    lepic_file_is_v3 "${reply}" ttl || fail "lepic's I2 is not V3 at 3/3 with a TTL" || return 1
    ew peer finalize -i "${reply}" >>"${RUN_LOG}" || fail "epic-wallet could not finalize lepic's V3 I2" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${paid}")"
    slate_id="$(jq -r .slate_id <<<"${paid}")"
    fee="$(to_units "$(jq -r .fee <<<"${paid}")")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 0.7) - fee))
    check_lepic_total || return 1
    DETAIL="V3 I2 with TTL finalized by epic-wallet; slate ${slate_id} confirmed on both sides"
}

# lepic pays the epic-wallet listening over HTTP; the send finalizes and posts in one command.
scenario_http_lepic_sends() {
    peer_http_listen_start || fail "epic-wallet http listener did not start" || return 1
    wait_until "lepic spendable" 180 lepic_spendable_at_least "$(($(to_units 1.3) + UNIT))" ||
        fail "lepic has no spendable funds" || return 1
    local sent
    sent="$(lepic tx send 1.3 --to "http://127.0.0.1:${PEER_HTTP_PORT}")" || fail "lepic http send failed" || return 1
    peer_listen_stop
    [[ "$(jq -r .transport <<<"${sent}")" == http && "$(jq -r .state <<<"${sent}")" == posted ]] ||
        fail "send was not finalized and posted over http: ${sent}" || return 1
    local tx_id slate_id fee
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    fee="$(to_units "$(jq -r .fee <<<"${sent}")")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL - $(to_units 1.3) - fee))
    check_lepic_total || return 1
    DETAIL="slate ${slate_id} posted by one command, confirmed on both sides"
}

# epic-wallet pays lepic's HTTP listener; epic-wallet finalizes and posts.
scenario_http_epic_wallet_sends() {
    peer_listen_stop
    wait_until "peer spendable" 180 ew_spendable_at_least peer "$(($(to_units 2.1) + UNIT))" ||
        fail "epic-wallet has no spendable funds" || return 1
    local last
    last="$(lepic_last_tx_id)"
    lepic_http_listen_start || fail "lepic http listener did not start" || return 1
    ew peer send -m http -d "http://127.0.0.1:${LEPIC_HTTP_PORT}" -c 1 -s smallest 2.1 >>"${RUN_LOG}" ||
        { lepic_http_listen_stop >/dev/null; fail "epic-wallet http send failed"; return 1; }
    # The listener holds the wallet open, so lepic's other commands wait until it is stopped.
    local report
    report="$(lepic_http_listen_stop)"
    [[ "$(jq -r '[.received, .repeated, .refused] | join(",")' <<<"${report}")" == 1,0,0 ]] ||
        fail "listener report is not one received payment: ${report}" || return 1
    local tx
    tx="$(lepic_incoming_after "${last}")"
    [[ "$(wc -l <<<"${tx}")" -eq 1 && -n "${tx}" ]] || fail "expected one new incoming tx, got: ${tx}" || return 1
    [[ "$(jq -r .amount_credited <<<"${tx}")" == 2.10000000 ]] || fail "credited amount wrong: ${tx}" || return 1
    local tx_id slate_id
    tx_id="$(jq -r .tx_id <<<"${tx}")"
    slate_id="$(jq -r .slate_id <<<"${tx}")"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 2.1)))
    check_lepic_total || return 1
    DETAIL="slate ${slate_id} received over http, confirmed on both sides"
}

# Posts a slate file to a wallet's foreign API as epic-wallet does, from the peer container, and
# prints the JSON-RPC answer.
post_receive_tx() {
    local port="$1" slate="$2"
    dc exec -T peer cat "${slate}" |
        jq -c '{jsonrpc: "2.0", id: 1, method: "receive_tx", params: [., null, null]}' |
        dc exec -T peer curl -s -H 'Content-Type: application/json' --data-binary @- \
            "http://127.0.0.1:${port}/v2/foreign"
}

# The same S1 delivered twice gets the same S2 and leaves one transaction.
scenario_http_repeat() {
    peer_listen_stop
    local slate=/exchange/http-repeat.slate
    wait_until "peer spendable" 180 ew_spendable_at_least peer "$(($(to_units 0.9) + UNIT))" ||
        fail "epic-wallet has no spendable funds" || return 1
    ew peer send -m file -d "${slate}" -c 1 -s smallest 0.9 >>"${RUN_LOG}" || fail "epic-wallet send failed" || return 1
    local slate_id count_before
    slate_id="$(dc exec -T peer cat "${slate}" | jq -r .id)"
    count_before="$(lepic_tx_count)"
    lepic_http_listen_start || fail "lepic http listener did not start" || return 1
    local first second
    first="$(post_receive_tx "${LEPIC_HTTP_PORT}" "${slate}")"
    second="$(post_receive_tx "${LEPIC_HTTP_PORT}" "${slate}")"
    local report
    report="$(lepic_http_listen_stop)"
    jq -e '.result.Ok.id' <<<"${first}" >/dev/null || fail "first delivery refused: ${first}" || return 1
    [[ "$(jq -S -c . <<<"${first}")" == "$(jq -S -c . <<<"${second}")" ]] ||
        fail "the repeat got another S2: ${first} / ${second}" || return 1
    [[ "$(jq -r '[.received, .repeated, .refused] | join(",")' <<<"${report}")" == 1,1,0 ]] ||
        fail "listener report is not one received and one repeated: ${report}" || return 1
    [[ "$(lepic_tx_count)" -eq $((count_before + 1)) ]] || fail "the repeat created a transaction" || return 1
    [[ "$(lepic_tx_by_slate "${slate_id}" | wc -l)" -eq 1 ]] || fail "not one transaction for ${slate_id}" || return 1
    # Settle it: epic-wallet finalizes the S2 and posts.
    jq -c '.result.Ok' <<<"${first}" | dc exec -T peer sh -c "cat >${slate}.response"
    ew peer finalize -i "${slate}.response" >>"${RUN_LOG}" || fail "epic-wallet could not finalize the S2" || return 1
    local tx_id
    tx_id="$(lepic_tx_by_slate "${slate_id}" | jq -r .tx_id)"
    confirm_both "${tx_id}" "${slate_id}" || return 1
    EXPECTED_TOTAL=$((EXPECTED_TOTAL + $(to_units 0.9)))
    check_lepic_total || return 1
    DETAIL="S1 ${slate_id} delivered twice: same S2, one transaction"
}

# shellcheck source=history.sh
source "${INTEROP_DIR}/history.sh"

SCENARIOS=(
    "lepic sends to epic-wallet:scenario_lepic_sends"
    "epic-wallet sends to lepic:scenario_epic_wallet_sends"
    "relay restart mid-transaction:scenario_relay_restart"
    "lepic offline, then one drain:scenario_offline_then_drain"
    "duplicates of open transactions:scenario_duplicate_open"
    "duplicates of settled slates:scenario_duplicate_settled"
    "lepic sends to epic-wallet by file:scenario_file_lepic_sends"
    "epic-wallet sends to lepic by file:scenario_file_epic_wallet_sends"
    "lepic invoices epic-wallet by file:scenario_file_lepic_invoices"
    "epic-wallet invoices lepic by file:scenario_file_epic_wallet_invoices"
    "lepic sends over http:scenario_http_lepic_sends"
    "epic-wallet sends over http:scenario_http_epic_wallet_sends"
    "same S1 twice over http:scenario_http_repeat"
    "import epic-wallet history:scenario_import_history"
)
