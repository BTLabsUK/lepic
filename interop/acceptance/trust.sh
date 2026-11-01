# SPDX-License-Identifier: Apache-2.0
# Trust checks on real wallets: what lepic sends to a stock epic-wallet's payments address once
# another install on that wallet's recovery phrase ran LEPIC. `run.sh --trust` sources this after
# probes.sh and runs TRUST_STEPS instead of STEPS, with step_trust_setup as its setup step.
#
# The stock wallet's relay queue is the thing under test. A stock listener never acknowledges a
# payload that is not a slate, and after three resend rounds the relay deletes every message of
# that address nobody acknowledged (docs/compat/epicbox.md, "Relay retention"). So a notice lepic
# sends to such an address costs the wallet whatever waits behind it.
#
# Run against the build under test, and against an older lepic with --lepic, to see the harm the
# per-exchange rule of ADR 0016 (schema version 12) prevents.
# shellcheck shell=bash disable=SC2034,SC2154 # run.sh reads DETAIL and TRUST_STEPS, sets log_dir

TWIN_DIR=""
# Payments lepic sends while the stock wallet is offline, after the first one.
QUEUED_PAYMENTS=3
# Long enough for the relay's nine challenge rounds of a minute, so a queue that is going to be
# deleted is deleted before the step gives up.
QUEUE_WAIT=900

# lepic on the stock wallet's recovery phrase, imported from its wallet.seed: the "twin".
twin() { lepic --data-dir "${TWIN_DIR}" "$@"; }

twin_spendable_at_least() {
    (($(to_units "$(twin wallet info | jq -r '.accounts[0].spendable')") >= $1))
}

# What lepic (the sender) knows of the stock wallet's key, through `epicbox peer`.
sender_view() { lepic epicbox peer "${PEER_ADDRESS}"; }

parse_errors() { peer_log_count 'Unable to parse slate'; }

relay_has_unmade() { (($(unmade_for "${PEER_KEY}") > 0)); }

step_trust_setup() {
    step_probe_setup || return 1
    TWIN_DIR="${STATE_DIR}/twin"
    LEPIC_ADDRESS="$(lepic wallet address | jq -r .address)" || fail "wallet address failed" || return 1
    peer_listen_stop
    local n
    # Separate outputs, so lepic can start every payment while earlier ones wait.
    local received
    for n in $(seq 0 "${QUEUED_PAYMENTS}"); do
        received="$(ew_sends_file_to_lepic funder 2 "trust-lepic-${n}")" || return 1
        wait_until "lepic funding ${n} confirmed" 180 lepic_tx_confirmed "$(jq -r .tx_id <<<"${received}")" ||
            fail "lepic's funding ${n} did not confirm" || return 1
    done
    fund_by_file peer 3 "trust-peer" || fail "funding the stock wallet failed" || return 1
    wait_until "lepic spendable" 300 lepic_spendable_at_least "$(to_units $((2 * (QUEUED_PAYMENTS + 1))))" ||
        fail "lepic's funds did not confirm" || return 1
    dc exec -T peer cat /data/.epic/user/wallet_data/wallet.seed >"${STATE_DIR}/peer.seed" ||
        fail "could not copy the peer's wallet.seed" || return 1
    local status=0
    printf 'peer-password\n' | lepic_env "${LEPIC_BIN}" --output json --data-dir "${TWIN_DIR}" \
        wallet import-seed "${STATE_DIR}/peer.seed" >>"${RUN_LOG}" 2>&1 || status=$?
    ((status == 0)) || fail "wallet import-seed exited ${status}" || return 1
    [[ "$(twin wallet address | jq -r .address | cut -d@ -f1)" == "${PEER_KEY}" ]] ||
        fail "the twin has another key than the stock wallet" || return 1
    wait_until "the twin's funds spendable" 300 twin_spendable_at_least "$(to_units 1)" ||
        fail "the twin's imported funds did not become spendable" || return 1
    peer_listen_start || fail "the stock listener did not restart" || return 1
    DETAIL="lepic ${LEPIC_ADDRESS} funded with $((QUEUED_PAYMENTS + 1)) outputs; twin of ${PEER_KEY} imported"
}

# The twin pays lepic, with the marker, from the stock wallet's key: lepic learns that key as
# running LEPIC just now. The stock listener is off, so the twin is the one that takes the S2.
trust_twin_marks_the_key() {
    peer_listen_stop
    local sent
    sent="$(twin tx send 0.5 --to "${LEPIC_ADDRESS}")" || fail "the twin's send failed" || return 1
    drain_until received 1 120 >/dev/null || fail "lepic did not receive the twin's payment" || return 1
    local finalized=0 deadline=$((SECONDS + 120)) report
    until ((finalized >= 1)); do
        ((SECONDS < deadline)) || fail "the twin finalized nothing" || return 1
        report="$(twin epicbox drain)" || fail "the twin's drain failed" || return 1
        finalized=$((finalized + $(jq -r .finalized <<<"${report}")))
        ((finalized >= 1)) || sleep 3
    done
    [[ "$(unmade_for "${PEER_KEY}")" == 0 ]] || fail "a message for the key waits unacknowledged" || return 1
    local view
    view="$(sender_view)" || fail "epicbox peer failed" || return 1
    printf 'after the twin: %s\n' "${view}" >>"${RUN_LOG}"
    jq -e '.capability == "lepic"' <<<"${view}" >/dev/null ||
        fail "lepic does not see the key as LEPIC: ${view}" || return 1
    peer_listen_start || fail "the stock listener did not restart" || return 1
    DETAIL="twin's $(jq -r .slate_id <<<"${sent}") answered and finalized; key seen as $(jq -c '{capability, notices}' <<<"${view}")"
}

# R1 and R2: lepic pays the stock wallet, which answers without the marker. While lepic
# finalizes, a probe posts a slate to the stock wallet, then lepic pays it three more times while
# it is offline, as a phone is. The stock wallet must get all four payments and the probe's
# slate, with no message left unacknowledged and no parse failure in its log.
trust_stock_queue_survives() {
    local errors_before parse_after deliveries_before
    errors_before="$(parse_errors)"
    deliveries_before="$(relay_deliveries_to "${PEER_KEY}")"
    local first
    first="$(lepic tx send 0.5 --to "${PEER_ADDRESS}")" || fail "lepic's first payment failed" || return 1
    drain_until finalized 1 120 >/dev/null || fail "lepic finalized nothing" || return 1
    # Whatever lepic sent after its push has reached the relay now; the stock wallet goes
    # offline, as a phone does, and the next messages queue.
    sleep 5
    peer_listen_stop
    local view_after_first
    view_after_first="$(sender_view)"
    printf 'after the stock answer: %s\n' "${view_after_first}" >>"${RUN_LOG}"

    ew funder send -m file -d /exchange/trust-probe-s1.slate -c 1 -s smallest 1 >>"${RUN_LOG}" ||
        fail "the probe's S1 could not be made" || return 1
    probe_saved trust-probe-post post "${PROBE_KEY}" "${RELAY_URL}" "${PEER_ADDRESS}" \
        "${EXCHANGE_DIR}/trust-probe-s1.slate" | jq -e '.answer == "Ok"' >/dev/null ||
        fail "the relay refused the probe's slate" || return 1
    local n sent_ids=()
    for n in $(seq 1 "${QUEUED_PAYMENTS}"); do
        sent_ids+=("$(lepic tx send 0.5 --to "${PEER_ADDRESS}" | jq -r .slate_id)") ||
            fail "lepic's payment ${n} failed" || return 1
    done
    local queued
    queued="$(unmade_for "${PEER_KEY}")"
    printf 'queued for the stock wallet while offline: %s\n' "${queued}" >>"${RUN_LOG}"

    peer_listen_start || fail "the stock listener did not restart" || return 1
    local summary probe_back finalized
    summary="$(drain_until finalized "${QUEUED_PAYMENTS}" "${QUEUE_WAIT}")"
    finalized="$(jq -r .finalized <<<"${summary}")"
    probe_back="$(probe_saved trust-probe-drain drain "${PROBE_KEY}" "${RELAY_URL}" \
        "${PROBE_DIR}/trust-probe-back" 1 60 | jq '.messages | length')"
    parse_after="$(parse_errors)"
    local left
    left="$(unmade_for "${PEER_KEY}")"
    local stock_answered=0 slate_id
    for slate_id in "$(jq -r .slate_id <<<"${first}")" "${sent_ids[@]}"; do
        ! ew_tx_known peer "${slate_id}" || stock_answered=$((stock_answered + 1))
    done
    local view
    view="$(sender_view)"
    printf 'trust queue: finalized %s, stock answered %s of %s, probe got %s, parse errors %s -> %s, unmade %s, relay handed out %s\n' \
        "${finalized}" "${stock_answered}" "$((QUEUED_PAYMENTS + 1))" "${probe_back}" \
        "${errors_before}" "${parse_after}" "${left}" \
        "$(($(relay_deliveries_to "${PEER_KEY}") - deliveries_before))" >>"${RUN_LOG}"
    DETAIL="stock wallet answered ${stock_answered}/$((QUEUED_PAYMENTS + 1)) payments, probe slate answered ${probe_back}/1, parse failures +$((parse_after - errors_before)), unacknowledged ${left}; lepic sees $(jq -c '{capability, notices, last_unmarked_at}' <<<"${view}")"
    ((stock_answered == QUEUED_PAYMENTS + 1 && finalized >= QUEUED_PAYMENTS)) || return 1
    ((probe_back == 1)) || return 1
    ((parse_after == errors_before && left == 0)) || return 1
    # R2: the stock answer on a key a twin had just shown as LEPIC turned it back, and no
    # notice goes to it.
    jq -e '.capability == "no_invoices" and (.notices | not) and .last_unmarked_at != null' \
        <<<"${view_after_first}" >/dev/null || return 1
}

# R3, the relay's half: every client tells the relay the version epic-wallet v4.1.0 sends.
trust_relay_sees_the_plain_version() {
    local versions
    # The relay prints each ClientDetails message it takes, one field per line.
    versions="$(dc logs epicbox 2>/dev/null | grep -o "wallet_version: '[^']*'" |
        sed "s/.*wallet_version: '//; s/'\$//" | sort | uniq -c | tr -s ' ' | paste -sd, -)"
    DETAIL="ClientDetails wallet_version seen: ${versions}"
    [[ -n "${versions}" ]] || return 1
    ! grep -q "lepic" <<<"${versions}" || return 1
}

TRUST_STEPS=(
    "twin on the stock key pays lepic:trust_twin_marks_the_key"
    "R1/R2 stock queue survives:trust_stock_queue_survives"
    "R3 relay sees the plain version:trust_relay_sees_the_plain_version"
)
