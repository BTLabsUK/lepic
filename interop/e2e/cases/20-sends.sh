# shellcheck shell=bash
# Payments: every way one LEPIC wallet pays another, the amounts and fees both sides record, the
# receiver's balance, and what a payer can do with a send afterwards.

CASES+=("send.epicbox|case_send_epicbox|crates/lepic-epicbox crates/lepic-wallet crates/lepic-cli")
CASES+=("send.epicbox-offline|case_send_epicbox_offline|crates/lepic-epicbox crates/lepic-wallet crates/lepic-cli")
CASES+=("send.http|case_send_http|crates/lepic-http crates/lepic-wallet crates/lepic-cli")
CASES+=("send.tor|case_send_tor|crates/lepic-tor crates/lepic-http crates/lepic-cli")
CASES+=("send.native-vs-legacy|case_send_native_vs_legacy|crates/lepic-native-slate crates/lepic-http crates/lepic-wallet")
CASES+=("send.file|case_send_file|crates/lepic-cli crates/lepic-wallet crates/lepic-slate")
CASES+=("send.epictx|case_send_epictx|crates/lepic-seal crates/lepic-native-slate crates/lepic-cli")
CASES+=("send.message|case_send_message|crates/lepic-cli crates/lepic-wallet")
CASES+=("send.idempotent|case_send_idempotent|crates/lepic-cli crates/lepic-wallet")
CASES+=("send.repeat|case_send_repeat|crates/lepic-wallet crates/lepic-cli")
CASES+=("send.manage|case_send_manage|crates/lepic-wallet crates/lepic-cli")
CASES+=("peer.pins|case_peer_pins|crates/lepic-http crates/lepic-cli crates/lepic-wallet")
CASES+=("send.refuse-unsolicited|case_send_refuse_unsolicited|crates/lepic-wallet crates/lepic-cli")

PAY_A="${E2E_PREFIX}-pay-a"
PAY_B="${E2E_PREFIX}-pay-b"
PAY_C="${E2E_PREFIX}-pay-c"
TOR_BIN="${LEPIC_E2E_TOR_BIN:-${E2E_TOR_DIR}/tor}"

# The wallets: A pays (a few EPIC in several outputs), B and C receive.
pay_ready() {
    local n
    for n in "${PAY_A}" "${PAY_B}" "${PAY_C}"; do ensure_wallet "${n}" || return 1; done
    wconfig_reset "${PAY_A}"
    wconfig_reset "${PAY_B}"
    wconfig_reset "${PAY_C}"
    ensure_funds "${PAY_A}" 3 4 || fail "could not fund ${PAY_A}" || return 1
    cancel_open_sends "${PAY_A}"
}

# Cancels the payer's sends that never reached a payee (state sent), so their inputs come back.
cancel_open_sends() {
    local id
    for id in $(w "$1" tx list | jq -r '.transactions[] | select(.state == "sent") | .tx_id'); do
        w "$1" tx cancel "${id}" >/dev/null || true
    done
}

# A listener that other computers can reach, addressed by this machine's LAN address. A native
# send never posts to a listener on this device, and plain http to another computer needs
# --allow-plain-http (NATIVE_SEND_ARGS).
NATIVE_SEND_ARGS=(--allow-plain-http)
native_listen() {
    local ip
    ip="$(hostname -I | tr ' ' '\n' | grep -E '^(192\.168|10\.)' | head -n 1)"
    [[ -n "${ip}" ]] || ip="$(hostname -I | awk '{print $1}')"
    [[ -n "${ip}" ]] || fail "this machine has no network address" || return 1
    http_listen "$1" --internet || return 1
    HTTP_URL="http://${ip}:${HTTP_PORT}"
}

# The address of a wallet, before any listener holds its lock.
addr_of() { w "$1" wallet address | jq -r .address; }

# The total a wallet holds, in units (spendable and pending alike).
total_units() { to_units "$(balance "$1" total)"; }

# `tx show` for a slate id on either side (`tx show --slate-id` finds sends only).
show_by_slate() {
    local id
    id="$(tx_by_slate "$1" "$2" | jq -r '.tx_id // empty')"
    [[ -n "${id}" ]] || return 1
    w "$1" tx show "${id}"
}

# Waits until a transaction, found by slate id, is in one of the states; `wallet info` refreshes.
wait_slate_state() {
    local wallet="$1" slate="$2" states="$3" timeout="${4:-240}"
    wait_until "${wallet} tx ${slate:0:8} in ${states}" "${timeout}" slate_state_refreshed "${wallet}" "${slate}" "${states}"
}
slate_state_refreshed() {
    w "$1" wallet info >/dev/null 2>&1 || true
    slate_state_in "$1" "$2" "$3"
}

# Waits for the receiver's spendable to reach `before + amount` (units).
wait_received() {
    local wallet="$1" want="$2"
    wait_until "${wallet} spendable >= $(from_units "${want}")" 240 spendable_at_least_refreshed "${wallet}" "${want}"
}
spendable_at_least_refreshed() { spendable_at_least "$1" "$2"; }

# After a payment: both sides' records, the amounts and the fee, and the receiver's balance.
#   check_paid <payer> <receiver> <slate_id> <amount_units> <receiver_spendable_before_units>
check_paid() {
    local payer="$1" payee="$2" slate="$3" amount="$4" before="$5" p r fee
    wait_slate_state "${payer}" "${slate}" "posted confirmed" || fail "payer never saw ${slate} posted: $(tx_by_slate "${payer}" "${slate}")" || return 1
    wait_slate_state "${payee}" "${slate}" "posted confirmed" || fail "payee never saw ${slate} posted: $(tx_by_slate "${payee}" "${slate}")" || return 1
    wait_received "${payee}" $((before + amount)) || fail "payee spendable did not grow by $(from_units "${amount}"): $(balance "${payee}")" || return 1
    wait_slate_state "${payer}" "${slate}" "confirmed" 120 || fail "payer's tx never confirmed" || return 1
    p="$(show_by_slate "${payer}" "${slate}")" || fail "payer tx show failed" || return 1
    r="$(show_by_slate "${payee}" "${slate}")" || fail "payee tx show failed" || return 1
    expect_json "${p}" '.direction == "outgoing" and .state == "confirmed"' "payer tx" || return 1
    expect_json "${r}" '.direction == "incoming" and .state == "confirmed"' "payee tx" || return 1
    fee="$(jq -r .fee <<<"${p}")"
    expect_eq "$(jq -r .amount_debited <<<"${p}")" "$(from_units $((amount + $(to_units "${fee}") + $(to_units "$(jq -r .amount_credited <<<"${p}")"))))" "payer debit = amount + fee + change" || return 1
    expect_eq "$(jq -r .amount_credited <<<"${r}")" "$(from_units "${amount}")" "payee credit" || return 1
    expect_match "${fee}" '^0\.0[0-9]+$' "fee" || return 1
    PAID_FEE="${fee}"
}

case_send_epicbox() {
    local before out slate addr amount="0.05"
    pay_ready || return 1
    addr="$(addr_of "${PAY_B}")"
    before="$(balance_units "${PAY_B}")" || return 1
    epicbox_listen "${PAY_B}" || fail "payee listener did not connect" || return 1
    out="$(w "${PAY_A}" tx send --to "${addr}" --min-confirmations "${E2E_MINCONF}" "${amount}")" || fail "tx send failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    expect_json "${out}" '.transport == "epicbox" and .delivered == true and .state == "sent"' "send result" || return 1
    # The reply goes back to the payer's relay inbox; the payer's own drain finalizes and posts.
    wait_until "payee received" 60 slate_state_in "${PAY_A}" "${slate}" "sent" || return 1
    sleep 4
    w "${PAY_A}" epicbox drain >"${CASE_DIR}/drain.json" || fail "payer drain failed" || return 1
    wait_slate_state "${PAY_A}" "${slate}" "posted confirmed" 60 || fail "payer did not post after drain: $(tx_by_slate "${PAY_A}" "${slate}")" || return 1
    wstop "${EPICBOX_PID}"
    check_paid "${PAY_A}" "${PAY_B}" "${slate}" "$(to_units "${amount}")" "${before}" || return 1
    note "epicbox ${amount} paid, fee ${PAID_FEE}"
}

case_send_epicbox_offline() {
    local before out slate addr amount="0.04"
    pay_ready || return 1
    addr="$(addr_of "${PAY_B}")"
    before="$(balance_units "${PAY_B}")" || return 1
    # The payee is offline: the relay holds the slate.
    out="$(w "${PAY_A}" tx send --to "${addr}" --min-confirmations "${E2E_MINCONF}" "${amount}")" || fail "tx send failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    expect_json "${out}" '.delivered == true' "queued at the relay" || return 1
    expect_eq "$(slate_state_is "${PAY_B}" "${slate}" received && echo yes || echo no)" no "payee knows the slate before it came online" || return 1
    w "${PAY_B}" epicbox drain >"${CASE_DIR}/drain-b.json" || fail "payee drain failed" || return 1
    wait_slate_state "${PAY_B}" "${slate}" "received finalized posted confirmed" 30 || fail "payee drain took no slate" || return 1
    sleep 3
    w "${PAY_A}" epicbox drain >"${CASE_DIR}/drain-a.json" || fail "payer drain failed" || return 1
    wait_slate_state "${PAY_A}" "${slate}" "posted confirmed" 60 || fail "payer did not post: $(tx_by_slate "${PAY_A}" "${slate}")" || return 1
    check_paid "${PAY_A}" "${PAY_B}" "${slate}" "$(to_units "${amount}")" "${before}" || return 1
    note "offline epicbox ${amount} paid after drains, fee ${PAID_FEE}"
}

case_send_http() {
    local before out slate amount="0.03"
    pay_ready || return 1
    before="$(balance_units "${PAY_B}")" || return 1
    http_listen "${PAY_B}" || fail "http listener did not start" || return 1
    out="$(w "${PAY_A}" tx send --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" "${amount}")" || fail "tx send over http failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    expect_json "${out}" '.delivered == true and (.state == "posted" or .state == "finalized")' "http send result" || return 1
    wstop "${HTTP_PID}"
    check_paid "${PAY_A}" "${PAY_B}" "${slate}" "$(to_units "${amount}")" "${before}" || return 1
    note "http ${amount} paid in one command, fee ${PAID_FEE}, format $(jq -r .format <<<"${out}")"
}

case_send_tor() {
    local before out slate amount="0.02" onion tor_args
    [[ -x "${TOR_BIN}" ]] || fail "no tor binary at ${TOR_BIN}" || return 1
    pay_ready || return 1
    tor_args=(--tor-binary "${TOR_BIN}" --lib-dir "${E2E_TOR_DIR}")
    before="$(balance_units "${PAY_B}")" || return 1
    wbg "${PAY_B}" tor tor listen "${tor_args[@]}"
    local tor_pid=${BG_PID} log="${BG_LOG}"
    wait_until "onion address printed" 240 grep -Eq '[a-z2-7]{56}\.onion' "${log}.out" "${log}.err" ||
        fail "tor listener never printed an onion address: $(tail -n 3 "${log}.err" | cut -c1-200)" || return 1
    onion="$(cat "${log}.out" "${log}.err" | grep -Eo '[a-z2-7]{56}\.onion' | head -n 1)"
    out="$(w "${PAY_A}" tx send --to "${onion}" "${tor_args[@]}" --min-confirmations "${E2E_MINCONF}" "${amount}")" ||
        fail "tx send over tor failed: $(tail -c 300 "${CASE_DIR}/last.err")" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    expect_json "${out}" '.delivered == true' "tor send result" || return 1
    wstop "${tor_pid}"
    check_paid "${PAY_A}" "${PAY_B}" "${slate}" "$(to_units "${amount}")" "${before}" || return 1
    note "tor ${amount} paid to ${onion:0:12}…, fee ${PAID_FEE}, transport $(jq -r .transport <<<"${out}")"
}

case_send_native_vs_legacy() {
    local out_legacy out_native out_forced rec
    pay_ready || return 1
    native_listen "${PAY_B}" || return 1
    # Native slates are off by default: a plain send goes as a legacy slate.
    out_legacy="$(w "${PAY_A}" tx send "${NATIVE_SEND_ARGS[@]}" --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "default send failed" || return 1
    expect_eq "$(jq -r .format <<<"${out_legacy}")" legacy "format with native_direct off" || return 1
    # Both sides need native_direct: the listener advertises the endpoint only when it is on.
    wstop "${HTTP_PID}"
    wconfig_set "${PAY_A}" 'native_direct = true'
    wconfig_set "${PAY_B}" 'native_direct = true'
    native_listen "${PAY_B}" || return 1
    out_native="$(w "${PAY_A}" tx send "${NATIVE_SEND_ARGS[@]}" --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "native send failed" || return 1
    expect_json "${out_native}" '.format != "legacy"' "format with native_direct on" || return 1
    out_forced="$(w "${PAY_A}" tx send "${NATIVE_SEND_ARGS[@]}" --to "${HTTP_URL}" --legacy --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "--legacy send failed" || return 1
    expect_eq "$(jq -r .format <<<"${out_forced}")" legacy "format with --legacy" || return 1
    wconfig_reset "${PAY_A}"
    wconfig_reset "${PAY_B}"
    wstop "${HTTP_PID}"
    # What each side records for each slate.
    for out in "${out_legacy}" "${out_native}" "${out_forced}"; do
        rec="$(tx_by_slate "${PAY_B}" "$(jq -r .slate_id <<<"${out}")")"
        expect_json "${rec}" '.direction == "incoming"' "payee records $(jq -r .format <<<"${out}") slate" || return 1
    done
    printf '%s\n' "$(w "${PAY_A}" tx show --slate-id "$(jq -r .slate_id <<<"${out_native}")")" >"${CASE_DIR}/native-payer.json"
    printf '%s\n' "$(show_by_slate "${PAY_B}" "$(jq -r .slate_id <<<"${out_native}")")" >"${CASE_DIR}/native-payee.json"
    note "formats: default $(jq -r .format <<<"${out_legacy}"), native_direct $(jq -r .format <<<"${out_native}"), --legacy $(jq -r .format <<<"${out_forced}"); payer stages $(jq -c .stages "${CASE_DIR}/native-payer.json") payee stages $(jq -c .stages "${CASE_DIR}/native-payee.json")"
}

case_send_file() {
    local out slate dir="${CASE_DIR}" before amount="0.02" r
    pay_ready || return 1
    before="$(balance_units "${PAY_B}")" || return 1
    out="$(w "${PAY_A}" tx send --to-file "${dir}/s1.slate" --min-confirmations "${E2E_MINCONF}" "${amount}")" || fail "send --to-file failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    expect_json "${out}" '.state == "sent"' "file send state" || return 1
    [[ -s "${dir}/s1.slate" ]] || fail "no slate file written" || return 1
    expect_json "$(cat "${dir}/s1.slate")" '.version_info.version == 3' "V3 slate JSON" || return 1
    r="$(w "${PAY_B}" tx receive "${dir}/s1.slate" --reply-file "${dir}/s2.slate")" || fail "tx receive failed" || return 1
    printf '%s\n' "${r}" >"${dir}/receive.json"
    [[ -s "${dir}/s2.slate" ]] || fail "no reply file" || return 1
    expect_eq "$(tx_state "${PAY_B}" "$(jq -r .tx_id <<<"${r}")")" received "payee state after receive" || return 1
    out="$(w "${PAY_A}" tx finalize "${dir}/s2.slate")" || fail "tx finalize failed" || return 1
    expect_json "${out}" '.state == "posted" or .state == "finalized"' "finalize result" || return 1
    check_paid_file "${slate}" "${amount}" "${before}" || return 1
}

# A file payment: the payee's tx is `received` until the chain shows it, then confirmed.
check_paid_file() {
    local slate="$1" amount="$2" before="$3"
    wait_slate_state "${PAY_A}" "${slate}" "confirmed" 240 || fail "payer's file tx never confirmed" || return 1
    wait_slate_state "${PAY_B}" "${slate}" "confirmed" 120 || fail "payee's file tx never confirmed: $(tx_by_slate "${PAY_B}" "${slate}")" || return 1
    wait_received "${PAY_B}" $((before + $(to_units "${amount}"))) || fail "payee balance did not grow" || return 1
    note "slate file ${amount} paid"
}

case_send_message() {
    local out slate tag="e2e-note-$$"
    pay_ready || return 1
    http_listen "${PAY_B}" || return 1
    out="$(w "${PAY_A}" tx send --to "${HTTP_URL}" -m "${tag}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "send -m failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    wstop "${HTTP_PID}"
    expect_json "$(w "${PAY_A}" tx show --slate-id "${slate}")" "[.messages[]? | select(.text == \"${tag}\")] | length >= 1" "payer sees the message" || return 1
    expect_json "$(show_by_slate "${PAY_B}" "${slate}")" "[.messages[]? | select(.text == \"${tag}\")] | length >= 1" "payee sees the message" || return 1
    # --purpose belongs to contact sends: with --to it is a usage error.
    wx 2 "${PAY_A}" tx send --to "${HTTP_URL}" --purpose payment 0.01 || return 1
    note "message '${tag}' on both sides; --purpose with --to is exit 2"
}

case_send_idempotent() {
    local id first again before after
    pay_ready || return 1
    id="$(cat /proc/sys/kernel/random/uuid)"
    http_listen "${PAY_B}" || return 1
    first="$(w "${PAY_A}" tx send --to "${HTTP_URL}" --slate-id "${id}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "first send failed" || return 1
    expect_eq "$(jq -r .slate_id <<<"${first}")" "${id}" "slate id used" || return 1
    expect_json "${first}" '.repeated == false' "first send is not repeated" || return 1
    before="$(w "${PAY_A}" tx list | jq '.transactions | length')"
    again="$(w "${PAY_A}" tx send --to "${HTTP_URL}" --slate-id "${id}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "repeat send failed" || return 1
    after="$(w "${PAY_A}" tx list | jq '.transactions | length')"
    wstop "${HTTP_PID}"
    expect_json "${again}" '.repeated == true and .delivered == true' "repeat result" || return 1
    expect_eq "$(jq -r .tx_id <<<"${again}")" "$(jq -r .tx_id <<<"${first}")" "same tx" || return 1
    expect_eq "${after}" "${before}" "tx count after the repeat" || return 1
    expect_eq "$(w "${PAY_A}" tx list | jq --arg id "${id}" '[.transactions[] | select(.slate_id == $id)] | length')" 1 "txs with the id" || return 1
    # Same id, another amount: rejected, nothing stored.
    wx 7 "${PAY_A}" tx send --to "http://127.0.0.1:9" --slate-id "${id}" 0.02 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "rejected"' "different send under the id" || return 1
    note "second send under ${id:0:8} repeated: true, tx count ${after}"
}

case_send_repeat() {
    local i out slates=() before amount=0.01
    pay_ready || return 1
    ensure_funds "${PAY_A}" 4 4 || return 1
    before="$(balance_units "${PAY_B}")" || return 1
    http_listen "${PAY_B}" || return 1
    for i in 1 2 3 4; do
        out="$(w "${PAY_A}" tx send --to "${HTTP_URL}" --change-outputs 2 --min-confirmations "${E2E_MINCONF}" "${amount}")" ||
            fail "send ${i} of 4 failed: $(tail -c 300 "${CASE_DIR}/last.err")" || return 1
        slates+=("$(jq -r .slate_id <<<"${out}")")
    done
    wstop "${HTTP_PID}"
    for i in "${slates[@]}"; do
        wait_slate_state "${PAY_A}" "${i}" "posted confirmed" 60 || fail "send ${i} not posted" || return 1
    done
    wait_received "${PAY_B}" $((before + 4 * $(to_units "${amount}"))) || fail "payee did not receive all four" || return 1
    expect_eq "$(printf '%s\n' "${slates[@]}" | sort -u | wc -l)" 4 "distinct slates" || return 1
    note "4 sends of ${amount} back to back with --change-outputs 2, all posted"
}

case_send_manage() {
    local out id slate dead locked_before
    pay_ready || return 1
    locked_before="$(w "${PAY_A}" wallet info | jq -r '.accounts[0].locked')"
    # cancel before post: the inputs come back.
    out="$(w "${PAY_A}" tx send --to-file "${CASE_DIR}/c.slate" --min-confirmations "${E2E_MINCONF}" 0.02)" || fail "file send failed" || return 1
    id="$(jq -r .tx_id <<<"${out}")"
    expect_json "$(w "${PAY_A}" wallet info | jq -c .accounts[0])" ".locked != \"${locked_before}\"" "inputs locked by the open send" || return 1
    w "${PAY_A}" tx cancel "${id}" >/dev/null || fail "tx cancel failed" || return 1
    expect_eq "$(tx_state "${PAY_A}" "${id}")" cancelled "state after cancel" || return 1
    expect_eq "$(w "${PAY_A}" wallet info | jq -r '.accounts[0].locked')" "${locked_before}" "locked amount after cancel" || return 1
    # resend after a failed delivery: a listener that is gone, then a live one.
    http_listen "${PAY_C}" || return 1
    dead="${HTTP_URL}"
    wstop "${HTTP_PID}"
    wx 11 "${PAY_A}" tx send --to "${dead}" --min-confirmations "${E2E_MINCONF}" 0.02 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "incomplete"' "failed delivery error kind" || return 1
    id="$(w "${PAY_A}" tx list | jq '[.transactions[] | select(.state == "sent")] | last | .tx_id')"
    slate="$(w "${PAY_A}" tx show "${id}" | jq -r .slate_id)"
    http_listen "${PAY_B}" || return 1
    out="$(w "${PAY_A}" tx resend "${id}" --to "${HTTP_URL}")" || fail "tx resend failed" || return 1
    expect_json "${out}" '.state == "posted"' "resend result" || return 1
    wait_slate_state "${PAY_A}" "${slate}" "posted confirmed" 60 || fail "resent tx not posted" || return 1
    # post again of a posted tx
    w "${PAY_A}" tx post "${id}" >"${CASE_DIR}/post-again.json" || fail "tx post of a posted tx failed" || return 1
    # release is refused while the chain is young.
    wx 7 "${PAY_A}" tx release "${id}" || return 1
    expect_json "${LAST_JSON}" '.error.kind == "rejected"' "release error kind" || return 1
    # --fluff
    out="$(w "${PAY_A}" tx send --to "${HTTP_URL}" --fluff --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "send --fluff failed" || return 1
    wstop "${HTTP_PID}"
    wait_slate_state "${PAY_A}" "$(jq -r .slate_id <<<"${out}")" "posted confirmed" 60 || fail "fluffed tx not posted" || return 1
    note "cancel frees inputs; dead listener exit 11; resend ok; post again ok; release refused; --fluff posted"
}

case_peer_pins() {
    local out origin
    pay_ready || return 1
    # Pins are made by native sends to LEPIC listeners: native_direct on both sides.
    wconfig_set "${PAY_A}" 'native_direct = true'
    wconfig_set "${PAY_B}" 'native_direct = true'
    native_listen "${PAY_B}" || return 1
    origin="${HTTP_URL}"
    expect_eq "$(w "${PAY_A}" peer pins | jq --arg o "${origin}" '[.. | objects | select(.origin? == $o)] | length')" 0 "pins before the first payment" || return 1
    w "${PAY_A}" tx send "${NATIVE_SEND_ARGS[@]}" --to "${origin}" --min-confirmations "${E2E_MINCONF}" 0.01 >/dev/null || fail "first send failed" || return 1
    out="$(w "${PAY_A}" peer pins)" || return 1
    printf '%s\n' "${out}" >"${CASE_DIR}/pins.json"
    expect_json "${out}" "[.. | objects | select(.origin? == \"${origin}\")] | length == 1" "pin after the first payment" || return 1
    w "${PAY_A}" peer forget "${origin}" >/dev/null || fail "peer forget failed" || return 1
    expect_json "$(w "${PAY_A}" peer pins)" "[.. | objects | select(.origin? == \"${origin}\")] | length == 0" "pin after forget" || return 1
    w "${PAY_A}" tx send "${NATIVE_SEND_ARGS[@]}" --to "${origin}" --min-confirmations "${E2E_MINCONF}" 0.01 >/dev/null || fail "send after forget failed" || return 1
    expect_json "$(w "${PAY_A}" peer pins)" "[.. | objects | select(.origin? == \"${origin}\")] | length == 1" "pinned again by the next send" || return 1
    wstop "${HTTP_PID}"
    wconfig_reset "${PAY_A}"
    wconfig_reset "${PAY_B}"
    note "pin made by the first send, dropped by peer forget, made again by the next send"
}

case_send_refuse_unsolicited() {
    local before_tx id
    pay_ready || return 1
    wconfig_set "${PAY_B}" 'refuse_unsolicited_payments = true' 'refuse_unsolicited_invoices = true'
    http_listen "${PAY_B}" || return 1
    before_tx="$(w "${PAY_A}" tx list | jq '.transactions | length')"
    wx 11 "${PAY_A}" tx send --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01 || return 1
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/refused-send.json"
    expect_json "${LAST_JSON}" '.error.kind == "incomplete"' "refused send error kind" || return 1
    # The refused send stays stored with its inputs locked; cancel it.
    id="$(w "${PAY_A}" tx list | jq '[.transactions[] | select(.state == "sent")] | last | .tx_id')"
    w "${PAY_A}" tx cancel "${id}" >/dev/null || fail "cancel of the refused send failed" || return 1
    wstop "${HTTP_PID}"
    wconfig_reset "${PAY_B}"
    # With the switch off again the same send is taken.
    http_listen "${PAY_B}" || return 1
    w "${PAY_A}" tx send --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01 >/dev/null || fail "send with the switch off failed" || return 1
    wstop "${HTTP_PID}"
    note "refused with the switch on (exit 11, incomplete; cancelled); taken with it off; tx before $((before_tx))"
}

# A payment file named .epictx: the CLI reads files by content, never by name. The CLI cannot
# make a sealed file of a plain send; a V3 slate carries the reply key (`lepic.reply`) a native
# receiver would seal to, and what `epictx open` and `tx receive` do with files is checked here.
case_send_epictx() {
    local out slate dir="${CASE_DIR}" before amount="0.02" r st=0
    pay_ready || return 1
    before="$(balance_units "${PAY_B}")" || return 1
    out="$(w "${PAY_A}" tx send --to-file "${dir}/send.epictx" --min-confirmations "${E2E_MINCONF}" "${amount}")" || fail "send --to-file send.epictx failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    expect_json "$(cat "${dir}/send.epictx")" '.lepic.reply | test("^[0-9a-f]{64}$")' "reply key on the V3 slate" || return 1
    # epictx open takes a sealed file; a plain slate is a usage error (not armor) and nothing is stored.
    lepic_env "${PAY_B}" --output json epictx open "${dir}/send.epictx" >"${dir}/open-plain.out" 2>"${dir}/open-plain.err" || st=$?
    printf 'exit=%s\n' "${st}" >"${dir}/open-plain.exit"
    [[ "${st}" == 2 ]] || fail "epictx open of a plain slate exited ${st}, wanted 2 (usage, not armor): $(head -c 300 "${dir}/open-plain.out")" || return 1
    # The receiver takes the file by its content and answers with a reply file.
    r="$(w "${PAY_B}" tx receive "${dir}/send.epictx" --reply-file "${dir}/reply.epictx")" || fail "tx receive of send.epictx failed" || return 1
    printf '%s\n' "${r}" >"${dir}/receive.json"
    [[ -s "${dir}/reply.epictx" ]] || fail "no reply file" || return 1
    printf 'reply starts: %s\n' "$(head -c 40 "${dir}/reply.epictx")" >"${dir}/reply.kind"
    out="$(w "${PAY_A}" tx finalize "${dir}/reply.epictx")" || fail "tx finalize of the reply failed" || return 1
    expect_json "${out}" '.state == "posted" or .state == "finalized"' "finalize result" || return 1
    check_paid_file "${slate}" "${amount}" "${before}" || return 1
    note ".epictx-named V3 file paid; epictx open of a plain slate exit ${st}; $(cat "${dir}/reply.kind")"
}
