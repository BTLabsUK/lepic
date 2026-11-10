# shellcheck shell=bash
# In-person codes: an invoice or send code shown once, the answer by relay or by hand, the TTL
# limits and the payer side with no relay.

CASES+=("ip.invoice|case_ip_invoice|crates/lepic-cli crates/lepic-wallet-contacts crates/lepic-wallet")
CASES+=("ip.send|case_ip_send|crates/lepic-cli crates/lepic-wallet-contacts crates/lepic-wallet")
CASES+=("ip.by-hand|case_ip_by_hand|crates/lepic-cli crates/lepic-wallet-contacts crates/lepic-wallet")
CASES+=("ip.ttl|case_ip_ttl|crates/lepic-cli crates/lepic-wallet-contacts crates/lepic-wallet")
CASES+=("ip.offline|case_ip_offline|crates/lepic-cli crates/lepic-wallet-contacts crates/lepic-wallet")

IP_SHOWER="${E2E_PREFIX}-ip-shower"
IP_PAYER="${E2E_PREFIX}-ip-payer"
IP_TTL=80

ip_setup() {
    ensure_wallet "${IP_SHOWER}" || fail "could not create ${IP_SHOWER}" || return 1
    ensure_wallet "${IP_PAYER}" || fail "could not create ${IP_PAYER}" || return 1
    ensure_funds "${IP_SHOWER}" 2 2 || fail "could not fund ${IP_SHOWER}" || return 1
    ensure_funds "${IP_PAYER}" 2 2 || fail "could not fund ${IP_PAYER}" || return 1
}

# `contact collect` on a wallet until `in-person answers` of a slate lists an answer.
ip_collect_answer() {
    local name="$1" slate="$2" i
    for ((i = 0; i < 40; i++)); do
        w "${name}" contact collect >"${CASE_DIR}/${name}.collect.json" || fail "contact collect on ${name} failed" || return 1
        IP_ANSWERS="$(w "${name}" in-person answers "${slate}")" || fail "in-person answers failed" || return 1
        jq -e '.answers | length > 0' >/dev/null <<<"${IP_ANSWERS}" && return 0
        sleep 3
    done
    fail "${name}: no answer to ${slate} arrived"
}

# Waits until a slate's transaction is confirmed on a wallet.
# `tx list` reads local state; `wallet info` refreshes it from the node first.
ip_state_refreshed() {
    w "$1" wallet info >/dev/null 2>&1 || true
    slate_state_is "$1" "$2" "$3"
}
ip_confirmed() { wait_until "$1 confirms $2" 400 ip_state_refreshed "$1" "$2" confirmed; }

# The whole relay round of one code. $1 invoice|send.
ip_round() {
    local kind="$1" shower="${IP_SHOWER}" payer="${IP_PAYER}" code slate read paid post t0=${SECONDS} n
    local bal0 bal1
    if [[ "${kind}" == invoice ]]; then
        code="$(w "${shower}" in-person invoice 0.1 --ttl-blocks "${IP_TTL}" -m "ip ${kind}")" || fail "in-person invoice failed" || return 1
    else
        code="$(w "${shower}" in-person send 0.1 --min-confirmations "${E2E_MINCONF}" --ttl-blocks "${IP_TTL}" -m "ip ${kind}")" || fail "in-person send failed" || return 1
    fi
    printf '%s\n' "${code}" >"${CASE_DIR}/code.json"
    slate="$(jq -r .slate_id <<<"${code}")"
    expect_json "${code}" ".code | test(\"^[0-9a-f]+\$\")" "code is hex" || return 1
    expect_json "${code}" ".mailbox != null and .ttl_cutoff > 0" "code mailbox and cutoff" || return 1
    read="$(w "${payer}" in-person read --hex "$(jq -r .code <<<"${code}")" --min-confirmations "${E2E_MINCONF}")" || fail "in-person read failed" || return 1
    printf '%s\n' "${read}" >"${CASE_DIR}/read.json"
    expect_json "${read}" ".slate_id == \"${slate}\" and .stage == \"${kind}\" and .mailbox.host == \"${E2E_RELAY}\"" "read" || return 1
    expect_json "${read}" '.amount == "0.1" or .amount == "0.10000000"' "read amount" || return 1
    if [[ "${kind}" == invoice ]]; then
        paid="$(w "${payer}" in-person pay 0.1 --hex "$(jq -r .code <<<"${code}")" --min-confirmations "${E2E_MINCONF}")" || fail "in-person pay failed" || return 1
    else
        paid="$(w "${payer}" in-person receive --hex "$(jq -r .code <<<"${code}")")" || fail "in-person receive failed" || return 1
    fi
    printf '%s\n' "${paid}" >"${CASE_DIR}/answer.json"
    expect_json "${paid}" ".slate_id == \"${slate}\" and (.check_code | length > 0)" "answer" || return 1
    w "${payer}" in-person post "${slate}" --relay-ok >"${CASE_DIR}/post.json" || fail "in-person post failed" || return 1
    ip_collect_answer "${shower}" "${slate}" || return 1
    printf '%s\n' "${IP_ANSWERS}" >"${CASE_DIR}/answers.json"
    expect_json "${IP_ANSWERS}" ".answers | length == 1 and .[0].check_code == \"$(jq -r .check_code <<<"${paid}")\"" "answer check code matches the payer's" || return 1
    n="$(jq -r '.answers[0].number' <<<"${IP_ANSWERS}")"
    w "${shower}" in-person finalize "${slate}" "${n}" >"${CASE_DIR}/finalize.json" || fail "in-person finalize failed" || return 1
    expect_json "$(cat "${CASE_DIR}/finalize.json")" '.state == "posted"' "finalize state" || return 1
    ip_confirmed "${shower}" "${slate}" || return 1
    ip_confirmed "${payer}" "${slate}" || return 1
    IP_SLATE="${slate}"
    note "${kind} round trip, confirmed both sides in $((SECONDS - t0))s"
}

case_ip_invoice() {
    ip_setup || return 1
    ip_round invoice || return 1
    # The same answer cannot finalize twice.
    w "${IP_SHOWER}" in-person answers "${IP_SLATE}" | jq -e '.finalized == 1 and .closed == true' >/dev/null || fail "code not closed after finalize" || return 1
}

case_ip_send() {
    ip_setup || return 1
    ip_round send || return 1
}

# Files only: the code and the answer travel as files, the answer is taken by hand and twice.
case_ip_by_hand() {
    local shower="${IP_SHOWER}" payer="${IP_PAYER}" code slate paid taken again n t0=${SECONDS}
    ip_setup || return 1
    code="$(w "${shower}" in-person invoice 0.05 --ttl-blocks "${IP_TTL}" --out "${CASE_DIR}/code.bin" -m "ip by hand")" || fail "invoice --out failed" || return 1
    slate="$(jq -r .slate_id <<<"${code}")"
    expect_json "${code}" '.file != null and .code == null' "code written to a file" || return 1
    [[ -s "${CASE_DIR}/code.bin" ]] || fail "code file empty" || return 1
    expect_json "$(w "${payer}" in-person read --file "${CASE_DIR}/code.bin" --offline --min-confirmations "${E2E_MINCONF}")" ".slate_id == \"${slate}\" and .stage == \"invoice\"" "read from the file" || return 1
    paid="$(w "${payer}" in-person pay 0.05 --file "${CASE_DIR}/code.bin" --out "${CASE_DIR}/answer.bin" --min-confirmations "${E2E_MINCONF}" --offline)" || fail "in-person pay --file --out failed" || return 1
    expect_json "${paid}" '.file != null and .envelope == null' "answer written to a file" || return 1
    taken="$(w "${shower}" in-person take --file "${CASE_DIR}/answer.bin" --offline)" || fail "in-person take failed" || return 1
    printf '%s\n' "${taken}" >"${CASE_DIR}/taken.json"
    expect_json "${taken}" ".slate_id == \"${slate}\" and .duplicate == false and .check_code == \"$(jq -r .check_code <<<"${paid}")\"" "take: same code as the payer's" || return 1
    again="$(w "${shower}" in-person take --file "${CASE_DIR}/answer.bin" --offline)" || fail "second take failed" || return 1
    printf '%s\n' "${again}" >"${CASE_DIR}/taken-again.json"
    expect_json "${again}" '.duplicate == true' "the same answer taken twice is a duplicate" || return 1
    expect_json "$(w "${shower}" in-person answers "${slate}")" '.answers | length == 1' "one answer stored" || return 1
    n="$(w "${shower}" in-person answers "${slate}" | jq -r '.answers[0].number')"
    w "${shower}" in-person finalize "${slate}" "${n}" >"${CASE_DIR}/finalize.json" || fail "finalize failed" || return 1
    ip_confirmed "${shower}" "${slate}" || return 1
    ip_confirmed "${payer}" "${slate}" || return 1
    note "by hand with files, duplicate answer flagged, confirmed in $((SECONDS - t0))s"
}

# The TTL: 10 blocks or less refused, 11 accepted; an expired code is refused to the payer.
case_ip_ttl() {
    local shower="${IP_SHOWER}" payer="${IP_PAYER}" code slate cutoff
    ip_setup || return 1
    wx 2 "${shower}" in-person invoice 0.01 --ttl-blocks 10 || return 1
    wx 2 "${shower}" in-person send 0.01 --ttl-blocks 10 --min-confirmations "${E2E_MINCONF}" || return 1
    code="$(w "${shower}" in-person invoice 0.01 --ttl-blocks 11)" || fail "11 blocks refused" || return 1
    printf '%s\n' "${code}" >"${CASE_DIR}/code.json"
    slate="$(jq -r .slate_id <<<"${code}")"
    cutoff="$(jq -r .ttl_cutoff <<<"${code}")"
    wait_until "tip passes cutoff ${cutoff}" 900 tip_above "${cutoff}" || return 1
    wx 7 "${payer}" in-person pay 0.01 --hex "$(jq -r .code <<<"${code}")" --min-confirmations "${E2E_MINCONF}" || return 1
    expect_json "${LAST_JSON}" '.error != null' "expired code has an error" || return 1
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/expired.json"
    # The expired invoice frees nothing to the payer, and the shower can cancel its own side.
    w "${shower}" tx cancel "$(w "${shower}" tx list | jq -r --arg id "${slate}" '.transactions[] | select(.slate_id == $id) | .tx_id')" >/dev/null || fail "cancel of the expired invoice failed" || return 1
    note "ttl 10 refused (2), 11 accepted, expired code refused to the payer (7)"
}

# The payer works with no relay: read and pay offline, post fails offline, post works online.
case_ip_offline() {
    local shower="${IP_SHOWER}" payer="${IP_PAYER}" code slate paid n status=0
    ip_setup || return 1
    code="$(w "${shower}" in-person invoice 0.02 --ttl-blocks "${IP_TTL}")" || fail "invoice failed" || return 1
    slate="$(jq -r .slate_id <<<"${code}")"
    expect_json "$(w "${payer}" in-person read --hex "$(jq -r .code <<<"${code}")" --offline --min-confirmations "${E2E_MINCONF}")" ".slate_id == \"${slate}\"" "read offline" || return 1
    paid="$(w "${payer}" in-person pay 0.02 --hex "$(jq -r .code <<<"${code}")" --offline --min-confirmations "${E2E_MINCONF}")" || fail "pay offline failed" || return 1
    expect_json "${paid}" '.envelope != null' "answer made offline" || return 1
    w "${payer}" in-person post "${slate}" --relay-ok --offline >"${CASE_DIR}/post-offline.json" 2>&1 && status=0 || status=$?
    ((status != 0)) || fail "post --offline succeeded" || return 1
    echo "post --offline exit ${status}" >>"${CASE_DIR}/post-offline.json"
    w "${payer}" in-person post "${slate}" --relay-ok >"${CASE_DIR}/post.json" || fail "post online failed after offline" || return 1
    ip_collect_answer "${shower}" "${slate}" || return 1
    n="$(jq -r '.answers[0].number' <<<"${IP_ANSWERS}")"
    w "${shower}" in-person finalize "${slate}" "${n}" >"${CASE_DIR}/finalize.json" || fail "finalize failed" || return 1
    ip_confirmed "${shower}" "${slate}" || return 1
    note "offline read/pay ok, post --offline exit ${status}, post online ok"
}
