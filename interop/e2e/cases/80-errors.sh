# shellcheck shell=bash
# Errors a service hits: the exact exit status and the JSON error's kind for each.

CASES+=("err.low-balance|case_err_low_balance|crates/lepic-wallet crates/lepic-cli")
CASES+=("err.bad-input|case_err_bad_input|crates/lepic-cli")
CASES+=("err.unreachable|case_err_unreachable|crates/lepic-http crates/lepic-epicbox crates/lepic-cli")
CASES+=("err.double-spend|case_err_double_spend|crates/lepic-wallet crates/lepic-node crates/lepic-cli")
CASES+=("err.cancel-after-post|case_err_cancel_after_post|crates/lepic-wallet crates/lepic-cli")
CASES+=("err.invoice-declined-or-expired|case_err_invoice_declined|crates/lepic-wallet crates/lepic-cli")
CASES+=("err.locked|case_err_locked|crates/lepic-cli")

ERR_A="${E2E_PREFIX}-err-a"
ERR_B="${E2E_PREFIX}-err-b"
ERR_C="${E2E_PREFIX}-err-c"

err_ready() {
    ensure_wallet "${ERR_A}" || return 1
    ensure_wallet "${ERR_B}" || return 1
    ensure_wallet "${ERR_C}" || return 1
    wconfig_reset "${ERR_A}"
    wconfig_reset "${ERR_B}"
}

# The last wx result's error kind.
err_kind() { jq -r '.error.kind // empty' <<<"${LAST_JSON}"; }
expect_kind() { expect_eq "$(err_kind)" "$1" "error kind of: $(head -c 200 <<<"${LAST_JSON}")"; }

case_err_low_balance() {
    err_ready || return 1
    # ERR_C never holds funds.
    http_listen "${ERR_B}" || return 1
    wx 8 "${ERR_C}" tx send --to "${HTTP_URL}" 1 || return 1
    expect_kind insufficient_funds || return 1
    expect_json "${LAST_JSON}" '.error.exit_code == 8' "exit_code field" || return 1
    wx 8 "${ERR_C}" tx send --to-file "${CASE_DIR}/x.slate" 1 || return 1
    expect_kind insufficient_funds || return 1
    wstop "${HTTP_PID}"
    expect_eq "$(w "${ERR_C}" tx list | jq '.transactions | length')" 0 "txs stored by refused sends" || return 1
    note "send without funds: exit 8, insufficient_funds, nothing stored"
}

case_err_bad_input() {
    err_ready || return 1
    ensure_funds "${ERR_A}" 1 1 || return 1
    wx 2 "${ERR_A}" tx send --to "not-an-address" 0.01 || return 1
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/bad-address.json"
    expect_kind usage || return 1
    wx 2 "${ERR_A}" tx send --to "zzNotARealAddress@${E2E_RELAY}" 0.01 || return 1
    expect_kind usage || return 1
    wx 2 "${ERR_A}" tx send --to-file "${CASE_DIR}/y.slate" abc || return 1
    expect_kind usage || return 1
    wx 2 "${ERR_A}" tx send --to-file "${CASE_DIR}/y.slate" 0 || return 1
    wx 2 "${ERR_A}" tx send --bogus-flag || return 1
    expect_kind usage || return 1
    wx 2 "${ERR_A}" tx send --to-file "${CASE_DIR}/y.slate" -- -1 || return 1
    wx 2 "${ERR_A}" tx send --to-file "${CASE_DIR}/y.slate" 0.000000001 || return 1
    wx 6 "${ERR_A}" tx show 99999 || return 1
    expect_kind not_found || return 1
    note "bad address and bad amounts: exit 2 (usage); unknown tx: exit 6"
}

case_err_unreachable() {
    err_ready || return 1
    ensure_funds "${ERR_A}" 1 1 || return 1
    cancel_open_sends "${ERR_A}"
    wx 11 "${ERR_A}" tx send --to "http://127.0.0.1:9" --min-confirmations "${E2E_MINCONF}" 0.01 || return 1
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/dead-http.json"
    expect_kind incomplete || return 1
    cancel_open_sends "${ERR_A}"
    local addr
    addr="$(addr_of "${ERR_B}")"
    sed 's/^epicbox_relay.*/epicbox_relay = "nonexistent.invalid"/' "${E2E_STATE}/config.toml" >"${E2E_STATE}/wallets/${ERR_A}.toml"
    wx 11 "${ERR_A}" tx send --to "${addr}" --min-confirmations "${E2E_MINCONF}" 0.01 || return 1
    expect_kind incomplete || return 1
    wx 10 "${ERR_A}" epicbox drain || return 1
    expect_kind transport || return 1
    wconfig_reset "${ERR_A}"
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/dead-relay.json"
    cancel_open_sends "${ERR_A}"
    note "dead http listener and dead relay: send exit 11 incomplete (stored, not delivered); epicbox drain on a dead relay exit 10 transport"
}

# Two wallets with the same database spend the same outputs: the node takes the first post and
# refuses the second. The second wallet is a copy of err-a's data directory, made after funding.
case_err_double_spend() {
    local clone="${E2E_PREFIX}-err-clone" out id
    err_ready || return 1
    ensure_funds "${ERR_A}" 1 1 || return 1
    cancel_open_sends "${ERR_A}"
    mkdir -p "$(wdir "${clone}")" && cp -a -T "$(wdir "${ERR_A}")" "$(wdir "${clone}")" || fail "could not copy the wallet" || return 1
    http_listen "${ERR_B}" || return 1
    out="$(w "${ERR_A}" tx send --selection all --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "first spend failed" || return 1
    expect_json "${out}" '.state == "posted"' "first spend posted" || return 1
    wx 11 "${clone}" tx send --selection all --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01 || return 1
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/double-spend.json"
    expect_kind incomplete || return 1
    expect_json "${LAST_JSON}" '[.error.causes[]? | select(test("did not accept"))] | length >= 1' "error says the node did not accept it" || return 1
    expect_json "${LAST_JSON}" '.error.tx_id != null and (.error.recovery | length) >= 1 and (.error.recovery | map(test("^lepic tx (resend|post|cancel) ")) | all)' "error names the transaction and its recovery commands" || return 1
    wstop "${HTTP_PID}"
    id="$(w "${clone}" tx list | jq '[.transactions[] | select(.state == "finalized")] | last | .tx_id')"
    expect_json "$(w "${clone}" tx show "${id}")" '.state == "finalized"' "the refused spend stays finalized, not posted" || return 1
    wx 11 "${clone}" tx post "${id}" || return 1
    w "${clone}" tx cancel "${id}" >/dev/null || fail "cancel of the refused spend failed" || return 1
    note "second wallet over the same outputs: node refuses (exit 11, incomplete, 'did not accept'); tx stays finalized; repost exit 11; cancel frees it"
}

case_err_cancel_after_post() {
    local out id
    err_ready || return 1
    ensure_funds "${ERR_A}" 1 1 || return 1
    http_listen "${ERR_B}" || return 1
    out="$(w "${ERR_A}" tx send --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "send failed" || return 1
    wstop "${HTTP_PID}"
    id="$(jq -r .tx_id <<<"${out}")"
    wx 7 "${ERR_A}" tx cancel "${id}" || return 1
    expect_kind rejected || return 1
    expect_json "$(w "${ERR_A}" tx show "${id}")" '.state == "posted" or .state == "confirmed"' "state after the refused cancel" || return 1
    note "cancel of a posted tx: exit 7, rejected; state unchanged"
}

case_err_invoice_declined() {
    local out id
    err_ready || return 1
    ensure_funds "${ERR_A}" 1 1 || return 1
    out="$(w "${ERR_B}" invoice issue --to-file "${CASE_DIR}/i.slate" 0.01)" || fail "invoice issue failed" || return 1
    # Paying an invoice slate nobody asked this wallet for another amount, or a file that is not a slate.
    wx 7 "${ERR_A}" invoice pay "${CASE_DIR}/i.slate" 0.02 || return 1
    expect_kind rejected || return 1
    printf 'not a slate' >"${CASE_DIR}/junk.slate"
    wx 2 "${ERR_A}" invoice pay "${CASE_DIR}/junk.slate" 0.01 || return 1
    expect_kind usage || return 1
    # An unknown parked invoice.
    wx 6 "${ERR_A}" invoice pay 00000000-0000-4000-8000-000000000000 0.01 || return 1
    expect_kind not_found || return 1
    note "wrong amount: exit 7; junk file: exit 2 (usage, not a payment file); unknown parked invoice: exit 6"
}

case_err_locked() {
    err_ready || return 1
    wbg "${ERR_B}" epicbox epicbox listen
    local pid=${BG_PID}
    wait_until "listener connected" 40 grep -q "connected to the relay" "${BG_LOG}.err" || return 1
    wx 5 "${ERR_B}" wallet info || return 1
    expect_kind wallet_state || return 1
    wx 5 "${ERR_B}" tx list || return 1
    wstop "${pid}"
    w "${ERR_B}" wallet info >/dev/null || fail "wallet still locked after the listener stopped" || return 1
    note "any command on a wallet whose listener runs: exit 5, wallet_state; free again after it stops"
}
