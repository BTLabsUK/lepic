# shellcheck shell=bash
# The bank: one wallet funded from the QA funder that funds every other case's wallets over HTTP,
# so the funder is called rarely and its 10-confirmation change wait stays off the cases.

CASES+=("bank.ready|case_bank_ready|crates/lepic-wallet crates/lepic-legacy-rpc")

case_bank_ready() {
    local bank="${E2E_PREFIX}-bank" floor
    ensure_wallet "${bank}" || return 1
    floor="$(to_units "${LEPIC_E2E_BANK_FLOOR:-10}")"
    if ! spendable_at_least "${bank}" "${floor}"; then
        fund_bank "${LEPIC_E2E_BANK_REFILL:-30}" || fail "the QA funder did not pay the bank" || return 1
        wait_until "bank funds confirmed" 300 spendable_at_least "${bank}" "${floor}" ||
            fail "bank funds not spendable after 300s: $(w "${bank}" wallet info | jq -c .accounts[0])" || return 1
    fi
    note "bank spendable $(balance "${bank}") at height $(tip)"
}
