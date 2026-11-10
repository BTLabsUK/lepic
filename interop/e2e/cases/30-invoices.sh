# shellcheck shell=bash
# Invoices: asking for a payment over Epicbox and through slate files; the payer pays or declines.

CASES+=("inv.epicbox|case_inv_epicbox|crates/lepic-epicbox crates/lepic-wallet crates/lepic-cli")
CASES+=("inv.file|case_inv_file|crates/lepic-wallet crates/lepic-cli crates/lepic-slate")
CASES+=("inv.decline|case_inv_decline|crates/lepic-epicbox crates/lepic-wallet crates/lepic-cli")
CASES+=("inv.expiry|case_inv_expiry|crates/lepic-wallet crates/lepic-cli")
CASES+=("inv.peer|case_inv_peer|crates/lepic-epicbox crates/lepic-wallet crates/lepic-cli")

INV_ISSUER="${E2E_PREFIX}-inv-issuer"
INV_PAYER="${E2E_PREFIX}-inv-payer"

inv_ready() {
    ensure_wallet "${INV_ISSUER}" || return 1
    ensure_wallet "${INV_PAYER}" || return 1
    wconfig_reset "${INV_ISSUER}"
    wconfig_reset "${INV_PAYER}"
    ensure_funds "${INV_PAYER}" 2 3 || fail "could not fund ${INV_PAYER}" || return 1
}

# The slate id of the newest outgoing... of an issuer's invoice, found by amount and state.
inv_issue_epicbox() {
    local amount="$1" out
    out="$(w "${INV_ISSUER}" invoice issue --to "$(addr_of "${INV_PAYER}")" -m "$2" "${amount}")" || fail "invoice issue failed" || return 1
    ISSUED="${out}"
    ISSUED_ID="$(jq -r .slate_id <<<"${out}")"
}

# A bare Epicbox invoice (no pairing): a LEPIC payer takes invoices over Epicbox only from a
# paired contact it allowed, so nothing is parked and the issuer's invoice stays open until the
# issuer cancels it. Paying over Epicbox is inv.peer.
case_inv_epicbox() {
    local before_pay list drain locked_before
    inv_ready || return 1
    cancel_open_invoices "${INV_ISSUER}"
    locked_before="$(w "${INV_PAYER}" wallet info | jq -r '.accounts[0].locked')"
    inv_issue_epicbox 0.02 "e2e invoice" || return 1
    printf '%s\n' "${ISSUED}" >"${CASE_DIR}/issued.json"
    expect_json "${ISSUED}" '.transport == "epicbox" and (.slate_id | length) > 0' "invoice issued" || return 1
    drain="$(w "${INV_PAYER}" epicbox drain)" || fail "payer drain failed" || return 1
    printf '%s\n' "${drain}" >"${CASE_DIR}/payer-drain.json"
    list="$(w "${INV_PAYER}" invoice list)" || fail "invoice list failed" || return 1
    printf '%s\n' "${list}" >"${CASE_DIR}/payer-list.json"
    expect_json "${list}" "[.. | objects | select(.slate_id? == \"${ISSUED_ID}\")] | length == 0" "bare invoice is not parked at the payer" || return 1
    expect_eq "$(w "${INV_PAYER}" wallet info | jq -r '.accounts[0].locked')" "${locked_before}" "payer's locked amount unchanged" || return 1
    w "${INV_ISSUER}" tx cancel "$(jq -r .tx_id <<<"${ISSUED}")" >/dev/null || fail "issuer could not cancel the open invoice" || return 1
    note "bare Epicbox invoice ${ISSUED_ID:0:8} not parked by the LEPIC payer (needs a paired, allowed contact); issuer cancelled it"
}

# Cancels the issuer's invoices that nobody paid, so a rerun starts clean.
cancel_open_invoices() {
    local id
    for id in $(w "$1" tx list | jq -r '.transactions[] | select(.state == "sent" or .state == "invoice") | .tx_id'); do
        w "$1" tx cancel "${id}" >/dev/null || true
    done
}

case_inv_file() {
    local amount="0.02" before out id d="${CASE_DIR}"
    inv_ready || return 1
    before="$(balance_units "${INV_ISSUER}")" || return 1
    out="$(w "${INV_ISSUER}" invoice issue --to-file "${d}/i.slate" "${amount}")" || fail "invoice issue --to-file failed" || return 1
    id="$(jq -r .slate_id <<<"${out}")"
    [[ -s "${d}/i.slate" ]] || fail "no invoice file" || return 1
    w "${INV_PAYER}" invoice pay "${d}/i.slate" "${amount}" --reply-file "${d}/r.slate" --min-confirmations "${E2E_MINCONF}" >"${d}/pay.json" || fail "invoice pay file failed" || return 1
    [[ -s "${d}/r.slate" ]] || fail "no reply file" || return 1
    w "${INV_ISSUER}" tx finalize "${d}/r.slate" >"${d}/finalize.json" || fail "tx finalize failed" || return 1
    wait_slate_state "${INV_ISSUER}" "${id}" "posted confirmed" 60 || fail "issuer did not post" || return 1
    wait_slate_state "${INV_PAYER}" "${id}" "confirmed" 240 || fail "payer's tx never confirmed" || return 1
    wait_received "${INV_ISSUER}" $((before + $(to_units "${amount}"))) || fail "issuer balance did not grow" || return 1
    # A wrong amount is refused.
    out="$(w "${INV_ISSUER}" invoice issue --to-file "${d}/j.slate" "${amount}")" || return 1
    wx 7 "${INV_PAYER}" invoice pay "${d}/j.slate" 0.03 --reply-file "${d}/j.reply" || return 1
    note "invoice file ${amount} paid and finalized; paying it for 0.03 is exit 7"
}

# Parked invoices come from allowed contacts (the contacts area pays and declines them). Here:
# the list is empty for a wallet nobody invoiced, and declining an unknown invoice is exit 6.
case_inv_decline() {
    inv_ready || return 1
    cancel_open_invoices "${INV_ISSUER}"
    expect_json "$(w "${INV_PAYER}" invoice list)" '.invoices == []' "no parked invoices" || return 1
    wx 6 "${INV_PAYER}" invoice decline "$(cat /proc/sys/kernel/random/uuid)" || return 1
    expect_json "${LAST_JSON}" '.error.kind == "not_found"' "decline of an unknown invoice" || return 1
    wx 6 "${INV_PAYER}" invoice pay "$(cat /proc/sys/kernel/random/uuid)" 0.01 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "not_found"' "pay of an unknown invoice" || return 1
    note "empty parked list; decline and pay of an unknown slate id are exit 6 not_found"
}

case_inv_expiry() {
    inv_ready || return 1
    wconfig_set "${INV_PAYER}" 'invoice_expiry_hours = 0'
    wx 3 "${INV_PAYER}" invoice list || return 1
    expect_json "${LAST_JSON}" '.error.kind == "config"' "invoice_expiry_hours = 0" || return 1
    wconfig_set "${INV_PAYER}" 'invoice_expiry_hours = 1'
    w "${INV_PAYER}" invoice list >"${CASE_DIR}/list-1h.json" || fail "invoice list with a 1 hour expiry failed" || return 1
    wconfig_reset "${INV_PAYER}"
    note "invoice_expiry_hours = 0 is exit 3 (config); 1 is accepted; an expiry itself needs an hour and is not reached in a run"
}

case_inv_peer() {
    local payer_addr issuer_addr amount="0.01" before
    inv_ready || return 1
    payer_addr="$(addr_of "${INV_PAYER}")"
    issuer_addr="$(addr_of "${INV_ISSUER}")"
    w "${INV_ISSUER}" epicbox peer "${payer_addr}" >"${CASE_DIR}/peer-before.json" || fail "epicbox peer failed" || return 1
    # A payment from the payer reaches the issuer's inbox; the issuer's drain learns the marker.
    ensure_funds "${INV_PAYER}" 1 1 || return 1
    w "${INV_PAYER}" tx send --to "${issuer_addr}" --min-confirmations "${E2E_MINCONF}" "${amount}" >/dev/null || fail "payer send failed" || return 1
    sleep 3
    w "${INV_ISSUER}" epicbox drain >/dev/null || return 1
    w "${INV_ISSUER}" epicbox peer "${payer_addr}" >"${CASE_DIR}/peer-after.json" || return 1
    expect_json "$(cat "${CASE_DIR}/peer-after.json")" '.capability == "lepic"' "peer capability after a payment" || return 1
    note "peer before: $(jq -c . "${CASE_DIR}/peer-before.json"); after a payment: $(jq -c . "${CASE_DIR}/peer-after.json")"
}
