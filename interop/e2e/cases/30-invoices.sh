# shellcheck shell=bash
# Invoices: asking for a payment through slate files; the payer pays.

CASES+=("inv.file|case_inv_file|crates/lepic-wallet crates/lepic-cli crates/lepic-slate")
CASES+=("inv.expiry|case_inv_expiry|crates/lepic-wallet crates/lepic-cli")

INV_ISSUER="${E2E_PREFIX}-inv-issuer"
INV_PAYER="${E2E_PREFIX}-inv-payer"

inv_ready() {
    ensure_wallet "${INV_ISSUER}" || return 1
    ensure_wallet "${INV_PAYER}" || return 1
    wconfig_reset "${INV_ISSUER}"
    wconfig_reset "${INV_PAYER}"
    ensure_funds "${INV_PAYER}" 2 3 || fail "could not fund ${INV_PAYER}" || return 1
}

case_inv_file() {
    local amount="0.02" before out id d="${CASE_DIR}"
    inv_ready || return 1
    before="$(balance_units "${INV_ISSUER}")" || return 1
    out="$(w "${INV_ISSUER}" invoice issue --to-file "${d}/i.slate" "${amount}")" || fail "invoice issue --to-file failed" || return 1
    id="$(jq -r .slate_id <<<"${out}")"
    [[ -s "${d}/i.slate" ]] || fail "no invoice file" || return 1
    w "${INV_PAYER}" invoice pay "${d}/i.slate" "${amount}" --reply-file "${d}/r.slate" --min-confirmations "${E2E_MINCONF}" --yes >"${d}/pay.json" || fail "invoice pay file failed" || return 1
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
