# shellcheck shell=bash
# Sealed text and files between paired contacts: seal/open-sealed for S1, S2, I1 and I2,
# send-slate through the mailbox, plain slates and the .epictx opener. Uses the helpers and the
# wallets of 60-pairing.sh (alice, bob, shop); every case pairs afresh.

SEAL_PATHS="crates/lepic-cli crates/lepic-seal crates/lepic-contact crates/lepic-wallet"

CASES+=("seal.text|case_seal_text|${SEAL_PATHS}")
CASES+=("seal.send-slate|case_seal_send_slate|${SEAL_PATHS}")
CASES+=("seal.plain|case_seal_plain|${SEAL_PATHS}")
CASES+=("seal.file|case_seal_file|${SEAL_PATHS}")

# Alice starts a file send of $1 EPIC; sets SEAL_TX (her tx id) and SEAL_SLATE.
seal_s1() {
    local out
    out="$(w "${CT_ALICE}" tx send --to-file "${CASE_DIR}/s1.slate" --min-confirmations "${E2E_MINCONF}" "$1")" || fail "tx send --to-file failed" || return 1
    SEAL_TX="$(jq -r .tx_id <<<"${out}")"
    SEAL_SLATE="$(jq -r .slate_id <<<"${out}")"
    [[ "${SEAL_TX}" != null && "${SEAL_SLATE}" != null ]] || fail "no tx id in: ${out}" || return 1
}
seal_ready() {
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_fund "${CT_ALICE}" || return 1
    ct_fresh "${CT_ALICE}" "${CT_BOB}"
}

case_seal_text() {
    local f="${CASE_DIR}/s1.epictx" r="${CASE_DIR}/s2.epictx" out
    seal_ready || return 1
    seal_s1 0.01 || return 1
    w "${CT_ALICE}" contact seal "${CT_A}" "${SEAL_TX}" --purpose payment --out "${f}" >"${CASE_DIR}/seal.json" || fail "contact seal failed" || return 1
    [[ -s "${f}" ]] || fail "no sealed file" || return 1
    # The sealed text is opaque: the slate id is not in it.
    ! grep -q "${SEAL_SLATE}" "${f}" || fail "the sealed file shows the slate id" || return 1
    out="$(w "${CT_BOB}" contact open-sealed "${f}" --answer-file "${r}")" || fail "bob's open-sealed (S1) failed" || return 1
    echo "${out}" >"${CASE_DIR}/open1.json"
    [[ -s "${r}" ]] || fail "no sealed answer written" || return 1
    out="$(w "${CT_ALICE}" contact open-sealed "${r}")" || fail "alice's open-sealed (S2) failed" || return 1
    echo "${out}" >"${CASE_DIR}/open2.json"
    ct_wait "alice's payment ${SEAL_SLATE} finalized" 120 "${CT_ALICE},${CT_BOB}" ct_tx_done "${CT_ALICE}" "${SEAL_SLATE}" || return 1
    note "S1 sealed to bob, S2 sealed back, alice finalized (${SEAL_SLATE})"
}

case_seal_send_slate() {
    seal_ready || return 1
    seal_s1 0.01 || return 1
    w "${CT_ALICE}" contact send-slate "${CT_A}" "${SEAL_TX}" --purpose payment >"${CASE_DIR}/send-slate.json" || fail "contact send-slate failed" || return 1
    ct_wait "alice's payment ${SEAL_SLATE} finalized" 120 "${CT_ALICE},${CT_BOB}" ct_tx_done "${CT_ALICE}" "${SEAL_SLATE}" || return 1
    ct_wait "bob holds the slate" 60 "${CT_ALICE},${CT_BOB}" ct_bob_has_slate "${CT_BOB}" "${SEAL_SLATE}" || return 1
    note "slate sent sealed through the mailbox, finalized (${SEAL_SLATE})"
}

case_seal_plain() {
    local f="${CASE_DIR}/plain.slate" r="${CASE_DIR}/reply.slate" out
    seal_ready || return 1
    seal_s1 0.01 || return 1
    w "${CT_ALICE}" contact plain "${SEAL_TX}" --out "${f}" >"${CASE_DIR}/plain.json" || fail "contact plain failed" || return 1
    [[ -s "${f}" ]] || fail "no plain file" || return 1
    expect_json "$(cat "${f}")" '.id != null or .version_info != null or .slate != null' "plain slate is readable JSON" || return 1
    out="$(w "${CT_BOB}" tx receive "${f}" --reply-file "${r}")" || fail "bob's tx receive of the plain slate failed" || return 1
    echo "${out}" >"${CASE_DIR}/receive.json"
    out="$(w "${CT_ALICE}" tx finalize "${r}")" || fail "tx finalize failed" || return 1
    expect_json "${out}" '.state == "posted" or .state == "finalized"' "finalize result" || return 1
    note "plain slate received and finalized (${SEAL_SLATE})"
}

case_seal_file() {
    local f="${CASE_DIR}/s1.epictx" st=0 inv ioid islate i1="${CASE_DIR}/i1.epictx" i2="${CASE_DIR}/i2.epictx" out
    seal_ready || return 1
    ct_wallets "${CT_SHOP}" || return 1
    # epictx open: the right wallet reads it, the wrong one is refused.
    seal_s1 0.01 || return 1
    w "${CT_ALICE}" contact seal "${CT_A}" "${SEAL_TX}" --out "${f}" >/dev/null || fail "contact seal failed" || return 1
    out="$(w "${CT_BOB}" epictx open "${f}")" || fail "bob could not open the .epictx" || return 1
    echo "${out}" >"${CASE_DIR}/epictx-bob.json"
    expect_json "${out}" '(.id // .slate.id // .slate_id // "") != ""' "epictx open prints the slate" || return 1
    lepic_env "${CT_SHOP}" --output json epictx open "${f}" >"${CASE_DIR}/epictx-shop.out" 2>&1 || st=$?
    echo "shop exit=${st}" >"${CASE_DIR}/epictx-shop.exit"
    [[ "${st}" == 7 ]] || fail "the wrong wallet's epictx open exited ${st}, wanted 7 (rejected): $(head -c 300 "${CASE_DIR}/epictx-shop.out")" || return 1
    # Invoice both ways: bob issues I1, alice pays it with --amount, bob finalizes the I2.
    inv="$(w "${CT_BOB}" invoice issue --to-file "${CASE_DIR}/i.slate" 0.01)" || fail "invoice issue failed" || return 1
    ioid="$(jq -r .tx_id <<<"${inv}")"
    islate="$(jq -r .slate_id <<<"${inv}")"
    w "${CT_BOB}" contact seal "${CT_B}" "${ioid}" --purpose payment --out "${i1}" >/dev/null || fail "seal of the invoice failed" || return 1
    out="$(lepic_try "${CT_ALICE}" contact open-sealed "${i1}" --answer-file "${i2}")"
    echo "${out}" >"${CASE_DIR}/i1-no-amount.txt"
    # Without --amount alice must not pay: no answer file.
    [[ ! -s "${i2}" ]] || fail "an invoice was answered without --amount" || return 1
    out="$(w "${CT_ALICE}" contact open-sealed "${i1}" --amount 0.01 --min-confirmations "${E2E_MINCONF}" --answer-file "${i2}")" || fail "alice's open-sealed --amount failed" || return 1
    echo "${out}" >"${CASE_DIR}/i1-amount.json"
    [[ -s "${i2}" ]] || fail "no sealed I2 answer" || return 1
    out="$(w "${CT_BOB}" contact open-sealed "${i2}")" || fail "bob's open-sealed (I2) failed" || return 1
    echo "${out}" >"${CASE_DIR}/i2.json"
    ct_wait "bob's invoice ${islate} finalized" 120 "${CT_ALICE},${CT_BOB}" ct_tx_done "${CT_BOB}" "${islate}" || return 1
    note "epictx open: bob read it, ${CT_SHOP} refused (exit ${st}); I1 paid with --amount, I2 finalized (${islate})"
}
