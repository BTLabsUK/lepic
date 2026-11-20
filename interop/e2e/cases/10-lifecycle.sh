# shellcheck shell=bash
# Wallet lifecycle: create, address, info and refresh, restore from the phrase with and without a
# scan, the outputs list.

CASES+=("life.create|case_life_create|crates/lepic-cli crates/lepic-wallet crates/lepic-keychain crates/lepic-store")
CASES+=("life.restore|case_life_restore|crates/lepic-cli crates/lepic-wallet crates/lepic-keychain crates/lepic-node")
CASES+=("life.restore-no-scan|case_life_restore_no_scan|crates/lepic-cli crates/lepic-wallet crates/lepic-node")
CASES+=("life.outputs|case_life_outputs|crates/lepic-cli crates/lepic-wallet")

LIFE_FUNDED="${E2E_PREFIX}-life-funded"

case_life_create() {
    local name="${E2E_PREFIX}-life-new" out phrase info
    # A new wallet every run: this directory is the suite's own.
    rm -rf "$(wdir "${name}")"
    out="$(w "${name}" wallet init --words 24)" || fail "wallet init failed" || return 1
    phrase="$(jq -r .recovery_phrase <<<"${out}")"
    expect_eq "$(wc -w <<<"${phrase}")" 24 "phrase words" || return 1
    expect_eq "$(jq -r .network <<<"${out}")" floonet "network" || return 1
    # A second init on the same data dir is refused as wallet state, and keeps the wallet.
    wx 5 "${name}" wallet init || return 1
    expect_json "${LAST_JSON}" '.error.kind == "wallet_state"' "second init refused" || return 1
    info="$(w "${name}" wallet info)" || fail "wallet info failed" || return 1
    expect_json "${info}" '.accounts[0].total == "0.00000000" and .catching_up == false and .node_behind == false' "new wallet info" || return 1
    expect_match "$(w "${name}" wallet address | jq -r .address)" "^zz[1-9A-HJ-NP-Za-km-z]+@${E2E_RELAY}$" "epicbox address" || return 1
    expect_match "$(w "${name}" epic1 address | jq -r .address)" '^tepic1[02-9ac-hj-np-z]+$' "epic1 address" || return 1
    note "24-word wallet at height $(jq -r .height <<<"${info}")"
}

case_life_restore() {
    local name="${E2E_PREFIX}-life-restored" phrase want got
    ensure_wallet "${LIFE_FUNDED}" || return 1
    ensure_funds "${LIFE_FUNDED}" 1 1 || fail "could not fund ${LIFE_FUNDED}" || return 1
    phrase="$(jq -r .recovery_phrase "${E2E_STATE}/wallets/${LIFE_FUNDED}.init.json")"
    want="$(balance "${LIFE_FUNDED}" total)"
    rm -rf "$(wdir "${name}")"
    w "${name}" wallet restore <<<"${phrase}" >"${CASE_DIR}/restore.json" || fail "wallet restore failed" || return 1
    got="$(balance "${name}" total)"
    expect_eq "${got}" "${want}" "restored total" || return 1
    expect_eq "$(w "${name}" wallet address | jq -r .address)" "$(w "${LIFE_FUNDED}" wallet address | jq -r .address)" "address after restore" || return 1
    expect_eq "$(w "${name}" epic1 address | jq -r .address)" "$(w "${LIFE_FUNDED}" epic1 address | jq -r .address)" "epic1 address after restore" || return 1
    note "restored total ${got}"
}

case_life_restore_no_scan() {
    local name="${E2E_PREFIX}-life-restored-ns" phrase want
    ensure_wallet "${LIFE_FUNDED}" || return 1
    ensure_funds "${LIFE_FUNDED}" 1 1 || return 1
    phrase="$(jq -r .recovery_phrase "${E2E_STATE}/wallets/${LIFE_FUNDED}.init.json")"
    want="$(balance "${LIFE_FUNDED}" total)"
    rm -rf "$(wdir "${name}")"
    w "${name}" wallet restore --no-scan <<<"${phrase}" >/dev/null || fail "wallet restore --no-scan failed" || return 1
    w "${name}" wallet scan --start-height 0 >"${CASE_DIR}/scan.json" || fail "wallet scan failed" || return 1
    expect_eq "$(balance "${name}" total)" "${want}" "total after scan" || return 1
    note "scan found ${want}"
}

case_life_outputs() {
    local out
    ensure_wallet "${LIFE_FUNDED}" || return 1
    ensure_funds "${LIFE_FUNDED}" 1 1 || return 1
    out="$(w "${LIFE_FUNDED}" wallet outputs)" || fail "wallet outputs failed" || return 1
    printf '%s\n' "${out}" >"${CASE_DIR}/outputs.json"
    expect_json "${out}" '[.. | objects | select(has("commit") or has("commitment"))] | length > 0' "outputs listed" || return 1
    note "$(jq '[.. | objects | select(has("commit") or has("commitment"))] | length' <<<"${out}") outputs"
}
