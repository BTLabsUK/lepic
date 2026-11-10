# shellcheck shell=bash
# Pairing and contacts: invite, pairing words, cards, by hand, requests, labels, backup, key
# check, check, relay moves, payments, invoices, payloads, profiles and offline contacts.
# Wallets e1s-ct-*: pairings persist in them, so every case clears the contacts of its own wallets
# first (they are the suite's own) and pairs again.

CT_PATHS="crates/lepic-cli crates/lepic-contact crates/lepic-seal crates/lepic-wallet-contacts"

CASES+=("pair.invite|case_pair_invite|${CT_PATHS}")
CASES+=("pair.words|case_pair_words|${CT_PATHS}")
CASES+=("pair.card|case_pair_card|${CT_PATHS}")
CASES+=("pair.by-hand|case_pair_by_hand|${CT_PATHS}")
CASES+=("pair.request|case_pair_request|${CT_PATHS} crates/lepic-wallet")
CASES+=("ct.manage|case_ct_manage|${CT_PATHS}")
CASES+=("ct.export-import|case_ct_export_import|${CT_PATHS} crates/lepic-wallet crates/lepic-store")
CASES+=("ct.key-check|case_ct_key_check|${CT_PATHS}")
CASES+=("ct.check|case_ct_check|${CT_PATHS}")
CASES+=("ct.move|case_ct_move|${CT_PATHS}")
CASES+=("ct.pay|case_ct_pay|${CT_PATHS} crates/lepic-wallet")
CASES+=("ct.invoices|case_ct_invoices|${CT_PATHS} crates/lepic-wallet")
CASES+=("ct.payload|case_ct_payload|${CT_PATHS}")
CASES+=("ct.profile|case_ct_profile|${CT_PATHS}")
CASES+=("ct.offline|case_ct_offline|${CT_PATHS} crates/lepic-wallet")

CT_ALICE="${E2E_PREFIX}-ct-alice"
CT_BOB="${E2E_PREFIX}-ct-bob"
CT_SHOP="${E2E_PREFIX}-ct-shop"
CT_REQUEST_ID="${E2E_STATE}/ct-request.id"   # alice's live pair request, withdrawn by the next run
CT_KEEP="${E2E_PREFIX}-ct-keep"   # created by the suite, so its phrase is on file for restores

# Helpers ------------------------------------------------------------------------------------

# Creates the wallets of this area once.
ct_wallets() {
    local n
    for n in "$@"; do ensure_wallet "${n}" || fail "could not create ${n}" || return 1; done
}

# Removes every pairing of a wallet; the contacts are the suite's own.
ct_reset() {
    local n="$1" id ids
    ids="$(w "${n}" contact list | jq -r '.contacts[].contact_id')" || fail "contact list on ${n} failed" || return 1
    for id in ${ids}; do
        w "${n}" contact remove "${id}" >/dev/null || fail "contact remove ${id} on ${n} failed" || return 1
    done
}

# `ct_state <wallet> <contact> <field>`
ct_field() { w "$1" contact list | jq -r --arg id "$2" --arg f "$3" '.contacts[] | select(.contact_id == $id) | .[$f] // empty'; }
ct_state_is() { [[ "$(ct_field "$1" "$2" state)" == "$3" ]]; }
ct_state_in() { [[ " $3 " == *" $(ct_field "$1" "$2" state) "* ]]; }

# Runs `contact collect` on each wallet (a comma list) every few seconds until the command
# succeeds or the time is out.
ct_wait() {
    local what="$1" timeout="$2" wallets="$3" end n
    shift 3
    end=$((SECONDS + timeout))
    while :; do
        if "$@"; then return 0; fi
        ((SECONDS >= end)) && { fail "timed out after ${timeout}s waiting for ${what}"; return 1; }
        for n in ${wallets//,/ }; do w "${n}" contact collect >/dev/null 2>&1 || true; done
        sleep 2
    done
}

# Pairs A (the inviter) with B online, sas matched on both sides. Sets CT_A (A's id of B) and
# CT_B (B's id of A). Both wallets must have no pairing with each other already.
ct_pair() {
    local a="$1" b="$2" nameA="${3:-Alice}" nameB="${4:-Bob}" out link wa wb
    out="$(w "${a}" contact invite --name "${nameA}")" || fail "contact invite failed" || return 1
    CT_A="$(jq -r .contact_id <<<"${out}")"
    link="$(jq -r .link <<<"${out}")"
    out="$(w "${b}" contact accept "${link}" --name "${nameB}")" || fail "contact accept failed" || return 1
    CT_B="$(jq -r .contact_id <<<"${out}")"
    ct_wait "${a} and ${b} paired" 90 "${a},${b}" ct_both_state_in "${a}" "${CT_A}" "${b}" "${CT_B}" "paired verified" || return 1
    wa="$(w "${a}" contact list | jq -c --arg id "${CT_A}" '.contacts[] | select(.contact_id == $id) | .sas')"
    wb="$(w "${b}" contact list | jq -c --arg id "${CT_B}" '.contacts[] | select(.contact_id == $id) | .sas')"
    expect_eq "${wa}" "${wb}" "SAS words on both sides" || return 1
    expect_json "${wa}" 'length == 4' "four SAS words" || return 1
    w "${a}" contact sas "${CT_A}" match >/dev/null || fail "sas match on ${a} failed" || return 1
    w "${b}" contact sas "${CT_B}" match >/dev/null || fail "sas match on ${b} failed" || return 1
    ct_wait "both sides verified" 60 "${a},${b}" ct_both_state_in "${a}" "${CT_A}" "${b}" "${CT_B}" "verified" || return 1
}

ct_both_state_in() {
    local sa sb
    sa="$(ct_field "$1" "$2" state)"
    sb="$(ct_field "$3" "$4" state)"
    [[ " $5 " == *" ${sa} "* && " $5 " == *" ${sb} "* ]]
}

# Funds the wallets that pay in a case; a few EPIC each, from the bank.
ct_fund() {
    local n
    for n in "$@"; do
        ensure_funds "${n}" 3 2 || fail "could not fund ${n}" || return 1
    done
}

# The newest transaction of a wallet: prints its JSON.
ct_last_tx() { w "$1" tx list | jq -c '[.transactions[]] | sort_by(.id) | last'; }

# Pair cases ---------------------------------------------------------------------------------

case_pair_invite() {
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_reset "${CT_ALICE}" || return 1
    ct_reset "${CT_BOB}" || return 1
    ct_pair "${CT_ALICE}" "${CT_BOB}" Alice Bob || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" claimed_name)" Bob "Alice's name for Bob" || return 1
    expect_eq "$(ct_field "${CT_BOB}" "${CT_B}" claimed_name)" Alice "Bob's name for Alice" || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" home_relay | sed 's/:443$//')" "${E2E_RELAY}" "home relay" || return 1
    note "verified on both sides; SAS $(w "${CT_ALICE}" contact list | jq -c '.contacts[0].sas')"
}

case_pair_words() {
    local out words link acc
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_reset "${CT_ALICE}" || return 1
    ct_reset "${CT_BOB}" || return 1
    out="$(w "${CT_ALICE}" contact invite --name Alice --pairing-words)" || fail "invite --pairing-words failed" || return 1
    CT_A="$(jq -r .contact_id <<<"${out}")"
    expect_json "${out}" '.words | length == 5' "five pairing words" || return 1
    # The words as the user types them: the names without the emoji.
    words="$(jq -r '.words[] | sub("^[^ ]+ "; "")' <<<"${out}" | tr '\n' ' ')"
    out="$(w "${CT_BOB}" contact enter ${words})" || fail "contact enter of the words failed" || return 1
    expect_json "${out}" '.outcome == "invite"' "words found an invite" || return 1
    link="$(jq -r .link <<<"${out}")"
    expect_match "${link}" '^epiccash://pair/1/' "invite link found by the words" || return 1
    acc="$(w "${CT_BOB}" contact accept "${link}" --name Bob)" || fail "accept of the found invite failed" || return 1
    CT_B="$(jq -r .contact_id <<<"${acc}")"
    ct_wait "paired through the words" 90 "${CT_ALICE},${CT_BOB}" ct_both_state_in "${CT_ALICE}" "${CT_A}" "${CT_BOB}" "${CT_B}" "paired" || return 1
    # Wrong words are refused with a usage error.
    wx 2 "${CT_BOB}" contact enter one two three four five || return 1
    note "invite found by five words, paired"
}

case_pair_card() {
    local ca cb
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_reset "${CT_ALICE}" || return 1
    ct_reset "${CT_BOB}" || return 1
    ca="$(w "${CT_ALICE}" contact show-card --name Alice)" || fail "show-card on alice failed" || return 1
    cb="$(w "${CT_BOB}" contact show-card --name Bob)" || fail "show-card on bob failed" || return 1
    expect_match "$(jq -r .link <<<"${ca}")" '^epiccash://contact/1/' "card link" || return 1
    CT_A="$(jq -r .contact_id <<<"${ca}")"
    CT_B="$(jq -r .contact_id <<<"${cb}")"
    # In person nothing goes through a relay: each scans the other's card.
    w "${CT_ALICE}" contact scan-card "${CT_A}" "$(jq -r .link <<<"${cb}")" >/dev/null || fail "alice scan-card failed" || return 1
    w "${CT_BOB}" contact scan-card "${CT_B}" "$(jq -r .link <<<"${ca}")" >/dev/null || fail "bob scan-card failed" || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" claimed_name)" Bob "name on alice's card of bob" || return 1
    expect_eq "$(ct_field "${CT_BOB}" "${CT_B}" claimed_name)" Alice "name on bob's card of alice" || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" sas)" "$(ct_field "${CT_BOB}" "${CT_B}" sas)" "in-person SAS words" || return 1
    w "${CT_ALICE}" contact sas "${CT_A}" match >/dev/null || fail "sas on alice failed" || return 1
    w "${CT_BOB}" contact sas "${CT_B}" match >/dev/null || fail "sas on bob failed" || return 1
    ct_wait "cards trade and both verified" 90 "${CT_ALICE},${CT_BOB}" ct_both_state_in "${CT_ALICE}" "${CT_A}" "${CT_BOB}" "${CT_B}" "verified" || return 1
    note "in-person pairing verified"
}

case_pair_by_hand() {
    local out link reply conf
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_reset "${CT_ALICE}" || return 1
    ct_reset "${CT_BOB}" || return 1
    out="$(w "${CT_ALICE}" contact invite --name Alice)" || fail "invite failed" || return 1
    CT_A="$(jq -r .contact_id <<<"${out}")"
    link="$(jq -r .link <<<"${out}")"
    out="$(w "${CT_BOB}" contact accept "${link}" --name Bob --by-hand)" || fail "accept --by-hand failed" || return 1
    expect_json "${out}" '.posted == false' "by-hand reply not posted" || return 1
    CT_B="$(jq -r .contact_id <<<"${out}")"
    reply="$(jq -r .reply_link <<<"${out}")"
    expect_match "${reply}" '^epiccash://pair-reply/1/' "reply link" || return 1
    out="$(w "${CT_ALICE}" contact enter "${reply}")" || fail "enter of the reply failed" || return 1
    expect_json "${out}" '.outcome == "confirm"' "reply answered with a confirm" || return 1
    conf="$(jq -r .link <<<"${out}")"
    expect_match "${conf}" '^epiccash://pair-confirm/1/' "confirm link" || return 1
    CT_A="$(jq -r .contact_id <<<"${out}")"
    out="$(w "${CT_BOB}" contact enter "${conf}")" || fail "enter of the confirm failed" || return 1
    expect_json "${out}" '.outcome == "paired"' "confirm paired" || return 1
    expect_eq "$(ct_field "${CT_BOB}" "${CT_B}" state)" paired "bob's state" || return 1
    ct_wait "alice paired" 30 "${CT_ALICE}" ct_state_is "${CT_ALICE}" "${CT_A}" paired || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" sas)" "$(ct_field "${CT_BOB}" "${CT_B}" sas)" "SAS words" || return 1
    note "paired with two links sent by hand"
}

case_pair_request() {
    local out link tx
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_fund "${CT_ALICE}" || return 1
    ct_reset "${CT_ALICE}" || return 1
    ct_reset "${CT_BOB}" || return 1
    # A request a stopped run left would refuse the next one (in progress): `contact list` shows
    # it under sent_requests, and request-cancel withdraws it.
    local stale
    for stale in $(w "${CT_ALICE}" contact list | jq -r '.sent_requests[].contact_id'); do
        w "${CT_ALICE}" contact request-cancel "${stale}" >/dev/null || fail "could not withdraw the old request ${stale}" || return 1
    done
    rm -f "${CT_REQUEST_ID}"
    # Alice pays Bob's payments address, so Bob is a wallet that was paid lately.
    local addr
    addr="$(w_addr "${CT_BOB}")" || fail "wallet address failed" || return 1
    epicbox_listen "${CT_BOB}" || fail "bob's listener did not start" || return 1
    w "${CT_ALICE}" tx send --to "${addr}" --min-confirmations "${E2E_MINCONF}" 0.01 >"${CASE_DIR}/send.json" || fail "payment to bob failed" || return 1
    sleep 15
    wstop "${EPICBOX_PID}"
    grep -q "Received [1-9]" "${BG_LOG}.out" || fail "bob never received the payment: $(tail -c 300 "${BG_LOG}.out")" || return 1
    # Alice takes bob's answer, which carries his claim to take pairing requests.
    epicbox_listen "${CT_ALICE}" || fail "alice's listener did not start" || return 1
    sleep 15
    wstop "${EPICBOX_PID}"
    grep -q "finalized [1-9]" "${BG_LOG}.out" || fail "alice never finalized the payment: $(tail -c 300 "${BG_LOG}.out")" || return 1
    out="$(w "${CT_ALICE}" contact request "${addr}" --name Alice)" || fail "contact request failed" || return 1
    CT_A="$(jq -r .contact_id <<<"${out}")"
    echo "${CT_A}" >"${CT_REQUEST_ID}"
    echo "${out}" >"${CASE_DIR}/request.json"
    expect_match "$(jq -r .link <<<"${out}")" '^epiccash://pair/1/' "request link" || return 1
    expect_json "$(w "${CT_ALICE}" contact list)" ".sent_requests | length == 1 and .[0].contact_id == \"${CT_A}\"" "alice lists the request she sent" || return 1
    wx 7 "${CT_ALICE}" contact request "${addr}" || return 1
    expect_json "${LAST_JSON}" '.error.kind == "rejected"' "a second request is refused while the first waits" || return 1
    # Bob's wallet takes the request from its payments inbox and keeps it for its user.
    wait_until "bob takes the request" 90 ct_took_notice "${CT_BOB}" || return 1
    out="$(w "${CT_BOB}" contact requests)" || fail "contact requests failed" || return 1
    echo "${out}" >"${CASE_DIR}/requests.json"
    expect_json "${out}" '.requests | length == 1 and (.[0].invite_link | startswith("epiccash://pair/")) and .[0].claimed_name == "Alice"' "bob lists the request" || return 1
    link="$(jq -r '.requests[0].request_id' <<<"${out}")"
    expect_json "$(w "${CT_BOB}" contact request-dismiss "${link}")" '.dismissed == true' "bob dismisses the request" || return 1
    expect_json "$(w "${CT_BOB}" contact requests)" '.requests | length == 0' "bob has no request left" || return 1
    wx 6 "${CT_BOB}" contact request-dismiss "${link}" || return 1
    expect_json "$(w "${CT_ALICE}" contact request-cancel "${CT_A}")" '.cancelled == true' "alice withdraws her request" || return 1
    expect_json "$(w "${CT_ALICE}" contact list)" '.sent_requests | length == 0' "alice lists no request" || return 1
    wx 6 "${CT_ALICE}" contact request-cancel "${CT_A}" || return 1
}

# Drains a wallet's payments inbox; true once it took at least one notice.
ct_took_notice() { (($(w "$1" epicbox drain | jq '.notices // 0') > 0)); }

w_addr() { w "$1" wallet address | jq -r .address; }
ct_has_contacts() { (($(w "$1" contact list | jq '.contacts | length') >= $2)); }

# Contact cases ------------------------------------------------------------------------------

# A fresh verified pairing between two wallets, both cleared first.
ct_fresh() {
    ct_wallets "$1" "$2" || return 1
    ct_reset "$1" || return 1
    ct_reset "$2" || return 1
    ct_pair "$1" "$2" "${3:-Alice}" "${4:-Bob}"
}

case_ct_manage() {
    local list
    ct_fresh "${CT_ALICE}" "${CT_BOB}" || return 1
    w "${CT_ALICE}" contact label "${CT_A}" "Bob at the bar" >/dev/null || fail "contact label failed" || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" label)" "Bob at the bar" "label" || return 1
    expect_eq "$(ct_field "${CT_ALICE}" "${CT_A}" claimed_name)" Bob "claimed name is kept next to the label" || return 1
    list="$(w "${CT_ALICE}" contact list)" || fail "contact list failed" || return 1
    expect_json "${list}" '.contacts | length == 1' "one contact" || return 1
    # Removing is local: the other side is not told.
    w "${CT_ALICE}" contact remove "${CT_A}" >/dev/null || fail "contact remove failed" || return 1
    expect_json "$(w "${CT_ALICE}" contact list)" '.contacts | length == 0' "alice has no contact after remove" || return 1
    w "${CT_ALICE}" contact collect >/dev/null || fail "collect after remove failed" || return 1
    w "${CT_BOB}" contact collect >/dev/null || fail "collect on bob failed" || return 1
    expect_eq "$(ct_field "${CT_BOB}" "${CT_B}" state)" verified "bob still holds the pairing (not told)" || return 1
    # Removing an unknown contact is not found.
    wx 6 "${CT_ALICE}" contact remove 00000000000000000000000000000000 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "not_found"' "remove of an unknown contact" || return 1
    # Pair again; bob clears its stale record first so only the new pairing exists.
    w "${CT_BOB}" contact remove "${CT_B}" >/dev/null || fail "bob remove failed" || return 1
    ct_pair "${CT_ALICE}" "${CT_BOB}" Alice Bob || return 1
    note "label, local remove (bob not told), re-paired"
}

# Pays `to_id` from `from` through the mailbox and drives both until the sender's transaction is
# finalized or posted. Prints nothing; sets CT_SLATE.
ct_pay() {
    local from="$1" to="$2" cid="$3" amount="$4" out
    out="$(w "${from}" tx send --to-contact "${cid}" --min-confirmations "${E2E_MINCONF}" "${amount}")" || fail "tx send --to-contact failed" || return 1
    printf '%s\n' "${out}" >>"${CASE_DIR}/pay.json"
    CT_SLATE="$(jq -r '.slate_id' <<<"${out}")"
    [[ "${CT_SLATE}" != null && -n "${CT_SLATE}" ]] || fail "no slate id in the send: ${out}" || return 1
    ct_wait "payment ${CT_SLATE} finalized" 120 "${from},${to}" ct_tx_done "${from}" "${CT_SLATE}" || return 1
}
ct_tx_done() { slate_state_in "$1" "$2" "posted confirmed finalized"; }

case_ct_pay() {
    local before after
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_fund "${CT_ALICE}" || return 1
    ct_fresh "${CT_ALICE}" "${CT_BOB}" || return 1
    before="$(balance_units "${CT_BOB}" total)"
    ct_pay "${CT_ALICE}" "${CT_BOB}" "${CT_A}" 0.01 || return 1
    ct_wait "bob sees the payment" 90 "${CT_ALICE},${CT_BOB}" ct_bob_has_slate "${CT_BOB}" "${CT_SLATE}" || return 1
    note "paid 0.01 through the mailboxes, slate ${CT_SLATE}, alice tx $(tx_by_slate "${CT_ALICE}" "${CT_SLATE}" | jq -r .state)"
}
ct_bob_has_slate() { [[ -n "$(tx_by_slate "$1" "$2")" ]]; }

case_ct_check() {
    local before after
    ct_fresh "${CT_ALICE}" "${CT_BOB}" || return 1
    # Let the pairing's own traffic settle first, so `before` is the time of the last of it.
    ct_wait "alice has heard bob" 60 "${CT_ALICE},${CT_BOB}" ct_has_heard "${CT_ALICE}" "${CT_A}" || return 1
    w "${CT_ALICE}" contact collect >/dev/null; w "${CT_BOB}" contact collect >/dev/null
    before="$(ct_field "${CT_ALICE}" "${CT_A}" last_heard)"
    [[ -n "${before}" ]] || fail "last_heard is empty before the check" || return 1
    sleep 2
    w "${CT_ALICE}" contact check "${CT_A}" >/dev/null || fail "contact check failed" || return 1
    # Bob takes the check and answers with its card; alice takes the answer.
    ct_wait "alice heard bob's answer" 90 "${CT_BOB},${CT_ALICE}" ct_heard_after "${CT_ALICE}" "${CT_A}" "${before}" || return 1
    after="$(ct_field "${CT_ALICE}" "${CT_A}" last_heard)"
    note "check answered: last_heard ${before} -> ${after}"
}
ct_has_heard() { [[ -n "$(ct_field "$1" "$2" last_heard)" ]]; }
ct_heard_after() {
    local now
    now="$(ct_field "$1" "$2" last_heard)"
    [[ -n "${now}" && "${now}" > "$3" ]]
}

case_ct_invoices() {
    local out id list
    ct_wallets "${CT_SHOP}" "${CT_BOB}" || return 1
    ct_fund "${CT_BOB}" || return 1
    ct_fresh "${CT_SHOP}" "${CT_BOB}" Shop Bob || return 1
    # Bob has not allowed invoices: the shop's invoice must not park (assert what happens).
    out="$(lepic_try "${CT_SHOP}" contact invoice "${CT_A}" 0.02 --reference not-allowed)"
    echo "${out}" >"${CASE_DIR}/not-allowed.txt"
    ct_wait "bob took the unallowed invoice" 20 "${CT_SHOP},${CT_BOB}" false || true
    expect_json "$(w "${CT_BOB}" contact invoices)" '.invoices | length == 0' "an invoice from a contact not allowed is not parked" || return 1
    w "${CT_BOB}" contact allow-invoices "${CT_B}" on >/dev/null || fail "allow-invoices on failed" || return 1
    expect_eq "$(ct_field "${CT_BOB}" "${CT_B}" allow_invoices)" true "allow_invoices" || return 1
    out="$(w "${CT_SHOP}" contact invoice "${CT_A}" 0.02 --reference order-1)" || fail "contact invoice failed" || return 1
    echo "${out}" >"${CASE_DIR}/invoice.json"
    ct_wait "bob parked the invoice" 90 "${CT_SHOP},${CT_BOB}" ct_invoices_count "${CT_BOB}" 1 || return 1
    list="$(w "${CT_BOB}" contact invoices)"
    echo "${list}" >"${CASE_DIR}/invoices.json"
    id="$(jq -r '.invoices[0].slate_id' <<<"${list}")"
    expect_json "${list}" '.invoices[0].amount == "0.02000000"' "parked amount" || return 1
    # The amount is typed again: a wrong amount is refused, nothing is paid.
    wx_not_zero "${CT_BOB}" contact pay-invoice "${id}" 0.03 --min-confirmations "${E2E_MINCONF}" || return 1
    w "${CT_BOB}" contact pay-invoice "${id}" 0.02 --min-confirmations "${E2E_MINCONF}" >/dev/null || fail "pay-invoice failed" || return 1
    ct_wait "invoice paid and finalized by the shop" 120 "${CT_SHOP},${CT_BOB}" ct_tx_done "${CT_SHOP}" "${id}" || return 1
    expect_json "$(w "${CT_BOB}" contact invoices)" '.invoices | length == 0' "paid invoice no longer parked" || return 1
    # A second invoice is declined; the shop is told.
    w "${CT_SHOP}" contact invoice "${CT_A}" 0.03 --reference order-2 >/dev/null || fail "second invoice failed" || return 1
    ct_wait "bob parked the second invoice" 90 "${CT_SHOP},${CT_BOB}" ct_invoices_count "${CT_BOB}" 1 || return 1
    id="$(w "${CT_BOB}" contact invoices | jq -r '.invoices[0].slate_id')"
    w "${CT_BOB}" contact decline "${id}" >/dev/null || fail "contact decline failed" || return 1
    expect_json "$(w "${CT_BOB}" contact invoices)" '.invoices | length == 0' "declined invoice no longer parked" || return 1
    # The issuer is told by a `declined` notice: it raises an event (no CLI output) and leaves the
    # tx `received` (lepic-wallet notices.rs take_decline). What the CLI shows is that the shop's
    # next collect takes one message, and that its tx is not paid or cancelled.
    local got=0 n m
    for n in 1 2 3 4 5 6 7 8; do
        w "${CT_BOB}" contact collect >/dev/null 2>&1
        m="$(w "${CT_SHOP}" contact collect | jq '.messages')" || m=0
        got=$((got + m))
        ((got >= 1)) && break
        sleep 3
    done
    ((got >= 1)) || fail "the shop took no message after the decline" || return 1
    expect_eq "$(tx_by_slate "${CT_SHOP}" "${id}" | jq -r .state)" received "the declined invoice stays unpaid on the shop" || return 1
    note "unallowed not parked; allowed paid; declined: the shop took the notice (tx stays received)"
}
ct_invoices_count() { (($(w "$1" contact invoices | jq '.invoices | length') >= $2)); }
ct_tx_cancelled() { slate_state_in "$1" "$2" "cancelled canceled"; }
# Runs a command on a wallet and prints exit status and output; never fails.
lepic_try() {
    local n="$1" out st=0
    shift
    out="$(lepic_env "${n}" --output json "$@" 2>&1)" || st=$?
    printf 'exit=%s %s' "${st}" "${out}"
}
wx_not_zero() {
    local n="$1" st=0
    shift
    lepic_env "${n}" --output json "$@" >"${CASE_DIR}/nz.out" 2>&1 || st=$?
    ((st != 0)) || fail "lepic $* exited 0, wanted a refusal"
}

case_ct_payload() {
    local id list hex
    ct_fresh "${CT_ALICE}" "${CT_BOB}" || return 1
    expect_json "$(w "${CT_BOB}" contact quarantine)" '[.. | arrays] | length >= 1' "quarantine lists" || return 1
    hex="$(printf 'e1s payload %s' "$$" | xxd -p | tr -d '\n')"
    id="$(w "${CT_ALICE}" contact payload post --hex "${hex}" "${CT_A}")" || fail "payload post failed" || return 1
    echo "${id}" >"${CASE_DIR}/post.json"
    ct_wait "bob has the payload" 90 "${CT_ALICE},${CT_BOB}" ct_payloads_count "${CT_BOB}" 1 || return 1
    list="$(w "${CT_BOB}" contact payload list)"
    echo "${list}" >"${CASE_DIR}/list.json"
    expect_json "${list}" "[.. | strings | select(. == \"${hex}\")] | length >= 1" "payload bytes arrived" || return 1
    local pid
    pid="$(jq -r '[.. | objects | select(has("id")) | .id][0]' <<<"${list}")"
    expect_json "$(w "${CT_BOB}" contact payload ack "${pid}")" '.. | numbers | select(. == 1)' "ack forgot one" || return 1
    expect_eq "$(w "${CT_BOB}" contact payload list | jq '[.. | objects | select(has("id"))] | length')" 0 "payloads after ack" || return 1
    note "payload posted, listed, acked"
}
ct_payloads_count() { (($(w "$1" contact payload list | jq '[.. | objects | select(has("id"))] | length') >= $2)); }

case_ct_profile() {
    local show
    ct_fresh "${CT_ALICE}" "${CT_BOB}" || return 1
    show="$(w "${CT_ALICE}" profile show)" || fail "profile show failed" || return 1
    echo "${show}" >"${CASE_DIR}/show0.json"
    show="$(w "${CT_ALICE}" profile set automated)" || fail "profile set failed" || return 1
    echo "${show}" >"${CASE_DIR}/set.json"
    expect_json "${show}" '.queued >= 1 and .profile != 0' "profile set queued for the contact" || return 1
    show="$(w "${CT_ALICE}" profile show)"
    echo "${show}" >"${CASE_DIR}/show1.json"
    # Note: `profile show` reads the configured profile, so it stays 0 after `profile set`.
    ct_wait "bob sees the new profile" 90 "${CT_ALICE},${CT_BOB}" ct_peer_profile_not_zero "${CT_BOB}" "${CT_B}" || return 1
    w "${CT_ALICE}" profile set --bits 0 >/dev/null || fail "profile set (clear) failed" || return 1
    ct_wait "bob sees the cleared profile" 90 "${CT_ALICE},${CT_BOB}" ct_peer_profile_zero "${CT_BOB}" "${CT_B}" || return 1
    w "${CT_ALICE}" profile domain show >"${CASE_DIR}/domain.json" || fail "profile domain show failed" || return 1
    note "profile set/cleared seen by the contact; domain shown"
}
ct_peer_profile_not_zero() { [[ "$(ct_field "$1" "$2" peer_profile)" != 0 ]]; }
ct_peer_profile_zero() { [[ "$(ct_field "$1" "$2" peer_profile)" == 0 ]]; }

case_ct_offline() {
    ct_wallets "${CT_ALICE}" "${CT_BOB}" || return 1
    ct_fund "${CT_ALICE}" || return 1
    ct_fresh "${CT_ALICE}" "${CT_BOB}" || return 1
    local out slate
    out="$(w "${CT_ALICE}" tx send --to-contact "${CT_A}" --min-confirmations "${E2E_MINCONF}" 0.01)" || fail "tx send --to-contact failed" || return 1
    slate="$(jq -r .slate_id <<<"${out}")"
    # Bob is offline: nothing collects for a while, and the payment stays open.
    sleep 15
    w "${CT_ALICE}" contact collect >/dev/null || fail "alice collect failed" || return 1
    ct_tx_done "${CT_ALICE}" "${slate}" && fail "payment finalized while bob was offline" && return 1
    # Bob comes back and collects; the payment completes.
    ct_wait "payment finalized after bob collected" 120 "${CT_BOB},${CT_ALICE}" ct_tx_done "${CT_ALICE}" "${slate}" || return 1
    note "payment waited for the offline contact, finalized after its collect (${slate})"
}

# A copy of the keeper (alice with a saved phrase) restored from the phrase into the data dir of `e1s-ct-alice2`; no contacts.
ct_restore_alice() {
    local name="${E2E_PREFIX}-ct-alice2" phrase
    phrase="$(jq -r .recovery_phrase "${E2E_STATE}/wallets/${CT_KEEP}.init.json")"
    rm -rf "$(wdir "${name}")"
    w "${name}" wallet restore <<<"${phrase}" >"${CASE_DIR}/restore-alice.json" ||
        fail "wallet restore of alice failed: $(tail -c 300 "${CASE_DIR}/restore-alice.json") $(tail -c 300 "${CASE_DIR}/last.err")" || return 1
}

case_ct_export_import() {
    local file="${CASE_DIR}/contacts.backup" alice2="${E2E_PREFIX}-ct-alice2" ids
    ct_wallets "${CT_KEEP}" "${CT_BOB}" || return 1
    ct_fund "${CT_KEEP}" || return 1
    ct_fresh "${CT_KEEP}" "${CT_BOB}" || return 1
    w "${CT_KEEP}" contact export "${file}" >/dev/null || fail "contact export failed" || return 1
    [[ -s "${file}" ]] || fail "the backup file is empty" || return 1
    ct_restore_alice || return 1
    expect_json "$(w "${alice2}" contact list)" '.contacts | length == 0' "a restored wallet starts with no contact" || return 1
    w "${alice2}" contact import "${file}" >/dev/null || fail "contact import failed" || return 1
    ids="$(w "${alice2}" contact list | jq -r '.contacts[].contact_id')"
    expect_eq "${ids}" "${CT_A}" "imported contact id" || return 1
    expect_eq "$(ct_field "${alice2}" "${CT_A}" state)" verified "imported state" || return 1
    # The pairing still works from the restored wallet: pay bob through it.
    ct_pay "${alice2}" "${CT_BOB}" "${CT_A}" 0.01 || return 1
    note "export, restore from the phrase, import; paid bob from the restored wallet (${CT_SLATE})"
}

case_ct_key_check() {
    local alice2="${E2E_PREFIX}-ct-alice2" out new old
    ct_fresh "${CT_KEEP}" "${CT_BOB}" || return 1
    old="${CT_B}"
    # Alice restores from her phrase and loses her pairings; she pairs with bob again.
    ct_restore_alice || return 1
    out="$(w "${alice2}" contact invite --name Alice)" || fail "invite from the restored wallet failed" || return 1
    out="$(w "${CT_BOB}" contact accept "$(jq -r .link <<<"${out}")" --name Bob)" || fail "accept failed" || return 1
    new="$(jq -r .contact_id <<<"${out}")"
    echo "${out}" >"${CASE_DIR}/accept.json"
    ct_wait "bob holds the second pairing" 90 "${alice2},${CT_BOB}" ct_state_in "${CT_BOB}" "${new}" "paired verified keys-changed checking" || return 1
    echo "$(w "${CT_BOB}" contact list)" >"${CASE_DIR}/bob-before.json"
    w "${CT_BOB}" contact key-check "${new}" "${old}" >"${CASE_DIR}/key-check.json" || fail "contact key-check failed" || return 1
    ct_wait "bob's key check settled" 120 "${alice2},${CT_BOB}" ct_key_check_settled "${CT_BOB}" "${new}" "${old}" || return 1
    echo "$(w "${CT_BOB}" contact list)" >"${CASE_DIR}/bob-after.json"
    expect_eq "$(w "${CT_BOB}" contact list | jq '.contacts | length')" 1 "one record left on bob" || return 1
    note "key check: the restored wallet proved its old keys; bob kept one record"
}
ct_key_check_settled() {
    [[ "$(w "$1" contact list | jq --arg n "$2" '[.contacts[] | select(.contact_id == $n)] | length')" == 0 ]]
}

case_ct_move() {
    local relay2="${E2E_RELAY2}" out hostport
    ct_wallets "${CT_KEEP}" "${CT_BOB}" || return 1
    ct_fund "${CT_KEEP}" || return 1
    ct_fresh "${CT_KEEP}" "${CT_BOB}" || return 1
    # Alice moves her home relay; her config names the new relay too.
    out="$(lepic_try "${CT_KEEP}" contact move-home "${relay2}" --drain-days 1)"
    echo "${out}" >"${CASE_DIR}/move-home.txt"
    if [[ "${out}" != exit=0* ]]; then
        fail "move-home to ${relay2} failed: ${out:0:300}" || return 1
    fi
    ct_wait "bob sees the relay request" 90 "${CT_KEEP},${CT_BOB}" ct_requested_relay "${CT_BOB}" "${CT_B}" || return 1
    hostport="$(ct_field "${CT_BOB}" "${CT_B}" requested_relay)"
    echo "${hostport}" >"${CASE_DIR}/requested.txt"
    w "${CT_BOB}" contact move "${CT_B}" --apply "${hostport}" >/dev/null || { fail "contact move failed" || return 1; }
    # Messages still arrive after the move: a payload each way.
    ct_payload_roundtrip "${CT_KEEP}" "${CT_BOB}" "${CT_A}" "${CT_B}" || return 1
    # And back.
    w "${CT_KEEP}" contact move-home "${E2E_RELAY}" >/dev/null || { fail "move-home back failed" || return 1; }
    ct_wait "bob sees the request to move back" 90 "${CT_KEEP},${CT_BOB}" ct_requested_relay "${CT_BOB}" "${CT_B}" || return 1
    hostport="$(ct_field "${CT_BOB}" "${CT_B}" requested_relay)"
    w "${CT_BOB}" contact move "${CT_B}" --apply "${hostport}" >/dev/null || { fail "contact move back failed" || return 1; }
    ct_payload_roundtrip "${CT_KEEP}" "${CT_BOB}" "${CT_A}" "${CT_B}" || return 1
    note "moved home to ${relay2} (drain 1 day), bob followed, payloads both ways, and back"
}
ct_requested_relay() { [[ -n "$(ct_field "$1" "$2" requested_relay)" ]]; }
# A payload each way between two paired wallets.
ct_payload_roundtrip() {
    local a="$1" b="$2" ida="$3" idb="$4" hex
    hex="$(printf 'rt-%s-%s' "$$" "${SECONDS}" | xxd -p | tr -d '\n')"
    w "${a}" contact payload post --hex "${hex}" "${ida}" >/dev/null || fail "payload post from ${a} failed" || return 1
    ct_wait "${b} has the payload" 90 "${a},${b}" ct_payload_has "${b}" "${hex}" || return 1
    w "${b}" contact payload post --hex "${hex}" "${idb}" >/dev/null || fail "payload post from ${b} failed" || return 1
    ct_wait "${a} has the payload" 90 "${a},${b}" ct_payload_has "${a}" "${hex}" || return 1
    local pid
    for pid in $(w "${a}" contact payload list | jq -r '[.. | objects | select(has("id")) | .id][]'); do w "${a}" contact payload ack "${pid}" >/dev/null || true; done
    for pid in $(w "${b}" contact payload list | jq -r '[.. | objects | select(has("id")) | .id][]'); do w "${b}" contact payload ack "${pid}" >/dev/null || true; done
}
ct_payload_has() { w "$1" contact payload list | jq -e --arg h "$2" '[.. | strings | select(. == $h)] | length >= 1' >/dev/null; }
