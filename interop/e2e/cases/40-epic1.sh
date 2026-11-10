# shellcheck shell=bash
# epic1 links: the address, on-screen and printed links, paying, collecting, answers, relays,
# proofs, restore, refusals and concurrent payers.

CASES+=("epic1.address|case_e1_address|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.link-pay|case_e1_link_pay|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts crates/lepic-wallet")

CASES+=("epic1.no-amount|case_e1_no_amount|crates/lepic-cli crates/lepic-epic1")
CASES+=("epic1.printed|case_e1_printed|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.epicbox-param|case_e1_epicbox_param|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.proof|case_e1_proof|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.restore|case_e1_restore|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet crates/lepic-keychain")
CASES+=("epic1.concurrent|case_e1_concurrent|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.refusals|case_e1_refusals|crates/lepic-cli crates/lepic-epic1")

E1_PAYEE="${E2E_PREFIX}-link-payee"
E1_PAYER="${E2E_PREFIX}-link-payer"

e1_setup() {
    ensure_wallet "${E1_PAYEE}" || fail "could not create ${E1_PAYEE}" || return 1
    ensure_wallet "${E1_PAYER}" || fail "could not create ${E1_PAYER}" || return 1
    ensure_funds "${E1_PAYER}" 3 3 || fail "could not fund ${E1_PAYER}" || return 1
}

# Runs `contact collect` on a wallet until the transaction of a slate shows in a state of `states`.
# Each round is a separate command, so the wallet's lock is held only while it runs.
e1_collect_until() {
    local name="$1" slate="$2" states="$3" i
    for ((i = 0; i < 40; i++)); do
        w "${name}" contact collect >"${CASE_DIR}/${name}.collect.json" || fail "contact collect on ${name} failed" || return 1
        w "${name}" wallet info >/dev/null 2>&1 || true
        slate_state_in "${name}" "${slate}" "${states}" && return 0
        sleep 3
    done
    fail "${name}: slate ${slate} never reached [${states}] (now '$(tx_by_slate "${name}" "${slate}" | jq -r '.state // "none"')')"
}

# `tx list` reads local state; `wallet info` refreshes it from the node first.
e1_confirmed() { wait_until "$1 confirms $2" 400 e1_state_refreshed "$1" "$2" confirmed; }
e1_state_refreshed() {
    w "$1" wallet info >/dev/null 2>&1 || true
    slate_state_is "$1" "$2" "$3"
}

case_e1_address() {
    local name="${E1_PAYEE}" a b
    ensure_wallet "${name}" || return 1
    a="$(w "${name}" epic1 address | jq -r .address)" || fail "epic1 address failed" || return 1
    b="$(w "${name}" epic1 address | jq -r .address)" || return 1
    expect_match "${a}" '^tepic1[02-9ac-hj-np-z]+$' "epic1 address" || return 1
    expect_eq "${#a}" 116 "floonet epic1 length" || return 1
    expect_eq "${a}" "${b}" "address stable between calls" || return 1
    note "${a:0:20}… (116 chars)"
}

case_e1_link_pay() {
    local link read slate t0 t pay answers
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link 0.1)" || fail "epic1 link failed" || return 1
    printf '%s\n' "${link}" >"${CASE_DIR}/link.json"
    expect_json "${link}" '.kind == "on_screen" and (.link | startswith("epic:tepic1"))' "link" || return 1
    link="$(jq -r .link <<<"${link}")"
    read="$(w "${E1_PAYER}" epic1 read "${link}")" || fail "epic1 read failed" || return 1
    expect_json "${read}" ".amount == \"0.1\" or .amount == \"0.10000000\"" "read amount" || return 1
    expect_json "${read}" ".hosts | length == 1 and .[0].host == \"${E2E_RELAY}\"" "read hosts" || return 1
    printf '%s\n' "${read}" >"${CASE_DIR}/read.json"
    t0=${SECONDS}
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay.json"
    expect_json "${pay}" '.posted == 0 and .attempts[0].error == null' "pay posted to entry 0" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    note "paid in $((SECONDS - t0))s"
    t=${SECONDS}
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized" || return 1
    printf '%s\n' "$(tx_by_slate "${E1_PAYEE}" "${slate}")" >"${CASE_DIR}/payee-tx.json"
    note "payee took in $((SECONDS - t))s"
    # The payee's answers list shows the payment; the answer is posted by collect or by hand.
    answers="$(w "${E1_PAYEE}" epic1 answers)" || fail "epic1 answers failed" || return 1
    printf '%s\n' "${answers}" >"${CASE_DIR}/answers.json"
    expect_json "${answers}" "[.. | objects | select(.slate_id? == \"${slate}\")] | length >= 1" "answer listed for the slate" || return 1
    expect_json "${answers}" "[.answers[] | select(.slate_id == \"${slate}\" and .posted == false)] | length == 1" "collect does not post the answer by itself" || return 1
    w "${E1_PAYEE}" epic1 post-answer "${slate}" --relay-ok >"${CASE_DIR}/post-answer.json" || fail "epic1 post-answer failed" || return 1
    expect_json "$(w "${E1_PAYEE}" epic1 answers)" "[.answers[] | select(.slate_id == \"${slate}\" and .posted == true)] | length == 1" "answer marked posted" || return 1
    t=${SECONDS}
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    note "payer finalized in $((SECONDS - t))s"
    e1_confirmed "${E1_PAYEE}" "${slate}" || return 1
    e1_confirmed "${E1_PAYER}" "${slate}" || return 1
    note "confirmed both sides after $((SECONDS - t0))s"
}

# A payer sends `amount` to a link and the payee's collect takes it; returns the slate in E1_SLATE.
e1_pay_and_take() {
    local link="$1" amount="${2:-}" pay args=()
    [[ -n "${amount}" ]] && args=("${amount}")
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" "${args[@]}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay ${amount} failed" || return 1
    E1_SLATE="$(jq -r .slate_id <<<"${pay}")"
    E1_PAY="${pay}"
    e1_collect_until "${E1_PAYEE}" "${E1_SLATE}" "pending_confirmation received finalized confirmed" || return 1
    # Answer it, so the payer finalizes and its inputs are not left locked.
    w "${E1_PAYEE}" epic1 post-answer "${E1_SLATE}" --relay-ok >/dev/null || fail "epic1 post-answer failed" || return 1
    e1_collect_until "${E1_PAYER}" "${E1_SLATE}" "posted confirmed" || return 1
}

# A link with no amount cannot be paid without one; an explicit amount works, and is what the payee gets.
case_e1_no_amount() {
    local link
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link | jq -r .link)" || fail "epic1 link (no amount) failed" || return 1
    expect_match "${link}" '^epic:tepic1' "link" || return 1
    [[ "${link}" != *amount=* ]] || fail "link with no amount carries one: ${link}" || return 1
    expect_json "$(w "${E1_PAYER}" epic1 read "${link}")" '.amount == null' "read shows no amount" || return 1
    wx 2 "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" || return 1
    printf "%s\n" "${LAST_JSON}" >"${CASE_DIR}/refused.json"
    e1_pay_and_take "${link}" 0.03 || return 1
    expect_json "$(tx_by_slate "${E1_PAYEE}" "${E1_SLATE}")" '.amount_credited == "0.03000000"' "payee credited the explicit amount" || return 1
    note "no amount: pay exits 2; explicit 0.03 taken"
}

# A printed link: reusable, listed, retired; a payment to a retired link is not taken.
case_e1_printed() {
    local out link n slate1 slate2 links
    e1_setup || return 1
    # Start clean: retire printed links left from an earlier run.
    for n in $(w "${E1_PAYEE}" epic1 links | jq -r '.links[] | select(.kind == "printed") | .n'); do
        w "${E1_PAYEE}" epic1 retire "${n}" >/dev/null || fail "retire ${n} failed" || return 1
    done
    out="$(w "${E1_PAYEE}" epic1 link --printed 0.01)" || fail "epic1 link --printed failed" || return 1
    printf '%s\n' "${out}" >"${CASE_DIR}/link.json"
    expect_json "${out}" '.kind == "printed"' "printed link kind" || return 1
    link="$(jq -r .link <<<"${out}")"
    n="$(jq -r .n <<<"${out}")"
    e1_pay_and_take "${link}" || return 1
    slate1="${E1_SLATE}"
    e1_pay_and_take "${link}" || return 1
    slate2="${E1_SLATE}"
    [[ "${slate1}" != "${slate2}" ]] || fail "two payments share a slate" || return 1
    links="$(w "${E1_PAYEE}" epic1 links)" || fail "epic1 links failed" || return 1
    printf '%s\n' "${links}" >"${CASE_DIR}/links.json"
    expect_json "${links}" "[.links[] | select(.kind == \"printed\" and .n == ${n} and .used_at != null)] | length == 1" "printed link listed as used" || return 1
    w "${E1_PAYEE}" epic1 retire "${n}" >/dev/null || fail "retire ${n} failed" || return 1
    expect_json "$(w "${E1_PAYEE}" epic1 links)" "[.links[] | select(.kind == \"printed\" and .n == ${n})] | length == 0" "retired link gone from links" || return 1
    wx 6 "${E1_PAYEE}" epic1 retire "${n}" || return 1
    # A payment to the retired link is posted by the payer but the payee never takes it.
    out="$(w "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 30)" || fail "pay to a retired link failed to post" || return 1
    slate1="$(jq -r .slate_id <<<"${out}")"
    for _ in 1 2 3; do w "${E1_PAYEE}" contact collect >/dev/null || fail "collect failed" || return 1; sleep 3; done
    [[ -z "$(tx_by_slate "${E1_PAYEE}" "${slate1}")" ]] || fail "payee took a payment to a retired link" || return 1
    note "printed link n=${n}: two payments taken, retire ok, retired link not taken"
}

# Refusals reachable from the CLI.
case_e1_refusals() {
    local link main bad
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link 0.01 | jq -r .link)" || fail "epic1 link failed" || return 1
    wx 2 "${E1_PAYER}" epic1 read "epic:notalink" || return 1
    wx 2 "${E1_PAYER}" epic1 pay "epic:tepic1qqqq" 0.01 --hosts-ok || return 1
    # No --hosts-ok: refused before anything is sent.
    wx 7 "${E1_PAYER}" epic1 pay "${link}" --min-confirmations "${E2E_MINCONF}" || return 1
    expect_json "${LAST_JSON}" '.error != null' "RelayNotConfirmed has an error" || return 1
    # The same link with a mainnet prefix is refused as the wrong network.
    main="$(python3 -I - "${link}" <<'PY'
import sys
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
def polymod(v):
    c = 1
    for x in v:
        b = c >> 25
        c = ((c & 0x1ffffff) << 5) ^ x
        for i in range(5):
            if (b >> i) & 1:
                c ^= G[i]
    return c
def expand(h):
    return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]
link = sys.argv[1]
body, _, query = link[len("epic:"):].partition("?")
hrp, _, data = body.rpartition("1")
vals = [CH.index(x) for x in data][:-6]
chk = polymod(expand("epic") + vals + [0] * 6) ^ 0x2bc830a3
vals += [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
print("epic:epic1" + "".join(CH[v] for v in vals) + ("?" + query if query else ""))
PY
)" || fail "could not build the mainnet link" || return 1
    wx 7 "${E1_PAYER}" epic1 read "${main}" || return 1
    printf "%s\n" "${LAST_JSON}" >"${CASE_DIR}/mainnet.json"
    # A retire of a slot never issued.
    wx 6 "${E1_PAYEE}" epic1 retire 31 || return 1
    note "malformed 2, no --hosts-ok 7, mainnet link 7, unissued retire 6; Signed/HintNotZero/NoReplyKey/NoReplyMailbox not reachable from the CLI"
}

# The relays of a link: --epicbox once and twice, a dead first relay falls through to the next,
# post-next sends the same payment to the next relay and the payee takes it once.
case_e1_epicbox_param() {
    local link read pay slate dead="unreachable.btlabs.uk" n
    e1_setup || return 1
    # 1. A link naming only the second relay.
    link="$(w "${E1_PAYEE}" epic1 link 0.01 --epicbox "${E2E_RELAY2}" | jq -r .link)" || fail "link --epicbox ${E2E_RELAY2} failed" || return 1
    expect_match "${link}" "%40${E2E_RELAY2}" "link names the second relay" || return 1
    expect_json "$(w "${E1_PAYER}" epic1 read "${link}")" ".hosts | length == 1 and .[0].host == \"${E2E_RELAY2}\"" "read shows the second relay" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "pay through ${E2E_RELAY2} failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay-relay2.json"
    expect_json "${pay}" '.posted == 0 and .attempts[0].error == null' "posted to the second relay" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    w "${E1_PAYEE}" epic1 post-answer "${slate}" --relay-ok >/dev/null || fail "post-answer via ${E2E_RELAY2} failed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    note "second relay ${E2E_RELAY2} answers floonet addresses: payment taken and finalized"
    # 2. Two relays, the first dead.
    link="$(w "${E1_PAYEE}" epic1 link 0.01 --epicbox "${dead}" --epicbox "${E2E_RELAY}" | jq -r .link)" || fail "link with two relays failed" || return 1
    read="$(w "${E1_PAYER}" epic1 read "${link}")" || fail "read failed" || return 1
    expect_json "${read}" ".hosts | length == 2 and .[0].host == \"${dead}\"" "read lists both, dead first" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "pay with a dead first relay failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay-dead-first.json"
    expect_json "${pay}" '.posted == 1 and (.attempts[0].error != null)' "dead first relay recorded, posted to the second" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    w "${E1_PAYEE}" epic1 post-answer "${slate}" --relay-ok >/dev/null || fail "post-answer failed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    # 3. post-next: the same payment to the next relay; the payee takes one transaction.
    link="$(w "${E1_PAYEE}" epic1 link 0.01 --epicbox "${E2E_RELAY}" --epicbox "${E2E_RELAY2}" | jq -r .link)" || fail "link failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "pay failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    expect_json "${pay}" '.posted == 0' "first entry took it" || return 1
    wx 7 "${E1_PAYER}" epic1 post-next "${slate}" || return 1
    w "${E1_PAYER}" epic1 post-next "${slate}" --hosts-ok >"${CASE_DIR}/post-next.json" || fail "post-next failed" || return 1
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    w "${E1_PAYEE}" contact collect >/dev/null || fail "second collect failed" || return 1
    n="$(w "${E1_PAYEE}" tx list | jq --arg id "${slate}" '[.transactions[] | select(.slate_id == $id)] | length')"
    expect_eq "${n}" 1 "one transaction for the slate posted twice" || return 1
    w "${E1_PAYEE}" epic1 post-answer "${slate}" --relay-ok >/dev/null || fail "post-answer failed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    note "relay2 ok, dead first relay falls through (posted 1), post-next needs --hosts-ok, payee takes the duplicate once"
}

# pay --proof: the payee signs a payment proof with its epic1 proof key.
case_e1_proof() {
    local link pay slate
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link 0.01 | jq -r .link)" || fail "epic1 link failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --proof --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "epic1 pay --proof failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay.json"
    slate="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    w "${E1_PAYEE}" epic1 post-answer "${slate}" --relay-ok >/dev/null || fail "post-answer failed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    e1_confirmed "${E1_PAYER}" "${slate}" || return 1
    w "${E1_PAYER}" tx show "$(tx_by_slate "${E1_PAYER}" "${slate}" | jq -r .tx_id)" >"${CASE_DIR}/payer-tx.json" || fail "tx show failed" || return 1
    w "${E1_PAYEE}" tx show "$(tx_by_slate "${E1_PAYEE}" "${slate}" | jq -r .tx_id)" >"${CASE_DIR}/payee-tx.json" || fail "tx show failed" || return 1
    note "pay --proof finalized and confirmed (the CLI shows no proof field to inspect)"
}

# A payee restored from its phrase reads the link mailboxes once and takes a payment made while
# the first copy of the wallet was not running.
case_e1_restore() {
    local first="${E2E_PREFIX}-link-rpayee" copy="${E2E_PREFIX}-link-rpayee-copy" phrase link pay slate
    e1_setup || return 1
    ensure_wallet "${first}" || fail "could not create ${first}" || return 1
    phrase="$(jq -r .recovery_phrase "${E2E_STATE}/wallets/${first}.init.json")"
    link="$(w "${first}" epic1 link 0.01 | jq -r .link)" || fail "epic1 link failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "pay failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    rm -rf "$(wdir "${copy}")"
    w "${copy}" wallet restore <<<"${phrase}" >"${CASE_DIR}/restore.json" || fail "wallet restore failed" || return 1
    expect_eq "$(w "${copy}" epic1 address | jq -r .address)" "$(w "${first}" epic1 address | jq -r .address)" "same epic1 address after restore" || return 1
    w "${copy}" epic1 restore >"${CASE_DIR}/epic1-restore.json" || fail "epic1 restore failed" || return 1
    e1_collect_until "${copy}" "${slate}" "pending_confirmation received finalized confirmed" || fail "the restored wallet did not take the payment: $(cat "${CASE_DIR}/epic1-restore.json")" || return 1
    w "${copy}" epic1 post-answer "${slate}" --relay-ok >/dev/null || fail "post-answer from the copy failed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    note "restored wallet took the payment made while it was gone (epic1 restore: $(jq -c . "${CASE_DIR}/epic1-restore.json" | cut -c1-120))"
}

# Three payers pay one printed link at once; one collect takes all three.
case_e1_concurrent() {
    local names=() n link slates=() pids=() logs=() i out slate
    for n in a b c; do
        names+=("${E2E_PREFIX}-link-pay-${n}")
        ensure_wallet "${names[-1]}" || fail "could not create ${names[-1]}" || return 1
        ensure_funds "${names[-1]}" 1 1 || fail "could not fund ${names[-1]}" || return 1
    done
    ensure_wallet "${E1_PAYEE}" || return 1
    for n in $(w "${E1_PAYEE}" epic1 links | jq -r '.links[] | select(.kind == "printed") | .n'); do
        w "${E1_PAYEE}" epic1 retire "${n}" >/dev/null || fail "retire ${n} failed" || return 1
    done
    out="$(w "${E1_PAYEE}" epic1 link --printed 0.01)" || fail "printed link failed" || return 1
    link="$(jq -r .link <<<"${out}")"
    for i in 0 1 2; do
        wbg "${names[i]}" pay --output json epic1 pay "${link}" --hosts-ok --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100
        pids+=("${BG_PID}")
        logs+=("${BG_LOG}")
    done
    for i in 0 1 2; do
        wait "${pids[i]}" || fail "payer ${names[i]} exited $?: $(tail -c 300 "${logs[i]}.err")" || return 1
        slate="$(jq -r .slate_id "${logs[i]}.out")" || return 1
        slates+=("${slate}")
    done
    [[ "$(printf '%s\n' "${slates[@]}" | sort -u | wc -l)" == 3 ]] || fail "payers share a slate: ${slates[*]}" || return 1
    for slate in "${slates[@]}"; do
        e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    done
    for slate in "${slates[@]}"; do
        w "${E1_PAYEE}" epic1 post-answer "${slate}" --relay-ok >/dev/null || fail "post-answer ${slate} failed" || return 1
    done
    for i in 0 1 2; do
        e1_collect_until "${names[i]}" "${slates[i]}" "posted confirmed" || return 1
    done
    w "${E1_PAYEE}" epic1 retire "$(jq -r .n <<<"${out}")" >/dev/null || fail "retire failed" || return 1
    note "three payers on one printed link, all taken and finalized"
}
