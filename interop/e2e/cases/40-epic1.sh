# shellcheck shell=bash
# epic1: the account's one address, request links, paying with another amount and message,
# collecting, restore, concurrent payers, the refuse switch and payment proofs.

CASES+=("epic1.address|case_e1_address|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.link-pay|case_e1_link_pay|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts crates/lepic-wallet")

CASES+=("epic1.no-amount|case_e1_no_amount|crates/lepic-cli crates/lepic-epic1")
CASES+=("epic1.proof|case_e1_proof|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts crates/lepic-seal")
CASES+=("epic1.restore|case_e1_restore|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet crates/lepic-keychain")
CASES+=("epic1.two-installs|case_e1_two_installs|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts crates/lepic-epicbox crates/lepic-wallet")
CASES+=("epic1.concurrent|case_e1_concurrent|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")
CASES+=("epic1.refusals|case_e1_refusals|crates/lepic-cli crates/lepic-epic1")
CASES+=("epic1.one-mailbox-down|case_e1_one_mailbox_down|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts crates/lepic-epicbox")
CASES+=("epic1.no-shared|case_e1_no_shared|crates/lepic-cli crates/lepic-epic1 crates/lepic-wallet-contacts")

E1_PAYEE="${E2E_PREFIX}-link-payee"
E1_PAYER="${E2E_PREFIX}-link-payer"

e1_setup() {
    ensure_wallet "${E1_PAYEE}" || fail "could not create ${E1_PAYEE}" || return 1
    ensure_wallet "${E1_PAYER}" || fail "could not create ${E1_PAYER}" || return 1
    ensure_funds "${E1_PAYER}" 3 3 || fail "could not fund ${E1_PAYER}" || return 1
}

# Runs `contact collect` on a wallet until the transaction of a slate shows in a state of `states`.
# Each round is a separate command, so the wallet's lock is held only while it runs.
# A fourth argument names a wallet that collects in each round too, so an answer it could not
# post at once is posted on a later round.
e1_collect_until() {
    local name="$1" slate="$2" states="$3" also="${4:-}" i
    for ((i = 0; i < 40; i++)); do
        [[ -z "${also}" ]] || w "${also}" contact collect >/dev/null 2>&1 || true
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
    expect_eq "${#a}" 118 "floonet epic1 length" || return 1
    expect_eq "${a}" "${b}" "address stable between calls" || return 1
    note "${a:0:20}… (118 chars)"
}

case_e1_link_pay() {
    local link read slate t0 t pay answers
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link 0.1)" || fail "epic1 link failed" || return 1
    printf '%s\n' "${link}" >"${CASE_DIR}/link.json"
    expect_json "${link}" '.link | startswith("epic:tepic1")' "link" || return 1
    link="$(jq -r .link <<<"${link}")"
    read="$(w "${E1_PAYER}" epic1 read "${link}")" || fail "epic1 read failed" || return 1
    expect_json "${read}" ".amount == \"0.1\" or .amount == \"0.10000000\"" "read amount" || return 1
    expect_json "${read}" '.http_host == null' "read: a mailbox link has no host" || return 1
    printf '%s\n' "${read}" >"${CASE_DIR}/read.json"
    t0=${SECONDS}
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay.json"
    expect_json "${pay}" '.posted == 0 and .posted_ok == true and .attempts[0].error == null' "pay posted to the delivery mailbox" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    note "paid in $((SECONDS - t0))s"
    t=${SECONDS}
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized" || return 1
    printf '%s\n' "$(tx_by_slate "${E1_PAYEE}" "${slate}")" >"${CASE_DIR}/payee-tx.json"
    note "payee took in $((SECONDS - t))s"
    # The payee's collect posted the answer itself.
    answers="$(w "${E1_PAYEE}" epic1 answers)" || fail "epic1 answers failed" || return 1
    printf '%s\n' "${answers}" >"${CASE_DIR}/answers.json"
    expect_json "${answers}" "[.. | objects | select(.slate_id? == \"${slate}\")] | length >= 1" "answer listed for the slate" || return 1
    expect_json "${answers}" "[.answers[] | select(.slate_id == \"${slate}\" and .posted == true)] | length == 1" "collect posted the answer by itself" || return 1
    t=${SECONDS}
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" "${E1_PAYEE}" || return 1
    note "payer finalized in $((SECONDS - t))s"
    e1_confirmed "${E1_PAYEE}" "${slate}" || return 1
    e1_confirmed "${E1_PAYER}" "${slate}" || return 1
    note "confirmed both sides after $((SECONDS - t0))s"
    # The same link paid with another amount and message: the payee takes what was paid.
    e1_pay_and_take "${link}" 0.02 "changed by the payer" || return 1
    expect_json "$(tx_by_slate "${E1_PAYEE}" "${E1_SLATE}")" '.amount_credited == "0.02000000"' "payee credited the changed amount, not the link's" || return 1
    expect_json "$(w "${E1_PAYEE}" tx show "$(tx_by_slate "${E1_PAYEE}" "${E1_SLATE}" | jq -r .tx_id)")" 'tostring | contains("changed by the payer")' "payee tx carries the payer's message" || return 1
    note "link of 0.1 paid with 0.02 and another message, taken"
}

# A payer sends `amount` and `message` (each optional) to a link or address and the payee's collect
# takes it; returns the slate in E1_SLATE.
e1_pay_and_take() {
    local link="$1" amount="${2:-}" message="${3:-}" pay args=()
    [[ -n "${amount}" ]] && args=("${amount}")
    [[ -z "${message}" ]] || args+=(-m "${message}")
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" "${args[@]}" --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay ${amount} failed" || return 1
    E1_SLATE="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${E1_PAYEE}" "${E1_SLATE}" "pending_confirmation received finalized confirmed" || return 1
    # The payee's collect answered it; the payer's collect finalizes.
    e1_collect_until "${E1_PAYER}" "${E1_SLATE}" "posted confirmed" "${E1_PAYEE}" || return 1
}

# A link with no amount cannot be paid without one; an explicit amount works, and is what the payee gets.
case_e1_no_amount() {
    local link
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link | jq -r .link)" || fail "epic1 link (no amount) failed" || return 1
    expect_match "${link}" '^epic:tepic1' "link" || return 1
    [[ "${link}" != *amount=* ]] || fail "link with no amount carries one: ${link}" || return 1
    expect_json "$(w "${E1_PAYER}" epic1 read "${link}")" '.amount == null' "read shows no amount" || return 1
    wx 2 "${E1_PAYER}" epic1 pay "${link}" --min-confirmations "${E2E_MINCONF}" || return 1
    printf "%s\n" "${LAST_JSON}" >"${CASE_DIR}/refused.json"
    e1_pay_and_take "${link}" 0.03 || return 1
    expect_json "$(tx_by_slate "${E1_PAYEE}" "${E1_SLATE}")" '.amount_credited == "0.03000000"' "payee credited the explicit amount" || return 1
    note "no amount: pay exits 2; explicit 0.03 taken"
}

# Refusals reachable from the CLI.
case_e1_refusals() {
    local link main
    e1_setup || return 1
    link="$(w "${E1_PAYEE}" epic1 link 0.01 | jq -r .link)" || fail "epic1 link failed" || return 1
    wx 2 "${E1_PAYER}" epic1 read "epic:notalink" || return 1
    wx 2 "${E1_PAYER}" epic1 pay "epic:tepic1qqqq" 0.01 || return 1
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
    e1_refuse_switch || return 1
    note "malformed 2, mainnet link 7; refuse switch: address and link payments declined, payer erased them"
}

# With refuse_unsolicited_payments on, a payment to the address and one by a link are both
# declined: the payee stores nothing and the payer's collect takes the `declined` notice. The notice
# cancels nothing (ADR 0067): the payer cancels the send, which frees its inputs.
e1_refuse_switch() {
    local link addr target before after n=0 rc=0
    addr="$(w "${E1_PAYEE}" epic1 address | jq -r .address)" || fail "epic1 address failed" || return 1
    link="$(w "${E1_PAYEE}" epic1 link 0.01 | jq -r .link)" || fail "epic1 link failed" || return 1
    w "${E1_PAYER}" wallet info >/dev/null || return 1
    before="$(usable_units "${E1_PAYER}")" || return 1
    wconfig_set "${E1_PAYEE}" 'refuse_unsolicited_payments = true'
    for target in "${addr}" "${link}"; do
        n=$((n + 1))
        e1_refused_payment "${target}" "${n}" || { rc=1; break; }
    done
    wconfig_reset "${E1_PAYEE}"
    ((rc == 0)) || return 1
    after="$(usable_units "${E1_PAYER}")" || return 1
    expect_eq "${after}" "${before}" "payer's spendable after both declines" || return 1
}

# One collect on each side; true once the payer's tx of `slate` is gone: a send its payee
# declined never happened, so the payer erases it and unlocks its inputs.
e1_declined_seen() {
    local list
    w "${E1_PAYEE}" contact collect >/dev/null 2>&1 || true
    w "${E1_PAYER}" contact collect >/dev/null 2>&1 || return 1
    list="$(w "${E1_PAYER}" tx list)" || return 1
    jq -e --arg id "$1" '[.transactions[] | select(.slate_id == $id)] | length == 0' <<<"${list}" >/dev/null
}

e1_refused_payment() {
    local target="$1" n="$2" pay slate
    pay="$(w "${E1_PAYER}" epic1 pay "${target}" 0.01 --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "epic1 pay to ${target:0:24}… failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    wait_until "the payer to take the decline of ${slate}" 120 e1_declined_seen "${slate}" || fail "the payer never took the decline" || return 1
    [[ -z "$(tx_by_slate "${E1_PAYEE}" "${slate}")" ]] || fail "the payee stored a declined payment" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/declined-${n}.json"
}

# A payee restored from its phrase reads the mailbox of its address once and takes a
# payment made while the first copy of the wallet was not running.
case_e1_restore() {
    local first="${E2E_PREFIX}-link-rpayee" copy="${E2E_PREFIX}-link-rpayee-copy" phrase link pay slate st
    e1_setup || return 1
    ensure_wallet "${first}" || fail "could not create ${first}" || return 1
    phrase="$(jq -r .recovery_phrase "${E2E_STATE}/wallets/${first}.init.json")"
    link="$(w "${first}" epic1 link 0.01 | jq -r .link)" || fail "epic1 link failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "pay failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    rm -rf "$(wdir "${copy}")"
    w "${copy}" wallet restore <<<"${phrase}" >"${CASE_DIR}/restore.json" || fail "wallet restore failed" || return 1
    expect_eq "$(w "${copy}" epic1 address | jq -r .address)" "$(w "${first}" epic1 address | jq -r .address)" "same epic1 address after restore" || return 1
    # Exit 0 when at least one mailbox of the list was read; the others are in `not_read` with a
    # reason. Exit 10 only when none was read.
    st=0
    lepic_env "${copy}" --output json epic1 restore >"${CASE_DIR}/epic1-restore.json" 2>"${CASE_DIR}/epic1-restore.err" || st=$?
    [[ "${st}" == 0 || "${st}" == 10 ]] || fail "epic1 restore exited ${st}: $(head -c 300 "${CASE_DIR}/epic1-restore.json")" || return 1
    if [[ "${st}" == 0 ]]; then
        expect_json "$(cat "${CASE_DIR}/epic1-restore.json")" '(.taken | type == "number") and (.not_read | type == "array") and all(.not_read[]; (.host | length > 0) and (.reason | length > 0))' "exit 0: taken and each unread mailbox with its reason" || return 1
    else
        expect_json "$(cat "${CASE_DIR}/epic1-restore.json")" '[.error.causes[] | test("not read|was not read")] | all' "exit 10 only when no mailbox was read, every cause says so" || return 1
    fi
    e1_collect_until "${copy}" "${slate}" "pending_confirmation received finalized confirmed" || fail "the restored wallet did not take the payment: $(cat "${CASE_DIR}/epic1-restore.json")" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" "${E1_PAYEE}" || return 1
    # At once after the restore: the same link as the first copy makes, taken by the restored wallet.
    expect_eq "$(w "${copy}" epic1 link 0.01 | jq -r .link)" "${link}" "restored wallet makes the same request link" || return 1
    link="$(w "${copy}" epic1 link 0.02 -m "after restore" | jq -r .link)" || fail "epic1 link on the restored wallet failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "pay to the restored wallet's link failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${copy}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" "${copy}" || return 1
    note "restored wallet took the payment made while it was gone, then a payment to its new link (epic1 restore exit ${st}: $(jq -c . "${CASE_DIR}/epic1-restore.json" | cut -c1-160))"
}

# Two installs of one wallet: one made with `wallet init`, one restored from its phrase. Both
# collect, then a payer pays a link of the first. Whichever collects first after the payment reads
# it and answers once; the other reads nothing. Once mined, the other's scan records the payment
# as an incoming entry from another wallet.
case_e1_two_installs() {
    local a="${E2E_PREFIX}-link-twin-a" b="${E2E_PREFIX}-link-twin-b" link pay slate i reader="" other before after id
    e1_setup || return 1
    ensure_wallet "${a}" || fail "could not create ${a}" || return 1
    if [[ ! -d "$(wdir "${b}")" ]]; then
        w "${b}" wallet restore <<<"$(jq -r .recovery_phrase "${E2E_STATE}/wallets/${a}.init.json")" >"${CASE_DIR}/restore.json" || fail "wallet restore of ${b} failed" || return 1
    fi
    expect_eq "$(w "${b}" epic1 address | jq -r .address)" "$(w "${a}" epic1 address | jq -r .address)" "same epic1 address on both installs" || return 1
    w "${a}" contact collect >/dev/null || fail "contact collect on ${a} failed" || return 1
    w "${b}" contact collect >/dev/null || fail "contact collect on ${b} failed" || return 1
    link="$(w "${a}" epic1 link 0.01 -m "two installs" | jq -r .link)" || fail "epic1 link failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${link}" --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    for ((i = 0; i < 40; i++)); do
        for name in "${a}" "${b}"; do
            w "${name}" contact collect >"${CASE_DIR}/${name}.collect.json" || fail "contact collect on ${name} failed" || return 1
            if slate_state_in "${name}" "${slate}" "pending_confirmation received finalized"; then
                reader="${name}"
                break 2
            fi
        done
        sleep 3
    done
    [[ -n "${reader}" ]] || fail "neither install took slate ${slate}" || return 1
    other="${a}"
    [[ "${reader}" == "${a}" ]] && other="${b}"
    # The reader answered once; the other holds no entry and no answer of the slate.
    w "${other}" contact collect >/dev/null || fail "contact collect on ${other} failed" || return 1
    expect_json "$(w "${reader}" epic1 answers)" "[.answers[] | select(.slate_id == \"${slate}\")] | length == 1" "${reader} answered once" || return 1
    expect_json "$(w "${other}" epic1 answers)" "[.answers[] | select(.slate_id == \"${slate}\")] | length == 0" "${other} did not answer" || return 1
    expect_eq "$(tx_by_slate "${other}" "${slate}")" "" "${other} holds no entry of the slate" || return 1
    # A scan first, so what the count starts from holds every payment of earlier runs.
    w "${other}" wallet scan >"${CASE_DIR}/scan-before.json" || fail "wallet scan on ${other} failed" || return 1
    e1_other_wallet_ids "${other}" >"${CASE_DIR}/before.ids"
    before="$(wc -l <"${CASE_DIR}/before.ids")"
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" "${reader}" || return 1
    e1_confirmed "${reader}" "${slate}" || return 1
    # `wallet scan` with no start scans from shortly before the last scanned block: the update
    # scan the app and serve run after each refresh.
    wait_until "${other} records the payment from the chain" 300 e1_other_wallet_grew "${other}" "${before}" || fail "${other} never recorded the payment from another wallet" || return 1
    e1_other_wallet_ids "${other}" >"${CASE_DIR}/after.ids"
    after="$(comm -13 "${CASE_DIR}/before.ids" "${CASE_DIR}/after.ids")"
    expect_eq "$(wc -l <<<"${after}")" 1 "one new entry on ${other}" || return 1
    id="${after}"
    expect_json "$(w "${other}" tx show "${id}")" '.direction == "incoming" and .state == "confirmed" and .amount_credited == "0.01000000" and .origin == "other-wallet"' "${other}'s entry from another wallet" || return 1
    note "${reader} read and answered, ${other} read nothing and recorded tx ${id} from the chain"
}

# The ids of the confirmed incoming entries of a wallet that have no slate: what a scan found,
# among them what another install of the phrase received.
e1_other_wallet_ids() {
    w "$1" tx list | jq -r '.transactions[] | select(.direction == "incoming" and .state == "confirmed" and .slate_id == null) | .tx_id' | sort
}
e1_other_wallet_grew() {
    w "$1" wallet scan >/dev/null 2>&1 || true
    (($(e1_other_wallet_ids "$1" | wc -l) > $2))
}

# Two payers pay one address at once; one collect takes both.
case_e1_concurrent() {
    local names=() n addr slates=() pids=() logs=() i slate
    for n in a b; do
        names+=("${E2E_PREFIX}-link-pay-${n}")
        ensure_wallet "${names[-1]}" || fail "could not create ${names[-1]}" || return 1
        ensure_funds "${names[-1]}" 1 1 || fail "could not fund ${names[-1]}" || return 1
    done
    ensure_wallet "${E1_PAYEE}" || return 1
    addr="$(w "${E1_PAYEE}" epic1 address | jq -r .address)" || fail "epic1 address failed" || return 1
    for i in 0 1; do
        wbg "${names[i]}" pay --output json epic1 pay "${addr}" 0.01 --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100
        pids+=("${BG_PID}")
        logs+=("${BG_LOG}")
    done
    for i in 0 1; do
        wait "${pids[i]}" || fail "payer ${names[i]} exited $?: $(tail -c 300 "${logs[i]}.err")" || return 1
        slate="$(jq -r .slate_id "${logs[i]}.out")" || return 1
        slates+=("${slate}")
    done
    [[ "$(printf '%s\n' "${slates[@]}" | sort -u | wc -l)" == 2 ]] || fail "payers share a slate: ${slates[*]}" || return 1
    for slate in "${slates[@]}"; do
        e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    done
    for i in 0 1; do
        e1_collect_until "${names[i]}" "${slates[i]}" "posted confirmed" "${E1_PAYEE}" || return 1
    done
    note "two payers on one address, both taken and finalized"
}

# Sets the list of a wallet to exactly the hosts given (given the wallet has its own settings):
# adds each missing one first, so the list is never empty, then removes the others. A host named
# in `anyway` is added with --anyway, the others must pass their test.
e1_set_mailboxes() {
    local name="$1" anyway="$2" host listed
    shift 2
    listed="$(w "${name}" mailbox list | jq -r '.mailboxes[].host')" || fail "mailbox list failed on ${name}" || return 1
    for host in "$@"; do
        grep -qxF "${host}" <<<"${listed}" && continue
        if [[ " ${anyway} " == *" ${host} "* ]]; then
            w "${name}" mailbox add "${host}" --anyway >"${CASE_DIR}/add-${name}-${host}.json" || fail "mailbox add --anyway ${host} failed on ${name}" || return 1
        else
            w "${name}" mailbox add "${host}" >"${CASE_DIR}/add-${name}-${host}.json" || fail "mailbox add ${host} failed on ${name}" || return 1
        fi
    done
    for host in ${listed}; do
        [[ " $* " == *" ${host} "* ]] && continue
        w "${name}" mailbox remove "${host}" >/dev/null || fail "mailbox remove ${host} failed on ${name}" || return 1
    done
    expect_eq "$(w "${name}" mailbox list | jq -r '[.mailboxes[].host] | sort | join(" ")')" "$(printf '%s\n' "$@" | sort | tr '\n' ' ' | sed 's/ $//')" "${name}'s mailbox list" || return 1
}

# The payee's list has three mailboxes: the suite's relay, the second relay (it does not offer
# push, so it is added with --anyway) and one that does not serve Epicmail at all: a public name
# that resolves and is not ours, also added with --anyway. The payer has the same list. The pay
# report names the relays that took the post; the down one is not among them. The payee takes the
# payment from the others.
# `mailbox list` connects nowhere and shows only what its own process saw, so the failure is read
# from the payer's report and the list is checked to still hold the down mailbox.
case_e1_one_mailbox_down() {
    local down="example.com" payee="${E2E_PREFIX}-link-mpayee" rc=0
    e1_setup || return 1
    ensure_wallet "${payee}" || fail "could not create ${payee}" || return 1
    wsettings_own "${payee}" && wsettings_own "${E1_PAYER}" || fail "could not copy the settings" || return 1
    e1_one_mailbox_down_run "${payee}" "${down}" || rc=1
    wsettings_reset "${payee}"
    wsettings_reset "${E1_PAYER}"
    return "${rc}"
}

e1_one_mailbox_down_run() {
    local payee="$1" down="$2" pay slate list
    local hosts=("${E2E_RELAY}" "${E2E_RELAY2}" "${down}") name
    for name in "${payee}" "${E1_PAYER}"; do
        e1_set_mailboxes "${name}" "${down} ${E2E_RELAY2}" "${hosts[@]}" || return 1
    done
    list="$(w "${payee}" mailbox list)" || return 1
    printf '%s\n' "${list}" >"${CASE_DIR}/payee-mailboxes.json"
    expect_json "${list}" "[.mailboxes[] | select(.host == \"${down}\" and .origin == \"added\")] | length == 1" "the down mailbox is listed as added" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "$(w "${payee}" epic1 address | jq -r .address)" 0.01 --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "epic1 pay failed with one mailbox down" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay.json"
    expect_json "${pay}" '.posted_ok == true' "the payment was posted" || return 1
    # The report lists the relays that took a post: the down mailbox is not among them.
    expect_json "${pay}" "[.attempts[].host | sub(\":443$\"; \"\")] | sort == ([\"${E2E_RELAY}\", \"${E2E_RELAY2}\"] | sort)" "posts were taken by the two relays that answer, not by the down mailbox" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${payee}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" "${payee}" || return 1
    # Health never drops a mailbox: after the run the down one is still listed.
    expect_json "$(w "${payee}" mailbox list)" "[.mailboxes[].host] | length == 3 and index(\"${down}\") != null" "all three mailboxes still listed after the run" || return 1
    note "one of three mailboxes down: the two relays took the post, the payee took the payment"
}

# A payer whose list holds none of the shipped mailboxes shares none with the payee: epic1 pay
# exits 14, `no_shared_mailbox`, and stores nothing; --mailbox with the payee's host makes the
# payment go. The payer's own settings are removed afterwards.
case_e1_no_shared() {
    local rc=0
    e1_setup || return 1
    wsettings_own "${E1_PAYER}" || fail "could not copy the settings" || return 1
    e1_no_shared_run || rc=1
    wsettings_reset "${E1_PAYER}"
    return "${rc}"
}

e1_no_shared_run() {
    local addr pay slate before
    # The list becomes the second relay alone: add it, then take the shipped ones off.
    e1_set_mailboxes "${E1_PAYER}" "${E2E_RELAY2}" "${E2E_RELAY2}" || return 1
    addr="$(w "${E1_PAYEE}" epic1 address | jq -r .address)" || fail "epic1 address failed" || return 1
    w "${E1_PAYER}" wallet info >/dev/null || return 1
    before="$(usable_units "${E1_PAYER}")" || return 1
    wx 14 "${E1_PAYER}" epic1 pay "${addr}" 0.01 --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100 || return 1
    printf '%s\n' "${LAST_JSON}" >"${CASE_DIR}/refused.json"
    expect_json "${LAST_JSON}" '.error.kind == "no_shared_mailbox"' "exit 14 names no_shared_mailbox" || return 1
    expect_eq "$(usable_units "${E1_PAYER}")" "${before}" "nothing was stored or locked by the refused payment" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${addr}" 0.01 --mailbox "${E2E_RELAY}" --min-confirmations "${E2E_MINCONF}" --ttl-blocks 100)" || fail "epic1 pay --mailbox ${E2E_RELAY} failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay.json"
    expect_json "${pay}" '.posted_ok == true and (.attempts | length) == 1' "posted to the payee's mailbox only" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    # The answer waits on the payee's mailbox; with the payer's own list restored its collect takes it.
    wsettings_reset "${E1_PAYER}"
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" "${E1_PAYEE}" || return 1
    note "payer sharing no mailbox: exit 14, then --mailbox ${E2E_RELAY} paid and was taken"
}

# A payee that signs no payment proof: a LEPIC release from before proofs. LEPIC_E2E_OLD_LEPIC
# names its binary; unset, the old-payee half of epic1.proof is left out and noted.
E1_OLD_LEPIC="${LEPIC_E2E_OLD_LEPIC:-}"
E1_OLD_PAYEE="${E2E_PREFIX}-link-oldpayee"

# `w` on the old payee, with the old binary. The release build is on mainnet unless told.
e1_old() { LEPIC_BIN="${E1_OLD_LEPIC}" w "${E1_OLD_PAYEE}" "$@"; }

# One collect on the old payee and one on the payer; true once the payer's tx of `slate` is in
# a state of `states`. The payer's collect may fail when it refuses an answer.
e1_old_round() {
    e1_old contact collect >/dev/null 2>&1 || true
    w "${E1_PAYER}" contact collect >/dev/null 2>&1 || true
    slate_state_in "${E1_PAYER}" "$1" "$2"
}

# A payment that requires a proof leaves one that verifies, on chain too; a changed one fails.
# A payee that does not sign leaves none, and a payer that requires one refuses its answer.
case_e1_proof() {
    local addr pay slate tx file checked old_addr before after
    e1_setup || return 1
    addr="$(w "${E1_PAYEE}" epic1 address | jq -r .address)" || fail "epic1 address failed" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${addr}" 0.02 --require-proof --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay --require-proof failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay.json"
    slate="$(jq -r .slate_id <<<"${pay}")"
    tx="$(jq -r .tx_id <<<"${pay}")"
    e1_collect_until "${E1_PAYEE}" "${slate}" "pending_confirmation received finalized confirmed" || return 1
    e1_collect_until "${E1_PAYER}" "${slate}" "posted confirmed" || return 1
    file="${CASE_DIR}/proof.json"
    w "${E1_PAYER}" proof export "${tx}" --out "${file}" >/dev/null || fail "proof export failed" || return 1
    checked="$(w "${E1_PAYER}" proof verify "${file}")" || fail "proof verify failed" || return 1
    printf '%s\n' "${checked}" >"${CASE_DIR}/verify.json"
    expect_json "${checked}" ".valid == true and .amount == 2000000 and .address == \"${addr}\" and .slate_id == \"${slate}\"" "proof verifies" || return 1
    jq -c '.amount += 1' "${file}" >"${CASE_DIR}/tampered.json"
    wx 7 "${E1_PAYER}" proof verify "${CASE_DIR}/tampered.json" || return 1
    expect_json "${LAST_JSON}" '.error.kind == "rejected" and (.error.message | test("signature"))' "a changed amount fails" || return 1
    e1_confirmed "${E1_PAYER}" "${slate}" || return 1
    checked="$(w "${E1_PAYER}" proof verify "${file}" --on-chain)" || fail "proof verify --on-chain failed" || return 1
    printf '%s\n' "${checked}" >"${CASE_DIR}/verify-on-chain.json"
    expect_json "${checked}" '.on_chain == true and (.height | type == "number")' "the kernel is on chain" || return 1
    note "proof verified, on chain at $(jq -r .height <<<"${checked}"); a changed amount fails"

    if [[ -z "${E1_OLD_LEPIC}" ]]; then
        note "old payee left out: LEPIC_E2E_OLD_LEPIC is not set"
        return 0
    fi
    [[ -x "${E1_OLD_LEPIC}" ]] || fail "no binary at ${E1_OLD_LEPIC}" || return 1
    [[ -f "${E2E_STATE}/wallets/${E1_OLD_PAYEE}.toml" ]] || wconfig_set "${E1_OLD_PAYEE}" 'network = "floonet"'
    LEPIC_BIN="${E1_OLD_LEPIC}" ensure_wallet "${E1_OLD_PAYEE}" || fail "could not create ${E1_OLD_PAYEE}" || return 1
    old_addr="$(e1_old epic1 address | jq -r .address)" || fail "old payee: epic1 address failed" || return 1

    # Not required: the payment goes through with no proof.
    pay="$(w "${E1_PAYER}" epic1 pay "${old_addr}" 0.01 --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay to the old payee failed" || return 1
    slate="$(jq -r .slate_id <<<"${pay}")"
    tx="$(jq -r .tx_id <<<"${pay}")"
    wait_until "the payer to finalize ${slate}" 120 e1_old_round "${slate}" "posted confirmed" || fail "the payer never finalized ${slate}" || return 1
    wx 6 "${E1_PAYER}" proof export "${tx}" || return 1
    expect_json "${LAST_JSON}" '.error.kind == "not_found"' "no proof from an old payee" || return 1

    # Required: the answer without a proof is refused and the payment cancelled. The miner moves
    # the chain, so usable funds grow as change confirms; the locked amount is what the refused
    # payment would hold, once the payment above is confirmed and holds nothing.
    e1_confirmed "${E1_PAYER}" "${slate}" || return 1
    before="$(w "${E1_PAYER}" wallet info | jq -r '.accounts[0].locked')" || return 1
    pay="$(w "${E1_PAYER}" epic1 pay "${old_addr}" 0.01 --require-proof --min-confirmations "${E2E_MINCONF}" --ttl-blocks 200)" || fail "epic1 pay --require-proof to the old payee failed" || return 1
    printf '%s\n' "${pay}" >"${CASE_DIR}/pay-required.json"
    slate="$(jq -r .slate_id <<<"${pay}")"
    wait_until "the payer to refuse ${slate}" 120 e1_old_round "${slate}" "cancelled" || fail "the payer never refused ${slate} (now $(tx_by_slate "${E1_PAYER}" "${slate}" | jq -r ".state // \"none\""))" || return 1
    after="$(w "${E1_PAYER}" wallet info | jq -r '.accounts[0].locked')" || return 1
    expect_eq "${after}" "${before}" "payer's locked amount after the refusal" || return 1
    note "old payee: no proof to export; with --require-proof the answer is refused and cancelled"
}
