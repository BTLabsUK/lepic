# SPDX-License-Identifier: Apache-2.0
# The EPICTX steps of the acceptance run: payments to paired contacts, sealed files, in-person
# codes and epic1 request links, between the service's lepic wallet and the payer's, which are the only
# two wallets that speak them. Sourced by steps.sh; the steps run after the others and use
# their helpers.
# shellcheck shell=bash disable=SC2034 # DETAIL and the shared state are read by run.sh

NATIVE_DIR=""
# What the payer's balance must be, as EXPECTED_TOTAL tracks lepic's.
PAYER_TOTAL=0
# Both wallets' balances when a step began.
L0=0
P0=0
# Pairings: NC_L and NC_P are lepic's and the payer's ids of the first pairing, MX_L and MX_P of
# the second.
NC_L=""
NC_P=""
MX_L=""
MX_P=""
PAIR_L=""
PAIR_P=""
# lepic's transaction id and the payer's for a slate id; empty when a side has none.
side_tx() { "$1" tx list | jq -r --arg id "$2" '[.transactions[] | select(.slate_id == $id) | .tx_id] | first // empty'; }

tx_field() { "$1" tx show "$2" | jq -r --arg field "$3" '.[$field] // empty'; }

tx_fee() {
    local fee
    fee="$(tx_field "$1" "$2" fee)"
    to_units "${fee:-0}"
}

# True when the transaction of `who` is in one of the given states.
tx_state_in() {
    local who="$1" tx="$2" state want
    shift 2
    state="$("${who}" tx show "${tx}" | jq -r .state)" || return 1
    for want in "$@"; do
        [[ "${state}" == "${want}" ]] && return 0
    done
    return 1
}

contact_state() {
    "$1" contact list | jq -r --arg id "$2" '.contacts[] | select(.contact_id == $id) | .state'
}

# Both wallets hold nothing locked or waiting for confirmations.
wallets_settled() {
    local who
    for who in lepic payer; do
        "${who}" wallet info | jq -e '.accounts[0] | .total == .spendable' >/dev/null || return 1
    done
}

balances_are() { [[ "$(lepic_balance total)" == "$1" && "$(payer_balance total)" == "$2" ]]; }

# Starts a step: both wallets settled, and at the balances the earlier steps left.
native_ready() {
    wait_until "both wallets settled" 180 wallets_settled || fail "the wallets did not settle" || return 1
    L0="$(lepic_balance total)"
    P0="$(payer_balance total)"
    ((L0 == EXPECTED_TOTAL && P0 == PAYER_TOTAL)) ||
        fail "balances moved between steps: lepic ${L0} (expected ${EXPECTED_TOTAL}), payer ${P0} (expected ${PAYER_TOTAL})" ||
        return 1
}

# Waits for both wallets to show these totals, which then become the ones tracked.
expect_totals() {
    wait_until "lepic ${1} and payer ${2}" 60 balances_are "$1" "$2" ||
        fail "lepic holds $(lepic_balance total), expected ${1}; payer $(payer_balance total), expected ${2}" ||
        return 1
    EXPECTED_TOTAL="$1"
    PAYER_TOTAL="$2"
}

# After one payment of `amount` units and `fee` units from `lepic` or `payer` to the other.
expect_transfer() {
    if [[ "$1" == lepic ]]; then
        expect_totals $((L0 - $2 - $3)) $((P0 + $2))
    else
        expect_totals $((L0 + $2)) $((P0 - $2 - $3))
    fi
}

# Waits until both wallets show the payment of a slate confirmed, with one kernel excess.
confirm_pair() {
    local slate_id="$1" ltx ptx lk pk
    ltx="$(side_tx lepic "${slate_id}")"
    ptx="$(side_tx payer "${slate_id}")"
    [[ -n "${ltx}" && -n "${ptx}" ]] ||
        fail "slate ${slate_id} is in lepic as '${ltx}' and in the payer as '${ptx}'" || return 1
    wait_until "lepic tx ${ltx} confirmed" 180 lepic_tx_confirmed "${ltx}" ||
        fail "lepic tx ${ltx} is $(lepic_tx_state "${ltx}"), not confirmed" || return 1
    wait_until "payer tx ${ptx} confirmed" 180 payer_tx_confirmed "${ptx}" ||
        fail "the payer's tx ${ptx} is $(payer tx show "${ptx}" | jq -r .state), not confirmed" || return 1
    lk="$(tx_field lepic "${ltx}" kernel_excess)"
    pk="$(tx_field payer "${ptx}" kernel_excess)"
    # The receiver of an S1 answers S2 and never sees the finalized slate, so its record
    # carries no kernel; receiver_blank accepts that for the payer wallet, never a mismatch.
    if [[ "${2:-}" == receiver_blank && -z "${pk}" ]]; then
        [[ -n "${lk}" ]] || fail "lepic has no kernel excess for ${slate_id}" || return 1
        return 0
    fi
    # either_blank: the receiver is lepic or the payer, and only one side may lack the kernel.
    if [[ "${2:-}" == either_blank && ( -z "${lk}" || -z "${pk}" ) ]]; then
        [[ -n "${lk}${pk}" ]] || fail "neither wallet has a kernel excess for ${slate_id}" || return 1
        return 0
    fi
    [[ -n "${lk}" && "${lk}" == "${pk}" ]] ||
        fail "kernel excess differs for ${slate_id}: lepic '${lk}', payer '${pk}'" || return 1
}

# Collects the contact mailboxes of the payer and of lepic in turn until a check holds, for at
# most `timeout` seconds.
collect_both() {
    local timeout="$1" check="$2" deadline
    deadline=$((SECONDS + timeout))
    while :; do
        payer contact collect >/dev/null || return 1
        lepic contact collect >/dev/null || return 1
        eval "${check}" && return 0
        ((SECONDS < deadline)) || return 1
        sleep 2
    done
}

# Pairs lepic, which invites, with the payer, which accepts. Sets PAIR_L and PAIR_P.
native_pair() {
    local name="$1" invite link accepted
    invite="$(lepic contact invite --name "${name} service")" || fail "contact invite failed" || return 1
    link="$(jq -r .link <<<"${invite}")"
    PAIR_L="$(jq -r .contact_id <<<"${invite}")"
    accepted="$(payer contact accept "${link}" --name "${name} payer")" ||
        fail "contact accept failed" || return 1
    PAIR_P="$(jq -r .contact_id <<<"${accepted}")"
    collect_both 60 '[[ "$(contact_state lepic "${PAIR_L}")" == paired && "$(contact_state payer "${PAIR_P}")" == paired ]]' ||
        fail "the ${name} pairing never completed: $(lepic contact list) $(payer contact list)" || return 1
    lepic contact sas "${PAIR_L}" match >/dev/null || fail "lepic's words check failed" || return 1
    payer contact sas "${PAIR_P}" match >/dev/null || fail "the payer's words check failed" || return 1
}

# Two pairings made over the relay.
step_native_setup() {
    NATIVE_DIR="${STATE_DIR}/native"
    mkdir -p "${NATIVE_DIR}"
    native_pair "Native" || return 1
    NC_L="${PAIR_L}"
    NC_P="${PAIR_P}"
    native_pair "Mixed" || return 1
    MX_L="${PAIR_L}"
    MX_P="${PAIR_P}"
    check_lepic_total || return 1
    PAYER_TOTAL="$(payer_balance total)"
    DETAIL="paired twice by invite, words matched (${NC_L}, ${MX_L})"
}

# 2. A contact payment through the mailboxes: the payment goes as V3 and the payer answers it, so
# it is finalized, posted and confirmed.
native_mixed_contact() {
    native_ready || return 1
    local sent slate_id
    sent="$(lepic tx send 0.2 --to-contact "${MX_L}")" || fail "the contact payment failed: ${sent}" || return 1
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    collect_both 120 '[[ -n "$(side_tx payer "${slate_id}")" ]] && tx_state_in lepic "$(side_tx lepic "${slate_id}")" posted confirmed' ||
        fail "the payment never completed: lepic tx is $(lepic_tx_by_slate "${slate_id}")" || return 1
    confirm_pair "${slate_id}" receiver_blank || return 1
    expect_transfer lepic "$(to_units 0.2)" "$(tx_fee lepic "$(side_tx lepic "${slate_id}")")" || return 1
    DETAIL="paid through the mailboxes and answered by the payer; ${slate_id} posted, confirmed"
}

# The first line of a sealed file.
sealed_header() { head -n 1 "$1"; }

# Seals a fresh send to a contact into a file and prints its tx id on stdout.
native_seal() {
    local contact="$1" file="$2" amount="$3" sent tx_id
    sent="$(lepic tx send "${amount}" --to-file "${file}.slate")" || return 1
    tx_id="$(jq -r .tx_id <<<"${sent}")"
    lepic contact seal "${contact}" "${tx_id}" --out "${file}" >/dev/null || return 1
    echo "${tx_id}"
}

# 3. A payment by file between contacts: the V3 sealed text, which the payer opens and answers.
native_epictx_files() {
    native_ready || return 1
    local opened
    local v3_tx mixed_tx v3_file="${NATIVE_DIR}/off.epicsealed" mixed_file="${NATIVE_DIR}/mixed.epicsealed"
    v3_tx="$(native_seal "${NC_L}" "${v3_file}" 0.1)" ||
        fail "sealing the first file failed" || return 1
    [[ "$(sealed_header "${v3_file}")" == BEGINEPICSEALED.* ]] ||
        fail "the first file starts $(sealed_header "${v3_file}")" || return 1
    lepic tx cancel "${v3_tx}" >/dev/null || fail "tx cancel failed" || return 1
    mixed_tx="$(native_seal "${MX_L}" "${mixed_file}" 0.15)" ||
        fail "sealing for the mixed contact failed" || return 1
    [[ "$(sealed_header "${mixed_file}")" == BEGINEPICSEALED.* ]] ||
        fail "the file for the mixed contact starts $(sealed_header "${mixed_file}")" || return 1
    opened="$(payer epictx open "${mixed_file}")" || fail "the payer's epictx open of the V3 file failed" || return 1
    jq -e '.native == false' <<<"${opened}" >/dev/null ||
        fail "epictx open of the V3 file: ${opened}" || return 1
    payer contact open-sealed "${mixed_file}" --answer-file "${mixed_file}.reply" >/dev/null ||
        fail "the payer could not open the V3 file" || return 1
    lepic contact open-sealed "${mixed_file}.reply" >/dev/null || fail "lepic could not open the V3 answer" || return 1
    local mixed_slate
    mixed_slate="$(lepic tx show "${mixed_tx}" | jq -r .slate_id)"
    if tx_state_in lepic "${mixed_tx}" finalized; then
        lepic tx post "${mixed_tx}" >/dev/null || fail "tx post failed" || return 1
    fi
    confirm_pair "${mixed_slate}" receiver_blank || return 1
    expect_transfer lepic "$(to_units 0.15)" "$(tx_fee lepic "${mixed_tx}")" || return 1
    DETAIL="V3 sealed form to both contacts, the second one paid and answered by the payer, ${mixed_slate}"
}

# One offline in-person exchange: lepic shows a code, the payer answers it, lepic takes the
# answer and finalizes. $1 invoice|send, $2 amount in EPIC. The payer pays an invoice, lepic
# sends in a send. The code's TTL is 120 blocks: the default 15 pass in under a minute on this chain.
in_person_exchange() {
    local direction="$1" amount="$2" flags=(--offline) code answer shown read paid
    code="${NATIVE_DIR}/ip-${direction}.code"
    answer="${NATIVE_DIR}/ip-${direction}.answer"
    native_ready || return 1
    if [[ "${direction}" == invoice ]]; then
        shown="$(lepic in-person invoice "${amount}" --ttl-blocks 120 --out "${code}" "${flags[@]}")"
    else
        shown="$(lepic in-person send "${amount}" --ttl-blocks 120 --out "${code}" "${flags[@]}")"
    fi || fail "in-person ${direction} failed" || return 1
    local slate_id lepic_tx
    slate_id="$(jq -r .slate_id <<<"${shown}")"
    lepic_tx="$(jq -r .tx_id <<<"${shown}")"
    [[ -s "${code}" ]] || fail "no code file: ${shown}" || return 1
    read="$(payer in-person read --file "${code}" "${flags[@]}")" || fail "in-person read failed" || return 1
    jq -e --arg amount "$(from_units "$(to_units "${amount}")")" '.amount == $amount' <<<"${read}" >/dev/null ||
        fail "in-person read shows another amount: ${read}" || return 1
    jq -e '.mailbox == null' <<<"${read}" >/dev/null || fail "an offline code names a mailbox: ${read}" || return 1
    if [[ "${direction}" == invoice ]]; then
        paid="$(payer in-person pay "${amount}" --file "${code}" --out "${answer}" "${flags[@]}")"
    else
        paid="$(payer in-person receive --file "${code}" --out "${answer}" "${flags[@]}")"
    fi || fail "the payer's in-person ${direction} answer failed" || return 1
    local check_code payer_tx taken
    payer_tx="$(jq -r .tx_id <<<"${paid}")"
    # The answering side shows its check code only once it posts; this answer is shown back.
    jq -e '.check_code == null' <<<"${paid}" >/dev/null || fail "a check code before posting: ${paid}" || return 1
    taken="$(lepic in-person take --file "${answer}" --offline)" || fail "in-person take failed" || return 1
    check_code="$(jq -r .check_code <<<"${taken}")"
    [[ "${check_code}" =~ ^[0-9]{4}$ ]] || fail "the check code is '${check_code}': ${taken}" || return 1
    local answers
    answers="$(lepic in-person answers "${slate_id}" "${flags[@]}")" || fail "in-person answers failed" || return 1
    jq -e --arg code "${check_code}" '(.answers | length) == 1 and .answers[0].check_code == $code' <<<"${answers}" >/dev/null ||
        fail "answers ${answers}, the answer taken had check code ${check_code}" || return 1
    # Nothing is finalized, or posted, until the finalize command.
    if tx_state_in lepic "${lepic_tx}" finalized posted confirmed; then
        fail "tx ${lepic_tx} is $(lepic_tx_state "${lepic_tx}") before in-person finalize" || return 1
    fi
    lepic in-person finalize "${slate_id}" 1 "${flags[@]}" >/dev/null || fail "in-person finalize failed" || return 1
    confirm_pair "${slate_id}" receiver_blank || return 1
    if [[ "${direction}" == invoice ]]; then
        expect_transfer payer "$(to_units "${amount}")" "$(tx_fee payer "${payer_tx}")"
    else
        expect_transfer lepic "$(to_units "${amount}")" "$(tx_fee lepic "${lepic_tx}")"
    fi || return 1
    IN_PERSON_DETAIL="${slate_id} check code ${check_code}, nothing finalized before the finalize command, then posted and confirmed"
}

# 4. An invoice code, offline.
native_in_person_invoice() {
    in_person_exchange invoice 0.3 || return 1
    DETAIL="invoice code offline: ${IN_PERSON_DETAIL}"
}

# 5. A send code, offline.
native_in_person_send() {
    in_person_exchange send 0.3 || return 1
    DETAIL="send code offline: ${IN_PERSON_DETAIL}"
}

# 6. An online code names a reply mailbox on the payee's own relay. A relay on the same device
# cannot be reached from the payer's, so the local stack's relay gets no mailbox: the code is
# made for an offline exchange and the answer is shown back.
native_in_person_post() {
    native_ready || return 1
    local shown code="${NATIVE_DIR}/online.code" read
    shown="$(lepic in-person invoice 0.2 --out "${code}")" || fail "the online code failed: ${shown}" || return 1
    jq -e '.mailbox == null' <<<"${shown}" >/dev/null || fail "the code names a mailbox on a local relay: ${shown}" || return 1
    [[ -s "${code}" ]] || fail "no code file: ${shown}" || return 1
    read="$(payer in-person read --file "${code}" --offline)" || fail "the payer could not read the code" || return 1
    jq -e '.mailbox == null' <<<"${read}" >/dev/null || fail "the payer's read shows a mailbox: ${read}" || return 1
    lepic tx cancel "$(jq -r .tx_id <<<"${shown}")" >/dev/null || fail "tx cancel failed" || return 1
    lepic_unlocked || fail "the code locked $(lepic_locked) units" || return 1
    DETAIL="online code with the relay on this device names no mailbox; the payer reads it, the answer is shown back and taken by hand as in step 4; the reply mailbox flow, invoice and send, was run on floonet against wss://epicbox.btlabs.uk"
}

# 7. A TTL of the margin or less is refused; a code past its TTL is not paid or answered, and an
# unanswered send code expires.
native_in_person_ttl() {
    native_ready || return 1
    local shown cutoff status code="${NATIVE_DIR}/ttl-invoice.code" send_code="${NATIVE_DIR}/ttl-send.code"
    local payer_count
    payer_count="$(payer tx list | jq '.transactions | length')"
    # A TTL of the 10-block margin or less is refused as a usage error; 11 is the shortest.
    local short_invoice short_send
    short_invoice="$(lepic_status in-person invoice 0.2 --ttl-blocks 10 --offline --out "${code}")"
    short_send="$(lepic_status in-person send 0.2 --ttl-blocks 10 --offline --out "${send_code}")"
    ((short_invoice == 2 && short_send == 2)) ||
        fail "a 10-block TTL: invoice exited ${short_invoice} and send ${short_send}, not 2 (usage)" || return 1
    shown="$(lepic in-person invoice 0.2 --ttl-blocks 11 --offline --out "${code}")" ||
        fail "in-person invoice with a TTL failed" || return 1
    cutoff="$(jq -r .ttl_cutoff <<<"${shown}")"
    local send_tx
    shown="$(lepic in-person send 0.2 --ttl-blocks 11 --offline --out "${send_code}")" ||
        fail "in-person send with a TTL failed" || return 1
    send_tx="$(jq -r .tx_id <<<"${shown}")"
    local send_cutoff
    send_cutoff="$(jq -r .ttl_cutoff <<<"${shown}")"
    (($(lepic_locked) > 0)) || fail "the send code locked nothing" || return 1
    # The stack mines a block every few seconds.
    wait_until "the chain past ${send_cutoff}" 300 node_past "${cutoff}" "${send_cutoff}" ||
        fail "the chain did not pass the TTL cutoff" || return 1
    local read_status=0 pay_status receive_status read_out
    read_out="$(payer in-person read --file "${code}" --offline)" || read_status=$?
    pay_status="$(payer_status in-person pay 0.2 --file "${code}" --offline)"
    receive_status="$(payer_status in-person receive --file "${send_code}" --offline)"
    ((pay_status == 7 && receive_status == 7)) ||
        fail "past the TTL, pay exited ${pay_status} and receive ${receive_status}, not 7 (rejected)" || return 1
    # Reading only shows the code, and its cutoff is the one the payee was told.
    ((read_status == 0)) && jq -e --argjson cutoff "${cutoff}" '.ttl_cutoff == $cutoff' <<<"${read_out}" >/dev/null ||
        fail "past the TTL, read exited ${read_status}: ${read_out}" || return 1
    [[ "$(payer tx list | jq '.transactions | length')" == "${payer_count}" ]] ||
        fail "a refused code left a transaction in the payer's wallet" || return 1
    # A refresh expires the send once the chain is past its TTL; `tx show` only reads.
    wait_until "the send code to expire" 120 refreshed_tx_state_in lepic "${send_tx}" cancelled expired ||
        fail "the unanswered send is $(lepic_tx_state "${send_tx}")" || return 1
    wait_until "the inputs unlocked" 60 lepic_unlocked || fail "the expired send left $(lepic_locked) units locked" || return 1
    expect_totals "${L0}" "${P0}" || return 1
    DETAIL="10-block TTL refused (2) for invoice and send; past TTL ${send_cutoff}: read shows cutoff ${cutoff}, pay exited ${pay_status}, receive ${receive_status}, nothing stored; the unanswered send is $(lepic_tx_state "${send_tx}"), inputs unlocked, balance back"
}

# Like tx_state_in, after a refresh from the node.
refreshed_tx_state_in() {
    "$1" wallet info >/dev/null || return 1
    tx_state_in "$@"
}

lepic_unlocked() { (($(lepic_locked) == 0)); }

# True when the chain is past both heights.
node_past() { (($(tip_height) > $1 && $(tip_height) > $2)); }

# 8. An epic1 link is paid on the relays of the payer's mailbox list. With local_mailbox the
# stack's relay is the whole list, so the payment goes through it: lepic answers it on collect and
# the payer finalizes and posts it.
native_epic1() {
    native_ready || return 1
    local issued link out slate_id ptx
    issued="$(lepic epic1 link 0.3)" || fail "epic1 link failed: ${issued}" || return 1
    link="$(jq -r .link <<<"${issued}")"
    out="$(payer epic1 pay "${link}" 0.3)" || fail "the epic1 payment failed: ${out}" || return 1
    jq -e '.posted_ok == true and ([.attempts[].host] | any(startswith("localhost:") or startswith("127.0.0.1:")))' <<<"${out}" >/dev/null ||
        fail "the epic1 payment did not go through the relay on this device: ${out}" || return 1
    slate_id="$(jq -r .slate_id <<<"${out}")"
    collect_both 120 '[[ -n "$(side_tx lepic "${slate_id}")" ]] && tx_state_in payer "$(side_tx payer "${slate_id}")" posted confirmed' ||
        fail "the payment never completed: the payer's tx is $(payer tx show "$(side_tx payer "${slate_id}")" | jq -r .state)" || return 1
    confirm_pair "${slate_id}" either_blank || return 1
    ptx="$(side_tx payer "${slate_id}")"
    expect_transfer payer "$(to_units 0.3)" "$(tx_fee payer "${ptx}")" || return 1
    DETAIL="epic1 payment through the relay on this device, answered by lepic, finalized by the payer; ${slate_id} posted, confirmed"
}

# 10. A payment cancelled before it is finalized, as a contact payment and as an in-person
# send, frees its inputs on both sides.
native_cancel() {
    native_ready || return 1
    local sent slate_id ltx ptx
    sent="$(lepic tx send 0.2 --to-contact "${NC_L}")" || fail "the contact payment failed: ${sent}" || return 1
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    ltx="$(jq -r .tx_id <<<"${sent}")"
    wait_until "the payer to take the payment" 90 payer_took "${slate_id}" ||
        fail "the payer's collect never took the payment" || return 1
    ptx="$(side_tx payer "${slate_id}")"
    payer tx cancel "${ptx}" >/dev/null || fail "the payer's tx cancel failed" || return 1
    lepic tx cancel "${ltx}" >/dev/null || fail "lepic's tx cancel failed" || return 1
    # A late answer does not bring the cancelled payment back.
    lepic contact collect >/dev/null || fail "lepic's collect failed" || return 1
    [[ "$(lepic_tx_state "${ltx}")" == cancelled && "$(payer tx show "${ptx}" | jq -r .state)" == cancelled ]] ||
        fail "after the cancel lepic's tx is $(lepic_tx_state "${ltx}"), the payer's $(payer tx show "${ptx}" | jq -r .state)" ||
        return 1
    wait_until "both wallets unlocked" 60 both_unlocked || fail "the cancel left funds locked" || return 1
    expect_totals "${L0}" "${P0}" || return 1

    local shown code="${NATIVE_DIR}/cancel.code" answer="${NATIVE_DIR}/cancel.answer" received
    shown="$(lepic in-person send 0.2 --offline --out "${code}")" || fail "in-person send failed" || return 1
    ltx="$(jq -r .tx_id <<<"${shown}")"
    received="$(payer in-person receive --file "${code}" --offline --out "${answer}")" ||
        fail "in-person receive failed" || return 1
    ptx="$(jq -r .tx_id <<<"${received}")"
    (($(lepic_locked) > 0)) || fail "the send code locked nothing" || return 1
    payer tx cancel "${ptx}" >/dev/null || fail "the payer's tx cancel failed" || return 1
    lepic tx cancel "${ltx}" >/dev/null || fail "lepic's tx cancel failed" || return 1
    wait_until "both wallets unlocked" 60 both_unlocked || fail "the in-person cancel left funds locked" || return 1
    expect_totals "${L0}" "${P0}" || return 1
    DETAIL="a contact payment and an in-person send each cancelled on both sides before finalizing; nothing locked, balances back"
}

both_unlocked() { (($(lepic_locked) == 0)) && (($(to_units "$(payer wallet info | jq -r '.accounts[0].locked')") == 0)); }

# True once the payer's collect has taken the payment of a slate into its wallet.
payer_took() {
    payer contact collect >/dev/null || return 1
    [[ -n "$(side_tx payer "$1")" ]]
}

step_native_mixed_contact() { native_mixed_contact; }
step_native_epictx_files() { native_epictx_files; }
step_native_in_person_invoice() { native_in_person_invoice; }
step_native_in_person_send() { native_in_person_send; }
step_native_in_person_post() { native_in_person_post; }
step_native_in_person_ttl() { native_in_person_ttl; }
step_native_epic1() { native_epic1; }
step_native_cancel() { native_cancel; }

NATIVE_STEPS=(
    "native wallets, pairings:step_native_setup"
    "native contact that did not claim native:step_native_mixed_contact"
    "native .epictx files between contacts:step_native_epictx_files"
    "native in person invoice, offline:step_native_in_person_invoice"
    "native in person send, offline:step_native_in_person_send"
    "native in person through the reply mailbox:step_native_in_person_post"
    "native in person TTL:step_native_in_person_ttl"
    "native epic1 payment:step_native_epic1"
    "native cancel before finalize:step_native_cancel"
)
