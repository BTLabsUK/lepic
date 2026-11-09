# SPDX-License-Identifier: Apache-2.0
# The EPICTX steps of the acceptance run: native `lepic.v1` slates to paired contacts and to
# Epicbox payments addresses, `.epictx` files, in-person codes, epic1 links and the direct HTTP
# endpoint, between the service's lepic wallet and the payer's, which are the only two wallets
# that speak them. Sourced by steps.sh; the steps run after the others and use their helpers.
# shellcheck shell=bash disable=SC2034 # DETAIL and the shared state are read by run.sh

# The direct HTTP step reaches its listener at the docker0 address of this host, a private
# address that the product accepts for a direct send where it refuses loopback. The listener
# binds loopback only, so a small forwarder on that address stands in front of it.
NATIVE_HOST=172.17.0.1
NATIVE_HTTP_PORT=23511

NATIVE_DIR=""
# What the payer's balance must be, as EXPECTED_TOTAL tracks lepic's.
PAYER_TOTAL=0
# Both wallets' balances when a step began.
L0=0
P0=0
# Pairings: NC_L and NC_P are lepic's and the payer's ids of the pairing made with native_direct
# on in both wallets, MX_L and MX_P of the pairing the payer made with it off.
NC_L=""
NC_P=""
MX_L=""
MX_P=""
PAIR_L=""
PAIR_P=""
# The background lepic of a step, its log file prefix, and the HTTP forwarder.
NATIVE_PID=""
NATIVE_LOG=""
NATIVE_FWD=""

# A third wallet, the listener the HTTP step swaps in for the payer.
third() { lepic --data-dir "${STATE_DIR}/third" "$@"; }

# Runs a step with native_direct on in both wallets and stops what it left running.
native_scope() {
    local status=0
    NATIVE_DIRECT=true
    "$1" || status=$?
    native_cleanup
    NATIVE_DIRECT=""
    return "${status}"
}

# Starts lepic for a data directory in the background, its output in `prefix`.out and .err.
# Started without the lepic_env function, so $! is lepic itself and the Ctrl-C reaches it.
native_bg() {
    local dir="$1" prefix="$2"
    shift 2
    env -i PATH="${PATH}" HOME="${STATE_DIR}/home" LEPIC_CONFIG="${STATE_DIR}/config.toml" \
        LEPIC_PASSWORD="${LEPIC_PASSWORD_VALUE}" ${NATIVE_DIRECT:+LEPIC_NATIVE_DIRECT="${NATIVE_DIRECT}"} \
        "${LEPIC_BIN}" --data-dir "${dir}" "$@" >"${prefix}.out" 2>"${prefix}.err" </dev/null &
}

native_stop() {
    local pid="$1" prefix="$2"
    kill -INT "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    cat "${prefix}.err" >>"${RUN_LOG}"
}

native_stop_listener() {
    [[ -z "${NATIVE_PID}" ]] || native_stop "${NATIVE_PID}" "${NATIVE_LOG}"
    NATIVE_PID=""
}

native_cleanup() {
    native_stop_listener
    if [[ -n "${NATIVE_FWD}" ]]; then
        kill "${NATIVE_FWD}" 2>/dev/null || true
        wait "${NATIVE_FWD}" 2>/dev/null || true
        NATIVE_FWD=""
    fi
}

native_tcp_open() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null; }

# The `epicbox listen` of a wallet, waiting until it is connected. It holds the wallet's data
# directory, so the wallet answers no other command until native_stop_listener.
native_epicbox_listen() {
    native_stop_listener
    NATIVE_LOG="$2"
    native_bg "$1" "${NATIVE_LOG}" epicbox listen
    NATIVE_PID=$!
    wait_until "the listener connected" 30 grep -q "connected to the relay" "${NATIVE_LOG}.err"
}

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
    [[ -n "${lk}" && "${lk}" == "${pk}" ]] ||
        fail "kernel excess differs for ${slate_id}: lepic '${lk}', payer '${pk}'" || return 1
}

# Collects the contact mailboxes of the payer and of lepic in turn until a check holds, for at
# most `timeout` seconds. Each wallet runs with its own switch, PAYER_SWITCH and LEPIC_SWITCH,
# which are native_direct unless a step sets them.
collect_both() {
    local timeout="$1" check="$2" deadline
    deadline=$((SECONDS + timeout))
    while :; do
        NATIVE_DIRECT="${PAYER_SWITCH-${NATIVE_DIRECT}}" payer contact collect >/dev/null || return 1
        NATIVE_DIRECT="${LEPIC_SWITCH-${NATIVE_DIRECT}}" lepic contact collect >/dev/null || return 1
        eval "${check}" && return 0
        ((SECONDS < deadline)) || return 1
        sleep 2
    done
}

# Pairs lepic, which invites with native_direct on, with the payer, which accepts with its switch
# set to $2. Sets PAIR_L and PAIR_P.
native_pair() {
    local name="$1" payer_switch="$2" invite link accepted
    invite="$(lepic contact invite --name "${name} service")" || fail "contact invite failed" || return 1
    link="$(jq -r .link <<<"${invite}")"
    PAIR_L="$(jq -r .contact_id <<<"${invite}")"
    accepted="$(NATIVE_DIRECT="${payer_switch}" payer contact accept "${link}" --name "${name} payer")" ||
        fail "contact accept failed" || return 1
    PAIR_P="$(jq -r .contact_id <<<"${accepted}")"
    local PAYER_SWITCH="${payer_switch}"
    collect_both 60 '[[ "$(contact_state lepic "${PAIR_L}")" == paired && "$(contact_state payer "${PAIR_P}")" == paired ]]' ||
        fail "the ${name} pairing never completed: $(lepic contact list) $(payer contact list)" || return 1
    lepic contact sas "${PAIR_L}" match >/dev/null || fail "lepic's words check failed" || return 1
    payer contact sas "${PAIR_P}" match >/dev/null || fail "the payer's words check failed" || return 1
}

# Two pairings made over the relay: native on both sides, and the payer's with native_direct off.
step_native_setup() {
    NATIVE_DIR="${STATE_DIR}/native"
    mkdir -p "${NATIVE_DIR}"
    NATIVE_DIRECT=true
    native_pair "Native" true || return 1
    NC_L="${PAIR_L}"
    NC_P="${PAIR_P}"
    native_pair "Mixed" "" || return 1
    MX_L="${PAIR_L}"
    MX_P="${PAIR_P}"
    NATIVE_DIRECT=""
    check_lepic_total || return 1
    PAYER_TOTAL="$(payer_balance total)"
    [[ "$(NATIVE_DIRECT=true native_slates_to lepic "${NC_L}")" == true &&
        "$(NATIVE_DIRECT=true native_slates_to payer "${NC_P}")" == true ]] ||
        fail "native_slates is not on in the native pairing: $(lepic contact list)" || return 1
    DETAIL="paired with native on both sides (${NC_L}) and with the payer's switch off (${MX_L})"
}

# 1. Payments to the payer's Epicbox address: the first send is V2/V3, and the payer's answer
# carries the claim that makes the next one native.
native_epicbox() {
    native_ready || return 1
    local payer_address first second third_send
    payer_address="$(payer wallet address | jq -r .address)"
    native_epicbox_listen "${STATE_DIR}/payer" "${NATIVE_DIR}/payer-listen" ||
        fail "the payer's listener did not connect" || return 1
    first="$(lepic tx send 0.3 --to "${payer_address}")" || fail "the first send failed" || return 1
    [[ "$(jq -r .format <<<"${first}")" == legacy ]] || fail "the first send's format is not legacy: ${first}" || return 1
    drain_until finalized 1 120 >/dev/null || fail "lepic finalized nothing after the first send" || return 1
    wait_until "the native claim" 30 jq -e '.native_slates == true' <(lepic epicbox peer "${payer_address}") ||
        fail "epicbox peer shows no native claim: $(lepic epicbox peer "${payer_address}")" || return 1
    second="$(lepic tx send 0.2 --to "${payer_address}")" || fail "the second send failed" || return 1
    [[ "$(jq -r .format <<<"${second}")" == native ]] || fail "the second send's format is not native: ${second}" || return 1
    drain_until finalized 2 120 >/dev/null || fail "lepic finalized nothing after the second send" || return 1
    third_send="$(NATIVE_DIRECT="" lepic tx send 0.1 --to "${payer_address}")" ||
        fail "the third send failed" || return 1
    [[ "$(jq -r .format <<<"${third_send}")" == legacy ]] ||
        fail "the send with native_direct off is not legacy: ${third_send}" || return 1
    drain_until finalized 3 120 >/dev/null || fail "lepic finalized nothing after the third send" || return 1
    native_stop_listener
    local sent fee=0 slate_id
    for sent in "${first}" "${second}" "${third_send}"; do
        slate_id="$(jq -r .slate_id <<<"${sent}")"
        confirm_pair "${slate_id}" || return 1
        fee=$((fee + $(to_units "$(jq -r .fee <<<"${sent}")")))
    done
    expect_totals $((L0 - $(to_units 0.6) - fee)) $((P0 + $(to_units 0.6))) || return 1
    DETAIL="first send legacy, peer claim native after the answer, second native, third with native_direct off legacy; three payments finalized, posted, confirmed, one kernel each"
}

# 2. A contact that did not claim native slates gets V3 from a native_direct wallet.
native_mixed_contact() {
    native_ready || return 1
    [[ "$(native_slates_to lepic "${MX_L}")" == false ]] ||
        fail "native_slates towards the mixed contact: $(lepic contact list)" || return 1
    local sent slate_id
    sent="$(lepic tx send 0.2 --to-contact "${MX_L}")" || fail "the contact payment failed: ${sent}" || return 1
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    local PAYER_SWITCH=""
    collect_both 120 '[[ -n "$(side_tx payer "${slate_id}")" ]] && tx_state_in lepic "$(side_tx lepic "${slate_id}")" posted confirmed' ||
        fail "the payment never completed: lepic tx is $(lepic_tx_by_slate "${slate_id}")" || return 1
    confirm_pair "${slate_id}" || return 1
    expect_transfer lepic "$(to_units 0.2)" "$(tx_fee lepic "$(side_tx lepic "${slate_id}")")" || return 1
    DETAIL="native_slates false towards the contact whose card did not claim it; the payment went through the mailbox, ${slate_id} finalized, posted, confirmed"
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

# 3. A payment by file between contacts: native .epictx text when both sides claim native
# slates, the V3 sealed form otherwise.
native_epictx_files() {
    native_ready || return 1
    local file="${NATIVE_DIR}/pay.epictx" answer="${NATIVE_DIR}/pay-reply.epictx"
    local tx_id slate_id
    tx_id="$(native_seal "${NC_L}" "${file}" 0.25)" || fail "sealing the native payment failed" || return 1
    slate_id="$(lepic tx show "${tx_id}" | jq -r .slate_id)"
    [[ "$(sealed_header "${file}")" == BEGINEPICTX.* ]] ||
        fail "the file between native contacts starts $(sealed_header "${file}")" || return 1
    local lepic_count payer_count opened
    lepic_count="$(lepic_tx_count)"
    payer_count="$(payer tx list | jq '.transactions | length')"
    opened="$(lepic epictx open "${file}")" || fail "epictx open failed" || return 1
    jq -e '.native == true' <<<"${opened}" >/dev/null || fail "epictx open: ${opened}" || return 1
    opened="$(payer epictx open "${file}")" || fail "the payer's epictx open failed" || return 1
    jq -e '.native == true' <<<"${opened}" >/dev/null || fail "the payer's epictx open: ${opened}" || return 1
    [[ "$(lepic_tx_count)" == "${lepic_count}" && "$(payer tx list | jq '.transactions | length')" == "${payer_count}" ]] ||
        fail "epictx open stored a transaction" || return 1
    payer contact open-sealed "${file}" --answer-file "${answer}" >/dev/null ||
        fail "the payer could not open the file" || return 1
    [[ "$(sealed_header "${answer}")" == BEGINEPICTX.* ]] ||
        fail "the answer starts $(sealed_header "${answer}")" || return 1
    lepic contact open-sealed "${answer}" >/dev/null || fail "lepic could not open the answer" || return 1
    if tx_state_in lepic "${tx_id}" finalized; then
        lepic tx post "${tx_id}" >/dev/null || fail "tx post failed" || return 1
    fi
    confirm_pair "${slate_id}" || return 1
    expect_transfer lepic "$(to_units 0.25)" "$(tx_fee lepic "${tx_id}")" || return 1

    # With lepic's switch off, or towards a contact that never claimed native slates, the file
    # is the V3 sealed text.
    local v3_tx mixed_tx v3_file="${NATIVE_DIR}/off.epicsealed" mixed_file="${NATIVE_DIR}/mixed.epicsealed"
    v3_tx="$(NATIVE_DIRECT="" native_seal "${NC_L}" "${v3_file}" 0.1)" ||
        fail "sealing with native_direct off failed" || return 1
    [[ "$(sealed_header "${v3_file}")" == BEGINEPICSEALED.* ]] ||
        fail "with native_direct off the file starts $(sealed_header "${v3_file}")" || return 1
    lepic tx cancel "${v3_tx}" >/dev/null || fail "tx cancel failed" || return 1
    mixed_tx="$(native_seal "${MX_L}" "${mixed_file}" 0.15)" || fail "sealing for the mixed contact failed" || return 1
    [[ "$(sealed_header "${mixed_file}")" == BEGINEPICSEALED.* ]] ||
        fail "the file for the mixed contact starts $(sealed_header "${mixed_file}")" || return 1
    jq -e '.native == false' <<<"$(lepic epictx open "${mixed_file}")" >/dev/null ||
        fail "epictx open of the V3 file shows a native slate" || return 1
    NATIVE_DIRECT="" payer contact open-sealed "${mixed_file}" --answer-file "${mixed_file}.reply" >/dev/null ||
        fail "the payer could not open the V3 file" || return 1
    lepic contact open-sealed "${mixed_file}.reply" >/dev/null || fail "lepic could not open the V3 answer" || return 1
    local mixed_slate
    mixed_slate="$(lepic tx show "${mixed_tx}" | jq -r .slate_id)"
    if tx_state_in lepic "${mixed_tx}" finalized; then
        lepic tx post "${mixed_tx}" >/dev/null || fail "tx post failed" || return 1
    fi
    confirm_pair "${mixed_slate}" || return 1
    L0="${EXPECTED_TOTAL}"
    P0="${PAYER_TOTAL}"
    expect_transfer lepic "$(to_units 0.15)" "$(tx_fee lepic "${mixed_tx}")" || return 1
    DETAIL="native file ${slate_id}: BEGINEPICTX., epictx open shows a native slate and stores nothing, answered, finalized, confirmed; V3 sealed form with native_direct off and for the mixed contact, the latter paid ${mixed_slate}"
}

# One offline in-person exchange: lepic shows a code, the payer answers it, lepic takes the
# answer and finalizes. $1 invoice|send, $2 amount in EPIC. The payer pays an invoice, lepic
# sends in a send.
in_person_exchange() {
    local direction="$1" amount="$2" flags=(--offline) code answer shown read paid
    code="${NATIVE_DIR}/ip-${direction}.code"
    answer="${NATIVE_DIR}/ip-${direction}.answer"
    native_ready || return 1
    if [[ "${direction}" == invoice ]]; then
        shown="$(lepic in-person invoice "${amount}" --out "${code}" "${flags[@]}")"
    else
        shown="$(lepic in-person send "${amount}" --out "${code}" "${flags[@]}")"
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
    local check_code payer_tx
    check_code="$(jq -r .check_code <<<"${paid}")"
    payer_tx="$(jq -r .tx_id <<<"${paid}")"
    [[ "${check_code}" =~ ^[0-9]{4}$ ]] || fail "the check code is '${check_code}': ${paid}" || return 1
    lepic in-person take --file "${answer}" --offline >/dev/null || fail "in-person take failed" || return 1
    local answers
    answers="$(lepic in-person answers "${slate_id}" "${flags[@]}")" || fail "in-person answers failed" || return 1
    jq -e --arg code "${check_code}" '(.answers | length) == 1 and .answers[0].check_code == $code' <<<"${answers}" >/dev/null ||
        fail "answers ${answers}, the payer showed check code ${check_code}" || return 1
    # Nothing is finalized, or posted, until the finalize command.
    if tx_state_in lepic "${lepic_tx}" finalized posted confirmed; then
        fail "tx ${lepic_tx} is $(lepic_tx_state "${lepic_tx}") before in-person finalize" || return 1
    fi
    lepic in-person finalize "${slate_id}" 1 "${flags[@]}" >/dev/null || fail "in-person finalize failed" || return 1
    confirm_pair "${slate_id}" || return 1
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

# 6. An online code names a mailbox on the payee's own relay. The product refuses a loopback relay
# for it, and a plain websocket relay must be loopback, so the local stack's relay cannot carry
# the reply mailbox: the code is refused and nothing is created.
native_in_person_post() {
    native_ready || return 1
    local count status=0 out
    count="$(lepic_tx_count)"
    out="$(lepic in-person invoice 0.2 --out "${NATIVE_DIR}/online.code" 2>&1)" || status=$?
    ((status != 0)) || fail "an online code on a loopback relay was made: ${out}" || return 1
    grep -qi "loopback\|local" <<<"${out}" || fail "the refusal does not name the loopback host: ${out}" || return 1
    [[ "$(lepic_tx_count)" == "${count}" && ! -e "${NATIVE_DIR}/online.code" ]] ||
        fail "the refused code left a transaction or a file" || return 1
    lepic_unlocked || fail "the refused code locked $(lepic_locked) units" || return 1
    DETAIL="online code refused with the local relay (exit ${status}), nothing created; the full flow, invoice and send through the reply mailbox, was run on floonet against wss://epicbox.btlabs.uk"
}

# 7. A code past its TTL is refused, and an unanswered send code expires.
native_in_person_ttl() {
    native_ready || return 1
    local shown cutoff status code="${NATIVE_DIR}/ttl-invoice.code" send_code="${NATIVE_DIR}/ttl-send.code"
    local payer_count
    payer_count="$(payer tx list | jq '.transactions | length')"
    shown="$(lepic in-person invoice 0.2 --ttl-blocks 3 --offline --out "${code}")" ||
        fail "in-person invoice with a TTL failed" || return 1
    cutoff="$(jq -r .ttl_cutoff <<<"${shown}")"
    local send_tx
    shown="$(lepic in-person send 0.2 --ttl-blocks 3 --offline --out "${send_code}")" ||
        fail "in-person send with a TTL failed" || return 1
    send_tx="$(jq -r .tx_id <<<"${shown}")"
    local send_cutoff
    send_cutoff="$(jq -r .ttl_cutoff <<<"${shown}")"
    (($(lepic_locked) > 0)) || fail "the send code locked nothing" || return 1
    # The stack mines a block every few seconds.
    wait_until "the chain past ${send_cutoff}" 120 node_past "${cutoff}" "${send_cutoff}" ||
        fail "the chain did not pass the TTL cutoff" || return 1
    local read_status pay_status receive_status
    read_status="$(payer_status in-person read --file "${code}" --offline)"
    pay_status="$(payer_status in-person pay 0.2 --file "${code}" --offline)"
    receive_status="$(payer_status in-person receive --file "${send_code}" --offline)"
    ((read_status != 0 && pay_status != 0 && receive_status != 0)) ||
        fail "past the TTL, read exited ${read_status}, pay ${pay_status}, receive ${receive_status}" || return 1
    [[ "$(payer tx list | jq '.transactions | length')" == "${payer_count}" ]] ||
        fail "a refused code left a transaction in the payer's wallet" || return 1
    wait_until "the send code to expire" 120 tx_state_in lepic "${send_tx}" cancelled expired ||
        fail "the unanswered send is $(lepic_tx_state "${send_tx}")" || return 1
    wait_until "the inputs unlocked" 60 lepic_unlocked || fail "the expired send left $(lepic_locked) units locked" || return 1
    expect_totals "${L0}" "${P0}" || return 1
    DETAIL="past TTL ${send_cutoff}: read exited ${read_status}, pay ${pay_status}, receive ${receive_status}, nothing stored; the unanswered send is $(lepic_tx_state "${send_tx}"), inputs unlocked, balance back"
}

lepic_unlocked() { (($(lepic_locked) == 0)); }

# True when the chain is past both heights.
node_past() { (($(tip_height) > $1 && $(tip_height) > $2)); }

# 8. An epic1 link names a mailbox on the wallet's own relay, which the product refuses when it is
# a loopback host, so the local stack's relay cannot carry link payments: no link is made.
native_epic1() {
    native_ready || return 1
    local status=0 out
    out="$(lepic epic1 link 0.3 2>&1)" || status=$?
    ((status != 0)) || fail "an epic1 link on a loopback relay was made: ${out}" || return 1
    grep -qi "loopback\|local" <<<"${out}" || fail "the refusal does not name the loopback host: ${out}" || return 1
    [[ "$(lepic epic1 links | jq '.links | length')" == 0 ]] || fail "the refused link was kept: $(lepic epic1 links)" || return 1
    DETAIL="epic1 link refused with the local relay (exit ${status}), none kept; the full flow, pay, answer and finalize, was run on floonet against wss://epicbox.btlabs.uk"
}

# The python forwarder from the docker0 address to the HTTP listener, which binds loopback only.
native_forwarder() {
    cat >"${NATIVE_DIR}/forward.py" <<'EOF'
import asyncio
import sys

host, port = sys.argv[1], int(sys.argv[2])


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def handle(reader, writer):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        writer.close()
        return
    await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))


async def main():
    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()


asyncio.run(main())
EOF
    python3 -I "${NATIVE_DIR}/forward.py" "${NATIVE_HOST}" "${NATIVE_HTTP_PORT}" >"${NATIVE_DIR}/forward.log" 2>&1 &
    NATIVE_FWD=$!
    wait_until "the forwarder on ${NATIVE_HOST}:${NATIVE_HTTP_PORT}" 15 native_tcp_open "${NATIVE_HOST}" "${NATIVE_HTTP_PORT}"
}

native_http_up() { curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${NATIVE_HTTP_PORT}/v2/foreign"; }

# `http listen` for a wallet with native_direct set to $2, on the loopback port the forwarder
# reaches. It replaces the one running.
native_http_listener() {
    native_stop_listener
    NATIVE_LOG="${NATIVE_DIR}/http-listen"
    NATIVE_DIRECT="$2" native_bg "$1" "${NATIVE_LOG}" http listen --port "${NATIVE_HTTP_PORT}"
    NATIVE_PID=$!
    wait_until "the http listener" 30 native_http_up
}

third_tx_confirmed() {
    third wallet info >/dev/null
    [[ "$(third tx show "$1" | jq -r .state)" == confirmed ]]
}

# 9. A direct send over HTTP: native to a listener that offers it, with the listener's key
# pinned, and V2/V3 on request or from a listener with native_direct off.
native_http() {
    native_ready || return 1
    local url="http://${NATIVE_HOST}:${NATIVE_HTTP_PORT}" origin="http://${NATIVE_HOST}:${NATIVE_HTTP_PORT}"
    local send=(tx send --allow-plain-http --to "${url}")
    third wallet init --words 12 >/dev/null || fail "the third wallet's init failed" || return 1
    native_forwarder || fail "the forwarder did not start: $(cat "${NATIVE_DIR}/forward.log")" || return 1
    native_http_listener "${STATE_DIR}/payer" true || fail "the payer's http listener did not start" || return 1

    local first second
    first="$(lepic "${send[@]}" 0.2)" || fail "the native send failed: ${first}" || return 1
    jq -e '.dialect == "native" and .format == "native"' <<<"${first}" >/dev/null ||
        fail "the first send reports ${first}" || return 1
    jq -e --arg origin "${origin}" 'any(.pins[]; .origin == $origin)' <<<"$(lepic peer pins)" >/dev/null ||
        fail "peer pins lists no pin for ${origin}: $(lepic peer pins)" || return 1
    wait_until "lepic spendable" 120 lepic_spendable_at_least "$(to_units 0.5)" || fail "lepic has no spendable funds" || return 1
    second="$(lepic "${send[@]}" 0.1 --legacy)" || fail "the legacy send failed: ${second}" || return 1
    [[ "$(jq -r .format <<<"${second}")" == legacy ]] || fail "the --legacy send reports ${second}" || return 1

    # Another wallet answers at the same URL: its key is not the pinned one, so the next native
    # send stops and nothing is stored.
    local before status=0 refused
    native_http_listener "${STATE_DIR}/third" true || fail "the third wallet's http listener did not start" || return 1
    before="$(lepic_tx_count)"
    refused="$(lepic "${send[@]}" 0.1)" || status=$?
    ((status == 7)) || fail "the send to a listener with another key exited ${status}: ${refused}" || return 1
    [[ "$(lepic_tx_count)" == "${before}" ]] || fail "the refused send stored a transaction" || return 1
    lepic peer forget "${origin}" >/dev/null || fail "peer forget failed" || return 1
    wait_until "lepic spendable" 120 lepic_spendable_at_least "$(to_units 0.5)" || fail "lepic has no spendable funds" || return 1
    local to_third
    to_third="$(lepic "${send[@]}" 0.1)" || fail "the send to the third wallet after peer forget failed: ${to_third}" || return 1
    jq -e '.format == "native"' <<<"${to_third}" >/dev/null || fail "the third wallet's send reports ${to_third}" || return 1

    # The payer answers again with native_direct off: no native endpoint, so a send is V2/V3.
    lepic peer forget "${origin}" >/dev/null || fail "the second peer forget failed" || return 1
    native_http_listener "${STATE_DIR}/payer" "" || fail "the payer's http listener did not restart" || return 1
    wait_until "lepic spendable" 120 lepic_spendable_at_least "$(to_units 0.5)" || fail "lepic has no spendable funds" || return 1
    local off
    off="$(lepic "${send[@]}" 0.1)" || fail "the send to a listener with native_direct off failed: ${off}" || return 1
    [[ "$(jq -r .format <<<"${off}")" == legacy ]] || fail "that send reports ${off}" || return 1
    native_cleanup

    local sent fee=0 payer_credit=0 slate_id
    for sent in "${first}" "${second}" "${off}"; do
        slate_id="$(jq -r .slate_id <<<"${sent}")"
        confirm_pair "${slate_id}" || return 1
        fee=$((fee + $(to_units "$(jq -r .fee <<<"${sent}")")))
        payer_credit=$((payer_credit + $(to_units "$(jq -r .amount <<<"${sent}")")))
    done
    local third_slate third_tx
    third_slate="$(jq -r .slate_id <<<"${to_third}")"
    third_tx="$(side_tx third "${third_slate}")"
    [[ -n "${third_tx}" ]] || fail "the third wallet has no transaction for ${third_slate}" || return 1
    wait_until "third tx ${third_tx} confirmed" 180 third_tx_confirmed "${third_tx}" ||
        fail "the third wallet's tx ${third_tx} did not confirm" || return 1
    fee=$((fee + $(to_units "$(jq -r .fee <<<"${to_third}")")))
    expect_totals $((L0 - payer_credit - $(to_units 0.1) - fee)) $((P0 + payer_credit)) || return 1
    DETAIL="native over http (dialect and format native), key pinned for ${origin}; --legacy and a listener with native_direct off legacy; another wallet's key stopped the send (exit 7, nothing stored) until peer forget"
}

# 10. A payment cancelled before it is finalized, as a native contact payment and as an in-person
# send, frees its inputs on both sides.
native_cancel() {
    native_ready || return 1
    local sent slate_id ltx ptx
    sent="$(lepic tx send 0.2 --to-contact "${NC_L}")" || fail "the contact payment failed: ${sent}" || return 1
    slate_id="$(jq -r .slate_id <<<"${sent}")"
    ltx="$(jq -r .tx_id <<<"${sent}")"
    local PAYER_SWITCH=true
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
    DETAIL="a native contact payment and an in-person send each cancelled on both sides before finalizing; nothing locked, balances back"
}

both_unlocked() { (($(lepic_locked) == 0)) && (($(to_units "$(payer wallet info | jq -r '.accounts[0].locked')") == 0)); }

# True once the payer's collect has taken the payment of a slate into its wallet.
payer_took() {
    NATIVE_DIRECT="${PAYER_SWITCH-${NATIVE_DIRECT}}" payer contact collect >/dev/null || return 1
    [[ -n "$(side_tx payer "$1")" ]]
}

step_native_epicbox() { native_scope native_epicbox; }
step_native_mixed_contact() { native_scope native_mixed_contact; }
step_native_epictx_files() { native_scope native_epictx_files; }
step_native_in_person_invoice() { native_scope native_in_person_invoice; }
step_native_in_person_send() { native_scope native_in_person_send; }
step_native_in_person_post() { native_scope native_in_person_post; }
step_native_in_person_ttl() { native_scope native_in_person_ttl; }
step_native_epic1() { native_scope native_epic1; }
step_native_http() { native_scope native_http; }
step_native_cancel() { native_scope native_cancel; }

NATIVE_STEPS=(
    "native wallets on the second relay, pairings:step_native_setup"
    "native Epicbox payments address:step_native_epicbox"
    "native contact that did not claim native:step_native_mixed_contact"
    "native .epictx files between contacts:step_native_epictx_files"
    "native in person invoice, offline:step_native_in_person_invoice"
    "native in person send, offline:step_native_in_person_send"
    "native in person through the reply mailbox:step_native_in_person_post"
    "native in person TTL:step_native_in_person_ttl"
    "native epic1 links:step_native_epic1"
    "native direct http:step_native_http"
    "native cancel before finalize:step_native_cancel"
)
