# shellcheck shell=bash
# A service on `lepic serve` and its wallet API, as a tip bot runs it: status and the CLI running
# through serve while it holds the wallet, withdrawals sent at once over HTTP and Epicbox,
# deposits arriving at once over HTTP and Epicbox, the event stream, and a payment id repeated in a
# race.

SVC_PATHS="crates/lepic-cli/src/api crates/lepic-cli/src/service.rs crates/lepic-cli/src/commands/serve.rs crates/lepic-cli/src/commands/serve crates/lepic-wallet crates/lepic-epicbox"
CASES+=("svc.status|case_svc_status|${SVC_PATHS}")
CASES+=("svc.withdraw-burst|case_svc_withdraw_burst|${SVC_PATHS} crates/lepic-legacy-rpc")
CASES+=("svc.withdraw-epicbox|case_svc_withdraw_epicbox|${SVC_PATHS}")
CASES+=("svc.deposit-burst|case_svc_deposit_burst|${SVC_PATHS} crates/lepic-legacy-rpc")
CASES+=("svc.deposit-epicbox|case_svc_deposit_epicbox|${SVC_PATHS}")

SVC_BOT="${E2E_PREFIX}-svc-bot"
SVC_USERS=("${E2E_PREFIX}-svc-u1" "${E2E_PREFIX}-svc-u2" "${E2E_PREFIX}-svc-u3")
SVC_AMOUNT=0.05

# One call to the wallet API: sets API_STATUS and API_BODY, and succeeds on a 2xx.
api() {
    local method="$1" path="$2" body="${3:-}" out
    out="${CASE_DIR}/api.${BASHPID}.${RANDOM}"
    local args=(-s -o "${out}" -w '%{http_code}' --max-time 180 --unix-socket "${SVC_SOCK}" -X "${method}")
    [[ -n "${body}" ]] && args+=(-H 'content-type: application/json' --data "${body}")
    API_STATUS="$(curl "${args[@]}" "http://lepic${path}")" || API_STATUS=000
    API_BODY="$(cat "${out}" 2>/dev/null)"
    rm -f "${out}"
    printf '%s %s %s -> %s %s\n' "${method}" "${path}" "${body}" "${API_STATUS}" "${API_BODY}" >>"${CASE_DIR}/api.log"
    [[ "${API_STATUS}" == 2* ]]
}

svc_ready() {
    api GET /api/v1/status || return 1
    jq -e '.listeners.epicbox.state == "connected"' <<<"${API_BODY}" >/dev/null || return 1
    api GET /api/v1/wallet || return 1
    jq -e '.height != null' <<<"${API_BODY}" >/dev/null
}

# Starts serve on the bot with extra arguments; sets SVC_PID and SVC_SOCK.
svc_start() {
    SVC_SOCK="$(wdir "${SVC_BOT}")/lepic.sock"
    wbg "${SVC_BOT}" serve serve "$@"
    SVC_PID=${BG_PID}
    wait_until "serve socket" 40 test -S "${SVC_SOCK}" || fail "serve did not open its socket" || return 1
    wait_until "serve synced and on the relay" 90 svc_ready || fail "serve not ready: ${API_BODY}" || return 1
}

# The bot's state of one payment (its id is the slate id), through the API.
svc_tx_state() {
    api GET "/api/v1/payments/$1" >/dev/null || return 1
    jq -r '.state' <<<"${API_BODY}"
}
svc_tx_state_is() { [[ "$(svc_tx_state "$1")" == "$2" ]]; }

# Outputs that are unspent and confirmed, which a send can take at once.
svc_ready_outputs() {
    w "$1" wallet outputs | jq '[.outputs[] | select(.category == "spendable")] | length'
}

# Gives the bot `n` confirmed outputs of at least `each` EPIC, so `n` sends can run at once.
svc_bot_outputs() {
    local n="$1" each="$2" have
    ensure_wallet "${SVC_BOT}" || return 1
    ensure_funds "${SVC_BOT}" "$(awk -v n="${n}" -v e="${each}" 'BEGIN { printf "%.2f", n * e * 1.5 }')" "${n}" || return 1
    have="$(svc_ready_outputs "${SVC_BOT}")" || return 1
    if ((have < n)); then
        log "the bot has ${have} ready outputs; splitting its funds into ${n}"
        http_listen "${SVC_USERS[0]}" || return 1
        w "${SVC_BOT}" tx send --to "${HTTP_URL}" --min-confirmations "${E2E_MINCONF}" --change-outputs "${n}" 0.01 \
            >/dev/null || fail "split send failed" || return 1
        wstop "${HTTP_PID}"
        wait_until "the bot's split change confirmed" 180 svc_outputs_at_least "${n}" || return 1
    fi
}
svc_outputs_at_least() {
    local have
    have="$(svc_ready_outputs "${SVC_BOT}")" || return 1
    ((have >= $1))
}

case_svc_status() {
    local address cli_address
    ensure_wallet "${SVC_BOT}" || return 1
    cli_address="$(w "${SVC_BOT}" wallet address | jq -r .address)"
    svc_start || return 1
    api GET /api/v1/status || fail "GET /api/v1/status ${API_STATUS}" || return 1
    # serve always listens on Epicbox; this one runs without --http. (/v1/methods has no direct
    # successor: the status listeners say what serve listens on.)
    expect_json "${API_BODY}" '.listeners.epicbox.state == "connected" and (.listeners | has("http") | not) and .refresh.failures == 0 and .collect.failures == 0 and (.requests.served >= 0)' "status listeners: epicbox connected, no http" || return 1
    api GET /api/v1/wallet || fail "GET /api/v1/wallet ${API_STATUS}" || return 1
    expect_json "${API_BODY}" '.network == "floonet" and .height != null' "wallet over the API" || return 1
    api GET /api/v1/accounts || fail "GET /api/v1/accounts ${API_STATUS}" || return 1
    expect_json "${API_BODY}" '(.items | length) >= 1' "accounts over the API" || return 1
    api GET '/api/v1/addresses?type=epicbox' || fail "GET /api/v1/addresses epicbox ${API_STATUS}" || return 1
    address="$(jq -r '.items[0].text' <<<"${API_BODY}")"
    expect_eq "${address}" "${cli_address}" "epicbox address over the API" || return 1
    api GET '/api/v1/addresses?type=epic1' || fail "GET /api/v1/addresses epic1 ${API_STATUS}" || return 1
    if [[ "$(jq '.items | length' <<<"${API_BODY}")" -gt 0 ]]; then
        expect_match "$(jq -r '.items[0].text' <<<"${API_BODY}")" '^tepic1' "epic1 address over the API" || return 1
    else
        note "no epic1 address issued yet"
    fi
    api GET /api/v1/node || fail "GET /api/v1/node ${API_STATUS}" || return 1
    expect_json "${API_BODY}" 'has("tip_height") and has("syncing")' "node over the API" || return 1
    api GET /api/v1/openapi.json || fail "GET /api/v1/openapi.json ${API_STATUS}" || return 1
    expect_json "${API_BODY}" '.openapi != null and (.paths | has("/payments"))' "openapi document" || return 1
    # A problem is RFC 9457 JSON with a code a client can branch on.
    api GET "/api/v1/payments/$(cat /proc/sys/kernel/random/uuid)" && { fail "an unknown payment answered ${API_STATUS}"; return 1; }
    expect_json "${API_BODY}" '.code == "not_found" and .status == 404' "unknown payment problem" || return 1
    api POST /api/v1/payments '{"to":"nonsense","amount":"abc"}' && { fail "a bad send was accepted"; return 1; }
    expect_eq "${API_STATUS}" 400 "bad send status" || return 1
    expect_json "${API_BODY}" '(.code | type) == "string" and .status == 400' "bad send problem ($(jq -r .code <<<"${API_BODY}"))" || return 1
    # Serve holds the data directory: a command with a route runs through serve's socket, errors
    # included, and one with no route exits 5 naming serve (ADR 0053).
    cli_address="$(w "${SVC_BOT}" wallet address | jq -r .address)"
    expect_eq "${cli_address}" "${address}" "wallet address through serve" || return 1
    w "${SVC_BOT}" wallet info >"${CASE_DIR}/info.json" || fail "wallet info through serve" || return 1
    expect_json "$(cat "${CASE_DIR}/info.json")" '.network == "floonet" and (.accounts | length) >= 1' "wallet info through serve" || return 1
    wx 6 "${SVC_BOT}" tx show 999999 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "not_found"' "unknown transaction through serve" || return 1
    w "${SVC_BOT}" contact list >"${CASE_DIR}/contacts.json" || fail "contact list through serve" || return 1
    expect_json "$(cat "${CASE_DIR}/contacts.json")" 'has("contacts")' "contact list through serve" || return 1
    wx 5 "${SVC_BOT}" tx send --to-file "${CASE_DIR}/unrouted.slate" 0.01 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "wallet_state" and (.error.message | contains("lepic serve is running"))' "a command with no route names serve" || return 1
    wstop "${SVC_PID}"
    note "status, wallet, accounts, addresses, node, openapi, problems; CLI through serve (wallet, transactions, contacts), exit 5 with no route"
}

# Three withdrawals at once to three HTTP listeners, then two requests racing under one id.
case_svc_withdraw_burst() {
    local i urls=() pids=() body slate ids race_slate status
    for i in "${!SVC_USERS[@]}"; do ensure_wallet "${SVC_USERS[i]}" || return 1; done
    svc_bot_outputs 4 0.2 || return 1
    for i in "${!SVC_USERS[@]}"; do
        http_listen "${SVC_USERS[i]}" || fail "listener on ${SVC_USERS[i]}" || return 1
        urls+=("${HTTP_URL}")
    done
    svc_start || return 1
    for i in "${!SVC_USERS[@]}"; do
        slate="$(cat /proc/sys/kernel/random/uuid)"
        body="$(jq -nc --arg to "${urls[i]}" --arg a "${SVC_AMOUNT}" --arg s "${slate}" \
            '{to:$to, amount:$a, via:"http", id:$s, min_confirmations:1, message:"e2e withdrawal", purpose:"withdrawal"}')"
        (api POST /api/v1/payments "${body}"; printf '%s\n%s\n' "${API_STATUS}" "${API_BODY}" >"${CASE_DIR}/burst.${i}") &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait "${i}"; done
    for i in "${!SVC_USERS[@]}"; do
        [[ "$(head -n 1 "${CASE_DIR}/burst.${i}")" == 201 ]] || fail "withdrawal ${i}: $(tail -n +1 "${CASE_DIR}/burst.${i}" | tr '\n' ' ')" || return 1
        expect_json "$(tail -n +2 "${CASE_DIR}/burst.${i}")" '(.state == "posted" or .state == "confirmed") and .direction == "out" and .via == "http"' "withdrawal ${i} posted" || return 1
    done
    ids="$(for i in "${!SVC_USERS[@]}"; do tail -n +2 "${CASE_DIR}/burst.${i}" | jq -r .id; done | sort -u | wc -l)"
    expect_eq "${ids}" 3 "distinct payments" || return 1
    # The same id sent twice at once: one payment. One answers 201; the other 200 (it saw the
    # stored payment) or 409 in_progress (the first was still running).
    race_slate="$(cat /proc/sys/kernel/random/uuid)"
    body="$(jq -nc --arg to "${urls[0]}" --arg a "${SVC_AMOUNT}" --arg s "${race_slate}" \
        '{to:$to, amount:$a, via:"http", id:$s, min_confirmations:1}')"
    pids=()
    for i in 0 1; do
        (api POST /api/v1/payments "${body}"; printf '%s\n%s\n' "${API_STATUS}" "${API_BODY}" >"${CASE_DIR}/race.${i}") &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait "${i}"; done
    for i in 0 1; do note "race ${i}: $(tr '\n' ' ' <"${CASE_DIR}/race.${i}" | head -c 300)"; done
    expect_eq "$(head -qn 1 "${CASE_DIR}"/race.0 "${CASE_DIR}"/race.1 | grep -c '^201$')" 1 "one 201 for a raced id" || return 1
    for i in 0 1; do
        status="$(head -n 1 "${CASE_DIR}/race.${i}")"
        case "${status}" in
        201 | 200) ;;
        409) expect_json "$(tail -n +2 "${CASE_DIR}/race.${i}")" '.code == "in_progress"' "race ${i} 409 is in_progress" || return 1 ;;
        *) fail "race ${i} answered ${status}" || return 1 ;;
        esac
    done
    api POST /api/v1/payments "${body}" || fail "repeat after the race ${API_STATUS}" || return 1
    expect_eq "${API_STATUS}" 200 "a later repeat answers 200" || return 1
    expect_eq "$(jq -r .id <<<"${API_BODY}")" "${race_slate}" "the repeat names the same payment" || return 1
    api GET '/api/v1/payments?limit=500' || return 1
    expect_eq "$(jq --arg s "${race_slate}" '[.items[] | select(.id == $s)] | length' <<<"${API_BODY}")" 1 "raced id listed once" || return 1
    # Serve refreshes on its own: the withdrawals confirm without a CLI call.
    for i in "${!SVC_USERS[@]}"; do
        wait_until "withdrawal ${i} confirmed" 240 svc_tx_state_is "$(tail -n +2 "${CASE_DIR}/burst.${i}" | jq -r .id)" confirmed \
            || fail "withdrawal ${i} not confirmed" || return 1
    done
    note "3 withdrawals at once posted and confirmed; raced id gave one payment"
}

# A withdrawal to an Epicbox address: serve's own relay connection takes the answer and posts it.
case_svc_withdraw_epicbox() {
    local user="${SVC_USERS[1]}" address slate body tx
    ensure_wallet "${user}" || return 1
    svc_bot_outputs 1 0.2 || return 1
    address="$(w "${user}" wallet address | jq -r .address)"
    epicbox_listen "${user}" || fail "${user} not on the relay" || return 1
    svc_start || return 1
    slate="$(cat /proc/sys/kernel/random/uuid)"
    body="$(jq -nc --arg to "${address}" --arg a "${SVC_AMOUNT}" --arg s "${slate}" '{to:$to, amount:$a, via:"epicbox", id:$s, min_confirmations:1}')"
    api POST /api/v1/payments "${body}" || fail "epicbox withdrawal ${API_STATUS}: ${API_BODY}" || return 1
    expect_eq "${API_STATUS}" 201 "epicbox withdrawal status" || return 1
    expect_json "${API_BODY}" '.id == "'"${slate}"'" and .via == "epicbox" and .direction == "out"' "withdrawal sent over Epicbox" || return 1
    tx="${slate}"
    local t0=${SECONDS}
    wait_until "epicbox withdrawal posted" 120 svc_tx_state_in "${tx}" "posted confirmed" || fail "the answer never came back" || return 1
    local leg=$((SECONDS - t0))
    wait_until "epicbox withdrawal confirmed" 240 svc_tx_state_is "${tx}" confirmed || fail "not confirmed" || return 1
    note "epicbox withdrawal answered and posted in ${leg}s, then confirmed"
}
svc_tx_state_in() {
    local s
    s="$(svc_tx_state "$1")" || return 1
    [[ " $2 " == *" ${s} "* ]]
}

# Three deposits at once to serve's HTTP listener (native, LEPIC to LEPIC through /api/v1/inbox),
# seen in the event stream.
case_svc_deposit_burst() {
    local i port ip pids=() slate events_pid got
    ensure_wallet "${SVC_BOT}" || return 1
    wconfig_set "${SVC_BOT}" 'native_direct = true'
    for i in "${!SVC_USERS[@]}"; do
        ensure_wallet "${SVC_USERS[i]}" || return 1
        ensure_funds "${SVC_USERS[i]}" 0.3 1 || return 1
        wconfig_set "${SVC_USERS[i]}" 'native_direct = true'
    done
    # A native send to a listener on the sender's own device is refused (ADR 0052), so serve listens
    # on the LAN and the payers send to the LAN address, as native_listen in 20-sends.sh does.
    ip="$(svc_lan_ip)" || return 1
    svc_start --http --port 0 --internet || return 1
    api GET /api/v1/status || return 1
    port="$(jq -r '.listeners.http.port // empty' <<<"${API_BODY}")"
    [[ "${port}" =~ ^[0-9]+$ ]] || fail "no http port in status: ${API_BODY}" || return 1
    curl -sN --unix-socket "${SVC_SOCK}" -H 'accept: text/event-stream' http://lepic/api/v1/events >"${CASE_DIR}/events.txt" 2>/dev/null &
    events_pid=$!
    E2E_BG[${events_pid}]="${CASE_DIR}/events"
    for i in "${!SVC_USERS[@]}"; do
        (lepic_env "${SVC_USERS[i]}" --output json tx send --allow-plain-http --to "http://${ip}:${port}" \
            --min-confirmations "${E2E_MINCONF}" -m "e2e deposit ${i}" "${SVC_AMOUNT}" \
            >"${CASE_DIR}/deposit.${i}.json" 2>"${CASE_DIR}/deposit.${i}.err"
         echo $? >"${CASE_DIR}/deposit.${i}.exit") &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait "${i}"; done
    for i in "${!SVC_USERS[@]}"; do
        expect_eq "$(cat "${CASE_DIR}/deposit.${i}.exit")" 0 "deposit ${i} exit ($(tail -c 300 "${CASE_DIR}/deposit.${i}.err"))" || return 1
        expect_json "$(cat "${CASE_DIR}/deposit.${i}.json")" '.state == "posted" and .format != "legacy"' "deposit ${i} posted, not legacy" || return 1
    done
    for i in "${!SVC_USERS[@]}"; do
        slate="$(jq -r .slate_id "${CASE_DIR}/deposit.${i}.json")"
        api GET "/api/v1/payments/${slate}" || fail "deposit ${i} (${slate}) not at the bot: ${API_STATUS}" || return 1
        got="${API_BODY}"
        expect_json "${got}" '.direction == "in"' "deposit ${i} incoming" || return 1
        # A payment.created event carries the payment.
        wait_until "payment.created event for deposit ${i}" 30 svc_created_event "${slate}" ||
            fail "no payment.created event for deposit ${i} (${slate})" || return 1
    done
    for i in "${!SVC_USERS[@]}"; do
        slate="$(jq -r .slate_id "${CASE_DIR}/deposit.${i}.json")"
        wait_until "deposit ${i} confirmed" 240 svc_tx_state_is "${slate}" confirmed || fail "deposit ${i} not confirmed" || return 1
    done
    note "3 native deposits at once over serve --http posted, evented and confirmed; events: $(grep -c '^event:' "${CASE_DIR}/events.txt")"
}
# This machine's LAN address, picked as native_listen does.
svc_lan_ip() {
    local ip
    ip="$(hostname -I | tr ' ' '\n' | grep -E '^(192\.168|10\.)' | head -n 1)"
    [[ -n "${ip}" ]] || ip="$(hostname -I | awk '{print $1}')"
    [[ -n "${ip}" ]] || fail "this machine has no network address" || return 1
    printf '%s\n' "${ip}"
}
# True when the event stream file holds a payment.created event for the payment id.
svc_created_event() {
    grep '^data:' "${CASE_DIR}/events.txt" | sed 's/^data: //' |
        jq -e --arg s "$1" 'select(.type == "payment.created" and ((.data.payment_id // .data.object.id) == $s))' >/dev/null
}

# A deposit over Epicbox: serve answers it unattended, the payer's drain finalizes and posts.
case_svc_deposit_epicbox() {
    local user="${SVC_USERS[2]}" address slate t0
    ensure_wallet "${SVC_BOT}" || return 1
    ensure_wallet "${user}" || return 1
    ensure_funds "${user}" 0.3 1 || return 1
    svc_start || return 1
    address="$(w "${SVC_BOT}" wallet address | jq -r .address)"
    w "${user}" tx send --to "${address}" --min-confirmations "${E2E_MINCONF}" "${SVC_AMOUNT}" >"${CASE_DIR}/send.json" \
        || fail "send to the bot failed" || return 1
    slate="$(jq -r .slate_id "${CASE_DIR}/send.json")"
    t0=${SECONDS}
    wait_until "the bot answered" 120 svc_tx_state "${slate}" || fail "serve never took the slate" || return 1
    wait_until "payer finalized and posted" 120 svc_drain_posted "${user}" "${slate}" || fail "the answer never reached the payer" || return 1
    local leg=$((SECONDS - t0))
    wait_until "deposit confirmed at the bot" 240 svc_tx_state_is "${slate}" confirmed || fail "not confirmed at the bot" || return 1
    note "epicbox deposit answered by serve and posted in ${leg}s, then confirmed"
}
svc_drain_posted() {
    w "$1" epicbox drain >/dev/null || true
    slate_state_in "$1" "$2" "posted confirmed"
}
