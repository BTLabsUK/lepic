# shellcheck shell=bash
# A service on `lepic serve` and its wallet API, as a tip bot runs it: status and the CLI running
# through serve while it holds the wallet, withdrawals sent at once over HTTP and Epicbox,
# deposits arriving at once over HTTP and Epicbox, the event stream, and a slate_id repeated in a
# race.

SVC_PATHS="crates/lepic-cli/src/api crates/lepic-cli/src/service.rs crates/lepic-cli/src/commands/serve.rs crates/lepic-wallet crates/lepic-epicbox"
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
    api GET /v1/status || return 1
    jq -e '.height != null and .epicbox == "connected"' <<<"${API_BODY}" >/dev/null
}

# Starts serve on the bot with extra arguments; sets SVC_PID and SVC_SOCK.
svc_start() {
    SVC_SOCK="$(wdir "${SVC_BOT}")/lepic.sock"
    wbg "${SVC_BOT}" serve serve "$@"
    SVC_PID=${BG_PID}
    wait_until "serve socket" 40 test -S "${SVC_SOCK}" || fail "serve did not open its socket" || return 1
    wait_until "serve synced and on the relay" 90 svc_ready || fail "serve not ready: ${API_BODY}" || return 1
}

# The bot's state of one transaction, through the API.
svc_tx_state() {
    api GET "/v1/transactions/$1" >/dev/null || return 1
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
    local address cli_address methods
    ensure_wallet "${SVC_BOT}" || return 1
    cli_address="$(w "${SVC_BOT}" wallet address | jq -r .address)"
    svc_start || return 1
    api GET /v1/wallet || fail "GET /v1/wallet ${API_STATUS}" || return 1
    expect_json "${API_BODY}" '.network == "floonet" and (.accounts | length) >= 1' "wallet over the API" || return 1
    api GET /v1/wallet/address || fail "GET /v1/wallet/address ${API_STATUS}" || return 1
    address="$(jq -r .address <<<"${API_BODY}")"
    expect_eq "${address}" "${cli_address}" "address over the API" || return 1
    api GET /v1/epic1/address || fail "GET /v1/epic1/address ${API_STATUS}" || return 1
    expect_match "$(jq -r .address <<<"${API_BODY}")" '^tepic1' "epic1 address over the API" || return 1
    api GET /v1/node || fail "GET /v1/node ${API_STATUS}" || return 1
    api GET /v1/methods || fail "GET /v1/methods ${API_STATUS}" || return 1
    methods="$(jq -c '[.methods[].id]' <<<"${API_BODY}")"
    expect_json "${methods}" 'index("epicbox") != null and index("http") != null' "methods epicbox and http" || return 1
    api GET /v1/openapi.json || fail "GET /v1/openapi.json ${API_STATUS}" || return 1
    # A problem is RFC 9457 JSON with a code a client can branch on.
    api GET /v1/transactions/999999 && { fail "an unknown transaction answered ${API_STATUS}"; return 1; }
    expect_json "${API_BODY}" '.code == "not_found" and .status == 404' "unknown transaction problem" || return 1
    api POST /v1/transactions '{"to":"nonsense","amount":"abc"}' && { fail "a bad send was accepted"; return 1; }
    expect_json "${API_BODY}" '.code == "usage" or .code == "rejected"' "bad send problem" || return 1
    # Serve holds the data directory: a command with a route runs through serve's socket, errors
    # included, and one with no route exits 5 naming serve (ADR 0053).
    cli_address="$(w "${SVC_BOT}" wallet address | jq -r .address)"
    expect_eq "${cli_address}" "${address}" "wallet address through serve" || return 1
    w "${SVC_BOT}" wallet info >"${CASE_DIR}/info.json" || fail "wallet info through serve" || return 1
    expect_json "$(cat "${CASE_DIR}/info.json")" '.network == "floonet" and (.accounts | length) >= 1' "wallet info through serve" || return 1
    wx 6 "${SVC_BOT}" tx show 999999 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "not_found"' "unknown transaction through serve" || return 1
    wx 5 "${SVC_BOT}" tx send --to-file "${CASE_DIR}/unrouted.slate" 0.01 || return 1
    expect_json "${LAST_JSON}" '.error.kind == "wallet_state" and (.error.message | contains("lepic serve is running"))' "a command with no route names serve" || return 1
    wstop "${SVC_PID}"
    note "status, wallet, address, epic1, node, methods, problems; CLI through serve, exit 5 with no route"
}

# Three withdrawals at once to three HTTP listeners, then two requests racing under one slate_id.
case_svc_withdraw_burst() {
    local i urls=() pids=() body slate ids race_slate
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
            '{to:$to, amount:$a, method:"http", slate_id:$s, min_confirmations:1, message:"e2e withdrawal"}')"
        (api POST /v1/transactions "${body}"; printf '%s\n%s\n' "${API_STATUS}" "${API_BODY}" >"${CASE_DIR}/burst.${i}") &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait "${i}"; done
    for i in "${!SVC_USERS[@]}"; do
        [[ "$(head -n 1 "${CASE_DIR}/burst.${i}")" == 200 ]] || fail "withdrawal ${i}: $(tail -n +1 "${CASE_DIR}/burst.${i}" | tr '\n' ' ')" || return 1
        expect_json "$(tail -n +2 "${CASE_DIR}/burst.${i}")" '.state == "posted" and .repeated == false and .dialect != null' "withdrawal ${i} posted" || return 1
    done
    ids="$(for i in "${!SVC_USERS[@]}"; do tail -n +2 "${CASE_DIR}/burst.${i}" | jq -r .tx_id; done | sort -u | wc -l)"
    expect_eq "${ids}" 3 "distinct transactions" || return 1
    # The same slate_id sent twice at once: one transaction, and one report says repeated.
    race_slate="$(cat /proc/sys/kernel/random/uuid)"
    body="$(jq -nc --arg to "${urls[0]}" --arg a "${SVC_AMOUNT}" --arg s "${race_slate}" \
        '{to:$to, amount:$a, method:"http", slate_id:$s, min_confirmations:1}')"
    pids=()
    for i in 0 1; do
        (api POST /v1/transactions "${body}"; printf '%s\n%s\n' "${API_STATUS}" "${API_BODY}" >"${CASE_DIR}/race.${i}") &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait "${i}"; done
    for i in 0 1; do note "race ${i}: $(tr '\n' ' ' <"${CASE_DIR}/race.${i}" | head -c 300)"; done
    expect_eq "$(cat "${CASE_DIR}"/race.* | grep -o '"tx_id":[0-9]*' | sort -u | wc -l)" 1 "one transaction for a raced slate_id" || return 1
    api POST /v1/transactions "${body}" || fail "repeat after the race ${API_STATUS}" || return 1
    expect_json "${API_BODY}" '.repeated == true' "a later repeat reports repeated" || return 1
    api GET /v1/transactions || return 1
    expect_eq "$(jq --arg s "${race_slate}" '[.transactions[] | select(.slate_id == $s)] | length' <<<"${API_BODY}")" 1 "raced slate stored once" || return 1
    # Serve refreshes on its own: the withdrawals confirm without a CLI call.
    for i in "${!SVC_USERS[@]}"; do
        wait_until "withdrawal ${i} confirmed" 240 svc_tx_state_is "$(tail -n +2 "${CASE_DIR}/burst.${i}" | jq -r .tx_id)" confirmed \
            || fail "withdrawal ${i} not confirmed" || return 1
    done
    note "3 withdrawals at once posted and confirmed; raced slate_id gave one transaction"
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
    body="$(jq -nc --arg to "${address}" --arg a "${SVC_AMOUNT}" --arg s "${slate}" '{to:$to, amount:$a, slate_id:$s, min_confirmations:1}')"
    api POST /v1/transactions "${body}" || fail "epicbox withdrawal ${API_STATUS}: ${API_BODY}" || return 1
    expect_json "${API_BODY}" '.state == "sent" and .transport == "epicbox"' "withdrawal sent over Epicbox" || return 1
    tx="$(jq -r .tx_id <<<"${API_BODY}")"
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

# Three deposits at once to serve's HTTP listener, seen in the event stream.
case_svc_deposit_burst() {
    local i id port pids=() slate events_pid got
    ensure_wallet "${SVC_BOT}" || return 1
    for i in "${!SVC_USERS[@]}"; do
        ensure_wallet "${SVC_USERS[i]}" || return 1
        ensure_funds "${SVC_USERS[i]}" 0.3 1 || return 1
    done
    svc_start --http --port 0 || return 1
    port="$(jq -r '.http.port // empty' <<<"${API_BODY}")"
    [[ "${port}" =~ ^[0-9]+$ ]] || fail "no http port in status: ${API_BODY}" || return 1
    curl -sN --unix-socket "${SVC_SOCK}" http://lepic/v1/events >"${CASE_DIR}/events.txt" 2>/dev/null &
    events_pid=$!
    E2E_BG[${events_pid}]="${CASE_DIR}/events"
    for i in "${!SVC_USERS[@]}"; do
        (lepic_env "${SVC_USERS[i]}" --output json tx send --to "http://127.0.0.1:${port}" \
            --min-confirmations "${E2E_MINCONF}" -m "e2e deposit ${i}" "${SVC_AMOUNT}" \
            >"${CASE_DIR}/deposit.${i}.json" 2>"${CASE_DIR}/deposit.${i}.err"
         echo $? >"${CASE_DIR}/deposit.${i}.exit") &
        pids+=($!)
    done
    for i in "${pids[@]}"; do wait "${i}"; done
    for i in "${!SVC_USERS[@]}"; do
        expect_eq "$(cat "${CASE_DIR}/deposit.${i}.exit")" 0 "deposit ${i} exit ($(tail -c 300 "${CASE_DIR}/deposit.${i}.err"))" || return 1
        expect_json "$(cat "${CASE_DIR}/deposit.${i}.json")" '.state == "posted"' "deposit ${i} posted" || return 1
    done
    api GET /v1/transactions || return 1
    for i in "${!SVC_USERS[@]}"; do
        slate="$(jq -r .slate_id "${CASE_DIR}/deposit.${i}.json")"
        got="$(jq -c --arg s "${slate}" '.transactions[] | select(.slate_id == $s)' <<<"${API_BODY}")"
        [[ -n "${got}" ]] || fail "deposit ${i} (${slate}) not in the bot's list" || return 1
        expect_json "${got}" '.direction == "incoming"' "deposit ${i} incoming" || return 1
        # A received event names the transaction by tx_id; the slate is in the transaction.
        id="$(jq -r .tx_id <<<"${got}")"
        grep '^data:' "${CASE_DIR}/events.txt" | sed 's/^data: //' |
            jq -e --argjson id "${id}" 'select(.kind == "received" and .tx_id == $id)' >/dev/null ||
            fail "no received event for deposit ${i} (tx ${id})" || return 1
    done
    for i in "${!SVC_USERS[@]}"; do
        slate="$(jq -r .slate_id "${CASE_DIR}/deposit.${i}.json")"
        wait_until "deposit ${i} confirmed" 240 svc_slate_state_is "${slate}" confirmed || fail "deposit ${i} not confirmed" || return 1
    done
    note "3 deposits at once over serve --http posted, evented and confirmed; events: $(grep -c '^event:' "${CASE_DIR}/events.txt")"
}
svc_slate_state_is() {
    api GET /v1/transactions || return 1
    [[ "$(jq -r --arg s "$1" '.transactions[] | select(.slate_id == $s) | .state' <<<"${API_BODY}")" == "$2" ]]
}

# A deposit over Epicbox: serve answers it unattended, the payer's drain finalizes and posts.
case_svc_deposit_epicbox() {
    local user="${SVC_USERS[2]}" address slate t0
    ensure_wallet "${SVC_BOT}" || return 1
    ensure_wallet "${user}" || return 1
    ensure_funds "${user}" 0.3 1 || return 1
    svc_start || return 1
    api GET /v1/wallet/address || return 1
    address="$(jq -r .address <<<"${API_BODY}")"
    w "${user}" tx send --to "${address}" --min-confirmations "${E2E_MINCONF}" "${SVC_AMOUNT}" >"${CASE_DIR}/send.json" \
        || fail "send to the bot failed" || return 1
    slate="$(jq -r .slate_id "${CASE_DIR}/send.json")"
    t0=${SECONDS}
    wait_until "the bot answered" 120 svc_slate_present "${slate}" || fail "serve never took the slate" || return 1
    wait_until "payer finalized and posted" 120 svc_drain_posted "${user}" "${slate}" || fail "the answer never reached the payer" || return 1
    local leg=$((SECONDS - t0))
    wait_until "deposit confirmed at the bot" 240 svc_slate_state_is "${slate}" confirmed || fail "not confirmed at the bot" || return 1
    note "epicbox deposit answered by serve and posted in ${leg}s, then confirmed"
}
svc_slate_present() {
    api GET /v1/transactions || return 1
    jq -e --arg s "$1" 'any(.transactions[]; .slate_id == $s)' <<<"${API_BODY}" >/dev/null
}
svc_drain_posted() {
    w "$1" epicbox drain >/dev/null || true
    slate_state_in "$1" "$2" "posted confirmed"
}
