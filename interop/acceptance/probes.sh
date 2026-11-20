# SPDX-License-Identifier: Apache-2.0
# Probes of how the relay serves addresses and how a stock epic-wallet listener treats a payload
# that is not a slate (recorded in docs/compat/epicbox.md). `run.sh --probes` sources this after
# steps.sh and runs PROBE_STEPS instead of STEPS, with step_probe_setup as its setup step.
#
# The probe client is ../probe: it posts any payload from a key of its own, and drains and
# acknowledges what comes back, so each check sees exactly what the relay and the stock
# listener did. Every probe's raw output is kept in the run's log directory under probes/.
# shellcheck shell=bash disable=SC2034,SC2154 # run.sh reads DETAIL and PROBE_STEPS, sets log_dir

PROBE_DIR=""
PROBE_BIN=""
PROBE_KEY=""
PROBE_ADDRESS=""
RELAY_URL="ws://localhost:${RELAY_PORT}"

probe() { "${PROBE_BIN}" "$@" 2>>"${RUN_LOG}"; }

# Saves a probe's JSON output under probes/<name>.json and prints it.
probe_saved() {
    local name="$1" output
    shift
    output="$(probe "$@")" || {
        printf 'lepic-probe %s failed\n' "$*" >>"${RUN_LOG}"
        return 1
    }
    printf '%s\n' "${output}" | tee "${PROBE_DIR}/${name}.json"
}

# How often the relay has handed a message for this key to a socket so far.
relay_deliveries_to() { dc logs epicbox 2>/dev/null | grep -cE "(Sent|Passthrough) slate to $1\$" || true; }

relay_delivered_more_than() { (($(relay_deliveries_to "$1") > $2)); }

peer_log_count() {
    dc exec -T peer sh -c "grep -c '$1' /data/.epic/user/epic-wallet.log 2>/dev/null || true"
}

step_probe_setup() {
    PROBE_DIR="${log_dir}/probes"
    mkdir -p "${PROBE_DIR}"
    log "building the probe client"
    cargo build --quiet --manifest-path "${ACCEPTANCE_DIR}/../probe/Cargo.toml" \
        --target-dir "${WORK_DIR}/probe-target" >>"${RUN_LOG}" 2>&1 ||
        fail "the probe client did not build" || return 1
    PROBE_BIN="${WORK_DIR}/probe-target/debug/lepic-interop-probe"
    PROBE_KEY="${STATE_DIR}/probe.key"
    PROBE_ADDRESS="$(probe key "${PROBE_KEY}" "${RELAY_URL}" | jq -r .address)" ||
        fail "no probe address" || return 1

    dc exec -T node cat /data/node/.foreign_api_secret >"${STATE_DIR}/foreign_api_secret" ||
        fail "could not read the node api secret" || return 1
    chmod 600 "${STATE_DIR}/foreign_api_secret"
    cat >"${STATE_DIR}/config.toml" <<EOF
network = mainnet
data_dir = "lepic"
node_url = "http://127.0.0.1:${NODE_PORT}"
node_api_secret_file = "foreign_api_secret"
epicbox_relay = "${RELAY_URL}"
EOF
    mkdir -p "${STATE_DIR}/home"
    lepic wallet init --words 12 >/dev/null || fail "lepic wallet init failed" || return 1

    local peer
    peer="$(ew_address peer)"
    [[ -n "${peer}" ]] || fail "no epic-wallet address" || return 1
    PEER_ADDRESS="${peer%%:*}:${RELAY_PORT}"
    PEER_KEY="${PEER_ADDRESS%%@*}"
    log "waiting for spendable funds in the funder wallet"
    wait_until "funder funds" 300 ew_spendable_at_least funder $((10 * UNIT)) ||
        fail "the funder wallet was not funded by mining" || return 1
    peer_listen_start || fail "the peer's epicbox listener did not start" || return 1
    DETAIL="probe ${PROBE_ADDRESS}, stock listener ${PEER_ADDRESS}"
}

# Fact 4. No wallet takes part: the probe holds every key.
probe_relay_sessions() {
    local report
    report="$(probe_saved sessions sessions "${RELAY_URL}")" || fail "the sessions probe failed" || return 1
    jq -e '.posts == ["Ok", "Ok"] and .one_socket.first_made == "Ok"' <<<"${report}" >/dev/null ||
        fail "setup of the one-socket case failed: ${report}" || return 1
    jq -e '.one_socket.second_subscribe_answer == "Slate" and .one_socket.second_message_opened
        and .one_socket.second_made == "Ok"' <<<"${report}" >/dev/null ||
        fail "a second subscribe on one socket did not switch it to the second address" || return 1
    jq -e '.one_socket.late_message_for_first_reached_socket
        and .one_socket.late_made_signed_by_first == "InvalidSignature"' <<<"${report}" >/dev/null ||
        fail "the first address was still served on the switched socket: ${report}" || return 1
    local queue
    queue="$(jq -r .addresses.late_message_queue <<<"${report}")"
    [[ "$(relay_unmade_for "${queue}")" == 1 ]] ||
        fail "the first address's late message is not left unacknowledged" || return 1
    # Nothing listens on that probe-only key, so a kept stack would hold the message forever.
    mongo_eval "db.slates.updateMany({queue: '${queue}', made: false}, {\$set: {made: true}})" >/dev/null
    jq -e '.two_sockets.both_queues_empty_at_subscribe and .two_sockets.made == ["Ok", "Ok"]' \
        <<<"${report}" >/dev/null || fail "two sockets did not serve two addresses: ${report}" || return 1
    jq -e '.error_kinds_seen == ["InvalidSignature"]' <<<"${report}" >/dev/null ||
        fail "unexpected relay errors: $(jq -c .error_kinds_seen <<<"${report}")" || return 1
    DETAIL="one socket serves the last subscribed address only; two sockets serve two"
}

# Fact 6. One socket drains several addresses in turn. No wallet takes part: the probe holds every
# key, and fresh drains collect what the shared socket left, so nothing stays pending.
probe_mailbox_drains() {
    local report
    report="$(probe_saved drains drains "${RELAY_URL}")" || fail "the drains probe failed" || return 1
    local mode
    for mode in send listener; do
        jq -e --arg m "${mode}" '.[$m] | (.posts + .late_posts | all(. == "Ok"))
            and (.drained | length == 2)
            and (.drained | all(.delivered == 2 and .opened == 2 and .repeats == 0
                and .made == ["Ok", "Ok"]))' <<<"${report}" >/dev/null ||
            fail "sequential subscribes in ${mode} mode did not drain both addresses: ${report}" || return 1
        jq -e --arg m "${mode}" '.[$m].collected_later | map(.delivered) == [1, 1]
            and all(.made == ["Ok"])' <<<"${report}" >/dev/null ||
            fail "the late messages in ${mode} mode were not left for the next drain" || return 1
    done
    jq -e '.send.late_arrivals == [] and .send.error_kinds_seen == []' <<<"${report}" >/dev/null ||
        fail "a send-mode socket was handed live messages: ${report}" || return 1
    jq -e '.listener.late_arrivals == [{"addressed_to": "first", "made": "InvalidSignature"}]' \
        <<<"${report}" >/dev/null ||
        fail "the listener socket did not get the earlier address's late message, unackable" || return 1
    jq -e '.kept.first_message_kept and .kept.second_subscribe_answer == "Ok"
        and (.kept.second_message_opened | not)
        and (.kept.collected_later | map(.delivered) == [1, 1])' <<<"${report}" >/dev/null ||
        fail "a kept message did not hold back the next address on its socket: ${report}" || return 1
    DETAIL="2+2 messages drained on one socket in send and listener mode; late messages wait for the next drain; listener socket gets the earlier key's late message, unackable; a kept message stops the socket serving the next key"
}

# Fact 3: a payload that is not a slate is never acknowledged by a stock listener, so the relay
# hands it out again. Runs last; the stack is torn down afterwards.
probe_non_slate_unacknowledged() {
    local payload="${PROBE_DIR}/non-slate.json"
    printf '{"type":"note","text":"not a slate"}' >"${payload}"
    local deliveries parse_errors
    deliveries="$(relay_deliveries_to "${PEER_KEY}")"
    parse_errors="$(peer_log_count 'Unable to parse slate')"
    probe_saved non-slate-post post "${PROBE_KEY}" "${RELAY_URL}" "${PEER_ADDRESS}" "${payload}" |
        jq -e '.answer == "Ok"' >/dev/null || fail "the relay refused the payload" || return 1
    wait_until "a second delivery" 120 relay_delivered_more_than "${PEER_KEY}" $((deliveries + 1)) ||
        fail "the relay did not hand the payload out twice" || return 1
    local unmade now_errors
    unmade="$(relay_unmade_for "${PEER_KEY}")"
    now_errors="$(peer_log_count 'Unable to parse slate')"
    ((unmade == 1)) || fail "${unmade} unacknowledged messages, expected the payload" || return 1
    ((now_errors >= parse_errors + 2)) || fail "the listener logged no parse failures" || return 1
    mongo_eval "db.slates.updateMany({queue: '${PEER_KEY}', made: false}, {\$set: {made: true}})" >/dev/null
    DETAIL="delivered $(($(relay_deliveries_to "${PEER_KEY}") - deliveries)) times, refused as no slate each time, never acknowledged"
}

PROBE_STEPS=(
    "fact 4 relay sessions and addresses:probe_relay_sessions"
    "fact 6 one socket drains mailboxes in turn:probe_mailbox_drains"
    "fact 3 non-slate payload unacknowledged:probe_non_slate_unacknowledged"
)
