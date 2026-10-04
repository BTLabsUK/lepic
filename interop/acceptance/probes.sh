# Probes of the relay and epic-wallet behaviour that invoices and notices over Epicbox rely on
# (plan task V-10, recorded in docs/compat/epicbox.md). `run.sh --probes` sources this after
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
INVOICE_ID=""

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

unmade_for() { mongo_eval "print(db.slates.countDocuments({queue: '$1', made: false}))"; }

# How often the relay has handed a message for this key to a socket so far.
relay_deliveries_to() { dc logs epicbox 2>/dev/null | grep -cE "(Sent|Passthrough) slate to $1\$" || true; }

relay_delivered_more_than() { (($(relay_deliveries_to "$1") > $2)); }

peer_log_count() {
    dc exec -T peer sh -c "grep -c '$1' /data/.epic/user/epic-wallet.log 2>/dev/null || true"
}

# Adds the capability marker LEPIC plans to put in the V3 slates it sends.
with_marker() { jq -c '. + {lepic: {version: 1}}' "$1"; }

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
    [[ "$(unmade_for "${queue}")" == 1 ]] ||
        fail "the first address's late message is not left unacknowledged" || return 1
    # Nothing listens on that probe-only key, so a kept stack would hold the message forever.
    mongo_eval "db.slates.updateMany({queue: '${queue}', made: false}, {\$set: {made: true}})" >/dev/null
    jq -e '.two_sockets.both_queues_empty_at_subscribe and .two_sockets.made == ["Ok", "Ok"]' \
        <<<"${report}" >/dev/null || fail "two sockets did not serve two addresses: ${report}" || return 1
    jq -e '.error_kinds_seen == ["InvalidSignature"]' <<<"${report}" >/dev/null ||
        fail "unexpected relay errors: $(jq -c .error_kinds_seen <<<"${report}")" || return 1
    local named
    named="$(grep -c TooManySubscriptions "${ACCEPTANCE_DIR}/../.work/src/epic-epicbox-docker/app_mongo.js" || true)"
    DETAIL="one socket serves the last subscribed address only; two sockets serve two; relay source names TooManySubscriptions ${named} times"
}

# Facts 1 and 2 for an invoice: a stock listener sends LEPIC's V3 I1 straight back.
probe_invoice_bounce() {
    local i1="${STATE_DIR}/probe-i1.slate"
    INVOICE_ID="$(lepic invoice issue 0.5 --to-file "${i1}" | jq -r .slate_id)" ||
        fail "lepic invoice issue failed" || return 1
    with_marker "${i1}" >"${PROBE_DIR}/i1-marked.json"
    local before
    before="$(peer_log_count 'Unable to parse slate')"
    probe_saved i1-post post "${PROBE_KEY}" "${RELAY_URL}" "${PEER_ADDRESS}" "${PROBE_DIR}/i1-marked.json" |
        jq -e '.answer == "Ok"' >/dev/null || fail "the relay refused the I1" || return 1
    local drained
    drained="$(probe_saved i1-drain drain "${PROBE_KEY}" "${RELAY_URL}" "${PROBE_DIR}/i1-back" 1 90)" ||
        fail "the probe drain failed" || return 1
    jq -e --arg peer "${PEER_KEY}" '.messages | length == 1 and (.[0].from | startswith($peer))
        and .[0].made == "Ok"' <<<"${drained}" >/dev/null ||
        fail "nothing came back from the stock listener: ${drained}" || return 1
    local back="${PROBE_DIR}/i1-back/1.json"
    [[ "$(jq -r .id "${back}")" == "${INVOICE_ID}" ]] || fail "a different slate came back" || return 1
    jq -e 'has("lepic") | not' "${back}" >/dev/null || fail "the marker survived the bounce" || return 1
    jq -S 'del(.lepic)' "${PROBE_DIR}/i1-marked.json" >"${PROBE_DIR}/i1-sent.sorted.json"
    jq -S . "${back}" >"${PROBE_DIR}/i1-back.sorted.json"
    diff "${PROBE_DIR}/i1-sent.sorted.json" "${PROBE_DIR}/i1-back.sorted.json" \
        >"${PROBE_DIR}/i1-bounce.diff" || true
    [[ ! -s "${PROBE_DIR}/i1-bounce.diff" ]] ||
        fail "the bounce changed the slate, see probes/i1-bounce.diff" || return 1
    [[ "$(unmade_for "${PEER_KEY}")" == 0 ]] || fail "the stock listener left the I1 unacknowledged" || return 1
    [[ "$(peer_log_count 'Unable to parse slate')" == "${before}" ]] ||
        fail "the stock listener could not parse LEPIC's V3 I1" || return 1
    ! ew_tx_known peer "${INVOICE_ID}" || fail "the stock listener recorded the I1" || return 1
    DETAIL="I1 ${INVOICE_ID} acknowledged, not recorded, posted back identical except the marker, which is gone"
}

# Fact 2 for a reply, and fact 1's later message: the stock listener answers a V3 S1 that
# carries the marker, after the bounce, and acknowledges it.
probe_reply_drops_marker() {
    ew funder send -m file -d /exchange/probe-s1.slate -c 1 -s smallest -b 1440 1 >>"${RUN_LOG}" ||
        fail "epic-wallet send to file failed" || return 1
    local s1="${EXCHANGE_DIR}/probe-s1.slate"
    jq -e '.version_info.version == 3 and .ttl_cutoff_height != null' "${s1}" >/dev/null ||
        fail "the funder's S1 is not V3 with a TTL" || return 1
    with_marker "${s1}" >"${PROBE_DIR}/s1-marked.json"
    probe_saved s1-post post "${PROBE_KEY}" "${RELAY_URL}" "${PEER_ADDRESS}" "${PROBE_DIR}/s1-marked.json" |
        jq -e '.answer == "Ok"' >/dev/null || fail "the relay refused the S1" || return 1
    local drained
    drained="$(probe_saved s1-drain drain "${PROBE_KEY}" "${RELAY_URL}" "${PROBE_DIR}/s1-back" 1 90)" ||
        fail "the probe drain failed" || return 1
    jq -e '.messages | length == 1' <<<"${drained}" >/dev/null || fail "no S2 came back: ${drained}" || return 1
    local back="${PROBE_DIR}/s1-back/1.json"
    jq -e --arg id "$(jq -r .id "${s1}")" '.id == $id and (.participant_data | length) == 2
        and .version_info.version == 3 and (has("lepic") | not)' "${back}" >/dev/null ||
        fail "the reply is not a V3 S2 without the marker" || return 1
    [[ "$(unmade_for "${PEER_KEY}")" == 0 ]] || fail "the stock listener left the S1 unacknowledged" || return 1
    DETAIL="V3 S1 with marker answered with a V3 S2 without it; acknowledged after the bounce"
}

# Fact 5: the policy reads a V3 invoice with the marker as V3, with and without a TTL.
probe_policy_decode() {
    local i1="${PROBE_DIR}/i1-marked.json" with_ttl="${PROBE_DIR}/i1-marked-ttl.json" plain ttl
    jq -c '.ttl_cutoff_height = "1440"' "${i1}" >"${with_ttl}"
    plain="$(probe_saved decode-i1 decode "${i1}")" || fail "the policy refused the marked I1" || return 1
    ttl="$(probe_saved decode-i1-ttl decode "${with_ttl}")" || fail "the policy refused the marked I1 with a TTL" || return 1
    jq -e '.codec == "legacy-v3" and .stage == "I1" and .ttl_cutoff_height == null' <<<"${plain}" >/dev/null ||
        fail "marked I1 decoded as ${plain}" || return 1
    jq -e '.codec == "legacy-v3" and .stage == "I1" and .ttl_cutoff_height == "1440"' <<<"${ttl}" >/dev/null ||
        fail "marked I1 with TTL decoded as ${ttl}" || return 1
    DETAIL="$(jq -r '"\(.codec) \(.stage) header \(.header)"' <<<"${plain}"), TTL read as $(jq -r .ttl_cutoff_height <<<"${ttl}")"
}

# Fact 3: a payload that is not a slate is never acknowledged by a stock listener, so the relay
# hands it out again. Runs last; the stack is torn down afterwards.
probe_non_slate_unacknowledged() {
    local notice="${PROBE_DIR}/notice.json"
    printf '{"lepic":1,"type":"posted","slate_id":"%s"}' "${INVOICE_ID}" >"${notice}"
    local deliveries parse_errors
    deliveries="$(relay_deliveries_to "${PEER_KEY}")"
    parse_errors="$(peer_log_count 'Unable to parse slate')"
    probe_saved notice-post post "${PROBE_KEY}" "${RELAY_URL}" "${PEER_ADDRESS}" "${notice}" |
        jq -e '.answer == "Ok"' >/dev/null || fail "the relay refused the notice" || return 1
    wait_until "a second delivery" 120 relay_delivered_more_than "${PEER_KEY}" $((deliveries + 1)) ||
        fail "the relay did not hand the notice out twice" || return 1
    local unmade now_errors
    unmade="$(unmade_for "${PEER_KEY}")"
    now_errors="$(peer_log_count 'Unable to parse slate')"
    ((unmade == 1)) || fail "${unmade} unacknowledged messages, expected the notice" || return 1
    ((now_errors >= parse_errors + 2)) || fail "the listener logged no parse failures" || return 1
    mongo_eval "db.slates.updateMany({queue: '${PEER_KEY}', made: false}, {\$set: {made: true}})" >/dev/null
    DETAIL="delivered $(($(relay_deliveries_to "${PEER_KEY}") - deliveries)) times, refused as no slate each time, never acknowledged"
}

PROBE_STEPS=(
    "fact 4 relay sessions and addresses:probe_relay_sessions"
    "fact 1, 2 stock listener bounces a V3 I1:probe_invoice_bounce"
    "fact 2 stock reply drops the marker:probe_reply_drops_marker"
    "fact 5 policy decodes a marked V3 invoice:probe_policy_decode"
    "fact 3 non-slate payload unacknowledged:probe_non_slate_unacknowledged"
)
