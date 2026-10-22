# The import-history scenario: builds a history in a fresh epic-wallet v4.0.2 wallet (`hist`, in the
# peer container, apart from the peer's own wallet), copies the stopped wallet's folder, imports
# it into lepic and compares both sides field by field. Sourced by scenarios.sh.
# shellcheck shell=bash

HIST_HOME=/data/hist
HIST_PASSWORD=hist-password
HIST_ADDRESS=""
FUNDER_ADDRESS=""
# The folder `epic-wallet --usernet` keeps its config and wallet_data in under HIST_HOME.
HIST_USER_DIR="${HIST_HOME}/.epic/user"
HISTORY_OUT="${HISTORY_OUT:-${INTEROP_DIR}/.work/history}"

# epic-wallet of the `hist` wallet, colour codes stripped.
hw() {
    local status
    dc exec -T peer sh -c "HOME=${HIST_HOME} exec epic-wallet --usernet -p ${HIST_PASSWORD} \"\$@\"" sh "$@" \
        2>>"${RUN_LOG}" | sed 's/\x1b\[[0-9;]*[mK]//g; s/\x1b[()][A-Z0-9]//g'
    status="${PIPESTATUS[0]}"
    ((status == 0)) || printf 'epic-wallet (hist) %s exited %d\n' "$*" "${status}" >>"${RUN_LOG}"
    return "${status}"
}

# `pay` of the hist wallet; it asks for the amount on a terminal prompt (see ew_pay).
hw_pay() {
    local amount="$1" status command
    shift
    command="HOME=${HIST_HOME} epic-wallet --usernet -p ${HIST_PASSWORD} pay $(printf '%q ' "$@")"
    printf '%s\n' "${amount}" |
        dc exec -T peer timeout 120 script -qec "${command}" /dev/null >>"${RUN_LOG}" 2>&1
    status="${PIPESTATUS[1]}"
    ((status == 0)) || printf 'epic-wallet (hist) pay %s exited %d\n' "$*" "${status}" >>"${RUN_LOG}"
    return "${status}"
}

hist_init() {
    dc exec -T peer sh -c "
        set -eu
        rm -rf ${HIST_HOME}; mkdir -p ${HIST_HOME}
        export HOME=${HIST_HOME}
        epic-wallet --usernet -p ${HIST_PASSWORD} init >/dev/null
        config=${HIST_USER_DIR}/epic-wallet.toml
        set_key() { grep -q \"^\$1 = \" \"\${config}\" || exit 1; sed -i \"s|^\$1 = .*|\$1 = \$2|\" \"\${config}\"; }
        set_key api_listen_interface '\"127.0.0.1\"'
        set_key check_node_api_http_addr '\"http://127.0.0.1:23413\"'
        set_key node_api_secret_path '\"/node/.foreign_api_secret\"'
        set_key use_tor_listener false
        set_key epicbox_domain '\"localhost\"'
        set_key epicbox_port 3423
        set_key epicbox_protocol_unsecure true
        set_key stdout_log_level '\"Warning\"'
        set_key log_to_file true
        set_key file_log_level '\"Info\"'" >>"${RUN_LOG}" 2>&1
}

hist_address() { hw address | awk '/^Epicbox address/ {getline; getline; print; exit}'; }

hist_listen_started() { dc exec -T peer sh -c "grep -c 'Starting epicbox listener' ${HIST_USER_DIR}/epic-wallet.log 2>/dev/null || true"; }

hist_listen_start() {
    hist_listen_stop
    local before
    before="$(hist_listen_started)"
    dc exec -d peer sh -c "echo \$\$ >/data/hist.pid; HOME=${HIST_HOME} exec epic-wallet --usernet -p ${HIST_PASSWORD} listen -m epicbox >>/data/hist-listen.log 2>&1"
    wait_until "the hist listener" 30 hist_listener_after "${before}" || return 1
    sleep 2
}

hist_listener_after() { (($(hist_listen_started) > $1)); }

hist_listen_stop() {
    dc exec -T peer sh -c '
        [ -f /data/hist.pid ] || exit 0
        pid="$(cat /data/hist.pid)"
        kill "${pid}" 2>/dev/null || true
        while kill -0 "${pid}" 2>/dev/null; do sleep 0.2; done
        rm -f /data/hist.pid'
}

# Prints one amount of `hw info` (a row label prefix) in units.
hw_info_units() {
    local value
    value="$(hw "${@:2}" info | awk -F'|' -v label="$1" 'index($1, label) == 1 {gsub(/ /, "", $2); print $2; exit}')"
    to_units "${value:-0}"
}

hw_awaiting_none() { (($(hw_info_units "Awaiting Confirmation" "$@") == 0)); }
hw_spendable_at_least() { (($(hw_info_units "Currently Spendable") >= $1)); }

hw_tx_count_at_least() { (($(hw_tx_count) >= $1)); }

hw_tx_count() { hw "${@}" txs | grep -cE '^ [0-9]+ ' || true; }

hw_confirmed_count() { hw "${@:1}" txs | grep -cE '^ [0-9]+ .* true ' || true; }

hw_confirmed_at_least() {
    local want="$1"
    shift
    (($(hw_confirmed_count "$@") >= want))
}

# Waits until the wallet's log holds `n` confirmed transactions (of the account given after it).
hw_wait_confirmed() {
    local n="$1"
    shift
    wait_until "${n} confirmed transactions in the hist wallet" 240 hw_confirmed_at_least "${n}" "$@"
}

# Slate id of a slate file in the exchange volume.
slate_file_id() { dc exec -T funder cat "$1" | jq -r .id; }

# Runs a command and fails the history build with its name when it does not succeed.
step() {
    local what="$1"
    shift
    log "history: ${what}"
    "$@" >>"${RUN_LOG}" || { DETAIL="history step failed: ${what}"; return 1; }
}

# Builds the hist wallet's history: every kind of entry epic-wallet 4.0.2 can keep that the
# import has to carry across. Amounts differ so each entry is told apart by its amount.
hist_build() {
    local x=/exchange id
    HIST_ADDRESS="$(hist_address)"
    FUNDER_ADDRESS="$(ew_address funder)"
    [[ -n "${HIST_ADDRESS}" && -n "${FUNDER_ADDRESS}" ]] || { DETAIL="no epicbox addresses"; return 1; }
    HIST_ADDRESS="${HIST_ADDRESS%%:*}:3423"
    FUNDER_ADDRESS="${FUNDER_ADDRESS%%:*}:3423"
    ew_listen_start funder && hist_listen_start || { DETAIL="listeners did not start"; return 1; }

    # 1. received over epicbox, with the sender's message
    step "funder sends 10 over epicbox" ew funder send -m epicbox -d "${HIST_ADDRESS}" -c 1 -s smallest -g "hello from the funder" 10 || return 1
    wait_until "hist received the epicbox slate" 60 hw_tx_count_at_least 1 || { DETAIL="no epicbox receipt"; return 1; }
    hw_wait_confirmed 1 || { DETAIL="epicbox receipt did not confirm"; return 1; }
    # 2. received by file, with a message on both sides
    step "funder sends 5 by file" ew funder send -m file -d "${x}/h-file.slate" -c 1 -s smallest -g "by file from the funder" 5 || return 1
    step "hist receives the file" hw receive -i "${x}/h-file.slate" -g "thanks for the file" || return 1
    step "funder finalizes" ew funder finalize -i "${x}/h-file.slate.response" || return 1
    hw_wait_confirmed 2 || { DETAIL="file receipt did not confirm"; return 1; }
    # 3. sent over epicbox with a message: fee and change
    step "hist sends 2.5 over epicbox" hw send -m epicbox -d "${FUNDER_ADDRESS}" -c 1 -s smallest -g "back to the funder" 2.5 || return 1
    wait_until "hist finalized the send" 90 hw_tx_count_at_least 3 || { DETAIL="no send in the log"; return 1; }
    hw_wait_confirmed 3 || { DETAIL="epicbox send did not confirm"; return 1; }
    # 4. a send that is cancelled
    step "hist writes a send of 1.25" hw send -m file -d "${x}/h-cancel-send.slate" -c 1 -s smallest -g "to be cancelled" 1.25 || return 1
    id="$(slate_file_id "${x}/h-cancel-send.slate")"
    step "hist cancels the send" hw cancel -t "${id}" || return 1
    # 5. a receipt that is cancelled
    step "funder sends 1.75 by file" ew funder send -m file -d "${x}/h-cancel-recv.slate" -c 1 -s smallest 1.75 || return 1
    id="$(slate_file_id "${x}/h-cancel-recv.slate")"
    step "hist receives it" hw receive -i "${x}/h-cancel-recv.slate" || return 1
    step "hist cancels the receipt" hw cancel -t "${id}" || return 1
    step "funder cancels its side" ew funder cancel -t "${id}" || return 1
    # 6. an invoice hist issues and the funder pays
    step "hist invoices 0.7" hw invoice -d "${x}/h-inv.slate" -g "invoice from hist" 0.7 || return 1
    step "funder pays the invoice" ew_pay funder 0.7 -i "${x}/h-inv.slate" -d "${x}/h-inv.slate.response" -c 1 -s smallest || return 1
    step "hist finalizes the invoice" hw finalize -i "${x}/h-inv.slate.response" || return 1
    hw_wait_confirmed 4 || { DETAIL="invoice did not confirm"; return 1; }
    # 7. an invoice the funder issues and hist pays
    step "funder invoices 0.4" ew funder invoice -d "${x}/f-inv.slate" 0.4 || return 1
    step "hist pays the invoice" hw_pay 0.4 -i "${x}/f-inv.slate" -d "${x}/f-inv.slate.response" -c 1 -s smallest -g "paid by hist" || return 1
    step "funder finalizes" ew funder finalize -i "${x}/f-inv.slate.response" || return 1
    hw_wait_confirmed 5 || { DETAIL="paid invoice did not confirm"; return 1; }
    # 8. a second account that receives
    step "hist creates savings" hw account -c savings || return 1
    step "funder sends 4 by file" ew funder send -m file -d "${x}/h-savings.slate" -c 1 -s smallest -g "for savings" 4 || return 1
    step "savings receives it" hw -a savings receive -i "${x}/h-savings.slate" || return 1
    step "funder finalizes" ew funder finalize -i "${x}/h-savings.slate.response" || return 1
    hw_wait_confirmed 1 -a savings || { DETAIL="savings receipt did not confirm"; return 1; }
    # 9. a send that stays unfinished
    step "hist writes an open send of 1.5" hw send -m file -d "${x}/h-open.slate" -c 1 -s smallest -g "left open" 1.5 || return 1
    hist_listen_stop
    ew_listen_stop funder
}

# sha256 of every file under a directory in a container, as "hash  relative-path" sorted by path.
tree_hashes() {
    dc exec -T "$1" sh -c "cd '$2' && find . -type f -print0 | sort -z | xargs -0 sha256sum"
}

# lepic with its own data directory (the history scenario keeps several wallets side by side).
lp() {
    local dir="$1" status=0
    shift
    dc exec -T -e "LEPIC_DATA_DIR=${dir}" lepic lepic "$@" 2>>"${RUN_LOG}" || status=$?
    ((status == 0)) || printf 'lepic (%s) %s exited %d\n' "${dir}" "$*" "${status}" >>"${RUN_LOG}"
    return "${status}"
}

# import-seed (dir, password of the seed file, seed path, options); the file's password comes in on stdin.
lp_import_seed() {
    local dir="$1" password="$2" status=0
    shift 2
    printf '%s\n' "${password}" |
        dc exec -T -e "LEPIC_DATA_DIR=${dir}" lepic lepic wallet import-seed "$@" 2>>"${RUN_LOG}" || status=$?
    return "${status}"
}

# Copies a directory from one container's /data to another's, as the receiving user.
copy_between() {
    local from="$1" name="$2" to="$3" as="$4"
    dc exec -T "${from}" tar -C /data -cf - "${name}" |
        dc exec -T "${to}" tar -C /data --transform "s,^${name},${as}," -xf -
}

# The reference wallet's own view of one account, saved as files in $1/before.
hist_snapshot_before() {
    local out="$1/before" account
    mkdir -p "${out}"
    for account in default savings; do
        hw -a "${account}" export_tx --all -o "/data/hist-before-${account}.json" >/dev/null || return 1
        dc exec -T peer cat "/data/hist-before-${account}.json" >"${out}/tx-${account}.json"
        hw -a "${account}" txs >"${out}/txs-${account}.txt"
        hw -a "${account}" info >"${out}/info-${account}.txt"
        hw -a "${account}" outputs -f >"${out}/outputs-${account}.txt"
        hw -a "${account}" outputs >"${out}/outputs-live-${account}.txt"
    done
    hw account >"${out}/accounts.txt"
}

tip_at_least() { (($(tip_height) >= $1)); }

# Mines until everything the build did is spendable, then stops the wallet's processes.
hist_settle() {
    local account
    hw_wait_confirmed 5 || return 1
    hw_wait_confirmed 1 -a savings || return 1
    # Both wallets count ten confirmations; the last receipt is at least that deep.
    local target=$(($(tip_height) + 12))
    wait_until "height ${target}" 240 tip_at_least "${target}"
}

# Everything lepic reports about the imported wallet in `dir`, as JSON files under `out`.
lepic_dump() {
    local dir="$1" out="$2" account id suffix
    mkdir -p "${out}"
    lp "${dir}" wallet info >"${out}/info.json" || return 1
    for suffix in "" "-again"; do
        for account in default savings; do
            lp "${dir}" tx list -a "${account}" >"${out}/tx-list-${account}${suffix}.json" || return 1
        done
        [[ -n "${suffix}" ]] && break
        for account in default savings; do
            for id in $(jq -r '.transactions[].tx_id' "${out}/tx-list-${account}.json"); do
                lp "${dir}" tx show "${id}" >"${out}/tx-${account}-${id}.json" || return 1
            done
        done
        # The second run must change nothing.
        lp "${dir}" wallet import-history "${COPY_DIR}/.epic/user" >"${out}/import-again.json" || return 1
    done
}

history_fail() {
    DETAIL="$*"
    return 1
}

scenario_import_history() {
    local stamp out
    stamp="$(date -u +%H%M%S)"
    out="${HISTORY_OUT}/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "${out}"
    COPY_DIR="/data/hist-copy-${stamp}"
    local seed="${COPY_DIR}/.epic/user/wallet_data/wallet.seed"

    hist_init || history_fail "could not create the hist wallet" || return 1
    hist_build || return 1
    hist_settle || history_fail "the hist wallet did not settle" || return 1

    log "history: copying the stopped wallet's folder"
    tree_hashes peer "${HIST_HOME}" >"${out}/source.sha256"
    copy_between peer hist lepic "hist-copy-${stamp}" || history_fail "copy failed" || return 1
    tree_hashes lepic "${COPY_DIR}" >"${out}/copy-before.sha256"
    diff -q "${out}/source.sha256" "${out}/copy-before.sha256" >/dev/null ||
        history_fail "the copy differs from the source" || return 1
    hist_snapshot_before "${out}" || history_fail "epic-wallet snapshot failed" || return 1

    log "history: import with the history first, then the scan"
    lp_import_seed "/data/lepic-hist-A-${stamp}" "${HIST_PASSWORD}" "${seed}" --no-scan >/dev/null ||
        history_fail "import-seed (history first) failed" || return 1
    mkdir -p "${out}/lepic-history-then-scan" "${out}/lepic-scan-then-history"
    lp "/data/lepic-hist-A-${stamp}" wallet import-history "${COPY_DIR}/.epic/user" \
        >"${out}/lepic-history-then-scan/import.json" || history_fail "import-history (A) failed" || return 1
    lp "/data/lepic-hist-A-${stamp}" wallet scan >/dev/null || history_fail "scan (A) failed" || return 1
    lepic_dump "/data/lepic-hist-A-${stamp}" "${out}/lepic-history-then-scan" || history_fail "lepic dump (A) failed" || return 1

    log "history: import with the scan first, then the history"
    lp_import_seed "/data/lepic-hist-B-${stamp}" "${HIST_PASSWORD}" "${seed}" >/dev/null ||
        history_fail "import-seed (scan first) failed" || return 1
    lp "/data/lepic-hist-B-${stamp}" wallet import-history "${COPY_DIR}/.epic/user" \
        >"${out}/lepic-scan-then-history/import.json" || history_fail "import-history (B) failed" || return 1
    lepic_dump "/data/lepic-hist-B-${stamp}" "${out}/lepic-scan-then-history" || history_fail "lepic dump (B) failed" || return 1

    tree_hashes lepic "${COPY_DIR}" >"${out}/copy-after.sha256"

    log "history: another wallet's folders into a wallet made from the peer's seed"
    copy_between peer .epic lepic "peer-copy-${stamp}" || return 1
    copy_between funder .epic lepic "funder-copy-${stamp}" 2>/dev/null || true
    local other="/data/lepic-hist-C-${stamp}" status
    lp_import_seed "${other}" peer-password "/data/peer-copy-${stamp}/user/wallet_data/wallet.seed" --no-scan >/dev/null ||
        history_fail "import-seed of the peer's seed failed" || return 1
    mkdir -p "${out}/negative"
    lp "${other}" wallet import-history "/data/funder-copy-${stamp}/user" >"${out}/negative/funder.json" || true
    lp "${other}" wallet import-history "${COPY_DIR}/.epic/user" >"${out}/negative/hist.json" || true
    lp "${other}" tx list >"${out}/negative/tx-list.json" || true

    log "history: comparing"
    local failures=0
    python3 -I "${INTEROP_DIR}/history_compare.py" "${out}" >"${out}/summary.txt" || failures=$((failures + 1))
    cat "${out}/summary.txt" >&2
    cmp -s "${out}/copy-before.sha256" "${out}/copy-after.sha256" || {
        log "FAIL: the copy changed during the import"
        failures=$((failures + 1))
    }
    for who in funder hist; do
        [[ "$(jq -r .status "${out}/negative/${who}.json")" == other-wallet ]] || {
            log "FAIL: ${who}'s folder into the peer-seeded wallet: $(cat "${out}/negative/${who}.json")"
            failures=$((failures + 1))
        }
    done
    [[ "$(jq '.transactions | length' "${out}/negative/tx-list.json")" == 0 ]] || {
        log "FAIL: the refused imports stored transactions"
        failures=$((failures + 1))
    }
    ((failures == 0)) || history_fail "${failures} group(s) of checks failed; report in ${out}/report.md" || return 1
    DETAIL="history imported in both orders and matches epic-wallet; report ${out}/report.md"
}
