#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The legacy interop gate: the stock 4.x send and receive scenarios between lepic and epic-wallet,
# both directions, over Epicbox, HTTP and file, with every frame lepic writes recorded and checked.
#
#   ./gate.sh            build, then run both passes on a fresh stack each
#   ./gate.sh --no-build use the binaries already in .work/bin and .work/capture-target
#
# Pass 1 runs GATE_PINNED against the pinned epic-wallet release (pins.env). Pass 2 runs every
# legacy scenario against the previous classic release. The two releases parse slates and
# Epicbox frames differently, so a frame one accepts can still break the other.
#
# The gate fails unless exactly GATE_CASES scenarios ran and all passed, and it prints the count.
# It refuses SCENARIO_FILTER and PEER_WALLET: it sets both itself.
#
# Tor is a named gap (TOR_GAP): the stack's network is internal, so there is no Tor network for
# either wallet to reach, and the gate does not open one.
#
# Frames: frames.py reads the loopback recording (Epicbox client frames lepic sent, opened with
# the peer's key; HTTP bodies lepic sent or answered) and the slate files lepic wrote, and prints
# each one that holds a "lepic" key. Lepic writes no such key on the classic lane, so any such
# frame fails the gate.
set -euo pipefail

INTEROP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${INTEROP_DIR}/lib.sh"
# shellcheck source=scenarios.sh
source "${INTEROP_DIR}/scenarios.sh"

readonly GATE_PINNED=(
    "lepic sends to epic-wallet"
    "epic-wallet sends to lepic"
    "lepic sends to epic-wallet by file"
    "epic-wallet sends to lepic by file"
    "lepic invoices epic-wallet by file"
    "epic-wallet invoices lepic by file"
    "lepic sends over http"
    "epic-wallet sends over http"
    "epic-wallet sends over http to serve"
)
readonly GATE_CASES_PINNED=9
readonly GATE_CASES_LEGACY=6
readonly GATE_CASES=15
# Stock sends over Tor and stock receives over Tor.
readonly TOR_GAP=2
readonly TOR_GAP_REASON="the stack's network is internal and has no Tor network to reach"

# At least this many frames of each kind per pass, or the recording missed something.
readonly CAPTURE_MINIMUM_PINNED='{"epicbox plaintext": 2, "http request": 1, "http response": 2, "slate file": 6}'
readonly CAPTURE_MINIMUM_LEGACY='{"epicbox plaintext": 2, "slate file": 6}'

build=true
for arg in "$@"; do
    case "${arg}" in
        --no-build) build=false ;;
        *) echo "unknown option ${arg}" >&2; exit 2 ;;
    esac
done
if [[ -n "${SCENARIO_FILTER:-}" || -n "${PEER_WALLET:-}" ]]; then
    echo "gate.sh sets SCENARIO_FILTER and PEER_WALLET itself; unset them" >&2
    exit 2
fi
if ((GATE_CASES != GATE_CASES_PINNED + GATE_CASES_LEGACY)) \
    || ((${#GATE_PINNED[@]} != GATE_CASES_PINNED)) \
    || ((${#LEGACY_SCENARIOS[@]} != GATE_CASES_LEGACY)); then
    echo "the gate's case lists and counts disagree" >&2
    exit 2
fi
known="|$(printf '%s|' "${SCENARIOS[@]%%:*}")"
for name in "${GATE_PINNED[@]}"; do
    [[ "${known}" == *"|${name}|"* ]] || {
        echo "no scenario named '${name}'" >&2
        exit 2
    }
done
hold_stack lepic-interop-gate

started=${SECONDS}
gate_dir="${INTEROP_DIR}/.work/logs/gate-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${gate_dir}"
open_frames="${INTEROP_DIR}/.work/capture-target/release/open-frames"
if [[ "${build}" == true ]]; then
    read -ra cargo <<<"${CARGO:-cargo}"
    "${cargo[@]}" build --release --locked --manifest-path "${INTEROP_DIR}/capture/Cargo.toml" \
        --target-dir "${INTEROP_DIR}/.work/capture-target"
fi
[[ -x "${open_frames}" ]] || { echo "${open_frames} is missing; run without --no-build" >&2; exit 2; }

filter="^($(IFS='|'; echo "${GATE_PINNED[*]}"))$"
pinned_status=0
INTEROP_CAPTURE=1 INTEROP_LOG_DIR="${gate_dir}/pinned" SCENARIO_FILTER="${filter}" \
    "${INTEROP_DIR}/run.sh" "$@" || pinned_status=$?
legacy_status=0
PEER_WALLET=legacy INTEROP_CAPTURE=1 INTEROP_LOG_DIR="${gate_dir}/legacy" \
    "${INTEROP_DIR}/run.sh" --no-build || legacy_status=$?

# Scenarios that ran in a pass, setup not counted.
ran_in() {
    [[ -f "$1/results.tsv" ]] || { echo 0; return; }
    tail -n +2 "$1/results.tsv" | grep -c . || true
}
passed_in() {
    [[ -f "$1/results.tsv" ]] || { echo 0; return; }
    tail -n +2 "$1/results.tsv" | grep -c $'\tPASS$' || true
}

frames_status=0
for pass in pinned legacy; do
    capture="${gate_dir}/${pass}/capture"
    minimum="${CAPTURE_MINIMUM_PINNED}"
    [[ "${pass}" == legacy ]] && minimum="${CAPTURE_MINIMUM_LEGACY}"
    printf '\nFrames, %s pass:\n' "${pass}"
    if [[ ! -f "${capture}/lo.pcap" ]]; then
        echo "no capture for the ${pass} pass"
        frames_status=2
        continue
    fi
    # shellcheck source=/dev/null
    peer_address="$(source "${capture}/addresses.env" && echo "${PEER_ADDRESS}")"
    python3 -I "${INTEROP_DIR}/capture/frames.py" --posts "${capture}" \
        | PEER_WALLET_PASSWORD=peer-password "${open_frames}" "${capture}/peer-wallet.seed" "${peer_address}" \
            >"${capture}/opened.jsonl" || frames_status=2
    status=0
    CAPTURE_MINIMUM="${minimum}" \
        python3 -I "${INTEROP_DIR}/capture/frames.py" "${capture}" >"${capture}/frames.txt" || status=$?
    cat "${capture}/frames.txt"
    if ((status > frames_status)); then frames_status=${status}; fi
done

ran=$(($(ran_in "${gate_dir}/pinned") + $(ran_in "${gate_dir}/legacy")))
passed=$(($(passed_in "${gate_dir}/pinned") + $(passed_in "${gate_dir}/legacy")))
elapsed=$((SECONDS - started))
printf '\nGate: ran %d of %d cases, %d passed (pinned %d of %d, legacy %d of %d)\n' \
    "${ran}" "${GATE_CASES}" "${passed}" \
    "$(ran_in "${gate_dir}/pinned")" "${GATE_CASES_PINNED}" \
    "$(ran_in "${gate_dir}/legacy")" "${GATE_CASES_LEGACY}"
printf 'Gap: Tor, %d cases (stock sends over Tor, stock receives over Tor): %s\n' "${TOR_GAP}" "${TOR_GAP_REASON}"
printf 'Run time: %dm%02ds\n' $((elapsed / 60)) $((elapsed % 60))
printf 'Logs: %s\n' "${gate_dir}"

fail=0
((ran == GATE_CASES)) || { log "expected ${GATE_CASES} cases to run, ${ran} ran"; fail=1; }
((passed == GATE_CASES)) || { log "${passed} of ${GATE_CASES} cases passed"; fail=1; }
((pinned_status == 0 && legacy_status == 0)) || { log "a pass failed (pinned ${pinned_status}, legacy ${legacy_status})"; fail=1; }
case "${frames_status}" in
    0) ;;
    1) log "frames hold a lepic key"; fail=1 ;;
    *) log "the frame capture is broken"; fail=1 ;;
esac
if ((fail)); then
    echo "Gate: FAIL"
    exit 1
fi
echo "Gate: PASS"
