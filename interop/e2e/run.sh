#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end cases for LEPIC on floonet, as a service or a user runs it: named wallets, funds from
# the QA funder through a bank wallet, every payment method, epic1 links, invoices, pairing,
# in-person codes, sealed text and files, and the errors a service hits. See README.md.
#
#   ./run.sh                       every case
#   ./run.sh --list                the cases, by area
#   ./run.sh --only <case|area>,…  just these cases or areas
#   ./run.sh --from <case>         this case and every one after it (resume after a failure)
#   ./run.sh --affected <range>    the cases whose paths changed in a git range, e.g. main..HEAD
#   ./run.sh --lepic <path>        the lepic binary to test (default: this tree's release build)
#   ./run.sh --no-mine             do not start the floonet miner (blocks will not move)
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${E2E_DIR}/../.." && pwd)"
# shellcheck source=../lib.sh
source "${E2E_DIR}/../lib.sh"
# shellcheck source=lib.sh
source "${E2E_DIR}/lib.sh"

# Every case file appends "id|function|paths" to CASES; paths are the repository prefixes whose
# change makes --affected pick the case. The order of the files and entries is the run order.
CASES=()
for file in "${E2E_DIR}"/cases/*.sh; do
    # shellcheck source=/dev/null
    source "${file}"
done

only=""
from=""
affected=""
list=false
LEPIC_BIN="${LEPIC_E2E_BIN:-}"
while (($# > 0)); do
    case "$1" in
        --only) only="${2:?--only needs names}"; shift ;;
        --from) from="${2:?--from needs a case}"; shift ;;
        --affected) affected="${2:?--affected needs a git range}"; shift ;;
        --lepic) LEPIC_BIN="${2:?--lepic needs a path}"; shift ;;
        --no-mine) E2E_MINE=false ;;
        --list) list=true ;;
        -h | --help) sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift
done

case_id() { echo "${1%%|*}"; }
case_area() { local id; id="$(case_id "$1")"; echo "${id%%.*}"; }
case_fn() { local rest="${1#*|}"; echo "${rest%%|*}"; }
case_paths() { local rest="${1#*|}"; echo "${rest#*|}"; }

if [[ "${list}" == true ]]; then
    for entry in "${CASES[@]}"; do printf '%-34s %s\n' "$(case_id "${entry}")" "$(case_paths "${entry}")"; done
    exit 0
fi

# Choose the cases.
selected=()
changed=""
if [[ -n "${affected}" ]]; then
    changed="$(git -C "${REPO_DIR}" diff --name-only "${affected}")"
fi
started_from=false
[[ -z "${from}" ]] && started_from=true
for entry in "${CASES[@]}"; do
    id="$(case_id "${entry}")"
    [[ "${id}" == "${from}" ]] && started_from=true
    [[ "${started_from}" == true ]] || continue
    if [[ -n "${only}" ]]; then
        [[ ",${only}," == *",${id},"* || ",${only}," == *",$(case_area "${entry}"),"* ]] || continue
    fi
    if [[ -n "${affected}" ]]; then
        hit=false
        for prefix in $(case_paths "${entry}"); do
            grep -q "^${prefix}" <<<"${changed}" && hit=true
        done
        [[ "${hit}" == true ]] || continue
    fi
    selected+=("${entry}")
done
if ((${#selected[@]} == 0)); then
    echo "no case matches; --list shows them" >&2
    exit 2
fi
if [[ -n "${from}" && "${started_from}" == false ]]; then
    echo "--from names no case: ${from}" >&2
    exit 2
fi

if [[ -z "${LEPIC_BIN}" ]]; then
    LEPIC_BIN="${REPO_DIR}/target/release/lepic"
fi
[[ -x "${LEPIC_BIN}" ]] || { echo "no lepic binary at ${LEPIC_BIN}; build it or pass --lepic" >&2; exit 1; }
for tool in jq flock pm2 python3; do
    command -v "${tool}" >/dev/null || { echo "needs ${tool}" >&2; exit 1; }
done

e2e_init_state
RUN_DIR="${E2E_STATE%/state}/runs/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "${RUN_DIR}"
RUN_LOG="${RUN_DIR}/run.log"
: >"${RUN_LOG}"
NOTES="${E2E_STATE%/state}/NOTES.md"
version="$("${LEPIC_BIN}" --version)"
tree="$(git -C "${REPO_DIR}" describe --always --dirty 2>/dev/null || echo unknown)"
log "testing ${version} at ${LEPIC_BIN}; ${#selected[@]} cases; logs in ${RUN_DIR}"

finish() {
    e2e_cleanup
    miner_stop
}
trap finish EXIT
trap 'exit 130' INT TERM

names=()
results=()
times=()
details=()
failed=0
run_t0=${SECONDS}
miner_start || true
for entry in "${selected[@]}"; do
    id="$(case_id "${entry}")"
    CASE_DIR="${RUN_DIR}/${id}"
    mkdir -p "${CASE_DIR}"
    log "${id}"
    DETAIL=""
    t0=${SECONDS}
    if ( set +e; trap e2e_cleanup EXIT; "$(case_fn "${entry}")" ) 2>>"${CASE_DIR}/case.log"; then
        result=PASS
    else
        result=FAIL
        failed=$((failed + 1))
        # The subshell's DETAIL is lost with it; fail and note write detail.txt.
        [[ -s "${CASE_DIR}/detail.txt" ]] || tail -n 1 "${CASE_DIR}/last.err" >"${CASE_DIR}/detail.txt" 2>/dev/null || true
    fi
    DETAIL="$(cat "${CASE_DIR}/detail.txt" 2>/dev/null || true)"
    e2e_cleanup
    names+=("${id}")
    results+=("${result}")
    times+=("$((SECONDS - t0))s")
    details+=("${DETAIL}")
    log "${result} ${id} ($((SECONDS - t0))s) ${DETAIL}"
    printf '%s | %s | %s | %ss | %s | %s\n' "$(date -u +%FT%TZ)" "${id}" "${result}" "$((SECONDS - t0))" \
        "${tree}" "${DETAIL}" >>"${NOTES}"
done

{
    printf 'lepic: %s at %s\n' "${version}" "${LEPIC_BIN}"
    printf 'tree: %s\n' "${tree}"
    printf '\n%-34s %-6s %6s  %s\n' "Case" "Result" "Time" "Detail"
    printf '%-34s %-6s %6s  %s\n' "----" "------" "----" "------"
    for i in "${!names[@]}"; do
        printf '%-34s %-6s %6s  %s\n' "${names[i]}" "${results[i]}" "${times[i]}" "${details[i]}"
    done
    printf '\n%d of %d cases passed in %ss\n' "$((${#names[@]} - failed))" "${#names[@]}" "$((SECONDS - run_t0))"
} | tee "${RUN_DIR}/results.txt"
printf '\nLogs: %s\n' "${RUN_DIR}"
((failed == 0))
