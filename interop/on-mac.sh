#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs the acceptance stack on the Mac, from a commit of this repository, in one command:
#
#   interop/on-mac.sh [--commit <ref>] [--stock-relay] [--only <steps>] [--sync-only] [-- <run.sh arguments>]
#
# 1. pushes the commit to the bare repository on the Mac (MAC_REPO) and checks it out in the clone there
#    (MAC_DIR), so only tracked files arrive and the Mac needs no route back to this machine;
# 2. builds the stack's pinned binaries there for arm64 (build.sh --no-lepic, into the Mac's own cache);
# 3. builds lepic natively (cargo xtask install) and runs acceptance/run.sh with it, from the Mac's saved
#    funded chain (the first run on the Mac mines and saves it).
#
# The relay is the Epicmail mailbox, as everywhere: its source is copied from LEPIC_MUX_RELAY_SRC (default
# ~/.cache/wfe-lepic/mux-relay/src), because the Mac cannot clone it, and its image is built there for the
# Mac's architecture (mux-relay-image.sh). --stock-relay runs the opt-in stock lane instead (stock relay,
# only the Legacy Epicbox and stock-wallet steps) and copies no source.
# --only runs setup and the named steps only (ACCEPTANCE_ONLY). Everything after `--` goes to run.sh:
# `-- --from-genesis` ignores the saved chain, `-- --keep` leaves the stack up.
# Commit first: the Mac gets the commit, not the working tree. A Docker stack already running on the Mac
# (the host-wide lock) makes the run wait for it.
#
#   MAC_HOST   the ssh target, required            (for example user@mac.example)
#   MAC_REPO   the bare repository on the Mac    (default lepic-delivery.git, under $HOME)
#   MAC_DIR    the clone the run happens in      (default lepic-delivery, under $HOME)
#
# The Mac needs Docker (Colima), Rust (rustup), and Homebrew's bash 5, flock and GNU coreutils; the
# script puts coreutils' gnubin and /opt/homebrew/bin first in PATH.
set -euo pipefail

host="${MAC_HOST:?set MAC_HOST to the ssh target of the Mac, for example user@mac.example}"
repo_on_mac="${MAC_REPO:-lepic-delivery.git}"
dir="${MAC_DIR:-lepic-delivery}"
commit=HEAD
mux=true
only=""
sync_only=false
run_args=()

while (($#)); do
    case "$1" in
        --commit) commit="${2:?--commit needs a ref}"; shift 2 ;;
        --stock-relay) mux=false; run_args+=(--stock-relay); shift ;;
        --only) only="${2:?--only needs step names}"; shift 2 ;;
        --sync-only) sync_only=true; shift ;;
        --) shift; run_args+=("$@"); break ;;
        -h | --help) sed -n '3,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "usage: on-mac.sh [--commit <ref>] [--stock-relay] [--only <steps>] [--sync-only] [-- <run.sh arguments>]" >&2; exit 2 ;;
    esac
done

repo="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
sha="$(git -C "${repo}" rev-parse --verify "${commit}^{commit}")"
log() { printf '[on-mac] %s\n' "$*" >&2; }
# The remote shell's PATH: brew's GNU tools first (the scripts use flock, sha256sum, stat -c).
# shellcheck disable=SC2016 # expanded on the Mac
mac_path='export PATH=/opt/homebrew/opt/coreutils/libexec/gnubin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH'

log "pushing ${sha:0:12} to ${host}:${repo_on_mac}"
git -C "${repo}" push --quiet --force "${host}:${repo_on_mac}" "${sha}:refs/heads/on-mac"
# shellcheck disable=SC2029 # the directory is expanded here on purpose
ssh "${host}" "set -e; cd '${dir}'; git fetch --quiet origin on-mac; git checkout --quiet --force --detach FETCH_HEAD; git log --oneline -1"
"${sync_only}" && exit 0

relay_env=""
if "${mux}"; then
    src="${LEPIC_MUX_RELAY_SRC:-${HOME}/.cache/wfe-lepic/mux-relay/src}"
    [[ -f "${src}/Dockerfile" ]] || { log "no relay source at ${src}; set LEPIC_MUX_RELAY_SRC"; exit 1; }
    log "copying the relay source to ${host}:lepic-mux-relay/src"
    ssh "${host}" "mkdir -p lepic-mux-relay/src"
    rsync -a --delete --exclude .git --exclude target "${src}/" "${host}:lepic-mux-relay/src/"
    # shellcheck disable=SC2016 # expanded on the Mac
    relay_env='interop/mux-relay-image.sh "$HOME/lepic-mux-relay/src" lepic-acceptance-mux-relay:local "$HOME/lepic-mux-relay/relay.toml"
export ACCEPTANCE_MUX_RELAY_IMAGE=lepic-acceptance-mux-relay:local ACCEPTANCE_MUX_RELAY_CONFIG="$HOME/lepic-mux-relay/relay.toml"'
fi
only_env=""
[[ -z "${only}" ]] || only_env="export ACCEPTANCE_ONLY=$(printf '%q' "${only}")"

# printf '%q ' with no arguments prints '' (an empty argument), so quote only when there is something.
run_args_q=""
((${#run_args[@]})) && run_args_q="$(printf '%q ' "${run_args[@]}")"

log "building and running on ${host}"
# shellcheck disable=SC2029 # the directory and arguments are expanded here on purpose
ssh "${host}" "${mac_path}
set -euo pipefail
cd '${dir}'
interop/build.sh --no-lepic
cargo xtask install --dir interop/.work/bin-host
${relay_env}
${only_env}
exec interop/acceptance/run.sh --no-build --lepic interop/.work/bin-host/lepic ${run_args_q}"
