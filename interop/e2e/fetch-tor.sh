#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Puts the pinned Tor binary and its libraries (tor-bundle.env) in <out dir>, for send.tor. Needs no
# network when a tarball with the pinned hash is already in the cache; every file is checked against
# its pinned SHA-256 and a mismatch writes nothing. Does nothing when <out dir> already holds them.
#
# Usage: fetch-tor.sh <out dir>
# Env:   TOR_CACHE=<dir>  where tarballs are kept (default ~/.cache/epic-gui-tor/<version>, the
#                         folder the app's tools/fetch-tor.sh uses, so one download serves both)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tor-bundle.env
source "${here}/tor-bundle.env"
out="${1:?usage: $0 <out dir>}"
cache="${TOR_CACHE:-${HOME}/.cache/epic-gui-tor/${TOR_BUNDLE_VERSION}}"

hash_of() { sha256sum "$1" | cut -d' ' -f1; }

complete() {
    local entry
    for entry in ${TOR_FILES}; do
        [[ -x "${out}/${entry%%:*}" && "$(hash_of "${out}/${entry%%:*}")" == "${entry#*:}" ]] || return 1
    done
}
if complete; then
    exit 0
fi

mkdir -p "${cache}"
file="${cache}/${TOR_BUNDLE_TARBALL}"
if [[ ! -f "${file}" || "$(hash_of "${file}")" != "${TOR_BUNDLE_SHA256}" ]]; then
    ok=
    for base in ${TOR_BASE_URLS}; do
        echo "downloading ${base}${TOR_BUNDLE_VERSION}/${TOR_BUNDLE_TARBALL}" >&2
        if curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 --connect-timeout 20 \
            -o "${file}.part.$$" "${base}${TOR_BUNDLE_VERSION}/${TOR_BUNDLE_TARBALL}"; then
            ok=1
            break
        fi
    done
    [[ -n "${ok}" ]] || {
        rm -f -- "${file}.part.$$"
        echo "tor bundle download failed" >&2
        exit 1
    }
    mv -f "${file}.part.$$" "${file}"
fi
if [[ "$(hash_of "${file}")" != "${TOR_BUNDLE_SHA256}" ]]; then
    rm -f -- "${file}"
    echo "tor bundle hash mismatch (removed); pinned ${TOR_BUNDLE_SHA256}" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
tar -xzf "${file}" -C "${work}" tor
for entry in ${TOR_FILES}; do
    [[ "$(hash_of "${work}/tor/${entry%%:*}")" == "${entry#*:}" ]] || {
        echo "${entry%%:*} hash mismatch" >&2
        exit 1
    }
done
mkdir -p "${out}"
for entry in ${TOR_FILES}; do
    install -m 755 "${work}/tor/${entry%%:*}" "${out}/${entry%%:*}"
done
echo "tor ${TOR_BUNDLE_VERSION} in ${out}" >&2
