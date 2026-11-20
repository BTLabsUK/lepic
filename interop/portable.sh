#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Small helpers that make build.sh and the acceptance scripts run on macOS as well as Linux: the hash
# command, file times and the build lock differ there. Sourced, never run.

# shellcheck disable=SC2034 # used by the scripts that source this file
if command -v sha256sum >/dev/null; then
    SHA256=(sha256sum)
else
    SHA256=(shasum -a 256)
fi

# file_mtime PATH: the modification time, in seconds since the epoch.
file_mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }

# fmt_epoch SECONDS: the time as YYYY-MM-DD HH:MM:SS, local.
fmt_epoch() { date -d "@$1" '+%F %T' 2>/dev/null || date -r "$1" '+%F %T'; }

# lock_run FILE COMMAND...: runs the command with FILE locked. Without flock (macOS) a directory next to
# the file is the lock; a run killed with SIGKILL leaves it behind, and rmdir FILE.d clears it.
lock_run() {
    local file="$1" rc
    shift
    if command -v flock >/dev/null; then
        (
            flock 9
            "$@"
        ) 9>"${file}"
        return
    fi
    until mkdir "${file}.d" 2>/dev/null; do sleep 2; done
    "$@" && rc=0 || rc=$?
    rmdir "${file}.d"
    return "${rc}"
}
