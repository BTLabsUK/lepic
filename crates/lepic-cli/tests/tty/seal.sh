#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs the interactive shell in a detached tmux at 80x24 and pays an epic1 link twice while the
# seal animation runs: the first time it resizes the window (120, 40, 80 columns) during the
# animation, the second time it presses a key to skip it. Then it reads the whole scrollback and
# checks that the final line appears once per payment and that no animation row, or a piece of
# one, is left behind. The scrollback is written to the file named by the first argument; the
# script exits 1 when a check fails.
#
# Usage: LEPIC=target/debug/lepic sh tests/tty/seal.sh seal.out
# The send is faked: a debug build waits LEPIC_SEAL_FAKE_MS (2500 here) instead of paying, so no
# link, relay or funds are needed. The environment names a test wallet whose password is in a
# file: LEPIC_DATA_DIR, LEPIC_NETWORK, LEPIC_PASSWORD_FILE and LEPIC_NODE_URL. A tmux server of
# its own is used.

set -eu

lepic=${LEPIC:?set LEPIC to the lepic binary}
out=${1:?name the file for the scrollback}
server=lepic-seal-$$
tm() { tmux -L "$server" "$@"; }
trap 'tm kill-server 2>/dev/null || true' EXIT

# Waits up to 15 s for `$1` on the visible screen.
wait_for() {
    tries=0
    while [ "$tries" -lt 150 ]; do
        if tm capture-pane -p -t shell | grep -qF -- "$1"; then
            return 0
        fi
        sleep 0.1
        tries=$((tries + 1))
    done
    echo "timed out waiting for: $1" >&2
    tm capture-pane -p -t shell >&2
    return 1
}

tm new-session -d -s shell -x 80 -y 24 \
    "env LEPIC_DATA_DIR='$LEPIC_DATA_DIR' LEPIC_NETWORK='$LEPIC_NETWORK' \
LEPIC_PASSWORD_FILE='$LEPIC_PASSWORD_FILE' LEPIC_NODE_URL='$LEPIC_NODE_URL' \
LEPIC_SEAL_FAKE_MS=2500 TERM=xterm-256color '$lepic'; echo SHELL-ENDED; sleep 30"
tm set-option -t shell history-limit 5000 >/dev/null

wait_for "unlocked"

# Resize while the seal is drawn, down to a width too narrow for it, and back.
tm send-keys -t shell "epic1 pay epic1:fake 1.5" Enter
sleep 0.5
for columns in 120 40 80; do
    tm resize-window -t shell -x "$columns" -y 24
    sleep 0.4
done
wait_for "Sealed with epic1"

# A key skips the animation; the payment still ends.
tm send-keys -t shell "epic1 pay epic1:fake 2" Enter
sleep 0.4
tm send-keys -t shell x
wait_for "> 2 EPIC" 2>/dev/null || true
sleep 3
tm send-keys -t shell C-u "exit" Enter
wait_for "SHELL-ENDED"

tm capture-pane -p -S - -t shell >"$out"

fail=0
check_count() {
    count=$(grep -cF -- "$1" "$out" || true)
    if [ "$count" -ne "$2" ]; then
        echo "FAIL: '$1' appears $count times, not $2" >&2
        fail=1
    else
        echo "ok: '$1' $2 times"
    fi
}
check_none() {
    # The welcome card's frame rows start with a corner or a side; any other row holding seal
    # characters is a piece of the animation.
    count=$(grep -vE '^(╭|╰|│|\+|\|)' "$out" | grep -cE -- "$1" || true)
    if [ "$count" -ne 0 ]; then
        echo "FAIL: $2 left behind ($count rows)" >&2
        fail=1
    else
        echo "ok: no $2 left behind"
    fi
}
check_count "> epic1 pay epic1:fake 1.5" 1
check_count "> epic1 pay epic1:fake 2" 1
check_count "Sealed with epic1" 2
check_count "> exit" 1
check_count "Session closed." 1
check_none "[▗▖▝▘▐▌]" "box piece"
check_none "(sealing|sending)\$" "status word"
check_none "Ctrl\\+C cancel" "progress row"
exit "$fail"
