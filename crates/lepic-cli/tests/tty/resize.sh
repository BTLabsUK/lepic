#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs the interactive shell in a detached tmux at 112x32 and resizes it (wider, to 40 columns,
# back: 112, 150, 40, 112) while a line is edited and while a long command runs. Then it reads
# the whole scrollback and checks that each command and its output appear once and that no
# live-area row, or a piece of one, is left behind. The scrollback is written to the file named
# by the first argument; the script exits 1 when a check fails.
#
# Usage: LEPIC=target/debug/lepic sh tests/tty/resize.sh resize.out
# The environment names a test wallet whose password is in a file: LEPIC_DATA_DIR,
# LEPIC_NETWORK, LEPIC_PASSWORD_FILE and LEPIC_NODE_URL. A tmux server of its own is used.

set -eu

lepic=${LEPIC:?set LEPIC to the lepic binary}
out=${1:?name the file for the scrollback}
server=lepic-resize-$$
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

resize_round() {
    for columns in 150 40 112; do
        tm resize-window -t shell -x "$columns" -y 32
        sleep 0.6
    done
}

tm new-session -d -s shell -x 112 -y 32 \
    "env LEPIC_DATA_DIR='$LEPIC_DATA_DIR' LEPIC_NETWORK='$LEPIC_NETWORK' \
LEPIC_PASSWORD_FILE='$LEPIC_PASSWORD_FILE' LEPIC_NODE_URL='$LEPIC_NODE_URL' \
TERM=xterm-256color '$lepic'; echo SHELL-ENDED; sleep 30"
tm set-option -t shell history-limit 5000 >/dev/null

wait_for "unlocked"
tm send-keys -t shell "status" Enter
wait_for "Idle lock"

# Resize while a line is being edited.
tm send-keys -t shell "tx li"
sleep 0.5
resize_round
tm send-keys -t shell C-u
sleep 0.3

# Resize while a long command runs: the Epicbox listener runs until Ctrl+C.
tm send-keys -t shell "epicbox listen" Enter
sleep 0.4
resize_round
wait_for "Ctrl+C cancel" || true
tm send-keys -t shell C-c
sleep 1.5
tm send-keys -t shell "node status" Enter
wait_for "Header"
tm send-keys -t shell "exit" Enter
wait_for "SHELL-ENDED"

tm capture-pane -p -S - -t shell >"$out"

fail=0
check_once() {
    count=$(grep -cF -- "$1" "$out" || true)
    if [ "$count" -ne 1 ]; then
        echo "FAIL: '$1' appears $count times" >&2
        fail=1
    else
        echo "ok: '$1' once"
    fi
}
check_none() {
    # The welcome card's frame rows start with a corner or a side; any other row holding rule
    # characters is a piece of the live area.
    count=$(grep -vE '^(╭|╰|│|\+|\|)' "$out" | grep -cE -- "$1" || true)
    if [ "$count" -ne 0 ]; then
        echo "FAIL: $2 left behind ($count rows)" >&2
        fail=1
    else
        echo "ok: no $2 left behind"
    fi
}
check_once "> status"
check_once "Idle lock"
check_once "> epicbox listen"
check_once "> node status"
check_once "Header"
check_once "> exit"
check_once "Session closed."
check_none "tx li" "edited line"
check_none "Ctrl\\+C cancel" "progress row"
check_none "──|---|[^ ]--( |$)" "rule piece"
check_none "default (·|\|) |(tor|api) (●|○|\*|o)( |$)|h [0-9,]+ " "status piece"
exit "$fail"
