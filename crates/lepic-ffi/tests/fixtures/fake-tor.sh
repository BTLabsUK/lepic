#!/bin/sh
# Stands in for tor in src/tests/tor.rs: called as `tor -f <dir>/torrc --defaults-torrc ...`,
# it copies the cookie and the control port file the test left in the wallet directory next to
# <dir>, then runs until the test's control port gets `SIGNAL SHUTDOWN` and writes `stop-now`
# there, for 30 seconds at most. The test serves the control port itself.
dir=$(dirname "$2")
echo "Oct 22 00:00:00.000 [notice] Tor 0.0.0 (fake) running"
cp "$dir/../fake-cookie" "$dir/control.cookie"
cp "$dir/../fake-control" "$dir/control.tmp"
mv "$dir/control.tmp" "$dir/control.txt"
i=0
while [ ! -f "$dir/../stop-now" ] && [ "$i" -lt 300 ]; do
  sleep 0.1
  i=$((i + 1))
done
