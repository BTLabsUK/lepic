#!/bin/sh
# Stands in for tor in tests/process.rs: called as `tor -f <dir>/torrc --defaults-torrc ...`,
# it writes its environment to fake-env, copies the cookie and the control port file the test
# left next to <dir>, logs one warning, and waits to be stopped. The test serves the control
# port itself.
dir=$(dirname "$2")
echo "Oct 22 00:00:00.000 [notice] Tor 0.0.0 (fake) running"
echo "Oct 22 00:00:00.000 [warn] fake tor warning"
if [ -f "$dir/../exit-now" ]; then exit 3; fi
env > "$dir/../fake-env"
cp "$dir/../fake-cookie" "$dir/control.cookie"
cp "$dir/../fake-control" "$dir/control.tmp"
mv "$dir/control.tmp" "$dir/control.txt"
exec sleep 30
