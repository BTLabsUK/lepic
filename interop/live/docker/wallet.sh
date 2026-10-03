#!/bin/sh
# Creates an epic-wallet v4.0.2 floonet wallet on first start, points it at the public floonet
# node through the loopback node proxy (node-proxy.py) and at the local relay, then either serves the foreign API on loopback
# (the funder, whose build_coinbase the live miner calls) or idles so the live test can drive it
# with `ew`. The wallet directory is bind-mounted from interop/live/data, so the wallet and its
# funds survive between runs.
set -eu

mode="$1"
config=/data/.epic/floo/epic-wallet.toml

set_key() {
    grep -q "^$1 = " "${config}" || { echo "wallet config has no key $1" >&2; exit 1; }
    sed -i "s|^$1 = .*|$1 = $2|" "${config}"
}

if [ ! -f "${config}" ]; then
    # Floonet test wallet; the recovery phrase is not printed. The seed stays encrypted in the
    # wallet directory under the container's test password.
    ew init >/dev/null
    set_key api_listen_interface '"127.0.0.1"'
    set_key api_listen_port 33415
    set_key owner_api_listen_port 33420
    # The proxy needs no secret; a path with no file sends none.
    set_key node_api_secret_path '"/data/no-node-api-secret"'
    set_key check_node_api_http_addr '"http://127.0.0.1:33413"'
    set_key use_tor_listener false
    set_key epicbox_domain '"localhost"'
    set_key epicbox_port 33423
    set_key epicbox_protocol_unsecure true
    set_key stdout_log_level '"Warning"'
    set_key log_to_file true
    set_key file_log_level '"Info"'
fi
touch /data/ready

case "${mode}" in
    listen-http) exec ew listen -m http ;;
    idle) exec sleep infinity ;;
    *) echo "unknown mode ${mode}" >&2; exit 2 ;;
esac
