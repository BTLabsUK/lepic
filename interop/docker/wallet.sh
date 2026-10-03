#!/bin/sh
# Creates an epic-wallet v4.0.2 wallet on the usernet chain on first start, points it at the
# local node and relay, then either serves the foreign API (the funder, which the node pays
# coinbase rewards to) or idles so the scenarios can drive it with `ew`.
#
# On usernet, epic-wallet derives mainnet Epicbox addresses (version bytes 0x01 0x00), so lepic
# runs with `--network mainnet` against this chain.
set -eu

mode="$1"
config=/data/.epic/user/epic-wallet.toml

set_key() {
    grep -q "^$1 = " "${config}" || { echo "wallet config has no key $1" >&2; exit 1; }
    sed -i "s|^$1 = .*|$1 = $2|" "${config}"
}

if [ ! -f "${config}" ]; then
    # The recovery phrase of a throwaway test wallet is not kept or shown.
    ew init >/dev/null
    set_key api_listen_interface '"127.0.0.1"'
    set_key check_node_api_http_addr '"http://127.0.0.1:23413"'
    set_key node_api_secret_path '"/node/.foreign_api_secret"'
    set_key use_tor_listener false
    set_key epicbox_domain '"localhost"'
    set_key epicbox_port 3423
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
