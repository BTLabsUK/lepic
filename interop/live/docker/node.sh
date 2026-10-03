#!/bin/sh
# Starts the reference node on floonet, peered only with LIVE_SEED (an IP:port; the node rejects
# host names there): peers_allow keeps it from dialling or accepting anyone else. Floonet blocks
# are RandomX only, so `only_randomx` is required to accept the chain. The stratum server lets the
# live miner mine through this node, which pays every coinbase to the funder wallet's foreign API.
# It runs in the host's network namespace, so every listener is bound to 127.0.0.1 on a 334xx port,
# clear of the ports of a floonet node the host may already run.
set -eu

dir=/data/node
config="${dir}/epic-server.toml"
mkdir -p "${dir}"
cd "${dir}"

set_key() {
    # Replaces the line `<key> = ...`; fails if the generated config has no such key.
    grep -q "^$1 = " "${config}" || { echo "node config has no key $1" >&2; exit 1; }
    sed -i "s|^$1 = .*|$1 = $2|" "${config}"
}

# Adds `<key> = <value>` as the first line of a section; fails if the section is missing.
add_key() {
    grep -q "^\[$1\]$" "${config}" || { echo "node config has no section $1" >&2; exit 1; }
    sed -i "s|^\[$1\]$|&\n$2 = $3|" "${config}"
}

: "${LIVE_SEED:?LIVE_SEED must be the floonet seed as IP:port}"

if [ ! -f "${config}" ]; then
    epic --floonet server config >/dev/null
    set_key chain_type '"Floonet"'
    set_key api_http_addr '"127.0.0.1:33413"'
    set_key api_secret_path "\"${dir}/.api_secret\""
    set_key foreign_api_secret_path "\"${dir}/.foreign_api_secret\""
    set_key only_randomx true
    set_key host '"127.0.0.1"'
    set_key port 33414
    set_key seeding_type '"List"'
    add_key server.p2p_config seeds "[\"${LIVE_SEED}\"]"
    add_key server.p2p_config peers_allow "[\"${LIVE_SEED}\"]"
    # The one outbound peer is the seed. With the default of four the node never starts syncing.
    add_key server.p2p_config peer_min_preferred_outbound_count 1
    set_key enable_stratum_server true
    set_key stratum_server_addr '"127.0.0.1:33416"'
    set_key wallet_listener_url '"http://127.0.0.1:33415"'
    set_key stdout_log_level '"WARN"'
    set_key log_to_file true
    set_key file_log_level '"INFO"'
fi

# The node enables basic auth on an API only when its secret file exists. epic-wallet sends one
# secret to both the owner API (sync status) and the foreign API, so both files hold the same one.
if [ ! -s "${dir}/.api_secret" ]; then
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${dir}/.api_secret"
fi
cp "${dir}/.api_secret" "${dir}/.foreign_api_secret"

exec epic --floonet server run
