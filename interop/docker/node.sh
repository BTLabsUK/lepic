#!/bin/sh
# Starts the reference node on a local test-mode (usernet) chain: no peers, no seeds, RandomX
# blocks only so the interop miner can mine every block through the stratum server, and coinbase
# rewards paid to the funder wallet's foreign API. The Dandelion settings stay at their defaults:
# with no peer to stem to, the node fluffs a pushed transaction at once, so it reaches the pool
# while epic-wallet still watches for it there.
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

if [ ! -f "${config}" ]; then
    epic --usernet server config >/dev/null
    set_key api_http_addr '"127.0.0.1:23413"'
    set_key api_secret_path "\"${dir}/.api_secret\""
    set_key foreign_api_secret_path "\"${dir}/.foreign_api_secret\""
    # Every service shares this network namespace, so the p2p listener needs only loopback too.
    set_key host '"127.0.0.1"'
    set_key skip_pow_validation false
    set_key skip_sync_wait true
    set_key only_randomx true
    set_key enable_stratum_server true
    set_key stratum_server_addr '"127.0.0.1:23416"'
    set_key attempt_time_per_block 2
    set_key cuckatoo_minimum_share_difficulty 1
    set_key randomx_minimum_share_difficulty 1
    set_key progpow_minimum_share_difficulty 1
    set_key wallet_listener_url "\"${FUNDER_URL}\""
    # With no peers to wait for, the sync loop reports the node synced and wallets accept it.
    sed -i 's|^\[server.p2p_config\]$|&\npeer_min_preferred_outbound_count = 0|' "${config}"
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

exec epic --usernet server run
