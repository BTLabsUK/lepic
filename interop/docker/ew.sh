#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# epic-wallet (or the binary EW_BIN names) on the usernet chain, unlocked with this container's test wallet password.
exec "${EW_BIN:-epic-wallet}" --usernet -p "${WALLET_PASSWORD}" "$@"
