#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# epic-wallet on the usernet chain, unlocked with this container's test wallet password.
exec epic-wallet --usernet -p "${WALLET_PASSWORD}" "$@"
