#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# epic-wallet on floonet, unlocked with this container's test wallet password.
exec epic-wallet --floonet -p "${WALLET_PASSWORD}" "$@"
