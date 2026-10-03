# CLI acceptance

`run.sh` installs `lepic` with `cargo xtask install` and drives that installed binary, as a user
would run it from a shell, through every command against the local interop stack: the Epicbox
relay, the reference node `v4.0.4` on a test-mode chain and two `epic-wallet` `v4.0.2` wallets. It
covers both directions over Epicbox and slate files, invoices both ways, a failed delivery and
`tx resend`, cancel, restore from the phrase, a restore with `--no-scan` that receives only after
`wallet scan`, import of an `epic-wallet` `wallet.seed`, and the
exit codes of common mistakes, then prints a pass or fail table. It exits 0 only when every step
passed.

```
interop/acceptance/run.sh               # build, install, start a clean stack, run, tear down
interop/acceptance/run.sh --no-build    # reuse the built binaries and the installed lepic
interop/acceptance/run.sh --keep        # leave the stack running afterwards
interop/acceptance/run.sh --lepic PATH  # test another lepic binary
```

Needs what `../README.md` lists, plus a Rust toolchain for `cargo xtask install`. Every run
starts from nothing: a new chain and new wallets, and a lepic home, config file and data
directory under `.work/state`. `lepic` runs with a cleared environment (`env -i`) apart from
`PATH`, that home and that config file, so nothing from the invoking shell or `~/.lepic` leaks
in.

The stack is `../compose.yaml` without the lepic container, under the project name
`lepic-acceptance`. Its services have no route out and listen on loopback, as in V-02. Two TCP
forwarders (`forward.js`, each listening on its own interface addresses, never a wildcard) carry
the node API to `127.0.0.1:43413` and the relay to `127.0.0.1:3423` on the host, and nothing
else: `node-port` in the node's namespace and `gateway` on the internal network and a host
bridge, since Docker publishes ports only from a container on a non-internal network. The relay
keeps port 3423 because Epicbox addresses name it. `run.sh` refuses to start when either port is
taken. Slate files are exchanged through `.work/exchange` (mode 1777, because the wallet
containers run as their own uid), mounted into the wallets as `/exchange`.

The chain is usernet, where `epic-wallet` derives mainnet Epicbox addresses, so the config file
says `network = mainnet`. `epic-wallet` prints its address without the relay port; the steps
add `:3423`.

Each run writes `.work/logs/<time>/`: `results.txt` with the table, the lepic version and the
git tree it ran from; `run.log` with every failed command and its JSON error; and `compose.log`.
