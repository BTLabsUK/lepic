# CLI acceptance

`run.sh` installs `lepic` with `cargo xtask install` and drives that installed binary, as a user
would run it from a shell, through every command against the local interop stack: the Epicbox
relay, the reference node `v4.1.0` on a test-mode chain and two `epic-wallet` `v4.1.0` wallets. It
covers both directions over Epicbox and slate files, a signed message each way over Epicbox
(shown by `lepic tx show` and `epic-wallet txs`), invoices both ways, a failed delivery and
`tx resend`, cancel, restore from the phrase, a restore with `--no-scan` that receives only after
`wallet scan`, import of an `epic-wallet` `wallet.seed`, and the
exit codes of common mistakes. Last, lepic invoices a second lepic wallet over Epicbox: the
payer allows the service, parks the invoice from its invoice address and pays it once, the
service finalizes, and the payer's drain shows the `posted` receipt. Then lepic sends to that wallet over
Epicbox while it listens: both slates carry the LEPIC marker, and the listener reports the
payment as posted by its sender seconds after the sender's push, before it confirms; a stock
`epic-wallet` receiver is recorded as nothing and sent no notice. A stock `epic-wallet`
listener sends lepic's invoice back unpaid; lepic counts it as bounced, records that peer as not
paying invoices (read from its store, which no command shows), sends it no notice when the
invoice is cancelled, and pays it over Epicbox afterwards. It then prints a pass or fail table and
exits 0 only when every step passed.

```
interop/acceptance/run.sh               # build, install, start a clean stack, run, tear down
interop/acceptance/run.sh --no-build    # reuse the built binaries and the installed lepic
interop/acceptance/run.sh --keep        # leave the stack running afterwards
interop/acceptance/run.sh --lepic PATH  # test another lepic binary
interop/acceptance/run.sh --stack-only  # start a clean stack and keep it until Ctrl-C
interop/acceptance/run.sh --probes      # probe the relay and a stock listener instead
```

`--probes` runs the checks in `probes.sh` instead of the steps. They cover what invoices and
notices over Epicbox build on: how a stock listener treats a V3 I1, a marker key and a payload
that is not a slate, how the relay serves two addresses, and how LEPIC's Epicbox policy reads a
marked V3 invoice. The probe client is `../probe`, built into `.work/probe-target`. The results are
recorded in `docs/compat/epicbox.md`, and the raw output goes to the run's `probes/` directory.

`--stack-only` funds nothing and runs no step: it prints the node URL, the node API secret file,
the relay and the exchange directory, and holds the stack and its lock until stopped, for a
lepic outside this script, such as the tests of the Flutter binding, a separate repository
(https://gitlab.com/epic-cash-bt/lepic-flutter). `chain.sh` drives that stack:
`env`, `height`, `mine <blocks>`, `fund <address> <epic>` (the funder sends over Epicbox) and
`receive <file>` (the funder answers a send file in the exchange directory).
The binding repository's README shows the whole workflow.

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
