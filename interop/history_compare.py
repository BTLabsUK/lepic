#!/usr/bin/env python3
"""Compares an epic-wallet's own record of its history (taken before the import) with what lepic
holds after `wallet import-history`, and prints one row per old transaction and a check list.

    history_compare.py <dir>

<dir> holds before/ (epic-wallet's `export_tx --all`, `info` and `outputs` per account) and one
directory per import order (lepic-<order>/) that history.sh filled from lepic's JSON output.
Writes <dir>/report.md and exits 1 when any check failed.
"""
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

UNIT = 10**8
ACCOUNTS = ["default", "savings"]


def units(text):
    if text is None:
        return None
    whole, _, frac = str(text).partition(".")
    return int(whole) * UNIT + int((frac + "00000000")[:8])


def epoch(text):
    """Seconds since the epoch of an RFC 3339 time, ignoring the fraction."""
    text = re.sub(r"\.\d+", "", text).replace("Z", "+00:00")
    return int(datetime.fromisoformat(text).astimezone(timezone.utc).timestamp())


def kebab(tx_type):
    return re.sub(r"(?<!^)(?=[A-Z])", "-", tx_type.removeprefix("Tx")).lower()


def load(path):
    return json.loads(Path(path).read_text())


def ew_info(path):
    """The amounts of an `epic-wallet info` text, in units, by their row label."""
    rows = {}
    for line in Path(path).read_text().splitlines():
        m = re.match(r"\s*([A-Za-z][^|]*?)\s*\|\s*([0-9]+\.[0-9]+)", line)
        if m:
            rows[re.sub(r" \(.*\)", "", m.group(1))] = units(m.group(2))
    return rows


def ew_live_outputs(path):
    """Values of the outputs an `epic-wallet outputs` text shows as unspent or locked."""
    values = []
    for line in Path(path).read_text().splitlines():
        m = re.search(r"\s(Unspent|Locked)\s+\w+\s+\d+\s+([0-9]+\.[0-9]+)\s", line)
        if m:
            values.append(units(m.group(2)))
    return values


def fmt(value):
    return "-" if value is None else f"{value // UNIT}.{value % UNIT:08d}"


class Report:
    def __init__(self):
        self.checks = []

    def check(self, scope, what, expected, observed, ok=None):
        ok = (expected == observed) if ok is None else ok
        self.checks.append((scope, what, expected, observed, bool(ok)))
        return ok


def expected_state(old):
    if old["tx_type"].endswith("Cancelled"):
        return "cancelled"
    return "confirmed" if old["confirmed"] else "open"


def compare_entry(rep, scope, old, tx, live):
    """One old transaction against its lepic entry; returns the names of the fields that differ."""
    bad = []

    def eq(name, expected, observed, ok=None):
        if not rep.check(scope, name, expected, observed, ok):
            bad.append(name)

    eq("origin", "imported", tx.get("origin"))
    imp = tx.get("imported") or {}
    eq("old id", old["id"], imp.get("source_id"))
    eq("kind", kebab(old["tx_type"]), imp.get("kind"))
    eq("direction", "incoming" if "Received" in old["tx_type"] else "outgoing", tx["direction"])
    eq("slate id", old["tx_slate_id"], tx["slate_id"])
    eq("created_at (s)", epoch(old["creation_ts"]), epoch(tx["created_at"]))
    eq("credited", int(old["amount_credited"]), units(tx["amount_credited"]))
    eq("debited", int(old["amount_debited"]), units(tx["amount_debited"]))
    eq("fee", None if old["fee"] is None else int(old["fee"]), units(tx["fee"]))
    state = expected_state(old)
    if state == "open":
        eq("state", "neither confirmed nor cancelled", tx["state"], tx["state"] not in ("confirmed", "cancelled"))
        eq("check", "anything but on-chain", imp.get("check"), imp.get("check") != "on-chain")
        eq("confirmed_height", None, tx.get("confirmed_height"))
    elif state == "cancelled":
        eq("state", state, tx["state"])
        eq("check", "anything but on-chain", imp.get("check"), imp.get("check") != "on-chain")
    else:
        eq("state", state, tx["state"])
        # A scan can only vouch for an output that is still unspent on chain; the old wallet
        # still held one of this value as unspent or locked.
        credited = int(old["amount_credited"])
        if credited in live:
            live.remove(credited)
            eq("check", "on-chain (its output is unspent)", imp.get("check"), imp.get("check") == "on-chain")
        else:
            eq("check", "unchecked or on-chain (spent)", imp.get("check"), imp.get("check") in ("unchecked", "on-chain"))
        # epic-wallet's own log is sometimes a block behind the block its output is in.
        got = tx.get("confirmed_height")
        eq("confirmed_height", f"{old['confirmation_height']} (+1 allowed)", got,
           got is not None and 0 <= got - old["confirmation_height"] <= 1)
        if old.get("kernel_excess"):
            eq("kernel_excess", old["kernel_excess"], tx.get("kernel_excess"))
    if state != "open":
        addr = old.get("public_addr") or ""
        want = "epicbox" if "@" in addr else "file" if addr.startswith("/") else None
        eq("transport", want, tx["transport"])
    # The same texts, each on the side of the money its author was on. epic-wallet numbers the
    # parties by who pays: participant 0 is the sender, also in an invoice.
    want_msgs = []
    for m in (old.get("messages") or {}).get("messages", []):
        if m["message"] is not None:
            want_msgs.append(("sender" if m["id"] == "0" else "receiver", m["message"]))
    got_msgs = [(m["role"], m["text"]) for m in tx.get("messages") or []]
    eq("messages", sorted(want_msgs), sorted(got_msgs))
    return bad


def main(root):
    root = Path(root)
    rep = Report()
    before = {a: load(root / "before" / f"tx-{a}.json") for a in ACCOUNTS}
    old_info = {a: ew_info(root / "before" / f"info-{a}.txt") for a in ACCOUNTS}
    table = []

    for variant_dir in sorted(root.glob("lepic-*")):
        variant = variant_dir.name.removeprefix("lepic-")
        scope = f"[{variant}] "
        rep.check(scope, "import-history status", "imported", load(variant_dir / "import.json")["status"])
        rep.check(scope, "second import-history status", "already-imported",
                  load(variant_dir / "import-again.json")["status"])
        info = load(variant_dir / "info.json")
        labels = {a["label"]: a for a in info["accounts"]}
        rep.check(scope, "account labels", sorted(ACCOUNTS), sorted(labels))
        for account in ACCOUNTS:
            ac = f"{scope}{account} "
            listing = load(variant_dir / f"tx-list-{account}.json")["transactions"]
            shown = [load(variant_dir / f"tx-{account}-{t['tx_id']}.json") for t in listing]
            after_again = load(variant_dir / f"tx-list-{account}-again.json")["transactions"]
            old = before[account]
            live = ew_live_outputs(root / "before" / f"outputs-live-{account}.txt")
            seen = Counter((t.get("imported") or {}).get("source_id") for t in shown)
            rep.check(ac, "entries in tx list", len(old), len(listing))
            rep.check(ac, "entries after the second import", len(listing), len(after_again))
            rep.check(ac, "each old id once", {o["id"]: 1 for o in old}, {k: v for k, v in seen.items() if k is not None})
            rep.check(ac, "entries of another origin", [], [t["tx_id"] for t in shown if t.get("origin") != "imported"])
            for o in old:
                match = [t for t in shown if (t.get("imported") or {}).get("source_id") == o["id"]]
                sc = f"{scope}{account}#{o['id']} "
                if len(match) != 1:
                    rep.check(sc, "entry exists", 1, len(match))
                    table.append((variant, account, o, None, ["missing"]))
                    continue
                table.append((variant, account, o, match[0], compare_entry(rep, sc, o, match[0], live)))
            exp = old_info[account]
            lab = labels.get(account)
            if lab:
                rep.check(ac, "total = epic-wallet Confirmed Total", exp["Confirmed Total"], units(lab["total"]))
                # lepic cannot know the old wallet locked the inputs of its unfinished send
                rep.check(ac, "spendable = epic-wallet Spendable + Locked",
                          exp["Currently Spendable"] + exp["Locked by transaction"], units(lab["spendable"]))
                rep.check(ac, "awaiting confirmation", exp["Awaiting Confirmation"],
                          units(lab["awaiting_confirmation"]))

    out = ["# lepic import-history against epic-wallet v4.0.2", "",
           "## Transactions: epic-wallet before | lepic after", "",
           "| order | account | old id | type | date | amount | fee | tx | origin | state | date | amount | fee | check | match |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for variant, account, o, t, bad in table:
        net = int(o["amount_credited"]) - int(o["amount_debited"])
        fee = None if o["fee"] is None else int(o["fee"])
        left = f"{o['id']} | {o['tx_type']} | {o['creation_ts'][:19]} | {fmt(abs(net))}{' out' if net < 0 else ''} | {fmt(fee)}"
        if t is None:
            right = "- | - | - | - | - | - | -"
        else:
            tnet = units(t["amount_credited"]) - units(t["amount_debited"])
            right = (f"{t['tx_id']} | {t.get('origin')} | {t['state']} | {t['created_at'][:19]} | "
                     f"{fmt(abs(tnet))}{' out' if tnet < 0 else ''} | {t['fee'] or '-'} | {(t.get('imported') or {}).get('check')}")
        verdict = "yes" if not bad else "NO: " + ", ".join(bad)
        out.append(f"| {variant} | {account} | {left} | {right} | {verdict} |")
    out += ["", "## Checks", "", "| scope | check | expected | observed | ok |", "|---|---|---|---|---|"]
    for scope, what, e, g, good in rep.checks:
        out.append(f"| {scope} | {what} | `{e}` | `{g}` | {'ok' if good else '**FAIL**'} |")
    (root / "report.md").write_text("\n".join(out) + "\n")

    failed = [c for c in rep.checks if not c[4]]
    for variant, account, o, t, bad in table:
        entry = "-" if t is None else f"{t['tx_id']} {t['state']}"
        print(f"{variant:8} {account:8} old#{o['id']:<3} {o['tx_type']:20} -> {entry:14} "
              f"{'ok' if not bad else 'MISMATCH ' + ','.join(bad)}")
    print(f"\n{len(rep.checks) - len(failed)} of {len(rep.checks)} checks passed")
    for scope, what, e, g, _ in failed:
        print(f"FAIL {scope}{what}: expected {e!r}, observed {g!r}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
