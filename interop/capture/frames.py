#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finds every frame LEPIC wrote during an interop gate pass and checks it for a "lepic" key.

    frames.py --posts <capture dir>   the PostSlate frames LEPIC sent, as JSON lines, for open-frames
    frames.py <capture dir>           the check

Each capture dir is what run.sh collected with INTEROP_CAPTURE=1: lo.pcap (the loopback of the
stack's network namespace: the relay port and both HTTP listener ports), exchange/ (the slate
files), opened.jsonl (LEPIC's Epicbox messages opened with the peer's key by open-frames) and
the addresses in addresses.env. What counts as written by LEPIC:

- Epicbox: every client frame on a connection where LEPIC subscribed its address or posted from
  it, and the decrypted text of each PostSlate it sent;
- HTTP: request bodies sent to the peer's listener, response bodies from LEPIC's listener;
- slate files: every file in exchange/ that epic-wallet did not write.

The check prints every frame with a "lepic" key, then the counts. CAPTURE_MINIMUM is a JSON
object that maps a frame kind to the fewest frames of that kind the capture must hold. The check
exits 2 when the capture is broken: a kind has fewer frames than CAPTURE_MINIMUM asks for, or an
Epicbox message open-frames could not open. It exits 1 when a frame holds a "lepic" key, and 0
otherwise.
"""

import json
import os
import struct
import sys
import zlib
from pathlib import Path

RELAY_PORT = 3423
PEER_HTTP_PORT = 23500
LEPIC_HTTP_PORT = 23510

# Files epic-wallet writes in /exchange during the gate's scenarios: the funder's and peer's
# sends, and the peer's replies to LEPIC's own slates.
EPIC_WALLET_FILES = {
    "file-epic-wallet-sends.slate",
    "file-epic-wallet-invoices.slate",
    "file-lepic-sends.slate.response",
    "file-lepic-invoices.slate.response",
}


def epic_wallet_wrote(name):
    if name in EPIC_WALLET_FILES:
        return True
    stem = name.removesuffix(".response")
    base = stem.removesuffix(".slate")
    if base.startswith("peer-"):
        return True  # the funder's S1 to the peer and the peer's S2
    return base.startswith("lepic-") and name == stem  # the funder's S1 to LEPIC


def packets(path):
    data = Path(path).read_bytes()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise SystemExit(f"{path}: not a pcap file")
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    offset = 24
    while offset + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[offset + 8 : offset + 12])[0]
        frame = data[offset + 16 : offset + 16 + incl]
        offset += 16 + incl
        if linktype == 1:
            proto, ip = struct.unpack(">H", frame[12:14])[0], frame[14:]
        elif linktype == 113:
            proto, ip = struct.unpack(">H", frame[14:16])[0], frame[16:]
        elif linktype == 276:
            proto, ip = struct.unpack(">H", frame[0:2])[0], frame[20:]
        elif linktype == 0:
            proto, ip = 0x0800 if frame[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02") else 0x86DD, frame[4:]
        else:
            raise SystemExit(f"{path}: link type {linktype} is not handled")
        if proto == 0x0800 and ip and ip[0] >> 4 == 4:
            if ip[9] != 6:
                continue
            ihl = (ip[0] & 0x0F) * 4
            total = struct.unpack(">H", ip[2:4])[0]
            src, dst, tcp = ip[12:16], ip[16:20], ip[ihl:total]
        elif proto == 0x86DD and ip and ip[0] >> 4 == 6:
            if ip[6] != 6:
                continue
            length = struct.unpack(">H", ip[4:6])[0]
            src, dst, tcp = ip[8:24], ip[24:40], ip[40 : 40 + length]
        else:
            continue
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        flags = tcp[13]
        payload = tcp[(tcp[12] >> 4) * 4 :]
        yield (src, sport, dst, dport), seq, flags, payload


def streams(path):
    """Connections to the three watched ports: (server port, client bytes, server bytes)."""
    conns = {}
    order = []
    for (src, sport, dst, dport), seq, flags, payload in packets(path):
        if dport in (RELAY_PORT, PEER_HTTP_PORT, LEPIC_HTTP_PORT) and sport not in (RELAY_PORT, PEER_HTTP_PORT, LEPIC_HTTP_PORT):
            key, side = (src, sport, dst, dport), 0
        elif sport in (RELAY_PORT, PEER_HTTP_PORT, LEPIC_HTTP_PORT):
            key, side = (dst, dport, src, sport), 1
        else:
            continue
        syn, ack = flags & 0x02, flags & 0x10
        if side == 0 and syn and not ack:
            conns[key] = [{}, {}]  # a new connection on this tuple
            order.append((key, conns[key]))
        if key not in conns:
            continue
        if payload:
            conns[key][side].setdefault(seq, payload)
    for key, sides in order:
        yield key[3], join(sides[0]), join(sides[1])


def join(segments):
    out = bytearray()
    end = None
    for seq in sorted(segments):
        data = segments[seq]
        if end is not None and seq < end:
            data = data[end - seq :]  # a retransmission overlapping what we have
        out += data
        end = seq + len(segments[seq]) if end is None or seq + len(segments[seq]) > end else end
    return bytes(out)


def websocket_messages(data):
    """Text messages of one direction of a websocket connection, after its HTTP head."""
    head = data.find(b"\r\n\r\n")
    if head < 0:
        return []
    pos, out, parts, deflated = head + 4, [], [], False
    inflater = zlib.decompressobj(-15)
    while pos + 2 <= len(data):
        b0, b1 = data[pos], data[pos + 1]
        length, pos = b1 & 0x7F, pos + 2
        if length == 126:
            length, pos = struct.unpack(">H", data[pos : pos + 2])[0], pos + 2
        elif length == 127:
            length, pos = struct.unpack(">Q", data[pos : pos + 8])[0], pos + 8
        key = b""
        if b1 & 0x80:
            key, pos = data[pos : pos + 4], pos + 4
        payload = data[pos : pos + length]
        pos += length
        if key:
            payload = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
        opcode = b0 & 0x0F
        if opcode in (1, 2):
            parts, deflated = [payload], bool(b0 & 0x40)
        elif opcode == 0:
            parts.append(payload)
        else:
            continue
        if b0 & 0x80:
            message = b"".join(parts)
            if deflated:
                message = inflater.decompress(message + b"\x00\x00\xff\xff")
            out.append(message.decode("utf-8", "replace"))
    return out


def http_bodies(data):
    """The bodies of the HTTP messages in one direction of a connection."""
    pos, out = 0, []
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            break
        head = data[pos:end].decode("latin-1").lower().split("\r\n")
        headers = dict(h.split(":", 1) for h in head[1:] if ":" in h)
        headers = {k.strip(): v.strip() for k, v in headers.items()}
        pos = end + 4
        if headers.get("transfer-encoding") == "chunked":
            body = bytearray()
            while True:
                line_end = data.find(b"\r\n", pos)
                size = int(data[pos:line_end].split(b";")[0] or b"0", 16)
                pos = line_end + 2
                if size == 0:
                    pos = data.find(b"\r\n", pos) + 2
                    break
                body += data[pos : pos + size]
                pos += size + 2
        elif "content-length" in headers:
            size = int(headers["content-length"])
            body, pos = data[pos : pos + size], pos + size
        elif head[0].startswith("http/"):
            body, pos = data[pos:], len(data)
        else:
            body = b""
        out.append((head[0], body.decode("utf-8", "replace")))
    return out


def lepic_keys(value, path="$"):
    """Every "lepic" key in a JSON value as "path = value", looking into strings that hold JSON."""
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in "{[":
            try:
                return lepic_keys(json.loads(text), path + "(json)")
            except ValueError:
                return []
        return []
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "lepic":
                found.append(f"{path}.lepic = {json.dumps(item)}")
            found += lepic_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            found += lepic_keys(item, f"{path}[{i}]")
    return found


def load_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def check(capture):
    """Frames LEPIC wrote in one capture dir: a list of (kind, label, text)."""
    env = load_env(capture / "addresses.env")
    lepic_key = env["LEPIC_KEY"]
    frames, posts = [], []
    for port, client, server in streams(capture / "lo.pcap"):
        if port == RELAY_PORT:
            messages = websocket_messages(client)
            parsed = []
            for text in messages:
                try:
                    parsed.append(json.loads(text))
                except ValueError:
                    parsed.append({})
            ours = any(
                (m.get("type") == "Subscribe" and m.get("address") == lepic_key)
                or (m.get("type") == "PostSlate" and str(m.get("from", "")).startswith(lepic_key))
                for m in parsed
                if isinstance(m, dict)
            )
            if not ours:
                continue
            for text, m in zip(messages, parsed):
                kind = m.get("type", "?") if isinstance(m, dict) else "?"
                frames.append(("epicbox", kind, text))
                if kind == "PostSlate":
                    posts.append(m)
        elif port == PEER_HTTP_PORT:
            for start, body in http_bodies(client):
                frames.append(("http request", start.split(" ")[0].upper() + f" to :{port}", body))
        elif port == LEPIC_HTTP_PORT:
            for start, body in http_bodies(server):
                frames.append(("http response", f"{start.upper()} from :{port}", body))
    opened = capture / "opened.jsonl"
    if opened.exists():
        for line in opened.read_text().splitlines():
            record = json.loads(line)
            if "plaintext" in record:
                frames.append(("epicbox plaintext", f"PostSlate to {record['to'][:12]}...", record["plaintext"]))
            else:
                frames.append(("epicbox unopened", record.get("error", "?"), ""))
    for path in sorted((capture / "exchange").iterdir()):
        if path.is_file() and not epic_wallet_wrote(path.name):
            frames.append(("slate file", path.name, path.read_text(errors="replace")))
    return frames, posts


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--posts":
        _, posts = check(Path(sys.argv[2]))
        for post in posts:
            print(json.dumps(post))
        return 0
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    minimum = json.loads(os.environ.get("CAPTURE_MINIMUM", "{}"))
    broken, caught, counts = False, [], {}
    for name in sys.argv[1:]:
        capture = Path(name)
        frames, _ = check(capture)
        for kind, label, text in frames:
            counts[kind] = counts.get(kind, 0) + 1
            try:
                value = json.loads(text) if text.strip() else None
            except ValueError:
                value = text
            for path in lepic_keys(value) if value is not None else []:
                caught.append((capture.name, kind, label, path, text))
    for kind, least in minimum.items():
        if counts.get(kind, 0) < least:
            print(f"capture broken: {counts.get(kind, 0)} {kind} frames, at least {least} expected")
            broken = True
    if counts.get("epicbox unopened"):
        print(f"capture broken: {counts['epicbox unopened']} Epicbox messages could not be opened")
        broken = True
    print("Frames LEPIC wrote, by kind: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    seen = set()
    for capture, kind, label, path, text in caught:
        print(f"lepic key: {capture}: {kind} {label}: {path}")
        if (kind, label, text) not in seen:
            seen.add((kind, label, text))
            print("  " + (text if len(text) <= 2000 else text[:2000] + " ...[cut]"))
    frames_caught = len({(c, k, l, t) for c, k, l, _, t in caught})
    print(f"Frames holding a lepic key: {frames_caught}")
    if broken:
        return 2
    if frames_caught:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
