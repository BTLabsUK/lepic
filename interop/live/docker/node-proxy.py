#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Loopback proxy from the live stack to a public floonet node's API.

epic-wallet v4.0.2 asks its node's owner API for `get_status` and keeps its HTTP and Epicbox
listeners paused until that reports `no_sync`. A public node serves its foreign API but not its
owner API, so this proxy answers owner `get_status` from the same node's public `/v1/status`, which
carries that node's real sync status, and forwards `/v2/foreign` unchanged. Every other owner
method is refused.

All node traffic of lepic, the epic-wallet wallets and the miner goes through here, so the request
rate is limited in one place: reads at most READS_PER_SECOND, writes at most one per WRITE_GAP
seconds, far below the public limits (20 reads and 2 writes per second). A 429 answer is retried
after a growing pause. Each forwarded request is logged with its method and status, and every
request sent upstream, retries included, is counted in LIVE_PROXY_STATS (a JSON file, kept across
restarts) so a run can report how many calls it made.
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ["LIVE_NODE_URL"].rstrip("/")
LISTEN = ("127.0.0.1", int(os.environ.get("LIVE_PROXY_PORT", "33413")))
READS_PER_SECOND = 4
WRITE_GAP = 2.0
WRITE_METHODS = {"push_transaction", "submit_block", "finalize_block_template"}
MAX_BODY = 16 * 1024 * 1024
BACKOFF_START = 10.0
BACKOFF_MAX = 300.0
BACKOFF_TRIES = 6
STATS_FILE = os.environ.get("LIVE_PROXY_STATS")


class Throttle:
    """Spaces calls at least `gap` seconds apart across all threads."""

    def __init__(self, gap):
        self.gap = gap
        self.lock = threading.Lock()
        self.next = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next)
            self.next = start + self.gap
        time.sleep(max(0.0, start - now))


READS = Throttle(1.0 / READS_PER_SECOND)
WRITES = Throttle(WRITE_GAP)


class Stats:
    """Counts the requests sent upstream and keeps STATS_FILE current. The counts carry over a
    restart of the proxy, so a run's difference between two readings stays right."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.counts = {"total": 0, "reads": 0, "writes": 0, "rate_limited": 0, "methods": {}}
        if path and os.path.exists(path):
            with open(path) as file:
                self.counts.update(json.load(file))
        self.save()

    def record(self, names, write, status):
        with self.lock:
            self.counts["total"] += 1
            self.counts["writes" if write else "reads"] += 1
            if status == 429:
                self.counts["rate_limited"] += 1
            for name in names:
                self.counts["methods"][name] = self.counts["methods"].get(name, 0) + 1
            self.save()

    def save(self):
        if not self.path:
            return
        temporary = self.path + ".tmp"
        with open(temporary, "w") as file:
            json.dump(self.counts, file)
        os.replace(temporary, self.path)


STATS = Stats(STATS_FILE)


def upstream(path, body, throttle, names):
    """Sends one request to the public node; returns (status, body bytes)."""
    pause = BACKOFF_START
    for attempt in range(1, BACKOFF_TRIES + 1):
        throttle.wait()
        status, data = send(path, body)
        STATS.record(names, throttle is WRITES, status)
        if status == 429 and attempt < BACKOFF_TRIES:
            log(f"{path} rate limited, retrying in {pause:.0f}s")
            time.sleep(pause)
            pause = min(pause * 2, BACKOFF_MAX)
            continue
        return status, data
    return 429, b"rate limited"


def send(path, body):
    request = urllib.request.Request(
        UPSTREAM + path,
        data=body,
        method="POST" if body is not None else "GET",
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as reply:
            return reply.status, reply.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, TimeoutError) as error:
        return 502, f"upstream unreachable: {error}".encode()


def methods(payload):
    calls = payload if isinstance(payload, list) else [payload]
    return [call.get("method", "?") for call in calls if isinstance(call, dict)]


def log(message):
    print(f"node-proxy: {message}", file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        if length <= 0 or length > MAX_BODY:
            return self.reply(400, b"bad request body")
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except ValueError:
            return self.reply(400, b"request is not JSON")
        names = methods(payload)
        if self.path == "/v2/foreign":
            throttle = WRITES if WRITE_METHODS & set(names) else READS
            status, data = upstream("/v2/foreign", body, throttle, names)
        elif self.path == "/v2/owner" and names == ["get_status"]:
            status, data = upstream("/v1/status", None, READS, names)
            if status == 200:
                result = {"Ok": json.loads(data)}
                data = json.dumps({"id": payload.get("id"), "jsonrpc": "2.0", "result": result}).encode()
        else:
            status, data = 403, b"only the foreign API and owner get_status are available"
        log(f"{self.path} {','.join(names)} -> {status}")
        self.reply(status, data)

    def reply(self, status, data):
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    log(f"forwarding {LISTEN[0]}:{LISTEN[1]} to {UPSTREAM}")
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
