#!/usr/bin/env python3
"""Loopback proxy from the live stack to a public floonet node's API.

epic-wallet v4.0.2 asks its node's owner API for `get_status` and keeps its HTTP and Epicbox
listeners paused until that reports `no_sync`. A public node serves its foreign API but not its
owner API, so this proxy answers owner `get_status` from the same node's public `/v1/status`, which
carries that node's real sync status, and forwards `/v2/foreign` unchanged. Every other owner
method is refused.

All node traffic of the epic-wallet wallets and the miner goes through here, so the request rate
is limited in one place: reads at most READS_PER_SECOND, writes at most one per WRITE_GAP seconds,
far below the public limits (20 reads and 2 writes per second). A 429 answer is retried after a
growing pause. Each forwarded request is logged with its method and status.
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


def upstream(path, body, throttle):
    """Sends one request to the public node; returns (status, body bytes)."""
    pause = BACKOFF_START
    for attempt in range(1, BACKOFF_TRIES + 1):
        throttle.wait()
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
            if error.code == 429 and attempt < BACKOFF_TRIES:
                log(f"{path} rate limited, retrying in {pause:.0f}s")
                time.sleep(pause)
                pause = min(pause * 2, BACKOFF_MAX)
                continue
            return error.code, error.read()
        except (urllib.error.URLError, TimeoutError) as error:
            return 502, f"upstream unreachable: {error}".encode()
    return 429, b"rate limited"


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
            status, data = upstream("/v2/foreign", body, throttle)
        elif self.path == "/v2/owner" and names == ["get_status"]:
            status, data = upstream("/v1/status", None, READS)
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
