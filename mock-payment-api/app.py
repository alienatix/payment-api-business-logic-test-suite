"""Deliberately vulnerable mock payment API. Insecure by design: for local testing only."""

import json
import os
import threading
import time
import uuid
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
DUPLICATE_WINDOW_SECONDS = 5


def flag(name):
    return os.environ.get(name, "false").lower() in ("1", "true", "yes")


ACCEPT_NEGATIVE_AMOUNT = flag("ACCEPT_NEGATIVE_AMOUNT")
ACCEPT_EXCESS_PRECISION = flag("ACCEPT_EXCESS_PRECISION")
ACCEPT_HUGE_AMOUNT = flag("ACCEPT_HUGE_AMOUNT")
MAX_AMOUNT = Decimal("1000000")
IGNORE_IDEMPOTENCY_KEY = flag("IGNORE_IDEMPOTENCY_KEY")
NO_DUPLICATE_PROTECTION = flag("NO_DUPLICATE_PROTECTION")

ROUTES = {"/payments": "payment", "/refunds": "refund", "/reloads": "reload"}

lock = threading.Lock()
by_key = {}
recent = {}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        kind = ROUTES.get(self.path.split("?")[0])
        if kind is None:
            return self.send_json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0:
                raise ValueError("negative Content-Length")
            raw = self.rfile.read(length)
            body = json.loads(raw)
            amount = Decimal(str(body["amount"]))
        except (ValueError, KeyError, InvalidOperation, TypeError):
            return self.send_json(400, {"error": "invalid amount"})
        if not amount.is_finite() or (amount <= 0 and not ACCEPT_NEGATIVE_AMOUNT):
            return self.send_json(400, {"error": "amount must be positive"})
        if amount.as_tuple().exponent < -2 and not ACCEPT_EXCESS_PRECISION:
            return self.send_json(400, {"error": "too many decimal places"})
        if amount > MAX_AMOUNT and not ACCEPT_HUGE_AMOUNT:
            return self.send_json(400, {"error": "amount too large"})

        key = self.headers.get("Idempotency-Key")
        fingerprint = (self.path, raw)
        with lock:
            if key and not IGNORE_IDEMPOTENCY_KEY and key in by_key:
                return self.send_json(200, by_key[key])
            now = time.monotonic()
            if not NO_DUPLICATE_PROTECTION and not key:
                if now - recent.get(fingerprint, -DUPLICATE_WINDOW_SECONDS) < DUPLICATE_WINDOW_SECONDS:
                    return self.send_json(409, {"error": "duplicate request"})
                recent[fingerprint] = now
            result = {"id": str(uuid.uuid4()), "type": kind, "amount": str(amount), "status": "created"}
            if key:
                by_key[key] = result
        self.send_json(201, result)

    def send_json(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"INSECURE BY DESIGN mock payment API on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
