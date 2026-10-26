"""Self-test for the mock payment API: each flag changes the mock as documented."""

import contextlib
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import unittest

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
FLAGS = (
    "ACCEPT_NEGATIVE_AMOUNT",
    "ACCEPT_EXCESS_PRECISION",
    "ACCEPT_HUGE_AMOUNT",
    "IGNORE_IDEMPOTENCY_KEY",
    "NO_DUPLICATE_PROTECTION",
    "ERROR_IN_BODY",
)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def server(**flags):
    port = free_port()
    env = {k: v for k, v in os.environ.items() if k not in FLAGS}
    env.update({"HOST": "127.0.0.1", "PORT": str(port)})
    env.update({name: "true" for name, on in flags.items() if on})
    proc = subprocess.Popen([sys.executable, APP], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError("mock exited early")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("mock did not start")
        yield port
    finally:
        proc.terminate()
        proc.wait()


def post(port, path, body, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    conn.request("POST", path, data, {"Content-Type": "application/json", **(headers or {})})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw)


class SecureDefaults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = server()
        cls.port = cls._ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def test_valid_amount_is_created_on_each_route(self):
        for path in ("/payments", "/refunds", "/reloads"):
            status, body = post(self.port, path, {"amount": "10.00"})
            self.assertEqual(status, 201, path)
            self.assertEqual(body["amount"], "10.00")

    def test_unknown_route_is_404(self):
        self.assertEqual(post(self.port, "/nope", {"amount": "10.00"})[0], 404)

    def test_bad_json_or_missing_amount_is_400(self):
        self.assertEqual(post(self.port, "/payments", b"not json")[0], 400)
        self.assertEqual(post(self.port, "/payments", {"note": "x"})[0], 400)

    def test_negative_content_length_is_400(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(
                b"POST /payments HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"
            )
            self.assertIn(b" 400 ", sock.recv(4096).split(b"\r\n")[0])

    def test_invalid_amounts_are_rejected(self):
        for amount in ("-10.00", "0", "10.001", "1000000.01", "NaN"):
            status, body = post(self.port, "/payments", {"amount": amount})
            self.assertEqual(status, 400, amount)
            self.assertIn("error", body)

    def test_numeric_json_amount_keeps_full_precision(self):
        self.assertEqual(post(self.port, "/payments", b'{"amount": 10.0000000000000001}')[0], 400)
        status, body = post(self.port, "/payments", b'{"amount": 10.50}')
        self.assertEqual((status, body["amount"]), (201, "10.50"))

    def test_lenient_numeric_forms_are_rejected(self):
        for amount in (" 10 ", "1_000", "\uff11\uff10", "+10", "0x10", "1,000"):
            self.assertEqual(post(self.port, "/payments", {"amount": amount})[0], 400, amount)

    def test_plain_decimal_forms_are_accepted(self):
        for amount in ("10", "10.5", "1e2"):
            self.assertEqual(post(self.port, "/payments", {"amount": amount})[0], 201, amount)

    def test_other_methods_are_405_with_allow_header(self):
        for method in ("GET", "PUT", "PATCH", "DELETE"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request(method, "/payments")
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
            self.assertEqual((resp.status, resp.getheader("Allow")), (405, "POST"), method)
            self.assertEqual(body, {"error": "method not allowed"})

    def test_duplicate_without_key_is_409(self):
        request = {"amount": "11.00"}
        self.assertEqual(post(self.port, "/payments", request)[0], 201)
        self.assertEqual(post(self.port, "/payments", request)[0], 409)

    def test_idempotency_key_replays_the_first_result(self):
        key = {"Idempotency-Key": "k1"}
        first = post(self.port, "/payments", {"amount": "12.00"}, key)
        second = post(self.port, "/payments", {"amount": "12.00"}, key)
        self.assertEqual(first[0], 201)
        self.assertEqual(second, (200, first[1]))


class VulnerabilityFlags(unittest.TestCase):
    def accepted(self, flag, amount):
        with server(**{flag: True}) as port:
            return post(port, "/payments", {"amount": amount})

    def test_accept_negative_amount(self):
        for amount in ("-10.00", "0"):
            status, body = self.accepted("ACCEPT_NEGATIVE_AMOUNT", amount)
            self.assertEqual(status, 201, amount)
            self.assertEqual(body["amount"], amount)

    def test_accept_excess_precision(self):
        status, body = self.accepted("ACCEPT_EXCESS_PRECISION", "10.00001")
        self.assertEqual((status, body["amount"]), (201, "10.00001"))

    def test_accept_huge_amount(self):
        status, body = self.accepted("ACCEPT_HUGE_AMOUNT", "999999999999")
        self.assertEqual((status, body["amount"]), (201, "999999999999"))

    def test_ignore_idempotency_key_creates_new_resources(self):
        with server(IGNORE_IDEMPOTENCY_KEY=True) as port:
            key = {"Idempotency-Key": "k1"}
            first = post(port, "/payments", {"amount": "12.00"}, key)
            second = post(port, "/payments", {"amount": "12.00"}, key)
            self.assertEqual((first[0], second[0]), (201, 201))
            self.assertNotEqual(first[1]["id"], second[1]["id"])

    def test_no_duplicate_protection_processes_every_copy(self):
        with server(NO_DUPLICATE_PROTECTION=True) as port:
            results = [post(port, "/payments", {"amount": "11.00"}) for _ in range(3)]
            self.assertEqual([status for status, _ in results], [201, 201, 201])
            self.assertEqual(len({body["id"] for _, body in results}), 3)

    def test_error_in_body_answers_200_with_error_and_amount(self):
        with server(ERROR_IN_BODY=True) as port:
            for amount in ("-10.00", "10.001", "1000000.01"):
                status, body = post(port, "/payments", {"amount": amount})
                self.assertEqual(status, 200, amount)
                self.assertEqual(body["amount"], amount)
                self.assertTrue(body["error"])

    def test_error_in_body_still_rejects_unparsable_amounts_with_400(self):
        with server(ERROR_IN_BODY=True) as port:
            self.assertEqual(post(port, "/payments", {"amount": "notanumber"})[0], 400)

    def test_error_in_body_keeps_valid_amounts_created(self):
        with server(ERROR_IN_BODY=True) as port:
            self.assertEqual(post(port, "/payments", {"amount": "10.00"})[0], 201)


if __name__ == "__main__":
    unittest.main()
