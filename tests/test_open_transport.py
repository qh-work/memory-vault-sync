"""Actual socket and resolver tests for the open destination policy/deadline."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import unittest
from unittest.mock import patch

from memory_vault import MemoryError
from memory_vault_open_transport import OpenHTTPTransport, _Resolver, endpoint, resolved_addresses


class _Reply(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.seen.append(self.path)
        self.rfile.read(int(self.headers["Content-Length"]))
        if self.server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/")
            self.end_headers()
        elif self.server.mode == "drip":
            try:
                self.connection.sendall(b"HTTP/1.0 200 OK\r\nX-slow: ")
                for _ in range(50):
                    time.sleep(.025)
                    self.connection.sendall(b"x")
            except OSError:
                pass
        elif self.server.mode == "large":
            self.send_response(200)
            self.send_header("Content-Length", "65537")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Length", "11")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')


class OpenTransportTests(unittest.TestCase):
    def server(self, mode):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Reply)
        server.mode, server.seen, server.daemon_threads = mode, [], True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, "http://127.0.0.1:" + str(server.server_port)

    def test_destination_policy_and_explicit_loopback(self):
        rejected = ["http://example.com", "https://127.0.0.1", "https://10.1.2.3", "https://169.254.169.254",
                    "https://[::1]", "https://[::ffff:127.0.0.1]", "https://2130706433", "https://127.1",
                    "https://example.com@127.0.0.1", "https://example.com/path", "https://example.com#x",
                    "https://example.com:0", "https://localhost.", "https://example.com/%2f"]
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(MemoryError):
                endpoint(value)
        self.assertEqual(endpoint("https://example.com"), ("https", "example.com", 443))
        self.assertEqual(endpoint("http://127.0.0.1:12345", allow_loopback=True), ("http", "127.0.0.1", 12345))
        with self.assertRaises(MemoryError):
            endpoint("http://192.168.1.2:12345", allow_loopback=True)

    def test_mixed_dns_answer_fails_closed(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, 443)) for value in ("8.8.8.8", "127.0.0.1")]
        with patch("socket.getaddrinfo", return_value=answers), self.assertRaisesRegex(MemoryError, "open_destination_rejected"):
            resolved_addresses("synthetic.example", 443)

    def test_real_socket_does_not_resolve_hostname_twice(self):
        server, base = self.server("ok")
        original = socket.getaddrinfo
        hosts = []
        def resolver(host, port, *args, **kwargs):
            hosts.append(host)
            return original("127.0.0.1" if host == "localhost" else host, port, *args, **kwargs)
        with patch("socket.getaddrinfo", side_effect=resolver):
            result = OpenHTTPTransport(allow_loopback=True).request(base.replace("127.0.0.1", "localhost"),
                          {"synthetic": True}, deadline=time.monotonic() + 2)
        self.assertEqual(result.response, {"ok": True})
        self.assertEqual(result.observed_address, "127.0.0.1")
        self.assertEqual(hosts.count("localhost"), 1)
        self.assertEqual(server.seen, ["/open/v1/rpc"])

    def test_redirect_and_oversized_reply_are_rejected(self):
        for mode, code in (("redirect", "open_request_rejected"), ("large", "open_response_too_large")):
            server, base = self.server(mode)
            with self.assertRaisesRegex(MemoryError, code):
                OpenHTTPTransport(allow_loopback=True).request(base, {"synthetic": True}, deadline=time.monotonic() + 2)
            self.assertEqual(len(server.seen), 1)

    def test_drip_fed_headers_end_at_whole_request_deadline(self):
        _, base = self.server("drip")
        start = time.monotonic()
        with self.assertRaises(MemoryError):
            OpenHTTPTransport(allow_loopback=True).request(base, {"synthetic": True}, deadline=start + .2)
        self.assertLess(time.monotonic() - start, .8)

    def test_slow_dns_has_fixed_workers_no_unbounded_queue(self):
        resolver = _Resolver()
        blocked = threading.Event()
        entered = threading.Barrier(4)
        def slow(*args, **kwargs):
            entered.wait(timeout=2)
            blocked.wait(timeout=2)
            return ["127.0.0.1"]
        def request():
            with self.assertRaisesRegex(MemoryError, "open_budget_exhausted"):
                resolver.resolve("synthetic.example", 443, False, time.monotonic() + .2)
        try:
            with patch("memory_vault_open_transport.resolved_addresses", side_effect=slow), ThreadPoolExecutor(max_workers=3) as pool:
                futures = [pool.submit(request) for _ in range(3)]
                entered.wait(timeout=2)
                with self.assertRaisesRegex(MemoryError, "open_dns_capacity"):
                    resolver.resolve("synthetic.example", 443, False, time.monotonic() + .2)
                for future in futures:
                    future.result(timeout=1)
                self.assertEqual(resolver.jobs.qsize(), 0)
                blocked.set()
        finally:
            blocked.set()


if __name__ == "__main__":
    unittest.main()
