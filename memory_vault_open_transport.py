"""Explicit outbound transport for untrusted open-network introductions.

DNS answers are checked and the selected address is pinned to the connection;
TLS still authenticates the original hostname. No redirects, proxy environment,
cookies, ambient authorization or private-network access are inherited.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import queue
import socket
import ssl
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document

MAX_RPC_BYTES = 65536
RPC_PATH = "/open/v1/rpc"


class _Resolver:
    """At most three uninterruptible OS resolutions, never an unbounded queue.

    A timed-out OS call may keep its fixed daemon worker, but the caller ends at
    its deadline. Later requests fail closed if all resolver slots are occupied.
    """
    def __init__(self):
        self.jobs = queue.Queue(maxsize=3)
        self.slots = threading.BoundedSemaphore(3)
        for _ in range(3):
            threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        while True:
            host, port, allow_loopback, result = self.jobs.get()
            try:
                try:
                    result.put((True, resolved_addresses(host, port, allow_loopback=allow_loopback)))
                except Exception as exc:
                    result.put((False, exc))
            finally:
                self.slots.release()
                self.jobs.task_done()

    def resolve(self, host, port, allow_loopback, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self.slots.acquire(blocking=False):
            raise MemoryError("open_dns_capacity", retryable=True)
        result = queue.Queue(maxsize=1)
        self.jobs.put_nowait((host, port, allow_loopback, result))
        try:
            ok, value = result.get(timeout=remaining)
        except queue.Empty:
            raise MemoryError("open_budget_exhausted", retryable=True) from None
        if not ok:
            raise value
        return value


_resolver = None
_resolver_lock = threading.Lock()


def _resolve(host, port, allow_loopback, deadline):
    global _resolver
    with _resolver_lock:
        if _resolver is None:
            _resolver = _Resolver()
        worker = _resolver
    return worker.resolve(host, port, allow_loopback, deadline)


def _close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def endpoint(value: Any, *, allow_loopback: bool = False) -> tuple[str, str, int]:
    if (not isinstance(value, str) or len(value) > 512 or not value
            or any(c.isspace() for c in value) or any(c in value for c in "\\%?#@")):
        raise MemoryError("open_destination_rejected")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (not host or not host.isascii() or parsed.path not in {"", "/"}
                or parsed.scheme not in {"https", "http"} or parsed.username or parsed.password):
            raise ValueError
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if parsed.netloc.endswith(":") or not 1 <= port <= 65535:
            raise ValueError
        local = host == "localhost"
        try:
            address = ipaddress.ip_address(host)
            local = address.is_loopback
            if not permitted_address(str(address), allow_loopback=allow_loopback):
                raise ValueError
        except ValueError:
            # IP-looking aliases must not become an alternate DNS parser path.
            if ":" in host or all(c in "0123456789." for c in host):
                raise ValueError
            if host not in {"localhost"} and ("." not in host or host.endswith(".")):
                raise ValueError
        if local and not allow_loopback:
            raise ValueError
        if parsed.scheme != "https" and not (allow_loopback and local):
            raise ValueError
    except (ValueError, TypeError):
        raise MemoryError("open_destination_rejected") from None
    return parsed.scheme, host, port


def permitted_address(value: str, *, allow_loopback: bool = False) -> bool:
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return (allow_loopback and address.is_loopback) or (
            address.is_global and not address.is_multicast and not address.is_unspecified)
    except ValueError:
        return False


def resolved_addresses(host: str, port: int, *, allow_loopback: bool = False) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise MemoryError("open_dns_unavailable", retryable=True) from None
    addresses = sorted({answer[4][0] for answer in answers}, key=lambda x: (":" in x, x))
    if not addresses or len(addresses) > 16 or any(
        not permitted_address(a, allow_loopback=allow_loopback) for a in addresses
    ):
        raise MemoryError("open_destination_rejected")
    return addresses


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        # Never pass the hostname to a second resolver after the policy check.
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


@dataclass(frozen=True)
class TransportReply:
    response: Mapping[str, Any]
    observed_address: str
    wire_bytes: int


class OpenHTTPTransport:
    def __init__(self, *, allow_loopback: bool = False):
        if type(allow_loopback) is not bool:
            raise MemoryError("open_invalid_local_policy")
        self.allow_loopback = allow_loopback
        self._slots = threading.BoundedSemaphore(3)
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def request(self, base: str, value: Mapping[str, Any], *, deadline: float) -> TransportReply:
        raw = canonical_bytes(document(value, maximum=MAX_RPC_BYTES))
        scheme, host, port = endpoint(base, allow_loopback=self.allow_loopback)
        remaining = deadline - time.monotonic()
        if self._closed:
            raise MemoryError("open_transport_closed")
        if remaining <= 0 or not self._slots.acquire(timeout=max(0, min(remaining, 10))):
            raise MemoryError("open_budget_exhausted", retryable=True)
        connection = None
        deadline_timer = None
        try:
            addresses = _resolve(host, port, self.allow_loopback, deadline)
            for address in addresses[:2]:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MemoryError("open_budget_exhausted", retryable=True)
                kind = _PinnedTLS if scheme == "https" else _PinnedHTTP
                connection = kind(host, port, address, min(3, remaining))
                try:
                    connection.connect()
                    break
                except OSError:
                    connection.close()
                    connection = None
            if connection is None or connection.sock is None:
                raise MemoryError("open_network_unavailable", retryable=True)
            observed = connection.sock.getpeername()[0]
            if observed not in addresses or not permitted_address(observed, allow_loopback=self.allow_loopback):
                raise MemoryError("open_destination_rejected")
            # Per-read timeouts alone do not bound a drip-fed HTTP header. Keep
            # the socket reference even when HTTPConnection transfers it to the
            # response file, and cut off the whole exchange at one deadline.
            deadline_timer = threading.Timer(max(0, deadline - time.monotonic()), _close_socket, (connection.sock,))
            deadline_timer.daemon = True
            deadline_timer.start()
            connection.request("POST", RPC_PATH, body=raw, headers={
                "Content-Type": "application/json", "Accept-Encoding": "identity", "Connection": "close"})
            response = connection.getresponse()
            if response.status != 200:
                # Unauthenticated HTTP errors cannot mutate identity/control state.
                raise MemoryError("open_request_rejected", retryable=response.status in {429, 503})
            if response.getheader("Content-Encoding", "identity").lower().strip() != "identity":
                raise MemoryError("open_response_encoding_rejected")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isascii() or not length.isdigit() or int(length) > MAX_RPC_BYTES):
                raise MemoryError("open_response_too_large")
            chunks = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MemoryError("open_budget_exhausted", retryable=True)
                if connection.sock is not None:
                    connection.sock.settimeout(min(3, remaining))
                chunk = response.read1(min(4096, MAX_RPC_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > MAX_RPC_BYTES:
                    raise MemoryError("open_response_too_large")
            if time.monotonic() >= deadline:
                raise MemoryError("open_budget_exhausted", retryable=True)
            return TransportReply(document(bytes(chunks), maximum=MAX_RPC_BYTES), observed, len(chunks))
        except (OSError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise MemoryError("open_budget_exhausted", retryable=True) from None
            raise MemoryError("open_network_unavailable", retryable=True) from None
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
            if connection is not None:
                connection.close()
            self._slots.release()
