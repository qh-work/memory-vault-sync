"""Explicit endpoint client for the optional taskless network-v1 carrier.

Only configured origins are contacted. The local outbox is durable before a
network attempt, and each frozen ciphertext is reused on retry. Inbox cursors
advance only after endpoint verification and durable local evidence storage.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import re
import sqlite3
import tempfile
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_client import ClientConfig
from memory_vault_storage import private_directory, open_file, atomic_write
from memory_vault_trust import Identity, TrustError, _read_private
from memory_vault_network_crypto import (EncryptionIdentity, PublicKeyTrust, document_sha256,
    seal, open_envelope, verify_envelope, b64url, unb64url, opaque, object_fields, integer, digest)
from memory_vault_network_control import (verify_roster, verify_status, verify_invite, sign_request,
    open_join_challenge, verify_request)

CONFIG_SCHEMA = "memory-vault-network-client/v1"
CONTENT_SCHEMA = "memory-vault-network-content/v1"
MAX_WIRE_BYTES = 8 * 1024 * 1024
MAX_SHARE_BYTES = 2 * 1024 * 1024
MAX_QUEUE_BYTES = 256 * 1024 * 1024
MAX_BODY_SECONDS = 10
MAX_QUARANTINE_MESSAGES = 128
MAX_QUARANTINE_BYTES = 16 * 1024 * 1024


def _text_preview(text: str) -> str:
    preview = text[:512]
    # Bound serialized UTF-8, including JSON escaping, not character count.
    while len(canonical_bytes(preview)) > 512:
        preview = preview[:max(1, len(preview) // 2)]
    return preview


def origin(value: Any) -> str:
    if not isinstance(value, str):
        raise MemoryError("network_invalid_url")
    parsed = urlsplit(value)
    if (parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
            or not parsed.hostname or (parsed.scheme != "https" and not
                (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1", "localhost"}))):
        raise MemoryError("network_https_required")
    return value.rstrip("/")


class HTTPTransport:
    """Caller-owned lazy connection pool; no background worker or global state.

    close() releases this transport's sockets. The 5-second HTTPX timeout is
    per I/O operation, not an absolute header/connect deadline. Once headers
    arrive, a separate 10-second body deadline rejects slow-drip bodies; a
    blocked individual read can additionally use its remaining I/O timeout.
    """
    def __init__(self) -> None:
        self._client: Any = None
        self._closed = False
        self._pool_lock = threading.Lock()

    def _pool(self, httpx: Any) -> Any:
        with self._pool_lock:
            if self._closed:
                raise MemoryError("network_transport_closed")
            if self._client is None:
                self._client = httpx.Client(timeout=5, follow_redirects=False,
                    limits=httpx.Limits(max_connections=8, max_keepalive_connections=8, keepalive_expiry=30))
            return self._client

    def close(self) -> None:
        with self._pool_lock:
            client, self._client = self._client, None
            self._closed = True
        if client is not None:
            client.close()

    def __enter__(self) -> HTTPTransport:
        if self._closed:
            raise MemoryError("network_transport_closed")
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def request(self, base: str, method: str, path: str, value: Any = None, *, deadline: float | None = None) -> Mapping[str, Any]:
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            raise MemoryError("network_budget_exhausted", retryable=True)
        try:
            import httpx
        except ImportError:
            raise MemoryError("network_http_dependency_unavailable") from None
        try:
            client = self._pool(httpx)
            # No redirects or ambient cookies: pooling must not let a relay's
            # Set-Cookie leak across configured services sharing a hostname.
            outgoing = client.build_request(method, origin(base) + path,
                content=None if value is None else canonical_bytes(value),
                headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
                timeout=5 if remaining is None else min(5, remaining))
            outgoing.headers.pop("cookie", None)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MemoryError("network_budget_exhausted", retryable=True)
                outgoing.extensions["timeout"] = httpx.Timeout(min(5, remaining)).as_dict()
            response = client.send(outgoing, stream=True)
            try:
                client.cookies.clear()
                body_deadline = time.monotonic() + MAX_BODY_SECONDS
                if deadline is not None:
                    body_deadline = min(body_deadline, deadline)
                if response.headers.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
                    raise MemoryError("network_response_encoding_rejected")
                raw = bytearray()
                # Iterate wire bytes so a decompressor cannot buffer an entire
                # slow body or expand a compressed response past the budget.
                chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    if time.monotonic() >= body_deadline:
                        raise MemoryError("network_body_deadline_exceeded", retryable=True)
                    if len(raw) + len(chunk) > MAX_WIRE_BYTES:
                        raise MemoryError("network_response_too_large")
                    raw.extend(chunk)
                if time.monotonic() >= body_deadline:
                    raise MemoryError("network_body_deadline_exceeded", retryable=True)
                result = strict_json_loads(bytes(raw))
                if not isinstance(result, dict):
                    raise MemoryError("network_invalid_response")
                if response.status_code != 200 or "error" in result:
                    error = result.get("error", {})
                    code = error.get("code") if isinstance(error, dict) else error
                    if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code) is None:
                        code = "network_request_rejected"
                    retryable = response.status_code == 429 or response.status_code >= 500
                    retryable = retryable or (isinstance(error, dict) and error.get("retryable") is True)
                    raise MemoryError(code, retryable=retryable)
                return result
            finally:
                response.close()
        except httpx.HTTPError:
            if deadline is not None and time.monotonic() >= deadline:
                raise MemoryError("network_budget_exhausted", retryable=True) from None
            raise MemoryError("network_unavailable", retryable=True) from None


class NetworkClient:
    def __init__(self, config_path: Path, *, transport: Any = None):
        self.config_path = Path(config_path)
        raw = _read_private(config_path, 64 * 1024)
        if raw is None:
            raise MemoryError("network_not_configured")
        config = strict_json_loads(raw)
        fields = {"schema_version", "network_id", "client_config_path", "state_directory", "encryption_key_path", "issuer_public_key", "relays", "authority_url"}
        if not isinstance(config, dict) or set(config) != fields or config["schema_version"] != CONFIG_SCHEMA:
            raise MemoryError("network_invalid_config")
        self.network_id = opaque(config["network_id"])
        self.client_config = ClientConfig.load(Path(config["client_config_path"]))
        if self.client_config.identity_path is None or self.client_config.trust_path is None:
            raise MemoryError("network_signing_identity_required")
        self.identity = Identity.load(self.client_config.identity_path)
        self.encryption = EncryptionIdentity.load(Path(config["encryption_key_path"]))
        self.issuers = PublicKeyTrust([config["issuer_public_key"]])
        self.authority_url = origin(config["authority_url"])
        if not isinstance(config["relays"], list) or not 1 <= len(config["relays"]) <= 2:
            raise MemoryError("network_one_or_two_relays_required")
        self.relays = [origin(item) for item in config["relays"]]
        if len(set(self.relays)) != len(self.relays):
            raise MemoryError("network_duplicate_relay")
        self.directory = Path(config["state_directory"])
        if not self.directory.is_absolute() or self.directory == self.client_config.vault_path.parent:
            raise MemoryError("network_separate_state_required")
        self._owns_transport = transport is None
        self.transport = HTTPTransport() if transport is None else transport
        self._binding = {"network_id": self.network_id, "signing_key": self.identity.public_descriptor(),
                         "encryption_key": self.encryption.public_descriptor(),
                         "issuer_public_key": config["issuer_public_key"],
                         "client_config_path": str(self.client_config.path)}

    def close(self) -> None:
        """Close only an internally owned pool, never a borrowed transport."""
        if self._owns_transport:
            self.transport.close()

    def __enter__(self) -> NetworkClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def db(self):
        private_directory(self.directory)
        database = self.directory / "network.sqlite3"
        descriptor = open_file(database, os.O_CREAT | os.O_RDWR, private=True)
        os.close(descriptor)
        for suffix in ("-wal", "-shm", "-journal"):
            sibling = Path(str(database) + suffix)
            if sibling.exists() or sibling.is_symlink():
                descriptor = open_file(sibling, os.O_RDONLY, private=True)
                os.close(descriptor)
        connection = sqlite3.connect(database, timeout=2)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA max_page_count=262144")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox(request_id TEXT PRIMARY KEY,message_id TEXT NOT NULL UNIQUE,input_sha TEXT NOT NULL,
                    body BLOB NOT NULL,envelope BLOB,roster BLOB,receipts TEXT NOT NULL DEFAULT '{}',recipients BLOB);
                CREATE TABLE IF NOT EXISTS inbox(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL,
                    sender TEXT NOT NULL,body BLOB NOT NULL,result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS acknowledgements(message_id TEXT NOT NULL,recipient TEXT NOT NULL,
                    receipt BLOB NOT NULL,PRIMARY KEY(message_id,recipient));
                CREATE TABLE IF NOT EXISTS quarantine(message_id TEXT PRIMARY KEY,digest TEXT NOT NULL UNIQUE,
                    sender TEXT NOT NULL,envelope BLOB NOT NULL,code TEXT NOT NULL);
            """)
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                if "recipients" not in {row[1] for row in connection.execute("PRAGMA table_info(outbox)")}:
                    # Older completely offline rows did not preserve routing.
                    # Keep them intact; only their original caller can supply
                    # missing recipients when no frozen envelope exists.
                    connection.execute("ALTER TABLE outbox ADD COLUMN recipients BLOB")
                binding = connection.execute("SELECT value FROM state WHERE key='configuration_binding'").fetchone()
                if binding is None:
                    occupied = any(connection.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone()
                                   for table in ("state", "outbox", "inbox", "acknowledgements", "quarantine"))
                    if occupied:
                        raise MemoryError("network_state_binding_missing")
                    connection.execute("INSERT INTO state VALUES('configuration_binding',?)", (canonical_bytes(self._binding).decode(),))
                elif strict_json_loads(binding["value"]) != self._binding:
                    raise MemoryError("network_state_configuration_mismatch")
            with connection:
                yield connection
        finally:
            connection.close()

    def _request(self, action: str, body: Mapping[str, Any], *, request_id: str | None = None) -> Mapping[str, Any]:
        now = int(time.time())
        return sign_request(self.identity, network_id=self.network_id, action=action,
                            request_id=request_id or "req_" + secrets.token_hex(16), body=body,
                            issued_at=now, expires_at=now + 60)

    def _transport_request(self, base: str, method: str, path: str, value: Any = None, *, deadline: float | None = None) -> Mapping[str, Any]:
        if deadline is not None and time.monotonic() >= deadline:
            raise MemoryError("network_budget_exhausted", retryable=True)
        if isinstance(self.transport, HTTPTransport):
            return self.transport.request(base, method, path, value, deadline=deadline)
        # Borrowed transports are caller-owned. The cooperative deadline
        # prevents new calls; their individual I/O timeout remains their own.
        return self.transport.request(base, method, path, value)

    def _status(self, nonce: str, *, deadline: float | None = None) -> Mapping[str, Any]:
        anchor = self._recovery_anchor()
        response = self._transport_request(self.authority_url, "POST", "/v1/status",
                                          {"network_id": self.network_id, "nonce": nonce,
                                           "request": self._request("status", {"nonce": nonce})}, deadline=deadline)
        roster_doc = response["roster"]
        roster = verify_roster(roster_doc, self.issuers, network_id=self.network_id, allow_expired=True)
        verify_status(response["status"], self.issuers, network_id=self.network_id, nonce=nonce,
                      roster_sha256=document_sha256(roster_doc), roster_version=roster["version"])
        if anchor is not None:
            minimum, previous_hash = anchor
            if roster["version"] < minimum or (roster["version"] == minimum and document_sha256(roster_doc) != previous_hash):
                raise MemoryError("network_recovery_roster_rollback")
            if previous_hash is not None and roster["version"] == minimum + 1 and roster["previous_sha256"] != previous_hash:
                raise MemoryError("network_recovery_roster_chain_mismatch")
        with self.db() as connection:
            existing = connection.execute("SELECT value FROM state WHERE key='roster'").fetchone()
            if existing:
                previous = strict_json_loads(existing["value"])
                if (roster["version"] < previous["payload"]["version"] or
                        (roster["version"] == previous["payload"]["version"] and document_sha256(previous) != document_sha256(roster_doc))):
                    raise MemoryError("network_roster_rollback")
                if (roster["version"] == previous["payload"]["version"] + 1
                        and roster["previous_sha256"] != document_sha256(previous)):
                    raise MemoryError("network_roster_chain_mismatch")
            members = {item["signing_key"]["key_id"]: item for item in roster["members"] if item["status"] == "active"}
            own = members.get(self.identity.key_id)
            if (not own or own["signing_key"] != self.identity.public_descriptor()
                    or own["encryption_key"] != self.encryption.public_descriptor()):
                raise MemoryError("network_identity_not_active")
            connection.execute("INSERT OR REPLACE INTO state VALUES('roster',?)", (canonical_bytes(roster_doc).decode(),))
        return response

    def _recovery_anchor(self) -> tuple[int, str | None] | None:
        # Restoring keys is not activation. The private marker supplies only a
        # previously verified lower bound; independent fresh status is still
        # required before any send, receive or invitation-consumption request.
        raw = _read_private(self.config_path.parent / "recovery-state.json", 2 * 1024 * 1024)
        if raw is None:
            return None
        marker = object_fields(strict_json_loads(raw), {"schema_version", "network_id", "activation_disabled",
            "requires_fresh_issuer_status", "minimum_roster_version", "last_verified_roster", "last_roster_sha256",
            "old_delivery_cursors_restored", "offline_outbox_restored", "vault_restored_by_this_command"})
        if (marker["schema_version"] != "memory-vault-network-restored-state/v1" or marker["network_id"] != self.network_id
                or marker["activation_disabled"] is not True or marker["requires_fresh_issuer_status"] is not True
                or any(marker[key] is not False for key in ("old_delivery_cursors_restored", "offline_outbox_restored", "vault_restored_by_this_command"))):
            raise MemoryError("network_recovery_marker_invalid")
        minimum = integer(marker["minimum_roster_version"])
        if marker["last_verified_roster"] is None:
            if minimum != 0 or marker["last_roster_sha256"] is not None:
                raise MemoryError("network_recovery_marker_invalid")
            return minimum, None
        previous = verify_roster(marker["last_verified_roster"], self.issuers, network_id=self.network_id, allow_expired=True)
        previous_hash = document_sha256(marker["last_verified_roster"])
        if previous["version"] != minimum or previous_hash != digest(marker["last_roster_sha256"]):
            raise MemoryError("network_recovery_marker_invalid")
        return minimum, previous_hash

    def _refresh(self, relay: str, *, deadline: float | None = None) -> Mapping[str, Any]:
        challenge = self._transport_request(relay, "GET", "/v1/status", deadline=deadline)
        response = self._status(challenge["nonce"], deadline=deadline)
        self._transport_request(relay, "POST", "/v1/status", response, deadline=deadline)
        return response["roster"]

    @staticmethod
    def _members(roster: Mapping[str, Any]) -> dict[str, Any]:
        return {item["signing_key"]["key_id"]: item for item in roster["payload"]["members"] if item["status"] == "active"}

    def connect(self, invitation: Mapping[str, Any] | None = None, request_id: str | None = None) -> Mapping[str, Any]:
        expired_invitation = False
        if invitation is not None:
            if (not isinstance(invitation, dict) or not {"invite", "roster"} <= set(invitation)
                    or set(invitation) - {"invite", "roster", "handoff"}):
                raise MemoryError("network_invalid_invitation_package")
            invite_doc, invited_roster = invitation["invite"], invitation["roster"]
            try:
                invite = verify_invite(invite_doc, self.issuers, network_id=self.network_id)
            except MemoryError as exc:
                if exc.code != "network_control_expired":
                    raise
                # This only permits lookup of a previously persisted exact
                # proof. A node with no consumption record still rejects it.
                invite = verify_invite(invite_doc, self.issuers, network_id=self.network_id,
                                       now=invite_doc["payload"]["issued_at"])
                expired_invitation = True
            if (invite["candidate_signing_key"] != self.identity.public_descriptor()
                    or invite["candidate_encryption_key"] != self.encryption.public_descriptor()
                    or invite["roster_sha256"] != document_sha256(invited_roster)):
                raise MemoryError("network_invitation_identity_mismatch")
            verify_roster(invited_roster, self.issuers, network_id=self.network_id, allow_expired=True)
            handoff = invitation.get("handoff")
            commitment = document_sha256(handoff) if handoff is not None else hashlib.sha256(b"").hexdigest()
            if commitment != invite["handoff_sha256"]:
                raise MemoryError("network_handoff_commitment_mismatch")
            if handoff is not None:
                # Verify/decrypt before consuming the invitation; import only
                # after a successful admission and independent current status.
                trust = PublicKeyTrust([m["signing_key"] for m in self._members(invited_roster).values()])
                open_envelope(handoff, self.encryption, trust, network_id=self.network_id)
        joined, errors = [], []
        for relay in self.relays:
            try:
                current = self._refresh(relay)
                if invitation is not None:
                    join_key = "join:" + relay + ":" + invite["invite_id"]
                    with self.db() as connection:
                        saved = connection.execute("SELECT value FROM state WHERE key=?", (join_key,)).fetchone()
                    if saved:
                        proof = strict_json_loads(saved["value"])
                        if proof["payload"]["body"]["invite_sha256"] != document_sha256(invite_doc):
                            raise MemoryError("network_invitation_retry_conflict")
                    else:
                        if expired_invitation:
                            raise MemoryError("network_control_expired")
                        challenge = self.transport.request(relay, "POST", "/v1/join", {"invite": invite_doc, "roster": invited_roster})["challenge"]
                        answer = open_join_challenge(challenge, self.encryption, network_id=self.network_id, invite_id=invite["invite_id"])
                        proof = self._request("join", {"invite_sha256": document_sha256(invite_doc),
                                                       "challenge_id": challenge["challenge_id"], "challenge_answer": answer}, request_id=request_id)
                        with self.db() as connection:
                            connection.execute("INSERT OR IGNORE INTO state VALUES(?,?)", (join_key, canonical_bytes(proof).decode()))
                            proof = strict_json_loads(connection.execute("SELECT value FROM state WHERE key=?", (join_key,)).fetchone()[0])
                    try:
                        joined_result = self.transport.request(relay, "POST", "/v1/join", {"invite": invite_doc, "roster": invited_roster, "request": proof})
                    except MemoryError as exc:
                        if expired_invitation or exc.code not in {"network_control_expired", "relay_join_challenge_required"}:
                            raise
                        # Exact retry comes first. Only an explicit rejection
                        # of an unconsumed/expired proof permits a new one.
                        challenge = self.transport.request(relay, "POST", "/v1/join", {"invite": invite_doc, "roster": invited_roster})["challenge"]
                        answer = open_join_challenge(challenge, self.encryption, network_id=self.network_id, invite_id=invite["invite_id"])
                        fresh_proof = self._request("join", {"invite_sha256": document_sha256(invite_doc),
                            "challenge_id": challenge["challenge_id"], "challenge_answer": answer})
                        with self.db() as connection:
                            connection.execute("UPDATE state SET value=? WHERE key=? AND value=?",
                                (canonical_bytes(fresh_proof).decode(), join_key, canonical_bytes(proof).decode()))
                            proof = strict_json_loads(connection.execute("SELECT value FROM state WHERE key=?", (join_key,)).fetchone()[0])
                        joined_result = self.transport.request(relay, "POST", "/v1/join", {"invite": invite_doc, "roster": invited_roster, "request": proof})
                    if (joined_result.get("state") != "joined" or joined_result.get("network_id") != self.network_id
                            or joined_result.get("member_key_id") != self.identity.key_id or joined_result.get("invite_id") != invite["invite_id"]):
                        raise MemoryError("network_invalid_join_receipt")
                else:
                    # A status refresh is not proof the member has joined.
                    self.transport.request(relay, "POST", "/v1/poll", self._request("poll", {"cursor": 0, "receipt_cursor": 0, "limit": 1, "maximum_bytes": MAX_WIRE_BYTES}))
                joined.append(relay)
            except (MemoryError, TrustError) as exc:
                errors.append({"node": self.relays.index(relay), "code": exc.code})
        if joined and invitation is not None and invitation.get("handoff") is not None:
            self._accept(invitation["handoff"], current)
        return {"state": "connected" if joined else "not_connected", "joined_nodes": len(joined),
                "configured_nodes": len(self.relays), "degraded": len(joined) != len(self.relays), "errors": errors,
                "member_key_id": self.identity.key_id, "network_accessed": True}

    def discover(self, online: bool = True) -> Mapping[str, Any]:
        response = self._status(secrets.token_hex(24))
        members = list(self._members(response["roster"]).values())
        return {"network_id": self.network_id, "members": [{"key_id": item["signing_key"]["key_id"], "scope": item["scope"]} for item in members[:32]],
                "member_count": len(members), "partial": len(members) > 32, "configured_nodes": len(self.relays), "network_accessed": True}

    def _prepare_body(self, request_id: str, text: str, memory_ids: list[str]) -> bytes:
        memory_ids = list(memory_ids)
        if text:
            # A message's text is an ordinary signed canonical observation at
            # its source, not a receiver-authored assertion about the sender.
            # Its original bytes/proof travel in the unchanged share-v1 format.
            written = self.client_config.vault(writing=True).handle({"op": "remember", "kind": "observation", "text": text,
                "request_id": "req_" + hashlib.sha256(("network-message:" + request_id).encode()).hexdigest()})
            if not written.get("ok"):
                raise MemoryError(written["error"]["code"])
            memory_ids.append(written["result"]["memory_id"])
            memory_ids = list(dict.fromkeys(memory_ids))
        share = None
        if memory_ids:
            from memory_vault_sharing import export_share
            private_directory(self.directory)
            with tempfile.TemporaryDirectory(prefix="selected-", dir=self.directory) as temporary:
                selected = Path(temporary) / "share.ndjson"
                export_share(self.client_config.path, selected, {"schema_version": "universal-memory-selection/v1", "memory_ids": memory_ids}, maximum_seconds=10)
                if selected.stat().st_size > MAX_SHARE_BYTES:
                    raise MemoryError("network_share_too_large_use_existing_pack")
                share = b64url(selected.read_bytes())
        return canonical_bytes({"schema_version": CONTENT_SCHEMA, "text": text, "share": share})

    def send(self, request_id: str, recipients: list[str], text: str = "", memory_ids: list[str] | None = None) -> Mapping[str, Any]:
        opaque(request_id)
        if (not isinstance(recipients, list) or not 1 <= len(recipients) <= 16
                or any(not isinstance(key, str) for key in recipients)
                or len(set(recipients)) != len(recipients) or not isinstance(text, str) or len(text.encode()) > 16384):
            raise MemoryError("network_invalid_send")
        memory_ids = memory_ids or []
        if not isinstance(memory_ids, list) or len(memory_ids) > 32:
            raise MemoryError("network_invalid_memory_selection")
        if not text and not memory_ids:
            raise MemoryError("network_empty_message")
        input_sha = hashlib.sha256(canonical_bytes({"recipients": recipients, "text": text, "memory_ids": memory_ids})).hexdigest()
        message_id = "msg_" + hashlib.sha256(canonical_bytes([self.network_id, self.identity.key_id, request_id])).hexdigest()
        with self.db() as connection:
            prior = connection.execute("SELECT * FROM outbox WHERE request_id=?", (request_id,)).fetchone()
            if prior and prior["input_sha"] != input_sha:
                raise MemoryError("network_request_id_conflict")
            if prior and prior["recipients"] is None:
                connection.execute("UPDATE outbox SET recipients=? WHERE request_id=? AND recipients IS NULL",
                                   (canonical_bytes(recipients), request_id))
                prior = connection.execute("SELECT * FROM outbox WHERE request_id=?", (request_id,)).fetchone()
        if prior is None:
            body = self._prepare_body(request_id, text, memory_ids)
            with self.db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                count, size = connection.execute("SELECT COUNT(*),COALESCE(SUM(length(body)+COALESCE(length(envelope),0)),0) FROM outbox").fetchone()
                if count >= 1024 or size + len(body) * 3 > MAX_QUEUE_BYTES:
                    raise MemoryError("network_outbox_capacity")
                connection.execute("INSERT OR IGNORE INTO outbox(request_id,message_id,input_sha,body,recipients) VALUES(?,?,?,?,?)",
                                   (request_id, message_id, input_sha, body, canonical_bytes(recipients)))
                prior = connection.execute("SELECT * FROM outbox WHERE request_id=?", (request_id,)).fetchone()
                if prior["input_sha"] != input_sha:
                    raise MemoryError("network_request_id_conflict")
        return self._deliver(prior, recipients)

    def _deliver(self, prior: sqlite3.Row, recipients: list[str], *, deadline: float | None = None,
                 pending_only: bool = False) -> Mapping[str, Any]:
        """Reuse durable content; never export memory or reseal a frozen row."""
        request_id, message_id = prior["request_id"], prior["message_id"]
        receipts = {node: receipt for node, receipt in strict_json_loads(prior["receipts"]).items() if node in self.relays}
        errors = []
        envelope = strict_json_loads(prior["envelope"]) if prior["envelope"] else None
        frozen_roster = strict_json_loads(prior["roster"]) if prior["roster"] else None
        if envelope is not None and set(envelope["recipient_key_ids"]) != set(recipients):
            raise MemoryError("network_outbox_routing_mismatch")
        for relay in self.relays:
            if pending_only and relay in receipts:
                continue
            try:
                current = self._refresh(relay, deadline=deadline)
                if deadline is not None and time.monotonic() >= deadline:
                    raise MemoryError("network_budget_exhausted", retryable=True)
                members = self._members(current)
                if "send" not in members[self.identity.key_id]["scope"] or any(k not in members or "receive" not in members[k]["scope"] for k in recipients):
                    raise MemoryError("network_send_scope_denied")
                if envelope is None:
                    candidate = seal(bytes(prior["body"]), signer=self.identity, network_id=self.network_id,
                                     message_id=message_id, recipients=[{"signing_key_id": k, "encryption_key": members[k]["encryption_key"]} for k in recipients],
                                     roster_version=current["payload"]["version"], roster_sha256=document_sha256(current))
                    with self.db() as connection:
                        connection.execute("UPDATE outbox SET envelope=?,roster=? WHERE request_id=? AND envelope IS NULL",
                                           (canonical_bytes(candidate), canonical_bytes(current), request_id))
                        row = connection.execute("SELECT envelope,roster FROM outbox WHERE request_id=?", (request_id,)).fetchone()
                        envelope, frozen_roster = strict_json_loads(row["envelope"]), strict_json_loads(row["roster"])
                historical = self._members(frozen_roster)
                if any(k not in historical or historical[k] != members[k] for k in [self.identity.key_id, *recipients]):
                    raise MemoryError("network_frozen_recipient_changed")
                response = self._transport_request(relay, "POST", "/v1/messages", {"envelope": envelope, "roster": frozen_roster}, deadline=deadline)
                if (response.get("state") != "stored" or response.get("message_id") != message_id
                        or response.get("envelope_sha256") != document_sha256(envelope)):
                    raise MemoryError("network_invalid_storage_receipt")
                receipts[relay] = response
                with self.db() as connection:
                    connection.execute("UPDATE outbox SET receipts=? WHERE request_id=?", (canonical_bytes(receipts).decode(), request_id))
            except (MemoryError, TrustError) as exc:
                errors.append({"node": self.relays.index(relay), "code": exc.code, "retryable": getattr(exc, "retryable", False)})
                if exc.code == "network_budget_exhausted":
                    break
        with self.db() as connection:
            validated = [row[0] for row in connection.execute("SELECT recipient FROM acknowledgements WHERE message_id=?", (message_id,))]
        return {"state": "stored" if len(receipts) == len(self.relays) else "queued_local", "message_id": message_id,
                "stored_nodes": len(receipts), "configured_nodes": len(self.relays), "degraded": len(receipts) < len(self.relays),
                "validated_recipients": validated, "endpoint_validated": set(recipients).issubset(validated),
                "understood": False, "errors": errors, "retry_same_request_id": True}

    def _pending_outbox(self) -> tuple[list[tuple[int, str]], int]:
        with self.db() as connection:
            rows = connection.execute("SELECT rowid AS position,request_id,receipts FROM outbox ORDER BY rowid LIMIT 1025").fetchall()
            cursor = connection.execute("SELECT value FROM state WHERE key='pump_cursor'").fetchone()
        if len(rows) > 1024:
            raise MemoryError("network_outbox_capacity")
        pending = []
        for row in rows:
            receipts = strict_json_loads(row["receipts"])
            if not isinstance(receipts, dict):
                raise MemoryError("network_invalid_storage_receipt")
            if not set(self.relays).issubset(receipts):
                pending.append((row["position"], row["request_id"]))
        return pending, integer(strict_json_loads(cursor["value"])) if cursor else 0

    def pump(self, maximum_messages: int = 4, maximum_seconds: int = 10, receive_limit: int = 4) -> Mapping[str, Any]:
        """Explicit bounded retry/receive pass, never a daemon or scheduler.

        maximum_messages caps outbox attempts (0..16); receive_limit separately
        caps incoming messages (0..4). The 1..60 second cooperative deadline
        starts no new network requests after expiry and limits HTTP timeouts.
        In-flight synchronous OS/storage calls are not forcibly interrupted;
        caller-owned transports remain responsible for their own I/O limits.
        """
        if (type(maximum_messages) is not int or not 0 <= maximum_messages <= 16
                or type(maximum_seconds) is not int or not 1 <= maximum_seconds <= 60
                or type(receive_limit) is not int or not 0 <= receive_limit <= 4):
            raise MemoryError("network_invalid_pump_budget")
        started = time.monotonic()
        deadline = started + maximum_seconds
        pending, cursor = self._pending_outbox()
        ordered = [item for item in pending if item[0] > cursor] + [item for item in pending if item[0] <= cursor]
        outgoing, errors = [], []
        attempted = set()
        for position, request_id in ordered[:maximum_messages]:
            if time.monotonic() >= deadline:
                break
            attempted.add(request_id)
            try:
                with self.db() as connection:
                    prior = connection.execute("SELECT * FROM outbox WHERE request_id=?", (request_id,)).fetchone()
                if prior is None:
                    continue
                if prior["recipients"] is not None:
                    recipients = strict_json_loads(prior["recipients"])
                elif prior["envelope"] is not None:
                    recipients = strict_json_loads(prior["envelope"])["recipient_key_ids"]
                else:
                    raise MemoryError("network_outbox_recipients_unavailable")
                if (not isinstance(recipients, list) or not 1 <= len(recipients) <= 16
                        or any(not isinstance(key, str) for key in recipients) or len(set(recipients)) != len(recipients)):
                    raise MemoryError("network_outbox_routing_mismatch")
                for key in recipients:
                    opaque(key)
                result = self._deliver(prior, recipients, deadline=deadline, pending_only=True)
                outgoing.append({"request_id": request_id, "message_id": result["message_id"],
                                 "state": result["state"], "stored_nodes": result["stored_nodes"], "errors": result["errors"]})
            except (MemoryError, TrustError) as exc:
                outgoing.append({"request_id": request_id, "state": "queued_local", "errors": [
                    {"code": exc.code, "retryable": getattr(exc, "retryable", False),
                     "requires_original_request": exc.code == "network_outbox_recipients_unavailable"}]})
            with self.db() as connection:
                # Rotate past failing rows so one withdrawn member or legacy
                # item cannot starve other queued deliveries on every pass.
                connection.execute("INSERT OR REPLACE INTO state VALUES('pump_cursor',?)", (str(position),))
        incoming = None
        if receive_limit and time.monotonic() < deadline:
            incoming = self.receive(receive_limit, _deadline=deadline)
        exhausted = time.monotonic() >= deadline
        if exhausted:
            errors.append({"code": "network_budget_exhausted", "retryable": True})
        remaining, _ = self._pending_outbox()
        item_errors = [error for item in outgoing for error in item["errors"]]
        receive_errors = [] if incoming is None else incoming["errors"]
        all_errors = errors + item_errors + receive_errors
        unattempted = any(request_id not in attempted for _, request_id in remaining)
        retryable = exhausted or unattempted or any(error.get("retryable", False) for error in all_errors)
        return {"state": "budget_exhausted" if exhausted else "needs_retry" if retryable else "needs_attention" if all_errors else "completed",
                "outbound_attempted": len(attempted), "outbound": outgoing, "remaining_outbox": len(remaining),
                "receive": incoming, "errors": errors, "retryable": retryable, "retry_after_ms": 1000 if retryable else 0,
                "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)), "budget_exhausted": exhausted,
                "limits": {"maximum_messages": maximum_messages, "maximum_seconds": maximum_seconds, "receive_limit": receive_limit},
                "deadline_semantics": "cooperative_no_new_requests_after_deadline", "worker_started": False}

    @staticmethod
    def _existing_delivery(connection: sqlite3.Connection, message_id: str, envelope_digest: str) -> Mapping[str, Any] | None:
        existing = connection.execute("SELECT digest,result FROM inbox WHERE message_id=?", (message_id,)).fetchone()
        if existing:
            if existing["digest"] != envelope_digest:
                raise MemoryError("network_inbox_identity_conflict")
            result = strict_json_loads(existing["result"])
            # Older alpha caches used a character cap. Keep their durable
            # evidence untouched while applying the current response budget.
            preview = _text_preview(result["text"])
            result["text_partial"] = result["text_partial"] or preview != result["text"]
            result["text"] = preview
            return result
        rejected = connection.execute("SELECT digest,sender,code FROM quarantine WHERE message_id=?", (message_id,)).fetchone()
        if rejected:
            if rejected["digest"] != envelope_digest:
                raise MemoryError("network_inbox_identity_conflict")
            return {"message_id": message_id, "sender_key_id": rejected["sender"],
                    "state": "rejected", "code": rejected["code"], "understood": False}
        return None

    def _reject_content(self, envelope: Mapping[str, Any], code: str) -> Mapping[str, Any]:
        # Only _accept's authenticated, authorized, successfully decrypted
        # application-content checks call this path. Store ciphertext, never
        # the invalid plaintext, in bounded local delivery bookkeeping.
        encoded = canonical_bytes(envelope)
        message_id, envelope_digest = envelope["message_id"], document_sha256(envelope)
        with self.db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._existing_delivery(connection, message_id, envelope_digest)
            if existing is not None:
                return existing
            count, size = connection.execute("SELECT COUNT(*),COALESCE(SUM(length(envelope)),0) FROM quarantine").fetchone()
            if count >= MAX_QUARANTINE_MESSAGES or size + len(encoded) > MAX_QUARANTINE_BYTES:
                raise MemoryError("network_quarantine_capacity")
            connection.execute("INSERT INTO quarantine VALUES(?,?,?,?,?)",
                (message_id, envelope_digest, envelope["sender_key_id"], encoded, code))
        return {"message_id": message_id, "sender_key_id": envelope["sender_key_id"],
                "state": "rejected", "code": code, "understood": False}

    def _accept(self, envelope: Mapping[str, Any], current: Mapping[str, Any]) -> Mapping[str, Any]:
        verify_roster(current, self.issuers, network_id=self.network_id, allow_expired=True)
        members = self._members(current)
        trust = PublicKeyTrust([m["signing_key"] for m in members.values()])
        payload = verify_envelope(envelope, trust, network_id=self.network_id)
        if self.identity.key_id not in payload["recipient_key_ids"]:
            raise MemoryError("network_wrong_recipient")
        own, sender = members.get(self.identity.key_id), members.get(payload["sender_key_id"])
        if (own is None or "receive" not in own["scope"] or own["signing_key"] != self.identity.public_descriptor()
                or own["encryption_key"] != self.encryption.public_descriptor()
                or sender is None or "send" not in sender["scope"]):
            raise MemoryError("network_receive_scope_denied")
        if (payload["roster_version"] > current["payload"]["version"]
                or (payload["roster_version"] == current["payload"]["version"]
                    and payload["roster_sha256"] != document_sha256(current))):
            raise MemoryError("network_envelope_roster_mismatch")
        expected_encryption_keys = set()
        for key in payload["recipient_key_ids"]:
            member = members.get(key)
            if member is None or "receive" not in member["scope"]:
                raise MemoryError("network_receive_scope_denied")
            expected_encryption_keys.add(member["encryption_key"]["key_id"])
        actual_encryption_keys = {item["header"]["kid"] for item in payload["jwe"]["recipients"]}
        if actual_encryption_keys != expected_encryption_keys:
            raise MemoryError("network_encryption_recipient_changed")
        body = open_envelope(envelope, self.encryption, trust, network_id=self.network_id)
        message_id, digest = payload["message_id"], document_sha256(envelope)
        with self.db() as connection:
            existing = self._existing_delivery(connection, message_id, digest)
            if existing is not None:
                return existing
        try:
            content = strict_json_loads(body)
        except MemoryError as exc:
            if exc.code not in {"invalid_json", "json_bom_forbidden", "non_finite_json_number", "duplicate_json_key"}:
                raise
            return self._reject_content(envelope, "network_invalid_content_json")
        if (not isinstance(content, dict) or set(content) != {"schema_version", "text", "share"}
                or content["schema_version"] != CONTENT_SCHEMA or not isinstance(content["text"], str)):
            return self._reject_content(envelope, "network_invalid_content")
        try:
            text_bytes = content["text"].encode("utf-8")
        except UnicodeEncodeError:
            return self._reject_content(envelope, "network_invalid_content")
        if len(text_bytes) > 16384:
            return self._reject_content(envelope, "network_invalid_content")
        imported = None
        text_memory_id = None
        if content["share"] is not None:
            from memory_vault_sharing import import_share
            try:
                selected = unb64url(content["share"], maximum=MAX_SHARE_BYTES)
            except MemoryError as exc:
                if exc.code != "network_invalid_base64url":
                    raise
                return self._reject_content(envelope, "network_invalid_content_share_encoding")
            with tempfile.TemporaryDirectory(prefix="received-", dir=self.directory) as temporary:
                source = Path(temporary) / "share.ndjson"
                atomic_write(source, selected, replace=False)
                try:
                    imported = import_share(self.client_config.path, source, verify_signatures=True, maximum_seconds=10)
                except (TrustError, MemoryError) as exc:
                    if exc.code not in {"unknown_key", "revoked_key", "share_record_signature_required", "share_independent_trust_required"}:
                        raise
                    imported = import_share(self.client_config.path, source, maximum_seconds=10)
            # Only inspect IDs after the unchanged share importer has checked
            # every canonical record and the selected dependency closure.
            # This reference is a local view, never a parent of the memory.
            for line in selected.splitlines():
                frame = strict_json_loads(line)
                if (frame.get("type") == "record" and frame["selected"]
                        and frame["record"]["text"] == content["text"]):
                    text_memory_id = frame["record"]["memory_id"]
                    break
        # The native result budget counts serialized UTF-8, including JSON
        # escaping. Four 512-character emoji previews would already exceed it.
        preview = _text_preview(content["text"])
        result = {"message_id": message_id, "sender_key_id": payload["sender_key_id"], "text": preview,
                  "text_partial": preview != content["text"], "text_memory_id": text_memory_id,
                  "share": None if imported is None else
                    {"state": imported["state"], "records_added": imported["records_added"], "admission": imported.get("admission")},
                  "state": "validated_saved", "understood": False}
        # Store complete plaintext locally, not in a relay. Memory text itself
        # never gets an execution or trust-enrollment path.
        with self.db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._existing_delivery(connection, message_id, digest)
            if existing is not None:
                return existing
            count, size = connection.execute("SELECT COUNT(*),COALESCE(SUM(length(body)),0) FROM inbox").fetchone()
            if count >= 4096 or size + len(body) > MAX_QUEUE_BYTES:
                raise MemoryError("network_inbox_capacity")
            connection.execute("INSERT OR IGNORE INTO inbox VALUES(?,?,?,?,?)", (message_id, digest, payload["sender_key_id"], body, canonical_bytes(result).decode()))
            actual = connection.execute("SELECT digest,result FROM inbox WHERE message_id=?", (message_id,)).fetchone()
            if actual["digest"] != digest:
                raise MemoryError("network_inbox_identity_conflict")
        return result

    def receive(self, limit: int = 4, *, _deadline: float | None = None) -> Mapping[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 16:
            raise MemoryError("network_invalid_limit")
        # Keep the high-level result small; further invocations continue from
        # durable per-node cursors. Wire envelopes use the separate larger cap.
        limit = min(limit, 4)
        received, errors, seen = [], [], set()
        unmatched_receipts = 0
        for relay in self.relays:
            if len(received) >= limit:
                break
            try:
                current = self._refresh(relay, deadline=_deadline)
                with self.db() as connection:
                    row = connection.execute("SELECT value FROM state WHERE key=?", ("cursor:" + relay,)).fetchone()
                    cursors = strict_json_loads(row["value"]) if row else {"cursor": 0, "receipt_cursor": 0}
                response = self._transport_request(relay, "POST", "/v1/poll", self._request("poll", {**cursors, "limit": limit - len(received), "maximum_bytes": MAX_WIRE_BYTES}), deadline=_deadline)
                object_fields(response, {"messages", "cursor", "receipts", "receipt_cursor", "has_more"})
                if (not isinstance(response["messages"], list) or not isinstance(response["receipts"], list)
                        or len(response["messages"]) > limit - len(received) or len(response["receipts"]) > limit - len(received)
                        or type(response["has_more"]) is not bool):
                    raise MemoryError("network_invalid_poll_page")
                next_cursors = {"cursor": integer(response["cursor"]), "receipt_cursor": integer(response["receipt_cursor"])}
                if (any(value < cursors[key] for key, value in next_cursors.items())
                        or next_cursors["cursor"] > 4096 or next_cursors["receipt_cursor"] > 4096 * 32
                        or (not response["receipts"] and next_cursors["receipt_cursor"] != cursors["receipt_cursor"])
                        or (response["messages"] and next_cursors["cursor"] <= cursors["cursor"])
                        or (response["receipts"] and next_cursors["receipt_cursor"] <= cursors["receipt_cursor"])):
                    raise MemoryError("network_invalid_cursor")
                for envelope in response["messages"]:
                    result = self._accept(envelope, current)
                    if result["message_id"] not in seen:
                        received.append(result)
                        seen.add(result["message_id"])
                    if result["state"] == "rejected":
                        # Durable local quarantine permits page progress, but
                        # is not validated storage and sends no success ack.
                        continue
                    ack_key = "ack:" + relay + ":" + envelope["message_id"]
                    with self.db() as connection:
                        stored = connection.execute("SELECT value FROM state WHERE key=?", (ack_key,)).fetchone()
                        if stored:
                            ack = strict_json_loads(stored["value"])
                        else:
                            ack = self._request("ack", {"message_id": envelope["message_id"], "envelope_sha256": document_sha256(envelope), "state": "validated_saved"})
                            connection.execute("INSERT INTO state VALUES(?,?)", (ack_key, canonical_bytes(ack).decode()))
                    expected_ack = {"message_id": envelope["message_id"], "envelope_sha256": document_sha256(envelope), "state": "validated_saved"}
                    if ack["payload"]["body"] != expected_ack:
                        raise MemoryError("network_receipt_binding_mismatch")
                    try:
                        ack_result = self._transport_request(relay, "POST", "/v1/ack", ack, deadline=_deadline)
                    except MemoryError as exc:
                        if exc.code != "network_control_expired":
                            raise
                        fresh_ack = self._request("ack", expected_ack)
                        with self.db() as connection:
                            connection.execute("UPDATE state SET value=? WHERE key=? AND value=?",
                                (canonical_bytes(fresh_ack).decode(), ack_key, canonical_bytes(ack).decode()))
                            ack = strict_json_loads(connection.execute("SELECT value FROM state WHERE key=?", (ack_key,)).fetchone()[0])
                        ack_result = self._transport_request(relay, "POST", "/v1/ack", ack, deadline=_deadline)
                    if (any(ack_result.get(key) != value for key, value in expected_ack.items())
                            or ack_result.get("recipient_key_id") != self.identity.key_id
                            or integer(ack_result.get("receipt_sequence"), minimum=1) > 4096 * 32):
                        raise MemoryError("network_invalid_ack_receipt")
                peers = PublicKeyTrust([m["signing_key"] for m in self._members(current).values()])
                with self.db() as connection:
                    for receipt in response["receipts"]:
                        body = object_fields(receipt.get("payload", {}).get("body"), {"message_id", "envelope_sha256", "state"})
                        opaque(body["message_id"])
                        digest(body["envelope_sha256"])
                        recipient = receipt.get("proof", {}).get("key_id")
                        known = connection.execute("SELECT receipt FROM acknowledgements WHERE message_id=? AND recipient=?",
                                                   (body["message_id"], recipient)).fetchone()
                        if known and bytes(known["receipt"]) == canonical_bytes(receipt):
                            continue
                        current_recipient = self._members(current).get(recipient)
                        if current_recipient is None or "receive" not in current_recipient["scope"]:
                            # A backdated proof does not prove it predated key
                            # revocation. Do not accept a new validated claim;
                            # retain already verified local receipts and make
                            # progress without trusting this first-seen claim.
                            errors.append({"node": self.relays.index(relay), "code": "network_receipt_peer_inactive", "retryable": False})
                            continue
                        signed = verify_request(receipt, peers, network_id=self.network_id, action="ack", now=receipt["payload"]["issued_at"])
                        body = signed["body"]
                        if body["state"] != "validated_saved":
                            raise MemoryError("network_receipt_binding_mismatch")
                        outbound = connection.execute("SELECT envelope FROM outbox WHERE message_id=?", (body["message_id"],)).fetchone()
                        if outbound is None:
                            # Recovery deliberately does not restore outbox
                            # state. A valid old peer claim cannot confirm a
                            # send without the original local envelope, but
                            # must not permanently block this relay's cursor.
                            # Do not save it as an acknowledgement or infer
                            # delivery; expose only a bounded diagnostic count.
                            unmatched_receipts += 1
                            continue
                        if outbound["envelope"] is None:
                            raise MemoryError("network_unexpected_receipt")
                        sent = strict_json_loads(outbound["envelope"])
                        recipient = receipt["proof"]["key_id"]
                        if recipient not in sent["recipient_key_ids"] or body["envelope_sha256"] != document_sha256(sent) or body["state"] != "validated_saved":
                            raise MemoryError("network_receipt_binding_mismatch")
                        # Two configured replicas legitimately obtain distinct
                        # signed requests for the same validated-save claim.
                        # Preserve the first accepted proof; do not overwrite it.
                        connection.execute("INSERT OR IGNORE INTO acknowledgements VALUES(?,?,?)", (body["message_id"], recipient, canonical_bytes(receipt)))
                    connection.execute("INSERT OR REPLACE INTO state VALUES(?,?)", ("cursor:" + relay, canonical_bytes(next_cursors).decode()))
            except (MemoryError, TrustError) as exc:
                errors.append({"node": self.relays.index(relay), "code": exc.code, "retryable": getattr(exc, "retryable", False)})
                if exc.code == "network_budget_exhausted":
                    break
        return {"messages": received, "partial": len(received) >= limit, "errors": errors,
                "unmatched_receipts": unmatched_receipts, "network_accessed": True,
                "receipts_mean": "endpoint_validated_saved_not_understood"}
