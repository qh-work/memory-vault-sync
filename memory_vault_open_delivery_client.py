"""Durable open delivery phases using explicit first-contact approval.

Transport state shares the participant's protected database. Chat stays in the
inbox; selected Memory shares use the existing exporter and idempotent importer.
No private network roster or transport-derived trust is used here.
"""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Any, Mapping

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network import NetworkClient, _text_preview
from memory_vault_network_content import (
    MAX_CONTENT_BYTES, MAX_CONTENT_SHARE_BYTES, content_text, validate_content,
)
from memory_vault_network_crypto import document, integer, object_fields, opaque, unb64url
from memory_vault_open_contact import ContactError, verify_decision
from memory_vault_open_contact_client import OpenContactClient
from memory_vault_open_delivery import (
    CHUNK_BYTES, create_envelope, decrypt_envelope, envelope_ref,
    immutable_ref, issue_recipient_receipt, issue_upload_intent, reader_intent, sign_rpc,
    solve_challenge, verify_envelope, verify_recipient_receipt,
    verify_response, verify_rpc, verify_storage_receipt, verify_upload_intent,
)
from memory_vault_open_routing import LookupBudget
from memory_vault_storage import atomic_write

MAX_ENVELOPE_BYTES = 6 * 1024 * 1024
MAX_LOCAL_BYTES = 256 * 1024 * 1024
MAX_OUTBOX_RECORDS = 1024
MAX_INBOX_RECORDS = 4096
MAX_SESSION_BYTES = 32768
MAX_INBOX_SESSION_BYTES = 65536
MAX_RESULT_BYTES = 16384
MAX_INTENT_BYTES = 49152


class _DeliveryBudget:
    """One finite application budget; routing retains its smaller own cap."""
    def __init__(self):
        self.deadline = time.monotonic() + 60
        self.requests = self.request_bytes = self.bytes = 0

    def check(self):
        if (time.monotonic() >= self.deadline or self.requests > 256
                or self.request_bytes + self.bytes > 64 * 1024 * 1024):
            raise MemoryError("open_delivery_budget_exhausted", retryable=True)

    def request(self, byte_count):
        self.check()
        if self.requests >= 256 or self.request_bytes + self.bytes + byte_count > 64 * 1024 * 1024:
            raise MemoryError("open_delivery_budget_exhausted", retryable=True)
        self.requests += 1
        self.request_bytes += byte_count

    def response(self, byte_count):
        self.bytes += byte_count
        self.check()

    def routing(self):
        self.check()
        return LookupBudget(maximum_seconds=min(10, self.deadline - time.monotonic()))

    def merge_routing(self, child):
        self.requests += child.requests
        self.request_bytes += child.request_bytes
        self.bytes += child.bytes
        self.check()


class OpenDeliveryClient:
    def __init__(self, participant, encryption, client_config):
        self.participant = participant
        self.identity = participant.identity
        self.encryption = encryption
        self.client_config = client_config
        self.directory = participant.state.directory
        self.contact = OpenContactClient(participant, encryption)
        binding = canonical_bytes({
            "schema_version": "memory-vault-open-delivery-client-state/v1",
            "signing_key_id": self.identity.key_id,
            "encryption_key_id": encryption.key_id,
            "client_config_path": str(client_config.path),
            "vault_path": str(client_config.vault_path),
        })
        with self.participant.state.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS open_delivery_client_state(
                    key TEXT PRIMARY KEY, body BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS open_delivery_outbox(
                    request_id TEXT PRIMARY KEY, message_id TEXT NOT NULL UNIQUE,
                    input_sha256 TEXT NOT NULL, recipient TEXT NOT NULL,
                    body BLOB NOT NULL, envelope BLOB, session BLOB, intent BLOB,
                    result BLOB, acknowledgement BLOB, upload_offset INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS open_delivery_inbox(
                    message_id TEXT PRIMARY KEY, envelope_sha256 TEXT NOT NULL,
                    sender TEXT NOT NULL, envelope BLOB NOT NULL, body BLOB NOT NULL,
                    session BLOB NOT NULL, phase TEXT NOT NULL, result BLOB,
                    receipt BLOB, receipt_sent INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS open_delivery_inbox_phase
                    ON open_delivery_inbox(phase,created_at,message_id);
            """)
            # These columns also allow resuming a queue created while this
            # carrier was being wired into the existing open facade.
            columns = {row[1] for row in db.execute("PRAGMA table_info(open_delivery_outbox)")}
            for name in ("intent", "acknowledgement"):
                if name not in columns:
                    db.execute("ALTER TABLE open_delivery_outbox ADD COLUMN " + name + " BLOB")
            if "receipt_sent" not in {row[1] for row in db.execute("PRAGMA table_info(open_delivery_inbox)")}:
                db.execute("ALTER TABLE open_delivery_inbox ADD COLUMN receipt_sent INTEGER NOT NULL DEFAULT 0")
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT body FROM open_delivery_client_state WHERE key='binding'").fetchone()
            if prior is None:
                if any(db.execute("SELECT 1 FROM " + name + " LIMIT 1").fetchone()
                       for name in ("open_delivery_outbox", "open_delivery_inbox")):
                    raise MemoryError("open_delivery_state_binding_missing")
                db.execute("INSERT INTO open_delivery_client_state VALUES('binding',?)", (binding,))
            elif bytes(prior[0]) != binding:
                raise MemoryError("open_delivery_state_binding_mismatch")

    @staticmethod
    def _send_input(request_id, recipients, text, memory_ids, control):
        opaque(request_id)
        if (not isinstance(recipients, list) or len(recipients) != 1
                or not isinstance(recipients[0], str)
                or re.fullmatch(r"ed25519_[0-9a-f]{64}", recipients[0]) is None
                or not isinstance(text, str) or control is not None):
            raise MemoryError("open_delivery_invalid_send")
        try:
            if len(text.encode("utf-8")) > 16384:
                raise MemoryError("network_invalid_send")
        except UnicodeError:
            raise MemoryError("network_invalid_send") from None
        if memory_ids is None:
            memory_ids = []
        if (not isinstance(memory_ids, list) or len(memory_ids) > 32
                or any(not isinstance(item, str) or re.fullmatch(r"mem_[0-9a-f]{40}", item) is None
                       for item in memory_ids)
                or len(set(memory_ids)) != len(memory_ids)):
            raise MemoryError("network_invalid_memory_selection")
        if not text and not memory_ids:
            raise MemoryError("network_empty_message")
        normalized = {"recipients": recipients, "text": text, "memory_ids": memory_ids}
        return hashlib.sha256(canonical_bytes(normalized)).hexdigest(), list(memory_ids)

    def _outbox(self, request_id):
        with self.participant.state.db() as db:
            row = db.execute("SELECT * FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _local_size(db, table):
        if table == "open_delivery_outbox":
            expression = "length(body)+COALESCE(length(envelope),6291456)+COALESCE(length(session),32768)+COALESCE(length(intent),49152)+32768"
        elif table == "open_delivery_inbox":
            expression = "length(body)+length(envelope)+length(session)+32768"
        else:
            raise MemoryError("open_delivery_invalid_local_table")
        return db.execute("SELECT count(*),COALESCE(sum(" + expression + "),0) FROM " + table).fetchone()

    def _prepare_outbox(self, request_id, recipient, input_sha256, text, memory_ids):
        prior = self._outbox(request_id)
        if prior is not None:
            if prior["input_sha256"] != input_sha256 or prior["recipient"] != recipient:
                raise MemoryError("network_request_id_conflict")
            return prior
        # This existing method only exports the explicit selection and validates
        # content/v2. It does not instantiate or invoke private-network routing.
        body = NetworkClient._prepare_body(self, request_id, text, memory_ids)
        message_id = "msg_" + hashlib.sha256(canonical_bytes([
            "memory-vault-open-delivery/v1", self.identity.key_id, request_id,
        ])).hexdigest()
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT * FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone()
            if prior is None:
                count, size = self._local_size(db, "open_delivery_outbox")
                # Reserve the eventual ciphertext, approval snapshot and result
                # before creating any remote application obligation.
                if count >= MAX_OUTBOX_RECORDS or size + len(body) + MAX_ENVELOPE_BYTES + MAX_SESSION_BYTES + MAX_INTENT_BYTES + 2 * MAX_RESULT_BYTES > MAX_LOCAL_BYTES:
                    raise MemoryError("network_outbox_capacity")
                db.execute("INSERT INTO open_delivery_outbox(request_id,message_id,input_sha256,recipient,body,created_at) VALUES(?,?,?,?,?,?)",
                           (request_id, message_id, input_sha256, recipient, body, int(time.time())))
                prior = db.execute("SELECT * FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone()
            if prior["input_sha256"] != input_sha256 or prior["recipient"] != recipient:
                raise MemoryError("network_request_id_conflict")
            return dict(prior)

    def _freeze_outbox(self, request_id, envelope, session):
        encoded = canonical_bytes(document(envelope, maximum=MAX_ENVELOPE_BYTES))
        proof = canonical_bytes(document(session, maximum=MAX_SESSION_BYTES))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT * FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone()
            if prior is None:
                raise MemoryError("open_delivery_outbox_missing")
            if prior["envelope"] is None:
                _, size = self._local_size(db, "open_delivery_outbox")
                if size - MAX_ENVELOPE_BYTES - MAX_SESSION_BYTES + len(encoded) + len(proof) > MAX_LOCAL_BYTES:
                    raise MemoryError("network_outbox_capacity")
                db.execute("UPDATE open_delivery_outbox SET envelope=?,session=? WHERE request_id=?", (encoded, proof, request_id))
            # A simultaneous sender may have frozen its own random JWE first.
            # Every caller must use that stored ciphertext, never its local one.
            return dict(db.execute("SELECT * FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone())

    def _save_send_result(self, request_id, result):
        raw = canonical_bytes(document(result, maximum=MAX_RESULT_BYTES))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT result FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone()
            if prior is None:
                raise MemoryError("open_delivery_outbox_missing")
            if prior[0] is not None and bytes(prior[0]) != raw:
                raise MemoryError("open_delivery_result_conflict")
            db.execute("UPDATE open_delivery_outbox SET result=? WHERE request_id=?", (raw, request_id))

    def _upload_intent(self, row, session):
        now = int(time.time())
        if row["intent"] is not None:
            prior_intent = document(bytes(row["intent"]), maximum=MAX_INTENT_BYTES)
            if prior_intent["payload"]["expires_at"] > now:
                return prior_intent
        intent = issue_upload_intent(self.identity, operation_id=row["request_id"],
            envelope_ref=envelope_ref(bytes(row["envelope"])), message_id=row["message_id"],
            authority={name: session[name] for name in ("request", "policy", "lease", "decision")},
            issued_at=now, expires_at=min(now + 3600, session["decision"]["payload"]["expires_at"]))
        verify_upload_intent(intent, node=session["node"])
        raw = canonical_bytes(document(intent, maximum=MAX_INTENT_BYTES))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT intent FROM open_delivery_outbox WHERE request_id=?", (row["request_id"],)).fetchone()
            if prior is None:
                raise MemoryError("open_delivery_outbox_missing")
            if prior[0] is not None:
                current = document(bytes(prior[0]), maximum=MAX_INTENT_BYTES)
                if current["payload"]["expires_at"] > now:
                    return current
            db.execute("UPDATE open_delivery_outbox SET intent=? WHERE request_id=?", (raw, row["request_id"]))
        return intent

    async def call(self, node, action, body, budget):
        budget.check()
        self.participant._accept(node)
        request = sign_rpc(self.identity, node=node, action=action, body=body)
        verify_rpc(request, node=node)
        budget.request(len(canonical_bytes(request)))
        reply = await asyncio.to_thread(self.participant.transport.request,
            node["payload"]["base_url"], request, deadline=budget.deadline)
        budget.response(reply.wire_bytes)
        checked = verify_response(reply.response, request=request, node=node)
        self.participant._accept(node)
        if "error" in checked["body"]:
            error = checked["body"]["error"]
            raise MemoryError(error["code"], retryable=error["retryable"])
        self.participant.table.learn_verified(node, reply.observed_address)
        return checked["body"]

    def _answer(self, challenge, *, intent, node):
        if challenge["payload"]["context"]["subject_key_id"] != self.identity.key_id:
            raise MemoryError("open_delivery_challenge_mismatch")
        return solve_challenge(challenge, encryption_identity=self.encryption, intent=intent, node=node)

    @staticmethod
    def _handle(value, ref):
        if not isinstance(value, Mapping):
            raise MemoryError("open_delivery_invalid_response")
        required = {"state", "handle_id", "envelope_ref", "durable_prefix", "expires_at", "chunk_size"}
        if not required <= set(value) or set(value) - required - {"intent", "source_node", "storage_receipt"}:
            raise MemoryError("open_delivery_invalid_response")
        opaque(value["handle_id"])
        prefix = integer(value["durable_prefix"])
        expires = integer(value["expires_at"])
        if (value["envelope_ref"] != ref or type(value["chunk_size"]) is not int
                or value["chunk_size"] != CHUNK_BYTES or not isinstance(value["state"], str)
                or prefix > ref["size"] or (prefix != ref["size"] and prefix % CHUNK_BYTES)
                or expires <= int(time.time())):
            raise MemoryError("open_delivery_handle_mismatch")
        return value

    async def _blob(self, node, action, handle_id, ref, offset, length, chunk, budget):
        from memory_vault_open_blob import sign_blob_request, verify_blob_response
        header = sign_blob_request(self.identity, node=node, action=action + ".chunk",
            handle_id=handle_id, ref=ref, offset=offset, length=length,
            chunk=chunk if action == "upload" else None)
        budget.request(14 + len(canonical_bytes(header)) + len(chunk))
        reply = await asyncio.to_thread(self.participant.transport.request_blob,
            node["payload"]["base_url"], header, chunk, deadline=budget.deadline)
        budget.response(reply.wire_bytes)
        payload = verify_blob_response(reply.header, request=header, node=node)
        body = payload["body"]
        if "error" in body:
            if reply.chunk:
                raise MemoryError("open_delivery_invalid_blob_response")
            error = body["error"]
            raise MemoryError(error["code"], retryable=error["retryable"])
        if action == "upload":
            if reply.chunk:
                raise MemoryError("open_delivery_invalid_blob_response")
        elif len(reply.chunk) != length or hashlib.sha256(reply.chunk).hexdigest() != body["chunk_sha256"]:
            raise MemoryError("open_delivery_blob_digest_mismatch")
        self.participant._accept(node)
        self.participant.table.learn_verified(node, reply.observed_address)
        return body, reply.chunk

    async def _upload(self, row, node, handle, budget):
        raw = bytes(row["envelope"])
        ref = envelope_ref(raw)
        checked = self._handle(handle, ref)
        if checked["state"] not in {"uploading", "committed"}:
            raise MemoryError("open_delivery_handle_mismatch")
        offset = checked["durable_prefix"]
        while offset < len(raw):
            chunk = raw[offset:offset + CHUNK_BYTES]
            result, _ = await self._blob(node, "upload", checked["handle_id"], ref,
                                         offset, len(chunk), chunk, budget)
            offset = result["durable_prefix"]
            with self.participant.state.db() as db:
                db.execute("UPDATE open_delivery_outbox SET upload_offset=? WHERE request_id=?", (offset, row["request_id"]))

    async def _download(self, node, handle, ref, budget):
        checked = self._handle(handle, ref)
        if checked["state"] != "reading":
            raise MemoryError("open_delivery_handle_mismatch")
        raw = bytearray()
        while len(raw) < ref["size"]:
            length = min(CHUNK_BYTES, ref["size"] - len(raw))
            _, chunk = await self._blob(node, "download", checked["handle_id"], ref,
                                        len(raw), length, b"", budget)
            raw.extend(chunk)
        frozen = bytes(raw)
        if hashlib.sha256(frozen).hexdigest() != ref["raw_sha256"] or envelope_ref(frozen) != ref:
            raise MemoryError("open_delivery_envelope_mismatch")
        return frozen

    async def send(self, request_id, recipients, text="", memory_ids=None, control=None):
        input_sha, selected = self._send_input(request_id, recipients, text, memory_ids, control)
        row = self._prepare_outbox(request_id, recipients[0], input_sha, text, selected)
        budget = _DeliveryBudget()
        if row["session"] is None:
            session = await self._sending_session(recipients[0], budget)
            row = self._encrypt_outbox(row, session)
        else:
            session = document(bytes(row["session"]), maximum=MAX_SESSION_BYTES)
        self._encrypt_outbox(row, session)
        node, pending_code = None, None
        if row["result"] is None:
            # Recover a committed upload even if its final response was lost
            # and its short upload intent has since expired. The signed result
            # is historical; this grants no new upload or memory authority.
            if row["intent"] is not None:
                route_budget = budget.routing()
                try:
                    node = await self.contact._session_node(session, route_budget)
                finally:
                    budget.merge_routing(route_budget)
                stored = await self.call(node, "stored.get", {"message_id": row["message_id"],
                    "envelope_ref": envelope_ref(bytes(row["envelope"]))}, budget)
                if stored.get("state") == "storage_accepted":
                    object_fields(stored, {"state", "storage_receipt", "source_node", "intent"})
                    if canonical_bytes(stored["intent"]) != bytes(row["intent"]):
                        raise MemoryError("open_delivery_intent_mismatch")
                    verify_storage_receipt(stored["storage_receipt"], node=stored["source_node"], intent=stored["intent"])
                    self._save_send_result(request_id, {name: stored[name] for name in ("state", "storage_receipt", "source_node")})
                    row = self._outbox(request_id)
                elif stored != {"state": "absent"}:
                    raise MemoryError("open_delivery_invalid_response")
        if row["result"] is None:
            session = await self._checked_session(session, budget)
            node = session["node"]
            intent = self._upload_intent(row, session)
            verify_upload_intent(intent, node=node)
            prepared = await self.call(node, "prepare", {"intent": intent}, budget)
            challenge = prepared["challenge"]
            answer = self._answer(challenge, intent=intent, node=node)
            handle = await self.call(node, "start", {"intent": intent, "challenge": challenge, "answer": answer}, budget)
            await self._upload(row, node, handle, budget)
            result = await self.call(node, "commit", {"handle_id": handle["handle_id"]}, budget)
            object_fields(result, {"state", "storage_receipt", "source_node"})
            if result["state"] != "storage_accepted":
                raise MemoryError("open_delivery_invalid_response")
            checked = verify_storage_receipt(result["storage_receipt"], node=result["source_node"], intent=intent)
            if checked["stored_at"] > int(time.time()) + 30:
                raise MemoryError("open_delivery_receipt_mismatch")
            self._save_send_result(request_id, result)
            row = self._outbox(request_id)
        else:
            # A stored result remains a historical fact even when its original
            # short upload authority has expired. It must still verify exactly.
            result = document(bytes(row["result"]), maximum=MAX_RESULT_BYTES)
            intent = document(bytes(row["intent"]), maximum=MAX_INTENT_BYTES)
            verify_storage_receipt(result["storage_receipt"], node=result["source_node"], intent=intent)
            if row["acknowledgement"] is None:
                route_budget = budget.routing()
                try:
                    node = await self.contact._session_node(session, route_budget)
                except MemoryError as exc:
                    pending_code = exc.code
                finally:
                    budget.merge_routing(route_budget)
        acknowledgement = None
        if row["acknowledgement"] is not None:
            acknowledgement = document(bytes(row["acknowledgement"]), maximum=4096)
        elif node is not None:
            try:
                response = await self.call(node, "receipt.get", {"message_id": row["message_id"]}, budget)
                object_fields(response, {"state", "receipt"})
                acknowledgement = response["receipt"]
                if response["state"] != ("pending" if acknowledgement is None else "validated_saved"):
                    raise MemoryError("open_delivery_invalid_response")
            except MemoryError as exc:
                pending_code = exc.code
        if acknowledgement is not None:
            verify_recipient_receipt(acknowledgement,
                recipient_signing_key=self._keys(session)["recipient_signing_key"],
                sender_key_id=self.identity.key_id, message_id=row["message_id"],
                envelope_ref=envelope_ref(bytes(row["envelope"])))
            raw = canonical_bytes(document(acknowledgement, maximum=4096))
            with self.participant.state.db() as db:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute("SELECT acknowledgement FROM open_delivery_outbox WHERE request_id=?", (request_id,)).fetchone()
                if prior[0] is not None and bytes(prior[0]) != raw:
                    raise MemoryError("open_delivery_receipt_conflict")
                db.execute("UPDATE open_delivery_outbox SET acknowledgement=? WHERE request_id=?", (raw, request_id))
        return {"state": "validated_saved" if acknowledgement is not None else "storage_accepted",
                "request_id": request_id, "message_id": row["message_id"],
                "content_kind": validate_content(bytes(row["body"]))["kind"],
                "storage_accepted": True, "endpoint_validated": acknowledgement is not None,
                "recipient_key_id": row["recipient"], "network_accessed": budget.requests > 0,
                "acknowledgement_pending": acknowledgement is None,
                **({"pending_code": pending_code} if pending_code is not None else {})}

    def _contact_sessions(self, *, outgoing, recipient=None):
        """Read actual bounded contact decisions, without creating approval."""
        category, decision_category = ("outgoing", "result") if outgoing else ("incoming", "decision")
        with self.participant.state.db() as db:
            rows = db.execute("SELECT a.reference,a.body,b.body AS decision FROM open_contact_local a JOIN open_contact_local b ON b.reference=a.reference AND b.category=? WHERE a.category=? AND a.expires_at>? AND b.expires_at>? ORDER BY a.expires_at DESC,a.reference LIMIT 128",
                              (decision_category, category, int(time.time()), int(time.time()))).fetchall()
        sessions = []
        for row in rows:
            session = document(bytes(row["body"]), maximum=MAX_SESSION_BYTES)
            decision = document(bytes(row["decision"]), maximum=24576).get("decision")
            if decision is None:
                continue
            request = session.get("request")
            if not isinstance(request, Mapping):
                raise MemoryError("open_delivery_invalid_session")
            original = request["payload"]
            if outgoing:
                if original["signing_key"] != self.identity.public_descriptor() or original["encryption_key"] != self.encryption.public_descriptor():
                    continue
                if recipient is not None and original["recipient_key_id"] != recipient:
                    continue
            elif original["recipient_key_id"] != self.identity.key_id or original["recipient_encryption_key_id"] != self.encryption.key_id:
                continue
            if decision["payload"].get("decision") != "approved":
                continue
            sessions.append({**session, "decision": decision})
        return sessions

    async def _checked_session(self, session, budget):
        route_budget = budget.routing()
        try:
            node = await self.contact._session_node(session, route_budget)
        finally:
            budget.merge_routing(route_budget)
        checked = verify_decision(session["decision"], request=session["request"],
                                  policy=session["policy"], lease=session["lease"], node=node)
        if checked["decision"] != "approved" or checked["grant"] is None:
            raise MemoryError("open_contact_approval_required")
        return {**session, "node": node}

    @staticmethod
    def _keys(session):
        if "intent" in session:
            session = session["intent"]["payload"]["authority"]
        request, policy = session["request"]["payload"], session["policy"]["payload"]
        return {"sender_signing_key": request["signing_key"],
                "sender_encryption_key": request["encryption_key"],
                "recipient_signing_key": policy["signing_key"],
                "recipient_encryption_key": policy["encryption_key"]}

    async def _sending_session(self, recipient, budget):
        sessions = self._contact_sessions(outgoing=True, recipient=recipient)
        if not sessions:
            # Fetch only an existing explicit request's decision. This neither
            # creates a first-contact request nor approves one for the user.
            with self.participant.state.db() as db:
                rows = db.execute("SELECT body FROM open_contact_local WHERE category='outgoing' AND expires_at>? ORDER BY expires_at DESC,reference LIMIT 128", (int(time.time()),)).fetchall()
            for row in rows:
                session = document(bytes(row[0]), maximum=MAX_SESSION_BYTES)
                request = session.get("request")
                if not isinstance(request, Mapping) or request["payload"]["recipient_key_id"] != recipient:
                    continue
                route_budget = budget.routing()
                try:
                    node = await self.contact._session_node(session, route_budget)
                    from memory_vault_open_contact import solve_challenge
                    challenge = (await self.contact.call(node, "challenge", {"request": request, "purpose": "result"}, route_budget))["challenge"]
                    answer = solve_challenge(challenge, request=request, node=node,
                                             purpose="result", encryption_identity=self.encryption)
                    result = await self.contact.call(node, "result", {"request": request, "challenge": challenge, "answer": answer}, route_budget)
                    decision = result["decision"]
                    if decision is not None:
                        verify_decision(decision, request=request, policy=session["policy"], lease=session["lease"], node=node)
                        self.contact._save("result", request["payload"]["request_id"], {"decision": decision}, request["payload"]["expires_at"])
                finally:
                    budget.merge_routing(route_budget)
                break
            sessions = self._contact_sessions(outgoing=True, recipient=recipient)
        for session in sessions:
            try:
                return await self._checked_session(session, budget)
            except ContactError as exc:
                if exc.code not in {"contact_expired", "contact_policy_mismatch"}:
                    raise
        raise MemoryError("open_contact_approval_required")

    def _encrypt_outbox(self, row, session):
        if row["envelope"] is not None:
            frozen = document(bytes(row["session"]), maximum=MAX_SESSION_BYTES)
            verify_envelope(bytes(row["envelope"]), **self._keys(frozen))
            return row
        keys = self._keys(session)
        envelope = create_envelope(bytes(row["body"]), signer=self.identity,
            sender_encryption_key=self.encryption.public_descriptor(),
            recipient_signing_key=keys["recipient_signing_key"],
            recipient_encryption_key=keys["recipient_encryption_key"],
            message_id=row["message_id"], object_key=secrets.token_hex(32),
            created_at=row["created_at"])
        grant = session["decision"]["payload"]["grant"]["payload"]
        if len(canonical_bytes(envelope)) > grant["resource_lease"]["payload"]["max_bytes"]:
            raise MemoryError("open_delivery_approval_bytes_insufficient")
        return self._freeze_outbox(row["request_id"], envelope, session)

    def _inbox(self, message_id):
        with self.participant.state.db() as db:
            row = db.execute("SELECT * FROM open_delivery_inbox WHERE message_id=?", (message_id,)).fetchone()
        return dict(row) if row is not None else None

    def _stage_inbox(self, *, message_id, sender_key_id, envelope, body, session):
        raw = canonical_bytes(document(envelope, maximum=MAX_ENVELOPE_BYTES))
        digest = hashlib.sha256(raw).hexdigest()
        content = validate_content(body)
        if content["kind"] not in {"message", "memory_transfer"}:
            raise MemoryError("open_delivery_invalid_content_kind")
        proof = canonical_bytes(document(session, maximum=MAX_INBOX_SESSION_BYTES))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT * FROM open_delivery_inbox WHERE message_id=?", (message_id,)).fetchone()
            if prior is not None:
                if prior["envelope_sha256"] != digest or prior["sender"] != sender_key_id or bytes(prior["body"]) != body:
                    raise MemoryError("network_inbox_identity_conflict")
                return dict(prior)
            count, size = self._local_size(db, "open_delivery_inbox")
            if count >= MAX_INBOX_RECORDS or size + len(raw) + len(body) + len(proof) + 2 * MAX_RESULT_BYTES > MAX_LOCAL_BYTES:
                raise MemoryError("network_inbox_capacity")
            db.execute("INSERT INTO open_delivery_inbox(message_id,envelope_sha256,sender,envelope,body,session,phase,created_at) VALUES(?,?,?,?,?,?,'staged',?)",
                       (message_id, digest, sender_key_id, raw, body, proof, int(time.time())))
            return dict(db.execute("SELECT * FROM open_delivery_inbox WHERE message_id=?", (message_id,)).fetchone())

    def _finish_inbox(self, message_id):
        row = self._inbox(message_id)
        if row is None:
            raise MemoryError("network_message_not_found")
        if row["phase"] in {"saved", "rejected"}:
            return document(bytes(row["result"]), maximum=MAX_RESULT_BYTES)
        envelope_raw = bytes(row["envelope"])
        session = document(bytes(row["session"]), maximum=MAX_INBOX_SESSION_BYTES)
        if hashlib.sha256(envelope_raw).hexdigest() != row["envelope_sha256"]:
            raise MemoryError("network_inbox_identity_conflict")
        verify_storage_receipt(session["storage_receipt"], node=session["source_node"], intent=session["intent"])
        if self._keys(session)["recipient_signing_key"] != self.identity.public_descriptor():
            raise MemoryError("open_delivery_key_binding_mismatch")
        reopened = decrypt_envelope(envelope_raw, encryption_identity=self.encryption, **self._keys(session))
        if reopened != bytes(row["body"]):
            raise MemoryError("network_inbox_identity_conflict")
        content = validate_content(bytes(row["body"]))
        imported = None
        if content["kind"] == "memory_transfer":
            from memory_vault_sharing import _scan
            selected = unb64url(content["share"], maximum=MAX_CONTENT_SHARE_BYTES)
            with tempfile.TemporaryDirectory(prefix="open-received-", dir=self.directory) as temporary:
                source = Path(temporary) / "share.ndjson"
                atomic_write(source, selected, replace=False)
                try:
                    _scan(source, time.monotonic() + 10)
                except MemoryError as exc:
                    if exc.retryable or exc.code in {"share_integer_index_unavailable", "share_source_changed"}:
                        raise
                    return self._reject_inbox(message_id, "network_invalid_content_share")
                # The immutable body is already durable. If the process stops
                # after Vault commit, its existing share transfer receipt makes
                # a repeat import idempotent before the inbox phase completes.
                imported = NetworkClient._import_received_share(self, source)
        elif content["kind"] != "message":
            raise MemoryError("open_delivery_invalid_content_kind")
        text = content_text(content)
        preview = _text_preview(text)
        result = {"message_id": message_id, "sender_key_id": row["sender"],
                  "text": preview, "text_partial": preview != text,
                  "text_memory_id": None, "content_kind": content["kind"],
                  "share": None if imported is None else {"state": imported["state"],
                      "records_added": imported["records_added"], "admission": imported.get("admission")},
                  "state": "validated_saved", "understood": False}
        encoded = canonical_bytes(document(result, maximum=MAX_RESULT_BYTES))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT phase,result,envelope_sha256 FROM open_delivery_inbox WHERE message_id=?", (message_id,)).fetchone()
            if prior is None or prior["envelope_sha256"] != row["envelope_sha256"]:
                raise MemoryError("network_inbox_identity_conflict")
            if prior["phase"] == "saved":
                return document(bytes(prior["result"]), maximum=MAX_RESULT_BYTES)
            db.execute("UPDATE open_delivery_inbox SET phase='saved',result=? WHERE message_id=?", (encoded, message_id))
        return result

    def _reject_inbox(self, message_id, code):
        result = {"message_id": message_id, "state": "rejected", "code": code}
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT phase,result FROM open_delivery_inbox WHERE message_id=?", (message_id,)).fetchone()
            if prior is None:
                raise MemoryError("network_message_not_found")
            if prior["phase"] in {"saved", "rejected"}:
                return document(bytes(prior["result"]), maximum=MAX_RESULT_BYTES)
            db.execute("UPDATE open_delivery_inbox SET phase='rejected',result=? WHERE message_id=?",
                       (canonical_bytes(result), message_id))
        return result

    def _saved_receipt(self, message_id):
        row = self._inbox(message_id)
        if row is None or row["phase"] != "saved":
            raise MemoryError("open_delivery_not_saved")
        if row["receipt"] is not None:
            return document(bytes(row["receipt"]), maximum=4096)
        receipt = issue_recipient_receipt(self.identity, message_id=message_id,
            envelope_ref=envelope_ref(bytes(row["envelope"])), sender_key_id=row["sender"])
        encoded = canonical_bytes(document(receipt, maximum=4096))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT phase,receipt FROM open_delivery_inbox WHERE message_id=?", (message_id,)).fetchone()
            if prior is None or prior["phase"] != "saved":
                raise MemoryError("open_delivery_not_saved")
            if prior["receipt"] is not None:
                return document(bytes(prior["receipt"]), maximum=4096)
            db.execute("UPDATE open_delivery_inbox SET receipt=? WHERE message_id=?", (encoded, message_id))
        return receipt

    async def _send_receipt(self, message_id, budget, node=None):
        row = self._inbox(message_id)
        if row is None or row["phase"] != "saved":
            raise MemoryError("open_delivery_not_saved")
        if row["receipt_sent"]:
            return
        receipt = self._saved_receipt(message_id)
        verify_recipient_receipt(receipt, recipient_signing_key=self.identity.public_descriptor(),
            sender_key_id=row["sender"], message_id=message_id,
            envelope_ref=envelope_ref(bytes(row["envelope"])))
        if node is None:
            session = document(bytes(row["session"]), maximum=MAX_INBOX_SESSION_BYTES)
            route_budget = budget.routing()
            try:
                node = await self.contact._session_node({"node": session["source_node"]}, route_budget)
            finally:
                budget.merge_routing(route_budget)
        response = await self.call(node, "receipt.put", {"message_id": message_id, "receipt": receipt}, budget)
        object_fields(response, {"state", "receipt_sha256"})
        if response["state"] != "receipt_stored" or response["receipt_sha256"] != hashlib.sha256(canonical_bytes(receipt)).hexdigest():
            raise MemoryError("open_delivery_receipt_mismatch")
        with self.participant.state.db() as db:
            db.execute("UPDATE open_delivery_inbox SET receipt_sent=1 WHERE message_id=? AND receipt=?",
                       (message_id, canonical_bytes(receipt)))

    @staticmethod
    def _cursor_key(session):
        lease = session["decision"]["payload"]["grant"]["payload"]["resource_lease"]["payload"]
        return "cursor_" + hashlib.sha256(canonical_bytes([
            lease["node_key_id"], lease["storage_epoch"], lease["lease_id"],
        ])).hexdigest()

    def _cursor(self, key):
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT body FROM open_delivery_client_state WHERE key=?", (key,)).fetchone()
            if row is None:
                if db.execute("SELECT count(*) FROM open_delivery_client_state").fetchone()[0] >= 4097:
                    raise MemoryError("open_delivery_cursor_capacity")
                db.execute("INSERT INTO open_delivery_client_state VALUES(?,?)", (key, canonical_bytes({"after_sequence": 0})))
                return 0
            return integer(document(bytes(row[0]), maximum=256)["after_sequence"])

    def _advance_cursor(self, key, sequence):
        integer(sequence, minimum=1)
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT body FROM open_delivery_client_state WHERE key=?", (key,)).fetchone()
            if row is None or document(bytes(row[0]), maximum=256)["after_sequence"] < sequence:
                db.execute("INSERT OR REPLACE INTO open_delivery_client_state VALUES(?,?)",
                           (key, canonical_bytes({"after_sequence": sequence})))

    async def _receive_entry(self, session, entry, budget):
        object_fields(entry, {"message_id", "envelope_ref", "sequence"})
        opaque(entry["message_id"])
        ref = immutable_ref(entry["envelope_ref"])
        if ref["namespace"] != "object":
            raise MemoryError("open_delivery_envelope_mismatch")
        sequence = integer(entry["sequence"], minimum=1)
        prior = self._inbox(entry["message_id"])
        if prior is not None:
            if prior["envelope_sha256"] != ref["raw_sha256"]:
                raise MemoryError("network_inbox_identity_conflict")
            already_saved = prior["phase"] in {"saved", "rejected"}
            return self._finish_inbox(entry["message_id"]), not already_saved
        node = session["node"]
        lease_id = session["decision"]["payload"]["grant"]["payload"]["resource_lease"]["payload"]["lease_id"]
        intent = reader_intent("read", lease_id=lease_id, caller_key_id=self.identity.key_id, message_id=entry["message_id"])
        prepared = await self.call(node, "read.prepare", {"lease_id": lease_id, "message_id": entry["message_id"]}, budget)
        challenge = prepared["challenge"]
        answer = self._answer(challenge, intent=intent, node=node)
        handle = await self.call(node, "read.start", {"lease_id": lease_id,
            "message_id": entry["message_id"], "challenge": challenge, "answer": answer}, budget)
        self._handle(handle, ref)
        original = handle["intent"]
        authority = original["payload"]["authority"]
        if any(canonical_bytes(authority.get(name)) != canonical_bytes(session[name])
               for name in ("request", "policy", "lease", "decision")):
            raise MemoryError("open_delivery_approval_mismatch")
        stored = verify_storage_receipt(handle["storage_receipt"], node=handle["source_node"], intent=original)
        if (stored["message_id"] != entry["message_id"] or stored["envelope_ref"] != ref
                or stored["sequence"] != sequence or stored["stored_at"] > int(time.time()) + 30):
            raise MemoryError("open_delivery_receipt_mismatch")
        frozen = await self._download(node, handle, ref, budget)
        body = decrypt_envelope(frozen, encryption_identity=self.encryption, **self._keys(session))
        self._stage_inbox(message_id=entry["message_id"],
            sender_key_id=session["request"]["payload"]["signing_key"]["key_id"],
            envelope=frozen, body=body, session={"intent": original,
                "storage_receipt": handle["storage_receipt"], "source_node": handle["source_node"]})
        return self._finish_inbox(entry["message_id"]), True

    async def receive(self, limit=4):
        if type(limit) is not int or not 1 <= limit <= 4:
            raise MemoryError("network_invalid_receive_limit")
        budget = _DeliveryBudget()
        messages, errors = [], []
        with self.participant.state.db() as db:
            pending = db.execute("SELECT message_id,phase FROM open_delivery_inbox WHERE phase='staged' OR (phase='saved' AND receipt_sent=0) ORDER BY created_at,message_id LIMIT 4").fetchall()
        for pending_row in pending:
            if len(messages) >= limit:
                break
            message_id = pending_row["message_id"]
            try:
                result = self._finish_inbox(message_id)
                if pending_row["phase"] == "staged":
                    messages.append(result)
                if result["state"] == "validated_saved":
                    await self._send_receipt(message_id, budget)
            except MemoryError as exc:
                errors.append({"message_id": message_id, "code": exc.code, "retryable": exc.retryable})
        for candidate in self._contact_sessions(outgoing=False):
            if len(messages) >= limit:
                break
            try:
                session = await self._checked_session(candidate, budget)
                node = session["node"]
                lease_id = session["decision"]["payload"]["grant"]["payload"]["resource_lease"]["payload"]["lease_id"]
                cursor_key = self._cursor_key(session)
                after = self._cursor(cursor_key)
                intent = reader_intent("list", lease_id=lease_id, caller_key_id=self.identity.key_id)
                prepared = await self.call(node, "list.prepare", {"lease_id": lease_id}, budget)
                challenge = prepared["challenge"]
                answer = self._answer(challenge, intent=intent, node=node)
                listing = await self.call(node, "list", {"lease_id": lease_id,
                    "challenge": challenge, "answer": answer, "after_sequence": after,
                    "limit": limit - len(messages)}, budget)
                object_fields(listing, {"state", "messages", "next_sequence", "has_more"})
                if (listing["state"] != "observed" or not isinstance(listing["messages"], list)
                        or len(listing["messages"]) > limit - len(messages) or type(listing["has_more"]) is not bool):
                    raise MemoryError("open_delivery_invalid_response")
                for entry in listing["messages"]:
                    if integer(entry["sequence"], minimum=1) <= after:
                        raise MemoryError("open_delivery_sequence_mismatch")
                    result, fresh = await self._receive_entry(session, entry, budget)
                    after = entry["sequence"]
                    self._advance_cursor(cursor_key, after)
                    if fresh:
                        messages.append(result)
                    if result["state"] == "validated_saved":
                        try:
                            await self._send_receipt(entry["message_id"], budget, node)
                        except MemoryError as exc:
                            errors.append({"message_id": entry["message_id"], "code": exc.code, "retryable": exc.retryable})
                if integer(listing["next_sequence"]) != after:
                    raise MemoryError("open_delivery_sequence_mismatch")
            except MemoryError as exc:
                errors.append({"code": exc.code, "retryable": exc.retryable})
                if len(errors) >= 4:
                    break
        return {"messages": messages, "errors": errors[:4], "network_accessed": budget.requests > 0}

    def read_message(self, message_id, offset=0):
        opaque(message_id)
        if type(offset) is not int or offset < 0:
            raise MemoryError("network_invalid_message_offset")
        row = self._inbox(message_id)
        if row is None or row["phase"] != "saved":
            raise MemoryError("network_message_not_found")
        text = content_text(validate_content(bytes(row["body"])))
        if offset > len(text):
            raise MemoryError("network_invalid_message_offset")
        fragment = text[offset:].encode("utf-8")[:1024].decode("utf-8", errors="ignore")
        end = offset + len(fragment)
        return {**document(bytes(row["result"]), maximum=MAX_RESULT_BYTES), "text": fragment,
                "text_partial": offset > 0 or end < len(text), "offset": offset,
                "next_offset": end if end < len(text) else None,
                "total_characters": len(text), "network_accessed": False}
