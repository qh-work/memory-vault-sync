"""Finite ciphertext storage on the existing open participant database.

Stored messages and recipient-saved receipts are different durable events.
An upload handle binds a verified subject, concrete local lease and immutable
envelope; it is never a bearer credential or a grant at another node.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, unb64url
from memory_vault_open_contact import verify_lease
from memory_vault_open_delivery import (
    CHUNK_BYTES, MAX_ENVELOPE_BYTES, original_document, raw_sha256,
    verify_rpc, verify_upload_intent, verify_envelope, issue_challenge,
    reader_intent, issue_storage_receipt, verify_recipient_receipt,
)


class DeliveryState:
    def __init__(self, db, identity, node, *, enabled=False,
                 maximum_bytes=64 * 1024 * 1024, maximum_items=512,
                 maximum_handles=64, maximum_challenges=128):
        if type(enabled) is not bool:
            raise MemoryError("open_delivery_invalid_policy")
        for value, maximum in ((maximum_bytes, 1024 * 1024 * 1024),
                               (maximum_items, 4096), (maximum_handles, 256),
                               (maximum_challenges, 512)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise MemoryError("open_delivery_invalid_policy")
        self.db, self.identity, self.node, self.enabled = db, identity, node, enabled
        self.maximum_bytes, self.maximum_items = maximum_bytes, maximum_items
        self.maximum_handles, self.maximum_challenges = maximum_handles, maximum_challenges

    def _fail(self, name):
        raise MemoryError("open_delivery_" + name)

    def initialize(self):
        statements = [
            """CREATE TABLE IF NOT EXISTS open_delivery_handles(
                handle_id TEXT PRIMARY KEY,subject TEXT NOT NULL,purpose TEXT NOT NULL,
                operation_id TEXT NOT NULL,message_id TEXT NOT NULL,lease_id TEXT NOT NULL,
                intent BLOB NOT NULL,ref BLOB NOT NULL,size INTEGER NOT NULL,
                prefix INTEGER NOT NULL,expires_at INTEGER NOT NULL,state TEXT NOT NULL,
                UNIQUE(subject,purpose,operation_id))""",
            """CREATE TABLE IF NOT EXISTS open_delivery_chunks(
                handle_id TEXT NOT NULL,offset INTEGER NOT NULL,body BLOB NOT NULL,
                digest TEXT NOT NULL,PRIMARY KEY(handle_id,offset))""",
            """CREATE TABLE IF NOT EXISTS open_delivery_messages(
                sequence INTEGER PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,
                message_id TEXT NOT NULL,lease_id TEXT NOT NULL,intent BLOB NOT NULL,
                ref BLOB NOT NULL,envelope BLOB NOT NULL,storage_receipt BLOB NOT NULL,
                source_node BLOB NOT NULL,stored_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                UNIQUE(sender,message_id))""",
            """CREATE TABLE IF NOT EXISTS open_delivery_receipts(
                sender TEXT NOT NULL,message_id TEXT NOT NULL,receipt BLOB NOT NULL,
                PRIMARY KEY(sender,message_id))""",
            """CREATE TABLE IF NOT EXISTS open_delivery_possessions(
                challenge_id TEXT PRIMARY KEY,subject TEXT NOT NULL,intent_sha256 TEXT NOT NULL,
                challenge BLOB NOT NULL,answer_sha256 TEXT NOT NULL,expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL)""",
            "CREATE INDEX IF NOT EXISTS open_delivery_mailbox ON open_delivery_messages(recipient,lease_id,sequence)",
            "CREATE INDEX IF NOT EXISTS open_delivery_handle_expiry ON open_delivery_handles(expires_at,state)",
            "CREATE INDEX IF NOT EXISTS open_delivery_message_expiry ON open_delivery_messages(retain_until)",
            "CREATE TABLE IF NOT EXISTS open_delivery_counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL)",
        ]
        for statement in statements:
            self.db.execute(statement)
        self.db.execute("INSERT OR IGNORE INTO open_delivery_counters SELECT 'sequence',coalesce(max(sequence),0) FROM open_delivery_messages")
        self.db.commit()

    def collect_expired(self, *, limit=16):
        """Release expired reservations in bounded transactions, keeping live data.

        A separate sequence counter survives message expiry so a receiver's
        durable cursor can never skip newly stored messages after collection.
        Recipient receipts share the original message's finite retention period.
        """
        if type(limit) is not int or not 1 <= limit <= 128:
            self._fail("invalid_limit")
        now = int(time.time())
        def collect():
            handles = self.db.execute("SELECT handle_id FROM open_delivery_handles WHERE expires_at<=? ORDER BY expires_at LIMIT ?", (now, limit)).fetchall()
            for row in handles:
                self.db.execute("DELETE FROM open_delivery_chunks WHERE handle_id=?", (row[0],))
                self.db.execute("DELETE FROM open_delivery_handles WHERE handle_id=?", (row[0],))
            messages = self.db.execute("SELECT sender,message_id FROM open_delivery_messages WHERE retain_until<=? ORDER BY retain_until LIMIT ?", (now, limit)).fetchall()
            for row in messages:
                self.db.execute("DELETE FROM open_delivery_receipts WHERE sender=? AND message_id=?", (row[0], row[1]))
                self.db.execute("DELETE FROM open_delivery_messages WHERE sender=? AND message_id=?", (row[0], row[1]))
            challenges = self.db.execute("SELECT challenge_id FROM open_delivery_possessions WHERE expires_at<=? LIMIT ?", (now, limit)).fetchall()
            for row in challenges:
                self.db.execute("DELETE FROM open_delivery_possessions WHERE challenge_id=?", (row[0],))
            return {"handles": len(handles), "messages": len(messages), "challenges": len(challenges)}
        return self._transaction(collect)

    def _transaction(self, operation):
        if self.db.in_transaction:
            self._fail("storage_transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            result = operation()
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise

    def _lease(self, lease_id, now):
        row = self.db.execute("SELECT * FROM open_contact_resource_leases WHERE lease_id=?", (lease_id,)).fetchone()
        if row is None or row["purpose"] != "delivery" or row["status"] != "active" or row["expires_at"] <= now:
            self._fail("lease_unavailable")
        return row

    def _authority(self, intent, now):
        payload = verify_upload_intent(intent, node=self.node, now=now)
        self._authority_current(payload, now)
        return payload

    def _authority_current(self, payload, now):
        authority = payload["authority"]
        request = authority["request"]["payload"]
        grant = authority["decision"]["payload"]["grant"]["payload"]
        signed_lease = grant["resource_lease"]
        lease = self._lease(signed_lease["payload"]["lease_id"], now)
        if (bytes(lease["record"]) != canonical_bytes(signed_lease)
                or lease["grant_request"] != raw_sha256(authority["request"])
                or lease["owner"] != request["recipient_key_id"]
                or payload["expires_at"] <= now):
            self._fail("authority_mismatch")
        known = self.db.execute("SELECT state,decision FROM open_contact_requests WHERE sender=? AND request_id=?",
            (request["signing_key"]["key_id"], request["request_id"])).fetchone()
        # CONTACT stores the request lifecycle as pending/decided. Approval
        # belongs to the signed decision verified by verify_upload_intent;
        # the persisted decision must still be that exact authorized document.
        if (known is None or known["state"] != "decided" or known["decision"] is None
                or bytes(known["decision"]) != canonical_bytes(authority["decision"])):
            self._fail("not_authorized")
        policy = self.db.execute("SELECT status,digest FROM open_contact_policies WHERE owner=?", (lease["owner"],)).fetchone()
        if policy is None or policy["status"] != "active" or policy["digest"] != raw_sha256(authority["policy"]):
            self._fail("revoked")
        return lease

    def _reader(self, lease_id, subject, now):
        lease = self._lease(lease_id, now)
        if lease["owner"] != subject:
            self._fail("not_authorized")
        return document(bytes(lease["record"]))["payload"]["owner_encryption_key"]

    def _challenge(self, intent, subject, encryption_key, now):
        challenge, answer_digest = issue_challenge(self.identity, node=self.node, intent=intent,
            subject_key_id=subject, encryption_key=encryption_key, now=now)
        context = challenge["payload"]["context"]
        def reserve():
            self.db.execute("DELETE FROM open_delivery_possessions WHERE expires_at<=?", (now,))
            if self.db.execute("SELECT count(*) FROM open_delivery_possessions").fetchone()[0] >= self.maximum_challenges:
                self._fail("capacity")
            self.db.execute("INSERT INTO open_delivery_possessions VALUES(?,?,?,?,?,?,0)",
                (context["challenge_id"], subject, raw_sha256(intent), canonical_bytes(challenge), answer_digest, context["expires_at"]))
        self._transaction(reserve)
        return {"challenge": challenge}

    def _possession(self, subject, intent, challenge, answer, now):
        context = challenge.get("payload", {}).get("context", {})
        identifier = context.get("challenge_id")
        row = self.db.execute("SELECT * FROM open_delivery_possessions WHERE challenge_id=?", (identifier,)).fetchone()
        nonce = unb64url(answer, maximum=32, size=32)
        if (row is None or row["expires_at"] <= now or row["used"] or row["subject"] != subject
                or row["intent_sha256"] != raw_sha256(intent)
                or bytes(row["challenge"]) != canonical_bytes(challenge)
                or not hmac.compare_digest(row["answer_sha256"], hashlib.sha256(nonce).hexdigest())):
            self._fail("invalid_challenge")
        self.db.execute("UPDATE open_delivery_possessions SET used=1 WHERE challenge_id=?", (identifier,))

    def _handle(self, handle_id, subject, now, *, purpose=None):
        row = self.db.execute("SELECT * FROM open_delivery_handles WHERE handle_id=?", (handle_id,)).fetchone()
        if row is None or row["subject"] != subject or row["expires_at"] <= now or purpose is not None and row["purpose"] != purpose:
            self._fail("handle_unavailable")
        return row

    @staticmethod
    def _handle_result(row):
        return {"state": row["state"], "handle_id": row["handle_id"], "envelope_ref": document(bytes(row["ref"])),
                "durable_prefix": row["prefix"], "expires_at": row["expires_at"], "chunk_size": CHUNK_BYTES}

    def _message(self, message_id, *, recipient=None, sender=None):
        column, identity = ("recipient", recipient) if recipient is not None else ("sender", sender)
        rows = self.db.execute("SELECT * FROM open_delivery_messages WHERE message_id=? AND " + column + "=? LIMIT 2",
            (message_id, identity)).fetchall()
        if len(rows) != 1:
            self._fail("message_unavailable")
        return rows[0]

    def _start_upload(self, body, subject, now):
        intent = body["intent"]
        payload = self._authority(intent, now)
        if payload["signing_key"]["key_id"] != subject:
            self._fail("not_authorized")
        ref = payload["envelope_ref"]
        lease_id = payload["authority"]["decision"]["payload"]["grant"]["payload"]["resource_lease"]["payload"]["lease_id"]
        def allocate():
            lease = self._authority_current(payload, int(time.time()))
            self._possession(subject, intent, body["challenge"], body["answer"], int(time.time()))
            old = self.db.execute("SELECT * FROM open_delivery_handles WHERE subject=? AND purpose='upload' AND operation_id=?",
                (subject, payload["operation_id"])).fetchone()
            if old is not None:
                if bytes(old["intent"]) != canonical_bytes(intent): self._fail("operation_conflict")
                if old["expires_at"] <= now: self._fail("handle_expired")
                return self._handle_result(old)
            # Reserve the complete envelope before receiving its first byte.
            used = self.db.execute("SELECT coalesce(sum(length(envelope)),0),count(*) FROM open_delivery_messages").fetchone()
            staged = self.db.execute("SELECT coalesce(sum(size),0),count(*) FROM open_delivery_handles WHERE purpose='upload' AND state='uploading'").fetchone()
            if used[0] + staged[0] + ref["size"] > self.maximum_bytes or used[1] + staged[1] >= self.maximum_items:
                self._fail("capacity")
            charged = self.db.execute("SELECT coalesce(sum(length(envelope)),0),count(*) FROM open_delivery_messages WHERE lease_id=?", (lease_id,)).fetchone()
            pending = self.db.execute("SELECT coalesce(sum(size),0),count(*) FROM open_delivery_handles WHERE lease_id=? AND purpose='upload' AND state='uploading'", (lease_id,)).fetchone()
            if charged[0] + pending[0] + ref["size"] > lease["max_bytes"] or charged[1] + pending[1] >= lease["max_items"]:
                self._fail("quota")
            self._handle_capacity()
            handle = "blob_" + secrets.token_hex(32)
            self.db.execute("INSERT INTO open_delivery_handles VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (handle, subject, "upload", payload["operation_id"], payload["message_id"], lease_id,
                 canonical_bytes(intent), canonical_bytes(ref), ref["size"], 0, min(now + 120, payload["expires_at"]), "uploading"))
            return self._handle_result(self._handle(handle, subject, now))
        return self._transaction(allocate)

    def _handle_capacity(self):
        if self.db.execute("SELECT count(*) FROM open_delivery_handles WHERE state!='committed'").fetchone()[0] >= self.maximum_handles:
            self._fail("capacity")

    def _commit(self, handle_id, subject, now):
        handle = self._handle(handle_id, subject, now, purpose="upload")
        intent = document(bytes(handle["intent"]), maximum=49152)
        payload = intent["payload"]
        prior = self.db.execute("SELECT * FROM open_delivery_messages WHERE sender=? AND message_id=?", (subject, payload["message_id"])).fetchone()
        if prior is not None:
            if bytes(prior["intent"]) != bytes(handle["intent"]): self._fail("message_conflict")
            return {"state": "storage_accepted", "storage_receipt": document(bytes(prior["storage_receipt"])),
                    "source_node": document(bytes(prior["source_node"]))}
        payload = self._authority(intent, now)
        chunks = self.db.execute("SELECT offset,body FROM open_delivery_chunks WHERE handle_id=? ORDER BY offset LIMIT 25", (handle_id,)).fetchall()
        raw = b"".join(bytes(row["body"]) for row in chunks)
        ref = payload["envelope_ref"]
        if (handle["prefix"] != ref["size"] or len(raw) != ref["size"]
                or hashlib.sha256(raw).hexdigest() != ref["raw_sha256"]
                or any(row["offset"] != i * CHUNK_BYTES for i, row in enumerate(chunks))):
            self._fail("incomplete")
        authority = payload["authority"]
        sender, recipient = authority["request"]["payload"], authority["policy"]["payload"]
        envelope = verify_envelope(raw, sender_signing_key=sender["signing_key"], sender_encryption_key=sender["encryption_key"],
            recipient_signing_key=recipient["signing_key"], recipient_encryption_key=recipient["encryption_key"], now=now)
        if envelope["context"]["message_id"] != payload["message_id"] or envelope["context"]["object_ref"]["key"] != ref["key"]:
            self._fail("envelope_mismatch")
        # Sign outside the writer transaction. A concurrently taken sequence
        # makes this attempt retry; no signed result escapes before commit.
        for _ in range(8):
            sequence = self.db.execute("SELECT value+1 FROM open_delivery_counters WHERE name='sequence'").fetchone()[0]
            lease = self._authority_current(payload, now)
            receipt = issue_storage_receipt(self.identity, node=self.node, intent=intent,
                sequence=sequence, stored_at=now, retain_until=lease["expires_at"])
            def publish():
                fresh = self._handle(handle_id, subject, int(time.time()), purpose="upload")
                self._authority_current(payload, int(time.time()))
                if fresh["prefix"] != len(raw) or fresh["state"] != "uploading": self._fail("operation_conflict")
                if self.db.execute("SELECT value+1 FROM open_delivery_counters WHERE name='sequence'").fetchone()[0] != sequence:
                    return False
                self.db.execute("INSERT INTO open_delivery_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (sequence, subject, recipient["signing_key"]["key_id"], payload["message_id"], handle["lease_id"],
                     canonical_bytes(intent), canonical_bytes(ref), raw, canonical_bytes(receipt), canonical_bytes(self.node), now, lease["expires_at"]))
                self.db.execute("UPDATE open_delivery_counters SET value=? WHERE name='sequence'", (sequence,))
                self.db.execute("UPDATE open_delivery_handles SET state='committed',expires_at=? WHERE handle_id=?", (lease["expires_at"], handle_id))
                self.db.execute("DELETE FROM open_delivery_chunks WHERE handle_id=?", (handle_id,))
                return True
            if self._transaction(publish):
                return {"state": "storage_accepted", "storage_receipt": receipt, "source_node": self.node}
        self._fail("busy")

    def handle(self, request):
        if not self.enabled: self._fail("closed")
        now = int(time.time())
        rpc = verify_rpc(request, node=self.node, now=now)
        action, body, subject = rpc["action"], rpc["body"], rpc["signing_key"]["key_id"]
        self.collect_expired(limit=16)
        if action == "node.info":
            return {"state": "available", "maximum_envelope_bytes": MAX_ENVELOPE_BYTES, "chunk_size": CHUNK_BYTES}
        if action == "prepare":
            intent = self._authority(body["intent"], now)
            if intent["signing_key"]["key_id"] != subject: self._fail("not_authorized")
            return self._challenge(body["intent"], subject, intent["authority"]["request"]["payload"]["encryption_key"], now)
        if action == "start": return self._start_upload(body, subject, now)
        if action == "commit": return self._commit(body["handle_id"], subject, now)
        if action == "status": return self._handle_result(self._handle(body["handle_id"], subject, now))
        if action == "stored.get":
            row = self.db.execute("SELECT * FROM open_delivery_messages WHERE sender=? AND message_id=? AND retain_until>?", (subject, body["message_id"], now)).fetchone()
            if row is None:
                return {"state": "absent"}
            if bytes(row["ref"]) != canonical_bytes(body["envelope_ref"]):
                self._fail("message_conflict")
            return {"state": "storage_accepted", "storage_receipt": document(bytes(row["storage_receipt"])),
                    "source_node": document(bytes(row["source_node"])),
                    "intent": document(bytes(row["intent"]), maximum=49152)}
        if action in {"list.prepare", "read.prepare"}:
            encryption = self._reader(body["lease_id"], subject, now)
            purpose = action.split(".")[0]
            if purpose == "read":
                msg = self._message(body["message_id"], recipient=subject)
                if msg["lease_id"] != body["lease_id"]: self._fail("not_authorized")
            intent = reader_intent(purpose, lease_id=body["lease_id"], caller_key_id=subject, message_id=body.get("message_id"))
            return self._challenge(intent, subject, encryption, now)
        if action in {"list", "read.start"}:
            purpose = "list" if action == "list" else "read"
            intent = reader_intent(purpose, lease_id=body["lease_id"], caller_key_id=subject, message_id=body.get("message_id"))
            def read():
                self._reader(body["lease_id"], subject, int(time.time()))
                self._possession(subject, intent, body["challenge"], body["answer"], int(time.time()))
                if purpose == "list":
                    rows = self.db.execute("SELECT sequence,message_id,ref FROM open_delivery_messages WHERE recipient=? AND lease_id=? AND sequence>? AND retain_until>? ORDER BY sequence LIMIT ?",
                        (subject, body["lease_id"], body["after_sequence"], now, body["limit"] + 1)).fetchall()
                    items = [{"message_id": row["message_id"], "envelope_ref": document(bytes(row["ref"])), "sequence": row["sequence"]} for row in rows[:body["limit"]]]
                    return {"state": "observed", "messages": items, "next_sequence": items[-1]["sequence"] if items else body["after_sequence"], "has_more": len(rows) > body["limit"]}
                message = self._message(body["message_id"], recipient=subject)
                if message["lease_id"] != body["lease_id"] or message["retain_until"] <= now: self._fail("not_authorized")
                self._handle_capacity()
                handle_id = "blob_" + secrets.token_hex(32)
                ref = document(bytes(message["ref"]))
                self.db.execute("INSERT INTO open_delivery_handles VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (handle_id, subject, "read", handle_id, message["message_id"], message["lease_id"],
                     canonical_bytes(intent), message["ref"], ref["size"], 0, min(now + 120, message["retain_until"]), "reading"))
                result = self._handle_result(self._handle(handle_id, subject, now))
                result.update({"intent": document(bytes(message["intent"]), maximum=49152),
                    "storage_receipt": document(bytes(message["storage_receipt"])), "source_node": document(bytes(message["source_node"]))})
                return result
            return self._transaction(read)
        if action == "receipt.put":
            message = self._message(body["message_id"], recipient=subject)
            original = document(bytes(message["intent"]), maximum=49152)
            recipient = original["payload"]["authority"]["policy"]["payload"]["signing_key"]
            verify_recipient_receipt(body["receipt"], recipient_signing_key=recipient,
                sender_key_id=message["sender"], message_id=message["message_id"], envelope_ref=document(bytes(message["ref"])))
            encoded = canonical_bytes(body["receipt"])
            def save():
                self._reader(message["lease_id"], subject, int(time.time()))
                prior = self.db.execute("SELECT receipt FROM open_delivery_receipts WHERE sender=? AND message_id=?", (message["sender"], message["message_id"])).fetchone()
                if prior is not None and bytes(prior["receipt"]) != encoded: self._fail("receipt_conflict")
                self.db.execute("INSERT OR IGNORE INTO open_delivery_receipts VALUES(?,?,?)", (message["sender"], message["message_id"], encoded))
                return {"state": "receipt_stored", "receipt_sha256": hashlib.sha256(encoded).hexdigest()}
            return self._transaction(save)
        if action == "receipt.get":
            self._message(body["message_id"], sender=subject)
            row = self.db.execute("SELECT receipt FROM open_delivery_receipts WHERE sender=? AND message_id=?", (subject, body["message_id"])).fetchone()
            return {"state": "validated_saved" if row is not None else "pending", "receipt": document(bytes(row[0])) if row is not None else None}
        self._fail("unsupported_action")

    def handle_blob(self, request, chunk):
        from memory_vault_open_blob import verify_blob_request
        if not self.enabled: self._fail("closed")
        now = int(time.time())
        rpc = verify_blob_request(request, node=self.node, now=now)
        body, subject, action = rpc["body"], rpc["signing_key"]["key_id"], rpc["action"]
        handle = self._handle(body["handle_id"], subject, now,
            purpose="upload" if action == "upload.chunk" else "read")
        if document(bytes(handle["ref"])) != body["ref"]: self._fail("object_mismatch")
        if action == "download.chunk":
            if chunk: self._fail("invalid_frame")
            self._reader(handle["lease_id"], subject, now)
            message = self._message(handle["message_id"], recipient=subject)
            data = bytes(message["envelope"])[body["offset"]:body["offset"] + body["length"]]
            if len(data) != body["length"]: self._fail("incomplete")
            return {**body, "chunk_sha256": hashlib.sha256(data).hexdigest()}, data
        if len(chunk) != body["length"] or hashlib.sha256(chunk).hexdigest() != body["chunk_sha256"]:
            self._fail("chunk_mismatch")
        intent = document(bytes(handle["intent"]), maximum=49152)
        payload = self._authority(intent, now)
        def upload():
            fresh = self._handle(body["handle_id"], subject, int(time.time()), purpose="upload")
            self._authority_current(payload, int(time.time()))
            if fresh["state"] != "uploading": self._fail("operation_conflict")
            if body["offset"] < fresh["prefix"]:
                old = self.db.execute("SELECT body FROM open_delivery_chunks WHERE handle_id=? AND offset=?", (fresh["handle_id"], body["offset"])).fetchone()
                if old is None or bytes(old[0]) != chunk: self._fail("chunk_mismatch")
                return {**body, "durable_prefix": fresh["prefix"]}, b""
            if body["offset"] != fresh["prefix"]: self._fail("wrong_offset")
            self.db.execute("INSERT INTO open_delivery_chunks VALUES(?,?,?,?)", (fresh["handle_id"], body["offset"], chunk, body["chunk_sha256"]))
            prefix = body["offset"] + body["length"]
            self.db.execute("UPDATE open_delivery_handles SET prefix=? WHERE handle_id=?", (prefix, fresh["handle_id"]))
            return {**body, "durable_prefix": prefix}, b""
        return self._transaction(upload)
