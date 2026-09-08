"""Explicit first-contact client using the existing participant and state DB.

The local bounded records are transport control, never long-term Memory, trust,
or permission to run an agent. Each method requires an already-running caller.
"""
from __future__ import annotations

import asyncio
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, document_sha256, object_fields, opaque
from memory_vault_open_control import coordinate, issue_contact, verify_contact, verify_node
from memory_vault_open_routing import LookupBudget
from memory_vault_open_contact import (
    SLOT_BYTES, ContactError, sign_document, sign_rpc, solve_challenge,
    verify_decision, verify_policy, verify_response, verify_request, verify_rpc, limit,
)

CONNECT_SCHEMA = "memory-vault-open-contact-connect/v1"
LOCAL_RESERVATION = canonical_bytes({"state": "reserved_contact_control"})


class OpenContactClient:
    def __init__(self, participant, encryption):
        self.participant, self.encryption = participant, encryption
        self.identity = participant.identity
        with participant.state.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS open_contact_local(category TEXT NOT NULL,reference TEXT NOT NULL,body BLOB NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(category,reference))")
            db.execute("CREATE INDEX IF NOT EXISTS open_contact_local_expiry ON open_contact_local(expires_at)")

    def _save(self, category, reference, value, expires):
        raw = canonical_bytes(document(value, maximum=24576))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM open_contact_local WHERE rowid IN (SELECT rowid FROM open_contact_local WHERE expires_at<=? ORDER BY expires_at LIMIT 32)", (int(time.time()),))
                prior = db.execute("SELECT body FROM open_contact_local WHERE category=? AND reference=?", (category, reference)).fetchone()
                if prior is not None:
                    if bytes(prior[0]) == LOCAL_RESERVATION:
                        db.execute("UPDATE open_contact_local SET body=?,expires_at=? WHERE category=? AND reference=?", (raw, expires, category, reference))
                    elif bytes(prior[0]) != raw:
                        raise ContactError("contact_local_conflict")
                else:
                    if db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0] >= 128:
                        raise ContactError("contact_local_capacity", retryable=True)
                    db.execute("INSERT INTO open_contact_local VALUES(?,?,?,?)", (category, reference, raw, expires))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _reserve(self, entries, expires):
        """Reserve every local phase before any remote allocation or submission."""
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM open_contact_local WHERE rowid IN (SELECT rowid FROM open_contact_local WHERE expires_at<=? ORDER BY expires_at LIMIT 32)", (int(time.time()),))
                missing = [(category, reference) for category, reference in entries if db.execute(
                    "SELECT 1 FROM open_contact_local WHERE category=? AND reference=?", (category, reference)).fetchone() is None]
                if db.execute("SELECT count(*) FROM open_contact_local").fetchone()[0] + len(missing) > 128:
                    raise ContactError("contact_local_capacity", retryable=True)
                for category, reference in missing:
                    db.execute("INSERT INTO open_contact_local VALUES(?,?,?,?)", (category, reference, LOCAL_RESERVATION, expires))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _load(self, category, reference):
        opaque(reference)
        with self.participant.state.db() as db:
            row = db.execute("SELECT body,expires_at FROM open_contact_local WHERE category=? AND reference=?", (category, reference)).fetchone()
        if row is None or bytes(row[0]) == LOCAL_RESERVATION:
            raise ContactError("contact_local_missing")
        if row[1] <= int(time.time()):
            raise ContactError("contact_expired")
        return document(bytes(row[0]), maximum=24576)

    def _save_policy(self, reservation_ref, lease_id, value, expires):
        raw = canonical_bytes(document(value, maximum=24576))
        with self.participant.state.db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                old = db.execute("SELECT body FROM open_contact_local WHERE category='policy' AND reference=?", (lease_id,)).fetchone()
                if old is not None:
                    if bytes(old[0]) != raw:
                        raise ContactError("contact_local_conflict")
                    db.execute("DELETE FROM open_contact_local WHERE category='policy_pending' AND reference=? AND body=?", (reservation_ref, LOCAL_RESERVATION))
                else:
                    changed = db.execute("UPDATE open_contact_local SET category='policy',reference=?,body=?,expires_at=? WHERE category='policy_pending' AND reference=? AND body=?",
                        (lease_id, raw, expires, reservation_ref, LOCAL_RESERVATION)).rowcount
                    if changed != 1:
                        raise ContactError("contact_local_capacity", retryable=True)
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def _known_policy(self, allocation_ref):
        # At most 128 total live local records; no unbounded historical scan.
        with self.participant.state.db() as db:
            rows = db.execute("SELECT body FROM open_contact_local WHERE category='policy' AND expires_at>? LIMIT 128", (int(time.time()),)).fetchall()
        for row in rows:
            value = document(bytes(row[0]), maximum=24576)
            if value.get("allocation_ref") == allocation_ref:
                return value
        return None

    async def call(self, node, action, body, budget=None):
        budget = budget or LookupBudget()
        budget.check()
        self.participant._accept(node)
        request = sign_rpc(self.identity, node=node, action=action, body=body)
        verify_rpc(request, node=node)
        budget.charge_request_bytes(len(canonical_bytes(request)))
        budget.charge_request()
        reply = await asyncio.to_thread(self.participant.transport.request, node["payload"]["base_url"], request, deadline=budget.deadline)
        budget.charge_bytes(reply.wire_bytes)
        checked = verify_response(reply.response, request=request, node=node)
        self.participant._accept(node)
        if "error" in checked["body"]:
            error = checked["body"]["error"]
            raise ContactError(error["code"], retryable=error["retryable"])
        self.participant.table.learn_verified(node, reply.observed_address)
        return checked["body"]

    async def _resolve(self, endpoint, budget):
        route = await self.participant._lookup(coordinate(endpoint["node_key_id"]), "general", budget)
        candidates = route["candidates"]
        if self.participant.descriptor:
            candidates = candidates + [self.participant.descriptor]
        for node in candidates:
            raw = verify_node(node)
            if (raw["signing_key"]["key_id"] == endpoint["node_key_id"] and raw["base_url"] == endpoint["base_url"]
                    and raw["storage_epoch"] == endpoint["storage_epoch"]):
                return node
        raise ContactError("contact_resource_unresolved", retryable=True)

    async def _session_node(self, session, budget):
        old = session["node"]["payload"]
        # Endpoint signatures may need refreshing while the logical request is
        # still live. Resolve through signed routing, retaining the epoch/URL.
        try:
            verify_node(session["node"])
            self.participant._accept(session["node"])
            return session["node"]
        except MemoryError:
            return await self._resolve({"node_key_id": old["signing_key"]["key_id"], "base_url": old["base_url"], "storage_epoch": old["storage_epoch"]}, budget)

    async def enable(self, node, *, allocation_id, max_pending=4, lease_seconds=600, revision=1):
        """B explicitly acquires resource permission and signs opt-in before publishing."""
        limit(max_pending, 32)
        limit(lease_seconds, 86400)
        limit(revision, 9007199254740991)
        opaque(allocation_id)
        budget = LookupBudget()
        allocation = {"encryption_key": self.encryption.public_descriptor(),
            "purpose": "knock", "max_items": max_pending, "max_bytes": max_pending * SLOT_BYTES,
            "lease_seconds": lease_seconds, "allocation_id": allocation_id}
        sign_rpc(self.identity, node=node, action="lease", body=allocation)
        reservation_ref = document_sha256({"node_key_id": node["payload"]["signing_key"]["key_id"],
            "storage_epoch": node["payload"]["storage_epoch"], "allocation_id": allocation_id})
        session = self._known_policy(reservation_ref)
        if session is not None:
            if session["allocation"] != allocation or session["policy"]["payload"]["revision"] != revision:
                raise ContactError("contact_local_conflict")
            lease, policy = session["lease"], session["policy"]
            verify_policy(policy, lease=lease, node=node)
        else:
            self._reserve([("policy_pending", reservation_ref)], int(time.time()) + lease_seconds + 60)
            lease = (await self.call(node, "lease", allocation, budget))["lease"]
            raw = lease["payload"]
            policy = sign_document(self.identity, "contact.policy", issued_at=raw["issued_at"], expires_at=raw["expires_at"],
                node_key_id=raw["node_key_id"], storage_epoch=raw["storage_epoch"], lease_id=raw["lease_id"],
                lease_sha256=document_sha256(lease), resource_id=raw["resource_id"], encryption_key=self.encryption.public_descriptor(),
                revision=revision, status="active", max_pending=max_pending)
            session = {"node": node, "lease": lease, "policy": policy, "allocation_ref": reservation_ref, "allocation": allocation}
            self._save_policy(reservation_ref, raw["lease_id"], session, raw["expires_at"])
        raw = lease["payload"]
        await self.call(node, "policy.put", {"lease": lease, "policy": policy}, budget)
        now = raw["issued_at"]
        contact = issue_contact(self.identity, encryption_key=self.encryption.public_descriptor(), revision=revision,
            allow_discovery=True, endpoints=[{"kind": "node", "node_key_id": raw["node_key_id"],
            "base_url": node["payload"]["base_url"], "storage_epoch": raw["storage_epoch"]}],
            issued_at=now, expires_at=min(now + 3600, raw["expires_at"]))
        published = await self.participant.publish_contact(contact, lease_seconds=min(300, lease_seconds))
        return {"state": "active", "lease_id": raw["lease_id"], "expires_at": raw["expires_at"],
                "directory_state": published["state"], "confirmed_index_leases": published["confirmed_leases"],
                "open_messaging_supported": False}

    async def request(self, recipient_key_id, *, request_id):
        opaque(request_id)
        budget = LookupBudget()
        try:
            session = self._load("outgoing", request_id)
            if session["request"]["payload"]["recipient_key_id"] != recipient_key_id:
                raise ContactError("contact_local_conflict")
        except ContactError as exc:
            if exc.code != "contact_local_missing":
                raise
            found = await self.participant.find_contact(recipient_key_id, budget=budget)
            if found["state"] != "found":
                raise ContactError("contact_unavailable", retryable=True)
            contact = verify_contact(found["contact"])
            self.participant._accept(found["contact"])
            if not contact["endpoints"]:
                raise ContactError("contact_unavailable")
            # Each attempt shares the original discovery budget. No graph or
            # arbitrary URL callback is supplied by the application.
            bundle, node, last_error = None, None, None
            for endpoint in contact["endpoints"]:
                try:
                    node = await self._resolve(endpoint, budget)
                    bundle = await self.call(node, "policy.get", {"recipient_key_id": recipient_key_id}, budget)
                    policy = verify_policy(bundle["policy"], lease=bundle["lease"], node=node)
                    if policy["encryption_key"] != contact["encryption_key"]:
                        raise ContactError("contact_policy_mismatch")
                    break
                except MemoryError as error:
                    last_error = error
                    bundle = None
            if bundle is None:
                raise ContactError("contact_unavailable", retryable=True) from last_error
            now = int(time.time())
            logical = sign_document(self.identity, "contact.request", issued_at=now, expires_at=min(now + 86400, policy["expires_at"]),
                request_id=request_id, encryption_key=self.encryption.public_descriptor(), recipient_key_id=recipient_key_id,
                recipient_encryption_key_id=policy["encryption_key"]["key_id"], node_key_id=policy["node_key_id"],
                storage_epoch=policy["storage_epoch"], lease_id=policy["lease_id"], resource_id=policy["resource_id"],
                policy_sha256=document_sha256(bundle["policy"]), request_class="message")
            session = {**bundle, "node": node, "request": logical}
            self._reserve([("outgoing", request_id), ("result", request_id)], logical["payload"]["expires_at"])
            self._save("outgoing", request_id, session, logical["payload"]["expires_at"])
        node = await self._session_node(session, budget)
        request = session["request"]
        verify_request(request, policy=session["policy"], lease=session["lease"], node=node)
        challenge = (await self.call(node, "challenge", {"request": request, "purpose": "submit"}, budget))["challenge"]
        answer = solve_challenge(challenge, request=request, node=node, purpose="submit", encryption_identity=self.encryption)
        result = await self.call(node, "submit", {"request": request, "challenge": challenge, "answer": answer}, budget)
        return {**result, "request_id": request_id, "expires_at": request["payload"]["expires_at"],
                "open_messaging_supported": False, "recipient_approved": False, "metrics": self.participant._metrics(budget)}

    async def poll(self, lease_id):
        session = self._load("policy", lease_id)
        budget = LookupBudget()
        node = await self._session_node(session, budget)
        response = await self.call(node, "poll", {"lease_id": lease_id}, budget)
        for request in response["requests"]:
            verify_request(request, policy=session["policy"], lease=session["lease"], node=node)
            self._save("incoming", document_sha256(request), {**session, "request": request}, request["payload"]["expires_at"])
        # B can inspect fixed request metadata; polling never approves it.
        return {"state": "unreviewed", "requests": [{"request_id": r["payload"]["request_id"],
            "sender_key_id": r["payload"]["signing_key"]["key_id"], "sender_encryption_key_id": r["payload"]["encryption_key"]["key_id"],
            "request_sha256": document_sha256(r), "request_ref": document_sha256(r), "request_class": r["payload"]["request_class"],
            "expires_at": r["payload"]["expires_at"]} for r in response["requests"]], "recipient_approved": False}

    async def decide(self, request_ref, *, decision, max_items=1, max_bytes=1048576):
        if not isinstance(decision, str) or decision not in {"approved", "rejected"}:
            raise ContactError("contact_invalid_decision")
        limit(max_items, 32)
        limit(max_bytes, 16 * 1024 * 1024)
        session = self._load("incoming", request_ref)
        budget = LookupBudget()
        node = await self._session_node(session, budget)
        request = session["request"]
        request_id = request["payload"]["request_id"]
        original = verify_request(request, policy=session["policy"], lease=session["lease"], node=node)
        # Persist exactly one explicit decision before sending, so transport
        # retry does not allocate another lease or sign a different decision.
        try:
            saved = self._load("decision", request_ref)
            signed = saved["decision"]
            if signed["payload"]["decision"] != decision:
                raise ContactError("contact_local_conflict")
            if decision == "approved":
                promised = signed["payload"]["grant"]["payload"]["resource_lease"]["payload"]
                if promised["max_items"] != max_items or promised["max_bytes"] != max_bytes:
                    raise ContactError("contact_local_conflict")
        except ContactError as exc:
            if exc.code != "contact_local_missing":
                raise
            self._reserve([("decision", request_ref)] + ([("allocation", request_ref)] if decision == "approved" else []), original["expires_at"])
            now = int(time.time())
            common = {"request_id": request_id, "request_sha256": document_sha256(request),
                      "subject_key_id": original["signing_key"]["key_id"], "subject_encryption_key_id": original["encryption_key"]["key_id"],
                      "recipient_encryption_key_id": self.encryption.key_id}
            grant = None
            if decision == "approved":
                try:
                    allocation = self._load("allocation", request_ref)
                    if allocation["max_items"] != max_items or allocation["max_bytes"] != max_bytes:
                        raise ContactError("contact_local_conflict")
                except ContactError as missing:
                    if missing.code != "contact_local_missing":
                        raise
                    allocation = {"encryption_key": self.encryption.public_descriptor(),
                    "purpose": "delivery", "max_items": max_items, "max_bytes": max_bytes,
                    "lease_seconds": original["expires_at"] - now, "allocation_id": "delivery_" + document_sha256(request)}
                    self._save("allocation", request_ref, allocation, original["expires_at"])
                resource = (await self.call(node, "lease", allocation, budget))["lease"]
                grant = sign_document(self.identity, "contact.grant", issued_at=now, expires_at=original["expires_at"],
                    **common, node_key_id=resource["payload"]["node_key_id"], storage_epoch=resource["payload"]["storage_epoch"],
                    resource_id=resource["payload"]["resource_id"], operations=["message.store"], resource_lease=resource)
            signed = sign_document(self.identity, "contact.decision", issued_at=now, expires_at=original["expires_at"],
                **common, node_key_id=original["node_key_id"], storage_epoch=original["storage_epoch"], policy_sha256=original["policy_sha256"],
                decision=decision, reason="accepted" if decision == "approved" else "declined", grant=grant)
            verify_decision(signed, request=request, policy=session["policy"], lease=session["lease"], node=node)
            self._save("decision", request_ref, {"decision": signed}, original["expires_at"])
        result = await self.call(node, "decide", {"request": request, "decision": signed}, budget)
        return {**result, "request_id": request_id, "decision": decision, "open_messaging_supported": False}

    async def result(self, request_id):
        session = self._load("outgoing", request_id)
        budget = LookupBudget()
        node = await self._session_node(session, budget)
        request = session["request"]
        challenge = (await self.call(node, "challenge", {"request": request, "purpose": "result"}, budget))["challenge"]
        answer = solve_challenge(challenge, request=request, node=node, purpose="result", encryption_identity=self.encryption)
        response = await self.call(node, "result", {"request": request, "challenge": challenge, "answer": answer}, budget)
        if response["decision"] is not None:
            verify_decision(response["decision"], request=request, policy=session["policy"], lease=session["lease"], node=node)
            self._save("result", request_id, {"decision": response["decision"]}, request["payload"]["expires_at"])
        return {"state": response["state"], "request_id": request_id, "recipient_approved": response["state"] == "approved",
                "authority_verified": response["state"] == "approved", "open_messaging_supported": False,
                "grant": response["decision"]["payload"]["grant"] if response["decision"] else None}

    async def dispatch(self, invitation, request_id=None):
        raw = document(invitation, maximum=8192)
        action = raw.get("action")
        variants = {"enable": {"node", "allocation_id", "max_pending", "lease_seconds", "revision"},
                    "request": {"recipient_key_id"}, "poll": {"lease_id"},
                    "decide": {"request_ref", "decision", "max_items", "max_bytes"}, "result": {"request_id"}}
        if raw.get("schema_version") != CONNECT_SCHEMA or not isinstance(action, str) or action not in variants:
            raise ContactError("contact_invalid_connect")
        object_fields(raw, {"schema_version", "action"} | variants[action])
        values = {k: raw[k] for k in variants[action]}
        if action == "request":
            values["request_id"] = request_id
        return await getattr(self, action)(**values)
