"""Explicit B authority for finite R maintenance of an unchanged public contact.

This grants directory publication only. It neither grants knock/delivery nor
renews a contact, policy, resource lease, identity, or original authorization.
"""
from __future__ import annotations

import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, document_sha256, public_signing_key
from memory_vault_open_contact import (
    ContactError, current_time, fields, limit, sign_document, verify_document,
    verify_lease, verify_policy,
)
from memory_vault_open_control import verify_contact, verify_node

AUTHORIZATION_KIND = "contact.directory_maintenance"
AUTHORIZATION_FIELDS = {"grant_id", "contact_sha256", "publisher_signing_key",
    "publisher_storage_epoch", "lease_id", "lease_sha256", "policy_sha256",
    "resource_id", "max_lease_seconds", "max_attempts", "max_requests", "max_bytes"}
ENROLLMENT_FIELDS = {"contact", "policy", "lease", "authorization"}
JOB_BYTES = 65536
MAX_JOBS = 128
REPLAY_TAIL = 90
WORK_REQUESTS = 8
WIRE_RESERVE_PER_REQUEST = 2 * 65536


def issue_authorization(signer, *, contact, policy, lease, node, max_attempts=32,
                        max_requests=256, max_bytes=16 * 1024 * 1024,
                        max_lease_seconds=300, now=None):
    """B signs once at the current time; the caller persists exact retry bytes."""
    owner, resource = contact["payload"], lease["payload"]
    result = sign_document(signer, AUTHORIZATION_KIND,
        issued_at=current_time(now),
        expires_at=min(owner["expires_at"], policy["payload"]["expires_at"], resource["expires_at"]),
        grant_id="directory_" + document_sha256({"contact": contact, "policy": policy, "lease": lease}),
        contact_sha256=document_sha256(contact), publisher_signing_key=node["payload"]["signing_key"],
        publisher_storage_epoch=resource["storage_epoch"], lease_id=resource["lease_id"],
        lease_sha256=document_sha256(lease), policy_sha256=document_sha256(policy),
        resource_id=resource["resource_id"], max_lease_seconds=max_lease_seconds,
        max_attempts=max_attempts, max_requests=max_requests, max_bytes=max_bytes)
    verify_authorization(result, contact=contact, policy=policy, lease=lease, node=node,
                         now=result["payload"]["issued_at"])
    return result


def verify_authorization(value, *, contact, policy, lease, node, now=None):
    """Authenticate every original and exact delegation; no implied owner power."""
    now = current_time(now)
    grant = verify_document(value, AUTHORIZATION_KIND, now=now)
    recipient = verify_contact(contact, now=now)
    resource = verify_lease(lease, node=node, now=now)
    permission = verify_policy(policy, lease=lease, node=node, now=now)
    publisher = verify_node(node, now=now)
    endpoint = {"kind": "node", "node_key_id": publisher["signing_key"]["key_id"],
                "base_url": publisher["base_url"], "storage_epoch": publisher["storage_epoch"]}
    if (recipient["status"] != "active" or not recipient["allow_discovery"]
            or permission["status"] != "active" or resource["purpose"] != "knock"
            or grant["signing_key"] != recipient["signing_key"]
            or permission["signing_key"] != recipient["signing_key"]
            or recipient["encryption_key"] != permission["encryption_key"]
            or grant["publisher_signing_key"] != publisher["signing_key"]
            or grant["publisher_storage_epoch"] != publisher["storage_epoch"]
            or endpoint not in recipient["endpoints"]
            or grant["lease_id"] != resource["lease_id"]
            or grant["resource_id"] != resource["resource_id"]
            or grant["expires_at"] > min(recipient["expires_at"], permission["expires_at"], resource["expires_at"])
            or grant["issued_at"] < max(recipient["issued_at"], permission["issued_at"], resource["issued_at"])
            or grant["contact_sha256"] != document_sha256(contact)
            or grant["policy_sha256"] != document_sha256(policy)
            or grant["lease_sha256"] != document_sha256(lease)):
        raise ContactError("contact_directory_authority_mismatch")
    return grant


def verify_delegated_put(body, *, signer=None, now=None):
    fields(body, ENROLLMENT_FIELDS | {"publisher_node", "lease_seconds"})
    grant = verify_authorization(body["authorization"], contact=body["contact"],
        policy=body["policy"], lease=body["lease"], node=body["publisher_node"], now=now)
    limit(body["lease_seconds"], grant["max_lease_seconds"])
    if signer is not None and signer != grant["publisher_signing_key"]:
        raise ContactError("contact_directory_wrong_publisher")
    return grant


def check_observed(db, contact, node):
    """Known local revocation, fork and revision floors remain authoritative."""
    for original in (contact, node):
        payload = original["payload"]
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_control_floors'").fetchone():
            row = db.execute("SELECT revision,digest,status FROM open_control_floors WHERE kind=? AND key_id=?",
                (payload["kind"], payload["signing_key"]["key_id"])).fetchone()
            _floor(row, payload["revision"], document_sha256(original))
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_contact_floors'").fetchone():
        row = db.execute("SELECT revision,digest,status FROM open_contact_floors WHERE owner=?",
            (contact["payload"]["signing_key"]["key_id"],)).fetchone()
        _floor(row, contact["payload"]["revision"], document_sha256(contact))


def _floor(row, revision, digest):
    if row and (row[2] != "active" or row[0] > revision or (row[0] == revision and row[1] != digest)):
        raise ContactError("contact_directory_known_inactive")


def check_resource_observed(db, body):
    """A co-located D/R must honor resource revocation it already retains.

    Other directories do not invent knowledge of remote R state. A policy
    for another resource node is not a revocation of this delegation.
    """
    resource = body["lease"]["payload"]
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_contact_resource_leases'").fetchone():
        row = db.execute("SELECT record,status FROM open_contact_resource_leases WHERE lease_id=?", (resource["lease_id"],)).fetchone()
        if row and (row[1] != "active" or document_sha256(document(bytes(row[0]))) != document_sha256(body["lease"])):
            raise ContactError("contact_directory_known_inactive")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_contact_policies'").fetchone():
        row = db.execute("SELECT record,status FROM open_contact_policies WHERE owner=?", (resource["owner_key_id"],)).fetchone()
        if row:
            held = document(bytes(row[0]))
            same_node = all(held["payload"][name] == resource[name] for name in ("node_key_id", "storage_epoch"))
            if same_node and (row[1] != "active" or document_sha256(held) != document_sha256(body["policy"])):
                raise ContactError("contact_directory_known_inactive")


class DirectoryMaintenanceState:
    """One bounded job per original knock lease; all durable mutations serialize.

    Attempts reserve worst-case request/response work before any network action.
    Bytes count bounded serialized RPC bodies, not HTTP/TLS framing. Unused
    request slots are returned only after a completed turn. Crashes keep
    their full reservation. Failed requests retain the same wire allowance as
    successful requests; no failure or exact enrollment retry resets a budget.
    """
    def __init__(self, contact_state):
        self.contact_state = contact_state
        self.db = contact_state.db

    def initialize(self):
        def create(now):
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_contact_directory_jobs (
                job_id TEXT PRIMARY KEY,lease_id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL,
                body BLOB NOT NULL,state TEXT NOT NULL,expires_at INTEGER NOT NULL,
                retain_until INTEGER NOT NULL,next_due INTEGER NOT NULL,attempts INTEGER NOT NULL,
                requests INTEGER NOT NULL,bytes INTEGER NOT NULL,receipts BLOB NOT NULL,
                last_error TEXT)""")
        self.contact_state._transaction(create)

    def _row(self, job_id):
        row = self.db.execute("SELECT * FROM open_contact_directory_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise ContactError("contact_directory_job_missing")
        return dict(zip(("job_id", "lease_id", "digest", "body", "state", "expires_at", "retain_until",
                         "next_due", "attempts", "requests", "bytes", "receipts", "last_error"), row))

    def _guard(self, body, now):
        if not self.contact_state.enabled:
            raise ContactError("contact_directory_closed")
        grant = verify_authorization(body["authorization"], contact=body["contact"],
            policy=body["policy"], lease=body["lease"], node=self.contact_state.node, now=now)
        resource = self.contact_state._lease(grant["lease_id"], now)
        if document_sha256(document(bytes(resource["record"]))) != grant["lease_sha256"]:
            raise ContactError("contact_directory_resource_changed")
        owner = grant["signing_key"]["key_id"]
        held = self.db.execute("SELECT digest,status FROM open_contact_policies WHERE owner=?", (owner,)).fetchone()
        if held is None or held[1] != "active" or held[0] != grant["policy_sha256"]:
            raise ContactError("contact_directory_policy_changed")
        check_observed(self.db, body["contact"], self.contact_state.node)
        return grant

    @staticmethod
    def _summary(row):
        receipts = document(bytes(row["receipts"]))["leases"]
        return {name: row[name] for name in ("state", "job_id", "expires_at", "attempts", "requests", "bytes", "last_error")} | {
            "directory_expires_at": min((r["payload"]["expires_at"] for r in receipts), default=None)}

    def enroll(self, request):
        from memory_vault_open_contact import verify_rpc
        from memory_vault_open_state import OpenCheckpoints
        rpc = verify_rpc(request, node=self.contact_state.node, now=self.contact_state._now())
        if rpc["action"] != "directory.maintain":
            raise ContactError("contact_unsupported_action")
        body = rpc["body"]
        verify_authorization(body["authorization"], contact=body["contact"], policy=body["policy"],
            lease=body["lease"], node=self.contact_state.node, now=self.contact_state._now())
        # Authenticated contact observations survive a later capacity refusal.
        OpenCheckpoints(self.db).accept(body["contact"], now=self.contact_state._now())
        def write(now):
            grant = self._guard(body, now)
            self._collect(now)
            prior = self.db.execute("SELECT job_id FROM open_contact_directory_jobs WHERE lease_id=?", (grant["lease_id"],)).fetchone()
            if prior:
                row = self._row(prior[0])
                if row["digest"] != document_sha256(body):
                    raise ContactError("contact_directory_job_conflict")
                return self._summary(row)
            if self.db.execute("SELECT count(*) FROM open_contact_directory_jobs").fetchone()[0] >= MAX_JOBS:
                raise ContactError("contact_directory_capacity")
            raw = canonical_bytes(document(body, maximum=24576))
            self.contact_state.capacity.reserve("contact_directory", grant["grant_id"], document_sha256(body),
                JOB_BYTES, grant["expires_at"] + REPLAY_TAIL, owner=grant["signing_key"]["key_id"],
                operation_id=grant["lease_id"])
            self.db.execute("INSERT INTO open_contact_directory_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (grant["grant_id"], grant["lease_id"], document_sha256(body), raw, "pending", grant["expires_at"],
                 grant["expires_at"] + REPLAY_TAIL, now, 0, 0, 0, canonical_bytes({"leases": []}), None))
            return self._summary(self._row(grant["grant_id"]))
        return self.contact_state._transaction(write, rpc=request)

    def _collect(self, now):
        self.db.execute("DELETE FROM open_contact_directory_jobs WHERE job_id IN (SELECT job_id FROM open_contact_directory_jobs WHERE retain_until<=? ORDER BY retain_until LIMIT 16)", (now,))
        self.contact_state.capacity.collect_released("contact_directory", now=now, limit=16)

    def begin(self, available_requests):
        if available_requests <= 0:
            return None
        def reserve(now):
            self._collect(now)
            found = self.db.execute("SELECT job_id FROM open_contact_directory_jobs WHERE next_due<=? AND state NOT IN ('stopped','exhausted') ORDER BY next_due,job_id LIMIT 1", (now,)).fetchone()
            if found is None:
                return None
            row = self._row(found[0])
            body = document(bytes(row["body"]), maximum=24576)
            try:
                grant = self._guard(body, now)
            except MemoryError as exc:
                self.db.execute("UPDATE open_contact_directory_jobs SET state='stopped',last_error=? WHERE job_id=?", (exc.code, row["job_id"]))
                return None
            count = min(WORK_REQUESTS, available_requests, grant["max_requests"] - row["requests"],
                        (grant["max_bytes"] - row["bytes"]) // WIRE_RESERVE_PER_REQUEST)
            if row["attempts"] >= grant["max_attempts"] or count <= 0:
                self.db.execute("UPDATE open_contact_directory_jobs SET state='exhausted',last_error='contact_directory_budget' WHERE job_id=?", (row["job_id"],))
                return None
            self.db.execute("UPDATE open_contact_directory_jobs SET state='running',next_due=?,attempts=attempts+1,requests=requests+?,bytes=bytes+? WHERE job_id=?",
                            (now + 10, count, count * WIRE_RESERVE_PER_REQUEST, row["job_id"]))
            return {"job_id": row["job_id"], "body": body, "attempt": row["attempts"] + 1, "reserved": count}
        return self.contact_state._transaction(reserve)

    def guard(self, attempt):
        def check(now):
            row = self._row(attempt["job_id"])
            if row["state"] != "running" or row["attempts"] != attempt["attempt"]:
                raise ContactError("contact_directory_attempt_changed")
            return self._guard(attempt["body"], now)
        return self.contact_state._transaction(check)

    def finish(self, attempt, requests, receipts, error):
        def write(now):
            last_error = error
            row = self._row(attempt["job_id"])
            if row["attempts"] != attempt["attempt"] or row["state"] != "running":
                raise ContactError("contact_directory_attempt_changed")
            state = "leased" if len(receipts) == 3 else "degraded"
            try:
                self._guard(attempt["body"], now)
            except MemoryError as exc:
                state, last_error, receipts[:] = "stopped", exc.code, []
            # Completed work keeps conservative wire charges for every request,
            # including failures. Only requests never sent are returned.
            unused = attempt["reserved"] - requests
            if not 0 <= unused <= attempt["reserved"]:
                raise ContactError("contact_directory_budget")
            expires = min((item["payload"]["expires_at"] for item in receipts), default=now + 60)
            next_due = max(now + 10, expires - min(60, max(1, (expires - now) // 5)))
            self.db.execute("UPDATE open_contact_directory_jobs SET state=?,next_due=?,requests=requests-?,bytes=bytes-?,receipts=?,last_error=? WHERE job_id=?",
                (state, next_due, unused, unused * WIRE_RESERVE_PER_REQUEST,
                 canonical_bytes(document({"leases": receipts}, maximum=16384)), last_error, row["job_id"]))
            return self._summary(self._row(row["job_id"]))
        return self.contact_state._transaction(write)


class _JobBudget:
    """A narrowed view of the node's existing turn allowance, never extra work."""
    def __init__(self, parent, maximum_requests, guard):
        from memory_vault_open_routing import LookupBudget
        self.parent, self.guard = parent, guard
        self.local = LookupBudget(maximum_requests=maximum_requests, maximum_bytes=maximum_requests * 65536,
                                  maximum_seconds=5)
        self.local.deadline = min(self.local.deadline, parent.deadline)

    def __getattr__(self, name):
        return getattr(self.local, name)

    def check(self):
        self.parent.check()
        self.local.check()

    def charge_request_bytes(self, amount):
        self.parent.charge_request_bytes(amount)
        self.local.charge_request_bytes(amount)

    def charge_request(self):
        self.guard()
        self.parent.charge_request()
        self.local.charge_request()

    def charge_bytes(self, amount):
        self.parent.charge_bytes(amount)
        self.local.charge_bytes(amount)


async def maintain_directory(participant, budget):
    """At most one due job inside the existing node maintenance turn."""
    from memory_vault import MemoryError
    from memory_vault_open_contact_state import ContactState
    from memory_vault_open_control import contact_key

    def state(db):
        return DirectoryMaintenanceState(ContactState(db, participant.identity, participant.descriptor,
                                                     **participant.contact_policy))
    with participant.state.db() as db:
        attempt = state(db).begin(budget.remaining_requests)
    if attempt is None:
        return None
    def guard():
        with participant.state.db() as db:
            state(db).guard(attempt)
    work = _JobBudget(budget, attempt["reserved"], guard)
    receipts, errors, seen, addresses = [], [], set(), set()
    try:
        body = attempt["body"]
        key = contact_key(body["contact"]["payload"]["signing_key"]["key_id"])
        # Preserve at least three request slots for actual directory writes.
        work.local.maximum_requests = max(1, attempt["reserved"] - 3)
        route = await participant._lookup(key, "directory", work)
        work.local.maximum_requests = attempt["reserved"]
        candidates = list(route["candidates"])
        if "directory" in participant.descriptor["payload"]["roles"]:
            candidates.append(participant.descriptor)
        for node in candidates:
            if node["payload"]["signing_key"]["key_id"] in seen:
                continue
            seen.add(node["payload"]["signing_key"]["key_id"])
            try:
                grant = body["authorization"]["payload"]
                observed = {}
                response = await participant._call(node, "delegated_put", {**body,
                    "publisher_node": participant.descriptor,
                    "lease_seconds": min(grant["max_lease_seconds"], grant["expires_at"] - int(time.time()))}, work,
                    endpoint_result=observed)
                if observed["socket"] not in addresses:
                    receipts.append(response["lease"])
                    addresses.add(observed["socket"])
            except MemoryError as exc:
                errors.append(exc.code)
            if len(receipts) == 3:
                break
    except MemoryError as exc:
        errors.append(exc.code)
    finally:
        with participant.state.db() as db:
            result = state(db).finish(attempt, work.requests, receipts, errors[-1] if errors else None)
    return result
