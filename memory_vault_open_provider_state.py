"""Finite opaque-provider directory in the existing protected transport DB.

The caller supplies its network.sqlite3 connection and owns HTTP and identity
lifecycle. No Vault, data body, new database or network request is created here.
"""
from __future__ import annotations

import hashlib
import threading
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import document, document_sha256, integer
from memory_vault_open_control import verify_node
from memory_vault_open_provider import (
    MAX_CONTROL_BYTES, PUBLISH, ProviderError, answer_target_challenge, as_dual,
    authority_scope, bounded, fail, issue_status, node_binding, resource_scope,
    sign_document, verify_document, verify_rpc, verify_status,
)

DEFAULT_POLICY = {"maximum_leases": 128, "maximum_facts": 512,
                  "maximum_replays": 4096, "maximum_state_bytes": 64 * 1024 * 1024,
                  "maximum_live_bytes": 64 * 1024 * 1024, "maximum_meta_bytes": 64 * 1024 * 1024,
                  "maximum_requests": 65536, "maximum_pending": 1024,
                  "maximum_jobs": 4096, "maximum_job_bytes": 16 * 1024 * 1024}
FACT_CHARGE = 40960  # Two signed facts, authority conflict and SQL reservation.
LEASE_CHARGE = 36864
REPLAY_CHARGE = 32768
_TARGET_SLOTS = threading.BoundedSemaphore(1)


class ProviderState:
    def __init__(self, db, identity, node, *, encryption_identity, enabled=False, policy=None, clock=None):
        if type(enabled) is not bool:
            fail("provider_invalid_policy")
        actual = dict(DEFAULT_POLICY)
        if policy is not None:
            if not isinstance(policy, dict) or set(policy) - set(actual):
                fail("provider_invalid_policy")
            actual.update(policy)
        for name, ceiling in DEFAULT_POLICY.items():
            bounded(actual[name], ceiling)
        checked = verify_node(node, now=node["payload"]["issued_at"])
        if checked["signing_key"] != identity.public_descriptor():
            fail("provider_wrong_node")
        self.db, self.identity, self.node = db, identity, document(node)
        self.encryption_identity, self.enabled, self.policy = encryption_identity, enabled, actual
        self.clock, self._lock = clock or time.time, threading.RLock()

    def _now(self):
        return integer(int(self.clock()))

    def _one(self, sql, parameters=()):
        cursor = self.db.execute(sql, parameters); row = cursor.fetchone()
        return dict(zip((column[0] for column in cursor.description), row)) if row is not None else None

    def _expected_binding(self):
        return self.identity.key_id + ":" + self.node["payload"]["storage_epoch"] + ":" + self.encryption_identity.key_id

    def _binding(self):
        row = self._one("SELECT value FROM open_provider_state WHERE name='binding'")
        if row is None or row["value"] != self._expected_binding():
            fail("provider_storage_epoch_mismatch")

    def initialize(self):
        with self._lock:
            if self.db.in_transaction:
                fail("provider_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for sql in [
                    "CREATE TABLE IF NOT EXISTS open_provider_state(name TEXT PRIMARY KEY,value TEXT NOT NULL)",
                    """CREATE TABLE IF NOT EXISTS open_provider_resources(
                        lease_id TEXT PRIMARY KEY,owner TEXT NOT NULL,allocation_id TEXT NOT NULL,
                        digest TEXT NOT NULL,intent BLOB NOT NULL,record BLOB NOT NULL,root_digest TEXT NOT NULL,
                        purpose TEXT NOT NULL,status TEXT NOT NULL,status_record BLOB NOT NULL,
                        generation INTEGER NOT NULL,expires_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                        requests_used INTEGER NOT NULL,UNIQUE(owner,allocation_id))""",
                    """CREATE TABLE IF NOT EXISTS open_provider_facts(
                        fact_key TEXT PRIMARY KEY,namespace TEXT NOT NULL,opaque_key TEXT NOT NULL,
                        provider TEXT NOT NULL,provider_epoch TEXT NOT NULL,custody_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,digest TEXT NOT NULL,record BLOB NOT NULL,second_record BLOB,
                        status TEXT NOT NULL,node BLOB NOT NULL,index_lease BLOB NOT NULL,resource_id TEXT NOT NULL,
                        grant_record BLOB NOT NULL,grant_digest TEXT NOT NULL,owner_status BLOB NOT NULL,
                        expires_at INTEGER NOT NULL,retain_until INTEGER NOT NULL)""",
                    """CREATE TABLE IF NOT EXISTS open_provider_status(
                        issuer TEXT NOT NULL,root_digest TEXT NOT NULL,scope_kind TEXT NOT NULL,scope_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,record BLOB NOT NULL,digest TEXT NOT NULL,second_record BLOB,
                        revoked_mask INTEGER NOT NULL,conflict INTEGER NOT NULL,valid_until INTEGER NOT NULL,
                        PRIMARY KEY(issuer,root_digest,scope_kind,scope_id))""",
                    """CREATE TABLE IF NOT EXISTS open_provider_replay(
                        caller TEXT NOT NULL,action TEXT NOT NULL,allocation_id TEXT NOT NULL,digest TEXT NOT NULL,
                        result BLOB NOT NULL,expires_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                        PRIMARY KEY(caller,action,allocation_id))""",
                    "CREATE INDEX IF NOT EXISTS open_provider_lookup ON open_provider_facts(namespace,opaque_key,fact_key)",
                    "CREATE INDEX IF NOT EXISTS open_provider_fact_expiry ON open_provider_facts(retain_until)",
                    "CREATE INDEX IF NOT EXISTS open_provider_resource_expiry ON open_provider_resources(retain_until)",
                    "CREATE INDEX IF NOT EXISTS open_provider_replay_expiry ON open_provider_replay(retain_until)",
                ]:
                    self.db.execute(sql)
                row = self._one("SELECT value FROM open_provider_state WHERE name='binding'")
                if row is None:
                    if any(self._one("SELECT 1 FROM " + table + " LIMIT 1") for table in (
                            "open_provider_resources", "open_provider_facts", "open_provider_status", "open_provider_replay")):
                        fail("provider_storage_binding_missing")
                    self.db.execute("INSERT INTO open_provider_state VALUES('binding',?)", (self._expected_binding(),))
                self._binding(); self.db.commit()
            except BaseException:
                self.db.rollback(); raise

    def _transaction(self, rpc, operation):
        with self._lock:
            if self.db.in_transaction:
                fail("provider_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                now = self._now(); self._binding()
                checked = verify_rpc(rpc, node=self.node, now=now)
                if not self.enabled:
                    fail("provider_closed")
                result = operation(checked, now)
                self._capacity(); self.db.commit()
            except BaseException:
                self.db.rollback(); raise
        if isinstance(result, ProviderError):
            raise result
        return result

    def _capacity(self):
        counts = {name: self._one("SELECT count(*) AS n FROM " + table)["n"] for name, table in (
            ("leases", "open_provider_resources"), ("facts", "open_provider_facts"),
            ("replays", "open_provider_replay"), ("statuses", "open_provider_status"))}
        charge = counts["leases"] * LEASE_CHARGE + counts["facts"] * FACT_CHARGE + counts["replays"] * REPLAY_CHARGE + counts["statuses"] * 33024
        if (counts["leases"] > self.policy["maximum_leases"] or counts["facts"] > self.policy["maximum_facts"]
                or counts["replays"] > self.policy["maximum_replays"] or charge > self.policy["maximum_state_bytes"]):
            fail("provider_capacity")

    def _replay(self, caller, action, allocation_id, digest, now):
        old = self._one("SELECT * FROM open_provider_replay WHERE caller=? AND action=? AND allocation_id=?", (caller, action, allocation_id))
        if old is None:
            return None
        if old["digest"] != digest:
            fail("provider_allocation_conflict")
        result = document(bytes(old["result"]))
        return self._current_result(result, now)

    def _current_result(self, result, now):
        if "lease" in result:
            lease = result["lease"]["payload"]
            row = self._one("SELECT status,status_record FROM open_provider_resources WHERE lease_id=?", (lease["resource"]["lease_id"],))
            result["current_state"] = "expired" if lease["expires_at"] <= now else (row["status"] if row else "expired")
            if row:
                result["status"] = document(bytes(row["status_record"]))
        else:
            lease = result["index_lease"]["payload"]
            row = self._one("SELECT * FROM open_provider_facts WHERE namespace=? AND opaque_key=? AND provider=? AND provider_epoch=? AND custody_id=?",
                (lease["ref"]["namespace"], lease["ref"]["key"], lease["provider_key_id"], lease["provider_storage_epoch"], lease["custody_id"]))
            if lease["expires_at"] <= now or row is None:
                state = "expired"
            elif row["status"] == "conflict":
                state = "conflict"
            elif row["digest"] != lease["fact_sha256"]:
                state = "superseded"
            else:
                state = "active" if self._eligible(row, now) else "revoked"
            result["current_state"] = state
        return result

    def _remember(self, caller, action, allocation, digest, result, expiry):
        self.db.execute("INSERT INTO open_provider_replay VALUES(?,?,?,?,?,?,?)",
                        (caller, action, allocation, digest, canonical_bytes(result), expiry, expiry + 60))

    def _resource(self, lease, now):
        raw = verify_document(lease, "root.resource.lease", now=now)
        if raw["resource"]["node_key_id"] != self.identity.key_id or raw["resource"]["storage_epoch"] != self.node["payload"]["storage_epoch"]:
            fail("provider_wrong_resource")
        row = self._one("SELECT * FROM open_provider_resources WHERE lease_id=?", (raw["resource"]["lease_id"],))
        if row is None or row["record"] != canonical_bytes(lease) or row["generation"] != raw["reservation_generation"]:
            fail("provider_unknown_resource")
        if row["status"] != "active" or row["expires_at"] <= now:
            fail("provider_resource_inactive")
        return raw, row

    def _allocate(self, rpc, now):
        intent = rpc["body"]["intent"]; raw = verify_document(intent, "root.resource.intent", now=now)
        node_binding(raw, self.node, now)
        if raw["signing_key"] != rpc["signing_key"]:
            fail("provider_wrong_owner")
        if raw["purpose"] == "provider_index" and "directory" not in self.node["payload"]["roles"]:
            fail("provider_not_directory")
        caller, digest = rpc["signing_key"]["key_id"], document_sha256(intent)
        previous = self._replay(caller, "resource.allocate", raw["allocation_id"], digest, now)
        if previous is not None:
            row = self._one("SELECT status FROM open_provider_resources WHERE owner=? AND allocation_id=?", (caller, raw["allocation_id"]))
            if row and row["status"] != "active":
                previous["current_state"] = row["status"]
            return previous
        if min(raw["windows"].values()) <= now:
            fail("provider_resource_expired")
        totals = {name: 0 for name in raw["budget"]}
        for row in self.db.execute("SELECT record FROM open_provider_resources"):
            for name, value in document(bytes(row[0]))["payload"]["budget"].items():
                totals[name] += value
        names = {"max_live_bytes": "maximum_live_bytes", "max_meta_bytes": "maximum_meta_bytes", "max_items": "maximum_facts",
                 "max_requests": "maximum_requests", "max_pending": "maximum_pending", "max_replay_records": "maximum_replays",
                 "max_jobs": "maximum_jobs", "max_job_bytes": "maximum_job_bytes"}
        if any(totals[name] + value > self.policy[names[name]] for name, value in raw["budget"].items()):
            fail("provider_resource_capacity")
        reserved_state = sum(document(bytes(row[0]))["payload"]["budget"]["max_meta_bytes"] + document(bytes(row[0]))["payload"]["budget"]["max_replay_records"] * REPLAY_CHARGE + LEASE_CHARGE for row in self.db.execute("SELECT record FROM open_provider_resources"))
        requested_state = raw["budget"]["max_meta_bytes"] + raw["budget"]["max_replay_records"] * REPLAY_CHARGE + LEASE_CHARGE
        if reserved_state + requested_state > self.policy["maximum_state_bytes"]:
            fail("provider_resource_capacity")
        if raw["purpose"] == "provider_index" and raw["budget"]["max_meta_bytes"] < raw["budget"]["max_items"] * (FACT_CHARGE + 33024):
            fail("provider_insufficient_metadata")
        token = hashlib.sha256((self._expected_binding() + ":" + caller + ":" + digest).encode()).hexdigest()
        resource = {"node_key_id": self.identity.key_id, "storage_epoch": self.node["payload"]["storage_epoch"],
                    "lease_id": "lease_" + token, "resource_id": "resource_" + token}
        lease = sign_document(self.identity, "root.resource.lease", issued_at=now, expires_at=raw["expires_at"],
            allocation_id=raw["allocation_id"], intent_sha256=digest, root_key=raw["root_key"], subject=as_dual(raw["subject"]),
            resource=resource, targetEncryptionKey=self.encryption_identity.public_descriptor(), reservation_generation=1,
            purpose=raw["purpose"], budget=raw["budget"], windows=raw["windows"])
        status = issue_status(self.identity, root=raw["root_key"], revision=self._next_status_revision(raw["root_key"]), issued_at=now, valid_until=raw["expires_at"],
            entries=[{"scope_kind": "resource", "scope_id": resource_scope(raw["root_key"], resource),
                      "minimum_document_revision": 1, "status": "active", "operation_mask": 127}])
        self.db.execute("INSERT INTO open_provider_resources VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (resource["lease_id"], caller, raw["allocation_id"], digest, canonical_bytes(intent), canonical_bytes(lease),
             document_sha256(raw["root_key"]), raw["purpose"], "active", canonical_bytes(status), 1,
             raw["expires_at"], raw["expires_at"] + 60))
        result = {"lease": lease, "status": status, "current_state": "active"}
        self._remember(caller, "resource.allocate", raw["allocation_id"], digest, result, raw["expires_at"])
        return result

    def _next_status_revision(self, root):
        name = "status_revision:" + document_sha256(root)
        old = self._one("SELECT value FROM open_provider_state WHERE name=?", (name,))
        revision = integer(int(old["value"]) + 1 if old else 1)
        self.db.execute("INSERT INTO open_provider_state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, str(revision)))
        return revision

    def _observe(self, status, *, root, issuer, kind, scope_id, required_revision, now):
        raw = verify_status(status, now=now)
        if raw["scope_key"] != {"root_key": root, "issuer_key_id": issuer}:
            fail("provider_status_scope_mismatch")
        entries = [e for e in raw["entries"] if e["scope_kind"] == kind and e["scope_id"] == scope_id]
        if len(entries) != 1:
            fail("provider_missing_status")
        entry = entries[0]
        if not entry["operation_mask"] & PUBLISH:
            fail("provider_status_operation")
        params = (issuer, document_sha256(root), kind, scope_id); digest = document_sha256(status)
        old = self._one("SELECT * FROM open_provider_status WHERE issuer=? AND root_digest=? AND scope_kind=? AND scope_id=?", params)
        same_revision = self._one("SELECT digest FROM open_provider_status WHERE issuer=? AND root_digest=? AND revision=? AND digest<>? LIMIT 1", (issuer, document_sha256(root), raw["revision"], digest))
        if same_revision:
            self.db.execute("UPDATE open_provider_status SET second_record=?,conflict=1 WHERE issuer=? AND root_digest=? AND revision=?", (canonical_bytes(status), issuer, document_sha256(root), raw["revision"]))
            return ProviderError("provider_status_conflict")
        if old and old["conflict"]:
            return ProviderError("provider_status_conflict")
        if old and raw["revision"] < old["revision"]:
            fail("provider_status_rollback")
        if old and raw["revision"] == old["revision"] and digest != old["digest"]:
            self.db.execute("UPDATE open_provider_status SET second_record=?,conflict=1 WHERE issuer=? AND root_digest=? AND scope_kind=? AND scope_id=?", (canonical_bytes(status), *params))
            return ProviderError("provider_status_conflict")
        if old:
            prior_entry = next(e for e in document(bytes(old["record"]))["payload"]["entries"] if e["scope_kind"] == kind and e["scope_id"] == scope_id)
            if entry["minimum_document_revision"] < prior_entry["minimum_document_revision"]:
                fail("provider_status_rollback")
        revoked = (old["revoked_mask"] if old else 0) | (entry["operation_mask"] if entry["status"] == "revoked" else 0)
        self.db.execute("""INSERT INTO open_provider_status VALUES(?,?,?,?,?,?,?,NULL,?,0,?)
            ON CONFLICT(issuer,root_digest,scope_kind,scope_id) DO UPDATE SET revision=excluded.revision,
            record=excluded.record,digest=excluded.digest,revoked_mask=excluded.revoked_mask,valid_until=excluded.valid_until""",
            (*params, raw["revision"], canonical_bytes(status), digest, revoked, raw["valid_until"]))
        if revoked & PUBLISH:
            return ProviderError("provider_authority_revoked")
        return ProviderError("provider_status_revision") if entry["minimum_document_revision"] > required_revision else None

    @staticmethod
    def _fact_key(raw):
        return document_sha256({"ref": raw["ref"], "provider_key_id": raw["signing_key"]["key_id"],
                                "storage_epoch": raw["storage_epoch"], "custody_id": raw["custody_id"]})

    def _put(self, rpc, now):
        body = rpc["body"]; fact = verify_document(body["fact"], "provider.fact", now=now)
        provider = verify_node(body["provider_node"], now=now)
        grant = verify_document(body["publication_grant"], "provider.publication.grant", now=now)
        lease, reservation = self._resource(body["resource_lease"], now)
        if ("directory" not in self.node["payload"]["roles"] or fact["status"] != "active" or fact["signing_key"] != rpc["signing_key"]
                or provider["signing_key"] != fact["signing_key"] or provider["status"] != "active" or provider["storage_epoch"] != fact["storage_epoch"]):
            fail("provider_wrong_publisher")
        if (lease["purpose"] != "provider_index" or grant["root_key"] != lease["root_key"] or grant["resource"] != lease["resource"]
                or grant["resource_lease_sha256"] != document_sha256(body["resource_lease"])
                or grant["publisher"]["signing_key_id"] != fact["signing_key"]["key_id"] or grant["ref"] != fact["ref"]
                or grant["expires_at"] > lease["windows"]["publish_until"] or body["lease_seconds"] > grant["maximum_fact_seconds"]
                or now >= min(lease["windows"]["publish_until"], lease["windows"]["admit_until"])):
            fail("provider_publication_not_authorized")
        grant_digest = document_sha256(body["publication_grant"])
        refusal = self._observe(body["owner_status"], root=grant["root_key"], issuer=grant["root_key"]["owner"]["signing_key_id"],
            kind="authority", scope_id=authority_scope(grant["root_key"], "provider.publication.grant", grant_digest), required_revision=grant["revision"], now=now)
        if refusal is not None:
            return refusal
        caller, operation_digest = rpc["signing_key"]["key_id"], document_sha256(body)
        previous = self._replay(caller, "provider.put", body["allocation_id"], operation_digest, now)
        if previous is not None:
            return previous
        key, fact_digest = self._fact_key(fact), document_sha256(body["fact"])
        old = self._one("SELECT * FROM open_provider_facts WHERE fact_key=?", (key,))
        if old:
            if old["status"] in {"withdrawn", "conflict"}:
                fail("provider_fact_inactive")
            if fact["revision"] < old["revision"]:
                fail("provider_fact_rollback")
            if fact["revision"] == old["revision"] and fact_digest != old["digest"]:
                self.db.execute("UPDATE open_provider_facts SET second_record=?,status='conflict' WHERE fact_key=?", (canonical_bytes(body["fact"]), key))
                return ProviderError("provider_fact_conflict")
            if old["grant_digest"] != grant_digest:
                fail("provider_grant_rebinding")
            if old["resource_id"] != lease["resource"]["lease_id"]:
                fail("provider_resource_rebinding")
        items = self._one("SELECT count(*) AS n FROM open_provider_facts WHERE resource_id=?", (reservation["lease_id"],))["n"]
        if items + (0 if old else 1) > lease["budget"]["max_items"] or reservation["requests_used"] >= min(lease["budget"]["max_requests"], lease["budget"]["max_replay_records"] - 1):
            fail("provider_resource_exhausted")
        if old is None:
            providers = self._one("SELECT count(DISTINCT provider) AS n FROM open_provider_facts WHERE namespace=? AND opaque_key=? AND status='active' AND expires_at>?", (fact["ref"]["namespace"], fact["ref"]["key"], now))["n"]
            positions = self._one("SELECT count(*) AS n FROM open_provider_facts WHERE namespace=? AND opaque_key=? AND provider=? AND status='active' AND expires_at>?", (fact["ref"]["namespace"], fact["ref"]["key"], caller, now))["n"]
            if positions >= 2 or providers >= 16 and positions == 0:
                fail("provider_ref_capacity")
        expires = min(now + body["lease_seconds"], fact["expires_at"], grant["expires_at"], lease["windows"]["publish_until"], body["owner_status"]["payload"]["valid_until"])
        if expires <= now:
            fail("provider_publication_expired")
        index = sign_document(self.identity, "provider.index_lease", issued_at=now, expires_at=expires,
            node_key_id=self.identity.key_id, storage_epoch=self.node["payload"]["storage_epoch"], index_lease_id="index_" + operation_digest,
            fact_sha256=fact_digest, ref=fact["ref"], provider_key_id=caller, provider_storage_epoch=fact["storage_epoch"], custody_id=fact["custody_id"])
        self.db.execute("""INSERT INTO open_provider_facts VALUES(?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(fact_key) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,record=excluded.record,
            node=excluded.node,index_lease=excluded.index_lease,grant_record=excluded.grant_record,
            grant_digest=excluded.grant_digest,owner_status=excluded.owner_status,
            expires_at=excluded.expires_at,retain_until=max(retain_until,excluded.retain_until)""",
            (key, fact["ref"]["namespace"], fact["ref"]["key"], caller, fact["storage_epoch"], fact["custody_id"], fact["revision"], fact_digest,
             canonical_bytes(body["fact"]), "active", canonical_bytes(body["provider_node"]), canonical_bytes(index), reservation["lease_id"],
             canonical_bytes(body["publication_grant"]), grant_digest, canonical_bytes(body["owner_status"]), expires, lease["expires_at"] + 60))
        self.db.execute("UPDATE open_provider_resources SET requests_used=requests_used+1 WHERE lease_id=?", (reservation["lease_id"],))
        result = {"index_lease": index, "current_state": "active"}
        self._remember(caller, "provider.put", body["allocation_id"], operation_digest, result, expires)
        return result

    def _eligible(self, row, now):
        if row["status"] != "active" or row["expires_at"] <= now:
            return False
        resource = self._one("SELECT status,expires_at FROM open_provider_resources WHERE lease_id=?", (row["resource_id"],))
        if not resource or resource["status"] != "active" or resource["expires_at"] <= now:
            return False
        grant = document(bytes(row["grant_record"]))["payload"]
        floor = self._one("SELECT * FROM open_provider_status WHERE issuer=? AND root_digest=? AND scope_kind='authority' AND scope_id=?",
            (grant["root_key"]["owner"]["signing_key_id"], document_sha256(grant["root_key"]), authority_scope(grant["root_key"], "provider.publication.grant", row["grant_digest"])))
        if not floor or floor["conflict"] or floor["revoked_mask"] & PUBLISH or floor["valid_until"] <= now:
            return False
        entry = next(e for e in document(bytes(floor["record"]))["payload"]["entries"] if e["scope_kind"] == "authority" and e["scope_id"] == floor["scope_id"])
        if entry["minimum_document_revision"] > grant["revision"]:
            return False
        try:
            return verify_node(document(bytes(row["node"])), now=now)["status"] == "active"
        except MemoryError:
            return False

    def _get(self, rpc, now):
        if "directory" not in self.node["payload"]["roles"]:
            fail("provider_not_directory")
        body = rpc["body"]; ref = body["ref"]
        rows = self.db.execute("SELECT * FROM open_provider_facts WHERE namespace=? AND opaque_key=? AND fact_key>? ORDER BY fact_key LIMIT 33",
                               (ref["namespace"], ref["key"], body["after"] or ""))
        columns = [c[0] for c in rows.description]
        result = {"ref": ref, "observed_at": now, "entries": [], "nodes": [], "next_cursor": None, "state": "not_observed"}
        node_keys = set()
        for values in rows.fetchall():
            row = dict(zip(columns, values))
            if not self._eligible(row, now):
                continue
            candidate = {"fact": document(bytes(row["record"])), "index_lease": document(bytes(row["index_lease"]))}
            node = document(bytes(row["node"])); new_node = row["provider"] not in node_keys
            trial = {**result, "entries": result["entries"] + [candidate], "nodes": result["nodes"] + ([node] if new_node else []), "next_cursor": row["fact_key"], "state": "observed"}
            if len(result["entries"]) >= body["limit"] or len(canonical_bytes(trial)) + 2048 > body["maximum_bytes"]:
                if not result["entries"]:
                    fail("provider_response_budget")
                break
            result = trial; node_keys.add(row["provider"])
        # Pages are explicitly current observations, not consistent global
        # absence proofs. The final cursor may lead to one empty terminal page.
        return result

    def _withdraw(self, rpc, now):
        fact = verify_document(rpc["body"]["fact"], "provider.fact", now=now)
        if fact["signing_key"] != rpc["signing_key"]:
            fail("provider_wrong_publisher")
        key = self._fact_key(fact); row = self._one("SELECT * FROM open_provider_facts WHERE fact_key=?", (key,))
        if row is None:
            fail("provider_fact_not_found")
        digest = document_sha256(rpc["body"]["fact"])
        if fact["revision"] < row["revision"]:
            fail("provider_fact_rollback")
        if fact["revision"] == row["revision"] and digest != row["digest"]:
            self.db.execute("UPDATE open_provider_facts SET second_record=?,status='conflict' WHERE fact_key=?", (canonical_bytes(rpc["body"]["fact"]), key))
            return ProviderError("provider_fact_conflict")
        if row["status"] == "conflict":
            fail("provider_fact_conflict")
        self.db.execute("UPDATE open_provider_facts SET revision=?,digest=?,record=?,status='withdrawn' WHERE fact_key=?", (fact["revision"], digest, canonical_bytes(rpc["body"]["fact"]), key))
        return {"state": "withdrawn"}

    def _status(self, rpc, now):
        status = rpc["body"]["status"]; raw = verify_status(status, now=now)
        if raw["signing_key"] != rpc["signing_key"] or raw["scope_key"]["root_key"]["owner"]["signing_key_id"] != rpc["signing_key"]["key_id"]:
            fail("provider_wrong_issuer")
        root = raw["scope_key"]["root_key"]; grants = {}
        for row in self.db.execute("SELECT grant_digest,grant_record FROM open_provider_facts"):
            grant = document(bytes(row[1]))["payload"]
            if grant["root_key"] == root:
                grants[authority_scope(root, "provider.publication.grant", row[0])] = grant
        if any(e["scope_kind"] != "authority" or e["scope_id"] not in grants for e in raw["entries"]):
            fail("provider_unknown_status_scope")
        refusal = None
        for entry in raw["entries"]:
            result = self._observe(status, root=root, issuer=rpc["signing_key"]["key_id"], kind="authority",
                scope_id=entry["scope_id"], required_revision=grants[entry["scope_id"]]["revision"], now=now)
            if result is not None:
                refusal = result
        return refusal or {"state": "observed"}

    def _revoke(self, rpc, now):
        row = self._one("SELECT * FROM open_provider_resources WHERE lease_id=?", (rpc["body"]["lease_id"],))
        if row is None or row["owner"] != rpc["signing_key"]["key_id"]:
            fail("provider_wrong_owner")
        if row["status"] == "revoked":
            return {"status": document(bytes(row["status_record"])), "state": "revoked"}
        lease = document(bytes(row["record"]))["payload"]
        if now >= row["expires_at"]:
            fail("provider_resource_expired")
        status = issue_status(self.identity, root=lease["root_key"], revision=self._next_status_revision(lease["root_key"]),
            issued_at=now, valid_until=row["expires_at"], entries=[{"scope_kind": "resource", "scope_id": resource_scope(lease["root_key"], lease["resource"]),
            "minimum_document_revision": 1, "status": "revoked", "operation_mask": 127}])
        self.db.execute("UPDATE open_provider_resources SET status='revoked',status_record=? WHERE lease_id=?", (canonical_bytes(status), row["lease_id"]))
        return {"status": status, "state": "revoked"}

    def handle(self, request):
        """Return a strict body; the HTTP participant signs the outer response."""
        signed = document(request, maximum=MAX_CONTROL_BYTES); checked = verify_rpc(signed, node=self.node, now=self._now())
        if not self.enabled:
            fail("provider_closed")
        if checked["action"] == "target.get":
            now = self._now()
            return {"target": sign_document(self.identity, "provider.target", issued_at=now, expires_at=min(now + 600, self.node["payload"]["expires_at"]),
                node_key_id=self.identity.key_id, storage_epoch=self.node["payload"]["storage_epoch"], targetEncryptionKey=self.encryption_identity.public_descriptor())}
        if checked["action"] == "target.answer":
            body = checked["body"]
            if body["challenge"]["payload"]["signing_key"] != checked["signing_key"]:
                fail("provider_wrong_subject")
            # Purpose-separated real JWE decryption stays outside writer locks.
            if not _TARGET_SLOTS.acquire(blocking=False):
                fail("provider_challenge_capacity")
            try:
                return {"answer": answer_target_challenge(self.identity, self.encryption_identity, target=body["target"],
                    challenge=body["challenge"], node=self.node, now=self._now())}
            finally:
                _TARGET_SLOTS.release()
        operations = {"resource.allocate": self._allocate, "resource.revoke": self._revoke, "provider.put": self._put,
                      "provider.get": self._get, "provider.withdraw": self._withdraw, "provider.status": self._status}
        if checked["action"] == "provider.result":
            def read_result(rpc, now):
                row = self._one("SELECT * FROM open_provider_replay WHERE caller=? AND action=? AND allocation_id=?",
                    (rpc["signing_key"]["key_id"], rpc["body"]["operation"], rpc["body"]["allocation_id"]))
                if row is None:
                    fail("provider_result_not_found")
                result = document(bytes(row["result"]))
                return self._current_result(result, now)
            return self._transaction(signed, read_result)
        return self._transaction(signed, operations[checked["action"]])


    def collect_expired(self, *, limit=128):
        """Bounded local maintenance; never delete object/root custody here.

        Only provider_index reservations can be reclaimed by this directory.
        Other resource purposes require their owning storage lifecycle to
        release real dependencies and are deliberately retained by this method.
        """
        bounded(limit, 128)
        with self._lock:
            if self.db.in_transaction:
                fail("provider_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self._binding(); now = self._now(); removed = 0
                for table in ("open_provider_facts", "open_provider_replay"):
                    cursor = self.db.execute("DELETE FROM " + table + " WHERE rowid IN (SELECT rowid FROM " + table + " WHERE retain_until<=? ORDER BY retain_until LIMIT ?)", (now, limit))
                    removed += cursor.rowcount
                self.db.execute("""DELETE FROM open_provider_resources WHERE lease_id IN (
                    SELECT lease_id FROM open_provider_resources WHERE purpose='provider_index' AND retain_until<=?
                    AND lease_id NOT IN (SELECT resource_id FROM open_provider_facts) ORDER BY retain_until LIMIT ?)""", (now, limit))
                self.db.execute("""DELETE FROM open_provider_status WHERE rowid IN (
                    SELECT rowid FROM open_provider_status WHERE valid_until+60<=? AND root_digest NOT IN
                    (SELECT root_digest FROM open_provider_resources) LIMIT ?)""", (now, limit))
                self.db.commit()
                return {"removed_rows": removed}
            except BaseException:
                self.db.rollback(); raise
