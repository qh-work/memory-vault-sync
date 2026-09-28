"""Transactional ACK source storage in the existing protected transport DB.

These are local node operations. HTTP callers still require the finite current
authorization and dual-key possession exchange before invoking them. No method
opens a Vault, creates another database or treats a historical proof as access.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import threading
import time

from memory_vault import canonical_bytes
from memory_vault_open_control import verify_node
from memory_vault_open_capacity import CapacityAuthority
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


DEFAULT_LIMITS = dict(max_probe_bytes=8192, max_proof_bytes=262144, max_proof_items=64,
    max_signature_checks=512, max_requests=64, max_pending=8, max_replay_records=128,
    max_concurrent_handles=8, max_candidate_attempts=8)
DEFAULT_POLICY = wire.RepairPolicy(524288, 16000000, 400000, 64, 262144,
                                  16000000, 2000, 2000, 16000000, 64)
ROW_CHARGE = 4096
REPLAY_CHARGE = 32768


def _fail(code):
    raise wire.RepairWireError(code)


class RepairAckState:
    def __init__(self, db, identity, node, *, encryption_identity, policy=DEFAULT_POLICY,
                 limit_policy=None, capacity_policy=None, clock=None):
        checked = verify_node(node, now=node["payload"]["issued_at"])
        if checked["signing_key"] != identity.public_descriptor():
            _fail("repair_wrong_node")
        self.db, self.identity, self.encryption_identity = db, identity, encryption_identity
        self.node = json.loads(canonical_bytes(node))
        self.policy = policy
        budget = wire.RepairBudget(policy)
        self.limits = wire.build_new_wire(DEFAULT_LIMITS if limit_policy is None else limit_policy, policy, budget).value
        bootstrap._limits(self.limits)
        self.capacity = CapacityAuthority(db, policy=capacity_policy)
        self.clock = clock or time.time
        self._lock = threading.RLock()

    @property
    def target(self):
        return dict(signing_key=self.identity.public_descriptor(),
                    encryption_key=self.encryption_identity.public_descriptor())

    def _now(self):
        return wire.u53(int(self.clock()))

    def _one(self, sql, args=()):
        cursor = self.db.execute(sql, args)
        row = cursor.fetchone()
        return None if row is None else dict(zip((column[0] for column in cursor.description), row))

    def _expected_binding(self):
        return self.identity.key_id + ":" + self.node["payload"]["storage_epoch"] + ":" + self.encryption_identity.key_id

    def _binding(self):
        row = self._one("SELECT value FROM open_repair_state WHERE name='binding'")
        if row is None or row["value"] != self._expected_binding():
            _fail("repair_storage_epoch_mismatch")

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self.db.in_transaction:
                _fail("repair_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self._binding()
                self.capacity.check_policy()
                yield self._now()
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def initialize(self):
        with self._lock:
            if self.db.in_transaction:
                _fail("repair_storage_transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for sql in (
                    "CREATE TABLE IF NOT EXISTS open_repair_state(name TEXT PRIMARY KEY,value TEXT NOT NULL)",
                    """CREATE TABLE IF NOT EXISTS open_repair_ack_resources(
                        resource_id TEXT PRIMARY KEY,owner TEXT NOT NULL,allocation_id TEXT NOT NULL,
                        request_digest TEXT NOT NULL,owner_keys BLOB NOT NULL,allocation BLOB NOT NULL,
                        allocation_ref BLOB NOT NULL,offer BLOB NOT NULL,offer_ref BLOB NOT NULL,
                        status TEXT NOT NULL,reservation_until INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                        activation_digest TEXT,activation_inputs BLOB,active BLOB,active_ref BLOB,
                        source_status BLOB,source_status_ref BLOB,final_digest TEXT,custody BLOB,custody_ref BLOB,
                        manifest_ref BLOB,metadata_bytes INTEGER NOT NULL DEFAULT 0,
                        UNIQUE(owner,allocation_id))""",
                    """CREATE TABLE IF NOT EXISTS open_repair_ack_objects(
                        namespace TEXT NOT NULL,opaque_key TEXT NOT NULL,raw_sha256 TEXT NOT NULL,
                        size INTEGER NOT NULL,raw BLOB NOT NULL,PRIMARY KEY(namespace,opaque_key))""",
                    """CREATE TABLE IF NOT EXISTS open_repair_ack_pins(
                        resource_id TEXT NOT NULL,namespace TEXT NOT NULL,opaque_key TEXT NOT NULL,
                        role TEXT NOT NULL,PRIMARY KEY(resource_id,namespace,opaque_key,role))""",
                ):
                    self.db.execute(sql)
                binding = self._one("SELECT value FROM open_repair_state WHERE name='binding'")
                if binding is None:
                    if any(self._one("SELECT 1 FROM " + table + " LIMIT 1") for table in
                           ("open_repair_ack_resources", "open_repair_ack_objects", "open_repair_ack_pins")):
                        _fail("repair_storage_binding_missing")
                    self.db.execute("INSERT INTO open_repair_state VALUES('binding',?)", (self._expected_binding(),))
                self._binding()
                self.capacity.initialize()
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def _entry(self, value, budget):
        raw, ref = ack._entry(value)
        parsed = wire.parse_new_wire(raw, self.policy, budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            _fail("repair_ref_mismatch")
        return parsed, ref

    def _sign(self, payload, name, budget):
        signed = dict(payload=payload, proof=self.identity.sign_message(payload))
        raw = wire.build_new_wire(signed, self.policy, budget).raw
        digest = budget._hash(raw)
        key = budget._hash(("memory-vault-repair-meta/v1:" + name + ":" + digest).encode())
        return dict(raw=raw, ref=dict(namespace="meta", key=key, raw_sha256=digest, size=len(raw)))

    def _saved(self, row, name):
        raw, ref = bytes(row[name]), json.loads(bytes(row[name + "_ref"]))
        checked = wire.RawRef(**ref)
        if len(raw) != checked.size or hashlib.sha256(raw).hexdigest() != checked.raw_sha256:
            _fail("repair_storage_corrupt")
        return dict(raw=raw, ref=ref)

    def _row(self, resource_id):
        original._opaque(resource_id)
        row = self._one("SELECT * FROM open_repair_ack_resources WHERE resource_id=?", (resource_id,))
        if row is None:
            _fail("repair_unknown_resource")
        return row

    def allocate(self, allocation_entry, *, expected_owner):
        """Reserve node capacity and commit the exact offer before returning it."""
        with self._transaction() as now:
            budget = wire.RepairBudget(self.policy)
            owner = wire.build_new_wire(expected_owner, self.policy, budget).value
            resource._dual_key(owner, budget)
            parsed, allocation_ref = self._entry(allocation_entry, budget)
            signed = resource._fields(parsed.value, {"payload", "proof"})
            payload = resource._fields(signed["payload"], resource.COMMON | set(resource._FIELDS[0].split()))
            if payload["schema_version"] != resource.SCHEMA or payload["kind"] != "resource.allocate":
                _fail("repair_invalid_resource")
            resource._role_shape("allocate", payload)
            original._verify_control_signature(payload, signed["proof"], owner["signing_key"], budget)
            intent = payload["intent"]
            root = intent["root_key"]
            owner_id = dict(signing_key_id=owner["signing_key"]["key_id"], encryption_key_id=owner["encryption_key"]["key_id"])
            if (intent["owner"] != owner or root["owner"] != owner_id or intent["target"] != self.target or
                    intent["target_storage_epoch"] != self.node["payload"]["storage_epoch"] or
                    payload["target_node_key_id"] != self.identity.key_id or
                    payload["target_storage_epoch"] != self.node["payload"]["storage_epoch"] or
                    intent["purpose"] != "ack_slot" or root["root_kind"] != "ack_return" or
                    payload["intent_sha256"] != budget._hash(wire._canonical(intent, budget))):
                _fail("repair_resource_mismatch")
            digest = budget._hash(wire._canonical(allocation_ref.as_dict(), budget))
            old = self._one("SELECT * FROM open_repair_ack_resources WHERE owner=? AND allocation_id=?",
                            (owner_id["signing_key_id"], intent["allocation_id"]))
            if old is not None:
                if old["request_digest"] != digest:
                    _fail("repair_allocation_conflict")
                return self._saved(old, "offer")
            if not payload["issued_at"] <= now < payload["expires_at"] or min(intent["windows"].values()) <= now:
                _fail("repair_resource_expired")
            caps = intent["budget"]
            if min(caps["max_meta_bytes"], caps["max_items"], caps["max_requests"], caps["max_pending"], caps["max_replay_records"]) <= 0:
                _fail("repair_insufficient_capacity")
            token = budget._hash((self._expected_binding() + ":" + owner_id["signing_key_id"] + ":" + digest).encode())
            resource_ref = dict(node_key_id=self.identity.key_id, storage_epoch=self.node["payload"]["storage_epoch"],
                                lease_id="lease_" + token, resource_id="resource_" + token)
            reservation_until = min(now + 60, payload["expires_at"])
            charge = caps["max_live_bytes"] + caps["max_meta_bytes"] + caps["max_job_bytes"] + caps["max_replay_records"] * REPLAY_CHARGE + ROW_CHARGE
            self.capacity.reserve("ack", resource_ref["resource_id"], digest, charge, intent["windows"]["retain_until"],
                                  owner=owner_id["signing_key_id"], operation_id=intent["allocation_id"])
            offer = self._sign(dict(schema_version=resource.SCHEMA, kind="resource.offer", signing_key=self.identity.public_descriptor(),
                issued_at=now, reservation_until=reservation_until, offer_id="offer_" + token,
                allocation_request_ref=allocation_ref.as_dict(), intent=intent, intent_sha256=payload["intent_sha256"],
                resource=resource_ref, target_encryption_key=self.encryption_identity.public_descriptor(),
                reservation_generation=1, budget=caps, windows=intent["windows"]), "offer", budget)
            owner_raw = canonical_bytes(owner)
            metadata = len(owner_raw) + len(parsed.raw) + len(offer["raw"]) + 3*ROW_CHARGE
            if metadata > caps["max_meta_bytes"]:
                _fail("repair_insufficient_capacity")
            self.db.execute("""INSERT INTO open_repair_ack_resources(resource_id,owner,allocation_id,request_digest,owner_keys,
                allocation,allocation_ref,offer,offer_ref,status,reservation_until,retain_until,metadata_bytes) VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?,?)""",
                (resource_ref["resource_id"], owner_id["signing_key_id"], intent["allocation_id"], digest, canonical_bytes(owner),
                 parsed.raw, canonical_bytes(allocation_ref.as_dict()), offer["raw"], canonical_bytes(offer["ref"]),
                 reservation_until, intent["windows"]["retain_until"], metadata))
            return offer

    def activate(self, resource_id, entries, *, expected_ack_slot):
        """Commit bounded owner originals and the exact active/status originals."""
        with self._transaction() as now:
            row = self._row(resource_id)
            budget = wire.RepairBudget(self.policy)
            resource._fields(entries, {"root", "read", "bootstrap", "activation"})
            snapped, refs = {}, {}
            for name in ("root", "read", "bootstrap", "activation"):
                parsed, ref = self._entry(entries[name], budget)
                snapped[name] = dict(raw=parsed.raw, ref=ref.as_dict())
                refs[name] = ref.as_dict()
            slot = ack._fields(wire.build_new_wire(expected_ack_slot, self.policy, budget).value,
                               {"root_key", "slot_id", "receipt_writer", "grant_id"})
            resource._shape(resource.history._slot, slot, slot["root_key"], ack=True)
            digest = budget._hash(wire._canonical(dict(refs=refs, ack_slot=slot), budget))
            if row["activation_digest"] is not None:
                if row["activation_digest"] != digest:
                    _fail("repair_activation_conflict")
                return dict(active=self._saved(row, "active"), status=self._saved(row, "source_status"))
            if row["status"] != "pending" or now >= row["reservation_until"]:
                _fail("repair_resource_inactive")
            offer = self._saved(row, "offer")
            offer_payload = wire.parse_new_wire(offer["raw"], self.policy, budget).value["payload"]
            active = self._sign(dict(schema_version=resource.SCHEMA, kind="resource.active", signing_key=self.identity.public_descriptor(),
                activated_at=now, offer_ref=offer["ref"], activation_ref=refs["activation"], resource=offer_payload["resource"],
                reservation_generation=offer_payload["reservation_generation"], root_key=offer_payload["intent"]["root_key"],
                purpose="ack_slot", budget=offer_payload["budget"], windows=offer_payload["windows"]), "active", budget)
            owner = json.loads(bytes(row["owner_keys"]))
            resource.verify_ack_resource_inputs(dict(allocate=self._saved(row, "allocation"), offer=offer,
                root=snapped["root"], read=snapped["read"], activation=snapped["activation"], active=active),
                expected_ack_slot=slot, expected_owner=owner, expected_target=self.target,
                target_storage_epoch=self.node["payload"]["storage_epoch"], policy=self.policy, budget=budget)
            boot = bootstrap.verify_ack_owner_bootstrap_original(snapped["bootstrap"],
                {name: snapped[name] for name in ("root", "read")}, expected_ack_slot=slot,
                expected_owner=owner, at=now, limit_policy=self.limits, policy=self.policy, budget=budget)
            activation = wire.parse_new_wire(snapped["activation"]["raw"], self.policy, budget).value["payload"]
            grant = boot.originals["bootstrap"].payload
            if (grant["issued_at"] > activation["issued_at"] or
                    min(offer_payload["windows"].values()) <= now or
                    min(grant[name] for name in ("probe_until", "proof_until", "upload_until")) <= now):
                _fail("repair_ack_mismatch")
            scope = status.status_scope(offer_payload["intent"]["root_key"], "resource", offer_payload["resource"], self.policy, budget)
            source_status = self._sign(dict(schema_version=status.SCHEMA, kind="authority.status", signing_key=self.identity.public_descriptor(),
                scope_key=dict(root_key=offer_payload["intent"]["root_key"], issuer_key_id=self.identity.key_id), revision=1,
                issued_at=now, valid_until=min(offer_payload["windows"]["retain_until"], now + status.MAX_STATUS_SECONDS), entries=[dict(scope_kind="resource", scope_id=scope,
                minimum_document_revision=1, status="active", operation_mask=127)]), "resource-status", budget)
            stored = {name: dict(raw=snapped[name]["raw"].decode(), ref=snapped[name]["ref"]) for name in snapped}
            metadata = row["metadata_bytes"] + sum(len(snapped[name]["raw"]) + ROW_CHARGE for name in snapped) + len(active["raw"]) + len(source_status["raw"]) + 2*ROW_CHARGE
            if metadata > offer_payload["budget"]["max_meta_bytes"]:
                _fail("repair_insufficient_capacity")
            self.db.execute("""UPDATE open_repair_ack_resources SET status='active',activation_digest=?,activation_inputs=?,active=?,active_ref=?,
                source_status=?,source_status_ref=?,metadata_bytes=? WHERE resource_id=?""", (digest, canonical_bytes(stored), active["raw"],
                canonical_bytes(active["ref"]), source_status["raw"], canonical_bytes(source_status["ref"]), metadata, resource_id))
            return dict(active=active, status=source_status)

    def finalize_unbound(self, resource_id, manifest_entry, packs, *, expected_ack_slot, read_until, retain_until):
        """Atomically pin the complete source closure and return its saved custody."""
        with self._transaction() as now:
            row = self._row(resource_id)
            budget = wire.RepairBudget(self.policy)
            manifest, manifest_ref = self._entry(manifest_entry, budget)
            wire.u53(read_until); wire.u53(retain_until)
            slot = ack._fields(wire.build_new_wire(expected_ack_slot, self.policy, budget).value,
                               {"root_key", "slot_id", "receipt_writer", "grant_id"})
            resource._shape(resource.history._slot, slot, slot["root_key"], ack=True)
            digest = budget._hash(wire._canonical(dict(manifest=manifest_ref.as_dict(),
                ack_slot=slot, read_until=read_until, retain_until=retain_until), budget))
            if row["final_digest"] is not None:
                if row["final_digest"] != digest:
                    _fail("repair_custody_conflict")
                return self._saved(row, "custody")
            if row["status"] != "active":
                _fail("repair_resource_inactive")
            if type(packs) not in (list, tuple) or not 1 <= len(packs) <= self.policy.max_entries:
                _fail("repair_invalid_pack")
            resolver = wire.LocalRawResolver(self.policy, budget)
            held_packs = []
            for packed in packs:
                body, ref = ack._entry(packed)
                found = resolver.put(ref.namespace, ref.key, body)
                if found.ref != ref:
                    _fail("repair_ref_mismatch")
                held_packs.append(found)
            active = wire.parse_new_wire(self._saved(row, "active")["raw"], self.policy, budget).value["payload"]
            custody = self._sign(dict(schema_version=resource.SCHEMA, kind="ack.slot_custody", signing_key=self.identity.public_descriptor(),
                ack_slot=slot, root_authority_ref=manifest.value["root_authority_ref"], historical_manifest_ref=manifest_ref.as_dict(),
                resource_ref=active["resource"], stored_at=now, read_until=read_until, retain_until=retain_until, state="unbound"), "custody", budget)
            checked = ack.verify_ack_unbound_source_event(dict(raw=manifest.raw, ref=manifest_ref.as_dict()), resolver, custody,
                expected_ack_slot=slot, expected_owner=json.loads(bytes(row["owner_keys"])), expected_target=self.target,
                target_storage_epoch=self.node["payload"]["storage_epoch"], limit_policy=self.limits, policy=self.policy, budget=budget)
            setup = json.loads(bytes(row["activation_inputs"]))
            exact = {"resource.ack_allocate": self._saved(row, "allocation"), "resource.ack_offer": self._saved(row, "offer"),
                     "resource.ack_active": self._saved(row, "active"), "historical.status.ack_resource": self._saved(row, "source_status")}
            for role, name in (("ack.root_authority", "root"), ("ack.read_grant", "read"),
                               ("bootstrap.ack_owner", "bootstrap"), ("resource.ack_activation", "activation")):
                exact[role] = dict(raw=setup[name]["raw"].encode(), ref=setup[name]["ref"])
            used_packs = set()
            objects = []
            for role in checked.manifest.roles:
                if role.role in exact and (role.original.raw != exact[role.role]["raw"] or role.original.ref.as_dict() != exact[role.role]["ref"]):
                    _fail("repair_local_original_mismatch")
                objects.append((role.original, role.role))
            for role in checked.manifest.manifest.value["roles"]:
                used_packs.add(wire.raw_ref(role["pack_ref"]))
            if {item.ref for item in held_packs} != used_packs or len(held_packs) != len(used_packs):
                _fail("repair_unused_pack")
            objects.extend((item, "pack") for item in held_packs)
            objects.extend(((wire.RawOriginal(manifest_ref, manifest.raw), "manifest"),
                            (wire.RawOriginal(wire.RawRef(**custody["ref"]), custody["raw"]), "custody")))
            unique = {item.ref: item.raw for item, _ in objects}
            charge = row["metadata_bytes"] + sum(len(raw) + ROW_CHARGE for raw in unique.values()) + len(objects)*256
            if charge > active["budget"]["max_meta_bytes"] or len(unique) > active["budget"]["max_items"]:
                _fail("repair_insufficient_capacity")
            for item, role in objects:
                ref = item.ref
                prior = self._one("SELECT * FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?", (ref.namespace, ref.key))
                if prior is None:
                    self.db.execute("INSERT INTO open_repair_ack_objects VALUES(?,?,?,?,?)",
                                    (ref.namespace, ref.key, ref.raw_sha256, ref.size, item.raw))
                elif (prior["raw_sha256"] != ref.raw_sha256 or prior["size"] != ref.size or bytes(prior["raw"]) != item.raw):
                    _fail("repair_ref_conflict")
                self.db.execute("INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)", (resource_id, ref.namespace, ref.key, role))
            self.db.execute("""UPDATE open_repair_ack_resources SET status='unbound',final_digest=?,custody=?,custody_ref=?,
                manifest_ref=?,metadata_bytes=? WHERE resource_id=?""", (digest, custody["raw"], canonical_bytes(custody["ref"]),
                canonical_bytes(manifest_ref.as_dict()), charge, resource_id))
            return custody

    def read_local_original(self, resource_id, reference):
        """Return an exact pinned local original; supplies no remote read right."""
        with self._transaction():
            row = self._row(resource_id)
            if row["status"] != "unbound":
                _fail("repair_resource_inactive")
            ref = ack._ref(reference)
            found = self._one("""SELECT o.* FROM open_repair_ack_objects o JOIN open_repair_ack_pins p
                ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.resource_id=? AND o.namespace=? AND o.opaque_key=? LIMIT 1""",
                (resource_id, ref.namespace, ref.key))
            if found is None:
                _fail("repair_ref_missing")
            raw = bytes(found["raw"])
            if found["raw_sha256"] != ref.raw_sha256 or found["size"] != ref.size or len(raw) != ref.size or hashlib.sha256(raw).hexdigest() != ref.raw_sha256:
                _fail("repair_storage_corrupt")
            return raw
