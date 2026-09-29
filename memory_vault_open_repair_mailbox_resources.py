"""Original mailbox reservations in the node's existing protected database.

Local operator/setup operations only: callers must establish current admission
and dual-key possession before exposing these through a transport. An offer is
a durable capacity reservation, never mailbox activation or message custody.
ACK grants and contact/index leases cannot allocate these resources.
"""
from memory_vault import canonical_bytes
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import ROW_CHARGE, REPLAY_CHARGE


PURPOSES = frozenset(("anchor_catalog", "feed_metadata", "mailbox_data"))


class RepairMailboxResources:
    """Share node identity, transaction guard and capacity with the ACK service.

    Resource rows are disjoint from ACK rows. No ACK activation, binding,
    receipt upload or garbage collector can consume a mailbox reservation.
    """

    def __init__(self, source):
        self.source, self.db = source, source.db

    def initialize(self):
        self.source.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_resources(
                resource_id TEXT PRIMARY KEY,owner TEXT NOT NULL,allocation_id TEXT NOT NULL,
                purpose TEXT NOT NULL,request_digest TEXT NOT NULL,owner_keys BLOB NOT NULL,
                allocation BLOB NOT NULL,allocation_ref BLOB NOT NULL,
                offer BLOB NOT NULL,offer_ref BLOB NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','active')),
                reservation_until INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                metadata_bytes INTEGER NOT NULL,UNIQUE(owner,allocation_id))''')

    def _validate(self, entry, owner, budget):
        parsed, reference = self.source._entry(entry, budget)
        signed = resource._fields(parsed.value, {"payload", "proof"})
        p = resource._fields(signed["payload"], resource.COMMON | set(resource._FIELDS[0].split()))
        if p["schema_version"] != resource.SCHEMA or p["kind"] != "resource.allocate":
            wire._fail("repair_invalid_resource")
        resource._lifetime(p)
        original._opaque(p["request_id"])
        original._key_id(p["target_node_key_id"])
        original._opaque(p["target_storage_epoch"])
        original._digest(p["intent_sha256"])
        intent = resource._fields(p["intent"], resource._INTENT)
        if (intent["kind"] != "resource.owner_intent" or type(intent["purpose"]) is not str
                or intent["purpose"] not in PURPOSES):
            wire._fail("repair_invalid_resource")
        original._opaque(intent["allocation_id"])
        original._opaque(intent["target_storage_epoch"])
        history._root(intent["root_key"])
        owner_id = resource._dual_key(owner, budget)
        resource._dual_key_shape(intent["owner"])
        resource._dual_key_shape(intent["target"])
        resource._budget(intent["budget"])
        resource._windows(intent["windows"], issued=p["issued_at"])
        original._verify_control_signature(p, signed["proof"], owner["signing_key"], budget)
        if (intent["owner"] != owner or intent["root_key"]["owner"] != owner_id
                or intent["root_key"]["root_kind"] != "mailbox"
                or intent["target"] != self.source.target
                or intent["target_storage_epoch"] != self.source.node["payload"]["storage_epoch"]
                or p["target_node_key_id"] != self.source.identity.key_id
                or p["target_storage_epoch"] != intent["target_storage_epoch"]
                or p["intent_sha256"] != budget._hash(wire._canonical(intent, budget))):
            wire._fail("repair_resource_mismatch")
        return parsed, reference, p, owner_id

    def allocate(self, entry, *, expected_owner, _budget=None, _transaction_guard=None):
        """Commit one exact pending offer; retry never extends its deadline."""
        s = self.source
        with s._transaction(guard=_transaction_guard) as now:
            budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
            wire._context(s.policy, budget)
            owner = wire.build_new_wire(expected_owner, s.policy, budget).value
            checked = self._validate(entry, owner, budget)
            return self._allocate(checked, owner, budget, now)

    def allocate_initial(self, entries, *, expected_owner, _budget=None, _transaction_guard=None):
        """Reserve all three initial mailbox resources atomically, or none.

        Exact retries return original offers, including expired offers; they do
        not imply that the caller can still activate them. New attempts need new
        allocation IDs and independently funded reservations.
        """
        if type(entries) not in (list, tuple) or len(entries) != 3:
            wire._fail("repair_invalid_resource")
        s = self.source
        with s._transaction(guard=_transaction_guard) as now:
            budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
            wire._context(s.policy, budget)
            owner = wire.build_new_wire(expected_owner, s.policy, budget).value
            checked = [self._validate(entry, owner, budget) for entry in entries]
            intents = [item[2]["intent"] for item in checked]
            if ({i["purpose"] for i in intents} != PURPOSES
                    or len({i["allocation_id"] for i in intents}) != 3
                    or any(i["root_key"] != intents[0]["root_key"] for i in intents)):
                wire._fail("repair_resource_mismatch")
            return {item[2]["intent"]["purpose"]: self._allocate(item, owner, budget, now)
                    for item in checked}

    def _allocate(self, checked, owner, budget, now):
        s = self.source
        parsed, reference, p, owner_id = checked
        intent, caps = p["intent"], p["intent"]["budget"]
        digest = budget._hash(wire._canonical(reference.as_dict(), budget))
        old = s._one("SELECT * FROM open_repair_mailbox_resources WHERE owner=? AND allocation_id=?",
                     (owner_id["signing_key_id"], intent["allocation_id"]))
        if old is not None:
            if old["request_digest"] != digest:
                wire._fail("repair_allocation_conflict")
            return s._saved(old, "offer")
        if not p["issued_at"] <= now < p["expires_at"] or min(intent["windows"].values()) <= now:
            wire._fail("repair_resource_expired")
        if (min(caps[name] for name in ("max_meta_bytes", "max_items", "max_requests",
                "max_pending", "max_replay_records")) <= 0
                or (intent["purpose"] == "mailbox_data" and caps["max_live_bytes"] <= 0)):
            wire._fail("repair_insufficient_capacity")
        token = budget._hash(("mailbox:" + s._expected_binding() + ":" +
                              owner_id["signing_key_id"] + ":" + digest).encode())
        resource_ref = dict(node_key_id=s.identity.key_id, storage_epoch=intent["target_storage_epoch"],
                            lease_id="lease_" + token, resource_id="resource_" + token)
        reservation_until = min(now + 60, p["expires_at"])
        charge = (caps["max_live_bytes"] + caps["max_meta_bytes"] + caps["max_job_bytes"]
                  + caps["max_replay_records"] * REPLAY_CHARGE + ROW_CHARGE)
        s.capacity.reserve("mailbox", resource_ref["resource_id"], digest, charge,
                           intent["windows"]["retain_until"], owner=owner_id["signing_key_id"],
                           operation_id=intent["allocation_id"])
        offer = s._sign(dict(schema_version=resource.SCHEMA, kind="resource.offer",
            signing_key=s.identity.public_descriptor(), issued_at=now,
            reservation_until=reservation_until, offer_id="offer_" + token,
            allocation_request_ref=reference.as_dict(), intent=intent,
            intent_sha256=p["intent_sha256"], resource=resource_ref,
            target_encryption_key=s.encryption_identity.public_descriptor(),
            reservation_generation=1, budget=caps, windows=intent["windows"]), "mailbox_offer", budget)
        owner_raw = canonical_bytes(owner)
        metadata = len(owner_raw) + len(parsed.raw) + len(offer["raw"]) + 3 * ROW_CHARGE
        if metadata > caps["max_meta_bytes"]:
            wire._fail("repair_insufficient_capacity")
        self.db.execute('''INSERT INTO open_repair_mailbox_resources(
            resource_id,owner,allocation_id,purpose,request_digest,owner_keys,allocation,
            allocation_ref,offer,offer_ref,status,reservation_until,retain_until,metadata_bytes)
            VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?,?)''',
            (resource_ref["resource_id"], owner_id["signing_key_id"], intent["allocation_id"],
             intent["purpose"], digest, owner_raw, parsed.raw, canonical_bytes(reference.as_dict()),
             offer["raw"], canonical_bytes(offer["ref"]), reservation_until,
             intent["windows"]["retain_until"], metadata))
        return offer
