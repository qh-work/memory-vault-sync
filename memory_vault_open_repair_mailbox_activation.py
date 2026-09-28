"""Atomic original data/metadata resource activation for one mailbox slot.

This local setup stage persists the exact owner chain and both node activation
events together. It is not a ready mailbox: genesis, current observations and
root custody must commit before a caller can publish or use a cold entry.
"""
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import ROW_CHARGE


FIELDS = {
    "maintenance": "issued_at expires_at root_key authority_id slot_key sender recipient maintainers operation_mask allowed_roles budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision",
    "read": "issued_at expires_at grant_id root_key slot_key reader serving_authority_id operation_mask budget windows revision",
    "slot": "issued_at expires_at revision slot_key feed_ref sender recipient data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref max_appends max_live_items budget windows",
    "bootstrap": "issued_at expires_at grant_id revision owner subject root_key consumer selector parent_authority_ref caller_authority_ref probe_until proof_until upload_until probe_profile response_profile upload_roles limits",
    "activation": resource._FIELDS[4],
}
KINDS = dict(maintenance="mailbox.maintenance_root", read="mailbox.read_grant",
             slot="mailbox.slot", bootstrap="bootstrap.grant", activation="resource.activation")
UPLOAD_ROLES = frozenset(("mailbox.slot", "mailbox.read_grant", "mailbox.maintenance_root", "bootstrap.grant"))


def _mismatch():
    wire._fail("repair_mailbox_activation_mismatch")


def _ordered(values, key, check):
    resource._array(values)
    previous = None
    for value in values:
        check(value)
        current = key(value)
        if previous is not None and current <= previous:
            _mismatch()
        previous = current


def _role(value):
    if type(value) is not str or value not in resource.KNOWN_ALLOWED_ROLES:
        _mismatch()


class MailboxSlotActivation:
    def __init__(self, resources):
        self.resources, self.source, self.db = resources, resources.source, resources.db

    def initialize(self):
        self.resources.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_slot_activations(
                slot_digest TEXT PRIMARY KEY,owner TEXT NOT NULL,activation_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,inputs BLOB NOT NULL,
                data_resource_id TEXT NOT NULL UNIQUE,metadata_resource_id TEXT NOT NULL UNIQUE,
                data_active BLOB NOT NULL,data_active_ref BLOB NOT NULL,
                metadata_active BLOB NOT NULL,metadata_active_ref BLOB NOT NULL,
                activated_at INTEGER NOT NULL,UNIQUE(owner,activation_id))''')

    def _originals(self, entries, owner, budget, now):
        resource._fields(entries, FIELDS)
        held, payloads = {}, {}
        for name in FIELDS:
            parsed, ref = self.source._entry(entries[name], budget)
            signed = resource._fields(parsed.value, {"payload", "proof"})
            p = resource._fields(signed["payload"], resource.COMMON | set(FIELDS[name].split()))
            if p["schema_version"] != resource.SCHEMA or p["kind"] != KINDS[name]:
                _mismatch()
            resource._lifetime(p)
            if not p["issued_at"] <= now < p["expires_at"]:
                wire._fail("repair_resource_expired")
            original._verify_control_signature(p, signed["proof"], owner["signing_key"], budget)
            held[name], payloads[name] = dict(raw=parsed.raw, ref=ref.as_dict()), p
        return held, payloads

    def _check(self, held, p, slot_key, owner, offers, budget, now):
        s = self.source
        root = slot_key["root_key"]
        owner_id = resource._dual_key(owner, budget)
        maintenance, read, slot, grant, activation = (p[k] for k in FIELDS)
        if (root["owner"] != owner_id or slot_key["writer"] != resource._dual_key(s.target, budget)
                or slot_key["writer_storage_epoch"] != s.node["payload"]["storage_epoch"]):
            _mismatch()
        for name in ("maintenance", "read", "slot"):
            value = p[name]
            history._slot(value["slot_key"], root)
            resource._budget(value["budget"])
            resource._windows(value["windows"], issued=value["issued_at"], expires=value["expires_at"])
            wire.u53(value["revision"])
            if value["slot_key"] != slot_key or (name != "slot" and value["root_key"] != root):
                _mismatch()
        for value in (maintenance, read):
            resource._opmask(value["operation_mask"])
        for value in (maintenance, slot):
            history._dual(value["sender"]); history._dual(value["recipient"])
            if value["recipient"] != owner_id:
                _mismatch()
        history._dual(read["reader"])
        for value in (maintenance["authority_id"], read["grant_id"], read["serving_authority_id"]):
            original._opaque(value)
        if (read["reader"] != owner_id or slot["sender"] != maintenance["sender"]
                or read["serving_authority_id"] != maintenance["authority_id"]
                or slot["read_grant_ref"] != held["read"]["ref"]
                or slot["maintenance_root_ref"] != held["maintenance"]["ref"]):
            _mismatch()
        resource._fields(slot["feed_ref"], {"namespace", "key"})
        if slot["feed_ref"]["namespace"] != "feed":
            _mismatch()
        original._digest(slot["feed_ref"]["key"])
        if not 1 <= wire.u53(slot["max_live_items"]) <= wire.u53(slot["max_appends"], 1) <= 65536:
            _mismatch()
        if slot["max_live_items"] > slot["budget"]["max_items"]:
            _mismatch()
        if wire.u53(maintenance["max_delegate_depth"]) != 2:
            _mismatch()
        wire.u53(maintenance["max_destinations_per_job"])
        wire.u53(maintenance["max_concurrent_jobs"])
        _ordered(maintenance["maintainers"], lambda v: (v["signing_key_id"], v["encryption_key_id"]), history._dual)
        _ordered(maintenance["allowed_roles"], lambda v: v, _role)
        if (maintenance["operation_mask"] & 10 != 10 or read["operation_mask"] & 2 != 2
                or read["operation_mask"] & ~maintenance["operation_mask"]
                or not {"bootstrap.grant", "selected_slot_service_v1"} <= set(maintenance["allowed_roles"])
                or any(read["budget"][k] > maintenance["budget"][k] for k in resource._BUDGET)
                or any(read["windows"][k] > maintenance["windows"][k] for k in resource._WINDOWS)
                or read["expires_at"] > maintenance["expires_at"]):
            _mismatch()
        for name, purpose in (("data", "mailbox_data"), ("metadata", "feed_metadata")):
            offer = offers[name]
            value = wire.parse_new_wire(offer["raw"], s.policy, budget).value["payload"]
            intent = value["intent"]
            if (slot[name+"_resource_ref"] != value["resource"]
                    or slot[name+"_resource_offer_ref"] != offer["ref"]
                    or intent["purpose"] != purpose or intent["root_key"] != root
                    or intent["owner"] != owner or intent["target"] != s.target
                    or value["issued_at"] > min(p[k]["issued_at"] for k in ("maintenance", "read", "slot"))
                    or min(intent["windows"].values()) <= now):
                _mismatch()
        # The read/maintenance grants may outlive a particular resource. The
        # later custody promise intersects their windows with the actual lease.
        resource._fields(grant["selector"], {"root_key_sha256", "slot_key_sha256", "feed_ref",
                                           "slot_sha256", "read_grant_sha256", "maintenance_root_sha256"})
        original._opaque(grant["grant_id"]); wire.u53(grant["revision"])
        if (grant["owner"] != owner_id or grant["subject"] != owner_id or grant["root_key"] != root
                or grant["consumer"] != "mailbox_feed" or grant["probe_profile"] != "opaque_v1"
                or grant["response_profile"] != "selected_slot_service_v1"
                or grant["parent_authority_ref"] != held["maintenance"]["ref"]
                or grant["caller_authority_ref"] != held["read"]["ref"]
                or grant["selector"] != dict(root_key_sha256=budget._hash(wire._canonical(root, budget)),
                    slot_key_sha256=budget._hash(wire._canonical(slot_key, budget)), feed_ref=slot["feed_ref"],
                    slot_sha256=held["slot"]["ref"]["raw_sha256"], read_grant_sha256=held["read"]["ref"]["raw_sha256"],
                    maintenance_root_sha256=held["maintenance"]["ref"]["raw_sha256"])):
            _mismatch()
        _ordered(grant["upload_roles"], lambda v: v, _role)
        if not set(grant["upload_roles"]) <= UPLOAD_ROLES & set(maintenance["allowed_roles"]):
            _mismatch()
        bootstrap._limits(grant["limits"])
        for key, parent_fields in bootstrap._PARENT_CAPS.items():
            value = grant["limits"][key]
            if value > s.limits[key] or any(value > parent["budget"][field]
                    for parent in (maintenance, read) for field in parent_fields):
                _mismatch()
        if not (maintenance["issued_at"] <= read["issued_at"] <= slot["issued_at"]
                <= grant["issued_at"] <= activation["issued_at"] <= now
                and grant["expires_at"] <= min(maintenance["expires_at"], read["expires_at"])):
            _mismatch()
        for key in ("probe_until", "proof_until", "upload_until"):
            if not now < wire.u53(grant[key]) <= grant["expires_at"]:
                _mismatch()
        if any(grant[key] > parent["windows"][window] for key in ("proof_until", "upload_until")
               for parent in (maintenance, read) for window in ("read_until", "retain_until")):
            _mismatch()
        original._opaque(activation["activation_id"])
        expected_offers = sorted((offer["ref"] for offer in offers.values()), key=history._ref_tuple)
        expected_authorities = [{"role": KINDS[name], "ref": held[name]["ref"]}
                                for name in ("maintenance", "read", "slot")]
        if (activation["subject"] != owner or activation["target_node_key_id"] != s.identity.key_id
                or activation["target_storage_epoch"] != slot_key["writer_storage_epoch"]
                or activation["root_key"] != root
                or activation["scope"] != dict(kind="mailbox_slot", slot_key=slot_key, slot_ref=held["slot"]["ref"])
                or activation["resource_offer_refs"] != expected_offers
                or activation["authority_refs"] != expected_authorities):
            _mismatch()

    def activate(self, entries, *, expected_slot, _budget=None, _transaction_guard=None):
        """Persist the stage, not a genesis/head/custody or network-ready result."""
        s = self.source
        deadlines = []
        def guard():
            if _transaction_guard is not None:
                code = _transaction_guard()
                if code:
                    return code
            if deadlines and s._now() >= min(deadlines):
                return "repair_resource_expired"
            return None
        with s._transaction(guard=guard) as now:
            budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
            wire._context(s.policy, budget)
            slot_key = wire.build_new_wire(expected_slot, s.policy, budget).value
            history._slot(slot_key, slot_key["root_key"])
            slot_digest = budget._hash(wire._canonical(slot_key, budget))
            resource._fields(entries, FIELDS)
            snapped = {}
            for name in FIELDS:
                parsed, ref = s._entry(entries[name], budget)
                snapped[name] = dict(raw=parsed.raw, ref=ref.as_dict())
            entries = snapped
            # Parse only bounded originals before selecting the local resources.
            draft, _ = s._entry(entries["slot"], budget)
            signed = resource._fields(draft.value, {"payload", "proof"})
            slot = resource._fields(signed["payload"], resource.COMMON | set(FIELDS["slot"].split()))
            rows, offers = {}, {}
            for name in ("data", "metadata"):
                history._resource(slot[name+"_resource_ref"])
                row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",
                             (slot[name+"_resource_ref"]["resource_id"],))
                if row is None:
                    wire._fail("repair_unknown_resource")
                rows[name], offers[name] = row, s._saved(row, "offer")
            owner = json.loads(bytes(rows["data"]["owner_keys"]))
            # An exact retry remains a replay after short setup authority expiry.
            refs = {name: entries[name]["ref"] for name in FIELDS}
            digest = budget._hash(wire._canonical(dict(slot_key=slot_key, refs=refs), budget))
            old = s._one("SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?", (slot_digest,))
            if old is not None:
                if old["input_digest"] != digest:
                    wire._fail("repair_activation_conflict")
                return {name: s._saved(old, name+"_active") for name in ("data", "metadata")}
            held, payloads = self._originals(entries, owner, budget, now)
            self._check(held, payloads, slot_key, owner, offers, budget, now)
            activation = payloads["activation"]
            if s._one("SELECT 1 FROM open_repair_mailbox_slot_activations WHERE owner=? AND activation_id=?",
                      (owner["signing_key"]["key_id"], activation["activation_id"])):
                wire._fail("repair_activation_conflict")
            if any(row["status"] != "pending" or now >= row["reservation_until"] for row in rows.values()):
                wire._fail("repair_resource_inactive")
            inputs = wire.build_new_wire({k: dict(raw=v["raw"].decode(), ref=v["ref"])
                for k, v in held.items()}, s.policy, budget).raw
            result = {}
            deadlines.extend(row["reservation_until"] for row in rows.values())
            deadlines += [p["expires_at"] for p in payloads.values()]
            deadlines += [payloads["bootstrap"][key] for key in ("probe_until", "proof_until", "upload_until")]
            for name, row in rows.items():
                offer = wire.parse_new_wire(offers[name]["raw"], s.policy, budget).value["payload"]
                deadlines.extend(offer["windows"].values())
                result[name] = s._sign(dict(schema_version=resource.SCHEMA, kind="resource.active",
                    signing_key=s.identity.public_descriptor(), activated_at=now,
                    offer_ref=offers[name]["ref"], activation_ref=held["activation"]["ref"],
                    resource=offer["resource"], reservation_generation=offer["reservation_generation"],
                    root_key=slot_key["root_key"], purpose=offer["intent"]["purpose"],
                    budget=offer["budget"], windows=offer["windows"]), "mailbox_active", budget)
                # Charge the shared chain in each independent reservation. No
                # unproven physical deduplication reduces either obligation.
                metadata = row["metadata_bytes"] + len(inputs) + len(result[name]["raw"]) + 8*ROW_CHARGE
                if metadata > offer["budget"]["max_meta_bytes"]:
                    wire._fail("repair_insufficient_capacity")
                self.db.execute("UPDATE open_repair_mailbox_resources SET status='active',metadata_bytes=? WHERE resource_id=?",
                                (metadata, row["resource_id"]))
            self.db.execute('''INSERT INTO open_repair_mailbox_slot_activations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                (slot_digest, owner["signing_key"]["key_id"], activation["activation_id"], digest, inputs,
                 rows["data"]["resource_id"], rows["metadata"]["resource_id"], result["data"]["raw"],
                 canonical_bytes(result["data"]["ref"]), result["metadata"]["raw"],
                 canonical_bytes(result["metadata"]["ref"]), now))
            return result
