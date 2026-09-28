"""Durable original mailbox anchor activation over already committed slots.

The local root/catalog stage preserves the recipient's original authority and
the exact earlier slot chains. It is not current service permission or root
custody; those must complete before an offline recipient is told S1 is ready.
"""
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_mailbox_activation import MailboxSlotActivation, _ordered, _role
from memory_vault_open_repair_state import ROW_CHARGE

FIELDS = {
    "root": "issued_at expires_at root_key authority_id original_resource_ref original_resource_offer_ref slot_ids maintainers operation_mask allowed_roles budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision",
    "read": "issued_at expires_at grant_id root_key reader root_authority_ref operation_mask budget windows revision",
    "catalog": "root_key revision issued_at expires_at slot_refs root_authority_ref",
    "bootstrap": bootstrap._GRANT_FIELDS,
    "activation": resource._FIELDS[4],
}
# The shared original parser takes space-delimited field lists.
FIELDS["bootstrap"] = " ".join(sorted(FIELDS["bootstrap"]))
KINDS = dict(root="mailbox.root_authority", read="mailbox.root_read_grant", catalog="mailbox.catalog",
             bootstrap="bootstrap.grant", activation="resource.activation")
UPLOAD_ROLES = frozenset(("mailbox.root_authority", "mailbox.root_read_grant", "bootstrap.grant"))


def _fail():
    wire._fail("repair_mailbox_root_mismatch")


class MailboxRootActivation:
    def __init__(self, resources):
        self.resources, self.source, self.db = resources, resources.source, resources.db
        self.slots = MailboxSlotActivation(resources)

    def initialize(self):
        self.slots.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_roots(
                root_digest TEXT PRIMARY KEY,owner TEXT NOT NULL,activation_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,resource_id TEXT NOT NULL UNIQUE,inputs BLOB NOT NULL,
                slots BLOB NOT NULL,active BLOB NOT NULL,active_ref BLOB NOT NULL,
                activated_at INTEGER NOT NULL,UNIQUE(owner,activation_id))''')

    def _committed_slots(self, slot_keys, root, budget):
        s = self.source
        keys = wire.build_new_wire(slot_keys, s.policy, budget).value
        if type(keys) is not wire._DraftList or not 1 <= len(keys) <= min(16, s.limits["max_proof_items"]):
            _fail()
        result, seen = [], set()
        for key in keys:
            history._slot(key, root)
            digest = budget._hash(wire._canonical(key, budget))
            if digest in seen:
                _fail()
            seen.add(digest)
            row = s._one("SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?", (digest,))
            genesis = s._one("SELECT * FROM open_repair_mailbox_genesis WHERE slot_digest=?", (digest,))
            if row is None or genesis is None:
                wire._fail("repair_mailbox_slot_incomplete")
            stored = wire.parse_new_wire(bytes(row["inputs"]), s.policy, budget).value
            entries = {name: dict(raw=value["raw"].encode(), ref=value["ref"]) for name,value in stored.items()}
            parsed, _ = s._entry(entries["slot"], budget)
            if parsed.value["payload"]["slot_key"] != key:
                _fail()
            # These bytes were committed by the local slot verifier; rebind
            # every stored original to its exact ref before anchoring it.
            deadlines = []
            for name,entry in entries.items():
                checked,_ = s._entry(entry, budget)
                if name in ("maintenance","read","slot","bootstrap"):
                    deadlines.append(checked.value["payload"]["expires_at"])
                if name == "bootstrap":
                    deadlines.extend(checked.value["payload"][k] for k in ("probe_until","proof_until","upload_until"))
            for name in ("data", "metadata"):
                resource_row = s._one("SELECT status FROM open_repair_mailbox_resources WHERE resource_id=?",
                                     (row[name+"_resource_id"],))
                if resource_row is None or resource_row["status"] != "active":
                    wire._fail("repair_resource_inactive")
                entries[name+"_active"] = s._saved(row, name+"_active")
                active,_ = s._entry(entries[name+"_active"],budget)
                deadlines.extend(active.value["payload"]["windows"].values())
            for name in ("checkpoint", "head"):
                entries[name] = s._saved(genesis, name)
            result.append(dict(key=key, slot=parsed.value["payload"], entries=entries,
                               activated_at=row["activated_at"], retain_until=genesis["retain_until"],deadlines=deadlines))
        return sorted(result, key=lambda item: history._ref_tuple(item["entries"]["slot"]["ref"]))

    def _check(self, held, p, root_key, owner, offer, slots, budget, now):
        s = self.source
        root, read, catalog, grant, activation = (p[name] for name in FIELDS)
        owner_id = resource._dual_key(owner, budget)
        if root_key["root_kind"] != "mailbox" or root_key["owner"] != owner_id:
            _fail()
        for name in ("root", "read", "catalog", "bootstrap", "activation"):
            if p[name]["root_key"] != root_key:
                _fail()
        for value in (root, read):
            resource._budget(value["budget"])
            resource._windows(value["windows"], issued=value["issued_at"], expires=value["expires_at"])
            resource._opmask(value["operation_mask"])
        for value in (root, read, catalog, grant):
            wire.u53(value["revision"])
        original._opaque(root["authority_id"]); original._opaque(read["grant_id"])
        original._opaque(grant["grant_id"]); original._opaque(activation["activation_id"])
        _ordered(root["slot_ids"], lambda v:v, original._opaque)
        _ordered(root["maintainers"], lambda v:(v["signing_key_id"],v["encryption_key_id"]), history._dual)
        _ordered(root["allowed_roles"], lambda v:v, _role)
        if wire.u53(root["max_delegate_depth"]) != 2:
            _fail()
        wire.u53(root["max_destinations_per_job"]); wire.u53(root["max_concurrent_jobs"])
        slot_ids = sorted(item["key"]["slot_id"] for item in slots)
        slot_refs = [item["entries"]["slot"]["ref"] for item in slots]
        if (len(set(slot_ids)) != len(slot_ids) or root["slot_ids"] != slot_ids
                or catalog["slot_refs"] != slot_refs
                or read["reader"] != owner_id or read["root_authority_ref"] != held["root"]["ref"]
                or catalog["root_authority_ref"] != held["root"]["ref"]
                or root["original_resource_ref"] != offer["resource"]
                or root["original_resource_offer_ref"] != offer["ref"]
                or offer["intent"]["root_key"] != root_key or offer["intent"]["purpose"] != "anchor_catalog"
                or offer["intent"]["owner"] != owner or offer["intent"]["target"] != s.target):
            _fail()
        if (root["operation_mask"] & 10 != 10 or read["operation_mask"] & 2 != 2
                or read["operation_mask"] & ~root["operation_mask"]
                or any(read["budget"][k] > root["budget"][k] for k in resource._BUDGET)
                or any(read["windows"][k] > root["windows"][k] for k in resource._WINDOWS)
                or read["expires_at"] > root["expires_at"]
                or not {"bootstrap.grant", "mailbox_root_service_v1"} <= set(root["allowed_roles"])):
            _fail()
        if (grant["owner"] != owner_id or grant["subject"] != owner_id
                or grant["consumer"] != "mailbox_root" or grant["probe_profile"] != "opaque_v1"
                or grant["response_profile"] != "mailbox_root_service_v1"
                or grant["parent_authority_ref"] != held["root"]["ref"]
                or grant["caller_authority_ref"] != held["read"]["ref"]
                or grant["selector"] != dict(root_key_sha256=budget._hash(wire._canonical(root_key,budget)),
                    anchor_ref=root_key["anchor_ref"],root_authority_sha256=held["root"]["ref"]["raw_sha256"],
                    read_grant_sha256=held["read"]["ref"]["raw_sha256"])):
            _fail()
        _ordered(grant["upload_roles"], lambda v:v, _role)
        if not set(grant["upload_roles"]) <= UPLOAD_ROLES & set(root["allowed_roles"]):
            _fail()
        bootstrap._limits(grant["limits"])
        for name, parents in bootstrap._PARENT_CAPS.items():
            value = grant["limits"][name]
            if value > s.limits[name] or any(value > item["budget"][key] for item in (root,read) for key in parents):
                _fail()
        if not (offer["issued_at"] <= root["issued_at"] <= min(read["issued_at"], catalog["issued_at"])
                and max(read["issued_at"],catalog["issued_at"]) <= grant["issued_at"] <= activation["issued_at"] <= now
                and grant["expires_at"] <= min(root["expires_at"],read["expires_at"])
                and all(item["activated_at"] <= catalog["issued_at"] and item["retain_until"] > now
                        and min(item["deadlines"]) > now for item in slots)):
            _fail()
        for name in ("probe_until", "proof_until", "upload_until"):
            if not now < wire.u53(grant[name]) <= grant["expires_at"]:
                _fail()
        if any(grant[name] > parent["windows"][window] for name in ("proof_until","upload_until")
               for parent in (root,read) for window in ("read_until","retain_until")):
            _fail()
        authorities = [dict(role=KINDS[name],ref=held[name]["ref"]) for name in ("root","read","catalog")]
        for item in slots:
            authorities += [dict(role=kind,ref=item["entries"][name]["ref"]) for name,kind in (
                ("slot","mailbox.slot"),("read","mailbox.read_grant"),("maintenance","mailbox.maintenance_root"))]
        authorities.sort(key=lambda value:(value["role"],*history._ref_tuple(value["ref"])))
        if (activation["subject"] != owner or activation["target_node_key_id"] != s.identity.key_id
                or activation["target_storage_epoch"] != s.node["payload"]["storage_epoch"]
                or activation["scope"] != dict(kind="mailbox_root",root_key=root_key,
                    root_authority_ref=held["root"]["ref"],catalog_ref=held["catalog"]["ref"])
                or activation["resource_offer_refs"] != [offer["ref"]]
                or activation["authority_refs"] != authorities):
            _fail()

    def activate(self, entries, *, expected_root, slot_keys, _budget=None, _transaction_guard=None):
        s = self.source
        deadlines = []
        def guard():
            if _transaction_guard is not None:
                code = _transaction_guard()
                if code:
                    return code
            if deadlines and s._now() >= min(deadlines):
                return "repair_resource_expired"
        with s._transaction(guard=guard) as now:
            budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
            wire._context(s.policy,budget)
            root_key = wire.build_new_wire(expected_root,s.policy,budget).value
            history._root(root_key)
            root_digest = budget._hash(wire._canonical(root_key,budget))
            resource._fields(entries,FIELDS)
            held = {}
            for name in FIELDS:
                parsed,ref = s._entry(entries[name],budget)
                held[name] = dict(raw=parsed.raw,ref=ref.as_dict())
            slots = self._committed_slots(slot_keys,root_key,budget)
            digest = budget._hash(wire.build_new_wire(dict(root_key=root_key,
                refs={k:v["ref"] for k,v in held.items()},slots=[item["entries"]["slot"]["ref"] for item in slots]),s.policy,budget).raw)
            old = s._one("SELECT * FROM open_repair_mailbox_roots WHERE root_digest=?",(root_digest,))
            if old is not None:
                if old["input_digest"] != digest:
                    wire._fail("repair_activation_conflict")
                return s._saved(old,"active")
            root_signed = resource._fields(wire.parse_new_wire(held["root"]["raw"],s.policy,budget).value,{"payload","proof"})
            root_payload = root_signed["payload"]
            resource._fields(root_payload,resource.COMMON | set(FIELDS["root"].split()))
            history._resource(root_payload["original_resource_ref"])
            row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",
                         (root_payload["original_resource_ref"]["resource_id"],))
            if row is None:
                wire._fail("repair_unknown_resource")
            owner = json.loads(bytes(row["owner_keys"]))
            held,payloads = self.slots._originals(held,owner,budget,now,fields=FIELDS,kinds=KINDS)
            offered = s._saved(row,"offer")
            offer = dict(wire.parse_new_wire(offered["raw"],s.policy,budget).value["payload"],ref=offered["ref"])
            self._check(held,payloads,root_key,owner,offer,slots,budget,now)
            activation = payloads["activation"]
            if s._one("SELECT 1 FROM open_repair_mailbox_roots WHERE owner=? AND activation_id=?",
                      (row["owner"],activation["activation_id"])):
                wire._fail("repair_activation_conflict")
            if row["status"] != "pending" or now >= row["reservation_until"]:
                wire._fail("repair_resource_inactive")
            deadlines.extend([row["reservation_until"],*offer["windows"].values()])
            deadlines.extend(p["expires_at"] for p in payloads.values())
            deadlines.extend(item["retain_until"] for item in slots)
            deadlines.extend(value for item in slots for value in item["deadlines"])
            deadlines.extend(payloads["bootstrap"][k] for k in ("probe_until","proof_until","upload_until"))
            active = s._sign(dict(schema_version=resource.SCHEMA,kind="resource.active",signing_key=s.identity.public_descriptor(),
                activated_at=now,offer_ref=offered["ref"],activation_ref=held["activation"]["ref"],resource=offer["resource"],
                reservation_generation=offer["reservation_generation"],root_key=root_key,purpose="anchor_catalog",
                budget=offer["budget"],windows=offer["windows"]),"mailbox_anchor_active",budget)
            def encoded(entries):
                return {k:dict(raw=v["raw"].decode(),ref=v["ref"]) for k,v in entries.items()}
            inputs = wire.build_new_wire(encoded(held),s.policy,budget).raw
            saved_slots = wire.build_new_wire([dict(slot_key=item["key"],entries=encoded(item["entries"]))
                for item in slots],s.policy,budget).raw
            metadata = row["metadata_bytes"]+len(inputs)+len(saved_slots)+len(active["raw"])+(8+len(slots)*12)*ROW_CHARGE
            if metadata > offer["budget"]["max_meta_bytes"]:
                wire._fail("repair_insufficient_capacity")
            self.db.execute("UPDATE open_repair_mailbox_resources SET status='active',metadata_bytes=? WHERE resource_id=?",(metadata,row["resource_id"]))
            self.db.execute("INSERT INTO open_repair_mailbox_roots VALUES(?,?,?,?,?,?,?,?,?,?)",
                (root_digest,row["owner"],activation["activation_id"],digest,row["resource_id"],inputs,saved_slots,
                 active["raw"],canonical_bytes(active["ref"]),now))
            return active
