"""Original mailbox source events over the node's committed local resources.

Resource observations are node-signed facts, not owner permission or custody.
All revisions for a given node/root share one durable counter, including
separate slot and anchor observations. A retry returns the original bytes.
"""
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import ROW_CHARGE


class MailboxRootSource:
    def __init__(self, root):
        self.root,self.source,self.db = root,root.source,root.db

    def initialize(self):
        self.root.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_node_revisions(
                root_digest TEXT PRIMARY KEY,revision INTEGER NOT NULL)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_node_observations(
                root_digest TEXT NOT NULL,request_id TEXT NOT NULL,resource_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,records BLOB NOT NULL,first_revision INTEGER NOT NULL,
                last_revision INTEGER NOT NULL,PRIMARY KEY(root_digest,request_id))''')

    def _resources(self, resource_id, slot_keys, budget):
        s = self.source
        anchor = s._one("SELECT * FROM open_repair_mailbox_roots WHERE resource_id=?",(resource_id,))
        if anchor is None:
            wire._fail("repair_unknown_resource")
        held = wire.parse_new_wire(bytes(anchor["inputs"]),s.policy,budget).value
        p,_ = s._entry(dict(raw=held["root"]["raw"].encode(),ref=held["root"]["ref"]),budget)
        root_key = p.value["payload"]["root_key"]
        slots = wire.parse_new_wire(bytes(anchor["slots"]),s.policy,budget).value
        selected = None if slot_keys is None else wire.build_new_wire(slot_keys,s.policy,budget).value
        if selected is not None:
            if type(selected) is not wire._DraftList or not 1 <= len(selected) <= 16:
                wire._fail("repair_invalid_status")
            for key in selected:
                history._slot(key,root_key)
            hashes = [budget._hash(wire._canonical(key,budget)) for key in selected]
            if len(set(hashes)) != len(hashes):
                wire._fail("repair_invalid_status")
            if any(key not in [item["slot_key"] for item in slots] for key in selected):
                wire._fail("repair_mailbox_slot_incomplete")
        ids = [resource_id] if selected is None else []
        for item in slots:
            if selected is not None and item["slot_key"] not in selected:
                continue
            slot,_ = s._entry(dict(raw=item["entries"]["slot"]["raw"].encode(),ref=item["entries"]["slot"]["ref"]),budget)
            ids.extend(slot.value["payload"][name+"_resource_ref"]["resource_id"] for name in ("data","metadata"))
        rows = {}
        for value in ids:
            row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(value,))
            if row is None or row["status"] != "active":
                wire._fail("repair_resource_inactive")
            offer = s._saved(row,"offer")
            payload = wire.parse_new_wire(offer["raw"],s.policy,budget).value["payload"]
            if payload["intent"]["root_key"] != root_key or payload["intent"]["target"] != s.target:
                wire._fail("repair_resource_mismatch")
            rows[value] = row,payload
        return anchor,root_key,rows

    def observe_resources(self, resource_id, request_id, *, valid_until, slot_keys=None,
                          _budget=None, _transaction_guard=None):
        """Commit current local resource facts; optionally only selected slots.

        The selected-slot branch excludes the anchor and other writers. This
        permits a future member's historical closure to carry whole originals
        without disclosing the owner's discovery catalog or another slot.
        """
        s = self.source
        original._opaque(request_id); wire.u53(valid_until)
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
            anchor,root_key,resources = self._resources(resource_id,slot_keys,budget)
            root_digest = budget._hash(wire._canonical(root_key,budget))
            refs = sorted([p["resource"] for _,p in resources.values()],key=lambda v:v["resource_id"])
            digest = budget._hash(wire.build_new_wire(dict(resource_id=resource_id,root_key=root_key,
                resources=refs,valid_until=valid_until),s.policy,budget).raw)
            old = s._one("SELECT * FROM open_repair_mailbox_node_observations WHERE root_digest=? AND request_id=?",(root_digest,request_id))
            if old is not None:
                if old["input_digest"] != digest:
                    wire._fail("repair_status_request_conflict")
                records = wire.parse_new_wire(bytes(old["records"]),s.policy,budget).value
                result = []
                for item in records:
                    parsed,ref = s._entry(dict(raw=item["raw"].encode(),ref=item["ref"]),budget)
                    result.append(dict(raw=parsed.raw,ref=ref.as_dict()))
                return result
            if not now < valid_until <= now+status.MAX_STATUS_SECONDS:
                wire._fail("repair_resource_expired")
            for _,p in resources.values():
                if valid_until > min(p["windows"][name] for name in ("read_until","retain_until")):
                    wire._fail("repair_resource_expired")
            anchor_row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(resource_id,))
            if anchor_row is None or anchor_row["status"] != "active":
                wire._fail("repair_resource_inactive")
            anchor_offer = wire.parse_new_wire(s._saved(anchor_row,"offer")["raw"],s.policy,budget).value["payload"]
            count = self.db.execute("SELECT count(*) FROM open_repair_mailbox_node_observations WHERE resource_id=?",(resource_id,)).fetchone()[0]
            if count >= min(s.limits["max_replay_records"],anchor_offer["budget"]["max_replay_records"]):
                wire._fail("repair_insufficient_capacity")
            entries = [dict(scope_kind="resource",scope_id=status.status_scope(root_key,"resource",p["resource"],s.policy,budget),
                minimum_document_revision=p["reservation_generation"],status="active",operation_mask=127) for _,p in resources.values()]
            entries.sort(key=lambda item:(item["scope_kind"],item["scope_id"]))
            prior = s._one("SELECT revision FROM open_repair_mailbox_node_revisions WHERE root_digest=?",(root_digest,))
            total,maximum,span = self.db.execute("SELECT count(*),coalesce(max(last_revision),0),coalesce(sum(last_revision-first_revision+1),0) FROM open_repair_mailbox_node_observations WHERE root_digest=?",(root_digest,)).fetchone()
            marker_name = "mailbox_node_status:"+root_digest
            marker = s._one("SELECT value FROM open_repair_state WHERE name=?",(marker_name,))
            if ((prior is None and (maximum or marker is not None))
                    or (prior is not None and (prior["revision"] != maximum or span != maximum or marker is None
                        or marker["value"] != s._expected_binding()+"|"+str(maximum)+"|"+str(total)))):
                wire._fail("repair_mailbox_status_ledger_missing")
            first = (prior["revision"] if prior else 0)+1
            result = []
            for offset in range(0,len(entries),16):
                revision = wire.u53(first+len(result),1)
                result.append(s._sign(dict(schema_version=status.SCHEMA,kind="authority.status",signing_key=s.identity.public_descriptor(),
                    scope_key=dict(root_key=root_key,issuer_key_id=s.identity.key_id),revision=revision,
                    issued_at=now,valid_until=valid_until,entries=entries[offset:offset+16]),"mailbox_resource_status",budget))
            records = wire.build_new_wire([dict(raw=item["raw"].decode(),ref=item["ref"]) for item in result],s.policy,budget).raw
            charge = len(records)+(len(result)+3)*ROW_CHARGE
            if anchor_row["metadata_bytes"]+charge > anchor_offer["budget"]["max_meta_bytes"]:
                wire._fail("repair_insufficient_capacity")
            last = first+len(result)-1
            self.db.execute("INSERT INTO open_repair_mailbox_node_revisions VALUES(?,?) ON CONFLICT(root_digest) DO UPDATE SET revision=excluded.revision",(root_digest,last))
            self.db.execute("INSERT INTO open_repair_state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                            (marker_name,s._expected_binding()+"|"+str(last)+"|"+str(total+1)))
            self.db.execute("INSERT INTO open_repair_mailbox_node_observations VALUES(?,?,?,?,?,?,?)",
                (root_digest,request_id,resource_id,digest,records,first,last))
            self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,resource_id))
            deadlines.append(valid_until)
            return result
