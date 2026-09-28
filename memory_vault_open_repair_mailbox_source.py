"""Original mailbox source events over the node's committed local resources.

Resource observations are node-signed facts, not owner permission or custody.
All revisions for a given node/root share one durable counter, including
separate slot and anchor observations. A retry returns the original bytes.
"""
import json

from memory_vault import canonical_bytes
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

            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_root_history(
                resource_id TEXT PRIMARY KEY,observation_id TEXT NOT NULL,
                manifest BLOB NOT NULL,manifest_ref BLOB NOT NULL,pack BLOB NOT NULL,
                pack_ref BLOB NOT NULL,created_at INTEGER NOT NULL)''')

    def prepare_history(self, resource_id, observation_id, *, _budget=None, _transaction_guard=None):
        """Pin the complete local root history before a future custody event.

        No caller-supplied proof bag, regenerated owner original, or projected
        status is accepted. This local staging operation grants no network read
        permission and does not itself issue a custody promise.
        """
        s = self.source
        original._opaque(observation_id)
        budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget)
        # Exact historical retries do not assert that permission is still live.
        with s._transaction():
            old = s._one("SELECT * FROM open_repair_mailbox_root_history WHERE resource_id=?",(resource_id,))
            if old is not None:
                if old["observation_id"] != observation_id:
                    wire._fail("repair_custody_conflict")
                return dict(manifest=s._saved(old,"manifest"),pack=s._saved(old,"pack"))
        context = self.root.owner_status_context(resource_id,_budget=budget)
        owner_guard = self.root.owner_status_guard(resource_id,_budget=budget)
        deadlines = []
        def guard():
            if _transaction_guard is not None:
                code = _transaction_guard()
                if code:
                    return code
            code = owner_guard()
            if code:
                return code
            if deadlines and s._now() >= min(deadlines):
                return "repair_status_mismatch"
        with s._transaction(guard=guard) as now:
            # Another caller may have committed between the preview and lock.
            if s._one("SELECT 1 FROM open_repair_mailbox_root_history WHERE resource_id=?",(resource_id,)):
                wire._fail("repair_custody_conflict")
            anchor,root_key,resources = self._resources(resource_id,None,budget)
            root_digest = budget._hash(wire._canonical(root_key,budget))
            held = wire.parse_new_wire(bytes(anchor["inputs"]),s.policy,budget).value
            slots = wire.parse_new_wire(bytes(anchor["slots"]),s.policy,budget).value
            roles = {}
            def entry(value):
                return dict(raw=value["raw"].encode(),ref=value["ref"])
            def add(role,value):
                parsed,ref = s._entry(value,budget)
                roles[(role,*history._ref_tuple(ref.as_dict()))] = (role,parsed.raw,ref.as_dict())
                return parsed.value["payload"]
            requirements = {(v["scope_kind"],v["scope_id"]):v for v in context["required"]}
            allowed = [dict(scope_kind=k,scope_id=i) for k,i in requirements]
            def owner_status(role,kind,subject):
                scope_id = status.status_scope(root_key,kind,subject,s.policy,budget)
                required = requirements[(kind,scope_id)]
                revision = self.db.execute("SELECT max(revision) FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?",
                    (root_digest,required["issuer"],kind,scope_id)).fetchone()[0]
                documents = self.db.execute("SELECT raw,ref FROM open_repair_mailbox_status_documents WHERE root_digest=? AND issuer=? AND revision=? ORDER BY ref_digest LIMIT 1",
                    (root_digest,required["issuer"],revision)).fetchall()
                for raw,reference in documents:
                    value = dict(raw=bytes(raw),ref=json.loads(bytes(reference)))
                    payload = original.parse_original_control(value["raw"],s.policy,budget).value["payload"]
                    if not any(v["scope_kind"]==kind and v["scope_id"]==scope_id for v in payload["entries"]):
                        continue
                    status.verify_status_original(value,expected_root=root_key,expected_signing_key=context["signing_key"],
                        at=now,allowed_scopes=allowed,required=[{k:v for k,v in required.items() if k!="issuer"}],
                        policy=s.policy,budget=budget)
                    add(role,value);deadlines.append(payload["valid_until"])
                    return
                wire._fail("repair_status_missing")
            def owner(role,status_role,value,kind="authority",subject=None):
                payload = add(role,value)
                if subject is None:
                    subject = dict(authority_kind=payload["kind"],authority_sha256=value["ref"]["raw_sha256"])
                owner_status(status_role,kind,subject)
            for name,role,observation in (("root","mailbox.root_authority","root"),
                    ("read","mailbox.root_read_grant","root_read"),("bootstrap","bootstrap.mailbox_root","root_bootstrap")):
                owner(role,"historical.status."+observation,entry(held[name]))
            owner("mailbox.catalog","historical.status.catalog",entry(held["catalog"]),"catalog",dict(root_key=root_key))
            add("resource.anchor_activation",entry(held["activation"]))
            add("resource.anchor_active",s._saved(anchor,"active"))
            observation = s._one("SELECT records FROM open_repair_mailbox_node_observations WHERE root_digest=? AND request_id=? AND resource_id=?",
                                (root_digest,observation_id,resource_id))
            if observation is None:
                wire._fail("repair_status_missing")
            node_records = wire.parse_new_wire(bytes(observation["records"]),s.policy,budget).value
            resource_scopes = {rid:status.status_scope(root_key,"resource",payload["resource"],s.policy,budget)
                               for rid,(_,payload) in resources.items()}
            node_allowed = [dict(scope_kind="resource",scope_id=value) for value in resource_scopes.values()]
            def node_resource(role,rid):
                row,payload = resources[rid]
                add("resource."+role+"_allocate",s._saved(row,"allocation"))
                add("resource."+role+"_offer",s._saved(row,"offer"))
                for item in node_records:
                    value = entry(item)
                    parsed,_ = s._entry(value,budget)
                    p = parsed.value["payload"]
                    if not any(v["scope_kind"]=="resource" and v["scope_id"]==resource_scopes[rid] for v in p["entries"]):
                        continue
                    status.verify_status_original(value,expected_root=root_key,expected_signing_key=s.identity.public_descriptor(),
                        at=now,allowed_scopes=node_allowed,required=[dict(scope_kind="resource",scope_id=resource_scopes[rid],
                            document_revision=payload["reservation_generation"],operation_mask=66)],policy=s.policy,budget=budget)
                    add("historical.status."+role+"_resource",value);deadlines.append(p["valid_until"])
                    return
                wire._fail("repair_status_missing")
            node_resource("anchor",resource_id)
            heads = []
            for item in slots:
                values = item["entries"]
                owner("mailbox.slot","historical.status.slot",entry(values["slot"]),"mailbox_slot",item["slot_key"])
                for name,role,observation in (("read","mailbox.read_grant","read"),
                        ("maintenance","mailbox.maintenance_root","maintenance"),("bootstrap","bootstrap.mailbox_feed","bootstrap")):
                    owner(role,"historical.status."+observation,entry(values[name]))
                add("resource.slot_activation",entry(values["activation"]))
                for name in ("data","metadata"):
                    payload = add("resource."+name+"_active",entry(values[name+"_active"]))
                    node_resource(name,payload["resource"]["resource_id"])
                for name in ("head","checkpoint"):
                    add("genesis."+name,entry(values[name]))
                heads.append(values["head"]["ref"])
            descriptor = wire.build_new_wire(s.node,s.policy,budget).raw
            digest = budget._hash(descriptor)
            add("source.descriptor",dict(raw=descriptor,ref=dict(namespace="meta",key=digest,raw_sha256=digest,size=len(descriptor))))
            ordered = [roles[key] for key in sorted(roles)]
            pack = wire.build_raw_pack([raw for _,raw,_ in ordered],s.policy,budget)
            indices = {(v.raw_sha256,v.size):i for i,v in enumerate(pack.entries)}
            manifest = history.build_historical_manifest(dict(schema_version=history.SCHEMA,kind="historical.manifest",
                variant="mailbox_root",root_key=root_key,root_authority_ref=held["root"]["ref"],catalog_ref=held["catalog"]["ref"],
                genesis_head_refs=sorted(heads,key=history._ref_tuple),roles=[dict(role=role,document_ref=ref,
                    pack_ref=pack.ref.as_dict(),entry_index=indices[(ref["raw_sha256"],ref["size"])]) for role,_,ref in ordered]),s.policy,budget)
            digest = budget._hash(manifest.raw)
            reference = dict(namespace="meta",key=digest,raw_sha256=digest,size=len(manifest.raw))
            row,offer = resources[resource_id]
            charge = len(manifest.raw)+len(pack.raw)+(len(pack.entries)+3)*ROW_CHARGE+len(ordered)*256
            if row["metadata_bytes"]+charge > offer["budget"]["max_meta_bytes"] or len(pack.entries)+2 > offer["budget"]["max_items"]:
                wire._fail("repair_insufficient_capacity")
            self.db.execute("INSERT INTO open_repair_mailbox_root_history VALUES(?,?,?,?,?,?,?)",
                (resource_id,observation_id,manifest.raw,canonical_bytes(reference),pack.raw,canonical_bytes(pack.ref.as_dict()),now))
            self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,resource_id))
            return dict(manifest=dict(raw=manifest.raw,ref=reference),pack=dict(raw=pack.raw,ref=pack.ref.as_dict()))

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
