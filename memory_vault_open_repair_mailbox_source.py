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
import memory_vault_open_repair_resource as resource
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

            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_root_custody(
                resource_id TEXT PRIMARY KEY,input_digest TEXT NOT NULL,
                custody BLOB NOT NULL,custody_ref BLOB NOT NULL,stored_at INTEGER NOT NULL,
                read_until INTEGER NOT NULL,retain_until INTEGER NOT NULL)''')

    def finalize_root(self, resource_id, *, read_until, retain_until, _budget=None, _transaction_guard=None):
        """Commit the node's original custody over its already pinned root.

        All source inputs come from local activation and status transactions.
        This does not expose a remote endpoint or replace a client's independent
        verification of the root source event and current read permission.
        """
        s = self.source
        wire.u53(read_until);wire.u53(retain_until)
        budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget)
        digest = budget._hash(wire.build_new_wire(dict(resource_id=resource_id,
            read_until=read_until,retain_until=retain_until),s.policy,budget).raw)
        with s._transaction():
            old = s._one("SELECT * FROM open_repair_mailbox_root_custody WHERE resource_id=?",(resource_id,))
            marker = s._one("SELECT value FROM open_repair_state WHERE name=?",("mailbox_root_custody:"+resource_id,))
            if (old is None) != (marker is None):
                wire._fail("repair_mailbox_custody_missing")
            if old is not None:
                saved = s._saved(old,"custody")
                if marker["value"] != s._expected_binding()+"|"+old["input_digest"]+"|"+saved["ref"]["raw_sha256"]:
                    wire._fail("repair_storage_corrupt")
                if old["input_digest"] != digest:
                    wire._fail("repair_custody_conflict")
                return s._saved(old,"custody")
        context = self.root.owner_status_context(resource_id,_budget=budget)
        owner_guard = self.root.owner_status_guard(resource_id,_budget=budget)
        deadlines = [read_until,retain_until]
        def guard():
            if _transaction_guard is not None:
                code = _transaction_guard()
                if code:
                    return code
            code = owner_guard()
            if code:
                return code
            if s._now() >= min(deadlines):
                return "repair_resource_expired"
        with s._transaction(guard=guard) as now:
            if (s._one("SELECT 1 FROM open_repair_mailbox_root_custody WHERE resource_id=?",(resource_id,))
                    or s._one("SELECT 1 FROM open_repair_state WHERE name=?",("mailbox_root_custody:"+resource_id,))):
                wire._fail("repair_custody_conflict")
            row = s._one("SELECT * FROM open_repair_mailbox_root_history WHERE resource_id=?",(resource_id,))
            if row is None:
                wire._fail("repair_mailbox_history_missing")
            anchor,root_key,resources = self._resources(resource_id,None,budget)
            manifest,pack = s._saved(row,"manifest"),s._saved(row,"pack")
            resolver = wire.LocalRawResolver(s.policy,budget)
            resolver.put(pack["ref"]["namespace"],pack["ref"]["key"],pack["raw"])
            resolved = history.resolve_historical_inputs(manifest["raw"],resolver,s.policy,budget)
            m = resolved.manifest.value
            if (m["variant"] != "mailbox_root" or m["root_key"] != root_key
                    or {v.role for v in resolved.roles} != history._ROLES["mailbox_root"]):
                wire._fail("repair_mailbox_root_mismatch")
            held = wire.parse_new_wire(bytes(anchor["inputs"]),s.policy,budget).value
            if m["root_authority_ref"] != held["root"]["ref"] or m["catalog_ref"] != held["catalog"]["ref"]:
                wire._fail("repair_mailbox_root_mismatch")
            if not now < read_until <= retain_until <= context["deadline"]:
                wire._fail("repair_resource_expired")
            for _,offer in resources.values():
                if read_until > offer["windows"]["read_until"] or retain_until > offer["windows"]["retain_until"]:
                    wire._fail("repair_resource_expired")
            # Historical T must cover this original storage event, even if a
            # later observation has independently refreshed the live ledger.
            for role in resolved.roles:
                if role.role.startswith("historical.status."):
                    payload = original.parse_original_control(role.original.raw,s.policy,budget).value["payload"]
                    if not payload["issued_at"] <= row["created_at"] <= now < payload["valid_until"]:
                        wire._fail("repair_status_mismatch")
                    deadlines.append(payload["valid_until"])
            slots = wire.parse_new_wire(bytes(anchor["slots"]),s.policy,budget).value
            feeds = []
            for item in slots:
                refs = {}
                for name in ("data","metadata"):
                    value = item["entries"][name+"_active"]
                    parsed,_ = s._entry(dict(raw=value["raw"].encode(),ref=value["ref"]),budget)
                    refs[name] = parsed.value["payload"]["resource"]
                feeds.append(dict(slot_key=item["slot_key"],**refs))
            custody = s._sign(dict(schema_version=history.SCHEMA,kind="root.custody",signing_key=s.identity.public_descriptor(),
                root_key=root_key,root_authority_ref=m["root_authority_ref"],catalog_ref=m["catalog_ref"],
                genesis_head_refs=m["genesis_head_refs"],historical_manifest_ref=manifest["ref"],
                resource_refs=dict(anchor=resources[resource_id][1]["resource"],feeds=feeds),stored_at=now,
                read_until=read_until,retain_until=retain_until),"mailbox_root_custody",budget)
            from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
            verify_mailbox_root_source_event(manifest,resolver,custody,expected_root=root_key,
                expected_owner=json.loads(bytes(resources[resource_id][0]["owner_keys"])),expected_target=s.target,
                target_storage_epoch=s.node["payload"]["storage_epoch"],limit_policy=s.limits,policy=s.policy,budget=budget)
            resource_row,offer = resources[resource_id]
            charge = len(custody["raw"])+2*ROW_CHARGE
            if (resource_row["metadata_bytes"]+charge > offer["budget"]["max_meta_bytes"]
                    or len({v.original.ref for v in resolved.roles})+3 > offer["budget"]["max_items"]):
                wire._fail("repair_insufficient_capacity")
            self.db.execute("INSERT INTO open_repair_state VALUES(?,?)",("mailbox_root_custody:"+resource_id,
                s._expected_binding()+"|"+digest+"|"+custody["ref"]["raw_sha256"]))
            self.db.execute("INSERT INTO open_repair_mailbox_root_custody VALUES(?,?,?,?,?,?,?)",
                (resource_id,digest,custody["raw"],canonical_bytes(custody["ref"]),now,read_until,retain_until))
            self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,resource_id))
            return custody

    def read_local_original(self, resource_id, reference, *, _budget=None):
        """Read only exact originals pinned by this committed root.

        Local storage primitive only: transport callers must separately enforce
        the subject's original bootstrap and current authorization.
        """
        s = self.source
        budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget)
        ref = wire.raw_ref(wire.build_new_wire(reference,s.policy,budget).value)
        with s._transaction() as now:
            custody_row = s._one("SELECT * FROM open_repair_mailbox_root_custody WHERE resource_id=?",(resource_id,))
            row = s._one("SELECT * FROM open_repair_mailbox_root_history WHERE resource_id=?",(resource_id,))
            if custody_row is None or row is None:
                wire._fail("repair_mailbox_history_missing")
            if now >= min(custody_row["read_until"],custody_row["retain_until"]):
                wire._fail("repair_resource_expired")
            custody,manifest,pack = s._saved(custody_row,"custody"),s._saved(row,"manifest"),s._saved(row,"pack")
            payload = wire.parse_new_wire(custody["raw"],s.policy,budget).value["payload"]
            if payload["historical_manifest_ref"] != manifest["ref"]:
                wire._fail("repair_storage_corrupt")
            for value in (custody,manifest,pack):
                if value["ref"] == ref.as_dict():
                    return value["raw"]
            parsed = history.parse_historical_manifest(manifest["raw"],s.policy,budget)
            for role in parsed.value["roles"]:
                if role["document_ref"] == ref.as_dict():
                    if role["pack_ref"] != pack["ref"]:
                        wire._fail("repair_storage_corrupt")
                    packed = wire.parse_raw_pack(pack["raw"],pack["ref"],s.policy,budget)
                    return packed.entry(role["entry_index"],ref).raw
            wire._fail("repair_ref_missing")

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
        held = wire.parse_new_wire(bytes(anchor["inputs"]),s._budget_policy(budget),budget).value
        p,_ = s._entry(dict(raw=held["root"]["raw"].encode(),ref=held["root"]["ref"]),budget)
        root_key = p.value["payload"]["root_key"]
        slots = wire.parse_new_wire(bytes(anchor["slots"]),s._budget_policy(budget),budget).value
        selected = None if slot_keys is None else wire.build_new_wire(slot_keys,s._budget_policy(budget),budget).value
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
            payload = wire.parse_new_wire(offer["raw"],s._budget_policy(budget),budget).value["payload"]
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
            wire._context(s._budget_policy(budget),budget)
            anchor,root_key,resources = self._resources(resource_id,slot_keys,budget)
            root_digest = budget._hash(wire._canonical(root_key,budget))
            refs = sorted([p["resource"] for _,p in resources.values()],key=lambda v:v["resource_id"])
            digest = budget._hash(wire.build_new_wire(dict(resource_id=resource_id,root_key=root_key,
                resources=refs,valid_until=valid_until),s._budget_policy(budget),budget).raw)
            old = s._one("SELECT * FROM open_repair_mailbox_node_observations WHERE root_digest=? AND request_id=?",(root_digest,request_id))
            if old is not None:
                if old["input_digest"] != digest:
                    wire._fail("repair_status_request_conflict")
                records = wire.parse_new_wire(bytes(old["records"]),s._budget_policy(budget),budget).value
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
            anchor_offer = wire.parse_new_wire(s._saved(anchor_row,"offer")["raw"],s._budget_policy(budget),budget).value["payload"]
            count = self.db.execute("SELECT count(*) FROM open_repair_mailbox_node_observations WHERE resource_id=?",(resource_id,)).fetchone()[0]
            if count >= min(s.limits["max_replay_records"],anchor_offer["budget"]["max_replay_records"]):
                wire._fail("repair_insufficient_capacity")
            entries = [dict(scope_kind="resource",scope_id=status.status_scope(root_key,"resource",p["resource"],s._budget_policy(budget),budget),
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
            records = wire.build_new_wire([dict(raw=item["raw"].decode(),ref=item["ref"]) for item in result],s._budget_policy(budget),budget).raw
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


class MailboxRecoveryService:
    """Persistent recipient possession exchange over an original root custody.

    The challenge phase reveals no mailbox originals. Proof publication and
    transport routing are separate operations and are not enabled by this class.
    """
    def __init__(self, mailbox, *, consumer="mailbox_root"):
        if consumer not in ("mailbox_root","mailbox_feed"):wire._fail("repair_invalid_context")
        self.consumer=consumer
        self.source_state="root" if consumer=="mailbox_root" else "feed"
        self.mailbox,self.source,self.db = mailbox,mailbox.source,mailbox.db

    def _find_resources(self, owner, grant_digest):
        if self.consumer=='mailbox_root':
            return self.db.execute('''SELECT r.resource_id FROM open_repair_mailbox_roots r
                JOIN open_repair_mailbox_root_custody c ON c.resource_id=r.resource_id
                WHERE r.owner=? AND json_extract(r.inputs,'$.bootstrap.ref.raw_sha256')=? LIMIT 2''',(owner,grant_digest)).fetchall()
        if self.source._one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_mailbox_feed_custody'") is None:return []
        return self.db.execute('''SELECT DISTINCT r.metadata_resource_id FROM open_repair_mailbox_slot_activations r
            JOIN open_mailbox_feed_custody c ON c.slot_digest=r.slot_digest
            WHERE r.owner=? AND json_extract(r.inputs,'$.bootstrap.ref.raw_sha256')=? LIMIT 2''',(owner,grant_digest)).fetchall()

    def _resource_inputs(self, rid, budget, *, head_ref=None):
        s=self.source
        if self.consumer=='mailbox_root':
            if head_ref is not None:wire._fail('repair_invalid_context')
            row=s._one('SELECT * FROM open_repair_mailbox_roots WHERE resource_id=?',(rid,))
            custody=s._one('SELECT * FROM open_repair_mailbox_root_custody WHERE resource_id=?',(rid,))
        else:
            row=s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE metadata_resource_id=?',(rid,))
            if row is None:wire._fail('repair_service_unavailable')
            selected=None if head_ref is None else wire.raw_ref(head_ref)
            if selected is not None and selected.namespace!='meta':wire._fail('repair_ref_mismatch')
            held=(s._one('SELECT * FROM open_mailbox_feed_custody WHERE slot_digest=? AND head_digest=?',(row['slot_digest'],selected.raw_sha256))
                if selected is not None else s._one("SELECT * FROM open_mailbox_feed_custody WHERE slot_digest=? ORDER BY json_extract(custody,'$.payload.covered_interval.end') DESC LIMIT 1",(row['slot_digest'],)))
            if held is None:wire._fail('repair_service_unavailable')
            entry=s._saved(held,'custody');custody=wire.parse_new_wire(entry['raw'],budget.policy,budget).value['payload']
            if selected is not None and custody['feed_head_ref']!=selected.as_dict():wire._fail('repair_ref_mismatch')
            marker=s._one('SELECT value FROM open_repair_state WHERE name=?',('mailbox_feed_custody:'+row['slot_digest']+':'+held['head_digest'],))
            if marker is None or marker['value']!=s._expected_binding()+'|'+entry['ref']['raw_sha256']:wire._fail('repair_storage_corrupt')
        if row is None or custody is None:wire._fail('repair_service_unavailable')
        return wire.parse_new_wire(bytes(row['inputs']),budget.policy,budget).value,custody

    def _owner_guard(self, rid, *, head_ref=None):
        if self.consumer=='mailbox_root':
            if head_ref is not None:wire._fail('repair_invalid_context')
            return self.mailbox.root.owner_status_guard(rid)
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        from memory_vault_open_repair_bind import decode_entry
        s=self.source;budget=wire.RepairBudget(s.policy);inputs,custody=self._resource_inputs(rid,budget,head_ref=head_ref)
        slot=wire.parse_new_wire(inputs['slot']['raw'].encode(),s.policy,budget).value['payload'];key=slot['slot_key']
        requirements=[];deadlines=[custody['read_until'],custody['retain_until']]
        def authority(raw,reference,mask):
            p=wire.parse_new_wire(raw,s.policy,budget).value['payload'];kind='mailbox_slot' if p['kind']=='mailbox.slot' else 'authority'
            subject=key if kind=='mailbox_slot' else dict(authority_kind=p['kind'],authority_sha256=reference['raw_sha256'])
            requirements.append(dict(issuer=p['signing_key']['key_id'],scope_kind=kind,scope_id=status.status_scope(key['root_key'],kind,subject,s.policy,budget),document_revision=p['revision'],operation_mask=mask))
            deadlines.append(p['expires_at'])
            if 'windows' in p:deadlines.extend(p['windows'][v] for v in ('read_until','retain_until'))
            if p['kind']=='message.disclosure':deadlines.extend((p['consent_until'],p['bootstrap_return']['until']))
            if p['kind']=='bootstrap.grant':deadlines.extend(p[v] for v in ('probe_until','proof_until'))
        for name,mask in (('slot',10),('read',2),('maintenance',10),('bootstrap',10)):
            authority(inputs[name]['raw'].encode(),inputs[name]['ref'],mask)
        digest=budget._hash(wire._canonical(key,budget));count=custody['covered_interval']['end']
        rows=self.db.execute('''SELECT s.originals FROM open_mailbox_admissions a JOIN open_mailbox_message_staging s
            ON s.sender=a.sender AND s.message_id=a.message_id WHERE a.slot_digest=? AND a.sequence<? ORDER BY a.sequence''',(digest,count)).fetchall()
        if len(rows)!=count:wire._fail('repair_storage_corrupt')
        for row in rows:
            draft=wire.parse_new_wire(bytes(row[0]),s.policy,budget).value;entry=decode_entry(draft['disclosure'],s.policy,budget)
            authority(entry['raw'],entry['ref'],2)
        resource_row=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(rid,))
        offer=wire.parse_new_wire(s._saved(resource_row,'offer')['raw'],s.policy,budget).value['payload']
        own_scope=status.status_scope(key['root_key'],'resource',offer['resource'],s.policy,budget)
        root_digest=budget._hash(wire._canonical(key['root_key'],budget))
        def guard():
            if s._now()>=min(deadlines):return 'repair_access_expired'
            current=s._one('SELECT status FROM open_repair_mailbox_resources WHERE resource_id=?',(rid,))
            if current is None or current['status']!='active':return 'repair_resource_inactive'
            code=MailboxStatusLedger(self.mailbox.root.resources).check_locked(rid,requirements)
            if code:return code
            # R can refresh its own expired resource observation from actual
            # active storage; immutable revocation/floor evidence still wins.
            rows=self.db.execute('SELECT revoked_mask,minimum_revision FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?',
                (root_digest,s.identity.key_id,'resource',own_scope)).fetchall()
            if any(v[0]&2 for v in rows):return 'repair_authority_revoked'
            if any(v[1]>offer['reservation_generation'] for v in rows):return 'repair_status_revision'
        return guard

    def initialize(self):
        self.mailbox.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_recovery_usage(
                resource_id TEXT PRIMARY KEY,requests INTEGER NOT NULL,signatures INTEGER NOT NULL)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_recovery_challenges(
                resource_id TEXT NOT NULL,subject TEXT NOT NULL,probe_id TEXT NOT NULL,
                probe BLOB NOT NULL,probe_ref BLOB NOT NULL,challenge BLOB NOT NULL,
                challenge_ref BLOB NOT NULL,nonce BLOB NOT NULL,expires_at INTEGER NOT NULL,
                PRIMARY KEY(subject,probe_id))''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_recovery_responses(
                challenge_digest TEXT PRIMARY KEY,resource_id TEXT NOT NULL,answer BLOB NOT NULL,answer_ref BLOB NOT NULL,
                response BLOB NOT NULL,children BLOB NOT NULL,expires_at INTEGER NOT NULL,proof_bytes INTEGER NOT NULL)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_recovery_handles(
                handle_digest TEXT PRIMARY KEY,handle_ref BLOB NOT NULL,challenge_digest TEXT NOT NULL UNIQUE)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_recovery_reads(
                subject TEXT NOT NULL,request_id TEXT NOT NULL,resource_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,PRIMARY KEY(subject,request_id))''')

    def _proof_inputs(self, rid, budget, observation_id, valid_until):
        """Build a local finite plan; caller must reserve work before calling."""
        if self.consumer=="mailbox_feed":return self._feed_proof_inputs(rid,budget,observation_id,valid_until)
        from memory_vault_open_repair_mailbox_root import verify_mailbox_root_source_event
        s=self.source
        guard=self._owner_guard(rid)
        node_statuses=self.mailbox.observe_resources(rid,observation_id,valid_until=valid_until,
            _budget=budget,_transaction_guard=guard)
        with s._transaction(guard=guard) as now:
            row=s._one("SELECT * FROM open_repair_mailbox_root_history WHERE resource_id=?",(rid,))
            custody_row=s._one("SELECT * FROM open_repair_mailbox_root_custody WHERE resource_id=?",(rid,))
            resource_row=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
            if row is None or custody_row is None or now>=min(custody_row["read_until"],custody_row["retain_until"]):
                wire._fail("repair_service_unavailable")
            manifest,pack,custody=s._saved(row,"manifest"),s._saved(row,"pack"),s._saved(custody_row,"custody")
            owner=json.loads(bytes(resource_row["owner_keys"]))
            offer=wire.parse_new_wire(s._saved(resource_row,"offer")["raw"],budget.policy,budget).value["payload"]
            root=offer["intent"]["root_key"]
            root_digest=budget._hash(wire._canonical(root,budget))
        resolver=wire.LocalRawResolver(budget.policy,budget)
        resolver.put(pack["ref"]["namespace"],pack["ref"]["key"],pack["raw"])
        verified=verify_mailbox_root_source_event(manifest,resolver,custody,expected_root=root,expected_owner=owner,
            expected_target=s.target,target_storage_epoch=s.node["payload"]["storage_epoch"],limit_policy=s.limits,
            policy=budget.policy,budget=budget)
        children={}
        def add(role,entry):
            parsed,ref=s._entry(entry,budget)
            children[(role,*history._ref_tuple(ref.as_dict()))]=dict(role=role,raw=parsed.raw,ref=ref.as_dict())
        for item in verified["manifest"].roles:
            add(item.role,dict(raw=item.original.raw,ref=item.original.ref.as_dict()))
        add("history.mailbox_root",manifest);add("root.custody",custody)
        # Raw packs are binary and must not pass through a JSON reserializer.
        children[("history.raw_pack",*history._ref_tuple(pack["ref"]))]=dict(role="history.raw_pack",**pack)
        obligations=verified["obligations"]
        with s._transaction(guard=guard) as now:
            for item in obligations:
                if item["signer"]==s.identity.public_descriptor():
                    candidates=node_statuses
                else:
                    revision=self.db.execute("SELECT max(revision) FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?",
                        (root_digest,item["signer"]["key_id"],item["kind"],item["scope_id"])).fetchone()[0]
                    row=s._one("SELECT raw,ref FROM open_repair_mailbox_status_documents WHERE root_digest=? AND issuer=? AND revision=? ORDER BY ref_digest LIMIT 1",
                        (root_digest,item["signer"]["key_id"],revision))
                    candidates=[] if row is None else [dict(raw=bytes(row["raw"]),ref=json.loads(bytes(row["ref"])))]
                found=False
                for entry in candidates:
                    payload=original.parse_original_control(entry["raw"],budget.policy,budget).value["payload"]
                    if not any(v["scope_kind"]==item["kind"] and v["scope_id"]==item["scope_id"] for v in payload["entries"]):
                        continue
                    permitted=[v for v in obligations if v["signer"]==item["signer"]]
                    present={(v["scope_kind"],v["scope_id"]) for v in payload["entries"]}
                    status.verify_status_original(entry,expected_root=root,expected_signing_key=item["signer"],at=now,
                        allowed_scopes=[dict(scope_kind=v["kind"],scope_id=v["scope_id"]) for v in permitted],
                        required=[dict(scope_kind=v["kind"],scope_id=v["scope_id"],document_revision=v["revision"],operation_mask=v["bits"])
                            for v in permitted if (v["kind"],v["scope_id"]) in present],policy=budget.policy,budget=budget)
                    add(item["role"].replace("historical.","current.",1),entry);found=True
                    break
                if not found:
                    wire._fail("repair_status_missing")
        return tuple(children[key] for key in sorted(children))

    def _feed_proof_inputs(self, rid, budget, observation_id, valid_until):
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_source_event
        s=self.source;policy=budget.policy;inputs,custody_payload=self._resource_inputs(rid,budget)
        guard=self._owner_guard(rid);key=custody_payload['slot_key']
        root_digest=budget._hash(wire._canonical(key['root_key'],budget));slot_digest=budget._hash(wire._canonical(key,budget))
        anchor=s._one('SELECT resource_id FROM open_repair_mailbox_roots WHERE root_digest=?',(root_digest,))
        observations=self.mailbox.observe_resources(anchor['resource_id'],observation_id,valid_until=valid_until,slot_keys=[key],_budget=budget,_transaction_guard=guard)
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        slot_payload=wire.parse_new_wire(inputs['slot']['raw'].encode(),policy,budget).value['payload']
        scopes=[dict(scope_kind='resource',scope_id=status.status_scope(key['root_key'],'resource',slot_payload[name+'_resource_ref'],policy,budget)) for name in ('data','metadata')]
        for entry in observations:
            MailboxStatusLedger(self.mailbox.root.resources).observe(rid,entry,expected_signing_key=s.identity.public_descriptor(),allowed_scopes=scopes,_budget=budget)
        with s._transaction(guard=guard) as now:
            custody_row=s._one('SELECT * FROM open_mailbox_feed_custody WHERE slot_digest=? AND head_digest=?',(slot_digest,custody_payload['feed_head_ref']['raw_sha256']))
            history_row=s._one('SELECT * FROM open_mailbox_feed_history WHERE slot_digest=? AND head_digest=?',(slot_digest,custody_payload['feed_head_ref']['raw_sha256']))
            resource_row=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(rid,))
            if custody_row is None or history_row is None:wire._fail('repair_original_missing')
            custody=s._saved(custody_row,'custody');manifest=s._saved(history_row,'manifest');pack=s._saved(history_row,'pack')
            slot=wire.parse_new_wire(inputs['slot']['raw'].encode(),policy,budget).value['payload']
            parsed=history.parse_historical_manifest(manifest['raw'],policy,budget)
            resolver=wire.LocalRawResolver(policy,budget);resolver.put('meta',pack['ref']['key'],pack['raw']);packs=[pack]
            for member in parsed.value['members']:
                row=s._one('SELECT * FROM open_mailbox_member_history WHERE sender=? AND message_id=?',(slot['sender']['signing_key_id'],member['message_id']))
                if row is None:wire._fail('repair_original_missing')
                held=s._saved(row,'pack');resolver.put('meta',held['ref']['key'],held['raw']);packs.append(held)
            resolved=history.resolve_historical_inputs(manifest['raw'],resolver,policy,budget)
            request=next(v.original.raw for v in resolved.predecessors[0].roles if v.role=='contact.request')
            p=original.parse_original_control(request,policy,budget).value['payload'];sender=dict(signing_key=p['signing_key'],encryption_key=p['encryption_key'])
            verified=verify_mailbox_feed_source_event(manifest,resolver,custody,expected_slot=key,
                expected_owner=json.loads(bytes(resource_row['owner_keys'])),expected_sender=sender,expected_target=s.target,
                limit_policy=s.limits,policy=policy,budget=budget)
            children={}
            def add(role,entry):
                ref=wire.raw_ref(entry['ref'])
                if len(entry['raw'])!=ref.size or budget._hash(entry['raw'])!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
                children[(role,*history._ref_tuple(ref.as_dict()))]=dict(role=role,raw=entry['raw'],ref=ref.as_dict())
            for tree in (verified['manifest'],*verified['manifest'].predecessors):
                for item in tree.roles:add(item.role,dict(raw=item.original.raw,ref=item.original.ref.as_dict()))
            add('history.mailbox_feed',manifest);add('feed.custody',custody)
            for value in packs:add('history.raw_pack',value)
            obligations=verified['graph']['obligations'];allowed={}
            for member in verified['graph']['members']:
                for item in member['obligations']:allowed[(item['signer']['key_id'],item['scope_kind'],item['scope_id'])]=item
            for item in obligations:
                revision=self.db.execute('SELECT max(revision) FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?',
                    (root_digest,item['signer']['key_id'],item['scope_kind'],item['scope_id'])).fetchone()[0]
                row=s._one('SELECT raw,ref FROM open_repair_mailbox_status_documents WHERE root_digest=? AND issuer=? AND revision=? ORDER BY ref_digest LIMIT 1',(root_digest,item['signer']['key_id'],revision))
                if row is None:wire._fail('repair_status_missing')
                entry=dict(raw=bytes(row['raw']),ref=json.loads(bytes(row['ref'])))
                required={name:item[name] for name in ('scope_kind','scope_id','document_revision','operation_mask')}
                required['operation_mask']=10 if item['role'] in ('slot','maintenance','bootstrap') else 2
                status.verify_status_original(entry,expected_root=key['root_key'],expected_signing_key=item['signer'],at=now,
                    allowed_scopes=[dict(scope_kind=v['scope_kind'],scope_id=v['scope_id']) for identity,v in allowed.items() if identity[0]==item['signer']['key_id']],
                    required=[required],policy=policy,budget=budget)
                add('current.status.'+item['role'],entry)
            return tuple(children[name] for name in sorted(children))

    def _usage_locked(self, rid):
        s=self.source
        row=s._one("SELECT * FROM open_repair_mailbox_recovery_usage WHERE resource_id=?",(rid,))
        marker=s._one("SELECT value FROM open_repair_state WHERE name=?",("mailbox_recovery:"+rid,))
        count=self.db.execute("SELECT count(*) FROM open_repair_mailbox_recovery_challenges WHERE resource_id=?",(rid,)).fetchone()[0]
        if ((row is None)!=(marker is None) or (row is None and count)
                or (row is not None and (count>row["requests"] or marker["value"]!=s._expected_binding()+"|"+str(row["requests"])+"|"+str(row["signatures"])) )):
            wire._fail("repair_mailbox_recovery_ledger_missing")
        return row

    def _mark_usage_locked(self, rid):
        row=self.source._one("SELECT * FROM open_repair_mailbox_recovery_usage WHERE resource_id=?",(rid,))
        self.db.execute("INSERT INTO open_repair_state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            ("mailbox_recovery:"+rid,self.source._expected_binding()+"|"+str(row["requests"])+"|"+str(row["signatures"])))

    def challenge(self, entry):
        from dataclasses import replace
        import memory_vault_open_repair_probe as probe
        s=self.source
        preview_budget=wire.RepairBudget(s.policy)
        parsed,ref=s._entry(entry,preview_budget)
        signed=probe._fields(parsed.value,{"payload","proof"})
        payload=probe._fields(signed["payload"],probe._FIELDS["probe"])
        original._digest(payload["bootstrap_grant_sha256"])
        subject=resource._dual_key_shape(payload["subject"])
        original._key_id(subject["signing_key"]["key_id"])
        rows=self._find_resources(subject["signing_key"]["key_id"],payload["bootstrap_grant_sha256"])
        if len(rows)!=1:
            wire._fail("repair_service_unavailable")
        rid=rows[0][0]
        row=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
        inputs,custody=self._resource_inputs(rid,preview_budget)
        grant=wire.parse_new_wire(inputs["bootstrap"]["raw"].encode(),s.policy,preview_budget).value["payload"]
        offer=wire.parse_new_wire(s._saved(row,"offer")["raw"],s.policy,preview_budget).value["payload"]
        usage=s._one("SELECT * FROM open_repair_mailbox_recovery_usage WHERE resource_id=?",(rid,))
        allowance=min(s.policy.max_signature_checks,grant["limits"]["max_signature_checks"]-(usage["signatures"] if usage else 0))
        if allowance<1 or len(parsed.raw)>grant["limits"]["max_probe_bytes"]:
            wire._fail("repair_service_capacity")
        budget=wire.RepairBudget(replace(s.policy,max_signature_checks=allowance))
        owner=json.loads(bytes(row["owner_keys"]))
        expected=dict(expected_subject=owner,expected_target=s.target,target_storage_epoch=s.node["payload"]["storage_epoch"],
            bootstrap_grant_sha256=inputs["bootstrap"]["ref"]["raw_sha256"],selector=grant["selector"],
            at=s._now(),consumer=self.consumer,policy=budget.policy,budget=budget)
        packet=dict(raw=parsed.raw,ref=ref.as_dict())
        verified=probe.verify_bootstrap_probe(packet,**expected)
        owner_guard=self._owner_guard(rid)
        expires=min(verified.payload["expires_at"],grant["probe_until"],custody["read_until"],custody["retain_until"])
        def guard():
            if s._now()>=expires:
                return "repair_access_expired"
            return owner_guard()
        # Reserve finite work before node encryption or signing. A process
        # interrupted after admission retains its entire reservation on disk.
        with s._transaction(guard=guard):
            current=self._usage_locked(rid)
            requests,signatures=(current["requests"],current["signatures"]) if current else (0,0)
            current_resource=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
            if (requests>=min(grant["limits"]["max_requests"],grant["limits"]["max_replay_records"],
                              offer["budget"]["max_requests"],offer["budget"]["max_replay_records"])
                    or signatures+allowance>grant["limits"]["max_signature_checks"]
                    or current_resource["metadata_bytes"]+(ROW_CHARGE if current is None else 0)>offer["budget"]["max_meta_bytes"]):
                wire._fail("repair_service_capacity")
            self.db.execute('''INSERT INTO open_repair_mailbox_recovery_usage VALUES(?,1,?)
                ON CONFLICT(resource_id) DO UPDATE SET requests=requests+1,signatures=signatures+excluded.signatures''',(rid,allowance))
            self._mark_usage_locked(rid)
            if current is None:
                self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(ROW_CHARGE,rid))
        try:
            with s._transaction(guard=guard) as now:
                old=s._one("SELECT * FROM open_repair_mailbox_recovery_challenges WHERE subject=? AND probe_id=?",
                    (owner["signing_key"]["key_id"],verified.payload["probe_id"]))
                if old is not None:
                    if (old["resource_id"]!=rid or bytes(old["probe"])!=parsed.raw
                            or json.loads(bytes(old["probe_ref"]))!=ref.as_dict()):
                        wire._fail("repair_probe_replay_conflict")
                    if now>=old["expires_at"]:
                        wire._fail("repair_access_expired")
                    return s._saved(old,"challenge")
                pending=self.db.execute("SELECT count(*) FROM open_repair_mailbox_recovery_challenges WHERE resource_id=? AND expires_at>?",(rid,now)).fetchone()[0]
                if pending>=min(grant["limits"]["max_pending"],offer["budget"]["max_pending"]):
                    wire._fail("repair_service_capacity")
            expected["at"]=s._now()
            created=probe.issue_bootstrap_challenge(packet,signer=s.identity,encryption_identity=s.encryption_identity,
                **expected,expires_at=expires)
            result=dict(raw=created.original.raw,ref=created.original.ref.as_dict())
            with s._transaction(guard=guard):
                old=s._one("SELECT 1 FROM open_repair_mailbox_recovery_challenges WHERE subject=? AND probe_id=?",
                    (owner["signing_key"]["key_id"],verified.payload["probe_id"]))
                if old is not None:
                    wire._fail("repair_probe_replay_conflict")
                pending=self.db.execute("SELECT count(*) FROM open_repair_mailbox_recovery_challenges WHERE resource_id=? AND expires_at>?",(rid,s._now())).fetchone()[0]
                current_resource=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
                charge=len(parsed.raw)+len(result["raw"])+len(created.nonce)+ROW_CHARGE
                if (pending>=min(grant["limits"]["max_pending"],offer["budget"]["max_pending"])
                        or current_resource["metadata_bytes"]+charge>offer["budget"]["max_meta_bytes"]):
                    wire._fail("repair_service_capacity")
                self.db.execute("INSERT INTO open_repair_mailbox_recovery_challenges VALUES(?,?,?,?,?,?,?,?,?)",
                    (rid,owner["signing_key"]["key_id"],verified.payload["probe_id"],parsed.raw,canonical_bytes(ref.as_dict()),
                     result["raw"],canonical_bytes(result["ref"]),created.nonce,expires))
                self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,rid))
            return result
        finally:
            actual=budget.snapshot()["signature_checks"]
            with s._transaction():
                self._usage_locked(rid)
                self.db.execute("UPDATE open_repair_mailbox_recovery_usage SET signatures=signatures-? WHERE resource_id=?",
                    (allowance-actual,rid))
                self._mark_usage_locked(rid)

    def answer(self, entry):
        """Complete possession and persist a finite recipient-bound proof plan."""
        from dataclasses import replace
        import base64
        import secrets
        import memory_vault_open_repair_probe as probe
        import memory_vault_open_repair_proof as proof
        s=self.source
        preview=wire.RepairBudget(s.policy)
        parsed,ref=s._entry(entry,preview)
        signed=probe._fields(parsed.value,{"payload","proof"})
        payload=probe._fields(signed["payload"],probe._FIELDS["answer"])
        parent=probe._ref(payload["challenge_ref"])
        rows=self.db.execute("SELECT * FROM open_repair_mailbox_recovery_challenges WHERE json_extract(challenge_ref,'$.raw_sha256')=? LIMIT 2",(parent.raw_sha256,)).fetchall()
        if len(rows)!=1:
            wire._fail("repair_service_unavailable")
        columns=[v[1] for v in self.db.execute("PRAGMA table_info(open_repair_mailbox_recovery_challenges)")]
        held=dict(zip(columns,rows[0]));rid=held["resource_id"]
        if json.loads(bytes(held["challenge_ref"]))!=parent.as_dict():
            wire._fail("repair_ref_mismatch")
        resource_row=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
        inputs,_=self._resource_inputs(rid,preview)
        grant=wire.parse_new_wire(inputs["bootstrap"]["raw"].encode(),s.policy,preview).value["payload"]
        offer=wire.parse_new_wire(s._saved(resource_row,"offer")["raw"],s.policy,preview).value["payload"]
        owner=json.loads(bytes(resource_row["owner_keys"]))
        usage=s._one("SELECT * FROM open_repair_mailbox_recovery_usage WHERE resource_id=?",(rid,))
        if usage is None:
            wire._fail("repair_mailbox_recovery_ledger_missing")
        allowance=min(s.policy.max_signature_checks,grant["limits"]["max_signature_checks"]-usage["signatures"])
        if allowance<1:
            wire._fail("repair_service_capacity")
        budget=wire.RepairBudget(replace(s.policy,max_signature_checks=allowance))
        original._verify_control_signature(payload,signed["proof"],owner["signing_key"],budget)
        expires=min(held["expires_at"],grant["proof_until"],payload["expires_at"])
        owner_guard=self._owner_guard(rid)
        def guard():
            if s._now()>=expires:
                return "repair_access_expired"
            return owner_guard()
        with s._transaction(guard=guard):
            usage=self._usage_locked(rid)
            if (usage["requests"]>=min(grant["limits"]["max_requests"],offer["budget"]["max_requests"],
                    grant["limits"]["max_replay_records"],offer["budget"]["max_replay_records"])
                    or usage["signatures"]+allowance>grant["limits"]["max_signature_checks"]):
                wire._fail("repair_service_capacity")
            generation=usage["requests"]+1
            self.db.execute("UPDATE open_repair_mailbox_recovery_usage SET requests=requests+1,signatures=signatures+? WHERE resource_id=?",(allowance,rid))
            self._mark_usage_locked(rid)
        try:
            expected=dict(expected_subject=owner,expected_target=s.target,target_storage_epoch=s.node["payload"]["storage_epoch"],
                bootstrap_grant_sha256=inputs["bootstrap"]["ref"]["raw_sha256"],selector=grant["selector"],at=s._now(),
                consumer=self.consumer,policy=budget.policy,budget=budget)
            p,c=s._saved(held,"probe"),s._saved(held,"challenge")
            packet=dict(raw=parsed.raw,ref=ref.as_dict())
            probe.verify_bootstrap_answer(p,c,packet,caller_nonce=bytes(held["nonce"]),**expected)
            with s._transaction(guard=guard):
                old=s._one("SELECT * FROM open_repair_mailbox_recovery_responses WHERE challenge_digest=?",(parent.raw_sha256,))
                if old is not None:
                    if bytes(old["answer"])!=parsed.raw or json.loads(bytes(old["answer_ref"]))!=ref.as_dict():
                        wire._fail("repair_probe_replay_conflict")
                    if s._now()>=old["expires_at"]:
                        wire._fail("repair_access_expired")
                    response_wire=wire.parse_new_wire(bytes(old["response"]),budget.policy,budget).value
                    cost=len(old["response"])+sum(len(original._decode64(response_wire[name],len(response_wire[name])*3//4,budget,url=True))
                        for name in ("handle_raw_base64url","manifest_raw_base64url"))
                    total=self.db.execute("SELECT coalesce(sum(proof_bytes),0) FROM open_repair_mailbox_recovery_responses WHERE resource_id=?",(rid,)).fetchone()[0]
                    if total+cost>grant["limits"]["max_proof_bytes"]:
                        wire._fail("repair_service_capacity")
                    self.db.execute("UPDATE open_repair_mailbox_recovery_responses SET proof_bytes=proof_bytes+? WHERE challenge_digest=?",(cost,parent.raw_sha256))
                    return bytes(old["response"])
            children=self._proof_inputs(rid,budget,"recovery_"+parent.raw_sha256,expires)
            expires=min(expires,*(wire.parse_new_wire(v["raw"],budget.policy,budget).value["payload"]["valid_until"]
                for v in children if v["role"].startswith("current.status.")))
            if len(children)>grant["limits"]["max_proof_items"]:
                wire._fail("repair_service_capacity")
            manifest=dict(schema_version=proof.SCHEMA,kind="bootstrap.proof_manifest",probe_ref=p["ref"],
                subject=probe._dual(owner),target=probe._dual(s.target),target_storage_epoch=expected["target_storage_epoch"],
                consumer=self.consumer,selector=grant["selector"],bootstrap_grant_ref=inputs["bootstrap"]["ref"],
                service_generation=generation,response_profile=self.consumer+"_service_v1",
                children=[dict(index=i,role=v["role"],ref=v["ref"]) for i,v in enumerate(children)])
            response=proof.make_bootstrap_proof_response(s.identity,manifest,probe_ref=p["ref"],challenge_ref=c["ref"],answer_ref=ref.as_dict(),
                subject=owner,target=s.target,at=s._now(),expires_at=expires,handle_id="handle_"+secrets.token_hex(16),policy=budget.policy,budget=budget)
            checked=proof.verify_bootstrap_proof_response(response.raw,expected_subject=owner,expected_target=s.target,
                target_storage_epoch=expected["target_storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=inputs["bootstrap"]["ref"],
                probe_ref=p["ref"],challenge_ref=c["ref"],answer_ref=ref.as_dict(),at=s._now(),
                max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],
                expected_source_state=self.source_state,consumer=self.consumer,policy=budget.policy,budget=budget)
            encoded=wire.build_new_wire([dict(role=v["role"],ref=v["ref"],raw_base64=base64.b64encode(v["raw"]).decode()) for v in children],budget.policy,budget).raw
            transferred=len(response.raw)+len(checked.handle.raw)+len(checked.manifest.raw)
            charge=len(encoded)+len(response.raw)+len(parsed.raw)+ROW_CHARGE
            with s._transaction(guard=guard):
                row=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
                count,total=self.db.execute("SELECT count(*),coalesce(sum(proof_bytes),0) FROM open_repair_mailbox_recovery_responses WHERE resource_id=?",(rid,)).fetchone()
                if (count>=grant["limits"]["max_concurrent_handles"] or total+transferred>grant["limits"]["max_proof_bytes"]
                        or row["metadata_bytes"]+charge>offer["budget"]["max_meta_bytes"]):
                    wire._fail("repair_service_capacity")
                if s._one("SELECT 1 FROM open_repair_mailbox_recovery_responses WHERE challenge_digest=?",(parent.raw_sha256,)):
                    wire._fail("repair_probe_replay_conflict")
                self.db.execute("INSERT INTO open_repair_mailbox_recovery_handles VALUES(?,?,?)",
                    (checked.handle.ref.raw_sha256,canonical_bytes(checked.handle.ref.as_dict()),parent.raw_sha256))
                self.db.execute("INSERT INTO open_repair_mailbox_recovery_responses VALUES(?,?,?,?,?,?,?,?)",
                    (parent.raw_sha256,rid,parsed.raw,canonical_bytes(ref.as_dict()),response.raw,encoded,expires,transferred))
                self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,rid))
            return response.raw
        finally:
            actual=budget.snapshot()["signature_checks"]
            with s._transaction():
                self._usage_locked(rid)
                self.db.execute("UPDATE open_repair_mailbox_recovery_usage SET signatures=signatures-? WHERE resource_id=?",(allowance-actual,rid))
                self._mark_usage_locked(rid)

    def _body_original(self, core_raw, request, metadata_id, budget):
        """Read the separately retained E under current mailbox/data authority."""
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        s=self.source
        signed=wire.parse_new_wire(core_raw,budget.policy,budget).value
        core=signed['payload'];key=core['slot_key']
        if core['kind']!='admission.core' or core['envelope_ref']!=request['envelope_ref']:
            wire._fail('repair_mailbox_member_mismatch')
        original._verify_control_signature(core,signed['proof'],s.identity.public_descriptor(),budget)
        digest=budget._hash(wire._canonical(key,budget))
        row=s._one('SELECT * FROM open_mailbox_admissions WHERE slot_digest=? AND sequence=?',(digest,core['sequence']))
        if row is None:wire._fail('repair_original_missing')
        artifacts=wire.parse_new_wire(bytes(row['result']),budget.policy,budget).value
        if artifacts['core']['raw'].encode()!=core_raw:wire._fail('repair_storage_corrupt')
        job=s._one('SELECT * FROM open_mailbox_message_staging WHERE sender=? AND message_id=?',(row['sender'],row['message_id']))
        if (job is None or job['phase']!='committed' or job['metadata_id']!=metadata_id
                or job['message_id']!=core['message_id']):wire._fail('repair_original_missing')
        data_id=job['data_id'];data=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(data_id,))
        if data is None:wire._fail('repair_original_missing')
        offer=wire.parse_new_wire(s._saved(data,'offer')['raw'],budget.policy,budget).value['payload']
        if offer['resource']!=core['data_resource_ref']:wire._fail('repair_mailbox_member_mismatch')
        scope=status.status_scope(key['root_key'],'resource',offer['resource'],budget.policy,budget)
        required=[dict(issuer=s.identity.key_id,scope_kind='resource',scope_id=scope,
            document_revision=offer['reservation_generation'],operation_mask=2)]
        envelope=bytes(job['envelope']);reference=wire.raw_ref(core['envelope_ref'])
        if len(envelope)!=reference.size or budget._hash(envelope)!=reference.raw_sha256:wire._fail('repair_storage_corrupt')
        def guard():
            if s._now()>=min(core['object_until'],job['retain_until']):return 'repair_access_expired'
            current=s._one('SELECT status FROM open_repair_mailbox_resources WHERE resource_id=?',(data_id,))
            if current is None or current['status']!='active':return 'repair_resource_inactive'
            # Charge the entire shared recovery session conservatively against
            # data's finite request/byte ceiling as well as metadata's budget.
            usage=self._usage_locked(metadata_id)
            transferred=self.db.execute('SELECT coalesce(sum(proof_bytes),0) FROM open_repair_mailbox_recovery_responses WHERE resource_id=?',(metadata_id,)).fetchone()[0]
            if (usage is None or usage['requests']>min(offer['budget']['max_requests'],offer['budget']['max_replay_records'])
                    or transferred>offer['budget']['max_job_bytes']):return 'repair_service_capacity'
            current_job=s._one('SELECT phase,envelope FROM open_mailbox_message_staging WHERE sender=? AND message_id=?',(row['sender'],row['message_id']))
            if current_job is None or current_job['phase']!='committed' or bytes(current_job['envelope'])!=envelope:return 'repair_storage_corrupt'
            return MailboxStatusLedger(self.mailbox.root.resources).check_locked(data_id,required)
        return envelope,guard

    def child(self, entry, *, body=False):
        """Serve a finite signed range from the recipient's frozen proof plan."""
        from dataclasses import replace
        import base64
        import memory_vault_open_repair_probe as probe
        import memory_vault_open_repair_proof as proof
        s=self.source;preview=wire.RepairBudget(s.policy)
        parsed,ref=s._entry(entry,preview)
        signed=proof._fields(parsed.value,{"payload","proof"})
        if body and self.consumer != 'mailbox_feed':wire._fail('repair_invalid_context')
        payload=proof._fields(signed["payload"],(proof.CHILD_FIELDS-{"bootstrap_grant_sha256"}) | ({'envelope_ref'} if body else set()))
        parent=probe._ref(payload["handle_ref"])
        handle=s._one("SELECT * FROM open_repair_mailbox_recovery_handles WHERE handle_digest=?",(parent.raw_sha256,))
        if handle is None or json.loads(bytes(handle["handle_ref"]))!=parent.as_dict():
            wire._fail("repair_service_unavailable")
        response=s._one("SELECT * FROM open_repair_mailbox_recovery_responses WHERE challenge_digest=?",(handle["challenge_digest"],))
        if response is None:
            wire._fail("repair_mailbox_recovery_ledger_missing")
        rid=response["resource_id"]
        resource_row=s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
        inputs,_=self._resource_inputs(rid,preview)
        grant=wire.parse_new_wire(inputs["bootstrap"]["raw"].encode(),s.policy,preview).value["payload"]
        offer=wire.parse_new_wire(s._saved(resource_row,"offer")["raw"],s.policy,preview).value["payload"]
        owner=json.loads(bytes(resource_row["owner_keys"]))
        usage=s._one("SELECT * FROM open_repair_mailbox_recovery_usage WHERE resource_id=?",(rid,))
        if usage is None:
            wire._fail("repair_mailbox_recovery_ledger_missing")
        allowance=min(s.policy.max_signature_checks,grant["limits"]["max_signature_checks"]-usage["signatures"])
        if allowance<1:
            wire._fail("repair_service_capacity")
        budget=wire.RepairBudget(replace(s.policy,max_signature_checks=allowance))
        original._verify_control_signature(payload,signed["proof"],owner["signing_key"],budget)
        owner_guard=self._owner_guard(rid)
        body_guard=lambda: None
        def guard():
            if s._now()>=min(response["expires_at"],grant["proof_until"],payload["expires_at"]):
                return "repair_access_expired"
            return owner_guard() or body_guard()
        with s._transaction(guard=guard):
            usage=self._usage_locked(rid)
            if (usage["requests"]>=min(grant["limits"]["max_requests"],offer["budget"]["max_requests"],
                    grant["limits"]["max_replay_records"],offer["budget"]["max_replay_records"])
                    or usage["signatures"]+allowance>grant["limits"]["max_signature_checks"]):
                wire._fail("repair_service_capacity")
            self.db.execute("UPDATE open_repair_mailbox_recovery_usage SET requests=requests+1,signatures=signatures+? WHERE resource_id=?",(allowance,rid))
            self._mark_usage_locked(rid)
        try:
            answer=wire.parse_new_wire(bytes(response["answer"]),budget.policy,budget).value["payload"]
            frozen=proof.verify_bootstrap_proof_response(bytes(response["response"]),expected_subject=owner,expected_target=s.target,
                target_storage_epoch=s.node["payload"]["storage_epoch"],selector=grant["selector"],bootstrap_grant_ref=inputs["bootstrap"]["ref"],
                probe_ref=answer["probe_ref"],challenge_ref=answer["challenge_ref"],answer_ref=json.loads(bytes(response["answer_ref"])),at=s._now(),
                max_proof_items=grant["limits"]["max_proof_items"],max_proof_bytes=grant["limits"]["max_proof_bytes"],
                expected_source_state=self.source_state,consumer=self.consumer,policy=budget.policy,budget=budget)
            if frozen.handle.ref!=parent:
                wire._fail("repair_proof_mismatch")
            verifier=proof.verify_mailbox_body_request if body else proof.verify_bootstrap_child_request
            request=verifier(dict(raw=parsed.raw,ref=ref.as_dict()),frozen,
                expected_subject=owner,expected_target=s.target,at=s._now(),policy=budget.policy,budget=budget).payload
            children=wire.parse_new_wire(bytes(response["children"]),budget.policy,budget).value
            index=request["child_index"]
            if len(children)!=len(frozen.manifest.value["children"]):
                wire._fail("repair_storage_corrupt")
            item=children[index];expected=frozen.manifest.value["children"][index]
            if item["ref"]!=expected["ref"] or item["role"]!=expected["role"]:
                wire._fail("repair_storage_corrupt")
            # Decode only the requested original, never unbounded adjacent data.
            budget._bytes("input_bytes",len(item["raw_base64"]))
            try:
                raw=base64.b64decode(item["raw_base64"],validate=True)
            except (ValueError,TypeError):
                wire._fail("repair_storage_corrupt")
            if len(raw)!=item["ref"]["size"] or budget._hash(raw)!=item["ref"]["raw_sha256"]:
                wire._fail("repair_storage_corrupt")
            if body:
                raw,body_guard=self._body_original(raw,request,rid,budget)
            budget._bytes("output_bytes",request["requested_bytes"])
            result=raw[request["offset"]:request["offset"]+request["requested_bytes"]]
            with s._transaction(guard=guard):
                if s._one("SELECT 1 FROM open_repair_mailbox_recovery_reads WHERE subject=? AND request_id=?",(owner["signing_key"]["key_id"],request["request_id"])):
                    wire._fail("repair_child_replay")
                current=s._one("SELECT * FROM open_repair_mailbox_recovery_responses WHERE challenge_digest=?",(handle["challenge_digest"],))
                if current is None or bytes(current["children"])!=bytes(response["children"]):
                    wire._fail("repair_access_generation")
                total=self.db.execute("SELECT coalesce(sum(proof_bytes),0) FROM open_repair_mailbox_recovery_responses WHERE resource_id=?",(rid,)).fetchone()[0]
                current_resource=s._one("SELECT metadata_bytes FROM open_repair_mailbox_resources WHERE resource_id=?",(rid,))
                if total+len(result)>grant["limits"]["max_proof_bytes"] or current_resource["metadata_bytes"]+ROW_CHARGE>offer["budget"]["max_meta_bytes"]:
                    wire._fail("repair_service_capacity")
                self.db.execute("INSERT INTO open_repair_mailbox_recovery_reads VALUES(?,?,?,?)",
                    (owner["signing_key"]["key_id"],request["request_id"],rid,ref.raw_sha256))
                self.db.execute("UPDATE open_repair_mailbox_recovery_responses SET proof_bytes=proof_bytes+? WHERE challenge_digest=?",(len(result),handle["challenge_digest"]))
                self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(ROW_CHARGE,rid))
            return result
        finally:
            actual=budget.snapshot()["signature_checks"]
            with s._transaction():
                self._usage_locked(rid)
                self.db.execute("UPDATE open_repair_mailbox_recovery_usage SET signatures=signatures-? WHERE resource_id=?",(allowance-actual,rid))
                self._mark_usage_locked(rid)


class MailboxMessageStaging:
    """Reserve a cold-mailbox admission job for an actually delivered E.

    The existing delivery commit supplies the original sender dual-possession
    exchange. This stage retains exact E and originals but releases no new
    custody or feed head until the complete admission closure is committed.
    """
    def __init__(self, resources, delivery_state):
        from memory_vault_open_delivery_state import DeliveryState
        if not isinstance(delivery_state,DeliveryState) or delivery_state.db is not resources.db or delivery_state.identity.key_id!=resources.source.identity.key_id:
            wire._fail('repair_invalid_context')
        self.resources,self.delivery,self.source,self.db=resources,delivery_state,resources.source,resources.db

    def initialize(self):
        from memory_vault_open_repair_mailbox_root import MailboxRootActivation
        self.root_source=MailboxRootSource(MailboxRootActivation(self.resources));self.root_source.initialize()
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        MailboxStatusLedger(self.resources).initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_message_staging(
                sender TEXT NOT NULL,message_id TEXT NOT NULL,attempt_id TEXT NOT NULL,input_digest TEXT NOT NULL,
                data_id TEXT NOT NULL,metadata_id TEXT NOT NULL,envelope BLOB NOT NULL,originals BLOB NOT NULL,
                owner_status BLOB NOT NULL,resource_status BLOB NOT NULL,staged_at INTEGER NOT NULL,retain_until INTEGER NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('pending','committed')),
                PRIMARY KEY(sender,message_id),UNIQUE(sender,attempt_id))''')

    def stage_delivered(self, draft_raw, owner_status_entry):
        from memory_vault_open_repair_bind import decode_entry
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        from memory_vault_open_delivery import verify_envelope
        if not self.delivery.enabled:wire._fail('repair_remote_setup_closed')
        s=self.source;budget=wire.RepairBudget(s.policy);now=s._now()
        if type(draft_raw) is not bytes or not 0<len(draft_raw)<=131072:wire._fail('repair_message_capacity')
        draft=wire.parse_new_wire(draft_raw,s.policy,budget)
        fields=resource._fields(draft.value,{'disclosure','disclosure_status','attempt','destination','slot','contact'}|({'ack_configuration'} if isinstance(draft.value,dict) and 'ack_configuration' in draft.value else set()))
        def decode(value):return decode_entry(value,s.policy,budget)
        attempt,destination,consent,consent_status=(decode(fields[name]) for name in ('attempt','destination','disclosure','disclosure_status'))
        def control(entry,kind,names,signer):
            doc,ref=s._entry(entry,budget);signed=resource._fields(doc.value,{'payload','proof'})
            p=resource._fields(signed['payload'],resource.COMMON|set(names.split()))
            if p['schema_version']!=resource.SCHEMA or p['kind']!=kind:wire._fail('repair_invalid_message')
            original._verify_control_signature(p,signed['proof'],signer,budget);resource._lifetime(p)
            if not p['issued_at']<=now<p['expires_at']:wire._fail('repair_resource_expired')
            return p,ref
        preview,_=s._entry(destination,budget)
        key=preview.value['payload']['slot_key'];history._slot(key,key['root_key'])
        slot_digest=budget._hash(wire._canonical(key,budget))
        root_digest=budget._hash(wire._canonical(key['root_key'],budget))
        with s._transaction():
            anchor=s._one('SELECT resource_id,slots FROM open_repair_mailbox_roots WHERE root_digest=?',(root_digest,))
            if anchor is None:wire._fail('repair_mailbox_history_missing')
            custody=s._one('SELECT read_until FROM open_repair_mailbox_root_custody WHERE resource_id=?',(anchor['resource_id'],))
            if custody is None or custody['read_until']<=now:wire._fail('repair_mailbox_history_missing')
            catalog=wire.parse_new_wire(bytes(anchor['slots']),s.policy,budget).value
            if key not in [item['slot_key'] for item in catalog]:wire._fail('repair_mailbox_slot_incomplete')
            slot_row=s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?',(slot_digest,))
            if slot_row is None:wire._fail('repair_unknown_resource')
            local=wire.parse_new_wire(bytes(slot_row['inputs']),s.policy,budget).value
            inputs={name:dict(raw=value['raw'].encode(),ref=value['ref']) for name,value in local.items()}
            supplied=resource._fields(fields['slot'],{'slot','read','maintenance'})
            if any(decode(value)!=inputs[name] for name,value in supplied.items()):wire._fail('repair_original_mismatch')
            slot=wire.parse_new_wire(inputs['slot']['raw'],s.policy,budget).value['payload']
            data_id,metadata_id=slot_row['data_resource_id'],slot_row['metadata_resource_id']
            data=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(data_id,))
            metadata=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(metadata_id,))
            if data is None or metadata is None:wire._fail('repair_unknown_resource')
            owner=json.loads(bytes(data['owner_keys']))
        dp,destination_ref=control(destination,'delivery.destination',
            'issued_at expires_at destination_id sender recipient contact_request_ref contact_policy_ref contact_knock_lease_ref contact_decision_ref store_grant_ref slot_key slot_ref data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref budget windows',owner['signing_key'])
        ap,attempt_ref=control(attempt,'delivery.attempt',
            'issued_at expires_at attempt_id message_id envelope_ref sender recipient destination_ref slot_key operation disclosure_ref ack_grant_ref',slot['sender']['signing_key_id'])
        original._opaque(ap['attempt_id']);original._opaque(dp['destination_id'])
        if (ap['operation']!='message.store' or ap['disclosure_ref']!=consent['ref']
                or ap['destination_ref']!=destination_ref.as_dict() or dp['slot_ref']!=inputs['slot']['ref']
                or any(p['slot_key']!=key or p['sender']!=slot['sender'] or p['recipient']!=slot['recipient'] for p in (ap,dp))):
            wire._fail('repair_message_mismatch')
        for name in ('data_resource_ref','metadata_resource_ref','data_resource_offer_ref','metadata_resource_offer_ref','read_grant_ref','maintenance_root_ref'):
            if dp[name]!=slot[name]:wire._fail('repair_message_mismatch')
        resource._budget(dp['budget']);resource._windows(dp['windows'])
        if any(dp['budget'][k]>slot['budget'][k] for k in dp['budget']) or any(dp['windows'][k]>slot['windows'][k] for k in dp['windows']):
            wire._fail('repair_message_mismatch')
        cp=wire.parse_new_wire(consent['raw'],s.policy,budget).value['payload']
        envelope_ref=wire.raw_ref(ap['envelope_ref'])
        if (cp['envelope_ref']!=ap['envelope_ref'] or cp['issued_at']>ap['issued_at'] or not cp['issued_at']<=now<cp['consent_until']):wire._fail('repair_message_mismatch')
        contact_entries={name:decode(value) for name,value in fields['contact'].items()}
        contact={name:value['raw'] for name,value in contact_entries.items()}
        checked=original.verify_contact_originals(contact,sender_key_id=slot['sender']['signing_key_id'],sender_encryption_key_id=slot['sender']['encryption_key_id'],
            recipient_key_id=slot['recipient']['signing_key_id'],recipient_encryption_key_id=slot['recipient']['encryption_key_id'],
            node_key_id=s.identity.key_id,storage_epoch=key['writer_storage_epoch'],at=now,policy=s.policy,budget=budget)
        for field,name in (('contact_request_ref','request'),('contact_policy_ref','policy'),('contact_knock_lease_ref','knock_lease'),('contact_decision_ref','decision'),('store_grant_ref','grant')):
            ref=wire.raw_ref(dp[field]);raw=checked.originals[name].document.raw
            if dp[field]!=contact_entries[name]['ref'] or ref.raw_sha256!=budget._hash(raw) or ref.size!=len(raw):wire._fail('repair_original_mismatch')
        delivered=s._one('SELECT * FROM open_delivery_messages WHERE sender=? AND message_id=?',(slot['sender']['signing_key_id'],ap['message_id']))
        if delivered is None:wire._fail('repair_message_delivery_missing')
        envelope=bytes(delivered['envelope']);intent=json.loads(bytes(delivered['intent']))
        if (json.loads(bytes(delivered['ref']))!=envelope_ref.as_dict() or len(envelope)!=envelope_ref.size
                or budget._hash(envelope)!=envelope_ref.raw_sha256 or delivered['recipient']!=slot['recipient']['signing_key_id']):
            wire._fail('repair_message_mismatch')
        for name,role in (('request','request'),('policy','policy'),('lease','knock_lease'),('decision','decision')):
            if canonical_bytes(intent['payload']['authority'][name])!=contact[role]:wire._fail('repair_original_mismatch')
        self.delivery._authority(intent,now)
        verified=verify_envelope(envelope,sender_signing_key=checked.originals['request'].payload['signing_key'],
            sender_encryption_key=checked.originals['request'].payload['encryption_key'],recipient_signing_key=owner['signing_key'],
            recipient_encryption_key=owner['encryption_key'],now=now)
        if verified['context']['message_id']!=ap['message_id']:wire._fail('repair_message_mismatch')
        from memory_vault_open_repair_mailbox_activation import ACK_CONFIGURATION_ROLES,verify_mailbox_ack_configuration
        if ap['ack_grant_ref'] is None:
            if 'ack_configuration' in fields:wire._fail('repair_message_mismatch')
        else:
            if 'ack_configuration' not in fields or not ACK_CONFIGURATION_ROLES<=set(cp['allowed_roles']):
                wire._fail('repair_status_disclosure')
            configuration=resource._fields(fields['ack_configuration'],ACK_CONFIGURATION_ROLES)
            configuration={name:decode(value) for name,value in configuration.items()}
            if ap['ack_grant_ref']!=configuration['ack.write_grant']['ref']:wire._fail('repair_message_mismatch')
            verify_mailbox_ack_configuration(configuration,
                sender=dict(signing_key=checked.originals['request'].payload['signing_key'],encryption_key=checked.originals['request'].payload['encryption_key']),
                recipient=owner,message_id=ap['message_id'],envelope_ref=ap['envelope_ref'],at=now,policy=s.policy,budget=budget)
        requirements=[];deadlines=[ap['expires_at'],dp['expires_at'],cp['consent_until'],dp['windows']['admit_until'],dp['windows']['retain_until']]
        deadlines.extend(value.payload['expires_at'] for value in checked.originals.values())
        def requirement(kind,subject,revision,mask,issuer):
            scope=status.status_scope(key['root_key'],kind,subject,s.policy,budget)
            requirements.append(dict(issuer=issuer,scope_kind=kind,scope_id=scope,document_revision=revision,operation_mask=mask))
        requirement('mailbox_slot',key,slot['revision'],65,slot['recipient']['signing_key_id'])
        requirement('authority',dict(authority_kind='delivery.destination',authority_sha256=destination_ref.raw_sha256),1,1,slot['recipient']['signing_key_id'])
        for name,mask in (('read',2),('maintenance',65),('bootstrap',10)):
            value=wire.parse_new_wire(inputs[name]['raw'],s.policy,budget).value['payload'];deadlines.append(value['expires_at'])
            if name=='maintenance' and value['operation_mask']&65!=65:wire._fail('repair_message_mismatch')
            requirement('authority',dict(authority_kind=value['kind'],authority_sha256=inputs[name]['ref']['raw_sha256']),value['revision'],mask,slot['recipient']['signing_key_id'])
        owner_scopes=[dict(scope_kind=v['scope_kind'],scope_id=v['scope_id']) for v in requirements]
        requirement('authority',dict(authority_kind='message.disclosure',authority_sha256=consent['ref']['raw_sha256']),cp['revision'],65,slot['sender']['signing_key_id'])
        if cp['operation_mask']&65!=65:wire._fail('repair_message_mismatch')
        ledger=MailboxStatusLedger(self.resources)
        ledger.observe_message_consent(data_id,consent,consent_status,_budget=budget)
        owner_observation=ledger.observe(metadata_id,owner_status_entry,expected_signing_key=owner['signing_key'],allowed_scopes=owner_scopes,_budget=budget)
        if {(value['scope_kind'],value['scope_id']) for value in owner_observation.payload['entries']}!={(value['scope_kind'],value['scope_id']) for value in owner_scopes}:
            wire._fail('repair_status_missing')
        owner_doc,_=s._entry(owner_status_entry,budget)
        digest=budget._hash(draft.raw+owner_doc.raw)
        root_guard=self.root_source.root.owner_status_guard(anchor['resource_id'],_budget=budget)
        deadlines.append(custody['read_until'])
        def guard():
            if s._now()>=min(deadlines):return 'repair_resource_expired'
            return root_guard() or ledger.check_locked(data_id,requirements,_budget=budget)
        with s._transaction(guard=guard):pass
        observations=self.root_source.observe_resources(anchor['resource_id'],'stage_'+attempt_ref.raw_sha256,
            valid_until=min(deadlines),slot_keys=[key],_budget=budget,_transaction_guard=guard)
        resource_scopes=[]
        for row in (data,metadata):
            offer=wire.parse_new_wire(s._saved(row,'offer')['raw'],s.policy,budget).value['payload']
            requirement('resource',offer['resource'],offer['reservation_generation'],67,s.identity.key_id)
            resource_scopes.append(dict(scope_kind='resource',scope_id=requirements[-1]['scope_id']))
        for observation in observations:
            ledger.observe(metadata_id,observation,expected_signing_key=s.identity.public_descriptor(),allowed_scopes=resource_scopes,_budget=budget)
        resource_raw=wire.build_new_wire([dict(raw=value['raw'].decode(),ref=value['ref']) for value in observations],s.policy,budget).raw
        with s._transaction(guard=guard) as committed_at:
            self.delivery._authority_current(intent['payload'],committed_at)
            old=s._one('SELECT * FROM open_mailbox_message_staging WHERE sender=? AND (message_id=? OR attempt_id=?)',
                (slot['sender']['signing_key_id'],ap['message_id'],ap['attempt_id']))
            if old is not None:
                if old['input_digest']!=digest:wire._fail('repair_message_conflict')
                return dict(state='staged',message_id=ap['message_id'],attempt_id=ap['attempt_id'],staged_at=old['staged_at'])
            charge=len(draft.raw)+len(owner_doc.raw)+len(resource_raw)+3*ROW_CHARGE
            for rid in (data_id,metadata_id):
                row=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(rid,))
                offer=wire.parse_new_wire(s._saved(row,'offer')['raw'],s.policy,budget).value['payload']
                caps={name:min(value,dp['budget'][name]) for name,value in offer['budget'].items()}
                if row['status']!='active' or committed_at>=min(offer['windows'][name] for name in ('admit_until','retain_until')):
                    wire._fail('repair_resource_expired')
                used=self.db.execute('SELECT count(*),coalesce(sum(length(envelope)),0) FROM open_mailbox_message_staging WHERE data_id=?',(data_id,)).fetchone()
                pending=self.db.execute("SELECT count(*),coalesce(sum(length(originals)+length(owner_status)+length(resource_status)),0) FROM open_mailbox_message_staging WHERE data_id=? AND phase='pending'",(data_id,)).fetchone()
                if (used[0]>=min(slot['max_live_items'],slot['max_appends'],caps['max_items']) or pending[0]>=min(caps['max_pending'],caps['max_jobs'])
                        or pending[1]+pending[0]*3*ROW_CHARGE+charge>caps['max_job_bytes']):wire._fail('repair_message_capacity')
                if rid==data_id and used[1]+len(envelope)>caps['max_live_bytes']:wire._fail('repair_message_capacity')
                if rid==metadata_id and row['metadata_bytes']+charge>caps['max_meta_bytes']:wire._fail('repair_message_capacity')
            until=min(cp['consent_until'],slot['windows']['retain_until'],dp['windows']['retain_until'])
            self.db.execute('INSERT INTO open_mailbox_message_staging VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (slot['sender']['signing_key_id'],ap['message_id'],ap['attempt_id'],digest,data_id,metadata_id,envelope,draft.raw,owner_doc.raw,resource_raw,committed_at,until,'pending'))
            self.db.execute('UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(charge,metadata_id))
        return dict(state='staged',message_id=ap['message_id'],attempt_id=ap['attempt_id'],staged_at=committed_at)

    def prepare_member_history(self, sender, message_id):
        """Pin the complete original member inputs before an admission core."""
        from memory_vault_open_repair_bind import decode_entry
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        s=self.source;budget=wire.RepairBudget(s.policy)
        original._key_id(sender);original._opaque(message_id)
        requirements=[];deadlines=[]
        def guard():
            if deadlines and s._now()>=min(deadlines):return 'repair_resource_expired'
            if requirements:return MailboxStatusLedger(self.resources).check_locked(resource_id,requirements,_budget=budget)
        with s._transaction(guard=guard) as now:
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_member_history(
                sender TEXT NOT NULL,message_id TEXT NOT NULL,input_digest TEXT NOT NULL,
                manifest BLOB NOT NULL,manifest_ref BLOB NOT NULL,pack BLOB NOT NULL,pack_ref BLOB NOT NULL,
                created_at INTEGER NOT NULL,PRIMARY KEY(sender,message_id))''')
            job=s._one('SELECT * FROM open_mailbox_message_staging WHERE sender=? AND message_id=?',(sender,message_id))
            if job is None:wire._fail('repair_message_delivery_missing')
            old=s._one('SELECT * FROM open_mailbox_member_history WHERE sender=? AND message_id=?',(sender,message_id))
            if old is not None:
                if old['input_digest']!=job['input_digest']:wire._fail('repair_message_conflict')
                return dict(manifest=s._saved(old,'manifest'),pack=s._saved(old,'pack'))
            slot_row=s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE data_resource_id=? AND metadata_resource_id=?',
                (job['data_id'],job['metadata_id']))
            if slot_row is None:wire._fail('repair_mailbox_slot_incomplete')
            local=wire.parse_new_wire(bytes(slot_row['inputs']),s.policy,budget).value
            draft=wire.parse_new_wire(bytes(job['originals']),s.policy,budget).value
            entries={name:dict(raw=value['raw'].encode(),ref=value['ref']) for name,value in local.items()}
            def decoded(value):return decode_entry(value,s.policy,budget)
            def local_entry(value):return dict(raw=value['raw'].encode(),ref=value['ref'])
            roles={};payloads={};resource_id=job['data_id']
            def add(role,entry):
                resource._fields(entry,{'raw','ref'});ref=wire.raw_ref(entry['ref'])
                parsed=original.parse_original_control(entry['raw'],s.policy,budget)
                if ref.namespace!='meta' or len(parsed.raw)!=ref.size or budget._hash(parsed.raw)!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
                roles[role]=dict(raw=parsed.raw,ref=ref.as_dict());payloads[role]=parsed.value['payload']
                return payloads[role]
            for role,name in (('contact.request','request'),('contact.policy','policy'),('contact.decision','decision'),
                    ('contact.store_grant','grant'),('contact.knock_lease','knock_lease'),('contact.delivery_lease','delivery_lease')):
                add(role,decoded(draft['contact'][name]))
            # This exact R descriptor was retained and authenticated at staging;
            # a descriptor issued after that event cannot replace its original.
            add('source.descriptor',decoded(draft['contact']['node']))
            for role,name in (('delivery.destination','destination'),('delivery.attempt','attempt'),('message.disclosure','disclosure'),
                    ('historical.status.disclosure','disclosure_status')):
                add(role,decoded(draft[name]))
            if not {'contact.request','delivery.attempt','message.disclosure','authority.status.disclosure'}<=set(payloads['message.disclosure']['allowed_roles']):
                wire._fail('repair_status_disclosure')
            if 'ack_configuration' in draft:
                from memory_vault_open_repair_mailbox_activation import ACK_CONFIGURATION_ROLES
                configuration=resource._fields(draft['ack_configuration'],ACK_CONFIGURATION_ROLES)
                if not ACK_CONFIGURATION_ROLES<=set(payloads['message.disclosure']['allowed_roles']):wire._fail('repair_status_disclosure')
                for role,value in configuration.items():add(role,decoded(value))
            slot=add('mailbox.slot',entries['slot']);root=slot['slot_key']['root_key']
            for role,name in (('mailbox.read_grant','read'),('mailbox.maintenance_root','maintenance'),('bootstrap.mailbox_feed','bootstrap'),('resource.slot_activation','activation')):
                add(role,entries[name])
            owner_raw=bytes(job['owner_status']);owner_hash=budget._hash(owner_raw)
            owner_entry=dict(raw=owner_raw,ref=dict(namespace='meta',key=owner_hash,raw_sha256=owner_hash,size=len(owner_raw)))
            # Keep the original locator as supplied at staging, including an
            # opaque locator that is distinct from the document content hash.
            saved_owner=s._one('SELECT ref FROM open_repair_mailbox_status_documents WHERE resource_id=? AND raw=? ORDER BY ref_digest LIMIT 1',
                (job['metadata_id'],owner_raw))
            if saved_owner is None:wire._fail('repair_status_missing')
            owner_entry['ref']=json.loads(bytes(saved_owner['ref']))
            for role in ('slot','read','maintenance','bootstrap','destination'):
                add('historical.status.'+role,owner_entry)
            observations=wire.parse_new_wire(bytes(job['resource_status']),s.policy,budget).value
            for name,rid in (('data',job['data_id']),('metadata',job['metadata_id'])):
                row=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(rid,))
                if row is None or row['status']!='active':wire._fail('repair_resource_inactive')
                add('resource.'+name+'_allocate',s._saved(row,'allocation'));add('resource.'+name+'_offer',s._saved(row,'offer'))
                active=add('resource.'+name+'_active',s._saved(slot_row,name+'_active'))
                scope=status.status_scope(root,'resource',active['resource'],s.policy,budget)
                selected=[]
                for value in observations:
                    entry=local_entry(value);p=original.parse_original_control(entry['raw'],s.policy,budget).value['payload']
                    if any(v['scope_kind']=='resource' and v['scope_id']==scope for v in p['entries']):selected.append(entry)
                if len(selected)!=1:wire._fail('repair_status_missing')
                add('historical.status.'+name+'_resource',selected[0])
                requirements.append(dict(issuer=s.identity.key_id,scope_kind='resource',scope_id=scope,
                    document_revision=active['reservation_generation'],operation_mask=66))
            for role,mask in (('mailbox.slot',66),('mailbox.read_grant',2),('mailbox.maintenance_root',66),('bootstrap.mailbox_feed',10),('message.disclosure',66)):
                p=payloads[role];kind='mailbox_slot' if role=='mailbox.slot' else 'authority'
                subject=slot['slot_key'] if kind=='mailbox_slot' else dict(authority_kind=p['kind'],authority_sha256=roles[role]['ref']['raw_sha256'])
                requirements.append(dict(issuer=p['signing_key']['key_id'],scope_kind=kind,scope_id=status.status_scope(root,kind,subject,s.policy,budget),
                    document_revision=p['revision'],operation_mask=mask))
                deadlines.append(p['expires_at'])
                if 'windows' in p:deadlines.extend(p['windows'][name] for name in ('read_until','retain_until'))
                if role=='message.disclosure':deadlines.append(p['consent_until'])
                if role=='bootstrap.mailbox_feed':deadlines.extend(p[name] for name in ('probe_until','proof_until','upload_until'))
            if now>=min(deadlines):wire._fail('repair_resource_expired')
            code=MailboxStatusLedger(self.resources).check_locked(job['data_id'],requirements,_budget=budget)
            if code:wire._fail(code)
            ordered=sorted(roles.items())
            pack=wire.build_raw_pack([value['raw'] for _,value in ordered],s.policy,budget)
            indices={(value.raw_sha256,value.size):i for i,value in enumerate(pack.entries)}
            manifest=history.build_historical_manifest(dict(schema_version=history.SCHEMA,kind='historical.manifest',variant='mailbox_member',
                root_key=root,slot_key=slot['slot_key'],message_id=message_id,envelope_ref=payloads['delivery.attempt']['envelope_ref'],
                attempt_ref=roles['delivery.attempt']['ref'],roles=[dict(role=role,document_ref=value['ref'],pack_ref=pack.ref.as_dict(),
                    entry_index=indices[(value['ref']['raw_sha256'],value['ref']['size'])]) for role,value in ordered]),s.policy,budget)
            digest=budget._hash(manifest.raw);reference=dict(namespace='meta',key=digest,raw_sha256=digest,size=len(manifest.raw))
            metadata=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(job['metadata_id'],))
            offer=wire.parse_new_wire(s._saved(metadata,'offer')['raw'],s.policy,budget).value['payload']
            draft=wire.parse_new_wire(bytes(job['originals']),s.policy,budget).value
            destination=wire.parse_new_wire(decode_entry(draft['destination'],s.policy,budget)['raw'],s.policy,budget).value['payload']
            caps={name:min(value,destination['budget'][name]) for name,value in offer['budget'].items()}
            charge=len(manifest.raw)+len(pack.raw)+(len(pack.entries)+3)*ROW_CHARGE+len(roles)*256
            if metadata['metadata_bytes']+charge>caps['max_meta_bytes'] or len(pack.entries)+2>caps['max_items']:
                wire._fail('repair_message_capacity')
            self.db.execute('INSERT INTO open_mailbox_member_history VALUES(?,?,?,?,?,?,?,?)',
                (sender,message_id,job['input_digest'],manifest.raw,canonical_bytes(reference),pack.raw,canonical_bytes(pack.ref.as_dict()),now))
            self.db.execute('UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(charge,job['metadata_id']))
            return dict(manifest=dict(raw=manifest.raw,ref=reference),pack=dict(raw=pack.raw,ref=pack.ref.as_dict()))

    def commit_member(self, sender, message_id, *, object_until, enum_until):
        """Commit the complete original event and its cold enumeration graph."""
        from memory_vault_network_crypto import encrypt_bytes
        from memory_vault_open_repair_bind import decode_entry
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        import memory_vault_open_repair_mailbox_range as ranges
        s=self.source;budget=wire.RepairBudget(s.policy)
        original._key_id(sender);original._opaque(message_id);wire.u53(object_until);wire.u53(enum_until)
        requirements=[];deadlines=[];resource_id=None
        def guard():
            if deadlines and s._now()>=min(deadlines):return 'repair_resource_expired'
            if requirements:return MailboxStatusLedger(self.resources).check_locked(resource_id,requirements,_budget=budget)
        with s._transaction(guard=guard) as now:
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_admission_objects(
                key TEXT PRIMARY KEY,raw_sha256 TEXT NOT NULL,size INTEGER NOT NULL,raw BLOB NOT NULL)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_admissions(
                sender TEXT NOT NULL,message_id TEXT NOT NULL,slot_digest TEXT NOT NULL,sequence INTEGER NOT NULL,
                input_digest TEXT NOT NULL,result BLOB NOT NULL,PRIMARY KEY(sender,message_id),UNIQUE(slot_digest,sequence))''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_feed_state(
                slot_digest TEXT PRIMARY KEY,count INTEGER NOT NULL,checkpoint BLOB NOT NULL,checkpoint_ref BLOB NOT NULL,
                head BLOB NOT NULL,head_ref BLOB NOT NULL)''')
            job=s._one('SELECT * FROM open_mailbox_message_staging WHERE sender=? AND message_id=?',(sender,message_id))
            if job is None:wire._fail('repair_message_delivery_missing')
            digest=budget._hash(wire.build_new_wire(dict(input_digest=job['input_digest'],object_until=object_until,enum_until=enum_until),s.policy,budget).raw)
            old=s._one('SELECT * FROM open_mailbox_admissions WHERE sender=? AND message_id=?',(sender,message_id))
            if old is not None:
                if old['input_digest']!=digest or job['phase']!='committed':wire._fail('repair_message_conflict')
                saved=wire.parse_new_wire(bytes(old['result']),s.policy,budget).value
                for value in saved.values():
                    ref=wire.raw_ref(value['ref']);raw=value['raw'].encode()
                    stored=s._one('SELECT raw,raw_sha256,size FROM open_mailbox_admission_objects WHERE key=?',(ref.key,))
                    if (stored is None or bytes(stored['raw'])!=raw or stored['raw_sha256']!=ref.raw_sha256
                            or stored['size']!=ref.size or len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256):
                        wire._fail('repair_storage_corrupt')
                current=s._one('SELECT * FROM open_mailbox_feed_state WHERE slot_digest=?',(old['slot_digest'],))
                marker=s._one('SELECT value FROM open_repair_state WHERE name=?',('mailbox_feed:'+old['slot_digest'],))
                if current is None or marker is None or current['count']<=old['sequence']:wire._fail('repair_storage_corrupt')
                head=s._saved(current,'head')
                if marker['value']!=s._expected_binding()+'|'+str(current['count'])+'|'+head['ref']['raw_sha256']:
                    wire._fail('repair_storage_corrupt')
                return {name:dict(raw=value['raw'].encode(),ref=value['ref']) for name,value in saved.items()}
            if job['phase']!='pending':wire._fail('repair_storage_corrupt')
            held=s._one('SELECT * FROM open_mailbox_member_history WHERE sender=? AND message_id=?',(sender,message_id))
            if held is None or held['input_digest']!=job['input_digest']:wire._fail('repair_mailbox_history_missing')
            manifest,pack=s._saved(held,'manifest'),s._saved(held,'pack')
            resolver=wire.LocalRawResolver(s.policy,budget);resolver.put('meta',pack['ref']['key'],pack['raw'])
            resolved=history.resolve_historical_inputs(manifest['raw'],resolver,s.policy,budget)
            docs={value.role:value.original for value in resolved.roles}
            payloads={name:original.parse_original_control(value.raw,s.policy,budget).value['payload'] for name,value in docs.items()}
            slot=payloads['mailbox.slot'];key=slot['slot_key'];root=key['root_key'];resource_id=job['data_id']
            slot_digest=budget._hash(wire._canonical(key,budget))
            expected=history._ROLES['mailbox_member']-{'ack.root_authority','ack.write_grant','bootstrap.ack_offer',
                'historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap'}
            if payloads['delivery.attempt']['ack_grant_ref'] is not None:expected=history._ROLES['mailbox_member']
            if set(docs)!=expected or resolved.manifest.value['message_id']!=message_id or payloads['delivery.attempt']['sender']['signing_key_id']!=sender:
                wire._fail('repair_message_mismatch')
            for role,mask in (('mailbox.slot',66),('mailbox.read_grant',2),('mailbox.maintenance_root',66),('bootstrap.mailbox_feed',10),('message.disclosure',66)):
                p=payloads[role];kind='mailbox_slot' if role=='mailbox.slot' else 'authority'
                subject=key if kind=='mailbox_slot' else dict(authority_kind=p['kind'],authority_sha256=docs[role].ref.raw_sha256)
                requirements.append(dict(issuer=p['signing_key']['key_id'],scope_kind=kind,scope_id=status.status_scope(root,kind,subject,s.policy,budget),
                    document_revision=p['revision'],operation_mask=mask))
                deadlines.append(p['expires_at'])
                if 'windows' in p:deadlines.extend(p['windows'][name] for name in ('read_until','retain_until'))
                if role=='message.disclosure':deadlines.extend((p['consent_until'],p['bootstrap_return']['until']))
                if role=='bootstrap.mailbox_feed':deadlines.extend(p[name] for name in ('probe_until','proof_until','upload_until'))
            rows={}
            for name,rid in (('data',job['data_id']),('metadata',job['metadata_id'])):
                row=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(rid,))
                if row is None or row['status']!='active':wire._fail('repair_resource_inactive')
                offer=wire.parse_new_wire(s._saved(row,'offer')['raw'],s.policy,budget).value['payload'];rows[name]=(row,offer)
                deadlines.extend(offer['windows'][field] for field in ('read_until','retain_until'))
                requirements.append(dict(issuer=s.identity.key_id,scope_kind='resource',scope_id=status.status_scope(root,'resource',offer['resource'],s.policy,budget),
                    document_revision=offer['reservation_generation'],operation_mask=66))
            if not now<object_until<=enum_until<=min(job['retain_until'],*deadlines):wire._fail('repair_resource_expired')
            code=guard()
            if code:wire._fail(code)
            previous=s._one('SELECT * FROM open_mailbox_feed_state WHERE slot_digest=?',(slot_digest,))
            marker_name='mailbox_feed:'+slot_digest;marker=s._one('SELECT value FROM open_repair_state WHERE name=?',(marker_name,))
            count,minimum,maximum=self.db.execute('SELECT count(*),min(sequence),max(sequence) FROM open_mailbox_admissions WHERE slot_digest=?',(slot_digest,)).fetchone()
            if previous is None:
                if marker is not None or count:wire._fail('repair_storage_corrupt')
                previous=s._one('SELECT * FROM open_repair_mailbox_genesis WHERE slot_digest=?',(slot_digest,))
                if previous is None:wire._fail('repair_mailbox_genesis_incomplete')
            prior_head=s._saved(previous,'head');prior_checkpoint=s._saved(previous,'checkpoint')
            hp=wire.parse_new_wire(prior_head['raw'],s.policy,budget).value['payload']
            checkpoint=wire.parse_new_wire(prior_checkpoint['raw'],s.policy,budget).value['payload']
            if (hp['count']!=count or checkpoint['count']!=count or hp['checkpoint_ref']!=prior_checkpoint['ref']
                    or (count and (minimum!=0 or maximum!=count-1 or marker is None
                        or marker['value']!=s._expected_binding()+'|'+str(count)+'|'+prior_head['ref']['raw_sha256']))):wire._fail('repair_storage_corrupt')
            if count>=min(slot['max_appends'],slot['max_live_items']) or (count and enum_until>hp['retain_until']):wire._fail('repair_message_capacity')
            state={name:checkpoint[name] for name in ('slot_binding','count','leaf_root','frontier')}
            state,empty=ranges._state(state,key,s.policy,budget)
            artifacts={};new_objects={}
            def remember(entry):
                ref=entry['ref'];row=s._one('SELECT raw_sha256,size FROM open_mailbox_admission_objects WHERE key=?',(ref['key'],))
                if row is not None and (row['raw_sha256']!=ref['raw_sha256'] or row['size']!=ref['size']):wire._fail('repair_storage_corrupt')
                if row is None:new_objects[ref['key']]=entry
                return entry
            def unsigned(value):
                raw=wire.build_new_wire(value,s.policy,budget).raw;sha=budget._hash(raw)
                return remember(dict(raw=raw,ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(raw))))
            def signed(name,kind,**fields):
                entry=remember(s._sign(dict(schema_version=resource.SCHEMA,kind=kind,signing_key=s.identity.public_descriptor(),**fields),name,budget))
                artifacts[name]=entry;return entry
            def load(reference):
                ref=wire.raw_ref(reference);row=s._one('SELECT raw FROM open_mailbox_admission_objects WHERE key=?',(ref.key,))
                if row is None:wire._fail('repair_original_missing')
                raw=bytes(row['raw'])
                if len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:wire._fail('repair_storage_corrupt')
                return wire.parse_new_wire(raw,s.policy,budget).value
            owner=json.loads(bytes(rows['data'][0]['owner_keys']))
            def seal(entry,kind,**fields):
                context=dict(schema_version=resource.SCHEMA,kind=kind,slot_key=key,plaintext_sha256=entry['ref']['raw_sha256'],plaintext_size=len(entry['raw']),**fields)
                return unsigned(encrypt_bytes(entry['raw'],[owner['encryption_key']],context=context))
            core=signed('core','admission.core',core_id='core_'+digest,slot_key=key,sequence=count,message_id=message_id,
                envelope_ref=resolved.manifest.value['envelope_ref'],attempt_ref=docs['delivery.attempt'].ref.as_dict(),historical_manifest_ref=manifest['ref'],
                data_resource_ref=rows['data'][1]['resource'],metadata_resource_ref=rows['metadata'][1]['resource'],accepted_at=job['staged_at'],object_until=object_until,enum_until=enum_until)
            sealed=seal(core,'admission.sealed_core',sequence=count);artifacts['sealed_core']=sealed
            siblings=[state['frontier'][height] if count&(1<<height) else empty[height] for height in range(16)]
            next_state=ranges.append(state,sealed['ref']['raw_sha256'],expected_slot=key,policy=s.policy,budget=budget)
            ranges.verify_inclusion(next_state,count,sealed['ref']['raw_sha256'],siblings,expected_slot=key,policy=s.policy,budget=budget)
            checkpoint_entry=signed('checkpoint','mailbox.checkpoint',slot_key=key,**next_state,committed_at=now,retain_until=enum_until)
            link=signed('link','admission.link',slot_key=key,sequence=count,message_id=message_id,envelope_ref=resolved.manifest.value['envelope_ref'],
                core_ref=core['ref'],sealed_core_ref=sealed['ref'],historical_manifest_ref=manifest['ref'],checkpoint_ref=checkpoint_entry['ref'],inclusion_path=siblings)
            tail=[];prior_index=None
            if count:
                prior_index=load(hp['range_root_ref'])
                if count%16:
                    last=prior_index
                    while last['kind']=='range.index':last=load(last['children'][-1]['ref'])
                    if last['kind']!='range.repair_page' or last['end']!=count:wire._fail('repair_storage_corrupt')
                    tail=list(last['entries'])
            tail.append(dict(sequence=count,admission_link_ref=link['ref'],sealed_core_ref=sealed['ref']))
            start=count-count%16;end=count+1
            private_page=wire.build_new_wire(dict(schema_version=resource.SCHEMA,kind='range.private_page',slot_key=key,start=start,end=end,entries=tail),s.policy,budget).raw
            private_hash=budget._hash(private_page)
            page_sealed=seal(dict(raw=private_page,ref=dict(namespace='meta',key=private_hash,raw_sha256=private_hash,size=len(private_page))),
                'range.sealed_page',start=start,end=end);artifacts['sealed_page']=page_sealed
            repair_page=unsigned(dict(schema_version=resource.SCHEMA,kind='range.repair_page',slot_key=key,start=start,end=end,sealed_page_ref=page_sealed['ref'],entries=tail))
            artifacts['repair_page']=repair_page
            level=0 if prior_index is None else prior_index['level']
            if end>16**(level+2):
                prior_index=dict(level=level+1,children=[dict(start=0,end=count,ref=hp['range_root_ref'])]);level+=1
            def update_index(value,height):
                children=[] if value is None else list(value['children'])
                child_start=(start//(16**(height+1)))*(16**(height+1))
                index=next((i for i,item in enumerate(children) if item['start']==child_start),len(children))
                child=repair_page if height==0 else update_index(load(children[index]['ref']) if index<len(children) else None,height-1)
                replacement=dict(start=child_start,end=end,ref=child['ref'])
                if index<len(children):children[index]=replacement
                else:children.append(replacement)
                if len(children)>16:wire._fail('repair_mailbox_full')
                return unsigned(dict(schema_version=resource.SCHEMA,kind='range.index',slot_key=key,level=height,start=children[0]['start'],end=end,children=children))
            index_root=update_index(prior_index,level);artifacts['index']=index_root
            head=signed('head','mailbox.feed_head',slot_key=key,checkpoint_ref=checkpoint_entry['ref'],count=end,range_root_ref=index_root['ref'],
                catalog_generation=hp['catalog_generation']+1,committed_at=now,retain_until=enum_until)
            signed('custody','message.custody',root_key=root,slot_key=key,message_id=message_id,envelope_ref=resolved.manifest.value['envelope_ref'],
                admission_link_ref=link['ref'],checkpoint_ref=checkpoint_entry['ref'],feed_head_ref=head['ref'],
                resource_refs=dict(data=rows['data'][1]['resource'],metadata=rows['metadata'][1]['resource']),stored_at=now,object_until=object_until,enum_until=enum_until)
            result=wire.build_new_wire({name:dict(raw=value['raw'].decode(),ref=value['ref']) for name,value in artifacts.items()},s.policy,budget).raw
            charge=sum(len(value['raw'])+ROW_CHARGE for value in new_objects.values())+len(result)+3*ROW_CHARGE
            draft=wire.parse_new_wire(bytes(job['originals']),s.policy,budget).value
            destination=wire.parse_new_wire(decode_entry(draft['destination'],s.policy,budget)['raw'],s.policy,budget).value['payload']
            cap=min(rows['metadata'][1]['budget']['max_meta_bytes'],destination['budget']['max_meta_bytes'])
            if rows['metadata'][0]['metadata_bytes']+charge>cap:wire._fail('repair_message_capacity')
            for value in new_objects.values():
                ref=value['ref'];self.db.execute('INSERT INTO open_mailbox_admission_objects VALUES(?,?,?,?)',(ref['key'],ref['raw_sha256'],ref['size'],value['raw']))
            self.db.execute('INSERT INTO open_mailbox_admissions VALUES(?,?,?,?,?,?)',(sender,message_id,slot_digest,count,digest,result))
            self.db.execute('INSERT OR REPLACE INTO open_mailbox_feed_state VALUES(?,?,?,?,?,?)',(slot_digest,end,checkpoint_entry['raw'],canonical_bytes(checkpoint_entry['ref']),head['raw'],canonical_bytes(head['ref'])))
            self.db.execute('INSERT OR REPLACE INTO open_repair_state VALUES(?,?)',(marker_name,s._expected_binding()+'|'+str(end)+'|'+head['ref']['raw_sha256']))
            self.db.execute("UPDATE open_mailbox_message_staging SET phase='committed' WHERE sender=? AND message_id=?",(sender,message_id))
            self.db.execute('UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(charge,job['metadata_id']))
            return artifacts

    def prepare_feed_history(self, slot_key, *, head_ref=None):
        """Pin a complete local nonempty prefix before a feed custody event.

        This is an internal producer stage; it grants no remote read and signs
        no custody. All member histories and the current index must exist.
        """
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        s=self.source;budget=wire.RepairBudget(s.policy)
        key=wire.build_new_wire(slot_key,s.policy,budget).value;history._slot(key,key['root_key'])
        digest=budget._hash(wire._canonical(key,budget));requirements=[];resource_id=None;deadlines=[]
        def guard():
            if deadlines and s._now()>=min(deadlines):return 'repair_resource_expired'
            if requirements:return MailboxStatusLedger(self.resources).check_locked(resource_id,requirements,_budget=budget)
        with s._transaction(guard=guard) as now:
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_feed_history(
                slot_digest TEXT NOT NULL,head_digest TEXT NOT NULL,manifest BLOB NOT NULL,manifest_ref BLOB NOT NULL,
                pack BLOB NOT NULL,pack_ref BLOB NOT NULL,created_at INTEGER NOT NULL,
                PRIMARY KEY(slot_digest,head_digest))''')
            feed=s._one('SELECT * FROM open_mailbox_feed_state WHERE slot_digest=?',(digest,))
            slot_row=s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?',(digest,))
            if feed is None or slot_row is None or not feed['count']:wire._fail('repair_mailbox_feed_missing')
            head=s._saved(feed,'head');checkpoint=s._saved(feed,'checkpoint')
            hp=wire.parse_new_wire(head['raw'],s.policy,budget).value['payload']
            marker=s._one('SELECT value FROM open_repair_state WHERE name=?',('mailbox_feed:'+digest,))
            if (hp['count']!=feed['count'] or hp['slot_key']!=key or hp['checkpoint_ref']!=checkpoint['ref']
                    or marker is None or marker['value']!=s._expected_binding()+'|'+str(feed['count'])+'|'+head['ref']['raw_sha256']):
                wire._fail('repair_storage_corrupt')
            old=s._one('SELECT * FROM open_mailbox_feed_history WHERE slot_digest=? AND head_digest=?',(digest,head['ref']['raw_sha256']))
            if old is not None and (head_ref is None or head_ref==head['ref']):return dict(manifest=s._saved(old,'manifest'),pack=s._saved(old,'pack'))
            resource_id=slot_row['metadata_resource_id'];roles={};member_packs=[];members=[];expected_links={};status_roles={}
            def add(role,entry):
                ref=wire.raw_ref(entry['ref']);raw=entry['raw']
                if ref.namespace!='meta' or len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
                roles[(role,*history._ref_tuple(ref.as_dict()))]=dict(raw=raw,ref=ref.as_dict())
            def load(reference):
                ref=wire.raw_ref(reference);row=s._one('SELECT raw FROM open_mailbox_admission_objects WHERE key=?',(ref.key,))
                if row is None:wire._fail('repair_original_missing')
                raw=bytes(row['raw'])
                if ref.namespace!='meta' or len(raw)!=ref.size or budget._hash(raw)!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
                return dict(raw=raw,ref=ref.as_dict())
            if head_ref is not None and head_ref!=head['ref']:
                selected=load(head_ref)
                selected_payload=wire.parse_new_wire(selected['raw'],s.policy,budget).value['payload']
                if (selected_payload['kind']!='mailbox.feed_head' or selected_payload['slot_key']!=key
                        or not 0<wire.u53(selected_payload['count'])<=feed['count']):wire._fail('repair_message_mismatch')
                head=selected;hp=selected_payload;checkpoint=load(hp['checkpoint_ref'])
                feed=dict(feed,count=hp['count'])
                held=s._one('SELECT result FROM open_mailbox_admissions WHERE slot_digest=? AND sequence=?',(digest,feed['count']-1))
                if held is None or wire.parse_new_wire(bytes(held['result']),s.policy,budget).value['head']['ref']!=head['ref']:
                    wire._fail('repair_storage_corrupt')
                old=s._one('SELECT * FROM open_mailbox_feed_history WHERE slot_digest=? AND head_digest=?',(digest,head['ref']['raw_sha256']))
                if old is not None:return dict(manifest=s._saved(old,'manifest'),pack=s._saved(old,'pack'))
            rows=self.db.execute('SELECT * FROM open_mailbox_admissions WHERE slot_digest=? AND sequence<? ORDER BY sequence',(digest,feed['count'])).fetchall()
            if len(rows)!=feed['count']:wire._fail('repair_storage_corrupt')
            for sequence,row in enumerate(rows):
                if row['sequence']!=sequence:wire._fail('repair_storage_corrupt')
                result=wire.parse_new_wire(bytes(row['result']),s.policy,budget).value
                artifacts={name:load(value['ref']) for name,value in result.items()}
                held=s._one('SELECT * FROM open_mailbox_member_history WHERE sender=? AND message_id=?',(row['sender'],row['message_id']))
                if held is None:wire._fail('repair_mailbox_history_missing')
                manifest,pack=s._saved(held,'manifest'),s._saved(held,'pack');member_packs.append(pack)
                resolver=wire.LocalRawResolver(s.policy,budget);resolver.put('meta',pack['ref']['key'],pack['raw'])
                resolved=history.resolve_historical_inputs(manifest['raw'],resolver,s.policy,budget)
                docs={item.role:item.original for item in resolved.roles}
                for role in history._SLOT_INPUT: add(role,dict(raw=docs[role].raw,ref=docs[role].ref.as_dict()))
                core=wire.parse_new_wire(artifacts['core']['raw'],s.policy,budget).value['payload']
                if (core['sequence']!=sequence or core['slot_key']!=key or core['historical_manifest_ref']!=manifest['ref']
                        or core['message_id']!=row['message_id']):wire._fail('repair_storage_corrupt')
                deadlines.append(core['enum_until'])
                add('history.member',manifest)
                for name in ('core','link','custody','checkpoint','head','sealed_core'):add('member.'+name,artifacts[name])
                members.append(dict(sequence=sequence,message_id=core['message_id'],envelope_ref=core['envelope_ref'],
                    historical_manifest_ref=manifest['ref'],admission_core_ref=artifacts['core']['ref'],
                    admission_link_ref=artifacts['link']['ref'],source_custody_ref=artifacts['custody']['ref']))
                expected_links[sequence]=dict(sequence=sequence,admission_link_ref=artifacts['link']['ref'],sealed_core_ref=artifacts['sealed_core']['ref'])
                for role,mask in (('mailbox.slot',66),('mailbox.read_grant',2),('mailbox.maintenance_root',66),('bootstrap.mailbox_feed',10),('message.disclosure',66)):
                    p=original.parse_original_control(docs[role].raw,s.policy,budget).value['payload']
                    kind='mailbox_slot' if role=='mailbox.slot' else 'authority'
                    subject=key if kind=='mailbox_slot' else dict(authority_kind=p['kind'],authority_sha256=docs[role].ref.raw_sha256)
                    scope=status.status_scope(key['root_key'],kind,subject,s.policy,budget)
                    requirement=dict(issuer=p['signing_key']['key_id'],scope_kind=kind,scope_id=scope,document_revision=p['revision'],operation_mask=mask)
                    if requirement not in requirements:requirements.append(requirement)
                    status_roles[(requirement['issuer'],kind,scope)]={'mailbox.slot':'slot','mailbox.read_grant':'read','mailbox.maintenance_root':'maintenance','bootstrap.mailbox_feed':'bootstrap','message.disclosure':'disclosure'}[role]
                    deadlines.append(p['expires_at'])
                    if 'windows' in p:deadlines.extend(p['windows'][name] for name in ('read_until','retain_until'))
                    if role=='message.disclosure':deadlines.extend((p['consent_until'],p['bootstrap_return']['until']))
                    if role=='bootstrap.mailbox_feed':deadlines.extend(p[name] for name in ('probe_until','proof_until','upload_until'))
            metadata=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(resource_id,))
            if metadata is None or metadata['status']!='active':wire._fail('repair_resource_inactive')
            offer=wire.parse_new_wire(s._saved(metadata,'offer')['raw'],s.policy,budget).value['payload']
            scope=status.status_scope(key['root_key'],'resource',offer['resource'],s.policy,budget)
            requirements.append(dict(issuer=s.identity.key_id,scope_kind='resource',scope_id=scope,document_revision=offer['reservation_generation'],operation_mask=66))
            deadlines.extend(offer['windows'][name] for name in ('read_until','retain_until'))
            code=guard()
            if code:wire._fail(code)
            root_digest=budget._hash(wire._canonical(key['root_key'],budget))
            for item in requirements:
                floor=s._one('SELECT max(revision) AS revision FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?',
                    (root_digest,item['issuer'],item['scope_kind'],item['scope_id']))
                observed=s._one('SELECT raw,ref FROM open_repair_mailbox_status_documents WHERE root_digest=? AND issuer=? AND revision=? ORDER BY ref_digest LIMIT 1',
                    (root_digest,item['issuer'],floor['revision'] if floor is not None else -1))
                if observed is None:wire._fail('repair_status_missing')
                name='metadata_resource' if item['scope_kind']=='resource' else status_roles[(item['issuer'],item['scope_kind'],item['scope_id'])]
                add('historical.status.'+name,dict(raw=bytes(observed['raw']),ref=json.loads(bytes(observed['ref']))))
            add('feed.head',head);add('feed.checkpoint',checkpoint)
            def walk(reference,level,start,end):
                entry=load(reference);p=wire.parse_new_wire(entry['raw'],s.policy,budget).value
                if p['slot_key']!=key or p['start']!=start or p['end']!=end:wire._fail('repair_storage_corrupt')
                if level>=0:
                    if p['kind']!='range.index' or p['level']!=level or not 1<=len(p['children'])<=16:wire._fail('repair_storage_corrupt')
                    add('range.index',entry);cursor=start;span=16**(level+1)
                    for child in p['children']:
                        stop=min(cursor+span,end)
                        if child['start']!=cursor or child['end']!=stop or cursor>=stop:wire._fail('repair_storage_corrupt')
                        walk(child['ref'],level-1,cursor,stop);cursor=stop
                    if cursor!=end:wire._fail('repair_storage_corrupt')
                else:
                    if p['kind']!='range.repair_page' or list(p['entries'])!=[expected_links[i] for i in range(start,end)]:wire._fail('repair_storage_corrupt')
                    add('range.repair_page',entry);add('range.sealed_page',load(p['sealed_page_ref']))
            level=0
            while feed['count']>16**(level+2):level+=1
            walk(hp['range_root_ref'],level,0,feed['count'])
            ordered=sorted(roles.items());pack=wire.build_raw_pack([value['raw'] for _,value in ordered],s.policy,budget)
            indices={(v.raw_sha256,v.size):i for i,v in enumerate(pack.entries)}
            manifest=history.build_historical_manifest(dict(schema_version=history.SCHEMA,kind='historical.manifest',variant='mailbox_feed',
                root_key=key['root_key'],slot_key=key,slot_ref=dict(next(v for (name,*_),v in roles.items() if name=='mailbox.slot')['ref']),
                feed_head_ref=head['ref'],covered_interval=dict(start=0,end=feed['count']),subtree=dict(root_ref=hp['range_root_ref'],parent_path_refs=[]),members=members,
                roles=[dict(role=role[0],document_ref=value['ref'],pack_ref=pack.ref.as_dict(),entry_index=indices[(value['ref']['raw_sha256'],value['ref']['size'])]) for role,value in ordered]),s.policy,budget)
            resolver=wire.LocalRawResolver(s.policy,budget);resolver.put('meta',pack.ref.key,pack.raw)
            for value in member_packs:resolver.put('meta',value['ref']['key'],value['raw'])
            history.resolve_historical_inputs(manifest.raw,resolver,s.policy,budget)
            charge=len(manifest.raw)+len(pack.raw)+(len(roles)+3)*ROW_CHARGE
            if metadata['metadata_bytes']+charge>offer['budget']['max_meta_bytes']:wire._fail('repair_message_capacity')
            sha=budget._hash(manifest.raw);ref=dict(namespace='meta',key=sha,raw_sha256=sha,size=len(manifest.raw))
            self.db.execute('INSERT INTO open_mailbox_feed_history VALUES(?,?,?,?,?,?,?)',(digest,head['ref']['raw_sha256'],manifest.raw,canonical_bytes(ref),pack.raw,canonical_bytes(pack.ref.as_dict()),now))
            self.db.execute('UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(charge,resource_id))
            return dict(manifest=dict(raw=manifest.raw,ref=ref),pack=dict(raw=pack.raw,ref=pack.ref.as_dict()))

    def finalize_feed(self, slot_key, head_ref, *, read_until, retain_until):
        """Atomically record original feed custody over an existing full prefix."""
        from memory_vault_open_repair_mailbox_activation import verify_mailbox_feed_history_inputs
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        s=self.source;budget=wire.RepairBudget(s.policy)
        key=wire.build_new_wire(slot_key,s.policy,budget).value;history._slot(key,key['root_key'])
        head=wire.raw_ref(head_ref);wire.u53(read_until);wire.u53(retain_until)
        digest=budget._hash(wire._canonical(key,budget));requirements=[];resource_id=None;deadlines=[]
        binding=budget._hash(wire.build_new_wire(dict(slot_key=key,head_ref=head.as_dict(),read_until=read_until,retain_until=retain_until),s.policy,budget).raw)
        def guard():
            if deadlines and s._now()>=min(deadlines):return 'repair_resource_expired'
            if requirements:return MailboxStatusLedger(self.resources).check_locked(resource_id,requirements,_budget=budget)
        with s._transaction(guard=guard) as now:
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_mailbox_feed_custody(
                slot_digest TEXT NOT NULL,head_digest TEXT NOT NULL,input_digest TEXT NOT NULL,
                custody BLOB NOT NULL,custody_ref BLOB NOT NULL,stored_at INTEGER NOT NULL,
                PRIMARY KEY(slot_digest,head_digest))''')
            marker_name='mailbox_feed_custody:'+digest+':'+head.raw_sha256
            marker=s._one('SELECT value FROM open_repair_state WHERE name=?',(marker_name,))
            old=s._one('SELECT * FROM open_mailbox_feed_custody WHERE slot_digest=? AND head_digest=?',(digest,head.raw_sha256))
            if old is not None:
                custody=s._saved(old,'custody')
                if old['input_digest']!=binding:wire._fail('repair_message_conflict')
                if marker is None or marker['value']!=s._expected_binding()+'|'+custody['ref']['raw_sha256']:wire._fail('repair_storage_corrupt')
                return custody
            if marker is not None:wire._fail('repair_storage_corrupt')
            held=s._one('SELECT * FROM open_mailbox_feed_history WHERE slot_digest=? AND head_digest=?',(digest,head.raw_sha256))
            slot_row=s._one('SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?',(digest,))
            if held is None or slot_row is None:wire._fail('repair_mailbox_history_missing')
            manifest,pack=s._saved(held,'manifest'),s._saved(held,'pack')
            parsed=history.parse_historical_manifest(manifest['raw'],s.policy,budget)
            if parsed.value['feed_head_ref']!=head.as_dict():wire._fail('repair_ref_mismatch')
            local=wire.parse_new_wire(bytes(slot_row['inputs']),s.policy,budget).value
            slot=wire.parse_new_wire(local['slot']['raw'].encode(),s.policy,budget).value['payload']
            resource_id=slot_row['metadata_resource_id']
            metadata=s._one('SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?',(resource_id,))
            if metadata is None or metadata['status']!='active':wire._fail('repair_resource_inactive')
            resolver=wire.LocalRawResolver(s.policy,budget);resolver.put('meta',pack['ref']['key'],pack['raw'])
            for member in parsed.value['members']:
                row=s._one('SELECT * FROM open_mailbox_member_history WHERE sender=? AND message_id=?',(slot['sender']['signing_key_id'],member['message_id']))
                if row is None:wire._fail('repair_original_missing')
                prior=s._saved(row,'pack');resolver.put('meta',prior['ref']['key'],prior['raw'])
            resolved=history.resolve_historical_inputs(manifest['raw'],resolver,s.policy,budget)
            request=next(v.original.raw for v in resolved.predecessors[0].roles if v.role=='contact.request')
            p=original.parse_original_control(request,s.policy,budget).value['payload']
            sender=dict(signing_key=p['signing_key'],encryption_key=p['encryption_key'])
            graph=verify_mailbox_feed_history_inputs(resolved,expected_slot=key,expected_owner=json.loads(bytes(metadata['owner_keys'])),
                expected_sender=sender,expected_target=s.target,at=now,limit_policy=s.limits,policy=s.policy,budget=budget)
            if not now<read_until<=retain_until<=graph['retain_until']:wire._fail('repair_resource_expired')
            deadlines.append(read_until)
            for item in graph['obligations']:
                requirements.append(dict(issuer=item['signer']['key_id'],**{name:item[name] for name in ('scope_kind','scope_id','document_revision','operation_mask')}))
            code=guard()
            if code:wire._fail(code)
            custody=s._sign(dict(schema_version=resource.SCHEMA,kind='feed.custody',signing_key=s.identity.public_descriptor(),
                root_key=key['root_key'],slot_key=key,slot_ref=parsed.value['slot_ref'],feed_head_ref=head.as_dict(),
                covered_interval=parsed.value['covered_interval'],subtree=parsed.value['subtree'],historical_manifest_ref=manifest['ref'],
                resource_refs=dict(metadata=graph['metadata_resource'],dependencies=[]),stored_at=now,read_until=read_until,retain_until=retain_until),'feed_custody',budget)
            offer=wire.parse_new_wire(s._saved(metadata,'offer')['raw'],s.policy,budget).value['payload']
            charge=len(custody['raw'])+len(canonical_bytes(custody['ref']))+3*ROW_CHARGE
            if metadata['metadata_bytes']+charge>min(offer['budget']['max_meta_bytes'],slot['budget']['max_meta_bytes']):wire._fail('repair_message_capacity')
            self.db.execute('INSERT INTO open_mailbox_feed_custody VALUES(?,?,?,?,?,?)',(digest,head.raw_sha256,binding,custody['raw'],canonical_bytes(custody['ref']),now))
            self.db.execute('INSERT INTO open_repair_state VALUES(?,?)',(marker_name,s._expected_binding()+'|'+custody['ref']['raw_sha256']))
            self.db.execute('UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?',(charge,resource_id))
            return custody
