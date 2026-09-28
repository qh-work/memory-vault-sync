"""Durable mailbox status observations, retained even when live use is denied.

Local callers derive disclosure scopes and required bits from their original
owner chain. This journal is neither an HTTP endpoint nor a source of grants.
"""
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire
from memory_vault_open_repair_state import ROW_CHARGE


class MailboxStatusLedger:
    def __init__(self, resources):
        self.resources,self.source,self.db = resources,resources.source,resources.db

    def initialize(self):
        self.resources.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_status_state(
                resource_id TEXT PRIMARY KEY,root_digest TEXT NOT NULL,generation INTEGER NOT NULL,
                documents INTEGER NOT NULL,floors INTEGER NOT NULL,blocked TEXT)''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_status_documents(
                resource_id TEXT NOT NULL,root_digest TEXT NOT NULL,issuer TEXT NOT NULL,
                revision INTEGER NOT NULL,digest TEXT NOT NULL,ref_digest TEXT NOT NULL,
                raw BLOB NOT NULL,ref BLOB NOT NULL,
                PRIMARY KEY(resource_id,issuer,digest,ref_digest))''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_status_floors(
                resource_id TEXT NOT NULL,root_digest TEXT NOT NULL,issuer TEXT NOT NULL,
                scope_kind TEXT NOT NULL,scope_id TEXT NOT NULL,revision INTEGER NOT NULL,
                minimum_revision INTEGER NOT NULL,revoked_mask INTEGER NOT NULL,
                active_mask INTEGER NOT NULL,valid_until INTEGER NOT NULL,observed_minimum INTEGER NOT NULL,
                PRIMARY KEY(resource_id,issuer,scope_kind,scope_id))''')
            self.db.execute('''CREATE INDEX IF NOT EXISTS open_repair_mailbox_status_revisions
                ON open_repair_mailbox_status_documents(root_digest,issuer,revision,digest)''')
            self.db.execute('''CREATE INDEX IF NOT EXISTS open_repair_mailbox_status_scopes
                ON open_repair_mailbox_status_floors(root_digest,issuer,scope_kind,scope_id)''')

    def _context(self, resource_id, budget):
        s = self.source
        row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",(resource_id,))
        if row is None or row["status"] != "active":
            wire._fail("repair_resource_inactive")
        offer = s._saved(row,"offer")
        p = wire.parse_new_wire(offer["raw"],s.policy,budget).value["payload"]
        root = p["intent"]["root_key"]
        return row,p,root,budget._hash(wire._canonical(root,budget))

    def _latch(self, root_digest, code):
        self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES(?,?)",
                        ("mailbox_status_blocked:"+root_digest,code))
        return code

    def _integrity(self, root_digest):
        s = self.source
        latch = s._one("SELECT value FROM open_repair_state WHERE name=?",("mailbox_status_blocked:"+root_digest,))
        if latch is not None:
            return latch["value"]
        binding = s._expected_binding()+"|"+root_digest
        resources = {name[len("mailbox_status:"):] for (name,) in self.db.execute(
            "SELECT name FROM open_repair_state WHERE name GLOB 'mailbox_status:*' AND value=?",(binding,)).fetchall()}
        for table in ("state","documents","floors"):
            resources.update(row[0] for row in self.db.execute("SELECT DISTINCT resource_id FROM open_repair_mailbox_status_"+table+" WHERE root_digest=?",(root_digest,)))
        for resource_id in resources:
            marker = s._one("SELECT value FROM open_repair_state WHERE name=?",("mailbox_status:"+resource_id,))
            held = s._one("SELECT * FROM open_repair_mailbox_status_state WHERE resource_id=?",(resource_id,))
            counts = self.db.execute('''SELECT
                (SELECT count(*) FROM open_repair_mailbox_status_documents WHERE resource_id=?),
                (SELECT count(*) FROM open_repair_mailbox_status_floors WHERE resource_id=?)''',(resource_id,resource_id)).fetchone()
            if (marker is None or marker["value"] != binding or held is None
                    or held["root_digest"] != root_digest or tuple(counts) != (held["documents"],held["floors"])):
                return self._latch(root_digest,"repair_mailbox_status_ledger_missing")
            if held["blocked"]:
                return self._latch(root_digest,held["blocked"])
        return None

    def _record(self, row, offer, root_digest, observed, budget):
        s = self.source; resource_id = row["resource_id"]
        code = self._integrity(root_digest)
        if code:
            return code
        held = s._one("SELECT * FROM open_repair_mailbox_status_state WHERE resource_id=?",(resource_id,))
        marker = "mailbox_status:"+resource_id
        marker_row = s._one("SELECT value FROM open_repair_state WHERE name=?",(marker,))
        binding = s._expected_binding()+"|"+root_digest
        if held is not None and (marker_row is None or marker_row["value"] != binding):
            return self._latch(root_digest,"repair_mailbox_status_ledger_missing")
        initial = ROW_CHARGE if held is None else 0
        if held is None:
            if marker_row is not None or any(self.db.execute("SELECT 1 FROM "+table+" WHERE resource_id=? LIMIT 1",(resource_id,)).fetchone()
                    for table in ("open_repair_mailbox_status_documents","open_repair_mailbox_status_floors")):
                return self._latch(root_digest,"repair_mailbox_status_ledger_missing")
            held = dict(generation=0,documents=0,floors=0)
        p = observed.payload; issuer = p["scope_key"]["issuer_key_id"]
        ref = wire.build_new_wire(observed.ref.as_dict(),s.policy,budget).raw
        ref_digest = budget._hash(ref)
        old = s._one("SELECT 1 FROM open_repair_mailbox_status_documents WHERE resource_id=? AND issuer=? AND digest=? AND ref_digest=?",
                     (resource_id,issuer,observed.canonical_sha256,ref_digest))
        if old is not None:
            return None
        priors = {(v["scope_kind"],v["scope_id"]):s._one("SELECT * FROM open_repair_mailbox_status_floors WHERE resource_id=? AND issuer=? AND scope_kind=? AND scope_id=?",
                  (resource_id,issuer,v["scope_kind"],v["scope_id"])) for v in p["entries"]}
        new_floors = sum(v is None for v in priors.values())
        charge = initial+len(observed.raw)+len(ref)+ROW_CHARGE+new_floors*ROW_CHARGE
        if (row["metadata_bytes"]+charge > offer["budget"]["max_meta_bytes"]
                or held["documents"]+1 > min(offer["budget"]["max_replay_records"],s.limits["max_replay_records"])):
            return self._latch(root_digest,"repair_mailbox_status_capacity")
        conflict = s._one("SELECT 1 FROM open_repair_mailbox_status_documents WHERE root_digest=? AND issuer=? AND revision=? AND digest<>? LIMIT 1",
            (root_digest,issuer,p["revision"],observed.canonical_sha256)) is not None
        self.db.execute("INSERT INTO open_repair_mailbox_status_documents VALUES(?,?,?,?,?,?,?,?)",
            (resource_id,root_digest,issuer,p["revision"],observed.canonical_sha256,ref_digest,observed.raw,ref))
        rollback = False
        for item in p["entries"]:
            prior = priors[(item["scope_kind"],item["scope_id"])]
            previous = self.db.execute("SELECT coalesce(max(revision),0),coalesce(max(minimum_revision),0) FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?",
                (root_digest,issuer,item["scope_kind"],item["scope_id"])).fetchone()
            rollback |= p["revision"] < previous[0] or item["minimum_document_revision"] < previous[1]
            latest = prior is None or p["revision"] >= prior["revision"]
            values = (resource_id,root_digest,issuer,item["scope_kind"],item["scope_id"],
                max(p["revision"],prior["revision"] if prior else 0),
                max(item["minimum_document_revision"],prior["minimum_revision"] if prior else 0),
                (prior["revoked_mask"] if prior else 0) | (item["operation_mask"] if item["status"] == "revoked" else 0),
                (item["operation_mask"] if item["status"] == "active" else 0) if latest else prior["active_mask"],
                p["valid_until"] if latest else prior["valid_until"],
                item["minimum_document_revision"] if latest else prior["observed_minimum"])
            self.db.execute('''INSERT INTO open_repair_mailbox_status_floors VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(resource_id,issuer,scope_kind,scope_id) DO UPDATE SET
                revision=excluded.revision,minimum_revision=excluded.minimum_revision,revoked_mask=excluded.revoked_mask,
                active_mask=excluded.active_mask,valid_until=excluded.valid_until,observed_minimum=excluded.observed_minimum''',values)
        self.db.execute('''INSERT INTO open_repair_mailbox_status_state VALUES(?,?,?,?,?,?)
            ON CONFLICT(resource_id) DO UPDATE SET generation=excluded.generation,documents=excluded.documents,
            floors=excluded.floors,blocked=excluded.blocked''',
            (resource_id,root_digest,held["generation"]+1,held["documents"]+1,held["floors"]+new_floors,
             "repair_status_conflict" if conflict else None))
        self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES(?,?)",(marker,binding))
        self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",(charge,resource_id))
        return self._latch(root_digest,"repair_status_conflict") if conflict else ("repair_status_rollback" if rollback else None)

    def observe(self, resource_id, entry, *, expected_signing_key, allowed_scopes, _budget=None):
        """Commit authenticated denials/expired observations before raising."""
        s = self.source; error = None; recorded_code = []; observed = None
        with s._transaction() as now:
            budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
            wire._context(s.policy,budget)
            row,offer,root,root_digest = self._context(resource_id,budget)
            expected_signing_key = wire.build_new_wire(expected_signing_key,s.policy,budget).value
            if expected_signing_key not in (offer["intent"]["owner"]["signing_key"],s.identity.public_descriptor()):
                wire._fail("repair_wrong_issuer")
            def retain(value):
                recorded_code.append(self._record(row,offer,root_digest,value,budget))
            try:
                observed = status.authenticate_status_original(entry,expected_root=root,expected_signing_key=expected_signing_key,
                    at=now,allowed_scopes=allowed_scopes,policy=s.policy,budget=budget,on_authenticated=retain)
            except wire.RepairWireError as caught:
                error = caught
        if any(recorded_code):
            wire._fail(next(code for code in recorded_code if code))
        if error is not None:
            raise error
        return observed

    def observe_message_consent(self, resource_id, consent_entry, status_entry, *, _budget=None):
        """Retain A's whole consent status only for the committed slot's sender.

        This records current evidence; no upload, append or custody is granted.
        Expired or revoked observations remain durable before use is refused.
        """
        import memory_vault_open_repair_resource as resource
        import memory_vault_open_repair_history as history
        s=self.source;budget=_budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget);error=None;recorded=[];observed=None
        with s._transaction() as now:
            row,offer,root,root_digest=self._context(resource_id,budget)
            slot_row=s._one("SELECT inputs FROM open_repair_mailbox_slot_activations WHERE data_resource_id=? OR metadata_resource_id=?",
                (resource_id,resource_id))
            if slot_row is None:wire._fail("repair_unknown_resource")
            entries=wire.parse_new_wire(bytes(slot_row['inputs']),s.policy,budget).value
            slot=wire.parse_new_wire(entries['slot']['raw'].encode(),s.policy,budget).value['payload']
            maintenance=wire.parse_new_wire(entries['maintenance']['raw'].encode(),s.policy,budget).value['payload']
            parsed,ref=s._entry(consent_entry,budget)
            signed=resource._fields(parsed.value,{'payload','proof'})
            p=resource._fields(signed['payload'],resource.COMMON|set('issued_at expires_at consent_id root_key slot_key sender recipient envelope_ref maintenance_root_ref allowed_roles operation_mask consent_until bootstrap_return revision'.split()))
            if p['schema_version']!=resource.SCHEMA or p['kind']!='message.disclosure':wire._fail('repair_invalid_message')
            resource._lifetime(p);status.original._opaque(p['consent_id']);wire.u53(p['revision'],1)
            envelope_ref=wire.raw_ref(p['envelope_ref']);status._mask(p['operation_mask'])
            if envelope_ref.namespace!='object':wire._fail('repair_message_mismatch')
            history._dual(p['sender']);history._dual(p['recipient'])
            if (p['root_key']!=root or p['slot_key']!=slot['slot_key'] or p['sender']!=slot['sender'] or p['recipient']!=slot['recipient']
                    or p['maintenance_root_ref']!=entries['maintenance']['ref']
                    or not p['issued_at']<wire.u53(p['consent_until'])<=p['expires_at']<=min(slot['expires_at'],maintenance['expires_at'])
                    or p['consent_until']>min(slot['windows']['retain_until'],maintenance['windows']['retain_until'])):
                wire._fail('repair_message_mismatch')
            allowed={'contact.request','delivery.attempt','message.disclosure','authority.status.disclosure','ack.root_authority','ack.write_grant',
                'bootstrap.ack_offer','historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap'}
            roles=p['allowed_roles']
            if type(roles) is not wire._DraftList or not roles or any(type(v) is not str or v not in allowed for v in roles) or list(roles)!=sorted(set(roles)):
                wire._fail('repair_status_disclosure')
            returned=resource._fields(p['bootstrap_return'],{'subject','consumer','roles','until'})
            if (returned['subject']!=slot['recipient'] or returned['consumer']!='mailbox_feed'
                    or returned['roles']!=['authority.status.disclosure','message.disclosure']
                    or not p['issued_at']<wire.u53(returned['until'])<=p['consent_until']):
                wire._fail('repair_status_disclosure')
            status.original._verify_control_signature(p,signed['proof'],slot['sender']['signing_key_id'],budget)
            scope=status.status_scope(root,'authority',dict(authority_kind='message.disclosure',authority_sha256=ref.raw_sha256),s.policy,budget)
            def retain(value):recorded.append(self._record(row,offer,root_digest,value,budget))
            try:
                observed=status.authenticate_status_original(status_entry,expected_root=root,expected_signing_key=p['signing_key'],at=now,
                    allowed_scopes=[dict(scope_kind='authority',scope_id=scope)],policy=s.policy,budget=budget,on_authenticated=retain)
            except wire.RepairWireError as caught:error=caught
        if any(recorded):wire._fail(next(code for code in recorded if code))
        if error is not None:raise error
        return observed

    def check_locked(self, resource_id, required, *, _budget=None):
        """Return a refusal code under the caller's transaction; grant nothing."""
        s = self.source
        if not self.db.in_transaction:
            wire._fail("repair_storage_transaction")
        s._binding(); s.capacity.check_policy()
        budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget)
        _,offer,_,root_digest = self._context(resource_id,budget)
        requirements = wire.build_new_wire(required,s.policy,budget).value
        if type(requirements) is not wire._DraftList or not 1 <= len(requirements) <= 80:
            wire._fail("repair_invalid_status")
        code = self._integrity(root_digest)
        if code:
            return code
        now = s._now()
        if min(offer["windows"][name] for name in ("read_until","retain_until")) <= now:
            return "repair_resource_expired"
        for item in requirements:
            wire.object_fields(item,{"issuer","scope_kind","scope_id","document_revision","operation_mask"})
            status.original._key_id(item["issuer"])
            status._scope_key(item); wire.u53(item["document_revision"]); status._mask(item["operation_mask"])
            rows = self.db.execute("SELECT revision,minimum_revision,revoked_mask,active_mask,valid_until,observed_minimum FROM open_repair_mailbox_status_floors WHERE root_digest=? AND issuer=? AND scope_kind=? AND scope_id=?",
                (root_digest,item["issuer"],item["scope_kind"],item["scope_id"])).fetchall()
            if not rows:
                return "repair_status_missing"
            if any(row[2] & item["operation_mask"] for row in rows):
                return "repair_authority_revoked"
            if max(row[1] for row in rows) > item["document_revision"]:
                return "repair_status_revision"
            revision = max(row[0] for row in rows)
            minimum = max(row[1] for row in rows)
            if any(row[0] == revision and row[5] < minimum for row in rows):
                return "repair_status_rollback"
            if not any(row[0] == revision and row[4] > now and row[3] & item["operation_mask"] == item["operation_mask"] for row in rows):
                return "repair_status_operation"
        return None
