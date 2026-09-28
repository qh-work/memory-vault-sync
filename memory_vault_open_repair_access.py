"""Current ACK-owner service permission in the existing source transport DB.

Preparation authenticates complete originals outside writer transactions.
check_locked returns permission refusals as data: its caller must commit the
observed floors/revocations before reporting denial. No remote operation, key
possession, replacement assignment, second Vault or database is supplied here.
This first slice retains all admitted observations; dependency-complete release
and collection are deliberately required before any later reclamation.
"""
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


CURRENT_ROLES = ("current.status.ack_root", "current.status.ack_read",
    "current.status.ack_owner_bootstrap", "current.status.ack_slot", "current.status.ack_resource")
STATE_CHARGE = 512
FLOOR_CHARGE = 512
DOCUMENT_CHARGE = 512


def _fail(code):
    raise wire.RepairWireError(code)


class _Preparation:
    __slots__ = ("__weakref__",)


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    code: str | None
    generation: int
    expires_at: int
    resource_id: str
    subject: object
    selector: object
    bootstrap_grant_ref: wire.RawRef
    limit_policy: object


class RepairAckAccess:
    def __init__(self, state):
        self.state, self.db = state, state.db
        self._prepared = WeakKeyDictionary()

    def initialize(self):
        with self.state._transaction():
            for sql in (
                """CREATE TABLE IF NOT EXISTS open_repair_access_state(
                    resource_id TEXT PRIMARY KEY,generation INTEGER NOT NULL,blocked TEXT,
                    documents INTEGER NOT NULL,floors INTEGER NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS open_repair_access_documents(
                    resource_id TEXT NOT NULL,issuer TEXT NOT NULL,root_digest TEXT NOT NULL,
                    revision INTEGER NOT NULL,digest TEXT NOT NULL,raw BLOB NOT NULL,ref BLOB NOT NULL,
                    valid_until INTEGER NOT NULL,PRIMARY KEY(resource_id,issuer,revision,digest))""",
                """CREATE TABLE IF NOT EXISTS open_repair_access_floors(
                    resource_id TEXT NOT NULL,issuer TEXT NOT NULL,root_digest TEXT NOT NULL,
                    scope_kind TEXT NOT NULL,scope_id TEXT NOT NULL,revision INTEGER NOT NULL,
                    digest TEXT NOT NULL,minimum_revision INTEGER NOT NULL,revoked_mask INTEGER NOT NULL,
                    conflict INTEGER NOT NULL,PRIMARY KEY(resource_id,issuer,scope_kind,scope_id))""",
            ):
                self.db.execute(sql)

    def _snapshot(self, resource_id):
        self.state._binding()
        row = self.state._row(resource_id)
        if row["status"] != "unbound":
            _fail("repair_resource_inactive")
        # metadata_bytes is a shared mutable charge ledger; it is reloaded
        # under the writer lock, not part of immutable source generation.
        stamp = tuple((key, value) for key, value in sorted(row.items()) if key != "metadata_bytes")
        cursor = self.db.execute("""SELECT p.role,o.namespace,o.opaque_key,o.raw_sha256,o.size,o.raw
            FROM open_repair_ack_pins p JOIN open_repair_ack_objects o
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.resource_id=?
            ORDER BY p.role,o.namespace,o.opaque_key LIMIT ?""", (resource_id, self.state.policy.max_entries + 1))
        pins = tuple(tuple(item) for item in cursor)
        pin_count = self.db.execute("SELECT count(*) FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,)).fetchone()[0]
        if not pins or len(pins) > self.state.policy.max_entries or pin_count != len(pins):
            _fail("repair_storage_corrupt")
        return row, stamp, pins

    def _get(self, prepared):
        if type(prepared) is not _Preparation or prepared not in self._prepared:
            _fail("repair_access_preparation")
        return self._prepared[prepared]

    @staticmethod
    def _saved(row, name, policy, budget):
        raw = row[name]
        size = wire._raw_size(raw, policy)
        budget._bytes("input_bytes", size)
        raw = bytes(raw)
        reference = wire.parse_new_wire(bytes(row[name + "_ref"]), policy, budget).value
        ref = wire.RawRef(**wire.object_fields(reference, {"namespace", "key", "raw_sha256", "size"}))
        if size != ref.size or budget._hash(raw) != ref.raw_sha256:
            _fail("repair_storage_corrupt")
        return dict(raw=raw, ref=ref.as_dict())

    def prepare(self, resource_id, *, action, current_statuses=None, expected_generation=None,
                policy=None, budget=None):
        if action not in ("challenge", "proof", "child"):
            _fail("repair_access_action")
        if (policy is None) != (budget is None):
            _fail("repair_invalid_context")
        policy = self.state.policy if policy is None else policy
        budget = wire.RepairBudget(policy) if budget is None else budget
        wire._context(policy, budget)
        if expected_generation is not None:
            wire.u53(expected_generation, 1)
        with self.state._lock:
            if self.db.in_transaction:
                _fail("repair_storage_transaction")
            row, stamp, pins = self._snapshot(resource_id)
            now = self.state._now()
            saved = tuple(self.db.execute("""SELECT DISTINCT d.raw,d.ref FROM open_repair_access_floors f
                JOIN open_repair_access_documents d ON d.resource_id=f.resource_id AND d.issuer=f.issuer
                AND d.revision=f.revision AND d.digest=f.digest WHERE f.resource_id=?
                ORDER BY d.issuer,d.revision,d.digest""", (resource_id,)))
        resolver = wire.LocalRawResolver(policy, budget)
        pin_entries, basis = {}, []
        for role, namespace, key, digest, size, raw in pins:
            ref = wire.RawRef(namespace, key, digest, size)
            held = dict(raw=bytes(raw), ref=ref.as_dict())
            pin_entries.setdefault(role, []).append(held)
            if role == "pack":
                if resolver.put(namespace, key, raw).ref != ref:
                    _fail("repair_ref_mismatch")
                basis.append(MappingProxyType(dict(role="history.raw_pack", raw=bytes(raw), ref=ref)))
        if (pin_entries.keys() != ack.ROLES | {"manifest", "custody", "pack"}
                or any(len(values) != 1 for role, values in pin_entries.items() if role != "pack")):
            _fail("repair_storage_corrupt")
        if any(len(pin_entries.get(role, ())) != 1 for role in ("manifest", "custody")):
            _fail("repair_storage_corrupt")
        manifest, custody = (pin_entries[name][0] for name in ("manifest", "custody"))
        if custody != self._saved(row, "custody", policy, budget) or manifest["ref"] != wire.parse_new_wire(bytes(row["manifest_ref"]), policy, budget).value:
            _fail("repair_storage_corrupt")
        setup = wire.parse_new_wire(bytes(row["activation_inputs"]), policy, budget).value
        root_raw = setup["root"]["raw"].encode()
        root_payload = wire.parse_new_wire(root_raw, policy, budget).value["payload"]
        slot = root_payload["ack_slot"]
        owner = wire.parse_new_wire(bytes(row["owner_keys"]), policy, budget).value
        checked = ack.verify_ack_unbound_source_event(manifest, resolver, custody,
            expected_ack_slot=slot, expected_owner=owner, expected_target=self.state.target,
            target_storage_epoch=self.state.node["payload"]["storage_epoch"],
            limit_policy=self.state.limits, policy=policy, budget=budget)
        exact = {"resource.ack_allocate": self._saved(row, "allocation", policy, budget),
            "resource.ack_offer": self._saved(row, "offer", policy, budget),
            "resource.ack_active": self._saved(row, "active", policy, budget),
            "historical.status.ack_resource": self._saved(row, "source_status", policy, budget)}
        for role, name in (("ack.root_authority", "root"), ("ack.read_grant", "read"),
                           ("bootstrap.ack_owner", "bootstrap"), ("resource.ack_activation", "activation")):
            exact[role] = dict(raw=setup[name]["raw"].encode(), ref=setup[name]["ref"])
        for item in checked.manifest.roles:
            if item.role in exact and (item.original.raw != exact[item.role]["raw"] or
                    item.original.ref.as_dict() != exact[item.role]["ref"]):
                _fail("repair_local_original_mismatch")
        for item in checked.manifest.roles:
            basis.append(MappingProxyType(dict(role=item.role, raw=item.original.raw, ref=item.original.ref)))
        basis.extend(MappingProxyType(dict(role=role, raw=entry["raw"], ref=wire.RawRef(**entry["ref"])))
                     for role, entry in (("history.ack_unbound", manifest), ("ack.unbound_custody", custody)))
        originals = checked.resources.originals
        root, read, active = (originals[name].payload for name in ("root", "read", "active"))
        grant_original = checked.bootstrap.originals["bootstrap"]
        grant = grant_original.payload
        root_key = slot["root_key"]
        root_digest = budget._hash(wire._canonical(root_key, budget))
        masks = (10 if action == "challenge" else 2, 2, 10 if action == "challenge" else 2, 2, 2)
        obligations = []
        for index, name, kind in ((0, "root", "ack.root_authority"), (1, "read", "ack.read_grant"), (2, "bootstrap", "bootstrap.grant")):
            item = grant_original if name == "bootstrap" else originals[name]
            scope_id = status.status_scope(root_key, "authority", dict(authority_kind=kind,
                authority_sha256=item.ref.raw_sha256), policy, budget)
            obligations.append(dict(role=CURRENT_ROLES[index], signer=owner["signing_key"],
                scope_kind="authority", scope_id=scope_id, revision=item.payload["revision"], mask=masks[index]))
        for index, kind, subject, revision, signer in (
            (3, "ack_slot", slot, root["revision"], owner["signing_key"]),
            (4, "resource", active["resource"], active["reservation_generation"], self.state.target["signing_key"])):
            obligations.append(dict(role=CURRENT_ROLES[index], signer=signer, scope_kind=kind,
                scope_id=status.status_scope(root_key, kind, subject, policy, budget), revision=revision, mask=masks[index]))
        expires = min(root["expires_at"], read["expires_at"], grant["expires_at"],
            grant["probe_until"] if action == "challenge" else grant["proof_until"],
            grant["proof_until"], checked.read_until, checked.descriptor.payload["expires_at"],
            *(item["windows"][name] for item in (root, read, active) for name in ("read_until", "retain_until")))
        code = None
        if (not all(item["issued_at"] <= now for item in (root, read, grant)) or now >= expires
                or root["operation_mask"] & masks[0] != masks[0] or read["operation_mask"] & 2 != 2):
            code = "repair_access_expired"
        if current_statuses is None:
            current_statuses = ([dict(raw=bytes(raw), ref=wire.parse_new_wire(bytes(ref), policy, budget).value) for raw, ref in saved]
                if saved else [dict(raw=item.raw, ref=item.ref.as_dict()) for item in checked.statuses])
        if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 5:
            _fail("repair_invalid_status")
        authenticated = []
        for entry in current_statuses:
            try:
                # The bounded preview selects only an independently held signer;
                # authentication repeats the same bytes and verifies its key.
                raw, reference = ack._entry(entry)
                parsed = status.original.parse_original_control(raw, policy, budget)
                payload = status._fields(status._fields(parsed.value, {"payload", "proof"})["payload"], status._PAYLOAD)
                issuer = status._fields(payload["scope_key"], {"root_key", "issuer_key_id"})["issuer_key_id"]
                permitted = [item for item in obligations if item["signer"]["key_id"] == issuer]
                if not permitted:
                    _fail("repair_status_mismatch")
                observed = status.authenticate_status_original(dict(raw=parsed.raw, ref=reference.as_dict()),
                    expected_root=root_key, expected_signing_key=permitted[0]["signer"], at=now,
                    allowed_scopes=[dict(scope_kind=item["scope_kind"], scope_id=item["scope_id"]) for item in permitted],
                    policy=policy, budget=budget)
                authenticated.append(observed)
            except wire.RepairWireError as error:
                code = code or error.code
        prepared = _Preparation()
        self._prepared[prepared] = dict(resource_id=resource_id, stamp=stamp, pins=pins, action=action,
            root_digest=root_digest, obligations=tuple(obligations), statuses=tuple(authenticated),
            status_refs={item.canonical_sha256: wire._canonical(item.ref.as_dict(), budget) for item in authenticated},
            basis=tuple(basis), expected_generation=expected_generation, expires=expires, code=code,
            subject=MappingProxyType(dict(grant["subject"])), selector=MappingProxyType(dict(grant["selector"])), grant_ref=grant_original.ref,
            limits=MappingProxyType(dict(grant["limits"])), capacity=active["budget"], checked=False, proof=())
        return prepared

    def _decision(self, held, row, code, expires):
        return AccessDecision(code is None, code, row["generation"], expires, held["resource_id"],
            held["subject"], held["selector"], held["grant_ref"], held["limits"])

    def _global_floor(self, held, key):
        # Rows remain charged to their admitting resource, but permission
        # floors belong to the issuer/root/typed scope across all resources.
        bits = (1, 2, 4, 8, 16, 32, 64)
        aggregates = ",".join("coalesce(max((revoked_mask & " + str(bit) + ")!=0),0)" for bit in bits)
        values = self.db.execute("SELECT coalesce(max(revision),0),coalesce(max(minimum_revision),0),coalesce(max(conflict),0)," +
            aggregates + " FROM open_repair_access_floors WHERE issuer=? AND root_digest=? AND scope_kind=? AND scope_id=?",
            (key[0], held["root_digest"], key[1], key[2])).fetchone()
        conflict = self.db.execute("""SELECT 1 FROM open_repair_access_documents WHERE issuer=? AND root_digest=?
            GROUP BY revision HAVING count(DISTINCT digest)>1 LIMIT 1""", (key[0], held["root_digest"])).fetchone()
        return dict(revision=values[0], minimum_revision=values[1], conflict=bool(values[2] or conflict),
                    revoked_mask=sum(bit for bit, set_bit in zip(bits, values[3:]) if set_bit))

    def check_locked(self, prepared):
        held = self._get(prepared)
        if not self.db.in_transaction:
            _fail("repair_storage_transaction")
        source, stamp, pins = self._snapshot(held["resource_id"])
        if stamp != held["stamp"] or pins != held["pins"]:
            _fail("repair_access_generation")
        self.state.capacity.check_policy()
        resource_id = held["resource_id"]
        root_latch = "access_root_blocked:" + held["root_digest"]
        row = self.state._one("SELECT * FROM open_repair_access_state WHERE resource_id=?", (resource_id,))
        marker = "access:" + resource_id
        marker_value = self.state._expected_binding() + "|" + held["root_digest"]
        marker_row = self.state._one("SELECT value FROM open_repair_state WHERE name=?", (marker,))
        if row is not None and (marker_row is None or marker_row["value"] != marker_value):
            _fail("repair_access_ledger_missing")
        if row is None:
            if marker_row is not None:
                _fail("repair_access_ledger_missing")
            blocked = "repair_access_capacity" if source["metadata_bytes"] + STATE_CHARGE > held["capacity"]["max_meta_bytes"] else None
            self.db.execute("INSERT INTO open_repair_access_state VALUES(?,1,?,0,0)", (resource_id, blocked))
            self.db.execute("INSERT INTO open_repair_state VALUES(?,?)", (marker, marker_value))
            # A denial latch fits the already reserved fixed resource-row
            # allowance. Positive admission pays its additional row charge.
            if blocked is None:
                self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?", (STATE_CHARGE, resource_id))
                source["metadata_bytes"] += STATE_CHARGE
            else:
                self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES(?,?)", (root_latch, blocked))
            row = dict(resource_id=resource_id, generation=1, blocked=blocked, documents=0, floors=0)
        counts = tuple(self.db.execute("SELECT (SELECT count(*) FROM open_repair_access_documents WHERE resource_id=?),(SELECT count(*) FROM open_repair_access_floors WHERE resource_id=?)", (resource_id, resource_id)).fetchone())
        if counts != (row["documents"], row["floors"]):
            _fail("repair_access_ledger_missing")
        siblings = self.db.execute("SELECT name FROM open_repair_state WHERE name LIKE 'access:%' AND value=?", (marker_value,))
        for (name,) in siblings:
            sibling = name[len("access:"):]
            actual = self.state._one("""SELECT documents,floors,
                (SELECT count(*) FROM open_repair_access_documents d WHERE d.resource_id=s.resource_id) AS actual_documents,
                (SELECT count(*) FROM open_repair_access_floors f WHERE f.resource_id=s.resource_id) AS actual_floors
                FROM open_repair_access_state s WHERE resource_id=?""", (sibling,))
            if actual is None or (actual["documents"], actual["floors"]) != (actual["actual_documents"], actual["actual_floors"]):
                _fail("repair_access_ledger_missing")
        now = self.state._now()
        code, changed = held["code"], False
        floors = {(item["issuer"], item["scope_kind"], item["scope_id"]): item for item in
            (dict(zip(("resource_id", "issuer", "root_digest", "scope_kind", "scope_id", "revision", "digest", "minimum_revision", "revoked_mask", "conflict"), item))
             for item in self.db.execute("SELECT * FROM open_repair_access_floors WHERE resource_id=?", (resource_id,)))}
        for observed in sorted(held["statuses"], key=lambda value: (value.payload["revision"], value.canonical_sha256)):
            payload = observed.payload
            if not payload["issued_at"] <= now + 30 < payload["valid_until"] + 30:
                code = code or "repair_status_mismatch"
                continue
            issuer, revision, digest = payload["scope_key"]["issuer_key_id"], payload["revision"], observed.canonical_sha256
            prior_doc = self.state._one("SELECT raw,ref FROM open_repair_access_documents WHERE resource_id=? AND issuer=? AND revision=? AND digest=?", (resource_id, issuer, revision, digest))
            conflict = self.state._one("SELECT 1 FROM open_repair_access_documents WHERE issuer=? AND root_digest=? AND revision=? AND digest<>? LIMIT 1", (issuer, held["root_digest"], revision, digest)) is not None
            new_keys = [(issuer, item["scope_kind"], item["scope_id"]) for item in payload["entries"]
                        if (issuer, item["scope_kind"], item["scope_id"]) not in floors]
            wire_changed = prior_doc and (bytes(prior_doc["raw"]) != observed.raw or bytes(prior_doc["ref"]) != held["status_refs"][digest])
            charge = (max(0, len(observed.raw) - len(prior_doc["raw"])) if prior_doc else len(observed.raw) + DOCUMENT_CHARGE) + len(new_keys)*FLOOR_CHARGE
            if (row["blocked"] is not None or source["metadata_bytes"] + charge > held["capacity"]["max_meta_bytes"]
                    or row["documents"] + (0 if prior_doc else 1) > held["limits"]["max_replay_records"]):
                if row["blocked"] is None:
                    row["blocked"], changed = "repair_access_capacity", True
                    self.db.execute("INSERT OR IGNORE INTO open_repair_state VALUES(?,?)", (root_latch, row["blocked"]))
                continue
            if not prior_doc:
                self.db.execute("INSERT INTO open_repair_access_documents VALUES(?,?,?,?,?,?,?,?)", (resource_id, issuer,
                    held["root_digest"], revision, digest, observed.raw, held["status_refs"][digest], payload["valid_until"]))
                row["documents"] += 1
                changed = True
            elif wire_changed:
                self.db.execute("UPDATE open_repair_access_documents SET raw=?,ref=? WHERE resource_id=? AND issuer=? AND revision=? AND digest=?",
                    (observed.raw, held["status_refs"][digest], resource_id, issuer, revision, digest))
                changed = True
            source["metadata_bytes"] += charge
            for item in payload["entries"]:
                key = issuer, item["scope_kind"], item["scope_id"]
                prior = floors.get(key)
                minimum = item["minimum_document_revision"]
                revoked = (prior["revoked_mask"] if prior else 0) | (item["operation_mask"] if item["status"] == "revoked" else 0)
                bad_order = prior and (revision < prior["revision"] or minimum < prior["minimum_revision"])
                if bad_order:
                    code = code or "repair_status_rollback"
                current = dict(resource_id=resource_id, issuer=issuer, root_digest=held["root_digest"],
                    scope_kind=key[1], scope_id=key[2], revision=max(revision, prior["revision"] if prior else 0),
                    digest=prior["digest"] if prior and revision < prior["revision"] else digest,
                    minimum_revision=max(minimum, prior["minimum_revision"] if prior else 0),
                    revoked_mask=revoked, conflict=int(conflict or bool(prior and prior["conflict"])))
                if current != prior:
                    changed = True
                    if prior is None:
                        row["floors"] += 1
                    floors[key] = current
                    self.db.execute("""INSERT INTO open_repair_access_floors VALUES(?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(resource_id,issuer,scope_kind,scope_id) DO UPDATE SET revision=excluded.revision,
                        digest=excluded.digest,minimum_revision=excluded.minimum_revision,revoked_mask=excluded.revoked_mask,conflict=excluded.conflict""", tuple(current.values()))
            if conflict:
                row["blocked"], changed = "repair_status_conflict", True
        if changed:
            row["generation"] += 1
        self.db.execute("UPDATE open_repair_access_state SET generation=?,blocked=?,documents=?,floors=? WHERE resource_id=?",
            (row["generation"], row["blocked"], row["documents"], row["floors"], resource_id))
        self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=? WHERE resource_id=?", (source["metadata_bytes"], resource_id))
        expires, proof = held["expires"], []
        for item in held["obligations"]:
            key = item["signer"]["key_id"], item["scope_kind"], item["scope_id"]
            floor = floors.get(key)
            global_floor = self._global_floor(held, key)
            if global_floor["conflict"]:
                code = "repair_status_conflict"
            elif global_floor["revoked_mask"] & item["mask"]:
                code = "repair_authority_revoked"
            elif global_floor["minimum_revision"] > item["revision"]:
                code = code or "repair_status_revision"
            if floor is None:
                code = code or "repair_status_missing"
                continue
            if floor["conflict"]:
                code = "repair_status_conflict"
            elif floor["revoked_mask"] & item["mask"]:
                code = "repair_authority_revoked"
            elif floor["minimum_revision"] > item["revision"]:
                code = code or "repair_status_revision"
            candidates = [value for value in held["statuses"] if value.payload["scope_key"]["issuer_key_id"] == key[0]
                and value.payload["revision"] == floor["revision"] and value.canonical_sha256 == floor["digest"]]
            observed = next((value for value in candidates if any((entry["scope_kind"], entry["scope_id"]) == key[1:] for entry in value.payload["entries"])), None)
            if observed is None:
                code = code or "repair_status_missing"
                continue
            if observed.payload["revision"] < global_floor["revision"]:
                code = code or "repair_status_rollback"
            entry = next(entry for entry in observed.payload["entries"] if (entry["scope_kind"], entry["scope_id"]) == key[1:])
            if entry["operation_mask"] & item["mask"] != item["mask"]:
                code = code or "repair_status_operation"
            expires = min(expires, observed.payload["valid_until"])
            proof.append(MappingProxyType(dict(role=item["role"], raw=observed.raw, ref=observed.ref)))
        if row["blocked"]:
            code = row["blocked"]
        latch = self.state._one("SELECT value FROM open_repair_state WHERE name=?", (root_latch,))
        if latch is not None:
            code = latch["value"]
        if now >= expires:
            code = code or "repair_access_expired"
        if held["expected_generation"] is not None and held["expected_generation"] != row["generation"]:
            code = code or "repair_access_generation"
        decision = self._decision(held, row, code, expires)
        held["checked"], held["proof"] = decision.allowed, tuple(proof)
        held["last_generation"] = row["generation"]
        return decision

    def proof_inputs(self, prepared):
        held = self._get(prepared)
        if not held["checked"]:
            _fail("repair_access_preparation")
        decision = self.check_locked(prepared)
        return decision, held["basis"] + held["proof"] if decision.allowed else ()
