"""Local durable unbound-to-empty ACK transition in the existing node DB.

This does not expose a network RPC. The old unbound-only service intentionally
refuses the resulting empty phase until a bound service consumer is present.
All original parsing, hashing, signing and source-proof verification happen
outside SQLite writer transactions. Current observations are committed before
subsequent permission, capacity or stable-grant conflict refusals are raised.
"""
from types import MappingProxyType

import memory_vault_open_repair_access as access
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_bound as bound
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_state as storage
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


def _fail(code):
    wire._fail(code)


def _entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


class _EmptyAccess(access.RepairAckAccess):
    """Use the same durable issuer/root floors for this additional operation."""
    def _snapshot(self, resource_id):
        self.state._binding()
        row = self.state._row(resource_id)
        if row["status"] not in ("unbound", "empty", "conflicted"):
            _fail("repair_resource_inactive")
        stamp = tuple((key, value) for key, value in sorted(row.items()) if key != "metadata_bytes")
        pins = tuple(tuple(item) for item in self.db.execute("""SELECT p.role,o.namespace,o.opaque_key,o.raw_sha256,o.size,o.raw
            FROM open_repair_ack_pins p JOIN open_repair_ack_objects o
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.resource_id=?
            ORDER BY p.role,o.namespace,o.opaque_key LIMIT ?""", (resource_id, self.state.policy.max_entries + 1)))
        count = self.db.execute("SELECT count(*) FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,)).fetchone()[0]
        if not pins or len(pins) > self.state.policy.max_entries or len(pins) != count:
            _fail("repair_storage_corrupt")
        return row, stamp, pins

    def prepare_bind(self, resource_id, write_entry, offer_entry, *, expected_receipt_writer,
                     expected_message_id, expected_envelope_ref, current_statuses,
                     read_until, retain_until, budget):
        policy = self.state.policy
        wire._context(policy, budget)
        with self.state._lock:
            if self.db.in_transaction:
                _fail("repair_storage_transaction")
            row, stamp, pins = self._snapshot(resource_id)
            now = self.state._now()
        resolver = wire.LocalRawResolver(policy, budget)
        entries, packs = {}, []
        for role, namespace, key, digest, size, raw in pins:
            if role.startswith("empty:"):
                continue
            ref = wire.RawRef(namespace, key, digest, size)
            raw = wire._snapshot(bytes(raw), policy, budget)
            if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
                _fail("repair_storage_corrupt")
            held = dict(raw=raw, ref=ref.as_dict())
            entries.setdefault(role, []).append(held)
            if role == "pack":
                if resolver.put(namespace, key, raw).ref != ref:
                    _fail("repair_ref_mismatch")
                packs.append(held)
        if (entries.keys() != ack.ROLES | {"pack", "manifest", "custody"}
                or any(len(values) != 1 for role, values in entries.items() if role != "pack")):
            _fail("repair_storage_corrupt")
        manifest, custody = (entries[name][0] for name in ("manifest", "custody"))
        if (custody != self._saved(row, "custody", policy, budget)
                or manifest["ref"] != wire.parse_new_wire(bytes(row["manifest_ref"]), policy, budget).value):
            _fail("repair_storage_corrupt")
        owner = wire.parse_new_wire(bytes(row["owner_keys"]), policy, budget).value
        setup = wire.parse_new_wire(bytes(row["activation_inputs"]), policy, budget).value
        root_entry = dict(raw=setup["root"]["raw"].encode(), ref=setup["root"]["ref"])
        slot = wire.parse_new_wire(root_entry["raw"], policy, budget).value["payload"]["ack_slot"]
        prior = ack.verify_ack_unbound_source_event(manifest, resolver, custody, expected_ack_slot=slot,
            expected_owner=owner, expected_target=self.state.target,
            target_storage_epoch=self.state.node["payload"]["storage_epoch"], limit_policy=self.state.limits,
            policy=policy, budget=budget)
        exact = {"resource.ack_allocate": self._saved(row, "allocation", policy, budget),
            "resource.ack_offer": self._saved(row, "offer", policy, budget),
            "resource.ack_active": self._saved(row, "active", policy, budget),
            "historical.status.ack_resource": self._saved(row, "source_status", policy, budget)}
        for role, name in (("ack.root_authority", "root"), ("ack.read_grant", "read"),
                           ("bootstrap.ack_owner", "bootstrap"), ("resource.ack_activation", "activation")):
            exact[role] = dict(raw=setup[name]["raw"].encode(), ref=setup[name]["ref"])
        for item in prior.manifest.roles:
            if entries[item.role][0] != _entry(item.original):
                _fail("repair_storage_corrupt")
            if item.role in exact and _entry(item.original) != exact[item.role]:
                _fail("repair_local_original_mismatch")
        used_packs = {wire.raw_ref(item["pack_ref"]) for item in prior.manifest.manifest.value["roles"]}
        if {wire.raw_ref(item["ref"]) for item in packs} != used_packs or len(packs) != len(used_packs):
            _fail("repair_unused_pack")
        expected = wire.build_new_wire(dict(receipt_writer=expected_receipt_writer, message_id=expected_message_id,
            envelope_ref=expected_envelope_ref, read_until=read_until, retain_until=retain_until), policy, budget).value
        if not now < wire.u53(expected["read_until"]) <= wire.u53(expected["retain_until"]):
            _fail("repair_invalid_ack_empty")
        authorities = bound.verify_ack_offer_bootstrap_original(offer_entry,
            dict(root=root_entry, write=write_entry), expected_ack_slot=slot, expected_owner=owner,
            expected_receipt_writer=expected["receipt_writer"], expected_message_id=expected["message_id"],
            expected_envelope_ref=expected["envelope_ref"], at=now, limit_policy=self.state.limits,
            policy=policy, budget=budget)
        root, read, active = (prior.resources.originals[name].payload for name in ("root", "read", "active"))
        write, offer = (authorities.originals[name].payload for name in ("write", "bootstrap"))
        owner_boot = prior.bootstrap.originals["bootstrap"].payload
        if prior.stored_at > write["issued_at"]:
            _fail("repair_ack_empty_mismatch")
        obligations = empty._obligations(prior, authorities, owner, self.state.target, slot, policy, budget)
        expires = min(*(item["expires_at"] for item in (root, read, write, owner_boot, offer)),
            *(item[name] for item in (owner_boot, offer) for name in ("probe_until", "proof_until", "upload_until")),
            *(item["windows"][name] for item in (root, active) for name in ("admit_until", "read_until", "retain_until")),
            read["windows"]["read_until"], write["windows"]["admit_until"])
        code = None
        if root["operation_mask"] & 75 != 75 or now >= expires:
            code = "repair_access_expired"
        if row["status"] == "conflicted":
            code = "repair_binding_conflict"
        if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 7:
            _fail("repair_invalid_status")
        authenticated = []
        for entry in current_statuses:
            try:
                raw, ref = ack._entry(entry)
                parsed = original.parse_original_control(raw, policy, budget)
                payload = status._fields(status._fields(parsed.value, {"payload", "proof"})["payload"], status._PAYLOAD)
                issuer = status._fields(payload["scope_key"], {"root_key", "issuer_key_id"})["issuer_key_id"]
                permitted = [item for item in obligations if item["signer"]["key_id"] == issuer]
                if not permitted:
                    _fail("repair_status_mismatch")
                authenticated.append(status.authenticate_status_original(dict(raw=parsed.raw, ref=ref.as_dict()),
                    expected_root=slot["root_key"], expected_signing_key=permitted[0]["signer"], at=now,
                    allowed_scopes=[dict(scope_kind=item["scope_kind"], scope_id=item["scope_id"]) for item in permitted],
                    policy=policy, budget=budget))
            except wire.RepairWireError as error:
                code = code or error.code
        try:
            empty._history_floors((*prior.statuses, *authenticated), previous=prior.statuses, current=authenticated)
        except wire.RepairWireError as error:
            code = code or error.code
        limits = {name: min(owner_boot["limits"][name], offer["limits"][name], self.state.limits[name])
                  for name in self.state.limits}
        prepared = access._Preparation()
        self._prepared[prepared] = dict(resource_id=resource_id, stamp=stamp, pins=pins, action="bind",
            root_digest=budget._hash(wire._canonical(slot["root_key"], budget)), obligations=obligations,
            statuses=tuple(authenticated), status_refs={item.canonical_sha256: wire._canonical(item.ref.as_dict(), budget)
                                                      for item in authenticated},
            basis=(), expected_generation=None, expires=expires, code=code, subject=MappingProxyType(dict(write["receipt_writer"])),
            selector=MappingProxyType(dict(offer["selector"])), grant_ref=authorities.originals["bootstrap"].ref,
            limits=MappingProxyType(limits), capacity=active["budget"], checked=False, proof=(),
            row=row, prior=prior, authorities=authorities, owner=owner, slot=slot, expected=expected,
            reservation_charge=active["budget"]["max_live_bytes"] + active["budget"]["max_meta_bytes"]
                + active["budget"]["max_job_bytes"] + active["budget"]["max_replay_records"] * storage.REPLAY_CHARGE + storage.ROW_CHARGE,
            source_manifest=manifest, source_custody=custody, packs=tuple(packs), resolver=resolver, at=now,
            request_digest=budget._hash(wire._canonical(dict(write=authorities.originals["write"].ref.as_dict(),
                bootstrap=authorities.originals["bootstrap"].ref.as_dict(), expected=expected), budget)))
        return prepared


class RepairAckEmptyState:
    def __init__(self, state):
        self.state, self.db = state, state.db
        self.access = _EmptyAccess(state)

    def initialize(self):
        self.access.initialize()
        with self.state._transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_ack_bindings(
                resource_id TEXT PRIMARY KEY,grant_id TEXT NOT NULL,write_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,binding_ref BLOB NOT NULL,manifest_ref BLOB NOT NULL,
                custody_ref BLOB NOT NULL,head_ref BLOB NOT NULL,generation INTEGER NOT NULL,
                writer_keys BLOB NOT NULL)""")
            columns = {row[1] for row in self.db.execute("PRAGMA table_info(open_repair_ack_bindings)")}
            if "writer_keys" not in columns:
                # Earlier local development rows cannot be reconstructed from
                # hashed DualIDs. Leave them explicitly incomplete; never
                # invent descriptors or bless a caller-provided replacement.
                self.db.execute("ALTER TABLE open_repair_ack_bindings ADD COLUMN writer_keys BLOB")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_ack_binding_conflicts(
                resource_id TEXT PRIMARY KEY,write_digest TEXT NOT NULL,raw BLOB,ref BLOB NOT NULL,
                retained INTEGER NOT NULL)""")

    def _existing(self, resource_id):
        return self.state._one("SELECT * FROM open_repair_ack_bindings WHERE resource_id=?", (resource_id,))

    def _gate(self, prepared):
        held = self.access._get(prepared)
        decision = self.access.check_locked(prepared)
        if not decision.allowed:
            return decision.code
        row = self.state._row(held["resource_id"])
        reserve = self.state._one("SELECT * FROM open_capacity_reservations WHERE service='ack' AND reservation_id=?", (held["resource_id"],))
        if (reserve is None or reserve["digest"] != row["request_digest"] or reserve["owner"] != row["owner"]
                or reserve["operation_id"] != row["allocation_id"] or reserve["retain_until"] != row["retain_until"]
                or reserve["charge_bytes"] != held["reservation_charge"]):
            return "repair_capacity_reservation_missing"
        existing = self._existing(held["resource_id"])
        if (row["status"] == "unbound") != (existing is None):
            return "repair_binding_ledger_missing"
        if existing is None:
            return None
        if type(existing["writer_keys"]) is not bytes or existing["writer_keys"] != held["writer_keys_raw"]:
            return "repair_binding_writer_mismatch"
        write = held["authorities"].originals["write"]
        if existing["write_digest"] != write.ref.raw_sha256:
            # Only an independently validated owner write/offer pair reaches
            # here. Invalid signatures, keys or E expectations cannot poison a
            # slot. Retain its exact conflict if capacity permits; otherwise a
            # pre-reserved fixed denial row records the digest/ref and blocks
            # every later empty observation, without claiming bytes retained.
            charge = len(write.raw) + storage.ROW_CHARGE
            count = self.db.execute("SELECT count(*) FROM (SELECT DISTINCT namespace,opaque_key FROM open_repair_ack_pins WHERE resource_id=?)",
                                    (held["resource_id"],)).fetchone()[0]
            retain = (row["metadata_bytes"] + charge <= held["capacity"]["max_meta_bytes"]
                      and count < held["capacity"]["max_items"])
            self.db.execute("INSERT OR IGNORE INTO open_repair_ack_binding_conflicts VALUES(?,?,?,?,?)",
                (held["resource_id"], write.ref.raw_sha256, write.raw if retain else None,
                 held["write_ref_raw"], int(retain)))
            if retain:
                self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?",
                                (charge, held["resource_id"]))
            self.db.execute("UPDATE open_repair_ack_resources SET status='conflicted' WHERE resource_id=?", (held["resource_id"],))
            return "repair_binding_conflict" if retain else "repair_binding_conflict_capacity"
        if existing["request_digest"] != held["request_digest"]:
            return "repair_binding_retry_mismatch"
        return None

    def _verify_result(self, held, result, budget):
        policy = budget.policy
        checked = empty.verify_ack_empty_source_event(result["manifest"], held["resolver"], result["custody"],
            expected_ack_slot=held["slot"], expected_owner=held["owner"], expected_target=self.state.target,
            expected_receipt_writer=held["expected"]["receipt_writer"], expected_message_id=held["expected"]["message_id"],
            expected_envelope_ref=held["expected"]["envelope_ref"], target_storage_epoch=self.state.node["payload"]["storage_epoch"],
            limit_policy=self.state.limits, policy=policy, budget=budget)
        if _entry(checked.binding) != result["binding"]:
            _fail("repair_storage_corrupt")
        head = wire.parse_new_wire(result["head"]["raw"], policy, budget).value
        wire.object_fields(head, {"payload", "proof"})
        payload = wire.object_fields(head["payload"], resource.COMMON | {
            "ack_slot", "generation", "observed_at", "retain_until", "state", "root_authority_ref", "grant_ref", "binding_ref"})
        if (payload["schema_version"] != resource.SCHEMA or payload["kind"] != "ack.head" or payload["state"] != "empty"
                or wire.u53(payload["generation"], 1) != 1 or payload["ack_slot"] != held["slot"]
                or payload["observed_at"] != checked.stored_at or payload["retain_until"] != checked.retain_until
                or any(payload[name] != checked.custody.payload[name] for name in ("root_authority_ref", "grant_ref", "binding_ref"))):
            _fail("repair_storage_corrupt")
        original._verify_control_signature(payload, head["proof"], self.state.identity.public_descriptor(), budget)
        return checked

    def _saved_result(self, held, existing, policy, budget):
        result = {}
        for name in ("binding", "manifest", "custody", "head"):
            ref = ack._ref(wire.parse_new_wire(bytes(existing[name + "_ref"]), policy, budget).value)
            row = self.state._one("SELECT * FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?", (ref.namespace, ref.key))
            if row is None:
                _fail("repair_storage_corrupt")
            raw = wire._snapshot(bytes(row["raw"]), policy, budget)
            if (row["raw_sha256"] != ref.raw_sha256 or row["size"] != ref.size or len(raw) != ref.size
                    or budget._hash(raw) != ref.raw_sha256):
                _fail("repair_storage_corrupt")
            result[name] = dict(raw=raw, ref=ref.as_dict())
        assigned = {}
        for role, namespace, key, digest, size, raw in held["pins"]:
            if not role.startswith("empty:"):
                continue
            role = role[len("empty:"):]
            ref = wire.RawRef(namespace, key, digest, size)
            assigned.setdefault(role, []).append(dict(raw=bytes(raw), ref=ref.as_dict()))
            if role == "pack" and held["resolver"].put(namespace, key, raw).ref != ref:
                _fail("repair_storage_corrupt")
        if (assigned.keys() != empty.ROLES | {"binding", "manifest", "custody", "head", "pack"}
                or any(len(values) != 1 for role, values in assigned.items() if role != "pack")
                or any(assigned[name][0] != result[name] for name in result)):
            _fail("repair_storage_corrupt")
        checked = self._verify_result(held, result, budget)
        if any(assigned[item.role][0] != _entry(item.original) for item in checked.manifest.roles):
            _fail("repair_storage_corrupt")
        used = {wire.raw_ref(item["pack_ref"]) for item in checked.manifest.manifest.value["roles"]}
        if {wire.raw_ref(item["ref"]) for item in assigned["pack"]} != used or len(assigned["pack"]) != len(used):
            _fail("repair_unused_pack")
        return result

    def _build(self, held, budget):
        policy, now = self.state.policy, held["at"]
        slot, prior, authorities = held["slot"], held["prior"], held["authorities"]
        root = prior.resources.originals["root"]
        write = authorities.originals["write"]
        actual_resource = prior.resources.originals["active"].payload["resource"]
        retain_until, read_until = held["expected"]["retain_until"], held["expected"]["read_until"]
        binding = self.state._sign(dict(schema_version=resource.SCHEMA, kind="ack.binding",
            signing_key=self.state.identity.public_descriptor(), ack_slot=slot, root_authority_ref=root.ref.as_dict(),
            grant_ref=write.ref.as_dict(), bound_at=now, resource_ref=actual_resource, retain_until=retain_until), "binding", budget)
        assigned = {"history.ack_unbound": held["source_manifest"], "ack.unbound_custody": held["source_custody"],
                    "ack.write_grant": _entry(write), "bootstrap.ack_offer": _entry(authorities.originals["bootstrap"]),
                    "ack.binding": binding}
        for item in held["proof"]:
            assigned[item["role"]] = dict(raw=item["raw"], ref=item["ref"].as_dict())
        if assigned.keys() != empty.ROLES:
            _fail("repair_status_missing")
        unique = {entry["raw"] for entry in assigned.values()}
        packed = wire.build_raw_pack(list(unique), policy, budget)
        positions = {entry.raw_sha256: index for index, entry in enumerate(packed.entries)}
        rows = [dict(role=role, document_ref=entry["ref"], pack_ref=packed.ref.as_dict(),
            entry_index=positions[entry["ref"]["raw_sha256"]]) for role, entry in assigned.items()]
        rows.sort(key=lambda item:(item["role"], *history._ref_tuple(item["document_ref"])))
        manifest_raw = wire.build_new_wire(dict(schema_version=history.SCHEMA, kind="historical.manifest",
            variant="ack_empty", root_key=slot["root_key"], ack_slot=slot, root_authority_ref=root.ref.as_dict(),
            grant_ref=write.ref.as_dict(), binding_ref=binding["ref"], roles=rows), policy, budget).raw
        digest = budget._hash(manifest_raw)
        manifest = dict(raw=manifest_raw, ref=dict(namespace="meta", key=digest, raw_sha256=digest, size=len(manifest_raw)))
        custody = self.state._sign(dict(schema_version=resource.SCHEMA, kind="ack.slot_custody",
            signing_key=self.state.identity.public_descriptor(), ack_slot=slot, root_authority_ref=root.ref.as_dict(),
            historical_manifest_ref=manifest["ref"], resource_ref=actual_resource, stored_at=now,
            read_until=read_until, retain_until=retain_until, state="empty", grant_ref=write.ref.as_dict(),
            binding_ref=binding["ref"]), "empty-custody", budget)
        head = self.state._sign(dict(schema_version=resource.SCHEMA, kind="ack.head",
            signing_key=self.state.identity.public_descriptor(), ack_slot=slot, generation=1, observed_at=now,
            retain_until=retain_until, state="empty", root_authority_ref=root.ref.as_dict(),
            grant_ref=write.ref.as_dict(), binding_ref=binding["ref"]), "empty-head", budget)
        held["resolver"].put("meta", packed.ref.key, packed.raw)
        result = dict(binding=binding, manifest=manifest, custody=custody, head=head)
        checked = self._verify_result(held, result, budget)
        objects = [(dict(raw=item.original.raw, ref=item.original.ref.as_dict()), "empty:" + item.role) for item in checked.manifest.roles]
        objects.extend((entry, "empty:" + name) for name, entry in result.items())
        objects.append((dict(raw=packed.raw, ref=packed.ref.as_dict()), "empty:pack"))
        return result, tuple(objects)

    def _store(self, held, result, objects):
        resource_id = held["resource_id"]
        source = self.state._row(resource_id)
        current = {(row[0], row[1]) for row in self.db.execute(
            "SELECT DISTINCT namespace,opaque_key FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,))}
        pins = {(row[0], row[1], row[2]) for row in self.db.execute(
            "SELECT namespace,opaque_key,role FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,))}
        new_objects, new_pins, charge = {}, [], 2 * storage.ROW_CHARGE + len(held["writer_keys_raw"])
        for entry, role in objects:
            ref = entry["ref"]
            key = ref["namespace"], ref["key"]
            prior = self.state._one("SELECT * FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?", key)
            if prior is not None and (prior["raw_sha256"] != ref["raw_sha256"] or prior["size"] != ref["size"] or bytes(prior["raw"]) != entry["raw"]):
                return "repair_ref_conflict"
            if key not in current and key not in new_objects:
                new_objects[key] = entry
                charge += len(entry["raw"]) + storage.ROW_CHARGE
            pin = *key, role
            if pin not in pins:
                pins.add(pin)
                new_pins.append(pin)
                charge += 256
        if (source["metadata_bytes"] + charge > held["capacity"]["max_meta_bytes"]
                or len(current) + len(new_objects) > held["capacity"]["max_items"]):
            return "repair_insufficient_capacity"
        for (namespace, key), entry in new_objects.items():
            ref = entry["ref"]
            self.db.execute("INSERT OR IGNORE INTO open_repair_ack_objects VALUES(?,?,?,?,?)",
                (namespace, key, ref["raw_sha256"], ref["size"], entry["raw"]))
        for namespace, key, role in new_pins:
            self.db.execute("INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)", (resource_id, namespace, key, role))
        self.db.execute("""INSERT INTO open_repair_ack_bindings(resource_id,grant_id,write_digest,request_digest,
            binding_ref,manifest_ref,custody_ref,head_ref,generation,writer_keys) VALUES(?,?,?,?,?,?,?,?,1,?)""",
            (resource_id, held["slot"]["grant_id"], held["authorities"].originals["write"].ref.raw_sha256,
             held["request_digest"], *(held["result_refs"][name] for name in ("binding", "manifest", "custody", "head")),
             held["writer_keys_raw"]))
        self.db.execute("UPDATE open_repair_ack_resources SET status='empty',metadata_bytes=metadata_bytes+? WHERE resource_id=?", (charge, resource_id))
        self.db.execute("UPDATE open_repair_access_state SET generation=generation+1 WHERE resource_id=?", (resource_id,))
        return None

    def bind(self, resource_id, write_entry, offer_bootstrap_entry, *, expected_receipt_writer,
             expected_message_id, expected_envelope_ref, current_statuses, read_until, retain_until,
             _budget=None, _transaction_hook=None):
        """Commit one real empty event, or return its original exact retry bytes."""
        policy = self.state.policy
        budget = wire.RepairBudget(policy) if _budget is None else _budget
        wire._context(policy,budget)
        if _transaction_hook is not None and not callable(_transaction_hook):
            _fail("repair_invalid_context")
        prepared = self.access.prepare_bind(resource_id, write_entry, offer_bootstrap_entry,
            expected_receipt_writer=expected_receipt_writer, expected_message_id=expected_message_id,
            expected_envelope_ref=expected_envelope_ref, current_statuses=current_statuses,
            read_until=read_until, retain_until=retain_until, budget=budget)
        held = self.access._get(prepared)
        held["write_ref_raw"] = wire._canonical(held["authorities"].originals["write"].ref.as_dict(), budget)
        held["writer_keys_raw"] = wire._canonical(held["expected"]["receipt_writer"], budget)
        with self.state._transaction():
            transport_code = _transaction_hook("prepare",held,None) if _transaction_hook else None
            code = self._gate(prepared)
            code = transport_code or code
            existing = self._existing(resource_id)
        if code is not None:
            _fail(code)
        if existing is None:
            result, objects = self._build(held, budget)
            held["result_refs"] = {name: wire._canonical(entry["ref"], budget) for name, entry in result.items()}
        else:
            result, objects = self._saved_result(held, existing, policy, budget), ()
        if _transaction_hook:
            # Encoding the bounded transport result must remain outside locks.
            _transaction_hook("result",held,result)
        # The same immutable source/pin snapshot and all current floors are
        # checked again after expensive signing and proof assembly, before any
        # new original or head becomes visible. A commit failure returns none.
        with self.state._transaction():
            transport_code = _transaction_hook("commit",held,result) if _transaction_hook else None
            code = self._gate(prepared)
            code = transport_code or code
            if code is None and existing is None:
                code = self._store(held, result, objects)
            elif code is None and self._existing(resource_id) != existing:
                code = "repair_access_generation"
            if code is None and _transaction_hook:
                # Publication accounting and replay result belong to this exact
                # commit. A failing hook rolls back the new binding as well.
                publish_code = _transaction_hook("publish",held,result)
                if publish_code:
                    _fail(publish_code)
        if code is not None:
            _fail(code)
        return result
