"""Atomic local empty-to-occupied receipt admission in RepairAckState.db.

This is a local node API, not a network-authentication shortcut. A remote
adapter must first complete the real ack_offer dual-key/preflight protocol and
use the final transaction guard. A committed pending head job is only pending;
this module makes no publication, replication or delivery claim.
"""
from types import MappingProxyType

import memory_vault_open_repair_access as access
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_empty_access as empty_access
import memory_vault_open_repair_empty_state as empty_state
import memory_vault_open_repair_history as history
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_state as storage
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


def _fail(code):
    wire._fail(code)


def _entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


class _OccupiedAccess(empty_access.RepairAckEmptyAccess):
    """Reuse the owner's full retained predecessor, then add real put duties."""
    def _snapshot(self, resource_id):
        self.state._binding()
        row = self.state._row(resource_id)
        if row["status"] not in ("empty", "occupied"):
            _fail("repair_resource_inactive")
        source_stamp = tuple((key,value) for key,value in sorted(row.items()) if key != "metadata_bytes")
        pins = tuple(tuple(item) for item in self.db.execute("""SELECT p.role,o.namespace,o.opaque_key,o.raw_sha256,o.size,o.raw
            FROM open_repair_ack_pins p JOIN open_repair_ack_objects o
            ON p.namespace=o.namespace AND p.opaque_key=o.opaque_key WHERE p.resource_id=?
            ORDER BY p.role,o.namespace,o.opaque_key LIMIT ?""", (resource_id, self.state.policy.max_entries + 1)))
        count = self.db.execute("SELECT count(*) FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,)).fetchone()[0]
        if not pins or len(pins) > self.state.policy.max_entries or len(pins) != count:
            _fail("repair_storage_corrupt")
        binding = self.state._one("SELECT * FROM open_repair_ack_bindings WHERE resource_id=?", (resource_id,))
        reservation = self.state._one("SELECT * FROM open_capacity_reservations WHERE service='ack' AND reservation_id=?", (resource_id,))
        if binding is None or type(binding.get("writer_keys")) is not bytes:
            _fail("repair_binding_ledger_missing")
        if reservation is None:
            _fail("repair_capacity_reservation_missing")
        for table in ("open_repair_ack_binding_conflicts", "open_repair_ack_receipt_conflicts"):
            if self.state._one("SELECT 1 FROM " + table + " WHERE resource_id=?", (resource_id,)):
                _fail("repair_receipt_conflict")
        commit = self.state._one("SELECT * FROM open_repair_ack_commits WHERE resource_id=?", (resource_id,))
        job = self.state._one("SELECT * FROM open_repair_ack_jobs WHERE resource_id=?", (resource_id,))
        if (row["status"] == "empty") != (commit is None) or (commit is None) != (job is None):
            _fail("repair_receipt_ledger_missing")
        added = tuple(item for item in pins if item[0].startswith("occupied:"))
        if (commit is None) != (not added):
            _fail("repair_receipt_ledger_missing")
        stamp = (source_stamp, tuple(sorted(binding.items())), tuple(sorted(reservation.items())),
                 tuple(sorted(commit.items())) if commit else None, tuple(sorted(job.items())) if job else None, added)
        return row, stamp, tuple(item for item in pins if not item[0].startswith("occupied:"))

    def prepare_put(self, resource_id, receipt_entry, disclosure_entry, put_entry, *, current_statuses,
                    read_until, retain_until, policy, budget):
        if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 8:
            _fail("repair_invalid_status")
        # Only choose inputs here. Signatures and all whole-document scopes are
        # authenticated below; self-declared issuers never become authorities.
        with self.state._lock:
            row = self.state._row(resource_id)
            binding = self.state._one("SELECT * FROM open_repair_ack_bindings WHERE resource_id=?", (resource_id,))
        if binding is None or type(binding.get("writer_keys")) is not bytes:
            _fail("repair_binding_ledger_missing")
        owner = wire.parse_new_wire(bytes(row["owner_keys"]), policy, budget).value
        writer = wire.parse_new_wire(binding["writer_keys"], policy, budget).value
        accepted = {owner["signing_key"]["key_id"], self.state.target["signing_key"]["key_id"]}
        owner_statuses = []
        for entry in current_statuses:
            raw, _ = ack._entry(entry)
            preview = original.parse_original_control(raw, policy, budget).value
            issuer = preview.get("payload", {}).get("scope_key", {}).get("issuer_key_id")
            if issuer in accepted:
                owner_statuses.append(entry)
        prepared = super().prepare(resource_id, action="proof", current_statuses=owner_statuses, policy=policy, budget=budget)
        held = self._get(prepared)
        prior, now = held["source"], self.state._now()
        slot = prior.custody.payload["ack_slot"]
        inputs = occupied._inputs(prior, receipt_entry, disclosure_entry, put_entry,
            owner=owner, writer=writer, at=now, policy=policy, budget=budget)
        maximum_read, maximum_retain, admit_until = occupied._windows(prior, inputs, now)
        if not now < wire.u53(read_until) <= wire.u53(retain_until) <= maximum_retain or read_until > maximum_read:
            _fail("repair_ack_occupied_mismatch")
        duties = occupied._obligations(prior, inputs, owner, writer, self.state.target, slot, policy, budget)
        # Already authenticated owner/R documents are reused; B is a separate
        # signer and may return only its exact completed consent's scope.
        authenticated = list(held["statuses"])
        for entry in current_statuses:
            if any(entry["raw"] == item.raw and wire.raw_ref(entry["ref"]) == item.ref for item in authenticated):
                continue
            raw, ref = ack._entry(entry)
            preview = original.parse_original_control(raw, policy, budget)
            payload = status._fields(status._fields(preview.value, {"payload", "proof"})["payload"], status._PAYLOAD)
            issuer = status._fields(payload["scope_key"], {"root_key", "issuer_key_id"})["issuer_key_id"]
            allowed = [item for item in duties if item["signer"]["key_id"] == issuer]
            if not allowed:
                _fail("repair_status_mismatch")
            authenticated.append(status.authenticate_status_original(dict(raw=preview.raw, ref=ref.as_dict()),
                expected_root=slot["root_key"], expected_signing_key=allowed[0]["signer"], at=now,
                allowed_scopes=[dict(scope_kind=item["scope_kind"], scope_id=item["scope_id"]) for item in allowed], policy=policy, budget=budget))
        try:
            previous = (*prior.predecessor.statuses, *prior.statuses)
            empty._history_floors((*previous, *authenticated), previous=previous, current=authenticated)
        except wire.RepairWireError as error:
            held["code"] = held["code"] or error.code
        expected = dict(receipt_writer=writer, message_id=prior.authorities.originals["write"].payload["message_id"],
            envelope_ref=prior.authorities.originals["write"].payload["envelope_ref"])
        basis = {item["role"]: dict(raw=item["raw"], ref=item["ref"].as_dict()) for item in held["basis"] if item["role"] != "history.raw_pack"}
        resolver = wire.LocalRawResolver(policy, budget)
        for item in held["basis"]:
            if item["role"] == "history.raw_pack":
                resolver.put(item["ref"].namespace, item["ref"].key, item["raw"])
        held.update(action="put", obligations=duties, statuses=tuple(authenticated),
            status_refs={item.canonical_sha256:wire._canonical(item.ref.as_dict(), budget) for item in authenticated},
            expires=min(held["expires"], admit_until), checked=False, proof=(), slot=slot, owner=owner,
            writer=writer, inputs=inputs, at=now, read_until=read_until, retain_until=retain_until,
            expected=expected, resolver=resolver, source_manifest=basis["history.ack_empty"],
            source_custody=basis["ack.empty_custody"], request_digest=budget._hash(wire._canonical(dict(
                receipt=inputs["receipt"].ref.as_dict(), disclosure=inputs["disclosure"].ref.as_dict(),
                put=inputs["put"].ref.as_dict(), read_until=read_until, retain_until=retain_until), budget)),
            receipt_ref_raw=wire._canonical(inputs["receipt"].ref.as_dict(), budget))
        return prepared


class RepairAckOccupiedState:
    def __init__(self, state):
        self.state, self.db = state, state.db
        self.access = _OccupiedAccess(state)

    def initialize(self):
        self.access.initialize()
        with self.state._transaction():
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_ack_commits(
                resource_id TEXT PRIMARY KEY,grant_id TEXT NOT NULL,receipt_digest TEXT NOT NULL,
                request_digest TEXT NOT NULL,receipt_ref BLOB NOT NULL,manifest_ref BLOB NOT NULL,
                commit_ref BLOB NOT NULL,head_ref BLOB NOT NULL,generation INTEGER NOT NULL,
                live_bytes INTEGER NOT NULL,job_bytes INTEGER NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_ack_jobs(
                resource_id TEXT PRIMARY KEY,kind TEXT NOT NULL,state TEXT NOT NULL,
                raw BLOB NOT NULL,head_ref BLOB NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS open_repair_ack_receipt_conflicts(
                resource_id TEXT PRIMARY KEY,receipt_digest TEXT NOT NULL,raw BLOB,ref BLOB NOT NULL,retained INTEGER NOT NULL)""")

    def _existing(self, resource_id):
        return self.state._one("SELECT * FROM open_repair_ack_commits WHERE resource_id=?", (resource_id,))

    def _verify_result(self, held, result, budget):
        expected, policy = held["expected"], budget.policy
        checked = occupied.verify_ack_occupied_source_event(result["manifest"], held["resolver"], result["commit"],
            expected_ack_slot=held["slot"], expected_owner=held["owner"], expected_receipt_writer=expected["receipt_writer"],
            expected_message_id=expected["message_id"], expected_envelope_ref=expected["envelope_ref"],
            expected_target=self.state.target, target_storage_epoch=self.state.node["payload"]["storage_epoch"],
            limit_policy=self.state.limits, policy=policy, budget=budget)
        occupied.verify_ack_occupied_head(result["head"], checked, expected_target=self.state.target, policy=policy, budget=budget)
        return checked

    def _saved_result(self, held, existing, budget):
        assigned, policy = {}, budget.policy
        for role, namespace, key, digest, size, raw in held["stamp"][5]:
            raw = wire._snapshot(bytes(raw), policy, budget)
            ref = wire.RawRef(namespace, key, digest, size)
            if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
                _fail("repair_storage_corrupt")
            name = role[len("occupied:"):]
            entry = dict(raw=raw, ref=ref.as_dict())
            assigned.setdefault(name, []).append(entry)
            if name == "pack" and held["resolver"].put(namespace, key, raw).ref != ref:
                _fail("repair_storage_corrupt")
        if (assigned.keys() != occupied.ROLES | {"manifest", "commit", "head", "pack"}
                or any(len(values) != 1 for role,values in assigned.items() if role != "pack")):
            _fail("repair_storage_corrupt")
        result = {name:assigned[name][0] for name in ("manifest", "commit", "head")}
        for name, entry in result.items():
            if entry["ref"] != wire.parse_new_wire(bytes(existing[name + "_ref"]), policy, budget).value:
                _fail("repair_storage_corrupt")
        checked = self._verify_result(held, result, budget)
        if any(assigned[item.role][0] != _entry(item.original) for item in checked.manifest.roles):
            _fail("repair_storage_corrupt")
        if (assigned["history.ack_empty"][0] != held["source_manifest"]
                or assigned["ack.empty_custody"][0] != held["source_custody"]):
            _fail("repair_storage_corrupt")
        used = {wire.raw_ref(item["pack_ref"]) for item in checked.manifest.manifest.value["roles"]}
        if {wire.raw_ref(item["ref"]) for item in assigned["pack"]} != used or len(assigned["pack"]) != len(used):
            _fail("repair_unused_pack")
        receipt = checked.inputs["receipt"]
        request = dict(receipt=receipt.ref.as_dict(), disclosure=checked.inputs["disclosure"].ref.as_dict(),
            put=checked.inputs["put"].ref.as_dict(), read_until=checked.read_until, retain_until=checked.retain_until)
        job = dict(held["stamp"][4])
        expected_job = self._job(held["resource_id"], result)
        if (existing["receipt_digest"] != receipt.ref.raw_sha256 or existing["grant_id"] != held["slot"]["grant_id"]
                or existing["generation"] != 2 or existing["live_bytes"] != len(receipt.raw)
                or wire.parse_new_wire(bytes(existing["receipt_ref"]), policy, budget).value != receipt.ref.as_dict()
                or existing["request_digest"] != budget._hash(wire._canonical(request, budget))
                or job["kind"] != "ack.head.publish" or job["state"] != "pending"
                or bytes(job["raw"]) != wire._canonical(expected_job, budget)
                or wire.parse_new_wire(bytes(job["head_ref"]), policy, budget).value != result["head"]["ref"]
                or existing["job_bytes"] != len(job["raw"]) + storage.ROW_CHARGE):
            _fail("repair_receipt_ledger_missing")
        held["occupied_source"] = checked
        return result

    @staticmethod
    def _job(resource_id, result):
        return dict(kind="ack.head.publish", resource_id=resource_id, head_ref=result["head"]["ref"],
                    original_ack_commit_ref=result["commit"]["ref"])

    def _gate(self, prepared, transaction_guard):
        held = self.access._get(prepared)
        decision = self.access.check_locked(prepared)
        if not decision.allowed:
            return decision.code
        if transaction_guard is not None:
            code = transaction_guard(decision)
            if code is not None:
                return code
        existing = self._existing(held["resource_id"])
        if existing is None:
            return None
        receipt = held["inputs"]["receipt"]
        if existing["receipt_digest"] != receipt.ref.raw_sha256:
            source = self.state._row(held["resource_id"])
            charge = len(receipt.raw) + storage.ROW_CHARGE
            count = self.db.execute("SELECT count(*) FROM (SELECT DISTINCT namespace,opaque_key FROM open_repair_ack_pins WHERE resource_id=?)",
                                    (held["resource_id"],)).fetchone()[0]
            retained = (source["metadata_bytes"] + charge <= held["capacity"]["max_meta_bytes"]
                        and count < held["capacity"]["max_items"])
            self.db.execute("INSERT OR IGNORE INTO open_repair_ack_receipt_conflicts VALUES(?,?,?,?,?)",
                (held["resource_id"], receipt.ref.raw_sha256, receipt.raw if retained else None,
                 held["receipt_ref_raw"], int(retained)))
            if retained:
                self.db.execute("UPDATE open_repair_ack_resources SET metadata_bytes=metadata_bytes+? WHERE resource_id=?", (charge, held["resource_id"]))
            self.db.execute("UPDATE open_repair_ack_resources SET status='conflicted' WHERE resource_id=?", (held["resource_id"],))
            self.db.execute("UPDATE open_repair_access_state SET generation=generation+1 WHERE resource_id=?", (held["resource_id"],))
            return "repair_receipt_conflict" if retained else "repair_receipt_conflict_capacity"
        if existing["request_digest"] != held["request_digest"]:
            return "repair_receipt_retry_mismatch"
        return None

    def _build(self, held, budget):
        policy, prior, now = budget.policy, held["source"], held["at"]
        slot, inputs = held["slot"], held["inputs"]
        root = prior.predecessor.resources.originals["root"]
        grant = prior.authorities.originals["write"]
        active = prior.predecessor.resources.originals["active"].payload["resource"]
        assigned = {"history.ack_empty":held["source_manifest"], "ack.empty_custody":held["source_custody"],
            "recipient.receipt":_entry(inputs["receipt"]), "ack.disclosure":_entry(inputs["disclosure"]), "ack.put":_entry(inputs["put"])}
        assigned.update({item["role"]:dict(raw=item["raw"], ref=item["ref"].as_dict()) for item in held["proof"]})
        if assigned.keys() != occupied.ROLES:
            _fail("repair_status_missing")
        packed = wire.build_raw_pack(list({entry["raw"] for entry in assigned.values()}), policy, budget)
        positions = {entry.raw_sha256:index for index,entry in enumerate(packed.entries)}
        rows = [dict(role=role, document_ref=entry["ref"], pack_ref=packed.ref.as_dict(), entry_index=positions[entry["ref"]["raw_sha256"]])
                for role,entry in assigned.items()]
        rows.sort(key=lambda item:(item["role"], *history._ref_tuple(item["document_ref"])))
        refs = dict(grant_ref=grant.ref.as_dict(), binding_ref=prior.binding.ref.as_dict(),
            receipt_ref=inputs["receipt"].ref.as_dict(), put_ref=inputs["put"].ref.as_dict(), disclosure_ref=inputs["disclosure"].ref.as_dict())
        raw = wire.build_new_wire(dict(schema_version=history.SCHEMA, kind="historical.manifest", variant="ack_occupied_inputs",
            root_key=slot["root_key"], ack_slot=slot, root_authority_ref=root.ref.as_dict(), admission_resource=active, roles=rows, **refs), policy, budget).raw
        digest = budget._hash(raw)
        manifest = dict(raw=raw, ref=dict(namespace="meta", key=digest, raw_sha256=digest, size=len(raw)))
        commit = self.state._sign(dict(schema_version=resource.SCHEMA, kind="ack.commit", signing_key=self.state.identity.public_descriptor(),
            ack_slot=slot, historical_manifest_ref=manifest["ref"], resource_ref=active, stored_at=now,
            read_until=held["read_until"], retain_until=held["retain_until"], **refs), "occupied-commit", budget)
        head = self.state._sign(dict(schema_version=resource.SCHEMA, kind="ack.head", signing_key=self.state.identity.public_descriptor(),
            ack_slot=slot, generation=2, observed_at=now, retain_until=held["retain_until"], state="occupied", root_authority_ref=root.ref.as_dict(),
            grant_ref=grant.ref.as_dict(), binding_ref=prior.binding.ref.as_dict(), original_ack_commit_ref=commit["ref"], receipt_ref=inputs["receipt"].ref.as_dict()), "occupied-head", budget)
        held["resolver"].put(packed.ref.namespace, packed.ref.key, packed.raw)
        result = dict(manifest=manifest, commit=commit, head=head)
        checked = self._verify_result(held, result, budget)
        objects = [(_entry(item.original), "occupied:" + item.role) for item in checked.manifest.roles]
        objects.extend((entry, "occupied:" + name) for name,entry in result.items())
        objects.append((dict(raw=packed.raw, ref=packed.ref.as_dict()), "occupied:pack"))
        held["result_refs"] = {name:wire._canonical(entry["ref"], budget) for name,entry in result.items()}
        held["job_raw"] = wire._canonical(self._job(held["resource_id"], result), budget)
        return result, tuple(objects)

    def _store(self, held, result, objects):
        resource_id, caps = held["resource_id"], held["capacity"]
        source = self.state._row(resource_id)
        current = {(row[0],row[1]) for row in self.db.execute("SELECT DISTINCT namespace,opaque_key FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,))}
        pins = {(row[0],row[1],row[2]) for row in self.db.execute("SELECT namespace,opaque_key,role FROM open_repair_ack_pins WHERE resource_id=?", (resource_id,))}
        new_objects, new_pins, metadata = {}, [], 2 * storage.ROW_CHARGE
        receipt = held["inputs"]["receipt"]
        live, job_bytes = len(receipt.raw), len(held["job_raw"]) + storage.ROW_CHARGE
        for entry, role in objects:
            ref = entry["ref"]
            key = ref["namespace"], ref["key"]
            prior = self.state._one("SELECT * FROM open_repair_ack_objects WHERE namespace=? AND opaque_key=?", key)
            if prior is not None and (prior["raw_sha256"] != ref["raw_sha256"] or prior["size"] != ref["size"] or bytes(prior["raw"]) != entry["raw"]):
                return "repair_ref_conflict"
            if key not in current and key not in new_objects:
                new_objects[key] = entry
                metadata += storage.ROW_CHARGE + (0 if ref == receipt.ref.as_dict() else len(entry["raw"]))
            pin = *key, role
            if pin not in pins:
                pins.add(pin)
                new_pins.append(pin)
                metadata += 256
        if (source["metadata_bytes"] + metadata > caps["max_meta_bytes"] or live > caps["max_live_bytes"]
                or len(current) + len(new_objects) > caps["max_items"] or caps["max_jobs"] < 1 or job_bytes > caps["max_job_bytes"]):
            return "repair_insufficient_capacity"
        for (namespace,key), entry in new_objects.items():
            ref = entry["ref"]
            self.db.execute("INSERT OR IGNORE INTO open_repair_ack_objects VALUES(?,?,?,?,?)", (namespace,key,ref["raw_sha256"],ref["size"],entry["raw"]))
        for namespace,key,role in new_pins:
            self.db.execute("INSERT INTO open_repair_ack_pins VALUES(?,?,?,?)", (resource_id,namespace,key,role))
        self.db.execute("INSERT INTO open_repair_ack_commits VALUES(?,?,?,?,?,?,?,?,2,?,?)", (resource_id,held["slot"]["grant_id"],receipt.ref.raw_sha256,
            held["request_digest"],held["receipt_ref_raw"],*(held["result_refs"][name] for name in ("manifest", "commit", "head")),live,job_bytes))
        self.db.execute("INSERT INTO open_repair_ack_jobs VALUES(?,?,?,?,?)", (resource_id,"ack.head.publish","pending",held["job_raw"],held["result_refs"]["head"]))
        self.db.execute("UPDATE open_repair_ack_resources SET status='occupied',metadata_bytes=metadata_bytes+? WHERE resource_id=?", (metadata,resource_id))
        self.db.execute("UPDATE open_repair_access_state SET generation=generation+1 WHERE resource_id=?", (resource_id,))
        return None

    def put(self, resource_id, receipt_entry, disclosure_entry, put_entry, *, current_statuses,
            read_until, retain_until, policy=None, budget=None, _transaction_guard=None, _transaction_hook=None):
        """Commit exact B originals or return the durably retained exact retry.

        ``_transaction_guard`` is for the trusted HTTP adapter's live session /
        replay checks, at both writer gates. It is never a possession boolean.
        """
        if (policy is None) != (budget is None):
            _fail("repair_invalid_context")
        policy = self.state.policy if policy is None else policy
        budget = wire.RepairBudget(policy) if budget is None else budget
        wire._context(policy, budget)
        if any(value is not None and not callable(value) for value in (_transaction_guard, _transaction_hook)):
            _fail("repair_invalid_context")
        prepared = self.access.prepare_put(resource_id, receipt_entry, disclosure_entry, put_entry,
            current_statuses=current_statuses, read_until=read_until, retain_until=retain_until, policy=policy, budget=budget)
        held = self.access._get(prepared)
        existing = dict(held["stamp"][3]) if held["stamp"][3] else None
        # A retry/conflict cannot hide corruption of an earlier committed event.
        result = self._saved_result(held, existing, budget) if existing else None
        with self.state._transaction():
            transport_code = _transaction_hook("prepare", held, None) if _transaction_hook else None
            code = self._gate(prepared, _transaction_guard)
            code = transport_code or code
        if code is not None:
            _fail(code)
        objects = ()
        if result is None:
            result, objects = self._build(held, budget)
        if _transaction_hook:
            # Carrier encoding and hashes belong outside the writer.
            result_code = _transaction_hook("result", held, result)
            if result_code:
                _fail(result_code)
        with self.state._transaction():
            transport_code = _transaction_hook("commit", held, result) if _transaction_hook else None
            code = self._gate(prepared, _transaction_guard)
            code = transport_code or code
            if code is None and existing is None:
                code = self._store(held, result, objects)
            if code is None and _transaction_hook:
                publish_code = _transaction_hook("publish", held, result)
                if publish_code:
                    # A response/replay accounting failure rolls back the
                    # entire receipt/head/job commit, never merely its reply.
                    _fail(publish_code)
        if code is not None:
            _fail(code)
        return result
