"""Current owner-only READ of a complete, durably bound empty ACK source.

The original owner bootstrap remains the actual authority. Its existing
service profile has a closed empty-phase child set; it creates no writer
admission, new grant or cross-owner disclosure right.
No signing, parsing or crypto runs under the writer gate. The caller must
commit check_locked's recorded observations before reporting a refusal.
"""
from types import MappingProxyType

import memory_vault_open_repair_access as access
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_empty_state as empty_state
import memory_vault_open_repair_original as original
import memory_vault_open_repair_state as storage
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire


PROFILE = "ack_owner_service_v1"
FIXED_PROOF_ROLES = empty.ROLES | frozenset(("history.ack_empty", "ack.empty_custody", "ack.head")) | frozenset(access.CURRENT_ROLES)


def _fail(code):
    wire._fail(code)


class RepairAckEmptyAccess(access.RepairAckAccess):
    def _snapshot(self, resource_id):
        row, stamp, pins = empty_state._EmptyAccess._snapshot(self, resource_id)
        if row["status"] != "empty":
            _fail("repair_resource_inactive")
        binding = self.state._one("SELECT * FROM open_repair_ack_bindings WHERE resource_id=?", (resource_id,))
        if binding is None or type(binding.get("writer_keys")) is not bytes:
            _fail("repair_binding_ledger_missing")
        reservation = self.state._one("SELECT * FROM open_capacity_reservations WHERE service='ack' AND reservation_id=?", (resource_id,))
        if reservation is None:
            _fail("repair_capacity_reservation_missing")
        if self.state._one("SELECT 1 FROM open_repair_ack_binding_conflicts WHERE resource_id=?", (resource_id,)) is not None:
            _fail("repair_binding_conflict")
        return row, (stamp, tuple(sorted(binding.items())), tuple(sorted(reservation.items()))), pins

    def _current_authority(self, checked, owner, slot, action, now, policy, budget):
        prior, authorities = checked.predecessor, checked.authorities
        root, read, active = (prior.resources.originals[name].payload for name in ("root", "read", "active"))
        grant_original = prior.bootstrap.originals["bootstrap"]
        grant = grant_original.payload
        permitted = empty._obligations(prior, authorities, owner, self.state.target, slot, policy, budget)
        current_by_historical = {"historical.status." + name[len("current.status."):]: name for name in access.CURRENT_ROLES}
        obligations = []
        for item in permitted:
            if item["role"] in current_by_historical:
                mask = 10 if action == "challenge" and item["role"] in ("historical.status.ack_root", "historical.status.ack_owner_bootstrap") else 2
                obligations.append(item | dict(role=current_by_historical[item["role"]], mask=mask))
        expires = min(root["expires_at"], read["expires_at"], grant["expires_at"], grant["proof_until"],
            grant["probe_until"] if action == "challenge" else grant["proof_until"], checked.read_until,
            prior.descriptor.payload["expires_at"], *(item["windows"][name] for item in (root, read, active)
            for name in ("read_until", "retain_until")))
        code = None
        if (not all(item["issued_at"] <= now for item in (root, read, grant)) or now >= expires
                or root["operation_mask"] & (10 if action == "challenge" else 2) != (10 if action == "challenge" else 2)
                or read["operation_mask"] & 2 != 2):
            code = "repair_access_expired"
        return grant_original, permitted, obligations, expires, code

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
            binding, reservation = dict(stamp[1]), dict(stamp[2])
            now = self.state._now()
            saved = tuple(self.db.execute("""SELECT f.scope_kind,f.scope_id,d.raw,d.ref FROM open_repair_access_floors f
                JOIN open_repair_access_documents d ON d.resource_id=f.resource_id AND d.issuer=f.issuer
                AND d.revision=f.revision AND d.digest=f.digest WHERE f.resource_id=?
                ORDER BY d.issuer,d.revision,d.digest""", (resource_id,)))
        old, new, packs = {}, {}, []
        resolver = wire.LocalRawResolver(policy, budget)
        for role, namespace, key, digest, size, raw in pins:
            ref = wire.RawRef(namespace, key, digest, size)
            raw = wire._snapshot(bytes(raw), policy, budget)
            if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
                _fail("repair_storage_corrupt")
            entry = dict(raw=raw, ref=ref.as_dict())
            table = new if role.startswith("empty:") else old
            name = role[len("empty:"):] if role.startswith("empty:") else role
            table.setdefault(name, []).append(entry)
            if name == "pack":
                if resolver.put(namespace, key, raw).ref != ref:
                    _fail("repair_storage_corrupt")
                packs.append(entry)
        if (old.keys() != ack.ROLES | {"manifest", "custody", "pack"}
                or new.keys() != empty.ROLES | {"binding", "manifest", "custody", "head", "pack"}
                or any(len(values) != 1 for table in (old, new) for name, values in table.items() if name != "pack")):
            _fail("repair_storage_corrupt")
        result = {name: new[name][0] for name in ("binding", "manifest", "custody", "head")}
        for name, entry in result.items():
            if entry["ref"] != wire.parse_new_wire(bytes(binding[name + "_ref"]), policy, budget).value:
                _fail("repair_storage_corrupt")
        if (old["custody"][0] != self._saved(row, "custody", policy, budget)
                or old["manifest"][0]["ref"] != wire.parse_new_wire(bytes(row["manifest_ref"]), policy, budget).value
                or new["history.ack_unbound"][0] != old["manifest"][0]
                or new["ack.unbound_custody"][0] != old["custody"][0]):
            _fail("repair_storage_corrupt")
        owner = wire.parse_new_wire(bytes(row["owner_keys"]), policy, budget).value
        writer = wire.parse_new_wire(binding["writer_keys"], policy, budget).value
        setup = wire.parse_new_wire(bytes(row["activation_inputs"]), policy, budget).value
        slot = wire.parse_new_wire(setup["root"]["raw"].encode(), policy, budget).value["payload"]["ack_slot"]
        # Preview only independently selects the saved message/ref. Its real
        # signature, full writer descriptors and all parents are checked below.
        write = wire.parse_new_wire(new["ack.write_grant"][0]["raw"], policy, budget).value["payload"]
        custody = wire.parse_new_wire(result["custody"]["raw"], policy, budget).value["payload"]
        expected = dict(receipt_writer=writer, message_id=write["message_id"], envelope_ref=write["envelope_ref"],
                        read_until=custody["read_until"], retain_until=custody["retain_until"])
        checker = empty_state.RepairAckEmptyState(self.state)
        checked = checker._verify_result(dict(resolver=resolver, slot=slot, owner=owner, expected=expected), result, budget)
        prior, authorities = checked.predecessor, checked.authorities
        for manifest, entries in ((prior.manifest, old), (checked.manifest, new)):
            for item in manifest.roles:
                if entries[item.role][0] != empty_state._entry(item.original):
                    _fail("repair_storage_corrupt")
            used = {wire.raw_ref(item["pack_ref"]) for item in manifest.manifest.value["roles"]}
            if {wire.raw_ref(item["ref"]) for item in entries["pack"]} != used or len(entries["pack"]) != len(used):
                _fail("repair_unused_pack")
        exact = {"resource.ack_allocate": self._saved(row, "allocation", policy, budget),
            "resource.ack_offer": self._saved(row, "offer", policy, budget),
            "resource.ack_active": self._saved(row, "active", policy, budget),
            "historical.status.ack_resource": self._saved(row, "source_status", policy, budget)}
        for role, name in (("ack.root_authority", "root"), ("ack.read_grant", "read"),
                           ("bootstrap.ack_owner", "bootstrap"), ("resource.ack_activation", "activation")):
            exact[role] = dict(raw=setup[name]["raw"].encode(), ref=setup[name]["ref"])
        if any(old[role][0] != entry for role, entry in exact.items()):
            _fail("repair_local_original_mismatch")
        if (binding["grant_id"] != slot["grant_id"] or binding["generation"] != 1
                or binding["write_digest"] != authorities.originals["write"].ref.raw_sha256
                or binding["request_digest"] != budget._hash(wire._canonical(dict(
                    write=authorities.originals["write"].ref.as_dict(),
                    bootstrap=authorities.originals["bootstrap"].ref.as_dict(), expected=expected), budget))):
            _fail("repair_binding_ledger_missing")
        root, read, active = (prior.resources.originals[name].payload for name in ("root", "read", "active"))
        caps = active["budget"]
        charge = caps["max_live_bytes"] + caps["max_meta_bytes"] + caps["max_job_bytes"] + caps["max_replay_records"] * storage.REPLAY_CHARGE + storage.ROW_CHARGE
        if (reservation["digest"] != row["request_digest"] or reservation["charge_bytes"] != charge
                or reservation["retain_until"] != row["retain_until"] or reservation["owner"] != row["owner"]
                or reservation["operation_id"] != row["allocation_id"]):
            _fail("repair_capacity_reservation_missing")
        grant_original, permitted, obligations, expires, code = self._current_authority(
            checked, owner, slot, action, now, policy, budget)
        grant = grant_original.payload
        if current_statuses is None:
            required = {(item["scope_kind"], item["scope_id"]) for item in obligations}
            held_documents = {(bytes(raw), bytes(ref)) for kind, scope_id, raw, ref in saved if (kind, scope_id) in required}
            current_statuses = ([dict(raw=raw, ref=wire.parse_new_wire(ref, policy, budget).value)
                                 for raw, ref in sorted(held_documents)] if saved
                                else [empty_state._entry(item) for item in checked.statuses])
        if type(current_statuses) not in (list, tuple) or not 1 <= len(current_statuses) <= 7:
            _fail("repair_invalid_status")
        authenticated = []
        for entry in current_statuses:
            try:
                raw, ref = ack._entry(entry)
                preview = original.parse_original_control(raw, policy, budget)
                payload = status._fields(status._fields(preview.value, {"payload", "proof"})["payload"], status._PAYLOAD)
                issuer = status._fields(payload["scope_key"], {"root_key", "issuer_key_id"})["issuer_key_id"]
                allowed = [item for item in permitted if item["signer"]["key_id"] == issuer]
                if not allowed:
                    _fail("repair_status_mismatch")
                authenticated.append(status.authenticate_status_original(dict(raw=preview.raw, ref=ref.as_dict()),
                    expected_root=slot["root_key"], expected_signing_key=allowed[0]["signer"], at=now,
                    allowed_scopes=[dict(scope_kind=item["scope_kind"], scope_id=item["scope_id"]) for item in allowed],
                    policy=policy, budget=budget))
            except wire.RepairWireError as error:
                code = code or error.code
        try:
            empty._history_floors((*prior.statuses, *checked.statuses, *authenticated),
                previous=(*prior.statuses, *checked.statuses), current=authenticated)
        except wire.RepairWireError as error:
            code = code or error.code
        basis = [MappingProxyType(dict(role=item.role, raw=item.original.raw, ref=item.original.ref)) for item in checked.manifest.roles]
        for role, name in (("history.ack_empty", "manifest"), ("ack.empty_custody", "custody"), ("ack.head", "head")):
            basis.append(MappingProxyType(dict(role=role, raw=result[name]["raw"], ref=wire.RawRef(**result[name]["ref"]))))
        for entry in packs:
            basis.append(MappingProxyType(dict(role="history.raw_pack", raw=entry["raw"], ref=wire.RawRef(**entry["ref"]))))
        prepared = access._Preparation()
        self._prepared[prepared] = dict(resource_id=resource_id, stamp=stamp, pins=pins, action=action,
            root_digest=budget._hash(wire._canonical(slot["root_key"], budget)), obligations=tuple(obligations),
            statuses=tuple(authenticated), status_refs={item.canonical_sha256: wire._canonical(item.ref.as_dict(), budget) for item in authenticated},
            basis=tuple(basis), expected_generation=expected_generation, expires=expires, code=code,
            subject=MappingProxyType(dict(grant["subject"])), selector=MappingProxyType(dict(grant["selector"])),
            grant_ref=grant_original.ref, limits=MappingProxyType(dict(grant["limits"])), capacity=caps,
            source=checked, checked=False, proof=())
        return prepared
