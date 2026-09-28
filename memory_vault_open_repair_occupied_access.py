"""Current A READ of an exact, locally retained occupied ACK closure.

Full bootstrap proof requires B's explicitly signed four-role return variant;
old two-role consent is never silently upgraded to receipt/put disclosure. All
three generations and the actual receipt/job ledger are authenticated outside
the writer, then every retained byte and current floor is rechecked atomically.
"""
from types import MappingProxyType

import memory_vault_open_repair_access as access
import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_empty_access as empty_access
import memory_vault_open_repair_empty_state as empty_state
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_occupied_state as occupied_state
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_state as storage
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

PROFILE = "ack_owner_service_v1"
CURRENT_ROLES = (*access.CURRENT_ROLES, "current.status.ack_disclosure")
FIXED_PROOF_ROLES = occupied.ROLES | frozenset(("history.ack_occupied_inputs", "ack.commit", "ack.head")) | frozenset(CURRENT_ROLES)


def _fail(code):
    wire._fail(code)


def _entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


class RepairAckOccupiedAccess(access.RepairAckAccess):
    def _snapshot(self, resource_id):
        row, stamp, pins = occupied_state._OccupiedAccess._snapshot(self, resource_id)
        if row["status"] != "occupied":
            _fail("repair_resource_inactive")
        return row, stamp, pins

    def prepare(self, resource_id, *, action, current_statuses=None, expected_generation=None, policy=None, budget=None):
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
            saved = tuple(self.db.execute("""SELECT f.scope_kind,f.scope_id,d.raw,d.ref FROM open_repair_access_floors f
                JOIN open_repair_access_documents d ON d.resource_id=f.resource_id AND d.issuer=f.issuer
                AND d.revision=f.revision AND d.digest=f.digest WHERE f.resource_id=?
                ORDER BY d.issuer,d.revision,d.digest""", (resource_id,)))
        binding, reservation, existing = dict(stamp[1]), dict(stamp[2]), dict(stamp[3])
        old, bound, packs = {}, {}, []
        resolver = wire.LocalRawResolver(policy, budget)
        for role, namespace, key, digest, size, raw in pins:
            ref = wire.RawRef(namespace, key, digest, size)
            raw = wire._snapshot(bytes(raw), policy, budget)
            if len(raw) != ref.size or budget._hash(raw) != ref.raw_sha256:
                _fail("repair_storage_corrupt")
            entry = dict(raw=raw, ref=ref.as_dict())
            table, name = (bound, role[len("empty:"):]) if role.startswith("empty:") else (old, role)
            table.setdefault(name, []).append(entry)
            if name == "pack":
                if resolver.put(namespace, key, raw).ref != ref:
                    _fail("repair_storage_corrupt")
                packs.append(entry)
        if (old.keys() != ack.ROLES | {"manifest", "custody", "pack"}
                or bound.keys() != empty.ROLES | {"binding", "manifest", "custody", "head", "pack"}
                or any(len(values) != 1 for table in (old, bound) for name,values in table.items() if name != "pack")):
            _fail("repair_storage_corrupt")
        owner = wire.parse_new_wire(bytes(row["owner_keys"]), policy, budget).value
        writer = wire.parse_new_wire(binding["writer_keys"], policy, budget).value
        setup = wire.parse_new_wire(bytes(row["activation_inputs"]), policy, budget).value
        slot = wire.parse_new_wire(setup["root"]["raw"].encode(), policy, budget).value["payload"]["ack_slot"]
        # These previews select independent durable inputs only. No claim is
        # accepted until the complete occupied validator authenticates them.
        write = wire.parse_new_wire(bound["ack.write_grant"][0]["raw"], policy, budget).value["payload"]
        expected = dict(receipt_writer=writer, message_id=write["message_id"], envelope_ref=write["envelope_ref"])
        local = dict(resource_id=resource_id, stamp=stamp, slot=slot, owner=owner, expected=expected,
            resolver=resolver, source_manifest=bound["manifest"][0], source_custody=bound["custody"][0])
        result = occupied_state.RepairAckOccupiedState(self.state)._saved_result(local, existing, budget)
        checked = local["occupied_source"]
        empty_source, prior = checked.predecessor, checked.predecessor.predecessor
        for manifest, entries in ((prior.manifest, old), (empty_source.manifest, bound)):
            if any(entries[item.role][0] != _entry(item.original) for item in manifest.roles):
                _fail("repair_storage_corrupt")
            used = {wire.raw_ref(item["pack_ref"]) for item in manifest.manifest.value["roles"]}
            if {wire.raw_ref(item["ref"]) for item in entries["pack"]} != used or len(entries["pack"]) != len(used):
                _fail("repair_unused_pack")
        if (old["custody"][0] != self._saved(row,"custody",policy,budget)
                or old["manifest"][0]["ref"] != wire.parse_new_wire(bytes(row["manifest_ref"]),policy,budget).value
                or bound["history.ack_unbound"][0] != old["manifest"][0]
                or bound["ack.unbound_custody"][0] != old["custody"][0]
                or bound["ack.binding"][0] != _entry(empty_source.binding)
                or bound["binding"][0] != _entry(empty_source.binding)):
            _fail("repair_storage_corrupt")
        for name in ("binding", "manifest", "custody", "head"):
            if bound[name][0]["ref"] != wire.parse_new_wire(bytes(binding[name + "_ref"]),policy,budget).value:
                _fail("repair_storage_corrupt")
        # The old head is a real retained original too, although it is not an
        # input to occupied H. Authenticate it once, without rerunning its H.
        head = occupied._signed(bound["head"][0], self.state.target["signing_key"], "ack.head",
            resource.COMMON | {"ack_slot","generation","observed_at","retain_until","state","root_authority_ref","grant_ref","binding_ref"}, policy,budget)
        h = head.payload
        if (h["state"] != "empty" or wire.u53(h["generation"],1) != 1 or h["ack_slot"] != slot
                or h["observed_at"] != empty_source.stored_at or h["retain_until"] != empty_source.retain_until
                or any(h[name] != empty_source.custody.payload[name] for name in ("root_authority_ref","grant_ref","binding_ref"))):
            _fail("repair_storage_corrupt")
        exact = {"resource.ack_allocate":self._saved(row,"allocation",policy,budget),
            "resource.ack_offer":self._saved(row,"offer",policy,budget),
            "resource.ack_active":self._saved(row,"active",policy,budget),
            "historical.status.ack_resource":self._saved(row,"source_status",policy,budget)}
        for role,name in (("ack.root_authority","root"),("ack.read_grant","read"),
                          ("bootstrap.ack_owner","bootstrap"),("resource.ack_activation","activation")):
            exact[role] = dict(raw=setup[name]["raw"].encode(),ref=setup[name]["ref"])
        if any(old[role][0] != entry for role,entry in exact.items()):
            _fail("repair_local_original_mismatch")
        bind_expected = expected | dict(read_until=empty_source.read_until,retain_until=empty_source.retain_until)
        authorities = empty_source.authorities
        if (binding["grant_id"] != slot["grant_id"] or binding["generation"] != 1
                or binding["write_digest"] != authorities.originals["write"].ref.raw_sha256
                or binding["request_digest"] != budget._hash(wire._canonical(dict(write=authorities.originals["write"].ref.as_dict(),
                    bootstrap=authorities.originals["bootstrap"].ref.as_dict(),expected=bind_expected),budget))):
            _fail("repair_binding_ledger_missing")
        caps = prior.resources.originals["active"].payload["budget"]
        charge = caps["max_live_bytes"] + caps["max_meta_bytes"] + caps["max_job_bytes"] + caps["max_replay_records"] * storage.REPLAY_CHARGE + storage.ROW_CHARGE
        if (reservation["digest"] != row["request_digest"] or reservation["charge_bytes"] != charge
                or reservation["retain_until"] != row["retain_until"] or reservation["owner"] != row["owner"]
                or reservation["operation_id"] != row["allocation_id"] or existing["live_bytes"] > caps["max_live_bytes"]
                or existing["job_bytes"] > caps["max_job_bytes"] or caps["max_jobs"] < 1):
            _fail("repair_capacity_reservation_missing")
        grant_original, permitted, obligations, expires, code = empty_access.RepairAckEmptyAccess._current_authority(
            self,empty_source,owner,slot,action,now,policy,budget)
        disclosure = checked.inputs["disclosure"]
        duty = occupied._obligations(empty_source,checked.inputs,owner,writer,self.state.target,slot,policy,budget)[-1]
        permitted = (*permitted,duty)
        obligations = (*obligations,duty | dict(role="current.status.ack_disclosure",mask=2))
        d = disclosure.payload
        expires = min(expires,checked.read_until,checked.retain_until,d["expires_at"],d["consent_until"],d["bootstrap_return"]["until"])
        if (d["bootstrap_return"]["roles"] != list(occupied.RETURN_ROLES_FULL)
                or not occupied.B_ROLES <= set(d["allowed_roles"]) or d["operation_mask"] & 2 != 2):
            code = code or "repair_disclosure_bootstrap_unsupported"
        if not d["issued_at"] <= now < expires:
            code = code or "repair_access_expired"
        if current_statuses is None:
            required = {(item["scope_kind"],item["scope_id"]) for item in obligations}
            documents = {(bytes(raw),bytes(ref)) for kind,scope_id,raw,ref in saved if (kind,scope_id) in required}
            current_statuses = ([dict(raw=raw,ref=wire.parse_new_wire(ref,policy,budget).value) for raw,ref in sorted(documents)]
                                if saved else [_entry(item) for item in checked.statuses])
        if type(current_statuses) not in (list,tuple) or not 1 <= len(current_statuses) <= 8:
            _fail("repair_invalid_status")
        authenticated=[]
        for entry in current_statuses:
            try:
                raw,ref=ack._entry(entry)
                preview=original.parse_original_control(raw,policy,budget)
                payload=status._fields(status._fields(preview.value,{"payload","proof"})["payload"],status._PAYLOAD)
                issuer=status._fields(payload["scope_key"],{"root_key","issuer_key_id"})["issuer_key_id"]
                allowed=[item for item in permitted if item["signer"]["key_id"]==issuer]
                if not allowed:
                    _fail("repair_status_mismatch")
                authenticated.append(status.authenticate_status_original(dict(raw=preview.raw,ref=ref.as_dict()),
                    expected_root=slot["root_key"],expected_signing_key=allowed[0]["signer"],at=now,
                    allowed_scopes=[dict(scope_kind=item["scope_kind"],scope_id=item["scope_id"]) for item in allowed],policy=policy,budget=budget))
            except wire.RepairWireError as error:
                code=code or error.code
        previous=(*prior.statuses,*empty_source.statuses,*checked.statuses)
        try:
            empty._history_floors((*previous,*authenticated),previous=previous,current=authenticated)
        except wire.RepairWireError as error:
            code=code or error.code
        basis=[MappingProxyType(dict(role=item.role,raw=item.original.raw,ref=item.original.ref)) for item in checked.manifest.roles]
        for role,name in (("history.ack_occupied_inputs","manifest"),("ack.commit","commit"),("ack.head","head")):
            basis.append(MappingProxyType(dict(role=role,raw=result[name]["raw"],ref=wire.raw_ref(result[name]["ref"]))))
        for role,namespace,key,digest,size,raw in stamp[5]:
            if role == "occupied:pack":
                packs.append(dict(raw=bytes(raw),ref=dict(namespace=namespace,key=key,raw_sha256=digest,size=size)))
        for entry in packs:
            basis.append(MappingProxyType(dict(role="history.raw_pack",raw=entry["raw"],ref=wire.raw_ref(entry["ref"]))))
        prepared=access._Preparation()
        grant=grant_original.payload
        self._prepared[prepared]=dict(resource_id=resource_id,stamp=stamp,pins=pins,action=action,
            root_digest=budget._hash(wire._canonical(slot["root_key"],budget)),obligations=obligations,statuses=tuple(authenticated),
            status_refs={item.canonical_sha256:wire._canonical(item.ref.as_dict(),budget) for item in authenticated},
            basis=tuple(basis),expected_generation=expected_generation,expires=expires,code=code,
            subject=MappingProxyType(dict(grant["subject"])),selector=MappingProxyType(dict(grant["selector"])),
            grant_ref=grant_original.ref,limits=MappingProxyType(dict(grant["limits"])),capacity=caps,
            source=checked,checked=False,proof=())
        return prepared
