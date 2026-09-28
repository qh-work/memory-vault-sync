"""Atomic original data/metadata resource activation for one mailbox slot.

This local setup stage persists the exact owner chain, both node activation
events and the count-zero checkpoint/head together. Current observations and
root custody must still commit before a caller can publish or use a cold entry.
"""
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_mailbox_range as mailbox_range
from memory_vault_open_repair_state import ROW_CHARGE


FIELDS = {
    "maintenance": "issued_at expires_at root_key authority_id slot_key sender recipient maintainers operation_mask allowed_roles budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision",
    "read": "issued_at expires_at grant_id root_key slot_key reader serving_authority_id operation_mask budget windows revision",
    "slot": "issued_at expires_at revision slot_key feed_ref sender recipient data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref max_appends max_live_items budget windows",
    "bootstrap": "issued_at expires_at grant_id revision owner subject root_key consumer selector parent_authority_ref caller_authority_ref probe_until proof_until upload_until probe_profile response_profile upload_roles limits",
    "activation": resource._FIELDS[4],
}
KINDS = dict(maintenance="mailbox.maintenance_root", read="mailbox.read_grant",
             slot="mailbox.slot", bootstrap="bootstrap.grant", activation="resource.activation")
UPLOAD_ROLES = frozenset(("mailbox.slot", "mailbox.read_grant", "mailbox.maintenance_root", "bootstrap.grant"))


def _mismatch():
    wire._fail("repair_mailbox_activation_mismatch")


def _ordered(values, key, check):
    resource._array(values)
    previous = None
    for value in values:
        check(value)
        current = key(value)
        if previous is not None and current <= previous:
            _mismatch()
        previous = current


def _role(value):
    if type(value) is not str or value not in resource.KNOWN_ALLOWED_ROLES:
        _mismatch()


def _check_slot_authority(held, p, slot_key, owner, offers, budget, now, *, target, epoch, policy, limits):
    root = slot_key["root_key"]
    owner_id = resource._dual_key(owner, budget)
    maintenance, read, slot, grant, activation = (p[k] for k in FIELDS)
    if (root["owner"] != owner_id or slot_key["writer"] != resource._dual_key(target, budget)
            or slot_key["writer_storage_epoch"] != epoch):
        _mismatch()
    for name in ("maintenance", "read", "slot"):
        value = p[name]
        history._slot(value["slot_key"], root)
        resource._budget(value["budget"])
        resource._windows(value["windows"], issued=value["issued_at"], expires=value["expires_at"])
        wire.u53(value["revision"])
        if value["slot_key"] != slot_key or (name != "slot" and value["root_key"] != root):
            _mismatch()
    for value in (maintenance, read):
        resource._opmask(value["operation_mask"])
    for value in (maintenance, slot):
        history._dual(value["sender"]); history._dual(value["recipient"])
        if value["recipient"] != owner_id:
            _mismatch()
    history._dual(read["reader"])
    for value in (maintenance["authority_id"], read["grant_id"], read["serving_authority_id"]):
        original._opaque(value)
    if (read["reader"] != owner_id or slot["sender"] != maintenance["sender"]
            or read["serving_authority_id"] != maintenance["authority_id"]
            or slot["read_grant_ref"] != held["read"]["ref"]
            or slot["maintenance_root_ref"] != held["maintenance"]["ref"]):
        _mismatch()
    resource._fields(slot["feed_ref"], {"namespace", "key"})
    if slot["feed_ref"]["namespace"] != "feed":
        _mismatch()
    original._digest(slot["feed_ref"]["key"])
    if not 1 <= wire.u53(slot["max_live_items"]) <= wire.u53(slot["max_appends"], 1) <= 65536:
        _mismatch()
    if slot["max_live_items"] > slot["budget"]["max_items"]:
        _mismatch()
    if wire.u53(maintenance["max_delegate_depth"]) != 2:
        _mismatch()
    wire.u53(maintenance["max_destinations_per_job"])
    wire.u53(maintenance["max_concurrent_jobs"])
    _ordered(maintenance["maintainers"], lambda v: (v["signing_key_id"], v["encryption_key_id"]), history._dual)
    _ordered(maintenance["allowed_roles"], lambda v: v, _role)
    if (maintenance["operation_mask"] & 10 != 10 or read["operation_mask"] & 2 != 2
            or read["operation_mask"] & ~maintenance["operation_mask"]
            or not {"bootstrap.grant", "selected_slot_service_v1"} <= set(maintenance["allowed_roles"])
            or any(read["budget"][k] > maintenance["budget"][k] for k in resource._BUDGET)
            or any(read["windows"][k] > maintenance["windows"][k] for k in resource._WINDOWS)
            or read["expires_at"] > maintenance["expires_at"]):
        _mismatch()
    for name, purpose in (("data", "mailbox_data"), ("metadata", "feed_metadata")):
        offer = offers[name]
        value = wire.parse_new_wire(offer["raw"], policy, budget).value["payload"]
        intent = value["intent"]
        if (slot[name+"_resource_ref"] != value["resource"]
                or slot[name+"_resource_offer_ref"] != offer["ref"]
                or intent["purpose"] != purpose or intent["root_key"] != root
                or intent["owner"] != owner or intent["target"] != target
                or value["issued_at"] > min(p[k]["issued_at"] for k in ("maintenance", "read", "slot"))
                or min(intent["windows"].values()) <= now):
            _mismatch()
    # The read/maintenance grants may outlive a particular resource. The
    # later custody promise intersects their windows with the actual lease.
    resource._fields(grant["selector"], {"root_key_sha256", "slot_key_sha256", "feed_ref",
                                       "slot_sha256", "read_grant_sha256", "maintenance_root_sha256"})
    original._opaque(grant["grant_id"]); wire.u53(grant["revision"])
    if (grant["owner"] != owner_id or grant["subject"] != owner_id or grant["root_key"] != root
            or grant["consumer"] != "mailbox_feed" or grant["probe_profile"] != "opaque_v1"
            or grant["response_profile"] != "selected_slot_service_v1"
            or grant["parent_authority_ref"] != held["maintenance"]["ref"]
            or grant["caller_authority_ref"] != held["read"]["ref"]
            or grant["selector"] != dict(root_key_sha256=budget._hash(wire._canonical(root, budget)),
                slot_key_sha256=budget._hash(wire._canonical(slot_key, budget)), feed_ref=slot["feed_ref"],
                slot_sha256=held["slot"]["ref"]["raw_sha256"], read_grant_sha256=held["read"]["ref"]["raw_sha256"],
                maintenance_root_sha256=held["maintenance"]["ref"]["raw_sha256"])):
        _mismatch()
    _ordered(grant["upload_roles"], lambda v: v, _role)
    if not set(grant["upload_roles"]) <= UPLOAD_ROLES & set(maintenance["allowed_roles"]):
        _mismatch()
    bootstrap._limits(grant["limits"])
    for key, parent_fields in bootstrap._PARENT_CAPS.items():
        value = grant["limits"][key]
        if value > limits[key] or any(value > parent["budget"][field]
                for parent in (maintenance, read) for field in parent_fields):
            _mismatch()
    if not (maintenance["issued_at"] <= read["issued_at"] <= slot["issued_at"]
            <= grant["issued_at"] <= activation["issued_at"] <= now
            and grant["expires_at"] <= min(maintenance["expires_at"], read["expires_at"])):
        _mismatch()
    for key in ("probe_until", "proof_until", "upload_until"):
        if not now < wire.u53(grant[key]) <= grant["expires_at"]:
            _mismatch()
    if any(grant[key] > parent["windows"][window] for key in ("proof_until", "upload_until")
           for parent in (maintenance, read) for window in ("read_until", "retain_until")):
        _mismatch()
    original._opaque(activation["activation_id"])
    expected_offers = sorted((offer["ref"] for offer in offers.values()), key=history._ref_tuple)
    expected_authorities = [{"role": KINDS[name], "ref": held[name]["ref"]}
                            for name in ("maintenance", "read", "slot")]
    if (activation["subject"] != owner or activation["target_node_key_id"] != target["signing_key"]["key_id"]
            or activation["target_storage_epoch"] != slot_key["writer_storage_epoch"]
            or activation["root_key"] != root
            or activation["scope"] != dict(kind="mailbox_slot", slot_key=slot_key, slot_ref=held["slot"]["ref"])
            or activation["resource_offer_refs"] != expected_offers
            or activation["authority_refs"] != expected_authorities):
        _mismatch()


def verify_mailbox_slot_owner_inputs(entries, *, expected_slot, expected_owner, expected_target,
        target_storage_epoch, offers, limit_policy, at, policy, budget):
    """Verify detached B slot/read/maintenance/bootstrap and activation originals.

    Expected identities are supplied independently by the caller. Resource
    offer signatures and custody are separate checks; this function checks the
    complete owner authority chain without a database, clock or signing key.
    """
    wire._context(policy,budget)
    expected = wire.build_new_wire(dict(slot=expected_slot,owner=expected_owner,target=expected_target,
        epoch=target_storage_epoch,limits=limit_policy,at=at),policy,budget).value
    history._slot(expected["slot"],expected["slot"]["root_key"])
    original._opaque(expected["epoch"]);wire.u53(expected["at"])
    resource._dual_key(expected["owner"],budget);resource._dual_key(expected["target"],budget)
    bootstrap._limits(expected["limits"])
    resource._fields(entries,FIELDS);resource._fields(offers,{"data","metadata"})
    held,payloads = {},{}
    for name in FIELDS:
        value = resource._fields(entries[name],{"raw","ref"})
        ref = resource._ref(wire.build_new_wire(value["ref"],policy,budget).value)
        parsed = wire.parse_new_wire(value["raw"],policy,budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            wire._fail("repair_ref_mismatch")
        signed = resource._fields(parsed.value,{"payload","proof"})
        payload = resource._fields(signed["payload"],resource.COMMON | set(FIELDS[name].split()))
        if payload["schema_version"] != resource.SCHEMA or payload["kind"] != KINDS[name]:
            _mismatch()
        resource._lifetime(payload)
        if not payload["issued_at"] <= expected["at"] < payload["expires_at"]:
            wire._fail("repair_resource_expired")
        original._verify_control_signature(payload,signed["proof"],expected["owner"]["signing_key"],budget)
        held[name],payloads[name] = dict(raw=parsed.raw,ref=ref.as_dict()),payload
    frozen_offers = {}
    for name in ("data","metadata"):
        value = resource._fields(offers[name],{"raw","ref"})
        ref = resource._ref(wire.build_new_wire(value["ref"],policy,budget).value)
        parsed = wire.parse_new_wire(value["raw"],policy,budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            wire._fail("repair_ref_mismatch")
        frozen_offers[name] = dict(raw=parsed.raw,ref=ref.as_dict())
    _check_slot_authority(held,payloads,expected["slot"],expected["owner"],frozen_offers,budget,expected["at"],
        target=expected["target"],epoch=expected["epoch"],policy=policy,limits=expected["limits"])
    return {name:resource.AuthenticatedRepairOriginal(held[name]["raw"],wire.raw_ref(held[name]["ref"]),payloads[name])
            for name in FIELDS}


def verify_mailbox_genesis(entries, *, expected_slot, expected_signing_key, committed_at, at, policy, budget):
    """Authenticate count-zero checkpoint/head bound to the original slot commit."""
    wire._context(policy,budget)
    resource._fields(entries,{"checkpoint","head"})
    slot = wire.build_new_wire(expected_slot,policy,budget).value
    history._slot(slot,slot["root_key"])
    key = wire.build_new_wire(expected_signing_key,policy,budget).value
    wire.u53(committed_at);wire.u53(at)
    initial = mailbox_range.empty_state(slot,policy=policy,budget=budget)
    checked = {}
    for name,kind,fields in (("checkpoint","mailbox.checkpoint",set(initial)),
            ("head","mailbox.feed_head",{"checkpoint_ref","count","range_root_ref","catalog_generation"})):
        value = resource._fields(entries[name],{"raw","ref"})
        ref = resource._ref(wire.build_new_wire(value["ref"],policy,budget).value)
        parsed = wire.parse_new_wire(value["raw"],policy,budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            wire._fail("repair_ref_mismatch")
        signed = resource._fields(parsed.value,{"payload","proof"})
        payload = resource._fields(signed["payload"],resource.COMMON | fields | {"slot_key","committed_at","retain_until"})
        if (payload["schema_version"] != resource.SCHEMA or payload["kind"] != kind
                or payload["slot_key"] != slot or payload["committed_at"] != committed_at
                or not wire.u53(payload["committed_at"]) <= at < wire.u53(payload["retain_until"])):
            _mismatch()
        original._verify_control_signature(payload,signed["proof"],key,budget)
        if name == "checkpoint":
            if any(payload[k] != v for k,v in initial.items()):
                _mismatch()
        elif (payload["checkpoint_ref"] != checked["checkpoint"].ref.as_dict()
                or wire.u53(payload["count"]) != 0 or payload["range_root_ref"] is not None
                or wire.u53(payload["catalog_generation"]) != 0
                or payload["retain_until"] != checked["checkpoint"].payload["retain_until"]):
            _mismatch()
        checked[name] = resource.AuthenticatedRepairOriginal(parsed.raw,ref,payload)
    return checked


class MailboxSlotActivation:
    def __init__(self, resources):
        self.resources, self.source, self.db = resources, resources.source, resources.db

    def initialize(self):
        self.resources.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_slot_activations(
                slot_digest TEXT PRIMARY KEY,owner TEXT NOT NULL,activation_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,inputs BLOB NOT NULL,
                data_resource_id TEXT NOT NULL UNIQUE,metadata_resource_id TEXT NOT NULL UNIQUE,
                data_active BLOB NOT NULL,data_active_ref BLOB NOT NULL,
                metadata_active BLOB NOT NULL,metadata_active_ref BLOB NOT NULL,
                activated_at INTEGER NOT NULL,UNIQUE(owner,activation_id))''')
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_genesis(
                slot_digest TEXT PRIMARY KEY,checkpoint BLOB NOT NULL,checkpoint_ref BLOB NOT NULL,
                head BLOB NOT NULL,head_ref BLOB NOT NULL,committed_at INTEGER NOT NULL,
                retain_until INTEGER NOT NULL)''')

    def _originals(self, entries, owner, budget, now, *, fields=FIELDS, kinds=KINDS):
        resource._fields(entries, fields)
        held, payloads = {}, {}
        for name in fields:
            parsed, ref = self.source._entry(entries[name], budget)
            signed = resource._fields(parsed.value, {"payload", "proof"})
            p = resource._fields(signed["payload"], resource.COMMON | set(fields[name].split()))
            if p["schema_version"] != resource.SCHEMA or p["kind"] != kinds[name]:
                _mismatch()
            resource._lifetime(p)
            if not p["issued_at"] <= now < p["expires_at"]:
                wire._fail("repair_resource_expired")
            original._verify_control_signature(p, signed["proof"], owner["signing_key"], budget)
            held[name], payloads[name] = dict(raw=parsed.raw, ref=ref.as_dict()), p
        return held, payloads

    def _check(self, held, p, slot_key, owner, offers, budget, now):
        return _check_slot_authority(held,p,slot_key,owner,offers,budget,now,
            target=self.source.target,epoch=self.source.node["payload"]["storage_epoch"],
            policy=self.source.policy,limits=self.source.limits)

    def activate(self, entries, *, expected_slot, _budget=None, _transaction_guard=None):
        """Commit the empty slot, not root custody or a network-ready result."""
        s = self.source
        deadlines = []
        def guard():
            if _transaction_guard is not None:
                code = _transaction_guard()
                if code:
                    return code
            if deadlines and s._now() >= min(deadlines):
                return "repair_resource_expired"
            return None
        with s._transaction(guard=guard) as now:
            budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
            wire._context(s.policy, budget)
            slot_key = wire.build_new_wire(expected_slot, s.policy, budget).value
            history._slot(slot_key, slot_key["root_key"])
            slot_digest = budget._hash(wire._canonical(slot_key, budget))
            resource._fields(entries, FIELDS)
            snapped = {}
            for name in FIELDS:
                parsed, ref = s._entry(entries[name], budget)
                snapped[name] = dict(raw=parsed.raw, ref=ref.as_dict())
            entries = snapped
            # Parse only bounded originals before selecting the local resources.
            draft, _ = s._entry(entries["slot"], budget)
            signed = resource._fields(draft.value, {"payload", "proof"})
            slot = resource._fields(signed["payload"], resource.COMMON | set(FIELDS["slot"].split()))
            rows, offers = {}, {}
            for name in ("data", "metadata"):
                history._resource(slot[name+"_resource_ref"])
                row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",
                             (slot[name+"_resource_ref"]["resource_id"],))
                if row is None:
                    wire._fail("repair_unknown_resource")
                rows[name], offers[name] = row, s._saved(row, "offer")
            owner = json.loads(bytes(rows["data"]["owner_keys"]))
            # An exact retry remains a replay after short setup authority expiry.
            refs = {name: entries[name]["ref"] for name in FIELDS}
            digest = budget._hash(wire._canonical(dict(slot_key=slot_key, refs=refs), budget))
            old = s._one("SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?", (slot_digest,))
            if old is not None:
                if old["input_digest"] != digest:
                    wire._fail("repair_activation_conflict")
                genesis = s._one("SELECT * FROM open_repair_mailbox_genesis WHERE slot_digest=?", (slot_digest,))
                if genesis is None:
                    # Older, unfinished local activation stages cannot silently
                    # become a new current promise using expired authority.
                    wire._fail("repair_mailbox_genesis_incomplete")
                return {**{name: s._saved(old, name+"_active") for name in ("data", "metadata")},
                        **{name: s._saved(genesis, name) for name in ("checkpoint", "head")}}
            held, payloads = self._originals(entries, owner, budget, now)
            self._check(held, payloads, slot_key, owner, offers, budget, now)
            activation = payloads["activation"]
            if s._one("SELECT 1 FROM open_repair_mailbox_slot_activations WHERE owner=? AND activation_id=?",
                      (owner["signing_key"]["key_id"], activation["activation_id"])):
                wire._fail("repair_activation_conflict")
            if any(row["status"] != "pending" or now >= row["reservation_until"] for row in rows.values()):
                wire._fail("repair_resource_inactive")
            inputs = wire.build_new_wire({k: dict(raw=v["raw"].decode(), ref=v["ref"])
                for k, v in held.items()}, s.policy, budget).raw
            result, offer_payloads, metadata_usage = {}, {}, {}
            deadlines.extend(row["reservation_until"] for row in rows.values())
            deadlines += [p["expires_at"] for p in payloads.values()]
            deadlines += [payloads["bootstrap"][key] for key in ("probe_until", "proof_until", "upload_until")]
            for name, row in rows.items():
                offer = wire.parse_new_wire(offers[name]["raw"], s.policy, budget).value["payload"]
                offer_payloads[name] = offer
                deadlines.extend(offer["windows"].values())
                result[name] = s._sign(dict(schema_version=resource.SCHEMA, kind="resource.active",
                    signing_key=s.identity.public_descriptor(), activated_at=now,
                    offer_ref=offers[name]["ref"], activation_ref=held["activation"]["ref"],
                    resource=offer["resource"], reservation_generation=offer["reservation_generation"],
                    root_key=slot_key["root_key"], purpose=offer["intent"]["purpose"],
                    budget=offer["budget"], windows=offer["windows"]), "mailbox_active", budget)
                # Charge the shared chain in each independent reservation. No
                # unproven physical deduplication reduces either obligation.
                metadata = row["metadata_bytes"] + len(inputs) + len(result[name]["raw"]) + 8*ROW_CHARGE
                if metadata > offer["budget"]["max_meta_bytes"]:
                    wire._fail("repair_insufficient_capacity")
                metadata_usage[name] = metadata
                self.db.execute("UPDATE open_repair_mailbox_resources SET status='active',metadata_bytes=? WHERE resource_id=?",
                                (metadata, row["resource_id"]))
            initial = mailbox_range.empty_state(slot_key, policy=s.policy, budget=budget)
            retain_until = min(payloads["slot"]["windows"]["retain_until"],
                               *(value["windows"]["retain_until"] for value in offer_payloads.values()))
            result["checkpoint"] = s._sign(dict(schema_version=resource.SCHEMA, kind="mailbox.checkpoint",
                signing_key=s.identity.public_descriptor(), slot_key=slot_key, **initial,
                committed_at=now, retain_until=retain_until), "mailbox_checkpoint", budget)
            result["head"] = s._sign(dict(schema_version=resource.SCHEMA, kind="mailbox.feed_head",
                signing_key=s.identity.public_descriptor(), slot_key=slot_key,
                checkpoint_ref=result["checkpoint"]["ref"], count=0, range_root_ref=None,
                catalog_generation=0, committed_at=now, retain_until=retain_until), "mailbox_feed_head", budget)
            extra = sum(len(result[name]["raw"]) for name in ("checkpoint", "head")) + 3*ROW_CHARGE
            for name, row in rows.items():
                total = metadata_usage[name] + extra
                if total > offer_payloads[name]["budget"]["max_meta_bytes"]:
                    wire._fail("repair_insufficient_capacity")
                self.db.execute("UPDATE open_repair_mailbox_resources SET metadata_bytes=? WHERE resource_id=?",
                                (total, row["resource_id"]))
            deadlines.append(retain_until)
            self.db.execute('''INSERT INTO open_repair_mailbox_slot_activations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                (slot_digest, owner["signing_key"]["key_id"], activation["activation_id"], digest, inputs,
                 rows["data"]["resource_id"], rows["metadata"]["resource_id"], result["data"]["raw"],
                 canonical_bytes(result["data"]["ref"]), result["metadata"]["raw"],
                 canonical_bytes(result["metadata"]["ref"]), now))
            self.db.execute("INSERT INTO open_repair_mailbox_genesis VALUES(?,?,?,?,?,?,?)",
                (slot_digest, result["checkpoint"]["raw"], canonical_bytes(result["checkpoint"]["ref"]),
                 result["head"]["raw"], canonical_bytes(result["head"]["ref"]), now, retain_until))
            return result


def verify_mailbox_member_setup(resolved, *, expected_slot, expected_owner, expected_sender,
        expected_target, target_storage_epoch, accepted_at, limit_policy, policy, budget):
    """Authenticate original contact and activated resources for a selected member.

    Message-specific disclosure, destination, attempt and status obligations are
    separate checks. This is an offline consumer of originals, not a new grant.
    """
    wire._context(policy,budget)
    expected=wire.build_new_wire(dict(slot=expected_slot,owner=expected_owner,sender=expected_sender,
        target=expected_target,epoch=target_storage_epoch,at=accepted_at,limits=limit_policy),policy,budget).value
    slot,owner,sender,target=(expected[k] for k in ('slot','owner','sender','target'))
    history._slot(slot,slot['root_key']);wire.u53(accepted_at)
    for keys in (owner,sender,target):resource._dual_key(keys,budget)
    m=resolved.manifest.value
    if m['variant']!='mailbox_member' or m['slot_key']!=slot or m['root_key']!=slot['root_key'] or resolved.predecessors:
        _mismatch()
    roles={}
    for item in resolved.roles:
        if item.role in roles:_mismatch()
        roles[item.role]=dict(raw=item.original.raw,ref=item.original.ref.as_dict())
    def get(role):
        if role not in roles:wire._fail('repair_original_missing')
        return roles[role]
    entries={name:get(role) for name,role in dict(slot='mailbox.slot',read='mailbox.read_grant',
        maintenance='mailbox.maintenance_root',bootstrap='bootstrap.mailbox_feed',activation='resource.slot_activation').items()}
    resources={name:{part:get('resource.'+name+'_'+part) for part in ('allocate','offer','active')} for name in ('data','metadata')}
    active=[wire.parse_new_wire(resources[name]['active']['raw'],policy,budget).value['payload'] for name in ('data','metadata')]
    activated_at=wire.u53(active[0]['activated_at'])
    if active[1]['activated_at']!=activated_at or activated_at>accepted_at:_mismatch()
    checked=verify_mailbox_slot_owner_inputs(entries,expected_slot=slot,expected_owner=owner,expected_target=target,
        target_storage_epoch=expected['epoch'],offers={name:values['offer'] for name,values in resources.items()},
        limit_policy=expected['limits'],at=activated_at,policy=policy,budget=budget)
    p=checked['slot'].payload
    if p['sender']!=resource._dual_key(sender,budget) or p['recipient']!=resource._dual_key(owner,budget):_mismatch()
    for name in ('slot','read','maintenance','bootstrap'):
        value=checked[name].payload
        if not value['issued_at']<=accepted_at<value['expires_at']:wire._fail('repair_resource_expired')
        if 'windows' in value and accepted_at>=min(value['windows'][field] for field in ('admit_until','retain_until')):
            wire._fail('repair_resource_expired')
    activation=checked['activation'].payload
    checked_resources={}
    for name,purpose in (('data','mailbox_data'),('metadata','feed_metadata')):
        group=resource.verify_mailbox_resource_inputs(dict(resources[name],activation=entries['activation']),
            expected_root=slot['root_key'],expected_owner=owner,expected_target=target,target_storage_epoch=expected['epoch'],
            expected_purpose=purpose,expected_scope=activation['scope'],expected_authority_refs=activation['authority_refs'],
            expected_offer_refs=activation['resource_offer_refs'],at=accepted_at,policy=policy,budget=budget)
        if group['active'].payload['resource']!=p[name+'_resource_ref']:_mismatch()
        checked_resources[name]=group
    contact={name:get(role)['raw'] for name,role in dict(node='source.descriptor',request='contact.request',
        policy='contact.policy',decision='contact.decision',grant='contact.store_grant',
        knock_lease='contact.knock_lease',delivery_lease='contact.delivery_lease').items()}
    verified=original.verify_contact_originals(contact,sender_key_id=sender['signing_key']['key_id'],
        sender_encryption_key_id=sender['encryption_key']['key_id'],recipient_key_id=owner['signing_key']['key_id'],
        recipient_encryption_key_id=owner['encryption_key']['key_id'],node_key_id=target['signing_key']['key_id'],
        storage_epoch=expected['epoch'],at=accepted_at,policy=policy,budget=budget)
    return dict(originals=checked,resources=checked_resources,contact=verified,roles=roles,accepted_at=accepted_at)


def verify_mailbox_member_inputs(resolved, *, expected_slot, expected_owner, expected_sender,
        expected_target, target_storage_epoch, accepted_at, limit_policy, policy, budget):
    """Verify the original non-ACK message authority at its actual admission.

    Current revocations, custody and the source event graph remain separate.
    """
    import memory_vault_open_repair_status as status
    graph=verify_mailbox_member_setup(resolved,expected_slot=expected_slot,expected_owner=expected_owner,
        expected_sender=expected_sender,expected_target=expected_target,target_storage_epoch=target_storage_epoch,
        accepted_at=accepted_at,limit_policy=limit_policy,policy=policy,budget=budget)
    roles=graph['roles'];m=resolved.manifest.value;root=m['root_key'];key=m['slot_key'];at=accepted_at
    expected_roles=history._ROLES['mailbox_member']-{'ack.root_authority','ack.write_grant','bootstrap.ack_offer',
        'historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap'}
    if set(roles)!=expected_roles:_mismatch()
    def control(role,kind,fields,signer):
        entry=roles[role];signed=resource._fields(wire.parse_new_wire(entry['raw'],policy,budget).value,{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|set(fields.split()))
        if p['schema_version']!=resource.SCHEMA or p['kind']!=kind:_mismatch()
        resource._lifetime(p)
        if not p['issued_at']<=at<p['expires_at']:wire._fail('repair_resource_expired')
        original._verify_control_signature(p,signed['proof'],signer,budget)
        return p
    dp=control('delivery.destination','delivery.destination',
        'issued_at expires_at destination_id sender recipient contact_request_ref contact_policy_ref contact_knock_lease_ref contact_decision_ref store_grant_ref slot_key slot_ref data_resource_ref data_resource_offer_ref metadata_resource_ref metadata_resource_offer_ref read_grant_ref maintenance_root_ref budget windows',expected_owner['signing_key'])
    ap=control('delivery.attempt','delivery.attempt',
        'issued_at expires_at attempt_id message_id envelope_ref sender recipient destination_ref slot_key operation disclosure_ref ack_grant_ref',expected_sender['signing_key'])
    cp=control('message.disclosure','message.disclosure',
        'issued_at expires_at consent_id root_key slot_key sender recipient envelope_ref maintenance_root_ref allowed_roles operation_mask consent_until bootstrap_return revision',expected_sender['signing_key'])
    originals=graph['originals'];slot=originals['slot'].payload;maintenance=originals['maintenance'].payload
    for p,identifier in ((dp,'destination_id'),(ap,'attempt_id'),(cp,'consent_id')):
        original._opaque(p[identifier])
        if p['slot_key']!=key or p['sender']!=slot['sender'] or p['recipient']!=slot['recipient']:_mismatch()
    if (ap['operation']!='message.store' or ap['ack_grant_ref'] is not None or ap['message_id']!=m['message_id']
            or ap['envelope_ref']!=m['envelope_ref'] or cp['envelope_ref']!=m['envelope_ref']
            or m['attempt_ref']!=roles['delivery.attempt']['ref'] or ap['destination_ref']!=roles['delivery.destination']['ref']
            or ap['disclosure_ref']!=roles['message.disclosure']['ref'] or dp['slot_ref']!=roles['mailbox.slot']['ref']):_mismatch()
    for name in ('data_resource_ref','metadata_resource_ref','data_resource_offer_ref','metadata_resource_offer_ref','read_grant_ref','maintenance_root_ref'):
        if dp[name]!=slot[name]:_mismatch()
    resource._budget(dp['budget']);resource._windows(dp['windows'])
    if (any(dp['budget'][k]>slot['budget'][k] for k in dp['budget'])
            or any(dp['windows'][k]>slot['windows'][k] for k in dp['windows'])
            or at>=min(dp['windows']['admit_until'],dp['windows']['retain_until'])):_mismatch()
    for field,name in (('contact_request_ref','request'),('contact_policy_ref','policy'),('contact_knock_lease_ref','knock_lease'),('contact_decision_ref','decision'),('store_grant_ref','grant')):
        role={'request':'contact.request','policy':'contact.policy','knock_lease':'contact.knock_lease','decision':'contact.decision','grant':'contact.store_grant'}[name]
        if dp[field]!=roles[role]['ref']:_mismatch()
    wire.u53(cp['revision'],1);status._mask(cp['operation_mask'])
    if wire.raw_ref(cp['envelope_ref']).namespace!='object':_mismatch()
    if (cp['root_key']!=root or cp['maintenance_root_ref']!=roles['mailbox.maintenance_root']['ref']
            or cp['issued_at']>ap['issued_at'] or cp['operation_mask']&65!=65
            or not at<wire.u53(cp['consent_until'])<=cp['expires_at']<=min(slot['expires_at'],maintenance['expires_at'])
            or cp['consent_until']>min(slot['windows']['retain_until'],maintenance['windows']['retain_until'])):_mismatch()
    required_roles={'contact.request','delivery.attempt','message.disclosure','authority.status.disclosure'}
    allowed_roles=required_roles|{'ack.root_authority','ack.write_grant','bootstrap.ack_offer',
        'historical.status.ack_root','historical.status.ack_write','historical.status.ack_offer_bootstrap'}
    allowed=cp['allowed_roles']
    if (type(allowed) is not wire._DraftList or any(type(v) is not str for v in allowed)
            or list(allowed)!=sorted(set(allowed)) or not required_roles<=set(allowed)<=allowed_roles):wire._fail('repair_status_disclosure')
    returned=resource._fields(cp['bootstrap_return'],{'subject','consumer','roles','until'})
    if (returned['subject']!=slot['recipient'] or returned['consumer']!='mailbox_feed'
            or returned['roles']!=['authority.status.disclosure','message.disclosure']
            or not at<wire.u53(returned['until'])<=cp['consent_until']):wire._fail('repair_status_disclosure')
    obligations=[]
    def add(role,kind,subject,revision,bits,signer):
        obligations.append(dict(role=role,scope_kind=kind,scope_id=status.status_scope(root,kind,subject,policy,budget),
            document_revision=revision,operation_mask=bits,signer=signer))
    add('slot','mailbox_slot',key,slot['revision'],65,expected_owner['signing_key'])
    authorities=[('read','mailbox.read_grant',originals['read'].payload,2,expected_owner['signing_key']),
        ('maintenance','mailbox.maintenance_root',maintenance,65,expected_owner['signing_key']),
        ('bootstrap','bootstrap.mailbox_feed',originals['bootstrap'].payload,10,expected_owner['signing_key']),
        ('destination','delivery.destination',dp,1,expected_owner['signing_key']),
        ('disclosure','message.disclosure',cp,65,expected_sender['signing_key'])]
    for name,role,p,bits,signer in authorities:
        add(name,'authority',dict(authority_kind=p['kind'],authority_sha256=roles[role]['ref']['raw_sha256']),p.get('revision',1),bits,signer)
    for name in ('data','metadata'):
        p=graph['resources'][name]['active'].payload
        add(name+'_resource','resource',p['resource'],p['reservation_generation'],65,expected_target['signing_key'])
    statuses=[];revisions={};floors={}
    for obligation in obligations:
        signer=obligation['signer'];permitted=[v for v in obligations if v['signer']==signer]
        entry=roles['historical.status.'+obligation['role']]
        required={k:obligation[k] for k in ('scope_kind','scope_id','document_revision','operation_mask')}
        preview=original.parse_original_control(entry['raw'],policy,budget).value['payload']
        present={(v['scope_kind'],v['scope_id']) for v in preview['entries']}
        requirements=[{k:v[k] for k in ('scope_kind','scope_id','document_revision','operation_mask')}
            for v in permitted if (v['scope_kind'],v['scope_id']) in present]
        if required not in requirements:wire._fail('repair_status_missing')
        observed=status.verify_status_original(entry,expected_root=root,expected_signing_key=signer,at=at,
            allowed_scopes=[{k:v[k] for k in ('scope_kind','scope_id')} for v in permitted],required=requirements,policy=policy,budget=budget)
        identity=(signer['key_id'],observed.payload['revision'])
        if identity in revisions and revisions[identity]!=observed.canonical_sha256:wire._fail('repair_status_conflict')
        revisions[identity]=observed.canonical_sha256;statuses.append(observed)
        for value in observed.payload['entries']:
            floors.setdefault((signer['key_id'],value['scope_kind'],value['scope_id']),[]).append(
                (observed.payload['revision'],value['minimum_document_revision']))
    for observations in floors.values():
        minimum=0
        for _,value in sorted(observations):
            if value<minimum:wire._fail('repair_status_rollback')
            minimum=value
    graph.update(destination=dp,attempt=ap,disclosure=cp,statuses=tuple(statuses),obligations=tuple(obligations))
    return graph


def verify_mailbox_feed_history_inputs(resolved, *, expected_slot, expected_owner, expected_sender,
        expected_target, at, limit_policy, policy, budget):
    """Authenticate a complete original prefix before signing feed custody.

    Ciphertext layout and authenticated references are checked without B's
    secret key. B must still decrypt pages/cores when consuming the feed.
    """
    import memory_vault_open_repair_status as status
    from memory_vault_network_crypto import validate_jwe, NetworkCryptoError
    wire._context(policy,budget);wire.u53(at)
    key=wire.build_new_wire(expected_slot,policy,budget).value;history._slot(key,key['root_key'])
    m=resolved.manifest.value
    if m['variant']!='mailbox_feed' or m['slot_key']!=key or m['root_key']!=key['root_key']:_mismatch()
    by_ref={};wanted=set()
    for item in resolved.roles:
        identity=(item.role,item.original.ref)
        if identity in by_ref:_mismatch()
        by_ref[identity]=item.original
    def get(role,reference):
        identity=(role,wire.raw_ref(reference));value=by_ref.get(identity)
        if value is None:wire._fail('repair_original_missing')
        wanted.add(identity)
        if len(value.raw)!=value.ref.size or budget._hash(value.raw)!=value.ref.raw_sha256:wire._fail('repair_ref_mismatch')
        return value
    def event(role,reference,kind,fields):
        value=get(role,reference);signed=resource._fields(wire.parse_new_wire(value.raw,policy,budget).value,{'payload','proof'})
        p=resource._fields(signed['payload'],resource.COMMON|set(fields.split())|{'slot_key'})
        if p['schema_version']!=resource.SCHEMA or p['kind']!=kind or p['slot_key']!=key:_mismatch()
        original._verify_control_signature(p,signed['proof'],expected_target['signing_key'],budget)
        return p
    head=event('feed.head',m['feed_head_ref'],'mailbox.feed_head','checkpoint_ref count range_root_ref catalog_generation committed_at retain_until')
    checkpoint=event('feed.checkpoint',head['checkpoint_ref'],'mailbox.checkpoint','slot_binding count leaf_root frontier committed_at retain_until')
    count=wire.u53(head['count'],1)
    if (m['covered_interval']!=dict(start=0,end=count) or m['subtree']!=dict(root_ref=head['range_root_ref'],parent_path_refs=[])
            or checkpoint['count']!=count or head['committed_at']!=checkpoint['committed_at']
            or head['retain_until']!=checkpoint['retain_until'] or not wire.u53(head['committed_at'])<=at<wire.u53(head['retain_until'])):_mismatch()
    def sealed(role,reference,raw,kind,**fields):
        value=get(role,reference)
        context=dict(schema_version=resource.SCHEMA,kind=kind,slot_key=key,plaintext_sha256=budget._hash(raw),plaintext_size=len(raw),**fields)
        try:checked=validate_jwe(value.raw,context=context)
        except NetworkCryptoError:_mismatch()
        if len(checked['recipients'])!=1 or checked['recipients'][0]['header']['kid']!=expected_owner['encryption_key']['key_id']:_mismatch()
    predecessors={budget._hash(v.manifest.raw):v for v in resolved.predecessors}
    expected_members={};setups=[];deadlines=[head['retain_until']]
    for member in m['members']:
        sequence=wire.u53(member['sequence']);manifest=get('history.member',member['historical_manifest_ref'])
        child=predecessors.get(manifest.ref.raw_sha256)
        if child is None:_mismatch()
        core=event('member.core',member['admission_core_ref'],'admission.core',
            'core_id sequence message_id envelope_ref attempt_ref historical_manifest_ref data_resource_ref metadata_resource_ref accepted_at object_until enum_until')
        if (core['sequence']!=sequence or any(core[field]!=member[field] for field in ('message_id','envelope_ref','historical_manifest_ref'))
                or any(core[field]!=child.manifest.value[field] for field in ('message_id','envelope_ref','attempt_ref'))
                or not wire.u53(core['accepted_at'])<=at<wire.u53(core['enum_until'])
                or not core['accepted_at']<wire.u53(core['object_until'])<=core['enum_until']):_mismatch()
        setup=verify_mailbox_member_inputs(child,expected_slot=key,expected_owner=expected_owner,expected_sender=expected_sender,
            expected_target=expected_target,target_storage_epoch=key['writer_storage_epoch'],accepted_at=core['accepted_at'],
            limit_policy=limit_policy,policy=policy,budget=budget)
        setups.append(setup);deadlines.extend((core['enum_until'],setup['disclosure']['consent_until'],setup['disclosure']['bootstrap_return']['until']))
        for role in history._SLOT_INPUT:
            original_entry=setup['roles'][role];get(role,original_entry['ref'])
        if setup['roles']['mailbox.slot']['ref']!=m['slot_ref']:_mismatch()
        for name in ('data','metadata'):
            if core[name+'_resource_ref']!=setup['resources'][name]['active'].payload['resource']:_mismatch()
        link=event('member.link',member['admission_link_ref'],'admission.link',
            'sequence message_id envelope_ref core_ref sealed_core_ref historical_manifest_ref checkpoint_ref inclusion_path')
        if (link['core_ref']!=member['admission_core_ref'] or link['sequence']!=sequence
                or any(link[field]!=core[field] for field in ('message_id','envelope_ref','historical_manifest_ref'))):_mismatch()
        sealed('member.sealed_core',link['sealed_core_ref'],get('member.core',member['admission_core_ref']).raw,'admission.sealed_core',sequence=sequence)
        cp=event('member.checkpoint',link['checkpoint_ref'],'mailbox.checkpoint','slot_binding count leaf_root frontier committed_at retain_until')
        if (cp['count']!=sequence+1 or not core['accepted_at']<=wire.u53(cp['committed_at'])<=head['committed_at']
                or wire.u53(cp['retain_until'])<core['enum_until']):_mismatch()
        mailbox_range.verify_inclusion({name:cp[name] for name in ('slot_binding','count','leaf_root','frontier')},sequence,
            link['sealed_core_ref']['raw_sha256'],link['inclusion_path'],expected_slot=key,policy=policy,budget=budget)
        custody=event('member.custody',member['source_custody_ref'],'message.custody',
            'root_key message_id envelope_ref admission_link_ref checkpoint_ref feed_head_ref resource_refs stored_at object_until enum_until')
        if (custody['root_key']!=key['root_key'] or custody['admission_link_ref']!=member['admission_link_ref']
                or custody['checkpoint_ref']!=link['checkpoint_ref'] or custody['stored_at']!=cp['committed_at']
                or custody['resource_refs']!=dict(data=core['data_resource_ref'],metadata=core['metadata_resource_ref'])
                or any(custody[name]!=core[name] for name in ('message_id','envelope_ref','object_until','enum_until'))):_mismatch()
        old_head=event('member.head',custody['feed_head_ref'],'mailbox.feed_head','checkpoint_ref count range_root_ref catalog_generation committed_at retain_until')
        if (old_head['checkpoint_ref']!=link['checkpoint_ref'] or old_head['count']!=sequence+1
                or old_head['committed_at']!=cp['committed_at'] or old_head['retain_until']!=cp['retain_until']):_mismatch()
        expected_members[sequence]=dict(sequence=sequence,admission_link_ref=member['admission_link_ref'],sealed_core_ref=link['sealed_core_ref'])
    if len(expected_members)!=count or len(predecessors)!=count:_mismatch()
    state=mailbox_range.empty_state(key,policy=policy,budget=budget)
    def walk(reference,level,start,end):
        nonlocal state
        role='range.index' if level>=0 else 'range.repair_page';value=get(role,reference)
        p=wire.parse_new_wire(value.raw,policy,budget).value
        resource._fields(p,{'schema_version','kind','slot_key','start','end'}|({'level','children'} if level>=0 else {'entries','sealed_page_ref'}))
        if p['schema_version']!=resource.SCHEMA or p['kind']!=role or p['slot_key']!=key or wire.u53(p['start'])!=start or wire.u53(p['end'])!=end:_mismatch()
        if level>=0:
            if wire.u53(p['level'])!=level or type(p['children']) is not wire._DraftList or not 1<=len(p['children'])<=16:_mismatch()
            cursor=start;span=16**(level+1)
            for child in p['children']:
                resource._fields(child,{'start','end','ref'});stop=min(cursor+span,end)
                if wire.u53(child['start'])!=cursor or wire.u53(child['end'])!=stop or cursor>=stop:_mismatch()
                walk(child['ref'],level-1,cursor,stop);cursor=stop
            if cursor!=end:_mismatch()
        else:
            if list(p['entries'])!=[expected_members[i] for i in range(start,end)] or not 1<=end-start<=16:_mismatch()
            plain=wire.build_new_wire(dict(schema_version=resource.SCHEMA,kind='range.private_page',slot_key=key,start=start,end=end,entries=p['entries']),policy,budget).raw
            sealed('range.sealed_page',p['sealed_page_ref'],plain,'range.sealed_page',start=start,end=end)
            for item in p['entries']:state=mailbox_range.append(state,item['sealed_core_ref']['raw_sha256'],expected_slot=key,policy=policy,budget=budget)
    level=0
    while count>16**(level+2):level+=1
    walk(head['range_root_ref'],level,0,count)
    if any(state[name]!=checkpoint[name] for name in state):_mismatch()
    obligations={};allowed={}
    for setup in setups:
        for item in setup['obligations']:
            identity=(item['signer']['key_id'],item['scope_kind'],item['scope_id']);allowed[identity]=item
            if item['role'] not in ('destination','data_resource'):
                obligations[identity]=dict(item,operation_mask=2 if item['role']=='read' else 10 if item['role']=='bootstrap' else 66)
        for name in ('slot','read','maintenance','bootstrap'):
            p=setup['originals'][name].payload;deadlines.append(p['expires_at'])
            if 'windows' in p:deadlines.extend(p['windows'][field] for field in ('read_until','retain_until'))
        p=setup['resources']['metadata']['active'].payload;deadlines.extend(p['windows'][field] for field in ('read_until','retain_until'))
    covered=set();statuses=[];revisions={}
    for (role,ref),entry in by_ref.items():
        if not role.startswith('historical.status.'):continue
        p=original.parse_original_control(entry.raw,policy,budget).value['payload'];issuer=p['signing_key']['key_id']
        matches=[(identity,v) for identity,v in obligations.items() if identity[0]==issuer and role=='historical.status.'+v['role']]
        present={(v['scope_kind'],v['scope_id']) for v in p['entries']}
        matches=[(identity,v) for identity,v in matches if (v['scope_kind'],v['scope_id']) in present]
        if not matches:_mismatch()
        required=[{name:v[name] for name in ('scope_kind','scope_id','document_revision','operation_mask')}
            for identity,v in obligations.items() if identity[0]==issuer and (v['scope_kind'],v['scope_id']) in present]
        observed=status.verify_status_original(dict(raw=entry.raw,ref=ref.as_dict()),expected_root=key['root_key'],
            expected_signing_key=matches[0][1]['signer'],at=at,allowed_scopes=[dict(scope_kind=v['scope_kind'],scope_id=v['scope_id'])
                for identity,v in allowed.items() if identity[0]==issuer],required=required,policy=policy,budget=budget)
        identity=(issuer,observed.payload['revision'])
        if identity in revisions and revisions[identity]!=observed.canonical_sha256:wire._fail('repair_status_conflict')
        revisions[identity]=observed.canonical_sha256;covered.update(identity for identity,_ in matches);statuses.append(observed);wanted.add((role,ref))
    if covered!=set(obligations):wire._fail('repair_status_missing')
    floors={}
    for observed in (*statuses,*(value for setup in setups for value in setup['statuses'])):
        issuer=observed.payload['scope_key']['issuer_key_id'];revision=observed.payload['revision'];identity=(issuer,revision)
        if identity in revisions and revisions[identity]!=observed.canonical_sha256:wire._fail('repair_status_conflict')
        revisions[identity]=observed.canonical_sha256
        for value in observed.payload['entries']:
            identity=(issuer,value['scope_kind'],value['scope_id']);required=obligations.get(identity)
            if required and value['status']=='revoked' and value['operation_mask']&required['operation_mask']:wire._fail('repair_authority_revoked')
            if required and value['minimum_document_revision']>required['document_revision']:wire._fail('repair_status_revision')
            floors.setdefault(identity,[]).append((revision,value['minimum_document_revision']))
    for values in floors.values():
        minimum=0
        for _,floor in sorted(values):
            if floor<minimum:wire._fail('repair_status_rollback')
            minimum=floor
    for observed in statuses:
        issuer=observed.payload['scope_key']['issuer_key_id']
        for value in observed.payload['entries']:
            if observed.payload['revision']<max(v[0] for v in floors[(issuer,value['scope_kind'],value['scope_id'])]):wire._fail('repair_status_rollback')
    if wanted!=set(by_ref) or at>=min(deadlines):_mismatch()
    return dict(head=head,checkpoint=checkpoint,members=tuple(setups),statuses=tuple(statuses),
        obligations=tuple(obligations.values()),retain_until=min(deadlines),
        metadata_resource=setups[0]['resources']['metadata']['active'].payload['resource'])


def verify_mailbox_feed_source_event(manifest_entry, resolver, custody_entry, *, expected_slot,
        expected_owner, expected_sender, expected_target, limit_policy, policy, budget):
    """Independently verify an original local-prefix feed custody and inputs."""
    wire._context(policy,budget)
    def parse(entry):
        resource._fields(entry,{'raw','ref'});ref=wire.raw_ref(entry['ref'])
        if ref.namespace!='meta' or len(entry['raw'])!=ref.size or budget._hash(entry['raw'])!=ref.raw_sha256:wire._fail('repair_ref_mismatch')
        return wire.parse_new_wire(entry['raw'],policy,budget),ref
    parsed,ref=parse(custody_entry);signed=resource._fields(parsed.value,{'payload','proof'})
    p=resource._fields(signed['payload'],resource.COMMON|set('root_key slot_key slot_ref feed_head_ref covered_interval subtree historical_manifest_ref resource_refs stored_at read_until retain_until'.split()))
    key=wire.build_new_wire(expected_slot,policy,budget).value
    if p['schema_version']!=resource.SCHEMA or p['kind']!='feed.custody' or p['slot_key']!=key or p['root_key']!=key['root_key']:_mismatch()
    original._verify_control_signature(p,signed['proof'],expected_target['signing_key'],budget)
    at=wire.u53(p['stored_at'])
    if not at<wire.u53(p['read_until'])<=wire.u53(p['retain_until']):_mismatch()
    manifest,mref=parse(manifest_entry)
    if p['historical_manifest_ref']!=mref.as_dict():_mismatch()
    resolved=history.resolve_historical_inputs(manifest.raw,resolver,policy,budget)
    for name in ('slot_ref','feed_head_ref','covered_interval','subtree'):
        if p[name]!=resolved.manifest.value[name]:_mismatch()
    graph=verify_mailbox_feed_history_inputs(resolved,expected_slot=key,expected_owner=expected_owner,
        expected_sender=expected_sender,expected_target=expected_target,at=at,limit_policy=limit_policy,policy=policy,budget=budget)
    if (p['resource_refs']!=dict(metadata=graph['metadata_resource'],dependencies=[])
            or p['retain_until']>graph['retain_until']):_mismatch()
    return dict(manifest=resolved,graph=graph,custody=resource.AuthenticatedRepairOriginal(parsed.raw,ref,p),
        read_until=p['read_until'],retain_until=p['retain_until'])
