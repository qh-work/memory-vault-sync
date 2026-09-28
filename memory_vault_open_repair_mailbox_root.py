"""Durable original mailbox anchor activation over already committed slots.

The local root/catalog stage preserves the recipient's original authority and
the exact earlier slot chains. It is not current service permission or root
custody; those must complete before an offline recipient is told S1 is ready.
"""
import json

from memory_vault import canonical_bytes
import memory_vault_open_repair_bootstrap as bootstrap
import memory_vault_open_repair_history as history
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire
import memory_vault_open_repair_status as status
from memory_vault_open_repair_mailbox_activation import MailboxSlotActivation, _ordered, _role
from memory_vault_open_repair_state import ROW_CHARGE

FIELDS = {
    "root": "issued_at expires_at root_key authority_id original_resource_ref original_resource_offer_ref slot_ids maintainers operation_mask allowed_roles budget windows max_delegate_depth max_destinations_per_job max_concurrent_jobs revision",
    "read": "issued_at expires_at grant_id root_key reader root_authority_ref operation_mask budget windows revision",
    "catalog": "root_key revision issued_at expires_at slot_refs root_authority_ref",
    "bootstrap": bootstrap._GRANT_FIELDS,
    "activation": resource._FIELDS[4],
}
# The shared original parser takes space-delimited field lists.
FIELDS["bootstrap"] = " ".join(sorted(FIELDS["bootstrap"]))
KINDS = dict(root="mailbox.root_authority", read="mailbox.root_read_grant", catalog="mailbox.catalog",
             bootstrap="bootstrap.grant", activation="resource.activation")
UPLOAD_ROLES = frozenset(("mailbox.root_authority", "mailbox.root_read_grant", "bootstrap.grant"))


def _fail():
    wire._fail("repair_mailbox_root_mismatch")


def _check_root_authority(held, p, root_key, owner, offer, slots, budget, now, *, target, epoch, limits):
    root, read, catalog, grant, activation = (p[name] for name in FIELDS)
    owner_id = resource._dual_key(owner, budget)
    if root_key["root_kind"] != "mailbox" or root_key["owner"] != owner_id:
        _fail()
    for name in ("root", "read", "catalog", "bootstrap", "activation"):
        if p[name]["root_key"] != root_key:
            _fail()
    for value in (root, read):
        resource._budget(value["budget"])
        resource._windows(value["windows"], issued=value["issued_at"], expires=value["expires_at"])
        resource._opmask(value["operation_mask"])
    for value in (root, read, catalog, grant):
        wire.u53(value["revision"])
    original._opaque(root["authority_id"]); original._opaque(read["grant_id"])
    original._opaque(grant["grant_id"]); original._opaque(activation["activation_id"])
    _ordered(root["slot_ids"], lambda v:v, original._opaque)
    _ordered(root["maintainers"], lambda v:(v["signing_key_id"],v["encryption_key_id"]), history._dual)
    _ordered(root["allowed_roles"], lambda v:v, _role)
    if wire.u53(root["max_delegate_depth"]) != 2:
        _fail()
    wire.u53(root["max_destinations_per_job"]); wire.u53(root["max_concurrent_jobs"])
    slot_ids = sorted(item["key"]["slot_id"] for item in slots)
    slot_refs = [item["entries"]["slot"]["ref"] for item in slots]
    if (len(set(slot_ids)) != len(slot_ids) or root["slot_ids"] != slot_ids
            or catalog["slot_refs"] != slot_refs
            or read["reader"] != owner_id or read["root_authority_ref"] != held["root"]["ref"]
            or catalog["root_authority_ref"] != held["root"]["ref"]
            or root["original_resource_ref"] != offer["resource"]
            or root["original_resource_offer_ref"] != offer["ref"]
            or offer["intent"]["root_key"] != root_key or offer["intent"]["purpose"] != "anchor_catalog"
            or offer["intent"]["owner"] != owner or offer["intent"]["target"] != target):
        _fail()
    if (root["operation_mask"] & 10 != 10 or read["operation_mask"] & 2 != 2
            or read["operation_mask"] & ~root["operation_mask"]
            or any(read["budget"][k] > root["budget"][k] for k in resource._BUDGET)
            or any(read["windows"][k] > root["windows"][k] for k in resource._WINDOWS)
            or read["expires_at"] > root["expires_at"]
            or not {"bootstrap.grant", "mailbox_root_service_v1"} <= set(root["allowed_roles"])):
        _fail()
    if (grant["owner"] != owner_id or grant["subject"] != owner_id
            or grant["consumer"] != "mailbox_root" or grant["probe_profile"] != "opaque_v1"
            or grant["response_profile"] != "mailbox_root_service_v1"
            or grant["parent_authority_ref"] != held["root"]["ref"]
            or grant["caller_authority_ref"] != held["read"]["ref"]
            or grant["selector"] != dict(root_key_sha256=budget._hash(wire._canonical(root_key,budget)),
                anchor_ref=root_key["anchor_ref"],root_authority_sha256=held["root"]["ref"]["raw_sha256"],
                read_grant_sha256=held["read"]["ref"]["raw_sha256"])):
        _fail()
    _ordered(grant["upload_roles"], lambda v:v, _role)
    if not set(grant["upload_roles"]) <= UPLOAD_ROLES & set(root["allowed_roles"]):
        _fail()
    bootstrap._limits(grant["limits"])
    for name, parents in bootstrap._PARENT_CAPS.items():
        value = grant["limits"][name]
        if value > limits[name] or any(value > item["budget"][key] for item in (root,read) for key in parents):
            _fail()
    if not (offer["issued_at"] <= root["issued_at"] <= min(read["issued_at"], catalog["issued_at"])
            and max(read["issued_at"],catalog["issued_at"]) <= grant["issued_at"] <= activation["issued_at"] <= now
            and grant["expires_at"] <= min(root["expires_at"],read["expires_at"])
            and all(item["activated_at"] <= catalog["issued_at"] and item["retain_until"] > now
                    and min(item["deadlines"]) > now for item in slots)):
        _fail()
    for name in ("probe_until", "proof_until", "upload_until"):
        if not now < wire.u53(grant[name]) <= grant["expires_at"]:
            _fail()
    if any(grant[name] > parent["windows"][window] for name in ("proof_until","upload_until")
           for parent in (root,read) for window in ("read_until","retain_until")):
        _fail()
    authorities = [dict(role=KINDS[name],ref=held[name]["ref"]) for name in ("root","read","catalog")]
    for item in slots:
        authorities += [dict(role=kind,ref=item["entries"][name]["ref"]) for name,kind in (
            ("slot","mailbox.slot"),("read","mailbox.read_grant"),("maintenance","mailbox.maintenance_root"))]
    authorities.sort(key=lambda value:(value["role"],*history._ref_tuple(value["ref"])))
    if (activation["subject"] != owner or activation["target_node_key_id"] != target["signing_key"]["key_id"]
            or activation["target_storage_epoch"] != epoch
            or activation["scope"] != dict(kind="mailbox_root",root_key=root_key,
                root_authority_ref=held["root"]["ref"],catalog_ref=held["catalog"]["ref"])
            or activation["resource_offer_refs"] != [offer["ref"]]
            or activation["authority_refs"] != authorities):
        _fail()


def verify_mailbox_root_inputs(entries, anchor_resources, slot_chains, *, expected_root, expected_owner,
        expected_target, target_storage_epoch, limit_policy, at, policy, budget):
    """Verify the full detached original root/catalog/slot activation graph.

    All inputs are signed bytes, with independently supplied owner and node
    identities. This verifies historical setup, not current status or custody.
    No database, network, clock, signing identity or local state is consulted.
    """
    from memory_vault_open_repair_mailbox_activation import verify_mailbox_slot_owner_inputs, verify_mailbox_genesis
    wire._context(policy,budget)
    expected = wire.build_new_wire(dict(root=expected_root,owner=expected_owner,target=expected_target,
        epoch=target_storage_epoch,limits=limit_policy,at=at),policy,budget).value
    root,owner,target,epoch = (expected[k] for k in ("root","owner","target","epoch"))
    history._root(root);original._opaque(epoch);wire.u53(expected["at"])
    resource._dual_key(owner,budget);resource._dual_key(target,budget);bootstrap._limits(expected["limits"])
    resource._fields(entries,FIELDS);resource._fields(anchor_resources,{"allocate","offer","active"})
    if type(slot_chains) not in (list,tuple) or not 1 <= len(slot_chains) <= min(16,expected["limits"]["max_proof_items"]):
        _fail()
    def parse(value):
        resource._fields(value,{"raw","ref"})
        ref = resource._ref(wire.build_new_wire(value["ref"],policy,budget).value)
        parsed = wire.parse_new_wire(value["raw"],policy,budget)
        if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
            wire._fail("repair_ref_mismatch")
        signed = resource._fields(parsed.value,{"payload","proof"})
        return dict(raw=parsed.raw,ref=ref.as_dict()),signed
    held,payloads = {},{}
    for name in FIELDS:
        value,signed = parse(entries[name])
        p = resource._fields(signed["payload"],resource.COMMON | set(FIELDS[name].split()))
        if p["schema_version"] != resource.SCHEMA or p["kind"] != KINDS[name]:
            _fail()
        resource._lifetime(p)
        original._verify_control_signature(p,signed["proof"],owner["signing_key"],budget)
        held[name],payloads[name] = value,p
    anchor = {name:parse(value)[0] for name,value in anchor_resources.items()}
    ap = wire.parse_new_wire(anchor["active"]["raw"],policy,budget).value["payload"]
    committed_at = wire.u53(ap["activated_at"])
    if committed_at > expected["at"] or any(not p["issued_at"] <= committed_at < p["expires_at"] for p in payloads.values()):
        wire._fail("repair_resource_expired")
    slots,seen = [],set()
    for chain in slot_chains:
        resource._fields(chain,{"entries","data","metadata","genesis"})
        resource._fields(chain["genesis"],{"head","checkpoint"})
        slot_entry,slot_signed = parse(chain["entries"]["slot"])
        key = slot_signed["payload"]["slot_key"]
        history._slot(key,root)
        digest = budget._hash(wire._canonical(key,budget))
        if digest in seen:
            _fail()
        seen.add(digest)
        resources = {}
        for name in ("data","metadata"):
            resource._fields(chain[name],{"allocate","offer","active"})
            resources[name] = {k:parse(v)[0] for k,v in chain[name].items()}
        active_payloads = [wire.parse_new_wire(resources[name]["active"]["raw"],policy,budget).value["payload"] for name in ("data","metadata")]
        slot_at = wire.u53(active_payloads[0]["activated_at"])
        if active_payloads[1]["activated_at"] != slot_at or slot_at > committed_at:
            _fail()
        originals = verify_mailbox_slot_owner_inputs(chain["entries"],expected_slot=key,expected_owner=owner,
            expected_target=target,target_storage_epoch=epoch,offers={k:v["offer"] for k,v in resources.items()},
            limit_policy=expected["limits"],at=slot_at,policy=policy,budget=budget)
        slot_held = {k:dict(raw=v.raw,ref=v.ref.as_dict()) for k,v in originals.items()}
        activation = originals["activation"].payload
        deadlines = [v.payload["expires_at"] for k,v in originals.items() if k!="activation"]
        deadlines.extend(originals["bootstrap"].payload[k] for k in ("probe_until","proof_until","upload_until"))
        checked_resources = {}
        for name,purpose in (("data","mailbox_data"),("metadata","feed_metadata")):
            checked = resource.verify_mailbox_resource_inputs(dict(resources[name],activation=slot_held["activation"]),
                expected_root=root,expected_owner=owner,expected_target=target,target_storage_epoch=epoch,
                expected_purpose=purpose,expected_scope=activation["scope"],expected_authority_refs=activation["authority_refs"],
                expected_offer_refs=activation["resource_offer_refs"],at=committed_at,policy=policy,budget=budget)
            checked_resources[name] = checked
            deadlines.extend(checked["active"].payload["windows"].values())
        genesis = verify_mailbox_genesis(chain["genesis"],expected_slot=key,expected_signing_key=target["signing_key"],
            committed_at=slot_at,at=committed_at,policy=policy,budget=budget)
        slots.append(dict(key=key,slot=originals["slot"].payload,entries=slot_held,activated_at=slot_at,
            retain_until=genesis["head"].payload["retain_until"],deadlines=deadlines,genesis=genesis,originals=originals,resources=checked_resources))
    slots.sort(key=lambda item:history._ref_tuple(item["entries"]["slot"]["ref"]))
    offer = dict(wire.parse_new_wire(anchor["offer"]["raw"],policy,budget).value["payload"],ref=anchor["offer"]["ref"])
    _check_root_authority(held,payloads,root,owner,offer,slots,budget,committed_at,
        target=target,epoch=epoch,limits=expected["limits"])
    activation = payloads["activation"]
    checked_anchor = resource.verify_mailbox_resource_inputs(dict(anchor,activation=held["activation"]),
        expected_root=root,expected_owner=owner,expected_target=target,target_storage_epoch=epoch,
        expected_purpose="anchor_catalog",expected_scope=activation["scope"],expected_authority_refs=activation["authority_refs"],
        expected_offer_refs=activation["resource_offer_refs"],at=expected["at"],policy=policy,budget=budget)
    return dict(originals={k:resource.AuthenticatedRepairOriginal(v["raw"],wire.raw_ref(v["ref"]),payloads[k]) for k,v in held.items()},
        anchor=checked_anchor,slots=tuple(slots),activated_at=committed_at)


def verify_mailbox_root_history_inputs(resolved, *, expected_root, expected_owner, expected_target,
        target_storage_epoch, limit_policy, at, policy, budget):
    """Resolve typed root setup from a byte-checked historical manifest.

    This checks setup originals and their exact associations. Historical status
    and the custody event itself remain separate consumer obligations.
    """
    m = resolved.manifest.value
    if m["variant"] != "mailbox_root" or m["root_key"] != expected_root or resolved.predecessors:
        _fail()
    def matching(role_name, predicate=lambda p:True):
        matches = []
        for item in resolved.roles:
            if item.role == role_name:
                payload = wire.parse_new_wire(item.original.raw,policy,budget).value["payload"]
                if predicate(payload):
                    matches.append(dict(raw=item.original.raw,ref=item.original.ref.as_dict()))
        if len(matches) != 1:
            _fail()
        return matches[0]
    def exact(role,reference):
        value = matching(role,lambda p:True) if reference is None else None
        if value is not None:
            return value
        matches = [dict(raw=v.original.raw,ref=v.original.ref.as_dict()) for v in resolved.roles
                   if v.role==role and v.original.ref.as_dict()==reference]
        if len(matches)!=1:
            _fail()
        return matches[0]
    def resources(name,reference=None):
        active = matching("resource."+name+"_active",lambda p:reference is None or p["resource"]==reference)
        payload = wire.parse_new_wire(active["raw"],policy,budget).value["payload"]
        offer = exact("resource."+name+"_offer",payload["offer_ref"])
        offer_payload = wire.parse_new_wire(offer["raw"],policy,budget).value["payload"]
        return dict(active=active,offer=offer,allocate=exact("resource."+name+"_allocate",offer_payload["allocation_request_ref"]))
    entries = {name:matching(role) for name,role in dict(root="mailbox.root_authority",read="mailbox.root_read_grant",
        catalog="mailbox.catalog",bootstrap="bootstrap.mailbox_root",activation="resource.anchor_activation").items()}
    if m["root_authority_ref"] != entries["root"]["ref"] or m["catalog_ref"] != entries["catalog"]["ref"]:
        _fail()
    slot_chains = []
    for item in resolved.roles:
        if item.role != "mailbox.slot":
            continue
        slot = wire.parse_new_wire(item.original.raw,policy,budget).value["payload"]
        slot_ref = item.original.ref.as_dict()
        head = matching("genesis.head",lambda p:p["slot_key"]==slot["slot_key"])
        hp = wire.parse_new_wire(head["raw"],policy,budget).value["payload"]
        slot_chains.append(dict(entries=dict(slot=dict(raw=item.original.raw,ref=slot_ref),
            read=exact("mailbox.read_grant",slot["read_grant_ref"]),maintenance=exact("mailbox.maintenance_root",slot["maintenance_root_ref"]),
            bootstrap=matching("bootstrap.mailbox_feed",lambda p:p["selector"]["slot_sha256"]==slot_ref["raw_sha256"]),
            activation=matching("resource.slot_activation",lambda p:p["scope"]["slot_ref"]==slot_ref)),
            data=resources("data",slot["data_resource_ref"]),metadata=resources("metadata",slot["metadata_resource_ref"]),
            genesis=dict(head=head,checkpoint=exact("genesis.checkpoint",hp["checkpoint_ref"]))))
    heads = sorted((chain["genesis"]["head"]["ref"] for chain in slot_chains),key=history._ref_tuple)
    if m["genesis_head_refs"] != heads:
        _fail()
    return verify_mailbox_root_inputs(entries,resources("anchor"),slot_chains,expected_root=expected_root,
        expected_owner=expected_owner,expected_target=expected_target,target_storage_epoch=target_storage_epoch,
        limit_policy=limit_policy,at=at,policy=policy,budget=budget)


def verify_mailbox_root_source_event(manifest_entry, resolver, custody_entry, *, expected_root, expected_owner,
        expected_target, target_storage_epoch, limit_policy, policy, budget):
    """Authenticate a complete historical root custody independently of its node.

    Successful historical verification never grants current network access.
    Live callers must still enforce original read grants and current statuses.
    """
    wire._context(policy,budget)
    expected = wire.build_new_wire(dict(root=expected_root,owner=expected_owner,target=expected_target,
        epoch=target_storage_epoch,limits=limit_policy),policy,budget).value
    root,owner,target = (expected[k] for k in ("root","owner","target"))
    def parse(entry):
        resource._fields(entry,{"raw","ref"})
        ref = resource._ref(wire.build_new_wire(entry["ref"],policy,budget).value)
        parsed = wire.parse_new_wire(entry["raw"],policy,budget)
        if len(parsed.raw)!=ref.size or budget._hash(parsed.raw)!=ref.raw_sha256:
            wire._fail("repair_ref_mismatch")
        return parsed,ref
    custody,cref = parse(custody_entry)
    signed = resource._fields(custody.value,{"payload","proof"})
    event = resource._fields(signed["payload"],resource.COMMON | set(
        "root_key root_authority_ref catalog_ref genesis_head_refs historical_manifest_ref resource_refs stored_at read_until retain_until".split()))
    if event["schema_version"] != resource.SCHEMA or event["kind"] != "root.custody" or event["root_key"] != root:
        _fail()
    original._verify_control_signature(event,signed["proof"],target["signing_key"],budget)
    at,read_until,retain_until = (wire.u53(event[k]) for k in ("stored_at","read_until","retain_until"))
    if not at < read_until <= retain_until:
        _fail()
    manifest,mref = parse(manifest_entry)
    if event["historical_manifest_ref"] != mref.as_dict():
        _fail()
    resolved = history.resolve_historical_inputs(manifest.raw,resolver,policy,budget)
    graph = verify_mailbox_root_history_inputs(resolved,expected_root=root,expected_owner=owner,expected_target=target,
        target_storage_epoch=expected["epoch"],limit_policy=expected["limits"],at=at,policy=policy,budget=budget)
    m = resolved.manifest.value
    if any(event[k]!=m[k] for k in ("root_authority_ref","catalog_ref","genesis_head_refs")):
        _fail()
    wanted,obligations,deadlines,feeds = set(),[],[],[]
    def want(role,value):
        wanted.add((role,value.ref))
    def obligation(role,kind,subject,revision,bits,signer):
        obligations.append(dict(role=role,kind=kind,scope_id=status.status_scope(root,kind,subject,policy,budget),
            revision=revision,bits=bits,signer=signer))
    def authority(role,status_role,value,bits):
        want(role,value);p=value.payload
        obligation(status_role,"authority",dict(authority_kind=p["kind"],authority_sha256=value.ref.raw_sha256),p["revision"],bits,owner["signing_key"])
        deadlines.append(p["expires_at"])
        if "windows" in p:
            deadlines.extend(p["windows"][k] for k in ("read_until","retain_until"))
        if p["kind"]=="bootstrap.grant":
            deadlines.extend(p[k] for k in ("probe_until","proof_until","upload_until"))
    r = graph["originals"]
    for name,role,obs,bits in (("root","mailbox.root_authority","root",10),("read","mailbox.root_read_grant","root_read",2),
            ("bootstrap","bootstrap.mailbox_root","root_bootstrap",10)):
        authority(role,"historical.status."+obs,r[name],bits)
    want("mailbox.catalog",r["catalog"]);want("resource.anchor_activation",r["activation"])
    deadlines.append(r["catalog"].payload["expires_at"])
    obligation("historical.status.catalog","catalog",dict(root_key=root),r["catalog"].payload["revision"],8,owner["signing_key"])
    def resource_group(name,values):
        for field in ("allocate","offer","active"):
            want("resource."+name+"_"+field,values[field])
        p=values["active"].payload
        if read_until > p["windows"]["read_until"] or retain_until > p["windows"]["retain_until"]:
            _fail()
        obligation("historical.status."+name+"_resource","resource",p["resource"],p["reservation_generation"],66,target["signing_key"])
        return p["resource"]
    anchor_ref=resource_group("anchor",graph["anchor"])
    for slot in graph["slots"]:
        values=slot["originals"];p=values["slot"].payload
        want("mailbox.slot",values["slot"]);want("resource.slot_activation",values["activation"])
        deadlines.extend((p["expires_at"],p["windows"]["read_until"],p["windows"]["retain_until"]))
        obligation("historical.status.slot","mailbox_slot",slot["key"],p["revision"],10,owner["signing_key"])
        for name,role,obs,bits in (("read","mailbox.read_grant","read",2),("maintenance","mailbox.maintenance_root","maintenance",10),
                ("bootstrap","bootstrap.mailbox_feed","bootstrap",10)):
            authority(role,"historical.status."+obs,values[name],bits)
        feeds.append(dict(slot_key=slot["key"],**{name:resource_group(name,slot["resources"][name]) for name in ("data","metadata")}))
        for name,value in slot["genesis"].items():
            want("genesis."+name,value)
            if retain_until > value.payload["retain_until"]:
                _fail()
    if event["resource_refs"] != dict(anchor=anchor_ref,feeds=feeds) or retain_until > min(deadlines):
        _fail()
    descriptors = [v.original for v in resolved.roles if v.role=="source.descriptor"]
    if len(descriptors)!=1:
        _fail()
    descriptor = original.verify_original_control(descriptors[0].raw,expected_signing_key=target["signing_key"],
        expected_schema="memory-vault-open-control/v1",expected_kind="node",at=at,policy=policy,budget=budget)
    original._node_shape(descriptor,at,budget)
    if descriptor.payload["storage_epoch"]!=expected["epoch"]:
        _fail()
    want("source.descriptor",descriptors[0])
    statuses,revisions,observations,covered = [],{},{},set()
    for item in resolved.roles:
        if not item.role.startswith("historical.status."):
            continue
        parsed=original.parse_original_control(item.original.raw,policy,budget)
        p=resource._fields(resource._fields(parsed.value,{"payload","proof"})["payload"],status._PAYLOAD)
        signer=p["signing_key"]
        permitted=[v for v in obligations if v["signer"]==signer]
        if not permitted or type(p["entries"]) is not wire._DraftList or not 1<=len(p["entries"])<=16:
            _fail()
        present={status._scope_key(status._fields(v,status._ENTRY)) for v in p["entries"]}
        matches=[v for v in permitted if v["role"]==item.role and (v["kind"],v["scope_id"]) in present]
        if not matches:
            _fail()
        required={(v["kind"],v["scope_id"]):dict(scope_kind=v["kind"],scope_id=v["scope_id"],document_revision=v["revision"],operation_mask=v["bits"])
            for v in permitted if (v["kind"],v["scope_id"]) in present}
        checked=status.verify_status_original(dict(raw=item.original.raw,ref=item.original.ref.as_dict()),
            expected_root=root,expected_signing_key=signer,at=at,allowed_scopes=[dict(scope_kind=v["kind"],scope_id=v["scope_id"]) for v in permitted],
            required=list(required.values()),policy=policy,budget=budget)
        key=(signer["key_id"],checked.payload["revision"])
        if key in revisions and revisions[key]!=checked.canonical_sha256:
            wire._fail("repair_status_conflict")
        revisions[key]=checked.canonical_sha256
        for value in checked.payload["entries"]:
            observations.setdefault((signer["key_id"],value["scope_kind"],value["scope_id"]),[]).append(
                (checked.payload["revision"],value["minimum_document_revision"]))
        covered.update((v["role"],v["kind"],v["scope_id"]) for v in matches)
        want(item.role,item.original);statuses.append(checked)
    if covered!={(v["role"],v["kind"],v["scope_id"]) for v in obligations}:
        wire._fail("repair_status_missing")
    for values in observations.values():
        floor=0
        for _,minimum in sorted(values):
            if minimum<floor:
                wire._fail("repair_status_rollback")
            floor=minimum
    if wanted!={(v.role,v.original.ref) for v in resolved.roles}:
        _fail()
    return dict(manifest=resolved,custody=resource.AuthenticatedRepairOriginal(custody.raw,cref,event),
        setup=graph,descriptor=descriptor,statuses=tuple(statuses),obligations=tuple(obligations),stored_at=at,read_until=read_until,retain_until=retain_until)


class MailboxRootActivation:
    def __init__(self, resources):
        self.resources, self.source, self.db = resources, resources.source, resources.db
        self.slots = MailboxSlotActivation(resources)

    def initialize(self):
        self.slots.initialize()
        with self.source._transaction():
            self.db.execute('''CREATE TABLE IF NOT EXISTS open_repair_mailbox_roots(
                root_digest TEXT PRIMARY KEY,owner TEXT NOT NULL,activation_id TEXT NOT NULL,
                input_digest TEXT NOT NULL,resource_id TEXT NOT NULL UNIQUE,inputs BLOB NOT NULL,
                slots BLOB NOT NULL,active BLOB NOT NULL,active_ref BLOB NOT NULL,
                activated_at INTEGER NOT NULL,UNIQUE(owner,activation_id))''')

    def _committed_slots(self, slot_keys, root, budget):
        s = self.source
        keys = wire.build_new_wire(slot_keys, s.policy, budget).value
        if type(keys) is not wire._DraftList or not 1 <= len(keys) <= min(16, s.limits["max_proof_items"]):
            _fail()
        result, seen = [], set()
        for key in keys:
            history._slot(key, root)
            digest = budget._hash(wire._canonical(key, budget))
            if digest in seen:
                _fail()
            seen.add(digest)
            row = s._one("SELECT * FROM open_repair_mailbox_slot_activations WHERE slot_digest=?", (digest,))
            genesis = s._one("SELECT * FROM open_repair_mailbox_genesis WHERE slot_digest=?", (digest,))
            if row is None or genesis is None:
                wire._fail("repair_mailbox_slot_incomplete")
            stored = wire.parse_new_wire(bytes(row["inputs"]), s.policy, budget).value
            entries = {name: dict(raw=value["raw"].encode(), ref=value["ref"]) for name,value in stored.items()}
            parsed, _ = s._entry(entries["slot"], budget)
            if parsed.value["payload"]["slot_key"] != key:
                _fail()
            # These bytes were committed by the local slot verifier; rebind
            # every stored original to its exact ref before anchoring it.
            deadlines = []
            for name,entry in entries.items():
                checked,_ = s._entry(entry, budget)
                if name in ("maintenance","read","slot","bootstrap"):
                    deadlines.append(checked.value["payload"]["expires_at"])
                if name == "bootstrap":
                    deadlines.extend(checked.value["payload"][k] for k in ("probe_until","proof_until","upload_until"))
            for name in ("data", "metadata"):
                resource_row = s._one("SELECT status FROM open_repair_mailbox_resources WHERE resource_id=?",
                                     (row[name+"_resource_id"],))
                if resource_row is None or resource_row["status"] != "active":
                    wire._fail("repair_resource_inactive")
                entries[name+"_active"] = s._saved(row, name+"_active")
                active,_ = s._entry(entries[name+"_active"],budget)
                deadlines.extend(active.value["payload"]["windows"].values())
            for name in ("checkpoint", "head"):
                entries[name] = s._saved(genesis, name)
            result.append(dict(key=key, slot=parsed.value["payload"], entries=entries,
                               activated_at=row["activated_at"], retain_until=genesis["retain_until"],deadlines=deadlines))
        return sorted(result, key=lambda item: history._ref_tuple(item["entries"]["slot"]["ref"]))

    def _check(self, held, p, root_key, owner, offer, slots, budget, now):
        return _check_root_authority(held,p,root_key,owner,offer,slots,budget,now,
            target=self.source.target,epoch=self.source.node["payload"]["storage_epoch"],limits=self.source.limits)

    def activate(self, entries, *, expected_root, slot_keys, _budget=None, _transaction_guard=None):
        s = self.source
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
            root_key = wire.build_new_wire(expected_root,s.policy,budget).value
            history._root(root_key)
            root_digest = budget._hash(wire._canonical(root_key,budget))
            resource._fields(entries,FIELDS)
            held = {}
            for name in FIELDS:
                parsed,ref = s._entry(entries[name],budget)
                held[name] = dict(raw=parsed.raw,ref=ref.as_dict())
            slots = self._committed_slots(slot_keys,root_key,budget)
            digest = budget._hash(wire.build_new_wire(dict(root_key=root_key,
                refs={k:v["ref"] for k,v in held.items()},slots=[item["entries"]["slot"]["ref"] for item in slots]),s.policy,budget).raw)
            old = s._one("SELECT * FROM open_repair_mailbox_roots WHERE root_digest=?",(root_digest,))
            if old is not None:
                if old["input_digest"] != digest:
                    wire._fail("repair_activation_conflict")
                return s._saved(old,"active")
            root_signed = resource._fields(wire.parse_new_wire(held["root"]["raw"],s.policy,budget).value,{"payload","proof"})
            root_payload = root_signed["payload"]
            resource._fields(root_payload,resource.COMMON | set(FIELDS["root"].split()))
            history._resource(root_payload["original_resource_ref"])
            row = s._one("SELECT * FROM open_repair_mailbox_resources WHERE resource_id=?",
                         (root_payload["original_resource_ref"]["resource_id"],))
            if row is None:
                wire._fail("repair_unknown_resource")
            owner = json.loads(bytes(row["owner_keys"]))
            held,payloads = self.slots._originals(held,owner,budget,now,fields=FIELDS,kinds=KINDS)
            offered = s._saved(row,"offer")
            offer = dict(wire.parse_new_wire(offered["raw"],s.policy,budget).value["payload"],ref=offered["ref"])
            self._check(held,payloads,root_key,owner,offer,slots,budget,now)
            activation = payloads["activation"]
            if s._one("SELECT 1 FROM open_repair_mailbox_roots WHERE owner=? AND activation_id=?",
                      (row["owner"],activation["activation_id"])):
                wire._fail("repair_activation_conflict")
            if row["status"] != "pending" or now >= row["reservation_until"]:
                wire._fail("repair_resource_inactive")
            deadlines.extend([row["reservation_until"],*offer["windows"].values()])
            deadlines.extend(p["expires_at"] for p in payloads.values())
            deadlines.extend(item["retain_until"] for item in slots)
            deadlines.extend(value for item in slots for value in item["deadlines"])
            deadlines.extend(payloads["bootstrap"][k] for k in ("probe_until","proof_until","upload_until"))
            active = s._sign(dict(schema_version=resource.SCHEMA,kind="resource.active",signing_key=s.identity.public_descriptor(),
                activated_at=now,offer_ref=offered["ref"],activation_ref=held["activation"]["ref"],resource=offer["resource"],
                reservation_generation=offer["reservation_generation"],root_key=root_key,purpose="anchor_catalog",
                budget=offer["budget"],windows=offer["windows"]),"mailbox_anchor_active",budget)
            def encoded(entries):
                return {k:dict(raw=v["raw"].decode(),ref=v["ref"]) for k,v in entries.items()}
            inputs = wire.build_new_wire(encoded(held),s.policy,budget).raw
            saved_slots = wire.build_new_wire([dict(slot_key=item["key"],entries=encoded(item["entries"]))
                for item in slots],s.policy,budget).raw
            metadata = row["metadata_bytes"]+len(inputs)+len(saved_slots)+len(active["raw"])+(8+len(slots)*12)*ROW_CHARGE
            if metadata > offer["budget"]["max_meta_bytes"]:
                wire._fail("repair_insufficient_capacity")
            self.db.execute("UPDATE open_repair_mailbox_resources SET status='active',metadata_bytes=? WHERE resource_id=?",(metadata,row["resource_id"]))
            self.db.execute("INSERT INTO open_repair_mailbox_roots VALUES(?,?,?,?,?,?,?,?,?,?)",
                (root_digest,row["owner"],activation["activation_id"],digest,row["resource_id"],inputs,saved_slots,
                 active["raw"],canonical_bytes(active["ref"]),now))
            return active

    def owner_status_context(self, resource_id, *, _budget=None):
        """Derive B's finite status scopes from this committed original catalog."""
        s = self.source
        budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
        wire._context(s.policy,budget)
        with s._transaction():
            row = s._one("SELECT inputs,slots FROM open_repair_mailbox_roots WHERE resource_id=?",(resource_id,))
            if row is None:
                wire._fail("repair_unknown_resource")
            held = wire.parse_new_wire(bytes(row["inputs"]),s.policy,budget).value
            slots = wire.parse_new_wire(bytes(row["slots"]),s.policy,budget).value
            def original_entry(value):
                parsed,ref = s._entry(dict(raw=value["raw"].encode(),ref=value["ref"]),budget)
                return parsed.value["payload"],ref
            root,_ = original_entry(held["root"])
            requirements,deadlines = {},[]
            def add(kind,subject,revision,bits):
                scope_id = status.status_scope(root["root_key"],kind,subject,s.policy,budget)
                requirements[(kind,scope_id)] = dict(issuer=root["signing_key"]["key_id"],scope_kind=kind,
                    scope_id=scope_id,document_revision=revision,operation_mask=bits)
            def authority(value,bits):
                p,ref = original_entry(value)
                deadlines.append(p["expires_at"])
                if "windows" in p:
                    deadlines.extend(p["windows"][name] for name in ("read_until","retain_until"))
                if p["kind"] == "bootstrap.grant":
                    deadlines.extend(p[name] for name in ("probe_until","proof_until","upload_until"))
                add("authority",dict(authority_kind=p["kind"],authority_sha256=ref.raw_sha256),p["revision"],bits)
            authority(held["root"],10); authority(held["read"],2); authority(held["bootstrap"],10)
            catalog,_ = original_entry(held["catalog"])
            deadlines.append(catalog["expires_at"])
            add("catalog",dict(root_key=root["root_key"]),catalog["revision"],8)
            for slot in slots:
                values = slot["entries"]
                p,_ = original_entry(values["slot"])
                deadlines.append(p["expires_at"])
                deadlines.extend(p["windows"][name] for name in ("read_until","retain_until"))
                add("mailbox_slot",p["slot_key"],p["revision"],10)
                for name,bits in (("read",2),("maintenance",10),("bootstrap",10)):
                    authority(values[name],bits)
            return dict(signing_key=root["signing_key"],root_key=root["root_key"],
                        required=[requirements[key] for key in sorted(requirements)],deadline=min(deadlines))

    def observe_owner_status(self, resource_id, entry, *, _budget=None):
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        s = self.source
        budget = _budget if _budget is not None else wire.RepairBudget(s.policy)
        context = self.owner_status_context(resource_id,_budget=budget)
        # A large catalog may span multiple whole signed documents. Select only
        # their claimed scopes from the independently derived set, never project
        # the signed original or authorize an extra entry by caller assertion.
        entry = status._fields(entry,{"raw","ref"})
        reference = wire.build_new_wire(entry["ref"],s.policy,budget).value
        preview = status.original.parse_original_control(entry["raw"],s.policy,budget)
        raw = preview.raw
        payload = status._fields(status._fields(preview.value,{"payload","proof"})["payload"],status._PAYLOAD)
        if type(payload["entries"]) is not wire._DraftList or not 1 <= len(payload["entries"]) <= 16:
            wire._fail("repair_invalid_status")
        claimed = {status._scope_key(status._fields(item,status._ENTRY)) for item in payload["entries"]}
        known = {(item["scope_kind"],item["scope_id"]):item for item in context["required"]}
        if not claimed <= known.keys():
            wire._fail("repair_status_disclosure")
        allowed = [dict(scope_kind=kind,scope_id=scope_id) for kind,scope_id in sorted(claimed)]
        ledger = MailboxStatusLedger(self.resources); ledger.initialize()
        return ledger.observe(resource_id,dict(raw=raw,ref=reference),expected_signing_key=context["signing_key"],
                              allowed_scopes=allowed,_budget=budget)

    def owner_status_guard(self, resource_id, *, _budget=None):
        from memory_vault_open_repair_mailbox_status import MailboxStatusLedger
        budget = _budget if _budget is not None else wire.RepairBudget(self.source.policy)
        context = self.owner_status_context(resource_id,_budget=budget)
        ledger = MailboxStatusLedger(self.resources); ledger.initialize()
        def guard():
            if self.source._now() >= context["deadline"]:
                return "repair_resource_expired"
            return ledger.check_locked(resource_id,context["required"],_budget=budget)
        return guard
