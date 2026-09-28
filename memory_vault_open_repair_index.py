"""One original ACK source publishes to one explicitly consented directory.

Pure verification only: callers must persist authenticated observations before
denial, recheck their real resource/generation/floors, and perform dual-key
possession. No owner bootstrap or directory lease grants publication here.
"""
from dataclasses import dataclass
from types import MappingProxyType

import memory_vault_open_provider as provider
import memory_vault_open_repair_empty as empty
import memory_vault_open_repair_history as history
import memory_vault_open_repair_occupied as occupied
import memory_vault_open_repair_original as original
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_status as status
import memory_vault_open_repair_wire as wire

SCHEMA = resource.SCHEMA
PUBLISH = 16
CONSENT_FIELDS = resource.COMMON | frozenset("variant issued_at expires_at consent_id revision ack_slot root_authority_ref grant_ref binding_ref receipt_ref original_disclosure_ref original_ack_commit_ref historical_manifest_ref publisher target target_storage_epoch operation_mask reservation_disclosure post_assignment_disclosure".split())
INTENT_FIELDS = frozenset("kind allocation_id job_id root_key caller target target_storage_epoch purpose scope advertised_custody_ref provider_fact_ref historical_manifest_ref budget windows".split())
ASSIGNMENT_FIELDS = resource.COMMON | frozenset("issued_at expires_at assignment_id job_id root_key parent_root_ref parent_assignment_ref depth subject target_node_key_id target_storage_epoch operation_mask scope resource_intent_sha256 resource_offer_ref resource bootstrap_grant_refs budget windows".split())
REQUEST_FIELDS = resource.COMMON | frozenset("issued_at expires_at request_id subject target target_storage_epoch allocation_request_ref resource_offer_ref assignment_ref owner_consent_ref recipient_consent_ref provider_fact_ref source_head_ref historical_manifest_ref original_ack_commit_ref stage_result_ref source_disclosure".split())
ALLOCATE_FIELDS = resource.COMMON | frozenset(resource._FIELDS[0].split())
OFFER_FIELDS = resource.COMMON | frozenset(resource._FIELDS[1].split())


def _fail(code="repair_invalid_ack_index"):
    wire._fail(code)


def _same(condition):
    if not condition:
        _fail("repair_ack_index_mismatch")


def _signed(entry, signer, kind, fields, policy, budget, *, schema=SCHEMA):
    wire.object_fields(entry, {"raw", "ref"})
    ref = wire.raw_ref(entry["ref"])
    parsed = wire.parse_new_wire(entry["raw"], policy, budget)
    if len(parsed.raw) > provider.MAX_CONTROL_BYTES or ref.namespace != "meta":
        _fail("repair_invalid_index_control")
    if len(parsed.raw) != ref.size or budget._hash(parsed.raw) != ref.raw_sha256:
        _fail("repair_ref_mismatch")
    value = wire.object_fields(parsed.value, {"payload", "proof"})
    payload = wire.object_fields(value["payload"], fields)
    _same(payload["schema_version"] == schema and payload["kind"] == kind)
    original._verify_control_signature(payload, value["proof"], signer, budget)
    return resource.AuthenticatedRepairOriginal(parsed.raw, ref, payload)


def _timed(payload, at):
    resource._lifetime(payload)
    _same(payload["issued_at"] <= at < payload["expires_at"])


def _entry(item):
    return dict(raw=item.raw, ref=item.ref.as_dict())


def _pair(role, ref):
    return role, *history._ref_tuple(ref)


@dataclass(frozen=True, slots=True)
class IndexOriginal:
    role: str
    original: object
    issuer: str


def source_original_inventory(source, head, *, policy, budget):
    """Inventory a checked source; this helper itself grants no permission."""
    rows = {}
    def add(role, item):
        # The source verifier has already checked every Signed input. Unsigned
        # manifests/packs gain no independent permission from this inventory.
        value = wire.parse_new_wire(item.raw, policy, budget).value
        if "payload" not in value:
            return
        issuer = value["payload"]["signing_key"]["key_id"]
        rows[_pair(role, item.ref)] = IndexOriginal(role, item, issuer)
    def walk(manifest):
        for item in manifest.roles:
            add(item.role, item.original)
        for prior in manifest.predecessors:
            walk(prior)
    walk(source.manifest)
    add("ack.commit", source.commit)
    add("ack.head", head)
    return tuple(rows[key] for key in sorted(rows))


def _permissions(rows, issuer, policy, budget):
    originals, scopes = [], set()
    for row in rows:
        if row.issuer != issuer:
            continue
        originals.append(dict(role=row.role, ref=row.original.ref.as_dict()))
        payload = wire.parse_new_wire(row.original.raw, policy, budget).value["payload"]
        if payload["kind"] == "authority.status":
            scopes.update((entry["scope_kind"], entry["scope_id"]) for entry in payload["entries"])
    return originals, [dict(scope_kind=kind, scope_id=scope) for kind, scope in sorted(scopes)]


def source_disclosure_permissions(source, head, *, issuer, policy, budget):
    """Exact signing inputs for new explicit consent, not an authorization."""
    return _permissions(source_original_inventory(source, head, policy=policy, budget=budget), issuer, policy, budget)


def _disclosure(value, rows, issuer, maximum, at, policy, budget):
    wire.object_fields(value, {"originals", "status_scopes", "until"})
    originals, scopes = _permissions(rows, issuer, policy, budget)
    # Equality closes the vocabulary and repeated-generation refs. A role can
    # repeat with a different full ref; a role/ref pair cannot repeat or move.
    _same(value["originals"] == originals and value["status_scopes"] == scopes)
    _same(at < wire.u53(value["until"]) <= maximum)
    return scopes


def _authority(root, item, policy, budget):
    return status.status_scope(root, "authority", dict(authority_kind=item.payload["kind"],
        authority_sha256=item.ref.raw_sha256), policy, budget)


def _obligation(signer, kind, scope, revision, mask):
    return dict(signer=signer, scope_kind=kind, scope_id=scope,
                revision=revision, mask=mask)


def _current(entries, *, signers, allowed, obligations, root, previous, at, policy, budget):
    if not isinstance(entries, (list, tuple, wire._DraftList)) or not 1 <= len(entries) <= 16:
        _fail("repair_status_missing")
    checked, seen = [], set()
    for entry in entries:
        wire.object_fields(entry, {"raw", "ref"})
        value = original.parse_original_control(entry["raw"], policy, budget).value
        issuer = value.get("payload", {}).get("signing_key", {}).get("key_id")
        if issuer not in signers:
            _fail("repair_status_disclosure")
        item = status.authenticate_status_original(entry, expected_root=root,
            expected_signing_key=signers[issuer], at=at, allowed_scopes=allowed[issuer],
            policy=policy, budget=budget)
        if item.ref in seen:
            _fail("repair_duplicate_status")
        seen.add(item.ref)
        checked.append(item)
    code = None
    try:
        empty._history_floors((*previous, *checked), previous=previous, current=checked)
    except wire.RepairWireError as error:
        code = error.code
    for need in obligations:
        observations = [(item.payload["revision"], entry) for item in checked
            if item.payload["signing_key"]["key_id"] == need["signer"]["key_id"]
            for entry in item.payload["entries"]
            if (entry["scope_kind"], entry["scope_id"]) == (need["scope_kind"], need["scope_id"])]
        if not observations:
            code = code or "repair_status_missing"
            continue
        for _, entry in observations:
            if entry["status"] == "revoked":
                code = code or "repair_authority_revoked"
            elif entry["minimum_document_revision"] > need["revision"]:
                code = code or "repair_status_revision"
            elif entry["operation_mask"] & need["mask"] != need["mask"]:
                code = code or "repair_status_operation"
    return tuple(checked), code


@dataclass(frozen=True, slots=True)
class AuthenticatedAckIndexPlan:
    source: object
    head: object
    fact: object
    intent: object
    intent_sha256: str
    owner_consent: object
    recipient_consent: object
    originals: tuple
    statuses: tuple
    obligations: tuple
    publish_until: int
    denial_code: str | None


def verify_ack_index_plan(source_manifest_entry, resolver, source_commit_entry, source_head_entry,
        provider_fact_entry, intent, owner_consent_entry, recipient_consent_entry, *,
        expected_ack_slot, expected_owner, expected_receipt_writer, expected_message_id, expected_envelope_ref,
        expected_source, source_storage_epoch, expected_directory, directory_storage_epoch,
        current_statuses, at, limit_policy, policy, budget):
    wire._context(policy, budget)
    with budget._lock:
        at = wire.u53(at)
        expected = wire.build_new_wire(dict(owner=expected_owner, writer=expected_receipt_writer,
            source=expected_source, directory=expected_directory, directory_epoch=directory_storage_epoch), policy, budget).value
        source_id, directory_id = (resource._dual_key(expected[name], budget) for name in ("source", "directory"))
        resource._opaque(directory_storage_epoch)
        _same(source_id != directory_id)
        source = occupied.verify_ack_occupied_source_event(source_manifest_entry, resolver, source_commit_entry,
            expected_ack_slot=expected_ack_slot, expected_owner=expected["owner"], expected_receipt_writer=expected["writer"],
            expected_message_id=expected_message_id, expected_envelope_ref=expected_envelope_ref,
            expected_target=expected["source"], target_storage_epoch=source_storage_epoch,
            limit_policy=limit_policy, policy=policy, budget=budget)
        head = occupied.verify_ack_occupied_head(source_head_entry, source, expected_target=expected["source"], policy=policy, budget=budget)
        prior = source.predecessor.predecessor
        root = prior.resources.originals["root"]
        active = prior.resources.originals["active"]
        slot, root_key = root.payload["ack_slot"], root.payload["ack_slot"]["root_key"]
        _same(source_id in root.payload["maintainers"] and root.payload["operation_mask"] & PUBLISH == PUBLISH)
        _same(at < min(source.read_until, source.retain_until, active.payload["windows"]["publish_until"], root.payload["windows"]["publish_until"], root.payload["expires_at"]))
        fact = _signed(provider_fact_entry, expected["source"]["signing_key"], "provider.fact",
            provider.COMMON | provider.KINDS["provider.fact"], policy, budget, schema=provider.PROFILE)
        _timed(fact.payload, at)
        _same(len(fact.raw) <= provider.CAPS["provider.fact"]
            and fact.payload["expires_at"] - fact.payload["issued_at"] <= provider.MAX_FACT_SECONDS)
        wire.u53(fact.payload["revision"], 1)
        _same(fact.ref.namespace == "meta" and fact.payload["ref"] == root_key["anchor_ref"]
            and fact.payload["storage_epoch"] == source_storage_epoch and fact.payload["status"] == "active"
            and fact.payload["custody_id"] == "ack_" + source.commit.ref.raw_sha256)
        intent = wire.build_new_wire(intent, policy, budget).value
        wire.object_fields(intent, INTENT_FIELDS)
        scope = dict(kind="ack_occupied", ack_slot=slot, grant_ref=source.commit.payload["grant_ref"],
            binding_ref=source.commit.payload["binding_ref"], receipt_ref=source.commit.payload["receipt_ref"],
            original_ack_commit_ref=source.commit.ref.as_dict())
        _same(intent["kind"] == "resource.index_intent" and intent["purpose"] == "provider_index"
            and intent["root_key"] == root_key and intent["caller"] == expected["source"]
            and intent["target"] == expected["directory"] and intent["target_storage_epoch"] == directory_storage_epoch
            and intent["scope"] == scope and wire.raw_ref(intent["advertised_custody_ref"]) == source.commit.ref
            and wire.raw_ref(intent["provider_fact_ref"]) == fact.ref
            and intent["historical_manifest_ref"] == source.commit.payload["historical_manifest_ref"])
        for name in ("allocation_id", "job_id"):
            resource._opaque(intent[name])
        resource._budget(intent["budget"])
        resource._windows(intent["windows"], issued=at)
        _same(intent["budget"]["max_live_bytes"] == 0 and all(intent["budget"][name] <= root.payload["budget"][name] for name in resource._BUDGET)
            and all(intent["windows"][name] <= root.payload["windows"][name] for name in resource._WINDOWS))
        digest = budget._hash(wire._canonical(intent, budget))
        rows = source_original_inventory(source, head, policy=policy, budget=budget)
        until = min(source.read_until, source.retain_until, active.payload["windows"]["publish_until"],
            root.payload["windows"]["publish_until"], root.payload["expires_at"], fact.payload["expires_at"],
            source.inputs["disclosure"].payload["consent_until"], intent["windows"]["publish_until"])
        base_until = until
        consents, allowed, signers = [], {}, {}
        for variant, role, entry in (("owner", "owner", owner_consent_entry), ("receipt_writer", "writer", recipient_consent_entry)):
            signer = expected[role]["signing_key"]
            consent = _signed(entry, signer, "ack.index_consent", CONSENT_FIELDS, policy, budget)
            value = consent.payload
            _timed(value, at)
            resource._opaque(value["consent_id"])
            wire.u53(value["revision"], 1)
            _same(value["variant"] == variant and value["ack_slot"] == slot and value["publisher"] == source_id
                and value["target"] == expected["directory"] and value["target_storage_epoch"] == directory_storage_epoch
                and wire.u53(value["operation_mask"]) == PUBLISH
                and value["issued_at"] >= max(source.stored_at, fact.payload["issued_at"]))
            wanted = dict(root_authority_ref=root.ref.as_dict(), grant_ref=source.commit.payload["grant_ref"],
                binding_ref=source.commit.payload["binding_ref"], receipt_ref=source.commit.payload["receipt_ref"],
                original_disclosure_ref=source.inputs["disclosure"].ref.as_dict(), original_ack_commit_ref=source.commit.ref.as_dict(),
                historical_manifest_ref=source.commit.payload["historical_manifest_ref"])
            _same(all(value[name] == ref for name, ref in wanted.items()))
            reserved = wire.object_fields(value["reservation_disclosure"], {"intent_sha256", "until"})
            maximum = min(base_until, value["expires_at"])
            _same(reserved["intent_sha256"] == digest and at < wire.u53(reserved["until"]) <= maximum)
            scopes = _disclosure(value["post_assignment_disclosure"], rows, signer["key_id"], maximum, at, policy, budget)
            allowed[signer["key_id"]] = [*scopes, dict(scope_kind="authority", scope_id=_authority(root_key, consent, policy, budget))]
            signers[signer["key_id"]] = signer
            until = min(until, reserved["until"], value["post_assignment_disclosure"]["until"], value["expires_at"])
            consents.append(consent)
        _, source_scopes = _permissions(rows, expected["source"]["signing_key"]["key_id"], policy, budget)
        source_signer = expected["source"]["signing_key"]
        allowed[source_signer["key_id"]] = source_scopes
        signers[source_signer["key_id"]] = source_signer
        obligations = [
            _obligation(expected["owner"]["signing_key"], "authority", _authority(root_key, root, policy, budget), root.payload["revision"], PUBLISH),
            _obligation(expected["owner"]["signing_key"], "ack_slot", status.status_scope(root_key, "ack_slot", slot, policy, budget), root.payload["revision"], PUBLISH),
            _obligation(expected["writer"]["signing_key"], "authority", _authority(root_key, source.inputs["disclosure"], policy, budget), source.inputs["disclosure"].payload["revision"], 64),
            _obligation(source_signer, "resource", status.status_scope(root_key, "resource", active.payload["resource"], policy, budget), active.payload["reservation_generation"], 80)]
        obligations.extend(_obligation(expected[role]["signing_key"], "authority", _authority(root_key, consent, policy, budget), consent.payload["revision"], PUBLISH)
            for role, consent in zip(("owner", "writer"), consents))
        previous = (*prior.statuses, *source.predecessor.statuses, *source.statuses)
        checked, code = _current(current_statuses, signers=signers, allowed=allowed, obligations=obligations,
            root=root_key, previous=previous, at=at, policy=policy, budget=budget)
        until = min(until, *(item.payload["valid_until"] for item in checked))
        return AuthenticatedAckIndexPlan(source, head, fact, intent, digest, *consents, rows, checked,
            tuple(MappingProxyType(value) for value in obligations), until, code)


@dataclass(frozen=True, slots=True)
class AuthenticatedAckIndexAdmission:
    plan: AuthenticatedAckIndexPlan
    allocation: object
    offer: object
    assignment: object
    request: object
    statuses: tuple
    obligations: tuple
    publish_until: int
    denial_code: str | None


@dataclass(frozen=True, slots=True)
class AuthenticatedAckIndexAssignment:
    plan: AuthenticatedAckIndexPlan
    allocation: object
    offer: object
    assignment: object
    statuses: tuple
    obligations: tuple
    publish_until: int
    denial_code: str | None


def verify_ack_index_assignment(*args, allocation_entry, offer_entry, assignment_entry,
        directory_statuses, **kwargs):
    """Complete pre-stage authority, without any future stage/publication ref."""
    plan = verify_ack_index_plan(*args, **kwargs)
    policy, budget, at = (kwargs[name] for name in ("policy", "budget", "at"))
    with budget._lock:
        intent, source = plan.intent, plan.source
        publisher, target = intent["caller"], intent["target"]
        source_id, target_id = resource._dual_key(publisher, budget), resource._dual_key(target, budget)
        epoch, root_key = intent["target_storage_epoch"], intent["root_key"]
        allocation = _signed(allocation_entry, publisher["signing_key"], "resource.allocate", ALLOCATE_FIELDS, policy, budget)
        offer = _signed(offer_entry, target["signing_key"], "resource.offer", OFFER_FIELDS, policy, budget)
        assignment = _signed(assignment_entry, publisher["signing_key"], "maintenance.assignment", ASSIGNMENT_FIELDS, policy, budget)
        a, o, m = (item.payload for item in (allocation, offer, assignment))
        for payload in (a, m):
            _timed(payload, at)
        resource._opaque(a["request_id"])
        resource._opaque(o["offer_id"])
        resource._opaque(m["assignment_id"])
        resource._budget(o["budget"])
        resource._windows(o["windows"])
        history._resource(o["resource"])
        wire.u53(o["reservation_generation"], 1)
        _same(a["intent"] == intent and o["intent"] == intent
            and a["intent_sha256"] == o["intent_sha256"] == plan.intent_sha256
            and o["allocation_request_ref"] == allocation.ref.as_dict()
            and o["target_encryption_key"] == target["encryption_key"]
            and o["resource"]["node_key_id"] == target_id["signing_key_id"] and o["resource"]["storage_epoch"] == epoch
            and o["budget"] == intent["budget"] and o["windows"] == intent["windows"]
            and a["issued_at"] <= wire.u53(o["issued_at"]) <= m["issued_at"]
            and max(plan.owner_consent.payload["issued_at"], plan.recipient_consent.payload["issued_at"]) <= a["issued_at"]
            and m["issued_at"] < wire.u53(o["reservation_until"]))
        root = source.predecessor.predecessor.resources.originals["root"]
        _same(m["job_id"] == intent["job_id"] and m["root_key"] == root_key and m["parent_root_ref"] == root.ref.as_dict()
            and m["parent_assignment_ref"] is None and wire.u53(m["depth"]) == 2 and m["subject"] == target_id
            and wire.u53(m["operation_mask"]) == PUBLISH and m["scope"] == intent["scope"]
            and m["resource_intent_sha256"] == plan.intent_sha256 and m["resource_offer_ref"] == offer.ref.as_dict()
            and m["resource"] == o["resource"] and m["bootstrap_grant_refs"] == []
            and m["budget"] == o["budget"] and m["windows"] == o["windows"])
        for payload in (a, m):
            _same(payload["target_node_key_id"] == target_id["signing_key_id"] and payload["target_storage_epoch"] == epoch)
        maximum = min(plan.publish_until, m["expires_at"], o["windows"]["publish_until"])
        assignment_scope = status.status_scope(root_key, "assignment", dict(assignment_kind="maintenance.assignment", assignment_sha256=assignment.ref.raw_sha256), policy, budget)
        resource_scope = status.status_scope(root_key, "resource", o["resource"], policy, budget)
        obligations = (
            _obligation(publisher["signing_key"], "assignment", assignment_scope, 0, PUBLISH),
            _obligation(target["signing_key"], "resource", resource_scope, o["reservation_generation"], PUBLISH))
        checked, code = _current(directory_statuses,
            signers={publisher["signing_key"]["key_id"]:publisher["signing_key"], target["signing_key"]["key_id"]:target["signing_key"]},
            allowed={publisher["signing_key"]["key_id"]:[dict(scope_kind="assignment",scope_id=assignment_scope)],
                     target["signing_key"]["key_id"]:[dict(scope_kind="resource",scope_id=resource_scope)]},
            obligations=obligations, root=root_key, previous=(), at=at, policy=policy, budget=budget)
        # R's index assignment and R's source resource share issuer/root floors.
        try:
            empty._history_floors((*plan.statuses, *checked))
        except wire.RepairWireError as error:
            code = code or error.code
        until = min(maximum, *(item.payload["valid_until"] for item in checked))
        return AuthenticatedAckIndexAssignment(plan, allocation, offer, assignment,
            (*plan.statuses, *checked), (*plan.obligations, *(MappingProxyType(value) for value in obligations)),
            until, plan.denial_code or code)


def verify_ack_index_admission(*args, allocation_entry, offer_entry, assignment_entry,
        publication_request_entry, directory_statuses, **kwargs):
    """Reverify full plan/assignment then the existing completed-stage request."""
    checked=verify_ack_index_assignment(*args,allocation_entry=allocation_entry,offer_entry=offer_entry,
        assignment_entry=assignment_entry,directory_statuses=directory_statuses,**kwargs)
    policy,budget,at=(kwargs[name] for name in ("policy","budget","at"))
    with budget._lock:
        plan=checked.plan
        source,publisher,target=plan.source,plan.intent["caller"],plan.intent["target"]
        request=_signed(publication_request_entry,publisher["signing_key"],"ack.index_publish",REQUEST_FIELDS,policy,budget)
        r=request.payload
        _timed(r,at)
        resource._opaque(r["request_id"])
        _same(r["subject"]==resource._dual_key(publisher,budget) and r["target"]==resource._dual_key(target,budget)
            and r["target_storage_epoch"]==plan.intent["target_storage_epoch"]
            and checked.assignment.payload["issued_at"]<=r["issued_at"])
        wanted=dict(allocation_request_ref=checked.allocation.ref,resource_offer_ref=checked.offer.ref,
            assignment_ref=checked.assignment.ref,owner_consent_ref=plan.owner_consent.ref,
            recipient_consent_ref=plan.recipient_consent.ref,provider_fact_ref=plan.fact.ref,
            source_head_ref=plan.head.ref,original_ack_commit_ref=source.commit.ref)
        _same(all(r[name]==ref.as_dict() for name,ref in wanted.items())
            and r["historical_manifest_ref"]==source.commit.payload["historical_manifest_ref"])
        resource._ref(r["stage_result_ref"])
        maximum=min(checked.publish_until,r["expires_at"])
        _disclosure(r["source_disclosure"],plan.originals,publisher["signing_key"]["key_id"],maximum,at,policy,budget)
        return AuthenticatedAckIndexAdmission(plan,checked.allocation,checked.offer,checked.assignment,request,
            checked.statuses,checked.obligations,min(maximum,r["source_disclosure"]["until"]),checked.denial_code)
