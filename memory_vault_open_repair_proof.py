"""Inline ACK-owner proof manifests and subject-bound finite child requests.

A verified handle is a signed source assertion. Its children still require the
complete historical/current authority consumers; it is never a bearer token.
"""
from dataclasses import dataclass
import weakref

import memory_vault_open_repair_ack as ack
import memory_vault_open_repair_original as original
import memory_vault_open_repair_probe as probe
import memory_vault_open_repair_resource as resource
import memory_vault_open_repair_wire as wire

SCHEMA = resource.SCHEMA
MAX_RESPONSE_BYTES = 65536
MAX_CHILD_BYTES = 65536
CURRENT_ROLES = frozenset("current.status.ack_root current.status.ack_read current.status.ack_owner_bootstrap current.status.ack_slot current.status.ack_resource".split())
FIXED_ROLES = ack.ROLES | CURRENT_ROLES | {"history.ack_unbound", "ack.unbound_custody"}
SERVICE_ROLES = FIXED_ROLES | {"history.raw_pack"}
HANDLE_FIELDS = probe._COMMON | {"handle_id", "probe_ref", "challenge_ref", "answer_ref", "service_generation", "manifest_ref", "child_count"}
CHILD_FIELDS = probe._COMMON | {"request_id", "probe_ref", "handle_ref", "manifest_ref", "service_generation", "child_index", "offset", "requested_bytes"}
MANIFEST_FIELDS = frozenset("schema_version kind probe_ref subject target target_storage_epoch consumer selector bootstrap_grant_ref service_generation response_profile children".split())
_PROOFS = weakref.WeakValueDictionary()


def _fail(code="repair_invalid_proof"):
    wire._fail(code)


def _fields(value, names):
    try:
        return wire.object_fields(value, names)
    except wire.RepairWireError:
        _fail()


def _entry(raw, policy, budget):
    parsed = wire.parse_new_wire(raw, policy, budget)
    digest = budget._hash(parsed.raw)
    return parsed, wire.RawRef("meta", digest, digest, len(parsed.raw))


def _expected(subject, target, epoch, selector, grant_ref, probe_ref, challenge_ref, answer_ref, at, policy, budget):
    value = wire.build_new_wire(dict(subject=subject, target=target, epoch=epoch, selector=selector,
        grant_ref=grant_ref, probe_ref=probe_ref, challenge_ref=challenge_ref, answer_ref=answer_ref, at=at), policy, budget).value
    for name in ("grant_ref", "probe_ref", "challenge_ref", "answer_ref"):
        probe._ref(value[name])
    probe._expected(value["subject"], value["target"], value["epoch"], value["grant_ref"]["raw_sha256"],
                    value["selector"], value["at"], policy, budget)
    return value


def _manifest(value, expected, maximum_items):
    payload = _fields(value, MANIFEST_FIELDS)
    if (payload["schema_version"] != SCHEMA or payload["kind"] != "bootstrap.proof_manifest" or
            payload["consumer"] != "ack_owner" or payload["response_profile"] != "ack_owner_service_v1" or
            payload["subject"] != probe._dual(expected["subject"]) or payload["target"] != probe._dual(expected["target"]) or
            payload["target_storage_epoch"] != expected["epoch"] or payload["selector"] != expected["selector"] or
            probe._ref(payload["bootstrap_grant_ref"]) != probe._ref(expected["grant_ref"]) or
            probe._ref(payload["probe_ref"]) != probe._ref(expected["probe_ref"])):
        _fail("repair_proof_mismatch")
    wire.u53(payload["service_generation"], 1)
    children = payload["children"]
    if type(children) is not wire._DraftList or not len(FIXED_ROLES) + 1 <= len(children) <= maximum_items:
        _fail()
    counts, packs = {}, set()
    for index, item in enumerate(children):
        item = _fields(item, {"index", "role", "ref"})
        if wire.u53(item["index"]) != index or type(item["role"]) is not str or item["role"] not in SERVICE_ROLES:
            _fail()
        ref = probe._ref(item["ref"])
        counts[item["role"]] = counts.get(item["role"], 0) + 1
        if item["role"] == "history.raw_pack":
            if ref in packs or ref.key != ref.raw_sha256:
                _fail()
            packs.add(ref)
    if any(counts.get(role) != 1 for role in FIXED_ROLES) or not packs:
        _fail()
    return payload


@dataclass(frozen=True, slots=True, weakref_slot=True)
class AuthenticatedBootstrapProof:
    handle: resource.AuthenticatedRepairOriginal
    manifest: wire.DraftJson
    manifest_ref: wire.RawRef


def make_bootstrap_proof_response(signer, manifest_payload, *, probe_ref, challenge_ref, answer_ref,
                                  subject, target, at, expires_at, handle_id, policy, budget):
    """Construct a response from a locally frozen and authorized child plan."""
    wire._context(policy, budget)
    with budget._lock:
        manifest = wire.build_new_wire(manifest_payload, policy, budget)
        body = _fields(manifest.value, MANIFEST_FIELDS)
        expected = _expected(subject, target, body["target_storage_epoch"], body["selector"], body["bootstrap_grant_ref"],
                             probe_ref, challenge_ref, answer_ref, at, policy, budget)
        _manifest(body, expected, policy.max_entries)
        digest = budget._hash(manifest.raw)
        manifest_ref = wire.RawRef("meta", digest, digest, len(manifest.raw))
        payload = dict(schema_version=SCHEMA, kind="bootstrap.proof_handle", signing_key=target["signing_key"],
            issued_at=at, expires_at=expires_at, handle_id=handle_id, probe_ref=probe_ref,
            challenge_ref=challenge_ref, answer_ref=answer_ref, subject=body["subject"], target=body["target"],
            target_storage_epoch=body["target_storage_epoch"], purpose="bootstrap.service_proof", consumer="ack_owner",
            bootstrap_grant_sha256=body["bootstrap_grant_ref"]["raw_sha256"], service_generation=body["service_generation"],
            manifest_ref=manifest_ref.as_dict(), child_count=len(body["children"]))
        probe._window(payload, at)
        original._opaque(handle_id)
        handle = probe._sign(payload, signer, policy, budget)
        response = wire.build_new_wire(dict(schema_version=SCHEMA, kind="bootstrap.proof_response",
            handle_raw_base64url=probe._encode(handle.raw, budget),
            manifest_raw_base64url=probe._encode(manifest.raw, budget)), policy, budget)
        if len(response.raw) > MAX_RESPONSE_BYTES:
            _fail("repair_proof_too_large")
        return response


def verify_bootstrap_proof_response(raw, *, expected_subject, expected_target, target_storage_epoch, selector,
        bootstrap_grant_ref, probe_ref, challenge_ref, answer_ref, at, max_proof_items, max_proof_bytes, policy, budget):
    wire._context(policy, budget)
    with budget._lock:
        wire.u53(max_proof_items, 1); wire.u53(max_proof_bytes, 1)
        if wire._raw_size(raw, policy) > min(MAX_RESPONSE_BYTES, max_proof_bytes):
            _fail("repair_proof_too_large")
        expected = _expected(expected_subject, expected_target, target_storage_epoch, selector, bootstrap_grant_ref,
                             probe_ref, challenge_ref, answer_ref, at, policy, budget)
        response = wire.parse_new_wire(raw, policy, budget)
        wrapper = _fields(response.value, {"schema_version", "kind", "handle_raw_base64url", "manifest_raw_base64url"})
        if wrapper["schema_version"] != SCHEMA or wrapper["kind"] != "bootstrap.proof_response":
            _fail()
        decoded = {}
        sizes = {}
        for name in ("handle", "manifest"):
            encoded = wrapper[name + "_raw_base64url"]
            if type(encoded) is not str or not encoded or len(encoded) > MAX_RESPONSE_BYTES:
                _fail()
            sizes[name] = len(encoded)*3//4
        if len(response.raw) + sum(sizes.values()) > max_proof_bytes:
            _fail("repair_proof_too_large")
        for name, size in sizes.items():
            decoded[name] = original._decode64(wrapper[name + "_raw_base64url"], size, budget, url=True)
        handle_doc, handle_ref = _entry(decoded["handle"], policy, budget)
        signed = _fields(handle_doc.value, {"payload", "proof"})
        payload = _fields(signed["payload"], HANDLE_FIELDS)
        probe._window(payload, expected["at"])
        original._opaque(payload["handle_id"])
        if (payload["schema_version"] != SCHEMA or payload["kind"] != "bootstrap.proof_handle" or
                payload["purpose"] != "bootstrap.service_proof" or payload["consumer"] != "ack_owner" or
                payload["subject"] != probe._dual(expected["subject"]) or payload["target"] != probe._dual(expected["target"]) or
                payload["target_storage_epoch"] != expected["epoch"] or payload["bootstrap_grant_sha256"] != expected["grant_ref"]["raw_sha256"] or
                any(probe._ref(payload[name]) != probe._ref(expected[name]) for name in ("probe_ref", "challenge_ref", "answer_ref"))):
            _fail("repair_proof_mismatch")
        original._verify_control_signature(payload, signed["proof"], expected["target"]["signing_key"], budget)
        manifest, actual_manifest_ref = _entry(decoded["manifest"], policy, budget)
        manifest_ref = probe._ref(payload["manifest_ref"])
        if manifest_ref.size != actual_manifest_ref.size or manifest_ref.raw_sha256 != actual_manifest_ref.raw_sha256:
            _fail("repair_ref_mismatch")
        m = _manifest(manifest.value, expected, max_proof_items)
        if (wire.u53(payload["child_count"]) != len(m["children"]) or
                wire.u53(payload["service_generation"], 1) != m["service_generation"]):
            _fail("repair_proof_mismatch")
        result = AuthenticatedBootstrapProof(resource.AuthenticatedRepairOriginal(handle_doc.raw, handle_ref, payload), manifest, manifest_ref)
        _PROOFS[id(result)] = result
        return result


def make_bootstrap_child_request(signer, proof, *, subject, target, at, expires_at, child_index, offset,
                                  requested_bytes, policy, budget):
    """Sign a finite subject request; a server still rechecks its live handle."""
    wire._context(policy, budget)
    with budget._lock:
        if _PROOFS.get(id(proof)) is not proof:
            _fail("repair_invalid_proof")
        handle = proof.handle
        expected = wire.build_new_wire(dict(subject=subject, target=target), policy, budget).value
        if (probe._dual(expected["subject"]) != handle.payload["subject"] or
                probe._dual(expected["target"]) != handle.payload["target"]):
            _fail("repair_proof_mismatch")
        payload = dict(schema_version=SCHEMA, kind="bootstrap.proof_child_request", signing_key=subject["signing_key"],
            issued_at=at, expires_at=expires_at, request_id=probe._fresh_id("child", budget),
            subject=probe._dual(subject), target=probe._dual(target), target_storage_epoch=handle.payload["target_storage_epoch"],
            purpose="bootstrap.service_proof_child", consumer="ack_owner", probe_ref=handle.payload["probe_ref"],
            handle_ref=handle.ref.as_dict(), manifest_ref=proof.manifest_ref.as_dict(),
            service_generation=handle.payload["service_generation"], child_index=child_index, offset=offset, requested_bytes=requested_bytes)
        # The child profile intentionally has no bootstrap_grant_sha256; it
        # binds the complete frozen handle, which already names that grant.
        probe._window(payload, at)
        _child_range(payload, proof.manifest.value["children"])
        if expires_at > handle.payload["expires_at"]:
            _fail("repair_proof_mismatch")
        return probe._sign(payload, signer, policy, budget)


def _child_range(payload, children):
    index, offset = wire.u53(payload["child_index"]), wire.u53(payload["offset"])
    size = wire.u53(payload["requested_bytes"], 1)
    if index >= len(children) or size > MAX_CHILD_BYTES or offset + size > children[index]["ref"]["size"]:
        _fail("repair_invalid_range")


def verify_bootstrap_child_request(entry, proof, *, expected_subject, expected_target, at, policy, budget):
    wire._context(policy, budget)
    with budget._lock:
        if _PROOFS.get(id(proof)) is not proof:
            _fail("repair_invalid_proof")
        expected = wire.build_new_wire(dict(subject=expected_subject, target=expected_target), policy, budget).value
        expected_subject, expected_target = expected["subject"], expected["target"]
        if (probe._dual(expected_subject) != proof.handle.payload["subject"] or
                probe._dual(expected_target) != proof.handle.payload["target"]):
            _fail("repair_proof_mismatch")
        body, reference = ack._entry(entry)
        if wire._raw_size(body, policy) > MAX_RESPONSE_BYTES:
            _fail("repair_proof_too_large")
        parsed = wire.parse_new_wire(body, policy, budget)
        if len(parsed.raw) != reference.size or budget._hash(parsed.raw) != reference.raw_sha256:
            _fail("repair_ref_mismatch")
        signed = _fields(parsed.value, {"payload", "proof"})
        fields = CHILD_FIELDS - {"bootstrap_grant_sha256"}
        payload = _fields(signed["payload"], fields)
        probe._window(payload, at)
        original._opaque(payload["request_id"])
        handle = proof.handle
        if (payload["schema_version"] != SCHEMA or payload["kind"] != "bootstrap.proof_child_request" or
                payload["purpose"] != "bootstrap.service_proof_child" or payload["consumer"] != "ack_owner" or
                payload["subject"] != probe._dual(expected_subject) or payload["target"] != probe._dual(expected_target) or
                payload["target_storage_epoch"] != handle.payload["target_storage_epoch"] or
                probe._ref(payload["handle_ref"]) != handle.ref or probe._ref(payload["manifest_ref"]) != proof.manifest_ref or
                probe._ref(payload["probe_ref"]) != probe._ref(handle.payload["probe_ref"]) or
                payload["service_generation"] != handle.payload["service_generation"] or
                payload["issued_at"] < handle.payload["issued_at"] or payload["expires_at"] > handle.payload["expires_at"]):
            _fail("repair_proof_mismatch")
        _child_range(payload, proof.manifest.value["children"])
        original._verify_control_signature(payload, signed["proof"], expected_subject["signing_key"], budget)
        return resource.AuthenticatedRepairOriginal(parsed.raw, reference, payload)
