"""Opaque provider observations and explicit, finite node-local resources.

A provider fact is a public availability assertion, never a read capability or
proof that a recipient saved a message. This module does not open a Vault.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from typing import Any

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_control import _sign, _verify, _window
from memory_vault_network_crypto import (
    PublicKeyTrust, b64url, decrypt_bytes, digest, document, document_sha256,
    encrypt_bytes, encryption_public_descriptor, integer, object_fields, opaque,
    public_signing_key, unb64url, validate_jwe,
)
from memory_vault_open_control import verify_node

PROFILE = "memory-vault-open-provider/v1"
MAX_CONTROL_BYTES = 65536
MAX_SECONDS = 604800
MAX_FACT_SECONDS = 600
MAX_STATUS_BYTES = 16384
PUBLISH = 16
OPERATIONS = {"admit": 1, "read": 2, "copy": 4, "discover": 8,
              "publish": PUBLISH, "renew": 32, "retain": 64}
ALL_OPERATIONS = sum(OPERATIONS.values())
BUDGET_LIMITS = {"max_live_bytes": 64 * 1024 * 1024, "max_meta_bytes": 64 * 1024 * 1024,
                 "max_items": 1024, "max_requests": 4096, "max_pending": 128,
                 "max_replay_records": 4096, "max_jobs": 1024, "max_job_bytes": 4 * 1024 * 1024}
WINDOWS = {"admit_until", "read_until", "copy_until", "publish_until", "retain_until"}
COMMON = {"schema_version", "kind", "signing_key", "issued_at", "expires_at"}
KINDS = {
    "provider.fact": {"ref", "storage_epoch", "custody_id", "revision", "status"},
    "provider.target": {"node_key_id", "storage_epoch", "targetEncryptionKey"},
    "provider.target.challenge": {"challenge_id", "target_sha256", "node_key_id", "storage_epoch", "jwe"},
    "provider.target.answer": {"challenge_sha256", "target_sha256", "requester_key_id", "node_key_id", "storage_epoch", "answer"},
    "root.resource.intent": {"allocation_id", "root_key", "subject", "node_key_id", "storage_epoch", "purpose", "budget", "windows"},
    "root.resource.lease": {"allocation_id", "intent_sha256", "root_key", "subject", "resource", "targetEncryptionKey", "reservation_generation", "purpose", "budget", "windows"},
    "provider.publication.grant": {"root_key", "resource", "resource_lease_sha256", "publisher", "ref", "grant_id", "revision", "operation_mask", "maximum_fact_seconds"},
    "provider.index_lease": {"node_key_id", "storage_epoch", "index_lease_id", "fact_sha256", "ref", "provider_key_id", "provider_storage_epoch", "custody_id"},
    "provider.rpc": {"request_id", "node_key_id", "storage_epoch", "action", "body"},
    "provider.response": {"request_id", "request_sha256", "node_key_id", "storage_epoch", "body"},
}
ACTIONS = {
    "target.get": set(), "target.answer": {"target", "challenge"},
    "resource.allocate": {"intent"}, "resource.revoke": {"lease_id"},
    "provider.put": {"fact", "provider_node", "publication_grant", "resource_lease", "owner_status", "allocation_id", "lease_seconds"},
    "provider.get": {"ref", "after", "limit", "maximum_bytes"},
    "provider.withdraw": {"fact"}, "provider.status": {"status"},
    "provider.result": {"allocation_id", "operation"},
}
CAPS = {"provider.fact": 2048, "provider.index_lease": 2048,
        "provider.target": 4096, "provider.target.challenge": 8192,
        "provider.target.answer": 4096, "root.resource.intent": 8192,
        "root.resource.lease": 8192, "provider.publication.grant": 8192}


class ProviderError(MemoryError):
    pass


def fail(code):
    raise ProviderError(code)


def now_value(now=None):
    return int(time.time()) if now is None else integer(now)


def fields(value, expected):
    return object_fields(value, expected, "provider_invalid_document")


def choice(value, values):
    if not isinstance(value, str) or value not in values:
        fail("provider_invalid_enum")
    return value


def key_id(value, prefix="ed25519"):
    if not isinstance(value, str) or re.fullmatch(prefix + r"_[0-9a-f]{64}", value) is None:
        fail("provider_invalid_key")
    return value


def bounded(value, maximum, minimum=1):
    if integer(value, minimum=minimum) > maximum:
        fail("provider_invalid_limit")
    return value


def dual_id(value):
    raw = fields(value, {"signing_key_id", "encryption_key_id"})
    key_id(raw["signing_key_id"]); key_id(raw["encryption_key_id"], "x25519")
    return raw


def dual_key(value):
    raw = fields(value, {"signing_key", "encryption_key"})
    public_signing_key(raw["signing_key"]); encryption_public_descriptor(raw["encryption_key"])
    return raw


def as_dual(value):
    raw = dual_key(value)
    return {"signing_key_id": raw["signing_key"]["key_id"], "encryption_key_id": raw["encryption_key"]["key_id"]}


def opaque_ref(value, namespaces=("anchor", "feed", "meta", "object")):
    raw = fields(value, {"namespace", "key"})
    choice(raw["namespace"], namespaces); digest(raw["key"])
    return raw


def root_key(value):
    raw = fields(value, {"owner", "root_kind", "anchor_ref", "owner_epoch", "root_id"})
    dual_id(raw["owner"]); choice(raw["root_kind"], {"mailbox", "ack_return"})
    opaque_ref(raw["anchor_ref"], {"anchor"}); opaque(raw["owner_epoch"]); opaque(raw["root_id"])
    return raw


def resource_ref(value):
    raw = fields(value, {"node_key_id", "storage_epoch", "lease_id", "resource_id"})
    key_id(raw["node_key_id"])
    for name in ("storage_epoch", "lease_id", "resource_id"):
        opaque(raw[name])
    return raw


def route_target(ref):
    raw = opaque_ref(ref)
    return hashlib.sha256(b"memory-vault-open-provider-key/v1\0" + raw["namespace"].encode("ascii") + b"\0" + bytes.fromhex(raw["key"])).hexdigest()


def authority_scope(root, authority_kind, authority_sha256):
    root_key(root); choice(authority_kind, {"provider.publication.grant", "mailbox.slot", "mailbox.read_grant", "maintenance.root", "root.authority", "root.read_grant", "ack.slot.grant", "ack.read.grant", "ack.maintenance.root", "message.disclosure", "contact.grant", "delivery.destination"})
    digest(authority_sha256)
    return document_sha256({"kind": "authority", "root_key": root, "authority_kind": authority_kind, "authority_sha256": authority_sha256})


def resource_scope(root, resource):
    root_key(root); resource_ref(resource)
    return document_sha256({"kind": "resource", "root_key": root, "resource": resource})


def _budget(raw):
    budget = fields(raw["budget"], set(BUDGET_LIMITS))
    for name, ceiling in BUDGET_LIMITS.items():
        bounded(budget[name], ceiling, 0)
    if not budget["max_meta_bytes"] or not budget["max_items"] or not budget["max_requests"] or not budget["max_replay_records"]:
        fail("provider_invalid_budget")
    choice(raw["purpose"], {"anchor_catalog", "feed_metadata", "ack_slot", "provider_index"})
    if raw["purpose"] in {"anchor_catalog", "feed_metadata", "provider_index"} and budget["max_live_bytes"] != 0:
        fail("provider_invalid_budget")
    if raw["purpose"] == "ack_slot" and raw["root_key"]["root_kind"] != "ack_return":
        fail("provider_wrong_root")
    windows = fields(raw["windows"], WINDOWS)
    for value in windows.values():
        integer(value)
        if not raw["issued_at"] < value <= raw["expires_at"]:
            fail("provider_invalid_window")
    if any(value > windows["retain_until"] for value in windows.values()):
        fail("provider_invalid_window")


def verify_status(value, *, now=None, allow_expired=False):
    signed = fields(document(value, maximum=MAX_STATUS_BYTES), {"payload", "proof"})
    raw = fields(signed["payload"], {"schema_version", "kind", "signing_key", "scope_key", "revision", "issued_at", "valid_until", "entries"})
    if raw["schema_version"] != "memory-vault-open-authority/v1" or raw["kind"] != "authority.status":
        fail("provider_invalid_status")
    signing = public_signing_key(raw["signing_key"])
    scope = fields(raw["scope_key"], {"root_key", "issuer_key_id"})
    root_key(scope["root_key"])
    if scope["issuer_key_id"] != signing["key_id"]:
        fail("provider_wrong_issuer")
    integer(raw["revision"], minimum=1)
    _window({"issued_at": raw["issued_at"], "expires_at": raw["valid_until"]}, maximum=MAX_SECONDS, now=now, allow_expired=allow_expired)
    entries = raw["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        fail("provider_invalid_status")
    keys = []
    for entry in entries:
        item = fields(entry, {"scope_kind", "scope_id", "minimum_document_revision", "status", "operation_mask"})
        choice(item["scope_kind"], {"catalog", "mailbox_slot", "ack_slot", "authority", "resource", "assignment", "contact_policy"})
        digest(item["scope_id"]); integer(item["minimum_document_revision"])
        choice(item["status"], {"active", "revoked"}); bounded(item["operation_mask"], ALL_OPERATIONS)
        keys.append((item["scope_kind"], item["scope_id"]))
    if keys != sorted(set(keys)):
        fail("provider_invalid_status")
    _verify(signed, PublicKeyTrust([signing]))
    return raw


def issue_status(signer, *, root, revision, entries, issued_at, valid_until):
    raw = {"schema_version": "memory-vault-open-authority/v1", "kind": "authority.status", "signing_key": signer.public_descriptor(),
           "scope_key": {"root_key": root, "issuer_key_id": signer.key_id}, "revision": revision,
           "issued_at": issued_at, "valid_until": valid_until, "entries": entries}
    result = _sign(raw, signer)
    verify_status(result, now=issued_at)
    return result


def verify_document(value, kind, *, now=None, allow_expired=False):
    choice(kind, KINDS)
    signed = fields(document(value, maximum=CAPS.get(kind, MAX_CONTROL_BYTES)), {"payload", "proof"})
    raw = fields(signed["payload"], COMMON | KINDS[kind])
    if raw["schema_version"] != PROFILE or raw["kind"] != kind:
        fail("provider_unsupported_document")
    public_signing_key(raw["signing_key"])
    maximum = MAX_FACT_SECONDS if kind in {"provider.fact", "provider.index_lease", "provider.target"} else MAX_SECONDS
    if kind in {"provider.rpc", "provider.response", "provider.target.challenge", "provider.target.answer"}:
        maximum = 60
    _window(raw, maximum=maximum, now=now, allow_expired=allow_expired)
    if kind == "provider.fact":
        opaque_ref(raw["ref"]); opaque(raw["storage_epoch"]); opaque(raw["custody_id"])
        integer(raw["revision"], minimum=1); choice(raw["status"], {"active", "withdrawn"})
    elif kind == "provider.target":
        key_id(raw["node_key_id"]); opaque(raw["storage_epoch"]); encryption_public_descriptor(raw["targetEncryptionKey"])
        if raw["node_key_id"] != raw["signing_key"]["key_id"]:
            fail("provider_wrong_node")
    elif kind.startswith("provider.target."):
        key_id(raw["node_key_id"]); opaque(raw["storage_epoch"]); digest(raw["target_sha256"])
        if kind.endswith("challenge"):
            opaque(raw["challenge_id"])
            validate_jwe(raw["jwe"], context={k: v for k, v in raw.items() if k != "jwe"})
        else:
            digest(raw["challenge_sha256"]); key_id(raw["requester_key_id"]); unb64url(raw["answer"], maximum=32, size=32)
            if raw["node_key_id"] != raw["signing_key"]["key_id"]:
                fail("provider_wrong_node")
    elif kind in {"root.resource.intent", "root.resource.lease"}:
        root_key(raw["root_key"]); opaque(raw["allocation_id"]); _budget(raw)
        if kind.endswith("intent"):
            dual_key(raw["subject"]); key_id(raw["node_key_id"]); opaque(raw["storage_epoch"])
            if as_dual(raw["subject"]) != raw["root_key"]["owner"] or raw["subject"]["signing_key"] != raw["signing_key"]:
                fail("provider_wrong_owner")
        else:
            dual_id(raw["subject"]); resource_ref(raw["resource"]); digest(raw["intent_sha256"])
            encryption_public_descriptor(raw["targetEncryptionKey"]); integer(raw["reservation_generation"], minimum=1)
            if raw["resource"]["node_key_id"] != raw["signing_key"]["key_id"] or raw["subject"] != raw["root_key"]["owner"]:
                fail("provider_wrong_owner")
    elif kind == "provider.publication.grant":
        root_key(raw["root_key"]); resource_ref(raw["resource"]); dual_id(raw["publisher"]); opaque_ref(raw["ref"])
        digest(raw["resource_lease_sha256"]); opaque(raw["grant_id"]); integer(raw["revision"], minimum=1)
        if raw["operation_mask"] != PUBLISH or type(raw["operation_mask"]) is not int:
            fail("provider_wrong_operation")
        bounded(raw["maximum_fact_seconds"], MAX_FACT_SECONDS)
        if raw["signing_key"]["key_id"] != raw["root_key"]["owner"]["signing_key_id"]:
            fail("provider_wrong_owner")
    elif kind == "provider.index_lease":
        for name in ("node_key_id", "provider_key_id"):
            key_id(raw[name])
        for name in ("storage_epoch", "provider_storage_epoch", "index_lease_id", "custody_id"):
            opaque(raw[name])
        digest(raw["fact_sha256"]); opaque_ref(raw["ref"])
        if raw["node_key_id"] != raw["signing_key"]["key_id"]:
            fail("provider_wrong_node")
    elif kind in {"provider.rpc", "provider.response"}:
        opaque(raw["request_id"]); key_id(raw["node_key_id"]); opaque(raw["storage_epoch"])
        if kind.endswith("rpc"):
            _body(raw["action"], raw["body"], now)
        else:
            digest(raw["request_sha256"])
            if not isinstance(raw["body"], dict):
                fail("provider_invalid_document")
    _verify(signed, PublicKeyTrust([raw["signing_key"]]))
    return raw


def sign_document(signer, kind, *, issued_at, expires_at, **values):
    raw = {"schema_version": PROFILE, "kind": kind, "signing_key": signer.public_descriptor(),
           "issued_at": issued_at, "expires_at": expires_at, **values}
    result = _sign(raw, signer)
    verify_document(result, kind, now=issued_at)
    return result


def _body(action, value, now):
    choice(action, ACTIONS); raw = fields(value, ACTIONS[action])
    if action == "target.answer":
        verify_document(raw["target"], "provider.target", now=now)
        verify_document(raw["challenge"], "provider.target.challenge", now=now)
    elif action == "resource.allocate":
        verify_document(raw["intent"], "root.resource.intent", now=now)
    elif action == "resource.revoke":
        opaque(raw["lease_id"])
    elif action == "provider.put":
        for field, kind in (("fact", "provider.fact"), ("publication_grant", "provider.publication.grant"), ("resource_lease", "root.resource.lease")):
            verify_document(raw[field], kind, now=now)
        verify_node(raw["provider_node"], now=now); verify_status(raw["owner_status"], now=now)
        opaque(raw["allocation_id"]); bounded(raw["lease_seconds"], MAX_FACT_SECONDS)
    elif action == "provider.get":
        opaque_ref(raw["ref"]); bounded(raw["limit"], 4); bounded(raw["maximum_bytes"], 49152, 4096)
        if raw["after"] is not None:
            digest(raw["after"])
    elif action == "provider.withdraw":
        if verify_document(raw["fact"], "provider.fact", now=now)["status"] != "withdrawn":
            fail("provider_wrong_operation")
    elif action == "provider.status":
        verify_status(raw["status"], now=now)
    elif action == "provider.result":
        opaque(raw["allocation_id"]); choice(raw["operation"], {"resource.allocate", "provider.put"})
    return raw


def node_binding(raw, node, now=None):
    target = verify_node(node, now=now)
    if target["status"] != "active" or raw["node_key_id"] != target["signing_key"]["key_id"] or raw["storage_epoch"] != target["storage_epoch"]:
        fail("provider_wrong_node")
    return target


def sign_rpc(signer, *, node, action, body, now=None, request_id=None):
    current = now_value(now); target = verify_node(node, now=current)
    return sign_document(signer, "provider.rpc", issued_at=current, expires_at=current + 60,
        request_id=request_id or "rpc_" + secrets.token_hex(32), node_key_id=target["signing_key"]["key_id"],
        storage_epoch=target["storage_epoch"], action=action, body=body)


def verify_rpc(value, *, node, now=None):
    raw = verify_document(value, "provider.rpc", now=now); node_binding(raw, node, now)
    return raw


def sign_response(signer, *, request, node, body, now=None):
    current = now_value(now); original = verify_rpc(request, node=node, now=current)
    if signer.public_descriptor() != node["payload"]["signing_key"]:
        fail("provider_wrong_node")
    _response_body(body, request=document(request), node=node, now=current)
    return sign_document(signer, "provider.response", issued_at=current, expires_at=min(current + 60, original["expires_at"]),
        request_id=original["request_id"], request_sha256=document_sha256(request), node_key_id=original["node_key_id"],
        storage_epoch=original["storage_epoch"], body=body)


def verify_response(value, *, request, node, now=None):
    raw = verify_document(value, "provider.response", now=now); original = verify_rpc(request, node=node, now=now)
    target = node_binding(raw, node, now)
    if raw["signing_key"] != target["signing_key"] or raw["request_id"] != original["request_id"] or raw["request_sha256"] != document_sha256(request) or raw["expires_at"] > original["expires_at"]:
        fail("provider_response_mismatch")
    _response_body(raw["body"], request=document(request), node=node, now=now)
    if original["action"] == "provider.get" and len(canonical_bytes(document(value))) > original["body"]["maximum_bytes"]:
        fail("provider_response_budget")
    return raw


def issue_fact(signer, *, ref, storage_epoch, custody_id, revision, issued_at, expires_at, status="active"):
    return sign_document(signer, "provider.fact", ref=ref, storage_epoch=storage_epoch, custody_id=custody_id,
                         revision=revision, status=status, issued_at=issued_at, expires_at=expires_at)


def make_target_challenge(signer, *, target, node, now=None):
    """Run before sending private grants; retain the returned nonce locally."""
    current = now_value(now); raw = verify_document(target, "provider.target", now=current)
    expected = node_binding(raw, node, current)
    if raw["signing_key"] != expected["signing_key"]:
        fail("provider_wrong_node")
    context = {"schema_version": PROFILE, "kind": "provider.target.challenge", "signing_key": signer.public_descriptor(),
               "issued_at": current, "expires_at": min(current + 60, raw["expires_at"]), "challenge_id": "challenge_" + secrets.token_hex(32),
               "target_sha256": document_sha256(target), "node_key_id": raw["node_key_id"], "storage_epoch": raw["storage_epoch"]}
    nonce = secrets.token_bytes(32)
    challenge = _sign({**context, "jwe": encrypt_bytes(nonce, [raw["targetEncryptionKey"]], context=context)}, signer)
    verify_document(challenge, "provider.target.challenge", now=current)
    return challenge, nonce


def answer_target_challenge(signer, encryption_identity, *, target, challenge, node, now=None):
    current = now_value(now); descriptor = verify_document(target, "provider.target", now=current)
    original = verify_document(challenge, "provider.target.challenge", now=current)
    node_binding(descriptor, node, current); node_binding(original, node, current)
    if descriptor["signing_key"] != signer.public_descriptor() or descriptor["targetEncryptionKey"] != encryption_identity.public_descriptor() or original["target_sha256"] != document_sha256(target):
        fail("provider_target_mismatch")
    recipients = original["jwe"]["recipients"]
    if len(recipients) != 1 or recipients[0]["header"]["kid"] != descriptor["targetEncryptionKey"]["key_id"]:
        fail("provider_target_mismatch")
    nonce = decrypt_bytes(original["jwe"], encryption_identity, context={k: v for k, v in original.items() if k != "jwe"})
    if len(nonce) != 32:
        fail("provider_invalid_challenge")
    return sign_document(signer, "provider.target.answer", issued_at=current, expires_at=min(current + 60, original["expires_at"]),
        challenge_sha256=document_sha256(challenge), target_sha256=document_sha256(target), requester_key_id=original["signing_key"]["key_id"],
        node_key_id=descriptor["node_key_id"], storage_epoch=descriptor["storage_epoch"], answer=b64url(nonce))


def verify_target_answer(answer, *, target, challenge, nonce, node, now=None):
    raw = verify_document(answer, "provider.target.answer", now=now)
    descriptor = verify_document(target, "provider.target", now=now)
    original = verify_document(challenge, "provider.target.challenge", now=now)
    expected = node_binding(raw, node, now); node_binding(descriptor, node, now); node_binding(original, node, now)
    if (raw["signing_key"] != expected["signing_key"] or descriptor["signing_key"] != expected["signing_key"]
            or raw["target_sha256"] != document_sha256(target) or original["target_sha256"] != document_sha256(target)
            or raw["challenge_sha256"] != document_sha256(challenge) or raw["requester_key_id"] != original["signing_key"]["key_id"]
            or raw["expires_at"] > original["expires_at"] or not isinstance(nonce, bytes) or len(nonce) != 32
            or not hmac.compare_digest(unb64url(raw["answer"], maximum=32, size=32), nonce)):
        fail("provider_invalid_target_proof")
    return descriptor


def verify_resource_lease(value, *, intent=None, node=None, target=None, now=None, allow_expired=False):
    raw = verify_document(value, "root.resource.lease", now=now, allow_expired=allow_expired)
    if node is not None:
        expected = verify_node(node, now=now)
        if raw["signing_key"] != expected["signing_key"] or raw["resource"]["storage_epoch"] != expected["storage_epoch"]:
            fail("provider_wrong_resource")
    if target is not None:
        proven = verify_document(target, "provider.target", now=now)
        if (raw["signing_key"] != proven["signing_key"] or raw["resource"]["storage_epoch"] != proven["storage_epoch"]
                or raw["targetEncryptionKey"] != proven["targetEncryptionKey"]):
            fail("provider_target_mismatch")
    if intent is not None:
        wanted = verify_document(intent, "root.resource.intent", now=now, allow_expired=allow_expired)
        if (raw["intent_sha256"] != document_sha256(intent) or raw["subject"] != as_dual(wanted["subject"])
                or raw["resource"]["node_key_id"] != wanted["node_key_id"] or raw["resource"]["storage_epoch"] != wanted["storage_epoch"]
                or raw["expires_at"] != wanted["expires_at"] or raw["issued_at"] < wanted["issued_at"]
                or any(raw[k] != wanted[k] for k in ("allocation_id", "root_key", "purpose", "budget", "windows"))):
            fail("provider_lease_mismatch")
    return raw


def verify_index_lease(value, *, fact, node, now=None, allow_expired=False):
    raw = verify_document(value, "provider.index_lease", now=now, allow_expired=allow_expired)
    advertisement = verify_document(fact, "provider.fact", now=now, allow_expired=allow_expired)
    expected = node_binding(raw, node, now)
    if (raw["signing_key"] != expected["signing_key"] or raw["fact_sha256"] != document_sha256(fact)
            or raw["ref"] != advertisement["ref"] or raw["provider_key_id"] != advertisement["signing_key"]["key_id"]
            or raw["provider_storage_epoch"] != advertisement["storage_epoch"] or raw["custody_id"] != advertisement["custody_id"]
            or raw["expires_at"] > advertisement["expires_at"]):
        fail("provider_index_lease_mismatch")
    return raw


def _response_body(body, *, request, node, now):
    original = request["payload"]; action = original["action"]; wanted = original["body"]
    if isinstance(body, dict) and set(body) == {"error"}:
        error = fields(body["error"], {"code", "retryable"})
        if not isinstance(error["code"], str) or re.fullmatch(r"[a-z][a-z0-9_]{1,63}", error["code"]) is None or type(error["retryable"]) is not bool:
            fail("provider_invalid_response")
        return
    if action == "provider.get":
        raw = fields(body, {"ref", "observed_at", "entries", "nodes", "next_cursor", "state"})
        if raw["ref"] != wanted["ref"] or not isinstance(raw["entries"], list) or len(raw["entries"]) > wanted["limit"] or not isinstance(raw["nodes"], list) or len(raw["nodes"]) > 4:
            fail("provider_invalid_response")
        integer(raw["observed_at"])
        choice(raw["state"], {"observed", "not_observed"})
        if (raw["state"] == "observed") != bool(raw["entries"]):
            fail("provider_invalid_response")
        if raw["next_cursor"] is not None:
            digest(raw["next_cursor"])
        nodes = {}
        for record in raw["nodes"]:
            candidate = verify_node(record, now=now)
            key = (candidate["signing_key"]["key_id"], candidate["storage_epoch"])
            if candidate["status"] != "active" or key in nodes:
                fail("provider_invalid_candidates")
            nodes[key] = candidate
        keys = []
        for entry in raw["entries"]:
            item = fields(entry, {"fact", "index_lease"})
            fact = verify_document(item["fact"], "provider.fact", now=now)
            if fact["ref"] != wanted["ref"] or fact["status"] != "active" or (fact["signing_key"]["key_id"], fact["storage_epoch"]) not in nodes:
                fail("provider_invalid_candidates")
            verify_index_lease(item["index_lease"], fact=item["fact"], node=node, now=now)
            keys.append(document_sha256({"ref": fact["ref"], "provider_key_id": fact["signing_key"]["key_id"], "storage_epoch": fact["storage_epoch"], "custody_id": fact["custody_id"]}))
        if keys != sorted(set(keys)) or keys and (keys[0] <= (wanted["after"] or "") or raw["next_cursor"] != keys[-1]):
            fail("provider_invalid_cursor")
        if not keys and raw["next_cursor"] is not None:
            fail("provider_invalid_cursor")
    elif action == "target.get":
        raw = fields(body, {"target"})
        target = verify_document(raw["target"], "provider.target", now=now)
        expected = node_binding(target, node, now)
        if target["signing_key"] != expected["signing_key"]:
            fail("provider_target_mismatch")
    elif action == "target.answer":
        fields(body, {"answer"})
        raw = verify_document(body["answer"], "provider.target.answer", now=now)
        expected = node_binding(raw, node, now)
        if raw["signing_key"] != expected["signing_key"] or raw["challenge_sha256"] != document_sha256(wanted["challenge"]) or raw["target_sha256"] != document_sha256(wanted["target"]) or raw["requester_key_id"] != original["signing_key"]["key_id"]:
            fail("provider_target_mismatch")
        # Caller must additionally use verify_target_answer with its retained nonce.
    elif action == "resource.allocate" or action == "provider.result" and wanted["operation"] == "resource.allocate":
        fields(body, {"lease", "status", "current_state"})
        choice(body["current_state"], {"active", "expired", "revoked"})
        lease = verify_resource_lease(body["lease"], intent=wanted["intent"] if action == "resource.allocate" else None,
                                      node=node, now=now, allow_expired=body["current_state"] != "active")
        status = verify_status(body["status"], now=now, allow_expired=body["current_state"] != "active")
        if lease["subject"]["signing_key_id"] != original["signing_key"]["key_id"] or status["scope_key"] != {"root_key": lease["root_key"], "issuer_key_id": lease["signing_key"]["key_id"]}:
            fail("provider_lease_mismatch")
        expected_scope = resource_scope(lease["root_key"], lease["resource"])
        if len(status["entries"]) != 1 or status["entries"][0]["scope_kind"] != "resource" or status["entries"][0]["scope_id"] != expected_scope:
            fail("provider_status_scope_mismatch")
        if body["current_state"] == "active" and status["entries"][0]["status"] != "active":
            fail("provider_resource_inactive")
    elif action == "provider.put" or action == "provider.result":
        fields(body, {"index_lease", "current_state"})
        choice(body["current_state"], {"active", "expired", "revoked", "conflict", "superseded"})
        raw = verify_document(body["index_lease"], "provider.index_lease", now=now, allow_expired=body["current_state"] != "active")
        expected = node_binding(raw, node, now)
        if raw["signing_key"] != expected["signing_key"] or raw["provider_key_id"] != original["signing_key"]["key_id"]:
            fail("provider_index_lease_mismatch")
        if action == "provider.put":
            verify_index_lease(body["index_lease"], fact=wanted["fact"], node=node, now=now, allow_expired=body["current_state"] != "active")
            if raw["expires_at"] - raw["issued_at"] > wanted["lease_seconds"]:
                fail("provider_index_lease_mismatch")
    elif action == "resource.revoke":
        fields(body, {"status", "state"}); choice(body["state"], {"revoked"})
        status = verify_status(body["status"], now=now, allow_expired=True)
        if status["signing_key"] != node["payload"]["signing_key"]:
            fail("provider_wrong_issuer")
    else:
        fields(body, {"state"})
        choice(body["state"], {"withdrawn"} if action == "provider.withdraw" else {"observed"})
