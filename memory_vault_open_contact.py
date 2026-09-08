"""Strict first-contact controls. These documents never authorize Vault actions.

Directory leases are deliberately excluded. A delivery grant names a real,
finite reservation at one resource node; the open message carrier is separate.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from typing import Any

from memory_vault import MemoryError
from memory_vault_network_control import _sign, _verify, _window
from memory_vault_network_crypto import (
    PublicKeyTrust, b64url, decrypt_bytes, document, document_sha256,
    encrypt_bytes, encryption_public_descriptor, integer, object_fields,
    opaque, public_signing_key, digest, unb64url, validate_jwe,
)
from memory_vault_open_control import verify_node

PROFILE = "memory-vault-open-contact-control/v1"
MAX_REQUEST_BYTES = 4096
MAX_DECISION_BYTES = 8192
MAX_CONTROL_BYTES = 65536
MAX_SECONDS = 86400
CHALLENGE_SECONDS = 60
SLOT_BYTES = MAX_REQUEST_BYTES + MAX_DECISION_BYTES + 512
KINDS = {
    "resource.lease": {"node_key_id", "storage_epoch", "owner_key_id", "owner_encryption_key", "lease_id", "resource_id", "purpose", "max_items", "max_bytes"},
    "contact.policy": {"node_key_id", "storage_epoch", "lease_id", "lease_sha256", "resource_id", "encryption_key", "revision", "status", "max_pending"},
    "contact.request": {"request_id", "encryption_key", "recipient_key_id", "recipient_encryption_key_id", "node_key_id", "storage_epoch", "lease_id", "resource_id", "policy_sha256", "request_class"},
    "contact.challenge": {"request_id", "request_sha256", "subject_key_id", "subject_encryption_key_id", "recipient_key_id", "node_key_id", "storage_epoch", "policy_sha256", "purpose", "challenge_id", "jwe"},
    "contact.grant": {"request_id", "request_sha256", "subject_key_id", "subject_encryption_key_id", "recipient_encryption_key_id", "node_key_id", "storage_epoch", "resource_id", "operations", "resource_lease"},
    "contact.decision": {"request_id", "request_sha256", "subject_key_id", "subject_encryption_key_id", "recipient_encryption_key_id", "node_key_id", "storage_epoch", "policy_sha256", "decision", "reason", "grant"},
    "contact.rpc": {"request_id", "node_key_id", "storage_epoch", "action", "body"},
    "contact.response": {"request_id", "request_sha256", "node_key_id", "storage_epoch", "body"},
}
COMMON = {"schema_version", "kind", "signing_key", "issued_at", "expires_at"}
ACTIONS = {
    "lease": {"encryption_key", "purpose", "max_items", "max_bytes", "lease_seconds", "allocation_id"},
    "policy.put": {"lease", "policy"},
    "policy.get": {"recipient_key_id"},
    "challenge": {"request", "purpose"},
    "submit": {"request", "challenge", "answer"},
    "poll": {"lease_id"},
    "decide": {"request", "decision"},
    "result": {"request", "challenge", "answer"},
}


class ContactError(MemoryError):
    pass


def fail(code):
    raise ContactError(code)


def current_time(now=None):
    return int(time.time()) if now is None else integer(now)


def fields(value, names):
    return object_fields(value, names, "contact_invalid_document")


def key(value, prefix="ed25519"):
    if not isinstance(value, str) or re.fullmatch(prefix + r"_[0-9a-f]{64}", value) is None:
        fail("contact_invalid_key")
    return value


def one_of(value, choices):
    if not isinstance(value, str) or value not in choices:
        fail("contact_invalid_enum")
    return value


def limit(value, maximum, minimum=1):
    if integer(value, minimum=minimum) > maximum:
        fail("contact_invalid_limit")
    return value


def _limits(raw):
    one_of(raw["purpose"], {"knock", "delivery"})
    limit(raw["max_items"], 32)
    limit(raw["max_bytes"], 16 * 1024 * 1024)
    if raw["purpose"] == "knock" and raw["max_bytes"] != raw["max_items"] * SLOT_BYTES:
        fail("contact_invalid_reservation")


def _body(action, value, now):
    one_of(action, ACTIONS)
    raw = fields(value, ACTIONS[action])
    if action == "lease":
        encryption_public_descriptor(raw["encryption_key"])
        _limits(raw)
        limit(raw["lease_seconds"], MAX_SECONDS)
        opaque(raw["allocation_id"])
    elif action == "policy.put":
        verify_document(raw["lease"], "resource.lease", now=now)
        verify_document(raw["policy"], "contact.policy", now=now)
    elif action == "policy.get":
        key(raw["recipient_key_id"])
    elif action == "poll":
        opaque(raw["lease_id"])
    else:
        verify_document(raw["request"], "contact.request", now=now)
        if action == "challenge":
            one_of(raw["purpose"], {"submit", "result"})
        elif action == "decide":
            verify_document(raw["decision"], "contact.decision", now=now)
        else:
            verify_document(raw["challenge"], "contact.challenge", now=now)
            unb64url(raw["answer"], maximum=32, size=32)
    return raw


def verify_document(value, kind, *, now=None):
    """Validate shape, budget and signature; callers must check resource bindings."""
    if kind not in KINDS:
        fail("contact_unsupported_kind")
    maximum = MAX_CONTROL_BYTES if kind in {"contact.rpc", "contact.response"} else MAX_DECISION_BYTES if kind == "contact.decision" else MAX_REQUEST_BYTES
    signed = fields(document(value, maximum=maximum), {"payload", "proof"})
    raw = fields(signed["payload"], COMMON | KINDS[kind])
    if raw["schema_version"] != PROFILE or raw["kind"] != kind:
        fail("contact_wrong_profile")
    public_signing_key(raw["signing_key"])
    _window(raw, maximum=CHALLENGE_SECONDS if kind in {"contact.rpc", "contact.response", "contact.challenge"} else MAX_SECONDS, now=now)
    for name in ("node_key_id", "owner_key_id", "subject_key_id", "recipient_key_id"):
        if name in raw:
            key(raw[name])
    for name in ("subject_encryption_key_id", "recipient_encryption_key_id"):
        if name in raw:
            key(raw[name], "x25519")
    for name in ("lease_id", "resource_id", "request_id", "challenge_id", "storage_epoch"):
        if name in raw:
            opaque(raw[name])
    for name in ("lease_sha256", "request_sha256", "policy_sha256"):
        if name in raw:
            digest(raw[name])
    for name in ("encryption_key", "owner_encryption_key"):
        if name in raw:
            encryption_public_descriptor(raw[name])
    if kind == "resource.lease":
        _limits(raw)
        if raw["signing_key"]["key_id"] != raw["node_key_id"]:
            fail("contact_wrong_node")
    elif kind == "contact.policy":
        integer(raw["revision"], minimum=1)
        one_of(raw["status"], {"active", "revoked"})
        limit(raw["max_pending"], 32)
    elif kind == "contact.request":
        one_of(raw["request_class"], {"message"})
        if raw["signing_key"]["key_id"] == raw["recipient_key_id"]:
            fail("contact_self_request")
    elif kind == "contact.challenge":
        one_of(raw["purpose"], {"submit", "result"})
        context = {k: v for k, v in raw.items() if k != "jwe"}
        jwe = validate_jwe(raw["jwe"], context=context)
        if (len(jwe["recipients"]) != 1 or jwe["recipients"][0]["header"]["kid"] != raw["subject_encryption_key_id"]
                or len(unb64url(jwe["ciphertext"], maximum=256)) > 128):
            fail("contact_invalid_challenge")
    elif kind == "contact.grant":
        if raw["operations"] != ["message.store"]:
            fail("contact_invalid_scope")
        lease = verify_document(raw["resource_lease"], "resource.lease", now=now)
        if (lease["purpose"] != "delivery" or lease["owner_key_id"] != raw["signing_key"]["key_id"]
                or lease["owner_encryption_key"]["key_id"] != raw["recipient_encryption_key_id"]
                or any(raw[k] != lease[k] for k in ("node_key_id", "storage_epoch", "resource_id"))
                or raw["expires_at"] > lease["expires_at"]):
            fail("contact_grant_mismatch")
    elif kind == "contact.decision":
        one_of(raw["decision"], {"approved", "rejected"})
        one_of(raw["reason"], {"accepted", "declined", "unavailable"})
        if raw["decision"] == "approved":
            if raw["reason"] != "accepted":
                fail("contact_invalid_decision")
            grant = verify_document(raw["grant"], "contact.grant", now=now)
            for name in ("request_id", "request_sha256", "signing_key", "subject_key_id", "subject_encryption_key_id", "recipient_encryption_key_id"):
                if raw[name] != grant[name]:
                    fail("contact_grant_mismatch")
            if grant["expires_at"] > raw["expires_at"]:
                fail("contact_grant_mismatch")
        elif raw["grant"] is not None or raw["reason"] == "accepted":
            fail("contact_invalid_decision")
    elif kind == "contact.rpc":
        _body(raw["action"], raw["body"], now)
    elif kind == "contact.response":
        document(raw["body"], maximum=MAX_CONTROL_BYTES)
    try:
        _verify(signed, PublicKeyTrust([raw["signing_key"]]))
    except MemoryError:
        fail("contact_invalid_signature")
    return raw


def sign_document(signer, kind, *, issued_at, expires_at, **values):
    raw = {"schema_version": PROFILE, "kind": kind, "signing_key": signer.public_descriptor(),
           "issued_at": issued_at, "expires_at": expires_at, **values}
    result = _sign(raw, signer)
    verify_document(result, kind, now=issued_at)
    return result


def node_binding(raw, node, *, now=None):
    target = verify_node(node, now=now)
    if (target["status"] != "active" or raw["node_key_id"] != target["signing_key"]["key_id"]
            or raw["storage_epoch"] != target["storage_epoch"]):
        fail("contact_wrong_node")
    return target


def verify_lease(value, *, node, now=None):
    raw = verify_document(value, "resource.lease", now=now)
    target = node_binding(raw, node, now=now)
    if raw["signing_key"] != target["signing_key"]:
        fail("contact_wrong_node")
    return raw


def verify_policy(value, *, lease, node, now=None):
    raw = verify_document(value, "contact.policy", now=now)
    resource = verify_lease(lease, node=node, now=now)
    if (resource["purpose"] != "knock" or raw["signing_key"]["key_id"] != resource["owner_key_id"]
            or raw["encryption_key"] != resource["owner_encryption_key"]
            or raw["lease_sha256"] != document_sha256(lease)
            or raw["max_pending"] > resource["max_items"] or raw["expires_at"] > resource["expires_at"]
            or any(raw[k] != resource[k] for k in ("node_key_id", "storage_epoch", "lease_id", "resource_id"))):
        fail("contact_policy_mismatch")
    return raw


def verify_request(value, *, policy, lease, node, now=None):
    raw = verify_document(value, "contact.request", now=now)
    owner = verify_policy(policy, lease=lease, node=node, now=now)
    if (owner["status"] != "active" or raw["recipient_key_id"] != owner["signing_key"]["key_id"]
            or raw["recipient_encryption_key_id"] != owner["encryption_key"]["key_id"]
            or raw["policy_sha256"] != document_sha256(policy) or raw["expires_at"] > owner["expires_at"]
            or any(raw[k] != owner[k] for k in ("node_key_id", "storage_epoch", "lease_id", "resource_id"))):
        fail("contact_request_mismatch")
    return raw


def verify_challenge(value, *, request, node, purpose, now=None):
    raw = verify_document(value, "contact.challenge", now=now)
    original = verify_document(request, "contact.request", now=now)
    target = node_binding(raw, node, now=now)
    if (raw["signing_key"] != target["signing_key"] or raw["purpose"] != purpose
            or raw["request_sha256"] != document_sha256(request)
            or raw["subject_key_id"] != original["signing_key"]["key_id"]
            or raw["subject_encryption_key_id"] != original["encryption_key"]["key_id"]
            or raw["expires_at"] > original["expires_at"]
            or any(raw[k] != original[k] for k in ("request_id", "recipient_key_id", "node_key_id", "storage_epoch", "policy_sha256"))):
        fail("contact_challenge_mismatch")
    return raw


def issue_challenge(signer, *, request, node, purpose, now=None):
    now = current_time(now)
    original = verify_document(request, "contact.request", now=now)
    target = node_binding(original, node, now=now)
    if signer.public_descriptor() != target["signing_key"]:
        fail("contact_wrong_node")
    answer = secrets.token_bytes(32)
    context = {"schema_version": PROFILE, "kind": "contact.challenge", "signing_key": signer.public_descriptor(),
               "issued_at": now, "expires_at": min(now + CHALLENGE_SECONDS, original["expires_at"]),
               "request_id": original["request_id"], "request_sha256": document_sha256(request),
               "subject_key_id": original["signing_key"]["key_id"],
               "subject_encryption_key_id": original["encryption_key"]["key_id"],
               "recipient_key_id": original["recipient_key_id"], "node_key_id": original["node_key_id"],
               "storage_epoch": original["storage_epoch"], "policy_sha256": original["policy_sha256"],
               "purpose": one_of(purpose, {"submit", "result"}), "challenge_id": "ch_" + secrets.token_hex(16)}
    result = _sign({**context, "jwe": encrypt_bytes(answer, [original["encryption_key"]], context=context)}, signer)
    verify_challenge(result, request=request, node=node, purpose=purpose, now=now)
    return result, hashlib.sha256(answer).hexdigest()


def solve_challenge(value, *, request, node, purpose, encryption_identity, now=None):
    raw = verify_challenge(value, request=request, node=node, purpose=purpose, now=now)
    if encryption_identity.key_id != raw["subject_encryption_key_id"]:
        fail("contact_wrong_subject")
    answer = decrypt_bytes(raw["jwe"], encryption_identity, context={k: v for k, v in raw.items() if k != "jwe"})
    if len(answer) != 32:
        fail("contact_invalid_challenge")
    return b64url(answer)


def verify_decision(value, *, request, policy, lease, node, now=None):
    raw = verify_document(value, "contact.decision", now=now)
    original = verify_request(request, policy=policy, lease=lease, node=node, now=now)
    owner = policy["payload"]
    if (raw["signing_key"] != owner["signing_key"] or raw["request_sha256"] != document_sha256(request)
            or raw["subject_key_id"] != original["signing_key"]["key_id"]
            or raw["subject_encryption_key_id"] != original["encryption_key"]["key_id"]
            or raw["expires_at"] > original["expires_at"]
            or any(raw[k] != original[k] for k in ("request_id", "recipient_encryption_key_id", "node_key_id", "storage_epoch", "policy_sha256"))):
        fail("contact_decision_mismatch")
    # First slice uses the same concrete resource node. Later independently
    # discovered nodes require their own current reservation verification.
    if raw["grant"] is not None:
        verify_lease(raw["grant"]["payload"]["resource_lease"], node=node, now=now)
    return raw


def sign_rpc(signer, *, node, action, body, request_id=None, now=None):
    now = current_time(now)
    target = verify_node(node, now=now)
    return sign_document(signer, "contact.rpc", issued_at=now, expires_at=now + 60,
                         request_id=request_id or "rpc_" + secrets.token_hex(16),
                         node_key_id=target["signing_key"]["key_id"], storage_epoch=target["storage_epoch"],
                         action=action, body=body)


def verify_rpc(value, *, node, now=None):
    raw = verify_document(value, "contact.rpc", now=now)
    node_binding(raw, node, now=now)
    body = raw["body"]
    if raw["action"] in {"challenge", "submit", "result"} and body["request"]["payload"]["signing_key"] != raw["signing_key"]:
        fail("contact_wrong_subject")
    if raw["action"] in {"policy.put", "decide"}:
        inner = body["policy"] if raw["action"] == "policy.put" else body["decision"]
        if inner["payload"]["signing_key"] != raw["signing_key"]:
            fail("contact_wrong_subject")
    return raw


def sign_response(signer, *, request, node, body, now=None):
    now = current_time(now)
    original = verify_rpc(request, node=node, now=now)
    return sign_document(signer, "contact.response", issued_at=now, expires_at=min(now + 60, original["expires_at"]),
                         request_id=original["request_id"], request_sha256=document_sha256(request),
                         node_key_id=original["node_key_id"], storage_epoch=original["storage_epoch"], body=body)


def verify_response(value, *, request, node, now=None):
    raw = verify_document(value, "contact.response", now=now)
    original = verify_rpc(request, node=node, now=now)
    target = node_binding(raw, node, now=now)
    if (raw["signing_key"] != target["signing_key"] or raw["request_id"] != original["request_id"]
            or raw["request_sha256"] != document_sha256(request) or raw["expires_at"] > original["expires_at"]):
        fail("contact_response_mismatch")
    body = raw["body"]
    if "error" in body:
        error = fields(fields(body, {"error"})["error"], {"code", "retryable"})
        if (not isinstance(error["code"], str) or re.fullmatch(r"[a-z][a-z0-9_]{1,63}", error["code"]) is None
                or type(error["retryable"]) is not bool):
            fail("contact_invalid_document")
    else:
        action = original["action"]
        expected = {"lease": {"lease"}, "policy.put": {"state"}, "policy.get": {"lease", "policy"},
                    "challenge": {"challenge"}, "submit": {"state", "request_sha256"},
                    "poll": {"requests"}, "decide": {"state", "request_sha256"}, "result": {"state", "decision"}}[action]
        fields(body, expected)
        if action == "lease":
            lease = verify_lease(body["lease"], node=node, now=now)
            wanted = original["body"]
            if (lease["owner_key_id"] != original["signing_key"]["key_id"] or lease["owner_encryption_key"] != wanted["encryption_key"]
                    or lease["expires_at"] - lease["issued_at"] > wanted["lease_seconds"]
                    or any(lease[k] != wanted[k] for k in ("purpose", "max_items", "max_bytes"))):
                fail("contact_lease_mismatch")
        elif action == "policy.get":
            policy = verify_policy(body["policy"], lease=body["lease"], node=node, now=now)
            if policy["status"] != "active" or policy["signing_key"]["key_id"] != original["body"]["recipient_key_id"]:
                fail("contact_policy_mismatch")
        elif action == "policy.put":
            one_of(body["state"], {"active", "revoked"})
            if body["state"] != original["body"]["policy"]["payload"]["status"]:
                fail("contact_policy_mismatch")
        elif action == "challenge":
            verify_challenge(body["challenge"], request=original["body"]["request"], node=node, purpose=original["body"]["purpose"], now=now)
        elif action in {"submit", "decide"}:
            one_of(body["state"], {"contact_queued", "decided"} if action == "submit" else {"decided"})
            if body["request_sha256"] != document_sha256(original["body"]["request"]):
                fail("contact_request_mismatch")
        elif action == "poll":
            if not isinstance(body["requests"], list) or len(body["requests"]) > 4:
                fail("contact_invalid_limit")
            for item in body["requests"]:
                item = verify_document(item, "contact.request", now=now)
                if item["recipient_key_id"] != original["signing_key"]["key_id"] or item["lease_id"] != original["body"]["lease_id"]:
                    fail("contact_wrong_subject")
        elif action == "result":
            one_of(body["state"], {"pending", "approved", "rejected"})
            if body["state"] == "pending":
                if body["decision"] is not None:
                    fail("contact_invalid_decision")
            else:
                decision = verify_document(body["decision"], "contact.decision", now=now)
                if decision["decision"] != body["state"]:
                    fail("contact_invalid_decision")
                requested = original["body"]["request"]
                logical = requested["payload"]
                if (decision["request_sha256"] != document_sha256(requested)
                        or decision["signing_key"]["key_id"] != logical["recipient_key_id"]
                        or decision["subject_key_id"] != logical["signing_key"]["key_id"]
                        or decision["subject_encryption_key_id"] != logical["encryption_key"]["key_id"]
                        or decision["expires_at"] > logical["expires_at"]
                        or any(decision[k] != logical[k] for k in ("request_id", "recipient_encryption_key_id", "node_key_id", "storage_epoch", "policy_sha256"))):
                    fail("contact_decision_mismatch")
                if decision["grant"] is not None:
                    verify_lease(decision["grant"]["payload"]["resource_lease"], node=node, now=now)
    return raw
