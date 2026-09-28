"""Immutable, recipient-bound encrypted content for the open network.

Transport authentication is deliberately separate from Vault author trust.
The caller supplies all four expected keys from its verified contact authority;
an envelope never promotes a self-declared key into a trusted author.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Mapping

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_content import CONTENT_SCHEMA, MAX_CONTENT_BYTES, validate_content
from memory_vault_network_crypto import (
    PublicKeyTrust, decrypt_bytes, document, encrypt_bytes,
    encryption_public_descriptor, integer, object_fields,
    public_signing_key, validate_jwe, b64url, unb64url, opaque,
)
from memory_vault_open_control import verify_node
from memory_vault_open_contact import verify_decision

ENVELOPE_SCHEMA = "memory-vault-open-message-envelope/v1"
CONTEXT_SCHEMA = "memory-vault-open-message-context/v1"
MAX_ENVELOPE_BYTES = 6 * 1024 * 1024
MAX_CONTEXT_BYTES = 4096
CONTEXT_FIELDS = {
    "schema_version", "message_id", "object_ref", "sender_signing_key",
    "sender_encryption_key", "recipient_signing_key", "recipient_encryption_key",
    "created_at", "content_schema", "content_kind",
}


def _fail(code):
    raise MemoryError("open_delivery_" + code)


def _hex(value, *, prefix=""):
    if not isinstance(value, str) or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is None:
        _fail("invalid_identifier")
    return value


def original_document(value, *, maximum=MAX_ENVELOPE_BYTES):
    """Validate before decoding; reject a noncanonical alternate wire encoding."""
    parsed = document(value, maximum=maximum)
    encoded = canonical_bytes(parsed)
    if len(encoded) > maximum:
        _fail("document_too_large")
    if isinstance(value, bytes) and value != encoded:
        _fail("noncanonical_document")
    return parsed


def _content(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_CONTENT_BYTES:
        _fail("invalid_content")
    content = validate_content(raw)
    if content["kind"] not in {"message", "memory_transfer"}:
        _fail("unsupported_content")
    if canonical_bytes(content) != raw:
        _fail("noncanonical_content")
    # The original share remains an encoded opaque byte string here. Its
    # record, dependency, signature and current-trust admission is performed
    # by the existing share importer, not by a second transport serializer.
    return content


def _context(value, *, now=None):
    raw = object_fields(original_document(value, maximum=MAX_CONTEXT_BYTES), CONTEXT_FIELDS)
    if raw["schema_version"] != CONTEXT_SCHEMA or raw["content_schema"] != CONTENT_SCHEMA:
        _fail("wrong_schema")
    _hex(raw["message_id"], prefix="msg_")
    ref = object_fields(raw["object_ref"], {"namespace", "key"})
    if ref["namespace"] != "object":
        _fail("wrong_object_namespace")
    _hex(ref["key"])
    public_signing_key(raw["sender_signing_key"])
    public_signing_key(raw["recipient_signing_key"])
    encryption_public_descriptor(raw["sender_encryption_key"])
    encryption_public_descriptor(raw["recipient_encryption_key"])
    created = integer(raw["created_at"])
    current = int(time.time()) if now is None else integer(now)
    if created > current + 30:
        _fail("from_future")
    if raw["content_kind"] not in {"message", "memory_transfer"}:
        _fail("unsupported_content")
    return raw


def create_envelope(content_bytes, *, signer, sender_encryption_key,
                    recipient_signing_key, recipient_encryption_key,
                    message_id, object_key, created_at=None):
    """Freeze one logical message; callers persist the returned original bytes."""
    content = _content(content_bytes)
    created = int(time.time()) if created_at is None else integer(created_at)
    context = _context({
        "schema_version": CONTEXT_SCHEMA,
        "message_id": message_id,
        "object_ref": {"namespace": "object", "key": object_key},
        "sender_signing_key": signer.public_descriptor(),
        "sender_encryption_key": dict(sender_encryption_key),
        "recipient_signing_key": dict(recipient_signing_key),
        "recipient_encryption_key": dict(recipient_encryption_key),
        "created_at": created,
        "content_schema": CONTENT_SCHEMA,
        "content_kind": content["kind"],
    })
    payload = {"schema_version": ENVELOPE_SCHEMA, "kind": "message.envelope",
               "context": context,
               "jwe": encrypt_bytes(content_bytes, [recipient_encryption_key], context=context)}
    signed = {"payload": payload, "proof": signer.sign_message(payload)}
    original_document(signed)
    return signed


def verify_envelope(value, *, sender_signing_key, sender_encryption_key,
                    recipient_signing_key, recipient_encryption_key, now=None):
    """Verify exact envelope/key bindings without claiming plaintext validity."""
    signed = object_fields(original_document(value), {"payload", "proof"})
    payload = object_fields(signed["payload"], {"schema_version", "kind", "context", "jwe"})
    if payload["schema_version"] != ENVELOPE_SCHEMA or payload["kind"] != "message.envelope":
        _fail("wrong_schema")
    context = _context(payload["context"], now=now)
    expected = {
        "sender_signing_key": public_signing_key(sender_signing_key),
        "sender_encryption_key": encryption_public_descriptor(sender_encryption_key),
        "recipient_signing_key": public_signing_key(recipient_signing_key),
        "recipient_encryption_key": encryption_public_descriptor(recipient_encryption_key),
    }
    for name, key in expected.items():
        if context[name] != key:
            _fail("key_binding_mismatch")
    jwe = validate_jwe(payload["jwe"], context=context)
    if len(jwe["recipients"]) != 1:
        _fail("wrong_recipient_count")
    if jwe["recipients"][0]["header"]["kid"] != context["recipient_encryption_key"]["key_id"]:
        _fail("key_binding_mismatch")
    PublicKeyTrust([sender_signing_key]).verify_message(payload, signed["proof"])
    return payload


def decrypt_envelope(value, *, encryption_identity, sender_signing_key,
                     sender_encryption_key, recipient_signing_key,
                     recipient_encryption_key, now=None):
    """Return original content bytes for the single existing Vault/inbox path."""
    payload = verify_envelope(value, sender_signing_key=sender_signing_key,
        sender_encryption_key=sender_encryption_key, recipient_signing_key=recipient_signing_key,
        recipient_encryption_key=recipient_encryption_key, now=now)
    if encryption_identity.public_descriptor() != recipient_encryption_key:
        _fail("wrong_recipient_identity")
    plain = decrypt_bytes(payload["jwe"], encryption_identity, context=payload["context"])
    content = _content(plain)
    if content["kind"] != payload["context"]["content_kind"]:
        _fail("content_binding_mismatch")
    return plain


def envelope_ref(value):
    """Private immutable reference. The opaque public key is not a digest."""
    raw = canonical_bytes(original_document(value))
    context = value["payload"]["context"] if isinstance(value, Mapping) else original_document(value)["payload"]["context"]
    return {"namespace": "object", "key": context["object_ref"]["key"],
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


PROFILE = "memory-vault-open-delivery-control/v1"
MAX_CONTROL_BYTES = 65536
CHUNK_BYTES = 262144
ACTIONS = {
    "node.info": set(), "prepare": {"intent"},
    "start": {"intent", "challenge", "answer"},
    "commit": {"handle_id"}, "status": {"handle_id"},
    "stored.get": {"message_id", "envelope_ref"},
    "list.prepare": {"lease_id"},
    "list": {"lease_id", "challenge", "answer", "after_sequence", "limit"},
    "read.prepare": {"message_id", "lease_id"},
    "read.start": {"message_id", "lease_id", "challenge", "answer"},
    "receipt.put": {"message_id", "receipt"},
    "receipt.get": {"message_id"},
}


def raw_sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def immutable_ref(value, *, maximum=MAX_ENVELOPE_BYTES):
    raw = object_fields(value, {"namespace", "key", "raw_sha256", "size"})
    if raw["namespace"] not in {"object", "meta"}:
        _fail("wrong_object_namespace")
    _hex(raw["key"]); _hex(raw["raw_sha256"])
    if integer(raw["size"], minimum=1) > maximum:
        _fail("document_too_large")
    return raw


def _signed(signer, kind, **values):
    payload = {"schema_version": PROFILE, "kind": kind,
               "signing_key": signer.public_descriptor(), **values}
    signed = {"payload": payload, "proof": signer.sign_message(payload)}
    original_document(signed, maximum=MAX_CONTROL_BYTES)
    return signed


def _verified(value, kind, fields, *, expected_signer=None, maximum=MAX_CONTROL_BYTES):
    signed = object_fields(original_document(value, maximum=maximum), {"payload", "proof"})
    payload = object_fields(signed["payload"], {"schema_version", "kind", "signing_key"} | set(fields))
    if payload["schema_version"] != PROFILE or payload["kind"] != kind:
        _fail("wrong_schema")
    key = public_signing_key(payload["signing_key"])
    if expected_signer is not None and key != expected_signer:
        _fail("key_binding_mismatch")
    PublicKeyTrust([key]).verify_message(payload, signed["proof"])
    return payload


def _window(payload, *, now=None, maximum=60):
    current = int(time.time()) if now is None else integer(now)
    issued, expires = integer(payload["issued_at"]), integer(payload["expires_at"])
    if not 1 <= expires - issued <= maximum or issued > current + 30 or expires <= current:
        _fail("expired")


def _node(payload, node, *, now=None):
    target = verify_node(node, now=now)
    if target["status"] != "active":
        _fail("inactive_node")
    if payload["node_key_id"] != target["signing_key"]["key_id"] or payload["storage_epoch"] != target["storage_epoch"]:
        _fail("wrong_target")
    return target


def _body(action, value):
    if not isinstance(action, str) or action not in ACTIONS:
        _fail("unsupported_action")
    body = object_fields(value, ACTIONS[action])
    for name in ("handle_id", "lease_id"):
        if name in body: opaque(body[name])
    if "message_id" in body: _hex(body["message_id"], prefix="msg_")
    if "envelope_ref" in body: immutable_ref(body["envelope_ref"])
    if action == "list":
        integer(body["after_sequence"])
        if integer(body["limit"], minimum=1) > 4: _fail("invalid_limit")
    if "answer" in body: unb64url(body["answer"], maximum=32, size=32)
    return body


def sign_rpc(signer, *, node, action, body, request_id=None, now=None):
    current = int(time.time()) if now is None else integer(now)
    target = verify_node(node, now=current)
    if target["status"] != "active": _fail("inactive_node")
    return _signed(signer, "delivery.rpc", issued_at=current, expires_at=current + 60,
        request_id=request_id or "rpc_" + secrets.token_hex(32), node_key_id=target["signing_key"]["key_id"],
        storage_epoch=target["storage_epoch"], action=action, body=_body(action, body))


def verify_rpc(value, *, node, now=None):
    payload = _verified(value, "delivery.rpc", {"issued_at", "expires_at", "request_id", "node_key_id", "storage_epoch", "action", "body"})
    _window(payload, now=now); _node(payload, node, now=now)
    opaque(payload["request_id"]); _body(payload["action"], payload["body"])
    return payload


def sign_response(signer, *, request, node, body, now=None):
    current = int(time.time()) if now is None else integer(now)
    original = verify_rpc(request, node=node, now=current)
    return _signed(signer, "delivery.response", issued_at=current,
        expires_at=min(current + 60, original["expires_at"]), request_id=original["request_id"],
        request_sha256=raw_sha256(request), requester_key_id=original["signing_key"]["key_id"],
        node_key_id=original["node_key_id"], storage_epoch=original["storage_epoch"],
        action=original["action"], body=dict(body))


def verify_response(value, *, request, node, now=None):
    original = verify_rpc(request, node=node, now=now)
    payload = _verified(value, "delivery.response", {"issued_at", "expires_at", "request_id", "request_sha256",
        "requester_key_id", "node_key_id", "storage_epoch", "action", "body"}, expected_signer=node["payload"]["signing_key"])
    _window(payload, now=now); _node(payload, node, now=now)
    if (payload["request_id"] != original["request_id"] or payload["request_sha256"] != raw_sha256(request)
            or payload["requester_key_id"] != original["signing_key"]["key_id"]
            or payload["action"] != original["action"] or payload["expires_at"] > original["expires_at"]):
        _fail("response_mismatch")
    if not isinstance(payload["body"], dict): _fail("invalid_response")
    if "error" in payload["body"]:
        object_fields(payload["body"], {"error"})
        error = object_fields(payload["body"]["error"], {"code", "retryable"})
        if not isinstance(error["code"], str) or type(error["retryable"]) is not bool:
            _fail("invalid_response")
    return payload


INTENT_FIELDS = {"operation_id", "message_id", "envelope_ref", "authority", "issued_at", "expires_at"}


def issue_upload_intent(signer, *, operation_id, envelope_ref, message_id, authority, issued_at, expires_at):
    opaque(operation_id); _hex(message_id, prefix="msg_"); immutable_ref(envelope_ref)
    object_fields(authority, {"request", "policy", "lease", "decision"})
    return _signed(signer, "delivery.upload.intent", operation_id=operation_id, message_id=message_id,
        envelope_ref=dict(envelope_ref), authority=dict(authority), issued_at=issued_at, expires_at=expires_at)


def verify_upload_intent(value, *, node, now=None):
    if verify_node(node, now=now)["status"] != "active": _fail("inactive_node")
    payload = _verified(value, "delivery.upload.intent", INTENT_FIELDS, maximum=49152)
    _window(payload, now=now, maximum=3600)
    opaque(payload["operation_id"]); _hex(payload["message_id"], prefix="msg_")
    ref = immutable_ref(payload["envelope_ref"])
    if ref["namespace"] != "object": _fail("wrong_object_namespace")
    authority = object_fields(payload["authority"], {"request", "policy", "lease", "decision"})
    decision = verify_decision(authority["decision"], request=authority["request"], policy=authority["policy"],
        lease=authority["lease"], node=node, now=now)
    request = authority["request"]["payload"]
    if decision["decision"] != "approved" or decision["grant"] is None:
        _fail("not_authorized")
    if payload["signing_key"] != request["signing_key"] or payload["expires_at"] > decision["expires_at"]:
        _fail("not_authorized")
    grant = decision["grant"]["payload"]
    if grant["operations"] != ["message.store"] or ref["size"] > grant["resource_lease"]["payload"]["max_bytes"]:
        _fail("quota")
    return payload


def reader_intent(action, *, lease_id, caller_key_id, message_id=None):
    opaque(lease_id)
    result = {"action": action, "lease_id": lease_id, "caller_key_id": caller_key_id}
    if action == "read": result["message_id"] = _hex(message_id, prefix="msg_")
    elif action != "list": _fail("unsupported_action")
    return result


def issue_challenge(signer, *, node, intent, subject_key_id, encryption_key, now=None):
    current = int(time.time()) if now is None else integer(now)
    target = verify_node(node, now=current)
    if target["status"] != "active": _fail("inactive_node")
    nonce = secrets.token_bytes(32)
    context = {"schema_version": PROFILE, "kind": "delivery.possession.context",
        "challenge_id": "challenge_" + secrets.token_hex(32), "intent_sha256": raw_sha256(intent),
        "subject_key_id": subject_key_id, "encryption_key_id": encryption_key["key_id"],
        "node_key_id": target["signing_key"]["key_id"], "storage_epoch": target["storage_epoch"],
        "issued_at": current, "expires_at": current + 60}
    challenge = _signed(signer, "delivery.challenge", context=context,
        jwe=encrypt_bytes(nonce, [encryption_key], context=context))
    return challenge, hashlib.sha256(nonce).hexdigest()


def solve_challenge(challenge, *, encryption_identity, intent, node, now=None):
    payload = _verified(challenge, "delivery.challenge", {"context", "jwe"}, expected_signer=node["payload"]["signing_key"], maximum=8192)
    context = object_fields(payload["context"], {"schema_version", "kind", "challenge_id", "intent_sha256",
        "subject_key_id", "encryption_key_id", "node_key_id", "storage_epoch", "issued_at", "expires_at"})
    if context["schema_version"] != PROFILE or context["kind"] != "delivery.possession.context": _fail("wrong_schema")
    _window(context, now=now); _node(context, node, now=now)
    subject = intent["payload"]["signing_key"]["key_id"] if "payload" in intent else intent.get("caller_key_id")
    if (context["intent_sha256"] != raw_sha256(intent) or context["encryption_key_id"] != encryption_identity.key_id
            or context["subject_key_id"] != subject):
        _fail("challenge_mismatch")
    plain = decrypt_bytes(payload["jwe"], encryption_identity, context=context)
    if len(plain) != 32: _fail("challenge_mismatch")
    return b64url(plain)


RECEIPT_FIELDS = {"message_id", "envelope_ref", "sender_key_id", "recipient_key_id", "saved_at", "status"}


def issue_recipient_receipt(signer, *, message_id, envelope_ref, sender_key_id, saved_at=None):
    return _signed(signer, "recipient.receipt", message_id=_hex(message_id, prefix="msg_"),
        envelope_ref=dict(immutable_ref(envelope_ref)), sender_key_id=sender_key_id,
        recipient_key_id=signer.key_id, saved_at=int(time.time()) if saved_at is None else integer(saved_at), status="validated_saved")


def verify_recipient_receipt(value, *, recipient_signing_key, sender_key_id, message_id, envelope_ref):
    payload = _verified(value, "recipient.receipt", RECEIPT_FIELDS, expected_signer=recipient_signing_key, maximum=4096)
    integer(payload["saved_at"])
    if (payload["status"] != "validated_saved" or payload["message_id"] != message_id
            or payload["envelope_ref"] != envelope_ref or payload["sender_key_id"] != sender_key_id
            or payload["recipient_key_id"] != recipient_signing_key["key_id"]):
        _fail("receipt_mismatch")
    return payload


STORAGE_FIELDS = {"message_id", "envelope_ref", "upload_intent_sha256", "sender_key_id", "recipient_key_id",
    "node_key_id", "storage_epoch", "lease_id", "sequence", "stored_at", "retain_until", "status"}


def issue_storage_receipt(signer, *, node, intent, sequence, stored_at, retain_until):
    original = verify_upload_intent(intent, node=node, now=stored_at)
    authority = original["authority"]
    lease = authority["decision"]["payload"]["grant"]["payload"]["resource_lease"]["payload"]
    if retain_until > lease["expires_at"] or retain_until <= stored_at:
        _fail("expired")
    return _signed(signer, "storage.receipt", message_id=original["message_id"],
        envelope_ref=original["envelope_ref"], upload_intent_sha256=raw_sha256(intent),
        sender_key_id=original["signing_key"]["key_id"], recipient_key_id=authority["policy"]["payload"]["signing_key"]["key_id"],
        node_key_id=lease["node_key_id"], storage_epoch=lease["storage_epoch"], lease_id=lease["lease_id"],
        sequence=integer(sequence, minimum=1), stored_at=integer(stored_at), retain_until=integer(retain_until), status="storage_accepted")


def verify_storage_receipt(value, *, node, intent):
    payload = _verified(value, "storage.receipt", STORAGE_FIELDS, expected_signer=node["payload"]["signing_key"], maximum=4096)
    stored_at = integer(payload["stored_at"])
    original = verify_upload_intent(intent, node=node, now=stored_at)
    lease = original["authority"]["decision"]["payload"]["grant"]["payload"]["resource_lease"]["payload"]
    integer(payload["sequence"], minimum=1)
    if (payload["message_id"] != original["message_id"] or payload["envelope_ref"] != original["envelope_ref"]
            or payload["upload_intent_sha256"] != raw_sha256(intent)
            or payload["sender_key_id"] != original["signing_key"]["key_id"]
            or payload["recipient_key_id"] != original["authority"]["policy"]["payload"]["signing_key"]["key_id"]
            or any(payload[k] != lease[k] for k in ("node_key_id", "storage_epoch", "lease_id"))
            or not stored_at < integer(payload["retain_until"]) <= lease["expires_at"]
            or payload["status"] != "storage_accepted"):
        _fail("receipt_mismatch")
    return payload
