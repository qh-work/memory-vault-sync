"""Self-authenticating, bounded open-network control; never Memory authority."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from memory_vault import MemoryError
from memory_vault_network_control import _sign, _verify, _window
from memory_vault_network_crypto import (
    PublicKeyTrust, digest, document, document_sha256, encryption_public_descriptor,
    integer, object_fields, opaque, public_signing_key,
)
from memory_vault_nodes import _base_url
from memory_vault_trust import Identity

CONTROL_SCHEMA = "memory-vault-open-control/v1"
REQUEST_SCHEMA = "memory-vault-open-request/v1"
RESPONSE_SCHEMA = "memory-vault-open-response/v1"
LEASE_SCHEMA = "memory-vault-open-index-lease/v1"
MAX_CONTROL_BYTES = 65_536
MAX_DESCRIPTOR_BYTES = 4_096
MAX_DESCRIPTOR_SECONDS = 3_600
MAX_REQUEST_SECONDS = 60
MAX_LEASE_SECONDS = 600
MAX_REPLY_NODES = 8
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")
_ERROR = re.compile(r"[a-z][a-z0-9_]{1,63}")


class OpenControlError(MemoryError):
    pass


def _key(value: Any) -> str:
    if not isinstance(value, str) or _KEY.fullmatch(value) is None:
        raise OpenControlError("open_invalid_key")
    return value


def coordinate(key_id: str) -> str:
    return hashlib.sha256(b"memory-vault-open-routing/v1\x00" + _key(key_id).encode("ascii")).hexdigest()


def contact_key(key_id: str) -> str:
    return hashlib.sha256(b"memory-vault-open-contact/v1\x00" + _key(key_id).encode("ascii")).hexdigest()


def _url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise OpenControlError("open_invalid_url")
    return _base_url(value)


def _signed(value: Mapping[str, Any] | bytes, maximum: int) -> dict[str, Any]:
    return object_fields(document(value, maximum=maximum), {"payload", "proof"})


def _status(value: Any) -> None:
    if not isinstance(value, str) or value not in {"active", "revoked"}:
        raise OpenControlError("open_invalid_status")


def _descriptor_payload(value: Any, kind: str, now: int | None, allow_expired: bool) -> dict[str, Any]:
    common = {"schema_version", "kind", "signing_key", "revision", "status", "issued_at", "expires_at"}
    fields = ({"coordinate", "base_url", "storage_epoch", "roles"} if kind == "node"
              else {"encryption_key", "allow_discovery", "endpoints"})
    raw = object_fields(value, common | fields)
    if raw["schema_version"] != CONTROL_SCHEMA or raw["kind"] != kind:
        raise OpenControlError("open_unsupported_control")
    signing = public_signing_key(raw["signing_key"])
    integer(raw["revision"], minimum=1)
    _status(raw["status"])
    _window(raw, maximum=MAX_DESCRIPTOR_SECONDS, now=now, allow_expired=allow_expired)
    if kind == "node":
        if raw["coordinate"] != coordinate(signing["key_id"]):
            raise OpenControlError("open_coordinate_mismatch")
        _url(raw["base_url"])
        opaque(raw["storage_epoch"])
        roles = raw["roles"]
        if (not isinstance(roles, list) or not roles or
                any(not isinstance(role, str) or role not in {"router", "directory"} for role in roles)
                or roles != sorted(set(roles))):
            raise OpenControlError("open_invalid_roles")
    else:
        encryption_public_descriptor(raw["encryption_key"])
        if type(raw["allow_discovery"]) is not bool:
            raise OpenControlError("open_invalid_discovery")
        endpoints = raw["endpoints"]
        if not isinstance(endpoints, list) or len(endpoints) > 4:
            raise OpenControlError("open_invalid_endpoints")
        seen = set()
        for endpoint in endpoints:
            item = object_fields(endpoint, {"kind", "node_key_id", "base_url", "storage_epoch"})
            if item["kind"] != "node":
                raise OpenControlError("open_unsupported_endpoint")
            binding = (_key(item["node_key_id"]), _url(item["base_url"]), opaque(item["storage_epoch"]))
            if binding in seen:
                raise OpenControlError("open_duplicate_endpoint")
            seen.add(binding)
    return raw


def _verify_descriptor(value: Mapping[str, Any] | bytes, kind: str, *, now: int | None,
                       allow_expired: bool = False) -> dict[str, Any]:
    signed = _signed(value, MAX_DESCRIPTOR_BYTES)
    raw = _descriptor_payload(signed["payload"], kind, now, allow_expired)
    # This trust object checks possession of the advertised key only. It never
    # modifies the Vault trust registry or grants access to any resource.
    _verify(signed, PublicKeyTrust([raw["signing_key"]]))
    return raw


def verify_node(value: Mapping[str, Any] | bytes, *, now: int | None = None,
                allow_expired: bool = False) -> dict[str, Any]:
    return _verify_descriptor(value, "node", now=now, allow_expired=allow_expired)


def verify_contact(value: Mapping[str, Any] | bytes, *, now: int | None = None,
                   allow_expired: bool = False) -> dict[str, Any]:
    return _verify_descriptor(value, "contact", now=now, allow_expired=allow_expired)


def issue_node(signer: Identity, *, base_url: str, storage_epoch: str, roles: list[str],
               revision: int, issued_at: int, expires_at: int, status: str = "active") -> dict[str, Any]:
    raw = {"schema_version": CONTROL_SCHEMA, "kind": "node", "signing_key": signer.public_descriptor(),
           "coordinate": coordinate(signer.key_id), "base_url": base_url, "storage_epoch": storage_epoch,
           "roles": roles, "revision": revision, "status": status, "issued_at": issued_at, "expires_at": expires_at}
    result = _sign(_descriptor_payload(raw, "node", issued_at, False), signer)
    document(result, maximum=MAX_DESCRIPTOR_BYTES)
    return result


def issue_contact(signer: Identity, *, encryption_key: Mapping[str, Any], revision: int,
                  allow_discovery: bool, endpoints: list[dict[str, Any]], issued_at: int,
                  expires_at: int, status: str = "active") -> dict[str, Any]:
    raw = {"schema_version": CONTROL_SCHEMA, "kind": "contact", "signing_key": signer.public_descriptor(),
           "encryption_key": dict(encryption_key), "revision": revision, "status": status,
           "allow_discovery": allow_discovery, "endpoints": endpoints,
           "issued_at": issued_at, "expires_at": expires_at}
    result = _sign(_descriptor_payload(raw, "contact", issued_at, False), signer)
    document(result, maximum=MAX_DESCRIPTOR_BYTES)
    return result


def _request_body(action: Any, value: Any, now: int | None) -> dict[str, Any]:
    if not isinstance(action, str) or action not in {"hello", "find", "get", "put", "renew"}:
        raise OpenControlError("open_unsupported_action")
    fields = {"hello": {"node"}, "find": {"target", "view"}, "get": {"key"},
              "put": {"contact", "lease_seconds"}, "renew": {"contact", "lease_id", "lease_seconds"}}[action]
    raw = object_fields(value, fields)
    if action == "hello":
        if raw["node"] is not None:
            verify_node(raw["node"], now=now)
    elif action == "find":
        digest(raw["target"])
        if not isinstance(raw["view"], str) or raw["view"] not in {"general", "directory"}:
            raise OpenControlError("open_invalid_view")
    elif action == "get":
        digest(raw["key"])
    else:
        verify_contact(raw["contact"], now=now)
        if integer(raw["lease_seconds"], minimum=1) > MAX_LEASE_SECONDS:
            raise OpenControlError("open_invalid_lease")
        if action == "renew":
            opaque(raw["lease_id"])
    return raw


def sign_request(signer: Identity, *, action: str, request_id: str, node: Mapping[str, Any],
                 body: Mapping[str, Any], issued_at: int, expires_at: int) -> dict[str, Any]:
    target = verify_node(node, now=issued_at)
    raw = {"schema_version": REQUEST_SCHEMA, "action": action, "request_id": request_id,
           "signer": signer.public_descriptor(), "node_key_id": target["signing_key"]["key_id"],
           "storage_epoch": target["storage_epoch"], "issued_at": issued_at,
           "expires_at": expires_at, "body": dict(body)}
    result = _sign(raw, signer)
    verify_request(result, node=node, now=issued_at)
    return result


def verify_request(value: Mapping[str, Any] | bytes, *, node: Mapping[str, Any],
                   now: int | None = None) -> dict[str, Any]:
    signed = _signed(value, MAX_CONTROL_BYTES)
    raw = object_fields(signed["payload"], {"schema_version", "action", "request_id", "signer", "node_key_id",
                                           "storage_epoch", "issued_at", "expires_at", "body"})
    if raw["schema_version"] != REQUEST_SCHEMA:
        raise OpenControlError("open_unsupported_request")
    opaque(raw["request_id"])
    public_signing_key(raw["signer"])
    target = verify_node(node, now=now)
    if (target["status"] != "active" or raw["node_key_id"] != target["signing_key"]["key_id"]
            or raw["storage_epoch"] != target["storage_epoch"]):
        raise OpenControlError("open_wrong_node")
    _window(raw, maximum=MAX_REQUEST_SECONDS, now=now)
    body = _request_body(raw["action"], raw["body"], now)
    if (raw["action"] == "hello" and body["node"] is not None
            and body["node"]["payload"]["signing_key"] != raw["signer"]):
        raise OpenControlError("open_sender_mismatch")
    _verify(signed, PublicKeyTrust([raw["signer"]]))
    return raw


def issue_lease(signer: Identity, *, node: Mapping[str, Any], contact: Mapping[str, Any],
                request: Mapping[str, Any], lease_id: str, issued_at: int, expires_at: int) -> dict[str, Any]:
    target = verify_node(node, now=issued_at)
    owner = verify_contact(contact, now=issued_at)
    request_payload = verify_request(request, node=node, now=issued_at)
    raw = {"schema_version": LEASE_SCHEMA, "node_key_id": target["signing_key"]["key_id"],
           "storage_epoch": target["storage_epoch"], "owner_key_id": owner["signing_key"]["key_id"],
           "contact_sha256": document_sha256(contact), "contact_revision": owner["revision"],
           "lease_id": opaque(lease_id), "request_id": request_payload["request_id"],
           "request_sha256": document_sha256(request), "issued_at": issued_at, "expires_at": expires_at}
    result = _sign(raw, signer)
    verify_lease(result, node=node, contact=contact, now=issued_at)
    return result


def verify_lease(value: Mapping[str, Any] | bytes, *, node: Mapping[str, Any],
                 contact: Mapping[str, Any], now: int | None = None) -> dict[str, Any]:
    signed = _signed(value, MAX_DESCRIPTOR_BYTES)
    raw = object_fields(signed["payload"], {"schema_version", "node_key_id", "storage_epoch", "owner_key_id",
                                           "contact_sha256", "contact_revision", "lease_id", "request_id",
                                           "request_sha256", "issued_at", "expires_at"})
    target, owner = verify_node(node, now=now), verify_contact(contact, now=now)
    integer(raw["contact_revision"], minimum=1)
    if (raw["schema_version"] != LEASE_SCHEMA or raw["node_key_id"] != target["signing_key"]["key_id"]
            or raw["storage_epoch"] != target["storage_epoch"] or raw["owner_key_id"] != owner["signing_key"]["key_id"]
            or raw["contact_sha256"] != document_sha256(contact) or raw["contact_revision"] != owner["revision"]
            or integer(raw["expires_at"]) > owner["expires_at"]):
        raise OpenControlError("open_lease_mismatch")
    opaque(raw["lease_id"])
    opaque(raw["request_id"])
    digest(raw["request_sha256"])
    _window(raw, maximum=MAX_LEASE_SECONDS, now=now)
    _verify(signed, PublicKeyTrust([target["signing_key"]]))
    return raw


def _response_body(value: Any, request: Mapping[str, Any], node: Mapping[str, Any], now: int | None) -> dict[str, Any]:
    if isinstance(value, Mapping) and set(value) == {"error"}:
        error = object_fields(value["error"], {"code", "retryable"})
        if (not isinstance(error["code"], str) or _ERROR.fullmatch(error["code"]) is None
                or type(error["retryable"]) is not bool):
            raise OpenControlError("open_invalid_error")
        return dict(value)
    action = request["action"]
    if action == "hello":
        raw = object_fields(value, {"node"})
        answer = verify_node(raw["node"], now=now)
        expected = verify_node(node, now=now)
        if (answer["signing_key"] != expected["signing_key"] or
                answer["storage_epoch"] != expected["storage_epoch"]):
            raise OpenControlError("open_wrong_node")
    elif action == "find":
        raw = object_fields(value, {"nodes"})
        if not isinstance(raw["nodes"], list) or len(raw["nodes"]) > MAX_REPLY_NODES:
            raise OpenControlError("open_invalid_candidates")
        seen = set()
        for candidate in raw["nodes"]:
            key = verify_node(candidate, now=now)["signing_key"]["key_id"]
            if key in seen:
                raise OpenControlError("open_duplicate_candidate")
            seen.add(key)
    elif action == "get":
        if not isinstance(value, Mapping) or not isinstance(value.get("state"), str):
            raise OpenControlError("open_invalid_result")
        if value["state"] == "found":
            raw = object_fields(value, {"state", "contact", "lease"})
            owner = verify_contact(raw["contact"], now=now)
            if (owner["status"] != "active" or not owner["allow_discovery"]
                    or contact_key(owner["signing_key"]["key_id"]) != request["body"]["key"]):
                raise OpenControlError("open_contact_mismatch")
            verify_lease(raw["lease"], node=node, contact=raw["contact"], now=now)
        elif value["state"] in {"not_found", "revoked", "conflict"}:
            raw = object_fields(value, {"state"})
        else:
            raise OpenControlError("open_invalid_result")
    else:
        raw = object_fields(value, {"lease"})
        lease = verify_lease(raw["lease"], node=node, contact=request["body"]["contact"], now=now)
        if lease["request_id"] != request["request_id"]:
            raise OpenControlError("open_lease_mismatch")
    return raw


def sign_response(signer: Identity, *, request: Mapping[str, Any], node: Mapping[str, Any],
                  body: Mapping[str, Any], issued_at: int, expires_at: int) -> dict[str, Any]:
    original = verify_request(request, node=node, now=issued_at)
    target = verify_node(node, now=issued_at)
    raw = {"schema_version": RESPONSE_SCHEMA, "request_id": original["request_id"],
           "request_sha256": document_sha256(request), "node_key_id": target["signing_key"]["key_id"],
           "storage_epoch": target["storage_epoch"], "issued_at": issued_at, "expires_at": expires_at,
           "body": _response_body(body, original, node, issued_at)}
    result = _sign(raw, signer)
    verify_response(result, request=request, node=node, now=issued_at)
    return result


def verify_response(value: Mapping[str, Any] | bytes, *, request: Mapping[str, Any],
                    node: Mapping[str, Any], now: int | None = None) -> dict[str, Any]:
    signed = _signed(value, MAX_CONTROL_BYTES)
    raw = object_fields(signed["payload"], {"schema_version", "request_id", "request_sha256", "node_key_id",
                                           "storage_epoch", "issued_at", "expires_at", "body"})
    target = verify_node(node, now=now)
    original = verify_request(request, node=node, now=now)
    if (raw["schema_version"] != RESPONSE_SCHEMA or raw["request_id"] != original["request_id"]
            or raw["request_sha256"] != document_sha256(request)
            or raw["node_key_id"] != target["signing_key"]["key_id"]
            or raw["storage_epoch"] != target["storage_epoch"]):
        raise OpenControlError("open_response_mismatch")
    _window(raw, maximum=MAX_REQUEST_SECONDS, now=now)
    if raw["expires_at"] > original["expires_at"]:
        raise OpenControlError("open_response_mismatch")
    _verify(signed, PublicKeyTrust([target["signing_key"]]))
    _response_body(raw["body"], original, node, now)
    if original["action"] in {"put", "renew"} and "lease" in raw["body"]:
        if raw["body"]["lease"]["payload"]["request_sha256"] != document_sha256(request):
            raise OpenControlError("open_lease_mismatch")
    return raw
