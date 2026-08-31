"""Signed storage-node control, independent of agent membership and memory.

Nodes hold only their own Ed25519 signing identity. A directory does not grant
agent send/receive rights, invite consumption, or access to plaintext. Importing
this module performs no I/O, discovery, key generation, or service startup.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from memory_vault_network_control import MAX_CONTROL_BYTES, _sign, _verify, _window
from memory_vault_network_crypto import (
    NetworkCryptoError, PublicKeyTrust, digest, document, document_sha256, integer, object_fields,
    opaque, public_signing_key,
)
from memory_vault_trust import Identity, TrustStore

DIRECTORY_SCHEMA = "memory-vault-node-directory/v1"
REQUEST_SCHEMA = "memory-vault-node-request/v1"
STATUS_SCHEMA = "memory-vault-node-status/v1"
MAX_NODES = 256
MAX_STORAGE_RECEIPT_BYTES = 16 * 1024
MAX_OUTBOX_RECEIPT_ROW_BYTES = 64 * 1024
MAX_OUTBOX_RECEIPTS_BYTES = 16 * 1024 * 1024
NODE_SCOPES = frozenset({"node.status", "export", "import"})
NODE_ACTIONS = frozenset({"refresh", "export", "import"})


def check_outbox_receipt_bounds(connection: Any) -> None:
    """Read lengths only; callers keep the same SQLite snapshot for the rows."""
    count, largest, total = connection.execute(
        "SELECT COUNT(*),COALESCE(MAX(length(CAST(receipts AS BLOB))),0),"
        "COALESCE(SUM(length(CAST(receipts AS BLOB))),0) FROM outbox"
    ).fetchone()
    if count > 1024:
        raise NetworkCryptoError("network_outbox_capacity")
    if largest > MAX_OUTBOX_RECEIPT_ROW_BYTES or total > MAX_OUTBOX_RECEIPTS_BYTES:
        raise NetworkCryptoError("network_storage_receipt_capacity")


def verify_storage_receipt(value: Mapping[str, Any] | bytes, *, network_id: str,
                           message_id: str, envelope_sha256: str,
                           node_binding: Mapping[str, Any] | None,
                           allow_legacy_unsigned: bool = False) -> dict[str, Any]:
    """Validate a historical assertion, never current retention or authority.

    A missing node binding permits only the explicit legacy unsigned path;
    an incoming receipt cannot supply its own trusted node key.
    """
    raw = document(value, maximum=MAX_STORAGE_RECEIPT_BYTES)
    opaque(network_id)
    binding = None
    if node_binding is None:
        if allow_legacy_unsigned is not True or "node_receipt" in raw:
            raise NetworkCryptoError("network_node_identity_required")
    else:
        binding = object_fields(node_binding, {"signing_key", "base_url", "storage_epoch"})
        public_signing_key(binding["signing_key"])
        _base_url(binding["base_url"])
        opaque(binding["storage_epoch"])
        if "node_receipt" not in raw:
            raise NetworkCryptoError("network_node_identity_required")
    fields = {"state", "message_id", "envelope_sha256", "sequence"}
    object_fields(raw, fields | ({"node_receipt"} if binding is not None else set()))
    receipt = {key: raw[key] for key in fields}
    if (receipt["state"] != "stored" or opaque(receipt["message_id"]) != opaque(message_id)
            or digest(receipt["envelope_sha256"]) != digest(envelope_sha256)):
        raise NetworkCryptoError("network_invalid_storage_receipt")
    integer(receipt["sequence"], minimum=1)
    if binding is not None:
        signed = object_fields(raw["node_receipt"], {"payload", "proof"})
        payload = object_fields(signed["payload"], {"schema_version", "network_id", "node", "receipt"})
        if (payload["schema_version"] != "memory-vault-node-storage-receipt/v1"
                or payload["network_id"] != network_id or payload["node"] != binding
                or payload["receipt"] != receipt):
            raise NetworkCryptoError("network_node_receipt_mismatch")
        PublicKeyTrust([binding["signing_key"]]).verify_message(payload, signed["proof"])
    return receipt


def _base_url(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048 or any(c.isspace() for c in value):
        raise NetworkCryptoError("network_node_invalid_url")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or "?" in value or "#" in value or parsed.path
                or parsed.netloc.endswith(":")
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if parsed.scheme != "https" and not loopback:
            raise NetworkCryptoError("network_node_https_required")
    except ValueError:
        raise NetworkCryptoError("network_node_invalid_url") from None
    return value


def node(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a public node entry; no encryption key or agent scope is legal."""
    raw = object_fields(value, {"signing_key", "base_url", "storage_epoch", "scope", "status"})
    public_signing_key(raw["signing_key"])
    _base_url(raw["base_url"])
    opaque(raw["storage_epoch"])
    scopes = raw["scope"]
    if (not isinstance(scopes, list) or not scopes or any(not isinstance(s, str) or s not in NODE_SCOPES for s in scopes)
            or scopes != sorted(set(scopes))):
        raise NetworkCryptoError("network_node_invalid_scope")
    if not isinstance(raw["status"], str) or raw["status"] not in {"active", "draining", "revoked"}:
        raise NetworkCryptoError("network_node_invalid_status")
    return raw


def _directory(value: Mapping[str, Any], *, network_id: str, now: int | None = None,
               allow_expired: bool = False) -> dict[str, Any]:
    raw = object_fields(value, {"schema_version", "network_id", "version", "previous_sha256", "nodes", "issued_at", "expires_at"})
    if raw["schema_version"] != DIRECTORY_SCHEMA or opaque(raw["network_id"]) != opaque(network_id):
        raise NetworkCryptoError("network_node_directory_binding_mismatch")
    version = integer(raw["version"], minimum=1)
    previous = digest(raw["previous_sha256"])
    if (version == 1) != (previous == "0" * 64):
        raise NetworkCryptoError("network_node_directory_genesis_mismatch")
    if not isinstance(raw["nodes"], list) or len(raw["nodes"]) > MAX_NODES:
        raise NetworkCryptoError("network_node_directory_limit")
    entries = [node(entry) for entry in raw["nodes"]]
    keys = [entry["signing_key"]["key_id"] for entry in entries]
    epochs = [entry["storage_epoch"] for entry in entries]
    live_urls = [entry["base_url"] for entry in entries if entry["status"] != "revoked"]
    if (keys != sorted(set(keys)) or len(set(epochs)) != len(epochs)
            or len(set(live_urls)) != len(live_urls)):
        raise NetworkCryptoError("network_node_directory_duplicate")
    _window(raw, now=now, allow_expired=allow_expired)
    return raw


def issue_directory(issuer: Identity, *, network_id: str, version: int, previous_sha256: str,
                    nodes: Sequence[Mapping[str, Any]], issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": DIRECTORY_SCHEMA, "network_id": network_id, "version": version,
           "previous_sha256": previous_sha256,
           "nodes": sorted([dict(entry) for entry in nodes], key=lambda entry: entry["signing_key"]["key_id"]),
           "issued_at": issued_at, "expires_at": expires_at}
    return _sign(_directory(raw, network_id=network_id, now=issued_at), issuer)


def verify_directory(value: Mapping[str, Any] | bytes, issuers: TrustStore, *, network_id: str,
                     minimum_version: int = 0, expected_previous_sha256: str | None = None,
                     previous_directory: Mapping[str, Any] | bytes | None = None,
                     now: int | None = None, allow_expired: bool = False) -> dict[str, Any]:
    """Verify a directory and, when supplied, its durable earlier checkpoint.

    Callers persist the complete last verified directory, then pass it back as
    previous_directory: a version alone cannot detect an equal-version fork or
    resurrection. Gaps require separately verified fresh issuer node status;
    this function never treats a historical signature as proof of currentness.
    A replacement uses a new node key and epoch; old entries remain tombstones.
    """
    raw = _directory(_verify(value, issuers), network_id=network_id, now=now, allow_expired=allow_expired)
    if raw["version"] < integer(minimum_version):
        raise NetworkCryptoError("network_node_directory_rollback")
    if expected_previous_sha256 is not None and raw["previous_sha256"] != digest(expected_previous_sha256):
        raise NetworkCryptoError("network_node_directory_chain_mismatch")
    if previous_directory is None:
        return raw
    old = _directory(_verify(previous_directory, issuers), network_id=network_id, now=now, allow_expired=True)
    if raw["version"] < old["version"] or raw["issued_at"] < old["issued_at"]:
        raise NetworkCryptoError("network_node_directory_rollback")
    if raw["version"] == old["version"]:
        if document_sha256(value) != document_sha256(previous_directory):
            raise NetworkCryptoError("network_node_directory_version_conflict")
        return raw
    if raw["version"] == old["version"] + 1 and raw["previous_sha256"] != document_sha256(previous_directory):
        raise NetworkCryptoError("network_node_directory_chain_mismatch")
    current = {entry["signing_key"]["key_id"]: entry for entry in raw["nodes"]}
    transitions = {"active": {"active", "draining", "revoked"}, "draining": {"draining", "revoked"}, "revoked": {"revoked"}}
    for entry in old["nodes"]:
        replacement = current.get(entry["signing_key"]["key_id"])
        if replacement is None:
            raise NetworkCryptoError("network_node_tombstone_required")
        if any(entry[key] != replacement[key] for key in ("signing_key", "base_url", "storage_epoch")):
            raise NetworkCryptoError("network_node_identity_changed")
        if replacement["status"] not in transitions[entry["status"]]:
            raise NetworkCryptoError("network_node_reactivation_forbidden")
    return raw


def authorized_node(directory_payload: Mapping[str, Any], key_id: str, action: str, *,
                    base_url: str | None = None, storage_epoch: str | None = None) -> dict[str, Any]:
    """Authorize against an already verified, independently fresh directory."""
    opaque(key_id)
    if not isinstance(action, str) or action not in NODE_ACTIONS:
        raise NetworkCryptoError("network_node_action_rejected")
    matches = [entry for entry in directory_payload["nodes"] if entry["signing_key"]["key_id"] == key_id]
    if len(matches) != 1:
        raise NetworkCryptoError("network_node_authorization_required")
    entry = node(matches[0])
    if entry["status"] == "revoked" or (action == "import" and entry["status"] != "active"):
        raise NetworkCryptoError("network_node_inactive")
    required = "node.status" if action == "refresh" else action
    if required not in entry["scope"]:
        raise NetworkCryptoError("network_node_scope_denied")
    if ((base_url is not None and entry["base_url"] != _base_url(base_url))
            or (storage_epoch is not None and entry["storage_epoch"] != opaque(storage_epoch))):
        raise NetworkCryptoError("network_node_identity_changed")
    return entry


def sign_node_request(signer: Identity, *, network_id: str, action: str, request_id: str,
                      body: Mapping[str, Any], issued_at: int, expires_at: int) -> dict[str, Any]:
    if not isinstance(action, str) or action not in NODE_ACTIONS:
        raise NetworkCryptoError("network_node_action_rejected")
    raw = {"schema_version": REQUEST_SCHEMA, "network_id": opaque(network_id), "action": action,
           "request_id": opaque(request_id), "body": document(body, maximum=MAX_CONTROL_BYTES // 2),
           "issued_at": issued_at, "expires_at": expires_at}
    _window(raw, now=issued_at)
    return _sign(raw, signer)


def verify_node_request(value: Mapping[str, Any] | bytes, nodes_trust: TrustStore, *, network_id: str,
                        action: str | None = None, now: int | None = None) -> dict[str, Any]:
    raw = object_fields(_verify(value, nodes_trust), {"schema_version", "network_id", "action", "request_id", "body", "issued_at", "expires_at"})
    if raw["schema_version"] != REQUEST_SCHEMA or opaque(raw["network_id"]) != opaque(network_id):
        raise NetworkCryptoError("network_node_request_binding_mismatch")
    if not isinstance(raw["action"], str) or raw["action"] not in NODE_ACTIONS or (action is not None and raw["action"] != action):
        raise NetworkCryptoError("network_node_action_rejected")
    opaque(raw["request_id"])
    document(raw["body"], maximum=MAX_CONTROL_BYTES // 2)
    _window(raw, now=now)
    return raw


def issue_node_status(issuer: Identity, *, network_id: str, nonce: str, roster_sha256: str,
                      roster_version: int, directory_sha256: str, directory_version: int,
                      issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": STATUS_SCHEMA, "network_id": opaque(network_id), "nonce": opaque(nonce),
           "roster_sha256": digest(roster_sha256), "roster_version": integer(roster_version, minimum=1),
           "directory_sha256": digest(directory_sha256), "directory_version": integer(directory_version, minimum=1),
           "issued_at": issued_at, "expires_at": expires_at}
    _window(raw, now=issued_at)
    return _sign(raw, issuer)


def verify_node_status(value: Mapping[str, Any] | bytes, issuers: TrustStore, *, network_id: str, nonce: str,
                       roster_sha256: str | None = None, roster_version: int | None = None,
                       directory_sha256: str | None = None, directory_version: int | None = None,
                       now: int | None = None) -> dict[str, Any]:
    raw = object_fields(_verify(value, issuers), {"schema_version", "network_id", "nonce", "roster_sha256", "roster_version",
                                              "directory_sha256", "directory_version", "issued_at", "expires_at"})
    if (raw["schema_version"] != STATUS_SCHEMA or opaque(raw["network_id"]) != opaque(network_id)
            or opaque(raw["nonce"]) != opaque(nonce)):
        raise NetworkCryptoError("network_node_status_binding_mismatch")
    expected = {"roster_sha256": roster_sha256, "roster_version": roster_version,
                "directory_sha256": directory_sha256, "directory_version": directory_version}
    for key, value in expected.items():
        actual = digest(raw[key]) if key.endswith("sha256") else integer(raw[key], minimum=1)
        if value is not None:
            checked = digest(value) if key.endswith("sha256") else integer(value, minimum=1)
            if actual != checked:
                raise NetworkCryptoError("network_node_status_checkpoint_mismatch")
    _window(raw, now=now)
    return raw
