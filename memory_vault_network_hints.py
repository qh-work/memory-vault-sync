"""Bounded, owner-authorized two-endpoint hints over the existing carrier.

Policies are local configuration, never claims supplied by a network message.
Every response remains transport state until an explicit selected share arrives.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
from pathlib import Path
import re
import secrets
import tempfile
import time
from typing import Any, Mapping

from memory_vault import MemoryError, Vault, canonical_bytes, strict_json_loads
from memory_vault_experience import decode
from memory_vault_network_content import (CONTENT_SCHEMA, HINT_SCHEMA, MAX_CONTENT_SHARE_BYTES,
    hint_identifier, hint_expiry, validate_content)
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_sharing import _row, _scan, export_share
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustError, _read_private

POLICY_SCHEMA = "memory-vault-hint-policy/v1"
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")


def _denied() -> MemoryError:
    return MemoryError("network_hint_not_available")


def _policy_path(network: Any) -> Path:
    return network.directory / "hint-policy.json"


def validate_policy(network: Any, value: Any) -> dict[str, Any]:
    try:
        if (not isinstance(value, dict) or set(value) != {"schema_version", "network_id", "owner_key_id", "revision", "expires_at", "peers"}
                or value["schema_version"] != POLICY_SCHEMA or value["network_id"] != network.network_id
                or value["owner_key_id"] != network.identity.key_id or not hint_expiry(value["revision"])
                or not hint_expiry(value["expires_at"]) or not isinstance(value["peers"], list) or len(value["peers"]) > 16
                or len(canonical_bytes(value)) > 65536):
            raise ValueError()
        peers = set()
        for peer in value["peers"]:
            if (not isinstance(peer, dict) or set(peer) != {"key_id", "hint_memory_ids", "record_memory_ids"}
                    or not isinstance(peer["key_id"], str) or _KEY.fullmatch(peer["key_id"]) is None
                    or peer["key_id"] in peers):
                raise ValueError()
            peers.add(peer["key_id"])
            for key in ("hint_memory_ids", "record_memory_ids"):
                ids = peer[key]
                if (not isinstance(ids, list) or len(ids) > 128 or any(not hint_identifier(item, memory=True) for item in ids)
                        or len(set(ids)) != len(ids)):
                    raise ValueError()
        return strict_json_loads(canonical_bytes(value))
    except (MemoryError, ValueError, TypeError, UnicodeError, RecursionError):
        raise MemoryError("network_invalid_hint_policy") from None


def set_policy(network: Any, value: Any) -> Mapping[str, Any]:
    policy = validate_policy(network, value)
    now = int(time.time())
    if not now < policy["expires_at"] <= now + 86400:
        raise MemoryError("network_invalid_hint_policy")
    # The existing endpoint DB serializes Python/TS setters; no new state row
    # or transaction spanning HTTP is introduced. A failed DB commit cannot
    # revert an already published higher-revision private policy file.
    with network.db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        raw = _read_private(_policy_path(network), 65536)
        if raw is not None:
            prior = validate_policy(network, strict_json_loads(raw))
            if (policy["revision"] < prior["revision"] or
                    (policy["revision"] == prior["revision"] and canonical_bytes(policy) != canonical_bytes(prior))):
                raise MemoryError("network_hint_policy_revision_conflict")
        atomic_write(_policy_path(network), canonical_bytes(policy), replace=raw is not None)
    return {"state": "hint_policy_set", "revision": policy["revision"], "network_accessed": False}


def policy_for(network: Any, recipient: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        raw = _read_private(_policy_path(network), 65536)
        if raw is None:
            raise _denied()
        policy = validate_policy(network, strict_json_loads(raw))
        if policy["expires_at"] <= int(time.time()):
            raise _denied()
        peer = next((item for item in policy["peers"] if item["key_id"] == recipient), None)
        if peer is None:
            raise _denied()
        return policy, peer
    except (MemoryError, TrustError, ValueError, TypeError):
        raise _denied() from None


def _inbox(network: Any, message_id: str, sender: str | None = None) -> tuple[str, dict[str, Any]]:
    if not hint_identifier(message_id):
        raise _denied()
    with network.db() as db:
        row = db.execute("SELECT sender,body,result FROM inbox WHERE message_id=?", (message_id,)).fetchone()
    if (row is None or (sender is not None and row["sender"] != sender)
            or strict_json_loads(row["result"]).get("state") != "validated_saved"):
        raise _denied()
    return row["sender"], validate_content(bytes(row["body"]))


def _offer(network: Any, offer_id: str, recipient: str, memory_id: str, *, incoming: bool) -> dict[str, Any]:
    if incoming:
        _, body = _inbox(network, offer_id, recipient)
    else:
        with network.db() as db:
            row = db.execute("SELECT request_id FROM outbox WHERE message_id=?", (offer_id,)).fetchone()
            prior = network._outbox_rows(db, row["request_id"], full=True)[0] if row else None
        if prior is None or strict_json_loads(prior["recipients"]) != [recipient]:
            raise _denied()
        body = validate_content(bytes(prior["body"]))
    control = body.get("control", {})
    if (body["kind"] != "hint_control" or control.get("kind") != "hints"
            or control["expires_at"] <= int(time.time())
            or memory_id not in {item["memory_id"] for item in control["hints"]}):
        raise _denied()
    return control


def validate_select(network: Any, control: Mapping[str, Any], recipient: str) -> None:
    _offer(network, control["offer_message_id"], recipient, control["memory_id"], incoming=True)


def validate_incoming_transfer(network: Any, body: Mapping[str, Any], sender: str) -> None:
    """A signed peer cannot skip this endpoint's explicit selection step."""
    try:
        with network.db() as db:
            row = db.execute("SELECT request_id FROM outbox WHERE message_id=?", (body["request_message_id"],)).fetchone()
            prior = network._outbox_rows(db, row["request_id"], full=True)[0] if row else None
        if prior is None or strict_json_loads(prior["recipients"]) != [sender]:
            raise _denied()
        selection = validate_content(bytes(prior["body"]))
        if selection != {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
                "schema_version": HINT_SCHEMA, "kind": "select", "offer_message_id": body["offer_message_id"], "memory_id": body["memory_id"]}}:
            raise _denied()
        offer = _offer(network, body["offer_message_id"], sender, body["memory_id"], incoming=True)
        if body["expires_at"] != offer["expires_at"] or body["expires_at"] <= int(time.time()):
            raise _denied()
        _share_ids(network, body)
    except (MemoryError, TrustError, ValueError, TypeError, KeyError) as exc:
        if getattr(exc, "retryable", False) or getattr(exc, "code", None) in {
                "share_integer_index_unavailable", "share_source_changed"}:
            raise
        raise MemoryError("network_invalid_content") from None


def _share_ids(network: Any, body: Mapping[str, Any]) -> set[str]:
    raw = unb64url(body["share"], maximum=MAX_CONTENT_SHARE_BYTES)
    ids: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="hint-check-", dir=network.directory) as temporary:
        source = Path(temporary) / "share.ndjson"
        atomic_write(source, raw, replace=False)
        _scan(source, time.monotonic() + 10, visitor=lambda record, proof: ids.add(record["memory_id"]))
    selected = [frame["record"]["memory_id"] for line in raw.splitlines()
                if (frame := strict_json_loads(line)).get("type") == "record" and frame["selected"]]
    if selected != [body["memory_id"]]:
        raise _denied()
    return ids


def guard(network: Any, body: Mapping[str, Any], recipients: list[str]) -> None:
    """Recheck immediately before send-start, including frozen outbox retries."""
    kind, control = body["kind"], body.get("control", {})
    if kind not in {"hint_control", "hint_transfer"}:
        return
    if len(recipients) != 1:
        raise _denied()
    recipient = recipients[0]
    if kind == "hint_control" and control["kind"] == "select":
        validate_select(network, control, recipient)
        return
    if kind == "hint_control" and control["kind"] in {"query", "refusal"}:
        return
    policy, peer = policy_for(network, recipient)
    if kind == "hint_control":
        _, request = _inbox(network, control["request_message_id"], recipient)
        if (request["kind"] != "hint_control" or request["control"]["kind"] != "query"
                or control["expires_at"] <= int(time.time())
                or control["expires_at"] > policy["expires_at"]
                or not {item["memory_id"] for item in control["hints"]}.issubset(peer["hint_memory_ids"])):
            raise _denied()
    else:
        _, request = _inbox(network, body["request_message_id"], recipient)
        offer = _offer(network, body["offer_message_id"], recipient, body["memory_id"], incoming=False)
        if (request["kind"] != "hint_control" or request["control"] != {
                "schema_version": HINT_SCHEMA, "kind": "select", "offer_message_id": body["offer_message_id"], "memory_id": body["memory_id"]}
                or body["expires_at"] != offer["expires_at"] or body["expires_at"] <= int(time.time())
                or not _share_ids(network, body).issubset(peer["record_memory_ids"])):
            raise _denied()
    # File checks performed after share parsing are the actual send-start
    # checkpoint, not the earlier snapshot used to prepare the response.
    latest, _ = policy_for(network, recipient)
    if canonical_bytes(latest) != canonical_bytes(policy):
        raise _denied()


def _hints(network: Any, query: str, authorized: list[str]) -> list[dict[str, Any]]:
    if not network.client_config.vault_path.exists():
        return []
    result = []
    with closing(network.client_config.vault()._connect(writable=False)) as db:
        db.execute("BEGIN")
        for memory_id in sorted(authorized):
            try:
                record = Vault._record_from_row(_row(db, memory_id))
            except MemoryError as exc:
                if exc.code == "share_dependency_not_admitted":
                    continue
                raise
            if query in record["text"]:
                result.append({"memory_id": memory_id,
                    "excerpt": record["text"].encode("utf-8")[:128].decode("utf-8", errors="ignore"),
                    "epistemic_type": decode(record)["epistemic_type"]})
                if len(result) == 4:
                    break
    return result


def respond_to(network: Any, message_id: str) -> Mapping[str, Any]:
    sender, request = _inbox(network, message_id)
    if request["kind"] != "hint_control" or request["control"]["kind"] not in {"query", "select"}:
        raise _denied()
    # A live authority can authorize local queue preparation while all relay
    # nodes are offline. Actual delivery still refreshes each relay binding.
    current = network._status("nonce_" + secrets.token_hex(16))["roster"]
    members = network._members(current)
    if any(key not in members or not {"send", "receive"}.issubset(members[key]["scope"])
           for key in (sender, network.identity.key_id)):
        raise _denied()
    request_id = "req_hint_response_" + hashlib.sha256(message_id.encode("ascii")).hexdigest()[:32]
    with network.db() as db:
        prior = (network._outbox_rows(db, request_id, full=True) or [None])[0]
    if prior is not None:
        return network._deliver(prior, [sender])
    control = request["control"]
    try:
        policy, peer = policy_for(network, sender)
        if control["kind"] == "query":
            body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
                "schema_version": HINT_SCHEMA, "kind": "hints", "request_message_id": message_id,
                "expires_at": min(int(time.time()) + 300, policy["expires_at"]),
                "hints": _hints(network, control["query"], peer["hint_memory_ids"])}}
        else:
            offer = _offer(network, control["offer_message_id"], sender, control["memory_id"], incoming=False)
            with tempfile.TemporaryDirectory(prefix="hint-share-", dir=network.directory) as temporary:
                destination = Path(temporary) / "share.ndjson"
                export_share(network.client_config.path, destination,
                    {"schema_version": "universal-memory-selection/v1", "memory_ids": [control["memory_id"]]},
                    maximum_seconds=10, authorized_memory_ids=set(peer["record_memory_ids"]))
                if destination.stat().st_size > MAX_CONTENT_SHARE_BYTES:
                    raise _denied()
                share = b64url(destination.read_bytes())
            body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_transfer", "request_message_id": message_id,
                "offer_message_id": control["offer_message_id"], "memory_id": control["memory_id"],
                "expires_at": offer["expires_at"], "share": share}
        guard(network, body, [sender])
    except (MemoryError, TrustError) as exc:
        if getattr(exc, "retryable", False) or exc.code in {"share_integer_index_unavailable", "share_source_changed"}:
            raise
        body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
            "schema_version": HINT_SCHEMA, "kind": "refusal", "request_message_id": message_id, "reason": "not_available"}}
    return network._send_hint_response(request_id, sender, validate_content(body), message_id)
