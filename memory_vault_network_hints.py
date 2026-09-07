"""Bounded, owner-authorized two-endpoint hints over the existing carrier.

Policies are local configuration, never claims supplied by a network message.
Every response remains transport state until an explicit selected share arrives.
"""
from __future__ import annotations

from contextlib import closing, nullcontext
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
    hint_identifier, hint_expiry, hint_cursor, hint_projection, validate_content)
from memory_vault_network_crypto import b64url, unb64url
from memory_vault_sharing import _row, _scan, export_share
from memory_vault_storage import atomic_write
from memory_vault_trust import TrustError, _read_private

POLICY_SCHEMA = "memory-vault-hint-policy/v1"
SESSION_SCHEMA = "memory-vault-hint-session/v2"
SESSION_PREFIX = "hint-session:"
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")


def _denied() -> MemoryError:
    return MemoryError("network_hint_not_available")


def _connection(network: Any, connection: Any = None) -> Any:
    return network.db() if connection is None else nullcontext(connection)


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


def validate_session(network: Any, key: str, value: Any, *, allow_expired: bool = True) -> dict[str, Any]:
    """Validate local control state without treating its policy as authority."""
    try:
        if isinstance(value, (str, bytes)):
            if len(value.encode("utf-8") if isinstance(value, str) else value) > 32768:
                raise ValueError()
            value = strict_json_loads(value)
        fields = {"schema_version", "role", "network_id", "owner_key_id", "peer_key_id", "query_message_id", "query", "expires_at", "state", "cancellation"}
        if not isinstance(value, dict) or value.get("role") not in ("requester", "owner"):
            raise ValueError()
        cancellation = value["cancellation"]
        if value["state"] == "active":
            if cancellation is not None:
                raise ValueError()
        elif value["state"] == "cancelled":
            if (not isinstance(cancellation, dict) or set(cancellation) != {"message_id", "offer_message_id", "expires_at"}
                    or not hint_identifier(cancellation["message_id"]) or not hint_identifier(cancellation["offer_message_id"])
                    or not hint_expiry(cancellation["expires_at"]) or cancellation["expires_at"] > value["expires_at"]):
                raise ValueError()
        else:
            raise ValueError()
        if value["role"] == "owner":
            fields |= {"policy_revision", "policy_sha256", "hints", "cursors"}
        if (set(value) != fields or value["schema_version"] != SESSION_SCHEMA
                or value["network_id"] != network.network_id or value["owner_key_id"] != network.identity.key_id
                or not isinstance(value["peer_key_id"], str) or _KEY.fullmatch(value["peer_key_id"]) is None
                or not hint_identifier(value["query_message_id"]) or key != SESSION_PREFIX + value["query_message_id"]
                or not isinstance(value["query"], str) or not 1 <= len(value["query"].encode("utf-8")) <= 256
                or not hint_expiry(value["expires_at"]) or (not allow_expired and value["expires_at"] <= int(time.time()))
                or len(canonical_bytes(value)) > 32768):
            raise ValueError()
        if value["role"] == "owner":
            hints, cursors = value["hints"], value["cursors"]
            if (not hint_expiry(value["policy_revision"]) or not isinstance(value["policy_sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", value["policy_sha256"]) is None
                    or not isinstance(hints, list) or len(hints) > 16 or any(not hint_projection(item) for item in hints)
                    or not isinstance(cursors, list) or len(cursors) != max(0, (len(hints) + 3) // 4 - 1)
                    or any(not hint_cursor(item) for item in cursors) or len(set(cursors)) != len(cursors)):
                raise ValueError()
            ids = [item["memory_id"] for item in hints]
            if ids != sorted(set(ids)):
                raise ValueError()
        return strict_json_loads(canonical_bytes(value))
    except (MemoryError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise _denied() from None


def _sessions(network: Any, db: Any) -> dict[str, dict[str, Any]]:
    rows = db.execute("""SELECT key,CASE WHEN length(CAST(value AS BLOB))<=32768 THEN value ELSE NULL END AS value
        FROM state WHERE key GLOB 'hint-session:*' LIMIT 65""").fetchall()
    if len(rows) > 64:
        raise _denied()
    return {row["key"]: validate_session(network, row["key"], row["value"]) for row in rows}


def _insert_session(network: Any, db: Any, session: dict[str, Any], rows: Mapping[str, Any]) -> None:
    # Call only in the same existing transport writer transaction as the new
    # query outbox or owner snapshot. Cleanup never touches durable memories.
    key = SESSION_PREFIX + session["query_message_id"]
    validate_session(network, key, session, allow_expired=False)
    if key in rows:
        raise _denied()
    now = int(time.time())
    for expired, value in rows.items():
        if value["expires_at"] <= now:
            db.execute("DELETE FROM state WHERE key=?", (expired,))
    if sum(item["expires_at"] > now for item in rows.values()) >= 64:
        raise _denied()
    db.execute("INSERT INTO state(key,value) VALUES(?,?)", (key, canonical_bytes(session).decode("utf-8")))


def _common_session(network: Any, role: str, query_id: str, peer: str, control: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema_version": SESSION_SCHEMA, "role": role, "network_id": network.network_id,
            "owner_key_id": network.identity.key_id, "peer_key_id": peer, "query_message_id": query_id,
            "query": control["query"], "expires_at": control["expires_at"], "state": "active", "cancellation": None}


def register_requester(network: Any, db: Any, message_id: str, recipients: list[str], content: Mapping[str, Any]) -> None:
    """Only the genuinely new outbox insertion may call this function."""
    if content["kind"] != "hint_control" or content["control"]["kind"] != "query":
        return
    control = content["control"]
    now = int(time.time())
    if len(recipients) != 1 or not now < control["expires_at"] <= now + 300:
        raise _denied()
    _insert_session(network, db, _common_session(network, "requester", message_id, recipients[0], control), _sessions(network, db))


def _session(network: Any, query_id: str, peer: str, role: str, *, connection: Any = None,
             allow_cancelled: bool = False) -> dict[str, Any]:
    with _connection(network, connection) as db:
        value = _sessions(network, db).get(SESSION_PREFIX + query_id)
    if (value is None or value["role"] != role or value["peer_key_id"] != peer or value["expires_at"] <= int(time.time())
            or not allow_cancelled and value["state"] != "active"):
        raise _denied()
    return value


def _outbox(network: Any, message_id: str, recipient: str, *, connection: Any = None) -> dict[str, Any]:
    with _connection(network, connection) as db:
        row = db.execute("SELECT request_id FROM outbox WHERE message_id=?", (message_id,)).fetchone()
        prior = network._outbox_rows(db, row["request_id"], full=True)[0] if row else None
    if prior is None or strict_json_loads(prior["recipients"]) != [recipient]:
        raise _denied()
    return validate_content(bytes(prior["body"]))


def _requester(network: Any, query_id: str, recipient: str, *, connection: Any = None) -> dict[str, Any]:
    session = _session(network, query_id, recipient, "requester", connection=connection)
    if session["expires_at"] > int(time.time()) + 300:
        raise _denied()
    original = _outbox(network, query_id, recipient, connection=connection)
    if original != {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
            "schema_version": HINT_SCHEMA, "kind": "query", "query": session["query"], "expires_at": session["expires_at"]}}:
        raise _denied()
    return session


def _previous_page(network: Any, query_id: str, recipient: str, cursor: str, *, connection: Any = None) -> dict[str, Any]:
    # Select only matching control projections, not every message or share.
    # Duplicate requests may produce the same logical page with different IDs.
    with _connection(network, connection) as db:
        rows = db.execute("""SELECT body,result FROM inbox WHERE sender=?
            AND json_valid(CAST(body AS TEXT))
            AND json_extract(CAST(body AS TEXT),'$.kind')='hint_control'
            AND json_extract(CAST(body AS TEXT),'$.control.kind')='hints'
            AND json_extract(CAST(body AS TEXT),'$.control.query_message_id')=?
            AND json_extract(CAST(body AS TEXT),'$.control.next_cursor')=? ORDER BY rowid LIMIT 2""",
            (recipient, query_id, cursor)).fetchall()
    controls = []
    for row in rows:
        if strict_json_loads(row["result"]).get("state") != "validated_saved":
            raise _denied()
        controls.append(validate_content(bytes(row["body"]))["control"])
    if not controls or controls[0]["expires_at"] <= int(time.time()):
        raise _denied()
    if len(controls) == 2 and {k: v for k, v in controls[0].items() if k != "request_message_id"} != {
            k: v for k, v in controls[1].items() if k != "request_message_id"}:
        raise _denied()
    return controls[0]


def _requester_page(network: Any, control: Mapping[str, Any], recipient: str, *, connection: Any = None) -> tuple[dict[str, Any], dict[str, Any]]:
    session = _requester(network, control["query_message_id"], recipient, connection=connection)
    previous = _previous_page(network, control["query_message_id"], recipient, control["cursor"], connection=connection)
    if previous["expires_at"] > session["expires_at"] or previous["page_index"] >= 3:
        raise _denied()
    return session, previous


def validate_incoming_hints(network: Any, control: Mapping[str, Any], sender: str, *, connection: Any = None) -> None:
    try:
        session = _requester(network, control["query_message_id"], sender, connection=connection)
        request = _outbox(network, control["request_message_id"], sender, connection=connection)
        if request["kind"] != "hint_control" or not int(time.time()) < control["expires_at"] <= session["expires_at"]:
            raise _denied()
        original = request["control"]
        if original["kind"] == "query":
            if control["page_index"] != 0 or control["request_message_id"] != control["query_message_id"]:
                raise _denied()
        elif original["kind"] == "page" and original["query_message_id"] == control["query_message_id"]:
            _, previous = _requester_page(network, original, sender, connection=connection)
            if (control["page_index"] != previous["page_index"] + 1 or control["policy_revision"] != previous["policy_revision"]
                    or control["expires_at"] != previous["expires_at"]):
                raise _denied()
        else:
            raise _denied()
    except (MemoryError, TrustError, ValueError, TypeError, KeyError) as exc:
        if getattr(exc, "retryable", False):
            raise
        raise MemoryError("network_invalid_content") from None


def _inbox(network: Any, message_id: str, sender: str | None = None, *, connection: Any = None) -> tuple[str, dict[str, Any]]:
    if not hint_identifier(message_id):
        raise _denied()
    with _connection(network, connection) as db:
        row = db.execute("SELECT sender,body,result FROM inbox WHERE message_id=?", (message_id,)).fetchone()
    if (row is None or (sender is not None and row["sender"] != sender)
            or strict_json_loads(row["result"]).get("state") != "validated_saved"):
        raise _denied()
    return row["sender"], validate_content(bytes(row["body"]))


def _owner_active(network: Any, query_id: str, recipient: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    session = _session(network, query_id, recipient, "owner")
    _, original = _inbox(network, query_id, recipient)
    policy, peer = policy_for(network, recipient)
    control = original.get("control", {})
    now = int(time.time())
    if (original["kind"] != "hint_control" or control.get("kind") != "query"
            or control["query"] != session["query"] or not now < control["expires_at"] <= now + 300
            or session["expires_at"] != min(control["expires_at"], policy["expires_at"])
            or session["policy_revision"] != policy["revision"]
            or session["policy_sha256"] != hashlib.sha256(canonical_bytes(policy)).hexdigest()
            or not {item["memory_id"] for item in session["hints"]}.issubset(peer["hint_memory_ids"])):
        raise _denied()
    return session, policy, peer


def _owner_snapshot(network: Any, query_id: str, recipient: str) -> dict[str, Any]:
    with network.db() as db:
        db.execute("BEGIN IMMEDIATE")
        rows = _sessions(network, db)
        if SESSION_PREFIX + query_id not in rows:
            row = db.execute("SELECT rowid AS position,sender,body,result FROM inbox WHERE message_id=?", (query_id,)).fetchone()
            if row is None or row["sender"] != recipient or strict_json_loads(row["result"]).get("state") != "validated_saved":
                raise _denied()
            boundary_row = db.execute("SELECT value FROM state WHERE key='hint_recovery_boundary'").fetchone()
            if boundary_row is not None:
                boundary = strict_json_loads(boundary_row["value"])
                if (not isinstance(boundary, dict) or set(boundary) != {"inbox_rowid", "outbox_rowid"}
                        or any(type(item) is not int or not 0 <= item <= 2**53 - 1 for item in boundary.values())
                        or row["position"] <= boundary["inbox_rowid"]):
                    raise _denied()
            original = validate_content(bytes(row["body"]))
            control = original.get("control", {})
            now = int(time.time())
            if (original["kind"] != "hint_control" or control.get("kind") != "query"
                    or not now < control["expires_at"] <= now + 300):
                raise _denied()
            policy, peer = policy_for(network, recipient)
            session = _common_session(network, "owner", query_id, recipient, control)
            hints = _hints(network, control["query"], peer["hint_memory_ids"])
            session.update({"expires_at": min(control["expires_at"], policy["expires_at"]),
                "policy_revision": policy["revision"], "policy_sha256": hashlib.sha256(canonical_bytes(policy)).hexdigest(),
                "hints": hints, "cursors": ["hintcur_" + secrets.token_hex(32) for _ in range(max(0, (len(hints) + 3) // 4 - 1))]})
            _insert_session(network, db, session, rows)
    # This policy check occurs after the snapshot commit. No transport HTTP
    # or nested transport connection is used while holding the writer lock.
    return _owner_active(network, query_id, recipient)[0]


def _request_page(session: Mapping[str, Any], request_id: str, request: Mapping[str, Any]) -> int:
    if request["kind"] != "hint_control":
        raise _denied()
    control = request["control"]
    if control["kind"] == "query" and request_id == session["query_message_id"]:
        return 0
    if control["kind"] == "page" and control["query_message_id"] == session["query_message_id"]:
        try:
            return session["cursors"].index(control["cursor"]) + 1
        except ValueError:
            pass
    raise _denied()


def _page_control(session: Mapping[str, Any], request_id: str, index: int) -> dict[str, Any]:
    return {"schema_version": HINT_SCHEMA, "kind": "hints", "request_message_id": request_id,
        "query_message_id": session["query_message_id"], "page_index": index, "policy_revision": session["policy_revision"],
        "expires_at": session["expires_at"], "hints": session["hints"][index * 4:(index + 1) * 4],
        "next_cursor": session["cursors"][index] if index < len(session["cursors"]) else None}


def _owner_offer(network: Any, control: Mapping[str, Any], recipient: str) -> tuple[dict[str, Any], dict[str, Any]]:
    session, policy, peer = _owner_active(network, control["query_message_id"], recipient)
    _, request = _inbox(network, control["request_message_id"], recipient)
    index = _request_page(session, control["request_message_id"], request)
    if control != _page_control(session, control["request_message_id"], index):
        raise _denied()
    return policy, peer


def _offer(network: Any, offer_id: str, recipient: str, memory_id: str, *, incoming: bool, connection: Any = None) -> dict[str, Any]:
    if incoming:
        _, body = _inbox(network, offer_id, recipient, connection=connection)
    else:
        body = _outbox(network, offer_id, recipient, connection=connection)
    control = body.get("control", {})
    if (body["kind"] != "hint_control" or control.get("kind") != "hints"
            or control["expires_at"] <= int(time.time())
            or memory_id not in {item["memory_id"] for item in control["hints"]}):
        raise _denied()
    if incoming:
        validate_incoming_hints(network, control, recipient, connection=connection)
    else:
        _owner_offer(network, control, recipient)
    return control


def _selection_offers(network: Any, control: Mapping[str, Any], recipient: str, *, incoming: bool, connection: Any = None) -> int:
    expires_at, revision = None, None
    for selected in control["selections"]:
        offer = _offer(network, selected["offer_message_id"], recipient, selected["memory_id"], incoming=incoming, connection=connection)
        if (offer["query_message_id"] != control["query_message_id"]
                or expires_at is not None and offer["expires_at"] != expires_at
                or revision is not None and offer["policy_revision"] != revision):
            raise _denied()
        expires_at, revision = offer["expires_at"], offer["policy_revision"]
    if expires_at is None:
        raise _denied()
    return expires_at


def validate_select(network: Any, control: Mapping[str, Any], recipient: str) -> None:
    _selection_offers(network, control, recipient, incoming=True)


def validate_incoming_transfer(network: Any, body: Mapping[str, Any], sender: str, *, check_share: bool = True, connection: Any = None) -> None:
    """A signed peer cannot skip this endpoint's explicit selection step."""
    try:
        selection = _outbox(network, body["request_message_id"], sender, connection=connection)
        control = selection.get("control", {})
        if (selection["kind"] != "hint_control" or control.get("kind") != "select"
                or control["query_message_id"] != body["query_message_id"]):
            raise _denied()
        expires_at = _selection_offers(network, control, sender, incoming=True, connection=connection)
        if body["expires_at"] != expires_at or body["expires_at"] <= int(time.time()):
            raise _denied()
        if check_share:
            _share_ids(network, body, {item["memory_id"] for item in control["selections"]})
    except (MemoryError, TrustError, ValueError, TypeError, KeyError) as exc:
        if getattr(exc, "retryable", False) or getattr(exc, "code", None) in {
                "share_integer_index_unavailable", "share_source_changed"}:
            raise
        raise MemoryError("network_invalid_content") from None


def _share_ids(network: Any, body: Mapping[str, Any], expected_roots: set[str]) -> set[str]:
    raw = unb64url(body["share"], maximum=MAX_CONTENT_SHARE_BYTES)
    ids: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="hint-check-", dir=network.directory) as temporary:
        source = Path(temporary) / "share.ndjson"
        atomic_write(source, raw, replace=False)
        _scan(source, time.monotonic() + 10, visitor=lambda record, proof: ids.add(record["memory_id"]))
    selected = [frame["record"]["memory_id"] for line in raw.splitlines()
                if (frame := strict_json_loads(line)).get("type") == "record" and frame["selected"]]
    if set(selected) != expected_roots or len(selected) != len(expected_roots):
        raise _denied()
    return ids


def _cancel_binding(network: Any, control: Mapping[str, Any], peer: str, notification_id: str,
                    role: str, *, connection: Any = None) -> dict[str, Any]:
    session = _session(network, control["query_message_id"], peer, role, connection=connection, allow_cancelled=True)
    cancellation = {"message_id": notification_id, "offer_message_id": control["offer_message_id"], "expires_at": control["expires_at"]}
    if (control["expires_at"] <= int(time.time()) or control["expires_at"] > session["expires_at"]
            or session["state"] == "cancelled" and session["cancellation"] != cancellation):
        raise _denied()
    if role == "requester":
        original = _outbox(network, control["query_message_id"], peer, connection=connection)
        _, offered = _inbox(network, control["offer_message_id"], peer, connection=connection)
    else:
        _, original = _inbox(network, control["query_message_id"], peer, connection=connection)
        offered = _outbox(network, control["offer_message_id"], peer, connection=connection)
    query, offer = original.get("control", {}), offered.get("control", {})
    if (original["kind"] != "hint_control" or query.get("kind") != "query" or query["query"] != session["query"]
            or not int(time.time()) < query["expires_at"] <= int(time.time()) + 300
            or session["expires_at"] > query["expires_at"]
            or role == "requester" and session["expires_at"] != query["expires_at"]
            or offered["kind"] != "hint_control" or offer.get("kind") != "hints"
            or offer["query_message_id"] != control["query_message_id"] or offer["expires_at"] != control["expires_at"]):
        raise _denied()
    if role == "owner":
        # Cancellation reduces authority. Validate the frozen issued page,
        # without requiring the now possibly revoked memory sharing policy.
        _, request = _inbox(network, offer["request_message_id"], peer, connection=connection)
        if offer != _page_control(session, offer["request_message_id"], _request_page(session, offer["request_message_id"], request)):
            raise _denied()
    elif session["state"] == "active":
        validate_incoming_hints(network, offer, peer, connection=connection)
    return session


def register_cancellation(network: Any, connection: Any, message_id: str, recipient: str, content: Mapping[str, Any]) -> None:
    """Called only with a new notification/ack insertion in the writer txn."""
    control = content.get("control", {})
    if content["kind"] != "hint_control" or control.get("kind") not in {"cancel", "cancel_ack"}:
        return
    if not connection.in_transaction:
        raise RuntimeError("cancellation requires the existing transport transaction")
    if control["kind"] == "cancel":
        notification, notification_id, role = control, message_id, "requester"
    else:
        _, request = _inbox(network, control["request_message_id"], recipient, connection=connection)
        notification = request.get("control", {})
        if (request["kind"] != "hint_control" or notification.get("kind") != "cancel"
                or notification["query_message_id"] != control["query_message_id"] or notification["expires_at"] != control["expires_at"]):
            raise _denied()
        notification_id, role = control["request_message_id"], "owner"
    session = _cancel_binding(network, notification, recipient, notification_id, role, connection=connection)
    updated = {**session, "state": "cancelled", "cancellation": {"message_id": notification_id,
               "offer_message_id": notification["offer_message_id"], "expires_at": notification["expires_at"]}}
    key = SESSION_PREFIX + notification["query_message_id"]
    validate_session(network, key, updated, allow_expired=False)
    connection.execute("UPDATE state SET value=? WHERE key=?", (canonical_bytes(updated).decode(), key))


def _cancelled_guard(network: Any, control: Mapping[str, Any], peer: str, message_id: str, role: str) -> None:
    session = _cancel_binding(network, control, peer, message_id, role)
    if session["state"] != "cancelled":
        raise _denied()
    original = (_outbox(network, message_id, peer) if role == "requester" else _inbox(network, message_id, peer)[1])
    if original != {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": control}:
        raise _denied()


def _ack_binding(network: Any, control: Mapping[str, Any], peer: str, *, incoming: bool) -> None:
    role = "requester" if incoming else "owner"
    session = _session(network, control["query_message_id"], peer, role, allow_cancelled=True)
    saved = session["cancellation"]
    if (session["state"] != "cancelled" or saved["message_id"] != control["request_message_id"]
            or saved["expires_at"] != control["expires_at"]):
        raise _denied()
    notification = {"schema_version": HINT_SCHEMA, "kind": "cancel", "query_message_id": control["query_message_id"],
                    "offer_message_id": saved["offer_message_id"], "expires_at": saved["expires_at"]}
    _cancelled_guard(network, notification, peer, control["request_message_id"], role)


def validate_incoming_cancel_ack(network: Any, control: Mapping[str, Any], sender: str) -> None:
    try:
        _ack_binding(network, control, sender, incoming=True)
    except (MemoryError, TrustError) as exc:
        if getattr(exc, "retryable", False):
            raise
        raise MemoryError("network_invalid_content") from None


def query_id_for_content(content: Mapping[str, Any], message_id: str) -> str | None:
    if content["kind"] == "hint_batch_transfer":
        return content["query_message_id"]
    if content["kind"] == "hint_control":
        control = content["control"]
        if control["kind"] == "query":
            return message_id
        if control["kind"] in {"page", "select", "hints"}:
            return control["query_message_id"]
    return None


def stopped_query_ids(network: Any, connection: Any) -> set[str]:
    return {value["query_message_id"] for value in _sessions(network, connection).values() if value["state"] == "cancelled"}


def stopped(network: Any, content: Mapping[str, Any], message_id: str) -> bool:
    query_id = query_id_for_content(content, message_id)
    if query_id is None:
        return False
    with network.db() as connection:
        return query_id in stopped_query_ids(network, connection)


def cancellation_result(network: Any, content: Mapping[str, Any], message_id: str, *, connection: Any = None) -> dict[str, Any]:
    control = content.get("control", {})
    if content["kind"] != "hint_control" or control.get("kind") not in {"cancel", "cancel_ack"}:
        return {}
    with _connection(network, connection) as db:
        session = _sessions(network, db).get(SESSION_PREFIX + control["query_message_id"])
    notification_id = message_id if control["kind"] == "cancel" else control["request_message_id"]
    if session is None or session["state"] != "cancelled" or session["cancellation"]["message_id"] != notification_id:
        return {}
    return {"cancellation": {"query_message_id": control["query_message_id"], "local_cancelled": True}}


def guard(network: Any, body: Mapping[str, Any], recipients: list[str], own_message_id: str | None = None) -> None:
    """Recheck immediately before send-start, including frozen outbox retries."""
    kind, control = body["kind"], body.get("control", {})
    if kind not in {"hint_control", "hint_batch_transfer"}:
        return
    if len(recipients) != 1:
        raise _denied()
    recipient = recipients[0]
    if kind == "hint_control" and control["kind"] == "cancel":
        if own_message_id is None:
            raise _denied()
        _cancelled_guard(network, control, recipient, own_message_id, "requester")
        return
    if kind == "hint_control" and control["kind"] == "cancel_ack":
        _ack_binding(network, control, recipient, incoming=False)
        return
    if kind == "hint_control" and control["kind"] == "select":
        validate_select(network, control, recipient)
        return
    if kind == "hint_control" and control["kind"] == "query":
        now = int(time.time())
        if not now < control["expires_at"] <= now + 300:
            raise _denied()
        if own_message_id is not None:
            session = _requester(network, own_message_id, recipient)
            if control["query"] != session["query"] or control["expires_at"] != session["expires_at"]:
                raise _denied()
        return
    if kind == "hint_control" and control["kind"] == "page":
        _requester_page(network, control, recipient)
        return
    if kind == "hint_control" and control["kind"] == "refusal":
        return
    policy, peer = policy_for(network, recipient)
    if kind == "hint_control":
        checked_policy, _ = _owner_offer(network, control, recipient)
        if canonical_bytes(checked_policy) != canonical_bytes(policy):
            raise _denied()
    else:
        _, request = _inbox(network, body["request_message_id"], recipient)
        selected = request.get("control", {})
        if (request["kind"] != "hint_control" or selected.get("kind") != "select"
                or selected["query_message_id"] != body["query_message_id"]):
            raise _denied()
        expires_at = _selection_offers(network, selected, recipient, incoming=False)
        if (body["expires_at"] != expires_at or body["expires_at"] <= int(time.time())
                or not _share_ids(network, body, {item["memory_id"] for item in selected["selections"]}).issubset(peer["record_memory_ids"])):
            raise _denied()
        # A bounded share parse can outlast this query. Recheck its offers
        # before the final policy checkpoint and actual transport send.
        if _selection_offers(network, selected, recipient, incoming=False) != body["expires_at"]:
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
                if len(result) == 16:
                    break
    return result


def respond_to(network: Any, message_id: str) -> Mapping[str, Any]:
    sender, request = _inbox(network, message_id)
    if request["kind"] != "hint_control" or request["control"]["kind"] not in {"query", "page", "select", "cancel"}:
        raise _denied()
    request_id = "req_hint_response_" + hashlib.sha256(message_id.encode("ascii")).hexdigest()[:32]
    with network.db() as db:
        prior = (network._outbox_rows(db, request_id, full=True) or [None])[0]
    if prior is not None:
        if request["control"]["kind"] == "cancel":
            prior = network._queue_body(request_id, [sender], hashlib.sha256(canonical_bytes({"respond_to": message_id})).hexdigest(),
                                        bytes(prior["body"]))
        return network._deliver(prior, [sender])
    if request["control"]["kind"] == "cancel":
        control = request["control"]
        content = {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
            "schema_version": HINT_SCHEMA, "kind": "cancel_ack", "request_message_id": message_id,
            "query_message_id": control["query_message_id"], "expires_at": control["expires_at"]}}
        try:
            # The queue hook verifies the raw binding and marks the session
            # in this same transaction, before any control/relay HTTP call.
            prior = network._queue_body(request_id, [sender], hashlib.sha256(canonical_bytes({"respond_to": message_id})).hexdigest(),
                                        canonical_bytes(validate_content(content)))
        except MemoryError as exc:
            if exc.code != "network_hint_not_available":
                raise
            refusal = {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
                "schema_version": HINT_SCHEMA, "kind": "refusal", "request_message_id": message_id, "reason": "not_available"}}
            return network._send_hint_response(request_id, sender, refusal, message_id)
        return network._deliver(prior, [sender])
    # A cancelled existing response is returned as stopped without authority
    # refresh above; new ordinary responses still require current membership.
    # A live authority can authorize local queue preparation while all relay
    # nodes are offline. Actual delivery still refreshes each relay binding.
    current = network._status("nonce_" + secrets.token_hex(16))["roster"]
    members = network._members(current)
    if any(key not in members or not {"send", "receive"}.issubset(members[key]["scope"])
           for key in (sender, network.identity.key_id)):
        raise _denied()
    control = request["control"]
    try:
        policy, peer = policy_for(network, sender)
        if control["kind"] in {"query", "page"}:
            session = (_owner_snapshot(network, message_id, sender) if control["kind"] == "query"
                       else _owner_active(network, control["query_message_id"], sender)[0])
            index = _request_page(session, message_id, request)
            body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": _page_control(session, message_id, index)}
        else:
            expires_at = _selection_offers(network, control, sender, incoming=False)
            with tempfile.TemporaryDirectory(prefix="hint-share-", dir=network.directory) as temporary:
                destination = Path(temporary) / "share.ndjson"
                export_share(network.client_config.path, destination,
                    {"schema_version": "universal-memory-selection/v1", "memory_ids": [item["memory_id"] for item in control["selections"]]},
                    maximum_seconds=10, authorized_memory_ids=set(peer["record_memory_ids"]))
                if destination.stat().st_size > MAX_CONTENT_SHARE_BYTES:
                    raise _denied()
                share = b64url(destination.read_bytes())
            body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_batch_transfer", "request_message_id": message_id,
                "query_message_id": control["query_message_id"], "expires_at": expires_at, "share": share}
        guard(network, body, [sender])
    except (MemoryError, TrustError) as exc:
        if (getattr(exc, "retryable", False) and exc.code != "share_work_limit"
                or exc.code in {"share_integer_index_unavailable", "share_source_changed"}):
            raise
        body = {"schema_version": CONTENT_SCHEMA, "kind": "hint_control", "control": {
            "schema_version": HINT_SCHEMA, "kind": "refusal", "request_message_id": message_id, "reason": "not_available"}}
    return network._send_hint_response(request_id, sender, validate_content(body), message_id)
