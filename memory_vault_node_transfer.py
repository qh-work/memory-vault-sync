"""Explicit, issuer-authorized transfer of a frozen ciphertext node.

No import starts a service, reads a configuration, imports optional crypto or
network libraries, transfers endpoint keys, or removes source data. The issuer
grant is a deliberate admission decision, not a generic node status response.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any, Mapping

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_network_crypto import (
    PublicKeyTrust, digest, document, document_sha256, integer, object_fields,
    opaque, encryption_public_descriptor as public_encryption_key, public_signing_key, verify_envelope,
)
from memory_vault_network_control import _window, verify_request, verify_roster
from memory_vault_nodes import authorized_node, sign_node_request, verify_directory, verify_node_request
from memory_vault_relay import Relay, RelayError, _read
from memory_vault_trust import TrustError
import memory_vault_storage as storage

SNAPSHOT_SCHEMA = "memory-vault-node-transfer-snapshot/v1"
GRANT_SCHEMA = "memory-vault-node-transfer-grant/v1"
RECEIPT_SCHEMA = "memory-vault-node-transfer-complete/v1"
PROGRESS_SCHEMA = "memory-vault-node-transfer-progress/v1"
EXPORT_KEY = "node_transfer_export"
IMPORT_KEY = "node_transfer_import"
MAX_SNAPSHOT_BYTES = 6 * 1024 * 1024
MAX_MESSAGES = 4096
MAX_MEMBERS = 256
MAX_RECEIPTS = MAX_MESSAGES * 32
MAX_OBJECT_BYTES = 256 * 1024 * 1024
MAX_OPERATION_SECONDS = 10


def _require(value: Any, code: str = "node_transfer_invalid") -> None:
    if not value:
        raise RelayError(code)


def _deadline(seconds: int, maximum: int = 60) -> float:
    _require(type(seconds) is int and 1 <= seconds <= maximum, "node_transfer_invalid_budget")
    return time.monotonic() + seconds


def _check(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RelayError("node_transfer_budget_exhausted", retryable=True)


def _descriptor(value: Any) -> dict[str, Any]:
    from memory_vault_network import origin
    raw = object_fields(value, {"signing_key", "base_url", "storage_epoch"})
    public_signing_key(raw["signing_key"])
    origin(raw["base_url"])
    opaque(raw["storage_epoch"])
    return raw


def _sign(payload: Mapping[str, Any], identity: Any) -> dict[str, Any]:
    return {"payload": dict(payload), "proof": identity.sign_message(payload)}


def _verify_signed(value: Any, trust: PublicKeyTrust, maximum: int) -> dict[str, Any]:
    raw = object_fields(document(value, maximum=maximum), {"payload", "proof"})
    _require(isinstance(raw["payload"], dict))
    try:
        trust.verify_message(raw["payload"], raw["proof"])
    except TrustError as exc:
        raise RelayError(exc.code) from None
    return raw["payload"]


def _checkpoint(roster: Mapping[str, Any], nodes: Mapping[str, Any]) -> dict[str, Any]:
    return {"roster_sha256": document_sha256(roster), "roster_version": roster["payload"]["version"],
            "node_directory_sha256": document_sha256(nodes), "node_directory_version": nodes["payload"]["version"]}


def _member_state(payload: Mapping[str, Any]) -> str:
    return document_sha256({"members": payload["members"], "invitations": payload["invitations"]})


def _counts(payload: Mapping[str, Any]) -> dict[str, int]:
    return {"members": len(payload["members"]), "invitations": len(payload["invitations"]),
            "messages": len(payload["messages"]), "receipts": len(payload["receipts"]),
            "objects": len(payload["messages"]), "object_bytes": sum(row["object_bytes"] for row in payload["messages"])}


def _historical_payloads(payload: Mapping[str, Any], issuers: PublicKeyTrust, network_id: str, deadline: float) -> dict[str, Any]:
    result, versions = {}, {}
    for entry in payload["rosters"]:
        _check(deadline)
        object_fields(entry, {"sha256", "document"})
        key = digest(entry["sha256"])
        _require(key == document_sha256(entry["document"]) and key not in result, "node_transfer_roster_mismatch")
        checked = verify_roster(entry["document"], issuers, network_id=network_id, allow_expired=True)
        _require(checked["version"] not in versions or versions[checked["version"]] == key, "node_transfer_roster_fork")
        versions[checked["version"]] = key
        result[key] = checked
    return result


def _snapshot(value: Any, issuers: PublicKeyTrust, network_id: str, deadline: float) -> dict[str, Any]:
    raw = object_fields(document(value, maximum=MAX_SNAPSHOT_BYTES), {"payload", "proof"})
    payload = object_fields(raw["payload"], {"schema_version", "network_id", "transfer_id", "source", "created_at",
        "source_checkpoint", "members", "invitations", "rosters", "messages", "receipts", "counts", "member_state_sha256"})
    source = _descriptor(payload["source"])
    _verify_signed(raw, PublicKeyTrust([source["signing_key"]]), MAX_SNAPSHOT_BYTES)
    _require(payload["schema_version"] == SNAPSHOT_SCHEMA and payload["network_id"] == network_id, "node_transfer_network_mismatch")
    opaque(payload["transfer_id"])
    integer(payload["created_at"])
    checkpoint = object_fields(payload["source_checkpoint"], {"roster_sha256", "roster_version", "node_directory_sha256", "node_directory_version"})
    for name in ("roster_sha256", "node_directory_sha256"):
        digest(checkpoint[name])
    for name in ("roster_version", "node_directory_version"):
        integer(checkpoint[name], minimum=1)
    for name, limit in (("members", MAX_MEMBERS), ("invitations", MAX_MEMBERS), ("rosters", MAX_MESSAGES + 1),
                        ("messages", MAX_MESSAGES), ("receipts", MAX_RECEIPTS)):
        _require(isinstance(payload[name], list) and len(payload[name]) <= limit, "node_transfer_snapshot_limit")
    rosters = _historical_payloads(payload, issuers, network_id, deadline)
    _require(checkpoint["roster_sha256"] in rosters and rosters[checkpoint["roster_sha256"]]["version"] == checkpoint["roster_version"], "node_transfer_roster_mismatch")
    _require(all(roster["version"] <= checkpoint["roster_version"] for roster in rosters.values()), "node_transfer_roster_mismatch")
    members, invitation_ids = {}, set()
    for member in payload["members"]:
        _check(deadline)
        object_fields(member, {"key_id", "encryption_key", "scopes", "invite_id"})
        key = opaque(member["key_id"])
        public_encryption_key(member["encryption_key"])
        scopes = member["scopes"]
        _require(isinstance(scopes, list) and bool(scopes) and all(scope in {"send", "receive"} for scope in scopes)
                 and scopes == sorted(set(scopes)) and key not in members, "node_transfer_member_state_invalid")
        if member["invite_id"] is not None:
            invite_id = opaque(member["invite_id"])
            _require(invite_id not in invitation_ids, "node_transfer_member_state_invalid")
            invitation_ids.add(invite_id)
        members[key] = member
    invites = set()
    for row in payload["invitations"]:
        object_fields(row, {"invite_id", "invite_sha256", "request_sha256", "result"})
        invite = opaque(row["invite_id"])
        digest(row["invite_sha256"])
        digest(row["request_sha256"])
        result = object_fields(row["result"], {"state", "network_id", "member_key_id", "invite_id", "roster_version"})
        _require(result["state"] == "joined" and result["network_id"] == network_id and result["invite_id"] == invite
                 and result["member_key_id"] in members and members[result["member_key_id"]]["invite_id"] == invite
                 and invite not in invites, "node_transfer_member_state_invalid")
        integer(result["roster_version"], minimum=1)
        invites.add(invite)
    _require(invites == invitation_ids, "node_transfer_member_state_invalid")
    messages, hashes, sequence = {}, set(), 0
    for row in payload["messages"]:
        _check(deadline)
        object_fields(row, {"sequence", "message_id", "envelope_sha256", "object_bytes", "sender_key_id", "roster_sha256", "recipient_key_ids"})
        number = integer(row["sequence"], minimum=1)
        _require(number > sequence, "node_transfer_sequence_invalid")
        sequence = number
        message_id, content_hash = opaque(row["message_id"]), digest(row["envelope_sha256"])
        _require(message_id not in messages and content_hash not in hashes and row["roster_sha256"] in rosters
                 and 1 <= integer(row["object_bytes"]) <= 6 * 1024 * 1024, "node_transfer_message_invalid")
        recipients = row["recipient_key_ids"]
        _require(isinstance(recipients, list) and 1 <= len(recipients) <= 32 and recipients == sorted(set(recipients)), "node_transfer_message_invalid")
        for key in [opaque(row["sender_key_id"]), *recipients]:
            opaque(key)
            _require(key in members, "node_transfer_membership_missing")
        messages[message_id] = row
        hashes.add(content_hash)
    sequence, pairs, requests = 0, set(), set()
    for row in payload["receipts"]:
        _check(deadline)
        object_fields(row, {"sequence", "message_id", "key_id", "request_id", "request_sha256", "document", "result"})
        number = integer(row["sequence"], minimum=1)
        _require(number > sequence and row["message_id"] in messages, "node_transfer_receipt_invalid")
        sequence = number
        message = messages[row["message_id"]]
        roster = rosters[message["roster_sha256"]]
        trust = PublicKeyTrust([member["signing_key"] for member in roster["members"]])
        receipt = row["document"]
        checked = verify_request(receipt, trust, network_id=network_id, action="ack", now=receipt["payload"]["issued_at"])
        pair, request = (row["message_id"], row["key_id"]), (row["key_id"], row["request_id"])
        _require(row["key_id"] in message["recipient_key_ids"] and receipt["proof"]["key_id"] == row["key_id"]
                 and checked["request_id"] == row["request_id"] and document_sha256(receipt) == row["request_sha256"]
                 and checked["body"] == {"message_id": row["message_id"], "envelope_sha256": message["envelope_sha256"], "state": "validated_saved"}
                 and pair not in pairs and request not in requests, "node_transfer_receipt_invalid")
        _require(row["result"] == {"state": "validated_saved", "message_id": row["message_id"], "envelope_sha256": message["envelope_sha256"],
                 "recipient_key_id": row["key_id"], "receipt_sequence": number}, "node_transfer_receipt_invalid")
        pairs.add(pair)
        requests.add(request)
    _require(payload["counts"] == _counts(payload) and payload["counts"]["object_bytes"] <= MAX_OBJECT_BYTES, "node_transfer_snapshot_limit")
    _require(digest(payload["member_state_sha256"]) == _member_state(payload), "node_transfer_member_state_invalid")
    return payload


def _object(encoded: bytes, row: Mapping[str, Any], payload: Mapping[str, Any], issuers: PublicKeyTrust) -> None:
    _require(len(encoded) == row["object_bytes"] and hashlib.sha256(encoded).hexdigest() == row["envelope_sha256"], "node_transfer_object_mismatch")
    value = document(encoded, maximum=6 * 1024 * 1024)
    _require(canonical_bytes(value) == encoded, "node_transfer_noncanonical_object")
    historical = next(item["document"] for item in payload["rosters"] if item["sha256"] == row["roster_sha256"])
    roster = verify_roster(historical, issuers, network_id=payload["network_id"], allow_expired=True)
    members = {member["signing_key"]["key_id"]: member for member in roster["members"]}
    envelope = verify_envelope(value, PublicKeyTrust([member["signing_key"] for member in roster["members"]]), network_id=payload["network_id"])
    _require(all(envelope[key] == row[key] for key in ("message_id", "sender_key_id", "recipient_key_ids", "roster_sha256"))
             and envelope["roster_version"] == roster["version"], "node_transfer_object_binding_mismatch")
    for key, scope in [(row["sender_key_id"], "send"), *[(key, "receive") for key in row["recipient_key_ids"]]]:
        member = members.get(key)
        _require(member is not None and member["status"] == "active" and scope in member["scope"], "node_transfer_historical_permission_invalid")
    expected = {members[key]["encryption_key"]["key_id"] for key in row["recipient_key_ids"]}
    actual = [item.get("header", {}).get("kid") for item in envelope["jwe"]["recipients"]]
    _require(len(actual) == len(expected) and set(actual) == expected, "node_transfer_recipient_mismatch")


def prepare_export(relay: Relay, transfer_id: str, *, maximum_seconds: int = 60) -> Mapping[str, Any]:
    """Freeze committed rows and signed ciphertext metadata under a DB lock."""
    opaque(transfer_id)
    deadline = _deadline(maximum_seconds)
    with relay._transaction() as db:
        relay._node_current(db, "export")
        _require(relay._get(db, IMPORT_KEY) is None or relay._get(db, IMPORT_KEY)["state"] == "committed", "node_transfer_import_incomplete")
        existing = relay._get(db, EXPORT_KEY)
        if existing is not None:
            _require(existing["transfer_id"] == transfer_id, "node_transfer_export_already_frozen")
            _snapshot(existing["snapshot"], relay.issuers, relay.network_id, deadline)
            return existing["snapshot"]
        if relay._get(db, "draining") is None:
            relay._set(db, "draining", {"state": "draining", "started_at": int(time.time()),
                "messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
                "receipts": db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0],
                "members": db.execute("SELECT COUNT(*) FROM members").fetchone()[0]})
        roster, _ = relay._current(db)
        payload = {"schema_version": SNAPSHOT_SCHEMA, "network_id": relay.network_id, "transfer_id": transfer_id,
                   "source": relay.node_descriptor(), "created_at": int(time.time()),
                   "source_checkpoint": _checkpoint(roster, relay._get(db, "node_directory")),
                   "members": [], "invitations": [], "rosters": [], "messages": [], "receipts": []}
        for row in db.execute("SELECT * FROM members ORDER BY key_id"):
            payload["members"].append({"key_id": row["key_id"], "encryption_key": strict_json_loads(row["encryption_key"]),
                "scopes": strict_json_loads(row["scopes"]), "invite_id": row["invite_id"]})
        for row in db.execute("SELECT * FROM invitations ORDER BY invite_id"):
            payload["invitations"].append({"invite_id": row["invite_id"], "invite_sha256": row["invite_sha256"],
                "request_sha256": row["request_sha256"], "result": strict_json_loads(row["result"])})
        rosters = {document_sha256(roster): roster}
        metadata_bytes = 0
        for row in db.execute("SELECT * FROM messages ORDER BY sequence"):
            _check(deadline)
            historical = strict_json_loads(row["roster"])
            key = document_sha256(historical)
            if key not in rosters:
                metadata_bytes += len(canonical_bytes(historical))
                rosters[key] = historical
            recipients = [item[0] for item in db.execute("SELECT key_id FROM recipients WHERE message_id=? ORDER BY key_id", (row["message_id"],))]
            message = {name: row[name] for name in ("sequence", "message_id", "envelope_sha256", "object_bytes", "sender_key_id")}
            message.update(roster_sha256=key, recipient_key_ids=recipients)
            metadata_bytes += len(canonical_bytes(message))
            _require(metadata_bytes <= MAX_SNAPSHOT_BYTES, "node_transfer_snapshot_limit")
            payload["messages"].append(message)
        payload["rosters"] = [{"sha256": key, "document": value} for key, value in sorted(rosters.items())]
        for row in db.execute("SELECT * FROM receipts ORDER BY sequence"):
            _check(deadline)
            receipt = {name: row[name] for name in ("sequence", "message_id", "key_id", "request_id", "request_sha256")}
            receipt.update(document=strict_json_loads(row["document"]), result=strict_json_loads(row["result"]))
            metadata_bytes += len(canonical_bytes(receipt))
            _require(metadata_bytes <= MAX_SNAPSHOT_BYTES, "node_transfer_snapshot_limit")
            payload["receipts"].append(receipt)
        payload.update(counts=_counts(payload), member_state_sha256=_member_state(payload))
        snapshot = _sign(payload, relay.node_identity)
        _snapshot(snapshot, relay.issuers, relay.network_id, deadline)
        for row in payload["messages"]:
            _check(deadline)
            _object(_read(relay.object_directory / (row["envelope_sha256"] + ".json"), relay.limits["maximum_envelope_bytes"]), row, payload, relay.issuers)
        _check(deadline)
        relay._set(db, EXPORT_KEY, {"transfer_id": transfer_id, "snapshot_sha256": document_sha256(snapshot), "snapshot": snapshot, "receipt": None})
        return snapshot


def issue_transfer_grant(issuer: Any, snapshot: Mapping[str, Any], target: Mapping[str, Any],
                         current_roster: Mapping[str, Any], current_nodes: Mapping[str, Any], *,
                         now: int | None = None, expires_at: int | None = None) -> Mapping[str, Any]:
    """OFFLINE deliberate issuer approval of the full source admission state.

    Call only after operator review. Older relays lack original join proofs;
    this new issuer signature, not the node's self-reported member rows, grants
    permission to carry those exact admissions to this exact destination.
    """
    now = int(time.time()) if now is None else integer(now)
    expires_at = now + 300 if expires_at is None else expires_at
    trust = PublicKeyTrust([issuer.public_descriptor()])
    network_id = opaque(current_roster["payload"]["network_id"])
    # This is an explicit offline issuer decision about its selected policy
    # files, not a status endpoint blessing data received from a node. Online
    # transfer still requires independently fresh status for these exact hashes.
    roster = verify_roster(current_roster, trust, network_id=network_id, now=now, allow_expired=True)
    nodes = verify_directory(current_nodes, trust, network_id=network_id, now=now, allow_expired=True)
    payload = _snapshot(snapshot, trust, network_id, _deadline(60))
    source, target = _descriptor(payload["source"]), _descriptor(target)
    _require(source["signing_key"]["key_id"] != target["signing_key"]["key_id"] and source["base_url"] != target["base_url"]
             and source["storage_epoch"] != target["storage_epoch"], "node_transfer_distinct_target_required")
    for descriptor, action in ((source, "export"), (target, "import")):
        entry = authorized_node(nodes, descriptor["signing_key"]["key_id"], action,
                                base_url=descriptor["base_url"], storage_epoch=descriptor["storage_epoch"])
        _require(entry["signing_key"] == descriptor["signing_key"], "node_transfer_node_identity_mismatch")
    _require(payload["source_checkpoint"]["roster_version"] <= roster["version"]
             and payload["source_checkpoint"]["node_directory_version"] <= nodes["version"], "node_transfer_checkpoint_rollback")
    for prefix, current in (("roster", current_roster), ("node_directory", current_nodes)):
        old_version = payload["source_checkpoint"][prefix + "_version"]
        old_hash = payload["source_checkpoint"][prefix + "_sha256"]
        current_version = current["payload"]["version"]
        if old_version == current_version:
            _require(old_hash == document_sha256(current), "node_transfer_checkpoint_fork")
        elif old_version + 1 == current_version:
            _require(old_hash == current["payload"]["previous_sha256"], "node_transfer_checkpoint_chain_mismatch")
    grant = {"schema_version": GRANT_SCHEMA, "network_id": network_id, "transfer_id": payload["transfer_id"],
             "snapshot_sha256": document_sha256(snapshot), "source": source, "target": target,
             "member_state_sha256": payload["member_state_sha256"], "counts": payload["counts"],
             "current_checkpoint": _checkpoint(current_roster, current_nodes), "issued_at": now, "expires_at": expires_at,
             "admission_transfer_authorized": True}
    _window(grant, now=now)
    return _sign(grant, issuer)


def _grant(value: Any, relay: Relay, db: Any, action: str) -> dict[str, Any]:
    payload = object_fields(_verify_signed(value, relay.issuers, 65536), {"schema_version", "network_id", "transfer_id", "snapshot_sha256",
        "source", "target", "member_state_sha256", "counts", "current_checkpoint", "issued_at", "expires_at", "admission_transfer_authorized"})
    _require(payload["schema_version"] == GRANT_SCHEMA and payload["network_id"] == relay.network_id
             and payload["admission_transfer_authorized"] is True, "node_transfer_grant_invalid")
    _window(payload)
    opaque(payload["transfer_id"])
    digest(payload["snapshot_sha256"])
    digest(payload["member_state_sha256"])
    source, target = _descriptor(payload["source"]), _descriptor(payload["target"])
    _require(source["signing_key"]["key_id"] != target["signing_key"]["key_id"] and source["base_url"] != target["base_url"]
             and source["storage_epoch"] != target["storage_epoch"], "node_transfer_distinct_target_required")
    relay._node_current(db, action)
    nodes_doc = relay._get(db, "node_directory")
    nodes = verify_directory(nodes_doc, relay.issuers, network_id=relay.network_id, allow_expired=True)
    roster, _ = relay._current(db)
    _require(payload["current_checkpoint"] == _checkpoint(roster, nodes_doc), "node_transfer_current_checkpoint_required")
    _require((source if action == "export" else target) == relay.node_descriptor(), "node_transfer_wrong_node")
    for descriptor, permission in ((source, "export"), (target, "import")):
        entry = authorized_node(nodes, descriptor["signing_key"]["key_id"], permission,
                                base_url=descriptor["base_url"], storage_epoch=descriptor["storage_epoch"])
        _require(entry["signing_key"] == descriptor["signing_key"], "node_transfer_node_identity_mismatch")
    return payload


def _bound_snapshot(snapshot: Mapping[str, Any], grant: Mapping[str, Any], relay: Relay, deadline: float) -> dict[str, Any]:
    _require(document_sha256(snapshot) == grant["snapshot_sha256"], "node_transfer_snapshot_mismatch")
    payload = _snapshot(snapshot, relay.issuers, relay.network_id, deadline)
    _require(payload["transfer_id"] == grant["transfer_id"] and payload["source"] == grant["source"]
             and payload["member_state_sha256"] == grant["member_state_sha256"] and payload["counts"] == grant["counts"], "node_transfer_grant_binding_mismatch")
    return payload


def _empty_target(relay: Relay, db: Any, payload: Mapping[str, Any]) -> None:
    _require(relay._get(db, "draining") is None and relay._get(db, EXPORT_KEY) is None, "node_transfer_target_not_empty")
    for table in ("messages", "recipients", "receipts", "invitations", "challenges"):
        _require(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0, "node_transfer_target_not_empty")
    members = {row["key_id"]: row for row in payload["members"]}
    for row in db.execute("SELECT * FROM members"):
        expected = members.get(row["key_id"])
        _require(row["key_id"] in relay.initial and row["invite_id"] is None and expected is not None
                 and strict_json_loads(row["encryption_key"]) == expected["encryption_key"]
                 and strict_json_loads(row["scopes"]) == expected["scopes"], "node_transfer_target_not_empty")


def _capacity(relay: Relay, payload: Mapping[str, Any], deadline: float) -> None:
    counts = payload["counts"]
    _require(counts["members"] <= relay.limits["maximum_members"] and counts["invitations"] <= relay.limits["maximum_control_rows"]
             and counts["messages"] <= relay.limits["maximum_messages"] and counts["object_bytes"] <= relay.limits["maximum_object_bytes"], "node_transfer_capacity")
    actual_count, actual_bytes = relay._object_usage()
    missing_count, missing_bytes = 0, 0
    for row in payload["messages"]:
        _check(deadline)
        _require(row["object_bytes"] <= relay.limits["maximum_envelope_bytes"], "node_transfer_capacity")
        path = relay.object_directory / (row["envelope_sha256"] + ".json")
        if path.exists() or path.is_symlink():
            value = _read(path, relay.limits["maximum_envelope_bytes"])
            _require(len(value) == row["object_bytes"] and hashlib.sha256(value).hexdigest() == row["envelope_sha256"], "node_transfer_object_mismatch")
        else:
            missing_count += 1
            missing_bytes += row["object_bytes"]
    _require(actual_count + missing_count <= relay.limits["maximum_messages"]
             and actual_bytes + missing_bytes <= relay.limits["maximum_object_bytes"], "node_transfer_capacity")


def _progress(relay: Relay, state: Mapping[str, Any]) -> Mapping[str, Any]:
    if state["state"] == "committed":
        return {"state": "committed", "receipt": state["receipt"]}
    payload = {"schema_version": PROGRESS_SCHEMA, "network_id": relay.network_id,
               "transfer_id": state["transfer_id"], "snapshot_sha256": state["snapshot_sha256"],
               "target": relay.node_descriptor(), "next_object": state["next_object"],
               "total_objects": state["snapshot"]["payload"]["counts"]["objects"]}
    return {"state": "receiving", "progress": _sign(payload, relay.node_identity)}


def _receive_transfer(relay: Relay, value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Handle one authenticated begin/object/commit; no remote read endpoint."""
    deadline = _deadline(MAX_OPERATION_SECONDS)
    raw = document(value, maximum=relay.limits["maximum_request_bytes"])
    _require(isinstance(raw, dict) and {"request", "grant"} <= set(raw))
    with relay._transaction() as db:
        grant = _grant(raw["grant"], relay, db, "import")
        request = verify_node_request(raw["request"], PublicKeyTrust([grant["source"]["signing_key"]]), network_id=relay.network_id, action="export")
        body = request["body"]
        base = {"transfer_id": grant["transfer_id"], "snapshot_sha256": grant["snapshot_sha256"], "grant_sha256": document_sha256(raw["grant"])}
        phase = body.get("phase")
        _require(phase in {"begin", "object", "commit"}, "node_transfer_phase_invalid")
        expected_fields = {"request", "grant", *({"snapshot"} if phase == "begin" else {"envelope"} if phase == "object" else set())}
        _require(set(raw) == expected_fields, "node_transfer_phase_invalid")
        expected_body = {**base, "phase": phase}
        if phase == "object":
            expected_body.update(object_index=integer(body.get("object_index")), envelope_sha256=digest(body.get("envelope_sha256")))
        _require(body == expected_body, "node_transfer_request_binding_mismatch")
        state = relay._get(db, IMPORT_KEY)
        if phase == "begin":
            payload = _bound_snapshot(raw["snapshot"], grant, relay, deadline)
            if state is None:
                _empty_target(relay, db, payload)
                _capacity(relay, payload, deadline)
                state = {"state": "receiving", "transfer_id": grant["transfer_id"], "snapshot_sha256": grant["snapshot_sha256"],
                         "snapshot": raw["snapshot"], "grant": raw["grant"], "next_object": 0, "receipt": None}
            else:
                _require(state["transfer_id"] == grant["transfer_id"] and state["snapshot_sha256"] == grant["snapshot_sha256"], "node_transfer_import_conflict")
                state["grant"] = raw["grant"]  # Explicit renewed issuer grant, same frozen snapshot.
            relay._set(db, IMPORT_KEY, state)
            return _progress(relay, state)
        _require(state is not None and state["transfer_id"] == grant["transfer_id"] and state["snapshot_sha256"] == grant["snapshot_sha256"], "node_transfer_begin_required")
        payload = _bound_snapshot(state["snapshot"], grant, relay, deadline)
        if phase == "object":
            index = body["object_index"]
            _require(index < len(payload["messages"]) and index <= state["next_object"], "node_transfer_object_order")
            row = payload["messages"][index]
            _require(body["envelope_sha256"] == row["envelope_sha256"], "node_transfer_object_mismatch")
            encoded = canonical_bytes(raw["envelope"])
            _object(encoded, row, payload, relay.issuers)
            path = relay.object_directory / (row["envelope_sha256"] + ".json")
            if state["state"] == "committed" or index < state["next_object"]:
                _require(hmac.compare_digest(_read(path, relay.limits["maximum_envelope_bytes"]), encoded), "node_transfer_object_mismatch")
                return _progress(relay, state)
            _capacity(relay, payload, deadline)
            if path.exists():
                _require(hmac.compare_digest(_read(path, relay.limits["maximum_envelope_bytes"]), encoded), "node_transfer_object_mismatch")
                # The previous publication may have renamed successfully but
                # failed its durability barrier. Re-publish identical verified
                # bytes through the existing cross-platform flush+rename path.
                storage.atomic_write(path, encoded, replace=True)
            else:
                storage.atomic_write(path, encoded, replace=False)
            _check(deadline)
            state["next_object"] = index + 1
            relay._set(db, IMPORT_KEY, state)
            return _progress(relay, state)
        if state["state"] == "committed":
            return _progress(relay, state)
        _require(state["next_object"] == len(payload["messages"]), "node_transfer_objects_incomplete")
        _empty_target(relay, db, payload)
        _capacity(relay, payload, deadline)
        for row in payload["messages"]:
            _check(deadline)
            path = relay.object_directory / (row["envelope_sha256"] + ".json")
            encoded = _read(path, relay.limits["maximum_envelope_bytes"])
            _object(encoded, row, payload, relay.issuers)
            # Completion acknowledges durable objects, including pre-existing
            # orphans and progress inherited after a process crash.
            storage.atomic_write(path, encoded, replace=True)
        db.execute("DELETE FROM members")
        for row in payload["members"]:
            db.execute("INSERT INTO members VALUES(?,?,?,?)", (row["key_id"], canonical_bytes(row["encryption_key"]), canonical_bytes(row["scopes"]), row["invite_id"]))
        for row in payload["invitations"]:
            db.execute("INSERT INTO invitations VALUES(?,?,?,?)", (row["invite_id"], row["invite_sha256"], row["request_sha256"], canonical_bytes(row["result"])))
        rosters = {entry["sha256"]: entry["document"] for entry in payload["rosters"]}
        for row in payload["messages"]:
            _check(deadline)
            db.execute("INSERT INTO messages(sequence,message_id,envelope_sha256,object_bytes,sender_key_id,roster) VALUES(?,?,?,?,?,?)",
                       (row["sequence"], row["message_id"], row["envelope_sha256"], row["object_bytes"], row["sender_key_id"], canonical_bytes(rosters[row["roster_sha256"]])))
            db.executemany("INSERT INTO recipients VALUES(?,?)", [(row["message_id"], key) for key in row["recipient_key_ids"]])
        for row in payload["receipts"]:
            _check(deadline)
            db.execute("INSERT INTO receipts(sequence,message_id,key_id,request_id,request_sha256,document,result) VALUES(?,?,?,?,?,?,?)",
                       (row["sequence"], row["message_id"], row["key_id"], row["request_id"], row["request_sha256"], canonical_bytes(row["document"]), canonical_bytes(row["result"])))
        completion = {"schema_version": RECEIPT_SCHEMA, "network_id": relay.network_id, "transfer_id": grant["transfer_id"],
                      "snapshot_sha256": grant["snapshot_sha256"], "source": grant["source"], "target": relay.node_descriptor(),
                      "counts": payload["counts"], "committed_at": int(time.time()), "all_objects_durable": True}
        state.update(state="committed", receipt=_sign(completion, relay.node_identity))
        _check(deadline)
        relay._set(db, IMPORT_KEY, state)
        return _progress(relay, state)


def receive_transfer(relay: Relay, value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Expose bounded retryable storage failures without losing the fence."""
    try:
        return _receive_transfer(relay, value)
    except storage.StorageError as exc:
        raise RelayError(exc.code, retryable=exc.retryable) from None
    except OSError:
        raise RelayError("node_transfer_storage_unavailable", retryable=True) from None


def _response(value: Any, grant: Mapping[str, Any], total: int) -> tuple[int, Any]:
    _require(isinstance(value, dict), "node_transfer_response_invalid")
    trust = PublicKeyTrust([grant["target"]["signing_key"]])
    if value.get("state") == "committed":
        object_fields(value, {"state", "receipt"})
        receipt = _verify_signed(value["receipt"], trust, 65536)
        object_fields(receipt, {"schema_version", "network_id", "transfer_id", "snapshot_sha256", "source", "target", "counts", "committed_at", "all_objects_durable"})
        expected = {key: grant[key] for key in ("network_id", "transfer_id", "snapshot_sha256", "source", "target", "counts")}
        _require(receipt["schema_version"] == RECEIPT_SCHEMA and receipt["all_objects_durable"] is True
                 and all(receipt[key] == val for key, val in expected.items()), "node_transfer_completion_mismatch")
        integer(receipt["committed_at"])
        return total, value["receipt"]
    object_fields(value, {"state", "progress"})
    progress = _verify_signed(value["progress"], trust, 65536)
    object_fields(progress, {"schema_version", "network_id", "transfer_id", "snapshot_sha256", "target", "next_object", "total_objects"})
    _require(value["state"] == "receiving" and progress["schema_version"] == PROGRESS_SCHEMA and progress["total_objects"] == total
             and all(progress[key] == grant[key] for key in ("network_id", "transfer_id", "snapshot_sha256", "target")), "node_transfer_progress_mismatch")
    next_object = integer(progress["next_object"])
    _require(next_object <= total, "node_transfer_progress_mismatch")
    return next_object, None


def transfer(relay: Relay, grant: Mapping[str, Any], transport: Any = None,
             maximum_objects: int = 4, maximum_seconds: int = 10) -> Mapping[str, Any]:
    """One explicit HTTP pass; restart/retry resumes signed target progress."""
    from memory_vault_network import HTTPTransport
    from memory_vault_node import refresh
    _require(type(maximum_objects) is int and 0 <= maximum_objects <= 16, "node_transfer_invalid_budget")
    deadline = _deadline(maximum_seconds)
    owned = transport is None
    transport = HTTPTransport() if owned else transport
    uploaded, receipt, next_object, total = 0, None, 0, 0
    started = time.monotonic()

    def request(base: str, method: str, path: str, value: Any = None) -> Any:
        _check(deadline)
        result = (transport.request(base, method, path, value, deadline=deadline) if isinstance(transport, HTTPTransport)
                  else transport.request(base, method, path, value))
        _check(deadline)
        return result

    try:
        refresh(relay, transport=transport, maximum_seconds=max(1, min(60, int(deadline - time.monotonic()))))
        with relay._transaction() as db:
            authorized = _grant(grant, relay, db, "export")
            frozen = relay._get(db, EXPORT_KEY)
            _require(frozen is not None, "node_transfer_prepare_required")
            payload = _bound_snapshot(frozen["snapshot"], authorized, relay, deadline)
            total = payload["counts"]["objects"]
            if frozen["receipt"] is not None:
                next_object, receipt = _response({"state": "committed", "receipt": frozen["receipt"]}, authorized, total)
        if receipt is None:
            target = authorized["target"]["base_url"]
            # Ask the independent issuer to bind the target's fresh nonce.
            # The source's node.status right cannot enroll any member/node.
            challenge = request(target, "GET", "/v1/status")
            bound = _verify_signed(challenge.get("node_challenge"), PublicKeyTrust([authorized["target"]["signing_key"]]), 65536)
            object_fields(bound, {"schema_version", "network_id", "node", "nonce", "issued_at", "expires_at"})
            _require(bound["schema_version"] == "memory-vault-node-challenge/v1" and bound["network_id"] == relay.network_id
                     and bound["node"] == authorized["target"] and bound["nonce"] == challenge["nonce"], "node_transfer_target_challenge_mismatch")
            _window(bound)
            now = int(time.time())
            status_request = sign_node_request(relay.node_identity, network_id=relay.network_id, action="refresh",
                request_id="req_" + secrets.token_hex(16), body={"nonce": challenge["nonce"]}, issued_at=now, expires_at=now + 60)
            status = request(relay.authority_url, "POST", "/v1/node-status", {"network_id": relay.network_id, "nonce": challenge["nonce"], "request": status_request})
            request(target, "POST", "/v1/status", status)

            def phase(name: str, *, index: int | None = None) -> tuple[int, Any]:
                _check(deadline)
                body = {"phase": name, "transfer_id": authorized["transfer_id"], "snapshot_sha256": authorized["snapshot_sha256"], "grant_sha256": document_sha256(grant)}
                value = {"grant": grant}
                if name == "begin":
                    value["snapshot"] = frozen["snapshot"]
                elif name == "object":
                    row = payload["messages"][index]
                    body.update(object_index=index, envelope_sha256=row["envelope_sha256"])
                    encoded = _read(relay.object_directory / (row["envelope_sha256"] + ".json"), relay.limits["maximum_envelope_bytes"])
                    _object(encoded, row, payload, relay.issuers)
                    value["envelope"] = strict_json_loads(encoded)
                now = int(time.time())
                value["request"] = sign_node_request(relay.node_identity, network_id=relay.network_id, action="export",
                    request_id="req_" + secrets.token_hex(16), body=body, issued_at=now, expires_at=min(now + 60, authorized["expires_at"]))
                return _response(request(target, "POST", "/v1/node-transfer", value), authorized, total)

            next_object, receipt = phase("begin")
            while receipt is None and next_object < total and uploaded < maximum_objects:
                previous = next_object
                next_object, receipt = phase("object", index=previous)
                _require(next_object >= previous + 1, "node_transfer_progress_mismatch")
                uploaded += 1
            if receipt is None and next_object == total:
                next_object, receipt = phase("commit")
        if receipt is not None:
            with relay._transaction() as db:
                _grant(grant, relay, db, "export")
                frozen = relay._get(db, EXPORT_KEY)
                _require(frozen is not None and frozen["snapshot_sha256"] == authorized["snapshot_sha256"], "node_transfer_snapshot_mismatch")
                frozen["receipt"] = receipt
                relay._set(db, EXPORT_KEY, frozen)
        return {"state": "exit_ready" if receipt is not None else "pending", "transfer_id": authorized["transfer_id"],
                "snapshot_sha256": authorized["snapshot_sha256"], "uploaded_objects": uploaded, "confirmed_objects": next_object,
                "total_objects": total, "target_receipt": receipt, "retryable": receipt is None,
                "source_data_deleted": False, "safe_to_remove": False, "background_worker_started": False,
                "elapsed_ms": max(0, int((time.monotonic() - started) * 1000))}
    except (MemoryError, TrustError, OSError) as exc:
        retryable = getattr(exc, "retryable", isinstance(exc, OSError))
        code = getattr(exc, "code", "node_transfer_storage_unavailable")
        return {"state": "pending" if retryable else "needs_attention", "uploaded_objects": uploaded,
                "confirmed_objects": next_object, "total_objects": total, "error": {"code": code, "retryable": retryable},
                "retryable": retryable, "source_data_deleted": False, "safe_to_remove": False,
                "background_worker_started": False, "elapsed_ms": max(0, int((time.monotonic() - started) * 1000))}
    finally:
        if owned:
            transport.close()
