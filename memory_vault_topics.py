"""Bounded topic control using existing identities and message signatures.

This module performs no I/O, enrollment, service startup or message delivery.
Historical validators do not grant current permission. Only a verified fresh
joint response can create the capability consumed by recipient/publisher checks.
"""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Mapping, Sequence
from weakref import WeakKeyDictionary

from memory_vault import canonical_bytes
from memory_vault_network_control import _window, verify_roster, verify_status
from memory_vault_network_crypto import (
    NetworkCryptoError, PublicKeyTrust, digest, document, document_sha256,
    integer, object_fields, opaque, public_signing_key,
)
from memory_vault_trust import Identity, TrustStore, TrustError, _key_id

POLICY_SCHEMA = "memory-vault-topic-policy/v1"
SUBSCRIPTION_SCHEMA = "memory-vault-topic-subscription-change/v1"
SNAPSHOT_SCHEMA = "memory-vault-topic-snapshot/v1"
TOPIC_STATUS_SCHEMA = "memory-vault-topic-status/v1"
RECEIPT_SCHEMA = "memory-vault-topic-subscription-receipt/v1"
MAX_POLICY_BYTES = 128 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024
MAX_SUBSCRIPTION_BYTES = 16 * 1024
MAX_TOPIC_STATUS_BYTES = 16 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
MAX_JOINT_BYTES = 2 * 1024 * 1024 + MAX_POLICY_BYTES + MAX_SNAPSHOT_BYTES + MAX_TOPIC_STATUS_BYTES
MAX_GRANTS = 256
MAX_TOPIC_RECIPIENTS = 16
ZERO = "0" * 64
_COMMON = {"schema_version", "network_id", "topic_id", "issuer_key_id", "version",
           "previous_sha256", "issued_at", "expires_at"}
_CHANGE = {"schema_version", "network_id", "topic_id", "member_key_id", "member_signing_key",
           "grant_id", "revision", "previous_change_sha256", "state", "request_id", "issued_at", "expires_at"}
_STATUS = {"schema_version", "network_id", "topic_id", "issuer_key_id", "nonce", "policy_version",
           "policy_sha256", "snapshot_version", "snapshot_sha256", "roster_version", "roster_sha256", "issued_at", "expires_at"}
_RECEIPT = {"schema_version", "network_id", "topic_id", "issuer_key_id", "member_key_id", "grant_id",
            "request_id", "revision", "change_sha256", "snapshot_version", "snapshot_sha256", "committed_at", "state"}
Doc = Mapping[str, Any] | bytes


def _fail(detail: str) -> None:
    raise NetworkCryptoError("network_topic_" + detail)


def _key(value: Any) -> str:
    try:
        return _key_id(value)
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None


def _now(now: int | None) -> int:
    return int(time.time()) if now is None else integer(now)


def _sign(payload: Mapping[str, Any], signer: Identity, maximum: int) -> dict[str, Any]:
    checked = document(payload, maximum=maximum)
    return document({"payload": checked, "proof": signer.sign_message(checked)}, maximum=maximum)


def _wrapper(value: Doc, maximum: int) -> dict[str, Any]:
    return object_fields(document(value, maximum=maximum), {"payload", "proof"})


def _issuer(value: Doc, issuers: TrustStore, issuer_key_id: str, maximum: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expected = _key(issuer_key_id)
    signed = _wrapper(value, maximum)
    raw = document(signed["payload"], maximum=maximum)
    if raw.get("issuer_key_id") != expected or not isinstance(signed["proof"], Mapping) or signed["proof"].get("key_id") != expected:
        _fail("issuer_mismatch")
    try:
        verified = issuers.verify_message(raw, signed["proof"])
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None
    if verified != expected:
        _fail("issuer_mismatch")
    return signed, raw


def _issuer_fields(signer: Identity, network_id: str, topic_id: str, issuer_key_id: str) -> dict[str, str]:
    if _key(issuer_key_id) != signer.key_id:
        _fail("issuer_mismatch")
    return {"network_id": opaque(network_id), "topic_id": opaque(topic_id), "issuer_key_id": issuer_key_id}


def _binding(raw: Mapping[str, Any], schema: str, network_id: str, topic_id: str, kind: str) -> None:
    if raw["schema_version"] != schema or opaque(raw["network_id"]) != opaque(network_id) or opaque(raw["topic_id"]) != opaque(topic_id):
        _fail(kind + "_binding_mismatch")


def _genesis(version: Any, previous: Any) -> None:
    if (integer(version, minimum=1) == 1) != (digest(previous) == ZERO):
        _fail("chain_mismatch")


def _grants(raw: Mapping[str, Any]) -> None:
    lists = [raw["publishers"], raw["subscriber_grants"]]
    if any(not isinstance(items, list) for items in lists) or sum(len(items) for items in lists) > MAX_GRANTS:
        _fail("grant_limit")
    seen: set[str] = set()
    for items in lists:
        order, active = [], set()
        for item in items:
            entry = object_fields(item, {"member_key_id", "grant_id", "status"})
            member, grant = _key(entry["member_key_id"]), opaque(entry["grant_id"])
            if entry["status"] not in ("active", "revoked"):
                _fail("invalid_status")
            if grant in seen:
                _fail("duplicate_grant")
            seen.add(grant)
            if entry["status"] == "active":
                if member in active:
                    _fail("active_grant_conflict")
                active.add(member)
            order.append((member, grant))
        if order != sorted(order):
            _fail("grant_order")


def _policy_payload(raw: Mapping[str, Any], *, network_id: str, topic_id: str, now: int | None, allow_expired: bool) -> dict[str, Any]:
    raw = object_fields(raw, _COMMON | {"status", "publishers", "subscriber_grants"})
    _binding(raw, POLICY_SCHEMA, network_id, topic_id, "policy")
    _key(raw["issuer_key_id"])
    _genesis(raw["version"], raw["previous_sha256"])
    if raw["status"] not in ("active", "revoked"):
        _fail("invalid_status")
    _grants(raw)
    _window(raw, now=now, allow_expired=allow_expired)
    return raw


def _continuity(signed: Mapping[str, Any], raw: Mapping[str, Any], previous: Mapping[str, Any], old: Mapping[str, Any], *, gaps: bool) -> None:
    if raw["version"] < old["version"] or raw["issued_at"] < old["issued_at"]:
        _fail("rollback")
    if raw["version"] == old["version"]:
        if document_sha256(signed) != document_sha256(previous):
            _fail("version_conflict")
    elif raw["version"] == old["version"] + 1:
        if raw["previous_sha256"] != document_sha256(previous):
            _fail("chain_mismatch")
    elif not gaps:
        _fail("gap_requires_current")


def _policy(value: Doc, issuers: TrustStore, *, network_id: str, topic_id: str, issuer_key_id: str,
            previous_policy: Doc | None, now: int | None, allow_expired: bool, gaps: bool) -> dict[str, Any]:
    signed, payload = _issuer(value, issuers, issuer_key_id, MAX_POLICY_BYTES)
    raw = _policy_payload(payload, network_id=network_id, topic_id=topic_id, now=now, allow_expired=allow_expired)
    if previous_policy is None:
        return raw
    previous, old = _issuer(previous_policy, issuers, issuer_key_id, MAX_POLICY_BYTES)
    old = _policy_payload(old, network_id=network_id, topic_id=topic_id, now=now, allow_expired=True)
    _continuity(signed, raw, previous, old, gaps=gaps)
    if old["status"] == "revoked" and raw["status"] != "revoked":
        _fail("reactivation_forbidden")
    current = {item["grant_id"]: (role, item) for role in ("publishers", "subscriber_grants") for item in raw[role]}
    for role in ("publishers", "subscriber_grants"):
        for entry in old[role]:
            found = current.get(entry["grant_id"])
            if found is None:
                _fail("tombstone_required")
            if found[0] != role or found[1]["member_key_id"] != entry["member_key_id"]:
                _fail("grant_identity_changed")
            if entry["status"] == "revoked" and found[1]["status"] != "revoked":
                _fail("reactivation_forbidden")
    return raw


def issue_policy(issuer: Identity, *, network_id: str, topic_id: str, issuer_key_id: str, version: int,
                 previous_sha256: str, status: str, publishers: Sequence[Mapping[str, Any]],
                 subscriber_grants: Sequence[Mapping[str, Any]], issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": POLICY_SCHEMA, **_issuer_fields(issuer, network_id, topic_id, issuer_key_id),
           "version": version, "previous_sha256": previous_sha256, "status": status,
           "publishers": sorted([dict(item) for item in publishers], key=lambda item: (item.get("member_key_id", ""), item.get("grant_id", ""))),
           "subscriber_grants": sorted([dict(item) for item in subscriber_grants], key=lambda item: (item.get("member_key_id", ""), item.get("grant_id", ""))),
           "issued_at": issued_at, "expires_at": expires_at}
    return _sign(_policy_payload(raw, network_id=network_id, topic_id=topic_id, now=issued_at, allow_expired=False), issuer, MAX_POLICY_BYTES)


def verify_policy(value: Doc, issuers: TrustStore, *, network_id: str, topic_id: str, issuer_key_id: str,
                  previous_policy: Doc | None = None, now: int | None = None, allow_expired: bool = False) -> dict[str, Any]:
    return _policy(value, issuers, network_id=network_id, topic_id=topic_id, issuer_key_id=issuer_key_id,
                   previous_policy=previous_policy, now=now, allow_expired=allow_expired, gaps=False)


def _change(value: Doc, *, network_id: str, topic_id: str, member_key_id: str | None,
            grant_id: str | None, now: int | None, allow_expired: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    signed = _wrapper(value, MAX_SUBSCRIPTION_BYTES)
    raw = object_fields(signed["payload"], _CHANGE)
    _binding(raw, SUBSCRIPTION_SCHEMA, network_id, topic_id, "subscription")
    member, grant = _key(raw["member_key_id"]), opaque(raw["grant_id"])
    public = public_signing_key(raw["member_signing_key"])
    if (public["key_id"] != member or (member_key_id is not None and member != _key(member_key_id))
            or (grant_id is not None and grant != opaque(grant_id)) or not isinstance(signed["proof"], Mapping)
            or signed["proof"].get("key_id") != member):
        _fail("subscription_binding_mismatch")
    _genesis(raw["revision"], raw["previous_change_sha256"])
    opaque(raw["request_id"])
    if raw["state"] not in ("subscribed", "unsubscribed"):
        _fail("invalid_state")
    _window(raw, now=now, allow_expired=allow_expired)
    try:
        PublicKeyTrust([public]).verify_message(raw, signed["proof"])
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None
    return signed, raw


def _change_continuity(signed: Mapping[str, Any], raw: Mapping[str, Any], previous: Mapping[str, Any], old: Mapping[str, Any], *, gaps: bool) -> None:
    if raw["revision"] < old["revision"]:
        _fail("change_rollback")
    if raw["revision"] == old["revision"]:
        if document_sha256(signed) != document_sha256(previous):
            _fail("change_conflict")
    elif raw["revision"] == old["revision"] + 1:
        if raw["previous_change_sha256"] != document_sha256(previous):
            _fail("change_chain_mismatch")
    elif not gaps:
        _fail("change_gap_requires_current")


def sign_subscription(member: Identity, *, network_id: str, topic_id: str, grant_id: str, revision: int,
                      previous_change_sha256: str, state: str, request_id: str, issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": SUBSCRIPTION_SCHEMA, "network_id": network_id, "topic_id": topic_id,
           "member_key_id": member.key_id, "member_signing_key": member.public_descriptor(), "grant_id": grant_id,
           "revision": revision, "previous_change_sha256": previous_change_sha256, "state": state,
           "request_id": request_id, "issued_at": issued_at, "expires_at": expires_at}
    signed = _sign(raw, member, MAX_SUBSCRIPTION_BYTES)
    _change(signed, network_id=network_id, topic_id=topic_id, member_key_id=None, grant_id=None, now=issued_at, allow_expired=False)
    return signed


def verify_subscription(value: Doc, *, network_id: str, topic_id: str, member_key_id: str | None = None,
                        grant_id: str | None = None, previous_change: Doc | None = None, now: int | None = None,
                        allow_expired: bool = False) -> dict[str, Any]:
    """Historical self-signature only; the authority separately checks admission.

    With no predecessor, later revisions may be inspected as historical facts.
    A first CAS acceptance must independently require revision 1 and ZERO.
    """
    signed, raw = _change(value, network_id=network_id, topic_id=topic_id, member_key_id=member_key_id,
                          grant_id=grant_id, now=now, allow_expired=allow_expired)
    if previous_change is not None:
        previous, old = _change(previous_change, network_id=network_id, topic_id=topic_id,
                                member_key_id=raw["member_key_id"], grant_id=raw["grant_id"], now=now, allow_expired=True)
        _change_continuity(signed, raw, previous, old, gaps=False)
    return raw


def _snapshot_payload(raw: Mapping[str, Any], *, network_id: str, topic_id: str, now: int | None, allow_expired: bool) -> dict[str, Any]:
    raw = object_fields(raw, _COMMON | {"policy_version", "policy_sha256", "subscriptions"})
    _binding(raw, SNAPSHOT_SCHEMA, network_id, topic_id, "snapshot")
    _key(raw["issuer_key_id"])
    _genesis(raw["version"], raw["previous_sha256"])
    integer(raw["policy_version"], minimum=1)
    digest(raw["policy_sha256"])
    _window(raw, now=now, allow_expired=allow_expired)
    entries = raw["subscriptions"]
    if not isinstance(entries, list) or len(entries) > MAX_GRANTS:
        _fail("grant_limit")
    order, ids = [], set()
    for entry in entries:
        item = object_fields(entry, {"member_key_id", "grant_id", "change"})
        member, grant = _key(item["member_key_id"]), opaque(item["grant_id"])
        if grant in ids:
            _fail("duplicate_grant")
        ids.add(grant)
        order.append((member, grant))
        if item["change"] is not None:
            verify_subscription(item["change"], network_id=network_id, topic_id=topic_id, member_key_id=member,
                                grant_id=grant, now=raw["issued_at"], allow_expired=True)
    if order != sorted(order):
        _fail("grant_order")
    return raw


def issue_snapshot(issuer: Identity, *, network_id: str, topic_id: str, issuer_key_id: str, version: int,
                   previous_sha256: str, policy_version: int, policy_sha256: str,
                   subscriptions: Sequence[Mapping[str, Any]], issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": SNAPSHOT_SCHEMA, **_issuer_fields(issuer, network_id, topic_id, issuer_key_id),
           "version": version, "previous_sha256": previous_sha256, "policy_version": policy_version,
           "policy_sha256": policy_sha256, "subscriptions": [dict(item) for item in subscriptions],
           "issued_at": issued_at, "expires_at": expires_at}
    return _sign(_snapshot_payload(raw, network_id=network_id, topic_id=topic_id, now=issued_at, allow_expired=False), issuer, MAX_SNAPSHOT_BYTES)


def _snapshot(value: Doc, issuers: TrustStore, *, policy: Doc, network_id: str, topic_id: str, issuer_key_id: str,
              previous_snapshot: Doc | None, now: int | None, allow_expired: bool, gaps: bool) -> dict[str, Any]:
    policy_raw = verify_policy(policy, issuers, network_id=network_id, topic_id=topic_id, issuer_key_id=issuer_key_id,
                               now=now, allow_expired=True)
    signed, raw = _issuer(value, issuers, issuer_key_id, MAX_SNAPSHOT_BYTES)
    raw = _snapshot_payload(raw, network_id=network_id, topic_id=topic_id, now=now, allow_expired=allow_expired)
    if raw["policy_version"] != policy_raw["version"] or raw["policy_sha256"] != document_sha256(policy):
        _fail("snapshot_policy_mismatch")
    wanted = [(item["member_key_id"], item["grant_id"]) for item in policy_raw["subscriber_grants"]]
    actual = [(item["member_key_id"], item["grant_id"]) for item in raw["subscriptions"]]
    if actual != wanted:
        _fail("snapshot_incomplete")
    if previous_snapshot is None:
        return raw
    previous, old = _issuer(previous_snapshot, issuers, issuer_key_id, MAX_SNAPSHOT_BYTES)
    old = _snapshot_payload(old, network_id=network_id, topic_id=topic_id, now=now, allow_expired=True)
    _continuity(signed, raw, previous, old, gaps=gaps)
    if raw["policy_version"] < old["policy_version"] or (raw["policy_version"] == old["policy_version"] and raw["policy_sha256"] != old["policy_sha256"]):
        _fail("snapshot_policy_mismatch")
    current = {(item["member_key_id"], item["grant_id"]): item for item in raw["subscriptions"]}
    for entry in old["subscriptions"]:
        item = current.get((entry["member_key_id"], entry["grant_id"]))
        if item is None:
            _fail("tombstone_required")
        if entry["change"] is None:
            continue
        if item["change"] is None:
            _fail("change_missing")
        _change_continuity(item["change"], item["change"]["payload"], entry["change"], entry["change"]["payload"], gaps=gaps)
    return raw


def verify_snapshot(value: Doc, issuers: TrustStore, *, policy: Doc, network_id: str, topic_id: str,
                    issuer_key_id: str, previous_snapshot: Doc | None = None, now: int | None = None,
                    allow_expired: bool = False) -> dict[str, Any]:
    return _snapshot(value, issuers, policy=policy, network_id=network_id, topic_id=topic_id, issuer_key_id=issuer_key_id,
                     previous_snapshot=previous_snapshot, now=now, allow_expired=allow_expired, gaps=False)


def _status_payload(raw: Mapping[str, Any], *, network_id: str, topic_id: str, nonce: str, now: int | None) -> dict[str, Any]:
    raw = object_fields(raw, _STATUS)
    _binding(raw, TOPIC_STATUS_SCHEMA, network_id, topic_id, "status")
    _key(raw["issuer_key_id"])
    if opaque(raw["nonce"]) != opaque(nonce):
        _fail("status_binding_mismatch")
    for kind in ("policy", "snapshot", "roster"):
        integer(raw[kind + "_version"], minimum=1)
        digest(raw[kind + "_sha256"])
    _window(raw, now=now)
    return raw


def issue_topic_status(issuer: Identity, *, network_id: str, topic_id: str, issuer_key_id: str, nonce: str,
                       policy_version: int, policy_sha256: str, snapshot_version: int, snapshot_sha256: str,
                       roster_version: int, roster_sha256: str, issued_at: int, expires_at: int) -> dict[str, Any]:
    raw = {"schema_version": TOPIC_STATUS_SCHEMA, **_issuer_fields(issuer, network_id, topic_id, issuer_key_id),
           "nonce": nonce, "policy_version": policy_version, "policy_sha256": policy_sha256,
           "snapshot_version": snapshot_version, "snapshot_sha256": snapshot_sha256,
           "roster_version": roster_version, "roster_sha256": roster_sha256, "issued_at": issued_at, "expires_at": expires_at}
    return _sign(_status_payload(raw, network_id=network_id, topic_id=topic_id, nonce=nonce, now=issued_at), issuer, MAX_TOPIC_STATUS_BYTES)


def verify_topic_status(value: Doc, issuers: TrustStore, *, network_id: str, topic_id: str, issuer_key_id: str,
                        nonce: str, policy_version: int | None = None, policy_sha256: str | None = None,
                        snapshot_version: int | None = None, snapshot_sha256: str | None = None,
                        roster_version: int | None = None, roster_sha256: str | None = None, now: int | None = None) -> dict[str, Any]:
    _, raw = _issuer(value, issuers, issuer_key_id, MAX_TOPIC_STATUS_BYTES)
    raw = _status_payload(raw, network_id=network_id, topic_id=topic_id, nonce=nonce, now=now)
    for name, value in (("policy_version", policy_version), ("snapshot_version", snapshot_version), ("roster_version", roster_version),
                        ("policy_sha256", policy_sha256), ("snapshot_sha256", snapshot_sha256), ("roster_sha256", roster_sha256)):
        if value is not None and raw[name] != (integer(value, minimum=1) if name.endswith("version") else digest(value)):
            _fail("status_binding_mismatch")
    return raw


@dataclass(frozen=True, eq=False)
class CurrentTopic:
    """Process-local verified capability; serialized/copy-constructed data is inert."""
    _wire: bytes
    verified_at: int
    expires_at: int

    @property
    def policy(self) -> dict[str, Any]:
        return document(self._wire, maximum=MAX_JOINT_BYTES)["policy"]

    @property
    def snapshot(self) -> dict[str, Any]:
        return document(self._wire, maximum=MAX_JOINT_BYTES)["snapshot"]

    @property
    def roster(self) -> dict[str, Any]:
        return document(self._wire, maximum=MAX_JOINT_BYTES)["roster"]

    @property
    def status(self) -> dict[str, Any]:
        return document(self._wire, maximum=MAX_JOINT_BYTES)["status"]

    @property
    def topic_status(self) -> dict[str, Any]:
        return document(self._wire, maximum=MAX_JOINT_BYTES)["topic_status"]


_CAPABILITIES: WeakKeyDictionary[CurrentTopic, tuple[bytes, int, int, float]] = WeakKeyDictionary()


def verify_current_topic(value: Doc, issuers: TrustStore, *, network_id: str, topic_id: str, issuer_key_id: str,
                         nonce: str, previous_policy: Doc | None = None, previous_snapshot: Doc | None = None,
                         previous_roster: Doc | None = None, minimum_topic_status_issued_at: int | None = None,
                         minimum_status_issued_at: int | None = None, now: int | None = None) -> CurrentTopic:
    started, at = time.monotonic(), _now(now)
    response = object_fields(document(value, maximum=MAX_JOINT_BYTES), {"roster", "status", "policy", "snapshot", "topic_status"})
    try:
        pinned = PublicKeyTrust([issuers.require_trusted(_key(issuer_key_id))])
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None
    roster = verify_roster(response["roster"], pinned, network_id=network_id, now=at, allow_expired=True)
    status = verify_status(response["status"], pinned, network_id=network_id, nonce=nonce,
                           roster_version=roster["version"], roster_sha256=document_sha256(response["roster"]), now=at)
    # Validate fresh proof and all selected hashes before allowing any gaps.
    topic_status = verify_topic_status(response["topic_status"], pinned, network_id=network_id, topic_id=topic_id,
        issuer_key_id=issuer_key_id, nonce=nonce, policy_sha256=document_sha256(response["policy"]),
        snapshot_sha256=document_sha256(response["snapshot"]), roster_sha256=document_sha256(response["roster"]),
        roster_version=roster["version"], now=at)
    for minimum, timestamp in ((minimum_status_issued_at, status["issued_at"]),
                               (minimum_topic_status_issued_at, topic_status["issued_at"])):
        if minimum is not None and timestamp < integer(minimum):
            _fail("status_rollback")
    if (previous_policy is None) != (previous_snapshot is None):
        _fail("checkpoint_incomplete")
    if previous_policy is not None:
        verify_snapshot(previous_snapshot, pinned, policy=previous_policy, network_id=network_id, topic_id=topic_id,
                        issuer_key_id=issuer_key_id, now=at, allow_expired=True)
    policy = _policy(response["policy"], pinned, network_id=network_id, topic_id=topic_id, issuer_key_id=issuer_key_id,
                      previous_policy=previous_policy, now=at, allow_expired=True, gaps=True)
    snapshot = _snapshot(response["snapshot"], pinned, policy=response["policy"], network_id=network_id, topic_id=topic_id,
                          issuer_key_id=issuer_key_id, previous_snapshot=previous_snapshot, now=at, allow_expired=True, gaps=True)
    if topic_status["policy_version"] != policy["version"] or topic_status["snapshot_version"] != snapshot["version"]:
        _fail("status_binding_mismatch")
    if previous_roster is not None:
        old = verify_roster(previous_roster, pinned, network_id=network_id, now=at, allow_expired=True)
        if roster["version"] < old["version"] or (roster["version"] == old["version"] and document_sha256(previous_roster) != document_sha256(response["roster"])):
            raise NetworkCryptoError("network_roster_rollback")
        if roster["version"] == old["version"] + 1 and roster["previous_sha256"] != document_sha256(previous_roster):
            raise NetworkCryptoError("network_roster_chain_mismatch")
    wire, expiry = canonical_bytes(response), min(status["expires_at"], topic_status["expires_at"], at + 300)
    current = CurrentTopic(wire, at, expiry)
    _CAPABILITIES[current] = (wire, at, expiry, started + max(0, expiry - at))
    return current


def _current(current: CurrentTopic, now: int | None) -> dict[str, Any]:
    if not isinstance(current, CurrentTopic) or current not in _CAPABILITIES:
        _fail("capability_required")
    wire, verified, expiry, deadline = _CAPABILITIES[current]
    if (current._wire, current.verified_at, current.expires_at) != (wire, verified, expiry):
        _fail("capability_required")
    at = _now(now)
    if at < verified:
        _fail("clock_rollback")
    if at >= expiry or time.monotonic() >= deadline:
        raise NetworkCryptoError("network_control_expired")
    return document(wire, maximum=MAX_JOINT_BYTES)


def topic_recipients(current: CurrentTopic, *, now: int | None = None) -> list[dict[str, Any]]:
    response = _current(current, now)
    policy, snapshot, roster = [response[name]["payload"] for name in ("policy", "snapshot", "roster")]
    if policy["status"] != "active":
        _fail("inactive")
    members = {item["signing_key"]["key_id"]: item for item in roster["members"]}
    result = []
    for grant, item in zip(policy["subscriber_grants"], snapshot["subscriptions"]):
        change, member = item["change"], members.get(grant["member_key_id"])
        if (grant["status"] != "active" or change is None or change["payload"]["state"] != "subscribed"
                or member is None or member["status"] != "active" or "receive" not in member["scope"]):
            continue
        if change["payload"]["member_signing_key"] != member["signing_key"]:
            _fail("member_key_changed")
        result.append({"member_key_id": grant["member_key_id"], "grant_id": grant["grant_id"],
                       "change_sha256": document_sha256(change), "signing_key": member["signing_key"], "encryption_key": member["encryption_key"]})
    if len(result) > MAX_TOPIC_RECIPIENTS:
        _fail("recipient_limit")
    return sorted(result, key=lambda item: item["member_key_id"])


def authorized_topic_publisher(current: CurrentTopic, member_key_id: str, *, now: int | None = None,
                               grant_id: str | None = None) -> dict[str, Any]:
    response = _current(current, now)
    policy, roster = response["policy"]["payload"], response["roster"]["payload"]
    if policy["status"] != "active":
        _fail("inactive")
    key = _key(member_key_id)
    expected = None if grant_id is None else opaque(grant_id)
    member = next((item for item in roster["members"] if item["signing_key"]["key_id"] == key and item["status"] == "active" and "send" in item["scope"]), None)
    grant = next((item for item in policy["publishers"] if item["member_key_id"] == key and item["status"] == "active" and (expected is None or item["grant_id"] == expected)), None)
    if member is None or grant is None:
        _fail("publisher_denied")
    return {"member_key_id": key, "grant_id": grant["grant_id"], "signing_key": member["signing_key"], "encryption_key": member["encryption_key"]}


def _receipt_payload(raw: Mapping[str, Any], *, network_id: str, topic_id: str, now: int | None) -> dict[str, Any]:
    raw = object_fields(raw, _RECEIPT)
    _binding(raw, RECEIPT_SCHEMA, network_id, topic_id, "receipt")
    _key(raw["issuer_key_id"])
    _key(raw["member_key_id"])
    opaque(raw["grant_id"])
    opaque(raw["request_id"])
    integer(raw["revision"], minimum=1)
    integer(raw["snapshot_version"], minimum=1)
    digest(raw["change_sha256"])
    digest(raw["snapshot_sha256"])
    if raw["state"] != "committed":
        _fail("invalid_state")
    if integer(raw["committed_at"]) > _now(now) + 30:
        raise NetworkCryptoError("network_control_from_future")
    return raw


def issue_subscription_receipt(issuer: Identity, *, network_id: str, topic_id: str, issuer_key_id: str,
                               member_key_id: str, grant_id: str, request_id: str, revision: int, change_sha256: str,
                               snapshot_version: int, snapshot_sha256: str, committed_at: int) -> dict[str, Any]:
    raw = {"schema_version": RECEIPT_SCHEMA, **_issuer_fields(issuer, network_id, topic_id, issuer_key_id),
           "member_key_id": member_key_id, "grant_id": grant_id, "request_id": request_id, "revision": revision,
           "change_sha256": change_sha256, "snapshot_version": snapshot_version, "snapshot_sha256": snapshot_sha256,
           "committed_at": committed_at, "state": "committed"}
    return _sign(_receipt_payload(raw, network_id=network_id, topic_id=topic_id, now=committed_at), issuer, MAX_RECEIPT_BYTES)


def verify_subscription_receipt(value: Doc, issuers: TrustStore, *, network_id: str, topic_id: str, issuer_key_id: str,
                                change: Doc | None = None, snapshot: Doc | None = None, now: int | None = None) -> dict[str, Any]:
    _, raw = _issuer(value, issuers, issuer_key_id, MAX_RECEIPT_BYTES)
    raw = _receipt_payload(raw, network_id=network_id, topic_id=topic_id, now=now)
    if change is not None:
        payload = verify_subscription(change, network_id=network_id, topic_id=topic_id,
            member_key_id=raw["member_key_id"], grant_id=raw["grant_id"], now=raw["committed_at"])
        if (document_sha256(change) != raw["change_sha256"] or payload["request_id"] != raw["request_id"]
                or payload["revision"] != raw["revision"]):
            _fail("receipt_binding_mismatch")
    if snapshot is not None:
        _, payload = _issuer(snapshot, issuers, issuer_key_id, MAX_SNAPSHOT_BYTES)
        payload = _snapshot_payload(payload, network_id=network_id, topic_id=topic_id, now=now, allow_expired=True)
        if document_sha256(snapshot) != raw["snapshot_sha256"] or payload["version"] != raw["snapshot_version"]:
            _fail("receipt_binding_mismatch")
    return raw
