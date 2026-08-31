"""Explicit private topic authority state; no identity or memory database.

Import and construction have no filesystem or network side effects. Callers
must explicitly initialize an operator-selected private state file. Synchronous
transactions belong in an HTTP worker thread, never on the event-loop thread.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import time
from typing import Any, Iterator, Mapping

from memory_vault import canonical_bytes
import memory_vault_storage as storage
from memory_vault_trust import Identity, TrustStore, _absolute_path, _read_private
from memory_vault_network_control import issue_status, verify_request, verify_roster
from memory_vault_network_crypto import (
    NetworkCryptoError, PublicKeyTrust, digest, document, document_sha256,
    integer, object_fields, opaque,
)
import memory_vault_topics as topics


STATE_SCHEMA = "memory-vault-topic-authority-state/v1"
MAX_TOPICS = 32
MAX_REQUESTS = 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_CHANGE_BYTES = 16 * 1024
MAX_TOPIC_BYTES = 128 * 1024
MAX_CONFIG_BYTES = 16 * 1024
MAX_ROSTER_BYTES = 1024 * 1024


class TopicStoreError(NetworkCryptoError):
    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.retryable = retryable


def _clock(now: int | None) -> int:
    return integer(int(time.time()) if now is None else now)


def _document_topic(value: Mapping[str, Any]) -> str:
    wrapped = object_fields(value, {"payload", "proof"})
    return opaque(document(wrapped["payload"], maximum=MAX_TOPIC_BYTES).get("topic_id"))


@dataclass
class _Context:
    config: dict[str, Any]
    issuer: Identity
    trust: TrustStore
    roster: dict[str, Any]
    roster_payload: dict[str, Any]
    path: Path
    state: dict[str, Any] | None

    @property
    def network_id(self) -> str:
        return self.config["network_id"]


class TopicAuthorityStore:
    """Bounded, independently configured control state with durable receipts.

    ``current`` is a local administrative read, not a public access check.
    ``status`` authenticates its member request while holding the same locks
    used to select the signed control state. Exact subscription retries return
    a historical receipt, never a fresh lease or restored authority.
    """

    def __init__(self, authority_config: Path):
        self.config_path = _absolute_path(authority_config)

    def _config(self) -> tuple[dict[str, Any], dict[str, Path]]:
        raw = _read_private(self.config_path, MAX_CONFIG_BYTES)
        if raw is None:
            raise TopicStoreError("network_authority_not_configured")
        config = document(raw, maximum=MAX_CONFIG_BYTES)
        required = {"schema_version", "network_id", "identity_path", "trust_store_path", "roster_path"}
        if (not required <= set(config) or set(config) - required - {"node_directory_path", "topic_state_path"}
                or config["schema_version"] != "memory-vault-network-authority-config/v1"):
            raise TopicStoreError("network_authority_configuration_invalid")
        opaque(config["network_id"])
        if "topic_state_path" not in config:
            raise TopicStoreError("network_topics_not_configured")
        names = ("identity_path", "trust_store_path", "roster_path", "topic_state_path")
        paths = {}
        for name in (*names, *(("node_directory_path",) if "node_directory_path" in config else ())):
            if not isinstance(config[name], str):
                raise TopicStoreError("network_authority_configuration_invalid")
            paths[name] = _absolute_path(Path(config[name]))
        # A state file must never replace a credential, roster, configuration
        # or any participating lock file, even if that path does not exist yet.
        selected = [self.config_path, *paths.values()]
        locks = [path.with_name(path.name + ".lock") for path in selected]
        if len(set(selected)) != len(selected) or set(selected) & set(locks):
            raise TopicStoreError("network_topic_path_conflict")
        return config, paths

    @contextmanager
    def _transaction(self, now: int, *, initialize: bool = False) -> Iterator[_Context]:
        config, paths = self._config()
        state_path = paths["topic_state_path"]
        # A network request cannot initialize missing state or its directory.
        if not initialize and _read_private(state_path, MAX_STATE_BYTES) is None:
            raise TopicStoreError("network_topic_state_missing")
        selected = (self.config_path, paths["trust_store_path"], paths["roster_path"], state_path)
        with ExitStack() as stack:
            try:
                for path in sorted(selected, key=str):
                    stack.enter_context(storage.file_lock(path.with_name(path.name + ".lock"),
                                                          busy_code="network_topic_busy"))
            except storage.StorageError as exc:
                raise TopicStoreError(exc.code, retryable=exc.retryable) from None
            checked, checked_paths = self._config()
            if checked != config or checked_paths != paths:
                raise TopicStoreError("network_topic_configuration_changed", retryable=True)
            issuer = Identity.load(paths["identity_path"])
            trust = TrustStore(paths["trust_store_path"])
            trust.require_trusted(issuer.key_id)
            raw = _read_private(state_path, MAX_STATE_BYTES)
            if initialize and raw is not None:
                raise TopicStoreError("network_topic_state_exists")
            if not initialize and raw is None:
                raise TopicStoreError("network_topic_state_missing")
            state = None if raw is None else document(raw, maximum=MAX_STATE_BYTES)
            historical_now = max(now, integer(state["last_clock"])) if state is not None and "last_clock" in state else now
            roster_raw = _read_private(paths["roster_path"], MAX_ROSTER_BYTES)
            if roster_raw is None:
                raise TopicStoreError("network_roster_missing")
            roster = document(roster_raw, maximum=MAX_ROSTER_BYTES)
            roster_payload = verify_roster(roster, PublicKeyTrust([trust.require_trusted(issuer.key_id)]), network_id=config["network_id"],
                                           now=historical_now, allow_expired=True)
            context = _Context(config, issuer, trust, roster, roster_payload, state_path, state)
            if state is not None:
                self._validate_state(context, state, now=historical_now)
            yield context

    @staticmethod
    def _monotonic(context: _Context, now: int) -> None:
        if context.state is not None and now < context.state["last_clock"]:
            raise TopicStoreError("network_topic_clock_rollback")

    @staticmethod
    def _topic(context: _Context, topic_id: str) -> dict[str, Any]:
        assert context.state is not None
        selected = context.state["topics"].get(opaque(topic_id))
        if selected is None:
            raise TopicStoreError("network_topic_missing")
        return selected

    def _validate_state(self, context: _Context, state: Mapping[str, Any], *, now: int) -> None:
        value = object_fields(state, {"schema_version", "network_id", "issuer_key_id", "last_clock", "roster_checkpoint", "topics", "requests"})
        if (value["schema_version"] != STATE_SCHEMA or value["network_id"] != context.network_id
                or value["issuer_key_id"] != context.issuer.key_id):
            raise TopicStoreError("network_topic_state_binding_mismatch")
        last_clock = integer(value["last_clock"])
        checkpoint = object_fields(value["roster_checkpoint"], {"version", "sha256", "issued_at"})
        version, checkpoint_hash = integer(checkpoint["version"], minimum=1), digest(checkpoint["sha256"])
        issued = integer(checkpoint["issued_at"])
        current_roster = context.roster_payload
        if (current_roster["version"] < version or current_roster["issued_at"] < issued
                or current_roster["version"] == version and document_sha256(context.roster) != checkpoint_hash):
            raise TopicStoreError("network_topic_roster_rollback")
        if current_roster["version"] == version + 1 and current_roster["previous_sha256"] != checkpoint_hash:
            raise TopicStoreError("network_roster_chain_mismatch")
        # This is the operator-selected authority file, not a relay's claim.
        # A valid version gap is permitted, but never lowers the checkpoint.
        if not isinstance(value["topics"], dict) or len(value["topics"]) > MAX_TOPICS:
            raise TopicStoreError("network_topic_capacity")
        if not isinstance(value["requests"], dict) or len(value["requests"]) > MAX_REQUESTS:
            raise TopicStoreError("network_topic_idempotency_capacity")
        verified: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for topic_id, entry in value["topics"].items():
            opaque(topic_id)
            object_fields(entry, {"policy", "snapshot"})
            policy = topics.verify_policy(entry["policy"], context.trust, network_id=context.network_id,
                topic_id=topic_id, issuer_key_id=context.issuer.key_id, now=now, allow_expired=True)
            snapshot = topics.verify_snapshot(entry["snapshot"], context.trust, policy=entry["policy"],
                network_id=context.network_id, topic_id=topic_id, issuer_key_id=context.issuer.key_id,
                now=now, allow_expired=True)
            verified[topic_id] = (policy, snapshot)
        for request_id, entry in value["requests"].items():
            opaque(request_id)
            object_fields(entry, {"change_sha256", "receipt"})
            change_hash = digest(entry["change_sha256"])
            raw_receipt = document(entry["receipt"], maximum=MAX_CHANGE_BYTES)
            topic_id = _document_topic(raw_receipt)
            receipt = topics.verify_subscription_receipt(raw_receipt, context.trust,
                network_id=context.network_id, topic_id=topic_id, issuer_key_id=context.issuer.key_id, now=now)
            if (receipt["request_id"] != request_id or receipt["change_sha256"] != change_hash
                    or receipt["committed_at"] > last_clock or topic_id not in verified):
                raise TopicStoreError("network_topic_cached_receipt_mismatch")
            _, snapshot = verified[topic_id]
            selected = next((item for item in snapshot["subscriptions"]
                if item["grant_id"] == receipt["grant_id"] and item["member_key_id"] == receipt["member_key_id"]), None)
            if selected is None or selected["change"] is None:
                raise TopicStoreError("network_topic_cached_receipt_mismatch")
            change = selected["change"]["payload"]
            if (receipt["revision"] > change["revision"] or receipt["snapshot_version"] > snapshot["version"]
                    or receipt["revision"] == change["revision"] and document_sha256(selected["change"]) != change_hash
                    or receipt["snapshot_version"] == snapshot["version"] and receipt["snapshot_sha256"] != document_sha256(value["topics"][topic_id]["snapshot"])):
                raise TopicStoreError("network_topic_cached_receipt_mismatch")
        self._encode(value)

    @staticmethod
    def _encode(state: Mapping[str, Any]) -> bytes:
        encoded = canonical_bytes(state) + b"\n"
        if len(encoded) > MAX_STATE_BYTES:
            raise TopicStoreError("network_topic_state_capacity")
        document(state, maximum=MAX_STATE_BYTES)
        return encoded

    def _commit(self, context: _Context, state: dict[str, Any], *, now: int, replace: bool = True) -> None:
        committed = deepcopy(state)
        committed["roster_checkpoint"] = self._roster_checkpoint(context)
        self._validate_state(context, committed, now=max(now, committed["last_clock"]))
        encoded = self._encode(committed)
        try:
            storage.atomic_write(context.path, encoded, replace=replace)
        except OSError:
            # Rename may already have succeeded. Never restore old state or
            # report a definite rollback; exact retries complete the barrier.
            raise TopicStoreError("network_topic_commit_uncertain", retryable=True) from None
        context.state = committed

    @staticmethod
    def _roster_checkpoint(context: _Context) -> dict[str, Any]:
        return {"version": context.roster_payload["version"], "sha256": document_sha256(context.roster),
                "issued_at": context.roster_payload["issued_at"]}

    @staticmethod
    def _effective(context: _Context, policy: Mapping[str, Any], snapshot: Mapping[str, Any]) -> list[str]:
        if policy["status"] != "active":
            return []
        members = {item["signing_key"]["key_id"]: item for item in context.roster_payload["members"]}
        grants = {item["grant_id"]: item for item in policy["subscriber_grants"]}
        recipients = []
        for item in snapshot["subscriptions"]:
            change, grant = item["change"], grants[item["grant_id"]]
            member = members.get(item["member_key_id"])
            if (grant["status"] == "active" and change is not None and change["payload"]["state"] == "subscribed"
                    and member is not None and member["status"] == "active" and "receive" in member["scope"]
                    and member["signing_key"] == change["payload"]["member_signing_key"]):
                recipients.append(item["member_key_id"])
        if len(recipients) > 16:
            raise TopicStoreError("network_topic_recipient_capacity")
        return sorted(recipients)

    def initialize(self, *, now: int | None = None) -> dict[str, Any]:
        current = _clock(now)
        with self._transaction(current, initialize=True) as context:
            state = {"schema_version": STATE_SCHEMA, "network_id": context.network_id,
                "issuer_key_id": context.issuer.key_id, "last_clock": current,
                "roster_checkpoint": self._roster_checkpoint(context), "topics": {}, "requests": {}}
            self._commit(context, state, now=current, replace=False)
            return {"state": "topic_authority_initialized", "network_id": context.network_id,
                    "issuer_key_id": context.issuer.key_id, "topic_count": 0}

    def put_policy(self, value: Mapping[str, Any] | bytes, *, now: int | None = None) -> dict[str, Any]:
        current = _clock(now)
        signed = document(value, maximum=MAX_TOPIC_BYTES)
        topic_id = _document_topic(signed)
        with self._transaction(current) as context:
            assert context.state is not None
            previous = context.state["topics"].get(topic_id)
            if previous is not None and canonical_bytes(previous["policy"]) == canonical_bytes(signed):
                self._commit(context, context.state, now=current)
                return deepcopy(previous)
            self._monotonic(context, current)
            policy = topics.verify_policy(signed, context.trust, network_id=context.network_id,
                topic_id=topic_id, issuer_key_id=context.issuer.key_id,
                previous_policy=None if previous is None else previous["policy"], now=current)
            if previous is None and policy["version"] != 1:
                raise TopicStoreError("network_topic_policy_cas_mismatch")
            if previous is not None and policy["version"] != previous["policy"]["payload"]["version"] + 1:
                raise TopicStoreError("network_topic_policy_cas_mismatch")
            if previous is None and len(context.state["topics"]) >= MAX_TOPICS:
                raise TopicStoreError("network_topic_capacity")
            old_changes = {} if previous is None else {
                item["grant_id"]: item["change"] for item in previous["snapshot"]["payload"]["subscriptions"]}
            subscriptions = [{"member_key_id": item["member_key_id"], "grant_id": item["grant_id"],
                              "change": old_changes.get(item["grant_id"])} for item in policy["subscriber_grants"]]
            snapshot = topics.issue_snapshot(context.issuer, network_id=context.network_id, topic_id=topic_id,
                issuer_key_id=context.issuer.key_id, version=1 if previous is None else previous["snapshot"]["payload"]["version"] + 1,
                previous_sha256="0" * 64 if previous is None else document_sha256(previous["snapshot"]),
                policy_version=policy["version"], policy_sha256=document_sha256(signed), subscriptions=subscriptions,
                issued_at=current, expires_at=current + 300)
            checked = topics.verify_snapshot(snapshot, context.trust, policy=signed, network_id=context.network_id,
                topic_id=topic_id, issuer_key_id=context.issuer.key_id,
                previous_snapshot=None if previous is None else previous["snapshot"], now=current, allow_expired=True)
            self._effective(context, policy, checked)
            updated = deepcopy(context.state)
            updated["last_clock"] = current
            updated["topics"][topic_id] = {"policy": signed, "snapshot": snapshot}
            self._commit(context, updated, now=current)
            return deepcopy(updated["topics"][topic_id])

    def subscribe(self, value: Mapping[str, Any] | bytes, *, now: int | None = None) -> dict[str, Any]:
        current = _clock(now)
        signed = document(value, maximum=MAX_CHANGE_BYTES)
        topic_id = _document_topic(signed)
        change_hash = document_sha256(signed)
        with self._transaction(current) as context:
            assert context.state is not None
            change = topics.verify_subscription(signed, network_id=context.network_id, topic_id=topic_id,
                now=max(current, context.state["last_clock"]), allow_expired=True)
            cached = context.state["requests"].get(change["request_id"])
            if cached is not None:
                if cached["change_sha256"] != change_hash:
                    raise TopicStoreError("network_topic_request_conflict")
                # Historical receipt only; no fresh status, clock advance or
                # restored subscription. This also retries a failed fsync.
                self._commit(context, context.state, now=current)
                return deepcopy(cached["receipt"])
            self._monotonic(context, current)
            selected = self._topic(context, topic_id)
            policy, prior = selected["policy"]["payload"], selected["snapshot"]["payload"]
            grant = next((item for item in policy["subscriber_grants"]
                          if item["grant_id"] == change["grant_id"] and item["member_key_id"] == change["member_key_id"]), None)
            member = next((item for item in context.roster_payload["members"]
                           if item["signing_key"]["key_id"] == change["member_key_id"]), None)
            if (policy["status"] != "active" or grant is None or grant["status"] != "active"
                    or member is None or member["status"] != "active" or "receive" not in member["scope"]
                    or member["signing_key"] != change["member_signing_key"]):
                raise TopicStoreError("network_topic_subscription_not_authorized")
            previous = next(item["change"] for item in prior["subscriptions"] if item["grant_id"] == change["grant_id"])
            expected_revision = 1 if previous is None else previous["payload"]["revision"] + 1
            expected_hash = "0" * 64 if previous is None else document_sha256(previous)
            if change["revision"] != expected_revision or change["previous_change_sha256"] != expected_hash:
                raise TopicStoreError("network_topic_subscription_cas_mismatch")
            topics.verify_subscription(signed, network_id=context.network_id, topic_id=topic_id,
                member_key_id=change["member_key_id"], grant_id=change["grant_id"], previous_change=previous, now=current)
            if len(context.state["requests"]) >= MAX_REQUESTS:
                raise TopicStoreError("network_topic_idempotency_capacity")
            subscriptions = [dict(item, change=signed) if item["grant_id"] == change["grant_id"] else item
                             for item in prior["subscriptions"]]
            snapshot = topics.issue_snapshot(context.issuer, network_id=context.network_id, topic_id=topic_id,
                issuer_key_id=context.issuer.key_id, version=prior["version"] + 1,
                previous_sha256=document_sha256(selected["snapshot"]), policy_version=policy["version"],
                policy_sha256=document_sha256(selected["policy"]), subscriptions=subscriptions,
                issued_at=current, expires_at=current + 300)
            checked = topics.verify_snapshot(snapshot, context.trust, policy=selected["policy"],
                network_id=context.network_id, topic_id=topic_id, issuer_key_id=context.issuer.key_id,
                previous_snapshot=selected["snapshot"], now=current, allow_expired=True)
            self._effective(context, policy, checked)
            receipt = topics.issue_subscription_receipt(context.issuer, network_id=context.network_id,
                topic_id=topic_id, issuer_key_id=context.issuer.key_id, member_key_id=change["member_key_id"],
                grant_id=change["grant_id"], request_id=change["request_id"], revision=change["revision"],
                change_sha256=change_hash, snapshot_version=checked["version"], snapshot_sha256=document_sha256(snapshot),
                committed_at=current)
            updated = deepcopy(context.state)
            updated["last_clock"] = current
            updated["topics"][topic_id]["snapshot"] = snapshot
            updated["requests"][change["request_id"]] = {"change_sha256": change_hash, "receipt": receipt}
            self._commit(context, updated, now=current)
            return deepcopy(receipt)

    def current(self, topic_id: str, *, now: int | None = None) -> dict[str, Any]:
        current = _clock(now)
        with self._transaction(current) as context:
            selected = self._topic(context, topic_id)
            return deepcopy({"roster": context.roster, **selected})

    def status(self, topic_id: str, nonce: str, request: Mapping[str, Any] | bytes,
               *, now: int | None = None) -> dict[str, Any]:
        current, topic_id, nonce = _clock(now), opaque(topic_id), opaque(nonce)
        signed_request = document(request, maximum=MAX_CHANGE_BYTES)
        with self._transaction(current) as context:
            assert context.state is not None
            self._monotonic(context, current)
            callers = PublicKeyTrust([item["signing_key"] for item in context.roster_payload["members"]
                                      if item["status"] == "active" and set(item["scope"]) & {"receive", "send"}])
            caller = verify_request(signed_request, callers, network_id=context.network_id, action="status", now=current)
            if object_fields(caller["body"], {"nonce", "topic_id"}) != {"nonce": nonce, "topic_id": topic_id}:
                raise TopicStoreError("network_topic_status_binding_mismatch")
            member_key_id = signed_request["proof"]["key_id"]
            selected = context.state["topics"].get(topic_id)
            if (selected is None or selected["policy"]["payload"]["status"] != "active"
                    or not any(item["member_key_id"] == member_key_id and item["status"] == "active"
                               for role in ("publishers", "subscriber_grants") for item in selected["policy"]["payload"][role])):
                raise TopicStoreError("network_topic_access_denied")
            policy, snapshot = selected["policy"]["payload"], selected["snapshot"]["payload"]
            self._effective(context, policy, snapshot)
            roster_hash = document_sha256(context.roster)
            response = {"roster": context.roster, **selected,
                "status": issue_status(context.issuer, network_id=context.network_id, nonce=nonce,
                    roster_sha256=roster_hash, roster_version=context.roster_payload["version"],
                    issued_at=current, expires_at=current + 300),
                "topic_status": topics.issue_topic_status(context.issuer, network_id=context.network_id,
                    topic_id=topic_id, issuer_key_id=context.issuer.key_id, nonce=nonce,
                    policy_version=policy["version"], policy_sha256=document_sha256(selected["policy"]),
                    snapshot_version=snapshot["version"], snapshot_sha256=document_sha256(selected["snapshot"]),
                    roster_version=context.roster_payload["version"], roster_sha256=roster_hash,
                    issued_at=current, expires_at=current + 300)}
            updated = deepcopy(context.state)
            updated["last_clock"] = current
            self._commit(context, updated, now=current)
            return deepcopy(response)
