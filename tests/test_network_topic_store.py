"""Private synthetic topic transactions; no user state, services or model calls."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_control import issue_roster, sign_request, verify_status
from memory_vault_network_crypto import EncryptionIdentity, document, document_sha256
import memory_vault_storage as storage
from memory_vault_trust import Identity, TrustStore
import memory_vault_topics as topics
import memory_vault_topic_store as module
from memory_vault_topic_store import TopicAuthorityStore, TopicStoreError


def _race_subscribe(config: str, change: dict, now: int, gate: object, results: object) -> None:
    try:
        gate.wait(timeout=10)
        receipt = TopicAuthorityStore(Path(config)).subscribe(change, now=now)
        results.put((True, receipt))
    except MemoryError as exc:
        results.put((False, exc.code))
    except Exception as exc:
        results.put((False, type(exc).__name__))


class TopicStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-topic-store-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.now = int(time.time())
        self.network_id, self.topic_id = "synthetic-topic-network", "synthetic-topic"
        self.issuer = Identity.generate(self.root / "issuer.json")
        self.trust = TrustStore(self.root / "trust.json")
        self.trust.add(self.issuer.public_descriptor())
        self.members = []
        self.identities = []
        self.add_member()
        self.add_member()
        self.roster = issue_roster(self.issuer, network_id=self.network_id, version=1, previous_sha256="0" * 64,
            members=self.members, issued_at=self.now, expires_at=self.now + 300)
        self.roster_path = self.root / "roster.json"
        self.state_path, self.config_path = self.root / "topics.json", self.root / "authority.json"
        self.config = {"schema_version": "memory-vault-network-authority-config/v1", "network_id": self.network_id,
            "identity_path": str(self.root / "issuer.json"), "trust_store_path": str(self.root / "trust.json"),
            "roster_path": str(self.roster_path), "topic_state_path": str(self.state_path)}
        storage.atomic_write(self.roster_path, canonical_bytes(self.roster), replace=False)
        storage.atomic_write(self.config_path, canonical_bytes(self.config), replace=False)
        self.store = TopicAuthorityStore(self.config_path)
        self.store.initialize(now=self.now)
        self.policy = self.make_policy()
        self.initial = self.store.put_policy(self.policy, now=self.now)

    def add_member(self) -> Identity:
        identity = Identity.generate(self.root / ("member-" + str(len(self.identities)) + ".json"))
        encryption = EncryptionIdentity.generate()
        self.identities.append(identity)
        self.members.append({"signing_key": identity.public_descriptor(), "encryption_key": encryption.public_descriptor(),
                             "status": "active", "scope": ["receive", "send"]})
        return identity

    def make_policy(self, *, topic_id: str | None = None, previous: dict | None = None,
                    status: str = "active", grants: list | None = None, now: int | None = None) -> dict:
        return topics.issue_policy(self.issuer, network_id=self.network_id, topic_id=topic_id or self.topic_id,
            issuer_key_id=self.issuer.key_id, version=1 if previous is None else previous["payload"]["version"] + 1,
            previous_sha256="0" * 64 if previous is None else document_sha256(previous), status=status,
            publishers=[{"member_key_id": self.identities[0].key_id, "grant_id": "synthetic-publisher-grant", "status": "active"}],
            subscriber_grants=grants if grants is not None else [
                {"member_key_id": self.identities[1].key_id, "grant_id": "synthetic-subscriber-grant", "status": "active"}],
            issued_at=self.now if now is None else now, expires_at=(self.now if now is None else now) + 300)

    def change(self, *, previous: dict | None = None, state: str = "subscribed", request_id: str = "synthetic-request",
               member: Identity | None = None, grant_id: str = "synthetic-subscriber-grant", now: int | None = None) -> dict:
        return topics.sign_subscription(member or self.identities[1], network_id=self.network_id,
            topic_id=self.topic_id, grant_id=grant_id, revision=1 if previous is None else previous["payload"]["revision"] + 1,
            previous_change_sha256="0" * 64 if previous is None else document_sha256(previous), state=state,
            request_id=request_id, issued_at=self.now if now is None else now,
            expires_at=(self.now if now is None else now) + 300)

    def query(self, *, member: Identity | None = None, now: int | None = None, body: dict | None = None) -> dict:
        current = self.now if now is None else now
        return sign_request(member or self.identities[0], network_id=self.network_id, action="status",
            request_id="synthetic-status-request", body=body or {"nonce": "synthetic-nonce", "topic_id": self.topic_id},
            issued_at=current, expires_at=current + 300)

    def state(self) -> dict:
        return document(self.state_path.read_bytes(), maximum=module.MAX_STATE_BYTES)

    def update_roster(self, *, revoked: int | None = None, now: int | None = None) -> None:
        if revoked is not None:
            self.members[revoked]["status"] = "revoked"
        current = self.now if now is None else now
        self.roster = issue_roster(self.issuer, network_id=self.network_id,
            version=self.roster["payload"]["version"] + 1, previous_sha256=document_sha256(self.roster),
            members=self.members, issued_at=current, expires_at=current + 300)
        with storage.file_lock(self.roster_path.with_name(self.roster_path.name + ".lock")):
            storage.atomic_write(self.roster_path, canonical_bytes(self.roster), replace=True)

    def test_constructor_is_offline_missing_state_is_not_created_and_paths_are_private(self) -> None:
        with (mock.patch.object(module, "_read_private", side_effect=AssertionError("constructor read")),
              mock.patch.object(storage, "file_lock", side_effect=AssertionError("constructor lock")),
              mock.patch.object(storage, "atomic_write", side_effect=AssertionError("constructor write"))):
            TopicAuthorityStore(self.root / "absent-authority.json")
        self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_state_exists"):
            self.store.initialize(now=self.now)
        alternative = {**self.config, "topic_state_path": str(self.root / "not-created" / "topics.json")}
        storage.atomic_write(self.config_path, canonical_bytes(alternative), replace=True)
        before = sorted(p.name for p in self.root.iterdir())
        with self.assertRaisesRegex(TopicStoreError, "network_topic_state_missing"):
            self.store.subscribe(self.change(), now=self.now)
        self.assertEqual(before, sorted(p.name for p in self.root.iterdir()))
        alternative.pop("topic_state_path")
        storage.atomic_write(self.config_path, canonical_bytes(alternative), replace=True)
        with self.assertRaisesRegex(TopicStoreError, "network_topics_not_configured"):
            self.store.initialize(now=self.now)
        for path in (self.config_path, self.roster_path, self.root / "issuer.json", self.root / "trust.json",
                     self.roster_path.with_name(self.roster_path.name + ".lock")):
            storage.atomic_write(self.config_path, canonical_bytes({**self.config, "topic_state_path": str(path)}), replace=True)
            with self.assertRaisesRegex(TopicStoreError, "network_topic_path_conflict"):
                self.store.initialize(now=self.now)

    def test_committed_receipt_restart_and_expired_exact_replay_never_reauthorizes(self) -> None:
        change = self.change()
        receipt = self.store.subscribe(change, now=self.now)
        checked = topics.verify_subscription_receipt(receipt, self.trust, network_id=self.network_id,
            topic_id=self.topic_id, issuer_key_id=self.issuer.key_id, change=change,
            snapshot=self.store.current(self.topic_id, now=self.now)["snapshot"], now=self.now)
        self.assertEqual(checked["state"], "committed")
        before = self.state_path.read_bytes()
        fresh = TopicAuthorityStore(self.config_path)
        self.assertEqual(canonical_bytes(fresh.subscribe(canonical_bytes(change), now=self.now + 1000)), canonical_bytes(receipt))
        self.assertEqual(self.state_path.read_bytes(), before)
        revoked = self.make_policy(previous=self.policy, status="revoked", now=self.now + 1001)
        fresh.put_policy(revoked, now=self.now + 1001)
        self.update_roster(revoked=1, now=self.now + 1001)
        revoked_state = self.state()
        self.assertEqual(fresh.subscribe(change, now=self.now + 1200), receipt)
        after_retry = self.state()
        self.assertEqual(after_retry["topics"], revoked_state["topics"])
        self.assertEqual(after_retry["requests"], revoked_state["requests"])
        self.assertEqual(after_retry["last_clock"], revoked_state["last_clock"])
        self.assertEqual(after_retry["roster_checkpoint"]["sha256"], document_sha256(self.roster))
        with self.assertRaisesRegex(TopicStoreError, "network_topic_subscription_not_authorized"):
            fresh.subscribe(self.change(previous=change, request_id="new-request", now=self.now + 1200), now=self.now + 1200)
        self.assertEqual(fresh.current(self.topic_id, now=self.now + 1200)["policy"], revoked)
        self.assertNotIn("status", receipt)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_access_denied"):
            fresh.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 1200), now=self.now + 1200)

    def test_request_conflict_expired_first_use_and_subscription_cas_are_atomic(self) -> None:
        original = self.change()
        self.store.subscribe(original, now=self.now)
        before = self.state_path.read_bytes()
        conflict = self.change(state="unsubscribed")
        with self.assertRaisesRegex(TopicStoreError, "network_topic_request_conflict"):
            self.store.subscribe(conflict, now=self.now)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_subscription_cas_mismatch"):
            self.store.subscribe(self.change(request_id="other-first-request"), now=self.now)
        expired = self.change(previous=original, request_id="expired-first-request")
        with self.assertRaises(MemoryError) as caught:
            self.store.subscribe(expired, now=self.now + 301)
        self.assertEqual(caught.exception.code, "network_control_expired")
        self.assertEqual(self.state_path.read_bytes(), before)
        # A current operator-selected policy can be old. A new, valid member
        # change creates a fresh snapshot without redefining that old policy.
        next_change = self.change(previous=original, state="unsubscribed", request_id="next-request", now=self.now + 301)
        self.store.subscribe(next_change, now=self.now + 301)
        current = self.store.current(self.topic_id, now=self.now + 301)
        self.assertEqual(current["policy"], self.policy)
        self.assertEqual(current["snapshot"]["payload"]["subscriptions"][0]["change"], next_change)
        packet = self.store.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 301), now=self.now + 301)
        verified = topics.verify_current_topic(packet, self.trust, network_id=self.network_id,
            topic_id=self.topic_id, issuer_key_id=self.issuer.key_id, nonce="synthetic-nonce", now=self.now + 301)
        self.assertEqual(topics.topic_recipients(verified, now=self.now + 301), [])

    def test_member_clock_correction_does_not_prevent_valid_unsubscription(self) -> None:
        first = self.change(now=self.now + 20)
        self.store.subscribe(first, now=self.now)
        corrected = self.change(previous=first, state="unsubscribed", request_id="synthetic-clock-corrected", now=self.now + 1)
        result = self.store.subscribe(corrected, now=self.now + 1)
        self.assertEqual(result["payload"]["revision"], 2)
        selected = self.state()["topics"][self.topic_id]["snapshot"]["payload"]["subscriptions"][0]
        self.assertEqual(selected["change"], corrected)
        self.assertEqual(self.state()["last_clock"], self.now + 1)

    def test_policy_tombstones_regrant_and_same_version_forks_cannot_reset_consent(self) -> None:
        subscribed = self.change()
        receipt = self.store.subscribe(subscribed, now=self.now)
        old_grant = self.policy["payload"]["subscriber_grants"][0]
        revoked_grant = {**old_grant, "status": "revoked"}
        revoke = self.make_policy(previous=self.policy, grants=[revoked_grant], now=self.now + 1)
        self.store.put_policy(revoke, now=self.now + 1)
        baseline = self.state_path.read_bytes()
        for bad in (self.policy, self.make_policy(previous=self.policy, now=self.now + 1),
                    self.make_policy(previous=revoke, grants=[old_grant], now=self.now + 2),
                    self.make_policy(previous=revoke, grants=[], now=self.now + 2)):
            with self.subTest(policy_version=bad["payload"]["version"]), self.assertRaises(MemoryError):
                self.store.put_policy(bad, now=self.now + 2)
            self.assertEqual(self.state_path.read_bytes(), baseline)
        regrant = self.make_policy(previous=revoke, grants=[revoked_grant, {**old_grant, "grant_id": "synthetic-new-grant"}], now=self.now + 2)
        result = self.store.put_policy(regrant, now=self.now + 2)
        changes = {entry["grant_id"]: entry["change"] for entry in result["snapshot"]["payload"]["subscriptions"]}
        self.assertEqual(changes[old_grant["grant_id"]], subscribed)
        self.assertIsNone(changes["synthetic-new-grant"])
        self.assertEqual(self.store.subscribe(subscribed, now=self.now + 2), receipt)
        self.assertIsNone({entry["grant_id"]: entry["change"] for entry in
            self.store.current(self.topic_id, now=self.now + 2)["snapshot"]["payload"]["subscriptions"]}["synthetic-new-grant"])
        self.store.subscribe(self.change(grant_id="synthetic-new-grant", request_id="new-grant-consent", now=self.now + 2), now=self.now + 2)

    def test_two_real_processes_cannot_commit_same_cas_revision_twice(self) -> None:
        context = multiprocessing.get_context("spawn")
        gate, results = context.Barrier(2), context.Queue()
        changes = [self.change(request_id="synthetic-process-" + str(i), state=state)
                   for i, state in enumerate(("subscribed", "unsubscribed"))]
        processes = [context.Process(target=_race_subscribe, args=(str(self.config_path), change, self.now, gate, results)) for change in changes]
        try:
            for process in processes:
                process.start()
            outcomes = [results.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            results.close()
            results.join_thread()
        self.assertEqual(sum(ok for ok, _ in outcomes), 1, outcomes)
        self.assertIn(next(value for ok, value in outcomes if not ok),
                      ("network_topic_busy", "network_topic_subscription_cas_mismatch"))
        state = self.state()
        self.assertEqual(len(state["requests"]), 1)
        self.assertEqual(state["topics"][self.topic_id]["snapshot"]["payload"]["version"], 2)
        winner = next(change for change in changes if change["payload"]["request_id"] in state["requests"])
        loser = next(change for change in changes if change is not winner)
        before = self.state_path.read_bytes()
        with self.assertRaisesRegex(TopicStoreError, "network_topic_subscription_cas_mismatch"):
            self.store.subscribe(loser, now=self.now)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self.store.subscribe(winner, now=self.now), next(value for ok, value in outcomes if ok))

    def test_policy_revocation_and_subscription_share_one_writer_transaction(self) -> None:
        entered, release = threading.Event(), threading.Event()
        real_write = storage.atomic_write
        revoke = self.make_policy(previous=self.policy, status="revoked", now=self.now + 1)
        def paused(path, data, *, replace):
            if path == self.state_path:
                entered.set()
                if not release.wait(5):
                    raise AssertionError("owned synthetic writer was not released")
            return real_write(path, data, replace=replace)
        with ThreadPoolExecutor(max_workers=1) as executor, mock.patch.object(storage, "atomic_write", side_effect=paused):
            future = executor.submit(self.store.put_policy, revoke, now=self.now + 1)
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaisesRegex(TopicStoreError, "network_topic_busy") as busy:
                    TopicAuthorityStore(self.config_path).subscribe(self.change(now=self.now + 1), now=self.now + 1)
                self.assertTrue(busy.exception.retryable)
            finally:
                release.set()
            self.assertEqual(future.result(timeout=5)["policy"], revoke)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_subscription_not_authorized"):
            self.store.subscribe(self.change(now=self.now + 1), now=self.now + 1)
        self.assertEqual(self.state()["requests"], {})

    def test_existing_roster_and_trust_locks_prevent_stale_membership_read(self) -> None:
        for path in (self.roster_path, self.root / "trust.json"):
            with self.subTest(path=path.name), storage.file_lock(path.with_name(path.name + ".lock")):
                with self.assertRaisesRegex(TopicStoreError, "network_topic_busy"):
                    self.store.subscribe(self.change(), now=self.now)
        self.update_roster(revoked=1)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_subscription_not_authorized"):
            self.store.subscribe(self.change(), now=self.now)
        self.assertEqual(self.state()["requests"], {})

    def test_atomic_write_failure_before_or_after_rename_has_no_false_success_and_exact_retry(self) -> None:
        initial = self.state_path.read_bytes()
        real_fsync, real_replace, real_open = storage.os.fsync, storage.os.replace, storage.open_file
        for stage in ("temporary_open", "file_fsync", "rename", "directory_fsync"):
            with self.subTest(stage=stage):
                storage.atomic_write(self.state_path, initial, replace=True)
                change = self.change(request_id="synthetic-failure-" + stage)
                def open_file(path, flags, **kwargs):
                    if stage == "temporary_open" and path.name.startswith(".memory-") and flags & os.O_WRONLY:
                        raise OSError("synthetic write fault")
                    return real_open(path, flags, **kwargs)
                def fsync(fd):
                    directory = stat.S_ISDIR(os.fstat(fd).st_mode)
                    if stage == "directory_fsync" and directory or stage == "file_fsync" and not directory:
                        raise OSError("synthetic flush fault")
                    return real_fsync(fd)
                def replace(source, target):
                    if stage == "rename":
                        raise OSError("synthetic rename fault")
                    return real_replace(source, target)
                with (mock.patch.object(storage, "open_file", side_effect=open_file),
                      mock.patch.object(storage.os, "fsync", side_effect=fsync),
                      mock.patch.object(storage.os, "replace", side_effect=replace)):
                    with self.assertRaisesRegex(TopicStoreError, "network_topic_commit_uncertain") as failed:
                        self.store.subscribe(change, now=self.now)
                self.assertTrue(failed.exception.retryable)
                state = self.state()
                if stage == "directory_fsync":
                    self.assertEqual(len(state["requests"]), 1)
                    prior_receipt = state["requests"][change["payload"]["request_id"]]["receipt"]
                else:
                    self.assertEqual(self.state_path.read_bytes(), initial)
                    prior_receipt = None
                self.assertFalse(any(path.name.startswith(".memory-") for path in self.root.iterdir()))
                receipt = TopicAuthorityStore(self.config_path).subscribe(change, now=self.now)
                self.assertEqual(self.state()["topics"][self.topic_id]["snapshot"]["payload"]["version"], 2)
                self.assertEqual(len(self.state()["requests"]), 1)
                if prior_receipt is not None:
                    self.assertEqual(receipt, prior_receipt)

    def test_whole_poststate_byte_limit_and_incoming_four_mib_limit(self) -> None:
        self.assertEqual(module.MAX_STATE_BYTES, 4 * 1024 * 1024)
        before = self.state_path.read_bytes()
        change = self.change()
        self.store.subscribe(change, now=self.now)
        after = self.state_path.read_bytes()
        self.assertGreater(len(after), len(before))
        storage.atomic_write(self.state_path, before, replace=True)
        with mock.patch.object(module, "MAX_STATE_BYTES", len(after) - 1):
            with self.assertRaisesRegex(TopicStoreError, "network_topic_state_capacity"):
                self.store.subscribe(change, now=self.now)
        self.assertEqual(self.state_path.read_bytes(), before)
        padded = before + b" " * (module.MAX_STATE_BYTES - len(before))
        storage.atomic_write(self.state_path, padded, replace=True)
        self.assertEqual(self.store.current(self.topic_id, now=self.now)["policy"], self.policy)
        storage.atomic_write(self.state_path, padded + b" ", replace=True)
        with self.assertRaises(Exception) as rejected:
            self.store.current(self.topic_id, now=self.now)
        self.assertEqual(getattr(rejected.exception, "code", None), "private_file_too_large")
        self.assertEqual(self.state_path.stat().st_size, module.MAX_STATE_BYTES + 1)

    def test_request_cache_is_bounded_without_evicting_exact_retries(self) -> None:
        self.assertEqual(module.MAX_REQUESTS, 1024)
        first = self.change()
        second = self.change(previous=first, request_id="synthetic-second", state="unsubscribed")
        with mock.patch.object(module, "MAX_REQUESTS", 2):
            receipt = self.store.subscribe(first, now=self.now)
            self.store.subscribe(second, now=self.now)
            before = self.state_path.read_bytes()
            third = self.change(previous=second, request_id="synthetic-third")
            with self.assertRaisesRegex(TopicStoreError, "network_topic_idempotency_capacity"):
                self.store.subscribe(third, now=self.now)
            self.assertEqual(self.store.subscribe(first, now=self.now + 301), receipt)
            self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(self.state()["requests"]), 2)

    def test_actual_thirty_two_topics_include_tombstones_and_do_not_evict(self) -> None:
        self.assertEqual(module.MAX_TOPICS, 32)
        for index in range(1, 32):
            self.store.put_policy(self.make_policy(topic_id="synthetic-topic-" + str(index)), now=self.now)
        revoke = self.make_policy(previous=self.policy, status="revoked")
        self.store.put_policy(revoke, now=self.now)
        before = self.state_path.read_bytes()
        with self.assertRaisesRegex(TopicStoreError, "network_topic_capacity"):
            self.store.put_policy(self.make_policy(topic_id="synthetic-topic-over-limit"), now=self.now)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(self.state()["topics"]), 32)
        self.assertEqual(self.store.put_policy(revoke, now=self.now + 1000)["policy"], revoke)

    def test_status_is_fresh_joint_member_authorized_and_clock_cannot_roll_back(self) -> None:
        self.store.subscribe(self.change(), now=self.now)
        response = self.store.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 4), now=self.now + 4)
        self.assertEqual(set(response), {"roster", "status", "policy", "snapshot", "topic_status"})
        verify_status(response["status"], self.trust, network_id=self.network_id, nonce="synthetic-nonce",
            roster_sha256=document_sha256(response["roster"]), roster_version=response["roster"]["payload"]["version"], now=self.now + 4)
        topics.verify_topic_status(response["topic_status"], self.trust, network_id=self.network_id,
            topic_id=self.topic_id, issuer_key_id=self.issuer.key_id, nonce="synthetic-nonce",
            policy_sha256=document_sha256(response["policy"]), snapshot_sha256=document_sha256(response["snapshot"]),
            roster_sha256=document_sha256(response["roster"]), now=self.now + 4)
        self.assertEqual(response["status"]["payload"]["issued_at"], response["topic_status"]["payload"]["issued_at"])
        before = self.state_path.read_bytes()
        with self.assertRaisesRegex(TopicStoreError, "network_topic_clock_rollback"):
            self.store.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 3), now=self.now + 3)
        with self.assertRaises(MemoryError):
            self.store.status(self.topic_id, "synthetic-nonce", self.query(body={"nonce": "synthetic-nonce"}, now=self.now + 4), now=self.now + 4)
        with self.assertRaises(MemoryError) as expired:
            self.store.status(self.topic_id, "synthetic-nonce", self.query(), now=self.now + 301)
        self.assertEqual(expired.exception.code, "network_control_expired")
        outsider = self.add_member()
        self.update_roster(now=self.now + 4)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_access_denied"):
            self.store.status(self.topic_id, "synthetic-nonce", self.query(member=outsider, now=self.now + 4), now=self.now + 4)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(self.state()["last_clock"], self.now + 4)

    def test_effective_subscriber_limit_is_checked_before_durable_commit(self) -> None:
        for _ in range(16):
            self.add_member()
        self.update_roster()
        grants = [{"member_key_id": self.identities[i].key_id, "grant_id": "synthetic-many-grant-" + str(i), "status": "active"}
                  for i in range(2, 18)]
        # Keep the original grant tombstone and add sixteen fresh member grants.
        original = self.policy["payload"]["subscriber_grants"][0]
        changed = self.make_policy(previous=self.policy, grants=[original, *grants])
        self.store.put_policy(changed, now=self.now)
        self.store.subscribe(self.change(), now=self.now)
        for i in range(2, 17):
            self.store.subscribe(self.change(member=self.identities[i], grant_id="synthetic-many-grant-" + str(i),
                request_id="synthetic-many-request-" + str(i)), now=self.now)
        before = self.state_path.read_bytes()
        with self.assertRaisesRegex(TopicStoreError, "network_topic_recipient_capacity"):
            self.store.subscribe(self.change(member=self.identities[17], grant_id="synthetic-many-grant-17",
                request_id="synthetic-many-request-17"), now=self.now)
        self.assertEqual(self.state_path.read_bytes(), before)
        self.assertEqual(len(self.state()["requests"]), 16)

    def test_partial_old_roster_restore_cannot_sign_fresh_status_or_restore_permission(self) -> None:
        change = self.change()
        receipt = self.store.subscribe(change, now=self.now)
        old_roster = self.roster_path.read_bytes()
        self.update_roster(revoked=1, now=self.now + 1)
        current_roster = self.roster_path.read_bytes()
        self.store.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 1), now=self.now + 1)
        before = self.state_path.read_bytes()
        self.assertEqual(self.state()["roster_checkpoint"]["version"], 2)
        storage.atomic_write(self.roster_path, old_roster, replace=True)
        for operation in (
                lambda: self.store.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 2), now=self.now + 2),
                lambda: self.store.subscribe(change, now=self.now + 2)):
            with self.assertRaisesRegex(TopicStoreError, "network_topic_roster_rollback"):
                operation()
        self.assertEqual(self.state_path.read_bytes(), before)
        # A same-version signed fork also cannot replace the checkpoint.
        fork_members = deepcopy(self.members)
        fork_members[1]["status"] = "active"
        forked = issue_roster(self.issuer, network_id=self.network_id, version=2,
            previous_sha256=document_sha256(document(old_roster)),
            members=fork_members, issued_at=self.now + 1, expires_at=self.now + 301)
        storage.atomic_write(self.roster_path, canonical_bytes(forked), replace=True)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_roster_rollback"):
            self.store.current(self.topic_id, now=self.now + 2)
        storage.atomic_write(self.roster_path, current_roster, replace=True)
        self.assertEqual(self.store.subscribe(change, now=self.now + 400), receipt)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_subscription_not_authorized"):
            self.store.subscribe(self.change(previous=change, request_id="not-revived", now=self.now + 400), now=self.now + 400)
        adjacent_fork = issue_roster(self.issuer, network_id=self.network_id, version=3,
            previous_sha256="a" * 64, members=self.members, issued_at=self.now + 2, expires_at=self.now + 302)
        storage.atomic_write(self.roster_path, canonical_bytes(adjacent_fork), replace=True)
        with self.assertRaisesRegex(TopicStoreError, "network_roster_chain_mismatch"):
            self.store.current(self.topic_id, now=self.now + 2)
        older_clock = issue_roster(self.issuer, network_id=self.network_id, version=3,
            previous_sha256=document_sha256(document(current_roster)), members=self.members,
            issued_at=self.now, expires_at=self.now + 300)
        storage.atomic_write(self.roster_path, canonical_bytes(older_clock), replace=True)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_roster_rollback"):
            self.store.current(self.topic_id, now=self.now + 2)
        # The explicit authority file can skip unseen intermediate versions;
        # after a durable joint status that higher checkpoint cannot go back.
        gap = issue_roster(self.issuer, network_id=self.network_id, version=4,
            previous_sha256="b" * 64, members=self.members, issued_at=self.now + 3, expires_at=self.now + 303)
        storage.atomic_write(self.roster_path, canonical_bytes(gap), replace=True)
        self.store.status(self.topic_id, "synthetic-nonce", self.query(now=self.now + 3), now=self.now + 3)
        self.assertEqual(self.state()["roster_checkpoint"]["version"], 4)
        storage.atomic_write(self.roster_path, current_roster, replace=True)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_roster_rollback"):
            self.store.current(self.topic_id, now=self.now + 4)

    def test_malformed_requests_state_binding_and_foreign_issuer_remain_typed_rejections(self) -> None:
        before = self.state_path.read_bytes()
        for value in ({"payload": [], "proof": {}}, {"payload": None, "proof": {}},
                      {"payload": "synthetic", "proof": {}}, {"not": "a signed change"}):
            for method in (self.store.subscribe, self.store.put_policy):
                with self.subTest(value_type=type(value.get("payload")).__name__, method=method.__name__), self.assertRaises(MemoryError):
                    method(value, now=self.now)
        self.assertEqual(self.state_path.read_bytes(), before)
        altered = self.state()
        altered["network_id"] = "synthetic-other-network"
        storage.atomic_write(self.state_path, canonical_bytes(altered), replace=True)
        with self.assertRaisesRegex(TopicStoreError, "network_topic_state_binding_mismatch"):
            self.store.current(self.topic_id, now=self.now)
        storage.atomic_write(self.state_path, before, replace=True)
        foreign = Identity.generate(self.root / "different-issuer.json")
        self.trust.add(foreign.public_descriptor())
        forged_roster = issue_roster(foreign, network_id=self.network_id, version=2,
            previous_sha256=document_sha256(self.roster), members=self.members,
            issued_at=self.now, expires_at=self.now + 300)
        storage.atomic_write(self.roster_path, canonical_bytes(forged_roster), replace=True)
        with self.assertRaises(MemoryError):
            self.store.current(self.topic_id, now=self.now)
        self.assertEqual(self.state_path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
