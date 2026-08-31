"""Synthetic topic control tests; no sockets, user keys or memory databases."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_control import issue_roster, issue_status
from memory_vault_network_crypto import EncryptionIdentity, PublicKeyTrust, document_sha256
from memory_vault_trust import Identity, TrustError
import memory_vault_topics as topics


def identity():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Identity(Ed25519PrivateKey.generate())


class NetworkTopicTests(unittest.TestCase):
    def setUp(self):
        self.issuer, self.other, self.publisher, self.subscriber = [identity() for _ in range(4)]
        self.now = 2_000_000_000
        self.network, self.topic, self.nonce = "synthetic-topic-network", "synthetic-topic-id", "synthetic-topic-nonce"
        self.options = {"network_id": self.network, "topic_id": self.topic, "issuer_key_id": self.issuer.key_id}
        self.trust = PublicKeyTrust([self.issuer.public_descriptor(), self.other.public_descriptor()])
        self.members = [{"signing_key": member.public_descriptor(), "encryption_key": EncryptionIdentity.generate().public_descriptor(),
                         "status": "active", "scope": ["receive", "send"]} for member in (self.publisher, self.subscriber)]
        self.roster = self.make_roster()
        self.publisher_grant = {"member_key_id": self.publisher.key_id, "grant_id": "synthetic-publisher-grant", "status": "active"}
        self.subscriber_grant = {"member_key_id": self.subscriber.key_id, "grant_id": "synthetic-subscriber-grant", "status": "active"}
        self.policy = self.make_policy()
        self.change = self.make_change()
        self.snapshot = self.make_snapshot()

    def sign(self, payload, signer=None):
        return {"payload": payload, "proof": (signer or self.issuer).sign_message(payload)}

    def make_roster(self, members=None, previous=None, at=None):
        at = self.now if at is None else at
        return issue_roster(self.issuer, network_id=self.network, members=self.members if members is None else members,
            version=1 if previous is None else previous["payload"]["version"] + 1,
            previous_sha256=topics.ZERO if previous is None else document_sha256(previous), issued_at=at, expires_at=at + 300)

    def make_policy(self, previous=None, **kwargs):
        args = {**self.options, "version": 1 if previous is None else previous["payload"]["version"] + 1,
                "previous_sha256": topics.ZERO if previous is None else document_sha256(previous),
                "status": "active", "publishers": [self.publisher_grant], "subscriber_grants": [self.subscriber_grant],
                "issued_at": self.now, "expires_at": self.now + 300}
        args.update(kwargs)
        return topics.issue_policy(self.issuer, **args)

    def make_change(self, previous=None, signer=None, **kwargs):
        args = {"network_id": self.network, "topic_id": self.topic, "grant_id": self.subscriber_grant["grant_id"],
                "revision": 1 if previous is None else previous["payload"]["revision"] + 1,
                "previous_change_sha256": topics.ZERO if previous is None else document_sha256(previous),
                "state": "subscribed", "request_id": "synthetic-subscription-request-" + str(1 if previous is None else previous["payload"]["revision"] + 1),
                "issued_at": self.now, "expires_at": self.now + 60}
        args.update(kwargs)
        return topics.sign_subscription(signer or self.subscriber, **args)

    def make_snapshot(self, policy=None, previous=None, changes=None, **kwargs):
        policy = self.policy if policy is None else policy
        changes = {self.subscriber_grant["grant_id"]: self.change} if changes is None else changes
        args = {**self.options, "version": 1 if previous is None else previous["payload"]["version"] + 1,
                "previous_sha256": topics.ZERO if previous is None else document_sha256(previous),
                "policy_version": policy["payload"]["version"], "policy_sha256": document_sha256(policy),
                "subscriptions": [{"member_key_id": grant["member_key_id"], "grant_id": grant["grant_id"],
                                   "change": changes.get(grant["grant_id"])} for grant in policy["payload"]["subscriber_grants"]],
                "issued_at": self.now, "expires_at": self.now + 300}
        args.update(kwargs)
        return topics.issue_snapshot(self.issuer, **args)

    def response(self, policy=None, snapshot=None, roster=None, at=None, nonce=None):
        policy, snapshot, roster = policy or self.policy, snapshot or self.snapshot, roster or self.roster
        at, nonce = self.now if at is None else at, self.nonce if nonce is None else nonce
        return {"policy": policy, "snapshot": snapshot, "roster": roster,
                "status": issue_status(self.issuer, network_id=self.network, nonce=nonce,
                    roster_sha256=document_sha256(roster), roster_version=roster["payload"]["version"], issued_at=at, expires_at=at + 300),
                "topic_status": topics.issue_topic_status(self.issuer, **self.options, nonce=nonce,
                    policy_version=policy["payload"]["version"], policy_sha256=document_sha256(policy),
                    snapshot_version=snapshot["payload"]["version"], snapshot_sha256=document_sha256(snapshot),
                    roster_version=roster["payload"]["version"], roster_sha256=document_sha256(roster), issued_at=at, expires_at=at + 300)}

    def current(self, response=None, **kwargs):
        return topics.verify_current_topic(response or self.response(), self.trust,
                                           **{**self.options, "nonce": self.nonce, "now": self.now, **kwargs})

    def reject(self, code, function, *args, **kwargs):
        with self.assertRaises(MemoryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_expected_issuer_is_pinned_even_among_trusted_roots(self):
        verified = topics.verify_policy(self.policy, self.trust, **self.options, now=self.now)
        self.assertEqual(verified, self.policy["payload"])
        forged = self.sign(self.policy["payload"], self.other)
        self.reject("network_topic_issuer_mismatch", topics.verify_policy, forged, self.trust, **self.options, now=self.now)
        changed = {**self.policy["payload"], "issuer_key_id": self.other.key_id}
        self.reject("network_topic_issuer_mismatch", topics.verify_policy, self.sign(changed, self.other), self.trust, **self.options, now=self.now)
        self.reject("network_topic_policy_binding_mismatch", topics.verify_policy, self.policy, self.trust,
                    **{**self.options, "topic_id": "different-topic"}, now=self.now)
        with self.assertRaises(TrustError):
            self.trust.require_trusted(self.subscriber.key_id)
        topics.verify_subscription(self.change, network_id=self.network, topic_id=self.topic, now=self.now)
        with self.assertRaises(TrustError):
            self.trust.require_trusted(self.subscriber.key_id)

    def test_grant_role_member_and_tombstones_cannot_be_rewritten(self):
        revoked = self.make_policy(self.policy, subscriber_grants=[{**self.subscriber_grant, "status": "revoked"}])
        topics.verify_policy(revoked, self.trust, **self.options, previous_policy=self.policy, now=self.now)
        cases = [(self.make_policy(revoked), "network_topic_reactivation_forbidden"),
                 (self.make_policy(revoked, subscriber_grants=[]), "network_topic_tombstone_required"),
                 (self.make_policy(self.policy, subscriber_grants=[{**self.subscriber_grant, "member_key_id": self.publisher.key_id}]), "network_topic_grant_identity_changed"),
                 (self.make_policy(self.policy, publishers=[self.subscriber_grant], subscriber_grants=[self.publisher_grant]), "network_topic_grant_identity_changed")]
        for doc, code in cases:
            previous = revoked if doc["payload"]["version"] == 3 else self.policy
            self.reject(code, topics.verify_policy, doc, self.trust, **self.options, previous_policy=previous, now=self.now)
        dead = self.make_policy(self.policy, status="revoked")
        self.reject("network_topic_reactivation_forbidden", topics.verify_policy, self.make_policy(dead), self.trust,
                    **self.options, previous_policy=dead, now=self.now)
        for entries, code in (([self.subscriber_grant, self.subscriber_grant], "network_topic_duplicate_grant"),
                              ([self.subscriber_grant, {**self.subscriber_grant, "grant_id": "synthetic-second"}], "network_topic_active_grant_conflict")):
            self.reject(code, self.make_policy, subscriber_grants=entries)
        same_id = {**self.subscriber_grant, "grant_id": self.publisher_grant["grant_id"]}
        self.reject("network_topic_duplicate_grant", self.make_policy, subscriber_grants=[same_id])

    def test_policy_continuity_and_fresh_joint_proof_required_for_gaps(self):
        second = self.make_policy(self.policy)
        third = self.make_policy(second)
        snapshot2 = self.make_snapshot(second, self.snapshot)
        snapshot3 = self.make_snapshot(third, snapshot2)
        self.reject("network_topic_gap_requires_current", topics.verify_policy, third, self.trust,
                    **self.options, previous_policy=self.policy, now=self.now)
        self.reject("network_topic_gap_requires_current", topics.verify_snapshot, snapshot3, self.trust,
                    policy=third, **self.options, previous_snapshot=self.snapshot, now=self.now)
        current = self.current(self.response(third, snapshot3), previous_policy=self.policy, previous_snapshot=self.snapshot)
        self.assertEqual(len(topics.topic_recipients(current, now=self.now)), 1)
        self.reject("network_topic_version_conflict", topics.verify_policy, self.make_policy(status="revoked"), self.trust,
                    **self.options, previous_policy=self.policy, now=self.now)
        self.reject("network_topic_rollback", topics.verify_policy, self.policy, self.trust, **self.options, previous_policy=second, now=self.now)
        broken = self.make_policy(self.policy, previous_sha256="a" * 64)
        self.reject("network_topic_chain_mismatch", topics.verify_policy, broken, self.trust, **self.options, previous_policy=self.policy, now=self.now)
        dropped = self.make_policy(second, subscriber_grants=[])
        empty = self.make_snapshot(dropped, snapshot2)
        self.reject("network_topic_tombstone_required", self.current, self.response(dropped, empty),
                    previous_policy=self.policy, previous_snapshot=self.snapshot)

    def test_removed_members_history_verifies_without_creating_admission(self):
        removed = self.make_roster([self.members[0]], self.roster)
        with patch("memory_vault_trust.TrustStore.add", side_effect=AssertionError("no identity enrollment")):
            topics.verify_snapshot(self.snapshot, self.trust, policy=self.policy, **self.options, now=self.now)
            self.assertEqual(topics.topic_recipients(self.current(self.response(roster=removed)), now=self.now), [])
        forged = {**self.change["payload"], "member_signing_key": self.publisher.public_descriptor()}
        self.reject("network_topic_subscription_binding_mismatch", topics.verify_subscription, self.sign(forged, self.publisher),
                    network_id=self.network, topic_id=self.topic, now=self.now)
        self.reject("network_topic_subscription_binding_mismatch", topics.verify_subscription, self.change,
                    network_id=self.network, topic_id=self.topic, member_key_id=self.publisher.key_id, now=self.now)

    def test_subscription_revision_compare_and_swap_and_self_signatures(self):
        next_change = self.make_change(self.change, state="unsubscribed")
        topics.verify_subscription(next_change, network_id=self.network, topic_id=self.topic,
                                   previous_change=self.change, now=self.now)
        topics.verify_subscription(self.change, network_id=self.network, topic_id=self.topic,
                                   previous_change=self.change, now=self.now)
        for doc, code in ((self.make_change(request_id="different-request"), "network_topic_change_conflict"),
                          (self.make_change(self.change, previous_change_sha256="a" * 64), "network_topic_change_chain_mismatch"),
                          (self.make_change(next_change), "network_topic_change_gap_requires_current")):
            self.reject(code, topics.verify_subscription, doc, network_id=self.network, topic_id=self.topic,
                        previous_change=self.change, now=self.now)
        self.reject("network_topic_change_rollback", topics.verify_subscription, self.change, network_id=self.network,
                    topic_id=self.topic, previous_change=next_change, now=self.now)
        tampered = copy.deepcopy(self.change)
        tampered["payload"]["state"] = "unsubscribed"
        with self.assertRaises(MemoryError):
            topics.verify_subscription(tampered, network_id=self.network, topic_id=self.topic, now=self.now)

    def test_snapshot_is_complete_and_cannot_erase_latest_consent(self):
        missing = self.make_snapshot(subscriptions=[])
        self.reject("network_topic_snapshot_incomplete", topics.verify_snapshot, missing, self.trust,
                    policy=self.policy, **self.options, now=self.now)
        cleared = self.make_snapshot(previous=self.snapshot, changes={})
        self.reject("network_topic_change_missing", topics.verify_snapshot, cleared, self.trust,
                    policy=self.policy, **self.options, previous_snapshot=self.snapshot, now=self.now)
        wrong = self.make_snapshot(policy_sha256="a" * 64)
        self.reject("network_topic_snapshot_policy_mismatch", topics.verify_snapshot, wrong, self.trust,
                    policy=self.policy, **self.options, now=self.now)
        null = self.make_snapshot(changes={})
        accepted = self.make_snapshot(previous=null)
        topics.verify_snapshot(accepted, self.trust, policy=self.policy, **self.options, previous_snapshot=null, now=self.now)

    def test_member_clock_correction_does_not_block_valid_unsubscribe(self):
        ahead = self.make_change(issued_at=self.now + 30, expires_at=self.now + 90)
        previous = self.make_snapshot(changes={self.subscriber_grant["grant_id"]: ahead})
        corrected = self.make_change(ahead, state="unsubscribed", issued_at=self.now + 1, expires_at=self.now + 61)
        topics.verify_subscription(corrected, network_id=self.network, topic_id=self.topic,
                                   previous_change=ahead, now=self.now + 1)
        snapshot = self.make_snapshot(previous=previous, changes={self.subscriber_grant["grant_id"]: corrected},
                                      issued_at=self.now + 1, expires_at=self.now + 301)
        topics.verify_snapshot(snapshot, self.trust, policy=self.policy, **self.options,
                               previous_snapshot=previous, now=self.now + 1)
        current = self.current(self.response(snapshot=snapshot, at=self.now + 1), now=self.now + 1,
                               previous_policy=self.policy, previous_snapshot=previous)
        self.assertEqual(topics.topic_recipients(current, now=self.now + 1), [])

    def test_resubscribe_changes_frozen_identity_and_regrant_does_not_copy_consent(self):
        original = topics.topic_recipients(self.current(), now=self.now)[0]
        unsub = self.make_change(self.change, state="unsubscribed")
        unsub_snapshot = self.make_snapshot(previous=self.snapshot, changes={self.subscriber_grant["grant_id"]: unsub})
        self.assertEqual(topics.topic_recipients(self.current(self.response(snapshot=unsub_snapshot)), now=self.now), [])
        resub = self.make_change(unsub)
        resub_snapshot = self.make_snapshot(previous=unsub_snapshot, changes={self.subscriber_grant["grant_id"]: resub})
        current = self.current(self.response(snapshot=resub_snapshot), previous_policy=self.policy, previous_snapshot=self.snapshot)
        changed = topics.topic_recipients(current, now=self.now)[0]
        self.assertEqual(changed["grant_id"], original["grant_id"])
        # Future carrier must compare this exact hash, not only current state.
        self.assertNotEqual(changed["change_sha256"], original["change_sha256"])
        new_grant = {**self.subscriber_grant, "grant_id": "synthetic-fresh-grant"}
        policy = self.make_policy(self.policy, subscriber_grants=[{**self.subscriber_grant, "status": "revoked"}, new_grant])
        snapshot = self.make_snapshot(policy, self.snapshot)
        self.assertEqual(topics.topic_recipients(self.current(self.response(policy, snapshot), previous_policy=self.policy,
                                                              previous_snapshot=self.snapshot), now=self.now), [])

    def test_joint_nonce_hash_versions_and_checkpoints_are_all_bound(self):
        self.reject("network_status_binding_mismatch", self.current, nonce="wrong-nonce")
        response = self.response()
        response["topic_status"] = self.response(nonce="other-nonce")["topic_status"]
        self.reject("network_topic_status_binding_mismatch", self.current, response)
        for key, value in (("policy_sha256", "a" * 64), ("snapshot_version", 2), ("roster_sha256", "a" * 64)):
            response = self.response()
            response["topic_status"] = self.sign({**response["topic_status"]["payload"], key: value})
            self.reject("network_topic_status_binding_mismatch", self.current, response)
        self.reject("network_topic_status_rollback", self.current, minimum_topic_status_issued_at=self.now + 1)
        self.reject("network_topic_status_rollback", self.current, minimum_status_issued_at=self.now + 1)
        self.reject("network_topic_checkpoint_incomplete", self.current, previous_policy=self.policy)
        response = self.response()
        response["status"] = self.sign(response["status"]["payload"], self.other)
        self.reject("unknown_key", self.current, response)

    def test_fresh_snapshot_and_joint_status_can_reuse_expired_policy(self):
        later = self.now + 400
        self.reject("network_control_expired", topics.verify_policy, self.policy, self.trust, **self.options, now=later)
        snapshot = self.make_snapshot(previous=self.snapshot, issued_at=later, expires_at=later + 300)
        topics.verify_snapshot(snapshot, self.trust, policy=self.policy, **self.options, now=later,
                               previous_snapshot=self.snapshot)
        current = self.current(self.response(snapshot=snapshot, at=later), now=later,
                               previous_policy=self.policy, previous_snapshot=self.snapshot)
        self.assertEqual(len(topics.topic_recipients(current, now=later)), 1)

    def test_capability_is_process_local_immutable_and_lease_bounded(self):
        current = self.current()
        copied = topics.CurrentTopic(current._wire, current.verified_at, current.expires_at)
        self.reject("network_topic_capability_required", topics.topic_recipients, copied, now=self.now)
        self.reject("network_topic_capability_required", topics.topic_recipients, self.response(), now=self.now)
        view = current.snapshot
        view["payload"]["subscriptions"][0]["change"] = None
        self.assertEqual(len(topics.topic_recipients(current, now=self.now)), 1)
        self.reject("network_topic_clock_rollback", topics.topic_recipients, current, now=self.now - 1)
        self.reject("network_control_expired", topics.topic_recipients, current, now=self.now + 300)
        with patch.object(topics.time, "monotonic", side_effect=[100.0, 401.0]):
            current = self.current()
            self.reject("network_control_expired", topics.topic_recipients, current, now=self.now)

    def test_publisher_requires_both_current_network_scope_and_topic_grant(self):
        result = topics.authorized_topic_publisher(self.current(), self.publisher.key_id, now=self.now)
        self.assertEqual(result["grant_id"], self.publisher_grant["grant_id"])
        self.reject("network_topic_publisher_denied", topics.authorized_topic_publisher, self.current(), self.subscriber.key_id, now=self.now)
        self.reject("network_topic_publisher_denied", topics.authorized_topic_publisher, self.current(), self.publisher.key_id,
                    now=self.now, grant_id="synthetic-other-grant")
        members = copy.deepcopy(self.members)
        members[0]["scope"] = ["receive"]
        limited = self.current(self.response(roster=self.make_roster(members, self.roster)))
        self.reject("network_topic_publisher_denied", topics.authorized_topic_publisher, limited, self.publisher.key_id, now=self.now)
        revoked = self.make_policy(self.policy, status="revoked")
        dead = self.current(self.response(revoked, self.make_snapshot(revoked, self.snapshot)))
        self.reject("network_topic_inactive", topics.topic_recipients, dead, now=self.now)

    def test_future_clock_allowance_does_not_extend_five_minute_capability(self):
        response = self.response(at=self.now + 30)
        self.assertEqual(response["topic_status"]["payload"]["expires_at"], self.now + 330)
        with patch.object(topics.time, "monotonic", side_effect=[100.0, 399.0, 400.0]):
            current = self.current(response)
            self.assertEqual(current.expires_at, self.now + 300)
            self.assertEqual(len(topics.topic_recipients(current, now=self.now)), 1)
            self.reject("network_control_expired", topics.topic_recipients, current, now=self.now)

    def test_effective_recipient_limit_rejects_without_truncation(self):
        recipients = [identity() for _ in range(17)]
        grants = [{"member_key_id": key.key_id, "grant_id": "synthetic-grant-" + str(index), "status": "active"}
                  for index, key in enumerate(recipients)]
        changes = {grant["grant_id"]: self.make_change(signer=key, grant_id=grant["grant_id"])
                   for key, grant in zip(recipients, grants)}
        members = [self.members[0]] + [{"signing_key": key.public_descriptor(), "encryption_key": EncryptionIdentity.generate().public_descriptor(),
                                       "status": "active", "scope": ["receive"]} for key in recipients]
        policy = self.make_policy(subscriber_grants=grants)
        snapshot = self.make_snapshot(policy, changes=changes)
        current = self.current(self.response(policy, snapshot, self.make_roster(members)))
        self.reject("network_topic_recipient_limit", topics.topic_recipients, current, now=self.now)
        members[-1]["status"] = "revoked"
        reduced = self.current(self.response(policy, snapshot, self.make_roster(members)))
        selected = topics.topic_recipients(reduced, now=self.now)
        self.assertEqual(len(selected), 16)
        self.assertEqual([row["member_key_id"] for row in selected], sorted(row["member_key_id"] for row in selected))

    def test_committed_receipt_remains_historical_and_bound_after_expiry(self):
        receipt = topics.issue_subscription_receipt(self.issuer, **self.options, member_key_id=self.subscriber.key_id,
            grant_id=self.subscriber_grant["grant_id"], request_id=self.change["payload"]["request_id"], revision=1,
            change_sha256=document_sha256(self.change), snapshot_version=1, snapshot_sha256=document_sha256(self.snapshot), committed_at=self.now)
        result = topics.verify_subscription_receipt(receipt, self.trust, **self.options, change=self.change,
                                                    snapshot=self.snapshot, now=self.now + 1000)
        self.assertEqual(result["state"], "committed")
        self.reject("network_topic_receipt_binding_mismatch", topics.verify_subscription_receipt, receipt, self.trust,
                    **self.options, change=self.make_change(request_id="synthetic-different-request"), now=self.now + 1000)
        self.reject("network_topic_receipt_binding_mismatch", topics.verify_subscription_receipt, receipt, self.trust,
                    **self.options, snapshot=self.make_snapshot(previous=self.snapshot), now=self.now + 1000)
        self.reject("network_topic_capability_required", topics.topic_recipients, result, now=self.now)

    def test_strict_json_safe_integers_and_complete_wrapper_byte_limits(self):
        raw = canonical_bytes(self.policy)
        duplicate = raw.replace(b'"version":1', b'"version":1,"version":1')
        with self.assertRaises(MemoryError):
            topics.verify_policy(duplicate, self.trust, **self.options, now=self.now)
        for value in (True, 0, 2**53):
            malicious = self.sign({**self.policy["payload"], "version": value})
            with self.assertRaises(MemoryError):
                topics.verify_policy(malicious, self.trust, **self.options, now=self.now)
        for signed, maximum, call in ((self.policy, topics.MAX_POLICY_BYTES,
                                      lambda value: topics.verify_policy(value, self.trust, **self.options, now=self.now)),
                                     (self.change, topics.MAX_SUBSCRIPTION_BYTES,
                                      lambda value: topics.verify_subscription(value, network_id=self.network, topic_id=self.topic, now=self.now)),
                                     (self.response()["topic_status"], topics.MAX_TOPIC_STATUS_BYTES,
                                      lambda value: topics.verify_topic_status(value, self.trust, **self.options, nonce=self.nonce, now=self.now))):
            raw = canonical_bytes(signed)
            call(raw + b" " * (maximum - len(raw)))
            self.reject("network_document_too_large", call, raw + b" " * (maximum + 1 - len(raw)))


if __name__ == "__main__":
    unittest.main()
