"""Synthetic authority HTTP integration; no installed client or public service."""
from __future__ import annotations

import copy
import asyncio
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from starlette.testclient import TestClient

from memory_vault import canonical_bytes
from memory_vault_network_control import create_authority_app, issue_roster, sign_request
from memory_vault_network_crypto import EncryptionIdentity, PublicKeyTrust, document_sha256
from memory_vault_storage import atomic_write
from memory_vault_topic_store import TopicAuthorityStore, TopicStoreError
from memory_vault_topics import issue_policy, sign_subscription, verify_subscription_receipt
from memory_vault_trust import Identity, TrustStore


class TopicAuthorityHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-topic-http-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.now = int(time.time())
        self.issuer, self.member, self.stranger = [Identity.generate(self.root / (name + ".json"))
            for name in ("issuer", "member", "stranger")]
        self.network, self.topic = "synthetic-topic-network", "synthetic-topic"
        trust = TrustStore(self.root / "trust.json")
        trust.add(self.issuer.public_descriptor())
        self.issuers = PublicKeyTrust([self.issuer.public_descriptor()])
        self.members = [{"signing_key": signer.public_descriptor(),
            "encryption_key": EncryptionIdentity.generate().public_descriptor(),
            "status": "active", "scope": ["receive", "send"]}
            for signer in (self.member, self.stranger)]
        self.roster = issue_roster(self.issuer, network_id=self.network, version=1,
            previous_sha256="0" * 64, members=self.members, issued_at=self.now, expires_at=self.now + 300)
        atomic_write(self.root / "roster.json", canonical_bytes(self.roster), replace=False)
        self.config = {"schema_version": "memory-vault-network-authority-config/v1",
            "network_id": self.network, "identity_path": str(self.root / "issuer.json"),
            "trust_store_path": str(self.root / "trust.json"), "roster_path": str(self.root / "roster.json"),
            "topic_state_path": str(self.root / "topics.json")}
        self.config_path = self.root / "authority.json"
        atomic_write(self.config_path, canonical_bytes(self.config), replace=False)
        self.store = TopicAuthorityStore(self.config_path)
        self.store.initialize(now=self.now)
        self.policy = issue_policy(self.issuer, network_id=self.network, topic_id=self.topic,
            issuer_key_id=self.issuer.key_id,
            version=1, previous_sha256="0" * 64, status="active",
            publishers=[{"member_key_id": self.member.key_id, "grant_id": "synthetic-publish", "status": "active"}],
            subscriber_grants=[{"member_key_id": self.member.key_id, "grant_id": "synthetic-subscribe", "status": "active"}],
            issued_at=self.now, expires_at=self.now + 300)
        self.store.put_policy(self.policy, now=self.now)

    def query(self, signer=None, *, body=None):
        nonce = "synthetic-topic-fresh-nonce"
        signed = sign_request(signer or self.member, network_id=self.network, action="status",
            request_id="synthetic-topic-status-request", body=body or {"nonce": nonce, "topic_id": self.topic},
            issued_at=self.now, expires_at=self.now + 60)
        return {"network_id": self.network, "topic_id": self.topic, "nonce": nonce, "request": signed}

    def change(self, signer=None):
        return sign_subscription(signer or self.member, network_id=self.network, topic_id=self.topic,
            grant_id="synthetic-subscribe", revision=1, previous_change_sha256="0" * 64,
            state="subscribed", request_id="synthetic-subscription-request",
            issued_at=self.now, expires_at=self.now + 60)

    def test_http_commit_retry_and_nonce_status_use_same_persistent_state(self):
        change = self.change()
        app = create_authority_app(self.config_path)
        event_threads, transaction_threads = [], []

        async def observe_thread(scope, receive, send):
            if scope["type"] == "http":
                event_threads.append(threading.get_ident())
            await app(scope, receive, send)

        original = TopicAuthorityStore.subscribe

        def observe_commit(store, *args, **kwargs):
            transaction_threads.append(threading.get_ident())
            return original(store, *args, **kwargs)

        with TestClient(observe_thread) as client, patch.object(TopicAuthorityStore, "subscribe", observe_commit):
            submitted = client.post("/v1/topic-subscriptions", json={"network_id": self.network, "change": change})
            self.assertEqual(submitted.status_code, 200, submitted.text)
            receipt = submitted.json()["receipt"]
            self.assertEqual(receipt["payload"]["change_sha256"], document_sha256(change))
            verify_subscription_receipt(receipt, self.issuers, network_id=self.network,
                topic_id=self.topic, issuer_key_id=self.issuer.key_id)
            self.assertEqual(client.post("/v1/topic-subscriptions", json={"network_id": self.network, "change": change}).json(), submitted.json())
            received = client.post("/v1/topic-status", json=self.query())
            self.assertEqual(received.status_code, 200, received.text)
            packet = received.json()
            self.assertEqual(set(packet), {"roster", "status", "policy", "snapshot", "topic_status"})
            self.assertEqual(packet["snapshot"]["payload"]["subscriptions"][0]["change"], change)
            self.assertEqual(packet["topic_status"]["payload"]["snapshot_sha256"], document_sha256(packet["snapshot"]))
            self.assertEqual(received.headers["cache-control"], "no-store")
        self.assertTrue(transaction_threads)
        self.assertFalse(set(transaction_threads) & set(event_threads), "file transaction blocked the event loop")
        self.assertEqual(TopicAuthorityStore(self.config_path).subscribe(change), receipt)

    def test_unauthorized_malformed_oversized_and_wrong_network_requests_do_not_commit(self):
        before = (self.root / "topics.json").read_bytes()
        with TestClient(create_authority_app(self.config_path)) as client:
            denied = client.post("/v1/topic-status", json=self.query(self.stranger))
            self.assertEqual(denied.status_code, 400, denied.text)
            old_body = self.query(body={"nonce": "synthetic-topic-fresh-nonce"})
            self.assertEqual(client.post("/v1/topic-status", json=old_body).status_code, 400)
            cases = [
                {"network_id": "different-network", "change": self.change()},
                {"network_id": self.network, "change": self.change(self.stranger)},
                {"network_id": self.network, "change": {"payload": [], "proof": {}}},
                {"network_id": self.network, "change": self.change(), "extra": True},
            ]
            for request in cases:
                with self.subTest(request=list(request)):
                    response = client.post("/v1/topic-subscriptions", json=request)
                    self.assertEqual(response.status_code, 400, response.text)
            oversized = client.post("/v1/topic-subscriptions", content=b" " * (20 * 1024 + 1), headers={"content-type": "application/json"})
            self.assertEqual(oversized.status_code, 400)
            self.assertEqual(oversized.json()["error"]["code"], "network_request_too_large")
            self.assertEqual(client.post("/v1/topic-subscriptions", content=b'{"network_id":"a","network_id":"b","change":{}}', headers={"content-type": "application/json"}).status_code, 400)
        self.assertEqual((self.root / "topics.json").read_bytes(), before)

    def test_bounded_admission_encoding_and_uncertain_commit_are_explicit(self):
        gate = threading.BoundedSemaphore(1)
        gate.acquire()
        with patch("memory_vault_network_control.threading.BoundedSemaphore", return_value=gate):
            app = create_authority_app(self.config_path)
        with TestClient(app) as client:
            busy = client.post("/v1/topic-status", json=self.query())
            self.assertEqual(busy.status_code, 429)
            self.assertEqual(busy.json(), {"error": {"code": "network_topic_busy", "retryable": True}})
            gate.release()
            bad_type = client.post("/v1/topic-status", content=b"{}", headers={"content-type": "text/plain"})
            self.assertEqual(bad_type.json()["error"]["code"], "network_topic_json_required")
            encoded = client.post("/v1/topic-status", json=self.query(), headers={"content-encoding": "gzip"})
            self.assertEqual(encoded.json()["error"]["code"], "network_topic_content_encoding_rejected")
            with patch.object(TopicAuthorityStore, "subscribe", side_effect=TopicStoreError("network_topic_commit_uncertain", retryable=True)):
                result = client.post("/v1/topic-subscriptions", json={"network_id": self.network, "change": self.change()})
            self.assertEqual(result.status_code, 503)
            self.assertEqual(result.json(), {"error": {"code": "network_topic_commit_uncertain", "retryable": True}})
            self.assertEqual(client.post("/v1/topic-status", json=self.query()).status_code, 200)

    def test_incomplete_body_times_out_and_releases_capacity(self):
        app = create_authority_app(self.config_path)
        response = []

        async def request():
            async def receive():
                await asyncio.Future()

            async def send(message):
                response.append(message)

            scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                "method": "POST", "scheme": "http", "path": "/v1/topic-status", "raw_path": b"/v1/topic-status",
                "query_string": b"", "root_path": "", "headers": [(b"content-type", b"application/json")],
                "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 2)}
            await asyncio.wait_for(app(scope, receive, send), timeout=1)

        with patch("memory_vault_network_control.TOPIC_HTTP_BODY_SECONDS", 0.01):
            asyncio.run(request())
        self.assertEqual(response[0]["status"], 408)
        self.assertEqual(json.loads(response[1]["body"]), {"error": {"code": "network_topic_request_timeout", "retryable": True}})
        with TestClient(app) as client:
            self.assertEqual(client.post("/v1/topic-status", json=self.query()).status_code, 200)

    def test_optional_configuration_preserves_legacy_status_and_no_auto_initialize(self):
        with TestClient(create_authority_app(self.config_path)) as client:
            query = self.query(body={"nonce": "synthetic-topic-fresh-nonce"})
            del query["topic_id"]
            response = client.post("/v1/status", json=query)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(set(response.json()), {"roster", "status"})
        legacy = copy.deepcopy(self.config)
        del legacy["topic_state_path"]
        atomic_write(self.config_path, canonical_bytes(legacy), replace=True)
        before = (self.root / "topics.json").read_bytes()
        with TestClient(create_authority_app(self.config_path)) as client:
            response = client.post("/v1/topic-status", json=self.query())
            self.assertEqual(response.status_code, 400, response.text)
            self.assertEqual(client.post("/v1/status", json=query).status_code, 200)
        self.assertEqual((self.root / "topics.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
