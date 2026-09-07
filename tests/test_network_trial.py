"""Synthetic one-command endpoint and reference-peer loopback checks."""
from contextlib import ExitStack, closing
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_network_admin import initialize
from memory_vault_network_control import create_authority_app
from memory_vault_relay import create_app as create_relay_app
from memory_vault_trial import (RESULT_SCHEMA, SERVICE_SCHEMA, STATE_PREFIX, TRUST_SCHEMA, SYNTHETIC_PREFIX,
                                _new_state_root, _selected_trial_memory, _validate_enrollment,
                                cleanup_trial_state, main, run_trial)
from memory_vault_trial_coordinator import TrialCoordinator, initialize_trial_coordinator
from memory_vault_trial_peer import SyntheticReferencePeer
from memory_vault_trust import TrustStore
from tests.test_network_worker import Transport, fixture


class TrialEndpointTests(unittest.TestCase):
    def test_automatic_state_resolves_symlinked_system_temporary_parent(self):
        with tempfile.TemporaryDirectory(prefix="memory-vault-trial-parent-") as temporary:
            root = Path(temporary).resolve()
            actual = root / "actual"
            actual.mkdir()
            alias = root / "alias"
            try:
                alias.symlink_to(actual, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            with patch("memory_vault_trial.tempfile.gettempdir", return_value=str(alias)):
                state = _new_state_root(None)
            try:
                self.assertEqual(state.parent, actual)
                self.assertTrue(state.is_dir())
            finally:
                cleanup_trial_state(state)

    def test_disposable_endpoint_runs_real_encrypted_round_trip(self):
        from starlette.testclient import TestClient
        with tempfile.TemporaryDirectory(prefix="memory-vault-trial-test-") as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            owner = root / "service"
            authority_url = "http://127.0.0.1:9980"
            relay_url = "http://127.0.0.1:9981"
            initialized = initialize(owner, network_id="synthetic-hosted-trial",
                                     authority_url=authority_url, relay_url=relay_url)
            clients = {
                authority_url: stack.enter_context(TestClient(create_authority_app(owner / "authority.json"))),
                relay_url: stack.enter_context(TestClient(create_relay_app(owner / "relay.json"))),
            }
            transport = Transport(clients)
            issuer = strict_json_loads((owner / "issuer-public.json").read_bytes())
            service = {"schema_version": SERVICE_SCHEMA, "network_id": "synthetic-hosted-trial",
                       "authority_url": authority_url, "relays": [relay_url],
                       "issuer_public_key": issuer, "reference_peer_key_id": initialized["owner_key_id"]}
            trust = {"schema_version": TRUST_SCHEMA,
                     "enrollment_url": authority_url + "/v1/trial/enroll", "service": service}
            last_enrollment = None
            run_code = "synthetic-run-code-00000000000001"
            coordinator_config = root / "coordinator.json"
            initialize_trial_coordinator(config=coordinator_config,
                authority_config=owner / "authority.json", state_directory=root / "coordinator-state",
                authority_url=authority_url, relays=[relay_url],
                reference_peer_key_id=initialized["owner_key_id"], run_codes=[run_code])
            coordinator = TrialCoordinator(coordinator_config)

            def enroll(url, body):
                nonlocal last_enrollment
                self.assertEqual(url, trust["enrollment_url"])
                self.assertEqual(set(body), {"run_code", "candidate"})
                self.assertNotIn("private_key", canonical_bytes(body).decode("utf-8"))
                last_enrollment = coordinator.enroll_bytes(canonical_bytes(body), source="127.0.0.2")
                return last_enrollment

            peer = SyntheticReferencePeer(owner / "client.json", owner / "network.json", transport=transport)
            state = root / (STATE_PREFIX + "endpoint")
            result = run_trial(service_trust=trust, run_code=run_code,
                               state_directory=state, transport=transport,
                               enrollment_request=enroll, progress_hook=peer.step,
                               timeout_seconds=5)
            self.assertEqual(result["schema_version"], RESULT_SCHEMA)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["stages"]["relay_stored"]["confirmed"])
            self.assertTrue(result["stages"]["peer_validated_saved"]["confirmed"])
            self.assertTrue(result["stages"]["local_recall"]["matched_synthetic_nonce"])
            self.assertTrue(result["stages"]["local_recall"]["inspection_only"])
            self.assertFalse(result["stages"]["local_recall"]["trusted_context_asserted"])
            self.assertEqual(result["stages"]["pump"]["remaining_outbox"], 0)
            self.assertTrue(result["cleanup"]["state_removed"])
            self.assertFalse(state.exists())
            self.assertNotIn("memory_id", json.dumps(result))
            self.assertNotIn("key_id", json.dumps(result))
            self.assertNotIn(str(root), json.dumps(result))
            self.assertIsNotNone(last_enrollment)
            broken = json.loads(json.dumps(last_enrollment))
            broken["service"]["reference_peer_key_id"] = broken["invitation"]["invite"]["payload"]["candidate_signing_key"]["key_id"]
            with self.assertRaises(Exception) as invalid_proof:
                _validate_enrollment(broken, service)
            self.assertEqual(getattr(invalid_proof.exception, "code", None), "trial_service_pin_mismatch")
            forged = json.loads(json.dumps(last_enrollment))
            forged["service_proof"]["signature"] = ("A" if forged["service_proof"]["signature"][0] != "A" else "B") + forged["service_proof"]["signature"][1:]
            with self.assertRaises(Exception) as bad_signature:
                _validate_enrollment(forged, service)
            self.assertEqual(getattr(bad_signature.exception, "code", None), "trial_service_proof_invalid")
            wrong_boundary = json.loads(json.dumps(last_enrollment))
            wrong_boundary["service"]["relay_plaintext_access"] = True
            with self.assertRaises(Exception) as invalid_boundary:
                _validate_enrollment(wrong_boundary, service)
            self.assertEqual(getattr(invalid_boundary.exception, "code", None), "trial_enrollment_invalid")
            for stored in (owner / "relay-state").rglob("*"):
                if stored.is_file():
                    self.assertNotIn(b"memory-vault synthetic trial/v1 nonce=", stored.read_bytes())

    def test_plain_chat_nonce_is_not_a_trial_memory_or_reply(self):
        with fixture() as (sender, recipient, transport):
            sender.send("req_trial_chat_only", [recipient.identity.key_id], SYNTHETIC_PREFIX + "a" * 64)
            peer = SyntheticReferencePeer(recipient.client_config.path, recipient.config_path, transport=transport)
            result = peer.step()
            self.assertEqual((result["received"], result["replied"], result["rejected"]), (1, 0, 1))
            self.assertFalse(sender.client_config.vault_path.exists())
            self.assertFalse(recipient.client_config.vault_path.exists())

    def test_selected_record_is_not_inferred_from_matching_dependency_text(self):
        with fixture() as (sender, recipient, transport):
            text = SYNTHETIC_PREFIX + "b" * 64
            source = Agent(sender.client_config.path, sender.config_path, transport=transport)
            parent = source.handle({"op": "remember", "request_id": "req_trial_matching_dependency",
                                    "kind": "fact", "text": text})["result"]["memory_id"]
            child = source.handle({"op": "remember", "request_id": "req_trial_selected_other",
                                   "kind": "fact", "text": "Synthetic selected record differs from the note.",
                                   "relations": [{"type": "derived_from", "target": parent}]})["result"]["memory_id"]
            sender.send("req_trial_dependency_note", [recipient.identity.key_id], text, [child])
            received = recipient.receive()["messages"][0]
            target = Agent(recipient.client_config.path, recipient.config_path, transport=transport)
            self.assertEqual(_selected_trial_memory(target, received), child)
            self.assertIsNone(received["text_memory_id"])
            # A new delivery lets the real peer consume the mismatch itself.
            sender.send("req_trial_dependency_peer", [recipient.identity.key_id], text, [child])
            peer = SyntheticReferencePeer(recipient.client_config.path, recipient.config_path, transport=transport)
            self.assertEqual(peer.step()["rejected"], 1)
            with recipient.db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)

    def test_multiple_selected_trial_records_are_rejected(self):
        with fixture() as (sender, recipient, transport):
            text = SYNTHETIC_PREFIX + "c" * 64
            source = Agent(sender.client_config.path, sender.config_path, transport=transport)
            identifiers = [source.handle({"op": "remember", "request_id": "req_trial_ambiguous_" + kind,
                                          "kind": kind, "text": text})["result"]["memory_id"]
                           for kind in ("fact", "observation")]
            sender.send("req_trial_ambiguous_transfer", [recipient.identity.key_id], text, identifiers)
            received = recipient.receive()["messages"][0]
            target = Agent(recipient.client_config.path, recipient.config_path, transport=transport)
            with self.assertRaises(MemoryError) as rejected:
                _selected_trial_memory(target, received)
            self.assertEqual(rejected.exception.code, "trial_memory_proof_invalid")

    def test_exact_id_inspection_preserves_proof_and_does_not_restore_revoked_trust(self):
        with fixture() as (sender, recipient, transport):
            text = SYNTHETIC_PREFIX + "d" * 64
            source = Agent(sender.client_config.path, sender.config_path, transport=transport)
            memory_id = source.handle({"op": "remember", "request_id": "req_trial_untrusted_memory",
                                       "kind": "fact", "text": text})["result"]["memory_id"]
            sender.send("req_trial_untrusted_transfer", [recipient.identity.key_id], text, [memory_id])
            delivery = recipient.receive()
            self.assertEqual(len(delivery["messages"]), 1, delivery)
            received = delivery["messages"][0]
            self.assertEqual(received["share"]["admission"], "verified")
            # Revocation after receipt changes context eligibility. It must
            # remain revoked even when the exact saved bytes are inspected.
            TrustStore(recipient.client_config.trust_path).revoke(sender.identity.key_id)
            trust_before = recipient.client_config.trust_path.read_bytes()
            with closing(recipient.client_config.vault()._connect(writable=False)) as db:
                before = tuple(db.execute("SELECT m.record_json,a.state,a.signer_key_id,a.attestation_json "
                                          "FROM memories m JOIN record_admissions a USING(memory_id) "
                                          "WHERE memory_id=?", (memory_id,)).fetchone())
            target = Agent(recipient.client_config.path, recipient.config_path, transport=transport)
            self.assertEqual(_selected_trial_memory(target, received), memory_id)
            self.assertEqual(recipient.client_config.trust_path.read_bytes(), trust_before)
            with closing(recipient.client_config.vault()._connect(writable=False)) as db:
                after = tuple(db.execute("SELECT m.record_json,a.state,a.signer_key_id,a.attestation_json "
                                         "FROM memories m JOIN record_admissions a USING(memory_id) "
                                         "WHERE memory_id=?", (memory_id,)).fetchone())
            self.assertEqual(after, before)
            recall = target.handle({"op": "recall", "query": text})
            self.assertTrue(recall["ok"], recall)
            self.assertEqual(recall["result"]["hits"], [])

    def test_unconfigured_trust_fails_before_state_creation_and_cleanup_needs_marker(self):
        with tempfile.TemporaryDirectory(prefix="memory-vault-trial-safety-") as temporary:
            root = Path(temporary).resolve()
            trust = root / "service-trust.json"
            trust.write_text('{"schema_version":"memory-vault-trial-service-trust/v1","state":"unconfigured"}\n')
            state = root / (STATE_PREFIX + "must-not-exist")
            with patch("builtins.print") as output:
                self.assertEqual(main(["--service-trust", str(trust), "--run-code", "synthetic-code",
                                       "--service", "https://trial.invalid",
                                       "--state-directory", str(state)]), 1)
            self.assertFalse(state.exists())
            result = json.loads(output.call_args.args[0])
            self.assertEqual(result["error"]["code"], "trial_service_unconfigured")
            unsafe = root / (STATE_PREFIX + "unmarked")
            unsafe.mkdir()
            with self.assertRaises(Exception) as refused:
                cleanup_trial_state(unsafe)
            self.assertEqual(getattr(refused.exception, "code", None), "trial_state_cleanup_refused")
            self.assertTrue(unsafe.exists())


if __name__ == "__main__":
    unittest.main()
