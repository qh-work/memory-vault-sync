"""Synthetic one-command endpoint and reference-peer loopback checks."""
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memory_vault import canonical_bytes, strict_json_loads
from memory_vault_network_admin import initialize
from memory_vault_network_control import create_authority_app
from memory_vault_relay import create_app as create_relay_app
from memory_vault_trial import (RESULT_SCHEMA, SERVICE_SCHEMA, STATE_PREFIX, TRUST_SCHEMA,
                                _new_state_root, _validate_enrollment, cleanup_trial_state, main, run_trial)
from memory_vault_trial_coordinator import TrialCoordinator, initialize_trial_coordinator
from memory_vault_trial_peer import SyntheticReferencePeer
from tests.test_network_worker import Transport


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
