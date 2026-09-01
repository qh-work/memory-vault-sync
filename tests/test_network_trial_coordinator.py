"""Synthetic checks for bounded, public-key-only trial enrollment."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from starlette.testclient import TestClient
except ImportError:  # pragma: no cover - server dependency is optional
    TestClient = None

from memory_vault_network_admin import _read, create_identity, initialize
from memory_vault_network_control import verify_invite, verify_roster
from memory_vault_network_crypto import PublicKeyTrust, document_sha256
from memory_vault_trial_coordinator import (
    RESULT_SCHEMA,
    SERVICE_SCHEMA,
    TrialCoordinator,
    add_run_codes,
    create_app,
    initialize_trial_coordinator,
)


@unittest.skipIf(TestClient is None, "network server test dependencies unavailable")
class TrialCoordinatorTests(unittest.TestCase):
    def _setup(self, root: Path, codes: list[str], *, limits: dict[str, int] | None = None):
        owner = root / "owner"
        initialized = initialize(owner, network_id="synthetic-trial-network")
        config, state = root / "trial.json", root / "trial-state"
        result = initialize_trial_coordinator(
            config=config,
            authority_config=owner / "authority.json",
            state_directory=state,
            authority_url="http://127.0.0.1:8767",
            relays=["http://127.0.0.1:8765"],
            reference_peer_key_id=initialized["owner_key_id"],
            run_codes=codes,
            limits=limits,
        )
        self.assertFalse(result["run_codes_returned"])
        self.assertFalse(result["services_started"])
        return owner, config, state

    @staticmethod
    def _candidate(root: Path, name: str) -> dict:
        directory = root / name
        create_identity(directory)
        return _read(directory / "member-public.json")

    def test_exact_retry_is_idempotent_and_binds_both_public_keys(self) -> None:
        code = "synthetic-run-code-alpha-000000000001"
        with tempfile.TemporaryDirectory(prefix="trial-coordinator-synthetic-") as temporary:
            root = Path(temporary).resolve()
            owner, config, state = self._setup(root, [code])
            candidate = self._candidate(root, "candidate")
            before = _read(owner / "roster.json")
            app = create_app(config)
            with TestClient(app) as client:
                first = client.post("/v1/trial/enroll", json={"run_code": code, "candidate": candidate})
            with TestClient(create_app(config)) as restarted:
                retry = restarted.post("/v1/trial/enroll", json={"run_code": code, "candidate": candidate})
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(first.content, retry.content)
            result = first.json()
            self.assertEqual(result["schema_version"], RESULT_SCHEMA)
            self.assertEqual(result["state"], "invited")
            self.assertEqual(result["service"]["schema_version"], SERVICE_SCHEMA)
            self.assertTrue(result["service"]["synthetic_only"])
            self.assertEqual(result["service"]["content_enforcement"], "endpoint-only")
            self.assertFalse(result["service"]["relay_plaintext_access"])
            self.assertFalse(result["service"]["execution_authority"])
            self.assertEqual(result["service_proof"]["key_id"], result["service"]["issuer_public_key"]["key_id"])
            issuers = PublicKeyTrust([_read(owner / "issuer-public.json")])
            issuers.verify_message(result["service"], result["service_proof"])
            invite = verify_invite(result["invitation"]["invite"], issuers, network_id="synthetic-trial-network")
            roster = verify_roster(result["invitation"]["roster"], issuers,
                                   network_id="synthetic-trial-network", allow_expired=True,
                                   expected_previous_sha256=document_sha256(before))
            self.assertEqual(invite["candidate_signing_key"], candidate["signing_key"])
            self.assertEqual(invite["candidate_encryption_key"], candidate["encryption_key"])
            self.assertLessEqual(invite["expires_at"] - invite["issued_at"], 300)
            self.assertEqual(roster["version"], before["payload"]["version"] + 1)
            self.assertNotIn(b"private_key", first.content)
            self.assertNotIn(code.encode(), b"".join(path.read_bytes() for path in state.iterdir() if path.is_file()))

    def test_used_code_rejects_a_different_candidate_and_private_material(self) -> None:
        code = "synthetic-run-code-bravo-000000000001"
        other_code = "synthetic-run-code-bravo-000000000002"
        with tempfile.TemporaryDirectory(prefix="trial-coordinator-binding-") as temporary:
            root = Path(temporary).resolve()
            owner, config, _state = self._setup(root, [code, other_code])
            first_candidate = self._candidate(root, "candidate-a")
            second_candidate = self._candidate(root, "candidate-b")
            app = create_app(config)
            with TestClient(app) as client:
                admitted = client.post("/v1/trial/enroll", json={"run_code": code, "candidate": first_candidate})
                conflict = client.post("/v1/trial/enroll", json={"run_code": code, "candidate": second_candidate})
                injected = deepcopy(second_candidate)
                injected["encryption_key"]["private_key"] = "must-never-be-accepted"
                rejected = client.post("/v1/trial/enroll", json={"run_code": other_code, "candidate": injected})
            self.assertEqual(admitted.status_code, 200, admitted.text)
            self.assertEqual(conflict.status_code, 409, conflict.text)
            self.assertEqual(conflict.json()["error"]["code"], "trial_run_code_already_used")
            self.assertEqual(rejected.status_code, 400, rejected.text)
            self.assertEqual(rejected.json()["error"]["code"], "trial_candidate_public_identity_invalid")
            roster = _read(owner / "roster.json")["payload"]
            self.assertEqual(len(roster["members"]), 2)

    def test_committed_invitation_recovers_after_result_commit_interruption(self) -> None:
        code = "synthetic-run-code-crash-0000000000001"
        with tempfile.TemporaryDirectory(prefix="trial-coordinator-recovery-") as temporary:
            root = Path(temporary).resolve()
            owner, config, _state = self._setup(root, [code])
            candidate = self._candidate(root, "candidate")
            app = create_app(config)
            coordinator = app.state.coordinator
            with TestClient(app) as client:
                with mock.patch.object(coordinator, "_complete", side_effect=RuntimeError("synthetic interruption")):
                    interrupted = client.post("/v1/trial/enroll", json={"run_code": code, "candidate": candidate})
            with TestClient(create_app(config)) as restarted:
                recovered = restarted.post("/v1/trial/enroll", json={"run_code": code, "candidate": candidate})
            self.assertEqual(interrupted.status_code, 503, interrupted.text)
            self.assertEqual(recovered.status_code, 200, recovered.text)
            roster = _read(owner / "roster.json")["payload"]
            self.assertEqual(roster["version"], 2)
            self.assertEqual(len(roster["members"]), 2)

    def test_body_concurrency_rate_and_capacity_limits_fail_closed(self) -> None:
        codes = ["synthetic-run-code-limit-000000000000" + str(index) for index in range(1, 4)]
        with tempfile.TemporaryDirectory(prefix="trial-coordinator-limits-") as temporary:
            root = Path(temporary).resolve()
            limits = {
                "maximum_request_bytes": 1024,
                "maximum_concurrency": 1,
                "maximum_codes": 3,
                "maximum_enrollments": 1,
                "rate_window_seconds": 60,
                "maximum_requests_per_source_window": 8,
                "maximum_requests_per_global_window": 8,
            }
            _owner, config, _state = self._setup(root, codes, limits=limits)
            first, second = self._candidate(root, "candidate-a"), self._candidate(root, "candidate-b")
            app = create_app(config)
            with TestClient(app) as client:
                wrong_type = client.post("/v1/trial/enroll", content=b"{}", headers={"content-type": "text/plain"})
                too_large = client.post("/v1/trial/enroll", content=b"{" + b" " * 1024,
                                        headers={"content-type": "application/json"})
                self.assertTrue(app.state.gate.acquire(blocking=False))
                try:
                    busy = client.post("/v1/trial/enroll", json={"run_code": codes[0], "candidate": first})
                finally:
                    app.state.gate.release()
                admitted = client.post("/v1/trial/enroll", json={"run_code": codes[0], "candidate": first})
                full = client.post("/v1/trial/enroll", json={"run_code": codes[1], "candidate": second})
            self.assertEqual(wrong_type.status_code, 415)
            self.assertEqual(too_large.status_code, 413)
            self.assertEqual(busy.status_code, 429)
            self.assertEqual(admitted.status_code, 200, admitted.text)
            self.assertEqual(full.status_code, 429, full.text)
            self.assertEqual(full.json()["error"]["code"], "trial_capacity_full")

    def test_rate_limit_counts_unknown_well_formed_codes_and_codes_can_be_added(self) -> None:
        initial = "synthetic-run-code-rate-00000000000001"
        added = "synthetic-run-code-rate-00000000000002"
        with tempfile.TemporaryDirectory(prefix="trial-coordinator-rate-") as temporary:
            root = Path(temporary).resolve()
            limits = {
                "maximum_codes": 2,
                "maximum_enrollments": 2,
                "maximum_requests_per_source_window": 2,
                "maximum_requests_per_global_window": 3,
            }
            _owner, config, _state = self._setup(root, [initial], limits=limits)
            added_result = add_run_codes(config, [added])
            self.assertEqual(added_result["added"], 1)
            candidate = self._candidate(root, "candidate")
            app = create_app(config)
            with TestClient(app) as client:
                results = [client.post("/v1/trial/enroll", json={
                    "run_code": "synthetic-unknown-code-0000000000000" + str(index),
                    "candidate": candidate,
                }) for index in range(3)]
            self.assertEqual([item.status_code for item in results], [403, 403, 429])
            self.assertEqual(results[-1].json()["error"]["code"], "trial_rate_limited")


if __name__ == "__main__":
    unittest.main()
