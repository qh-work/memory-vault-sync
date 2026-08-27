from __future__ import annotations

import argparse
import contextlib
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    PLUGIN_ROOT / "scripts" / "memory_vault_runtime" / "core.py"
)
SPEC = importlib.util.spec_from_file_location(
    "memory_vault_sync_trace_readiness_hardening_tests",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
vault_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault_sync
SPEC.loader.exec_module(vault_sync)


TASK_ID = "task-trace-readiness"
MANIFEST_PATH = f"tasks/{TASK_ID}/versions/snap-current.json"


class RemoteTaskGit:
    def __init__(
        self,
        *,
        current_readiness: str = "partial",
        manifest_readiness: str = "partial",
    ) -> None:
        self.documents = {
            f"tasks/{TASK_ID}/TASK.json": {
                "schema_version": "task/v2",
                "minimum_client_protocol": "content-evidence-routing-v1",
                "task_id": TASK_ID,
                "identity_status": "confirmed",
            },
            f"tasks/{TASK_ID}/CURRENT.json": {
                "schema_version": "task-current/v1",
                "task_id": TASK_ID,
                "generation": 4,
                "snapshot_id": "snap-current",
                "manifest_path": MANIFEST_PATH,
                "continuation_readiness": current_readiness,
                "published_transaction_id": "tx-current",
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            },
            MANIFEST_PATH: {
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": "snap-current",
                "generation": 4,
                "transaction_id": "tx-current",
                "state": "published",
                "continuation_readiness": manifest_readiness,
            },
        }

    def show_json(self, path: str):
        return self.documents[path]

    def blob_sha(self, _path: str) -> str:
        return "a" * 40

    def head_sha(self) -> str:
        return "b" * 40


class CurrentManifestReadinessTests(unittest.TestCase):
    def test_remote_load_rejects_legacy_task_identity_epoch(self) -> None:
        git = RemoteTaskGit()
        git.documents[f"tasks/{TASK_ID}/TASK.json"]["schema_version"] = "task/v1"
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "content-evidence-routing-v1",
        ):
            vault_sync.load_remote_task_by_id(git, TASK_ID)

    def test_remote_load_requires_content_evidence_protocol(self) -> None:
        for protocol in (None, "legacy-score-routing-v1"):
            with self.subTest(protocol=protocol):
                git = RemoteTaskGit()
                task = git.documents[f"tasks/{TASK_ID}/TASK.json"]
                if protocol is None:
                    task.pop("minimum_client_protocol")
                else:
                    task["minimum_client_protocol"] = protocol
                with self.assertRaisesRegex(
                    vault_sync.IdentityError,
                    "content-evidence-routing-v1",
                ):
                    vault_sync.load_remote_task_by_id(git, TASK_ID)

    def test_historical_task_identity_accepts_v1_and_safe_v2_only(self) -> None:
        self.assertTrue(
            vault_sync._historical_task_identity_supported(
                {"schema_version": "task/v1"}
            )
        )
        self.assertTrue(
            vault_sync._historical_task_identity_supported(
                {
                    "schema_version": "task/v2",
                    "minimum_client_protocol": "content-evidence-routing-v1",
                }
            )
        )
        self.assertFalse(
            vault_sync._historical_task_identity_supported(
                {"schema_version": "task/v2"}
            )
        )
        self.assertFalse(
            vault_sync._historical_task_identity_supported(
                {
                    "schema_version": "task/v2",
                    "minimum_client_protocol": "legacy-score-routing-v1",
                }
            )
        )

    def test_remote_load_rejects_current_manifest_readiness_mismatch(self) -> None:
        git = RemoteTaskGit(
            current_readiness="ready",
            manifest_readiness="partial",
        )
        with (
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(
                vault_sync,
                "_load_task_memory_projection",
                return_value=(None, None),
            ) as projection_loader,
        ):
            with self.assertRaisesRegex(
                vault_sync.VerificationError,
                "manifest does not match CURRENT",
            ):
                vault_sync.load_remote_task_by_id(git, TASK_ID)
        projection_loader.assert_not_called()

    def test_remote_load_accepts_matching_readiness(self) -> None:
        git = RemoteTaskGit()
        with (
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(
                vault_sync,
                "_load_task_memory_projection",
                return_value=(None, None),
            ),
        ):
            state = vault_sync.load_remote_task_by_id(git, TASK_ID)
        self.assertEqual(state.current["continuation_readiness"], "partial")
        self.assertEqual(state.manifest["continuation_readiness"], "partial")


class TraceEvidenceNoRawAnchorTests(unittest.TestCase):
    def test_memory_event_without_anchor_returns_reference_only_result(self) -> None:
        reference = {
            "kind": "memory_event",
            "memory_event_id": "evt-no-raw-anchor",
            "event_sha256": "c" * 64,
        }
        projection = {
            "projection_id": "proj-no-raw-anchor",
            "evidence_index": [
                {
                    "entry_id": "entry-no-raw-anchor",
                    "topic": "Imported decision without exact message anchor",
                    "references": [reference],
                }
            ],
        }
        remote = types.SimpleNamespace(
            current={"snapshot_id": "snap-no-raw-anchor"},
            manifest={},
            memory_projection=projection,
        )
        event = {
            "memory_event_id": "evt-no-raw-anchor",
            "kind": "decision",
            "claim_key": "claim-no-raw-anchor",
            "confidence": "imported_unverified",
            "source": {
                "source_id": "src-no-raw-anchor",
                "revision_id": "rev-no-raw-anchor",
                "source_sequence": 2,
                "evidence_anchor_sha256": None,
            },
            "payload": {"topic": "reference-only imported decision"},
            "event_sha256": "c" * 64,
        }
        git = mock.Mock()
        engine = types.SimpleNamespace(
            lock_path=Path("/tmp/trace-readiness-hardening.lock"),
            git=git,
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            entry_id="entry-no-raw-anchor",
            reference_index=None,
        )
        with (
            mock.patch.object(
                vault_sync,
                "FileLock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=remote,
            ),
            mock.patch.object(
                vault_sync,
                "_verify_projection_reference",
                return_value=event,
            ),
        ):
            result = vault_sync.trace_evidence_command(args, engine)

        traced = result["resolved_references"][0]
        self.assertEqual(
            traced["anchor_resolution"],
            {
                "status": "reference_only",
                "reason": "no_raw_anchor",
                "raw_message_available": False,
            },
        )
        self.assertIsNone(traced["anchored_message"])
        self.assertNotIn("text", traced)
        git.show_bytes.assert_not_called()


if __name__ == "__main__":
    unittest.main()
