from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    PLUGIN_ROOT / "scripts" / "memory_vault_runtime" / "core.py"
)
SPEC = importlib.util.spec_from_file_location(
    "memory_vault_sync_projection_handoff_semantics_tests",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
vault_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault_sync
SPEC.loader.exec_module(vault_sync)


TASK_ID = "task-handoff-hardening"
SNAPSHOT_ID = "snap-handoff-hardening"
TRANSACTION_ID = "tx-handoff-hardening"
MANIFEST_PATH = (
    f"tasks/{TASK_ID}/versions/{SNAPSHOT_ID}.json"
)


def evidence() -> dict:
    return {
        "kind": "memory_event",
        "memory_event_id": "evt-handoff-hardening",
        "event_sha256": "a" * 64,
    }


def projection_fixture() -> dict:
    reference = evidence()
    completeness = {
        "overall": "partial",
        "goal_and_scope": "partial",
        "decisions": "partial",
        "rationales": "partial",
        "progress": "partial",
        "artifacts": "partial",
        "conflicts": "partial",
        "evidence": "partial",
    }
    return {
        "schema_version": "task-memory-projection/v1",
        "projection_id": "proj-handoff-hardening",
        "authority": "rebuildable_task_handoff_cache",
        "basis": {
            "task_id": TASK_ID,
            "snapshot_id": SNAPSHOT_ID,
            "generation": 1,
            "transaction_id": TRANSACTION_ID,
            "manifest_path": MANIFEST_PATH,
            "source_current_precondition": None,
        },
        "completeness": completeness,
        "completeness_basis": {
            dimension: {
                "status": status,
                "reason": "Verified but intentionally partial test basis.",
                "evidence": [],
            }
            for dimension, status in completeness.items()
            if dimension != "overall"
        },
        "current_goal": {
            "status": "active",
            "statement": "Continue the verified handoff task.",
            "evidence": [copy.deepcopy(reference)],
        },
        "scope_boundaries": {
            "in_scope": [
                {
                    "boundary_id": "scope-primary-work",
                    "statement": "Continue the primary verified work.",
                    "evidence": [copy.deepcopy(reference)],
                }
            ],
            "out_of_scope": [],
        },
        "unprojected_deltas": [],
        "reconciliation_receipts": [],
        "effective_claims": [],
        "contested_claims": [],
        "superseded_claims": [],
        "rejected_options": [],
        "artifact_authorities": [],
        "unclassified_artifact_policy": (
            "reference_only_do_not_infer_from_filename_or_inventory"
        ),
        "completed": [],
        "in_progress": [],
        "next_actions": [
            {
                "action_id": "progress-continue",
                "statement": "Continue from the verified checkpoint.",
                "depends_on_claim_ids": [],
                "evidence": [],
            }
        ],
        "open_questions": [],
        "risks": [],
        "blocking_conflicts": [],
        "nonblocking_contradictions": [],
        "known_gaps": [],
        "evidence_index": [],
        "trace_policy": {
            "mode": "on_demand_verified_evidence",
            "triggers": {
                "missing_rationale": True,
                "blocking_conflict": True,
                "multiple_same_role_current_authoritative_artifacts": True,
                "user_says_previously_explained": True,
                "projection_gap": True,
            },
            "action": (
                "trace_to_original_verified_evidence_before_asking_or_"
                "changing_state"
            ),
        },
    }


class ProjectionHandoffSemanticsTests(unittest.TestCase):
    def validate(
        self,
        projection: dict,
        *,
        strict_successor: bool,
    ) -> None:
        vault_sync._validate_task_memory_projection_structure(projection)
        current = {
            "task_id": TASK_ID,
            "snapshot_id": SNAPSHOT_ID,
            "generation": 1,
            "published_transaction_id": TRANSACTION_ID,
            "continuation_readiness": "partial",
        }
        manifest = {
            "task_id": TASK_ID,
            "snapshot_id": SNAPSHOT_ID,
            "generation": 1,
            "transaction_id": TRANSACTION_ID,
            "continuation_readiness": "partial",
            "parents": [],
            "artifacts": [],
        }
        with (
            mock.patch.object(
                vault_sync,
                "_validate_projection_precondition",
            ),
            mock.patch.object(
                vault_sync,
                "_verify_projection_reference",
            ),
            mock.patch.object(
                vault_sync,
                "_projection_ancestor_manifests",
                return_value={SNAPSHOT_ID: manifest},
            ),
            mock.patch.object(
                vault_sync,
                "_validate_projection_reconciliation_receipts",
            ),
        ):
            vault_sync._validate_projection_semantics(
                mock.Mock(),
                current,
                MANIFEST_PATH,
                manifest,
                projection,
                strict_successor=strict_successor,
            )

    def test_identifier_uniqueness_and_progress_bucket_exclusivity(self) -> None:
        projection = projection_fixture()
        shared_scope = copy.deepcopy(
            projection["scope_boundaries"]["in_scope"][0]
        )
        shared_scope["statement"] = "A conflicting scope direction."
        projection["scope_boundaries"]["out_of_scope"] = [shared_scope]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "scope boundary ID is duplicated",
        ):
            self.validate(projection, strict_successor=True)

        projection = projection_fixture()
        rejected = {
            "option_id": "option-shared",
            "claim_key": "target-choice",
            "statement": "Use option A.",
            "rejection_rationale": {
                "statement": "Verified evidence selected another option.",
                "evidence": [evidence()],
            },
            "evidence": [evidence()],
        }
        duplicate = copy.deepcopy(rejected)
        duplicate["statement"] = "Use option B."
        projection["rejected_options"] = [rejected, duplicate]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "rejected option ID is duplicated",
        ):
            self.validate(projection, strict_successor=True)

        projection = projection_fixture()
        projection["completed"] = [
            {
                "item_id": "progress-shared",
                "statement": "The first record is complete.",
                "evidence": [evidence()],
            },
            {
                "item_id": "progress-shared",
                "statement": "A second record claims completion.",
                "evidence": [evidence()],
            },
        ]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "completed progress item ID is duplicated",
        ):
            self.validate(projection, strict_successor=True)

        projection = projection_fixture()
        projection["completed"] = [
            {
                "item_id": "progress-continue",
                "statement": "The same item is marked complete.",
                "evidence": [evidence()],
            }
        ]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "multiple status buckets",
        ):
            self.validate(projection, strict_successor=True)

    def test_active_goal_requires_action_or_honest_progress_gap(self) -> None:
        projection = projection_fixture()
        projection["next_actions"] = []
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "lacks both a next action and an explicit progress gap",
        ):
            self.validate(projection, strict_successor=True)

        projection["known_gaps"] = [
            {
                "gap_id": "gap-next-action",
                "area": "progress",
                "statement": "The next executable action is not recovered.",
                "trace_status": "partial",
                "evidence": [],
            }
        ]
        self.validate(projection, strict_successor=True)

        projection["known_gaps"] = []
        projection["completeness"]["progress"] = "unknown"
        projection["completeness_basis"]["progress"] = {
            "status": "unknown",
            "reason": "The next executable action is not yet known.",
            "evidence": [],
        }
        self.validate(projection, strict_successor=True)

    def test_empty_scope_requires_gap_and_cannot_claim_complete(self) -> None:
        projection = projection_fixture()
        projection["scope_boundaries"] = {
            "in_scope": [],
            "out_of_scope": [],
        }
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "lacks an explicit goal-and-scope gap",
        ):
            self.validate(projection, strict_successor=True)

        projection["known_gaps"] = [
            {
                "gap_id": "gap-scope",
                "area": "goal_and_scope",
                "statement": "The exact boundary is not recovered.",
                "trace_status": "partial",
                "evidence": [],
            }
        ]
        self.validate(projection, strict_successor=True)

        projection["completeness"]["goal_and_scope"] = "complete"
        projection["completeness_basis"]["goal_and_scope"] = {
            "status": "complete",
            "reason": "An invalid claim that empty scope is complete.",
            "evidence": [evidence()],
        }
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "empty projection scope cannot be complete",
        ):
            self.validate(projection, strict_successor=True)

    def test_legacy_read_is_relaxed_but_ambiguous_identity_still_fails(self) -> None:
        projection = projection_fixture()
        projection.pop("completeness_basis")
        projection["next_actions"] = []
        projection["scope_boundaries"] = {
            "in_scope": [],
            "out_of_scope": [],
        }
        self.validate(projection, strict_successor=False)

        projection["rejected_options"] = [
            {
                "option_id": "option-duplicate",
                "claim_key": "target-choice",
                "statement": statement,
                "rejection_rationale": {
                    "statement": "The option was explicitly rejected.",
                    "evidence": [evidence()],
                },
                "evidence": [evidence()],
            }
            for statement in ("Historical option A.", "Historical option B.")
        ]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "rejected option ID is duplicated",
        ):
            self.validate(projection, strict_successor=False)

    def test_loader_relaxes_only_a_projection_missing_persisted_basis(self) -> None:
        current = {
            "task_id": TASK_ID,
            "snapshot_id": SNAPSHOT_ID,
            "generation": 1,
            "published_transaction_id": TRANSACTION_ID,
            "continuation_readiness": "partial",
        }
        manifest = {
            "task_id": TASK_ID,
            "snapshot_id": SNAPSHOT_ID,
            "generation": 1,
            "transaction_id": TRANSACTION_ID,
            "continuation_readiness": "partial",
            "parents": [],
            "artifacts": [],
        }
        projection_path = (
            f"tasks/{TASK_ID}/projections/proj-handoff-hardening.json"
        )

        def load(projection: dict) -> bool:
            raw = vault_sync.pretty_json_bytes(projection)
            reference_manifest = copy.deepcopy(manifest)
            reference_manifest["memory_projection"] = {
                "projection_id": "proj-handoff-hardening",
                "path": projection_path,
                "content_sha256": hashlib.sha256(raw).hexdigest(),
            }
            git = mock.Mock(unsafe=True)
            git.blob_size.return_value = len(raw)
            git.show_bytes.side_effect = lambda path: (
                raw
                if path == projection_path
                else vault_sync.pretty_json_bytes(reference_manifest)
            )
            with mock.patch.object(
                vault_sync,
                "_validate_projection_semantics",
            ) as semantics:
                vault_sync._load_task_memory_projection(
                    git,
                    current=current,
                    manifest_path=MANIFEST_PATH,
                    manifest=reference_manifest,
                )
            return bool(semantics.call_args.kwargs["strict_successor"])

        self.assertTrue(load(projection_fixture()))
        legacy = projection_fixture()
        legacy.pop("completeness_basis")
        self.assertFalse(load(legacy))


if __name__ == "__main__":
    unittest.main()
