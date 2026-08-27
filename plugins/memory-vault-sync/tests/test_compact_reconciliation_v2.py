from __future__ import annotations

import argparse
import contextlib
import copy
import dataclasses
import importlib.util
import json
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    PLUGIN_ROOT / "scripts" / "memory_vault_runtime" / "core.py"
)

SPEC = importlib.util.spec_from_file_location(
    "memory_vault_sync_compact_reconciliation_tests",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
vault_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault_sync
SPEC.loader.exec_module(vault_sync)


TASK_ID = "review-article-alpha"
DELTA_ID = "delta-typed-reconciliation-test"
EVIDENCE_ENTRY_ID = "evidence-typed-reconciliation-test"
SOURCE_ID = "src-typed-reconciliation-test"
REVISION_ID = "rev-typed-reconciliation-test"
TARGET_CLAIM_ID = "claim-current-journal-b"
AUTHORITATIVE_SOURCE_CLAIM_ID = "claim-authoritative-working-source"
PRESERVE_HISTORY_CLAIM_ID = "claim-preserve-history"
PROGRESS_ITEM_ID = "progress-primary-document-integration"
NEXT_ACTION_ID = "next-validate-primary-document"


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def message_reference(ordinal: int) -> dict[str, Any]:
    return {
        "kind": "source_message",
        "source_id": SOURCE_ID,
        "revision_id": REVISION_ID,
        "source_sequence": 1,
        "revision_content_sha256": f"{ordinal + 1:064x}",
        "message_ordinal": ordinal,
        "evidence_anchor_sha256": f"{ordinal + 101:064x}",
    }


def representative_review_projection() -> dict[str, Any]:
    """Return a de-identified projection with the production review shape.

    The record cardinality and large-artifact inventory exercise the same
    compact-view boundary as the private review handoff without depending on
    any user task, conversation, path, title, or unpublished artifact.
    """

    references = [message_reference(index) for index in range(8)]
    artifacts = []
    for index in range(40):
        authority_status = (
            "current_authoritative"
            if index == 0
            else "current_companion"
            if index == 1
            else "historical"
            if index % 2 == 0
            else "reference_only"
        )
        artifacts.append(
            {
                "artifact_id": f"artifact-synthetic-{index:02d}",
                "sha256": f"{index + 1000:064x}",
                "purpose": (
                    "De-identified fixed artifact record used to exercise "
                    "compact pagination, authority classification, content "
                    "hash identity, and historical provenance. "
                )
                * 2,
                "role": "supporting-file",
                "authority_status": authority_status,
                "source_snapshot_id": "snap-parent-redacted",
                "dependencies": [],
                "verification": {
                    "status": "partially_verified",
                    "checks": [],
                    "evidence": [copy.deepcopy(references[index % 8])],
                },
                "relations": [],
            }
        )
    return {
        "schema_version": "task-memory-projection/v1",
        "projection_id": "proj-review-shaped-redacted-v1",
        "authority": "rebuildable_task_handoff_cache",
        "basis": {
            "task_id": TASK_ID,
            "snapshot_id": "snap-review-shaped-redacted-v1",
            "generation": 5,
            "transaction_id": "tx-review-shaped-redacted-v1",
            "manifest_path": (
                f"tasks/{TASK_ID}/versions/"
                "snap-review-shaped-redacted-v1.json"
            ),
            "source_current_precondition": {
                "current_blob_sha": "a" * 40,
                "snapshot_id": "snap-parent-redacted",
                "generation": 4,
                "transaction_id": "tx-parent-redacted",
            },
        },
        "completeness": {
            "overall": "partial",
            "goal_and_scope": "complete",
            "decisions": "partial",
            "rationales": "partial",
            "progress": "partial",
            "artifacts": "partial",
            "conflicts": "complete",
            "evidence": "partial",
        },
        "completeness_basis": {
            dimension: {
                "status": status,
                "reason": (
                    "De-identified evidence-backed completeness status for "
                    "the representative continuation projection."
                ),
                "evidence": [
                    copy.deepcopy(references[index % len(references)])
                ],
            }
            for index, (dimension, status) in enumerate(
                (
                    ("goal_and_scope", "complete"),
                    ("decisions", "partial"),
                    ("rationales", "partial"),
                    ("progress", "partial"),
                    ("artifacts", "partial"),
                    ("conflicts", "complete"),
                    ("evidence", "partial"),
                )
            )
        },
        "current_goal": {
            "status": "active",
            "statement": (
                "Complete the de-identified review article and its verified "
                "submission package."
            ),
            "evidence": [copy.deepcopy(references[0])],
        },
        "scope_boundaries": {
            "in_scope": [
                {
                    "boundary_id": "scope-primary-review",
                    "statement": "Only the current review article is in scope.",
                    "evidence": [copy.deepcopy(references[0])],
                }
            ],
            "out_of_scope": [
                {
                    "boundary_id": "scope-unrelated-projects",
                    "statement": "Unrelated projects remain separate.",
                    "evidence": [copy.deepcopy(references[1])],
                }
            ],
        },
        "effective_claims": [
            {
                "claim_id": TARGET_CLAIM_ID,
                "claim_key": "target-journal",
                "kind": "decision",
                "statement": "The current publication target is Journal B.",
                "rationale": {
                    "status": "known",
                    "statement": (
                        "Journal B is the current target after the scope and "
                        "fit were reassessed."
                    ),
                    "evidence": [copy.deepcopy(references[0])],
                },
                "settled": True,
                "superseded_claim_ids": ["claim-historical-journal-a"],
                "reask_policy": (
                    "reask_on_blocking_conflict_or_explicit_reopen"
                ),
                "evidence": [copy.deepcopy(references[0])],
            },
            {
                "claim_id": AUTHORITATIVE_SOURCE_CLAIM_ID,
                "claim_key": "authoritative-document-source",
                "kind": "artifact_selection",
                "statement": (
                    "The editable primary document is the authoritative "
                    "working source."
                ),
                "rationale": {
                    "status": "known",
                    "statement": "It is the latest explicitly selected source.",
                    "evidence": [copy.deepcopy(references[1])],
                },
                "settled": True,
                "superseded_claim_ids": [],
                "reask_policy": "reask_only_on_blocking_conflict",
                "evidence": [copy.deepcopy(references[1])],
            },
            {
                "claim_id": PRESERVE_HISTORY_CLAIM_ID,
                "claim_key": "historical-output-preservation",
                "kind": "constraint",
                "statement": "Accepted historical outputs must be preserved.",
                "rationale": {
                    "status": "known",
                    "statement": (
                        "Historical versions provide provenance and rollback."
                    ),
                    "evidence": [copy.deepcopy(references[2])],
                },
                "settled": True,
                "superseded_claim_ids": [],
                "reask_policy": "do_not_reask",
                "evidence": [copy.deepcopy(references[2])],
            },
        ],
        "superseded_claims": [
            {
                "claim_id": "claim-historical-journal-a",
                "claim_key": "target-journal",
                "kind": "decision",
                "statement": "The historical publication target was Journal A.",
                "rationale": {
                    "status": "known",
                    "statement": "It predates the current fit reassessment.",
                    "evidence": [copy.deepcopy(references[0])],
                },
                "superseded_by_claim_id": TARGET_CLAIM_ID,
                "evidence": [copy.deepcopy(references[0])],
            }
        ],
        "contested_claims": [],
        "rejected_options": [
            {
                "option_id": "option-use-unverified-draft",
                "claim_key": "authoritative-document-source",
                "statement": "Use an unverified historical draft as current.",
                "rejection_rationale": {
                    "statement": "The draft has not passed current validation.",
                    "evidence": [copy.deepcopy(references[2])],
                },
                "evidence": [copy.deepcopy(references[2])],
            }
        ],
        "artifact_authorities": artifacts,
        "unclassified_artifact_policy": (
            "reference_only_do_not_infer_from_filename_or_inventory"
        ),
        "completed": [
            {
                "item_id": f"completed-synthetic-{index}",
                "statement": f"Synthetic milestone {index} was completed.",
                "evidence": [copy.deepcopy(references[index])],
            }
            for index in range(3)
        ],
        "in_progress": [
            {
                "item_id": PROGRESS_ITEM_ID,
                "statement": (
                    "The primary document is being integrated with its "
                    "supporting materials."
                ),
                "next_checkpoint": (
                    "Validate the rebuilt primary document page by page."
                ),
                "evidence": [copy.deepcopy(references[3])],
            }
        ],
        "next_actions": [
            {
                "action_id": NEXT_ACTION_ID,
                "statement": (
                    "Finish the primary document and run rendering checks."
                ),
                "depends_on_claim_ids": [
                    TARGET_CLAIM_ID,
                    AUTHORITATIVE_SOURCE_CLAIM_ID,
                ],
                "evidence": [copy.deepcopy(references[3])],
            }
        ],
        "open_questions": [
            {
                "question_id": "question-final-layout",
                "question": "Has the final layout passed visual validation?",
                "blocking": False,
                "claim_key": None,
                "related_claim_ids": [AUTHORITATIVE_SOURCE_CLAIM_ID],
                "blocking_conflict_id": None,
                "evidence": [copy.deepcopy(references[4])],
            }
        ],
        "risks": [
            {
                "risk_id": "risk-layout-regression",
                "statement": "A later edit could regress the validated layout.",
                "severity": "medium",
                "blocking": False,
                "evidence": [copy.deepcopy(references[4])],
            }
        ],
        "blocking_conflicts": [],
        "nonblocking_contradictions": [
            {
                "contradiction_id": "contradiction-target-history",
                "statement": (
                    "The historical target remains reference-only and does "
                    "not override the current target."
                ),
                "effective_claim_id": TARGET_CLAIM_ID,
                "historical_claim_ids": ["claim-historical-journal-a"],
                "evidence": [copy.deepcopy(references[0])],
                "handling": (
                    "treat_history_as_reference_and_do_not_reask"
                ),
            }
        ],
        "known_gaps": [
            {
                "gap_id": "gap-final-layout-check",
                "area": "artifact",
                "statement": "Final visual validation is still pending.",
                "trace_status": "partial",
                "evidence": [copy.deepcopy(references[4])],
            },
            {
                "gap_id": "gap-remaining-rationale",
                "area": "rationale",
                "statement": "One historical rationale is not fully recovered.",
                "trace_status": "partial",
                "evidence": [copy.deepcopy(references[5])],
            },
        ],
        "evidence_index": [
            {
                "entry_id": f"evidence-synthetic-{index}",
                "topic": f"De-identified evidence topic {index}.",
                "references": [copy.deepcopy(references[index])],
            }
            for index in range(6)
        ],
        "unprojected_deltas": [],
        "reconciliation_receipts": [],
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


def typed_parent_projection() -> dict[str, Any]:
    projection = representative_review_projection()
    projection["projection_id"] = "proj-typed-reconciliation-parent"
    projection["reconciliation_receipts"] = []
    references = [message_reference(0), message_reference(1)]
    projection["unprojected_deltas"] = [
        {
            "delta_id": DELTA_ID,
            "status": "requires_semantic_reconciliation",
            "evidence_entry_id": EVIDENCE_ENTRY_ID,
            "message_evidence": references,
            "handling": (
                "read_newest_verified_messages_before_relying_on_"
                "prior_structured_state"
            ),
        }
    ]
    projection["evidence_index"] = [
        entry
        for entry in projection["evidence_index"]
        if entry["entry_id"] != EVIDENCE_ENTRY_ID
    ]
    projection["evidence_index"].append(
        {
            "entry_id": EVIDENCE_ENTRY_ID,
            "topic": "Isolated exact-message reconciliation evidence.",
            "references": copy.deepcopy(references),
        }
    )
    return projection


def evidence_selector(*ordinals: int) -> list[dict[str, Any]]:
    return [
        {
            "delta_id": DELTA_ID,
            "message_ordinals": list(ordinals),
        }
    ]


def typed_proposal(
    *,
    projection_id: str = "proj-typed-reconciliation-parent",
    operations: list[dict[str, Any]] | None = None,
    dispositions: list[dict[str, Any]] | None = None,
    assertions: list[dict[str, Any]] | None = None,
    rationale: str = "Apply exact messages without replacing the full projection.",
) -> dict[str, Any]:
    return {
        "schema_version": "memory-vault-reconciliation-patch/v2",
        "task_id": TASK_ID,
        "source_projection_id": projection_id,
        "resolved_delta_ids": [DELTA_ID],
        "outcome_rationale": rationale,
        "operations": operations or [],
        "message_dispositions": dispositions
        or [
            {
                "delta_id": DELTA_ID,
                "message_ordinal": 0,
                "disposition": "evidence_only",
                "reason": "The message is retained as evidence only.",
            },
            {
                "delta_id": DELTA_ID,
                "message_ordinal": 1,
                "disposition": "evidence_only",
                "reason": "The message is retained as evidence only.",
            },
        ],
        "completeness_assertions": assertions or [],
    }


def record_without_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(record))
    value.pop("evidence", None)
    rationale = value.get("rationale")
    if isinstance(rationale, dict):
        rationale.pop("evidence", None)
    rejection = value.get("rejection_rationale")
    if isinstance(rejection, dict):
        rejection.pop("evidence", None)
    return value


def validate_v2(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return vault_sync._load_reconciliation_proposal_v2(value)


class ProjectionEngine:
    def __init__(
        self,
        root: Path,
        projection: Mapping[str, Any],
        *,
        offline: bool = False,
    ):
        self.lock_path = root / "projection.lock"
        self.git = ProjectionGit(offline=offline)
        self.remote = types.SimpleNamespace(
            memory_projection=projection,
            current_blob_sha="f" * 40,
            current={"snapshot_id": "snap-review-shaped-redacted-v1"},
        )


class ProjectionGit:
    def __init__(self, *, offline: bool = False):
        self.offline = offline

    def ensure(self) -> None:
        if self.offline:
            raise vault_sync.OfflineError("offline test")

    def has_cache(self) -> bool:
        return True


class CompactProjectionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.projection = representative_review_projection()

    def show(
        self,
        *,
        full: bool = False,
        kind: str | None = None,
        record_id: str | None = None,
        delta_id: str | None = None,
        cursor: int = 0,
        offline: bool = False,
        projection: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        engine = ProjectionEngine(
            self.root,
            projection or self.projection,
            offline=offline,
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            full=full,
            kind=kind,
            record_id=record_id,
            delta_id=delta_id,
            cursor=cursor,
        )
        with mock.patch.object(
            vault_sync,
            "load_remote_task_by_id",
            return_value=engine.remote,
        ):
            return vault_sync.show_memory_projection_command(args, engine)

    def test_review_equivalent_default_view_is_compact_and_not_full_projection(
        self,
    ) -> None:
        full_projection_bytes = compact_json_bytes(self.projection)
        self.assertGreater(
            len(full_projection_bytes),
            vault_sync.COMPACT_RECONCILIATION_VIEW_MAX_BYTES,
        )

        result = self.show()
        encoded = compact_json_bytes(result)

        self.assertLessEqual(
            len(encoded),
            vault_sync.COMPACT_RECONCILIATION_VIEW_MAX_BYTES,
        )
        self.assertEqual(
            result["schema_version"],
            "memory-vault-memory-projection-compact-view/v1",
        )
        self.assertNotIn("projection", result)
        self.assertNotIn("trace_policy", result)
        self.assertNotIn("reconciliation_receipts", result)
        self.assertEqual(
            result["projection_id"],
            self.projection["projection_id"],
        )
        self.assertTrue(result["record_index"])
        self.assertTrue(
            all(
                set(("kind", "id", "jcs_sha256")) <= set(item)
                for item in result["record_index"]
            )
        )
        self.assertLess(len(encoded), len(full_projection_bytes))

    def test_exact_record_fetch_matches_compact_jcs_identity(self) -> None:
        compact = self.show()
        expected = next(
            item
            for item in compact["record_index"]
            if item["kind"] == "effective_claim"
            and item["id"] == TARGET_CLAIM_ID
        )

        detail = self.show(
            kind="effective_claim",
            record_id=TARGET_CLAIM_ID,
        )

        self.assertEqual(
            detail["schema_version"],
            "memory-vault-memory-projection-record-view/v1",
        )
        self.assertIn("Journal B", detail["record"]["statement"])
        self.assertEqual(
            expected["jcs_sha256"],
            vault_sync.sha256_jcs(detail["record"]),
        )
        self.assertNotIn("projection", detail)

    def test_offline_show_uses_verified_cache_as_reference_only(self) -> None:
        result = self.show(offline=True)

        self.assertEqual(result["authority"], "cached_reference_only")
        self.assertLessEqual(
            len(compact_json_bytes(result)),
            vault_sync.COMPACT_RECONCILIATION_VIEW_MAX_BYTES,
        )

    def test_compact_record_pagination_covers_every_stable_record(self) -> None:
        pages: list[Mapping[str, Any]] = []
        cursor = 0
        for _page_number in range(10):
            page = self.show(cursor=cursor)
            pages.append(page)
            self.assertLessEqual(
                len(compact_json_bytes(page)),
                vault_sync.COMPACT_RECONCILIATION_VIEW_MAX_BYTES,
            )
            next_cursor = page["record_page"]["next_cursor"]
            if next_cursor is None:
                break
            self.assertIsInstance(next_cursor, int)
            cursor = int(next_cursor)
        else:
            self.fail("compact record pagination did not terminate")
        records = [
            item
            for page in pages
            for item in page["record_index"]
        ]
        identities = {
            (item["kind"], item["id"])
            for item in records
        }

        self.assertEqual(
            len(records),
            pages[0]["record_page"]["total"],
        )
        self.assertEqual(len(identities), len(records))
        self.assertTrue(pages[-1]["record_page"]["complete"])
        self.assertIsNone(pages[-1]["record_page"]["next_cursor"])
        self.assertTrue(
            all(
                len(item["jcs_sha256"]) == 64
                for item in records
            )
        )

    def test_compact_delta_index_requires_exact_delta_fetch_for_evidence(
        self,
    ) -> None:
        projection = typed_parent_projection()

        compact = self.show(projection=projection)
        detail = self.show(
            projection=projection,
            delta_id=DELTA_ID,
        )

        self.assertEqual(
            compact["unprojected_delta_index"],
            [
                {
                    "delta_id": DELTA_ID,
                    "evidence_entry_id": EVIDENCE_ENTRY_ID,
                    "message_count": 2,
                }
            ],
        )
        self.assertNotIn(
            b"message_evidence",
            compact_json_bytes(compact),
        )
        self.assertEqual(
            detail["schema_version"],
            "memory-vault-memory-delta-view/v1",
        )
        self.assertEqual(
            [
                reference["message_ordinal"]
                for reference in detail["delta"]["message_evidence"]
            ],
            [0, 1],
        )
        self.assertEqual(
            [
                request["reference_index"]
                for request in detail["trace_requests"]
            ],
            [0, 1],
        )


class TypedReconciliationPatchTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.parent = typed_parent_projection()

    def in_progress_update_operation(self) -> dict[str, Any]:
        before = next(
            item
            for item in self.parent["in_progress"]
            if item["item_id"] == PROGRESS_ITEM_ID
        )
        value = record_without_evidence(before)
        value["next_checkpoint"] = (
            "Validate the rebuilt Word manuscript page by page."
        )
        return {
            "operation_id": "op-update-progress",
            "op": "upsert",
            "kind": "in_progress_item",
            "id": before["item_id"],
            "prior_jcs_sha256": vault_sync.sha256_jcs(before),
            "evidence": evidence_selector(0),
            "value": value,
        }

    def mixed_proposal(self) -> dict[str, Any]:
        return typed_proposal(
            operations=[self.in_progress_update_operation()],
            dispositions=[
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 0,
                    "disposition": "applied",
                    "operation_ids": ["op-update-progress"],
                },
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 1,
                    "disposition": "evidence_only",
                    "reason": "This message supplies context but no state change.",
                },
            ],
        )

    def apply(self, proposal: Mapping[str, Any]) -> dict[str, Any]:
        validated = validate_v2(proposal)
        return vault_sync._apply_typed_reconciliation_patch(
            self.parent,
            validated,
            transaction_id="tx-typed-reconciliation-test",
        )

    def test_representative_patch_is_below_24_kib_and_oversize_is_rejected(
        self,
    ) -> None:
        proposal = self.mixed_proposal()
        path = self.root / "patch.json"
        path.write_bytes(compact_json_bytes(proposal))

        self.assertLessEqual(
            path.stat().st_size,
            vault_sync.RECONCILIATION_PATCH_MAX_BYTES,
        )
        loaded = vault_sync._load_reconciliation_proposal(path)
        self.assertEqual(
            loaded["schema_version"],
            "memory-vault-reconciliation-patch/v2",
        )

        oversized = self.mixed_proposal()
        oversized["outcome_rationale"] = "x" * (
            vault_sync.RECONCILIATION_PATCH_MAX_BYTES
        )
        oversized_path = self.root / "oversized.json"
        oversized_path.write_bytes(compact_json_bytes(oversized))
        self.assertGreater(
            oversized_path.stat().st_size,
            vault_sync.RECONCILIATION_PATCH_MAX_BYTES,
        )
        with self.assertRaisesRegex(
            vault_sync.PrivacyError,
            "exceeds 24 KiB",
        ):
            vault_sync._load_reconciliation_proposal(oversized_path)

    def test_typed_identity_is_canonical_and_changes_with_patch_or_parent(
        self,
    ) -> None:
        proposal = validate_v2(self.mixed_proposal())
        reordered = dict(reversed(list(proposal.items())))
        first = vault_sync._reconciliation_identity(
            TASK_ID,
            "a" * 40,
            proposal,
        )
        second = vault_sync._reconciliation_identity(
            TASK_ID,
            "a" * 40,
            reordered,
        )

        self.assertEqual(first, second)
        self.assertRegex(first[0], r"^memrec-[0-9a-f]{40}$")
        self.assertRegex(first[1], r"^snap-memrec-[0-9a-f]{32}$")
        self.assertRegex(first[2], r"^proj-memrec-[0-9a-f]{32}$")
        self.assertRegex(first[3], r"^[0-9a-f]{64}$")

        changed = copy.deepcopy(proposal)
        changed["outcome_rationale"] = (
            "A materially different typed reconciliation decision."
        )
        self.assertNotEqual(
            first,
            vault_sync._reconciliation_identity(
                TASK_ID,
                "a" * 40,
                changed,
            ),
        )
        self.assertNotEqual(
            first,
            vault_sync._reconciliation_identity(
                TASK_ID,
                "b" * 40,
                proposal,
            ),
        )

    def test_mixed_applied_and_evidence_only_messages_are_exactly_accounted(
        self,
    ) -> None:
        result = self.apply(self.mixed_proposal())

        updated = next(
            item
            for item in result["in_progress"]
            if item["item_id"] == PROGRESS_ITEM_ID
        )
        self.assertEqual(
            updated["next_checkpoint"],
            "Validate the rebuilt Word manuscript page by page.",
        )
        self.assertEqual(
            [reference["message_ordinal"] for reference in updated["evidence"]],
            [0],
        )
        receipt = result["reconciliation_receipts"][0]
        self.assertEqual(receipt["outcome"], "state_updated")
        self.assertEqual(
            [reference["message_ordinal"] for reference in receipt["message_evidence"]],
            [0, 1],
        )
        self.assertEqual(result["unprojected_deltas"], [])
        self.assertEqual(result["completeness"]["overall"], "partial")

    def test_missing_or_double_used_message_disposition_is_rejected(self) -> None:
        missing = self.mixed_proposal()
        missing["message_dispositions"] = missing["message_dispositions"][:1]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "does not disposition every exact message",
        ):
            self.apply(missing)

        double_used = self.mixed_proposal()
        double_used["message_dispositions"][1] = {
            "delta_id": DELTA_ID,
            "message_ordinal": 1,
            "disposition": "evidence_only",
            "reason": "This message must remain evidence-only.",
        }
        double_used["operations"][0]["evidence"] = evidence_selector(0, 1)
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "evidence-only message is also applied",
        ):
            self.apply(double_used)

    def test_evidence_only_patch_changes_no_semantic_record(self) -> None:
        before = {
            key: vault_sync.sha256_jcs(value)
            for key, value in vault_sync._typed_parent_records(
                self.parent
            ).items()
        }

        result = self.apply(typed_proposal())

        after = {
            key: vault_sync.sha256_jcs(value)
            for key, value in vault_sync._typed_parent_records(result).items()
        }
        self.assertEqual(after, before)
        self.assertEqual(
            result["reconciliation_receipts"][0]["outcome"],
            "evidence_only_no_semantic_change",
        )
        self.assertEqual(result["unprojected_deltas"], [])

    def test_completeness_changes_retain_reason_evidence_and_receipt(
        self,
    ) -> None:
        proposal = typed_proposal(
            assertions=[
                {
                    "dimension": "decisions",
                    "status": "partial",
                    "reason": (
                        "The decision inventory remains partial, but its "
                        "basis was refreshed from the newest exact message."
                    ),
                    "evidence": evidence_selector(0),
                },
                {
                    "dimension": "conflicts",
                    "status": "partial",
                    "reason": (
                        "The newest exact message requires another conflict "
                        "review before completeness can remain asserted."
                    ),
                    "evidence": evidence_selector(1),
                },
            ],
        )
        result = self.apply(proposal)
        transitions = {
            item["dimension"]: item
            for item in result["reconciliation_receipts"][0][
                "completeness_transitions"
            ]
        }

        self.assertEqual(
            transitions["decisions"]["change_kind"],
            "basis_refreshed",
        )
        self.assertEqual(
            transitions["conflicts"]["change_kind"],
            "status_changed",
        )
        self.assertNotEqual(
            transitions["decisions"]["before_basis_sha256"],
            transitions["decisions"]["after_basis_sha256"],
        )
        self.assertEqual(
            result["completeness_basis"]["decisions"]["reason"],
            proposal["completeness_assertions"][0]["reason"],
        )
        self.assertEqual(
            result["completeness"]["conflicts"],
            "partial",
        )
        self.assertEqual(
            {
                (reference["kind"], reference["id"])
                for reference in result["reconciliation_receipts"][0][
                    "result_refs"
                ]
            }
            & {
                ("completeness", "decisions"),
                ("completeness", "conflicts"),
            },
            {
                ("completeness", "decisions"),
                ("completeness", "conflicts"),
            },
        )
        vault_sync._validate_task_memory_projection_structure(result)

        inconsistent = copy.deepcopy(result)
        inconsistent["completeness_basis"]["conflicts"]["status"] = (
            "complete"
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "basis status is inconsistent",
        ):
            vault_sync._validate_task_memory_projection_structure(
                inconsistent
            )

    def test_update_requires_matching_prior_jcs_hash(self) -> None:
        proposal = self.mixed_proposal()
        result = self.apply(proposal)
        self.assertTrue(result["reconciliation_receipts"])

        stale = self.mixed_proposal()
        stale["operations"][0]["prior_jcs_sha256"] = "1" * 64
        with self.assertRaisesRegex(
            vault_sync.ConflictError,
            "precondition changed",
        ):
            self.apply(stale)

        missing = self.mixed_proposal()
        missing["operations"][0].pop("prior_jcs_sha256")
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "exactly one record precondition",
        ):
            validate_v2(missing)

        ambiguous = self.mixed_proposal()
        ambiguous["operations"][0]["expect_absent"] = True
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "exactly one record precondition",
        ):
            validate_v2(ambiguous)

    def test_add_requires_expect_absent_and_refuses_existing_record(self) -> None:
        add_risk = {
            "operation_id": "op-add-risk",
            "op": "upsert",
            "kind": "risk",
            "id": "risk-typed-test",
            "expect_absent": True,
            "evidence": evidence_selector(0),
            "value": {
                "risk_id": "risk-typed-test",
                "statement": "A synthetic isolated reconciliation risk.",
                "severity": "low",
                "blocking": False,
            },
        }
        proposal = typed_proposal(
            operations=[add_risk],
            dispositions=[
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 0,
                    "disposition": "applied",
                    "operation_ids": ["op-add-risk"],
                },
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 1,
                    "disposition": "evidence_only",
                    "reason": "No state change follows from this message.",
                },
            ],
        )
        result = self.apply(proposal)
        self.assertTrue(
            any(item["risk_id"] == "risk-typed-test" for item in result["risks"])
        )

        duplicate = self.mixed_proposal()
        duplicate["operations"][0].pop("prior_jcs_sha256")
        duplicate["operations"][0]["expect_absent"] = True
        with self.assertRaisesRegex(
            vault_sync.ConflictError,
            "expected an absent record",
        ):
            self.apply(duplicate)

    def test_pure_retirement_is_audited_with_exact_message(self) -> None:
        before = next(
            item
            for item in self.parent["next_actions"]
            if item["action_id"] == NEXT_ACTION_ID
        )
        proposal = typed_proposal(
            operations=[
                {
                    "operation_id": "op-retire-next-action",
                    "op": "retire",
                    "kind": "next_action",
                    "id": before["action_id"],
                    "prior_jcs_sha256": vault_sync.sha256_jcs(before),
                    "evidence": evidence_selector(0),
                }
            ],
            dispositions=[
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 0,
                    "disposition": "applied",
                    "operation_ids": ["op-retire-next-action"],
                },
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 1,
                    "disposition": "evidence_only",
                    "reason": "This message does not retire another record.",
                },
            ],
        )

        result = self.apply(proposal)

        self.assertFalse(
            any(
                item["action_id"] == before["action_id"]
                for item in result["next_actions"]
            )
        )
        receipt = result["reconciliation_receipts"][0]
        self.assertEqual(
            receipt["retired_refs"],
            [{"kind": "next_action", "id": before["action_id"]}],
        )
        self.assertEqual(
            [
                reference["message_ordinal"]
                for reference in receipt["retirement_message_evidence"]
            ],
            [0],
        )

    def test_in_progress_to_completed_is_one_atomic_transition(self) -> None:
        before = next(
            item
            for item in self.parent["in_progress"]
            if item["item_id"] == PROGRESS_ITEM_ID
        )
        proposal = typed_proposal(
            operations=[
                {
                    "operation_id": "op-retire-progress",
                    "op": "retire",
                    "kind": "in_progress_item",
                    "id": before["item_id"],
                    "prior_jcs_sha256": vault_sync.sha256_jcs(before),
                    "evidence": evidence_selector(0),
                },
                {
                    "operation_id": "op-complete-progress",
                    "op": "upsert",
                    "kind": "completed_item",
                    "id": before["item_id"],
                    "expect_absent": True,
                    "evidence": evidence_selector(0),
                    "value": {
                        "item_id": before["item_id"],
                        "statement": "The Word integration passed validation.",
                    },
                },
            ],
            dispositions=[
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 0,
                    "disposition": "applied",
                    "operation_ids": [
                        "op-retire-progress",
                        "op-complete-progress",
                    ],
                },
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 1,
                    "disposition": "evidence_only",
                    "reason": "This message is contextual only.",
                },
            ],
        )

        result = self.apply(proposal)

        self.assertFalse(
            any(item["item_id"] == before["item_id"] for item in result["in_progress"])
        )
        self.assertTrue(
            any(item["item_id"] == before["item_id"] for item in result["completed"])
        )
        receipt = result["reconciliation_receipts"][0]
        self.assertIn(
            {"kind": "in_progress_item", "id": before["item_id"]},
            receipt["retired_refs"],
        )
        self.assertIn(
            {"kind": "completed_item", "id": before["item_id"]},
            receipt["result_refs"],
        )

    def test_effective_claim_can_only_move_to_history_atomically(self) -> None:
        before = next(
            item
            for item in self.parent["effective_claims"]
            if item["claim_id"] == PRESERVE_HISTORY_CLAIM_ID
        )
        historical_value = {
            "claim_id": before["claim_id"],
            "claim_key": before["claim_key"],
            "kind": before["kind"],
            "statement": before["statement"],
            "rationale": {
                "status": "known",
                "statement": "A newer preservation decision superseded it.",
            },
            "superseded_by_claim_id": AUTHORITATIVE_SOURCE_CLAIM_ID,
        }
        proposal = typed_proposal(
            operations=[
                {
                    "operation_id": "op-retire-effective",
                    "op": "retire",
                    "kind": "effective_claim",
                    "id": before["claim_id"],
                    "prior_jcs_sha256": vault_sync.sha256_jcs(before),
                    "evidence": evidence_selector(0),
                },
                {
                    "operation_id": "op-record-superseded",
                    "op": "upsert",
                    "kind": "superseded_claim",
                    "id": before["claim_id"],
                    "expect_absent": True,
                    "evidence": evidence_selector(0),
                    "value": historical_value,
                },
            ],
            dispositions=[
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 0,
                    "disposition": "applied",
                    "operation_ids": [
                        "op-retire-effective",
                        "op-record-superseded",
                    ],
                },
                {
                    "delta_id": DELTA_ID,
                    "message_ordinal": 1,
                    "disposition": "evidence_only",
                    "reason": "This message is contextual only.",
                },
            ],
        )
        result = self.apply(proposal)
        self.assertFalse(
            any(
                item["claim_id"] == before["claim_id"]
                for item in result["effective_claims"]
            )
        )
        self.assertTrue(
            any(
                item["claim_id"] == before["claim_id"]
                for item in result["superseded_claims"]
            )
        )

        non_atomic = copy.deepcopy(proposal)
        non_atomic["operations"] = non_atomic["operations"][:1]
        non_atomic["message_dispositions"][0]["operation_ids"] = [
            "op-retire-effective"
        ]
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "lacks an atomic claim transition",
        ):
            self.apply(non_atomic)


class FiveLayerHandoffContractTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.projection = representative_review_projection()

    def state(
        self,
        projection: Mapping[str, Any] | None = None,
    ) -> vault_sync.RemoteTaskState:
        selected = projection or self.projection
        basis = selected["basis"]
        snapshot_id = str(basis["snapshot_id"])
        manifest_path = str(basis["manifest_path"])
        manifest = {
            "schema_version": "task-version/v1",
            "task_id": TASK_ID,
            "snapshot_id": snapshot_id,
            "generation": int(basis["generation"]),
            "state": "published",
            "transaction_id": str(basis["transaction_id"]),
            "change_type": "content_revision",
            "continuation_readiness": "partial",
            "parents": [],
            "artifacts": [],
            "memory_projection": {
                "projection_id": selected["projection_id"],
                "path": (
                    f"tasks/{TASK_ID}/projections/"
                    f"{selected['projection_id']}.json"
                ),
                "content_sha256": "9" * 64,
            },
        }
        return vault_sync.RemoteTaskState(
            commit_sha="8" * 40,
            task_path=f"tasks/{TASK_ID}/TASK.json",
            task={
                "task_id": TASK_ID,
                "status": "active",
                "display_title": "De-identified review handoff",
            },
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
            current_blob_sha="7" * 40,
            current={
                "schema_version": "task-current/v1",
                "task_id": TASK_ID,
                "generation": int(basis["generation"]),
                "state": "active",
                "snapshot_id": snapshot_id,
                "manifest_path": manifest_path,
                "continuation_readiness": "partial",
                "published_transaction_id": str(
                    basis["transaction_id"]
                ),
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            },
            manifest_path=manifest_path,
            manifest=manifest,
            memory_projection_path=manifest["memory_projection"]["path"],
            memory_projection=selected,
        )

    def test_capsule_keeps_every_protected_handoff_section(self) -> None:
        context = vault_sync._projected_continuation_context(
            self.state(),
            git=mock.Mock(),
            offline=False,
        )

        self.assertLessEqual(
            len(context.encode("utf-8")),
            vault_sync.CONTINUATION_CAPSULE_TARGET_BYTES,
        )
        for protected in (
            "2. CURRENT GOAL AND BOUNDARY:",
            "3. BLOCKING CONFLICTS:",
            "4. EFFECTIVE SETTLED CLAIMS",
            "5. NEXT ACTION:",
            "6. CURRENT AUTHORITATIVE ARTIFACTS:",
            "7. EXECUTION STATUS",
            "8. REJECTED / SUPERSEDED HISTORY",
            "9. OPEN QUESTIONS, RISKS, AND GAPS:",
            "10. VERIFIED EVIDENCE ENTRY IDS:",
            "11. COMPLETENESS:",
            "Completeness basis lookup:",
            "Trace rule:",
            "Publish rule:",
        ):
            self.assertIn(protected, context)
        self.assertIn("The current publication target is Journal B.", context)
        self.assertIn(
            "Journal B is the current target after the scope and fit were",
            context,
        )
        self.assertIn("option-use-unverified-draft", context)
        self.assertIn("claim-historical-journal-a", context)
        self.assertIn(PROGRESS_ITEM_ID, context)
        self.assertIn(NEXT_ACTION_ID, context)
        self.assertIn("gap-final-layout-check", context)

    def test_capsule_and_remote_documents_reject_credentials(self) -> None:
        secret = "github_pat_" + ("A" * 32)
        unsafe = copy.deepcopy(self.projection)
        unsafe["current_goal"]["statement"] = (
            f"Never expose this credential: {secret}"
        )

        with self.assertRaisesRegex(
            vault_sync.PrivacyError,
            "github_token",
        ):
            vault_sync._projected_continuation_context(
                self.state(unsafe),
                git=mock.Mock(),
                offline=False,
            )
        with self.assertRaisesRegex(
            vault_sync.PrivacyError,
            "github_token",
        ):
            vault_sync.assert_remote_safe(unsafe)

    def test_private_handoff_capabilities_are_secret_scanned_without_false_positives(
        self,
    ) -> None:
        token = "A" * 43
        for leaked in (
            f"--session-token {token}",
            f"session_token:{token}",
            f"[[memory-vault-handoff:{token}]]",
        ):
            with self.subTest(leaked=leaked), self.assertRaises(
                vault_sync.PrivacyError
            ):
                vault_sync._scan_text_content(
                    f"Unsafe copied control text: {leaked}",
                    "isolated handoff text",
                )

        for safe in (
            f"--session-token {'A' * 42}",
            "The session token is issued locally and is never backed up.",
            "[[memory-vault-handoff:short-placeholder]]",
            token,
        ):
            with self.subTest(safe=safe):
                self.assertEqual(
                    vault_sync._scan_text_content(
                        safe,
                        "isolated ordinary text",
                    ),
                    safe,
                )

    @staticmethod
    def verified_authority(
        *,
        index: int,
        role: str,
        snapshot_id: str,
    ) -> dict[str, Any]:
        artifact_id = f"artifact-role-slot-{index}"
        digest = f"{index + 5000:064x}"
        evidence = {
            "kind": "artifact",
            "artifact_id": artifact_id,
            "sha256": digest,
        }
        return {
            "artifact_id": artifact_id,
            "sha256": digest,
            "purpose": f"Verified artifact occupying role slot {role}.",
            "role": role,
            "authority_status": "current_authoritative",
            "source_snapshot_id": snapshot_id,
            "dependencies": [],
            "verification": {
                "status": "verified",
                "checks": [
                    {
                        "check_id": f"check-sha-{index}",
                        "kind": "sha256",
                        "result": "passed",
                        "evidence": [copy.deepcopy(evidence)],
                    },
                    {
                        "check_id": f"check-size-{index}",
                        "kind": "size",
                        "result": "passed",
                        "evidence": [copy.deepcopy(evidence)],
                    },
                ],
                "evidence": [copy.deepcopy(evidence)],
            },
            "relations": [],
        }

    def validate_role_slots(
        self,
        projection: Mapping[str, Any],
        manifest: Mapping[str, Any],
    ) -> None:
        current = {
            "task_id": TASK_ID,
            "snapshot_id": manifest["snapshot_id"],
            "generation": manifest["generation"],
            "published_transaction_id": manifest["transaction_id"],
            "continuation_readiness": manifest.get(
                "continuation_readiness",
                "partial",
            ),
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
                "_validate_projection_reconciliation_receipts",
            ),
            mock.patch.object(
                vault_sync,
                "_projection_ancestor_manifests",
                return_value={
                    str(manifest["snapshot_id"]): manifest,
                },
            ),
        ):
            vault_sync._validate_projection_semantics(
                mock.Mock(),
                current,
                str(projection["basis"]["manifest_path"]),
                manifest,
                projection,
            )

    def test_current_authority_is_unique_per_role_not_globally(self) -> None:
        projection = copy.deepcopy(self.projection)
        snapshot_id = str(projection["basis"]["snapshot_id"])
        first = self.verified_authority(
            index=1,
            role="primary-manuscript",
            snapshot_id=snapshot_id,
        )
        second = self.verified_authority(
            index=2,
            role="submission-figure",
            snapshot_id=snapshot_id,
        )
        projection["artifact_authorities"] = [first, second]
        projection["blocking_conflicts"] = []
        manifest = {
            "snapshot_id": snapshot_id,
            "generation": projection["basis"]["generation"],
            "transaction_id": projection["basis"]["transaction_id"],
            "continuation_readiness": "partial",
            "artifacts": [
                {
                    "artifact_id": item["artifact_id"],
                    "sha256": item["sha256"],
                }
                for item in (first, second)
            ],
        }

        vault_sync._validate_task_memory_projection_structure(projection)
        self.validate_role_slots(projection, manifest)

        same_role = copy.deepcopy(projection)
        same_role["artifact_authorities"][1]["role"] = (
            "primary-manuscript"
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "same role|in role",
        ):
            self.validate_role_slots(same_role, manifest)

        reference = message_reference(0)
        same_role["blocking_conflicts"] = [
            {
                "conflict_id": "conflict-primary-manuscript-slot",
                "statement": (
                    "Two verified files currently compete for the same "
                    "primary manuscript role."
                ),
                "claim_ids": [],
                "artifact_ids": [
                    first["artifact_id"],
                    second["artifact_id"],
                ],
                "evidence": [reference],
                "handling": (
                    "stop_disputed_work_and_request_resolution"
                ),
            }
        ]
        blocked_manifest = {
            **manifest,
            "continuation_readiness": "blocked",
        }
        self.validate_role_slots(same_role, blocked_manifest)


class SessionTicketGit:
    def __init__(self, worktree: Path):
        self.worktree = worktree
        self.written_files: Mapping[str, bytes] | None = None

    def ensure(self) -> None:
        return None

    def has_cache(self) -> bool:
        return True

    def create_worktree(self) -> contextlib.AbstractContextManager[Path]:
        self.worktree.mkdir(parents=True, exist_ok=True)
        return contextlib.nullcontext(self.worktree)

    def write_generated_files(
        self,
        _worktree: Path,
        files: Mapping[str, bytes],
    ) -> None:
        self.written_files = files

    def commit_and_push(
        self,
        _worktree: Path,
        _files: Mapping[str, bytes],
        _task_id: str,
        _transaction_id: str,
    ) -> str:
        return "c" * 40

    def fetch(self) -> None:
        return None

    def file_exists(self, _path: str) -> bool:
        return False


class DeterministicRetryGit(SessionTicketGit):
    def __init__(self, worktree: Path):
        super().__init__(worktree)
        self.files: dict[str, bytes] = {}
        self.path_history: dict[str, list[tuple[str, bytes]]] = {}
        self.commit_snapshots: dict[tuple[str, str], bytes] = {}
        self.changed_paths: dict[str, set[str]] = {}
        self.commit_calls = 0

    def file_exists(self, path: str) -> bool:
        return path in self.files

    def show_bytes(self, path: str) -> bytes:
        return self.files[path]

    def show_json(self, path: str) -> Mapping[str, Any]:
        value = json.loads(self.show_bytes(path).decode("utf-8"))
        if not isinstance(value, dict):
            raise AssertionError(f"{path} is not a JSON object")
        return value

    def assert_immutable_path(self, path: str, raw: bytes) -> None:
        if self.show_bytes(path) != raw:
            raise AssertionError(f"{path} changed")

    def path_commits(self, path: str, maximum: int = 512) -> list[str]:
        return [
            commit
            for commit, _raw in self.path_history.get(path, [])
        ][:maximum]

    def show_bytes_at(self, commit: str, path: str) -> bytes:
        snapshot = self.commit_snapshots.get((commit, path))
        if snapshot is not None:
            return snapshot
        for historical_commit, raw in self.path_history.get(path, []):
            if historical_commit == commit:
                return raw
        raise KeyError((commit, path))

    def commit_changed_paths(self, commit: str) -> set[str]:
        return set(self.changed_paths.get(commit, set()))

    def commit_and_push(
        self,
        _worktree: Path,
        _files: Mapping[str, bytes],
        _task_id: str,
        _transaction_id: str,
    ) -> str:
        self.commit_calls += 1
        raise AssertionError(
            "a deterministic reconciliation retry must not create a commit"
        )


class TwoTurnSessionRefreshTests(unittest.TestCase):
    session_id = "codex-session-typed-reconciliation"
    turn_id = "turn-reconcile-and-continue"
    binding_id = "bnd-session-reconciliation-test"
    source_id = "src-session-reconciliation-test"
    parent_blob = "a" * 40
    parent_projection_id = "proj-typed-reconciliation-parent"

    def setUp(self) -> None:
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git = SessionTicketGit(self.root / "worktree")
        self.engine = object.__new__(vault_sync.SyncEngine)
        self.engine.config = {
            "_test_mode": True,
            "enabled": True,
            "sync": {
                "memory_network_enabled": False,
                "legacy_task_handoff_enabled": True,
                "startup_pull": True,
                "conversation_backup": True,
                "stop_publish": True,
            },
            "privacy": {"allowed_roots": []},
        }
        self.engine.provider_pins = vault_sync._provider_transaction_pins(
            vault_sync.default_config()
        )
        self.engine.data_dir = self.root
        self.engine.git = self.git
        self.engine.drive = None
        self.engine.lock_path = self.root / "locks" / "sync.lock"
        self.engine._validate_worktree = mock.Mock()
        self.device = vault_sync._device_state(self.root)
        self.session_key = vault_sync._session_key(
            self.device,
            self.session_id,
        )
        self.artifact_snapshot = {
            "sentinel.txt": [10, 20, 30, 40, "1" * 64]
        }
        self.session = {
            "schema_version": vault_sync.SESSION_SCHEMA,
            "continuation_context_contract": (
                vault_sync.CONTINUATION_CONTEXT_CONTRACT
            ),
            "identity_kind": "source",
            "task_id": TASK_ID,
            "binding_id": self.binding_id,
            "source_id": self.source_id,
            "source_external_key_sha256": vault_sync._codex_source_key(
                self.session_id
            ),
            "base": {
                "remote_commit_sha": "b" * 40,
                "task_current_path": f"tasks/{TASK_ID}/CURRENT.json",
                "task_current_blob_sha": self.parent_blob,
                "task_generation": 5,
                "snapshot_id": "snap-parent-session-test",
                "manifest_path": (
                    f"tasks/{TASK_ID}/versions/snap-parent-session-test.json"
                ),
                "published_transaction_id": "tx-parent-session-test",
            },
            "base_manifest": {
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": "snap-parent-session-test",
                "memory_projection": {
                    "projection_id": self.parent_projection_id,
                    "path": (
                        f"tasks/{TASK_ID}/projections/"
                        f"{self.parent_projection_id}.json"
                    ),
                    "content_sha256": "2" * 64,
                },
            },
            "artifact_snapshot": copy.deepcopy(self.artifact_snapshot),
            "continuation_context": (
                "Continue the current task from the verified parent capsule."
            ),
            "reconciliation_required": True,
            "pending_context_injection": True,
            "needs_remote_refresh": False,
            "started_at": "2026-07-29T00:00:00Z",
        }
        vault_sync._save_session(
            self.root,
            self.session_key,
            self.session,
        )

    def prompt_input(
        self,
        *,
        turn_id: str | None = None,
        prompt: str = "Continue from the latest verified task state.",
    ) -> dict[str, Any]:
        return {
            "hook_event_name": "UserPromptSubmit",
            "session_id": self.session_id,
            "turn_id": turn_id or self.turn_id,
            "prompt": prompt,
            "cwd": str(self.root),
        }

    def submit_prompt(
        self,
        *,
        turn_id: str | None = None,
        prompt: str = "Continue from the latest verified task state.",
    ) -> Mapping[str, Any]:
        def keep_session(
            _hook_input: Mapping[str, Any],
            _session_key: str,
            session: Mapping[str, Any],
        ) -> tuple[dict[str, Any], None]:
            return dict(session), None

        with mock.patch.object(
            self.engine,
            "_refresh_open_session",
            side_effect=keep_session,
        ):
            return self.engine.user_prompt_submit(
                self.prompt_input(turn_id=turn_id, prompt=prompt)
            )

    @staticmethod
    def context_from(output: Mapping[str, Any]) -> str | None:
        specific = output.get("hookSpecificOutput")
        if not isinstance(specific, Mapping):
            return None
        context = specific.get("additionalContext")
        return context if isinstance(context, str) else None

    def token_from(self, output: Mapping[str, Any]) -> str:
        context = self.context_from(output)
        self.assertIsNotNone(context)
        match = re.search(
            r"--session-token ([A-Za-z0-9_-]{43})",
            str(context),
        )
        self.assertIsNotNone(match)
        return str(match.group(1))

    def ticket_path(self, token: str) -> Path:
        return vault_sync._reconciliation_ticket_path(
            self.root,
            vault_sync.sha256_bytes(token.encode("ascii")),
        )

    def store_authorized_pending(
        self,
        *,
        observed_current_blob_sha: str | None = None,
        proposal: Mapping[str, Any] | None = None,
    ) -> tuple[str, Path, Mapping[str, Any], str]:
        token = self.token_from(self.submit_prompt())
        proposal = validate_v2(proposal or typed_proposal())
        with mock.patch.dict(
            os.environ,
            {"CODEX_THREAD_ID": self.session_id},
            clear=False,
        ):
            ticket_record = vault_sync._verified_reconciliation_ticket(
                self.engine,
                token=token,
                task_id=TASK_ID,
                expected_current_blob_sha=self.parent_blob,
                source_projection_id=self.parent_projection_id,
            )
        vault_sync._bind_reconciliation_ticket_proposal(
            self.engine,
            ticket_record,
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal=proposal,
        )
        pending_id = vault_sync._store_pending_reconciliation(
            self.engine,
            proposal,
            expected_current_blob_sha=self.parent_blob,
            observed_current_blob_sha=observed_current_blob_sha,
            ticket_record=ticket_record,
        )
        pending_path = (
            self.root
            / "state"
            / "reconciliation-pending"
            / f"{pending_id}.json"
        )
        self.assertTrue(pending_path.is_file())
        self.assertIsNotNone(
            vault_sync.load_json(pending_path)["authorization"]
        )
        return pending_id, pending_path, proposal, token

    def pending_terminal_path(self, pending_id: str) -> Path:
        return (
            self.root
            / "state"
            / "reconciliation-terminal"
            / f"{pending_id}.json"
        )

    def defer_unresolved_history_pending(
        self,
    ) -> tuple[str, Path, Mapping[str, Any], vault_sync.RemoteTaskState]:
        token = self.token_from(self.submit_prompt())
        proposal = validate_v2(typed_proposal())
        proposal_path = self.root / "history-temporarily-unavailable.json"
        proposal_path.write_bytes(compact_json_bytes(proposal))
        parent = self.retry_parent_remote()
        latest = dataclasses.replace(
            parent,
            commit_sha="f" * 40,
            current_blob_sha="f" * 40,
            current={
                **parent.current,
                "generation": 6,
                "snapshot_id": "snap-remote-history-unavailable",
                "published_transaction_id": "tx-remote-history-unavailable",
            },
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=latest,
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                return_value=None,
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                side_effect=vault_sync.ConflictError(
                    "isolated history lookup lag"
                ),
            ),
        ):
            deferred = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )
        self.assertEqual(deferred["status"], "pending_remote_advance")
        pending_id = str(deferred["pending_id"])
        pending_path = (
            self.root
            / "state"
            / "reconciliation-pending"
            / f"{pending_id}.json"
        )
        pending = vault_sync.load_json(pending_path)
        self.assertIsNone(pending["authorization"])
        self.assertEqual(
            vault_sync.load_json(self.ticket_path(token))["state"],
            "invalidated",
        )
        self.assertIsNone(self.engine.git.written_files)
        return pending_id, pending_path, proposal, latest

    def retry_parent_remote(self) -> vault_sync.RemoteTaskState:
        evidence_sources = [
            {
                "source_id": SOURCE_ID,
                "revision_id": REVISION_ID,
                "source_sequence": 1,
                "binding_id": "bnd-typed-test",
                "content_path": (
                    f"sources/{SOURCE_ID}/revisions/{REVISION_ID}.json"
                ),
                "content_sha256": "1" * 64,
            }
        ]
        return vault_sync.RemoteTaskState(
            commit_sha="1" * 40,
            task_path=f"tasks/{TASK_ID}/TASK.json",
            task={"task_id": TASK_ID, "status": "active"},
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
            current_blob_sha=self.parent_blob,
            current={
                "schema_version": "task-current/v1",
                "task_id": TASK_ID,
                "generation": 5,
                "state": "active",
                "snapshot_id": "snap-parent-session-test",
                "manifest_path": (
                    f"tasks/{TASK_ID}/versions/"
                    "snap-parent-session-test.json"
                ),
                "continuation_readiness": "partial",
                "published_transaction_id": "tx-parent-session-test",
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            },
            manifest_path=(
                f"tasks/{TASK_ID}/versions/"
                "snap-parent-session-test.json"
            ),
            manifest={
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": "snap-parent-session-test",
                "generation": 5,
                "state": "published",
                "transaction_id": "tx-parent-session-test",
                "change_type": "content_revision",
                "continuation_readiness": "partial",
                "parents": [],
                "artifacts": [],
                "evidence_sources": evidence_sources,
            },
            memory_projection_path=(
                f"tasks/{TASK_ID}/projections/"
                f"{self.parent_projection_id}.json"
            ),
            memory_projection=typed_parent_projection(),
        )

    def prepared_retry_state(
        self,
        *,
        existing_state: str,
        relation: str,
        task_status: str = "active",
    ) -> tuple[
        DeterministicRetryGit,
        vault_sync.RemoteTaskState,
        vault_sync.RemoteTaskState,
        dict[str, bytes],
        str,
        str,
        str,
    ]:
        if existing_state not in {"published", "candidate"}:
            raise AssertionError(existing_state)
        if relation not in {"current", "historical", "candidate"}:
            raise AssertionError(relation)
        parent = self.retry_parent_remote()
        proposal = validate_v2(typed_proposal())
        git = DeterministicRetryGit(self.root / "retry-worktree")
        with (
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            files, transaction_id, snapshot_id = (
                vault_sync._reconciliation_documents(
                    git,
                    parent,
                    proposal,
                    candidate=existing_state == "candidate",
                )
            )
        projection_id = vault_sync._reconciliation_identity(
            TASK_ID,
            self.parent_blob,
            proposal,
        )[2]
        version_path = (
            f"tasks/{TASK_ID}/versions/{snapshot_id}.json"
        )
        projection_path = (
            f"tasks/{TASK_ID}/projections/{projection_id}.json"
        )
        immutable_files = {
            version_path: files[version_path],
            projection_path: files[projection_path],
        }
        git.files.update(immutable_files)
        published_commit = "6" * 40
        git.path_history[version_path] = [
            (published_commit, files[version_path])
        ]
        git.path_history[projection_path] = [
            (published_commit, files[projection_path])
        ]
        git.commit_snapshots[(published_commit, version_path)] = files[
            version_path
        ]
        git.commit_snapshots[(published_commit, projection_path)] = files[
            projection_path
        ]
        git.changed_paths[published_commit] = {
            version_path,
            projection_path,
            *(
                [parent.current_path]
                if existing_state == "published"
                else []
            ),
        }

        if relation == "current":
            current_raw = files[parent.current_path]
            current = json.loads(current_raw.decode("utf-8"))
            version = json.loads(files[version_path].decode("utf-8"))
            projection = json.loads(
                files[projection_path].decode("utf-8")
            )
            git.files[parent.current_path] = current_raw
            git.path_history[parent.current_path] = [
                (published_commit, current_raw)
            ]
            git.commit_snapshots[
                (published_commit, parent.current_path)
            ] = current_raw
            latest = vault_sync.RemoteTaskState(
                commit_sha=published_commit,
                task_path=parent.task_path,
                task=parent.task,
                current_path=parent.current_path,
                current_blob_sha=vault_sync.git_blob_sha(current_raw),
                current=current,
                manifest_path=version_path,
                manifest=version,
                memory_projection_path=projection_path,
                memory_projection=projection,
            )
        else:
            newer_commit = "7" * 40
            newer_snapshot = "snap-after-reconciliation"
            newer_manifest_path = (
                f"tasks/{TASK_ID}/versions/{newer_snapshot}.json"
            )
            newer_current = {
                "schema_version": "task-current/v1",
                "task_id": TASK_ID,
                "generation": 7,
                "state": "active",
                "snapshot_id": newer_snapshot,
                "manifest_path": newer_manifest_path,
                "continuation_readiness": "partial",
                "published_transaction_id": "tx-after-reconciliation",
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            }
            newer_raw = vault_sync.pretty_json_bytes(newer_current)
            newer_projection = {
                "projection_id": "proj-after-reconciliation",
                "unprojected_deltas": [],
            }
            newer_manifest = {
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": newer_snapshot,
                "generation": 7,
                "state": "published",
                "transaction_id": "tx-after-reconciliation",
                "memory_projection": {
                    "projection_id": "proj-after-reconciliation",
                    "path": (
                        f"tasks/{TASK_ID}/projections/"
                        "proj-after-reconciliation.json"
                    ),
                    "content_sha256": "8" * 64,
                },
            }
            git.files[parent.current_path] = newer_raw
            git.path_history[parent.current_path] = [
                (newer_commit, newer_raw)
            ]
            if existing_state == "published":
                published_current = files[parent.current_path]
                git.path_history[parent.current_path].append(
                    (published_commit, published_current)
                )
                git.commit_snapshots[
                    (published_commit, parent.current_path)
                ] = published_current
            else:
                git.commit_snapshots[
                    (published_commit, parent.current_path)
                ] = newer_raw
            latest = vault_sync.RemoteTaskState(
                commit_sha=newer_commit,
                task_path=parent.task_path,
                task=parent.task,
                current_path=parent.current_path,
                current_blob_sha=vault_sync.git_blob_sha(newer_raw),
                current=newer_current,
                manifest_path=newer_manifest_path,
                manifest=newer_manifest,
                memory_projection_path=(
                    f"tasks/{TASK_ID}/projections/"
                    "proj-after-reconciliation.json"
                ),
                memory_projection=newer_projection,
            )
        latest = dataclasses.replace(
            latest,
            task={"task_id": TASK_ID, "status": task_status},
        )
        return (
            git,
            parent,
            latest,
            immutable_files,
            transaction_id,
            snapshot_id,
            projection_id,
        )

    def run_existing_retry(
        self,
        *,
        existing_state: str,
        relation: str,
        task_status: str = "active",
    ) -> tuple[
        Mapping[str, Any],
        DeterministicRetryGit,
        Mapping[str, Any],
        bytes,
        dict[str, bytes],
    ]:
        token = self.token_from(self.submit_prompt())
        turn_key = vault_sync._turn_key(
            self.device,
            self.session_id,
            self.turn_id,
        )
        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            turn_key,
        )
        prompt_before = prompt_path.read_bytes()
        proposal_path = self.root / (
            f"retry-{existing_state}-{relation}.json"
        )
        proposal_path.write_bytes(compact_json_bytes(typed_proposal()))
        (
            git,
            parent,
            latest,
            immutable_files,
            _transaction_id,
            _snapshot_id,
            _projection_id,
        ) = self.prepared_retry_state(
            existing_state=existing_state,
            relation=relation,
            task_status=task_status,
        )
        self.engine.git = git
        session_before = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=latest,
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Recovered deterministic continuation capsule.",
            ),
        ):
            result = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )
        self.assertEqual(git.commit_calls, 0)
        self.assertIsNone(git.written_files)
        for path, raw in immutable_files.items():
            self.assertEqual(git.show_bytes(path), raw)
            self.assertEqual(len(git.path_commits(path)), 1)
        self.assertEqual(prompt_path.read_bytes(), prompt_before)
        return (
            result,
            git,
            session_before,
            prompt_before,
            immutable_files,
        )

    def classify_existing_retry(
        self,
        git: DeterministicRetryGit,
        parent: vault_sync.RemoteTaskState,
        latest: vault_sync.RemoteTaskState,
    ) -> Mapping[str, Any] | None:
        with (
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            return vault_sync._existing_typed_reconciliation(
                git,
                latest,
                TASK_ID,
                self.parent_blob,
                validate_v2(typed_proposal()),
            )

    def test_context_and_exact_session_ticket_are_injected_once(self) -> None:
        first = self.submit_prompt()
        token = self.token_from(first)
        second = self.submit_prompt(prompt="The same turn was delivered again.")

        self.assertIsNone(self.context_from(second))
        ticket_files = list(
            (self.root / "state" / "reconciliation-tickets").glob("*.json")
        )
        self.assertEqual(len(ticket_files), 1)
        session_bytes = vault_sync._session_path(
            self.root,
            self.session_key,
        ).read_bytes()
        ticket_bytes = self.ticket_path(token).read_bytes()
        self.assertNotIn(token.encode("ascii"), session_bytes)
        self.assertNotIn(token.encode("ascii"), ticket_bytes)

        with mock.patch.dict(
            os.environ,
            {"CODEX_THREAD_ID": self.session_id},
            clear=False,
        ):
            path, ticket, _session = (
                vault_sync._verified_reconciliation_ticket(
                    self.engine,
                    token=token,
                    task_id=TASK_ID,
                    expected_current_blob_sha=self.parent_blob,
                    source_projection_id=self.parent_projection_id,
                )
            )
            with self.assertRaisesRegex(
                vault_sync.IdentityError,
                "scope is invalid",
            ):
                vault_sync._verified_reconciliation_ticket(
                    self.engine,
                    token=token,
                    task_id=TASK_ID,
                    expected_current_blob_sha="d" * 40,
                    source_projection_id=self.parent_projection_id,
                )
            with self.assertRaisesRegex(
                vault_sync.IdentityError,
                "scope is invalid",
            ):
                vault_sync._verified_reconciliation_ticket(
                    self.engine,
                    token=token,
                    task_id=TASK_ID,
                    expected_current_blob_sha=self.parent_blob,
                    source_projection_id="proj-another-source",
                )

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": "another-codex-session"},
                clear=False,
            ),
            self.assertRaisesRegex(
                vault_sync.IdentityError,
                "belongs to another Codex task",
            ),
        ):
            vault_sync._verified_reconciliation_ticket(
                self.engine,
                token=token,
                task_id=TASK_ID,
                expected_current_blob_sha=self.parent_blob,
                source_projection_id=self.parent_projection_id,
            )

        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            vault_sync._turn_key(
                self.device,
                self.session_id,
                self.turn_id,
            ),
        )
        prompt_bytes = prompt_path.read_bytes()
        prompt_path.unlink()
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            self.assertRaisesRegex(
                vault_sync.IdentityError,
                "outside its issuing turn",
            ),
        ):
            vault_sync._verified_reconciliation_ticket(
                self.engine,
                token=token,
                task_id=TASK_ID,
                expected_current_blob_sha=self.parent_blob,
                source_projection_id=self.parent_projection_id,
            )
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_bytes(prompt_bytes)

        vault_sync._finish_reconciliation_ticket(
            self.engine,
            path,
            ticket,
            state="consumed",
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            self.assertRaisesRegex(
                vault_sync.IdentityError,
                "scope is invalid",
            ),
        ):
            vault_sync._verified_reconciliation_ticket(
                self.engine,
                token=token,
                task_id=TASK_ID,
                expected_current_blob_sha=self.parent_blob,
                source_projection_id=self.parent_projection_id,
            )
        self.assertEqual(
            vault_sync.load_json(path)["state"],
            "consumed",
        )
        refreshed = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            refreshed,
        )

    def test_ticket_is_not_committed_before_identity_and_prompt_staging(
        self,
    ) -> None:
        def keep_session(
            _hook_input: Mapping[str, Any],
            _session_key: str,
            session: Mapping[str, Any],
        ) -> tuple[dict[str, Any], None]:
            return dict(session), None

        with (
            mock.patch.object(
                self.engine,
                "_refresh_open_session",
                side_effect=keep_session,
            ),
            mock.patch.object(
                self.engine,
                "_identity_from_session_input",
                side_effect=vault_sync.IdentityError(
                    "isolated identity failure"
                ),
            ),
        ):
            output = self.engine.user_prompt_submit(self.prompt_input())

        self.assertIsNone(self.context_from(output))
        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertTrue(session["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session,
        )
        ticket_root = self.root / "state" / "reconciliation-tickets"
        issued = []
        if ticket_root.exists():
            issued = [
                vault_sync.load_json(path)
                for path in ticket_root.glob("*.json")
                if vault_sync.load_json(path).get("state") == "issued"
            ]
        self.assertEqual(issued, [])

    def test_prompt_staging_failure_leaves_injection_retryable(self) -> None:
        def keep_session(
            _hook_input: Mapping[str, Any],
            _session_key: str,
            session: Mapping[str, Any],
        ) -> tuple[dict[str, Any], None]:
            return dict(session), None

        real_atomic_write_json = vault_sync.atomic_write_json

        def fail_prompt_write(
            path: Path,
            value: Any,
            *args: Any,
            **kwargs: Any,
        ) -> None:
            if "prompts" in path.parts:
                raise OSError("isolated prompt staging failure")
            real_atomic_write_json(path, value, *args, **kwargs)

        with (
            mock.patch.object(
                self.engine,
                "_refresh_open_session",
                side_effect=keep_session,
            ),
            mock.patch.object(
                vault_sync,
                "atomic_write_json",
                side_effect=fail_prompt_write,
            ),
            self.assertRaisesRegex(
                OSError,
                "prompt staging failure",
            ),
        ):
            self.engine.user_prompt_submit(self.prompt_input())

        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertTrue(session["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session,
        )
        ticket_root = self.root / "state" / "reconciliation-tickets"
        self.assertFalse(ticket_root.exists())

    def test_expired_ticket_is_invalidated_without_remote_write(self) -> None:
        token = self.token_from(self.submit_prompt())
        path = self.ticket_path(token)
        ticket = vault_sync.load_json(path)
        ticket["expires_at"] = "2000-01-01T00:00:00Z"
        vault_sync.atomic_write_json(path, ticket)

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            self.assertRaisesRegex(
                vault_sync.IdentityError,
                "expired",
            ),
        ):
            vault_sync._verified_reconciliation_ticket(
                self.engine,
                token=token,
                task_id=TASK_ID,
                expected_current_blob_sha=self.parent_blob,
                source_projection_id=self.parent_projection_id,
            )

        self.assertEqual(
            vault_sync.load_json(path)["state"],
            "invalidated",
        )
        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session,
        )
        self.assertTrue(session["pending_context_injection"])
        self.assertIsNone(self.git.written_files)

    def test_pending_recovery_retains_authorized_work_while_offline(
        self,
    ) -> None:
        pending_id, pending_path, _proposal, _token = (
            self.store_authorized_pending()
        )
        self.engine.git.ensure = mock.Mock(
            side_effect=vault_sync.OfflineError("isolated offline recovery")
        )

        result = vault_sync._recover_pending_reconciliations(
            self.engine,
            session_key=self.session_key,
        )

        self.assertEqual(result["status"], "retained_offline")
        self.assertFalse(result["remote_write_attempted"])
        self.assertTrue(pending_path.is_file())
        self.assertFalse(self.pending_terminal_path(pending_id).exists())
        self.assertIsNone(self.engine.git.written_files)

    def test_pending_without_authorization_moves_byte_exact_with_signed_reason(
        self,
    ) -> None:
        proposal = validate_v2(typed_proposal())
        pending_id = vault_sync._store_pending_reconciliation(
            self.engine,
            proposal,
            expected_current_blob_sha=self.parent_blob,
            observed_current_blob_sha=None,
            ticket_record=None,
        )
        pending_path = (
            self.root
            / "state"
            / "reconciliation-pending"
            / f"{pending_id}.json"
        )
        pending_bytes = pending_path.read_bytes()
        pending = vault_sync.load_json(pending_path)
        parent = self.retry_parent_remote()
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                return_value=None,
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
                session_key=self.session_key,
            )

        self.assertEqual(result["status"], "requires_new_authorization")
        self.assertFalse(result["remote_write_attempted"])
        self.assertIsNone(self.engine.git.written_files)
        self.assertFalse(pending_path.exists())
        review_root = (
            self.root
            / "state"
            / "reconciliation-needs-authorization"
        )
        preserved_path = review_root / f"{pending_id}.json"
        self.assertEqual(preserved_path.read_bytes(), pending_bytes)
        reason_path = review_root / f"{pending_id}.reason.json"
        reason = vault_sync.load_json(reason_path)
        reason_signature = reason.pop("integrity_hmac_sha256")
        self.assertEqual(
            reason_signature,
            vault_sync._pending_reconciliation_signature(
                self.engine,
                reason,
            ),
        )
        self.assertEqual(
            reason["preserved_sha256"],
            vault_sync.sha256_bytes(pending_bytes),
        )
        self.assertEqual(
            reason["preserved_integrity_hmac_sha256"],
            pending["integrity_hmac_sha256"],
        )
        self.assertTrue(reason["content_preserved"])
        self.assertEqual(
            result["deferred_needs_authorization_ids"],
            [pending_id],
        )
        self.assertEqual(
            result["needs_authorization"],
            {
                "count": 1,
                "pending_ids": [pending_id],
                "next_step": (
                    vault_sync.RECONCILIATION_NEEDS_AUTHORIZATION_NEXT_STEP
                ),
            },
        )

    def test_tampered_unsigned_pending_is_quarantined_before_remote_access(
        self,
    ) -> None:
        proposal = validate_v2(typed_proposal())
        pending_id = vault_sync._store_pending_reconciliation(
            self.engine,
            proposal,
            expected_current_blob_sha=self.parent_blob,
            observed_current_blob_sha=None,
            ticket_record=None,
        )
        pending_path = (
            self.root
            / "state"
            / "reconciliation-pending"
            / f"{pending_id}.json"
        )

        tampered = vault_sync.load_json(pending_path)
        tampered["observed_current_blob_sha"] = "d" * 40
        vault_sync.atomic_write_json(pending_path, tampered)
        tampered_bytes = pending_path.read_bytes()
        self.engine.git.ensure = mock.Mock(
            side_effect=AssertionError(
                "tampered pending work must be rejected before remote access"
            )
        )

        quarantined = vault_sync._recover_pending_reconciliations(
            self.engine,
        )

        self.assertEqual(quarantined["status"], "quarantined")
        self.assertFalse(quarantined["remote_write_attempted"])
        self.assertFalse(pending_path.exists())
        quarantine_root = (
            self.root / "state" / "reconciliation-quarantine"
        )
        preserved_path = quarantine_root / f"{pending_id}.json"
        self.assertEqual(preserved_path.read_bytes(), tampered_bytes)
        reason = vault_sync.load_json(
            quarantine_root / f"{pending_id}.reason.json"
        )
        self.assertEqual(reason["preserved_sha256"], vault_sync.sha256_bytes(
            tampered_bytes
        ))
        self.assertTrue(reason["content_preserved"])

    def test_unsigned_pending_does_not_starve_later_authorized_work(
        self,
    ) -> None:
        authorized_proposal = validate_v2(
            typed_proposal(
                rationale=(
                    "Later work carries exact durable authorization."
                )
            )
        )
        authorized_id, authorized_path, _proposal, _token = (
            self.store_authorized_pending(
                proposal=authorized_proposal,
            )
        )
        unsigned_proposal = validate_v2(
            typed_proposal(
                rationale=(
                    "Earlier preserved work requires new exact authorization."
                )
            )
        )
        unsigned_id = vault_sync._store_pending_reconciliation(
            self.engine,
            unsigned_proposal,
            expected_current_blob_sha=self.parent_blob,
            observed_current_blob_sha=None,
            ticket_record=None,
        )
        unsigned_path = (
            self.root
            / "state"
            / "reconciliation-pending"
            / f"{unsigned_id}.json"
        )
        unsigned_bytes = unsigned_path.read_bytes()
        os.utime(unsigned_path, ns=(1, 1))

        transaction_id, snapshot_id, projection_id, _digest = (
            vault_sync._reconciliation_identity(
                TASK_ID,
                self.parent_blob,
                authorized_proposal,
            )
        )
        existing = {
            "state": "candidate",
            "relation": "candidate",
            "transaction_id": transaction_id,
            "snapshot_id": snapshot_id,
            "projection_id": projection_id,
            "commit": "d" * 40,
        }
        parent = self.retry_parent_remote()
        commit = mock.Mock(
            side_effect=AssertionError(
                "read-only recovery must not create another commit"
            )
        )
        self.engine.git.commit_and_push = commit
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[None, existing],
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
                session_key=self.session_key,
            )

        self.assertEqual(result["status"], "candidate_remote_advance")
        self.assertEqual(
            result["deferred_needs_authorization_ids"],
            [unsigned_id],
        )
        self.assertEqual(result["pending_id"], authorized_id)
        commit.assert_not_called()
        self.assertFalse(unsigned_path.exists())
        self.assertFalse(authorized_path.exists())
        self.assertEqual(
            (
                self.root
                / "state"
                / "reconciliation-needs-authorization"
                / f"{unsigned_id}.json"
            ).read_bytes(),
            unsigned_bytes,
        )
        self.assertTrue(
            self.pending_terminal_path(authorized_id).is_file()
        )

    def test_unsigned_pending_existing_remote_result_terminalizes_read_only(
        self,
    ) -> None:
        proposal = validate_v2(
            typed_proposal(
                rationale=(
                    "Unsigned local record already has a deterministic "
                    "remote candidate."
                )
            )
        )
        pending_id = vault_sync._store_pending_reconciliation(
            self.engine,
            proposal,
            expected_current_blob_sha=self.parent_blob,
            observed_current_blob_sha=None,
            ticket_record=None,
        )
        pending_path = (
            self.root
            / "state"
            / "reconciliation-pending"
            / f"{pending_id}.json"
        )
        transaction_id, snapshot_id, projection_id, _digest = (
            vault_sync._reconciliation_identity(
                TASK_ID,
                self.parent_blob,
                proposal,
            )
        )
        existing = {
            "state": "candidate",
            "relation": "candidate",
            "transaction_id": transaction_id,
            "snapshot_id": snapshot_id,
            "projection_id": projection_id,
            "commit": "e" * 40,
        }
        commit = mock.Mock(
            side_effect=AssertionError(
                "existing deterministic work must not be republished"
            )
        )
        self.engine.git.commit_and_push = commit
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=self.retry_parent_remote(),
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                return_value=existing,
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
            )

        self.assertEqual(result["status"], "candidate_remote_advance")
        commit.assert_not_called()
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.pending_terminal_path(pending_id).is_file())
        self.assertFalse(
            (
                self.root
                / "state"
                / "reconciliation-needs-authorization"
                / f"{pending_id}.json"
            ).exists()
        )

    def test_needs_authorization_is_visible_in_legacy_status_and_doctor(
        self,
    ) -> None:
        proposal = validate_v2(
            typed_proposal(
                rationale="Preserved work needs a new authorization decision."
            )
        )
        pending_id = vault_sync._store_pending_reconciliation(
            self.engine,
            proposal,
            expected_current_blob_sha=self.parent_blob,
            observed_current_blob_sha=None,
            ticket_record=None,
        )
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=self.retry_parent_remote(),
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                return_value=None,
            ),
        ):
            moved = vault_sync._recover_pending_reconciliations(
                self.engine,
            )
        self.assertEqual(moved["status"], "requires_new_authorization")

        self.engine.config.update(
            {
                "projection": {"enabled": False, "root": None},
                "matching": {
                    "enabled": False,
                    "auto_provisional": False,
                    "auto_promote_after_consistency_check": False,
                    "prompt_on_ambiguity": True,
                    "policy_version": vault_sync.MATCHING_POLICY_VERSION,
                },
                "updates": {
                    "enabled": False,
                    "auto_install": False,
                    "check_interval_seconds": 24 * 60 * 60,
                },
            }
        )
        expected = {
            "count": 1,
            "pending_ids": [pending_id],
            "next_step": (
                vault_sync.RECONCILIATION_NEEDS_AUTHORIZATION_NEXT_STEP
            ),
        }
        self.assertEqual(
            self.engine.status()["needs_authorization"],
            expected,
        )

        completed = types.SimpleNamespace(
            stdout=b"git version 2.0.0\n",
        )
        with mock.patch.object(
            vault_sync,
            "run_process",
            return_value=completed,
        ):
            doctor = self.engine.doctor(online=False)
        check = next(
            item
            for item in doctor["checks"]
            if item["name"] == "reconciliation_needs_authorization"
        )
        self.assertFalse(check["ok"])
        self.assertIn(pending_id, check["detail"])
        self.assertIn(expected["next_step"], check["detail"])

    def test_durable_authorization_survives_natural_ticket_expiry(
        self,
    ) -> None:
        pending_id, pending_path, proposal, token = (
            self.store_authorized_pending()
        )
        ticket = vault_sync.load_json(self.ticket_path(token))
        expires_at = vault_sync.dt.datetime.fromisoformat(
            str(ticket["expires_at"]).replace("Z", "+00:00")
        )
        future = expires_at + vault_sync.dt.timedelta(days=1)
        real_datetime = vault_sync.dt.datetime

        class FutureDateTime(real_datetime):
            @classmethod
            def now(
                cls,
                tz: vault_sync.dt.tzinfo | None = None,
            ) -> vault_sync.dt.datetime:
                return future if tz is not None else future.replace(tzinfo=None)

        parent = self.retry_parent_remote()
        transaction_id, snapshot_id, projection_id, _digest = (
            vault_sync._reconciliation_identity(
                TASK_ID,
                self.parent_blob,
                proposal,
            )
        )
        published = dataclasses.replace(
            parent,
            commit_sha="c" * 40,
            current_blob_sha="e" * 40,
            current={
                **parent.current,
                "generation": 6,
                "snapshot_id": snapshot_id,
                "published_transaction_id": transaction_id,
            },
            memory_projection={
                **typed_parent_projection(),
                "projection_id": projection_id,
            },
        )
        existing = {
            "state": "published",
            "relation": "current",
            "transaction_id": transaction_id,
            "snapshot_id": snapshot_id,
            "projection_id": projection_id,
            "commit": "c" * 40,
        }
        commit = mock.Mock(return_value="c" * 40)
        self.engine.git.commit_and_push = commit

        with (
            mock.patch.object(vault_sync.dt, "datetime", FutureDateTime),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[parent, published],
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[None, existing],
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Recovered current continuation capsule.",
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
                session_key=self.session_key,
            )

        self.assertGreater(
            FutureDateTime.now(vault_sync.dt.timezone.utc),
            expires_at,
        )
        self.assertEqual(result["status"], "published")
        commit.assert_called_once()
        self.assertFalse(pending_path.exists())
        terminal = vault_sync.load_json(
            self.pending_terminal_path(pending_id)
        )
        self.assertEqual(terminal["result"]["status"], "published")
        self.assertIn(parent.current_path, self.engine.git.written_files)
        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(
            session["base"]["task_current_blob_sha"],
            published.current_blob_sha,
        )

    def test_pending_remote_advance_is_published_only_as_candidate(
        self,
    ) -> None:
        pending_id, pending_path, proposal, _token = (
            self.store_authorized_pending(
                observed_current_blob_sha="f" * 40,
            )
        )
        session_before = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            vault_sync._turn_key(
                self.device,
                self.session_id,
                self.turn_id,
            ),
        )
        prompt_before = prompt_path.read_bytes()
        parent = self.retry_parent_remote()
        transaction_id, snapshot_id, projection_id, _digest = (
            vault_sync._reconciliation_identity(
                TASK_ID,
                self.parent_blob,
                proposal,
            )
        )
        latest = dataclasses.replace(
            parent,
            commit_sha="f" * 40,
            current_blob_sha="f" * 40,
            current={
                **parent.current,
                "generation": 6,
                "snapshot_id": "snap-remote-advance",
                "published_transaction_id": "tx-remote-advance",
            },
        )
        existing = {
            "state": "candidate",
            "relation": "candidate",
            "transaction_id": transaction_id,
            "snapshot_id": snapshot_id,
            "projection_id": projection_id,
            "commit": "d" * 40,
        }
        commit = mock.Mock(return_value="d" * 40)
        self.engine.git.commit_and_push = commit

        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[latest, latest],
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[None, existing],
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Newer remote continuation capsule.",
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
                session_key=self.session_key,
            )

        self.assertEqual(result["status"], "candidate_remote_advance")
        commit.assert_called_once()
        self.assertFalse(pending_path.exists())
        self.assertNotIn(
            parent.current_path,
            self.engine.git.written_files,
        )
        terminal = vault_sync.load_json(
            self.pending_terminal_path(pending_id)
        )
        self.assertEqual(
            terminal["result"]["status"],
            "candidate_remote_advance",
        )
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(session_after["base"], session_before["base"])
        self.assertEqual(
            session_after["base_manifest"],
            session_before["base_manifest"],
        )
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])
        self.assertEqual(prompt_path.read_bytes(), prompt_before)

    def test_pending_published_then_advanced_preserves_local_turn(
        self,
    ) -> None:
        pending_id, pending_path, _proposal, _token = (
            self.store_authorized_pending(
                observed_current_blob_sha="7" * 40,
            )
        )
        session_before = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            vault_sync._turn_key(
                self.device,
                self.session_id,
                self.turn_id,
            ),
        )
        prompt_before = prompt_path.read_bytes()
        (
            git,
            parent,
            latest,
            _immutable_files,
            _transaction_id,
            _snapshot_id,
            _projection_id,
        ) = self.prepared_retry_state(
            existing_state="published",
            relation="historical",
        )
        self.engine.git = git
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=latest,
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Newer remote continuation capsule.",
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
                session_key=self.session_key,
            )

        self.assertEqual(result["status"], "published_then_advanced")
        self.assertEqual(git.commit_calls, 0)
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.pending_terminal_path(pending_id).exists())
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(session_after["base"], session_before["base"])
        self.assertEqual(
            session_after["base_manifest"],
            session_before["base_manifest"],
        )
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])
        self.assertEqual(prompt_path.read_bytes(), prompt_before)

    def test_lost_ack_pending_converges_once_and_terminal_does_not_replay(
        self,
    ) -> None:
        pending_id, pending_path, proposal, token = (
            self.store_authorized_pending()
        )
        (
            git,
            parent,
            latest,
            _immutable_files,
            _transaction_id,
            _snapshot_id,
            _projection_id,
        ) = self.prepared_retry_state(
            existing_state="published",
            relation="current",
        )
        self.engine.git = git
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=latest,
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Recovered current continuation capsule.",
            ),
        ):
            first = vault_sync._recover_pending_reconciliations(
                self.engine,
                session_key=self.session_key,
            )

        self.assertEqual(first["status"], "already_published")
        self.assertEqual(git.commit_calls, 0)
        self.assertFalse(pending_path.exists())
        terminal_path = self.pending_terminal_path(pending_id)
        self.assertTrue(terminal_path.is_file())
        terminal = vault_sync.load_json(terminal_path)
        self.assertEqual(
            terminal["proposal_digest"],
            vault_sync.sha256_jcs(
                {
                    "task_id": TASK_ID,
                    "expected_current_blob_sha": self.parent_blob,
                    "proposal": proposal,
                }
            ),
        )
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(
            session_after["base"]["task_current_blob_sha"],
            latest.current_blob_sha,
        )
        self.assertEqual(
            session_after["base"]["snapshot_id"],
            latest.current["snapshot_id"],
        )
        self.assertFalse(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])

        stop_input = {
            "hook_event_name": "Stop",
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "cwd": str(self.root),
            "last_assistant_message": (
                "Continue after the recovered current reconciliation."
            ),
        }
        with mock.patch.object(
            self.engine,
            "flush_once",
            return_value="done",
        ):
            self.engine.stop(stop_input)
        next_transaction = vault_sync._transaction_id(
            self.device,
            self.session_id,
            self.turn_id,
        )
        next_intent = vault_sync.load_json(
            vault_sync._outbox_path(
                self.root,
                "pending",
                next_transaction,
            )
        )
        self.assertEqual(
            next_intent["base"]["task_current_blob_sha"],
            latest.current_blob_sha,
        )
        self.assertEqual(
            next_intent["base"]["snapshot_id"],
            latest.current["snapshot_id"],
        )
        self.assertNotIn("force_candidate", next_intent)

        retry_path = self.root / "terminal-old-ticket-retry.json"
        retry_path.write_bytes(compact_json_bytes(proposal))
        retry_args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=retry_path,
            session_token=token,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            self.assertRaises(vault_sync.IdentityError),
        ):
            vault_sync.reconcile_memory_command(
                retry_args,
                self.engine,
            )
        self.assertEqual(git.commit_calls, 0)

        terminal_bytes = terminal_path.read_bytes()
        second = vault_sync._recover_pending_reconciliations(
            self.engine,
            session_key=self.session_key,
        )
        self.assertEqual(second["status"], "noop")
        self.assertEqual(git.commit_calls, 0)
        self.assertEqual(
            self.pending_terminal_path(pending_id).read_bytes(),
            terminal_bytes,
        )

    def test_session_identity_mismatch_cannot_block_remote_terminalization(
        self,
    ) -> None:
        pending_id, pending_path, _proposal, _token = (
            self.store_authorized_pending()
        )
        session_path = vault_sync._session_path(
            self.root,
            self.session_key,
        )
        changed_session = vault_sync.load_json(session_path)
        changed_session["binding_id"] = "bnd-locally-rebound-after-push"
        vault_sync._save_session(
            self.root,
            self.session_key,
            changed_session,
        )
        (
            git,
            parent,
            latest,
            _immutable_files,
            _transaction_id,
            _snapshot_id,
            _projection_id,
        ) = self.prepared_retry_state(
            existing_state="published",
            relation="current",
        )
        self.engine.git = git
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=latest,
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Recovered current continuation capsule.",
            ),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
            )

        self.assertEqual(result["status"], "already_published")
        self.assertEqual(git.commit_calls, 0)
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.pending_terminal_path(pending_id).exists())
        self.assertEqual(
            vault_sync.load_json(session_path)["binding_id"],
            "bnd-locally-rebound-after-push",
        )

    def test_corrupt_local_session_cannot_block_historical_terminalization(
        self,
    ) -> None:
        pending_id, pending_path, _proposal, _token = (
            self.store_authorized_pending(
                observed_current_blob_sha="7" * 40,
            )
        )
        session_path = vault_sync._session_path(
            self.root,
            self.session_key,
        )
        session_path.write_bytes(b"{invalid-local-session")
        (
            git,
            parent,
            latest,
            _immutable_files,
            _transaction_id,
            _snapshot_id,
            _projection_id,
        ) = self.prepared_retry_state(
            existing_state="published",
            relation="historical",
        )
        self.engine.git = git
        with (
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                return_value=latest,
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=parent,
            ),
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            result = vault_sync._recover_pending_reconciliations(
                self.engine,
            )

        self.assertEqual(result["status"], "published_then_advanced")
        self.assertEqual(git.commit_calls, 0)
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.pending_terminal_path(pending_id).exists())
        self.assertEqual(
            session_path.read_bytes(),
            b"{invalid-local-session",
        )

    def test_lost_ack_retry_recovers_current_publish_without_duplicate(
        self,
    ) -> None:
        result, _git, session_before, _prompt, _files = (
            self.run_existing_retry(
                existing_state="published",
                relation="current",
            )
        )

        self.assertEqual(result["status"], "already_published")
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(
            session_after["base"]["task_current_blob_sha"],
            result["current_blob_sha"],
        )
        self.assertEqual(
            session_after["base"]["snapshot_id"],
            result["snapshot_id"],
        )
        self.assertNotEqual(
            session_after["base"],
            session_before["base"],
        )
        self.assertEqual(
            session_after["artifact_snapshot"],
            session_before["artifact_snapshot"],
        )
        self.assertFalse(session_after["needs_remote_refresh"])
        self.assertFalse(session_after["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session_after,
        )
        tickets = [
            vault_sync.load_json(path)
            for path in (
                self.root / "state" / "reconciliation-tickets"
            ).glob("*.json")
        ]
        self.assertEqual([ticket["state"] for ticket in tickets], ["consumed"])

    def test_published_then_advanced_retry_preserves_local_base_and_prompt(
        self,
    ) -> None:
        result, _git, session_before, _prompt, _files = (
            self.run_existing_retry(
                existing_state="published",
                relation="historical",
            )
        )

        self.assertEqual(result["status"], "published_then_advanced")
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(session_after["base"], session_before["base"])
        self.assertEqual(
            session_after["base_manifest"],
            session_before["base_manifest"],
        )
        self.assertEqual(
            session_after["artifact_snapshot"],
            session_before["artifact_snapshot"],
        )
        self.assertEqual(
            session_after["continuation_context"],
            session_before["continuation_context"],
        )
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session_after,
        )
        tickets = [
            vault_sync.load_json(path)
            for path in (
                self.root / "state" / "reconciliation-tickets"
            ).glob("*.json")
        ]
        self.assertEqual(
            [ticket["state"] for ticket in tickets],
            ["invalidated"],
        )

    def test_existing_candidate_retry_is_not_duplicated_and_needs_refresh(
        self,
    ) -> None:
        result, _git, session_before, _prompt, _files = (
            self.run_existing_retry(
                existing_state="candidate",
                relation="candidate",
            )
        )

        self.assertEqual(result["status"], "candidate_remote_advance")
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(session_after["base"], session_before["base"])
        self.assertEqual(
            session_after["base_manifest"],
            session_before["base_manifest"],
        )
        self.assertEqual(
            session_after["artifact_snapshot"],
            session_before["artifact_snapshot"],
        )
        self.assertEqual(
            session_after["continuation_context"],
            session_before["continuation_context"],
        )
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session_after,
        )
        tickets = [
            vault_sync.load_json(path)
            for path in (
                self.root / "state" / "reconciliation-tickets"
            ).glob("*.json")
        ]
        self.assertEqual(
            [ticket["state"] for ticket in tickets],
            ["invalidated"],
        )

    def test_existing_recovery_requires_one_exact_atomic_commit(self) -> None:
        def prepared() -> tuple[
            DeterministicRetryGit,
            vault_sync.RemoteTaskState,
            vault_sync.RemoteTaskState,
            str,
            str,
        ]:
            (
                git,
                parent,
                latest,
                immutable_files,
                _transaction_id,
                _snapshot_id,
                _projection_id,
            ) = self.prepared_retry_state(
                existing_state="published",
                relation="current",
            )
            version_path = next(
                path
                for path in immutable_files
                if "/versions/" in path
            )
            projection_path = next(
                path
                for path in immutable_files
                if "/projections/" in path
            )
            return git, parent, latest, version_path, projection_path

        with self.subTest("version_and_projection_different_commits"):
            git, parent, latest, _version_path, projection_path = prepared()
            different_commit = "8" * 40
            raw = git.files[projection_path]
            git.path_history[projection_path] = [
                (different_commit, raw)
            ]
            git.commit_snapshots[
                (different_commit, projection_path)
            ] = raw
            with self.assertRaisesRegex(
                vault_sync.ConflictError,
                "atomically introduced",
            ):
                self.classify_existing_retry(git, parent, latest)

        with self.subTest("transaction_changed_unexpected_path"):
            git, parent, latest, version_path, _projection_path = prepared()
            commit = git.path_commits(version_path)[0]
            git.changed_paths[commit].add("memory/unexpected.json")
            with self.assertRaisesRegex(
                vault_sync.ConflictError,
                "unexpected path",
            ):
                self.classify_existing_retry(git, parent, latest)

        with self.subTest("current_bytes_were_not_introduced_together"):
            git, parent, latest, version_path, _projection_path = prepared()
            commit = git.path_commits(version_path)[0]
            git.commit_snapshots[
                (commit, latest.current_path)
            ] = b'{"different":"CURRENT"}\n'
            with self.assertRaisesRegex(
                vault_sync.ConflictError,
                "atomically introduced",
            ):
                self.classify_existing_retry(git, parent, latest)

    def test_candidate_commit_requires_a_preexisting_remote_advance(
        self,
    ) -> None:
        parent = self.retry_parent_remote()
        current_raw = vault_sync.pretty_json_bytes(parent.current)
        expected = vault_sync.git_blob_sha(current_raw)
        parent = dataclasses.replace(
            parent,
            current_blob_sha=expected,
        )
        proposal = validate_v2(typed_proposal())
        git = DeterministicRetryGit(self.root / "invalid-candidate-worktree")
        with (
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            files, transaction_id, snapshot_id = (
                vault_sync._reconciliation_documents(
                    git,
                    parent,
                    proposal,
                    candidate=True,
                )
            )
        projection_id = vault_sync._reconciliation_identity(
            TASK_ID,
            expected,
            proposal,
        )[2]
        version_path = (
            f"tasks/{TASK_ID}/versions/{snapshot_id}.json"
        )
        projection_path = (
            f"tasks/{TASK_ID}/projections/{projection_id}.json"
        )
        transaction_commit = "6" * 40
        for path in (version_path, projection_path):
            git.files[path] = files[path]
            git.path_history[path] = [
                (transaction_commit, files[path])
            ]
            git.commit_snapshots[
                (transaction_commit, path)
            ] = files[path]
        git.files[parent.current_path] = current_raw
        git.path_history[parent.current_path] = [
            (parent.commit_sha, current_raw)
        ]
        git.commit_snapshots[
            (transaction_commit, parent.current_path)
        ] = current_raw
        git.changed_paths[transaction_commit] = {
            version_path,
            projection_path,
        }
        latest = dataclasses.replace(
            parent,
            task={"task_id": TASK_ID, "status": "active"},
        )

        with (
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
            self.assertRaises(vault_sync.ConflictError),
        ):
            vault_sync._existing_typed_reconciliation(
                git,
                latest,
                TASK_ID,
                expected,
                proposal,
            )

    def test_candidate_with_same_current_is_recoverable_if_task_was_split(
        self,
    ) -> None:
        parent = self.retry_parent_remote()
        current_raw = vault_sync.pretty_json_bytes(parent.current)
        expected = vault_sync.git_blob_sha(current_raw)
        parent = dataclasses.replace(
            parent,
            current_blob_sha=expected,
        )
        proposal = validate_v2(typed_proposal())
        git = DeterministicRetryGit(self.root / "split-candidate-worktree")
        with (
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            files, transaction_id, snapshot_id = (
                vault_sync._reconciliation_documents(
                    git,
                    parent,
                    proposal,
                    candidate=True,
                )
            )
        projection_id = vault_sync._reconciliation_identity(
            TASK_ID,
            expected,
            proposal,
        )[2]
        version_path = (
            f"tasks/{TASK_ID}/versions/{snapshot_id}.json"
        )
        projection_path = (
            f"tasks/{TASK_ID}/projections/{projection_id}.json"
        )
        transaction_commit = "6" * 40
        for path in (version_path, projection_path):
            git.files[path] = files[path]
            git.path_history[path] = [
                (transaction_commit, files[path])
            ]
            git.commit_snapshots[
                (transaction_commit, path)
            ] = files[path]
        git.files[parent.current_path] = current_raw
        git.path_history[parent.current_path] = [
            (parent.commit_sha, current_raw)
        ]
        git.commit_snapshots[
            (transaction_commit, parent.current_path)
        ] = current_raw
        git.commit_snapshots[
            (transaction_commit, parent.task_path)
        ] = vault_sync.pretty_json_bytes(
            {
                "schema_version": "task/v1",
                "task_id": TASK_ID,
                "status": "split",
            }
        )
        git.changed_paths[transaction_commit] = {
            version_path,
            projection_path,
        }
        latest = dataclasses.replace(
            parent,
            task={"task_id": TASK_ID, "status": "split"},
        )
        with (
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            recovered = vault_sync._existing_typed_reconciliation(
                git,
                latest,
                TASK_ID,
                expected,
                proposal,
            )

        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertEqual(recovered["state"], "candidate")
        self.assertEqual(recovered["relation"], "candidate")
        self.assertEqual(
            recovered["transaction_id"],
            transaction_id,
        )

    def test_existing_published_result_is_readable_after_task_archival(
        self,
    ) -> None:
        result, _git, _session, _prompt, _files = (
            self.run_existing_retry(
                existing_state="published",
                relation="current",
                task_status="archived",
            )
        )
        self.assertEqual(result["status"], "already_published")

    def test_existing_candidate_is_readable_after_task_split(
        self,
    ) -> None:
        result, _git, _session, _prompt, _files = (
            self.run_existing_retry(
                existing_state="candidate",
                relation="candidate",
                task_status="split",
            )
        )
        self.assertEqual(result["status"], "candidate_remote_advance")

    def test_successful_publish_followed_by_immediate_advance_is_recovered(
        self,
    ) -> None:
        token = self.token_from(self.submit_prompt())
        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            vault_sync._turn_key(
                self.device,
                self.session_id,
                self.turn_id,
            ),
        )
        prompt_before = prompt_path.read_bytes()
        session_before = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        proposal_path = self.root / "post-push-advance.json"
        proposal_path.write_bytes(compact_json_bytes(typed_proposal()))
        transaction_id = "memrec-post-push-race"
        snapshot_id = "snap-memrec-post-push-race"
        projection_id = "proj-memrec-post-push-race"
        initial = types.SimpleNamespace(
            current_blob_sha=self.parent_blob,
            current={"state": "active", "task_id": TASK_ID},
            task={"status": "active"},
        )
        advanced = types.SimpleNamespace(
            current_blob_sha="d" * 40,
            current={
                "state": "active",
                "task_id": TASK_ID,
                "snapshot_id": "snap-after-post-push-race",
                "published_transaction_id": "tx-after-post-push-race",
            },
            task={"status": "active"},
        )
        existing = {
            "state": "published",
            "relation": "historical",
            "transaction_id": transaction_id,
            "snapshot_id": snapshot_id,
            "projection_id": projection_id,
            "commit": "e" * 40,
        }
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[initial, advanced],
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[None, existing],
            ),
            mock.patch.object(
                vault_sync,
                "_reconciliation_documents",
                return_value=(
                    {
                        f"tasks/{TASK_ID}/versions/{snapshot_id}.json": b"{}",
                        f"tasks/{TASK_ID}/CURRENT.json": b"{}",
                    },
                    transaction_id,
                    snapshot_id,
                ),
            ),
        ):
            result = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )

        self.assertEqual(result["status"], "published_then_advanced")
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(session_after["base"], session_before["base"])
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])
        self.assertEqual(prompt_path.read_bytes(), prompt_before)
        tickets = [
            vault_sync.load_json(path)
            for path in (
                self.root / "state" / "reconciliation-tickets"
            ).glob("*.json")
        ]
        self.assertEqual(
            [ticket["state"] for ticket in tickets],
            ["invalidated"],
        )

    def test_successful_candidate_survives_another_immediate_advance(
        self,
    ) -> None:
        token = self.token_from(self.submit_prompt())
        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            vault_sync._turn_key(
                self.device,
                self.session_id,
                self.turn_id,
            ),
        )
        prompt_before = prompt_path.read_bytes()
        session_before = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        proposal_path = self.root / "candidate-post-push-advance.json"
        proposal_path.write_bytes(compact_json_bytes(typed_proposal()))
        first_advance = types.SimpleNamespace(
            current_blob_sha="d" * 40,
            current={"state": "active", "task_id": TASK_ID},
            task={"status": "active"},
        )
        second_advance = types.SimpleNamespace(
            current_blob_sha="e" * 40,
            current={
                "state": "active",
                "task_id": TASK_ID,
                "snapshot_id": "snap-second-advance",
                "published_transaction_id": "tx-second-advance",
            },
            task={"status": "active"},
        )
        historical = types.SimpleNamespace(
            current_blob_sha=self.parent_blob,
        )
        existing = {
            "state": "candidate",
            "relation": "candidate",
            "transaction_id": "memrec-candidate-race",
            "snapshot_id": "snap-memrec-candidate-race",
            "projection_id": "proj-memrec-candidate-race",
            "commit": "f" * 40,
        }
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[first_advance, second_advance],
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[None, existing],
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=historical,
            ),
            mock.patch.object(
                vault_sync,
                "_reconciliation_documents",
                return_value=(
                    {
                        f"tasks/{TASK_ID}/versions/"
                        "snap-memrec-candidate-race.json": b"{}"
                    },
                    "memrec-candidate-race",
                    "snap-memrec-candidate-race",
                ),
            ),
        ):
            result = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )

        self.assertEqual(result["status"], "candidate_remote_advance")
        self.assertEqual(
            result["current_blob_sha"],
            second_advance.current_blob_sha,
        )
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(session_after["base"], session_before["base"])
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])
        self.assertEqual(prompt_path.read_bytes(), prompt_before)

    def test_rejected_push_with_remote_advance_auto_publishes_candidate(
        self,
    ) -> None:
        token = self.token_from(self.submit_prompt())
        proposal_path = self.root / "push-conflict-auto-candidate.json"
        proposal_path.write_bytes(compact_json_bytes(typed_proposal()))
        initial = types.SimpleNamespace(
            current_blob_sha=self.parent_blob,
            current={"state": "active", "task_id": TASK_ID},
            task={"status": "active"},
        )
        advanced = types.SimpleNamespace(
            current_blob_sha="d" * 40,
            current={
                "state": "active",
                "task_id": TASK_ID,
                "snapshot_id": "snap-remote-winner",
                "published_transaction_id": "tx-remote-winner",
            },
            task={"status": "active"},
        )
        historical = types.SimpleNamespace(
            current_blob_sha=self.parent_blob,
        )
        transaction_id = "memrec-auto-candidate"
        snapshot_id = "snap-memrec-auto-candidate"
        existing = {
            "state": "candidate",
            "relation": "candidate",
            "transaction_id": transaction_id,
            "snapshot_id": snapshot_id,
            "projection_id": "proj-memrec-auto-candidate",
            "commit": "f" * 40,
        }
        self.git.commit_and_push = mock.Mock(
            side_effect=[
                vault_sync.ConflictError("simulated push race"),
                "f" * 40,
            ]
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        documents = mock.Mock(
            side_effect=[
                (
                    {
                        f"tasks/{TASK_ID}/versions/{snapshot_id}.json": b"{}",
                        f"tasks/{TASK_ID}/CURRENT.json": b"{}",
                    },
                    transaction_id,
                    snapshot_id,
                ),
                (
                    {
                        f"tasks/{TASK_ID}/versions/{snapshot_id}.json": b"{}"
                    },
                    transaction_id,
                    snapshot_id,
                ),
            ]
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[initial, advanced, advanced],
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[None, None, None, existing],
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=historical,
            ),
            mock.patch.object(
                vault_sync,
                "_reconciliation_documents",
                documents,
            ),
        ):
            result = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )

        self.assertEqual(result["status"], "candidate_remote_advance")
        self.assertEqual(
            result["current_blob_sha"],
            advanced.current_blob_sha,
        )
        self.assertEqual(self.git.commit_and_push.call_count, 2)
        self.assertEqual(
            {
                call.args[3]
                for call in self.git.commit_and_push.call_args_list
            },
            {transaction_id},
        )
        self.assertFalse(
            (self.root / "state" / "pending-reconciliations").exists()
        )
        self.assertTrue(documents.call_args_list[1].kwargs["candidate"])
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertTrue(session_after["needs_remote_refresh"])
        self.assertTrue(session_after["pending_context_injection"])

    def test_successful_reconcile_refreshes_session_before_next_stop(self) -> None:
        prompt_output = self.submit_prompt()
        token = self.token_from(prompt_output)
        turn_key = vault_sync._turn_key(
            self.device,
            self.session_id,
            self.turn_id,
        )
        prompt_path = vault_sync._prompt_path(
            self.root,
            self.session_key,
            turn_key,
        )
        staged_prompt_before = prompt_path.read_bytes()
        proposal_path = self.root / "typed-patch.json"
        proposal_path.write_bytes(compact_json_bytes(typed_proposal()))
        transaction_id = "tx-reconciliation-session-success"
        snapshot_id = "snap-reconciliation-session-success"
        initial_remote = types.SimpleNamespace(
            current_blob_sha=self.parent_blob,
            current={"state": "active"},
            task={"status": "active"},
        )
        verified_remote = types.SimpleNamespace(
            commit_sha="e" * 40,
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
            current_blob_sha="f" * 40,
            current={
                "task_id": TASK_ID,
                "state": "active",
                "generation": 6,
                "snapshot_id": snapshot_id,
                "manifest_path": (
                    f"tasks/{TASK_ID}/versions/{snapshot_id}.json"
                ),
                "published_transaction_id": transaction_id,
            },
            manifest_path=f"tasks/{TASK_ID}/versions/{snapshot_id}.json",
            manifest={
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": snapshot_id,
                "memory_projection": {
                    "projection_id": "proj-reconciliation-session-success",
                    "path": (
                        f"tasks/{TASK_ID}/projections/"
                        "proj-reconciliation-session-success.json"
                    ),
                    "content_sha256": "3" * 64,
                },
            },
            memory_projection={
                "projection_id": "proj-reconciliation-session-success",
                "unprojected_deltas": [],
            },
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        generated_files = {
            f"tasks/{TASK_ID}/versions/{snapshot_id}.json": b"{}",
            f"tasks/{TASK_ID}/CURRENT.json": b"{}",
        }

        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[initial_remote, verified_remote],
            ),
            mock.patch.object(
                vault_sync,
                "_reconciliation_documents",
                return_value=(
                    generated_files,
                    transaction_id,
                    snapshot_id,
                ),
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[
                    None,
                    {
                        "state": "published",
                        "relation": "current",
                        "transaction_id": transaction_id,
                        "snapshot_id": snapshot_id,
                        "projection_id": (
                            "proj-reconciliation-session-success"
                        ),
                        "commit": "e" * 40,
                    },
                ],
            ),
            mock.patch.object(
                vault_sync,
                "_continuation_context",
                return_value="Refreshed continuation capsule.",
            ),
        ):
            result = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )

        self.assertEqual(result["status"], "published")
        session_after = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertEqual(
            session_after["base"]["task_current_blob_sha"],
            verified_remote.current_blob_sha,
        )
        self.assertEqual(
            session_after["base"]["published_transaction_id"],
            transaction_id,
        )
        self.assertEqual(
            session_after["artifact_snapshot"],
            self.artifact_snapshot,
        )
        self.assertFalse(session_after["pending_context_injection"])
        self.assertFalse(session_after["needs_remote_refresh"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session_after,
        )
        self.assertEqual(prompt_path.read_bytes(), staged_prompt_before)
        self.assertEqual(
            vault_sync.load_json(self.ticket_path(token))["state"],
            "consumed",
        )

        stop_input = {
            "hook_event_name": "Stop",
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "cwd": str(self.root),
            "last_assistant_message": (
                "The typed reconciliation completed; continue from it."
            ),
        }
        with mock.patch.object(
            self.engine,
            "flush_once",
            return_value="done",
        ) as flush:
            stop_result = self.engine.stop(stop_input)

        transaction = vault_sync._transaction_id(
            self.device,
            self.session_id,
            self.turn_id,
        )
        pending = vault_sync._outbox_path(
            self.root,
            "pending",
            transaction,
        )
        intent = vault_sync.load_json(pending)
        self.assertEqual(
            intent["base"]["task_current_blob_sha"],
            verified_remote.current_blob_sha,
        )
        self.assertNotIn("force_candidate", intent)
        flush.assert_called_once_with(
            transaction_id=transaction,
            already_locked=True,
        )
        self.assertEqual(stop_result, {"continue": True})

    def test_remote_advance_candidate_invalidates_ticket_and_requests_refresh(
        self,
    ) -> None:
        token = self.token_from(self.submit_prompt())
        proposal_path = self.root / "candidate-patch.json"
        proposal_path.write_bytes(compact_json_bytes(typed_proposal()))
        latest = types.SimpleNamespace(
            current_blob_sha="d" * 40,
            current={
                "task_id": TASK_ID,
                "snapshot_id": "snap-newer-remote",
                "state": "active",
            },
            task={"status": "active"},
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
        )
        historical = types.SimpleNamespace(
            current_blob_sha=self.parent_blob,
        )
        self.git.show_json = mock.Mock(return_value={"state": "candidate"})
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=self.parent_blob,
            proposal_file=proposal_path,
            session_token=token,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"CODEX_THREAD_ID": self.session_id},
                clear=False,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[latest, latest],
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=historical,
            ),
            mock.patch.object(
                vault_sync,
                "_reconciliation_documents",
                return_value=(
                    {
                        f"tasks/{TASK_ID}/versions/"
                        "snap-session-candidate.json": b"{}"
                    },
                    "tx-session-candidate",
                    "snap-session-candidate",
                ),
            ),
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[
                    None,
                    {
                        "state": "candidate",
                        "relation": "candidate",
                        "transaction_id": "tx-session-candidate",
                        "snapshot_id": "snap-session-candidate",
                        "projection_id": "proj-session-candidate",
                        "commit": "c" * 40,
                    },
                ],
            ),
        ):
            result = vault_sync.reconcile_memory_command(
                args,
                self.engine,
            )

        self.assertEqual(result["status"], "candidate_remote_advance")
        self.assertEqual(
            result["current_blob_sha"],
            latest.current_blob_sha,
        )
        ticket = vault_sync.load_json(self.ticket_path(token))
        self.assertEqual(ticket["state"], "invalidated")
        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertTrue(session["needs_remote_refresh"])
        self.assertTrue(session["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            session,
        )

    def test_known_stale_session_cannot_issue_ticket_while_work_is_pending(
        self,
    ) -> None:
        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        session["needs_remote_refresh"] = True
        session["pending_context_injection"] = True
        vault_sync._save_session(
            self.root,
            self.session_key,
            session,
        )
        old_turn = "turn-pending-before-refresh"
        old_turn_key = vault_sync._turn_key(
            self.device,
            self.session_id,
            old_turn,
        )
        vault_sync.atomic_write_json(
            vault_sync._prompt_path(
                self.root,
                self.session_key,
                old_turn_key,
            ),
            {
                "schema_version": "memory-vault-sync-prompt/v1",
                "turn_key": old_turn_key,
                "task_id": TASK_ID,
                "prompt": "Unpublished local work.",
                "created_at": "2026-07-29T00:00:00Z",
            },
        )

        with mock.patch.object(
            vault_sync,
            "load_remote_task",
            return_value=types.SimpleNamespace(
                current_blob_sha="d" * 40,
            ),
        ):
            output = self.engine.user_prompt_submit(
                self.prompt_input(
                    turn_id="turn-after-candidate-before-refresh",
                )
            )

        self.assertIsNone(self.context_from(output))
        self.assertIn("pending local work", output["systemMessage"])
        refreshed = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertTrue(refreshed["needs_remote_refresh"])
        self.assertTrue(refreshed["pending_context_injection"])
        self.assertNotIn(
            "active_reconciliation_token_sha256",
            refreshed,
        )
        ticket_root = self.root / "state" / "reconciliation-tickets"
        if ticket_root.exists():
            self.assertFalse(
                any(
                    vault_sync.load_json(path).get("state") == "issued"
                    for path in ticket_root.glob("*.json")
                )
            )


class WorkspaceRemoteAdvanceGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.workspace = self.workspace.resolve()
        self.session_id = "workspace-session-remote-advance"
        self.turn_id = "turn-after-remote-advance"
        self.binding_id = "bnd-workspace-remote-advance"
        self.lineage_id = "lineage-workspace-remote-advance"
        self.device = vault_sync._device_state(self.root)
        self.session_key = vault_sync._session_key(
            self.device,
            self.session_id,
        )
        self.identity = vault_sync.PortableIdentity(
            path=self.workspace / ".vault_identity.yaml",
            workspace_root=self.workspace,
            binding_id=self.binding_id,
            task_id=TASK_ID,
            lineage_id=self.lineage_id,
            base={},
        )
        self.engine = object.__new__(vault_sync.SyncEngine)
        self.engine.config = {
            "_test_mode": True,
            "enabled": True,
            "sync": {
                "memory_network_enabled": False,
                "legacy_task_handoff_enabled": True,
                "startup_pull": True,
                "conversation_backup": True,
                "stop_publish": True,
            },
            "privacy": {"allowed_roots": [str(self.workspace)]},
        }
        self.engine.provider_pins = vault_sync._provider_transaction_pins(
            vault_sync.default_config()
        )
        self.engine.data_dir = self.root
        self.engine.git = types.SimpleNamespace()
        self.engine.drive = None
        self.engine.lock_path = self.root / "locks" / "sync.lock"
        vault_sync._save_session(
            self.root,
            self.session_key,
            {
                "schema_version": vault_sync.SESSION_SCHEMA,
                "continuation_context_contract": (
                    vault_sync.CONTINUATION_CONTEXT_CONTRACT
                ),
                "identity_kind": "workspace",
                "task_id": TASK_ID,
                "binding_id": self.binding_id,
                "source_id": "src-workspace-remote-advance",
                "source_external_key_sha256": vault_sync._codex_source_key(
                    self.session_id
                ),
                "workspace_lineage_id": self.lineage_id,
                "workspace_instance_id": "wsi-workspace-remote-advance",
                "workspace_root": str(self.workspace),
                "base": {
                    "remote_commit_sha": "1" * 40,
                    "task_current_path": f"tasks/{TASK_ID}/CURRENT.json",
                    "task_current_blob_sha": "2" * 40,
                    "task_generation": 5,
                    "snapshot_id": "snap-before-remote-advance",
                    "manifest_path": (
                        f"tasks/{TASK_ID}/versions/"
                        "snap-before-remote-advance.json"
                    ),
                    "published_transaction_id": (
                        "tx-before-remote-advance"
                    ),
                },
                "base_manifest": {
                    "schema_version": "task-version/v1",
                    "task_id": TASK_ID,
                    "snapshot_id": "snap-before-remote-advance",
                },
                "artifact_snapshot": {
                    "draft.docx": [1, 2, 3, 4, "3" * 64]
                },
                "continuation_context": "Old verified capsule.",
                "reconciliation_required": False,
                "pending_context_injection": False,
                "needs_remote_refresh": False,
                "started_at": "2026-07-29T00:00:00Z",
            },
        )

    def test_remote_advance_blocks_stale_artifact_promotion_but_queues_chat(
        self,
    ) -> None:
        remote = types.SimpleNamespace(
            commit_sha="4" * 40,
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
            current_blob_sha="5" * 40,
            current={
                "generation": 6,
                "snapshot_id": "snap-after-remote-advance",
                "manifest_path": (
                    f"tasks/{TASK_ID}/versions/"
                    "snap-after-remote-advance.json"
                ),
                "published_transaction_id": "tx-after-remote-advance",
            },
            manifest_path=(
                f"tasks/{TASK_ID}/versions/"
                "snap-after-remote-advance.json"
            ),
            manifest={
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": "snap-after-remote-advance",
            },
            memory_projection=None,
        )
        with mock.patch.object(
            vault_sync,
            "_continuation_context",
            return_value="New verified capsule.",
        ):
            self.engine._refresh_session_after_publish(
                {
                    "session_key": self.session_key,
                    "task_id": TASK_ID,
                    "binding_id": self.binding_id,
                },
                remote,
                pending_injection=True,
                remote_advance=True,
            )
        session = vault_sync.load_json(
            vault_sync._session_path(self.root, self.session_key)
        )
        self.assertTrue(
            session["artifact_publication_blocked_due_remote_advance"]
        )
        self.assertTrue(session["pending_context_injection"])
        self.assertEqual(
            session["base"]["task_current_blob_sha"],
            remote.current_blob_sha,
        )

        turn_key = vault_sync._turn_key(
            self.device,
            self.session_id,
            self.turn_id,
        )
        vault_sync.atomic_write_json(
            vault_sync._prompt_path(
                self.root,
                self.session_key,
                turn_key,
            ),
            {
                "schema_version": "memory-vault-sync-prompt/v1",
                "turn_key": turn_key,
                "task_id": TASK_ID,
                "prompt": "Continue the conversation without stale files.",
                "created_at": "2026-07-29T00:00:00Z",
            },
        )
        hook_input = {
            "hook_event_name": "Stop",
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "cwd": str(self.workspace),
            "last_assistant_message": "Conversation-only continuation.",
        }
        with (
            mock.patch.object(
                self.engine,
                "_identity_from_session_input",
                return_value=self.identity,
            ),
            mock.patch.object(
                self.engine,
                "_artifact_publication_plan",
                return_value=(True, ["draft.docx"]),
            ) as publication_plan,
            mock.patch.object(
                self.engine,
                "_spool_artifacts",
            ) as spool,
        ):
            transaction, state = self.engine._queue_stop(hook_input)

        self.assertEqual(state, "pending")
        publication_plan.assert_called_once()
        spool.assert_not_called()
        intent = vault_sync.load_json(
            vault_sync._outbox_path(
                self.root,
                "pending",
                transaction,
            )
        )
        self.assertEqual(intent["artifacts"], [])
        self.assertEqual(
            intent["base"]["task_current_blob_sha"],
            remote.current_blob_sha,
        )
        self.assertEqual(
            intent["conversation_delta"]["prompt"],
            "Continue the conversation without stale files.",
        )


class CandidateAndOfflineGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def proposal_path(self) -> Path:
        path = self.root / "proposal.json"
        path.write_bytes(compact_json_bytes(typed_proposal()))
        return path

    def test_candidate_documents_never_include_current_pointer(self) -> None:
        parent = typed_parent_projection()
        evidence_sources = [
            {
                "source_id": SOURCE_ID,
                "revision_id": REVISION_ID,
                "source_sequence": 1,
                "binding_id": "bnd-typed-test",
                "content_path": (
                    f"sources/{SOURCE_ID}/revisions/{REVISION_ID}.json"
                ),
                "content_sha256": "1" * 64,
            }
        ]
        remote = vault_sync.RemoteTaskState(
            commit_sha="a" * 40,
            task_path=f"tasks/{TASK_ID}/TASK.json",
            task={"task_id": TASK_ID},
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
            current_blob_sha="b" * 40,
            current={
                "schema_version": "task-current/v1",
                "task_id": TASK_ID,
                "generation": 5,
                "state": "active",
                "snapshot_id": "snap-parent-typed-test",
                "manifest_path": (
                    f"tasks/{TASK_ID}/versions/snap-parent-typed-test.json"
                ),
                "continuation_readiness": "partial",
                "published_transaction_id": "tx-parent-typed-test",
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            },
            manifest_path=(
                f"tasks/{TASK_ID}/versions/snap-parent-typed-test.json"
            ),
            manifest={
                "schema_version": "task-version/v1",
                "task_id": TASK_ID,
                "snapshot_id": "snap-parent-typed-test",
                "generation": 5,
                "state": "published",
                "transaction_id": "tx-parent-typed-test",
                "change_type": "content_revision",
                "continuation_readiness": "partial",
                "parents": [],
                "artifacts": [],
                "evidence_sources": evidence_sources,
            },
            memory_projection_path=(
                f"tasks/{TASK_ID}/projections/"
                "proj-typed-reconciliation-parent.json"
            ),
            memory_projection=parent,
        )
        proposal = validate_v2(typed_proposal())

        with (
            mock.patch.object(
                vault_sync,
                "_validate_task_memory_projection_structure",
            ),
            mock.patch.object(vault_sync, "_validate_task_version"),
            mock.patch.object(vault_sync, "_validate_task_current"),
            mock.patch.object(vault_sync, "_validate_projection_semantics"),
        ):
            files, _transaction_id, snapshot_id = (
                vault_sync._reconciliation_documents(
                    types.SimpleNamespace(),
                    remote,
                    proposal,
                    candidate=True,
                )
            )

        self.assertNotIn(remote.current_path, files)
        manifest_path = f"tasks/{TASK_ID}/versions/{snapshot_id}.json"
        manifest = json.loads(files[manifest_path].decode("utf-8"))
        self.assertEqual(manifest["state"], "candidate")
        projection_path = manifest["memory_projection"]["path"]
        projection = json.loads(files[projection_path].decode("utf-8"))
        self.assertEqual(
            projection["reconciliation_receipts"][0]["outcome"],
            "evidence_only_no_semantic_change",
        )

    def test_remote_advance_routes_to_candidate_without_moving_current(self) -> None:
        expected = "1" * 40
        latest = types.SimpleNamespace(
            current_blob_sha="2" * 40,
            current={
                "task_id": TASK_ID,
                "snapshot_id": "snap-latest",
                "state": "active",
            },
            task={"status": "active"},
            current_path=f"tasks/{TASK_ID}/CURRENT.json",
        )
        historical = types.SimpleNamespace(current_blob_sha=expected)
        fake_git = mock.Mock()
        fake_git.create_worktree.return_value = contextlib.nullcontext(
            self.root / "worktree"
        )
        fake_git.commit_and_push.return_value = "3" * 40
        fake_git.show_json.return_value = {"state": "candidate"}
        engine = types.SimpleNamespace(
            lock_path=self.root / "candidate.lock",
            git=fake_git,
            _validate_worktree=mock.Mock(),
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha=expected,
            proposal_file=self.proposal_path(),
            session_token="A" * 43,
        )
        candidate_files = {
            f"tasks/{TASK_ID}/versions/snap-candidate-test.json": b"{}"
        }
        ticket_record = (
            self.root / "candidate-ticket.json",
            {"schema_version": "memory-vault-reconciliation-ticket/v1"},
            {},
        )
        with (
            mock.patch.object(
                vault_sync,
                "_verified_reconciliation_ticket",
                return_value=ticket_record,
            ),
            mock.patch.object(
                vault_sync,
                "load_remote_task_by_id",
                side_effect=[latest, latest],
            ),
            mock.patch.object(
                vault_sync,
                "_historical_task_state_by_current_blob",
                return_value=historical,
            ) as historical_lookup,
            mock.patch.object(
                vault_sync,
                "_reconciliation_documents",
                return_value=(
                    candidate_files,
                    "tx-candidate-test",
                    "snap-candidate-test",
                ),
            ) as documents,
            mock.patch.object(
                vault_sync,
                "_existing_typed_reconciliation",
                side_effect=[
                    None,
                    {
                        "state": "candidate",
                        "relation": "candidate",
                        "transaction_id": "tx-candidate-test",
                        "snapshot_id": "snap-candidate-test",
                        "projection_id": "proj-candidate-test",
                        "commit": "3" * 40,
                    },
                ],
            ),
            mock.patch.object(
                vault_sync,
                "_finish_reconciliation_ticket",
            ) as finish_ticket,
        ):
            result = vault_sync.reconcile_memory_command(args, engine)

        self.assertEqual(result["status"], "candidate_remote_advance")
        historical_lookup.assert_called_once_with(fake_git, latest, expected)
        self.assertTrue(documents.call_args.kwargs["candidate"])
        self.assertNotIn(latest.current_path, candidate_files)
        self.assertEqual(
            finish_ticket.call_args.kwargs["state"],
            "invalidated",
        )

    def test_offline_reconciliation_performs_no_write(self) -> None:
        class OfflineGit:
            def __init__(self) -> None:
                self.write_attempts = 0

            def ensure(self) -> None:
                raise vault_sync.OfflineError("offline test")

            def create_worktree(self) -> contextlib.AbstractContextManager[Path]:
                self.write_attempts += 1
                return contextlib.nullcontext(self.root)

        git = OfflineGit()
        engine = types.SimpleNamespace(
            lock_path=self.root / "offline.lock",
            git=git,
        )
        args = argparse.Namespace(
            task_id=TASK_ID,
            expected_current_blob_sha="1" * 40,
            proposal_file=self.proposal_path(),
            session_token="A" * 43,
        )

        with (
            mock.patch.object(
                vault_sync,
                "_verified_reconciliation_ticket",
                return_value=(
                    self.root / "offline-ticket.json",
                    {},
                    {},
                ),
            ),
            self.assertRaises(vault_sync.OfflineError),
        ):
            vault_sync.reconcile_memory_command(args, engine)
        self.assertEqual(git.write_attempts, 0)


if __name__ == "__main__":
    unittest.main()
