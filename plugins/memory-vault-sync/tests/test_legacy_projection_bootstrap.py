from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest import mock
from typing import Any, Mapping


TESTS_ROOT = Path(__file__).resolve().parent
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

from test_vault_sync import VaultFixture, run, vault_sync, write_json


class LegacyProjectionBootstrapAcceptanceTests(unittest.TestCase):
    """Acceptance boundary for upgrading an exact-bound legacy task."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vault-legacy-projection-bootstrap-"
        )
        self.root = Path(self.temporary.name)
        self.previous_testing = os.environ.get("MEMORY_VAULT_SYNC_TESTING")
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.fixture = VaultFixture(self.root)
        self.legacy_artifact = self._install_null_projection_legacy_current()

    def tearDown(self) -> None:
        if self.previous_testing is None:
            os.environ.pop("MEMORY_VAULT_SYNC_TESTING", None)
        else:
            os.environ["MEMORY_VAULT_SYNC_TESTING"] = self.previous_testing
        self.temporary.cleanup()

    def _install_null_projection_legacy_current(self) -> Mapping[str, Any]:
        """Create an ordinary legacy successor whose projection is explicit null."""

        clone = self.fixture.clone_remote("install-null-projection")
        run(["git", "config", "user.name", "Legacy fixture"], clone)
        run(["git", "config", "user.email", "legacy@localhost"], clone)
        parent_commit = run(["git", "rev-parse", "HEAD"], clone)
        current_path = clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
        previous_current = json.loads(current_path.read_text(encoding="utf-8"))
        previous_manifest = json.loads(
            (clone / previous_current["manifest_path"]).read_text(
                encoding="utf-8"
            )
        )
        artifact = {
            "artifact_id": "artifact-legacy-manuscript",
            "role": "manuscript",
            "logical_path": "workspace/legacy/manuscript.docx",
            "display_name": "legacy manuscript.docx",
            "storage_mode": "full",
            "sha256": "d" * 64,
            "size": 321,
            "mime_type": (
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
            "drive_file_id": "legacy-file-object",
            "drive_parent_id": "private-object-root",
        }
        snapshot_id = "snap-legacy-null-projection"
        transaction_id = "tx-legacy-null-projection"
        manifest_path = (
            f"tasks/{self.fixture.task_id}/versions/{snapshot_id}.json"
        )
        manifest = {
            **previous_manifest,
            "snapshot_id": snapshot_id,
            "generation": int(previous_current["generation"]) + 1,
            "parents": [
                {
                    "kind": "version_snapshot",
                    "snapshot_id": previous_current["snapshot_id"],
                    "commit": parent_commit,
                    "path": previous_current["manifest_path"],
                }
            ],
            "state": "published",
            "change_type": "metadata_import",
            "transaction_id": transaction_id,
            "continuation_readiness": "partial",
            "artifacts": [artifact],
            "memory_projection": None,
        }
        current = {
            **previous_current,
            "generation": manifest["generation"],
            "snapshot_id": snapshot_id,
            "manifest_path": manifest_path,
            "continuation_readiness": "partial",
            "published_transaction_id": transaction_id,
        }
        write_json(clone / manifest_path, manifest)
        write_json(current_path, current)
        run(
            [
                "git",
                "add",
                "--",
                manifest_path,
                f"tasks/{self.fixture.task_id}/CURRENT.json",
            ],
            clone,
        )
        run(["git", "commit", "-m", "install null projection legacy current"], clone)
        run(["git", "push", "origin", "main"], clone)
        return artifact

    def _publish_exact_source_turn(self) -> tuple[Path, Mapping[str, Any]]:
        engine = self.fixture.engine()
        with mock.patch.object(
            engine,
            "_drive",
            side_effect=AssertionError(
                "conversation-only legacy projection bootstrap must not access Drive"
            ),
        ):
            engine.session_start(
                self.fixture.session_input(
                    session=self.fixture.source_session_id,
                    workspace=self.fixture.projectless,
                )
            )
            engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session=self.fixture.source_session_id,
                    turn="legacy-bootstrap-turn",
                    prompt="继续这个已精确绑定的旧任务，并保留本轮原始依据。",
                    workspace=self.fixture.projectless,
                )
            )
            stopped = engine.stop(
                self.fixture.stop_input(
                    session=self.fixture.source_session_id,
                    turn="legacy-bootstrap-turn",
                    assistant="本轮证据已经保存；下一步建立结构化接续状态。",
                    workspace=self.fixture.projectless,
                )
            )
        self.assertNotIn("systemMessage", stopped)
        clone = self.fixture.clone_remote("inspect-legacy-evidence")
        current = self._load_current(clone)
        return clone, current

    def _load_current(self, clone: Path) -> Mapping[str, Any]:
        return json.loads(
            (
                clone
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )

    def _load_manifest(
        self, clone: Path, current: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return json.loads(
            (clone / str(current["manifest_path"])).read_text(
                encoding="utf-8"
            )
        )

    def _bootstrap_proposal(
        self,
        clone: Path,
        manifest: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        reference = manifest["evidence_sources"][-1]
        selector = {
            "source_id": reference["source_id"],
            "revision_id": reference["revision_id"],
            "message_ordinals": [0],
        }
        return {
            "schema_version": "memory-vault-projection-bootstrap-patch/v1",
            "task_id": self.fixture.task_id,
            "operations": [
                {
                    "operation_id": "bootstrap-current-goal",
                    "op": "upsert",
                    "kind": "current_goal",
                    "id": "current_goal",
                    "expect_absent": True,
                    "value": {
                        "status": "active",
                        "statement": (
                            "继续这个已精确绑定的旧任务，并建立可追溯的结构化接续状态。"
                        ),
                    },
                    "evidence": [selector],
                },
                {
                    "operation_id": "bootstrap-scope",
                    "op": "upsert",
                    "kind": "scope_boundary",
                    "id": "scope-exact-bound-task",
                    "expect_absent": True,
                    "value": {
                        "direction": "in_scope",
                        "boundary": {
                            "boundary_id": "scope-exact-bound-task",
                            "statement": "只接续当前已验证绑定的语义任务。",
                        },
                    },
                    "evidence": [selector],
                },
                {
                    "operation_id": "bootstrap-evidence-preservation",
                    "op": "upsert",
                    "kind": "effective_claim",
                    "id": "claim-preserve-original-evidence",
                    "expect_absent": True,
                    "value": {
                        "claim_id": "claim-preserve-original-evidence",
                        "claim_key": "original-evidence-preservation",
                        "kind": "constraint",
                        "statement": "原始依据必须保留，结构化状态不能替代它。",
                        "rationale": {
                            "status": "not_recovered",
                            "gap_id": "gap-preservation-rationale",
                        },
                        "settled": True,
                        "superseded_claim_ids": [],
                        "reask_policy": "reask_only_on_blocking_conflict",
                    },
                    "evidence": [selector],
                },
                {
                    "operation_id": "bootstrap-rationale-gap",
                    "op": "upsert",
                    "kind": "known_gap",
                    "id": "gap-preservation-rationale",
                    "expect_absent": True,
                    "value": {
                        "gap_id": "gap-preservation-rationale",
                        "area": "rationale",
                        "statement": "现有已验证消息没有说明该约束的完整理由。",
                        "trace_status": "partial",
                    },
                    "evidence": [selector],
                },
                {
                    "operation_id": "bootstrap-progress",
                    "op": "upsert",
                    "kind": "in_progress_item",
                    "id": "progress-structure-handoff",
                    "expect_absent": True,
                    "value": {
                        "item_id": "progress-structure-handoff",
                        "statement": "旧任务的原始依据已固定，正在建立结构化接续状态。",
                        "next_checkpoint": "验证首个五层投影及其证据追溯。",
                    },
                    "evidence": [selector],
                },
                {
                    "operation_id": "bootstrap-next-action",
                    "op": "upsert",
                    "kind": "next_action",
                    "id": "next-verify-projection",
                    "expect_absent": True,
                    "value": {
                        "action_id": "next-verify-projection",
                        "statement": "验证首个投影后，从权威 CURRENT 继续任务。",
                        "depends_on_claim_ids": [
                            "claim-preserve-original-evidence"
                        ],
                    },
                    "evidence": [selector],
                },
            ],
            "completeness_assertions": [
                {
                    "dimension": "goal_and_scope",
                    "status": "complete",
                    "reason": "当前目标与边界由精确消息支持。",
                    "evidence": [selector],
                },
                {
                    "dimension": "decisions",
                    "status": "partial",
                    "reason": "只恢复了当前消息明确支持的约束。",
                    "evidence": [selector],
                },
                {
                    "dimension": "rationales",
                    "status": "partial",
                    "reason": "约束理由尚未完整恢复。",
                    "evidence": [selector],
                },
                {
                    "dimension": "progress",
                    "status": "partial",
                    "reason": "只确认了本轮可见进度。",
                    "evidence": [selector],
                },
                {
                    "dimension": "artifacts",
                    "status": "partial",
                    "reason": "旧成果未从文件名或时间自动提升为权威成果。",
                    "evidence": [selector],
                },
                {
                    "dimension": "conflicts",
                    "status": "complete",
                    "reason": "现有精确消息没有提出阻断冲突。",
                    "evidence": [selector],
                },
                {
                    "dimension": "evidence",
                    "status": "complete",
                    "reason": "本次结构化记录均追溯到固定的原始消息。",
                    "evidence": [selector],
                },
            ],
        }

    def _bootstrap(
        self,
        proposal: Mapping[str, Any],
        expected_current_blob_sha: str,
    ) -> Mapping[str, Any]:
        proposal_path = self.root / "Windows safe 空格" / "接续 proposal.json"
        write_json(proposal_path, proposal)
        engine = self.fixture.engine()
        with mock.patch.object(
            engine,
            "_drive",
            side_effect=AssertionError(
                "metadata-only projection bootstrap must not access Drive"
            ),
        ):
            return vault_sync.bootstrap_memory_projection_command(
                SimpleNamespace(
                    task_id=self.fixture.task_id,
                    expected_current_blob_sha=expected_current_blob_sha,
                    proposal_file=proposal_path,
                    session_token=None,
                ),
                engine,
            )

    def _advance_legacy_current(self, label: str) -> bytes:
        clone = self.fixture.clone_remote(f"external-{label}")
        run(["git", "config", "user.name", "Other legacy client"], clone)
        run(["git", "config", "user.email", "other@localhost"], clone)
        parent_commit = run(["git", "rev-parse", "HEAD"], clone)
        current_path = clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        manifest = json.loads(
            (clone / str(current["manifest_path"])).read_text(encoding="utf-8")
        )
        snapshot_id = f"snap-{label}"
        transaction_id = f"tx-{label}"
        manifest_path = (
            f"tasks/{self.fixture.task_id}/versions/{snapshot_id}.json"
        )
        successor = {
            **manifest,
            "snapshot_id": snapshot_id,
            "generation": int(current["generation"]) + 1,
            "parents": [
                {
                    "kind": "version_snapshot",
                    "snapshot_id": current["snapshot_id"],
                    "commit": parent_commit,
                    "path": current["manifest_path"],
                }
            ],
            "state": "published",
            "change_type": "content_revision",
            "transaction_id": transaction_id,
            "continuation_readiness": "partial",
            "memory_projection": None,
        }
        advanced_current = {
            **current,
            "generation": successor["generation"],
            "snapshot_id": snapshot_id,
            "manifest_path": manifest_path,
            "continuation_readiness": "partial",
            "published_transaction_id": transaction_id,
        }
        write_json(clone / manifest_path, successor)
        write_json(current_path, advanced_current)
        expected = current_path.read_bytes()
        run(
            [
                "git",
                "add",
                "--",
                manifest_path,
                f"tasks/{self.fixture.task_id}/CURRENT.json",
            ],
            clone,
        )
        run(["git", "commit", "-m", f"advance legacy current {label}"], clone)
        run(["git", "push", "origin", "main"], clone)
        return expected

    @staticmethod
    def _assert_repo_path_is_cross_platform(relative: str) -> None:
        # Repository identities are POSIX and never contain a local drive/root.
        PurePosixPath(relative)
        if "\\" in relative or relative.startswith("/"):
            raise AssertionError(f"non-portable repository path: {relative}")
        if re.match(r"^[A-Za-z]:", relative):
            raise AssertionError(f"local drive leaked into repository path: {relative}")

    def test_legacy_exact_bound_stop_pins_verified_durable_evidence(self) -> None:
        clone, current = self._publish_exact_source_turn()
        self.assertEqual(current["generation"], 3)
        manifest = self._load_manifest(clone, current)

        # A normal Stop records raw evidence first. Semantic projection is a
        # separate model-callable operation and cannot be guessed by the hook.
        self.assertIsNone(manifest.get("memory_projection"))
        self.assertEqual(manifest["artifacts"], [self.legacy_artifact])
        evidence_sources = manifest.get("evidence_sources")
        self.assertIsInstance(evidence_sources, list)
        self.assertEqual(len(evidence_sources), 1)
        evidence = evidence_sources[0]
        self.assertEqual(evidence["source_id"], self.fixture.source_id)
        self.assertEqual(evidence["source_sequence"], 1)
        self.assertEqual(
            evidence["binding_id"],
            self.fixture.source_binding_id,
        )

        for path_field in (
            str(current["manifest_path"]),
            str(evidence["content_path"]),
        ):
            self._assert_repo_path_is_cross_platform(path_field)

        content_raw = (clone / str(evidence["content_path"])).read_bytes()
        self.assertEqual(
            evidence["content_sha256"],
            vault_sync.sha256_bytes(content_raw),
        )
        conversation = json.loads(content_raw.decode("utf-8"))
        self.assertEqual(
            [item["text"] for item in conversation["messages"]],
            [
                "继续这个已精确绑定的旧任务，并保留本轮原始依据。",
                "本轮证据已经保存；下一步建立结构化接续状态。",
            ],
        )

        binding_path = (
            clone
            / "bindings"
            / "confirmed"
            / f"{evidence['binding_id']}.json"
        )
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        self.assertEqual(
            binding["subject"],
            {"kind": "source", "id": evidence["source_id"]},
        )
        self.assertEqual(binding["state"], "confirmed")
        self.assertTrue(
            any(
                target.get("semantic_task_id") == self.fixture.task_id
                and target.get("relation") == "source_for"
                for target in binding["targets"]
            )
        )
        effective = binding["effective_range"]
        self.assertLessEqual(
            effective["source_sequence_from"],
            evidence["source_sequence"],
        )
        self.assertTrue(
            effective["source_sequence_to"] is None
            or effective["source_sequence_to"]
            >= evidence["source_sequence"]
        )

        self.assertFalse((self.fixture.drive / "objects").exists())
        remote_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in clone.rglob("*.json")
            if ".git" not in path.parts
        )
        self.assertNotIn(str(self.fixture.projectless.resolve()), remote_text)
        self.assertNotIn(self.fixture.source_session_id, remote_text)

    def test_cas_bootstrap_publishes_verified_first_projection_idempotently(
        self,
    ) -> None:
        before, legacy_current = self._publish_exact_source_turn()
        legacy_manifest = self._load_manifest(before, legacy_current)
        expected_blob = vault_sync.git_blob_sha(
            (
                before
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes()
        )
        parent_commit = run(["git", "rev-parse", "HEAD"], before)
        proposal = self._bootstrap_proposal(before, legacy_manifest)

        result = self._bootstrap(proposal, expected_blob)
        self.assertEqual(result["status"], "published")

        inspect = self.fixture.clone_remote("inspect-published-bootstrap")
        current = self._load_current(inspect)
        self.assertEqual(
            current["generation"],
            int(legacy_current["generation"]) + 1,
        )
        manifest = self._load_manifest(inspect, current)
        self.assertEqual(manifest["state"], "published")
        self.assertEqual(manifest["artifacts"], [self.legacy_artifact])
        self.assertEqual(manifest["evidence_sources"], legacy_manifest["evidence_sources"])
        self.assertEqual(manifest["parents"], [
            {
                "kind": "version_snapshot",
                "snapshot_id": legacy_current["snapshot_id"],
                "commit": parent_commit,
                "path": legacy_current["manifest_path"],
            }
        ])

        projection_ref = manifest["memory_projection"]
        projection_raw = (inspect / projection_ref["path"]).read_bytes()
        self.assertEqual(
            projection_ref["content_sha256"],
            vault_sync.sha256_bytes(projection_raw),
        )
        projection = json.loads(projection_raw.decode("utf-8"))
        self.assertEqual(projection["projection_id"], projection_ref["projection_id"])
        self.assertEqual(
            projection["basis"],
            {
                "task_id": self.fixture.task_id,
                "snapshot_id": current["snapshot_id"],
                "generation": current["generation"],
                "transaction_id": current["published_transaction_id"],
                "manifest_path": current["manifest_path"],
                "source_current_precondition": {
                    "current_blob_sha": expected_blob,
                    "snapshot_id": legacy_current["snapshot_id"],
                    "generation": legacy_current["generation"],
                    "transaction_id": legacy_current[
                        "published_transaction_id"
                    ],
                },
            },
        )
        self.assertEqual(
            projection["authority"],
            "rebuildable_task_handoff_cache",
        )
        self.assertEqual(projection["unprojected_deltas"], [])
        self.assertEqual(projection["reconciliation_receipts"], [])
        goal_evidence = projection["current_goal"]["evidence"]
        self.assertEqual(len(goal_evidence), 1)
        self.assertEqual(
            (
                goal_evidence[0]["source_id"],
                goal_evidence[0]["revision_id"],
                goal_evidence[0]["message_ordinal"],
            ),
            (
                legacy_manifest["evidence_sources"][-1]["source_id"],
                legacy_manifest["evidence_sources"][-1]["revision_id"],
                0,
            ),
        )

        claim = next(
            item
            for item in projection["effective_claims"]
            if item["claim_id"] == "claim-preserve-original-evidence"
        )
        self.assertEqual(claim["rationale"]["status"], "not_recovered")
        gap_id = claim["rationale"]["gap_id"]
        self.assertTrue(
            any(
                gap["gap_id"] == gap_id and gap["area"] == "rationale"
                for gap in projection["known_gaps"]
            )
        )
        self.assertFalse(
            any(
                item["authority_status"]
                in {"current_authoritative", "current_companion"}
                for item in projection["artifact_authorities"]
            )
        )
        self.assertTrue(
            any(
                gap["area"] == "artifact"
                for gap in projection["known_gaps"]
            )
        )
        self.assertEqual(
            projection["unclassified_artifact_policy"],
            "reference_only_do_not_infer_from_filename_or_inventory",
        )
        self.assertEqual(current["continuation_readiness"], "partial")

        verify_engine = self.fixture.engine()
        verify_engine.git.ensure()
        verified = vault_sync.load_remote_task_by_id(
            verify_engine.git,
            self.fixture.task_id,
        )
        self.assertEqual(
            verified.memory_projection["projection_id"],
            projection["projection_id"],
        )
        self.assertFalse((self.fixture.drive / "objects").exists())

        head_before_retry = self.fixture.remote_head()
        current_before_retry = (
            inspect / f"tasks/{self.fixture.task_id}/CURRENT.json"
        ).read_bytes()
        repeated = self._bootstrap(proposal, expected_blob)
        self.assertEqual(repeated["status"], "already_published")
        self.assertEqual(self.fixture.remote_head(), head_before_retry)
        retried = self.fixture.clone_remote("inspect-bootstrap-retry")
        self.assertEqual(
            (
                retried / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes(),
            current_before_retry,
        )

    def test_published_bootstrap_retry_after_current_advance_reuses_exact_bytes(
        self,
    ) -> None:
        before, legacy_current = self._publish_exact_source_turn()
        legacy_manifest = self._load_manifest(before, legacy_current)
        expected_blob = vault_sync.git_blob_sha(
            (
                before
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes()
        )
        proposal = self._bootstrap_proposal(before, legacy_manifest)
        published = self._bootstrap(proposal, expected_blob)
        self.assertEqual(published["status"], "published")

        published_clone = self.fixture.clone_remote(
            "inspect-bootstrap-before-later-current"
        )
        version_path = (
            f"tasks/{self.fixture.task_id}/versions/"
            f"{published['snapshot_id']}.json"
        )
        version_before = (published_clone / version_path).read_bytes()
        version = json.loads(version_before.decode("utf-8"))
        projection_path = version["memory_projection"]["path"]
        projection_before = (
            published_clone / projection_path
        ).read_bytes()

        engine = self.fixture.engine()
        with mock.patch.object(
            engine,
            "_drive",
            side_effect=AssertionError(
                "conversation-only CURRENT advance must not access Drive"
            ),
        ):
            engine.session_start(
                self.fixture.session_input(
                    session=self.fixture.source_session_id,
                    workspace=self.fixture.projectless,
                )
            )
            engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session=self.fixture.source_session_id,
                    turn="turn-after-bootstrap-published",
                    prompt="在已发布结构化交接之后继续推进任务。",
                    workspace=self.fixture.projectless,
                )
            )
            stopped = engine.stop(
                self.fixture.stop_input(
                    session=self.fixture.source_session_id,
                    turn="turn-after-bootstrap-published",
                    assistant="这次推进形成新的 CURRENT，但不改写首次投影。",
                    workspace=self.fixture.projectless,
                )
            )
        self.assertNotIn("systemMessage", stopped)

        advanced = self.fixture.clone_remote(
            "inspect-current-after-bootstrap"
        )
        advanced_current = self._load_current(advanced)
        self.assertNotEqual(
            advanced_current["snapshot_id"],
            published["snapshot_id"],
        )
        self.assertGreater(
            advanced_current["generation"],
            version["generation"],
        )
        head_before_retry = self.fixture.remote_head()

        repeated = self._bootstrap(proposal, expected_blob)

        self.assertEqual(repeated["status"], "already_published")
        self.assertTrue(repeated["historical"])
        self.assertEqual(
            repeated["snapshot_id"],
            published["snapshot_id"],
        )
        self.assertEqual(
            repeated["projection_id"],
            published["projection_id"],
        )
        self.assertEqual(
            repeated["current_blob_sha"],
            vault_sync.git_blob_sha(
                (
                    advanced
                    / f"tasks/{self.fixture.task_id}/CURRENT.json"
                ).read_bytes()
            ),
        )
        self.assertEqual(self.fixture.remote_head(), head_before_retry)

        retried = self.fixture.clone_remote(
            "inspect-bootstrap-after-historical-retry"
        )
        self.assertEqual(
            (retried / version_path).read_bytes(),
            version_before,
        )
        self.assertEqual(
            (retried / projection_path).read_bytes(),
            projection_before,
        )

    def test_inherited_artifact_keeps_legacy_parent_snapshot_provenance(
        self,
    ) -> None:
        before, legacy_current = self._publish_exact_source_turn()
        legacy_manifest = self._load_manifest(before, legacy_current)
        expected_blob = vault_sync.git_blob_sha(
            (
                before
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes()
        )
        proposal = self._bootstrap_proposal(before, legacy_manifest)

        published = self._bootstrap(proposal, expected_blob)

        inspect = self.fixture.clone_remote(
            "inspect-bootstrap-artifact-provenance"
        )
        current = self._load_current(inspect)
        manifest = self._load_manifest(inspect, current)
        projection = json.loads(
            (
                inspect / manifest["memory_projection"]["path"]
            ).read_text(encoding="utf-8")
        )
        authority = next(
            item
            for item in projection["artifact_authorities"]
            if item["artifact_id"]
            == self.legacy_artifact["artifact_id"]
        )
        self.assertEqual(
            authority["source_snapshot_id"],
            legacy_current["snapshot_id"],
        )
        self.assertNotEqual(
            authority["source_snapshot_id"],
            published["snapshot_id"],
        )
        self.assertEqual(
            authority["authority_status"],
            "reference_only",
        )

    def test_stale_bootstrap_becomes_candidate_without_changing_current(
        self,
    ) -> None:
        before, legacy_current = self._publish_exact_source_turn()
        legacy_manifest = self._load_manifest(before, legacy_current)
        expected_blob = vault_sync.git_blob_sha(
            (
                before
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes()
        )
        expected_parent_commit = run(["git", "rev-parse", "HEAD"], before)
        proposal = self._bootstrap_proposal(before, legacy_manifest)
        advanced_current = self._advance_legacy_current(
            "other-client-before-bootstrap"
        )

        result = self._bootstrap(proposal, expected_blob)
        self.assertEqual(result["status"], "candidate_remote_advance")
        inspect = self.fixture.clone_remote("inspect-bootstrap-candidate")
        self.assertEqual(
            (
                inspect / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes(),
            advanced_current,
        )
        candidate_path = (
            inspect
            / f"tasks/{self.fixture.task_id}/versions/{result['snapshot_id']}.json"
        )
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        self.assertEqual(candidate["state"], "candidate")
        self.assertEqual(
            candidate["parents"],
            [
                {
                    "kind": "version_snapshot",
                    "snapshot_id": legacy_current["snapshot_id"],
                    "commit": expected_parent_commit,
                    "path": legacy_current["manifest_path"],
                }
            ],
        )
        projection_ref = candidate["memory_projection"]
        projection = json.loads(
            (inspect / projection_ref["path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(
            projection["basis"]["source_current_precondition"][
                "current_blob_sha"
            ],
            expected_blob,
        )
        self.assertEqual(
            projection["basis"]["generation"],
            int(legacy_current["generation"]) + 1,
        )
        self.assertFalse(
            any(
                item["authority_status"]
                in {"current_authoritative", "current_companion"}
                for item in projection["artifact_authorities"]
            )
        )
        self.assertFalse((self.fixture.drive / "objects").exists())

    def test_bootstrap_rejects_unbound_unsafe_and_evidence_free_proposals(
        self,
    ) -> None:
        before, legacy_current = self._publish_exact_source_turn()
        legacy_manifest = self._load_manifest(before, legacy_current)
        expected_blob = vault_sync.git_blob_sha(
            (
                before
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes()
        )
        valid = self._bootstrap_proposal(before, legacy_manifest)
        baseline_head = self.fixture.remote_head()
        baseline_current = (
            before / f"tasks/{self.fixture.task_id}/CURRENT.json"
        ).read_bytes()

        unbound = json.loads(json.dumps(valid, ensure_ascii=False))
        unbound["operations"][0]["evidence"][0]["source_id"] = (
            "src-not-confirmed-for-this-task"
        )
        unsafe = json.loads(json.dumps(valid, ensure_ascii=False))
        unsafe["operations"][0]["value"]["statement"] = (
            r"C:\Users\example\secret.txt Authorization: Bearer test-secret"
        )
        evidence_free = json.loads(json.dumps(valid, ensure_ascii=False))
        evidence_free["operations"][0]["evidence"] = []

        for label, proposal in (
            ("unbound", unbound),
            ("unsafe", unsafe),
            ("evidence-free", evidence_free),
        ):
            with self.subTest(label=label):
                with self.assertRaises(
                    (vault_sync.PrivacyError, vault_sync.VerificationError)
                ):
                    self._bootstrap(proposal, expected_blob)
                self.assertEqual(self.fixture.remote_head(), baseline_head)
                inspect = self.fixture.clone_remote(f"inspect-rejected-{label}")
                self.assertEqual(
                    (
                        inspect
                        / f"tasks/{self.fixture.task_id}/CURRENT.json"
                    ).read_bytes(),
                    baseline_current,
                )


if __name__ == "__main__":
    unittest.main()
