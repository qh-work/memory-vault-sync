from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_layout_v1.py"
SPEC = importlib.util.spec_from_file_location("validate_layout_v1", SCRIPT)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

from memory_vault_runtime import protocol as runtime_protocol


def dump_json_yaml(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def valid_event(event_id: str = "evt-alpha-0001") -> dict:
    event = {
        "schema_version": "memory-event/v1",
        "memory_event_id": event_id,
        "kind": "decision",
        "confidence": "user_confirmed",
        "semantic_task_ids": ["task-alpha"],
        "source": {
            "source_id": "src-alpha",
            "revision_id": "rev-alpha-0001",
            "source_sequence": 0,
            "evidence_anchor_sha256": None,
        },
        "claim_key": "target-journal",
        "parents": [],
        "supersedes": [],
        "conflicts_with": [],
        "resolves": [],
        "payload": {
            "topic": "target",
            "decision": "retain both concurrent candidates",
        },
        "payload_sha256": "",
        "hash_profile": "jcs-rfc8785+sha256/event-v1",
        "event_sha256": "",
        "created_at": "2026-07-28T08:00:00+08:00",
    }
    event["payload_sha256"] = validator.sha256_jcs(event["payload"])
    event_domain = dict(event)
    event_domain.pop("event_sha256")
    event["event_sha256"] = validator.sha256_jcs(event_domain)
    return event


def valid_event_v2() -> dict:
    event = valid_event("evt-" + ("c" * 40))
    event["schema_version"] = "memory-event/v2"
    event.pop("semantic_task_ids")
    event["confidence"] = "assistant_inferred"
    episode = valid_episode()
    event["source"] = {
        "source_id": episode["source_id"],
        "revision_id": episode["episode_id"],
        "source_sequence": episode["source_sequence"],
        "evidence_anchor_sha256": episode["episode_sha256"],
    }
    event["payload"] = {
        "profile": "memory-network-semantic/v1",
        "claim": {
            "topic": "target",
            "decision": "retain both concurrent candidates",
        },
    }
    identity_domain = {
        "source_id": event["source"]["source_id"],
        "episode_id": event["source"]["revision_id"],
        "kind": event["kind"],
        "claim_key": event["claim_key"],
        "parents": event["parents"],
        "supersedes": event["supersedes"],
        "conflicts_with": event["conflicts_with"],
        "resolves": event["resolves"],
        "payload": event["payload"],
    }
    event["memory_event_id"] = "evt-" + validator.sha256_jcs(
        identity_domain
    )[:40]
    event["hash_profile"] = "jcs-rfc8785+sha256/event-v2"
    rehash_event(event)
    return event


def valid_episode() -> dict:
    episode = {
        "schema_version": "memory-episode/v1",
        "episode_id": "ep-" + ("a" * 40),
        "source_id": "src-" + ("b" * 40),
        "source_sequence": 0,
        "parent_episode_ids": [],
        "captured_at": "2026-08-12T00:00:00Z",
        "coverage": "partial_active_turn",
        "included_content": [
            "visible user prompt",
            "visible final assistant message",
        ],
        "excluded_content": [
            "hidden reasoning",
            "tool traces",
            "credentials",
            "local absolute paths",
            "native conversation identifiers",
        ],
        "messages": [
            {
                "ordinal": 0,
                "role": "user",
                "phase": "unknown",
                "text": "请只增量接收新的记忆。",
            },
            {
                "ordinal": 1,
                "role": "assistant",
                "phase": "final_answer",
                "text": "已使用提交游标接收新增记忆。",
            },
        ],
        "hash_profile": "jcs-rfc8785+sha256/episode-v1",
        "created_at": "2026-08-12T00:00:00Z",
        "episode_sha256": "",
    }
    rehash_episode(episode)
    return episode


def rehash_episode(episode: dict) -> None:
    domain = dict(episode)
    domain.pop("episode_sha256", None)
    episode["episode_sha256"] = validator.sha256_jcs(domain)


def rehash_event(event: dict) -> None:
    event["payload_sha256"] = validator.sha256_jcs(event["payload"])
    event_domain = dict(event)
    event_domain.pop("event_sha256", None)
    event["event_sha256"] = validator.sha256_jcs(event_domain)


def rehash_checkpoint(checkpoint: dict) -> None:
    checkpoint_domain = dict(checkpoint)
    checkpoint_domain.pop("checkpoint_sha256", None)
    checkpoint["checkpoint_sha256"] = validator.sha256_jcs(checkpoint_domain)


def event_evidence(event: dict) -> dict:
    return {
        "kind": "memory_event",
        "memory_event_id": event["memory_event_id"],
        "event_sha256": event["event_sha256"],
    }


def replace_projection_event_hash(value: object, event_id: str, event_hash: str) -> None:
    if isinstance(value, dict):
        if (
            value.get("kind") == "memory_event"
            and value.get("memory_event_id") == event_id
        ):
            value["event_sha256"] = event_hash
        for child in value.values():
            replace_projection_event_hash(child, event_id, event_hash)
    elif isinstance(value, list):
        for child in value:
            replace_projection_event_hash(child, event_id, event_hash)


def valid_task_memory_projection(event: dict) -> dict:
    evidence = event_evidence(event)
    return {
        "schema_version": "task-memory-projection/v1",
        "projection_id": "proj-alpha-0001",
        "authority": "rebuildable_task_handoff_cache",
        "basis": {
            "task_id": "task-alpha",
            "snapshot_id": "snap-alpha-0001",
            "generation": 1,
            "transaction_id": "tx-alpha-0001",
            "manifest_path": (
                "tasks/task-alpha/versions/snap-alpha-0001.json"
            ),
            "source_current_precondition": None,
        },
        "completeness": {
            "overall": "partial",
            "goal_and_scope": "partial",
            "decisions": "partial",
            "rationales": "partial",
            "progress": "partial",
            "artifacts": "partial",
            "conflicts": "partial",
            "evidence": "partial",
        },
        "completeness_basis": {
            dimension: {
                "status": "partial",
                "reason": (
                    "The fixture retains a verified but intentionally partial "
                    f"basis for {dimension}."
                ),
                "evidence": [evidence],
            }
            for dimension in validator.PROJECTION_COMPLETENESS_DIMENSIONS
        },
        "current_goal": {
            "status": "active",
            "statement": "Continue the verified task checkpoint.",
            "evidence": [evidence],
        },
        "unprojected_deltas": [],
        "reconciliation_receipts": [],
        "scope_boundaries": {
            "in_scope": [],
            "out_of_scope": [],
        },
        "effective_claims": [
            {
                "claim_id": "claim-current-target",
                "claim_key": "target-journal",
                "kind": "decision",
                "statement": "Use the current verified target.",
                "rationale": {
                    "status": "known",
                    "statement": "The user explicitly confirmed the target.",
                    "evidence": [evidence],
                },
                "settled": True,
                "superseded_claim_ids": [],
                "reask_policy": "do_not_reask",
                "evidence": [evidence],
            }
        ],
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
                "action_id": "action-continue",
                "statement": "Continue from the current checkpoint.",
                "depends_on_claim_ids": ["claim-current-target"],
                "evidence": [evidence],
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


def valid_source(source_id: str = "src-alpha") -> dict:
    return {
        "schema_version": "source/v1",
        "source_id": source_id,
        "source_type": "chat_thread",
        "external_source_key_sha256": "c" * 64,
        "source_instance_id": None,
        "visibility": "private",
        "sensitivity": "restricted",
        "current_revision_id": "rev-alpha-0001",
        "revisions": [
            {
                "revision_id": "rev-alpha-0001",
                "previous_revision_id": None,
                "source_sequence": 0,
                "captured_at": "2026-07-28T08:00:00+08:00",
                "coverage": "partial",
                "content_ref": None,
                "content_sha256": None,
                "redaction": {
                    "credentials_scanned": False,
                    "content_removed": True,
                    "reason": "Only non-sensitive metadata was imported.",
                },
            }
        ],
        "created_at": "2026-07-28T08:00:00+08:00",
    }


def valid_source_binding(
    *,
    binding_id: str = "bnd-source-alpha",
    source_id: str = "src-alpha",
    task_id: str = "task-alpha",
) -> dict:
    return {
        "schema_version": "binding/v1",
        "binding_id": binding_id,
        "subject": {"kind": "source", "id": source_id},
        "targets": [
            {
                "semantic_task_id": task_id,
                "relation": "source_for",
                "role": "primary",
            }
        ],
        "effective_range": {
            "source_sequence_from": 0,
            "source_sequence_to": None,
        },
        "state": "confirmed",
        "confidence": "user_confirmed",
        "confirmation_basis": "user_confirmation",
        "evidence": [
            {
                "evidence_id": "evd-source-alpha",
                "kind": "user_confirmation",
                "strength": "authoritative",
                "assertion": "The user confirmed this source-to-task binding.",
            }
        ],
        "created_at": "2026-07-28T08:00:00+08:00",
        "created_by": {
            "actor_kind": "user_action",
            "actor_id": "user-primary",
        },
    }


def valid_drive_import(
    import_id: str = "drive-backup-test-000001",
) -> dict:
    source_inventory = "migration/pending/test-artifacts.json"
    objects = [
        {
            "drive_file_id": f"file-{index:03d}",
            "drive_parent_id": "parent-alpha",
            "display_name": f"item-{index:03d}.bin",
            "drive_name": f"{index:03d}__item-{index:03d}.bin",
            "logical_path": (
                f"imports/{import_id}/test-artifacts/item-{index:03d}.bin"
            ),
            "size": index + 1,
            "mime_type": "application/octet-stream",
            "sha256": f"{index + 1:064x}",
            "mapping_status": "exact",
            "source_inventory": source_inventory,
            "aliases": [f"source/item-{index:03d}.bin"],
        }
        for index in range(121)
    ]
    return {
        "schema_version": "drive-import/v1",
        "import_id": import_id,
        "drive_root_id": "drive-root-alpha",
        "recorded_at": "2026-07-28T13:52:09Z",
        "source_inventories": [source_inventory],
        "objects": objects,
        "summary": {
            "total_objects": 121,
            "uniquely_mapped_objects": 121,
            "exact": 121,
            "needs_hash_verification": 0,
            "content_primary": 0,
            "redundant_duplicate": 0,
            "path_ambiguous_objects": 0,
            "missing": 0,
        },
    }


class RepositoryFixture:
    def __init__(self, root: Path):
        self.root = root
        for directory in (
            "tasks",
            "sources",
            "instances",
            "bindings",
            "memory/events",
            "schemas",
            "migration/layout-v1",
        ):
            (root / directory).mkdir(parents=True, exist_ok=True)

        dump_json_yaml(
            root / "VAULT.yaml",
            {
                "schema_version": "vault-layout/v1",
                "vault_id": "codex-memory-vault",
                "active": True,
                "layout_state": "active",
                "active_layout": "five_layer_v1",
                "authority": {
                    "memory_model": "taskless_associative",
                    "memory_evidence": (
                        "memory/episodes/<shard>/<episode_id>.json"
                    ),
                    "memory_relations": (
                        "memory/events/<shard>/<event_id>.json"
                    ),
                    "legacy_task_records": "migration_history_only",
                    "latest_by_timestamp": False,
                },
                "write_policy": {
                    "authoritative_target": "taskless_memory_network",
                    "memory_append_only": True,
                    "task_binding_writable": False,
                    "legacy_writable": False,
                    "single_authoritative_write": True,
                    "publication_strategy": (
                        "immutable_additions_with_single_disjoint_replay"
                    ),
                },
                "legacy_ref": {
                    "kind": "git_branch",
                    "ref": "legacy/pre-rewrite-20260728",
                    "commit_sha": (
                        "1b5710f802ab2efc56669a8f2ec80e9d2149b0cf"
                    ),
                },
            },
        )
        dump_json_yaml(
            root / "migration/legacy/BASELINE.json",
            {
                "schema_version": "legacy-baseline/v1",
                "repository": "example/codex-memory-vault",
                "branch": "legacy/pre-rewrite-20260728",
                "commit": "1b5710f802ab2efc56669a8f2ec80e9d2149b0cf",
                "registry_blob_sha": (
                    "49a201269e2fe3217f6c2af01e01c0e1d84f6372"
                ),
                "inventory": {
                    "visible_records": 54,
                    "registry_complete": False,
                    "excluded_sensitive_records": 1,
                    "excluded_categories": ["credential_or_authentication_task"],
                },
                "rewrite_policy": {
                    "legacy_branch_is_read_only": True,
                    "automatic_alias_from_hash_forbidden": True,
                    "automatic_task_promotion_from_artifact_presence_forbidden": True,
                },
            },
        )
        (root / "schemas/vault.schema.json").write_text(
            json.dumps(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        dump_json_yaml(
            root / "tasks/task-alpha/.vault_identity.yaml",
            {
                "schema_version": "portable-workspace-identity/v1",
                "vault_id": "codex-memory-vault",
                "binding_id": "bnd-alpha",
                "semantic_task_id": "task-alpha",
                "workspace_lineage_id": "wsl-alpha",
                "binding_state": "confirmed",
                "base": {
                    "snapshot_id": None,
                    "manifest_sha256": None,
                    "current_blob_sha": None,
                    "transaction_id": None,
                },
            },
        )
        dump_json_yaml(
            root / "bindings/confirmed/bnd-alpha.yaml",
            {
                "schema_version": "binding/v1",
                "binding_id": "bnd-alpha",
                "subject": {"kind": "workspace_lineage", "id": "wsl-alpha"},
                "targets": [
                    {
                        "semantic_task_id": "task-alpha",
                        "relation": "workspace_for",
                        "role": "primary",
                    }
                ],
                "effective_range": {
                    "source_sequence_from": None,
                    "source_sequence_to": None,
                },
                "state": "confirmed",
                "confidence": "user_confirmed",
                "confirmation_basis": "user_confirmation",
                "evidence": [
                    {
                        "evidence_id": "evd-alpha",
                        "kind": "user_confirmation",
                        "strength": "authoritative",
                        "assertion": "The user confirmed this binding.",
                    }
                ],
                "created_at": "2026-07-28T08:00:00+08:00",
                "created_by": {
                    "actor_kind": "user_action",
                    "actor_id": "user-primary",
                },
            },
        )
        dump_json_yaml(
            root / "memory/events/evt-alpha-0001.yaml",
            valid_event(),
        )
        dump_json_yaml(
            root / "tasks/INDEX.json",
            {
                "schema_version": "task-index/v1",
                "authority": "discovery_only",
                "generated_from": "tasks/*/TASK.json",
                "tasks": [
                    {
                        "task_id": "task-alpha",
                        "task_type": "semantic_task",
                        "status": "active",
                        "current": "tasks/task-alpha/CURRENT.json",
                    }
                ],
            },
        )
        dump_json_yaml(
            root / "tasks/task-alpha/CURRENT.json",
            {
                "schema_version": "task-current/v1",
                "task_id": "task-alpha",
                "generation": 1,
                "state": "active",
                "snapshot_id": "snap-alpha-0001",
                "manifest_path": "tasks/task-alpha/versions/snap-alpha-0001.json",
                "continuation_readiness": "partial",
                "published_transaction_id": "tx-alpha-0001",
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            },
        )
        event = validator.load_document(
            root / "memory/events/evt-alpha-0001.yaml"
        )
        event_set_hash = validator.sha256_jcs(
            [
                {
                    "memory_event_id": event["memory_event_id"],
                    "event_sha256": event["event_sha256"],
                }
            ]
        )
        checkpoint = {
            "schema_version": "memory-checkpoint/v1",
            "checkpoint_id": "mcp-alpha-0001",
            "scope": {"type": "vault", "id": "codex-memory-vault"},
            "authority": "cache_only",
            "basis": {
                "git_commit_sha": (
                    "1b5710f802ab2efc56669a8f2ec80e9d2149b0cf"
                ),
                "task_currents": [
                    {
                        "semantic_task_id": "task-alpha",
                        "current_blob_sha": validator._git_blob_sha(
                            root / "tasks/task-alpha/CURRENT.json"
                        ),
                        "task_generation": 1,
                        "snapshot_id": "snap-alpha-0001",
                        "transaction_id": "tx-alpha-0001",
                    }
                ],
                "event_heads": ["evt-alpha-0001"],
                "event_set_sha256": event_set_hash,
            },
            "summary": {
                "current_goal": None,
                "completed": [],
                "next_actions": [],
                "active_constraint_event_ids": [],
                "unresolved_conflict_event_ids": [],
                "candidate_artifact_ids": [],
                "task_continuations": [
                    {
                        "semantic_task_id": "task-alpha",
                        "snapshot_id": "snap-alpha-0001",
                    }
                ],
                "known_gaps": [],
            },
            "hash_profile": "jcs-rfc8785+sha256/checkpoint-v1",
            "created_at": "2026-07-28T08:00:00+08:00",
            "checkpoint_sha256": "",
        }
        checkpoint_domain = dict(checkpoint)
        checkpoint_domain.pop("checkpoint_sha256")
        checkpoint["checkpoint_sha256"] = validator.sha256_jcs(checkpoint_domain)
        dump_json_yaml(
            root / "memory/checkpoints/mcp-alpha-0001.json",
            checkpoint,
        )
        dump_json_yaml(
            root / "memory/CURRENT.json",
            {
                "schema_version": "memory-current/v1",
                "checkpoint_id": "mcp-alpha-0001",
                "checkpoint_path": "memory/checkpoints/mcp-alpha-0001.json",
                "generation": 1,
                "authority": {
                    "strategy": "git-blob-sha-compare-and-swap",
                    "timestamps_are_authoritative": False,
                },
            },
        )


class LayoutValidatorTests(unittest.TestCase):
    def test_portable_ids_enforce_64_bytes_and_windows_reserved_names(self) -> None:
        self.assertTrue(validator._valid_id("a" * 64))
        self.assertFalse(validator._valid_id("a" * 65))
        for reserved in (
            "con",
            "prn",
            "aux",
            "nul",
            "com1",
            "com9",
            "lpt1",
            "lpt9",
        ):
            with self.subTest(reserved=reserved):
                self.assertFalse(validator._valid_id(reserved))

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = RepositoryFixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def codes(self, compare_ref: str | None = None) -> set[str]:
        return {
            issue.code
            for issue in validator.validate_repository(
                self.root,
                compare_ref,
                allow_exported_checkpoint_fallback=True,
            )
        }

    def _write_drive_import(self, manifest: dict | None = None) -> Path:
        value = manifest or valid_drive_import()
        path = (
            self.root
            / "migration/imported"
            / f"{value['import_id']}.json"
        )
        dump_json_yaml(path, value)
        return path

    def _install_projection_schemas(self) -> None:
        schema_root = SCRIPT.parent.parent / "schemas"
        for name in (
            "task_version.schema.json",
            "task_memory_projection.schema.json",
        ):
            (self.root / "schemas" / name).write_bytes(
                (schema_root / name).read_bytes()
            )

    def _write_valid_projection(
        self,
        *,
        projection: dict | None = None,
        manifest_artifacts: list[dict] | None = None,
    ) -> tuple[Path, Path]:
        self._install_projection_schemas()
        source_content = {
            "schema_version": "conversation-export/v1",
            "source_id": "src-alpha",
            "title": "Verified event source",
            "captured_at": "2026-07-28T08:00:00+08:00",
            "coverage": "partial",
            "included_content": ["user_messages"],
            "excluded_content": ["hidden_reasoning"],
            "messages": [
                {
                    "ordinal": 0,
                    "role": "user",
                    "text": "This source anchors the verified memory event.",
                }
            ],
        }
        source_content_path = (
            self.root
            / "sources/src-alpha/revisions/rev-alpha-0001.json"
        )
        dump_json_yaml(source_content_path, source_content)
        source_content_hash = hashlib.sha256(
            source_content_path.read_bytes()
        ).hexdigest()
        source = valid_source()
        source["revisions"][0]["content_sha256"] = source_content_hash
        source["revisions"][0]["redaction"] = {
            "credentials_scanned": True,
            "content_removed": False,
        }
        dump_json_yaml(self.root / "sources/src-alpha/SOURCE.json", source)
        dump_json_yaml(
            self.root / "bindings/confirmed/bnd-source-alpha.yaml",
            valid_source_binding(),
        )
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection_value = projection or valid_task_memory_projection(event)
        projection_path = (
            self.root
            / "tasks/task-alpha/projections/proj-alpha-0001.json"
        )
        dump_json_yaml(projection_path, projection_value)
        projection_hash = hashlib.sha256(projection_path.read_bytes()).hexdigest()
        manifest = {
            "schema_version": "task-version/v1",
            "task_id": "task-alpha",
            "snapshot_id": "snap-alpha-0001",
            "generation": 1,
            "state": "published",
            "transaction_id": "tx-alpha-0001",
            "change_type": "content_revision",
            "continuation_readiness": "partial",
            "parents": [],
            "artifacts": manifest_artifacts or [],
            "evidence_sources": [
                {
                    "source_id": "src-alpha",
                    "revision_id": "rev-alpha-0001",
                    "source_sequence": 0,
                    "binding_id": "bnd-source-alpha",
                    "content_path": (
                        "sources/src-alpha/revisions/rev-alpha-0001.json"
                    ),
                    "content_sha256": source_content_hash,
                }
            ],
            "memory_projection": {
                "projection_id": "proj-alpha-0001",
                "path": (
                    "tasks/task-alpha/projections/proj-alpha-0001.json"
                ),
                "content_sha256": projection_hash,
            },
        }
        manifest_path = (
            self.root
            / "tasks/task-alpha/versions/snap-alpha-0001.json"
        )
        dump_json_yaml(manifest_path, manifest)
        return projection_path, manifest_path

    def _rewrite_projection(
        self,
        projection_path: Path,
        manifest_path: Path,
        projection: dict,
    ) -> None:
        dump_json_yaml(projection_path, projection)
        manifest = validator.load_document(manifest_path)
        manifest["memory_projection"]["content_sha256"] = hashlib.sha256(
            projection_path.read_bytes()
        ).hexdigest()
        dump_json_yaml(manifest_path, manifest)

    def _write_source_message_projection(
        self,
        *,
        messages: list[dict] | None = None,
        export_source_id: str = "src-alpha",
        use_evidence_sources: bool = True,
        conversation_only: bool = False,
    ) -> tuple[Path, Path, Path]:
        projection_path, manifest_path = self._write_valid_projection()
        message_values = messages or [
            {
                "ordinal": 0,
                "role": "user",
                "text": "The current target has been explicitly confirmed.",
            },
            {
                "ordinal": 1,
                "role": "assistant",
                "phase": "final_answer",
                "text": "The verified target is now active.",
            },
        ]
        revision_content = {
            "schema_version": "conversation-export/v1",
            "source_id": export_source_id,
            "title": "Verified source",
            "captured_at": "2026-07-28T08:00:00+08:00",
            "coverage": "partial",
            "included_content": ["user_messages", "assistant_messages"],
            "excluded_content": ["hidden_reasoning"],
            "messages": message_values,
        }
        content_path = (
            self.root
            / "sources/src-alpha/revisions/rev-alpha-0001.json"
        )
        dump_json_yaml(content_path, revision_content)
        revision_hash = hashlib.sha256(content_path.read_bytes()).hexdigest()

        source = valid_source()
        source["revisions"][0]["content_sha256"] = revision_hash
        source["revisions"][0]["redaction"] = {
            "credentials_scanned": True,
            "content_removed": False,
        }
        dump_json_yaml(self.root / "sources/src-alpha/SOURCE.json", source)

        manifest = validator.load_document(manifest_path)
        source_binding_id = "bnd-source-alpha"
        dump_json_yaml(
            self.root
            / f"bindings/confirmed/{source_binding_id}.yaml",
            valid_source_binding(binding_id=source_binding_id),
        )
        durable_source = {
            "source_id": "src-alpha",
            "revision_id": "rev-alpha-0001",
            "source_sequence": 0,
            "binding_id": source_binding_id,
            "content_path": (
                "sources/src-alpha/revisions/rev-alpha-0001.json"
            ),
            "content_sha256": revision_hash,
        }
        if use_evidence_sources:
            manifest["evidence_sources"] = [durable_source]
        if conversation_only:
            manifest["conversation_sources"] = [
                {
                    key: value
                    for key, value in durable_source.items()
                    if key not in {"source_sequence", "binding_id"}
                }
            ]
        dump_json_yaml(manifest_path, manifest)

        message_text = str(message_values[0]["text"])
        projection = validator.load_document(projection_path)
        projection["evidence_index"] = [
            {
                "entry_id": "evidence-message-target",
                "topic": "Current target",
                "references": [
                    {
                        "kind": "source_message",
                        "source_id": "src-alpha",
                        "revision_id": "rev-alpha-0001",
                        "source_sequence": 0,
                        "revision_content_sha256": revision_hash,
                        "message_ordinal": 0,
                        "evidence_anchor_sha256": hashlib.sha256(
                            message_text.encode("utf-8")
                        ).hexdigest(),
                    }
                ],
            }
        ]
        self._rewrite_projection(projection_path, manifest_path, projection)
        return projection_path, manifest_path, content_path

    def _git_baseline(self) -> str:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        self._git_commit_all("baseline")
        return subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def _git_commit_all(self, message: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), "add", "."],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", message],
            check=True,
        )

    def _add_second_event_and_checkpoint(self) -> Path:
        first_event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        second_event = valid_event("evt-alpha-0002")
        second_event["parents"] = ["evt-alpha-0001"]
        rehash_event(second_event)
        dump_json_yaml(
            self.root / "memory/events/evt-alpha-0002.json",
            second_event,
        )

        old_checkpoint = validator.load_document(
            self.root / "memory/checkpoints/mcp-alpha-0001.json"
        )
        new_checkpoint = json.loads(json.dumps(old_checkpoint))
        new_checkpoint["checkpoint_id"] = "mcp-alpha-0002"
        new_checkpoint["basis"]["event_heads"] = ["evt-alpha-0002"]
        new_checkpoint["basis"]["event_set_sha256"] = validator.sha256_jcs(
            [
                {
                    "memory_event_id": event["memory_event_id"],
                    "event_sha256": event["event_sha256"],
                }
                for event in sorted(
                    (first_event, second_event),
                    key=lambda item: item["memory_event_id"],
                )
            ]
        )
        new_checkpoint["created_at"] = "2026-07-28T09:00:00+08:00"
        rehash_checkpoint(new_checkpoint)
        new_path = (
            self.root / "memory/checkpoints/mcp-alpha-0002.json"
        )
        dump_json_yaml(new_path, new_checkpoint)

        memory_current = validator.load_document(
            self.root / "memory/CURRENT.json"
        )
        memory_current["checkpoint_id"] = "mcp-alpha-0002"
        memory_current["checkpoint_path"] = (
            "memory/checkpoints/mcp-alpha-0002.json"
        )
        memory_current["generation"] = 2
        dump_json_yaml(self.root / "memory/CURRENT.json", memory_current)
        return new_path

    def test_valid_active_layout_passes(self) -> None:
        self.assertEqual(
            validator.validate_repository(
                self.root,
                allow_exported_checkpoint_fallback=True,
            ),
            [],
        )

    def test_valid_drive_import_passes(self) -> None:
        self._write_drive_import()
        self.assertEqual(
            validator.validate_repository(
                self.root,
                allow_exported_checkpoint_fallback=True,
            ),
            [],
        )

    def test_drive_import_rejects_duplicate_drive_id(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"][1]["drive_file_id"] = (
            manifest["objects"][0]["drive_file_id"]
        )
        self._write_drive_import(manifest)
        self.assertIn("DRIVE_IMPORT_DUPLICATE", self.codes())

    def test_drive_import_requires_exact_object_and_summary_counts(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"].pop()
        self._write_drive_import(manifest)
        self.assertIn("DRIVE_IMPORT_COUNT", self.codes())

    def test_drive_import_rejects_duplicate_and_unsafe_paths(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"][1]["logical_path"] = (
            manifest["objects"][0]["logical_path"]
        )
        manifest["objects"][2]["aliases"] = [
            "/Users/example/private-item.bin"
        ]
        self._write_drive_import(manifest)
        codes = self.codes()
        self.assertIn("DRIVE_IMPORT_DUPLICATE", codes)
        self.assertIn("DRIVE_IMPORT_PATH", codes)

    def test_drive_import_rejects_invalid_mapping_status(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"][0]["mapping_status"] = "guessed"
        self._write_drive_import(manifest)
        self.assertIn("DRIVE_IMPORT_STATUS", self.codes())

    def test_drive_import_requires_status_summary_consistency(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"][0]["mapping_status"] = "needs_hash_verification"
        self._write_drive_import(manifest)
        self.assertIn("DRIVE_IMPORT_STATUS", self.codes())

    def test_drive_import_rejects_unexpected_fields(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"][0]["owner_email"] = "redacted"
        self._write_drive_import(manifest)
        self.assertIn("DRIVE_IMPORT_FORMAT", self.codes())

    def test_drive_import_rejects_credential_like_values(self) -> None:
        manifest = valid_drive_import()
        manifest["objects"][0]["aliases"] = [
            "github_pat_" + "a" * 32
        ]
        self._write_drive_import(manifest)
        self.assertIn("DRIVE_IMPORT_PRIVACY", self.codes())

    def test_exported_vault_is_not_accepted_as_authoritative_history(self) -> None:
        issues = validator.validate_repository(self.root)
        self.assertTrue(
            any(
                issue.code == "CHECKPOINT_BASIS_HISTORY"
                and "complete Git worktree" in issue.message
                for issue in issues
            )
        )

    def test_shadow_or_cutover_state_is_rejected(self) -> None:
        vault = validator.load_document(self.root / "VAULT.yaml")
        vault["layout_state"] = "shadow"
        vault["cutover"] = False
        dump_json_yaml(self.root / "VAULT.yaml", vault)
        self.assertIn("VAULT_STATE", self.codes())

    def test_vault_authority_cannot_reactivate_task_owned_memory(self) -> None:
        vault = validator.load_document(self.root / "VAULT.yaml")
        vault["authority"]["memory_model"] = "task_owned"
        vault["write_policy"]["task_binding_writable"] = True
        dump_json_yaml(self.root / "VAULT.yaml", vault)
        codes = self.codes()
        self.assertIn("VAULT_AUTHORITY", codes)
        self.assertIn("VAULT_WRITE_POLICY", codes)

    def test_five_layers_reject_bom_non_nfc_and_symlink(self) -> None:
        (self.root / "sources/bom.yaml").write_bytes(
            b"\xef\xbb\xbf" + b'{"ok": true}\n'
        )
        (self.root / "instances/not-nfc.txt").write_text(
            "e\u0301\n", encoding="utf-8"
        )
        os.symlink(
            self.root / "sources/bom.yaml",
            self.root / "sources/symlink.yaml",
        )
        codes = self.codes()
        self.assertIn("UTF8_BOM", codes)
        self.assertIn("TEXT_NFC", codes)
        self.assertIn("SYMLINK", codes)

    def test_portable_identity_rejects_instance_and_local_path(self) -> None:
        path = self.root / "tasks/task-alpha/.vault_identity.yaml"
        identity = validator.load_document(path)
        identity["workspace_instance_id"] = "instance-local"
        identity["local_path"] = "/Users/example/project"
        dump_json_yaml(path, identity)
        issues = validator.validate_repository(
            self.root,
            allow_exported_checkpoint_fallback=True,
        )
        private_issues = [
            issue for issue in issues if issue.code == "IDENTITY_PRIVATE_FIELD"
        ]
        self.assertGreaterEqual(len(private_issues), 2)

    def test_portable_identity_null_does_not_make_private_field_safe(self) -> None:
        path = self.root / "tasks/task-alpha/.vault_identity.yaml"
        identity = validator.load_document(path)
        identity["user_email"] = None
        dump_json_yaml(path, identity)
        self.assertIn("IDENTITY_PRIVATE_FIELD", self.codes())

    def test_confirmed_binding_cannot_use_hash_only_evidence(self) -> None:
        path = self.root / "bindings/confirmed/bnd-alpha.yaml"
        binding = validator.load_document(path)
        binding["evidence"] = [
            {
                "evidence_id": "evd-hash-only",
                "kind": "full_hash",
                "strength": "strong",
                "object_sha256": "a" * 64,
            }
        ]
        dump_json_yaml(path, binding)
        self.assertIn("BINDING_HASH_ONLY", self.codes())

    def test_alias_binding_cannot_use_hash_only_evidence_even_as_candidate(self) -> None:
        path = self.root / "bindings/confirmed/bnd-alpha.yaml"
        binding = validator.load_document(path)
        binding["state"] = "candidate"
        binding["state"] = "proposed"
        binding["confirmation_basis"] = None
        binding["targets"][0]["relation"] = "alias_of"
        binding["evidence"] = [
            {
                "evidence_id": "evd-manifest-hash",
                "kind": "full_hash",
                "strength": "strong",
                "object_sha256": "b" * 64,
            }
        ]
        dump_json_yaml(path, binding)
        self.assertIn("BINDING_HASH_ONLY", self.codes())

    def test_binding_evidence_requires_identity_and_strength(self) -> None:
        path = self.root / "bindings/confirmed/bnd-alpha.yaml"
        binding = validator.load_document(path)
        binding["evidence"] = [{"kind": "user_confirmation"}]
        dump_json_yaml(path, binding)
        self.assertIn("BINDING_EVIDENCE", self.codes())

    def test_route_correction_requires_exact_superseding_sequence_scope(
        self,
    ) -> None:
        path = (
            self.root
            / "bindings/confirmed/bnd-route-correction-alpha.yaml"
        )
        relative = path.relative_to(self.root).as_posix()
        valid = valid_source_binding(
            binding_id="bnd-route-correction-alpha",
        )
        valid["effective_range"]["source_sequence_from"] = 4
        valid["supersedes_binding_id"] = "bnd-source-previous"
        valid["route_correction"] = {
            "previous_task_id": "task-previous",
            "effective_source_sequence_from": 4,
            "historical_content_review_required": True,
            "potentially_misrouted_sequence_count": 3,
        }

        def correction_issues(value: dict) -> list[validator.Issue]:
            dump_json_yaml(path, value)
            issues: list[validator.Issue] = []
            validator.validate_bindings(self.root, issues)
            return [
                issue
                for issue in issues
                if issue.path == relative
                and issue.code == "BINDING_ROUTE_CORRECTION"
            ]

        self.assertEqual(correction_issues(valid), [])

        invalid_values: list[tuple[str, dict]] = []

        extra = json.loads(json.dumps(valid))
        extra["route_correction"]["unexpected"] = True
        invalid_values.append(("unexpected correction field", extra))

        null_correction = json.loads(json.dumps(valid))
        null_correction["route_correction"] = None
        invalid_values.append(("null correction", null_correction))

        missing_correction_field = json.loads(json.dumps(valid))
        missing_correction_field["route_correction"].pop(
            "previous_task_id"
        )
        invalid_values.append(
            ("missing correction field", missing_correction_field)
        )

        no_superseded_binding = json.loads(json.dumps(valid))
        no_superseded_binding.pop("supersedes_binding_id")
        invalid_values.append(
            ("missing superseded binding", no_superseded_binding)
        )

        self_superseding = json.loads(json.dumps(valid))
        self_superseding["supersedes_binding_id"] = self_superseding[
            "binding_id"
        ]
        invalid_values.append(("self-superseding binding", self_superseding))

        invalid_previous_task = json.loads(json.dumps(valid))
        invalid_previous_task["route_correction"]["previous_task_id"] = "../old"
        invalid_values.append(("invalid previous task", invalid_previous_task))

        invalid_sequence = json.loads(json.dumps(valid))
        invalid_sequence["route_correction"][
            "effective_source_sequence_from"
        ] = -1
        invalid_values.append(("negative effective sequence", invalid_sequence))

        mismatched_sequence = json.loads(json.dumps(valid))
        mismatched_sequence["route_correction"][
            "effective_source_sequence_from"
        ] = 5
        invalid_values.append(
            ("mismatched effective sequence", mismatched_sequence)
        )

        invalid_count = json.loads(json.dumps(valid))
        invalid_count["route_correction"][
            "potentially_misrouted_sequence_count"
        ] = True
        invalid_values.append(("boolean sequence count", invalid_count))

        inconsistent_review_flag = json.loads(json.dumps(valid))
        inconsistent_review_flag["route_correction"][
            "potentially_misrouted_sequence_count"
        ] = 0
        invalid_values.append(
            ("inconsistent review flag", inconsistent_review_flag)
        )

        for label, value in invalid_values:
            with self.subTest(label=label):
                self.assertTrue(correction_issues(value))

    def test_memory_event_rejects_wall_clock_total_order(self) -> None:
        path = self.root / "memory/events/evt-alpha-0001.yaml"
        event = validator.load_document(path)
        event["global_sequence"] = 99
        event["order_basis"] = "created_at"
        domain = dict(event)
        domain.pop("event_sha256")
        event["event_sha256"] = validator.sha256_jcs(domain)
        dump_json_yaml(path, event)
        self.assertIn("EVENT_TOTAL_ORDER", self.codes())

    def test_memory_event_hashes_are_verified(self) -> None:
        path = self.root / "memory/events/evt-alpha-0001.yaml"
        event = validator.load_document(path)
        event["payload"]["decision"] = "silently overwrite old work"
        dump_json_yaml(path, event)
        self.assertIn("EVENT_HASH", self.codes())

    def test_memory_event_hashed_domain_rejects_float(self) -> None:
        path = self.root / "memory/events/evt-alpha-0001.yaml"
        event = validator.load_document(path)
        event["payload"]["score"] = 0.9
        dump_json_yaml(path, event)
        self.assertIn("EVENT_JCS", self.codes())

    def test_taskless_memory_event_v2_has_no_task_scope(self) -> None:
        episode = valid_episode()
        episode_path = self.root / (
            "memory/episodes/aa/ep-" + ("a" * 40) + ".json"
        )
        dump_json_yaml(episode_path, episode)
        event = valid_event_v2()
        event_id = event["memory_event_id"]
        path = self.root / (
            f"memory/events/{event_id[4:6]}/{event_id}.json"
        )
        dump_json_yaml(path, event)
        issues: list[validator.Issue] = []
        validator.validate_memory_events(self.root, issues)
        self.assertEqual(
            [
                issue
                for issue in issues
                if issue.path == path.relative_to(self.root).as_posix()
            ],
            [],
        )

        flat_path = self.root / f"memory/events/{event_id}.json"
        path.unlink()
        dump_json_yaml(flat_path, event)
        issues = []
        validator.validate_memory_events(self.root, issues)
        self.assertIn("EVENT_FORMAT", {issue.code for issue in issues})
        flat_path.unlink()
        dump_json_yaml(path, event)

        episode_path.unlink()
        issues = []
        validator.validate_memory_events(self.root, issues)
        self.assertIn("EVENT_EVIDENCE", {issue.code for issue in issues})
        dump_json_yaml(episode_path, episode)

        event["semantic_task_ids"] = []
        rehash_event(event)
        dump_json_yaml(path, event)
        issues = []
        validator.validate_memory_events(self.root, issues)
        self.assertIn("EVENT_FORMAT", {issue.code for issue in issues})

        event["kind"] = "decision"
        event["confidence"] = "user_confirmed"
        rehash_event(event)
        dump_json_yaml(path, event)
        issues = []
        validator.validate_memory_events(self.root, issues)
        self.assertIn("EVENT_FORMAT", {issue.code for issue in issues})

        event["confidence"] = "assistant_inferred"
        event["parents"] = ["evt-" + ("d" * 40)]
        rehash_event(event)
        dump_json_yaml(path, event)
        issues = []
        validator.validate_memory_events(self.root, issues)
        self.assertIn("EVENT_EVIDENCE", {issue.code for issue in issues})

        event.pop("semantic_task_ids")
        event["kind"] = "binding_decision"
        rehash_event(event)
        dump_json_yaml(path, event)
        issues = []
        validator.validate_memory_events(self.root, issues)
        self.assertIn("EVENT_FORMAT", {issue.code for issue in issues})

    def test_memory_episode_is_pseudonymous_private_and_hashed(self) -> None:
        path = self.root / (
            "memory/episodes/aa/ep-" + ("a" * 40) + ".json"
        )
        episode = valid_episode()
        dump_json_yaml(path, episode)
        issues: list[validator.Issue] = []
        validator.validate_memory_episodes(self.root, issues)
        self.assertEqual(issues, [])

        episode["source_key_sha256"] = "c" * 64
        rehash_episode(episode)
        dump_json_yaml(path, episode)
        issues = []
        validator.validate_memory_episodes(self.root, issues)
        self.assertIn("EPISODE_FORMAT", {issue.code for issue in issues})

        episode.pop("source_key_sha256")
        episode["messages"][0]["text"] = "github_pat_" + ("A" * 32)
        rehash_episode(episode)
        dump_json_yaml(path, episode)
        issues = []
        validator.validate_memory_episodes(self.root, issues)
        self.assertIn("EPISODE_PRIVACY", {issue.code for issue in issues})

        episode["messages"][0]["text"] = "安全可见记忆"
        episode["episode_sha256"] = "d" * 64
        dump_json_yaml(path, episode)
        issues = []
        validator.validate_memory_episodes(self.root, issues)
        self.assertIn("EPISODE_HASH", {issue.code for issue in issues})

    def test_runtime_and_validator_share_one_jcs_encoder(self) -> None:
        self.assertIs(
            validator._protocol_jcs_json_bytes,
            runtime_protocol.jcs_json_bytes,
        )
        value = {
            "unicode": "记忆🔐",
            "ordered": {"z": 1, "a": 2},
            "values": [None, True, False, 7],
        }
        self.assertEqual(
            validator.canonical_json_bytes(value),
            runtime_protocol.jcs_json_bytes(value),
        )

    def test_duplicate_memory_event_ids_are_rejected(self) -> None:
        dump_json_yaml(
            self.root / "memory/events/duplicate.yaml",
            valid_event("evt-alpha-0001"),
        )
        self.assertIn("EVENT_DUPLICATE_ID", self.codes())

    def test_valid_task_memory_projection_passes(self) -> None:
        self._write_valid_projection()
        projection_issues = [
            issue
            for issue in validator.validate_repository(
                self.root,
                allow_exported_checkpoint_fallback=True,
            )
            if issue.code.startswith("PROJECTION")
        ]
        self.assertEqual(projection_issues, [])

    def test_task_memory_projection_rejects_stale_content_hash(self) -> None:
        projection_path, _manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        projection["current_goal"]["statement"] = "Changed after publication."
        dump_json_yaml(projection_path, projection)
        self.assertIn("PROJECTION_HASH", self.codes())

    def test_task_memory_projection_requires_exact_path_and_basis(self) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        projection["basis"]["transaction_id"] = "tx-wrong-0001"
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_BASIS", self.codes())

        manifest = validator.load_document(manifest_path)
        manifest["memory_projection"]["path"] = (
            "tasks/task-alpha/projections/proj-other-0001.json"
        )
        dump_json_yaml(manifest_path, manifest)
        self.assertIn("PROJECTION_REF", self.codes())

    def test_task_memory_projection_verifies_event_task_and_claim_key(self) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        event_path = self.root / "memory/events/evt-alpha-0001.yaml"
        event = validator.load_document(event_path)
        event["semantic_task_ids"] = ["task-other"]
        event["claim_key"] = "other-question"
        rehash_event(event)
        dump_json_yaml(event_path, event)

        projection = validator.load_document(projection_path)
        replace_projection_event_hash(
            projection,
            event["memory_event_id"],
            event["event_sha256"],
        )
        self._rewrite_projection(projection_path, manifest_path, projection)
        codes = self.codes()
        self.assertIn("PROJECTION_EVIDENCE_TASK", codes)
        self.assertIn("PROJECTION_CLAIM_EVIDENCE", codes)

    def test_task_memory_projection_enforces_claim_lineage_and_gaps(self) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        current = projection["effective_claims"][0]
        current["superseded_claim_ids"] = ["claim-old-target"]
        current["rationale"] = {
            "status": "not_recovered",
            "gap_id": "gap-missing-rationale",
            "evidence": [],
        }
        projection["superseded_claims"] = [
            {
                "claim_id": "claim-old-target",
                "claim_key": "target-journal",
                "kind": "decision",
                "statement": "Use the historical target.",
                "rationale": {
                    "status": "known",
                    "statement": "This was the earlier recorded target.",
                    "evidence": current["evidence"],
                },
                "superseded_by_claim_id": "claim-wrong-successor",
                "evidence": current["evidence"],
            }
        ]
        projection["next_actions"][0]["depends_on_claim_ids"] = [
            "claim-not-effective"
        ]
        self._rewrite_projection(projection_path, manifest_path, projection)
        codes = self.codes()
        self.assertIn("PROJECTION_SUPERSEDES", codes)
        self.assertIn("PROJECTION_RATIONALE_GAP", codes)
        self.assertIn("PROJECTION_CLAIM_REFERENCE", codes)

    def test_task_memory_projection_rejects_duplicate_effective_claim_key(
        self,
    ) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        duplicate = json.loads(json.dumps(projection["effective_claims"][0]))
        duplicate["claim_id"] = "claim-second-target"
        projection["effective_claims"].append(duplicate)
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_CLAIM_CONFLICT", self.codes())

    def test_contested_claims_and_blocking_questions_share_one_conflict(
        self,
    ) -> None:
        first_event_path = self.root / "memory/events/evt-alpha-0001.yaml"
        first_event = validator.load_document(first_event_path)
        first_event["claim_key"] = None
        rehash_event(first_event)
        dump_json_yaml(first_event_path, first_event)

        second_event = valid_event("evt-alpha-0002")
        second_event["claim_key"] = None
        rehash_event(second_event)
        dump_json_yaml(
            self.root / "memory/events/evt-alpha-0002.json",
            second_event,
        )
        first_evidence = event_evidence(first_event)
        second_evidence = event_evidence(second_event)

        projection = valid_task_memory_projection(first_event)
        projection["effective_claims"][0]["claim_key"] = "other-scope"
        projection["contested_claims"] = [
            {
                "claim_id": "claim-contested-alpha",
                "claim_key": "target-journal",
                "kind": "decision",
                "statement": "Use candidate target alpha.",
                "rationale": {
                    "status": "known",
                    "statement": "Evidence supports candidate alpha.",
                    "evidence": [first_evidence],
                },
                "settled": False,
                "evidence": [first_evidence],
            },
            {
                "claim_id": "claim-contested-beta",
                "claim_key": "target-journal",
                "kind": "decision",
                "statement": "Use candidate target beta.",
                "rationale": {
                    "status": "known",
                    "statement": "Evidence supports candidate beta.",
                    "evidence": [second_evidence],
                },
                "settled": False,
                "evidence": [second_evidence],
            },
        ]
        projection_path, manifest_path = self._write_valid_projection(
            projection=projection,
        )
        self.assertIn("PROJECTION_CLAIM_CONFLICT", self.codes())

        projection["blocking_conflicts"] = [
            {
                "conflict_id": "conflict-target-journal",
                "statement": "The two target candidates require resolution.",
                "claim_ids": [
                    "claim-contested-alpha",
                    "claim-contested-beta",
                ],
                "artifact_ids": [],
                "evidence": [first_evidence, second_evidence],
                "handling": "stop_disputed_work_and_request_resolution",
            }
        ]
        projection["open_questions"] = [
            {
                "question_id": "question-target-journal",
                "question": "Which target should remain active?",
                "blocking": True,
                "claim_key": "target-journal",
                "related_claim_ids": ["claim-current-target"],
                "blocking_conflict_id": "conflict-target-journal",
                "evidence": [first_evidence],
            }
        ]
        self._rewrite_projection(projection_path, manifest_path, projection)
        codes = self.codes()
        self.assertNotIn("PROJECTION_CLAIM_CONFLICT", codes)
        self.assertIn("PROJECTION_QUESTION", codes)

        projection["open_questions"][0]["related_claim_ids"] = [
            "claim-contested-alpha"
        ]
        projection["open_questions"][0]["evidence"] = []
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_FORMAT", self.codes())

        projection["open_questions"][0]["evidence"] = [first_evidence]
        self._rewrite_projection(projection_path, manifest_path, projection)
        codes = self.codes()
        self.assertNotIn("PROJECTION_CLAIM_CONFLICT", codes)
        self.assertNotIn("PROJECTION_QUESTION", codes)
        self.assertNotIn("PROJECTION_FORMAT", codes)
        self.assertIn("PROJECTION_READINESS", codes)

        manifest = validator.load_document(manifest_path)
        manifest["continuation_readiness"] = "blocked"
        dump_json_yaml(manifest_path, manifest)
        self.assertNotIn("PROJECTION_READINESS", self.codes())

    def test_task_memory_projection_validates_artifact_authority(self) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)
        artifact = {
            "artifact_id": "artifact-alpha",
            "display_name": "manuscript.docx",
            "drive_file_id": "file-alpha",
            "drive_parent_id": "parent-alpha",
            "logical_path": "task-alpha/manuscript.docx",
            "mime_type": (
                "application/vnd.openxmlformats-officedocument."
                "wordprocessingml.document"
            ),
            "role": "manuscript",
            "sha256": "a" * 64,
            "size": 1024,
            "storage_mode": "full",
        }
        projection["artifact_authorities"] = [
            {
                "artifact_id": "artifact-alpha",
                "sha256": "b" * 64,
                "purpose": "Current manuscript.",
                "role": "manuscript",
                "authority_status": "current_authoritative",
                "source_snapshot_id": "snap-alpha-0001",
                "dependencies": [],
                "verification": {
                    "status": "unverified",
                    "checks": [],
                    "evidence": [event_evidence(event)],
                },
                "relations": [],
            }
        ]
        self._write_valid_projection(
            projection=projection,
            manifest_artifacts=[artifact],
        )
        codes = self.codes()
        self.assertIn("PROJECTION_ARTIFACT", codes)
        self.assertIn("PROJECTION_ARTIFACT_VERIFICATION", codes)
        self.assertIn("PROJECTION_FORMAT", codes)

    def test_task_manifest_accepts_generic_storage_ref_and_rejects_mixed_refs(
        self,
    ) -> None:
        artifact = {
            "artifact_id": "artifact-generic-storage",
            "display_name": "generic.bin",
            "logical_path": "task-alpha/generic.bin",
            "mime_type": "application/octet-stream",
            "role": "supporting",
            "sha256": "c" * 64,
            "size": 128,
            "storage_mode": "full",
            "storage_ref": {
                "schema_version": "artifact-storage-ref/v1",
                "store_id": "object-store-primary",
                "driver": "verified-object-v1",
                "object_id": "object-generic-alpha",
                "container_id": "container-private-alpha",
                "verification_level": "remote-content-sha256-verified",
            },
        }
        _projection_path, manifest_path = self._write_valid_projection(
            manifest_artifacts=[artifact]
        )
        self.assertNotIn("PROJECTION_MANIFEST_FORMAT", self.codes())

        manifest = validator.load_document(manifest_path)
        manifest["artifacts"][0]["drive_file_id"] = "drive-mixed"
        manifest["artifacts"][0]["drive_parent_id"] = "drive-parent"
        dump_json_yaml(manifest_path, manifest)
        self.assertIn("PROJECTION_MANIFEST_FORMAT", self.codes())

    def test_task_manifest_accepts_only_exact_chunked_rclone_reference(
        self,
    ) -> None:
        artifact = {
            "artifact_id": "artifact-encrypted-chunks",
            "display_name": "archive.bin",
            "logical_path": "task-alpha/archive.bin",
            "mime_type": "application/octet-stream",
            "role": "supporting",
            "sha256": "d" * 64,
            "size": 16 * 1024 * 1024,
            "storage_mode": "chunked-v1",
            "storage_ref": {
                "schema_version": "artifact-storage-ref/v1",
                "store_id": "rclone-crypt-primary",
                "driver": "rclone-crypt",
                "object_id": "chunk-manifest-" + "e" * 64,
                "container_id": "rclone-" + "f" * 32,
                "verification_level": (
                    "rclone-crypt-chunk-manifest-sha256"
                ),
            },
        }
        _projection_path, manifest_path = self._write_valid_projection(
            manifest_artifacts=[artifact]
        )
        self.assertNotIn("PROJECTION_MANIFEST_FORMAT", self.codes())

        for key, replacement in (
            ("driver", "verified-object-v1"),
            ("object_id", "sha256-" + "e" * 64),
            ("verification_level", "rclone-crypt-download-sha256"),
        ):
            with self.subTest(key=key):
                manifest = validator.load_document(manifest_path)
                manifest["artifacts"][0]["storage_ref"][key] = replacement
                dump_json_yaml(manifest_path, manifest)
                self.assertIn(
                    "PROJECTION_MANIFEST_FORMAT",
                    self.codes(),
                )
                manifest["artifacts"][0]["storage_ref"][key] = artifact[
                    "storage_ref"
                ][key]
                dump_json_yaml(manifest_path, manifest)
        manifest = validator.load_document(manifest_path)
        manifest["artifacts"][0]["size"] = 64 * 1024 * 1024 * 1024 + 1
        dump_json_yaml(manifest_path, manifest)
        self.assertIn("PROJECTION_MANIFEST_FORMAT", self.codes())

    def test_task_memory_projection_accepts_fully_verified_artifact(
        self,
    ) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)
        artifact = {
            "artifact_id": "artifact-alpha",
            "display_name": "manuscript.docx",
            "drive_file_id": "file-alpha",
            "drive_parent_id": "parent-alpha",
            "logical_path": "task-alpha/manuscript.docx",
            "mime_type": "application/octet-stream",
            "role": "manuscript",
            "sha256": "a" * 64,
            "size": 1024,
            "storage_mode": "full",
        }
        check_evidence = [event_evidence(event)]
        projection["artifact_authorities"] = [
            {
                "artifact_id": "artifact-alpha",
                "sha256": "a" * 64,
                "purpose": "Current manuscript.",
                "role": "manuscript",
                "authority_status": "current_authoritative",
                "source_snapshot_id": "snap-alpha-0001",
                "dependencies": [],
                "verification": {
                    "status": "verified",
                    "checks": [
                        {
                            "check_id": "check-artifact-sha",
                            "kind": "sha256",
                            "result": "passed",
                            "evidence": check_evidence,
                        },
                        {
                            "check_id": "check-artifact-remote",
                            "kind": "remote_identity",
                            "result": "passed",
                            "evidence": check_evidence,
                        },
                    ],
                    "evidence": check_evidence,
                },
                "relations": [],
            }
        ]
        projection_path, manifest_path = self._write_valid_projection(
            projection=projection,
            manifest_artifacts=[artifact],
        )
        self.assertNotIn(
            "PROJECTION_ARTIFACT_VERIFICATION",
            self.codes(),
        )

        projection = validator.load_document(projection_path)
        projection["artifact_authorities"][0]["verification"]["checks"][0][
            "result"
        ] = "failed"
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn(
            "PROJECTION_ARTIFACT_VERIFICATION",
            self.codes(),
        )

    def test_task_memory_projection_rejects_artifact_cycles(self) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)
        manifest_artifacts = []
        authorities = []
        for suffix, dependency in (
            ("alpha", "artifact-beta"),
            ("beta", "artifact-alpha"),
        ):
            artifact_id = f"artifact-{suffix}"
            artifact_hash = ("a" if suffix == "alpha" else "b") * 64
            manifest_artifacts.append(
                {
                    "artifact_id": artifact_id,
                    "display_name": f"{suffix}.bin",
                    "drive_file_id": f"file-{suffix}",
                    "drive_parent_id": "parent-alpha",
                    "logical_path": f"task-alpha/{suffix}.bin",
                    "mime_type": "application/octet-stream",
                    "role": "supporting",
                    "sha256": artifact_hash,
                    "size": 16,
                    "storage_mode": "full",
                }
            )
            authorities.append(
                {
                    "artifact_id": artifact_id,
                    "sha256": artifact_hash,
                    "purpose": f"Supporting artifact {suffix}.",
                    "role": "supporting",
                    "authority_status": "reference_only",
                    "source_snapshot_id": "snap-alpha-0001",
                    "dependencies": [dependency],
                    "verification": {
                        "status": "unverified",
                        "checks": [],
                        "evidence": [],
                    },
                    "relations": [],
                }
            )
        projection["artifact_authorities"] = authorities
        self._write_valid_projection(
            projection=projection,
            manifest_artifacts=manifest_artifacts,
        )
        self.assertIn("PROJECTION_ARTIFACT_CYCLE", self.codes())

    def test_multiple_current_artifacts_conflict_despite_arbitrary_relation(
        self,
    ) -> None:
        manifest = {
            "artifacts": [
                {"artifact_id": "artifact-alpha", "sha256": "a" * 64},
                {"artifact_id": "artifact-beta", "sha256": "b" * 64},
            ]
        }
        projection = {
            "artifact_authorities": [
                {
                    "artifact_id": "artifact-alpha",
                    "sha256": "a" * 64,
                    "role": "manuscript",
                    "authority_status": "current_authoritative",
                    "dependencies": [],
                    "relations": [
                        {
                            "kind": "derived_from",
                            "target_artifact_id": "artifact-beta",
                        }
                    ],
                    "verification": {
                        "status": "verified",
                        "checks": [
                            {
                                "kind": "sha256",
                                "result": "passed",
                                "evidence": [{"kind": "memory_event"}],
                            },
                            {
                                "kind": "remote_identity",
                                "result": "passed",
                                "evidence": [{"kind": "memory_event"}],
                            },
                        ],
                        "evidence": [{"kind": "memory_event"}],
                    },
                },
                {
                    "artifact_id": "artifact-beta",
                    "sha256": "b" * 64,
                    "role": "manuscript",
                    "authority_status": "current_authoritative",
                    "dependencies": [],
                    "relations": [],
                    "verification": {
                        "status": "verified",
                        "checks": [
                            {
                                "kind": "sha256",
                                "result": "passed",
                                "evidence": [{"kind": "memory_event"}],
                            },
                            {
                                "kind": "size",
                                "result": "passed",
                                "evidence": [{"kind": "memory_event"}],
                            },
                        ],
                        "evidence": [{"kind": "memory_event"}],
                    },
                },
            ],
            "blocking_conflicts": [],
        }
        issues: list[validator.Issue] = []
        validator._validate_projection_artifacts(
            manifest,
            projection,
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_ARTIFACT_CONFLICT",
            {issue.code for issue in issues},
        )

        projection["artifact_authorities"][1]["role"] = "dataset"
        issues = []
        validator._validate_projection_artifacts(
            manifest,
            projection,
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertNotIn(
            "PROJECTION_ARTIFACT_CONFLICT",
            {issue.code for issue in issues},
        )

    def test_artifact_completeness_requires_full_classification_or_gap(
        self,
    ) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)
        manifest_artifacts = [
            {
                "artifact_id": f"artifact-{suffix}",
                "display_name": f"{suffix}.bin",
                "drive_file_id": f"file-{suffix}",
                "drive_parent_id": "parent-alpha",
                "logical_path": f"task-alpha/{suffix}.bin",
                "mime_type": "application/octet-stream",
                "role": "supporting",
                "sha256": digest * 64,
                "size": 16,
                "storage_mode": "full",
            }
            for suffix, digest in (("alpha", "a"), ("beta", "b"))
        ]
        projection["artifact_authorities"] = [
            {
                "artifact_id": "artifact-alpha",
                "sha256": "a" * 64,
                "purpose": "Classified supporting artifact.",
                "role": "supporting",
                "authority_status": "reference_only",
                "source_snapshot_id": "snap-alpha-0001",
                "dependencies": [],
                "verification": {
                    "status": "unverified",
                    "checks": [],
                    "evidence": [],
                },
                "relations": [],
            }
        ]
        projection["completeness"]["artifacts"] = "complete"
        projection_path, manifest_path = self._write_valid_projection(
            projection=projection,
            manifest_artifacts=manifest_artifacts,
        )
        self.assertIn("PROJECTION_COMPLETENESS", self.codes())

        projection["completeness"]["artifacts"] = "partial"
        projection["known_gaps"] = []
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_COMPLETENESS", self.codes())

        projection["known_gaps"] = [
            {
                "gap_id": "gap-unclassified-artifact",
                "area": "artifact",
                "statement": "One task-version artifact is not yet classified.",
                "trace_status": "partial",
                "evidence": [],
            }
        ]
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertNotIn("PROJECTION_COMPLETENESS", self.codes())

    def test_task_memory_projection_complete_dimension_cannot_have_gap(
        self,
    ) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        projection["completeness"]["decisions"] = "complete"
        projection["known_gaps"] = [
            {
                "gap_id": "gap-decision-unknown",
                "area": "decision",
                "statement": "A decision is not fully recovered.",
                "trace_status": "partial",
                "evidence": [],
            }
        ]
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_COMPLETENESS", self.codes())

    def test_projection_handoff_identifiers_are_unique_and_progress_is_exclusive(
        self,
    ) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        evidence = event_evidence(event)

        duplicate_scope = valid_task_memory_projection(event)
        duplicate_scope["scope_boundaries"] = {
            "in_scope": [
                {
                    "boundary_id": "scope-shared",
                    "statement": "Include the verified manuscript.",
                    "evidence": [evidence],
                }
            ],
            "out_of_scope": [
                {
                    "boundary_id": "scope-shared",
                    "statement": "Exclude unrelated teaching materials.",
                    "evidence": [evidence],
                }
            ],
        }
        issues: list[validator.Issue] = []
        validator._validate_projection_handoff_integrity(
            duplicate_scope,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertIn(
            "PROJECTION_IDENTIFIER_UNIQUENESS",
            {issue.code for issue in issues},
        )

        duplicate_rejected = valid_task_memory_projection(event)
        duplicate_rejected["rejected_options"] = [
            {
                "option_id": "option-shared",
                "claim_key": "target-journal",
                "statement": statement,
                "rejection_rationale": {
                    "statement": "The verified decision chose another option.",
                    "evidence": [evidence],
                },
                "evidence": [evidence],
            }
            for statement in ("Use option A.", "Use option B.")
        ]
        issues = []
        validator._validate_projection_handoff_integrity(
            duplicate_rejected,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertIn(
            "PROJECTION_IDENTIFIER_UNIQUENESS",
            {issue.code for issue in issues},
        )

        duplicate_progress = valid_task_memory_projection(event)
        duplicate_progress["completed"] = [
            {
                "item_id": "progress-shared",
                "statement": "The first copy is complete.",
                "evidence": [evidence],
            },
            {
                "item_id": "progress-shared",
                "statement": "A conflicting second copy is complete.",
                "evidence": [evidence],
            },
        ]
        duplicate_progress["in_progress"] = [
            {
                "item_id": "progress-shared",
                "statement": "The same item is also marked in progress.",
                "next_checkpoint": "Resolve the contradictory state.",
                "evidence": [evidence],
            }
        ]
        issues = []
        validator._validate_projection_handoff_integrity(
            duplicate_progress,
            "projection.json",
            issues,
            strict_successor=True,
        )
        codes = {issue.code for issue in issues}
        self.assertIn("PROJECTION_IDENTIFIER_UNIQUENESS", codes)
        self.assertIn("PROJECTION_PROGRESS_STATE", codes)

    def test_active_goal_requires_action_or_honest_progress_gap(self) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)
        projection["next_actions"] = []

        issues: list[validator.Issue] = []
        validator._validate_projection_handoff_integrity(
            projection,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertIn(
            "PROJECTION_NEXT_ACTION",
            {issue.code for issue in issues},
        )

        projection["known_gaps"] = [
            {
                "gap_id": "gap-next-action",
                "area": "progress",
                "statement": "The next executable action is not yet recovered.",
                "trace_status": "partial",
                "evidence": [],
            }
        ]
        issues = []
        validator._validate_projection_handoff_integrity(
            projection,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertNotIn(
            "PROJECTION_NEXT_ACTION",
            {issue.code for issue in issues},
        )

        projection["known_gaps"] = []
        projection["completeness_basis"]["progress"]["status"] = "unknown"
        projection["completeness"]["progress"] = "unknown"
        issues = []
        validator._validate_projection_handoff_integrity(
            projection,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertNotIn(
            "PROJECTION_NEXT_ACTION",
            {issue.code for issue in issues},
        )

    def test_new_empty_scope_requires_gap_but_legacy_stays_readable(self) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)

        issues: list[validator.Issue] = []
        validator._validate_projection_handoff_integrity(
            projection,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertIn("PROJECTION_SCOPE", {issue.code for issue in issues})

        projection["known_gaps"] = [
            {
                "gap_id": "gap-scope-boundary",
                "area": "goal_and_scope",
                "statement": "The exact task boundary is not yet recovered.",
                "trace_status": "partial",
                "evidence": [],
            }
        ]
        issues = []
        validator._validate_projection_handoff_integrity(
            projection,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertNotIn("PROJECTION_SCOPE", {issue.code for issue in issues})

        projection["completeness"]["goal_and_scope"] = "complete"
        issues = []
        validator._validate_projection_handoff_integrity(
            projection,
            "projection.json",
            issues,
            strict_successor=True,
        )
        self.assertIn("PROJECTION_SCOPE", {issue.code for issue in issues})

        legacy = valid_task_memory_projection(event)
        legacy.pop("completeness_basis")
        legacy["next_actions"] = []
        issues = []
        validator._validate_projection_handoff_integrity(
            legacy,
            "projection.json",
            issues,
            strict_successor=False,
        )
        self.assertNotIn(
            "PROJECTION_NEXT_ACTION",
            {issue.code for issue in issues},
        )
        self.assertNotIn("PROJECTION_SCOPE", {issue.code for issue in issues})

    def test_projection_completeness_basis_is_strict_but_legacy_is_readable(
        self,
    ) -> None:
        event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        projection = valid_task_memory_projection(event)
        relative = "tasks/task-alpha/projections/proj-alpha-0001.json"

        issues: list[validator.Issue] = []
        validator._validate_projection_completeness_basis(
            projection,
            relative,
            issues,
            required=True,
        )
        self.assertNotIn(
            "PROJECTION_COMPLETENESS_BASIS",
            {issue.code for issue in issues},
        )

        legacy = json.loads(json.dumps(projection))
        legacy.pop("completeness_basis")
        issues = []
        validator._validate_projection_completeness_basis(
            legacy,
            relative,
            issues,
            required=False,
        )
        self.assertNotIn(
            "PROJECTION_COMPLETENESS_BASIS",
            {issue.code for issue in issues},
        )
        validator._validate_projection_completeness_basis(
            legacy,
            relative,
            issues,
            required=True,
        )
        self.assertIn(
            "PROJECTION_COMPLETENESS_BASIS",
            {issue.code for issue in issues},
        )

        legacy_receipt = json.loads(json.dumps(projection))
        legacy_receipt["reconciliation_receipts"] = [
            {
                "receipt_id": "receipt-legacy-without-transitions",
            }
        ]
        issues = []
        validator._validate_projection_completeness_basis(
            legacy_receipt,
            relative,
            issues,
            required=False,
        )
        self.assertNotIn(
            "PROJECTION_COMPLETENESS_BASIS",
            {issue.code for issue in issues},
        )
        validator._validate_projection_completeness_basis(
            legacy_receipt,
            relative,
            issues,
            required=True,
        )
        self.assertIn(
            "PROJECTION_COMPLETENESS_BASIS",
            {issue.code for issue in issues},
        )

        mismatched = json.loads(json.dumps(projection))
        mismatched["completeness_basis"]["decisions"]["status"] = "complete"
        issues = []
        validator._validate_projection_completeness_basis(
            mismatched,
            relative,
            issues,
            required=True,
        )
        self.assertIn(
            "PROJECTION_COMPLETENESS_BASIS",
            {issue.code for issue in issues},
        )

    def test_task_memory_projection_resolves_exact_message_anchor(self) -> None:
        projection_path, manifest_path, _content_path = (
            self._write_source_message_projection()
        )
        projection = validator.load_document(projection_path)
        self.assertNotIn("PROJECTION_EVIDENCE_SOURCE", self.codes())
        self.assertNotIn("PROJECTION_EVIDENCE_HASH", self.codes())

        projection["evidence_index"][0]["references"][0][
            "message_ordinal"
        ] = 2
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_EVIDENCE_SOURCE", self.codes())

    def test_source_message_requires_durable_exact_contiguous_source(
        self,
    ) -> None:
        self._write_source_message_projection()
        codes = self.codes()
        self.assertNotIn("PROJECTION_EVIDENCE_SOURCE", codes)
        self.assertNotIn("PROJECTION_EVIDENCE_HASH", codes)

        self._write_source_message_projection(
            use_evidence_sources=False,
            conversation_only=True,
        )
        self.assertIn("PROJECTION_EVIDENCE_SOURCE", self.codes())

        self._write_source_message_projection(
            export_source_id="src-other",
        )
        self.assertIn("PROJECTION_EVIDENCE_SOURCE", self.codes())

        self._write_source_message_projection(
            messages=[
                {
                    "ordinal": 0,
                    "role": "user",
                    "text": "The current target has been explicitly confirmed.",
                },
                {
                    "ordinal": 2,
                    "role": "assistant",
                    "phase": "final_answer",
                    "text": "This ordinal is not contiguous.",
                },
            ],
        )
        self.assertIn("PROJECTION_EVIDENCE_SOURCE", self.codes())

    def test_source_message_rejects_cross_task_confirmed_binding(self) -> None:
        self._write_source_message_projection()
        binding_path = (
            self.root / "bindings/confirmed/bnd-source-alpha.yaml"
        )
        binding = validator.load_document(binding_path)
        binding["targets"][0]["semantic_task_id"] = "task-other"
        dump_json_yaml(binding_path, binding)
        self.assertIn("PROJECTION_EVIDENCE_BINDING", self.codes())

    def test_unprojected_delta_forbids_complete_or_ready_state(self) -> None:
        projection_path, manifest_path, _content_path = (
            self._write_source_message_projection()
        )
        projection = validator.load_document(projection_path)
        message_evidence = json.loads(
            json.dumps(
                projection["evidence_index"][0]["references"][0]
            )
        )
        projection["unprojected_deltas"] = [
            {
                "delta_id": "delta-latest-visible-message",
                "status": "requires_semantic_reconciliation",
                "message_evidence": [message_evidence],
                "handling": (
                    "read_newest_verified_messages_before_relying_on_"
                    "prior_structured_state"
                ),
            }
        ]
        projection["completeness"]["goal_and_scope"] = "complete"
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_UNPROJECTED_DELTA", self.codes())

        projection["completeness"]["goal_and_scope"] = "partial"
        self._rewrite_projection(projection_path, manifest_path, projection)
        manifest = validator.load_document(manifest_path)
        manifest["continuation_readiness"] = "ready"
        dump_json_yaml(manifest_path, manifest)
        self.assertIn("PROJECTION_UNPROJECTED_DELTA", self.codes())

    def test_reconciliation_receipt_proves_exact_delta_absorption(self) -> None:
        projection_path, manifest_path, _content_path = (
            self._write_source_message_projection()
        )
        successor = validator.load_document(projection_path)
        message_evidence = json.loads(
            json.dumps(successor["evidence_index"][0]["references"][0])
        )
        parent_projection = json.loads(json.dumps(successor))
        parent_projection["projection_id"] = "proj-alpha-parent"
        parent_projection["unprojected_deltas"] = [
            {
                "delta_id": "delta-parent-visible",
                "status": "requires_semantic_reconciliation",
                "evidence_entry_id": "evidence-message-target",
                "message_evidence": [message_evidence],
                "handling": (
                    "read_newest_verified_messages_before_relying_on_"
                    "prior_structured_state"
                ),
            }
        ]
        parent_path = (
            self.root
            / "tasks/task-alpha/projections/proj-alpha-parent.json"
        )
        dump_json_yaml(parent_path, parent_projection)
        parent_manifest_path = (
            self.root
            / "tasks/task-alpha/versions/snap-alpha-parent.json"
        )
        dump_json_yaml(
            parent_manifest_path,
            {
                "memory_projection": {
                    "projection_id": "proj-alpha-parent",
                    "path": (
                        "tasks/task-alpha/projections/proj-alpha-parent.json"
                    ),
                    "content_sha256": hashlib.sha256(
                        parent_path.read_bytes()
                    ).hexdigest(),
                }
            },
        )
        parent_commit = self._git_baseline()
        manifest = validator.load_document(manifest_path)
        manifest["parents"] = [
            {
                "snapshot_id": "snap-alpha-parent",
                "commit": parent_commit,
                "path": (
                    "tasks/task-alpha/versions/snap-alpha-parent.json"
                ),
            }
        ]
        successor["effective_claims"][0]["statement"] = (
            "Use the newly reconciled and verified target."
        )
        successor["effective_claims"][0]["evidence"].append(message_evidence)
        successor["effective_claims"][0]["rationale"]["evidence"].append(
            message_evidence
        )
        successor["unprojected_deltas"] = [
            json.loads(json.dumps(parent_projection["unprojected_deltas"][0]))
        ]
        issues: list[validator.Issue] = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            successor,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        successor["unprojected_deltas"] = []
        successor["reconciliation_receipts"] = [
            {
                "receipt_id": "receipt-parent-visible",
                "source_projection_id": "proj-alpha-parent",
                "resolved_delta_ids": ["delta-parent-visible"],
                "message_evidence": [message_evidence],
                "outcome": "state_updated",
                "outcome_rationale": (
                    "The verified message updates the effective target claim."
                ),
                "result_refs": [
                    {
                        "kind": "effective_claim",
                        "id": "claim-current-target",
                    },
                    {
                        "kind": "evidence_index_entry",
                        "id": "evidence-message-target",
                    },
                ],
                "retired_refs": [],
                "retirement_message_evidence": [],
                "completeness_transitions": [],
                "evidence_entry_ids": ["evidence-message-target"],
                "status": "semantically_reconciled",
            }
        ]
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            successor,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertNotIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        before_basis = json.loads(
            json.dumps(parent_projection["completeness_basis"]["decisions"])
        )
        after_basis = {
            "status": "complete",
            "reason": "The exact visible message completes this decision basis.",
            "evidence": [message_evidence],
        }
        successor["completeness"]["decisions"] = "complete"
        successor["completeness_basis"]["decisions"] = after_basis
        successor["reconciliation_receipts"][0]["result_refs"].insert(
            1,
            {"kind": "completeness", "id": "decisions"},
        )
        successor["reconciliation_receipts"][0][
            "completeness_transitions"
        ] = [
            {
                "dimension": "decisions",
                "before": "partial",
                "after": "complete",
                "change_kind": "status_changed",
                "before_basis_sha256": validator.sha256_jcs(before_basis),
                "after_basis_sha256": validator.sha256_jcs(after_basis),
                "reason": after_basis["reason"],
                "evidence": [message_evidence],
            }
        ]
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            successor,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertNotIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        successor["reconciliation_receipts"][0][
            "completeness_transitions"
        ][0]["after_basis_sha256"] = "0" * 64
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            successor,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )
        successor["reconciliation_receipts"][0][
            "completeness_transitions"
        ][0]["after_basis_sha256"] = validator.sha256_jcs(after_basis)

        refreshed = json.loads(json.dumps(successor))
        refreshed_after_basis = {
            "status": "partial",
            "reason": (
                "The exact visible message refreshes this still-partial "
                "decision basis."
            ),
            "evidence": [message_evidence],
        }
        refreshed["completeness"]["decisions"] = "partial"
        refreshed["completeness_basis"]["decisions"] = refreshed_after_basis
        refreshed_transition = refreshed["reconciliation_receipts"][0][
            "completeness_transitions"
        ][0]
        refreshed_transition.update(
            {
                "before": "partial",
                "after": "partial",
                "change_kind": "basis_refreshed",
                "before_basis_sha256": validator.sha256_jcs(before_basis),
                "after_basis_sha256": validator.sha256_jcs(
                    refreshed_after_basis
                ),
                "reason": refreshed_after_basis["reason"],
                "evidence": [message_evidence],
            }
        )
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            refreshed,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertNotIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )
        refreshed_transition["change_kind"] = "status_changed"
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            refreshed,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        rollforward = json.loads(json.dumps(parent_projection))
        rollforward["unprojected_deltas"].append(
            {
                "delta_id": "delta-newest-visible",
                "status": "requires_semantic_reconciliation",
                "evidence_entry_id": "evidence-message-target",
                "message_evidence": [message_evidence],
                "handling": (
                    "read_newest_verified_messages_before_relying_on_"
                    "prior_structured_state"
                ),
            }
        )
        rollforward["completeness_basis"] = {
            dimension: {
                "status": "partial",
                "reason": validator.ROLL_FORWARD_COMPLETENESS_BASIS_REASON,
                "evidence": [message_evidence],
            }
            for dimension in validator.PROJECTION_COMPLETENESS_DIMENSIONS
        }
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            rollforward,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertNotIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )
        rollforward["completeness_basis"]["decisions"]["reason"] = (
            "An arbitrary unreceipted semantic basis rewrite."
        )
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            rollforward,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        transitioned = json.loads(json.dumps(parent_projection))
        transitioned["unprojected_deltas"] = []
        transitioned["next_actions"] = []
        transitioned["completed"] = [
            {
                "item_id": "action-continue",
                "statement": "The reconciled continuation action is complete.",
                "evidence": [message_evidence],
            }
        ]
        transitioned["reconciliation_receipts"] = [
            {
                "receipt_id": "receipt-parent-transition",
                "source_projection_id": "proj-alpha-parent",
                "resolved_delta_ids": ["delta-parent-visible"],
                "message_evidence": [message_evidence],
                "outcome": "state_updated",
                "outcome_rationale": (
                    "The verified message completes the pending action."
                ),
                "result_refs": [
                    {
                        "kind": "completed_item",
                        "id": "action-continue",
                    },
                    {
                        "kind": "evidence_index_entry",
                        "id": "evidence-message-target",
                    },
                ],
                "retired_refs": [
                    {
                        "kind": "next_action",
                        "id": "action-continue",
                    }
                ],
                "retirement_message_evidence": [message_evidence],
                "completeness_transitions": [],
                "evidence_entry_ids": ["evidence-message-target"],
                "status": "semantically_reconciled",
            }
        ]
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            transitioned,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertNotIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        successor["unprojected_deltas"] = [
            json.loads(json.dumps(parent_projection["unprojected_deltas"][0]))
        ]
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            successor,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

        successor["unprojected_deltas"] = []
        successor["reconciliation_receipts"][0]["result_refs"][0][
            "id"
        ] = "claim-missing"
        issues = []
        validator._validate_projection_reconciliation_receipts(
            self.root,
            manifest,
            successor,
            {},
            "tasks/task-alpha/projections/proj-alpha-0001.json",
            issues,
        )
        self.assertIn(
            "PROJECTION_RECONCILIATION_RECEIPT",
            {issue.code for issue in issues},
        )

    def test_task_memory_projection_requires_previous_current_after_gen1(
        self,
    ) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        projection["basis"]["generation"] = 2
        manifest = validator.load_document(manifest_path)
        manifest["generation"] = 2
        dump_json_yaml(manifest_path, manifest)
        self._rewrite_projection(projection_path, manifest_path, projection)
        self.assertIn("PROJECTION_PRECONDITION", self.codes())

    def test_invalid_json_schema_is_rejected(self) -> None:
        (self.root / "schemas/broken.schema.json").write_text(
            '{"$schema": "x",}',
            encoding="utf-8",
        )
        self.assertIn("SCHEMA_JSON", self.codes())

    def test_source_uses_single_private_source_document(self) -> None:
        path = self.root / "sources/src-alpha/SOURCE.json"
        dump_json_yaml(path, valid_source())
        self.assertFalse(
            {
                issue.code
                for issue in validator.validate_repository(
                    self.root,
                    allow_exported_checkpoint_fallback=True,
                )
                if issue.code.startswith("SOURCE")
            }
        )
        dump_json_yaml(path.parent / "HEAD.json", {"revision": "rev-alpha-0001"})
        self.assertIn("SOURCE_SELECTOR", self.codes())

    def test_source_rejects_raw_native_locator(self) -> None:
        path = self.root / "sources/src-alpha/SOURCE.json"
        source = valid_source()
        source["native_locator"] = {"thread_id": "raw-provider-id"}
        dump_json_yaml(path, source)
        self.assertIn("SOURCE_FORMAT", self.codes())

    def test_checkpoint_rejects_zero_or_stale_hash(self) -> None:
        path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        checkpoint = validator.load_document(path)
        checkpoint["checkpoint_sha256"] = "0" * 64
        dump_json_yaml(path, checkpoint)
        self.assertIn("CHECKPOINT_HASH", self.codes())

    def test_checkpoint_task_basis_must_match_current(self) -> None:
        path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        checkpoint = validator.load_document(path)
        checkpoint["basis"]["task_currents"][0]["task_generation"] = 99
        domain = dict(checkpoint)
        domain.pop("checkpoint_sha256")
        checkpoint["checkpoint_sha256"] = validator.sha256_jcs(domain)
        dump_json_yaml(path, checkpoint)
        self.assertIn("CHECKPOINT_TASK_BASIS", self.codes())

    def test_immutable_checkpoints_keep_distinct_historical_event_sets(self) -> None:
        self._add_second_event_and_checkpoint()
        self.assertEqual(
            validator.validate_repository(
                self.root,
                allow_exported_checkpoint_fallback=True,
            ),
            [],
        )

    def test_git_basis_validates_two_immutable_historical_checkpoints(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "add", "."],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "first event basis"],
            check=True,
        )
        first_basis = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        old_path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        old_checkpoint = validator.load_document(old_path)
        old_checkpoint["basis"]["git_commit_sha"] = first_basis
        rehash_checkpoint(old_checkpoint)
        dump_json_yaml(old_path, old_checkpoint)
        subprocess.run(
            ["git", "-C", str(self.root), "add", str(old_path)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "first checkpoint"],
            check=True,
        )

        second_event = valid_event("evt-alpha-0002")
        second_event["parents"] = ["evt-alpha-0001"]
        rehash_event(second_event)
        second_event_path = self.root / "memory/events/evt-alpha-0002.json"
        dump_json_yaml(second_event_path, second_event)
        current_path = self.root / "tasks/task-alpha/CURRENT.json"
        current = validator.load_document(current_path)
        current["generation"] = 2
        current["snapshot_id"] = "snap-alpha-0002"
        current["manifest_path"] = (
            "tasks/task-alpha/versions/snap-alpha-0002.json"
        )
        current["published_transaction_id"] = "tx-alpha-0002"
        dump_json_yaml(current_path, current)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "add",
                str(second_event_path),
                str(current_path),
            ],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "commit",
                "-qm",
                "second task and event basis",
            ],
            check=True,
        )
        second_basis = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        new_path = self._add_second_event_and_checkpoint()
        new_checkpoint = validator.load_document(new_path)
        new_checkpoint["basis"]["git_commit_sha"] = second_basis
        new_task_current = new_checkpoint["basis"]["task_currents"][0]
        new_task_current["current_blob_sha"] = validator._git_blob_sha(
            current_path
        )
        new_task_current["task_generation"] = 2
        new_task_current["snapshot_id"] = "snap-alpha-0002"
        new_task_current["transaction_id"] = "tx-alpha-0002"
        new_checkpoint["summary"]["task_continuations"][0][
            "snapshot_id"
        ] = "snap-alpha-0002"
        rehash_checkpoint(new_checkpoint)
        dump_json_yaml(new_path, new_checkpoint)

        self.assertEqual(validator.validate_repository(self.root), [])

    def test_missing_git_basis_does_not_fall_back_to_live_current(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "baseline"],
            check=True,
        )
        path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        checkpoint = validator.load_document(path)
        checkpoint["basis"]["git_commit_sha"] = "f" * 40
        rehash_checkpoint(checkpoint)
        dump_json_yaml(path, checkpoint)

        self.assertIn("CHECKPOINT_BASIS_HISTORY", self.codes())

    def test_historical_current_path_must_exist(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "baseline"],
            check=True,
        )
        current_path = self.root / "tasks/task-alpha/CURRENT.json"
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "rm",
                "--cached",
                str(current_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "commit",
                "-qm",
                "remove historical current",
            ],
            check=True,
        )
        missing_basis = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        checkpoint = validator.load_document(path)
        checkpoint["basis"]["git_commit_sha"] = missing_basis
        rehash_checkpoint(checkpoint)
        dump_json_yaml(path, checkpoint)

        self.assertIn("CHECKPOINT_TASK_HISTORY", self.codes())

    def test_historical_current_blob_must_match_basis_tree(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "baseline"],
            check=True,
        )
        basis = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        checkpoint = validator.load_document(path)
        checkpoint["basis"]["git_commit_sha"] = basis
        checkpoint["basis"]["task_currents"][0]["current_blob_sha"] = "f" * 40
        rehash_checkpoint(checkpoint)
        dump_json_yaml(path, checkpoint)

        issues = validator.validate_repository(self.root)
        self.assertTrue(
            any(
                issue.code == "CHECKPOINT_TASK_BASIS"
                and "current_blob_sha mismatch" in issue.message
                for issue in issues
            )
        )

    def test_malformed_current_checkpoint_event_set_still_fails(self) -> None:
        path = self._add_second_event_and_checkpoint()
        checkpoint = validator.load_document(path)
        checkpoint["basis"]["event_set_sha256"] = "f" * 64
        rehash_checkpoint(checkpoint)
        dump_json_yaml(path, checkpoint)
        self.assertIn("CHECKPOINT_EVENT_SET", self.codes())

    def test_available_git_basis_precedes_explicit_head_closure(self) -> None:
        concurrent_event = valid_event("evt-alpha-0002")
        dump_json_yaml(
            self.root / "memory/events/evt-alpha-0002.json",
            concurrent_event,
        )
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "add", "."],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "event basis"],
            check=True,
        )
        basis_commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        checkpoint = validator.load_document(path)
        checkpoint["basis"]["git_commit_sha"] = basis_commit
        rehash_checkpoint(checkpoint)
        dump_json_yaml(path, checkpoint)

        self.assertIn("CHECKPOINT_EVENT_SET", self.codes())

    def test_historical_event_hashes_are_recomputed_at_basis_commit(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "initial basis"],
            check=True,
        )
        first_basis = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        old_path = self.root / "memory/checkpoints/mcp-alpha-0001.json"
        old_checkpoint = validator.load_document(old_path)
        old_checkpoint["basis"]["git_commit_sha"] = first_basis
        rehash_checkpoint(old_checkpoint)
        dump_json_yaml(old_path, old_checkpoint)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "anchor checkpoint"],
            check=True,
        )

        first_event = validator.load_document(
            self.root / "memory/events/evt-alpha-0001.yaml"
        )
        second_event = valid_event("evt-alpha-0002")
        second_event["parents"] = ["evt-alpha-0001"]
        rehash_event(second_event)
        second_event["payload"]["decision"] = "changed without rehashing"
        stale_event_hash = second_event["event_sha256"]
        second_path = self.root / "memory/events/evt-alpha-0002.json"
        dump_json_yaml(second_path, second_event)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "bad event basis"],
            check=True,
        )
        bad_basis = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        rehash_event(second_event)
        dump_json_yaml(second_path, second_event)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "repair event"],
            check=True,
        )

        new_checkpoint = json.loads(json.dumps(old_checkpoint))
        new_checkpoint["checkpoint_id"] = "mcp-alpha-0002"
        new_checkpoint["basis"]["git_commit_sha"] = bad_basis
        new_checkpoint["basis"]["event_heads"] = ["evt-alpha-0002"]
        new_checkpoint["basis"]["event_set_sha256"] = validator.sha256_jcs(
            [
                {
                    "memory_event_id": first_event["memory_event_id"],
                    "event_sha256": first_event["event_sha256"],
                },
                {
                    "memory_event_id": second_event["memory_event_id"],
                    "event_sha256": stale_event_hash,
                },
            ]
        )
        new_checkpoint["created_at"] = "2026-07-28T09:00:00+08:00"
        rehash_checkpoint(new_checkpoint)
        new_path = self.root / "memory/checkpoints/mcp-alpha-0002.json"
        dump_json_yaml(new_path, new_checkpoint)
        memory_current = validator.load_document(
            self.root / "memory/CURRENT.json"
        )
        memory_current["checkpoint_id"] = "mcp-alpha-0002"
        memory_current["checkpoint_path"] = (
            "memory/checkpoints/mcp-alpha-0002.json"
        )
        memory_current["generation"] = 2
        dump_json_yaml(self.root / "memory/CURRENT.json", memory_current)

        issues = validator.validate_repository(self.root)
        self.assertTrue(
            any(
                issue.code == "CHECKPOINT_EVENT_HISTORY"
                and "event_sha256 mismatch" in issue.message
                for issue in issues
            )
        )

    def test_historical_event_semantics_are_revalidated(self) -> None:
        event = valid_event()
        event["kind"] = "invented-authority"
        rehash_event(event)
        issues: list[validator.Issue] = []

        valid = validator._historical_event_integrity_is_valid(
            event,
            "memory/events/evt-alpha-0001.yaml",
            "a" * 40,
            "memory/checkpoints/mcp-alpha-0001.json",
            issues,
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                issue.code == "CHECKPOINT_EVENT_HISTORY"
                and "kind is invalid" in issue.message
                for issue in issues
            )
        )

    def test_legacy_payload_directory_is_rejected(self) -> None:
        (self.root / "legacy").mkdir()
        self.assertIn("LEGACY_ON_MAIN", self.codes())

    def test_baseline_frozen_inventory_cannot_be_rewritten(self) -> None:
        path = self.root / "migration/legacy/BASELINE.json"
        baseline = validator.load_document(path)
        baseline["inventory"]["registry_complete"] = True
        dump_json_yaml(path, baseline)
        self.assertIn("LEGACY_BASELINE", self.codes())

    def test_conservative_yaml_parser_accepts_nested_evidence(self) -> None:
        text = """
schema_version: binding/v1
binding_id: bnd-yaml
subject:
  kind: source
  id: src-yaml
targets:
  - semantic_task_id: task-yaml
    relation: source_for
    role: primary
effective_range:
  source_sequence_from: 0
  source_sequence_to: null
state: confirmed
confidence: user_confirmed
confirmation_basis: user_confirmation
evidence:
  - evidence_id: evd-yaml-confirm
    kind: user_confirmation
    strength: authoritative
created_at: "2026-07-28T08:00:00+08:00"
created_by:
  actor_kind: migration
  actor_id: migration-layout-v1
""".lstrip()
        value = validator._SubsetYamlParser(text).parse()
        self.assertEqual(value["targets"][0]["semantic_task_id"], "task-yaml")
        self.assertEqual(value["evidence"][0]["kind"], "user_confirmation")

    def test_git_comparison_forbids_task_version_rewrite(self) -> None:
        _projection_path, manifest_path = self._write_valid_projection()
        baseline = self._git_baseline()

        manifest = validator.load_document(manifest_path)
        manifest["continuation_readiness"] = "ready"
        dump_json_yaml(manifest_path, manifest)
        self._git_commit_all("rewrite task version")

        self.assertIn(
            "TASK_VERSION_APPEND_ONLY",
            self.codes(compare_ref=baseline),
        )

    def test_git_comparison_forbids_projection_rewrite(self) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        baseline = self._git_baseline()

        projection = validator.load_document(projection_path)
        projection["current_goal"]["statement"] = (
            "This immutable projection was rewritten."
        )
        projection.pop("completeness_basis")
        self._rewrite_projection(projection_path, manifest_path, projection)
        self._git_commit_all("rewrite projection")

        codes = self.codes(compare_ref=baseline)
        self.assertIn(
            "PROJECTION_APPEND_ONLY",
            codes,
        )
        self.assertIn(
            "PROJECTION_COMPLETENESS_BASIS",
            codes,
        )

    def test_compare_ref_allows_immutable_legacy_projection_without_basis(
        self,
    ) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        projection.pop("completeness_basis")
        self._rewrite_projection(projection_path, manifest_path, projection)
        baseline = self._git_baseline()

        self.assertNotIn(
            "PROJECTION_COMPLETENESS_BASIS",
            self.codes(compare_ref=baseline),
        )

    def test_compare_ref_requires_basis_when_current_selects_legacy_projection(
        self,
    ) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        projection = validator.load_document(projection_path)
        projection.pop("completeness_basis")
        self._rewrite_projection(projection_path, manifest_path, projection)

        projected_manifest = validator.load_document(manifest_path)
        plain_manifest = json.loads(json.dumps(projected_manifest))
        plain_manifest.pop("memory_projection")
        plain_manifest["snapshot_id"] = "snap-alpha-plain"
        plain_manifest["transaction_id"] = "tx-alpha-plain"
        plain_manifest_path = (
            self.root
            / "tasks/task-alpha/versions/snap-alpha-plain.json"
        )
        dump_json_yaml(plain_manifest_path, plain_manifest)
        current_path = self.root / "tasks/task-alpha/CURRENT.json"
        current = validator.load_document(current_path)
        current["snapshot_id"] = "snap-alpha-plain"
        current["manifest_path"] = (
            "tasks/task-alpha/versions/snap-alpha-plain.json"
        )
        current["published_transaction_id"] = "tx-alpha-plain"
        dump_json_yaml(current_path, current)
        baseline = self._git_baseline()

        current["snapshot_id"] = "snap-alpha-0001"
        current["manifest_path"] = (
            "tasks/task-alpha/versions/snap-alpha-0001.json"
        )
        current["published_transaction_id"] = "tx-alpha-0001"
        dump_json_yaml(current_path, current)
        self._git_commit_all("select legacy projected successor")

        codes = self.codes(compare_ref=baseline)
        self.assertIn("PROJECTION_COMPLETENESS_BASIS", codes)
        self.assertIn("PROJECTION_SCOPE", codes)

    def test_compare_ref_requires_basis_on_new_successor_projection(
        self,
    ) -> None:
        projection_path, manifest_path = self._write_valid_projection()
        baseline = self._git_baseline()

        projection = validator.load_document(projection_path)
        projection["projection_id"] = "proj-alpha-0002"
        projection["basis"]["snapshot_id"] = "snap-alpha-0002"
        projection["basis"]["generation"] = 2
        projection["basis"]["transaction_id"] = "tx-alpha-0002"
        projection["basis"]["manifest_path"] = (
            "tasks/task-alpha/versions/snap-alpha-0002.json"
        )
        projection["basis"]["source_current_precondition"] = {
            "current_blob_sha": validator._git_blob_sha(
                self.root / "tasks/task-alpha/CURRENT.json"
            ),
            "snapshot_id": "snap-alpha-0001",
            "generation": 1,
            "transaction_id": "tx-alpha-0001",
        }
        projection.pop("completeness_basis")
        successor_projection_path = (
            self.root
            / "tasks/task-alpha/projections/proj-alpha-0002.json"
        )
        dump_json_yaml(successor_projection_path, projection)

        manifest = validator.load_document(manifest_path)
        manifest["snapshot_id"] = "snap-alpha-0002"
        manifest["generation"] = 2
        manifest["transaction_id"] = "tx-alpha-0002"
        manifest["parents"] = [
            {
                "kind": "version_snapshot",
                "snapshot_id": "snap-alpha-0001",
                "commit": baseline,
                "path": "tasks/task-alpha/versions/snap-alpha-0001.json",
            }
        ]
        manifest["memory_projection"] = {
            "projection_id": "proj-alpha-0002",
            "path": (
                "tasks/task-alpha/projections/proj-alpha-0002.json"
            ),
            "content_sha256": hashlib.sha256(
                successor_projection_path.read_bytes()
            ).hexdigest(),
        }
        successor_manifest_path = (
            self.root
            / "tasks/task-alpha/versions/snap-alpha-0002.json"
        )
        dump_json_yaml(successor_manifest_path, manifest)
        current_path = self.root / "tasks/task-alpha/CURRENT.json"
        current = validator.load_document(current_path)
        current["generation"] = 2
        current["snapshot_id"] = "snap-alpha-0002"
        current["manifest_path"] = (
            "tasks/task-alpha/versions/snap-alpha-0002.json"
        )
        current["published_transaction_id"] = "tx-alpha-0002"
        dump_json_yaml(current_path, current)
        self._git_commit_all("add successor without completeness basis")

        self.assertIn(
            "PROJECTION_COMPLETENESS_BASIS",
            self.codes(compare_ref=baseline),
        )

    def test_git_comparison_forbids_source_revision_rewrite(self) -> None:
        _projection_path, _manifest_path = self._write_valid_projection()
        baseline = self._git_baseline()

        revision_path = (
            self.root
            / "sources/src-alpha/revisions/rev-alpha-0001.json"
        )
        revision = validator.load_document(revision_path)
        revision["messages"][0]["text"] = "Rewritten source evidence."
        dump_json_yaml(revision_path, revision)
        self._git_commit_all("rewrite source revision")

        self.assertIn(
            "SOURCE_REVISION_APPEND_ONLY",
            self.codes(compare_ref=baseline),
        )

    def test_git_comparison_forbids_confirmed_binding_rewrite(self) -> None:
        self._write_valid_projection()
        baseline = self._git_baseline()

        binding_path = (
            self.root / "bindings/confirmed/bnd-source-alpha.yaml"
        )
        binding = validator.load_document(binding_path)
        binding["evidence"][0]["assertion"] = (
            "This confirmed binding was rewritten in place."
        )
        dump_json_yaml(binding_path, binding)
        self._git_commit_all("rewrite confirmed binding")

        self.assertIn(
            "BINDING_APPEND_ONLY",
            self.codes(compare_ref=baseline),
        )

    def test_git_comparison_allows_appended_source_revision(self) -> None:
        self._write_valid_projection()
        baseline = self._git_baseline()

        next_revision = {
            "schema_version": "conversation-export/v1",
            "source_id": "src-alpha",
            "title": "Appended source revision",
            "captured_at": "2026-07-28T09:00:00+08:00",
            "coverage": "partial",
            "included_content": ["user_messages"],
            "excluded_content": ["hidden_reasoning"],
            "messages": [
                {
                    "ordinal": 0,
                    "role": "user",
                    "text": "This is a newly appended source revision.",
                }
            ],
        }
        next_path = (
            self.root
            / "sources/src-alpha/revisions/rev-alpha-0002.json"
        )
        dump_json_yaml(next_path, next_revision)
        next_hash = hashlib.sha256(next_path.read_bytes()).hexdigest()

        source_path = self.root / "sources/src-alpha/SOURCE.json"
        source = validator.load_document(source_path)
        source["revisions"].append(
            {
                "revision_id": "rev-alpha-0002",
                "previous_revision_id": "rev-alpha-0001",
                "source_sequence": 1,
                "captured_at": "2026-07-28T09:00:00+08:00",
                "coverage": "partial",
                "content_ref": None,
                "content_sha256": next_hash,
                "redaction": {
                    "credentials_scanned": True,
                    "content_removed": False,
                },
            }
        )
        source["current_revision_id"] = "rev-alpha-0002"
        dump_json_yaml(source_path, source)
        self._git_commit_all("append source revision")

        codes = self.codes(compare_ref=baseline)
        self.assertNotIn("SOURCE_APPEND_ONLY", codes)
        self.assertNotIn("SOURCE_REVISION_APPEND_ONLY", codes)

    def test_git_comparison_makes_events_append_only(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "add", "."],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "baseline"],
            check=True,
        )
        baseline = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        path = self.root / "memory/events/evt-alpha-0001.yaml"
        event = validator.load_document(path)
        event["payload"]["decision"] = "rewritten in place"
        event["payload_sha256"] = validator.sha256_jcs(event["payload"])
        domain = dict(event)
        domain.pop("event_sha256")
        event["event_sha256"] = validator.sha256_jcs(domain)
        dump_json_yaml(path, event)
        subprocess.run(
            ["git", "-C", str(self.root), "add", "."],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "rewrite event"],
            check=True,
        )
        self.assertIn("EVENT_APPEND_ONLY", self.codes(compare_ref=baseline))

    def test_git_comparison_allows_a_new_event(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Vault Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "vault-test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "baseline"],
            check=True,
        )
        baseline = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

        dump_json_yaml(
            self.root / "memory/events/evt-alpha-0002.yaml",
            valid_event("evt-alpha-0002"),
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "append event"],
            check=True,
        )
        self.assertNotIn("EVENT_APPEND_ONLY", self.codes(compare_ref=baseline))


if __name__ == "__main__":
    unittest.main()
