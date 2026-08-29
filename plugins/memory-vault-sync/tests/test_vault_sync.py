from __future__ import annotations

import importlib.util
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import zipfile
from contextlib import closing
from unittest import mock
from pathlib import Path
from typing import Any, Mapping, Sequence


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
REPOSITORY_ATTRIBUTES = REPOSITORY_ROOT / ".gitattributes"
MODULE_PATH = (
    PLUGIN_ROOT / "scripts" / "memory_vault_runtime" / "core.py"
)
SPEC = importlib.util.spec_from_file_location("memory_vault_sync", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
vault_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault_sync
SPEC.loader.exec_module(vault_sync)


def run(arguments: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        arguments,
        cwd=str(cwd) if cwd else None,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise AssertionError(
            f"command failed ({result.returncode}): {arguments}\n{result.stderr}"
        )
    return result.stdout.strip()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n"
        ).encode("utf-8")
    )


def stub_runtime_bundle(version: str) -> dict[str, bytes]:
    """Build the fixed module inventory used by isolated updater fixtures."""

    return {
        "scripts/vault_sync.py": (
            f'VERSION = "{version}"\n'
        ).encode("utf-8"),
        "scripts/windows_launcher.ps1": b"verified windows runtime\n",
        "scripts/memory_vault_runtime/__init__.py": b"# package fixture\n",
        "scripts/memory_vault_runtime/bundle.py": b"# bundle fixture\n",
        "scripts/memory_vault_runtime/checkpoint.py": b"# checkpoint fixture\n",
        "scripts/memory_vault_runtime/chunks.py": b"# chunk fixture\n",
        "scripts/memory_vault_runtime/crypto_adapter.py": b"# crypto adapter fixture\n",
        "scripts/memory_vault_runtime/device_trust.py": b"# device trust fixture\n",
        "scripts/memory_vault_runtime/diagnostics.py": b"# diagnostics fixture\n",
        "scripts/memory_vault_runtime/encrypted_replication.py": b"# encrypted replication fixture\n",
        "scripts/memory_vault_runtime/memory_network.py": (
            b"# memory network fixture\n"
        ),
        "scripts/memory_vault_runtime/packs.py": b"# packs fixture\n",
        "scripts/memory_vault_runtime/retrieval.py": (
            b"# retrieval adapter fixture\n"
        ),
        "scripts/memory_vault_runtime/sharing.py": b"# sharing fixture\n",
        "scripts/memory_vault_runtime/signed_updates.py": (
            b"# signed update fixture\n"
        ),
        "scripts/memory_vault_runtime/transport.py": b"# transport fixture\n",
        "scripts/memory_vault_runtime/core.py": (
            f'VERSION = "{version}"\n'
        ).encode("utf-8"),
        "scripts/memory_vault_runtime/errors.py": b"# errors fixture\n",
        "scripts/memory_vault_runtime/graph_views.py": (
            b"# graph views fixture\n"
        ),
        "scripts/memory_vault_runtime/host_adapter.py": (
            b"# host adapter fixture\n"
        ),
        "scripts/memory_vault_runtime/privacy.py": b"# privacy fixture\n",
        "scripts/memory_vault_runtime/protocol.py": b"# protocol fixture\n",
    }


class VaultFixture:
    task_id = "task-alpha"
    binding_id = "bnd-alpha"
    lineage_id = "lineage-alpha"
    source_id = "src-existing-codex-task"
    source_binding_id = "bnd-existing-codex-task"
    source_session_id = "raw-source-session-91"
    default_session_id = "session-a"
    default_source_id = "src-default-workspace-session"
    default_source_binding_id = "bnd-default-workspace-session"

    def __init__(self, root: Path):
        self.root = root
        self.seed = root / "seed"
        self.remote = root / "remote.git"
        self.data = root / "plugin data"
        self.codex_home = root / "codex-home"
        self.sessions = self.codex_home / "sessions"
        self.drive = root / "Fake Drive"
        self.allowed = root / "工作区集合"
        self.workspace = self.allowed / "科研 项目 A"
        self.projectless = root / "无工作文件夹的对话"
        self._create_remote()
        self._create_drive()
        self._create_workspace(self.workspace)
        self.projectless.mkdir(parents=True)
        self.sessions.mkdir(parents=True)
        self.config = self._create_config()

    def session_log_path(self, session_id: str) -> Path:
        return (
            self.sessions
            / "2026"
            / "07"
            / "29"
            / f"rollout-2026-07-29T12-00-00-{session_id}.jsonl"
        )

    def write_session_log(
        self,
        session_id: str,
        *,
        user_text: str = (
            "核对当前任务的实际目标、决定理由、已完成成果和下一步。"
        ),
        assistant_text: str = (
            "已读取当前可见对话并逐项比较远端原始证据。"
        ),
        rollout_id: str | None = None,
    ) -> list[dict[str, Any]]:
        token = vault_sync.sha256_bytes(session_id.encode("utf-8"))[:16]
        user_record_id = f"msg-user-{token}"
        assistant_record_id = f"msg-assistant-{token}"
        turn_id = f"turn-{token}"
        records = [
            {
                "timestamp": "2026-07-29T12:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": rollout_id or session_id,
                    "session_id": session_id,
                    "timestamp": "2026-07-29T12:00:00Z",
                },
            },
            {
                "timestamp": "2026-07-29T12:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "developer",
                    "id": f"msg-developer-{token}",
                    "content": [
                        {
                            "type": "input_text",
                            "text": "Injected developer context is not visible.",
                        }
                    ],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": turn_id
                    },
                },
            },
            {
                "timestamp": "2026-07-29T12:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "id": f"msg-injected-user-{token}",
                    "content": [
                        {
                            "type": "input_text",
                            "text": "Injected ambient context is not a visible turn.",
                        }
                    ],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": turn_id
                    },
                },
            },
            {
                "timestamp": "2026-07-29T12:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "id": user_record_id,
                    "content": [
                        {"type": "input_text", "text": user_text}
                    ],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": turn_id
                    },
                },
            },
            {
                "timestamp": "2026-07-29T12:00:00Z",
                "type": "event_msg",
                "payload": {
                    "type": "user_message",
                    "message": user_text,
                },
            },
            {
                "timestamp": "2026-07-29T12:00:01Z",
                "type": "response_item",
                "payload": {
                    "type": "reasoning",
                    "id": f"reasoning-{token}",
                    "encrypted_content": "not-visible",
                },
            },
            {
                "timestamp": "2026-07-29T12:00:02Z",
                "type": "event_msg",
                "payload": {
                    "type": "agent_message",
                    "phase": "final_answer",
                    "message": assistant_text,
                },
            },
            {
                "timestamp": "2026-07-29T12:00:02Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "phase": "final_answer",
                    "id": assistant_record_id,
                    "content": [
                        {"type": "output_text", "text": assistant_text}
                    ],
                    "internal_chat_message_metadata_passthrough": {
                        "turn_id": turn_id
                    },
                },
            },
            {
                "timestamp": "2026-07-29T12:00:03Z",
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "id": f"tool-{token}",
                    "name": "ignored_tool",
                },
            },
        ]
        path = self.session_log_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            b"".join(
                (
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                for record in records
            )
        )
        return [
            {
                "ordinal": 0,
                "record_id": user_record_id,
                "turn_id": turn_id,
                "role": "user",
                "phase": None,
                "text": user_text,
            },
            {
                "ordinal": 1,
                "record_id": assistant_record_id,
                "turn_id": turn_id,
                "role": "assistant",
                "phase": "final_answer",
                "text": assistant_text,
            },
        ]

    def append_session_log_record(
        self,
        session_id: str,
        record: Mapping[str, Any],
    ) -> None:
        with self.session_log_path(session_id).open("ab") as stream:
            stream.write(
                (
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            )

    def _create_remote(self) -> None:
        self.seed.mkdir()
        run(["git", "init", "-b", "main"], self.seed)
        run(["git", "config", "user.name", "Fixture"], self.seed)
        run(["git", "config", "user.email", "fixture@localhost"], self.seed)
        shutil.copyfile(
            REPOSITORY_ATTRIBUTES,
            self.seed / ".gitattributes",
        )
        task = {
            "schema_version": "task/v2",
            "minimum_client_protocol": "content-evidence-routing-v1",
            "task_id": self.task_id,
            "display_title": "跨设备科研任务",
            "task_type": "semantic_task",
            "status": "active",
            "identity_status": "confirmed",
            "purpose": "验证跨设备继续点与候选保护。",
            "privacy": {
                "classification": "private",
                "credentials_allowed": False,
                "raw_runtime_database_allowed": False,
            },
            "migration": {
                "legacy_commit": "1" * 40,
                "legacy_task_path": f"tasks/{self.task_id}/TASK.yaml",
                "coverage": "partial",
            },
        }
        evidence_source_id = "src-task-alpha-evidence"
        evidence_revision_id = "rev-task-alpha-evidence"
        evidence_content_path = (
            f"sources/{evidence_source_id}/revisions/"
            f"{evidence_revision_id}.json"
        )
        evidence_conversation = {
            "schema_version": "conversation-export/v1",
            "source_id": evidence_source_id,
            "title": "Verified task-alpha conversation",
            "captured_at": "2026-07-28T00:00:00Z",
            "coverage": "partial",
            "included_content": ["visible conversation messages"],
            "excluded_content": ["hidden reasoning", "tool traces"],
            "messages": [
                {
                    "ordinal": 0,
                    "role": "user",
                    "text": "继续验证跨设备实验设计与候选保护。",
                },
                {
                    "ordinal": 1,
                    "role": "assistant",
                    "phase": "final_answer",
                    "text": "已完成当前基线，下一步继续实验设计。",
                },
            ],
        }
        write_json(
            self.seed / evidence_content_path,
            evidence_conversation,
        )
        manifest = {
            "schema_version": "task-version/v1",
            "snapshot_id": "snap-initial",
            "task_id": self.task_id,
            "generation": 1,
            "parents": [],
            "state": "published",
            "change_type": "metadata_import",
            "transaction_id": "tx-initial",
            "continuation_readiness": "partial",
            "artifacts": [],
            "conversation_sources": [
                {
                    "source_id": evidence_source_id,
                    "revision_id": evidence_revision_id,
                    "content_path": evidence_content_path,
                    "content_sha256": vault_sync.sha256_bytes(
                        (self.seed / evidence_content_path).read_bytes()
                    ),
                }
            ],
            "remaining_work": ["继续撰写实验设计。"],
            "open_questions": ["下一组对照如何设置？"],
            "coverage": {
                "artifacts": "not_catalogued",
                "conversation": "partial",
                "decisions": "partial",
            },
        }
        current = {
            "schema_version": "task-current/v1",
            "task_id": self.task_id,
            "generation": 1,
            "state": "active",
            "snapshot_id": "snap-initial",
            "manifest_path": f"tasks/{self.task_id}/versions/snap-initial.json",
            "continuation_readiness": "partial",
            "published_transaction_id": "tx-initial",
            "authority": {
                "strategy": "git-blob-sha-compare-and-swap",
                "timestamps_are_authoritative": False,
            },
        }
        binding = {
            "schema_version": "binding/v1",
            "binding_id": self.binding_id,
            "subject": {"kind": "workspace_lineage", "id": self.lineage_id},
            "targets": [
                {
                    "semantic_task_id": self.task_id,
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
                    "evidence_id": "evidence-test",
                    "kind": "user_confirmation",
                    "strength": "authoritative",
                }
            ],
            "created_at": "2026-07-28T00:00:00Z",
            "created_by": {"actor_kind": "user_action", "actor_id": "test-user"},
        }
        source_key = vault_sync.sha256_bytes(
            f"codex:{self.source_session_id}".encode("utf-8")
        )
        source = {
            "schema_version": "source/v1",
            "source_id": self.source_id,
            "source_type": "codex_task",
            "external_source_key_sha256": source_key,
            "source_instance_id": None,
            "visibility": "private",
            "sensitivity": "restricted",
            "current_revision_id": "rev-metadata-initial",
            "revisions": [
                {
                    "revision_id": "rev-metadata-initial",
                    "previous_revision_id": None,
                    "source_sequence": 0,
                    "captured_at": "2026-07-28T00:00:00Z",
                    "coverage": "partial",
                    "content_ref": None,
                    "content_sha256": None,
                    "redaction": {
                        "credentials_scanned": True,
                        "content_removed": True,
                        "reason": "Fixture identity metadata only.",
                    },
                }
            ],
            "created_at": "2026-07-28T00:00:00Z",
        }
        source_index = {
            "schema_version": "source-index/v1",
            "authority": "discovery_only",
            "sources": [
                {
                    "source_id": self.source_id,
                    "source_path": f"sources/{self.source_id}/SOURCE.json",
                }
            ],
        }
        source_binding = {
            "schema_version": "binding/v1",
            "binding_id": self.source_binding_id,
            "subject": {"kind": "source", "id": self.source_id},
            "targets": [
                {
                    "semantic_task_id": self.task_id,
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
            "confirmation_basis": vault_sync.SOURCE_ROUTE_CONFIRMATION_BASIS,
            "content_review_attestation": {
                "schema_version": (
                    vault_sync.SOURCE_ROUTE_CONTENT_ATTESTATION_SCHEMA
                ),
                "authority_epoch": vault_sync.SOURCE_ROUTE_AUTHORITY_EPOCH,
                "matching_policy_version": vault_sync.MATCHING_POLICY_VERSION,
                "source_id": self.source_id,
                "request_id": "route-fixture-source-binding",
                "review_nonce": "1" * 32,
                "reviewed_remote_commit_sha": "1" * 40,
                "candidate_set_sha256": "1" * 64,
                "selected_task_id": self.task_id,
                "remote_evidence_receipt_sha256": "2" * 64,
                "local_evidence_receipt_sha256": "3" * 64,
                "choice_sha256": "4" * 64,
                "decision_prompt_sha256": "5" * 64,
                "local_transcript_sha256": "6" * 64,
                "reviewed_turn_anchor_set_sha256": "7" * 64,
                "conversation_coverage": "full_visible_task",
                "confirmation_mode": "next_visible_numeric_choice",
            },
            "evidence": [
                {
                    "evidence_id": "evidence-source-test",
                    "kind": "user_confirmation",
                    "strength": "authoritative",
                }
            ],
            "created_at": "2026-07-28T00:00:00Z",
            "created_by": {"actor_kind": "user_action", "actor_id": "test-user"},
        }
        default_source = json.loads(json.dumps(source))
        default_source.update(
            {
                "source_id": self.default_source_id,
                "external_source_key_sha256": vault_sync.sha256_bytes(
                    f"codex:{self.default_session_id}".encode("utf-8")
                ),
                "current_revision_id": "rev-default-metadata",
            }
        )
        default_source["revisions"][0].update(
            {
                "revision_id": "rev-default-metadata",
            }
        )
        default_source_binding = json.loads(json.dumps(source_binding))
        default_source_binding.update(
            {
                "binding_id": self.default_source_binding_id,
                "subject": {
                    "kind": "source",
                    "id": self.default_source_id,
                },
            }
        )
        default_source_binding["content_review_attestation"][
            "source_id"
        ] = self.default_source_id
        default_source_binding["content_review_attestation"][
            "request_id"
        ] = "route-fixture-default-source"
        default_source_binding["evidence"][0][
            "evidence_id"
        ] = "evidence-default-source"
        source_index["sources"].append(
            {
                "source_id": self.default_source_id,
                "source_path": (
                    f"sources/{self.default_source_id}/SOURCE.json"
                ),
            }
        )
        task_index = {
            "schema_version": "task-index/v1",
            "authority": "discovery_only",
            "generated_from": "tasks/*/TASK.json",
            "tasks": [
                {
                    "task_id": self.task_id,
                    "task_type": task["task_type"],
                    "status": task["status"],
                    "current": f"tasks/{self.task_id}/CURRENT.json",
                }
            ],
        }
        write_json(self.seed / f"tasks/{self.task_id}/TASK.json", task)
        write_json(
            self.seed / f"tasks/{self.task_id}/versions/snap-initial.json",
            manifest,
        )
        write_json(self.seed / f"tasks/{self.task_id}/CURRENT.json", current)
        write_json(
            self.seed / f"bindings/confirmed/{self.binding_id}.json",
            binding,
        )
        write_json(
            self.seed
            / f"bindings/confirmed/{self.source_binding_id}.json",
            source_binding,
        )
        write_json(
            self.seed
            / f"bindings/confirmed/{self.default_source_binding_id}.json",
            default_source_binding,
        )
        write_json(self.seed / "tasks/INDEX.json", task_index)
        write_json(
            self.seed / f"sources/{self.source_id}/SOURCE.json",
            source,
        )
        write_json(
            self.seed / f"sources/{self.default_source_id}/SOURCE.json",
            default_source,
        )
        write_json(self.seed / "sources/INDEX.json", source_index)
        run(
            [
                "git",
                "add",
                "--",
                ".gitattributes",
                "tasks",
                "bindings",
                "sources",
            ],
            self.seed,
        )
        run(["git", "commit", "-m", "fixture baseline"], self.seed)
        run(["git", "clone", "--bare", str(self.seed), str(self.remote)])

    def _create_drive(self) -> None:
        self.drive.mkdir()
        write_json(
            self.drive / ".memory-vault-private.json",
            {
                "vault_id": "codex-memory-vault",
                "owner_only": True,
                "shared": False,
            },
        )

    def _create_workspace(self, workspace: Path) -> None:
        workspace.mkdir(parents=True)
        current_bytes = (
            self.seed / f"tasks/{self.task_id}/CURRENT.json"
        ).read_bytes()
        manifest_bytes = (
            self.seed / f"tasks/{self.task_id}/versions/snap-initial.json"
        ).read_bytes()
        current_blob = run(
            [
                "git",
                "hash-object",
                str(self.seed / f"tasks/{self.task_id}/CURRENT.json"),
            ]
        )
        identity = {
            "schema_version": "portable-workspace-identity/v1",
            "vault_id": "codex-memory-vault",
            "binding_id": self.binding_id,
            "semantic_task_id": self.task_id,
            "workspace_lineage_id": self.lineage_id,
            "binding_state": "confirmed",
            "base": {
                "snapshot_id": "snap-initial",
                "manifest_sha256": vault_sync.sha256_bytes(manifest_bytes),
                "current_blob_sha": current_blob,
                "transaction_id": "tx-initial",
            },
        }
        write_json(workspace / ".vault_identity.yaml", identity)

    def _create_config(self) -> dict[str, Any]:
        config = vault_sync.default_config()
        # Keep a v0.12-shaped local configuration available for the explicit
        # legacy-audit tests. Production defaults and loaded configs retire
        # these flags, while the runtime kill switch remains authoritative.
        config["matching"] = {
            "enabled": True,
            "auto_provisional": False,
            "auto_promote_after_consistency_check": False,
            "prompt_on_ambiguity": True,
            "policy_version": vault_sync.MATCHING_POLICY_VERSION,
        }
        config["matching"]["auto_provisional"] = True
        config["matching"]["auto_promote_after_consistency_check"] = True
        config["projection"] = {
            "enabled": False,
            "root": None,
            "materialize_missing": True,
        }
        # This large fixture exercises the quarantined v0.14 task-handoff
        # compatibility layer.  New runtime integration tests enable the
        # taskless memory network explicitly.
        config["sync"]["memory_network_enabled"] = False
        config["sync"]["legacy_task_handoff_enabled"] = True
        config["_test_mode"] = True
        profile = vault_sync._provider_profile(config)
        control = profile["control_plane"]
        control["driver"] = "git-local-test"
        config["adapter_configs"][control["adapter_config_ref"]].update(
            {
                "repo_url": str(self.remote),
                "branch": "main",
                "privacy_verifier": "test-local-v1",
                "expected_repository": None,
            }
        )
        store = profile["object_stores"][0]
        store["driver"] = "filesystem-test"
        config["adapter_configs"][store["adapter_config_ref"]] = {
            "root": str(self.drive),
        }
        config["privacy"]["allowed_roots"] = [str(self.allowed)]
        config["sync"]["artifact_mode"] = "declared-only"
        config["updates"]["enabled"] = False
        config["updates"]["auto_install"] = False
        vault_sync._refresh_provider_scope_fingerprints(config)
        config = vault_sync.validate_config(config)
        write_json(self.data / "config.json", config)
        return config

    def legacy_config(self) -> dict[str, Any]:
        control = vault_sync._control_plane_config(self.config)
        object_store = vault_sync._object_store_config(self.config)
        return {
            "schema_version": vault_sync.LEGACY_CONFIG_SCHEMA,
            "enabled": self.config["enabled"],
            "vault": {
                "vault_id": vault_sync.VAULT_ID,
                "repo_url": control["repo_url"],
                "branch": control["branch"],
                "expected_github_repository": control.get(
                    "expected_repository"
                ),
                "github_privacy_credential_host": control[
                    "credential_host"
                ],
            },
            "drive": {
                "backend": object_store["driver"],
                "root": object_store.get("root"),
                "credential_host": object_store["credential_host"],
            },
            "sync": json.loads(json.dumps(self.config["sync"])),
            "projection": json.loads(json.dumps(self.config["projection"])),
            "matching": json.loads(json.dumps(self.config["matching"])),
            "updates": json.loads(json.dumps(self.config["updates"])),
            "privacy": json.loads(json.dumps(self.config["privacy"])),
            "_test_mode": True,
        }

    def engine(self):
        return vault_sync.SyncEngine(self.config, self.data)

    def confirm_source_route(
        self,
        session_id: str,
        task_id: str | None = None,
    ) -> vault_sync.SourceIdentity:
        engine = self.engine()
        engine.git.ensure()
        selected_task_id = task_id or self.task_id
        seed = vault_sync.sha256_bytes(
            f"{session_id}:{selected_task_id}".encode("utf-8")
        )
        attestation = {
            "schema_version": (
                vault_sync.SOURCE_ROUTE_CONTENT_ATTESTATION_SCHEMA
            ),
            "authority_epoch": vault_sync.SOURCE_ROUTE_AUTHORITY_EPOCH,
            "matching_policy_version": vault_sync.MATCHING_POLICY_VERSION,
            "source_id": (
                f"src-codex-"
                f"{vault_sync._codex_source_key(session_id)[:32]}"
            ),
            "request_id": f"route-fixture-{seed[:24]}",
            "review_nonce": seed[:32],
            "reviewed_remote_commit_sha": engine.git.head_sha(),
            "candidate_set_sha256": seed,
            "selected_task_id": selected_task_id,
            "remote_evidence_receipt_sha256": seed,
            "local_evidence_receipt_sha256": seed,
            "choice_sha256": seed,
            "decision_prompt_sha256": seed,
            "local_transcript_sha256": seed,
            "reviewed_turn_anchor_set_sha256": seed,
            "conversation_coverage": "full_visible_task",
            "confirmation_mode": "next_visible_numeric_choice",
        }
        return engine._register_native_handoff_source(
            session_id,
            selected_task_id,
            "existing_adoption",
            content_review_attestation=attestation,
        )

    def session_input(
        self,
        session: str = "session-a",
        workspace: Path | None = None,
    ) -> dict[str, Any]:
        selected_workspace = workspace or self.workspace
        return {
            "session_id": session,
            "transcript_path": "/must/not/be/read",
            "cwd": str(selected_workspace),
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "test",
            "permission_mode": "default",
        }

    def prompt_input(
        self,
        session: str = "session-a",
        turn: str = "turn-a",
        prompt: str = "继续完成本任务，并保存今天的可靠进度。",
        workspace: Path | None = None,
    ) -> dict[str, Any]:
        return {
            "session_id": session,
            "turn_id": turn,
            "transcript_path": "/must/not/be/read",
            "cwd": str(workspace or self.workspace),
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
            "model": "test",
            "permission_mode": "default",
        }

    def stop_input(
        self,
        session: str = "session-a",
        turn: str = "turn-a",
        assistant: str = "已经完成本轮修改，下一步是复核对照设置。",
        workspace: Path | None = None,
    ) -> dict[str, Any]:
        return {
            "session_id": session,
            "turn_id": turn,
            "transcript_path": "/must/not/be/read",
            "cwd": str(workspace or self.workspace),
            "hook_event_name": "Stop",
            "last_assistant_message": assistant,
            "stop_hook_active": False,
            "model": "test",
            "permission_mode": "default",
        }

    def clone_remote(self, name: str = "inspect") -> Path:
        destination = self.root / name
        run(["git", "clone", str(self.remote), str(destination)])
        return destination

    def remote_head(self) -> str:
        return run(
            [
                "git",
                f"--git-dir={self.remote}",
                "rev-parse",
                "refs/heads/main",
            ]
        )

    def write_remote_json(
        self, repo_path: str, value: Mapping[str, Any], label: str
    ) -> str:
        clone = self.clone_remote(f"change-{label}")
        run(["git", "config", "user.name", "Fixture mutation"], clone)
        run(["git", "config", "user.email", "mutation@localhost"], clone)
        write_json(clone / repo_path, value)
        run(["git", "add", "--", repo_path], clone)
        run(["git", "commit", "-m", label], clone)
        run(["git", "push", "origin", "main"], clone)
        return run(["git", "rev-parse", "HEAD"], clone)

    def advance_remote(self, label: str = "external") -> bytes:
        clone = self.clone_remote(f"advance-{label}")
        run(["git", "config", "user.name", "Other device"], clone)
        run(["git", "config", "user.email", "other@localhost"], clone)
        parent = run(["git", "rev-parse", "HEAD"], clone)
        snapshot = f"snap-{label}"
        transaction = f"tx-{label}"
        manifest_path = f"tasks/{self.task_id}/versions/{snapshot}.json"
        manifest = {
            "schema_version": "task-version/v1",
            "snapshot_id": snapshot,
            "task_id": self.task_id,
            "generation": 2,
            "parents": [
                {
                    "kind": "version_snapshot",
                    "snapshot_id": "snap-initial",
                    "commit": parent,
                    "path": f"tasks/{self.task_id}/versions/snap-initial.json",
                }
            ],
            "state": "published",
            "change_type": "content_revision",
            "transaction_id": transaction,
            "continuation_readiness": "partial",
            "artifacts": [],
            "remaining_work": ["另一台设备已经推进。"],
            "open_questions": [],
            "coverage": {
                "artifacts": "not_catalogued",
                "conversation": "partial",
                "decisions": "partial",
            },
        }
        current = {
            "schema_version": "task-current/v1",
            "task_id": self.task_id,
            "generation": 2,
            "state": "active",
            "snapshot_id": snapshot,
            "manifest_path": manifest_path,
            "continuation_readiness": "partial",
            "published_transaction_id": transaction,
            "authority": {
                "strategy": "git-blob-sha-compare-and-swap",
                "timestamps_are_authoritative": False,
            },
        }
        write_json(clone / manifest_path, manifest)
        current_path = clone / f"tasks/{self.task_id}/CURRENT.json"
        write_json(current_path, current)
        expected = current_path.read_bytes()
        run(["git", "add", "--", manifest_path, f"tasks/{self.task_id}/CURRENT.json"], clone)
        run(["git", "commit", "-m", f"advance {label}"], clone)
        run(["git", "push", "origin", "main"], clone)
        return expected

    def link_conversation_to_current(
        self,
        messages: list[Mapping[str, Any]],
        label: str,
    ) -> str:
        clone = self.clone_remote(f"conversation-{label}")
        run(["git", "config", "user.name", "Conversation fixture"], clone)
        run(
            ["git", "config", "user.email", "conversation@localhost"],
            clone,
        )
        source_id = f"src-{label}"
        revision_id = f"rev-{label}"
        content_path = (
            f"sources/{source_id}/revisions/{revision_id}.json"
        )
        normalized_messages = []
        for ordinal, message in enumerate(messages):
            normalized = dict(message)
            normalized["ordinal"] = ordinal
            normalized_messages.append(normalized)
        conversation = {
            "schema_version": "conversation-export/v1",
            "source_id": source_id,
            "title": f"Conversation fixture {label}",
            "captured_at": "2026-07-29T08:00:00Z",
            "coverage": "partial",
            "included_content": ["visible conversation messages"],
            "excluded_content": ["hidden reasoning", "tool traces"],
            "messages": normalized_messages,
        }
        write_json(clone / content_path, conversation)
        raw = (clone / content_path).read_bytes()
        current = json.loads(
            (
                clone / f"tasks/{self.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest_path = str(current["manifest_path"])
        manifest = json.loads(
            (clone / manifest_path).read_text(encoding="utf-8")
        )
        references = list(manifest.get("conversation_sources", []))
        references.append(
            {
                "source_id": source_id,
                "revision_id": revision_id,
                "content_path": content_path,
                "content_sha256": vault_sync.sha256_bytes(raw),
            }
        )
        manifest["conversation_sources"] = references[-8:]
        manifest["coverage"]["conversation"] = "partial"
        write_json(clone / manifest_path, manifest)
        run(
            ["git", "add", "--", content_path, manifest_path],
            clone,
        )
        run(
            ["git", "commit", "-m", f"link conversation {label}"],
            clone,
        )
        run(["git", "push", "origin", "main"], clone)
        return content_path

    def install_split_topology(
        self,
        *,
        omit_raw_conversation_for: str | None = None,
    ) -> dict[str, str]:
        clone = self.clone_remote("install-split-topology")
        run(["git", "config", "user.name", "Topology fixture"], clone)
        run(["git", "config", "user.email", "topology@localhost"], clone)
        task_beta = "task-beta"
        task_gamma = "task-gamma"
        coordinator = "task-review-coordinator"
        split_source = "src-split-combined"
        event_id = "split-combined-three"

        def add_task(task_id: str, task_type: str, title: str) -> None:
            snapshot = f"snap-{task_id}"
            transaction = f"tx-{task_id}"
            manifest_path = f"tasks/{task_id}/versions/{snapshot}.json"
            source_id = f"src-evidence-{task_id}"
            revision_id = f"rev-evidence-{task_id}"
            content_path = (
                f"sources/{source_id}/revisions/{revision_id}.json"
            )
            conversation = {
                "schema_version": "conversation-export/v1",
                "source_id": source_id,
                "title": f"Verified evidence for {title}",
                "captured_at": "2026-07-29T00:00:00Z",
                "coverage": "partial",
                "included_content": ["visible conversation messages"],
                "excluded_content": ["hidden reasoning", "tool traces"],
                "messages": [
                    {
                        "ordinal": 0,
                        "role": "user",
                        "text": f"Continue the distinct scope of {title}.",
                    },
                    {
                        "ordinal": 1,
                        "role": "assistant",
                        "phase": "final_answer",
                        "text": f"The current outcome belongs only to {title}.",
                    },
                ],
            }
            conversation_sources: list[dict[str, Any]] = []
            if task_id != omit_raw_conversation_for:
                write_json(clone / content_path, conversation)
                conversation_sha = vault_sync.sha256_bytes(
                    (clone / content_path).read_bytes()
                )
                conversation_sources.append(
                    {
                        "source_id": source_id,
                        "revision_id": revision_id,
                        "content_path": content_path,
                        "content_sha256": conversation_sha,
                    }
                )
            write_json(
                clone / f"tasks/{task_id}/TASK.json",
                {
                    "schema_version": "task/v2",
                    "minimum_client_protocol": "content-evidence-routing-v1",
                    "task_id": task_id,
                    "display_title": title,
                    "task_type": task_type,
                    "status": "active",
                    "identity_status": "confirmed",
                    "purpose": f"Continue {title} independently.",
                    "privacy": {
                        "classification": "private",
                        "credentials_allowed": False,
                        "raw_runtime_database_allowed": False,
                    },
                    "migration": {
                        "legacy_commit": "2" * 40,
                        "legacy_task_path": f"tasks/{task_id}/TASK.yaml",
                        "coverage": "partial",
                    },
                },
            )
            write_json(
                clone / manifest_path,
                {
                    "schema_version": "task-version/v1",
                    "snapshot_id": snapshot,
                    "task_id": task_id,
                    "generation": 1,
                    "parents": [],
                    "state": "published",
                    "change_type": "metadata_import",
                    "transaction_id": transaction,
                    "continuation_readiness": "partial",
                    "artifacts": [],
                    "conversation_sources": conversation_sources,
                    "remaining_work": [f"Continue {title}."],
                    "open_questions": [],
                    "coverage": {
                        "artifacts": "not_catalogued",
                        "conversation": "partial",
                        "decisions": "partial",
                    },
                },
            )
            write_json(
                clone / f"tasks/{task_id}/CURRENT.json",
                {
                    "schema_version": "task-current/v1",
                    "task_id": task_id,
                    "generation": 1,
                    "state": "active",
                    "snapshot_id": snapshot,
                    "manifest_path": manifest_path,
                    "continuation_readiness": "partial",
                    "published_transaction_id": transaction,
                    "authority": {
                        "strategy": "git-blob-sha-compare-and-swap",
                        "timestamps_are_authoritative": False,
                    },
                },
            )

        add_task(task_beta, "semantic_task", "Second child task")
        add_task(task_gamma, "semantic_task", "Third child task")
        add_task(coordinator, "portfolio_coordinator", "Review coordinator")
        for task_id, suffix in ((task_beta, "beta"), (task_gamma, "gamma")):
            write_json(
                clone / f"bindings/confirmed/bnd-workspace-{suffix}.json",
                {
                    "schema_version": "binding/v1",
                    "binding_id": f"bnd-workspace-{suffix}",
                    "subject": {
                        "kind": "workspace_lineage",
                        "id": f"lineage-{suffix}",
                    },
                    "targets": [
                        {
                            "semantic_task_id": task_id,
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
                            "evidence_id": f"evidence-workspace-{suffix}",
                            "kind": "user_confirmation",
                            "strength": "authoritative",
                        }
                    ],
                    "created_at": "2026-07-29T00:00:00Z",
                    "created_by": {
                        "actor_kind": "user_action",
                        "actor_id": "test-user",
                    },
                },
            )
        write_json(
            clone / f"sources/{split_source}/SOURCE.json",
            {
                "schema_version": "source/v1",
                "source_id": split_source,
                "source_type": "codex_task",
                "external_source_key_sha256": vault_sync.sha256_bytes(
                    b"codex:combined-local-task"
                ),
                "source_instance_id": None,
                "visibility": "private",
                "sensitivity": "restricted",
                "current_revision_id": "rev-metadata-split",
                "revisions": [
                    {
                        "revision_id": "rev-metadata-split",
                        "previous_revision_id": None,
                        "source_sequence": 0,
                        "captured_at": "2026-07-29T00:00:00Z",
                        "coverage": "partial",
                        "content_ref": None,
                        "content_sha256": None,
                        "redaction": {
                            "credentials_scanned": True,
                            "content_removed": True,
                            "reason": "Synthetic split source.",
                        },
                    }
                ],
                "created_at": "2026-07-29T00:00:00Z",
            },
        )
        write_json(
            clone / "bindings/confirmed/bnd-split-coordination.json",
            {
                "schema_version": "binding/v1",
                "binding_id": "bnd-split-coordination",
                "subject": {"kind": "source", "id": split_source},
                "targets": [
                    {
                        "semantic_task_id": coordinator,
                        "relation": "source_for",
                        "role": "coordination",
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
                        "evidence_id": "evidence-split-coordination",
                        "kind": "user_confirmation",
                        "strength": "authoritative",
                    }
                ],
                "created_at": "2026-07-29T00:00:00Z",
                "created_by": {
                    "actor_kind": "user_action",
                    "actor_id": "test-user",
                },
            },
        )
        write_json(
            clone / f"bindings/structural/{event_id}.json",
            {
                "schema_version": "structural-binding/v1",
                "structural_event_id": event_id,
                "event_type": "source_split",
                "source_id": split_source,
                "state": "confirmed",
                "historical_baseline": {"available": False, "value": None},
                "child_task_ids": [self.task_id, task_beta, task_gamma],
                "coordinator_task_id": coordinator,
                "policy": {
                    "source_may_continue": True,
                    "source_events_route_at_sync": True,
                    "child_progress_is_independent": True,
                    "latest_is_per_child": True,
                    "ui_interception_required": False,
                },
                "evidence": {"confirmation": "explicit_user"},
            },
        )
        index = json.loads(
            (clone / "tasks/INDEX.json").read_text(encoding="utf-8")
        )
        for task_id, task_type in (
            (task_beta, "semantic_task"),
            (task_gamma, "semantic_task"),
            (coordinator, "portfolio_coordinator"),
        ):
            index["tasks"].append(
                {
                    "task_id": task_id,
                    "task_type": task_type,
                    "status": "active",
                    "current": f"tasks/{task_id}/CURRENT.json",
                }
            )
        write_json(clone / "tasks/INDEX.json", index)
        run(
            [
                "git",
                "add",
                "--",
                "tasks",
                "bindings",
                "sources",
            ],
            clone,
        )
        run(["git", "commit", "-m", "install split topology"], clone)
        run(["git", "push", "origin", "main"], clone)

        projection_root = self.allowed / "接力任务"
        projection_root.mkdir()
        self.config["projection"] = {
            "enabled": True,
            "root": str(projection_root),
            "materialize_missing": True,
        }
        write_json(self.data / "config.json", self.config)
        return {
            "task_beta": task_beta,
            "task_gamma": task_gamma,
            "coordinator": coordinator,
            "source_id": split_source,
            "event_id": event_id,
            "projection_root": str(projection_root),
        }

    def install_confirmed_split_route_fixture(
        self,
        topology: Mapping[str, str],
        target_task_id: str,
        *,
        content_attested: bool = True,
    ) -> dict[str, Any]:
        """Install historical confirmed state without exercising the disabled CLI."""

        clone = self.clone_remote(
            f"fixture-confirmed-split-{target_task_id}"
        )
        run(["git", "config", "user.name", "Split route fixture"], clone)
        run(
            ["git", "config", "user.email", "split-route@localhost"],
            clone,
        )
        event_id = topology["event_id"]
        source_id = topology["source_id"]
        event_path = f"bindings/structural/{event_id}.json"
        event = json.loads(
            (clone / event_path).read_text(encoding="utf-8")
        )
        source = json.loads(
            (
                clone / f"sources/{source_id}/SOURCE.json"
            ).read_text(encoding="utf-8")
        )
        source_sequence_from = len(source["revisions"])
        route_key = vault_sync.sha256_bytes(
            f"{event_id}\0{source_id}\0{target_task_id}".encode("utf-8")
        )
        binding_id = f"bnd-split-route-{route_key[:32]}"
        binding_path = f"bindings/confirmed/{binding_id}.json"
        now = vault_sync.utc_now()
        binding = {
            "schema_version": "binding/v1",
            "binding_id": binding_id,
            "subject": {"kind": "source", "id": source_id},
            "targets": [
                {
                    "semantic_task_id": target_task_id,
                    "relation": "source_for",
                    "role": "primary",
                }
            ],
            "effective_range": {
                "source_sequence_from": source_sequence_from,
                "source_sequence_to": None,
            },
            "state": "confirmed",
            "confidence": "user_confirmed",
            "confirmation_basis": (
                vault_sync.SOURCE_ROUTE_CONFIRMATION_BASIS
                if content_attested
                else "user_confirmation"
            ),
            "evidence": [
                {
                    "evidence_id": (
                        f"evidence-split-route-{route_key[:24]}"
                    ),
                    "kind": "user_confirmation",
                    "strength": "authoritative",
                    "assertion": (
                        "Historical fixture for an already confirmed split route."
                    ),
                }
            ],
            "created_at": now,
            "created_by": {
                "actor_kind": "client",
                "actor_id": "memory-vault-sync",
            },
            "decision_event_id": event_id,
            "supersedes_binding_id": None,
        }
        if content_attested:
            binding["content_review_attestation"] = {
                "schema_version": (
                    vault_sync.SOURCE_ROUTE_CONTENT_ATTESTATION_SCHEMA
                ),
                "authority_epoch": vault_sync.SOURCE_ROUTE_AUTHORITY_EPOCH,
                "matching_policy_version": vault_sync.MATCHING_POLICY_VERSION,
                "source_id": source_id,
                "request_id": f"route-split-{route_key[:24]}",
                "review_nonce": route_key[:32],
                "reviewed_remote_commit_sha": "2" * 40,
                "candidate_set_sha256": route_key,
                "selected_task_id": target_task_id,
                "remote_evidence_receipt_sha256": route_key,
                "local_evidence_receipt_sha256": route_key,
                "choice_sha256": route_key,
                "decision_prompt_sha256": route_key,
                "local_transcript_sha256": route_key,
                "reviewed_turn_anchor_set_sha256": route_key,
                "conversation_coverage": "full_visible_task",
                "confirmation_mode": "next_visible_numeric_choice",
            }
        policy = dict(event["policy"])
        policy["continuation_route"] = {
            "state": "confirmed",
            "source_id": source_id,
            "target_task_id": target_task_id,
            "binding_id": binding_id,
            "source_sequence_from": source_sequence_from,
        }
        event["policy"] = policy
        write_json(clone / event_path, event)
        write_json(clone / binding_path, binding)
        run(["git", "add", "--", event_path, binding_path], clone)
        run(
            ["git", "commit", "-m", "install confirmed split route fixture"],
            clone,
        )
        run(["git", "push", "origin", "main"], clone)
        return {
            "binding_id": binding_id,
            "source_sequence_from": source_sequence_from,
        }


class RoutingArtifactExtractionTests(unittest.TestCase):
    def test_csv_uses_delimited_text_extractor(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="vault-routing-csv-extraction-"
        ) as temporary:
            artifact = Path(temporary) / "results.csv"
            artifact.write_text(
                "sample,condition,result\n"
                "A,control,unchanged\n"
                "B,treatment,improved\n",
                encoding="utf-8",
            )
            object_sha256 = vault_sync.sha256_bytes(artifact.read_bytes())

            profile, coverage, blocks, unavailable_reason = (
                vault_sync._extract_routing_artifact(
                    artifact,
                    object_sha256=object_sha256,
                    mime_type="text/csv",
                )
            )

        self.assertEqual(profile, "delimited-text-utf8/v1")
        self.assertEqual(coverage, "full")
        self.assertIsNone(unavailable_reason)
        self.assertTrue(blocks)
        self.assertTrue(all(block["kind"] == "row" for block in blocks))
        self.assertIn(
            '["sample","condition","result"]',
            [block["text"] for block in blocks],
        )

    def test_docx_external_hyperlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="vault-routing-docx-extraction-"
        ) as temporary:
            artifact = Path(temporary) / "linked-document.docx"
            with vault_sync.zipfile.ZipFile(
                artifact,
                "w",
                compression=vault_sync.zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr(
                    "[Content_Types].xml",
                    (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<Types xmlns="http://schemas.openxmlformats.org/'
                        'package/2006/content-types">'
                        '<Default Extension="rels" ContentType="application/'
                        'vnd.openxmlformats-package.relationships+xml"/>'
                        '<Default Extension="xml" '
                        'ContentType="application/xml"/>'
                        '<Override PartName="/word/document.xml" '
                        'ContentType="application/vnd.openxmlformats-'
                        'officedocument.wordprocessingml.document.main+xml"/>'
                        "</Types>"
                    ),
                )
                archive.writestr(
                    "_rels/.rels",
                    (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<Relationships xmlns="http://schemas.openxmlformats.org/'
                        'package/2006/relationships">'
                        '<Relationship Id="rId1" Type="http://schemas.openxml'
                        'formats.org/officeDocument/2006/relationships/'
                        'officeDocument" Target="word/document.xml"/>'
                        "</Relationships>"
                    ),
                )
                archive.writestr(
                    "word/document.xml",
                    (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                        'wordprocessingml/2006/main" '
                        'xmlns:r="http://schemas.openxmlformats.org/'
                        'officeDocument/2006/relationships">'
                        "<w:body><w:p>"
                        '<w:hyperlink r:id="rIdHyperlink">'
                        "<w:r><w:t>trusted offline body text</w:t></w:r>"
                        "</w:hyperlink>"
                        "</w:p></w:body></w:document>"
                    ),
                )
                archive.writestr(
                    "word/_rels/document.xml.rels",
                    (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<Relationships xmlns="http://schemas.openxmlformats.org/'
                        'package/2006/relationships">'
                        '<Relationship Id="rIdHyperlink" '
                        'Type="http://schemas.openxmlformats.org/'
                        'officeDocument/2006/relationships/hyperlink" '
                        'Target="https://example.invalid/must-not-open" '
                        'TargetMode="External"/>'
                        "</Relationships>"
                    ),
                )
            object_sha256 = vault_sync.sha256_bytes(artifact.read_bytes())

            network_error = AssertionError(
                "trusted DOCX extraction must never follow external links"
            )
            with (
                mock.patch.object(
                    vault_sync,
                    "open_verified_url",
                    side_effect=network_error,
                ) as verified_open,
                mock.patch.object(
                    vault_sync.urllib.request,
                    "urlopen",
                    side_effect=network_error,
                ) as raw_open,
            ):
                profile, coverage, blocks, unavailable_reason = (
                    vault_sync._extract_routing_artifact(
                        artifact,
                        object_sha256=object_sha256,
                        mime_type=(
                            "application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document"
                        ),
                    )
                )

            verified_open.assert_not_called()
            raw_open.assert_not_called()

        self.assertEqual(profile, "ooxml-docx-text/v1")
        self.assertEqual(coverage, "full")
        self.assertIsNone(unavailable_reason)
        self.assertTrue(blocks)
        extracted_text = "\n".join(str(block["text"]) for block in blocks)
        self.assertIn("trusted offline body text", extracted_text)
        self.assertNotIn("https://example.invalid", extracted_text)

    def test_frozen_shortlist_redownloads_only_selected_task_artifact(
        self,
    ) -> None:
        selected_task_id = "task-selected"
        unselected_task_id = "task-unselected"
        selected_content = b'{"candidate":"selected"}\n'
        unselected_content = b'{"candidate":"unselected"}\n'

        def artifact(
            task_id: str,
            content: bytes,
        ) -> Mapping[str, Any]:
            digest = vault_sync.sha256_bytes(content)
            return {
                "artifact_id": f"artifact-{task_id.removeprefix('task-')}",
                "display_name": f"{task_id}.json",
                "drive_file_id": f"drive-{task_id}",
                "drive_parent_id": "drive-parent-routing",
                "logical_path": f"results/{task_id}.json",
                "mime_type": "application/json",
                "role": "analysis-result",
                "sha256": digest,
                "size": len(content),
                "storage_mode": "full",
            }

        selected_artifact = artifact(
            selected_task_id,
            selected_content,
        )
        unselected_artifact = artifact(
            unselected_task_id,
            unselected_content,
        )
        selected_remote = types.SimpleNamespace(
            label=selected_task_id,
            manifest={"artifacts": [selected_artifact]},
        )
        unselected_remote = types.SimpleNamespace(
            label=unselected_task_id,
            manifest={"artifacts": [unselected_artifact]},
        )
        catalog = {
            selected_task_id: selected_remote,
            unselected_task_id: unselected_remote,
        }
        receipt_sha256 = {
            selected_task_id: "1" * 64,
            unselected_task_id: "2" * 64,
        }
        bundle_sha256 = {
            selected_task_id: "3" * 64,
            unselected_task_id: "4" * 64,
        }

        def review(
            task_id: str,
            remote_artifact: Mapping[str, Any],
        ) -> Mapping[str, Any]:
            return {
                "task_id": task_id,
                "verdict": "consistent",
                "remote_evidence_receipt_sha256": receipt_sha256[task_id],
                "artifact_pairs": [
                    {
                        "remote_artifact_id": remote_artifact[
                            "artifact_id"
                        ],
                        "remote_receipt_id": (
                            f"artx-{task_id.removeprefix('task-')}"
                        ),
                        "remote_bundle_sha256": bundle_sha256[task_id],
                    }
                ],
                "local_artifact_gaps": [],
                "uncompared_remote_artifacts": [],
                "dimension_matrix": [
                    {
                        "dimension": dimension,
                        "relation": "preserved",
                        "summary": f"Verified {dimension}.",
                    }
                    for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
                ],
            }

        local_review = {
            "candidate_reviews": [
                review(selected_task_id, selected_artifact),
                review(unselected_task_id, unselected_artifact),
            ]
        }
        local_review_sha256 = "5" * 64
        request = {
            "request_id": "request-two-reviewed-candidates",
            "review_nonce": "a" * 32,
            "remote_commit_sha": "b" * 40,
        }
        choice = {
            "shortlist_task_ids": [
                selected_task_id,
                unselected_task_id,
            ],
            "local_evidence_receipt_sha256": local_review_sha256,
            "evidence_receipt_sha256": receipt_sha256,
        }
        content_by_artifact_id = {
            selected_artifact["artifact_id"]: selected_content,
            unselected_artifact["artifact_id"]: unselected_content,
        }
        downloaded_artifact_ids: list[str] = []

        def download_and_verify(
            remote_artifact: Mapping[str, Any],
            destination: Path,
        ) -> None:
            artifact_id = str(remote_artifact["artifact_id"])
            downloaded_artifact_ids.append(artifact_id)
            destination.write_bytes(content_by_artifact_id[artifact_id])

        drive = types.SimpleNamespace(
            download_and_verify=mock.Mock(side_effect=download_and_verify)
        )

        def load_remote_receipt(
            _data_dir: Path,
            _request: Mapping[str, Any],
            remote: Any,
        ) -> tuple[Mapping[str, Any], str]:
            return {}, receipt_sha256[str(remote.label)]

        artifact_by_receipt_id = {
            "artx-selected": selected_artifact,
            "artx-unselected": unselected_artifact,
        }

        def load_artifact_bundle(
            _data_dir: Path,
            _request: Mapping[str, Any],
            receipt_id: str,
            **_scope: Any,
        ) -> tuple[Mapping[str, Any], str]:
            remote_artifact = artifact_by_receipt_id[receipt_id]
            task_id = (
                selected_task_id
                if receipt_id == "artx-selected"
                else unselected_task_id
            )
            return (
                {
                    "artifact_id": remote_artifact["artifact_id"],
                    "object_sha256": remote_artifact["sha256"],
                    "object_size": remote_artifact["size"],
                },
                bundle_sha256[task_id],
            )

        with tempfile.TemporaryDirectory(
            prefix="vault-frozen-shortlist-download-"
        ) as temporary:
            engine = types.SimpleNamespace(
                data_dir=Path(temporary),
                _drive=mock.Mock(return_value=drive),
                _artifact_store=mock.Mock(return_value=drive),
                _verified_routing_request=mock.Mock(
                    return_value=(
                        Path(temporary) / "request.json",
                        request,
                        catalog,
                    )
                ),
            )
            with (
                mock.patch.object(
                    vault_sync,
                    "_load_local_routing_review_receipt",
                    return_value=(local_review, local_review_sha256),
                ),
                mock.patch.object(
                    vault_sync,
                    "_load_routing_evidence_receipt",
                    side_effect=load_remote_receipt,
                ) as remote_receipt_loader,
                mock.patch.object(
                    vault_sync,
                    "_load_artifact_extraction_bundle",
                    side_effect=load_artifact_bundle,
                ) as artifact_bundle_loader,
            ):
                vault_sync._assert_frozen_routing_evidence(
                    engine,
                    request,
                    choice,
                    catalog,
                    remote_artifact_task_id=selected_task_id,
                )

                self.assertEqual(remote_receipt_loader.call_count, 2)
                artifact_bundle_loader.assert_called_once()
                self.assertEqual(
                    artifact_bundle_loader.call_args.args[2],
                    "artx-selected",
                )
                drive.download_and_verify.assert_called_once()
                self.assertEqual(
                    downloaded_artifact_ids,
                    [selected_artifact["artifact_id"]],
                )
                self.assertNotIn(
                    unselected_artifact["artifact_id"],
                    downloaded_artifact_ids,
                )

                remote_receipt_loader.reset_mock()
                artifact_bundle_loader.reset_mock()
                engine._drive.reset_mock()
                engine._artifact_store.reset_mock()
                drive.download_and_verify.reset_mock()
                downloaded_artifact_ids.clear()
                vault_sync._assert_frozen_routing_evidence(
                    engine,
                    request,
                    choice,
                    catalog,
                    remote_artifact_task_id=None,
                )

                self.assertEqual(remote_receipt_loader.call_count, 2)
                artifact_bundle_loader.assert_not_called()
                engine._drive.assert_not_called()
                engine._artifact_store.assert_not_called()
                drive.download_and_verify.assert_not_called()
                self.assertEqual(downloaded_artifact_ids, [])

                remote_receipt_loader.reset_mock()
                artifact_bundle_loader.reset_mock()
                engine._drive.reset_mock()
                engine._artifact_store.reset_mock()

                def download_replaced_object(
                    remote_artifact: Mapping[str, Any],
                    destination: Path,
                ) -> None:
                    downloaded_artifact_ids.append(
                        str(remote_artifact["artifact_id"])
                    )
                    destination.write_bytes(
                        b'{"candidate":"replaced after choice"}\n'
                    )

                drive.download_and_verify.side_effect = (
                    download_replaced_object
                )
                with self.assertRaisesRegex(
                    vault_sync.VerificationError,
                    "remote artifact changed after the routing choice",
                ):
                    vault_sync._assert_frozen_routing_evidence(
                        engine,
                        request,
                        choice,
                        catalog,
                        remote_artifact_task_id=selected_task_id,
                    )

                self.assertEqual(remote_receipt_loader.call_count, 2)
                artifact_bundle_loader.assert_called_once()
                drive.download_and_verify.assert_called_once()
                self.assertEqual(
                    downloaded_artifact_ids,
                    [selected_artifact["artifact_id"]],
                )
                self.assertNotIn(
                    unselected_artifact["artifact_id"],
                    downloaded_artifact_ids,
                )

    def test_remote_artifact_bundle_rejects_cross_candidate_scope(
        self,
    ) -> None:
        candidate_a_artifact_id = "artifact-shared-result"
        candidate_b_artifact_id = "artifact-shared-result"
        self.assertEqual(
            candidate_a_artifact_id,
            candidate_b_artifact_id,
        )

        with tempfile.TemporaryDirectory(
            prefix="vault-cross-candidate-artifact-"
        ) as temporary:
            root = Path(temporary)
            source = root / "candidate-b.json"
            source.write_text(
                '{"result":"verified candidate B content"}\n',
                encoding="utf-8",
            )
            content = source.read_bytes()
            object_sha256 = vault_sync.sha256_bytes(content)
            profile, coverage, blocks, unavailable_reason = (
                vault_sync._extract_routing_artifact(
                    source,
                    object_sha256=object_sha256,
                    mime_type="application/json",
                )
            )
            self.assertEqual(profile, "json-structure/v1")
            self.assertEqual(coverage, "full")
            self.assertTrue(blocks)
            self.assertIsNone(unavailable_reason)

            engine = types.SimpleNamespace(data_dir=root / "data")
            request = {
                "request_id": "request-cross-candidate-artifact",
                "review_nonce": "a" * 32,
                "remote_commit_sha": "b" * 40,
            }
            candidate_b_bundle = (
                vault_sync._write_artifact_extraction_bundle(
                    engine,
                    request=request,
                    source_kind="remote",
                    source_path=None,
                    task_id="task-b",
                    artifact_id=candidate_b_artifact_id,
                    role="analysis-result",
                    mime_type="application/json",
                    object_sha256=object_sha256,
                    object_size=len(content),
                    extractor_profile=profile,
                    coverage=coverage,
                    blocks=blocks,
                    unavailable_reason=unavailable_reason,
                )
            )

            loaded, _bundle_sha256 = (
                vault_sync._load_artifact_extraction_bundle(
                    engine.data_dir,
                    request,
                    candidate_b_bundle["receipt_id"],
                    expected_source_kind="remote",
                    expected_task_id="task-b",
                )
            )
            self.assertEqual(
                loaded["artifact_id"],
                candidate_a_artifact_id,
            )
            self.assertTrue(loaded["blocks"])
            with self.assertRaisesRegex(
                vault_sync.IdentityError,
                "belongs to another routing scope",
            ):
                vault_sync._load_artifact_extraction_bundle(
                    engine.data_dir,
                    request,
                    candidate_b_bundle["receipt_id"],
                    expected_source_kind="remote",
                    expected_task_id="task-a",
                )

            def descriptor(
                artifact_id: str,
                display_name: str,
                role: str,
                artifact_content: bytes,
            ) -> Mapping[str, Any]:
                digest = vault_sync.sha256_bytes(artifact_content)
                return {
                    "artifact_id": artifact_id,
                    "display_name": display_name,
                    "drive_file_id": f"drive-{artifact_id}",
                    "drive_parent_id": "drive-parent-disclosure",
                    "logical_path": f"results/{display_name}",
                    "mime_type": "application/json",
                    "role": role,
                    "sha256": digest,
                    "size": len(artifact_content),
                    "storage_mode": "full",
                }

            paired = descriptor(
                candidate_a_artifact_id,
                "paired-result.json",
                "analysis-result",
                content,
            )
            extra = descriptor(
                "artifact-unpaired-appendix",
                "unpaired-appendix.json",
                "appendix",
                b'{"appendix":"remote only"}\n',
            )
            disclosure = vault_sync._routing_choice_artifact_disclosures(
                types.SimpleNamespace(
                    manifest={"artifacts": [paired, extra]}
                ),
                {
                    "artifact_pairs": [
                        {
                            "remote_artifact_id": paired["artifact_id"],
                        }
                    ],
                    "local_artifact_gaps": [],
                    "uncompared_remote_artifacts": [
                        extra["artifact_id"],
                    ],
                    "dimension_matrix": [
                        {
                            "dimension": dimension,
                            "relation": "preserved",
                            "summary": f"Verified {dimension}.",
                        }
                        for dimension in (
                            vault_sync.ROUTING_ARTIFACT_DIMENSIONS
                        )
                    ],
                },
            )
            self.assertEqual(
                disclosure["uncompared_remote_artifact_count"],
                1,
            )
            self.assertEqual(
                disclosure["uncompared_remote_artifacts"],
                [
                    {
                        "artifact_id": extra["artifact_id"],
                        "display_name": extra["display_name"],
                        "role": extra["role"],
                        "sha256": extra["sha256"],
                        "size": extra["size"],
                    }
                ],
            )


class MemoryVaultSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="vault-sync-tests-")
        self.root = Path(self.temporary.name)
        self.previous_testing = os.environ.get("MEMORY_VAULT_SYNC_TESTING")
        self.previous_codex_home = os.environ.get("CODEX_HOME")
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        os.environ["CODEX_HOME"] = str(self.root / "codex-home")
        self.fixture = VaultFixture(self.root)

    def tearDown(self) -> None:
        if self.previous_testing is None:
            os.environ.pop("MEMORY_VAULT_SYNC_TESTING", None)
        else:
            os.environ["MEMORY_VAULT_SYNC_TESTING"] = self.previous_testing
        if self.previous_codex_home is None:
            os.environ.pop("CODEX_HOME", None)
        else:
            os.environ["CODEX_HOME"] = self.previous_codex_home
        self.temporary.cleanup()

    def network_engine(self, data: Path | None = None):
        config = json.loads(json.dumps(self.fixture.config))
        config["sync"]["memory_network_enabled"] = True
        config["sync"]["legacy_task_handoff_enabled"] = False
        selected_data = data or self.fixture.data
        if data is not None:
            write_json(selected_data / "config.json", config)
        return vault_sync.SyncEngine(config, selected_data)

    def host_request(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        request_id: str,
        adapter_id: str = "generic-stdio",
        host_family: str = "local-model",
    ):
        return vault_sync.host_adapter.validate_request(
            {
                "schema_version": "memory-vault-host-request/v1",
                "protocol_version": "1.0",
                "request_id": request_id,
                "operation": operation,
                "adapter": {
                    "id": adapter_id,
                    "version": "0.21.0",
                    "host_family": host_family,
                },
                "payload": dict(payload),
            }
        )

    def test_taskless_memory_network_is_the_production_default(self) -> None:
        config = vault_sync.default_config()
        self.assertNotIn("memory_network_enabled", config["sync"])
        self.assertNotIn("legacy_task_handoff_enabled", config["sync"])
        validated = vault_sync.validate_config(config)
        self.assertNotIn("memory_network_enabled", validated["sync"])
        self.assertNotIn("legacy_task_handoff_enabled", validated["sync"])
        self.assertNotIn("matching", validated)
        self.assertNotIn("projection", validated)
        engine = vault_sync.SyncEngine(validated, self.fixture.data)
        self.assertTrue(engine._memory_network_enabled())

    def test_cross_model_host_protocol_shares_one_taskless_vault(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["startup_pull"] = False
        claude_open = engine.host_adapter_request(
            self.host_request(
                "session.open",
                {"continuity_handle": None, "reason": "compact"},
                request_id="claude-open-001",
                adapter_id="claude-code",
                host_family="claude-code",
            )
        )
        claude_handle = claude_open["result"]["continuity_handle"]
        prompt = "跨模型共享规则：只传输新增的可见记忆。"
        claude_input = engine.host_adapter_request(
            self.host_request(
                "turn.input",
                {
                    "continuity_handle": claude_handle,
                    "turn_handle": None,
                    "visible_user_text": prompt,
                    "limit": 8,
                },
                request_id="claude-input-001",
                adapter_id="claude-code",
                host_family="claude-code",
            )
        )
        claude_turn = claude_input["result"]["turn_handle"]
        committed = engine.host_adapter_request(
            self.host_request(
                "turn.commit",
                {
                    "continuity_handle": claude_handle,
                    "turn_handle": claude_turn,
                    "outcome": "final",
                    "visible_user_text": prompt,
                    "visible_assistant_text": "这条共享规则已经可靠排队。",
                },
                request_id="claude-commit-001",
                adapter_id="claude-code",
                host_family="claude-code",
            )
        )
        self.assertEqual(committed["status"], "accepted_local")
        self.assertFalse(committed["result"]["network_accessed"])
        engine.flush_memory_network()

        gemini_open = engine.host_adapter_request(
            self.host_request(
                "session.open",
                {"continuity_handle": None, "reason": "compact"},
                request_id="gemini-open-001",
                adapter_id="gemini-cli",
                host_family="gemini-cli",
            )
        )
        gemini_input = engine.host_adapter_request(
            self.host_request(
                "turn.input",
                {
                    "continuity_handle": gemini_open["result"][
                        "continuity_handle"
                    ],
                    "turn_handle": None,
                    "visible_user_text": "跨模型共享规则是什么？",
                    "limit": 8,
                },
                request_id="gemini-input-001",
                adapter_id="gemini-cli",
                host_family="gemini-cli",
            )
        )
        context = gemini_input["result"]["evidence_context"]
        self.assertIn("只传输新增", context["text"])
        self.assertEqual(context["authority"], "none")
        self.assertFalse(context["instruction_eligible"])

        local_recall = engine.host_adapter_request(
            self.host_request(
                "memory.recall",
                {
                    "query": "新增可见记忆",
                    "limit": 8,
                    "maximum_context_bytes": 8192,
                },
                request_id="local-recall-001",
            )
        )
        self.assertIn(
            "只传输新增",
            local_recall["result"]["evidence_context"]["text"],
        )
        clone = self.fixture.clone_remote("inspect-cross-model-host-protocol")
        episode_bytes = b"\n".join(
            path.read_bytes()
            for path in (clone / "memory" / "episodes").glob("*/*.json")
        )
        for forbidden in (
            b"claude-code",
            b"gemini-cli",
            b"continuity_handle",
            b"turn_handle",
            b"task_id",
            b"project_id",
            b"model_id",
        ):
            self.assertNotIn(forbidden, episode_bytes)

    def test_host_request_and_turn_retries_are_exactly_idempotent(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["startup_pull"] = False
        opened_request = self.host_request(
            "session.open",
            {"continuity_handle": None, "reason": "compact"},
            request_id="retry-open-001",
        )
        opened = engine.host_adapter_request(opened_request)
        repeated_open = engine.host_adapter_request(opened_request)
        self.assertEqual(repeated_open["status"], "duplicate")
        self.assertEqual(
            repeated_open["result"]["continuity_handle"],
            opened["result"]["continuity_handle"],
        )
        with self.assertRaises(vault_sync.ConflictError):
            engine.host_adapter_request(
                self.host_request(
                    "session.open",
                    {
                        "continuity_handle": opened["result"][
                            "continuity_handle"
                        ],
                        "reason": "resume",
                    },
                    request_id="retry-open-001",
                )
            )

        prompt_request = self.host_request(
            "turn.input",
            {
                "continuity_handle": opened["result"]["continuity_handle"],
                "turn_handle": None,
                "visible_user_text": "精确幂等只接受相同内容。",
                "limit": 8,
            },
            request_id="retry-input-001",
        )
        prompted = engine.host_adapter_request(prompt_request)
        repeated_prompt = engine.host_adapter_request(prompt_request)
        self.assertEqual(repeated_prompt["status"], "duplicate")
        turn_handle = prompted["result"]["turn_handle"]
        with self.assertRaises(vault_sync.ConflictError):
            engine.host_adapter_request(
                self.host_request(
                    "turn.input",
                    {
                        "continuity_handle": opened["result"][
                            "continuity_handle"
                        ],
                        "turn_handle": turn_handle,
                        "visible_user_text": "同一回合的不同内容必须拒绝。",
                        "limit": 8,
                    },
                    request_id="retry-input-conflict-001",
                )
            )

        commit_request = self.host_request(
            "turn.commit",
            {
                "continuity_handle": opened["result"]["continuity_handle"],
                "turn_handle": turn_handle,
                "outcome": "final",
                "visible_user_text": "精确幂等只接受相同内容。",
                "visible_assistant_text": "已按相同字节排队。",
            },
            request_id="retry-commit-001",
        )
        engine.host_adapter_request(commit_request)
        self.assertEqual(
            engine.host_adapter_request(commit_request)["status"],
            "duplicate",
        )
        with self.assertRaises(vault_sync.ConflictError):
            engine.host_adapter_request(
                self.host_request(
                    "turn.commit",
                    {
                        "continuity_handle": opened["result"][
                            "continuity_handle"
                        ],
                        "turn_handle": turn_handle,
                        "outcome": "final",
                        "visible_user_text": "精确幂等只接受相同内容。",
                        "visible_assistant_text": "不同的最终内容。",
                    },
                    request_id="retry-commit-conflict-001",
                )
            )
        pending = list(
            (self.fixture.data / "memory-network" / "outbox" / "pending").glob(
                "*.json"
            )
        )
        self.assertEqual(len(pending), 1)
        receipt_bytes = b"".join(
            path.read_bytes()
            for path in (
                self.fixture.data / "state" / "host-adapter" / "receipts"
            ).glob("*.json")
        )
        self.assertNotIn(b"retry-input-001", receipt_bytes)
        self.assertNotIn("精确幂等".encode("utf-8"), receipt_bytes)

    def test_host_prompt_and_recall_are_strictly_network_free(self) -> None:
        engine = self.network_engine()
        opened = engine.host_adapter_request(
            self.host_request(
                "session.open",
                {"continuity_handle": None, "reason": "compact"},
                request_id="offline-open-001",
            )
        )
        network_error = AssertionError("prompt-time host protocol used network")
        with (
            mock.patch.object(engine.git, "ensure", side_effect=network_error),
            mock.patch.object(engine.git, "fetch", side_effect=network_error),
            mock.patch.object(
                vault_sync.PluginUpdater,
                "check",
                side_effect=network_error,
            ),
        ):
            prompted = engine.host_adapter_request(
                self.host_request(
                    "turn.input",
                    {
                        "continuity_handle": opened["result"][
                            "continuity_handle"
                        ],
                        "turn_handle": None,
                        "visible_user_text": "本地召回不得等待网络。",
                        "limit": 8,
                    },
                    request_id="offline-input-001",
                )
            )
            recalled = engine.host_adapter_request(
                self.host_request(
                    "memory.recall",
                    {
                        "query": "本地召回",
                        "limit": 8,
                        "maximum_context_bytes": 8192,
                    },
                    request_id="offline-recall-001",
                )
            )
        self.assertFalse(prompted["result"]["network_accessed"])
        self.assertFalse(recalled["result"]["network_accessed"])
        self.assertEqual(
            prompted["authority"],
            {
                "memory": "untrusted_historical_evidence",
                "instruction_eligible": False,
                "authorization_eligible": False,
                "execution_eligible": False,
                "policy_change_eligible": False,
                "current_user_input_precedence": True,
            },
        )

    def test_host_atomic_commit_and_abort_fail_closed(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["startup_pull"] = False
        opened = engine.host_adapter_request(
            self.host_request(
                "session.open",
                {"continuity_handle": None, "reason": "compact"},
                request_id="atomic-open-001",
            )
        )
        continuity = opened["result"]["continuity_handle"]
        atomic = engine.host_adapter_request(
            self.host_request(
                "turn.commit",
                {
                    "continuity_handle": continuity,
                    "turn_handle": None,
                    "outcome": "final",
                    "visible_user_text": "只有回合结束事件也能原子备份。",
                    "visible_assistant_text": "原子回合已进入本地队列。",
                },
                request_id="atomic-commit-001",
            )
        )
        self.assertRegex(atomic["result"]["turn_handle"], r"^mvt1_")
        recovered_abort = engine.host_adapter_request(
            self.host_request(
                "turn.abort",
                {
                    "continuity_handle": continuity,
                    "turn_handle": atomic["result"]["turn_handle"],
                    "reason": "unknown",
                },
                request_id="atomic-post-commit-abort-001",
            )
        )
        self.assertFalse(recovered_abort["result"]["aborted"])
        self.assertEqual(
            recovered_abort["result"]["terminal_state"], "committed"
        )
        staged = engine.host_adapter_request(
            self.host_request(
                "turn.input",
                {
                    "continuity_handle": continuity,
                    "turn_handle": None,
                    "visible_user_text": "这个回合随后被用户取消。",
                    "limit": 8,
                },
                request_id="abort-input-001",
            )
        )
        aborted_turn = staged["result"]["turn_handle"]
        engine.host_adapter_request(
            self.host_request(
                "turn.abort",
                {
                    "continuity_handle": continuity,
                    "turn_handle": aborted_turn,
                    "reason": "user_interrupt",
                },
                request_id="abort-turn-001",
            )
        )
        with self.assertRaises(vault_sync.ConflictError):
            engine.host_adapter_request(
                self.host_request(
                    "turn.commit",
                    {
                        "continuity_handle": continuity,
                        "turn_handle": aborted_turn,
                        "outcome": "final",
                        "visible_user_text": "这个回合随后被用户取消。",
                        "visible_assistant_text": "不应被保存。",
                    },
                    request_id="abort-commit-001",
                )
            )

    def test_host_protocol_rejects_ownership_authority_and_float_fields(
        self,
    ) -> None:
        base = {
            "schema_version": "memory-vault-host-request/v1",
            "protocol_version": "1.0",
            "request_id": "invalid-host-001",
            "operation": "memory.remember",
            "adapter": {
                "id": "generic-stdio",
                "version": "0.21.0",
                "host_family": "local-model",
            },
            "payload": {
                "proposal": {
                    "schema_version": "memory-network-semantic-proposal/v1",
                    "task_id": "forbidden",
                }
            },
        }
        with self.assertRaises(vault_sync.HostProtocolError):
            vault_sync.host_adapter.validate_request(base)
        floated = json.loads(json.dumps(base))
        floated["payload"] = {"proposal": {"weight": 0.5}}
        with self.assertRaises(vault_sync.HostProtocolError):
            vault_sync.host_adapter.validate_request(floated)
        native = json.loads(json.dumps(base))
        native["payload"] = {"proposal": {"conversation_id": "native"}}
        with self.assertRaises(vault_sync.HostProtocolError):
            vault_sync.host_adapter.validate_request(native)
        cancelled_commit = {
            "schema_version": "memory-vault-host-request/v1",
            "protocol_version": "1.0",
            "request_id": "invalid-cancelled-commit-001",
            "operation": "turn.commit",
            "adapter": base["adapter"],
            "payload": {
                "continuity_handle": "mvc1_" + "a" * 43,
                "turn_handle": "mvt1_" + "b" * 43,
                "outcome": "cancelled",
                "visible_user_text": "取消的回合不得形成长期记忆。",
                "visible_assistant_text": None,
            },
        }
        with self.assertRaises(vault_sync.HostProtocolError):
            vault_sync.host_adapter.validate_request(cancelled_commit)

    def test_device_trust_bootstrap_is_local_opaque_and_fail_closed(self) -> None:
        engine = self.network_engine()
        created = engine.initialize_device_trust_state(
            installation_fingerprint="install:mac",
            device_fingerprint="device:mac",
            public_key_fingerprint="key:mac",
        )
        state_path = self.fixture.data / "memory-network" / "device-trust.json"
        self.assertEqual(created["schema_version"], "memory-device-trust-status/v1")
        self.assertTrue(created["created"])
        self.assertEqual(created["device_fingerprints"], ["device:mac"])
        self.assertFalse(created["private_keys_present"])
        self.assertTrue(state_path.is_file())
        raw = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual(raw["schema_version"], "memory-device-trust/v1")
        self.assertNotIn("private_key", raw)
        self.assertEqual(
            engine.device_trust_status()["state_sha256"],
            created["state_sha256"],
        )
        with self.assertRaises(vault_sync.ConflictError):
            engine.initialize_device_trust_state(
                installation_fingerprint="install:mac",
                device_fingerprint="device:mac",
                public_key_fingerprint="key:mac",
            )
        with self.assertRaises(vault_sync.ConfigurationError):
            engine.initialize_device_trust_state(
                installation_fingerprint="install:mac",
                device_fingerprint="task-owner",
                public_key_fingerprint="key:other",
                state_path=self.fixture.data / "memory-network" / "other.json",
            )
        with self.assertRaises(vault_sync.PrivacyError):
            engine.device_trust_status(self.root / "outside-state.json")

    def test_old_binding_config_is_persistently_migrated_to_taskless(self) -> None:
        data_dir = self.root / "production-config"
        config = vault_sync.default_config()
        config["matching"] = {
            "enabled": True,
            "auto_provisional": False,
            "auto_promote_after_consistency_check": False,
            "prompt_on_ambiguity": True,
            "policy_version": vault_sync.MATCHING_POLICY_VERSION,
        }
        config["projection"] = {
            "enabled": False,
            "root": None,
            "materialize_missing": True,
        }
        config["sync"]["memory_network_enabled"] = True
        config["sync"]["legacy_task_handoff_enabled"] = False
        write_json(data_dir / "config.json", config)

        loaded = vault_sync.load_config(data_dir)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        persisted = json.loads(
            (data_dir / "config.json").read_text(encoding="utf-8")
        )
        for value in (loaded, persisted):
            self.assertNotIn("matching", value)
            self.assertNotIn("projection", value)
            self.assertNotIn("memory_network_enabled", value["sync"])
            self.assertNotIn("legacy_task_handoff_enabled", value["sync"])
        receipt = json.loads(
            (
                data_dir / "migration" / "taskless-config-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            receipt["removed_sections"], ["matching", "projection"]
        )

    def test_taskless_turn_publishes_immutable_memory_without_moving_task_current(
        self,
    ) -> None:
        engine = self.network_engine()
        before_current = engine.git.show_bytes(
            f"tasks/{self.fixture.task_id}/CURRENT.json"
        ) if engine.git.has_cache() else None
        started = engine.session_start(
            self.fixture.session_input(
                session="network-source-a",
                workspace=self.fixture.projectless,
            )
        )
        self.assertNotIn("systemMessage", started)
        if before_current is None:
            before_current = engine.git.show_bytes(
                f"tasks/{self.fixture.task_id}/CURRENT.json"
            )
        prompted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="network-source-a",
                turn="network-turn-a",
                prompt="记住：跨对话传输只读取新增提交，不能全库重扫。",
                workspace=self.fixture.projectless,
            )
        )
        context = prompted.get("hookSpecificOutput", {}).get(
            "additionalContext", ""
        )
        self.assertNotIn("unbound_pending_model", context)
        stopped = engine.stop(
            self.fixture.stop_input(
                session="network-source-a",
                turn="network-turn-a",
                assistant="已将增量接收设为记忆网络的默认传输方式。",
                workspace=self.fixture.projectless,
            )
        )
        self.assertNotIn("systemMessage", stopped)
        self.assertEqual(
            engine.git.show_bytes(f"tasks/{self.fixture.task_id}/CURRENT.json"),
            before_current,
        )
        clone = self.fixture.clone_remote("inspect-memory-network")
        episodes = list((clone / "memory" / "episodes").glob("*/*.json"))
        self.assertEqual(len(episodes), 1)
        episode = json.loads(episodes[0].read_text(encoding="utf-8"))
        serialized = json.dumps(episode, ensure_ascii=False)
        self.assertNotIn("task_id", serialized)
        self.assertNotIn("binding", serialized)
        self.assertNotIn("source_key_sha256", serialized)
        event_id = vault_sync.memory_network.episode_event_id(
            episode["source_id"], episode["episode_id"]
        )
        event_relative = vault_sync.memory_network.event_relative_path(event_id)
        event = json.loads(
            (clone / event_relative).read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn("semantic_task_ids", event)

    def test_second_client_retrieves_related_memory_without_binding_or_network_wait(
        self,
    ) -> None:
        first = self.network_engine()
        first.session_start(
            self.fixture.session_input(
                session="network-source-one",
                workspace=self.fixture.projectless,
            )
        )
        first.user_prompt_submit(
            self.fixture.prompt_input(
                session="network-source-one",
                turn="network-turn-one",
                prompt="独特规则：海蓝索引只处理远端新提交。",
                workspace=self.fixture.projectless,
            )
        )
        first.stop(
            self.fixture.stop_input(
                session="network-source-one",
                turn="network-turn-one",
                assistant="海蓝索引规则已经保存。",
                workspace=self.fixture.projectless,
            )
        )

        second_data = self.root / "second-network-client"
        second = self.network_engine(second_data)
        second.session_start(
            self.fixture.session_input(
                session="network-source-two",
                workspace=self.fixture.projectless,
            )
        )
        with mock.patch.object(
            second.git,
            "fetch",
            side_effect=AssertionError("prompt recall opened a network window"),
        ):
            recalled = second.user_prompt_submit(
                self.fixture.prompt_input(
                    session="network-source-two",
                    turn="network-turn-two",
                    prompt="海蓝索引的传输规则是什么？",
                    workspace=self.fixture.projectless,
                )
            )
        context = recalled["hookSpecificOutput"]["additionalContext"]
        self.assertIn("海蓝索引只处理远端新提交", context)
        self.assertIn("untrusted historical evidence", context)
        self.assertNotIn("unbound_pending_model", context)

    def test_memory_receive_uses_commit_delta_after_initial_index(self) -> None:
        first = self.network_engine()
        first.session_start(
            self.fixture.session_input(
                session="delta-source-one",
                workspace=self.fixture.projectless,
            )
        )
        first.user_prompt_submit(
            self.fixture.prompt_input(
                session="delta-source-one",
                turn="delta-turn-one",
                prompt="第一条增量记忆：紫杉游标已经建立。",
                workspace=self.fixture.projectless,
            )
        )
        first.stop(
            self.fixture.stop_input(
                session="delta-source-one",
                turn="delta-turn-one",
                assistant="紫杉游标已保存。",
                workspace=self.fixture.projectless,
            )
        )
        second_data = self.root / "delta-second-client"
        second = self.network_engine(second_data)
        second.session_start(
            self.fixture.session_input(
                session="delta-reader",
                workspace=self.fixture.projectless,
            )
        )

        first.user_prompt_submit(
            self.fixture.prompt_input(
                session="delta-source-one",
                turn="delta-turn-two",
                prompt="第二条增量记忆：紫杉游标只读取新提交。",
                workspace=self.fixture.projectless,
            )
        )
        first.stop(
            self.fixture.stop_input(
                session="delta-source-one",
                turn="delta-turn-two",
                assistant="第二条紫杉规则已保存。",
                workspace=self.fixture.projectless,
            )
        )
        with mock.patch.object(
            second.git,
            "list_blob_paths",
            side_effect=AssertionError("incremental receive rescanned the tree"),
        ), mock.patch.object(
            second.git,
            "changed_paths_between",
            wraps=second.git.changed_paths_between,
        ) as changed:
            second.session_start(
                self.fixture.session_input(
                    session="delta-reader",
                    workspace=self.fixture.projectless,
                )
            )
        changed.assert_called()
        recalled = second.user_prompt_submit(
            self.fixture.prompt_input(
                session="delta-reader",
                turn="delta-reader-turn",
                prompt="紫杉游标后来新增了什么规则？",
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn(
            "紫杉游标只读取新提交",
            recalled["hookSpecificOutput"]["additionalContext"],
        )

    def test_memory_outbox_batches_multiple_turns_into_one_remote_commit(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.session_start(
            self.fixture.session_input(
                session="batch-source",
                workspace=self.fixture.projectless,
            )
        )
        before = engine.git.head_sha()
        for index in range(3):
            turn = f"batch-turn-{index}"
            engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session="batch-source",
                    turn=turn,
                    prompt=f"批量记忆片段 {index}：只发送新增对象。",
                    workspace=self.fixture.projectless,
                )
            )
            queued = engine.stop(
                self.fixture.stop_input(
                    session="batch-source",
                    turn=turn,
                    assistant=f"批量片段 {index} 已排队。",
                    workspace=self.fixture.projectless,
                )
            )
            self.assertIn("safely queued", queued.get("systemMessage", ""))
        engine.config["sync"]["stop_publish"] = True
        with vault_sync.FileLock(engine.lock_path):
            result = engine._publish_memory_network_batch()
        self.assertEqual(result["published"], 3)
        after = engine.git.head_sha()
        commit_count = int(
            run(
                [
                    "git",
                    f"--git-dir={self.fixture.remote}",
                    "rev-list",
                    "--count",
                    f"{before}..{after}",
                ]
            )
        )
        self.assertEqual(commit_count, 1)
        clone = self.fixture.clone_remote("inspect-batched-memory")
        self.assertEqual(
            len(list((clone / "memory" / "episodes").glob("*/*.json"))),
            3,
        )

    def test_memory_stop_retry_requires_identical_visible_content(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        session_id = "exact-stop-source"
        turn_id = "exact-stop-turn"
        prompt = "相同回合标识只能接受完全相同的可见内容。"
        assistant = "这条可见记忆已经可靠排队。"
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                turn=turn_id,
                prompt=prompt,
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session=session_id,
                turn=turn_id,
                assistant=assistant,
                workspace=self.fixture.projectless,
            )
        )
        transaction, state = engine._queue_memory_network_stop(
            self.fixture.stop_input(
                session=session_id,
                turn=turn_id,
                assistant=assistant,
                workspace=self.fixture.projectless,
            )
        )
        self.assertEqual(state, "pending")
        self.assertRegex(transaction, r"^tx-[0-9a-f]{32}$")
        with self.assertRaisesRegex(
            vault_sync.ConflictError,
            "different visible content",
        ):
            engine._queue_memory_network_stop(
                self.fixture.stop_input(
                    session=session_id,
                    turn=turn_id,
                    assistant="同一标识下被替换成了另一段内容。",
                    workspace=self.fixture.projectless,
                )
            )
        pending = list(
            (self.fixture.data / "memory-network" / "outbox" / "pending").glob(
                "*.json"
            )
        )
        self.assertEqual(len(pending), 1)

    def test_memory_stop_retry_repairs_crash_after_durable_intent(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        session_id = "crash-repair-source"
        turn_id = "crash-repair-turn"
        prompt = "持久意图写入后崩溃，重试必须修复会话游标。"
        assistant = "这条回合已经进入本地持久意图。"
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                turn=turn_id,
                prompt=prompt,
                workspace=self.fixture.projectless,
            )
        )
        session_path, before_session = engine._memory_session(session_id)
        original_write = vault_sync.atomic_write_json

        def crash_on_session_advance(path, value):
            if Path(path) == session_path:
                raise OSError("simulated crash after durable intent")
            return original_write(path, value)

        stop_input = self.fixture.stop_input(
            session=session_id,
            turn=turn_id,
            assistant=assistant,
            workspace=self.fixture.projectless,
        )
        with mock.patch.object(
            vault_sync,
            "atomic_write_json",
            side_effect=crash_on_session_advance,
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                engine._queue_memory_network_stop(stop_input)
        transaction, state = engine._queue_memory_network_stop(stop_input)
        self.assertEqual(state, "pending")
        repaired = json.loads(session_path.read_text(encoding="utf-8"))
        self.assertEqual(
            repaired["next_source_sequence"],
            before_session["next_source_sequence"] + 1,
        )
        self.assertRegex(repaired["last_episode_id"], r"^ep-[0-9a-f]{40}$")
        self.assertFalse(
            vault_sync._memory_network_prompt_path(
                self.fixture.data,
                vault_sync._session_key(
                    vault_sync._device_state(self.fixture.data), session_id
                ),
                vault_sync._turn_key(
                    vault_sync._device_state(self.fixture.data),
                    session_id,
                    turn_id,
                ),
            ).exists()
        )
        pending = list(
            (self.fixture.data / "memory-network" / "outbox" / "pending").glob(
                "*.json"
            )
        )
        self.assertEqual([path.stem for path in pending], [transaction])

    def test_memory_network_outbox_rejects_local_tampering(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="network-integrity",
                turn="turn-integrity",
                prompt="这条可见记忆需要完整性保护。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="network-integrity",
                turn="turn-integrity",
                assistant="记忆已安全排队。",
                workspace=self.fixture.projectless,
            )
        )
        pending = next(
            (
                self.fixture.data
                / "memory-network"
                / "outbox"
                / "pending"
            ).glob("*.json")
        )
        value = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(value["schema_version"], "memory-network-outbox/v2")
        self.assertRegex(value["integrity_hmac_sha256"], r"^[0-9a-f]{64}$")
        value["prompt"] = "本机篡改内容不得被发布。"
        write_json(pending, value)
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "integrity check failed",
        ):
            engine._pending_memory_network_intents()

    def test_legacy_memory_network_outbox_is_recovered_without_publication(
        self,
    ) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.session_start(
            self.fixture.session_input(
                session="legacy-network-outbox",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="legacy-network-outbox",
                turn="legacy-network-turn",
                prompt="旧版待发记忆只能保留恢复，不能代签发布。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="legacy-network-outbox",
                turn="legacy-network-turn",
                assistant="迁移前无法证明它没有被本机篡改。",
                workspace=self.fixture.projectless,
            )
        )
        pending = next(
            (
                self.fixture.data
                / "memory-network"
                / "outbox"
                / "pending"
            ).glob("*.json")
        )
        legacy = json.loads(pending.read_text(encoding="utf-8"))
        legacy["schema_version"] = "memory-network-outbox/v1"
        legacy.pop("integrity_hmac_sha256")
        legacy["prompt"] = "降级后的内容不得成为远端记忆。"

        legacy_with_extra = dict(legacy)
        legacy_with_extra["unexpected"] = True
        write_json(pending, legacy_with_extra)
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "outbox intent is invalid",
        ):
            engine._pending_memory_network_intents()
        self.assertEqual(
            json.loads(pending.read_text(encoding="utf-8"))["schema_version"],
            "memory-network-outbox/v1",
        )

        write_json(pending, legacy)
        original_raw = pending.read_bytes()
        before = self.fixture.remote_head()

        with vault_sync.FileLock(engine.lock_path):
            result = engine._publish_memory_network_batch()
        self.assertEqual(result, {"state": "idle", "published": 0})
        self.assertEqual(self.fixture.remote_head(), before)
        self.assertFalse(pending.exists())
        recovery = (
            self.fixture.data
            / "memory-network"
            / "outbox"
            / "recovery-v1"
        )
        recovered = recovery / pending.name
        self.assertEqual(recovered.read_bytes(), original_raw)
        receipt_path = recovery / pending.name.replace(
            ".json", ".receipt.json"
        )
        receipt_raw = receipt_path.read_bytes()
        receipt = json.loads(receipt_raw.decode("utf-8"))
        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "transaction_id",
                "recovered_filename",
                "recovered_sha256",
                "recovered_size",
                "source_schema",
                "disposition",
                "integrity_hmac_sha256",
            },
        )
        self.assertEqual(
            receipt["schema_version"],
            "memory-network-outbox-recovery-receipt/v1",
        )
        self.assertEqual(receipt["recovered_filename"], pending.name)
        self.assertEqual(receipt["recovered_sha256"], vault_sync.sha256_bytes(original_raw))
        self.assertEqual(receipt["recovered_size"], len(original_raw))
        self.assertEqual(receipt["disposition"], "preserved_not_publishable")
        self.assertNotIn("降级后的内容", receipt_raw.decode("utf-8"))
        signature = receipt.pop("integrity_hmac_sha256")
        device = vault_sync._device_state(self.fixture.data)
        expected_signature = hmac.new(
            str(device["device_secret"]).encode("ascii"),
            b"memory-network-outbox-recovery-receipt-v1\0"
            + vault_sync.jcs_json_bytes(receipt),
            hashlib.sha256,
        ).hexdigest()
        self.assertTrue(hmac.compare_digest(signature, expected_signature))
        clone = self.fixture.clone_remote("inspect-no-legacy-publication")
        remote_json = "\n".join(
            path.read_text(encoding="utf-8")
            for path in clone.rglob("*.json")
        )
        self.assertNotIn("降级后的内容不得成为远端记忆", remote_json)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "symlink"),
        "POSIX symlink regression; Windows rejects reparse parents in fallback",
    )
    def test_memory_network_outbox_rejects_linked_pending_parent(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="network-linked-parent",
                turn="network-linked-parent-turn",
                prompt="链接目录不能改变受控待发记录的读取位置。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="network-linked-parent",
                turn="network-linked-parent-turn",
                assistant="外部目录不能被读取或改写。",
                workspace=self.fixture.projectless,
            )
        )
        pending_dir = (
            self.fixture.data / "memory-network" / "outbox" / "pending"
        )
        pending = next(pending_dir.glob("*.json"))
        external = self.root / "external-network-outbox"
        external.mkdir()
        external_pending = external / pending.name
        pending.replace(external_pending)
        pending_dir.rmdir()
        pending_dir.symlink_to(external, target_is_directory=True)
        before = external_pending.read_bytes()

        with self.assertRaisesRegex(
            vault_sync.PrivacyError,
            "outbox directory could not be opened safely",
        ):
            engine._pending_memory_network_intents()
        self.assertEqual(external_pending.read_bytes(), before)

    def test_memory_network_stale_attempt_update_does_not_overwrite(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="network-stale-attempt",
                turn="network-stale-attempt-turn",
                prompt="旧快照不得覆盖后来出现的待发记录。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="network-stale-attempt",
                turn="network-stale-attempt-turn",
                assistant="重试写回必须比较原始字节。",
                workspace=self.fixture.projectless,
            )
        )
        selected = engine._pending_memory_network_intents()
        self.assertEqual(len(selected), 1)
        name, stale_raw, stale_intent = selected[0]
        pending = (
            self.fixture.data
            / "memory-network"
            / "outbox"
            / "pending"
            / name
        )
        replacement = dict(stale_intent)
        replacement["attempt_count"] = 17
        replacement.pop("integrity_hmac_sha256")
        replacement["integrity_hmac_sha256"] = (
            engine._memory_network_intent_signature(replacement)
        )
        write_json(pending, replacement)
        replacement_raw = pending.read_bytes()

        with vault_sync._MemoryNetworkOutbox(self.fixture.data) as outbox:
            with self.assertRaisesRegex(
                vault_sync.BusyError,
                "changed before retry update",
            ):
                engine._increment_memory_network_intent_attempt(
                    outbox,
                    name,
                    stale_raw,
                    stale_intent,
                )
        self.assertEqual(pending.read_bytes(), replacement_raw)
        persisted = json.loads(replacement_raw.decode("utf-8"))
        self.assertEqual(engine._validate_memory_network_intent(persisted), persisted)

    def test_memory_network_attempt_increment_is_resigned(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="network-attempt-integrity",
                turn="network-attempt-turn",
                prompt="失败重试也必须保持本地待发记录可验证。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="network-attempt-integrity",
                turn="network-attempt-turn",
                assistant="本次将模拟离线并保留待发项。",
                workspace=self.fixture.projectless,
            )
        )
        pending = next(
            (
                self.fixture.data
                / "memory-network"
                / "outbox"
                / "pending"
            ).glob("*.json")
        )
        before = json.loads(pending.read_text(encoding="utf-8"))
        with (
            mock.patch.object(
                engine.git,
                "ensure",
                side_effect=vault_sync.OfflineError("simulated offline"),
            ),
            self.assertRaises(vault_sync.OfflineError),
        ):
            engine._publish_memory_network_batch()

        retried = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(retried["attempt_count"], 1)
        self.assertNotEqual(
            retried["integrity_hmac_sha256"],
            before["integrity_hmac_sha256"],
        )
        self.assertEqual(
            engine._validate_memory_network_intent(retried), retried
        )

        retried["attempt_count"] = 2
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "integrity check failed",
        ):
            engine._validate_memory_network_intent(retried)

    def test_public_flush_command_only_publishes_memory_network(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.session_start(
            self.fixture.session_input(
                session="public-flush-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="public-flush-source",
                turn="public-flush-turn",
                prompt="公开 flush 只发送无任务归属的记忆对象。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="public-flush-source",
                turn="public-flush-turn",
                assistant="无任务归属的记忆已排队。",
                workspace=self.fixture.projectless,
            )
        )
        printed: list[Mapping[str, Any]] = []
        with (
            mock.patch.object(
                vault_sync,
                "load_config",
                return_value=engine.config,
            ),
            mock.patch.object(
                vault_sync,
                "SyncEngine",
                return_value=engine,
            ),
            mock.patch.object(
                vault_sync,
                "_print_json",
                side_effect=printed.append,
            ),
        ):
            exit_code = vault_sync.main(
                ["--data-dir", str(self.fixture.data), "flush"]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(printed), 1)
        self.assertEqual(
            printed[0]["schema_version"],
            "memory-network-flush/v1",
        )
        self.assertEqual(printed[0]["publication"]["published"], 1)
        self.assertNotIn("reconciliation", printed[0])

    def test_ordinary_memory_stop_uses_no_redundant_git_fetch(self) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="no-fetch-memory-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="no-fetch-memory-source",
                turn="no-fetch-memory-turn",
                prompt="普通记忆发送不应在 push 前后重复 fetch。",
                workspace=self.fixture.projectless,
            )
        )
        with mock.patch.object(
            engine.git,
            "fetch",
            side_effect=AssertionError("ordinary Stop performed a Git fetch"),
        ):
            stopped = engine.stop(
                self.fixture.stop_input(
                    session="no-fetch-memory-source",
                    turn="no-fetch-memory-turn",
                    assistant="普通发送只执行隐私证明和一次 push。",
                    workspace=self.fixture.projectless,
                )
            )
        self.assertNotIn("systemMessage", stopped)
        clone = self.fixture.clone_remote("inspect-no-fetch-memory")
        self.assertEqual(
            len(list((clone / "memory" / "episodes").glob("*/*.json"))),
            1,
        )

    def test_git_ensure_proves_repository_privacy_only_once(self) -> None:
        engine = self.network_engine()
        with mock.patch.object(
            engine.git,
            "assert_remote_private",
            wraps=engine.git.assert_remote_private,
        ) as privacy:
            engine.git.ensure()
        self.assertEqual(privacy.call_count, 1)

    def test_initial_git_ensure_does_not_fetch_after_clone(self) -> None:
        engine = self.network_engine(self.root / "initial-clone-client")
        with mock.patch.object(
            engine.git,
            "_fetch_after_privacy_proof",
            side_effect=AssertionError("initial clone performed a second fetch"),
        ):
            engine.git.ensure()
        self.assertEqual(engine.git.head_sha(), self.fixture.remote_head())

    def test_git_reads_memory_blobs_in_verified_batches(self) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="batch-read-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="batch-read-source",
                turn="batch-read-turn",
                prompt="批量读取必须逐个验证对象身份。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="batch-read-source",
                turn="batch-read-turn",
                assistant="批量对象已经写入。",
                workspace=self.fixture.projectless,
            )
        )
        listing = engine.git.list_blob_paths(
            ["memory/episodes", "memory/events"]
        )
        blobs = list(listing.values())
        self.assertGreaterEqual(len(blobs), 2)
        expected = {
            blob: engine.git.show_blob_bytes(blob) for blob in blobs
        }
        with mock.patch.object(
            engine.git,
            "_run_bare",
            wraps=engine.git._run_bare,
        ) as runner:
            observed = engine.git.show_blob_bytes_many(
                [*blobs, blobs[0]]
            )
        self.assertEqual(observed, expected)
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(
            sum("--batch" in command for command in commands),
            1,
        )
        self.assertEqual(
            sum(
                any(part.startswith("--batch-check=") for part in command)
                for command in commands
            ),
            1,
        )

    def test_initial_memory_receive_uses_bulk_blob_reads(self) -> None:
        writer = self.network_engine()
        writer.session_start(
            self.fixture.session_input(
                session="bulk-receive-writer",
                workspace=self.fixture.projectless,
            )
        )
        writer.user_prompt_submit(
            self.fixture.prompt_input(
                session="bulk-receive-writer",
                turn="bulk-receive-turn",
                prompt="首次接收应该批量读取松柏记忆。",
                workspace=self.fixture.projectless,
            )
        )
        writer.stop(
            self.fixture.stop_input(
                session="bulk-receive-writer",
                turn="bulk-receive-turn",
                assistant="松柏记忆已保存。",
                workspace=self.fixture.projectless,
            )
        )
        reader = self.network_engine(self.root / "bulk-receive-reader")
        with mock.patch.object(
            reader.git,
            "show_blob_bytes",
            side_effect=AssertionError(
                "initial receive spawned one Git reader per memory object"
            ),
        ):
            reader.session_start(
                self.fixture.session_input(
                    session="bulk-receive-reader",
                    workspace=self.fixture.projectless,
                )
            )
        recalled = reader.recall_memory("松柏记忆", limit=4)
        self.assertIn("松柏记忆", recalled["context"])

    def test_invalid_legacy_revision_is_excluded_without_blocking_network(
        self,
    ) -> None:
        writer = self.network_engine()
        writer.session_start(
            self.fixture.session_input(
                session="legacy-skip-writer",
                workspace=self.fixture.projectless,
            )
        )
        writer.user_prompt_submit(
            self.fixture.prompt_input(
                session="legacy-skip-writer",
                turn="legacy-skip-turn",
                prompt="新式海棠记忆不能被旧记录阻塞。",
                workspace=self.fixture.projectless,
            )
        )
        writer.stop(
            self.fixture.stop_input(
                session="legacy-skip-writer",
                turn="legacy-skip-turn",
                assistant="海棠记忆已经写入新网络。",
                workspace=self.fixture.projectless,
            )
        )
        clone = self.fixture.clone_remote("install-invalid-legacy")
        run(["git", "config", "user.name", "Legacy fixture"], clone)
        run(
            ["git", "config", "user.email", "legacy@localhost"],
            clone,
        )
        invalid = {
            "schema_version": "conversation-export/v1",
            "source_id": "src-invalid-legacy",
            "title": "Invalid legacy record",
            "captured_at": "2026-08-12T00:00:00Z",
            "coverage": "partial",
            "included_content": ["visible conversation messages"],
            "excluded_content": ["hidden reasoning"],
            "messages": [
                {
                    "ordinal": 9,
                    "role": "user",
                    "text": "This invalid legacy text must not be indexed.",
                }
            ],
        }
        invalid_path = (
            clone
            / "sources"
            / "src-invalid-legacy"
            / "revisions"
            / "rev-invalid-legacy.json"
        )
        write_json(invalid_path, invalid)
        run(["git", "add", "."], clone)
        run(["git", "commit", "-m", "add invalid legacy migration record"], clone)
        run(["git", "push", "origin", "main"], clone)

        reader = self.network_engine(self.root / "legacy-skip-reader")
        reader.git.ensure()
        received = reader._receive_memory_network()
        self.assertEqual(received["state"], "updated")
        self.assertEqual(received["skipped_legacy_revisions"], 1)
        recalled = reader.recall_memory("新式海棠记忆", limit=4)
        self.assertIn("海棠记忆", recalled["context"])
        excluded = reader.recall_memory("invalid legacy text", limit=4)
        self.assertNotIn("invalid legacy text", excluded.get("context") or "")

    def test_memory_publish_replays_once_after_concurrent_disjoint_advance(self) -> None:
        engine = self.network_engine()
        engine.config["sync"]["stop_publish"] = False
        engine.session_start(
            self.fixture.session_input(
                session="concurrent-memory-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="concurrent-memory-source",
                turn="concurrent-memory-turn",
                prompt="并发记忆对象可以交换顺序安全合并。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="concurrent-memory-source",
                turn="concurrent-memory-turn",
                assistant="并发增量已进入队列。",
                workspace=self.fixture.projectless,
            )
        )
        engine.config["sync"]["stop_publish"] = True
        original = engine.git.commit_and_push
        calls = 0

        def race_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.fixture.write_remote_json(
                    "coordination/concurrent-device.json",
                    {
                        "schema_version": "test-concurrent-note/v1",
                        "state": "advanced",
                    },
                    "concurrent-disjoint-advance",
                )
                raise vault_sync.VaultSyncError("non-fast-forward")
            return original(*args, **kwargs)

        with mock.patch.object(
            engine.git, "commit_and_push", side_effect=race_once
        ), vault_sync.FileLock(engine.lock_path):
            result = engine._publish_memory_network_batch()
        self.assertEqual(calls, 2)
        self.assertEqual(result["published"], 1)
        clone = self.fixture.clone_remote("inspect-concurrent-memory")
        self.assertEqual(
            len(list((clone / "memory" / "episodes").glob("*/*.json"))),
            1,
        )

    def test_complete_memory_network_bundle_transfers_without_task_binding(self) -> None:
        source = self.network_engine()
        source.session_start(
            self.fixture.session_input(
                session="portable-network-source",
                workspace=self.fixture.projectless,
            )
        )
        for index, phrase in enumerate(("珊瑚增量", "琥珀联想")):
            turn = f"portable-turn-{index}"
            source.user_prompt_submit(
                self.fixture.prompt_input(
                    session="portable-network-source",
                    turn=turn,
                    prompt=f"便携网络规则 {phrase} 必须保持。",
                    workspace=self.fixture.projectless,
                )
            )
            source.stop(
                self.fixture.stop_input(
                    session="portable-network-source",
                    turn=turn,
                    assistant=f"已保存 {phrase}。",
                    workspace=self.fixture.projectless,
                )
            )
        bundle = self.root / "portable-memory.network.zip"
        with mock.patch.object(
            source.git,
            "show_blob_bytes",
            side_effect=AssertionError(
                "memory export spawned one Git reader per object"
            ),
        ):
            exported = source.export_memory_network(bundle)
        self.assertEqual(exported["episodes"], 2)
        self.assertEqual(exported["events"], 2)
        self.assertGreaterEqual(exported["legacy_visible_revisions"], 1)
        self.assertNotIn("task_binding_included", exported)

        target_remote = self.root / "target-memory.git"
        run(["git", "clone", "--bare", str(self.fixture.seed), str(target_remote)])
        target_data = self.root / "target-memory-client"
        target_config = json.loads(json.dumps(self.fixture.config))
        target_config["sync"]["memory_network_enabled"] = True
        target_config["sync"]["legacy_task_handoff_enabled"] = False
        control = vault_sync._provider_profile(target_config)["control_plane"]
        target_config["adapter_configs"][control["adapter_config_ref"]][
            "repo_url"
        ] = str(target_remote)
        vault_sync._refresh_provider_scope_fingerprints(target_config)
        write_json(target_data / "config.json", target_config)
        target = vault_sync.SyncEngine(target_config, target_data)
        with mock.patch.object(
            target.git,
            "fetch",
            side_effect=AssertionError(
                "network import performed a redundant post-push fetch"
            ),
        ):
            imported = target.import_memory_network(bundle)
        self.assertEqual(imported["imported"], 4)
        self.assertEqual(
            imported["reused"], exported["legacy_visible_revisions"]
        )
        self.assertNotIn("task_binding_created", imported)
        repeated = target.import_memory_network(bundle)
        self.assertEqual(repeated["imported"], 0)
        self.assertEqual(repeated["reused"], exported["entries"])
        recalled = target.recall_memory("琥珀联想规则", limit=4)
        self.assertGreater(recalled["result_count"], 0)
        self.assertIn("琥珀联想", recalled["context"])

        # 0.15.4 used the local index contract name in the portable manifest.
        # The durable entries/profile did not change, so 0.16 must retain
        # import compatibility while new exports use the decoupled graph ID.
        with zipfile.ZipFile(bundle, "r") as archive:
            legacy_members = {
                info.filename: archive.read(info.filename)
                for info in archive.infolist()
            }
        legacy_manifest = json.loads(
            legacy_members["MANIFEST.json"].decode("utf-8")
        )
        self.assertEqual(
            legacy_manifest["network_contract"],
            "memory-network-graph/v1",
        )
        legacy_manifest["network_contract"] = "memory-network-index/v1"
        legacy_domain = dict(legacy_manifest)
        legacy_domain.pop("network_sha256")
        legacy_manifest["network_sha256"] = vault_sync.sha256_jcs(
            legacy_domain
        )
        legacy_members["MANIFEST.json"] = vault_sync.pretty_json_bytes(
            legacy_manifest
        )
        legacy_bundle = self.root / "portable-memory-0154.network.zip"
        with zipfile.ZipFile(
            legacy_bundle, "w", zipfile.ZIP_DEFLATED
        ) as archive:
            for name, raw in sorted(legacy_members.items()):
                archive.writestr(name, raw)
        legacy_import = target.import_memory_network(legacy_bundle)
        self.assertEqual(legacy_import["imported"], 0)
        self.assertEqual(legacy_import["reused"], exported["entries"])

    def test_selective_share_requires_external_provider_and_leaves_no_plaintext(self) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="selective-share-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="selective-share-source",
                turn="selective-share-turn",
                prompt="选择性加密分享必须只包含明确闭包。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="selective-share-source",
                turn="selective-share-turn",
                assistant="分享协议保持无任务归属。",
                workspace=self.fixture.projectless,
            )
        )
        episode_path = engine.git.list_paths("memory/episodes")[0]
        episode = engine.git.show_json(episode_path)
        selector = {
            "schema_version": "memory-share-selection/v1",
            "evidence_ids": [episode["episode_id"]],
            "claim_keys": [],
            "concepts": [],
            "captured_after": None,
            "captured_before": None,
        }
        output = self.root / "should-not-be-published.share.enc"
        with self.assertRaises(vault_sync.ConfigurationError):
            engine.share_memory_network(
                selector,
                output,
                recipient_fingerprint="recipient:test",
                key_epoch=1,
            )
        self.assertFalse(output.exists())
        self.assertEqual(list(self.fixture.data.glob(".memory-share-*.zip")), [])

    def test_ai_semantic_relation_supersedes_without_rewriting_old_memory(self) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="semantic-memory-source",
                workspace=self.fixture.projectless,
            )
        )
        for turn, prompt in (
            ("semantic-old", "同步策略暂定为每次扫描全部记忆。"),
            ("semantic-new", "同步策略改为只接收新增提交。"),
        ):
            engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session="semantic-memory-source",
                    turn=turn,
                    prompt=prompt,
                    workspace=self.fixture.projectless,
                )
            )
            engine.stop(
                self.fixture.stop_input(
                    session="semantic-memory-source",
                    turn=turn,
                    assistant="同步策略已记录。",
                    workspace=self.fixture.projectless,
                )
            )
        clone = self.fixture.clone_remote("inspect-semantic-source")
        episodes = sorted(
            (
                json.loads(path.read_text(encoding="utf-8"))
                for path in (clone / "memory" / "episodes").glob("*/*.json")
            ),
            key=lambda item: item["source_sequence"],
        )
        old_episode, new_episode = episodes

        def proposal(episode, statement, supersedes):
            return {
                "schema_version": "memory-network-semantic-proposal/v1",
                "source_id": episode["source_id"],
                "episode_id": episode["episode_id"],
                "kind": "decision",
                "claim_key": "sync-receive-policy",
                "parents": [],
                "supersedes": supersedes,
                "conflicts_with": [],
                "resolves": [],
                "payload": {"statement": statement},
            }

        missing_target = proposal(
            old_episode,
            "这条关系引用不存在的记忆",
            [],
        )
        missing_target["parents"] = ["evt-" + ("f" * 40)]
        before_missing = engine.git.head_sha()
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "target is missing or ambiguous",
        ):
            engine.record_semantic_memory(missing_target)
        self.assertEqual(engine.git.head_sha(), before_missing)

        with mock.patch.object(
            engine.git,
            "fetch",
            side_effect=AssertionError(
                "semantic memory performed a redundant post-push fetch"
            ),
        ):
            old_result = engine.record_semantic_memory(
                proposal(old_episode, "同步策略每次扫描全部记忆", [])
            )
        new_result = engine.record_semantic_memory(
            proposal(
                new_episode,
                "同步策略只接收新增提交",
                [old_result["memory_event_id"]],
            )
        )
        self.assertEqual(old_result["confidence"], "assistant_inferred")
        self.assertNotIn("task_binding_created", old_result)
        repeated = engine.record_semantic_memory(
            proposal(old_episode, "同步策略每次扫描全部记忆", [])
        )
        self.assertEqual(repeated["state"], "already_recorded")
        recalled = engine.recall_memory("同步接收策略", limit=16)
        statuses = {
            hit["event_id"]: hit["status"]
            for hit in recalled["hits"]
            if hit["event_id"]
            in {
                old_result["memory_event_id"],
                new_result["memory_event_id"],
            }
        }
        self.assertEqual(
            statuses[old_result["memory_event_id"]], "superseded"
        )
        self.assertEqual(statuses[new_result["memory_event_id"]], "current")
        clone_after = self.fixture.clone_remote("inspect-semantic-relations")
        old_path = (
            clone_after
            / "memory"
            / "episodes"
            / old_episode["episode_id"][3:5]
            / f"{old_episode['episode_id']}.json"
        )
        self.assertEqual(
            json.loads(old_path.read_text(encoding="utf-8")), old_episode
        )

    def test_memory_network_quarantines_secret_turn_without_remote_content(
        self,
    ) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="secret-memory-source",
                workspace=self.fixture.projectless,
            )
        )
        secret = "github_pat_" + ("A" * 32)
        prompted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="secret-memory-source",
                turn="secret-memory-turn",
                prompt=f"不要保存这个凭据 {secret}",
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn("was not queued", prompted.get("systemMessage", ""))
        stopped = engine.stop(
            self.fixture.stop_input(
                session="secret-memory-source",
                turn="secret-memory-turn",
                assistant=f"可见回复也包含 {secret}",
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn("was not transmitted", stopped.get("systemMessage", ""))
        clone = self.fixture.clone_remote("inspect-secret-memory-network")
        self.assertEqual(
            list((clone / "memory" / "episodes").glob("*/*.json")),
            [],
        )
        quarantines = list(
            (
                self.fixture.data
                / "memory-network"
                / "outbox"
                / "quarantine"
            ).glob("*.json")
        )
        self.assertEqual(len(quarantines), 1)
        quarantine_text = quarantines[0].read_text(encoding="utf-8")
        self.assertNotIn(secret, quarantine_text)
        self.assertIn('"content_preserved": false', quarantine_text)

    def test_semantic_memory_rejects_secret_payload_before_remote_write(
        self,
    ) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="semantic-secret-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="semantic-secret-source",
                turn="semantic-secret-turn",
                prompt="记录一个普通、可安全传输的决定。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="semantic-secret-source",
                turn="semantic-secret-turn",
                assistant="普通决定已经保存。",
                workspace=self.fixture.projectless,
            )
        )
        clone = self.fixture.clone_remote("inspect-semantic-secret-source")
        episode = json.loads(
            next((clone / "memory" / "episodes").glob("*/*.json")).read_text(
                encoding="utf-8"
            )
        )
        before = engine.git.head_sha()
        proposal = {
            "schema_version": "memory-network-semantic-proposal/v1",
            "source_id": episode["source_id"],
            "episode_id": episode["episode_id"],
            "kind": "decision",
            "claim_key": "secret-rejection-check",
            "parents": [],
            "supersedes": [],
            "conflicts_with": [],
            "resolves": [],
            "payload": {
                "statement": "github_pat_" + ("B" * 32),
            },
        }
        with self.assertRaises(vault_sync.PrivacyError):
            engine.record_semantic_memory(proposal)
        self.assertEqual(engine.git.head_sha(), before)

    def test_incremental_receive_rejects_modified_immutable_episode(
        self,
    ) -> None:
        writer = self.network_engine()
        writer.session_start(
            self.fixture.session_input(
                session="immutable-writer",
                workspace=self.fixture.projectless,
            )
        )
        writer.user_prompt_submit(
            self.fixture.prompt_input(
                session="immutable-writer",
                turn="immutable-turn",
                prompt="不可变 episode 只能追加，不能修改。",
                workspace=self.fixture.projectless,
            )
        )
        writer.stop(
            self.fixture.stop_input(
                session="immutable-writer",
                turn="immutable-turn",
                assistant="不可变规则已保存。",
                workspace=self.fixture.projectless,
            )
        )
        reader_data = self.root / "immutable-reader-data"
        reader = self.network_engine(reader_data)
        reader.session_start(
            self.fixture.session_input(
                session="immutable-reader",
                workspace=self.fixture.projectless,
            )
        )
        accepted_head = reader._memory_index().remote_head()
        clone = self.fixture.clone_remote("mutate-immutable-episode")
        episode_path = next(
            (clone / "memory" / "episodes").glob("*/*.json")
        )
        relative = episode_path.relative_to(clone).as_posix()
        episode = json.loads(episode_path.read_text(encoding="utf-8"))
        episode["messages"][0]["text"] += " 已被恶意改写。"
        self.fixture.write_remote_json(
            relative,
            episode,
            "mutate-immutable-memory",
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "append-only remote memory was modified or removed",
        ):
            reader.session_start(
                self.fixture.session_input(
                    session="immutable-reader",
                    workspace=self.fixture.projectless,
                )
            )
        self.assertEqual(reader._memory_index().remote_head(), accepted_head)

    def test_incremental_receive_rejects_dangling_taskless_relation(
        self,
    ) -> None:
        writer = self.network_engine()
        writer.session_start(
            self.fixture.session_input(
                session="dangling-writer",
                workspace=self.fixture.projectless,
            )
        )
        writer.user_prompt_submit(
            self.fixture.prompt_input(
                session="dangling-writer",
                turn="dangling-turn",
                prompt="关联记忆不能指向不存在的关系节点。",
                workspace=self.fixture.projectless,
            )
        )
        writer.stop(
            self.fixture.stop_input(
                session="dangling-writer",
                turn="dangling-turn",
                assistant="闭合关系规则已保存。",
                workspace=self.fixture.projectless,
            )
        )
        reader = self.network_engine(self.root / "dangling-reader")
        reader.session_start(
            self.fixture.session_input(
                session="dangling-reader-session",
                workspace=self.fixture.projectless,
            )
        )
        accepted_head = reader._memory_index().remote_head()
        episode_path = writer.git.list_paths("memory/episodes")[0]
        episode = writer.git.show_json(episode_path)
        missing_target = "evt-" + ("f" * 40)
        payload = {
            "profile": "memory-network-semantic/v1",
            "claim": {"statement": "悬空关系应被拒绝。"},
        }
        identity_domain = {
            "source_id": episode["source_id"],
            "episode_id": episode["episode_id"],
            "kind": "decision",
            "claim_key": "dangling-relation-rejection",
            "parents": [missing_target],
            "supersedes": [],
            "conflicts_with": [],
            "resolves": [],
            "payload": payload,
        }
        event_id = "evt-" + vault_sync.sha256_jcs(identity_domain)[:40]
        event = {
            "schema_version": "memory-event/v2",
            "memory_event_id": event_id,
            "kind": "decision",
            "confidence": "assistant_inferred",
            "source": {
                "source_id": episode["source_id"],
                "revision_id": episode["episode_id"],
                "source_sequence": episode["source_sequence"],
                "evidence_anchor_sha256": episode["episode_sha256"],
            },
            "claim_key": "dangling-relation-rejection",
            "parents": [missing_target],
            "supersedes": [],
            "conflicts_with": [],
            "resolves": [],
            "payload": payload,
            "payload_sha256": vault_sync.sha256_jcs(payload),
            "hash_profile": "jcs-rfc8785+sha256/event-v2",
            "created_at": "2026-08-12T00:00:00Z",
        }
        event["event_sha256"] = vault_sync.sha256_jcs(event)
        self.fixture.write_remote_json(
            f"memory/events/{event_id[4:6]}/{event_id}.json",
            event,
            "inject-dangling-taskless-relation",
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "missing relation target",
        ):
            reader.session_start(
                self.fixture.session_input(
                    session="dangling-reader-session",
                    workspace=self.fixture.projectless,
                )
            )
        self.assertEqual(reader._memory_index().remote_head(), accepted_head)

    def test_incompatible_derived_index_is_preserved_and_rebuilt(
        self,
    ) -> None:
        writer = self.network_engine()
        writer.session_start(
            self.fixture.session_input(
                session="index-rebuild-writer",
                workspace=self.fixture.projectless,
            )
        )
        writer.user_prompt_submit(
            self.fixture.prompt_input(
                session="index-rebuild-writer",
                turn="index-rebuild-turn",
                prompt="雪松索引可以从远端不可变记忆重建。",
                workspace=self.fixture.projectless,
            )
        )
        writer.stop(
            self.fixture.stop_input(
                session="index-rebuild-writer",
                turn="index-rebuild-turn",
                assistant="雪松索引规则已保存。",
                workspace=self.fixture.projectless,
            )
        )
        reader_data = self.root / "index-rebuild-reader"
        reader = self.network_engine(reader_data)
        reader.session_start(
            self.fixture.session_input(
                session="index-rebuild-reader-session",
                workspace=self.fixture.projectless,
            )
        )
        index_path = vault_sync._memory_network_index_path(reader_data)
        with closing(sqlite3.connect(str(index_path))) as connection:
            connection.execute(
                "UPDATE metadata SET value = '1' WHERE key = 'schema_version'"
            )
            connection.commit()
        reader.session_start(
            self.fixture.session_input(
                session="index-rebuild-reader-session",
                workspace=self.fixture.projectless,
            )
        )
        recovered = list(
            (reader_data / "memory-network" / "recovery").glob(
                "index-*/memory-network-v1.sqlite3"
            )
        )
        self.assertEqual(len(recovered), 1)
        recalled = reader.recall_memory("雪松索引如何恢复", limit=4)
        self.assertIn("雪松索引", recalled["context"])

    def test_memory_bundle_rejects_tampering_and_path_traversal(self) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="bundle-negative-source",
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="bundle-negative-source",
                turn="bundle-negative-turn",
                prompt="便携包必须拒绝篡改和路径穿越。",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session="bundle-negative-source",
                turn="bundle-negative-turn",
                assistant="便携包负向规则已保存。",
                workspace=self.fixture.projectless,
            )
        )
        episode_path = engine.git.list_paths("memory/episodes")[0]
        episode = engine.git.show_json(episode_path)
        semantic = engine.record_semantic_memory(
            {
                "schema_version": "memory-network-semantic-proposal/v1",
                "source_id": episode["source_id"],
                "episode_id": episode["episode_id"],
                "kind": "decision",
                "claim_key": "portable-bundle-negative",
                "parents": [],
                "supersedes": [],
                "conflicts_with": [],
                "resolves": [],
                "payload": {"statement": "便携包关系必须闭合。"},
            }
        )
        bundle = self.root / "negative.memory-network.zip"
        engine.export_memory_network(bundle)
        with zipfile.ZipFile(bundle, "r") as archive:
            members = {
                info.filename: archive.read(info.filename)
                for info in archive.infolist()
            }
        manifest = json.loads(members["MANIFEST.json"].decode("utf-8"))
        first_path = manifest["entries"][0]["path"]

        def rewritten_bundle(
            destination: Path,
            old_path: str,
            new_path: str,
            value: Mapping[str, Any],
        ) -> None:
            rewritten_members = dict(members)
            rewritten_members.pop(old_path)
            raw = vault_sync.pretty_json_bytes(value)
            rewritten_members[new_path] = raw
            rewritten_manifest = json.loads(
                json.dumps(manifest, ensure_ascii=False)
            )
            for entry in rewritten_manifest["entries"]:
                if entry["path"] == old_path:
                    entry.update(
                        {
                            "path": new_path,
                            "sha256": vault_sync.sha256_bytes(raw),
                            "size": len(raw),
                        }
                    )
                    break
            else:
                raise AssertionError("bundle event entry is missing")
            rewritten_manifest["entries"].sort(
                key=lambda item: item["path"]
            )
            domain = dict(rewritten_manifest)
            domain.pop("network_sha256")
            rewritten_manifest["network_sha256"] = vault_sync.sha256_jcs(
                domain
            )
            rewritten_members["MANIFEST.json"] = (
                vault_sync.pretty_json_bytes(rewritten_manifest)
            )
            with zipfile.ZipFile(
                destination, "w", zipfile.ZIP_DEFLATED
            ) as archive:
                for name, member in sorted(rewritten_members.items()):
                    archive.writestr(name, member)

        semantic_path = next(
            entry["path"]
            for entry in manifest["entries"]
            if entry["path"].endswith(
                f"/{semantic['memory_event_id']}.json"
            )
        )
        semantic_event = json.loads(
            members[semantic_path].decode("utf-8")
        )
        legacy_event = json.loads(
            json.dumps(semantic_event, ensure_ascii=False)
        )
        legacy_event["schema_version"] = "memory-event/v1"
        legacy_event["semantic_task_ids"] = ["legacy-task"]
        legacy_event["hash_profile"] = "jcs-rfc8785+sha256/event-v1"
        legacy_domain = dict(legacy_event)
        legacy_domain.pop("event_sha256")
        legacy_event["event_sha256"] = vault_sync.sha256_jcs(legacy_domain)
        legacy_bundle = self.root / "legacy-event.memory-network.zip"
        rewritten_bundle(
            legacy_bundle,
            semantic_path,
            semantic_path,
            legacy_event,
        )
        with self.assertRaisesRegex(
            vault_sync.PrivacyError,
            "legacy task-scoped events",
        ):
            engine.import_memory_network(legacy_bundle)

        dangling_event = json.loads(
            json.dumps(semantic_event, ensure_ascii=False)
        )
        dangling_event["parents"] = ["evt-" + ("e" * 40)]
        identity_domain = {
            "source_id": dangling_event["source"]["source_id"],
            "episode_id": dangling_event["source"]["revision_id"],
            "kind": dangling_event["kind"],
            "claim_key": dangling_event["claim_key"],
            "parents": dangling_event["parents"],
            "supersedes": dangling_event["supersedes"],
            "conflicts_with": dangling_event["conflicts_with"],
            "resolves": dangling_event["resolves"],
            "payload": dangling_event["payload"],
        }
        dangling_id = "evt-" + vault_sync.sha256_jcs(identity_domain)[:40]
        dangling_event["memory_event_id"] = dangling_id
        dangling_domain = dict(dangling_event)
        dangling_domain.pop("event_sha256")
        dangling_event["event_sha256"] = vault_sync.sha256_jcs(
            dangling_domain
        )
        dangling_path = (
            f"memory/events/{dangling_id[4:6]}/{dangling_id}.json"
        )
        dangling_bundle = self.root / "dangling.memory-network.zip"
        rewritten_bundle(
            dangling_bundle,
            semantic_path,
            dangling_path,
            dangling_event,
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "relation is not self-contained",
        ):
            engine.import_memory_network(dangling_bundle)

        tampered = self.root / "tampered.memory-network.zip"
        tampered_members = dict(members)
        changed = bytearray(tampered_members[first_path])
        changed[-2] = changed[-2] ^ 1
        tampered_members[first_path] = bytes(changed)
        with zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, raw in sorted(tampered_members.items()):
                archive.writestr(name, raw)
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "entry hash is invalid",
        ):
            engine.import_memory_network(tampered)

        traversal = self.root / "traversal.memory-network.zip"
        traversal_manifest = json.loads(
            json.dumps(manifest, ensure_ascii=False)
        )
        traversal_manifest["entries"][0]["path"] = "../escape.json"
        domain = dict(traversal_manifest)
        domain.pop("network_sha256")
        traversal_manifest["network_sha256"] = vault_sync.sha256_jcs(domain)
        traversal_members = dict(members)
        unsafe_raw = traversal_members.pop(first_path)
        traversal_members["../escape.json"] = unsafe_raw
        traversal_members["MANIFEST.json"] = vault_sync.pretty_json_bytes(
            traversal_manifest
        )
        with zipfile.ZipFile(traversal, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, raw in sorted(traversal_members.items()):
                archive.writestr(name, raw)
        with self.assertRaises(vault_sync.PrivacyError):
            engine.import_memory_network(traversal)

        symlink = self.root / "symlink.memory-network.zip"
        with zipfile.ZipFile(symlink, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, raw in sorted(members.items()):
                archive.writestr(name, raw)
            link = zipfile.ZipInfo("memory/events/aa/evt-link.json")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "MANIFEST.json")
        with self.assertRaisesRegex(
            vault_sync.PrivacyError,
            "contains a symlink",
        ):
            engine.import_memory_network(symlink)

        compression_bomb = self.root / "compression-bomb.memory-network.zip"
        with zipfile.ZipFile(
            compression_bomb,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name, raw in sorted(members.items()):
                archive.writestr(name, raw)
            archive.writestr("memory/events/bomb.json", b"0" * 600_000)
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "compression ratio is unsafe",
        ):
            engine.import_memory_network(compression_bomb)

    def test_memory_pack_and_hash_checkpoint_round_trip(self) -> None:
        engine = self.network_engine()
        engine.session_start(
            self.fixture.session_input(
                session="pack-source",
                workspace=self.fixture.projectless,
            )
        )
        pack = self.root / "network.memory-pack"
        result = engine.pack_memory_network(pack)
        self.assertGreater(result["object_count"], 0)
        self.assertRegex(result["pack_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["object_root_sha256"], r"^[0-9a-f]{64}$")
        copied_pack = self.root / "copied.network.memory-pack"
        journal = self.root / "copied.network.memory-pack.journal"
        copied = engine.copy_memory_pack(pack, copied_pack, journal)
        self.assertTrue(copied["complete"])
        self.assertEqual(copied["source_bytes"], copied["copied_bytes"])
        self.assertEqual(pack.read_bytes(), copied_pack.read_bytes())
        imported = engine.import_memory_pack(pack)
        self.assertIn("imported", imported)
        checkpoint_path = self.root / "network.checkpoint.json"
        checkpoint_result = engine.checkpoint_memory_pack(
            pack,
            checkpoint_path,
            generation=1,
        )
        verified = engine.verify_network_checkpoint(checkpoint_path)
        self.assertTrue(verified["valid"])
        self.assertEqual(
            checkpoint_result["checkpoint_sha256"],
            verified["checkpoint_sha256"],
        )

    def test_production_rejects_reactivation_of_task_binding(self) -> None:
        config = vault_sync.default_config()
        config["sync"]["memory_network_enabled"] = False
        config["sync"]["legacy_task_handoff_enabled"] = True
        with self.assertRaisesRegex(
            vault_sync.ConfigurationError,
            "task binding is retired",
        ):
            vault_sync.validate_config(config)

    def test_network_status_and_doctor_expose_no_task_runtime(self) -> None:
        engine = self.network_engine()
        status = engine.status()
        self.assertNotIn("automatic_task_matching", status)
        self.assertNotIn("task_projection", status)
        self.assertNotIn("needs_authorization", status)
        self.assertNotIn("legacy_task_handoff", status["memory_network"])
        checks = {item["name"] for item in engine.doctor()["checks"]}
        self.assertIn("associative_memory_network", checks)
        self.assertNotIn("task_matching", checks)
        self.assertNotIn("task_projection", checks)

    @staticmethod
    def self_contained_five_layer_projection() -> dict[str, Any]:
        source_evidence = {
            "kind": "source_message",
            "source_id": "src-neutral-handoff",
            "revision_id": "rev-neutral-handoff",
            "source_sequence": 1,
            "revision_content_sha256": "a" * 64,
            "message_ordinal": 0,
            "evidence_anchor_sha256": "b" * 64,
        }
        artifact_evidence = {
            "kind": "artifact",
            "artifact_id": "artifact-neutral-manuscript",
            "sha256": "c" * 64,
        }
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
            "projection_id": "proj-neutral-five-layer",
            "authority": "rebuildable_task_handoff_cache",
            "basis": {
                "task_id": "neutral-five-layer-task",
                "snapshot_id": "snap-neutral-five-layer",
                "generation": 1,
                "transaction_id": "tx-neutral-five-layer",
                "manifest_path": (
                    "tasks/neutral-five-layer-task/versions/"
                    "snap-neutral-five-layer.json"
                ),
                "source_current_precondition": None,
            },
            "completeness": completeness,
            "current_goal": {
                "status": "active",
                "statement": (
                    "Prepare the current manuscript for Journal B without "
                    "reopening historical targets."
                ),
                "evidence": [source_evidence],
            },
            "scope_boundaries": {
                "in_scope": [
                    {
                        "boundary_id": "scope-current-manuscript",
                        "statement": "Revise only the current manuscript.",
                        "evidence": [source_evidence],
                    }
                ],
                "out_of_scope": [],
            },
            "unprojected_deltas": [],
            "reconciliation_receipts": [],
            "effective_claims": [
                {
                    "claim_id": "claim-current-journal",
                    "claim_key": "target-journal",
                    "kind": "decision",
                    "statement": (
                        "The current target is Journal B."
                    ),
                    "rationale": {
                        "status": "known",
                        "statement": (
                            "Its scope matches the verified process-engineering "
                            "focus of the manuscript."
                        ),
                        "evidence": [source_evidence],
                    },
                    "settled": True,
                    "superseded_claim_ids": [],
                    "reask_policy": "do_not_reask",
                    "evidence": [source_evidence],
                }
            ],
            "contested_claims": [],
            "superseded_claims": [],
            "rejected_options": [],
            "artifact_authorities": [
                {
                    "artifact_id": "artifact-neutral-manuscript",
                    "sha256": "c" * 64,
                    "purpose": "Current manuscript source.",
                    "role": "manuscript",
                    "authority_status": "current_authoritative",
                    "source_snapshot_id": "snap-neutral-five-layer",
                    "dependencies": [],
                    "verification": {
                        "status": "verified",
                        "checks": [
                            {
                                "check_id": "check-neutral-sha",
                                "kind": "sha256",
                                "result": "passed",
                                "evidence": [artifact_evidence],
                            },
                            {
                                "check_id": "check-neutral-size",
                                "kind": "size",
                                "result": "passed",
                                "evidence": [artifact_evidence],
                            },
                        ],
                        "evidence": [artifact_evidence],
                    },
                    "relations": [],
                }
            ],
            "unclassified_artifact_policy": (
                "reference_only_do_not_infer_from_filename_or_inventory"
            ),
            "completed": [],
            "in_progress": [
                {
                    "item_id": "progress-neutral-revision",
                    "statement": "The manuscript is being revised.",
                    "next_checkpoint": "Validate the final companion file.",
                    "evidence": [source_evidence],
                }
            ],
            "next_actions": [
                {
                    "action_id": "next-neutral-validation",
                    "statement": "Validate the final companion file.",
                    "depends_on_claim_ids": ["claim-current-journal"],
                    "evidence": [source_evidence],
                }
            ],
            "open_questions": [],
            "risks": [],
            "blocking_conflicts": [],
            "nonblocking_contradictions": [],
            "known_gaps": [],
            "evidence_index": [
                {
                    "entry_id": "evidence-neutral-handoff",
                    "topic": "Verified current goal and rationale.",
                    "references": [source_evidence],
                }
            ],
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

    def run_hook_process(
        self,
        event: str,
        payload: dict[str, Any],
        *,
        data_dir: Path | None = None,
    ) -> dict[str, Any]:
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(data_dir or self.fixture.data)
        environment["PLUGIN_ROOT"] = str(PLUGIN_ROOT)
        environment["MEMORY_VAULT_SYNC_TESTING"] = "1"
        process = subprocess.run(
            [sys.executable, str(MODULE_PATH), "hook", event],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        stderr = process.stderr.decode("utf-8", "replace")
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stderr, "")
        return json.loads(process.stdout.decode("utf-8", "strict"))

    def assert_source_lifecycle_does_not_write(self) -> None:
        baseline_head = self.fixture.remote_head()
        engine = self.fixture.engine()
        started = engine.session_start(
            self.fixture.session_input(
                session=self.fixture.source_session_id,
                workspace=self.fixture.projectless,
            )
        )
        self.assertNotIn("Generation:", json.dumps(started, ensure_ascii=False))
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=self.fixture.source_session_id,
                turn="source-rejected-turn",
                workspace=self.fixture.projectless,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session=self.fixture.source_session_id,
                turn="source-rejected-turn",
                workspace=self.fixture.projectless,
            )
        )
        self.assertEqual(self.fixture.remote_head(), baseline_head)

    def start_unbound_routing(
        self,
        *,
        session: str = "unbound-local-task",
        engine: Any | None = None,
        workspace: Path | None = None,
    ) -> tuple[Any, dict[str, Any], str]:
        active_engine = engine or self.fixture.engine()
        output = active_engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=workspace or self.fixture.projectless,
            )
        )
        device = vault_sync._device_state(self.fixture.data)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(record)
        assert record is not None
        return active_engine, output, str(record[1]["request_id"])

    @staticmethod
    def routing_decision_token(output: Mapping[str, Any]) -> str:
        specific = output.get("hookSpecificOutput")
        if not isinstance(specific, Mapping):
            raise AssertionError("routing hook context is missing")
        context = specific.get("additionalContext")
        if not isinstance(context, str) or not context.startswith(
            "MEMORY_VAULT_ROUTING "
        ):
            raise AssertionError("routing control payload is missing")
        payload = json.loads(
            context.removeprefix("MEMORY_VAULT_ROUTING ")
        )
        token = payload.get("user_decision_token")
        if not isinstance(token, str):
            raise AssertionError("routing decision token is missing")
        return token

    def record_local_routing_review(
        self,
        engine: Any,
        request_id: str,
        task_ids: Sequence[str],
        *,
        verdict: str = "consistent",
        artifacts: Mapping[str, Any] | None = None,
        reported_user_text: str | None = None,
        remove_session_log_before_review: bool = False,
        coverage: str = "full_visible_task",
        logged_rollout_id: str | None = None,
    ) -> Mapping[str, Any]:
        _request_path, request, catalog = engine._verified_routing_request(
            request_id
        )
        local_turns = self.fixture.write_session_log(
            str(request["session_id"]),
            rollout_id=logged_rollout_id,
        )
        if reported_user_text is not None:
            local_turns[0] = {
                **local_turns[0],
                "text": reported_user_text,
            }
        if remove_session_log_before_review:
            self.fixture.session_log_path(
                str(request["session_id"])
            ).unlink()
        remote_receipts: dict[str, Mapping[str, Any]] = {}
        for candidate_task_id in sorted(catalog):
            vault_sync.routing_candidate_evidence_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=candidate_task_id,
                ),
                engine,
            )
            remote_receipts[candidate_task_id] = json.loads(
                vault_sync._routing_evidence_receipt_path(
                    self.fixture.data,
                    request_id,
                    candidate_task_id,
                ).read_text(encoding="utf-8")
            )
        selected_task_ids = set(task_ids)
        artifact_document = (
            dict(artifacts)
            if artifacts is not None
            else {
                "disposition": "none_declared_for_task_identity",
                "extraction_receipt_ids": [],
            }
        )
        candidate_reviews: list[Mapping[str, Any]] = []
        for candidate_task_id in sorted(catalog):
            candidate_selected = candidate_task_id in selected_task_ids
            candidate_verdict = (
                verdict if candidate_selected else "contradictory"
            )
            receipt = remote_receipts[candidate_task_id]
            relation = (
                "preserved"
                if candidate_verdict != "contradictory"
                else "unrelated"
            )
            candidate_reviews.append(
                {
                    "task_id": candidate_task_id,
                    "verdict": candidate_verdict,
                    "local_turn_ordinals": [0, 1],
                    "remote_conversation_anchors": [
                        {
                            "source_id": anchor["source_id"],
                            "revision_id": anchor["revision_id"],
                            "message_ordinals": list(
                                range(len(anchor["message_roles"]))
                            ),
                        }
                        for anchor in receipt["conversation_anchors"]
                    ],
                    "contradictions": (
                        ["实际对话目标与候选任务冲突"]
                        if candidate_verdict == "contradictory"
                        else []
                    ),
                    "identity_assessment": (
                        "same_work_lineage"
                        if candidate_verdict == "consistent"
                        else (
                            "uncertain"
                            if candidate_verdict == "uncertain"
                            else "different_work"
                        )
                    ),
                    "version_assessment": "unknown",
                    "dimension_matrix": [
                        {
                            "dimension": dimension,
                            "relation": relation,
                            "local_anchor_ids": [],
                            "remote_anchor_ids": [],
                            "summary": (
                                "The verified visible conversations preserve "
                                "this semantic dimension."
                                if relation == "preserved"
                                else (
                                    "The verified visible conversations show "
                                    "that this dimension is unrelated."
                                )
                            ),
                        }
                        for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
                    ],
                    "artifact_pairs": [],
                    "local_artifact_gaps": [],
                    "rationale": (
                        "基于完整可见对话及已获取的远端内容证据。"
                    ),
                }
            )
        return vault_sync.record_local_routing_review_command(
            types.SimpleNamespace(
                request_id=request_id,
                review_document={
                    "schema_version": vault_sync.LOCAL_ROUTING_REVIEW_SCHEMA,
                    "request_id": request_id,
                    "source_session_id": request["session_id"],
                    "conversation": {
                        "coverage": coverage,
                        "omission_reason": (
                            None
                            if coverage == "full_visible_task"
                            else "The native API returned a bounded view."
                        ),
                        "turns": local_turns,
                    },
                    "artifacts": artifact_document,
                    "candidate_reviews": candidate_reviews,
                },
            ),
            engine,
        )

    def install_remote_routing_artifact(
        self,
        *,
        artifact_id: str,
        display_name: str,
        role: str,
        mime_type: str,
        content: bytes,
        additional_artifacts: Sequence[Mapping[str, Any]] = (),
        remote_user_text: str | None = None,
        remote_assistant_text: str | None = None,
    ) -> Mapping[str, Any]:
        artifact_inputs = [
            {
                "artifact_id": artifact_id,
                "display_name": display_name,
                "role": role,
                "mime_type": mime_type,
                "content": content,
            },
            *additional_artifacts,
        ]
        artifacts: list[dict[str, Any]] = []
        for item in artifact_inputs:
            item_content = item["content"]
            if not isinstance(item_content, bytes):
                raise AssertionError("routing artifact fixture content must be bytes")
            item_artifact_id = str(item["artifact_id"])
            item_display_name = str(item["display_name"])
            item_mime_type = str(item["mime_type"])
            source = (
                self.root
                / f"remote-{item_artifact_id}-{item_display_name}"
            )
            source.write_bytes(item_content)
            digest = vault_sync.sha256_bytes(item_content)
            verified = self.fixture.engine()._drive().upload_and_verify(
                source,
                digest,
                len(item_content),
                item_mime_type,
            )
            artifacts.append(
                {
                    "artifact_id": item_artifact_id,
                    "display_name": item_display_name,
                    "drive_file_id": verified.file_id,
                    "drive_parent_id": verified.parent_id,
                    "logical_path": f"results/{item_display_name}",
                    "mime_type": item_mime_type,
                    "role": str(item["role"]),
                    "sha256": digest,
                    "size": len(item_content),
                    "storage_mode": "full",
                }
            )

        clone = self.fixture.clone_remote(f"routing-{artifact_id}")
        run(["git", "config", "user.name", "Artifact fixture"], clone)
        run(
            ["git", "config", "user.email", "artifact@localhost"],
            clone,
        )
        current = json.loads(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest_path = str(current["manifest_path"])
        manifest = json.loads(
            (clone / manifest_path).read_text(encoding="utf-8")
        )
        manifest["artifacts"] = artifacts
        changed_paths = [manifest_path]
        if (
            remote_user_text is None
        ) != (
            remote_assistant_text is None
        ):
            raise AssertionError(
                "remote routing conversation fixture requires both visible turns"
            )
        if remote_user_text is not None:
            conversation_source = manifest["conversation_sources"][0]
            prior_conversation_path = str(
                conversation_source["content_path"]
            )
            conversation = json.loads(
                (clone / prior_conversation_path).read_text(encoding="utf-8")
            )
            conversation["messages"][0]["text"] = remote_user_text
            conversation["messages"][1]["text"] = remote_assistant_text
            revision_id = (
                "rev-routing-"
                + vault_sync.sha256_bytes(
                    (
                        artifact_id
                        + "\0"
                        + remote_user_text
                        + "\0"
                        + str(remote_assistant_text)
                    ).encode("utf-8")
                )[:24]
            )
            conversation_path = (
                f"sources/{conversation_source['source_id']}/revisions/"
                f"{revision_id}.json"
            )
            write_json(clone / conversation_path, conversation)
            conversation_source["revision_id"] = revision_id
            conversation_source["content_path"] = conversation_path
            conversation_source["content_sha256"] = vault_sync.sha256_bytes(
                (clone / conversation_path).read_bytes()
            )
            changed_paths.append(conversation_path)
        write_json(clone / manifest_path, manifest)
        run(["git", "add", "--", *changed_paths], clone)
        run(
            ["git", "commit", "-m", f"add {artifact_id} routing fixture"],
            clone,
        )
        run(["git", "push", "origin", "main"], clone)
        return artifacts[0]

    def prepare_artifact_routing_evidence(
        self,
        *,
        session: str,
        artifact_id: str,
        display_name: str,
        role: str,
        mime_type: str,
        local_content: bytes,
        remote_content: bytes,
        local_role: str | None = None,
        extract_remote_artifact: bool = True,
        additional_remote_artifacts: Sequence[Mapping[str, Any]] = (),
        local_user_text: str | None = None,
        local_assistant_text: str | None = None,
        remote_user_text: str | None = None,
        remote_assistant_text: str | None = None,
    ) -> dict[str, Any]:
        remote_artifact = self.install_remote_routing_artifact(
            artifact_id=artifact_id,
            display_name=display_name,
            role=role,
            mime_type=mime_type,
            content=remote_content,
            additional_artifacts=additional_remote_artifacts,
            remote_user_text=remote_user_text,
            remote_assistant_text=remote_assistant_text,
        )
        workspace = self.fixture.allowed / f"review-{session}"
        workspace.mkdir()
        local_path = workspace / display_name
        local_path.write_bytes(local_content)
        engine, _started, request_id = self.start_unbound_routing(
            session=session,
            workspace=workspace,
        )
        candidate_evidence = (
            vault_sync.routing_candidate_evidence_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                ),
                engine,
            )
        )
        request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )[1]
        local_turns = self.fixture.write_session_log(
            session,
            user_text=local_user_text
            or "核对本地成果与远端候选是否属于同一工作，并比较版本变化。",
            assistant_text=local_assistant_text
            or "已读取双方实际内容，并按六个语义维度记录证据。",
        )
        local_evidence = vault_sync.local_artifact_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                artifact_document={
                    "path": str(local_path),
                    "role": local_role or role,
                },
            ),
            engine,
        )["evidence"]
        remote_evidence = None
        if extract_remote_artifact:
            remote_evidence = vault_sync.remote_artifact_evidence_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                    artifact_id=artifact_id,
                ),
                engine,
            )["evidence"]
        return {
            "engine": engine,
            "request_id": request_id,
            "request": request,
            "session": session,
            "workspace": workspace,
            "local_path": local_path,
            "local_turns": local_turns,
            "local_evidence": local_evidence,
            "remote_evidence": remote_evidence,
            "remote_artifact": remote_artifact,
            "candidate_evidence": candidate_evidence,
        }

    def artifact_routing_review_document(
        self,
        evidence: Mapping[str, Any],
        *,
        verdict: str,
        identity_assessment: str,
        version_assessment: str,
        relation: str,
        pair_receipts: bool,
        anchor_dimensions: bool,
    ) -> Mapping[str, Any]:
        local_evidence = evidence["local_evidence"]
        remote_evidence = evidence["remote_evidence"]
        local_blocks = local_evidence["blocks"]
        remote_blocks = (
            remote_evidence["blocks"]
            if isinstance(remote_evidence, Mapping)
            else []
        )

        def dimension_anchor(
            blocks: Sequence[Mapping[str, Any]],
            dimension: str,
        ) -> list[str]:
            if not anchor_dimensions:
                return []
            exact = next(
                (
                    block
                    for block in blocks
                    if block["locator"] == f"$.{dimension}"
                ),
                None,
            )
            selected = exact or (blocks[0] if blocks else None)
            return [str(selected["anchor_id"])] if selected is not None else []

        conversation_anchors = [
            {
                "source_id": conversation["source_id"],
                "revision_id": conversation["revision_id"],
                "message_ordinals": list(
                    range(len(conversation["document"]["messages"]))
                ),
            }
            for conversation in evidence["candidate_evidence"][
                "verified_remote_conversations"
            ]
        ]
        artifact_pairs = []
        local_artifact_gaps = []
        if pair_receipts:
            if not isinstance(remote_evidence, Mapping):
                raise AssertionError("remote artifact evidence is required")
            artifact_pairs = [
                {
                    "local_receipt_id": local_evidence["receipt_id"],
                    "remote_receipt_id": remote_evidence["receipt_id"],
                }
            ]
        else:
            local_artifact_gaps = [
                {
                    "local_receipt_id": local_evidence["receipt_id"],
                    "reason": (
                        "The matching remote extraction receipt was not "
                        "supplied."
                    ),
                }
            ]
        return {
            "schema_version": vault_sync.LOCAL_ROUTING_REVIEW_SCHEMA,
            "request_id": evidence["request_id"],
            "source_session_id": evidence["request"]["session_id"],
            "conversation": {
                "coverage": "full_visible_task",
                "omission_reason": None,
                "turns": evidence["local_turns"],
            },
            "artifacts": {
                "disposition": "extracted_declared_artifacts",
                "extraction_receipt_ids": [
                    local_evidence["receipt_id"]
                ],
            },
            "candidate_reviews": [
                {
                    "task_id": self.fixture.task_id,
                    "verdict": verdict,
                    "local_turn_ordinals": [0, 1],
                    "remote_conversation_anchors": conversation_anchors,
                    "contradictions": [],
                    "identity_assessment": identity_assessment,
                    "version_assessment": version_assessment,
                    "dimension_matrix": [
                        {
                            "dimension": dimension,
                            "relation": relation,
                            "local_anchor_ids": dimension_anchor(
                                local_blocks,
                                dimension,
                            ),
                            "remote_anchor_ids": dimension_anchor(
                                remote_blocks,
                                dimension,
                            ),
                            "summary": (
                                f"Verified both artifact versions for "
                                f"{dimension}."
                            ),
                        }
                        for dimension in (
                            vault_sync.ROUTING_ARTIFACT_DIMENSIONS
                        )
                    ],
                    "artifact_pairs": artifact_pairs,
                    "local_artifact_gaps": local_artifact_gaps,
                    "rationale": (
                        "Compared the exact local and remote artifact contents "
                        "together with both visible conversations."
                    ),
                }
            ],
        }

    @staticmethod
    def auto_match_args(
        request_id: str,
        *,
        task_id: str = VaultFixture.task_id,
        goal_score_bp: int = 9700,
        distinctive_score_bp: int = 9600,
        runner_up_score_bp: int = 7000,
        contradiction_count: int = 0,
        evidence_seed: bytes = b"initial-visible-goal",
    ) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            request_id=request_id,
            task_id=task_id,
            goal_score_bp=goal_score_bp,
            distinctive_score_bp=distinctive_score_bp,
            runner_up_score_bp=runner_up_score_bp,
            contradiction_count=contradiction_count,
            evidence_sha256=vault_sync.sha256_bytes(evidence_seed),
        )

    def prepare_high_confidence_match(
        self,
        *,
        session: str = "unbound-high-confidence",
        engine: Any | None = None,
        task_id: str = VaultFixture.task_id,
        evidence_seed: bytes = b"initial-visible-goal",
    ) -> tuple[Any, dict[str, Any], str]:
        active_engine, _output, request_id = self.start_unbound_routing(
            session=session,
            engine=engine,
        )
        result = vault_sync.prepare_auto_match_command(
            self.auto_match_args(
                request_id,
                task_id=task_id,
                evidence_seed=evidence_seed,
            ),
            active_engine,
        )
        return active_engine, dict(result), request_id

    def install_legacy_auto_route(
        self,
        *,
        session: str,
        task_id: str = VaultFixture.task_id,
    ) -> tuple[Any, str, str]:
        with mock.patch.object(
            vault_sync,
            "LEGACY_AUTO_BINDING_DISABLED",
            False,
        ):
            engine, prepared, request_id = (
                self.prepare_high_confidence_match(
                    session=session,
                    task_id=task_id,
                    evidence_seed=(
                        b"legacy-auto-initial-" + session.encode("utf-8")
                    ),
                )
            )
            vault_sync.promote_auto_match_command(
                types.SimpleNamespace(
                    claim_id=prepared["claim_id"],
                    consistency_score_bp=9800,
                    contradiction_count=0,
                    evidence_sha256=vault_sync.sha256_bytes(
                        b"legacy-auto-verification-"
                        + session.encode("utf-8")
                    ),
                ),
                engine,
            )
            legacy = vault_sync.resolve_source_identity(
                engine.git,
                session,
            )
        return engine, request_id, legacy.binding_id

    def install_legacy_user_route(
        self,
        *,
        session: str,
        task_id: str = VaultFixture.task_id,
    ) -> tuple[Any, str, str]:
        engine, _output, request_id = self.start_unbound_routing(
            session=session,
        )
        with mock.patch.object(
            vault_sync,
            "LEGACY_AUTO_BINDING_DISABLED",
            False,
        ):
            legacy = engine._register_native_handoff_source(
                session,
                task_id,
                "existing_adoption",
            )
        return engine, request_id, legacy.binding_id

    def test_fixture_checkout_keeps_protocol_bytes_canonical_with_autocrlf(
        self,
    ) -> None:
        clone = self.root / "autocrlf-clone"
        run(
            [
                "git",
                "-c",
                "core.autocrlf=true",
                "clone",
                str(self.fixture.remote),
                str(clone),
            ]
        )
        run(["git", "config", "core.autocrlf", "true"], clone)
        repo_path = f"tasks/{self.fixture.task_id}/CURRENT.json"
        working_bytes = (clone / repo_path).read_bytes()
        committed = subprocess.run(
            ["git", "show", f"HEAD:{repo_path}"],
            cwd=str(clone),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout

        self.assertNotIn(b"\r\n", working_bytes)
        self.assertEqual(working_bytes, committed)
        attributes = run(
            [
                "git",
                "check-attr",
                "text",
                "eol",
                "working-tree-encoding",
                "--",
                repo_path,
            ],
            clone,
        )
        self.assertIn(f"{repo_path}: text: set", attributes)
        self.assertIn(f"{repo_path}: eol: lf", attributes)
        self.assertIn(
            f"{repo_path}: working-tree-encoding: UTF-8",
            attributes,
        )

    def test_fixture_write_json_is_canonical_before_git_normalization(
        self,
    ) -> None:
        target = self.root / "canonical-json-before-git.json"
        write_json(target, {"multiline": "first\nsecond"})
        raw = target.read_bytes()

        self.assertNotIn(b"\r\n", raw)
        self.assertEqual(
            raw,
            vault_sync.pretty_json_bytes({"multiline": "first\nsecond"}),
        )

    def test_unbound_session_start_surfaces_routing_without_reading_transcript(
        self,
    ) -> None:
        transcript = self.root / "transcript-must-never-be-read.jsonl"
        transcript.write_text("private transcript sentinel", encoding="utf-8")
        payload = self.fixture.session_input(
            session="unbound-routing-notice",
            workspace=self.fixture.projectless,
        )
        payload["transcript_path"] = str(transcript)
        original_read_bytes = Path.read_bytes

        def guarded_read_bytes(path: Path) -> bytes:
            if path == transcript:
                raise AssertionError("transcript_path was read")
            return original_read_bytes(path)

        engine = self.fixture.engine()
        with mock.patch.object(Path, "read_bytes", new=guarded_read_bytes):
            output = engine.session_start(payload)

        self.assertIn("systemMessage", output)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("MEMORY_VAULT_ROUTING", context)
        self.assertIn("unbound_pending_model", context)
        device = vault_sync._device_state(self.fixture.data)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            "unbound-routing-notice",
        )
        self.assertIsNotNone(record)
        assert record is not None
        request_text = json.dumps(record[1], ensure_ascii=False)
        self.assertNotIn(str(transcript), request_text)
        self.assertNotIn("private transcript sentinel", request_text)
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                "unbound-routing-notice",
            )
        )

    def test_unbound_session_start_includes_lightweight_candidate_preview(
        self,
    ) -> None:
        output = self.fixture.engine().session_start(
            self.fixture.session_input(
                session="unbound-routing-preview",
                workspace=self.fixture.projectless,
            )
        )
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn('"candidate_preview"', context)
        self.assertIn('"candidate_preview_policy"', context)
        self.assertIn("show_numbered_lightweight_candidate_preview", context)

    def test_user_choice_is_only_a_deep_validation_hint_before_confirmation(
        self,
    ) -> None:
        session = "unbound-routing-selection-hint"
        engine, _output, _request_id = self.start_unbound_routing(
            session=session
        )
        prompted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="selection-hint-turn",
                prompt="1",
                workspace=self.fixture.projectless,
            )
        )
        context = prompted["hookSpecificOutput"]["additionalContext"]
        self.assertIn('"user_selected_candidate_hint"', context)
        self.assertIn('"scope":"prioritize_deep_validation_only;', context)
        self.assertNotIn('"user_decision_token"', context)

    def test_user_prompt_submit_recovers_routing_when_session_start_was_missed(
        self,
    ) -> None:
        session = "resumed-old-task-without-session-start"
        turn = "first-visible-turn-after-resume"
        prompt = "Continue the synthetic prior objective from its latest checkpoint."
        device = vault_sync._device_state(self.fixture.data)
        self.assertIsNone(
            vault_sync._load_routing_request_for_session(
                self.fixture.data,
                device,
                session,
            )
        )
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session,
            )
        )

        output = self.run_hook_process(
            "user-prompt-submit",
            self.fixture.prompt_input(
                session=session,
                turn=turn,
                prompt=prompt,
                workspace=self.fixture.projectless,
            ),
        )

        self.assertTrue(output["continue"])
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("MEMORY_VAULT_ROUTING", context)
        self.assertIn("unbound_pending_model", context)
        self.assertNotIn(session, context)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(record)
        assert record is not None
        request = record[1]
        self.assertEqual(request["state"], "pending")
        self.assertEqual(request["pending_turn_id"], turn)
        self.assertEqual(request["pending_prompt"], prompt)
        self.assertEqual(
            request["candidate_task_ids"],
            [self.fixture.task_id],
        )
        self.assertNotIn("transcript_path", request)
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session,
            )
        )

    def test_user_prompt_submit_routes_content_but_blocks_invalid_artifact_identity(
        self,
    ) -> None:
        valid_identity = json.loads(
            (
                self.fixture.workspace / ".vault_identity.yaml"
            ).read_text(encoding="utf-8")
        )
        cases = ("malformed", "conflicting")
        for case in cases:
            with self.subTest(case=case):
                workspace = self.fixture.allowed / f"invalid-identity-{case}"
                workspace.mkdir()
                if case == "malformed":
                    write_json(
                        workspace / ".vault_identity.yaml",
                        {
                            "schema_version": (
                                "portable-workspace-identity/v1"
                            ),
                        },
                    )
                else:
                    write_json(
                        workspace / ".vault_identity.yaml",
                        valid_identity,
                    )
                    write_json(
                        workspace / ".vault_identities.json",
                        {
                            "schema_version": "portable-workspace-set/v1",
                            "vault_id": "codex-memory-vault",
                            "identities": [valid_identity],
                        },
                    )

                session = f"resumed-invalid-identity-{case}"
                output = self.run_hook_process(
                    "user-prompt-submit",
                    self.fixture.prompt_input(
                        session=session,
                        turn=f"invalid-identity-turn-{case}",
                        workspace=workspace,
                    ),
                )

                rendered = json.dumps(output, ensure_ascii=False)
                self.assertIn("MEMORY_VAULT_ROUTING", rendered)
                self.assertIn("成果身份无效", rendered)
                device = vault_sync._device_state(self.fixture.data)
                request = vault_sync._load_routing_request_for_session(
                    self.fixture.data,
                    device,
                    session,
                )
                self.assertIsNotNone(request)
                assert request is not None
                self.assertIsNotNone(
                    request[1]["workspace_identity_fingerprint"]
                )
                self.assertIsNone(
                    vault_sync._load_session(
                        self.fixture.data,
                        device,
                        session,
                    )
                )

    def test_routing_candidates_include_only_active_semantic_tasks(self) -> None:
        topology = self.fixture.install_split_topology()
        clone = self.fixture.clone_remote("archive-routing-candidate")
        run(["git", "config", "user.name", "Routing fixture"], clone)
        run(["git", "config", "user.email", "routing@localhost"], clone)
        task_path = clone / f"tasks/{topology['task_beta']}/TASK.json"
        task = json.loads(task_path.read_text(encoding="utf-8"))
        task["status"] = "archived"
        write_json(task_path, task)
        index_path = clone / "tasks/INDEX.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        for row in index["tasks"]:
            if row["task_id"] == topology["task_beta"]:
                row["status"] = "archived"
        write_json(index_path, index)
        run(
            [
                "git",
                "add",
                "--",
                f"tasks/{topology['task_beta']}/TASK.json",
                "tasks/INDEX.json",
            ],
            clone,
        )
        run(["git", "commit", "-m", "archive one semantic task"], clone)
        run(["git", "push", "origin", "main"], clone)

        engine, _output, request_id = self.start_unbound_routing(
            session="routing-candidate-filter"
        )
        candidates = vault_sync.routing_candidates_command(
            types.SimpleNamespace(request_id=request_id),
            engine,
        )
        candidate_ids = {
            row["task_id"] for row in candidates["candidates"]
        }
        self.assertEqual(
            candidate_ids,
            {self.fixture.task_id, topology["task_gamma"]},
        )
        self.assertNotIn(topology["coordinator"], candidate_ids)
        self.assertNotIn(topology["task_beta"], candidate_ids)
        self.assertFalse(
            candidates["automatic_policy"]["timestamps_are_authoritative"]
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_auto_match_rejects_weak_or_ambiguous_assessments_without_writes(
        self,
    ) -> None:
        engine, _output, request_id = self.start_unbound_routing(
            session="weak-or-ambiguous-local-task"
        )
        baseline_head = self.fixture.remote_head()
        assessments = [
            self.auto_match_args(
                request_id,
                goal_score_bp=9100,
                distinctive_score_bp=9700,
                runner_up_score_bp=5000,
                evidence_seed=b"low-goal-score",
            ),
            self.auto_match_args(
                request_id,
                goal_score_bp=9500,
                distinctive_score_bp=9500,
                runner_up_score_bp=8500,
                evidence_seed=b"small-runner-up-margin",
            ),
            self.auto_match_args(
                request_id,
                goal_score_bp=9800,
                distinctive_score_bp=9700,
                runner_up_score_bp=5000,
                contradiction_count=1,
                evidence_seed=b"identity-contradiction",
            ),
        ]
        for assessment in assessments:
            with self.subTest(assessment=assessment.evidence_sha256):
                with self.assertRaises(vault_sync.IdentityError):
                    vault_sync.prepare_auto_match_command(
                        assessment,
                        engine,
                    )
                self.assertEqual(self.fixture.remote_head(), baseline_head)

        engine.git.fetch()
        self.assertEqual(
            [
                path
                for path in engine.git.list_paths("bindings/candidates")
                if path.endswith(".json")
            ],
            [],
        )
        device = vault_sync._device_state(self.fixture.data)
        session_key = vault_sync._session_key(
            device,
            "weak-or-ambiguous-local-task",
        )
        self.assertIsNone(
            vault_sync._load_provisional_claim(
                self.fixture.data,
                session_key,
            )
        )
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                "weak-or-ambiguous-local-task",
            )
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_high_confidence_match_is_provisional_and_loads_cloud_current(
        self,
    ) -> None:
        session = "provisional-cloud-current"
        engine, _output, request_id = self.start_unbound_routing(
            session=session
        )
        engine.git.ensure()
        current_path = f"tasks/{self.fixture.task_id}/CURRENT.json"
        expected_current = engine.git.show_bytes(current_path)
        with mock.patch.object(
            engine,
            "_drive",
            side_effect=AssertionError(
                "provisional matching must not access artifact storage"
            ),
        ):
            result = vault_sync.prepare_auto_match_command(
                self.auto_match_args(request_id),
                engine,
            )

        self.assertEqual(result["status"], "provisional_active")
        self.assertTrue(result["cloud_current_loaded"])
        self.assertEqual(result["authority"], "read_only_provisional")
        self.assertEqual(result["local_history_role"], "reference_only")
        self.assertFalse(result["artifacts_loaded"])
        self.assertIn("Generation: 1", result["context"])
        engine.git.fetch()
        self.assertEqual(engine.git.show_bytes(current_path), expected_current)
        proposals = [
            engine.git.show_json(path)
            for path in engine.git.list_paths("bindings/candidates")
            if path.endswith(".json")
        ]
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["state"], "proposed")
        self.assertEqual(proposals[0]["confidence"], "assistant_inferred")
        self.assertIsNone(proposals[0]["confirmation_basis"])
        self.assertEqual(
            proposals[0]["proposal_assessment"]["contradiction_count"],
            0,
        )
        self.assertFalse(
            (self.fixture.projectless / ".vault_identity.yaml").exists()
        )
        self.assertFalse(
            (self.fixture.projectless / ".vault_identities.json").exists()
        )
        device = vault_sync._device_state(self.fixture.data)
        local_session = vault_sync._load_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(local_session)
        assert local_session is not None
        self.assertEqual(
            local_session[1]["identity_kind"],
            "provisional_source",
        )
        self.assertTrue(
            local_session[1]["adoption"]["artifact_publication_blocked"]
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_provisional_stop_is_candidate_and_does_not_move_current(
        self,
    ) -> None:
        session = "provisional-candidate-stop"
        engine, prepared, _request_id = self.prepare_high_confidence_match(
            session=session
        )
        current_path = f"tasks/{self.fixture.task_id}/CURRENT.json"
        engine.git.fetch()
        expected_current = engine.git.show_bytes(current_path)
        prompted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="provisional-turn",
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn(
            "provisional_consistency_check",
            prompted["hookSpecificOutput"]["additionalContext"],
        )
        stopped = engine.stop(
            self.fixture.stop_input(
                session=session,
                turn="provisional-turn",
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn("systemMessage", stopped)
        self.assertIn("recoverable candidate", stopped["systemMessage"])
        engine.git.fetch()
        self.assertEqual(engine.git.show_bytes(current_path), expected_current)
        candidate_versions = []
        for path in engine.git.list_paths(
            f"tasks/{self.fixture.task_id}/versions"
        ):
            if not path.endswith(".json"):
                continue
            version = engine.git.show_json(path)
            if version.get("state") == "candidate":
                candidate_versions.append(version)
        self.assertEqual(len(candidate_versions), 1)
        self.assertEqual(
            candidate_versions[0]["parents"][0]["snapshot_id"],
            prepared["snapshot_id"],
        )
        receipts = list(
            (self.fixture.data / "outbox" / "candidate").glob("*.json")
        )
        self.assertEqual(len(receipts), 1)

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_independent_consistency_digest_promotes_assistant_inferred_binding(
        self,
    ) -> None:
        session = "semantic-quorum-promotion"
        engine, prepared, _request_id = self.prepare_high_confidence_match(
            session=session,
            evidence_seed=b"initial-local-goal-digest",
        )
        current_path = f"tasks/{self.fixture.task_id}/CURRENT.json"
        engine.git.fetch()
        expected_current = engine.git.show_bytes(current_path)
        result = vault_sync.promote_auto_match_command(
            types.SimpleNamespace(
                claim_id=prepared["claim_id"],
                consistency_score_bp=9700,
                contradiction_count=0,
                evidence_sha256=vault_sync.sha256_bytes(
                    b"independent-cloud-checkpoint-digest"
                ),
            ),
            engine,
        )
        self.assertEqual(result["status"], "confirmed")
        self.assertTrue(result["cloud_current_loaded"])
        engine.git.fetch()
        self.assertEqual(engine.git.show_bytes(current_path), expected_current)
        confirmed = []
        for path in engine.git.list_paths("bindings/confirmed"):
            binding = engine.git.show_json(path)
            if (
                binding.get("confidence") == "assistant_inferred"
                and binding.get("confirmation_basis")
                == "user_authorized_semantic_quorum"
            ):
                confirmed.append(binding)
        self.assertEqual(len(confirmed), 1)
        binding = confirmed[0]
        self.assertEqual(
            {item["kind"] for item in binding["evidence"]},
            {
                "user_policy_authorization",
                "content_similarity",
                "cloud_consistency_check",
            },
        )
        self.assertTrue(binding["supersedes_binding_id"].startswith(
            "bnd-proposed-"
        ))
        claim_path, claim = vault_sync._claim_by_id(
            self.fixture.data,
            prepared["claim_id"],
        )
        self.assertTrue(claim_path.exists())
        self.assertEqual(claim["state"], "promoted")

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_auto_promotion_rejects_reused_evidence_digest(self) -> None:
        engine, prepared, _request_id = self.prepare_high_confidence_match(
            session="same-digest-promotion",
            evidence_seed=b"same-digest-is-not-independent",
        )
        baseline_head = self.fixture.remote_head()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.promote_auto_match_command(
                types.SimpleNamespace(
                    claim_id=prepared["claim_id"],
                    consistency_score_bp=9800,
                    contradiction_count=0,
                    evidence_sha256=vault_sync.sha256_bytes(
                        b"same-digest-is-not-independent"
                    ),
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), baseline_head)
        _path, claim = vault_sync._claim_by_id(
            self.fixture.data,
            prepared["claim_id"],
        )
        self.assertEqual(claim["state"], "provisional_active")

    def test_ambiguous_task_can_be_confirmed_once_by_the_user(self) -> None:
        topology = self.fixture.install_split_topology()
        session = "ambiguous-user-selection"
        engine, output, request_id = self.start_unbound_routing(
            session=session
        )
        self.assertIn("有歧义", output["systemMessage"])
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=topology["task_gamma"],
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [topology["task_gamma"]],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[topology["task_gamma"]],
            ),
            engine,
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="ambiguous-turn",
                prompt="1",
                workspace=self.fixture.projectless,
            )
        )
        decision_token = self.routing_decision_token(submitted)
        selected = vault_sync.confirm_routing_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=topology["task_gamma"],
                user_decision_token=decision_token,
            ),
            engine,
        )
        self.assertEqual(selected["status"], "confirmed")
        self.assertEqual(selected["task_id"], topology["task_gamma"])
        self.assertTrue(selected["cloud_current_loaded"])
        device = vault_sync._device_state(self.fixture.data)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record[1]["state"], "confirmed_by_user")
        local_session = vault_sync._load_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(local_session)
        assert local_session is not None
        prompt_path = vault_sync._prompt_path(
            self.fixture.data,
            local_session[0],
            vault_sync._turn_key(
                device,
                session,
                "ambiguous-turn",
            ),
        )
        staged_prompt = vault_sync.load_json(prompt_path)
        self.assertEqual(
            staged_prompt["prompt"],
            "1",
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_promotion_refuses_a_remotely_changed_proposal(self) -> None:
        engine, prepared, _request_id = self.prepare_high_confidence_match(
            session="changed-proposal-before-promotion"
        )
        _claim_path, claim = vault_sync._claim_by_id(
            self.fixture.data,
            prepared["claim_id"],
        )
        proposal_path = str(claim["proposal_binding_path"])
        engine.git.fetch()
        expected_current = engine.git.show_bytes(
            f"tasks/{self.fixture.task_id}/CURRENT.json"
        )
        proposal = dict(engine.git.show_json(proposal_path))
        proposal["created_at"] = "2026-07-29T23:59:59Z"
        self.fixture.write_remote_json(
            proposal_path,
            proposal,
            "change-provisional-proposal",
        )
        with self.assertRaises(vault_sync.ConflictError):
            vault_sync.promote_auto_match_command(
                types.SimpleNamespace(
                    claim_id=prepared["claim_id"],
                    consistency_score_bp=9800,
                    contradiction_count=0,
                    evidence_sha256=vault_sync.sha256_bytes(
                        b"independent-check-after-remote-change"
                    ),
                ),
                engine,
            )
        engine.git.fetch()
        self.assertEqual(
            engine.git.show_bytes(
                f"tasks/{self.fixture.task_id}/CURRENT.json"
            ),
            expected_current,
        )
        _claim_path, claim_after = vault_sync._claim_by_id(
            self.fixture.data,
            prepared["claim_id"],
        )
        self.assertEqual(claim_after["state"], "provisional_active")

    def test_session_start_pulls_authoritative_current(self) -> None:
        engine = self.fixture.engine()
        first = engine.session_start(self.fixture.session_input())
        self.assertIn("Generation: 1", json.dumps(first, ensure_ascii=False))
        self.fixture.advance_remote("newer")
        second = engine.session_start(self.fixture.session_input())
        rendered = json.dumps(second, ensure_ascii=False)
        self.assertIn("Generation: 2", rendered)
        self.assertIn("snap-newer", rendered)
        self.assertNotIn("/must/not/be/read", rendered)

    def test_handoff_keeps_resolved_result_before_later_progress(self) -> None:
        self.fixture.confirm_source_route("decision-progress")
        self.fixture.link_conversation_to_current(
            [
                {
                    "role": "user",
                    "phase": "unknown",
                    "text": "初始目标：完成这篇综述并保持投稿范围一致。",
                },
                {
                    "role": "assistant",
                    "phase": "final_answer",
                    "text": (
                        "已决结果：当前目标是期刊 B；旧的期刊 A 路线已被替代，"
                        "因为当前稿件采用食品生物过程工程范围。"
                    ),
                },
                {
                    "role": "assistant",
                    "phase": "commentary",
                    "text": "这条中间进度不应替代最新进度。",
                },
                {
                    "role": "user",
                    "phase": "unknown",
                    "text": "继续完成图片，不要重新讨论已确定的投稿目标。",
                },
                {
                    "role": "assistant",
                    "phase": "commentary",
                    "text": "最新进度：图片正在复核，正文决定保持不变。",
                },
            ],
            "decision-progress",
        )
        engine = self.fixture.engine()
        output = engine.session_start(
            self.fixture.session_input(session="decision-progress")
        )
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Initial user goal/context", context)
        self.assertIn("初始目标：完成这篇综述", context)
        self.assertIn("Latest completed assistant result", context)
        self.assertIn("当前目标是期刊 B", context)
        self.assertIn("Latest user direction", context)
        self.assertIn("不要重新讨论已确定的投稿目标", context)
        self.assertIn("Latest assistant progress update", context)
        self.assertIn("图片正在复核", context)
        self.assertNotIn("这条中间进度不应替代最新进度", context)

    def test_memory_use_contract_persists_in_workspace_and_conversation_modes(
        self,
    ) -> None:
        workspace_session = "workspace-contract"
        conversation_session = self.fixture.source_session_id
        self.fixture.confirm_source_route(workspace_session)
        engine = self.fixture.engine()
        outputs = [
            engine.session_start(
                self.fixture.session_input(session=workspace_session)
            ),
            engine.session_start(
                self.fixture.session_input(
                    session=conversation_session,
                    workspace=self.fixture.projectless,
                )
            ),
        ]
        for output in outputs:
            context = output["hookSpecificOutput"]["additionalContext"]
            self.assertIn("Five-layer handoff integrity", context)
            self.assertIn("Legacy fallback completeness", context)
            self.assertIn(
                "pre-existing local conversation and working files",
                context,
            )
            self.assertIn(
                "Do not ask the user to explain or re-justify",
                context,
            )
            self.assertIn("Raw-evidence entry point", context)

        device = vault_sync._device_state(self.fixture.data)
        for session_id in (workspace_session, conversation_session):
            loaded = vault_sync._load_session(
                self.fixture.data,
                device,
                session_id,
            )
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(
                loaded[1]["continuation_context_contract"],
                vault_sync.CONTINUATION_CONTEXT_CONTRACT,
            )
            self.assertIn(
                "Legacy fallback completeness",
                loaded[1]["continuation_context"],
            )

    def test_long_handoff_preserves_contract_active_state_and_footer(
        self,
    ) -> None:
        self.fixture.confirm_source_route("long-context")
        self.fixture.link_conversation_to_current(
            [
                {
                    "role": "assistant",
                    "phase": "final_answer",
                    "text": "ACTIVE-DECISION " + ("甲" * 9000),
                },
                {
                    "role": "user",
                    "phase": "unknown",
                    "text": "LATEST-DIRECTION " + ("乙" * 9000),
                },
                {
                    "role": "assistant",
                    "phase": "commentary",
                    "text": "LATEST-PROGRESS " + ("丙" * 9000),
                },
            ],
            "long-context",
        )
        engine = self.fixture.engine()
        output = engine.session_start(
            self.fixture.session_input(session="long-context")
        )
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertLessEqual(
            len(context),
            vault_sync.CONTINUATION_CONTEXT_MAX_CHARS,
        )
        self.assertIn("Five-layer handoff integrity", context)
        self.assertIn("Legacy fallback completeness", context)
        self.assertIn("ACTIVE-DECISION", context)
        self.assertIn("LATEST-DIRECTION", context)
        self.assertIn("LATEST-PROGRESS", context)
        self.assertIn("Raw-evidence entry point", context)
        self.assertTrue(
            context.endswith(
                "Before publishing, preserve object-store-first order and compare "
                "the recorded CURRENT blob."
            )
        )
        adopted = vault_sync._with_adoption_context(context, blocked=True)
        self.assertLessEqual(
            len(adopted),
            vault_sync.CONTINUATION_CONTEXT_MAX_CHARS,
        )
        self.assertLess(
            adopted.index(vault_sync.ADOPTION_CONTEXT_PREFIX),
            adopted.index("Newest verified visible handoff"),
        )
        self.assertTrue(
            adopted.endswith(
                "Before publishing, preserve object-store-first order and compare "
                "the recorded CURRENT blob."
            )
        )

    def test_old_open_session_self_heals_memory_use_contract_once(self) -> None:
        session_id = "old-open-session"
        self.fixture.confirm_source_route(session_id)
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(session=session_id)
        )
        device = vault_sync._device_state(self.fixture.data)
        loaded = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(loaded)
        assert loaded is not None
        session_key, old_session = loaded
        old_session.pop("continuation_context_contract", None)
        old_session["continuation_context"] = "legacy context"
        vault_sync._save_session(
            self.fixture.data,
            session_key,
            old_session,
        )

        with mock.patch.object(
            engine,
            "session_start",
            wraps=engine.session_start,
        ) as resume:
            output = engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session=session_id,
                    turn="self-heal-first",
                )
            )
        resume.assert_called_once()
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Five-layer handoff integrity", context)
        refreshed = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        self.assertEqual(
            refreshed[1]["continuation_context_contract"],
            vault_sync.CONTINUATION_CONTEXT_CONTRACT,
        )

        with mock.patch.object(
            engine,
            "session_start",
            wraps=engine.session_start,
        ) as second_resume:
            engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session=session_id,
                    turn="self-heal-second",
                )
            )
        second_resume.assert_not_called()

    def test_remote_history_rollback_is_refused_and_cache_is_retained(self) -> None:
        self.fixture.confirm_source_route("rollback-reference")
        baseline = run(
            [
                "git",
                f"--git-dir={self.fixture.remote}",
                "rev-parse",
                "refs/heads/main",
            ]
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        self.fixture.advance_remote("forward-before-rollback")
        engine.session_start(self.fixture.session_input())
        verified_head = engine.git.head_sha()
        self.assertNotEqual(verified_head, baseline)
        run(
            [
                "git",
                f"--git-dir={self.fixture.remote}",
                "update-ref",
                "refs/heads/main",
                baseline,
            ]
        )
        with self.assertRaises(vault_sync.ConflictError):
            engine.git.fetch()
        self.assertEqual(engine.git.head_sha(), verified_head)
        cached = engine.session_start(
            self.fixture.session_input(session="rollback-reference")
        )
        rendered = json.dumps(cached, ensure_ascii=False)
        self.assertIn("Generation: 2", rendered)
        self.assertIn("reference-only", rendered)

    def test_binding_must_match_lineage_and_primary_workspace_role(self) -> None:
        engine = self.fixture.engine()
        engine.git.ensure()
        identity = vault_sync.resolve_workspace(
            self.fixture.workspace, self.fixture.config["privacy"]["allowed_roots"]
        )
        binding_path = f"bindings/confirmed/{self.fixture.binding_id}.json"
        clone = self.fixture.clone_remote("change-binding")
        run(["git", "config", "user.name", "Binding test"], clone)
        run(["git", "config", "user.email", "binding@localhost"], clone)
        binding_file = clone / binding_path
        binding = json.loads(binding_file.read_text(encoding="utf-8"))
        binding["subject"]["id"] = "lineage-other"
        write_json(binding_file, binding)
        run(["git", "add", "--", binding_path], clone)
        run(["git", "commit", "-m", "change lineage binding"], clone)
        run(["git", "push", "origin", "main"], clone)
        engine.git.fetch()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.load_remote_task(engine.git, identity)

        binding["subject"]["id"] = self.fixture.lineage_id
        binding["targets"][0]["role"] = "supporting"
        write_json(binding_file, binding)
        run(["git", "add", "--", binding_path], clone)
        run(["git", "commit", "-m", "make workspace read only"], clone)
        run(["git", "push", "origin", "main"], clone)
        engine.git.fetch()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.load_remote_task(engine.git, identity)

    def test_source_bound_task_pulls_and_publishes_without_workspace_or_drive(
        self,
    ) -> None:
        ignored = self.fixture.projectless / "must-not-be-captured.bin"
        ignored.write_bytes(b"local file outside the configured roots")
        write_json(
            self.fixture.projectless / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["must-not-be-captured.bin"],
            },
        )
        session_id = self.fixture.source_session_id
        raw_cwd = str(self.fixture.projectless.resolve())
        engine = self.fixture.engine()
        with mock.patch.object(
            engine,
            "_drive",
            side_effect=AssertionError(
                "conversation-only source binding must not access Drive"
            ),
        ):
            started = engine.session_start(
                self.fixture.session_input(
                    session=session_id,
                    workspace=self.fixture.projectless,
                )
            )
            self.assertIn(
                "Generation: 1", json.dumps(started, ensure_ascii=False)
            )
            prompted = engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session=session_id,
                    turn="source-turn",
                    prompt="无工作文件夹也要保存这条可见进度。",
                    workspace=self.fixture.projectless,
                )
            )
            self.assertTrue(prompted["continue"])
            stopped = engine.stop(
                self.fixture.stop_input(
                    session=session_id,
                    turn="source-turn",
                    assistant="纯对话进度已完成，下一步检查引用。",
                    workspace=self.fixture.projectless,
                )
            )
        self.assertNotIn("systemMessage", stopped)

        device = vault_sync._device_state(self.fixture.data)
        local_session = vault_sync._load_session(
            self.fixture.data, device, session_id
        )
        self.assertIsNotNone(local_session)
        assert local_session is not None
        session_state = local_session[1]
        self.assertEqual(session_state["identity_kind"], "source")
        self.assertEqual(session_state["source_id"], self.fixture.source_id)
        self.assertNotIn("workspace_root", session_state)
        self.assertNotIn("workspace_lineage_id", session_state)
        self.assertEqual(session_state["artifact_snapshot"], {})

        clone = self.fixture.clone_remote("inspect-source-bound")
        current = json.loads(
            (
                clone
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(current["generation"], 2)
        manifest = json.loads(
            (clone / current["manifest_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["artifacts"], [])
        self.assertEqual(
            manifest["conversation_sources"][-1]["source_id"],
            self.fixture.source_id,
        )
        source = json.loads(
            (
                clone / f"sources/{self.fixture.source_id}/SOURCE.json"
            ).read_text(encoding="utf-8")
        )
        expected_key = vault_sync.sha256_bytes(
            f"codex:{session_id}".encode("utf-8")
        )
        self.assertEqual(source["external_source_key_sha256"], expected_key)
        self.assertEqual(len(source["revisions"]), 2)
        conversation_path = clone / manifest["conversation_sources"][-1][
            "content_path"
        ]
        conversation = json.loads(
            conversation_path.read_text(encoding="utf-8")
        )
        self.assertEqual(
            [message["text"] for message in conversation["messages"]],
            [
                "无工作文件夹也要保存这条可见进度。",
                "纯对话进度已完成，下一步检查引用。",
            ],
        )
        self.assertFalse((self.fixture.drive / "objects").exists())

        outbox_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (self.fixture.data / "outbox").rglob("*.json")
        )
        remote_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in clone.rglob("*")
            if path.is_file() and ".git" not in path.parts
        )
        remote_log = run(["git", "log", "--all", "--format=%B"], clone)
        for private_value in (session_id, raw_cwd):
            self.assertNotIn(private_value, outbox_text)
            self.assertNotIn(private_value, remote_text)
            self.assertNotIn(private_value, remote_log)

    def test_reconcile_accepts_mixed_source_and_workspace_session_registry(
        self,
    ) -> None:
        self.fixture.confirm_source_route("workspace-mixed-session")
        projection_root = self.fixture.allowed / "混合会话接力"
        projection_root.mkdir()
        self.fixture.config["projection"] = {
            "enabled": True,
            "root": str(projection_root),
            "materialize_missing": True,
        }
        write_json(
            self.fixture.data / "config.json",
            self.fixture.config,
        )
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(
                session=self.fixture.source_session_id,
                workspace=self.fixture.projectless,
            )
        )
        engine.session_start(
            self.fixture.session_input(session="workspace-mixed-session")
        )
        result = engine.reconcile(materialize=True)
        rows = {item["task_id"]: item for item in result["tasks"]}
        self.assertEqual(rows[self.fixture.task_id]["local_state"], "in_sync")
        self.assertEqual(result["local_errors"], [])

    def test_source_identity_requires_exact_confirmed_binding_subject(
        self,
    ) -> None:
        binding_path = (
            f"bindings/confirmed/{self.fixture.source_binding_id}.json"
        )
        binding = json.loads(
            (self.fixture.seed / binding_path).read_text(encoding="utf-8")
        )
        binding["subject"]["id"] = "src-another-codex-task"
        self.fixture.write_remote_json(
            binding_path,
            binding,
            "detach-confirmed-source-binding",
        )
        self.assert_source_lifecycle_does_not_write()

    def test_content_attestation_must_match_binding_source(self) -> None:
        binding_path = (
            f"bindings/confirmed/{self.fixture.source_binding_id}.json"
        )
        binding = json.loads(
            (self.fixture.seed / binding_path).read_text(encoding="utf-8")
        )
        binding["content_review_attestation"]["source_id"] = (
            "src-another-codex-task"
        )
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._validate_generated_evidence_binding(binding)

    def test_source_binding_supporting_role_is_read_only(self) -> None:
        binding_path = (
            f"bindings/confirmed/{self.fixture.source_binding_id}.json"
        )
        binding = json.loads(
            (self.fixture.seed / binding_path).read_text(encoding="utf-8")
        )
        binding["targets"][0]["role"] = "supporting"
        self.fixture.write_remote_json(
            binding_path,
            binding,
            "make-source-binding-supporting",
        )
        self.assert_source_lifecycle_does_not_write()

    def test_source_binding_wrong_relation_is_read_only(self) -> None:
        binding_path = (
            f"bindings/confirmed/{self.fixture.source_binding_id}.json"
        )
        binding = json.loads(
            (self.fixture.seed / binding_path).read_text(encoding="utf-8")
        )
        binding["targets"][0]["relation"] = "related_to"
        self.fixture.write_remote_json(
            binding_path,
            binding,
            "make-source-binding-reference-only",
        )
        self.assert_source_lifecycle_does_not_write()

    def test_source_external_hash_is_revalidated_before_publish(self) -> None:
        session_id = self.fixture.source_session_id
        engine = self.fixture.engine()
        started = engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn(
            "Generation: 1", json.dumps(started, ensure_ascii=False)
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                turn="source-hash-race",
                prompt="这条内容只能写入原始精确匹配的 source。",
                workspace=self.fixture.projectless,
            )
        )
        source_path = f"sources/{self.fixture.source_id}/SOURCE.json"
        source = json.loads(
            (self.fixture.seed / source_path).read_text(encoding="utf-8")
        )
        source["external_source_key_sha256"] = vault_sync.sha256_bytes(
            b"a different external source"
        )
        tampered_head = self.fixture.write_remote_json(
            source_path,
            source,
            "change-external-source-hash",
        )
        stopped = engine.stop(
            self.fixture.stop_input(
                session=session_id,
                turn="source-hash-race",
                assistant="发现远端身份改变后必须停止写入。",
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn("systemMessage", stopped)
        self.assertEqual(self.fixture.remote_head(), tampered_head)
        clone = self.fixture.clone_remote("inspect-source-hash-race")
        current = json.loads(
            (
                clone
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(current["generation"], 1)
        self.assertFalse(
            (
                clone
                / f"sources/{self.fixture.source_id}/revisions"
            ).exists()
        )
        pending_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (self.fixture.data / "outbox" / "pending").glob(
                "*.json"
            )
        )
        self.assertNotIn(session_id, pending_text)
        self.assertNotIn(
            str(self.fixture.projectless.resolve()), pending_text
        )

    def test_confirmed_source_route_preempts_conflicting_single_workspace_marker(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.git.ensure()
        session_id = "combined-local-task-exact-beta"
        source_identity = self.fixture.confirm_source_route(
            session_id,
            topology["task_beta"],
        )
        marker = self.fixture.workspace / ".vault_identity.yaml"
        marker_before = marker.read_bytes()

        with (
            mock.patch.object(
                vault_sync,
                "artifact_snapshot",
                side_effect=AssertionError(
                    "conflicting workspace marker granted artifact access"
                ),
            ),
            mock.patch.object(
                engine,
                "_materialize_remote_artifacts",
                side_effect=AssertionError(
                    "conflicting workspace marker downloaded artifacts"
                ),
            ),
        ):
            started = engine.session_start(
                self.fixture.session_input(
                    session=session_id,
                )
            )

        rendered = json.dumps(started, ensure_ascii=False)
        self.assertIn("Task: Second child task", rendered)
        self.assertIn("成果发布已暂停", rendered)
        self.assertEqual(marker.read_bytes(), marker_before)
        self.assertFalse(
            (self.fixture.workspace / ".vault_identities.json").exists()
        )
        device = vault_sync._device_state(self.fixture.data)
        saved = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved[1]["task_id"], topology["task_beta"])
        self.assertEqual(saved[1]["identity_kind"], "source")
        self.assertEqual(saved[1]["binding_id"], source_identity.binding_id)
        self.assertIsNone(
            vault_sync._load_routing_request_for_session(
                self.fixture.data,
                device,
                session_id,
            )
        )

    def test_unbound_session_cannot_auto_adopt_from_single_workspace_marker(
        self,
    ) -> None:
        engine = self.fixture.engine()
        session_id = "never-bound-local-task"
        marker = self.fixture.workspace / ".vault_identity.yaml"
        marker_before = marker.read_bytes()
        remote_before = self.fixture.remote_head()

        with (
            mock.patch.object(
                vault_sync,
                "artifact_snapshot",
                side_effect=AssertionError(
                    "unbound task inspected workspace artifacts"
                ),
            ),
            mock.patch.object(
                engine,
                "_materialize_remote_artifacts",
                side_effect=AssertionError(
                    "unbound task downloaded remote artifacts"
                ),
            ),
        ):
            started = engine.session_start(
                self.fixture.session_input(
                    session=session_id,
                )
            )

        context = started["hookSpecificOutput"]["additionalContext"]
        self.assertIn("MEMORY_VAULT_ROUTING", context)
        self.assertIn("unbound_pending_model", context)
        self.assertNotIn("Generation: 1", context)
        self.assertEqual(marker.read_bytes(), marker_before)
        self.assertFalse(
            (self.fixture.workspace / ".vault_identities.json").exists()
        )
        self.assertEqual(self.fixture.remote_head(), remote_before)
        device = vault_sync._device_state(self.fixture.data)
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session_id,
            )
        )
        request = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(request)
        assert request is not None
        self.assertEqual(request[1]["state"], "pending")
        self.assertIsNotNone(
            request[1]["workspace_identity_fingerprint"]
        )

    def test_explicit_routing_confirmation_is_conversation_only(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        session_id = "explicit-second-task-route"
        marker = self.fixture.workspace / ".vault_identity.yaml"
        marker_before = marker.read_bytes()
        engine.session_start(
            self.fixture.session_input(
                session=session_id,
            )
        )
        device = vault_sync._device_state(self.fixture.data)
        request = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(request)
        assert request is not None

        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request[1]["request_id"],
                task_id=topology["task_beta"],
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request[1]["request_id"],
            [topology["task_beta"]],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request[1]["request_id"],
                task_id=[topology["task_beta"]],
            ),
            engine,
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                turn="explicit-second-task-selection",
                prompt="1",
            )
        )
        confirmed = vault_sync.confirm_routing_match_command(
            types.SimpleNamespace(
                request_id=request[1]["request_id"],
                task_id=topology["task_beta"],
                user_decision_token=self.routing_decision_token(
                    submitted
                ),
            ),
            engine,
        )

        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["binding_mode"], "conversation_only")
        self.assertEqual(marker.read_bytes(), marker_before)
        self.assertFalse(
            (self.fixture.workspace / ".vault_identities.json").exists()
        )
        saved = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved[1]["task_id"], topology["task_beta"])
        self.assertEqual(saved[1]["identity_kind"], "source")
        self.assertEqual(saved[1]["artifact_snapshot"], {})
        self.assertTrue(
            saved[1]["adoption"]["artifact_publication_blocked"]
        )

    def test_confirmed_source_route_survives_a_malformed_workspace_marker(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.git.ensure()
        session_id = "exact-source-malformed-marker"
        source_identity = self.fixture.confirm_source_route(
            session_id,
            topology["task_beta"],
        )
        marker = self.fixture.workspace / ".vault_identity.yaml"
        marker.write_text("{malformed marker", encoding="utf-8")

        with (
            mock.patch.object(
                vault_sync,
                "artifact_snapshot",
                side_effect=AssertionError(
                    "malformed marker granted artifact access"
                ),
            ),
            mock.patch.object(
                engine,
                "_materialize_remote_artifacts",
                side_effect=AssertionError(
                    "malformed marker downloaded artifacts"
                ),
            ),
        ):
            started = engine.session_start(
                self.fixture.session_input(session=session_id)
            )

        rendered = json.dumps(started, ensure_ascii=False)
        self.assertIn("Task: Second child task", rendered)
        self.assertIn("成果", rendered)
        device = vault_sync._device_state(self.fixture.data)
        saved = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(saved)
        assert saved is not None
        self.assertEqual(saved[1]["task_id"], topology["task_beta"])
        self.assertEqual(saved[1]["binding_id"], source_identity.binding_id)
        self.assertEqual(saved[1]["identity_kind"], "source")
        self.assertEqual(saved[1]["artifact_snapshot"], {})

    def test_explicit_route_correction_supersedes_wrong_primary_route(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.git.ensure()
        session_id = "wrong-auto-route-correction"
        wrong = self.fixture.confirm_source_route(
            session_id,
            self.fixture.task_id,
        )
        alpha_current_path = (
            self.fixture.clone_remote("before-route-correction")
            / f"tasks/{self.fixture.task_id}/CURRENT.json"
        )
        alpha_current_before = alpha_current_path.read_bytes()

        review = vault_sync.begin_route_switch_review_command(
            types.SimpleNamespace(
                workspace=str(self.fixture.workspace),
                existing_session_id=session_id,
                workspace_mode="session-only",
            ),
            engine,
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=review["request_id"],
                task_id=topology["task_beta"],
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            review["request_id"],
            [topology["task_beta"]],
        )
        vault_sync.prepare_route_switch_choice_command(
            types.SimpleNamespace(
                request_id=review["request_id"],
                task_id=[topology["task_beta"]],
                workspace=str(self.fixture.workspace),
                existing_session_id=session_id,
                workspace_mode="session-only",
            ),
            engine,
        )
        prechoice_head = self.fixture.remote_head()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.switch_task_route_command(
                types.SimpleNamespace(
                    task_id=topology["task_beta"],
                    workspace=str(self.fixture.workspace),
                    existing_session_id=session_id,
                    workspace_mode="session-only",
                    user_decision_token=None,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), prechoice_head)
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                turn="explicit-route-correction-choice",
                prompt="1",
            )
        )
        decision_token = self.routing_decision_token(submitted)
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.switch_task_route_command(
                types.SimpleNamespace(
                    task_id=topology["task_beta"],
                    workspace=str(self.fixture.workspace),
                    existing_session_id=session_id,
                    workspace_mode="shared",
                    user_decision_token=decision_token,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), prechoice_head)
        corrected = vault_sync.switch_task_route_command(
            types.SimpleNamespace(
                task_id=topology["task_beta"],
                workspace=str(self.fixture.workspace),
                existing_session_id=session_id,
                workspace_mode="session-only",
                user_decision_token=decision_token,
            ),
            engine,
        )

        self.assertEqual(corrected["status"], "corrected")
        self.assertEqual(
            corrected["previous_task_id"],
            self.fixture.task_id,
        )
        self.assertEqual(corrected["task_id"], topology["task_beta"])
        self.assertTrue(corrected["artifact_publication_blocked"])
        resolved = vault_sync.resolve_source_identity(
            engine.git,
            session_id,
        )
        self.assertEqual(resolved.task_id, topology["task_beta"])
        self.assertNotEqual(resolved.binding_id, wrong.binding_id)
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.load_remote_task(engine.git, wrong)
        replacement = engine.git.show_json(
            f"bindings/confirmed/{resolved.binding_id}.json"
        )
        self.assertEqual(
            replacement["supersedes_binding_id"],
            wrong.binding_id,
        )
        original = engine.git.show_json(
            f"bindings/confirmed/{wrong.binding_id}.json"
        )
        self.assertEqual(original["state"], "confirmed")
        self.assertEqual(
            original["targets"][0]["semantic_task_id"],
            self.fixture.task_id,
        )
        clone = self.fixture.clone_remote("after-route-correction")
        self.assertEqual(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes(),
            alpha_current_before,
        )
        self.assertTrue(
            (self.fixture.workspace / ".vault_identity.yaml").exists()
        )
        self.assertFalse(
            (self.fixture.workspace / ".vault_identities.json").exists()
        )
        decision_path = vault_sync._routing_decision_path(
            self.fixture.data,
            decision_token,
        )
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        self.assertEqual(decision["state"], "consumed")
        choice = vault_sync._load_routing_choice(
            self.fixture.data,
            review["request_id"],
        )
        self.assertIsNotNone(choice)
        assert choice is not None
        self.assertEqual(choice[1]["state"], "consumed")
        device = vault_sync._device_state(self.fixture.data)
        saved = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(saved)
        assert saved is not None
        turn_key = vault_sync._turn_key(
            device,
            session_id,
            "explicit-route-correction-choice",
        )
        staged = json.loads(
            vault_sync._prompt_path(
                self.fixture.data,
                saved[0],
                turn_key,
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(staged["task_id"], topology["task_beta"])
        replay_head = self.fixture.remote_head()
        with self.assertRaises(vault_sync.VaultSyncError):
            vault_sync.switch_task_route_command(
                types.SimpleNamespace(
                    task_id=topology["task_beta"],
                    workspace=str(self.fixture.workspace),
                    existing_session_id=session_id,
                    workspace_mode="session-only",
                    user_decision_token=decision_token,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), replay_head)

    def _valid_shared_workspace_identities(
        self,
    ) -> tuple[
        Any,
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.git.ensure()
        primary = json.loads(
            (
                self.fixture.workspace / ".vault_identity.yaml"
            ).read_text(encoding="utf-8")
        )

        def identity_for(task_id: str, suffix: str) -> dict[str, Any]:
            current_path = f"tasks/{task_id}/CURRENT.json"
            current = engine.git.show_json(current_path)
            manifest_bytes = engine.git.show_bytes(current["manifest_path"])
            identity = dict(primary)
            identity.update(
                {
                    "binding_id": f"bnd-workspace-{suffix}",
                    "semantic_task_id": task_id,
                    "workspace_lineage_id": f"lineage-{suffix}",
                    "base": {
                        "snapshot_id": current["snapshot_id"],
                        "manifest_sha256": vault_sync.sha256_bytes(
                            manifest_bytes
                        ),
                        "current_blob_sha": engine.git.blob_sha(current_path),
                        "transaction_id": current[
                            "published_transaction_id"
                        ],
                    },
                }
            )
            return identity

        return (
            engine,
            primary,
            identity_for(topology["task_beta"], "beta"),
            identity_for(topology["task_gamma"], "gamma"),
        )

    def test_shared_workspace_routes_exact_source_to_one_task_identity(self) -> None:
        single_marker = self.fixture.workspace / ".vault_identity.yaml"
        primary = json.loads(single_marker.read_text(encoding="utf-8"))
        secondary = dict(primary)
        secondary.update(
            {
                "binding_id": "bnd-beta",
                "semantic_task_id": "task-beta",
                "workspace_lineage_id": "lineage-beta",
            }
        )
        single_marker.unlink()
        write_json(
            self.fixture.workspace / ".vault_identities.json",
            {
                "schema_version": "portable-workspace-set/v1",
                "vault_id": "codex-memory-vault",
                "identities": [primary, secondary],
            },
        )
        selected = self.fixture.workspace / "task-alpha-result.bin"
        selected.write_bytes(b"alpha only")
        unselected = self.fixture.workspace / "task-beta-result.bin"
        unselected.write_bytes(b"beta must not be read")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v2",
                "tasks": [
                    {
                        "semantic_task_id": self.fixture.task_id,
                        "artifacts": [selected.name],
                    },
                    {
                        "semantic_task_id": "task-beta",
                        "artifacts": [unselected.name],
                    },
                ],
            },
        )

        with self.assertRaises(vault_sync.UnboundIdentityError):
            vault_sync.resolve_workspace(
                self.fixture.workspace,
                self.fixture.config["privacy"]["allowed_roots"],
            )
        routed = vault_sync.resolve_workspace(
            self.fixture.workspace,
            self.fixture.config["privacy"]["allowed_roots"],
            task_id=self.fixture.task_id,
        )
        self.assertEqual(routed.task_id, self.fixture.task_id)

        session_id = self.fixture.source_session_id
        engine = self.fixture.engine()
        started = engine.session_start(
            self.fixture.session_input(session=session_id)
        )
        self.assertIn("Generation: 1", json.dumps(started, ensure_ascii=False))
        device = vault_sync._device_state(self.fixture.data)
        session_state = vault_sync._load_session(
            self.fixture.data, device, session_id
        )[1]
        self.assertEqual(session_state["identity_kind"], "workspace")
        self.assertEqual(session_state["task_id"], self.fixture.task_id)
        engine.user_prompt_submit(
            self.fixture.prompt_input(session=session_id, turn="shared-turn")
        )
        stopped = engine.stop(
            self.fixture.stop_input(session=session_id, turn="shared-turn")
        )
        self.assertNotIn("systemMessage", stopped)

        clone = self.fixture.clone_remote("inspect-shared-workspace")
        current = json.loads(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (clone / current["manifest_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["artifacts"]), 1)
        self.assertEqual(
            manifest["artifacts"][0]["sha256"],
            vault_sync.sha256_bytes(selected.read_bytes()),
        )
        self.assertEqual(
            manifest["artifacts"][0]["display_name"],
            selected.name,
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_shared_workspace_without_exact_source_route_allows_only_provisional_conversation(
        self,
    ) -> None:
        engine, primary, secondary, _tertiary = (
            self._valid_shared_workspace_identities()
        )
        single_marker = self.fixture.workspace / ".vault_identity.yaml"
        single_marker.unlink()
        write_json(
            self.fixture.workspace / ".vault_identities.json",
            {
                "schema_version": "portable-workspace-set/v1",
                "vault_id": "codex-memory-vault",
                "identities": [primary, secondary],
            },
        )
        artifact = self.fixture.workspace / "must-remain-blocked.bin"
        artifact.write_bytes(b"shared workspace artifact must stay blocked")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v2",
                "tasks": [
                    {
                        "semantic_task_id": self.fixture.task_id,
                        "artifacts": [artifact.name],
                    }
                ],
            },
        )
        session = "unknown-shared-source"
        output = engine.session_start(
            self.fixture.session_input(session=session)
        )
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("MEMORY_VAULT_ROUTING", context)
        self.assertIn("unbound_pending_model", context)
        device = vault_sync._device_state(self.fixture.data)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(record)
        assert record is not None
        request_id = str(record[1]["request_id"])
        self.assertEqual(record[1]["state"], "pending")
        self.assertEqual(
            record[1]["workspace_root"],
            str(self.fixture.workspace.resolve()),
        )

        with (
            mock.patch.object(
                vault_sync,
                "artifact_snapshot",
                side_effect=AssertionError(
                    "provisional conversation matching inspected artifacts"
                ),
            ),
            mock.patch.object(
                engine,
                "_drive",
                side_effect=AssertionError(
                    "provisional conversation matching accessed Drive"
                ),
            ),
        ):
            prepared = vault_sync.prepare_auto_match_command(
                self.auto_match_args(request_id),
                engine,
            )
            engine.git.fetch()
            current_path = f"tasks/{self.fixture.task_id}/CURRENT.json"
            current_before_stop = engine.git.show_bytes(current_path)
            engine.user_prompt_submit(
                self.fixture.prompt_input(
                    session=session,
                    turn="shared-provisional-turn",
                )
            )
            stopped = engine.stop(
                self.fixture.stop_input(
                    session=session,
                    turn="shared-provisional-turn",
                )
            )

        self.assertEqual(prepared["status"], "provisional_active")
        self.assertEqual(prepared["authority"], "read_only_provisional")
        self.assertFalse(prepared["artifacts_loaded"])
        self.assertIn("recoverable candidate", stopped["systemMessage"])
        local_session = vault_sync._load_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(local_session)
        assert local_session is not None
        self.assertEqual(
            local_session[1]["identity_kind"],
            "provisional_source",
        )
        self.assertEqual(local_session[1]["artifact_snapshot"], {})
        self.assertTrue(
            local_session[1]["adoption"]["artifact_publication_blocked"]
        )
        self.assertNotIn("workspace_lineage_id", local_session[1])
        engine.git.fetch()
        self.assertEqual(
            engine.git.show_bytes(current_path),
            current_before_stop,
        )
        candidate_versions = [
            engine.git.show_json(path)
            for path in engine.git.list_paths(
                f"tasks/{self.fixture.task_id}/versions"
            )
            if path.endswith(".json")
            and engine.git.show_json(path).get("state") == "candidate"
        ]
        self.assertEqual(len(candidate_versions), 1)
        self.assertEqual(candidate_versions[0]["artifacts"], [])

    def test_shared_workspace_routing_rejects_marker_added_after_request(
        self,
    ) -> None:
        engine, primary, secondary, _tertiary = (
            self._valid_shared_workspace_identities()
        )
        workspace = self.fixture.allowed / "shared-marker-added"
        workspace.mkdir()
        session = "shared-marker-added-after-request"
        output = engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=workspace,
            )
        )
        self.assertIn(
            "MEMORY_VAULT_ROUTING",
            output["hookSpecificOutput"]["additionalContext"],
        )
        device = vault_sync._device_state(self.fixture.data)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(record)
        assert record is not None
        write_json(
            workspace / ".vault_identities.json",
            {
                "schema_version": "portable-workspace-set/v1",
                "vault_id": "codex-memory-vault",
                "identities": [primary, secondary],
            },
        )

        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.routing_candidates_command(
                types.SimpleNamespace(request_id=record[1]["request_id"]),
                engine,
            )
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session,
            )
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_shared_workspace_routing_rejects_marker_changed_after_request(
        self,
    ) -> None:
        engine, primary, secondary, tertiary = (
            self._valid_shared_workspace_identities()
        )
        single_marker = self.fixture.workspace / ".vault_identity.yaml"
        single_marker.unlink()
        marker = self.fixture.workspace / ".vault_identities.json"
        write_json(
            marker,
            {
                "schema_version": "portable-workspace-set/v1",
                "vault_id": "codex-memory-vault",
                "identities": [primary, secondary],
            },
        )
        session = "shared-marker-changed-after-request"
        output = engine.session_start(
            self.fixture.session_input(session=session)
        )
        self.assertIn(
            "MEMORY_VAULT_ROUTING",
            output["hookSpecificOutput"]["additionalContext"],
        )
        device = vault_sync._device_state(self.fixture.data)
        record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(record)
        assert record is not None
        write_json(
            marker,
            {
                "schema_version": "portable-workspace-set/v1",
                "vault_id": "codex-memory-vault",
                "identities": [primary, tertiary],
            },
        )

        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.prepare_auto_match_command(
                self.auto_match_args(str(record[1]["request_id"])),
                engine,
            )
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session,
            )
        )

    def test_shared_workspace_invalid_markers_allow_content_routing_only(
        self,
    ) -> None:
        engine, primary, secondary, _tertiary = (
            self._valid_shared_workspace_identities()
        )
        valid_set = {
            "schema_version": "portable-workspace-set/v1",
            "vault_id": "codex-memory-vault",
            "identities": [primary, secondary],
        }
        malformed_set = dict(valid_set)
        malformed_set["unexpected"] = True
        cases = {
            "malformed": (None, malformed_set),
            "conflicting": (primary, valid_set),
        }
        device = vault_sync._device_state(self.fixture.data)
        for case, (single_identity, identity_set) in cases.items():
            with self.subTest(case=case):
                workspace = self.fixture.allowed / f"shared-{case}-marker"
                workspace.mkdir()
                if single_identity is not None:
                    write_json(
                        workspace / ".vault_identity.yaml",
                        single_identity,
                    )
                write_json(
                    workspace / ".vault_identities.json",
                    identity_set,
                )
                session = f"shared-{case}-marker"
                output = engine.session_start(
                    self.fixture.session_input(
                        session=session,
                        workspace=workspace,
                    )
                )

                rendered = json.dumps(output, ensure_ascii=False)
                self.assertIn("MEMORY_VAULT_ROUTING", rendered)
                self.assertIn("成果身份无效", rendered)
                request = vault_sync._load_routing_request_for_session(
                    self.fixture.data,
                    device,
                    session,
                )
                self.assertIsNotNone(request)
                assert request is not None
                self.assertIsNotNone(
                    request[1]["workspace_identity_fingerprint"]
                )
                self.assertIsNone(
                    vault_sync._load_session(
                        self.fixture.data,
                        device,
                        session,
                    )
                )

    def test_split_reconcile_refuses_to_guess_before_one_time_route(self) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        result = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        rows = {item["task_id"]: item for item in result["tasks"]}
        self.assertEqual(rows[self.fixture.task_id]["local_state"], "in_sync")
        self.assertEqual(
            rows[topology["task_beta"]]["local_state"],
            "awaiting_split_route",
        )
        self.assertEqual(
            rows[topology["task_gamma"]]["local_state"],
            "awaiting_split_route",
        )
        self.assertEqual(result["materialized"], [])
        self.assertEqual(
            result["decisions"][0]["status"],
            "needs_one_time_decision",
        )
        projection_root = Path(topology["projection_root"])
        self.assertFalse((projection_root / topology["task_beta"]).exists())
        self.assertFalse((projection_root / topology["task_gamma"]).exists())

    def test_late_split_source_observation_keeps_projected_children_ambiguous(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        initial = engine.reconcile(
            materialize=True,
            extra_workspaces=[self.fixture.workspace],
        )
        self.assertEqual(len(initial["materialized"]), 2)

        observed = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        decision = observed["decisions"][0]
        self.assertEqual(
            set(decision["candidate_task_ids"]),
            {topology["task_beta"], topology["task_gamma"]},
        )
        rows = {item["task_id"]: item for item in observed["tasks"]}
        self.assertEqual(
            rows[topology["task_beta"]]["local_state"],
            "awaiting_split_route",
        )
        self.assertEqual(
            rows[topology["task_gamma"]]["local_state"],
            "awaiting_split_route",
        )
        self.assertEqual(observed["materialized"], [])

    def test_confirmed_split_route_maps_existing_and_materializes_missing(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        remote_before = self.fixture.remote_head()
        with self.assertRaises(
            vault_sync.StructuralRouteCorrectionRequired
        ):
            vault_sync.confirm_split_route_command(
                types.SimpleNamespace(
                    event_id=topology["event_id"],
                    target_task_id=topology["task_beta"],
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), remote_before)
        confirmation = self.fixture.install_confirmed_split_route_fixture(
            topology,
            topology["task_beta"],
        )
        self.assertEqual(confirmation["source_sequence_from"], 1)

        result = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        rows = {item["task_id"]: item for item in result["tasks"]}
        self.assertEqual(rows[topology["task_beta"]]["local_state"], "mapped")
        self.assertEqual(
            rows[topology["task_gamma"]]["local_state"],
            "ready_to_open",
        )
        self.assertEqual(len(result["materialized"]), 1)
        projected = (
            Path(topology["projection_root"]) / topology["task_gamma"]
        )
        identity = vault_sync.parse_identity(
            projected / ".vault_identity.yaml"
        )
        self.assertEqual(identity.task_id, topology["task_gamma"])

        repeated = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        self.assertEqual(repeated["materialized"], [])
        stabilized = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        self.assertFalse(stabilized["changed"])
        idempotent = vault_sync.confirm_split_route_command(
            types.SimpleNamespace(
                event_id=topology["event_id"],
                target_task_id=topology["task_beta"],
            ),
            engine,
        )
        self.assertEqual(idempotent["status"], "already_confirmed")

    def test_legacy_split_route_cannot_rebase_local_task_state(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        installed = self.fixture.install_confirmed_split_route_fixture(
            topology,
            topology["task_beta"],
            content_attested=False,
        )
        self.assertTrue(installed["binding_id"])
        engine = self.fixture.engine()

        result = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        self.assertEqual(
            result["decisions"][0]["status"],
            "needs_content_revalidation",
        )
        rows = {item["task_id"]: item for item in result["tasks"]}
        self.assertEqual(
            rows[topology["task_beta"]]["local_state"],
            "awaiting_split_route",
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "full-content-attested",
        ):
            vault_sync.confirm_split_route_command(
                types.SimpleNamespace(
                    event_id=topology["event_id"],
                    target_task_id=topology["task_beta"],
                ),
                engine,
            )
        sessions_root = self.fixture.data / "state" / "sessions"
        self.assertFalse(
            sessions_root.exists() and any(sessions_root.glob("*.json"))
        )

    def test_compact_refuses_preupgrade_legacy_split_session_cache(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        installed = self.fixture.install_confirmed_split_route_fixture(
            topology,
            topology["task_beta"],
            content_attested=False,
        )
        engine = self.fixture.engine()
        engine.git.ensure()
        source = engine.git.show_json(
            f"sources/{topology['source_id']}/SOURCE.json"
        )
        session_id = "combined-local-task"
        device = vault_sync._device_state(self.fixture.data)
        session_key = vault_sync._session_key(device, session_id)
        stale_context = "STALE LEGACY SPLIT CONTEXT MUST NOT LOAD"
        vault_sync._save_session(
            self.fixture.data,
            session_key,
            {
                "schema_version": vault_sync.SESSION_SCHEMA,
                "continuation_context_contract": (
                    vault_sync.CONTINUATION_CONTEXT_CONTRACT
                ),
                "identity_kind": "source",
                "task_id": topology["task_beta"],
                "binding_id": installed["binding_id"],
                "source_id": topology["source_id"],
                "source_external_key_sha256": source[
                    "external_source_key_sha256"
                ],
                "base": {},
                "base_manifest": {},
                "artifact_snapshot": {},
                "continuation_context": stale_context,
                "pending_context_injection": False,
                "needs_remote_refresh": False,
                "started_at": "2026-07-28T00:00:00Z",
            },
        )

        compact_input = self.fixture.session_input(
            session=session_id,
            workspace=self.fixture.projectless,
        )
        compact_input["source"] = "compact"
        compact = engine.session_start(compact_input)
        compact_text = json.dumps(compact, ensure_ascii=False)
        self.assertNotIn(stale_context, compact_text)
        self.assertIn("revalidation", compact_text)

        reconciled = engine.reconcile(
            materialize=True,
            extra_source_ids=[topology["source_id"]],
            extra_workspaces=[self.fixture.workspace],
        )
        self.assertIn("session_identity:identity", reconciled["local_errors"])
        self.assertEqual(
            reconciled["decisions"][0]["status"],
            "needs_content_revalidation",
        )
        rows = {item["task_id"]: item for item in reconciled["tasks"]}
        self.assertEqual(
            rows[topology["task_beta"]]["local_state"],
            "awaiting_split_route",
        )

    def test_split_route_lazily_attaches_the_existing_native_task(self) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        self.fixture.install_confirmed_split_route_fixture(
            topology,
            topology["task_beta"],
        )

        output = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="combined-local-task",
                turn="turn-after-route",
                workspace=self.fixture.projectless,
            )
        )

        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Task: Second child task", context)
        device = vault_sync._device_state(self.fixture.data)
        session = vault_sync._load_session(
            self.fixture.data,
            device,
            "combined-local-task",
        )[1]
        self.assertEqual(session["task_id"], topology["task_beta"])
        self.assertEqual(session["identity_kind"], "source")

    def test_new_native_handoff_is_fail_closed_without_creation_receipt(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        self.fixture.install_confirmed_split_route_fixture(
            topology,
            topology["task_beta"],
        )
        identity_before = (
            self.fixture.workspace / ".vault_identity.yaml"
        ).read_bytes()
        with self.assertRaisesRegex(
            vault_sync.ConfigurationError,
            "create-thread receipt",
        ):
            vault_sync.prepare_native_handoff_command(
                types.SimpleNamespace(
                    task_id=topology["task_gamma"],
                    workspace=str(self.fixture.workspace),
                    preserve_task_id=[topology["task_beta"]],
                ),
                engine,
            )
        self.assertEqual(
            (self.fixture.workspace / ".vault_identity.yaml").read_bytes(),
            identity_before,
        )
        self.assertFalse(
            (self.fixture.data / "state" / "native-handoffs").exists()
        )

    def test_unbound_existing_task_cannot_bypass_content_routing_by_adoption(
        self,
    ) -> None:
        engine = self.fixture.engine()
        remote_before = self.fixture.remote_head()
        handoff_root = self.fixture.data / "state" / "native-handoffs"

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "content review and explicit routing confirmation",
        ):
            vault_sync.prepare_existing_adoption_command(
                types.SimpleNamespace(
                    task_id=self.fixture.task_id,
                    workspace=str(self.fixture.workspace),
                    existing_session_id="never-bound-old-task",
                    preserve_task_id=[],
                ),
                engine,
            )

        self.assertEqual(self.fixture.remote_head(), remote_before)
        self.assertFalse(
            handoff_root.exists() and any(handoff_root.glob("*.json"))
        )

    def test_existing_adoption_is_scoped_to_exact_old_task_and_blocks_old_files(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        old_session = "old-windows-review-task"
        stale = self.fixture.workspace / "旧稿.docx"
        with vault_sync.zipfile.ZipFile(stale, "w") as archive:
            archive.writestr("word/document.xml", "<document>stale Windows draft</document>")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": [stale.name],
            },
        )
        engine = self.fixture.engine()
        self.fixture.confirm_source_route(
            old_session,
            topology["task_gamma"],
        )
        prepared = vault_sync.prepare_existing_adoption_command(
            types.SimpleNamespace(
                task_id=topology["task_gamma"],
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
                preserve_task_id=[self.fixture.task_id],
            ),
            engine,
        )
        self.assertEqual(prepared["mode"], "existing_adoption")
        self.assertEqual(
            prepared["native_adoption"]["tool"],
            "codex_app.send_message_to_thread",
        )
        self.assertNotIn("native_creation", prepared)
        identities_before = {
            identity.task_id
            for identity in vault_sync._portable_identities_in_workspace(
                self.fixture.workspace
            )
        }
        self.assertEqual(identities_before, {self.fixture.task_id})

        adoption_prompt = prepared["native_adoption"]["initial_prompt"]
        self.assertIn("不要仅因旧记录不同", adoption_prompt)
        self.assertNotIn("先核对差异", adoption_prompt)
        marker = vault_sync.NATIVE_HANDOFF_MARKER_RE.search(adoption_prompt)
        self.assertIsNotNone(marker)
        token = marker.group(1)
        token_path = vault_sync._native_handoff_path(self.fixture.data, token)
        token_text = token_path.read_text(encoding="utf-8")
        self.assertNotIn(old_session, token_text)
        self.assertIn(
            vault_sync._codex_source_key(old_session),
            token_text,
        )

        wrong = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="another-task-in-the-same-workspace",
                turn="wrong-adoption-turn",
                prompt=adoption_prompt,
                workspace=self.fixture.workspace,
            )
        )
        self.assertIn("systemMessage", wrong)
        self.assertTrue(token_path.exists())
        identities_after_wrong_target = {
            identity.task_id
            for identity in vault_sync._portable_identities_in_workspace(
                self.fixture.workspace
            )
        }
        self.assertEqual(
            identities_after_wrong_target,
            {self.fixture.task_id},
        )
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.resolve_source_identity(
                engine.git,
                "another-task-in-the-same-workspace",
            )

        adopted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=old_session,
                turn="adoption-turn",
                prompt=adoption_prompt,
                workspace=self.fixture.workspace,
            )
        )
        context = adopted["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Task: Third child task", context)
        self.assertIn("reference-only", context)
        self.assertFalse(token_path.exists())
        identities_after_adoption = {
            identity.task_id
            for identity in vault_sync._portable_identities_in_workspace(
                self.fixture.workspace
            )
        }
        self.assertEqual(
            identities_after_adoption,
            {self.fixture.task_id, topology["task_gamma"]},
        )

        first_stop = engine.stop(
            self.fixture.stop_input(
                session=old_session,
                turn="adoption-turn",
                workspace=self.fixture.workspace,
            )
        )
        self.assertNotIn("systemMessage", first_stop)
        device = vault_sync._device_state(self.fixture.data)
        refreshed_session = vault_sync._load_session(
            self.fixture.data,
            device,
            old_session,
        )[1]
        self.assertIn(
            vault_sync.ADOPTION_CONTEXT_PREFIX,
            refreshed_session["continuation_context"],
        )
        compact_input = self.fixture.session_input(
            session=old_session,
            workspace=self.fixture.workspace,
        )
        compact_input["source"] = "compact"
        compact = engine.session_start(compact_input)
        self.assertIn(
            vault_sync.ADOPTION_CONTEXT_PREFIX,
            compact["hookSpecificOutput"]["additionalContext"],
        )
        clone = self.fixture.clone_remote("inspect-old-task-adoption")
        current = json.loads(
            (
                clone / f"tasks/{topology['task_gamma']}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (clone / current["manifest_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["artifacts"], [])
        self.assertEqual(stale.read_bytes()[:2], b"PK")

        stale.write_bytes(stale.read_bytes() + b"changed but still blocked")
        engine.session_start(
            self.fixture.session_input(
                session=old_session,
                workspace=self.fixture.workspace,
            )
        )
        resumed = vault_sync._load_session(
            self.fixture.data,
            device,
            old_session,
        )[1]
        self.assertTrue(resumed["adoption"]["artifact_publication_blocked"])
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=old_session,
                turn="blocked-after-resume",
                workspace=self.fixture.workspace,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session=old_session,
                turn="blocked-after-resume",
                workspace=self.fixture.workspace,
            )
        )
        clone_after_resume = self.fixture.clone_remote(
            "inspect-blocked-after-resume"
        )
        current_after_resume = json.loads(
            (
                clone_after_resume
                / f"tasks/{topology['task_gamma']}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest_after_resume = json.loads(
            (
                clone_after_resume / current_after_resume["manifest_path"]
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest_after_resume["artifacts"], [])

    def test_existing_adoption_requires_explicit_task_scoped_artifact_approval(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        old_session = "old-windows-artifact-task"
        engine = self.fixture.engine()
        self.fixture.confirm_source_route(
            old_session,
            topology["task_gamma"],
        )
        prepared = vault_sync.prepare_existing_adoption_command(
            types.SimpleNamespace(
                task_id=topology["task_gamma"],
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
                preserve_task_id=[self.fixture.task_id],
            ),
            engine,
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=old_session,
                turn="adopt-and-reconcile",
                prompt=prepared["native_adoption"]["initial_prompt"],
                workspace=self.fixture.workspace,
            )
        )
        reconciled = self.fixture.workspace / "第三篇-已核对.docx"
        with vault_sync.zipfile.ZipFile(reconciled, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<document>verified continuation based on cloud CURRENT</document>",
            )
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v2",
                "tasks": [
                    {
                        "semantic_task_id": topology["task_gamma"],
                        "artifacts": [reconciled.name],
                    }
                ],
            },
        )
        inspected = vault_sync.inspect_existing_adoption_artifacts_command(
            types.SimpleNamespace(
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
            ),
            engine,
        )
        self.assertEqual(inspected["artifacts"], [reconciled.name])
        publish_path = self.fixture.workspace / ".vault_publish.json"
        reviewed_publish = json.loads(publish_path.read_text(encoding="utf-8"))
        changed_before_approval = json.loads(
            json.dumps(reviewed_publish, ensure_ascii=False)
        )
        changed_before_approval["tasks"][0]["artifacts"].append(
            "changed-after-inspection.docx"
        )
        write_json(publish_path, changed_before_approval)
        with self.assertRaises(vault_sync.ConflictError):
            vault_sync.approve_existing_adoption_artifacts_command(
                types.SimpleNamespace(
                    workspace=str(self.fixture.workspace),
                    existing_session_id=old_session,
                    expected_manifest_sha256=inspected["manifest_sha256"],
                ),
                engine,
            )
        write_json(publish_path, reviewed_publish)
        approved = vault_sync.approve_existing_adoption_artifacts_command(
            types.SimpleNamespace(
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
                expected_manifest_sha256=inspected["manifest_sha256"],
            ),
            engine,
        )
        self.assertEqual(approved["status"], "artifacts_reconciled")
        engine.stop(
            self.fixture.stop_input(
                session=old_session,
                turn="adopt-and-reconcile",
                workspace=self.fixture.workspace,
            )
        )
        clone = self.fixture.clone_remote("inspect-approved-adoption")
        current = json.loads(
            (
                clone / f"tasks/{topology['task_gamma']}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (clone / current["manifest_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["artifacts"]), 1)
        self.assertEqual(
            manifest["artifacts"][0]["sha256"],
            vault_sync.sha256_bytes(reconciled.read_bytes()),
        )

        extra = self.fixture.workspace / "未经再次核对.docx"
        with vault_sync.zipfile.ZipFile(extra, "w") as archive:
            archive.writestr("word/document.xml", "<document>not approved</document>")
        publish = json.loads(
            (
                self.fixture.workspace / ".vault_publish.json"
            ).read_text(encoding="utf-8")
        )
        publish["tasks"][0]["artifacts"].append(extra.name)
        write_json(self.fixture.workspace / ".vault_publish.json", publish)
        engine.session_start(
            self.fixture.session_input(
                session=old_session,
                workspace=self.fixture.workspace,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=old_session,
                turn="manifest-changed-without-approval",
                workspace=self.fixture.workspace,
            )
        )
        engine.stop(
            self.fixture.stop_input(
                session=old_session,
                turn="manifest-changed-without-approval",
                workspace=self.fixture.workspace,
            )
        )
        clone_after_change = self.fixture.clone_remote(
            "inspect-unapproved-manifest-change"
        )
        current_after_change = json.loads(
            (
                clone_after_change
                / f"tasks/{topology['task_gamma']}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest_after_change = json.loads(
            (
                clone_after_change / current_after_change["manifest_path"]
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest_after_change["artifacts"]), 1)
        self.assertEqual(
            manifest_after_change["artifacts"][0]["sha256"],
            vault_sync.sha256_bytes(reconciled.read_bytes()),
        )
        device = vault_sync._device_state(self.fixture.data)
        identity = vault_sync.resolve_workspace(
            self.fixture.workspace,
            self.fixture.config["privacy"]["allowed_roots"],
            task_id=topology["task_gamma"],
        )
        local_guard = vault_sync._load_adoption_guard(
            self.fixture.data,
            device,
            identity.workspace_root,
            identity.task_id,
        )[1]
        self.assertTrue(local_guard["artifact_publication_blocked"])
        self.assertIsNone(local_guard["approved_publish_manifest_sha256"])

    def test_approved_adoption_copy_requires_new_device_local_approval(
        self,
    ) -> None:
        old_session = "old-windows-single-task"
        self.fixture.confirm_source_route("fresh-device-native-task")
        self.fixture.confirm_source_route(old_session)
        engine = self.fixture.engine()
        prepared = vault_sync.prepare_existing_adoption_command(
            types.SimpleNamespace(
                task_id=self.fixture.task_id,
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
                preserve_task_id=[],
            ),
            engine,
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=old_session,
                turn="single-task-adoption",
                prompt=prepared["native_adoption"]["initial_prompt"],
                workspace=self.fixture.workspace,
            )
        )
        artifact = self.fixture.workspace / "核对后成果.docx"
        with vault_sync.zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<document>approved on the first device</document>",
            )
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v2",
                "tasks": [
                    {
                        "semantic_task_id": self.fixture.task_id,
                        "artifacts": [artifact.name],
                    }
                ],
            },
        )
        inspected = vault_sync.inspect_existing_adoption_artifacts_command(
            types.SimpleNamespace(
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
            ),
            engine,
        )
        vault_sync.approve_existing_adoption_artifacts_command(
            types.SimpleNamespace(
                workspace=str(self.fixture.workspace),
                existing_session_id=old_session,
                expected_manifest_sha256=inspected["manifest_sha256"],
            ),
            engine,
        )
        adopted_identity = vault_sync.resolve_workspace(
            self.fixture.workspace,
            self.fixture.config["privacy"]["allowed_roots"],
            task_id=self.fixture.task_id,
        )
        portable_guard = vault_sync._portable_adoption_for(adopted_identity)
        self.assertIsNotNone(portable_guard)
        self.assertTrue(portable_guard["artifact_publication_blocked"])
        engine.stop(
            self.fixture.stop_input(
                session=old_session,
                turn="single-task-adoption",
                workspace=self.fixture.workspace,
            )
        )

        copied = self.fixture.allowed / "复制到另一设备的旧任务"
        shutil.copytree(self.fixture.workspace, copied)
        other_data = self.fixture.root / "fresh-device-plugin-data"
        other_config = json.loads(
            json.dumps(self.fixture.config, ensure_ascii=False)
        )
        write_json(other_data / "config.json", other_config)
        other_engine = vault_sync.SyncEngine(other_config, other_data)
        copied_artifact = copied / artifact.name
        with vault_sync.zipfile.ZipFile(copied_artifact, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<document>changed on copied device before approval</document>",
            )
        started = other_engine.session_start(
            self.fixture.session_input(
                session="fresh-device-native-task",
                workspace=copied,
            )
        )
        self.assertIn(
            "artifact publication is blocked",
            json.dumps(started, ensure_ascii=False),
        )
        other_engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="fresh-device-native-task",
                turn="fresh-device-turn",
                workspace=copied,
            )
        )
        other_engine.stop(
            self.fixture.stop_input(
                session="fresh-device-native-task",
                turn="fresh-device-turn",
                workspace=copied,
            )
        )
        clone = self.fixture.clone_remote("inspect-fresh-device-copy")
        current = json.loads(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (clone / current["manifest_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(len(manifest["artifacts"]), 1)
        self.assertNotEqual(
            manifest["artifacts"][0]["sha256"],
            vault_sync.sha256_bytes(copied_artifact.read_bytes()),
        )

    def test_existing_adoption_refuses_changed_identity_and_pending_checkpoint(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        changed_session = "old-task-with-changed-identity"
        changed_route = self.fixture.confirm_source_route(
            changed_session,
            topology["task_gamma"],
        )
        prepared = vault_sync.prepare_existing_adoption_command(
            types.SimpleNamespace(
                task_id=topology["task_gamma"],
                workspace=str(self.fixture.workspace),
                existing_session_id=changed_session,
                preserve_task_id=[self.fixture.task_id],
            ),
            engine,
        )
        marker = vault_sync.NATIVE_HANDOFF_MARKER_RE.search(
            prepared["native_adoption"]["initial_prompt"]
        )
        self.assertIsNotNone(marker)
        token_path = vault_sync._native_handoff_path(
            self.fixture.data,
            marker.group(1),
        )
        identity_path = self.fixture.workspace / ".vault_identity.yaml"
        identity_value = json.loads(identity_path.read_text(encoding="utf-8"))
        identity_value["base"]["transaction_id"] = "tx-locally-changed"
        write_json(identity_path, identity_value)
        refused = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=changed_session,
                turn="changed-identity-turn",
                prompt=prepared["native_adoption"]["initial_prompt"],
                workspace=self.fixture.workspace,
            )
        )
        self.assertIn("systemMessage", refused)
        self.assertTrue(token_path.exists())
        unchanged_route = vault_sync.resolve_source_identity(
            engine.git,
            changed_session,
        )
        self.assertEqual(
            unchanged_route.binding_id,
            changed_route.binding_id,
        )
        self.assertEqual(
            unchanged_route.task_id,
            topology["task_gamma"],
        )

        identity_value["base"]["transaction_id"] = "tx-initial"
        write_json(identity_path, identity_value)
        pending_session = "old-task-with-pending-checkpoint"
        self.fixture.confirm_source_route(pending_session)
        engine.session_start(
            self.fixture.session_input(
                session=pending_session,
                workspace=self.fixture.workspace,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=pending_session,
                turn="pending-old-turn",
                workspace=self.fixture.workspace,
            )
        )
        transaction, state = engine._queue_stop(
            self.fixture.stop_input(
                session=pending_session,
                turn="pending-old-turn",
                workspace=self.fixture.workspace,
            )
        )
        self.assertEqual(state, "pending")
        pending_prepared = vault_sync.prepare_existing_adoption_command(
            types.SimpleNamespace(
                task_id=self.fixture.task_id,
                workspace=str(self.fixture.workspace),
                existing_session_id=pending_session,
                preserve_task_id=[],
            ),
            engine,
        )
        pending_marker = vault_sync.NATIVE_HANDOFF_MARKER_RE.search(
            pending_prepared["native_adoption"]["initial_prompt"]
        )
        self.assertIsNotNone(pending_marker)
        pending_token_path = vault_sync._native_handoff_path(
            self.fixture.data,
            pending_marker.group(1),
        )
        pending_refused = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=pending_session,
                turn="adoption-before-old-flush",
                prompt=pending_prepared["native_adoption"]["initial_prompt"],
                workspace=self.fixture.workspace,
            )
        )
        self.assertIn("systemMessage", pending_refused)
        self.assertTrue(pending_token_path.exists())
        self.assertTrue(
            vault_sync._outbox_path(
                self.fixture.data,
                "pending",
                transaction,
            ).exists()
        )

    def test_multi_task_workspace_rejects_unscoped_publish_v1(self) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.git.ensure()
        remote = vault_sync.load_remote_task_by_id(
            engine.git,
            topology["task_gamma"],
        )
        vault_sync._merge_workspace_identity_documents(
            self.fixture.workspace,
            [
                vault_sync._portable_identity_document(
                    engine.git,
                    remote,
                    vault_sync.WorkspaceAuthority(
                        binding_id="bnd-workspace-gamma",
                        task_id=topology["task_gamma"],
                        lineage_id="lineage-gamma",
                    ),
                )
            ],
        )
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": [],
            },
        )
        identity = vault_sync.resolve_workspace(
            self.fixture.workspace,
            self.fixture.config["privacy"]["allowed_roots"],
            task_id=topology["task_gamma"],
        )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._artifact_declarations(identity)

    def test_new_device_materializes_remote_task_catalog_without_duplicates(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        first_engine = self.fixture.engine()
        self.fixture.install_confirmed_split_route_fixture(
            topology,
            topology["task_beta"],
        )

        other_allowed = self.root / "另一台设备工作区"
        other_projection = other_allowed / "接力任务"
        other_projection.mkdir(parents=True)
        other_data = self.root / "other plugin data"
        other_config = json.loads(json.dumps(self.fixture.config))
        other_config["privacy"]["allowed_roots"] = [str(other_allowed)]
        other_config["projection"] = {
            "enabled": True,
            "root": str(other_projection),
            "materialize_missing": True,
        }
        write_json(other_data / "config.json", other_config)
        other_engine = vault_sync.SyncEngine(other_config, other_data)
        result = other_engine.reconcile(materialize=True)
        materialized_ids = {
            item["task_id"] for item in result["materialized"]
        }
        self.assertEqual(
            materialized_ids,
            {
                self.fixture.task_id,
                topology["task_beta"],
                topology["task_gamma"],
            },
        )
        self.assertFalse(
            (other_projection / topology["coordinator"]).exists()
        )
        repeated = other_engine.reconcile(materialize=True)
        self.assertEqual(repeated["materialized"], [])

    def test_preexisting_declared_artifact_is_not_assumed_backed_up(self) -> None:
        artifact = self.fixture.workspace / "启动前成果.bin"
        artifact.write_bytes(b"created before the first plugin session")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["启动前成果.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        result = engine.stop(self.fixture.stop_input())
        self.assertNotIn("systemMessage", result)
        clone = self.fixture.clone_remote("preexisting-artifact")
        current = json.loads(
            (clone / f"tasks/{self.fixture.task_id}/CURRENT.json").read_text(encoding="utf-8")
        )
        manifest = json.loads((clone / current["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["artifacts"]), 1)
        self.assertEqual(
            manifest["artifacts"][0]["sha256"],
            vault_sync.sha256_bytes(artifact.read_bytes()),
        )

    def test_stop_publishes_visible_turn_and_changed_artifact(self) -> None:
        self.fixture.confirm_source_route("session-next-device")
        artifact = self.fixture.workspace / "实验结果.docx"
        with vault_sync.zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("word/document.xml", "<document>version one</document>")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["实验结果.docx"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        with vault_sync.zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<document>version two is immutable</document>",
            )
        expected_artifact = artifact.read_bytes()
        engine.user_prompt_submit(self.fixture.prompt_input())
        output = engine.stop(self.fixture.stop_input())
        self.assertNotIn("systemMessage", output)

        clone = self.fixture.clone_remote()
        current = json.loads(
            (clone / f"tasks/{self.fixture.task_id}/CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(current["generation"], 2)
        manifest = json.loads((clone / current["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["state"], "published")
        self.assertEqual(len(manifest["artifacts"]), 1)
        published_artifact = manifest["artifacts"][0]
        digest = published_artifact["sha256"]
        self.assertEqual(
            published_artifact["storage_ref"]["schema_version"],
            vault_sync.ARTIFACT_STORAGE_REF_SCHEMA,
        )
        self.assertEqual(
            published_artifact["storage_ref"]["driver"],
            "filesystem-test",
        )
        self.assertNotIn("drive_file_id", published_artifact)
        self.assertNotIn("drive_parent_id", published_artifact)
        self.assertTrue(
            (self.fixture.drive / "objects" / "sha256" / digest[:2] / digest).is_file()
        )
        source_files = list((clone / "sources").glob("*/revisions/*.json"))
        self.assertEqual(len(source_files), 2)
        current_source = manifest["conversation_sources"][-1]
        current_source_path = clone / current_source["content_path"]
        conversation = json.loads(
            current_source_path.read_text(encoding="utf-8")
        )
        self.assertEqual([item["role"] for item in conversation["messages"]], ["user", "assistant"])
        self.assertNotIn(
            "transcript_path",
            current_source_path.read_text(encoding="utf-8"),
        )
        second_device_data = self.root / "second-device-data"
        write_json(second_device_data / "config.json", self.fixture.config)
        second_device = vault_sync.SyncEngine(
            self.fixture.config, second_device_data
        )
        resumed = second_device.session_start(
            self.fixture.session_input(session="session-next-device")
        )
        resumed_text = json.dumps(resumed, ensure_ascii=False)
        self.assertIn("继续完成本任务", resumed_text)
        self.assertIn("已经完成本轮修改", resumed_text)
        versioned = list(
            (
                self.fixture.workspace
                / ".memory-vault"
                / "versions"
                / self.fixture.task_id
                / current["snapshot_id"]
            ).glob("artifact-*")
        )
        downloaded = [path for path in versioned if not path.name.startswith("RECEIPT-")]
        self.assertEqual(len(downloaded), 1)
        self.assertEqual(downloaded[0].read_bytes(), expected_artifact)
        self.assertEqual(artifact.read_bytes(), expected_artifact)

    def test_large_artifact_stop_queues_until_explicit_flush(self) -> None:
        self.fixture.confirm_source_route("stop-queue-large-artifact")
        self.fixture.config["sync"]["max_stop_upload_bytes"] = 1
        artifact = self.fixture.workspace / "大型结果.bin"
        artifact.write_bytes(b"baseline")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["大型结果.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        artifact.write_bytes(b"changed artifact that should stay queued")
        engine.user_prompt_submit(self.fixture.prompt_input())

        output = engine.stop(self.fixture.stop_input())
        self.assertIn("queued this checkpoint locally", output["systemMessage"])
        pending = list((self.fixture.data / "outbox" / "pending").glob("*.json"))
        self.assertEqual(len(pending), 1)
        before = self.fixture.clone_remote("large-artifact-before-flush")
        current_before = json.loads(
            (
                before
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(current_before["generation"], 1)

        self.assertEqual(engine.flush_once(transaction_id=pending[0].stem), "done")
        after = self.fixture.clone_remote("large-artifact-after-flush")
        current_after = json.loads(
            (
                after
                / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(current_after["generation"], 2)

    def test_blocked_outbox_requires_explicit_retry_and_is_visible_in_status(
        self,
    ) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        with mock.patch.object(
            engine.git,
            "ensure",
            side_effect=vault_sync.AuthenticationError("credentials expired"),
        ):
            output = engine.stop(self.fixture.stop_input())
        self.assertIn("blocked", output["systemMessage"])
        pending = list((self.fixture.data / "outbox" / "pending").glob("*.json"))
        self.assertEqual(len(pending), 1)
        transaction = pending[0].stem
        intent = json.loads(pending[0].read_text(encoding="utf-8"))
        self.assertEqual(intent["recovery"]["status"], "blocked")
        self.assertEqual(
            engine.status()["outbox_recovery"]["blocked"],
            1,
        )
        self.assertFalse(
            next(
                check
                for check in engine.doctor()["checks"]
                if check["name"] == "outbox_recovery"
            )["ok"]
        )

        duplicate = engine.stop(self.fixture.stop_input())
        self.assertIn("blocked", duplicate["systemMessage"])
        self.assertEqual(engine.flush_once(transaction_id=transaction), "blocked")
        self.assertEqual(
            engine.flush_once(
                transaction_id=transaction,
                retry_blocked=True,
            ),
            "done",
        )

    def test_distinct_artifacts_upload_in_parallel_and_duplicate_content_once(
        self,
    ) -> None:
        engine = self.fixture.engine()
        payloads = (b"parallel-a", b"parallel-b", b"parallel-a")
        artifacts: list[dict[str, Any]] = []
        for index, payload in enumerate(payloads):
            digest = vault_sync.sha256_bytes(payload)
            relative = f"spool/sha256/{digest[:2]}/{digest}"
            path = self.fixture.data / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            artifacts.append(
                {
                    "logical_path": f"result-{index}.bin",
                    "display_name": f"result-{index}.bin",
                    "spool_path": relative,
                    "sha256": digest,
                    "size": len(payload),
                    "mime_type": "application/octet-stream",
                    "stat": [1, 1, len(payload), index, digest],
                }
            )
        intent = {
            "transaction_id": "tx-parallel-artifacts",
            "state": "queued",
            "provider_pins": engine.provider_pins,
            "artifacts": artifacts,
        }
        pending = vault_sync._outbox_path(
            self.fixture.data,
            "pending",
            intent["transaction_id"],
        )
        write_json(pending, intent)

        class ParallelAdapter(vault_sync.DriveAdapter):
            store_id = vault_sync.DEFAULT_OBJECT_STORE_ID
            driver = "filesystem-test"

            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.gate = threading.Event()
                self.active = 0
                self.max_active = 0
                self.uploaded: list[str] = []

            def assert_private(self) -> None:
                return None

            def find_verified(
                self,
                sha256: str,
                size: int,
                mime_type: str,
            ) -> vault_sync.VerifiedDriveObject | None:
                return None

            def upload_and_verify(
                self,
                path: Path,
                sha256: str,
                size: int,
                mime_type: str,
            ) -> vault_sync.VerifiedDriveObject:
                with self.lock:
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                    self.uploaded.append(sha256)
                    if self.active >= 2:
                        self.gate.set()
                self.gate.wait(timeout=2)
                with self.lock:
                    self.active -= 1
                return vault_sync.VerifiedDriveObject(
                    store_id=self.store_id,
                    driver=self.driver,
                    file_id=f"object-{sha256[:16]}",
                    parent_id="root-private",
                    sha256=sha256,
                    size=size,
                    mime_type=mime_type,
                    verification_level="remote-content-sha256-verified",
                )

            def download_and_verify(
                self,
                artifact: Mapping[str, Any],
                destination: Path,
            ) -> None:
                raise AssertionError("download is not part of this test")

        adapter = ParallelAdapter()
        original_hash_file = vault_sync.stable_hash_file
        hash_calls: list[Path] = []

        def counted_hash_file(path: Path, *args: Any, **kwargs: Any) -> Any:
            hash_calls.append(path)
            return original_hash_file(path, *args, **kwargs)

        with mock.patch.object(engine, "_drive", return_value=adapter), mock.patch.object(
            vault_sync,
            "stable_hash_file",
            side_effect=counted_hash_file,
        ):
            engine._upload_artifacts(intent, pending)

        self.assertEqual(adapter.max_active, 2)
        self.assertEqual(len(adapter.uploaded), 2)
        self.assertEqual(len(hash_calls), 2)
        self.assertEqual(
            artifacts[0]["storage"]["file_id"],
            artifacts[2]["storage"]["file_id"],
        )
        persisted = json.loads(pending.read_text(encoding="utf-8"))
        self.assertTrue(
            all("storage" in artifact for artifact in persisted["artifacts"])
        )
        manifest_artifacts = vault_sync._merge_artifacts(
            {"artifacts": []},
            intent,
            preserve_replaced=False,
        )
        self.assertEqual(len(manifest_artifacts), 3)
        self.assertEqual(
            len({artifact["artifact_id"] for artifact in manifest_artifacts}),
            3,
        )
        self.assertEqual(
            len(
                {
                    artifact["storage_ref"]["object_id"]
                    for artifact in manifest_artifacts
                }
            ),
            2,
        )

    def test_parallel_partial_success_is_persisted_and_reused_on_retry(
        self,
    ) -> None:
        engine = self.fixture.engine()
        payloads = (b"parallel-success", b"parallel-failure")
        artifacts: list[dict[str, Any]] = []
        for index, payload in enumerate(payloads):
            digest = vault_sync.sha256_bytes(payload)
            relative = f"spool/sha256/{digest[:2]}/{digest}"
            path = self.fixture.data / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            artifacts.append(
                {
                    "logical_path": f"partial-{index}.bin",
                    "display_name": f"partial-{index}.bin",
                    "spool_path": relative,
                    "sha256": digest,
                    "size": len(payload),
                    "mime_type": "application/octet-stream",
                    "stat": [1, 1, len(payload), index, digest],
                }
            )
        intent = {
            "transaction_id": "tx-partial-parallel-artifacts",
            "state": "queued",
            "artifacts": artifacts,
        }
        pending = vault_sync._outbox_path(
            self.fixture.data,
            "pending",
            intent["transaction_id"],
        )
        write_json(pending, intent)
        success_sha = artifacts[0]["sha256"]
        failure_sha = artifacts[1]["sha256"]

        def verified(
            sha256: str,
            size: int,
            mime_type: str,
        ) -> vault_sync.VerifiedDriveObject:
            return vault_sync.VerifiedDriveObject(
                store_id=vault_sync.DEFAULT_OBJECT_STORE_ID,
                driver="filesystem-test",
                file_id=f"object-{sha256[:16]}",
                parent_id="root-private",
                sha256=sha256,
                size=size,
                mime_type=mime_type,
                verification_level="remote-content-sha256-verified",
            )

        first = mock.MagicMock(spec=vault_sync.DriveAdapter)
        first.store_id = vault_sync.DEFAULT_OBJECT_STORE_ID
        first.driver = "filesystem-test"
        first.assert_private.return_value = None
        first.should_chunk.return_value = False
        first.find_verified.return_value = None

        def first_upload(
            path: Path,
            sha256: str,
            size: int,
            mime_type: str,
        ) -> vault_sync.VerifiedDriveObject:
            if sha256 == failure_sha:
                raise vault_sync.OfflineError("simulated object-store outage")
            return verified(sha256, size, mime_type)

        first.upload_and_verify.side_effect = first_upload
        with (
            mock.patch.object(engine, "_drive", return_value=first),
            self.assertRaises(vault_sync.OfflineError),
        ):
            engine._upload_artifacts(intent, pending)

        partial = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(partial["state"], "queued")
        self.assertIn("storage", partial["artifacts"][0])
        self.assertNotIn("storage", partial["artifacts"][1])

        second = mock.MagicMock(spec=vault_sync.DriveAdapter)
        second.store_id = vault_sync.DEFAULT_OBJECT_STORE_ID
        second.driver = "filesystem-test"
        second.assert_private.return_value = None
        second.should_chunk.return_value = False

        def second_find(
            sha256: str,
            size: int,
            mime_type: str,
        ) -> vault_sync.VerifiedDriveObject | None:
            if sha256 == success_sha:
                return verified(sha256, size, mime_type)
            return None

        second.find_verified.side_effect = second_find
        second.upload_and_verify.side_effect = (
            lambda path, sha256, size, mime_type: verified(
                sha256,
                size,
                mime_type,
            )
        )
        retry_intent = partial
        with mock.patch.object(engine, "_drive", return_value=second):
            engine._upload_artifacts(retry_intent, pending)

        self.assertEqual(second.upload_and_verify.call_count, 1)
        self.assertEqual(
            second.upload_and_verify.call_args.args[1],
            failure_sha,
        )
        completed = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(completed["state"], "drive_verified")
        self.assertTrue(
            all("storage" in artifact for artifact in completed["artifacts"])
        )

    def test_pending_publish_avoids_redundant_pre_publish_fetch(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        with mock.patch.object(
            engine.git,
            "fetch",
            wraps=engine.git.fetch,
        ) as fetch:
            output = engine.stop(self.fixture.stop_input())
        self.assertNotIn("systemMessage", output)
        # _publish_git fetches once before the CAS comparison and once after
        # the push verification; ensure() must not add a third fetch.
        self.assertEqual(fetch.call_count, 2)

    def test_retry_backoff_preserves_fairness_for_ready_work(self) -> None:
        self.fixture.confirm_source_route("retry-fairness")
        self.fixture.config["sync"]["max_stop_upload_bytes"] = 1
        artifact = self.fixture.workspace / "fairness.bin"
        artifact.write_bytes(b"baseline")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["fairness.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        artifact.write_bytes(b"first queued revision")
        engine.user_prompt_submit(
            self.fixture.prompt_input(turn="turn-one", prompt="第一轮排队。")
        )
        engine.stop(
            self.fixture.stop_input(
                turn="turn-one",
                assistant="第一轮先排队。",
            )
        )
        artifact.write_bytes(b"second queued revision")
        engine.user_prompt_submit(
            self.fixture.prompt_input(turn="turn-two", prompt="第二轮排队。")
        )
        engine.stop(
            self.fixture.stop_input(
                turn="turn-two",
                assistant="第二轮先排队。",
            )
        )
        pending = sorted(
            (self.fixture.data / "outbox" / "pending").glob("*.json"),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
        )
        self.assertEqual(len(pending), 2)
        first, second = (path.stem for path in pending)
        with mock.patch.object(
            engine.git,
            "ensure",
            side_effect=[
                vault_sync.VaultSyncError("temporary failure"),
                vault_sync.VaultSyncError("temporary failure"),
            ],
        ):
            self.assertEqual(engine.flush_once(transaction_id=first), "pending")
            self.assertEqual(engine.flush_once(transaction_id=first), "pending")
        first_intent = json.loads(pending[0].read_text(encoding="utf-8"))
        self.assertEqual(first_intent["recovery"]["status"], "retryable")
        self.assertIsNotNone(first_intent["recovery"]["next_attempt_at"])
        self.assertEqual(engine.flush_once(), "done")
        self.assertTrue(
            (self.fixture.data / "outbox" / "pending" / f"{first}.json").exists()
        )
        self.assertTrue(
            (self.fixture.data / "outbox" / "done" / f"{second}.json").exists()
        )

    def test_offline_git_retries_without_drive_reupload(self) -> None:
        self.fixture.confirm_source_route("session-retry")
        artifact = self.fixture.workspace / "dataset.bin"
        artifact.write_bytes(b"A" * 8192)
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["dataset.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        artifact.write_bytes(b"B" * 8192)
        engine.user_prompt_submit(self.fixture.prompt_input())
        hidden_remote = self.root / "remote-offline.git"
        self.fixture.remote.rename(hidden_remote)
        output = engine.stop(self.fixture.stop_input())
        self.assertIn("systemMessage", output)
        pending = list((self.fixture.data / "outbox" / "pending").glob("*.json"))
        self.assertEqual(len(pending), 1)
        intent = json.loads(pending[0].read_text(encoding="utf-8"))
        self.assertEqual(intent["state"], "drive_verified")
        digest = intent["artifacts"][0]["sha256"]
        drive_object = (
            self.fixture.drive / "objects" / "sha256" / digest[:2] / digest
        )
        before = drive_object.stat().st_mtime_ns
        hidden_remote.rename(self.fixture.remote)
        restarted_engine = self.fixture.engine()
        resumed = restarted_engine.session_start(
            self.fixture.session_input(session="session-retry")
        )
        self.assertNotIn("systemMessage", resumed)
        self.assertEqual(before, drive_object.stat().st_mtime_ns)
        self.assertFalse(pending[0].exists())

    def test_concurrent_update_becomes_candidate_without_current_change(self) -> None:
        self.fixture.confirm_source_route("session-after-conflict")
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        expected_current = self.fixture.advance_remote("other-device")
        output = engine.stop(self.fixture.stop_input())
        self.assertIn("conflict candidate", output["systemMessage"])
        clone = self.fixture.clone_remote()
        actual_current = (
            clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
        ).read_bytes()
        self.assertEqual(actual_current, expected_current)
        candidates = []
        for path in (clone / f"tasks/{self.fixture.task_id}/versions").glob("*.json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("state") == "candidate":
                candidates.append(value)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["parents"][0]["snapshot_id"], "snap-initial")
        self.assertEqual(
            len(list((self.fixture.data / "outbox" / "candidate").glob("*.json"))),
            1,
        )
        conflict_device_data = self.root / "conflict-device-data"
        write_json(conflict_device_data / "config.json", self.fixture.config)
        conflict_device = vault_sync.SyncEngine(
            self.fixture.config, conflict_device_data
        )
        resumed = conflict_device.session_start(
            self.fixture.session_input(session="session-after-conflict")
        )
        resumed_text = json.dumps(resumed, ensure_ascii=False)
        self.assertIn("Unresolved conflict candidates", resumed_text)
        self.assertIn(candidates[0]["snapshot_id"], resumed_text)

    def test_other_remote_change_does_not_create_false_conflict(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        clone = self.fixture.clone_remote("other-task-change")
        run(["git", "config", "user.name", "Other device"], clone)
        run(["git", "config", "user.email", "other@localhost"], clone)
        (clone / "unrelated-note.txt").write_text("unrelated remote change\n")
        run(["git", "add", "--", "unrelated-note.txt"], clone)
        run(["git", "commit", "-m", "change another area"], clone)
        run(["git", "push", "origin", "main"], clone)
        engine.user_prompt_submit(self.fixture.prompt_input())
        output = engine.stop(self.fixture.stop_input())
        self.assertNotIn("systemMessage", output)
        inspect = self.fixture.clone_remote("inspect-other-task")
        current = json.loads(
            (inspect / f"tasks/{self.fixture.task_id}/CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(current["generation"], 2)
        self.assertTrue((inspect / "unrelated-note.txt").is_file())
        self.assertFalse(
            any(
                json.loads(path.read_text(encoding="utf-8")).get("state") == "candidate"
                for path in (
                    inspect / f"tasks/{self.fixture.task_id}/versions"
                ).glob("*.json")
            )
        )

    def test_drive_privacy_failure_never_updates_current(self) -> None:
        artifact = self.fixture.workspace / "result.bin"
        artifact.write_bytes(b"initial")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["result.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        baseline = (
            self.fixture.seed / f"tasks/{self.fixture.task_id}/CURRENT.json"
        ).read_bytes()
        artifact.write_bytes(b"changed")
        write_json(
            self.fixture.drive / ".memory-vault-private.json",
            {
                "vault_id": "codex-memory-vault",
                "owner_only": True,
                "shared": True,
            },
        )
        engine.user_prompt_submit(self.fixture.prompt_input())
        output = engine.stop(self.fixture.stop_input())
        self.assertIn("systemMessage", output)
        inspect = self.fixture.clone_remote("inspect-drive-failure")
        self.assertEqual(
            (
                inspect / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes(),
            baseline,
        )
        pending = list((self.fixture.data / "outbox" / "pending").glob("*.json"))
        self.assertEqual(len(pending), 1)
        intent = json.loads(pending[0].read_text(encoding="utf-8"))
        self.assertEqual(intent["state"], "queued")

    def test_duplicate_stop_is_idempotent(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        engine.stop(self.fixture.stop_input())
        clone = self.fixture.clone_remote()
        before = run(["git", "rev-parse", "HEAD"], clone)
        engine.stop(self.fixture.stop_input())
        run(["git", "pull", "--ff-only"], clone)
        after = run(["git", "rev-parse", "HEAD"], clone)
        self.assertEqual(before, after)
        self.assertEqual(engine.flush_once(), "noop")

    def test_same_session_two_successful_turns_refreshes_baseline(self) -> None:
        self.fixture.confirm_source_route("fresh-session")
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                turn="turn-one", prompt="第一轮完成方法部分。"
            )
        )
        first = engine.stop(
            self.fixture.stop_input(
                turn="turn-one", assistant="第一轮已保存，下一步整理结果。"
            )
        )
        self.assertNotIn("systemMessage", first)
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                turn="turn-two", prompt="第二轮继续整理结果。"
            )
        )
        second = engine.stop(
            self.fixture.stop_input(
                turn="turn-two", assistant="第二轮已保存，下一步复核图表。"
            )
        )
        self.assertNotIn("systemMessage", second)
        clone = self.fixture.clone_remote("two-turns")
        current = json.loads(
            (clone / f"tasks/{self.fixture.task_id}/CURRENT.json").read_text(encoding="utf-8")
        )
        self.assertEqual(current["generation"], 3)
        manifest = json.loads((clone / current["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["conversation_sources"]), 3)
        self.assertFalse(
            any(
                json.loads(path.read_text(encoding="utf-8")).get("state") == "candidate"
                for path in (
                    clone / f"tasks/{self.fixture.task_id}/versions"
                ).glob("*.json")
            )
        )
        fresh_data = self.root / "third-device"
        write_json(fresh_data / "config.json", self.fixture.config)
        resumed = vault_sync.SyncEngine(
            self.fixture.config, fresh_data
        ).session_start(self.fixture.session_input(session="fresh-session"))
        text = json.dumps(resumed, ensure_ascii=False)
        self.assertIn("第一轮已保存", text)
        self.assertIn("第二轮已保存", text)

    def test_immutable_spool_survives_source_overwrite(self) -> None:
        self.fixture.confirm_source_route("spool-retry")
        artifact = self.fixture.workspace / "queued-result.bin"
        artifact.write_bytes(b"baseline")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["queued-result.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        queued_bytes = b"immutable queued version"
        artifact.write_bytes(queued_bytes)
        engine.user_prompt_submit(self.fixture.prompt_input())
        hidden_remote = self.root / "remote-hidden-for-spool.git"
        self.fixture.remote.rename(hidden_remote)
        result = engine.stop(self.fixture.stop_input())
        self.assertIn("systemMessage", result)
        artifact.write_bytes(b"new unqueued version")
        hidden_remote.rename(self.fixture.remote)
        resumed = self.fixture.engine().session_start(
            self.fixture.session_input(session="spool-retry")
        )
        self.assertNotIn("systemMessage", resumed)
        clone = self.fixture.clone_remote("inspect-spool")
        current = json.loads(
            (clone / f"tasks/{self.fixture.task_id}/CURRENT.json").read_text(encoding="utf-8")
        )
        manifest = json.loads((clone / current["manifest_path"]).read_text(encoding="utf-8"))
        digest = manifest["artifacts"][0]["sha256"]
        drive_file = (
            self.fixture.drive / "objects" / "sha256" / digest[:2] / digest
        )
        self.assertEqual(drive_file.read_bytes(), queued_bytes)
        self.assertEqual(artifact.read_bytes(), b"new unqueued version")

    def test_remote_validator_is_never_executed(self) -> None:
        clone = self.fixture.clone_remote("malicious-validator")
        run(["git", "config", "user.name", "Other device"], clone)
        run(["git", "config", "user.email", "other@localhost"], clone)
        marker = self.root / "remote-code-executed.txt"
        validator = clone / "scripts" / "validate_layout_v1.py"
        validator.parent.mkdir(parents=True)
        validator.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('unsafe')\n",
            encoding="utf-8",
        )
        run(["git", "add", "--", "scripts/validate_layout_v1.py"], clone)
        run(["git", "commit", "-m", "add untrusted validator"], clone)
        run(["git", "push", "origin", "main"], clone)
        engine = self.fixture.engine()
        engine.config["_test_mode"] = False
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        output = engine.stop(self.fixture.stop_input())
        self.assertNotIn("systemMessage", output)
        self.assertFalse(marker.exists())

    def test_cached_git_origin_mismatch_is_rejected(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        other = self.root / "other-private.git"
        run(["git", "init", "--bare", str(other)])
        engine.git._run_bare(
            ["config", "remote.origin.url", str(other)]
        )
        with self.assertRaises(vault_sync.PrivacyError):
            engine.git.fetch()

    def test_git_config_environment_cannot_rewrite_remote(self) -> None:
        self.fixture.confirm_source_route("isolated-git-env")
        evil = self.root / "redirected.git"
        run(["git", "init", "--bare", str(evil)])
        fresh_data = self.root / "environment-isolation-data"
        write_json(fresh_data / "config.json", self.fixture.config)
        keys = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"url.{evil}.insteadOf",
            "GIT_CONFIG_VALUE_0": str(self.fixture.remote),
        }
        previous = {key: os.environ.get(key) for key in keys}
        os.environ.update(keys)
        try:
            engine = vault_sync.SyncEngine(self.fixture.config, fresh_data)
            output = engine.session_start(
                self.fixture.session_input(session="isolated-git-env")
            )
        finally:
            for key, old in previous.items():
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old
        self.assertIn("Generation: 1", json.dumps(output, ensure_ascii=False))
        actual = engine.git._run_bare(
            ["config", "--get", "remote.origin.url"]
        ).stdout.decode().strip()
        self.assertEqual(Path(actual).resolve(), self.fixture.remote.resolve())

    def test_spool_snapshot_does_not_hide_a_later_source_change(self) -> None:
        artifact = self.fixture.workspace / "racing-result.bin"
        artifact.write_bytes(b"baseline")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["racing-result.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        artifact.write_bytes(b"version-a")
        original_spool = engine._spool_artifacts

        def spool_then_change(items: Any) -> Any:
            result = original_spool(items)
            artifact.write_bytes(b"version-bb")
            return result

        engine._spool_artifacts = spool_then_change
        engine.user_prompt_submit(self.fixture.prompt_input())
        output = engine.stop(self.fixture.stop_input())
        self.assertNotIn("systemMessage", output)
        device = vault_sync._device_state(self.fixture.data)
        session = vault_sync._load_session(
            self.fixture.data, device, "session-a"
        )[1]
        identity = vault_sync.resolve_workspace(
            self.fixture.workspace, self.fixture.config["privacy"]["allowed_roots"]
        )
        later = vault_sync.changed_artifacts(
            identity, session["artifact_snapshot"], self.fixture.config
        )
        self.assertEqual(len(later), 1)
        self.assertEqual(later[0]["sha256"], vault_sync.sha256_bytes(b"version-bb"))

    def test_ctime_detects_same_size_change_with_restored_mtime(self) -> None:
        self.fixture.confirm_source_route("ctime-first")
        self.fixture.confirm_source_route("ctime-second")
        artifact = self.fixture.workspace / "ctime-result.bin"
        artifact.write_bytes(b"version-one")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["ctime-result.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input("ctime-first"))
        engine.user_prompt_submit(
            self.fixture.prompt_input(session="ctime-first", turn="ctime-turn-one")
        )
        engine.stop(
            self.fixture.stop_input(session="ctime-first", turn="ctime-turn-one")
        )
        engine.session_start(self.fixture.session_input("ctime-second"))
        before = artifact.stat()
        artifact.write_bytes(b"version-two")
        os.utime(
            artifact,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(session="ctime-second", turn="ctime-turn-two")
        )
        result = engine.stop(
            self.fixture.stop_input(session="ctime-second", turn="ctime-turn-two")
        )
        self.assertNotIn("systemMessage", result)
        clone = self.fixture.clone_remote("ctime-artifact")
        current = json.loads(
            (clone / f"tasks/{self.fixture.task_id}/CURRENT.json").read_text(encoding="utf-8")
        )
        manifest = json.loads((clone / current["manifest_path"]).read_text(encoding="utf-8"))
        self.assertIn(
            vault_sync.sha256_bytes(b"version-two"),
            {item["sha256"] for item in manifest["artifacts"]},
        )

    def test_lock_file_symlink_is_rejected(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        target = self.root / "lock-target"
        target.write_bytes(b"x")
        link = self.root / "lock-link"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symbolic links are not permitted")
        with self.assertRaises(vault_sync.PrivacyError):
            with vault_sync.FileLock(link):
                self.fail("unsafe lock unexpectedly opened")

    def test_lock_file_hardlink_is_rejected_without_mutating_target(self) -> None:
        target = self.root / "hardlink-target"
        target.write_bytes(b"")
        link = self.root / "hardlink-lock"
        try:
            os.link(target, link)
        except OSError:
            self.skipTest("hard links are not permitted")
        before_mode = target.stat().st_mode
        with self.assertRaises(vault_sync.PrivacyError):
            with vault_sync.FileLock(link):
                self.fail("hard-linked lock unexpectedly opened")
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(target.stat().st_mode, before_mode)

    def test_windows_style_metadata_match_still_rechecks_content_hash(self) -> None:
        artifact = self.fixture.workspace / "windows-recheck.bin"
        artifact.write_bytes(b"version-one")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["windows-recheck.bin"],
            },
        )
        old_sha = vault_sync.sha256_bytes(artifact.read_bytes())
        artifact.write_bytes(b"version-two")
        metadata = artifact.stat()
        simulated_windows_snapshot = {
            "windows-recheck.bin": [
                int(metadata.st_size),
                int(metadata.st_mtime_ns),
                int(getattr(metadata, "st_ino", 0)),
                int(getattr(metadata, "st_ctime_ns", 0)),
                old_sha,
            ]
        }
        identity = vault_sync.resolve_workspace(
            self.fixture.workspace,
            self.fixture.config["privacy"]["allowed_roots"],
        )
        with mock.patch.object(
            vault_sync,
            "_requires_content_hash_recheck",
            return_value=True,
        ):
            changed = vault_sync.changed_artifacts(
                identity,
                simulated_windows_snapshot,
                self.fixture.config,
            )
        self.assertEqual(len(changed), 1)
        self.assertEqual(
            changed[0]["sha256"],
            vault_sync.sha256_bytes(b"version-two"),
        )

    def test_windows_path_and_open_file_stats_tolerate_only_unavailable_fields(
        self,
    ) -> None:
        base = {
            "st_mode": vault_sync.stat.S_IFREG,
            "st_size": 19,
            "st_mtime_ns": 123456700,
            "st_ctime_ns": 111111100,
            "st_dev": 7,
            "st_ino": 41,
            "st_nlink": 1,
        }
        named = types.SimpleNamespace(**base)
        opened = types.SimpleNamespace(
            **{
                **base,
                "st_ctime_ns": 222222200,
                "st_dev": 0,
                "st_ino": 0,
                "st_nlink": 0,
            }
        )
        self.assertTrue(
            vault_sync._stable_file_observations_match(
                named,
                opened,
                cross_interface=True,
            )
        )
        self.assertFalse(
            vault_sync._stable_file_observations_match(
                named,
                types.SimpleNamespace(**{**base, "st_size": 20}),
                cross_interface=True,
            )
        )
        self.assertFalse(
            vault_sync._stable_file_observations_match(
                named,
                types.SimpleNamespace(
                    **{**base, "st_mtime_ns": 123456800}
                ),
            )
        )
        self.assertFalse(
            vault_sync._stable_file_observations_match(
                named,
                types.SimpleNamespace(**{**base, "st_ino": 42}),
                cross_interface=True,
            )
        )
        self.assertFalse(
            vault_sync._stable_file_observations_match(
                named,
                opened,
            )
        )
        self.assertFalse(
            vault_sync._stable_file_observations_match(
                named,
                types.SimpleNamespace(
                    **{
                        **base,
                        "st_dev": 0,
                        "st_ino": 0,
                        "st_nlink": 0,
                    }
                ),
            )
        )

    def test_runtime_and_artifact_readers_accept_cross_api_windows_stats(
        self,
    ) -> None:
        source = self.root / "cross-api.json"
        raw = b'{"identity":"same task content"}\n'
        source.write_bytes(raw)
        named = source.stat()
        opened = types.SimpleNamespace(
            st_mode=named.st_mode,
            st_size=named.st_size,
            st_mtime_ns=named.st_mtime_ns + 100,
            st_ctime_ns=named.st_ctime_ns + 100,
            st_dev=0,
            st_ino=0,
            st_nlink=0,
        )
        with mock.patch.object(
            vault_sync.os,
            "fstat",
            side_effect=[opened, opened],
        ):
            self.assertEqual(
                vault_sync._read_bounded_plain_runtime_file(
                    source,
                    maximum_bytes=1024,
                    label="test runtime",
                ),
                raw,
            )
        with mock.patch.object(
            vault_sync.os,
            "fstat",
            side_effect=[opened, opened],
        ):
            self.assertEqual(
                vault_sync._read_routing_artifact_bytes(source),
                raw,
            )

        changed_opened = types.SimpleNamespace(
            **{
                **vars(opened),
                "st_mtime_ns": opened.st_mtime_ns + 1,
            }
        )
        with mock.patch.object(
            vault_sync.os,
            "fstat",
            side_effect=[opened, changed_opened],
        ):
            with self.assertRaises(vault_sync.BusyError):
                vault_sync._read_routing_artifact_bytes(source)

    def test_versioned_download_publish_never_overwrites_a_racing_file(self) -> None:
        source = self.root / "drive-source.bin"
        source.write_bytes(b"verified-drive-object")
        digest, size = vault_sync.stable_hash_file(source, inspect_text=False)
        destination = self.root / "versioned" / "artifact.bin"
        destination.parent.mkdir()
        operation = "rename" if os.name == "nt" else "link"
        real_operation = getattr(os, operation)

        def racing_publish(src: Any, dst: Any) -> None:
            destination.write_bytes(b"independent-local-version")
            real_operation(src, dst)

        with mock.patch.object(
            vault_sync.os, operation, side_effect=racing_publish
        ):
            with self.assertRaises(vault_sync.VerificationError):
                vault_sync._copy_verified_file(
                    source, destination, digest, size
                )
        self.assertEqual(destination.read_bytes(), b"independent-local-version")

    def test_builtin_schema_rejects_malformed_inherited_fields(self) -> None:
        malformed = {
            "schema_version": "task-version/v1",
            "snapshot_id": "snap-valid",
            "task_id": self.fixture.task_id,
            "generation": 2,
            "parents": [],
            "state": "published",
            "change_type": "content_revision",
            "transaction_id": "tx-valid",
            "continuation_readiness": "partial",
            "artifacts": [],
            "remaining_work": "this must be an array",
        }
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._validate_task_version(malformed)

    def test_contentless_import_revision_may_record_no_scan(self) -> None:
        source = {
            "schema_version": "source/v1",
            "source_id": "src-imported",
            "source_type": "codex_task",
            "external_source_key_sha256": "1" * 64,
            "source_instance_id": None,
            "visibility": "private",
            "sensitivity": "ordinary",
            "current_revision_id": "rev-metadata-000001",
            "revisions": [
                {
                    "revision_id": "rev-metadata-000001",
                    "previous_revision_id": None,
                    "source_sequence": 0,
                    "captured_at": "2026-07-28T00:00:00Z",
                    "coverage": "partial",
                    "content_ref": None,
                    "content_sha256": None,
                    "redaction": {
                        "credentials_scanned": False,
                        "content_removed": True,
                        "reason": "No conversation content was imported.",
                    },
                }
            ],
            "created_at": "2026-07-28T00:00:00Z",
        }
        vault_sync._validate_source(source)

        unsafe = json.loads(json.dumps(source))
        revision = unsafe["revisions"][0]
        revision["content_ref"] = {
            "storage": "git_blob",
            "object_id": "2" * 40,
            "object_revision_id": None,
            "byte_size": 10,
            "media_type": "application/json",
        }
        revision["content_sha256"] = "3" * 64
        revision["redaction"]["content_removed"] = False
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._validate_source(unsafe)

    def test_privacy_scanner_covers_common_cloud_oauth_and_app_tokens(self) -> None:
        rejected = (
            ("anthropic_api_key", "sk-ant-api03-" + "A" * 24),
            ("openai_api_key", "sk-" + "A" * 24),
            ("google_api_key", "AIza" + "A" * 24),
            ("aws_access_key", "AKIA" + "A" * 16),
            ("oauth_access_token", "ya29." + "A" * 24),
            ("oauth_client_secret", "GOCSPX-" + "A" * 24),
            (
                "jwt",
                "eyJ" + "A" * 20 + ".eyJ" + "B" * 20 + "." + "C" * 24,
            ),
            ("bearer_token_value", "Bearer " + "A" * 24),
            ("slack_token", "xoxb-" + "A" * 24),
            ("gitlab_token", "glpat-" + "A" * 24),
            ("npm_token", "npm_" + "A" * 32),
            ("pypi_token", "pypi-" + "A" * 24),
            ("huggingface_token", "hf_" + "A" * 32),
            ("stripe_secret_key", "sk_live_" + "A" * 24),
            ("sendgrid_token", "SG." + "A" * 20 + "." + "B" * 24),
            ("telegram_bot_token", "123456789:" + "A" * 35),
            ("digitalocean_token", "dop_v1_" + "A" * 64),
            ("square_token", "sq0atp-" + "A" * 24),
            ("generic_secret_assignment", "api_key=" + "A" * 20),
        )
        for category, value in rejected:
            with self.subTest(category=category):
                with self.assertRaises(vault_sync.PrivacyError) as caught:
                    vault_sync.scan_visible_text(value, "fixture")
                self.assertIn(f"contains {category}", str(caught.exception))
                self.assertNotIn(value, str(caught.exception))

        accepted = (
            "sk-" + "A" * 19,
            "AKIA" + "A" * 15,
            "Bearer token",
            "ordinary prose mentions /docs/guide",
            "file:///etc/private-config",
            "https://example.com/srv/app",
        )
        for value in accepted:
            with self.subTest(accepted=value):
                self.assertEqual(vault_sync.scan_visible_text(value, "fixture"), value)

        streamed = ("prefix " + "sk_live_" + "A" * 24).encode("utf-8")
        scanner = vault_sync._PrivacyStreamScanner(
            "stream fixture",
            known_text=True,
            reject_absolute_paths=True,
        )
        with self.assertRaises(vault_sync.PrivacyError):
            for offset in range(0, len(streamed), 3):
                scanner.feed(streamed[offset : offset + 3])
            scanner.finish()

        utf16 = ("api_key=" + "B" * 20).encode("utf-16-le")
        utf16_scanner = vault_sync._PrivacyStreamScanner(
            "utf16 fixture",
            known_text=True,
            reject_absolute_paths=True,
        )
        with self.assertRaises(vault_sync.PrivacyError):
            utf16_scanner.feed(utf16[:8])
            for offset in range(8, len(utf16), 2):
                utf16_scanner.feed(utf16[offset : offset + 2])
            utf16_scanner.finish()

        for path in (
            "/srv/project/config",
            "/workspace/project/output",
            "/usr/bin/python",
            "/Applications/Codex.app",
        ):
            with self.subTest(path=path):
                with self.assertRaises(vault_sync.PrivacyError):
                    vault_sync.scan_visible_text(path, "fixture")

        office = self.fixture.workspace / "cloud-secret.docx"
        with vault_sync.zipfile.ZipFile(office, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<document>api_key=" + "C" * 20 + "</document>",
            )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(office)

    def test_late_secrets_paths_and_zero_byte_artifacts_are_rejected(self) -> None:
        text_file = self.fixture.workspace / "late-secret.txt"
        token = "github_pat_" + "Z" * 32
        text_file.write_text("A" * (1024 * 1024 + 100) + token, encoding="utf-8")
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(text_file)
        for content in (
            "prefix Cookie: sessionid=abcdefghijklmnop",
            "read this path `/etc/private-config`",
        ):
            text_file.write_text(content, encoding="utf-8")
            with self.assertRaises(vault_sync.PrivacyError):
                vault_sync.stable_hash_file(text_file)
        text_file.write_bytes(b"prefix\x00\npassword=abcdefghijklmnop")
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(text_file)
        text_file.write_bytes(b"\xff\xfei")
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(text_file)
        binary = self.fixture.workspace / "opaque.bin"
        binary.write_bytes(
            b"\x00\xffbinary\n" + b"password=abcdefghijklmnop"
        )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(binary)
        binary.write_bytes(b"\x00\xffbinary\nfile:///etc/private-config")
        vault_sync.stable_hash_file(binary)
        binary.write_bytes(
            ("password=" + "utf16-secret-value").encode("utf-16-le")
        )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(binary)
        binary.write_bytes(
            (
                "汉" * 3000 + " password=abcdefghijklmnop"
            ).encode("utf-16-le")
        )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(binary)
        office = self.fixture.workspace / "secret.docx"
        with vault_sync.zipfile.ZipFile(office, "w") as archive:
            archive.writestr(
                "word/document.xml",
                "<document>client_secret=archive-secret-value</document>",
            )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(office)
        office_with_private_link = self.fixture.workspace / "linked.docx"
        with vault_sync.zipfile.ZipFile(office_with_private_link, "w") as archive:
            archive.writestr(
                "word/_rels/document.xml.rels",
                '<Relationship Target="file:///Users/example/input.png"/>',
            )
        vault_sync.stable_hash_file(office_with_private_link)
        large_archive = self.fixture.workspace / "large-secret.zip"
        with vault_sync.zipfile.ZipFile(
            large_archive,
            "w",
            compression=vault_sync.zipfile.ZIP_DEFLATED,
        ) as archive:
            archive.writestr(
                "payload.bin",
                b"A" * (5 * 1024 * 1024)
                + b"\npassword=abcdefghijklmnop",
            )
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync.stable_hash_file(large_archive)
        zero = self.fixture.workspace / "empty.bin"
        zero.write_bytes(b"temporary")
        write_json(
            self.fixture.workspace / ".vault_publish.json",
            {
                "schema_version": "vault-publish/v1",
                "artifacts": ["empty.bin"],
            },
        )
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        zero.write_bytes(b"")
        engine.user_prompt_submit(self.fixture.prompt_input())
        output = engine.stop(self.fixture.stop_input())
        self.assertIn("quarantined", output["systemMessage"])

    def test_published_then_advanced_recovers_after_lost_receipt(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        transaction, _ = engine._queue_stop(self.fixture.stop_input())
        pending = vault_sync._outbox_path(
            self.fixture.data, "pending", transaction
        )
        engine._finish_outbox = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("simulated crash after push")
        )
        with self.assertRaises(RuntimeError):
            engine.flush_once(transaction_id=transaction)
        self.assertTrue(pending.exists())
        self.fixture.advance_remote("after-published")
        recovered = self.fixture.engine().flush_once(transaction_id=transaction)
        self.assertEqual(recovered, "published_then_advanced")
        self.assertFalse(pending.exists())
        receipt = json.loads(
            vault_sync._outbox_path(
                self.fixture.data, "done", transaction
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["result"], "published_then_advanced")

    def test_push_race_retries_as_candidate_on_next_session_start(self) -> None:
        self.fixture.confirm_source_route("race-retry")
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        original = engine.git.commit_and_push
        remote_current: list[bytes] = []

        def race(git_self: Any, *args: Any, **kwargs: Any) -> str:
            remote_current.append(self.fixture.advance_remote("push-race"))
            return original(*args, **kwargs)

        engine.git.commit_and_push = types.MethodType(race, engine.git)
        first = engine.stop(self.fixture.stop_input())
        self.assertIn("offline retry", first["systemMessage"])
        resumed = self.fixture.engine().session_start(
            self.fixture.session_input(session="race-retry")
        )
        text = json.dumps(resumed, ensure_ascii=False)
        self.assertIn("Unresolved conflict candidates", text)
        clone = self.fixture.clone_remote("inspect-race")
        self.assertEqual(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes(),
            remote_current[0],
        )

    def test_full_three_process_hook_chain_and_new_device_resume(self) -> None:
        self.fixture.confirm_source_route("new-process-session")
        started = self.run_hook_process(
            "session-start", self.fixture.session_input()
        )
        self.assertIn("Generation: 1", json.dumps(started, ensure_ascii=False))
        prompted = self.run_hook_process(
            "user-prompt-submit",
            self.fixture.prompt_input(prompt="子进程链：记录今日进度。"),
        )
        self.assertTrue(prompted["continue"])
        stopped = self.run_hook_process(
            "stop",
            self.fixture.stop_input(
                assistant="子进程链已收尾，下一步检查引用。"
            ),
        )
        self.assertNotIn("systemMessage", stopped)
        new_data = self.root / "new subprocess device"
        write_json(new_data / "config.json", self.fixture.config)
        resumed = self.run_hook_process(
            "session-start",
            self.fixture.session_input(session="new-process-session"),
            data_dir=new_data,
        )
        text = json.dumps(resumed, ensure_ascii=False)
        self.assertIn("记录今日进度", text)
        self.assertIn("下一步检查引用", text)

    def test_compact_uses_cached_context_without_network(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        hidden = self.root / "remote-hidden-for-compact.git"
        self.fixture.remote.rename(hidden)
        compact = self.fixture.session_input()
        compact["source"] = "compact"
        output = engine.session_start(compact)
        self.assertIn("Generation: 1", json.dumps(output, ensure_ascii=False))
        hidden.rename(self.fixture.remote)

    def test_secret_prompt_is_quarantined_and_not_remote(self) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        prompt = "Use github_pat_" + "A" * 30
        output = engine.user_prompt_submit(
            self.fixture.prompt_input(prompt=prompt)
        )
        self.assertIn("systemMessage", output)
        engine.stop(self.fixture.stop_input())
        clone = self.fixture.clone_remote()
        all_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in clone.rglob("*")
            if path.is_file() and ".git" not in path.parts
        )
        self.assertNotIn(prompt, all_text)
        self.assertEqual(
            len(list((self.fixture.data / "outbox" / "quarantine").glob("*.json"))),
            1,
        )

    def test_copied_workspace_keeps_task_but_gets_new_instance(self) -> None:
        self.fixture.confirm_source_route("session-one")
        self.fixture.confirm_source_route("session-two")
        copy = self.fixture.allowed / "复制的科研 项目"
        shutil.copytree(self.fixture.workspace, copy)
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input("session-one"))
        engine.session_start(self.fixture.session_input("session-two", copy))
        device = vault_sync._device_state(self.fixture.data)
        first = vault_sync._load_session(
            self.fixture.data, device, "session-one"
        )[1]
        second = vault_sync._load_session(
            self.fixture.data, device, "session-two"
        )[1]
        self.assertEqual(first["task_id"], second["task_id"])
        self.assertEqual(
            first["workspace_lineage_id"], second["workspace_lineage_id"]
        )
        self.assertNotEqual(
            first["workspace_instance_id"], second["workspace_instance_id"]
        )

    def test_unsafe_identifiers_and_paths_are_rejected(self) -> None:
        bad_ids = [
            "CON",
            "nul",
            "com1",
            "UPPER",
            "a",
            "a" * 65,
            "../escape",
        ]
        for value in bad_ids:
            with self.subTest(value=value):
                with self.assertRaises(vault_sync.PrivacyError):
                    vault_sync.validate_identifier(value, "task_id")
        bad_paths = [
            "/Users/name/file",
            r"C:\Users\name\file",
            r"\\server\share\file",
            "../escape",
            "folder/../file",
            "folder/NUL.txt",
            "folder/trailing. ",
        ]
        for value in bad_paths:
            with self.subTest(value=value):
                with self.assertRaises(vault_sync.PrivacyError):
                    vault_sync.validate_repo_path(value)

    def test_hooks_have_one_cross_platform_handler_per_event(self) -> None:
        hooks = json.loads((PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        self.assertIn("clear", hooks["hooks"]["SessionStart"][0]["matcher"])
        self.assertIn("compact", hooks["hooks"]["SessionStart"][0]["matcher"])
        for event in ("SessionStart", "UserPromptSubmit", "Stop"):
            groups = hooks["hooks"][event]
            self.assertEqual(len(groups), 1)
            handlers = groups[0]["hooks"]
            self.assertEqual(len(handlers), 1)
            self.assertIn("commandWindows", handlers[0])
            self.assertIn("windows_launcher.ps1", handlers[0]["commandWindows"])
            self.assertIn(
                "${PLUGIN_DATA}/runtime/active",
                handlers[0]["command"],
            )
            self.assertIn("$env:PLUGIN_DATA", handlers[0]["commandWindows"])
            self.assertIn(
                "'runtime','active'",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime/core.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/chunks.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/diagnostics.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/signed_updates.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/crypto_adapter.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/device_trust.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/encrypted_replication.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/sharing.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime\\core.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\chunks.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\diagnostics.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\signed_updates.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\crypto_adapter.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\device_trust.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\encrypted_replication.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\sharing.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime/privacy.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime/host_adapter.py",
                handlers[0]["command"],
            )
            self.assertIn(
                "memory_vault_runtime\\privacy.py",
                handlers[0]["commandWindows"],
            )
            self.assertIn(
                "memory_vault_runtime\\host_adapter.py",
                handlers[0]["commandWindows"],
            )
            self.assertNotIn("py -", handlers[0]["commandWindows"].lower())
            self.assertNotIn("python ", handlers[0]["commandWindows"].lower())
            for unsafe_shell_operator in ("&", "|", "<", ">"):
                self.assertNotIn(
                    unsafe_shell_operator,
                    handlers[0]["commandWindows"],
                )
            self.assertNotIn("async", handlers[0])
        self.assertNotIn("SessionEnd", hooks["hooks"])

    def test_semver_comparison_never_treats_build_metadata_as_upgrade(self) -> None:
        self.assertGreater(vault_sync.compare_semver("1.2.0", "1.2.0-rc.1"), 0)
        self.assertGreater(vault_sync.compare_semver("1.2.1", "1.2.0"), 0)
        self.assertEqual(
            vault_sync.compare_semver(
                "1.2.0+codex.new",
                "1.2.0+codex.old",
            ),
            0,
        )
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.compare_semver("1.2", "1.2.0")
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.compare_semver("1.2.0-01", "1.2.0")

    def test_runtime_version_matches_plugin_manifest(self) -> None:
        manifest = json.loads(
            (
                PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["version"], vault_sync.VERSION)

    def test_private_deployment_identity_stays_in_fork_boundary(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        boundary, runtime = source.split('\nVERSION = "', 1)
        marketplace_name = json.loads(
            (
                REPOSITORY_ROOT / ".agents/plugins/marketplace.json"
            ).read_text(encoding="utf-8")
        )["name"]
        self.assertEqual(
            vault_sync.DEPLOYMENT_MARKETPLACE_NAME,
            marketplace_name,
        )
        self.assertIn(marketplace_name, boundary)
        if marketplace_name != vault_sync.PLUGIN_NAME:
            self.assertNotIn(marketplace_name, runtime)
        for private_identity in (
            "qh-work",
            "https://github.com/qh-work/memory-vault-sync.git",
        ):
            self.assertIn(private_identity, boundary)
            self.assertNotIn(private_identity, runtime)

    def test_old_config_gets_safe_automatic_update_defaults(self) -> None:
        config = vault_sync.default_config()
        del config["updates"]

        validated = vault_sync.validate_config(config)

        self.assertTrue(validated["updates"]["enabled"])
        self.assertTrue(validated["updates"]["auto_install"])
        self.assertEqual(
            validated["updates"]["check_interval_seconds"],
            vault_sync.DEFAULT_UPDATE_INTERVAL_SECONDS,
        )

    def test_old_config_gets_stop_upload_threshold_default(self) -> None:
        config = vault_sync.default_config()
        config["sync"].pop("max_stop_upload_bytes")

        validated = vault_sync.validate_config(config)

        self.assertEqual(
            validated["sync"]["max_stop_upload_bytes"],
            vault_sync.DEFAULT_MAX_STOP_UPLOAD_BYTES,
        )

    def test_old_config_gets_bounded_parallel_upload_default(self) -> None:
        config = vault_sync.default_config()
        config["sync"].pop("max_parallel_artifact_uploads")

        validated = vault_sync.validate_config(config)

        self.assertEqual(
            validated["sync"]["max_parallel_artifact_uploads"],
            vault_sync.DEFAULT_MAX_PARALLEL_ARTIFACT_UPLOADS,
        )
        for invalid in (0, vault_sync.MAX_PARALLEL_ARTIFACT_UPLOADS + 1, True):
            with self.subTest(invalid=invalid):
                candidate = vault_sync.default_config()
                candidate["sync"]["max_parallel_artifact_uploads"] = invalid
                with self.assertRaises(vault_sync.ConfigurationError):
                    vault_sync.validate_config(candidate)

    def test_generic_artifact_storage_reference_keeps_legacy_compatibility(
        self,
    ) -> None:
        common = {
            "artifact_id": "artifact-generic-reference",
            "display_name": "result.bin",
            "logical_path": "result.bin",
            "mime_type": "application/octet-stream",
            "role": "workspace-artifact",
            "sha256": "a" * 64,
            "size": 1,
            "storage_mode": "full",
        }
        generic = {
            **common,
            "storage_ref": {
                "schema_version": vault_sync.ARTIFACT_STORAGE_REF_SCHEMA,
                "store_id": vault_sync.DEFAULT_OBJECT_STORE_ID,
                "driver": "google-drive-v3",
                "object_id": "file-generic",
                "container_id": "root-private",
                "verification_level": "drive-native-sha256",
            },
        }
        legacy = {
            **common,
            "drive_file_id": "file-legacy",
            "drive_parent_id": "root-private",
        }

        vault_sync._validate_artifact(generic)
        vault_sync._validate_artifact(legacy)
        self.assertEqual(
            vault_sync._artifact_storage_ref(generic)["object_id"],
            "file-generic",
        )
        self.assertEqual(
            vault_sync._artifact_storage_ref(legacy)["object_id"],
            "file-legacy",
        )
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._validate_artifact(
                {
                    **generic,
                    "drive_file_id": "mixed-file",
                    "drive_parent_id": "mixed-root",
                }
            )

    def test_gitlab_private_control_plane_is_vendor_neutral_and_fail_closed(
        self,
    ) -> None:
        config = vault_sync.default_config()
        profile = vault_sync._provider_profile(config)
        control = profile["control_plane"]
        adapter_ref = control["adapter_config_ref"]
        credential_ref = control["credential_ref"]
        config["adapter_configs"][adapter_ref].update(
            {
                "repo_url": "https://gitlab.com/example-group/private-vault.git",
                "privacy_verifier": "gitlab-private-v1",
                "expected_repository": "example-group/private-vault",
            }
        )
        config["credential_bindings"][credential_ref]["helper_host"] = (
            "gitlab.com"
        )
        vault_sync._refresh_provider_scope_fingerprints(config)
        validated = vault_sync.validate_config(config)
        git = vault_sync.GitVault(validated, self.fixture.data)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps(
            {
                "visibility": "private",
                "path_with_namespace": "example-group/private-vault",
            }
        ).encode("utf-8")
        with (
            mock.patch.object(
                vault_sync,
                "credential_get",
                return_value={"username": "token-user", "password": "token-value"},
            ),
            mock.patch.object(
                vault_sync,
                "open_verified_url",
                return_value=response,
            ) as opener,
        ):
            git.assert_remote_private()

        request = opener.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://gitlab.com/api/v4/projects/example-group%2Fprivate-vault",
        )
        self.assertEqual(
            opener.call_args.kwargs["policy"],
            vault_sync.GITLAB_API_POLICY,
        )

        response.read.return_value = json.dumps(
            {
                "visibility": "public",
                "path_with_namespace": "example-group/private-vault",
            }
        ).encode("utf-8")
        with (
            mock.patch.object(
                vault_sync,
                "credential_get",
                return_value={"username": "token-user", "password": "token-value"},
            ),
            mock.patch.object(
                vault_sync,
                "open_verified_url",
                return_value=response,
            ),
            self.assertRaises(vault_sync.PrivacyError),
        ):
            git.assert_remote_private()

    def test_legacy_automatic_matching_config_is_persistently_retired(
        self,
    ) -> None:
        data_dir = self.fixture.root / "legacy-auto-config"
        data_dir.mkdir()
        config = vault_sync.default_config()
        config["matching"] = {
            "enabled": True,
            "auto_provisional": False,
            "auto_promote_after_consistency_check": False,
            "prompt_on_ambiguity": True,
            "policy_version": vault_sync.MATCHING_POLICY_VERSION,
        }
        config["matching"]["auto_provisional"] = True
        config["matching"]["auto_promote_after_consistency_check"] = True
        config["matching"]["policy_version"] = (
            "user-authorized-semantic-quorum-v1"
        )
        write_json(data_dir / "config.json", config)

        loaded = vault_sync.load_config(data_dir)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertNotIn("matching", loaded)
        persisted = json.loads(
            (data_dir / "config.json").read_text(encoding="utf-8")
        )
        self.assertNotIn("matching", persisted)
        audit = json.loads(
            (
                data_dir
                / "state"
                / "config-migrations"
                / "legacy-auto-matching-retired-v1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            audit["schema_version"],
            vault_sync.LEGACY_AUTO_MATCHING_RETIREMENT_SCHEMA,
        )
        self.assertEqual(audit["state"], "completed")

    def test_legacy_config_migration_records_exact_provider_pins(
        self,
    ) -> None:
        data_dir = self.fixture.root / "legacy-provider-config"
        data_dir.mkdir()
        legacy = self.fixture.legacy_config()
        write_json(data_dir / "config.json", legacy)

        loaded = vault_sync.load_config(data_dir)

        self.assertIsNotNone(loaded)
        self.assertEqual(
            loaded["schema_version"],
            vault_sync.CONFIG_SCHEMA,
        )
        self.assertNotIn("vault", loaded)
        self.assertNotIn("drive", loaded)
        receipt = json.loads(
            vault_sync._config_v2_migration_receipt_path(
                data_dir
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            receipt["schema_version"],
            vault_sync.CONFIG_MIGRATION_SCHEMA,
        )
        self.assertEqual(
            receipt["provider_pins"],
            vault_sync._provider_transaction_pins(loaded),
        )
        self.assertRegex(
            receipt["source_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_legacy_outbox_migrates_from_config_receipt_and_publishes(
        self,
    ) -> None:
        write_json(
            self.fixture.data / "config.json",
            self.fixture.legacy_config(),
        )
        loaded = vault_sync.load_config(self.fixture.data)
        self.assertIsNotNone(loaded)
        self.fixture.config = loaded
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        transaction, _state = engine._queue_stop(
            self.fixture.stop_input()
        )
        pending = vault_sync._outbox_path(
            self.fixture.data,
            "pending",
            transaction,
        )
        intent = json.loads(pending.read_text(encoding="utf-8"))
        intent["schema_version"] = vault_sync.LEGACY_OUTBOX_SCHEMA
        intent.pop("provider_pins")
        write_json(pending, intent)

        migrated = engine._prepare_pending_outbox(pending, intent)

        self.assertIsNotNone(migrated)
        self.assertEqual(
            migrated["schema_version"],
            vault_sync.OUTBOX_SCHEMA,
        )
        self.assertEqual(
            migrated["provider_pins"],
            engine.provider_pins,
        )
        self.assertEqual(
            migrated["migrated_from_schema"],
            vault_sync.LEGACY_OUTBOX_SCHEMA,
        )
        self.assertEqual(
            engine.flush_once(transaction_id=transaction),
            "done",
        )
        self.assertFalse(pending.exists())

    def test_outbox_provider_change_is_quarantined_before_remote_write(
        self,
    ) -> None:
        engine = self.fixture.engine()
        engine.session_start(self.fixture.session_input())
        engine.user_prompt_submit(self.fixture.prompt_input())
        transaction, _state = engine._queue_stop(
            self.fixture.stop_input()
        )
        pending = vault_sync._outbox_path(
            self.fixture.data,
            "pending",
            transaction,
        )
        queued = json.loads(pending.read_text(encoding="utf-8"))
        self.assertEqual(queued["provider_pins"], engine.provider_pins)
        baseline_head = self.fixture.remote_head()

        replacement_drive = self.root / "Replacement Drive"
        replacement_drive.mkdir()
        write_json(
            replacement_drive / ".memory-vault-private.json",
            {
                "vault_id": vault_sync.VAULT_ID,
                "owner_only": True,
                "shared": False,
            },
        )
        changed = json.loads(json.dumps(self.fixture.config))
        profile = vault_sync._provider_profile(changed)
        store = profile["object_stores"][0]
        changed["adapter_configs"][store["adapter_config_ref"]][
            "root"
        ] = str(replacement_drive)
        vault_sync._refresh_provider_scope_fingerprints(changed)
        changed_engine = vault_sync.SyncEngine(
            changed,
            self.fixture.data,
        )

        self.assertEqual(
            changed_engine.flush_once(transaction_id=transaction),
            "quarantined",
        )
        self.assertEqual(self.fixture.remote_head(), baseline_head)
        self.assertFalse(pending.exists())
        quarantine = json.loads(
            vault_sync._outbox_path(
                self.fixture.data,
                "quarantine",
                transaction,
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            quarantine["reason_code"],
            "outbox_provider_changed",
        )
        self.assertTrue(quarantine["content_preserved"])

    def test_verified_update_installs_once_then_respects_interval(self) -> None:
        marketplace = (self.root / "managed marketplace").resolve()
        plugin = marketplace / "plugins" / vault_sync.PLUGIN_NAME
        write_json(
            plugin / ".codex-plugin" / "plugin.json",
            {
                "name": vault_sync.PLUGIN_NAME,
                "version": "9.0.0",
                "author": {"name": "qh-work"},
            },
        )
        required = {
            "hooks/hooks.json": b"{}\n",
            **stub_runtime_bundle("9.0.0"),
            "skills/sync-memory-vault/SKILL.md": b"verified skill\n",
        }
        for relative, content in required.items():
            path = plugin / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        config = json.loads(json.dumps(self.fixture.config))
        config["updates"] = {
            "enabled": True,
            "auto_install": True,
            "check_interval_seconds": vault_sync.DEFAULT_UPDATE_INTERVAL_SECONDS,
            "codex_executable": None,
        }
        fake_codex = self.root / "trusted-codex"
        fake_codex.write_bytes(b"test executable")
        fake_codex.chmod(0o700)
        installed_version = {"value": vault_sync.VERSION}
        invocations: list[tuple[str, ...]] = []

        def completed(
            arguments: list[str] | tuple[str, ...],
            payload: Mapping[str, Any] | None = None,
            stdout: bytes | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            if stdout is None:
                stdout = json.dumps(payload or {}).encode("utf-8")
            return subprocess.CompletedProcess(
                list(arguments),
                0,
                stdout=stdout,
                stderr=b"",
            )

        def fake_run_process(
            arguments: Any,
            **kwargs: Any,
        ) -> subprocess.CompletedProcess[bytes]:
            invocation = tuple(str(item) for item in arguments)
            invocations.append(invocation)
            if invocation[0] == str(fake_codex):
                self.assertTrue(kwargs.get("inherit_git_environment"))
                command = invocation[1:]
                if command == (
                    "plugin",
                    "marketplace",
                    "list",
                    "--json",
                ):
                    return completed(
                        arguments,
                        {
                            "marketplaces": [
                                {
                                    "name": vault_sync.MARKETPLACE_NAME,
                                    "root": str(marketplace),
                                    "marketplaceSource": {
                                        "sourceType": "git",
                                        "source": (
                                            vault_sync.EXPECTED_MARKETPLACE_REPOSITORY
                                        ),
                                    },
                                }
                            ]
                        },
                    )
                if command == (
                    "plugin",
                    "marketplace",
                    "upgrade",
                    vault_sync.MARKETPLACE_NAME,
                    "--json",
                ):
                    return completed(arguments, {"upgraded": True})
                if command == ("plugin", "list", "--json"):
                    return completed(
                        arguments,
                        {
                            "installed": [
                                {
                                    "pluginId": (
                                        f"{vault_sync.PLUGIN_NAME}@"
                                        f"{vault_sync.MARKETPLACE_NAME}"
                                    ),
                                    "version": installed_version["value"],
                                    "enabled": True,
                                }
                            ]
                        },
                    )
                if command == (
                    "plugin",
                    "add",
                    (
                        f"{vault_sync.PLUGIN_NAME}@"
                        f"{vault_sync.MARKETPLACE_NAME}"
                    ),
                    "--json",
                ):
                    installed_version["value"] = "9.0.0"
                    return completed(arguments, {"installed": True})
            if (
                invocation[0] == "git"
                and invocation[1:4] == ("-C", str(marketplace), "rev-parse")
                and invocation[4:] == ("HEAD",)
            ):
                return completed(arguments, stdout=(b"1" * 40) + b"\n")
            if (
                invocation[0] == "git"
                and invocation[1:4] == ("-C", str(marketplace), "status")
            ):
                return completed(arguments, stdout=b"")
            raise AssertionError(f"unexpected update command: {invocation}")

        updater = vault_sync.PluginUpdater(config, self.fixture.data)
        with (
            mock.patch.object(
                vault_sync,
                "_trusted_codex_executable",
                return_value=fake_codex,
            ),
            mock.patch.object(
                vault_sync,
                "run_process",
                side_effect=fake_run_process,
            ),
        ):
            first = updater.check(force=True)
            state_path = self.fixture.data / "updates" / "state.json"
            first_mtime = state_path.stat().st_mtime_ns
            first_invocation_count = len(invocations)
            second = updater.check()

        self.assertEqual(first["status"], "updated")
        self.assertEqual(first["available_version"], "9.0.0")
        self.assertEqual(first["installed_version"], "9.0.0")
        self.assertEqual(first["activated_runtime_version"], "9.0.0")
        self.assertRegex(first["bundle_sha256"], r"^[0-9a-f]{64}$")
        runtime_metadata = json.loads(
            (
                self.fixture.data / "runtime" / "active" / "runtime.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(runtime_metadata["plugin_version"], "9.0.0")
        self.assertEqual(
            runtime_metadata["bundle_sha256"],
            first["bundle_sha256"],
        )
        self.assertEqual(
            runtime_metadata["marketplace_commit_sha"],
            first["marketplace_commit_sha"],
        )
        self.assertEqual(second["status"], "not_due")
        self.assertEqual(len(invocations), first_invocation_count)
        self.assertEqual(state_path.stat().st_mtime_ns, first_mtime)
        installs = [
            item
            for item in invocations
            if item[1:4] == (
                "plugin",
                "add",
                f"{vault_sync.PLUGIN_NAME}@{vault_sync.MARKETPLACE_NAME}",
            )
        ]
        self.assertEqual(len(installs), 1)

    def test_same_version_bootstraps_exact_install_then_rejects_changes(
        self,
    ) -> None:
        marketplace = (self.root / "same-version marketplace").resolve()
        plugin = marketplace / "plugins" / vault_sync.PLUGIN_NAME
        write_json(
            plugin / ".codex-plugin" / "plugin.json",
            {
                "name": vault_sync.PLUGIN_NAME,
                "version": vault_sync.VERSION,
                "author": {"name": "qh-work"},
            },
        )
        required = {
            "hooks/hooks.json": b"{}\n",
            **stub_runtime_bundle(vault_sync.VERSION),
            "skills/sync-memory-vault/SKILL.md": b"verified skill\n",
        }
        for relative, content in required.items():
            path = plugin / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        config = json.loads(json.dumps(self.fixture.config))
        config["updates"] = {
            "enabled": True,
            "auto_install": True,
            "check_interval_seconds": vault_sync.DEFAULT_UPDATE_INTERVAL_SECONDS,
            "codex_executable": None,
        }
        fake_codex = self.root / "trusted-codex-same-version"
        fake_codex.write_bytes(b"test executable")
        fake_codex.chmod(0o700)
        invocations: list[tuple[str, ...]] = []

        def completed(
            arguments: list[str] | tuple[str, ...],
            payload: Mapping[str, Any] | None = None,
            stdout: bytes | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            if stdout is None:
                stdout = json.dumps(payload or {}).encode("utf-8")
            return subprocess.CompletedProcess(
                list(arguments),
                0,
                stdout=stdout,
                stderr=b"",
            )

        def fake_run_process(
            arguments: Any,
            **kwargs: Any,
        ) -> subprocess.CompletedProcess[bytes]:
            invocation = tuple(str(item) for item in arguments)
            invocations.append(invocation)
            if invocation[0] == str(fake_codex):
                self.assertTrue(kwargs.get("inherit_git_environment"))
                command = invocation[1:]
                if command == (
                    "plugin",
                    "marketplace",
                    "list",
                    "--json",
                ):
                    return completed(
                        arguments,
                        {
                            "marketplaces": [
                                {
                                    "name": vault_sync.MARKETPLACE_NAME,
                                    "root": str(marketplace),
                                    "marketplaceSource": {
                                        "sourceType": "git",
                                        "source": (
                                            vault_sync.EXPECTED_MARKETPLACE_REPOSITORY
                                        ),
                                    },
                                }
                            ]
                        },
                    )
                if command == (
                    "plugin",
                    "marketplace",
                    "upgrade",
                    vault_sync.MARKETPLACE_NAME,
                    "--json",
                ):
                    return completed(arguments, {"upgraded": True})
                if command == ("plugin", "list", "--json"):
                    return completed(
                        arguments,
                        {
                            "installed": [
                                {
                                    "pluginId": (
                                        f"{vault_sync.PLUGIN_NAME}@"
                                        f"{vault_sync.MARKETPLACE_NAME}"
                                    ),
                                    "version": vault_sync.VERSION,
                                    "enabled": True,
                                    "source": {
                                        "source": "local",
                                        "path": str(plugin),
                                    },
                                }
                            ]
                        },
                    )
            if (
                invocation[0] == "git"
                and invocation[1:4] == ("-C", str(marketplace), "rev-parse")
                and invocation[4:] == ("HEAD",)
            ):
                return completed(arguments, stdout=(b"2" * 40) + b"\n")
            if (
                invocation[0] == "git"
                and invocation[1:4] == ("-C", str(marketplace), "status")
            ):
                return completed(arguments, stdout=b"")
            if (
                invocation[0] == "git"
                and invocation[1:4] == (
                    "-C",
                    str(marketplace),
                    "cat-file",
                )
            ):
                raise vault_sync.VerificationError(
                    "fixture release commit is not in the repository"
                )
            raise AssertionError(f"unexpected update command: {invocation}")

        updater = vault_sync.PluginUpdater(config, self.fixture.data)
        with (
            mock.patch.object(
                vault_sync,
                "_trusted_codex_executable",
                return_value=fake_codex,
            ),
            mock.patch.object(
                vault_sync,
                "run_process",
                side_effect=fake_run_process,
            ),
        ):
            bootstrapped = updater.check(force=True)
            candidate = updater._candidate(marketplace)

            self.assertEqual(
                bootstrapped["status"],
                "identity_bootstrapped",
            )
            self.assertEqual(
                vault_sync._load_verified_stable_runtime_identity(
                    self.fixture.data
                ),
                {
                    "plugin_version": vault_sync.VERSION,
                    "bundle_sha256": candidate["bundle_sha256"],
                    "marketplace_commit_sha": "2" * 40,
                },
            )

            vault_sync._refresh_stable_runtime_from_plugin(
                self.fixture.data,
                plugin,
                vault_sync.VERSION,
                bundle_sha256=str(candidate["bundle_sha256"]),
                marketplace_commit_sha="1" * 40,
            )
            commit_changed = updater.check(force=True)
            self.assertEqual(commit_changed["status"], "identity_mismatch")
            self.assertEqual(
                commit_changed["last_error_code"],
                "same_version_commit_mismatch",
            )
            self.assertEqual(
                commit_changed["identity_issue"],
                "marketplace_commit_sha_changed",
            )

            (plugin / "skills" / "sync-memory-vault" / "SKILL.md").write_bytes(
                b"changed skill with the same version\n"
            )
            bundle_changed = updater.check(force=True)

        self.assertEqual(bundle_changed["status"], "identity_mismatch")
        self.assertEqual(
            bundle_changed["last_error_code"],
            "same_version_bundle_mismatch",
        )
        self.assertEqual(
            bundle_changed["identity_issue"],
            "bundle_sha256_changed",
        )
        self.assertFalse(
            any(
                item[1:4]
                == (
                    "plugin",
                    "add",
                    f"{vault_sync.PLUGIN_NAME}@{vault_sync.MARKETPLACE_NAME}",
                )
                for item in invocations
            )
        )

    def test_same_version_identity_bootstrap_requires_exact_installed_path(
        self,
    ) -> None:
        config = json.loads(json.dumps(self.fixture.config))
        config["updates"]["enabled"] = True
        config["updates"]["auto_install"] = True
        updater = vault_sync.PluginUpdater(config, self.fixture.data)
        marketplace = (self.root / "bootstrap marketplace").resolve()
        plugin = marketplace / "plugins" / vault_sync.PLUGIN_NAME
        plugin.mkdir(parents=True)
        candidate = {
            "version": vault_sync.VERSION,
            "bundle_sha256": "a" * 64,
            "bundle_length": 123,
            "commit_sha": "b" * 40,
            "plugin_root": str(plugin),
        }
        installed = {
            "version": vault_sync.VERSION,
            "enabled": True,
            "source": {
                "source": "local",
                "path": str(self.root / "different plugin"),
            },
        }
        with (
            mock.patch.object(
                vault_sync,
                "_trusted_codex_executable",
                return_value=self.root / "codex",
            ),
            mock.patch.object(
                updater,
                "_marketplace",
                return_value=(marketplace, "local"),
            ),
            mock.patch.object(updater, "_candidate", return_value=candidate),
            mock.patch.object(
                updater,
                "_verify_signed_candidate",
                return_value={
                    "required": False,
                    "identity_commit_sha": "b" * 40,
                    "target": None,
                },
            ),
            mock.patch.object(updater, "_installed", return_value=installed),
            mock.patch.object(
                vault_sync,
                "_refresh_stable_runtime_from_plugin",
            ) as refresh,
        ):
            result = updater.check(force=True)

        self.assertEqual(result["status"], "identity_unverified")
        self.assertEqual(
            result["last_error_code"],
            "same_version_identity_unverified",
        )
        refresh.assert_not_called()

    def test_same_version_identity_allows_only_data_only_descendant(
        self,
    ) -> None:
        repository = self.root / "shared code and memory repository"
        repository.mkdir()
        run(["git", "init", "-b", "main"], repository)
        run(["git", "config", "user.name", "Fixture"], repository)
        run(["git", "config", "user.email", "fixture@example.invalid"], repository)
        plugin_file = (
            repository
            / "plugins"
            / vault_sync.PLUGIN_NAME
            / "payload.txt"
        )
        plugin_file.parent.mkdir(parents=True)
        plugin_file.write_text("release plugin\n", encoding="utf-8")
        marketplace_file = repository / ".agents" / "plugins" / "marketplace.json"
        marketplace_file.parent.mkdir(parents=True)
        marketplace_file.write_text("{}\n", encoding="utf-8")
        run(["git", "add", "."], repository)
        run(["git", "commit", "-m", "release"], repository)
        release_commit = run(["git", "rev-parse", "HEAD"], repository)

        memory_file = repository / "memory" / "episodes" / "aa" / "ep.json"
        memory_file.parent.mkdir(parents=True)
        memory_file.write_text("{}\n", encoding="utf-8")
        run(["git", "add", "."], repository)
        run(["git", "commit", "-m", "append memory"], repository)
        data_commit = run(["git", "rev-parse", "HEAD"], repository)

        updater = vault_sync.PluginUpdater(
            vault_sync.default_config(),
            self.fixture.data,
        )
        self.assertTrue(
            updater._verify_release_commit_still_identifies_candidate(
                repository,
                release_commit=release_commit,
                observed_commit=data_commit,
            )
        )

        plugin_file.write_text("changed plugin\n", encoding="utf-8")
        run(["git", "add", "."], repository)
        run(["git", "commit", "-m", "change plugin"], repository)
        plugin_commit = run(["git", "rev-parse", "HEAD"], repository)
        self.assertFalse(
            updater._verify_release_commit_still_identifies_candidate(
                repository,
                release_commit=release_commit,
                observed_commit=plugin_commit,
            )
        )

    def test_exact_newer_install_replaces_verified_older_stable_runtime(
        self,
    ) -> None:
        config = json.loads(json.dumps(self.fixture.config))
        config["updates"]["enabled"] = True
        config["updates"]["auto_install"] = True
        updater = vault_sync.PluginUpdater(config, self.fixture.data)
        marketplace = (self.root / "newer installed marketplace").resolve()
        plugin = marketplace / "plugins" / vault_sync.PLUGIN_NAME
        plugin.mkdir(parents=True)
        candidate = {
            "version": vault_sync.VERSION,
            "bundle_sha256": "c" * 64,
            "bundle_length": 456,
            "commit_sha": "d" * 40,
            "plugin_root": str(plugin),
        }
        installed = {
            "version": vault_sync.VERSION,
            "enabled": True,
            "source": {"source": "local", "path": str(plugin)},
        }
        older = {
            "plugin_version": "0.15.2+codex.older",
            "bundle_sha256": "a" * 64,
            "marketplace_commit_sha": "b" * 40,
        }
        activated = {
            "plugin_version": vault_sync.VERSION,
            "updated": True,
        }
        with (
            mock.patch.object(
                vault_sync,
                "_trusted_codex_executable",
                return_value=self.root / "codex",
            ),
            mock.patch.object(
                updater,
                "_marketplace",
                return_value=(marketplace, "local"),
            ),
            mock.patch.object(updater, "_candidate", return_value=candidate),
            mock.patch.object(
                updater,
                "_verify_signed_candidate",
                return_value={
                    "required": False,
                    "identity_commit_sha": "d" * 40,
                    "target": None,
                },
            ),
            mock.patch.object(updater, "_installed", return_value=installed),
            mock.patch.object(
                vault_sync,
                "_load_verified_stable_runtime_identity",
                return_value=older,
            ),
            mock.patch.object(updater, "_assert_candidate_unchanged") as unchanged,
            mock.patch.object(
                vault_sync,
                "_refresh_stable_runtime_from_plugin",
                return_value=activated,
            ) as refresh,
        ):
            result = updater.check(force=True, check_only=True)

        self.assertEqual(result["status"], "new_version_already_installed")
        self.assertEqual(
            result["activated_runtime_version"],
            vault_sync.VERSION,
        )
        unchanged.assert_called_once_with(marketplace, candidate)
        refresh.assert_called_once_with(
            self.fixture.data.resolve(),
            plugin.resolve(),
            vault_sync.VERSION,
            bundle_sha256="c" * 64,
            marketplace_commit_sha="d" * 40,
        )

    def test_update_refuses_downgrade_and_unexpected_source(self) -> None:
        self.assertLess(vault_sync.compare_semver("0.1.0", vault_sync.VERSION), 0)
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._github_repository_identity(
                "https://example.invalid/qh-work/memory-vault-sync"
            )
        output = vault_sync._decorate_update_result(
            {"continue": True},
            {
                "status": "updated",
                "available_version": "9.0.0",
            },
        )
        self.assertIn("9.0.0", output["systemMessage"])

    def test_update_marketplace_identity_supports_github_and_gitlab(self) -> None:
        deployment_identity = vault_sync._deployment_marketplace_identity()
        deployment_url = vault_sync.urllib.parse.urlsplit(
            vault_sync.DEPLOYMENT_DEFAULT_REPO_URL
        )
        deployment_path = deployment_url.path.strip("/")
        if deployment_path.endswith(".git"):
            deployment_path = deployment_path[:-4]
        self.assertEqual(
            deployment_identity,
            f"{deployment_url.hostname}/{deployment_path}".lower(),
        )
        self.assertEqual(
            vault_sync._marketplace_repository_identity(
                "git@github.com:example-owner/memory-vault.git"
            ),
            "github.com/example-owner/memory-vault",
        )
        self.assertEqual(
            vault_sync._marketplace_repository_identity(
                f"{deployment_path}.git@release"
            ),
            deployment_identity,
        )
        with mock.patch.object(
            vault_sync,
            "DEPLOYMENT_DEFAULT_REPO_URL",
            "https://gitlab.com/example/team/memory-vault.git",
        ):
            self.assertEqual(
                vault_sync._deployment_marketplace_identity(),
                "gitlab.com/example/team/memory-vault",
            )
            self.assertEqual(
                vault_sync._marketplace_repository_identity(
                    "example/team/memory-vault"
                ),
                "gitlab.com/example/team/memory-vault",
            )
            self.assertEqual(
                vault_sync._marketplace_repository_identity(
                    "https://gitlab.com/example/team/memory-vault.git"
                ),
                "gitlab.com/example/team/memory-vault",
            )

    def test_stable_runtime_seed_is_idempotent_and_executable(self) -> None:
        first = vault_sync._refresh_stable_runtime(self.fixture.data)
        stable_root = self.fixture.data / "runtime" / "active"
        stable_script = stable_root / "scripts" / "vault_sync.py"
        stable_launcher = stable_root / "scripts" / "windows_launcher.ps1"
        metadata_path = stable_root / "runtime.json"
        self.assertTrue(first["updated"])
        self.assertEqual(first["plugin_version"], vault_sync.VERSION)
        self.assertTrue(stable_script.is_file())
        self.assertFalse(stable_script.is_symlink())
        self.assertTrue(stable_launcher.is_file())
        self.assertFalse(stable_launcher.is_symlink())
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["plugin_version"], vault_sync.VERSION)
        self.assertIsNone(metadata["bundle_sha256"])
        self.assertIsNone(metadata["marketplace_commit_sha"])
        self.assertEqual(
            metadata["script_sha256"],
            vault_sync.sha256_bytes(stable_script.read_bytes()),
        )
        self.assertEqual(
            [item["path"] for item in metadata["files"]],
            [spec.path for spec in vault_sync.RUNTIME_FILE_SPECS],
        )
        tracked_paths = [
            stable_root / spec.path
            for spec in vault_sync.RUNTIME_FILE_SPECS
        ]
        for path in tracked_paths:
            self.assertTrue(path.is_file(), path)
            self.assertFalse(path.is_symlink(), path)
        before = {
            path: path.stat().st_mtime_ns
            for path in (*tracked_paths, metadata_path)
        }

        second = vault_sync._refresh_stable_runtime(self.fixture.data)

        self.assertFalse(second["updated"])
        self.assertEqual(
            before,
            {
                path: path.stat().st_mtime_ns
                for path in (*tracked_paths, metadata_path)
            },
        )
        process = subprocess.run(
            [sys.executable, str(stable_script), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(
            process.stdout.decode("utf-8", "strict").strip(),
            vault_sync.VERSION,
        )
        self.assertEqual(process.stderr.decode("utf-8", "replace"), "")

    def test_stable_runtime_identity_rejects_tampered_or_missing_module(
        self,
    ) -> None:
        bundle_sha256 = "a" * 64
        marketplace_commit_sha = "b" * 40
        vault_sync._refresh_stable_runtime_from_plugin(
            self.fixture.data,
            PLUGIN_ROOT,
            vault_sync.VERSION,
            bundle_sha256=bundle_sha256,
            marketplace_commit_sha=marketplace_commit_sha,
        )
        expected = {
            "plugin_version": vault_sync.VERSION,
            "bundle_sha256": bundle_sha256,
            "marketplace_commit_sha": marketplace_commit_sha,
        }
        self.assertEqual(
            vault_sync._load_verified_stable_runtime_identity(
                self.fixture.data
            ),
            expected,
        )
        stable_root = self.fixture.data / "runtime" / "active"
        protocol_module = (
            stable_root
            / "scripts"
            / "memory_vault_runtime"
            / "protocol.py"
        )
        protocol_module.write_bytes(protocol_module.read_bytes() + b"# tamper\n")
        self.assertIsNone(
            vault_sync._load_verified_stable_runtime_identity(
                self.fixture.data
            )
        )

        repaired = vault_sync._refresh_stable_runtime_from_plugin(
            self.fixture.data,
            PLUGIN_ROOT,
            vault_sync.VERSION,
            bundle_sha256=bundle_sha256,
            marketplace_commit_sha=marketplace_commit_sha,
        )
        self.assertTrue(repaired["updated"])
        core_module = (
            stable_root / "scripts" / "memory_vault_runtime" / "core.py"
        )
        core_module.unlink()
        self.assertIsNone(
            vault_sync._load_verified_stable_runtime_identity(
                self.fixture.data
            )
        )

    def test_stable_runtime_refresh_preserves_verified_release_identity(
        self,
    ) -> None:
        expected = {
            "plugin_version": vault_sync.VERSION,
            "bundle_sha256": "a" * 64,
            "marketplace_commit_sha": "b" * 40,
        }
        vault_sync._refresh_stable_runtime_from_plugin(
            self.fixture.data,
            PLUGIN_ROOT,
            vault_sync.VERSION,
            bundle_sha256=expected["bundle_sha256"],
            marketplace_commit_sha=expected["marketplace_commit_sha"],
        )

        refreshed = vault_sync._refresh_stable_runtime(self.fixture.data)

        self.assertFalse(refreshed["updated"])
        self.assertEqual(
            vault_sync._load_verified_stable_runtime_identity(
                self.fixture.data
            ),
            expected,
        )

    def test_stable_runtime_supports_unicode_and_space_paths(self) -> None:
        data_dir = self.root / "同步 缓存" / "插件 数据"
        result = vault_sync._refresh_stable_runtime(data_dir)
        stable_script = (
            data_dir / "runtime" / "active" / "scripts" / "vault_sync.py"
        )
        process = subprocess.run(
            [sys.executable, str(stable_script), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertTrue(result["updated"])
        self.assertEqual(process.returncode, 0)
        self.assertEqual(
            process.stdout.decode("utf-8", "strict").strip(),
            vault_sync.VERSION,
        )
        self.assertEqual(process.stderr, b"")

    def test_runtime_version_accepts_windows_crlf_but_rejects_bare_cr(
        self,
    ) -> None:
        self.assertEqual(
            vault_sync._runtime_version_from_bytes(
                b'VERSION = "1.2.3"\r\n',
                "Windows runtime",
            ),
            "1.2.3",
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "unsupported line ending",
        ):
            vault_sync._runtime_version_from_bytes(
                b'VERSION = "1.2.3"\r',
                "ambiguous runtime",
            )

    def test_verified_activation_retires_only_older_verified_cache_scripts(
        self,
    ) -> None:
        codex_home = self.root / "codex-home-retirement"
        data_dir = (
            codex_home
            / "plugins"
            / "data"
            / (
                f"{vault_sync.PLUGIN_NAME}-"
                f"{vault_sync.MARKETPLACE_NAME}"
            )
        )
        cache_root = (
            codex_home
            / "plugins"
            / "cache"
            / vault_sync.MARKETPLACE_NAME
            / vault_sync.PLUGIN_NAME
        )
        release_root = self.root / "verified-release"
        activated_version = "2.0.0"
        release_files = stub_runtime_bundle(activated_version)
        release_script = release_files["scripts/vault_sync.py"]
        for relative, content in release_files.items():
            path = release_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        def cached_plugin(
            directory_version: str,
            *,
            manifest_name: str = vault_sync.PLUGIN_NAME,
            manifest_author: str = "qh-work",
            manifest_version: str | None = None,
            script_version: str | None = None,
        ) -> Path:
            root = cache_root / directory_version
            write_json(
                root / ".codex-plugin" / "plugin.json",
                {
                    "name": manifest_name,
                    "version": manifest_version or directory_version,
                    "author": {"name": manifest_author},
                },
            )
            script = root / "scripts" / "vault_sync.py"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_bytes(
                (
                    f'VERSION = "{script_version or directory_version}"\r\n'
                ).encode("utf-8")
            )
            return script

        verified_old = cached_plugin("1.4.0")
        wrong_name = cached_plugin(
            "1.3.0",
            manifest_name="another-plugin",
        )
        wrong_author = cached_plugin(
            "1.2.0",
            manifest_author="another-author",
        )
        wrong_manifest_version = cached_plugin(
            "1.1.0",
            manifest_version="1.1.1",
        )
        wrong_script_version = cached_plugin(
            "1.0.0",
            script_version="1.0.1",
        )
        same_version = cached_plugin(activated_version)
        newer_version = cached_plugin("2.1.0")
        outside_cache = self.root / "outside-cache" / "vault_sync.py"
        outside_cache.parent.mkdir()
        outside_cache.write_bytes(b'VERSION = "0.1.0"\n')
        original_old = verified_old.read_bytes()

        with mock.patch.object(
            vault_sync,
            "_codex_home",
            return_value=codex_home.resolve(),
        ):
            first = vault_sync._refresh_stable_runtime_from_plugin(
                data_dir,
                release_root,
                activated_version,
            )
            second = vault_sync._refresh_stable_runtime_from_plugin(
                data_dir,
                release_root,
                activated_version,
            )

        backup = verified_old.with_name("vault_sync.py.retired.bak")
        self.assertFalse(verified_old.exists())
        self.assertEqual(backup.read_bytes(), original_old)
        self.assertEqual(
            first["runtime_retirement"]["retired_versions"],
            ["1.4.0"],
        )
        self.assertEqual(
            first["runtime_retirement"][
                "unverified_older_version_count"
            ],
            4,
        )
        self.assertFalse(second["updated"])
        self.assertEqual(
            second["runtime_retirement"]["already_retired_versions"],
            ["1.4.0"],
        )
        for untouched in (
            wrong_name,
            wrong_author,
            wrong_manifest_version,
            wrong_script_version,
            same_version,
            newer_version,
            outside_cache,
        ):
            self.assertTrue(untouched.is_file())
        stable_script = (
            data_dir / "runtime" / "active" / "scripts" / "vault_sync.py"
        )
        self.assertEqual(stable_script.read_bytes(), release_script)

    def test_cached_runtime_retirement_rejects_symbolic_link(self) -> None:
        outside_cache_root = self.root / "not-a-plugin-cache"
        outside_cache_root.mkdir()
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._retire_older_cached_runtimes(
                outside_cache_root,
                "2.0.0",
            )

        cache_root = (
            self.root
            / "plugins"
            / "cache"
            / vault_sync.MARKETPLACE_NAME
            / vault_sync.PLUGIN_NAME
        )
        version_root = cache_root / "1.0.0"
        write_json(
            version_root / ".codex-plugin" / "plugin.json",
            {
                "name": vault_sync.PLUGIN_NAME,
                "version": "1.0.0",
                "author": {"name": "qh-work"},
            },
        )
        scripts = version_root / "scripts"
        scripts.mkdir(parents=True)
        outside = self.root / "untrusted-runtime.py"
        outside.write_bytes(b'VERSION = "1.0.0"\n')
        linked = scripts / "vault_sync.py"
        try:
            linked.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"symbolic links are unavailable: {exc}")

        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._retire_older_cached_runtimes(
                cache_root,
                "2.0.0",
            )

        self.assertTrue(linked.is_symlink())
        self.assertFalse(
            (scripts / "vault_sync.py.retired.bak").exists()
        )

    @unittest.skipUnless(os.name == "posix", "POSIX hook command requires /bin/sh")
    def test_posix_hook_falls_back_after_version_cache_is_pruned(self) -> None:
        self.fixture.confirm_source_route("session-stable-fallback")
        vault_sync._refresh_stable_runtime(self.fixture.data)
        hooks = json.loads(
            (PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8")
        )
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.fixture.data)
        environment["PLUGIN_ROOT"] = str(
            self.root / "pruned plugin cache" / "0.6.2"
        )
        environment["MEMORY_VAULT_SYNC_TESTING"] = "1"
        events = [
            (
                "SessionStart",
                self.fixture.session_input(session="session-stable-fallback"),
            ),
            (
                "UserPromptSubmit",
                self.fixture.prompt_input(
                    session="session-stable-fallback",
                    turn="turn-stable-fallback",
                ),
            ),
            (
                "Stop",
                self.fixture.stop_input(
                    session="session-stable-fallback",
                    turn="turn-stable-fallback",
                    assistant="稳定运行时已完成升级期间的收尾。",
                ),
            ),
        ]
        for event, payload in events:
            command = hooks["hooks"][event][0]["hooks"][0]["command"]
            process = subprocess.run(
                ["/bin/sh", "-c", command],
                cwd=self.fixture.workspace,
                input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
                timeout=120,
            )
            stderr = process.stderr.decode("utf-8", "replace")
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stderr, "")
            parsed = json.loads(process.stdout.decode("utf-8", "strict"))
            self.assertTrue(parsed["continue"])

    def test_windows_setup_does_not_assume_a_drive_letter(self) -> None:
        setup = (PLUGIN_ROOT / "references" / "WINDOWS_SETUP.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(r'D:\Research', setup)
        self.assertNotIn(r'D:\Codex', setup)
        self.assertIn("memory_network.py", setup)
        self.assertIn("retrieval.py", setup)
        self.assertIn("taskless Memory Network", setup)
        self.assertNotIn("legacy-bind", setup)
        self.assertNotIn("--workspace", setup)
        lowered = setup.lower()
        for task_specific_phrase in (
            "three reviews",
            "three review",
            "三篇综述",
            "三个综述",
        ):
            self.assertNotIn(task_specific_phrase, lowered)
        self.assertNotIn("trust the three", lowered)
        self.assertNotIn("high-frequency file watcher", lowered)
        self.assertNotIn("restarts chatgpt", lowered)

    def test_status_omits_routine_operational_assurances(self) -> None:
        status = self.fixture.engine().status()
        self.assertNotIn("background_process", status)
        self.assertNotIn("high_frequency_watcher", status)
        signed_trust = status["automatic_updates"]["signed_update_trust"]
        self.assertFalse(signed_trust["required"])
        self.assertTrue(signed_trust["valid"])
        self.assertEqual(
            signed_trust["mode"],
            "exact-repository-bundle-and-commit-identity",
        )

    def test_hook_subprocess_outputs_one_json_object(self) -> None:
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.fixture.data)
        environment["PLUGIN_ROOT"] = str(PLUGIN_ROOT)
        environment["MEMORY_VAULT_SYNC_TESTING"] = "1"
        process = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "hook",
                "session-start",
            ],
            input=json.dumps(
                self.fixture.session_input(),
                ensure_ascii=False,
            ).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr.decode("utf-8", "replace"), "")
        output = json.loads(process.stdout.decode("utf-8", "strict"))
        self.assertTrue(output["continue"])
        self.assertEqual(
            output["hookSpecificOutput"]["hookEventName"], "SessionStart"
        )

    def test_macos_https_context_loads_system_keychains(self) -> None:
        fake_context = mock.Mock()
        fake_context.cert_store_stats.return_value = {"x509_ca": 1}
        certificate = (
            b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n"
            b"-----END CERTIFICATE-----\n"
        )
        security_result = subprocess.CompletedProcess(
            args=["security"],
            returncode=0,
            stdout=certificate,
            stderr=b"",
        )
        previous_context = vault_sync._HTTPS_CONTEXT
        vault_sync._HTTPS_CONTEXT = None
        try:
            with (
                mock.patch.object(vault_sync.sys, "platform", "darwin"),
                mock.patch.object(
                    vault_sync.ssl,
                    "create_default_context",
                    return_value=fake_context,
                ),
                mock.patch.object(
                    vault_sync,
                    "run_process",
                    return_value=security_result,
                ) as run_process_mock,
            ):
                self.assertIs(vault_sync._https_context(), fake_context)
            self.assertEqual(run_process_mock.call_count, 2)
            fake_context.load_verify_locations.assert_called_once()
        finally:
            vault_sync._HTTPS_CONTEXT = previous_context

    def test_drive_exact_reference_accepts_private_root_descendant(self) -> None:
        config = vault_sync.default_config()
        profile = vault_sync._provider_profile(config)
        store = profile["object_stores"][0]
        config["adapter_configs"][store["adapter_config_ref"]].update(
            {
                "root_folder_id": "root-private",
                "oauth_client_id": "client-id",
            }
        )
        vault_sync._refresh_provider_scope_fingerprints(config)
        adapter = vault_sync.GoogleDriveAdapter(config)
        folders = {
            "folder-leaf": {
                "id": "folder-leaf",
                "mimeType": "application/vnd.google-apps.folder",
                "parents": ["folder-parent"],
                "trashed": False,
            },
            "folder-parent": {
                "id": "folder-parent",
                "mimeType": "application/vnd.google-apps.folder",
                "parents": ["root-private"],
                "trashed": False,
            },
        }

        def read_folder(url: str, **_: Any) -> Mapping[str, Any]:
            for folder_id, metadata in folders.items():
                if f"/files/{folder_id}?" in url:
                    return metadata
            raise AssertionError(f"unexpected Drive request: {url}")

        adapter._json_request = mock.Mock(side_effect=read_folder)
        adapter._assert_file_owner_only = mock.Mock()
        payload = b"verified legacy object"
        digest = vault_sync.sha256_bytes(payload)
        verified = adapter._verify_exact_reference(
            {
                "id": "legacy-file",
                "parents": ["folder-leaf"],
                "size": str(len(payload)),
                "mimeType": "application/octet-stream",
                "sha256Checksum": digest,
            },
            expected_file_id="legacy-file",
            expected_parent_id="folder-leaf",
            sha256=digest,
            size=len(payload),
            mime_type="application/octet-stream",
        )
        self.assertEqual(verified.file_id, "legacy-file")
        self.assertEqual(verified.parent_id, "folder-leaf")
        self.assertEqual(verified.verification_level, "drive-native-sha256")
        self.assertEqual(
            adapter._verified_private_folders,
            {"root-private", "folder-parent", "folder-leaf"},
        )
        outside = vault_sync.GoogleDriveAdapter(config)
        outside._assert_file_owner_only = mock.Mock()
        outside._json_request = mock.Mock(
            return_value={
                "id": "folder-outside",
                "mimeType": "application/vnd.google-apps.folder",
                "parents": ["folder-outside"],
                "trashed": False,
            }
        )
        with self.assertRaises(vault_sync.PrivacyError):
            outside._verify_exact_reference(
                {
                    "id": "legacy-file",
                    "parents": ["folder-outside"],
                    "size": str(len(payload)),
                    "mimeType": "application/octet-stream",
                    "sha256Checksum": digest,
                },
                expected_file_id="legacy-file",
                expected_parent_id="folder-outside",
                sha256=digest,
                size=len(payload),
                mime_type="application/octet-stream",
            )

    def test_open_verified_url_uses_verified_context(self) -> None:
        request = vault_sync.urllib.request.Request("https://example.test/")
        context = object()
        response = object()
        with (
            mock.patch.object(
                vault_sync,
                "_https_context",
                return_value=context,
            ),
            mock.patch.object(
                vault_sync.urllib.request,
                "urlopen",
                return_value=response,
            ) as urlopen_mock,
        ):
            self.assertIs(
                vault_sync.open_verified_url(request, timeout=7),
                response,
            )
        urlopen_mock.assert_called_once_with(
            request,
            timeout=7,
            context=context,
        )

    @unittest.skipUnless(os.name == "nt", "Windows command override test")
    def test_windows_commands_run_from_unicode_space_path(self) -> None:
        copied_root = self.root
        for index in range(6):
            copied_root = copied_root / (
                f"插件目录 {index} " + "长路径" * 8
            )
        copied_root = copied_root / "插件 根目录"
        shutil.copytree(PLUGIN_ROOT, copied_root)
        hooks = json.loads((copied_root / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        import winreg

        registry_view = getattr(winreg, "KEY_WOW64_64KEY", 0)
        registry_tag_path = (
            "Software\\Python\\PythonCore\\"
            f"CodexMemoryVaultTest-{os.getpid()}"
        )
        registry_install_path = registry_tag_path + "\\InstallPath"
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_install_path,
            0,
            winreg.KEY_WRITE | registry_view,
        ) as install_key:
            winreg.SetValueEx(
                install_key,
                "",
                0,
                winreg.REG_SZ,
                str(Path(sys.executable).parent),
            )
            winreg.SetValueEx(
                install_key,
                "ExecutablePath",
                0,
                winreg.REG_SZ,
                sys.executable,
            )

        def cleanup_test_registry() -> None:
            for key_path in (registry_install_path, registry_tag_path):
                try:
                    winreg.DeleteKeyEx(
                        winreg.HKEY_CURRENT_USER,
                        key_path,
                        registry_view,
                        0,
                    )
                except FileNotFoundError:
                    pass

        self.addCleanup(cleanup_test_registry)
        environment = os.environ.copy()
        environment["PLUGIN_DATA"] = str(self.fixture.data)
        environment["PLUGIN_ROOT"] = str(copied_root)
        environment["MEMORY_VAULT_SYNC_TESTING"] = "1"
        environment["PYTHONIOENCODING"] = "ascii"
        environment["PYTHONPATH"] = str(self.fixture.workspace)
        hijack_marker = self.fixture.workspace / "python-path-hijack.txt"
        (self.fixture.workspace / "mimetypes.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(hijack_marker)!r}).write_text('hijacked')\n",
            encoding="utf-8",
        )
        (self.fixture.workspace / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(hijack_marker)!r}).write_text('hijacked')\n",
            encoding="utf-8",
        )
        (self.fixture.workspace / "py.exe").write_bytes(
            b"This is not a Windows executable."
        )
        cmd_hijack_marker = self.fixture.workspace / "cmd-host-hijack.txt"
        (self.fixture.workspace / "$hostPath.cmd").write_text(
            "@echo off\r\n"
            f'> "{cmd_hijack_marker}" echo hijacked\r\n'
            "exit /b 0\r\n",
            encoding="utf-8",
        )
        environment["PATH"] = (
            str(self.fixture.workspace)
            + os.pathsep
            + environment.get("PATH", "")
        )
        comspec = os.environ.get("COMSPEC", "cmd.exe")
        powershells: list[str] = []
        discovered_shells: set[str] = set()
        for candidate in ("pwsh.exe", "pwsh", "powershell.exe", "powershell"):
            discovered = shutil.which(candidate)
            if discovered is None:
                continue
            normalized = os.path.normcase(os.path.realpath(discovered))
            if normalized not in discovered_shells:
                discovered_shells.add(normalized)
                powershells.append(discovered)
        self.assertTrue(powershells)
        shells = [
            (f"powershell-{index}", executable)
            for index, executable in enumerate(powershells)
        ]
        for shell_name, shell_executable in shells:
            session_id = f"session-{shell_name}"
            turn_id = f"turn-{shell_name}"
            self.fixture.confirm_source_route(session_id)
            events = [
                (
                    "SessionStart",
                    self.fixture.session_input(session=session_id),
                ),
                (
                    "UserPromptSubmit",
                    self.fixture.prompt_input(
                        session=session_id,
                        turn=turn_id,
                        prompt=f"Windows {shell_name} 子进程链进度。",
                    ),
                ),
                (
                    "Stop",
                    self.fixture.stop_input(
                        session=session_id,
                        turn=turn_id,
                        assistant=f"Windows {shell_name} 子进程链已收尾。",
                    ),
                ),
            ]
            for event, payload in events:
                command = hooks["hooks"][event][0]["hooks"][0]["commandWindows"]
                invocation = [
                    shell_executable,
                    "-NoProfile",
                    "-Command",
                    command,
                ]
                process = subprocess.run(
                    invocation,
                    cwd=self.fixture.workspace,
                    input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    check=False,
                    timeout=120,
                )
                stderr = process.stderr.decode("utf-8", "replace")
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stderr, "")
                parsed = json.loads(process.stdout.decode("utf-8", "strict"))
                self.assertTrue(parsed["continue"])
        self.assertFalse(hijack_marker.exists())

        # The secure Windows launcher intentionally requires PowerShell. A
        # configured cmd shell must fail closed instead of resolving a
        # workspace-controlled py.exe.
        command = hooks["hooks"]["SessionStart"][0]["hooks"][0]["commandWindows"]
        command_prefix = subprocess.list2cmdline([comspec, "/C"])
        command_line = f'{command_prefix} "{command}"'
        cmd_process = subprocess.run(
            command_line,
            executable=comspec,
            cwd=self.fixture.workspace,
            input=json.dumps(
                self.fixture.session_input(session="session-cmd-refused"),
                ensure_ascii=False,
            ).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(cmd_process.returncode, 0)
        self.assertFalse(hijack_marker.exists())
        self.assertFalse(cmd_hijack_marker.exists())

    def test_unbound_session_immediately_creates_private_routing_request(
        self,
    ) -> None:
        session_id = "legacy-unbound-routing"
        output = self.fixture.engine().session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )

        self.assertIn("systemMessage", output)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("unbound_pending_model", context)
        self.assertNotIn(session_id, context)
        device = vault_sync._device_state(self.fixture.data)
        request_id = vault_sync._routing_request_id(device, session_id)
        request_path, request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        self.assertTrue(request_path.is_file())
        self.assertEqual(request["state"], "pending")
        self.assertEqual(
            request["source_external_key_sha256"],
            vault_sync._codex_source_key(session_id),
        )
        self.assertNotIn("transcript_path", request)
        candidates = vault_sync.routing_candidates_command(
            types.SimpleNamespace(request_id=request_id),
            self.fixture.engine(),
        )
        self.assertEqual(
            [item["task_id"] for item in candidates["candidates"]],
            [self.fixture.task_id],
        )

    def test_score_only_auto_matching_is_disabled_without_writes(
        self,
    ) -> None:
        engine, _output, request_id = self.start_unbound_routing(
            session="score-only-matcher-disabled"
        )
        remote_before = self.fixture.remote_head()
        with self.assertRaises(vault_sync.ConfigurationError):
            vault_sync.prepare_auto_match_command(
                self.auto_match_args(request_id),
                engine,
            )
        with self.assertRaises(vault_sync.ConfigurationError):
            vault_sync.promote_auto_match_command(
                types.SimpleNamespace(
                    claim_id="claim-score-only-disabled",
                    consistency_score_bp=10000,
                    contradiction_count=0,
                    evidence_sha256="a" * 64,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), remote_before)
        device = vault_sync._device_state(self.fixture.data)
        session_key = vault_sync._session_key(
            device,
            "score-only-matcher-disabled",
        )
        self.assertIsNone(
            vault_sync._load_provisional_claim(
                self.fixture.data,
                session_key,
            )
        )
        status = engine.status()["automatic_task_matching"]
        self.assertFalse(status["automatic_binding_enabled"])
        self.assertTrue(status["legacy_auto_match_disabled"])
        self.assertEqual(
            status["mode"],
            "content_review_then_explicit_confirmation",
        )

    def test_legacy_user_confirmed_route_resets_to_full_content_review(
        self,
    ) -> None:
        session = "legacy-user-confirmed-route"
        engine, request_id, _legacy_binding_id = (
            self.install_legacy_user_route(session=session)
        )
        request_path, request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        old_nonce = request["review_nonce"]
        request["state"] = "confirmed_by_user"
        vault_sync.atomic_write_json(request_path, request)

        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.resolve_source_identity(engine.git, session)
        started = engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=self.fixture.projectless,
            )
        )

        self.assertIn(
            "MEMORY_VAULT_ROUTING",
            json.dumps(started, ensure_ascii=False),
        )
        _path, reset = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        self.assertEqual(reset["state"], "pending")
        self.assertNotEqual(reset["review_nonce"], old_nonce)

    def test_legacy_awaiting_choice_without_current_review_resets(
        self,
    ) -> None:
        session = "legacy-awaiting-stale-choice"
        engine, request_id, _legacy_binding_id = (
            self.install_legacy_user_route(session=session)
        )
        request_path, request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        old_nonce = request["review_nonce"]
        request["state"] = "awaiting_user_reply"
        vault_sync.atomic_write_json(request_path, request)
        vault_sync.atomic_write_json(
            vault_sync._routing_choice_path(
                self.fixture.data,
                request_id,
            ),
            {
                "schema_version": "memory-vault-routing-choice/v3",
                "request_id": request_id,
                "state": "awaiting_user_reply",
                "shortlist_task_ids": [self.fixture.task_id],
                "selection_codes": {"1": self.fixture.task_id},
                "remote_commit_sha": request["remote_commit_sha"],
                "candidate_set_sha256": (
                    vault_sync._routing_candidate_set_sha256(request)
                ),
                "workspace_identity_fingerprint": request[
                    "workspace_identity_fingerprint"
                ],
                "evidence_receipt_sha256": {
                    self.fixture.task_id: "a" * 64
                },
                "local_evidence_receipt_sha256": "b" * 64,
                "operation": "initial_binding",
                "previous_binding_id": None,
                "previous_task_id": None,
                "workspace_mode": None,
                "created_at": "2026-07-28T00:00:00Z",
                "completed_at": None,
                "expires_at_epoch": request["expires_at_epoch"],
            },
        )

        engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=self.fixture.projectless,
            )
        )

        _path, reset = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        self.assertEqual(reset["state"], "pending")
        self.assertNotEqual(reset["review_nonce"], old_nonce)
        self.assertFalse(
            vault_sync._routing_choice_path(
                self.fixture.data,
                request_id,
            ).exists()
        )

    def test_legacy_auto_route_same_target_requires_content_revalidation(
        self,
    ) -> None:
        session = "legacy-auto-same-target"
        engine, request_id, legacy_binding_id = (
            self.install_legacy_auto_route(session=session)
        )

        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.resolve_source_identity(engine.git, session)
        started = engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn(
            "MEMORY_VAULT_ROUTING",
            json.dumps(started, ensure_ascii=False),
        )
        request_path, request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        self.assertTrue(request_path.exists())
        self.assertEqual(request["state"], "pending")
        device = vault_sync._device_state(self.fixture.data)
        session_key = vault_sync._session_key(device, session)
        claim_record = vault_sync._load_provisional_claim(
            self.fixture.data,
            session_key,
        )
        self.assertIsNotNone(claim_record)
        assert claim_record is not None
        self.assertEqual(claim_record[1]["state"], "revoked")
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session,
            )
        )

        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        _path, awaiting = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        awaiting_nonce = awaiting["review_nonce"]
        engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=self.fixture.projectless,
            )
        )
        _path, still_awaiting = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )
        self.assertEqual(still_awaiting["state"], "awaiting_user_reply")
        self.assertEqual(still_awaiting["review_nonce"], awaiting_nonce)
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="legacy-auto-same-target-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        confirmed = vault_sync.confirm_routing_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
                user_decision_token=self.routing_decision_token(
                    submitted
                ),
            ),
            engine,
        )
        self.assertEqual(confirmed["status"], "confirmed")
        resolved = vault_sync.resolve_source_identity(engine.git, session)
        self.assertEqual(resolved.task_id, self.fixture.task_id)
        self.assertNotEqual(resolved.binding_id, legacy_binding_id)
        replacement = engine.git.show_json(
            f"bindings/confirmed/{resolved.binding_id}.json"
        )
        self.assertEqual(
            replacement["supersedes_binding_id"],
            legacy_binding_id,
        )
        self.assertEqual(replacement["confidence"], "user_confirmed")
        self.assertEqual(
            replacement["confirmation_basis"],
            vault_sync.SOURCE_ROUTE_CONFIRMATION_BASIS,
        )
        self.assertIn("content_review_attestation", replacement)
        self.assertIn("route_revalidation", replacement)
        self.assertNotIn("route_correction", replacement)

        other_data = self.fixture.root / "attested-route-other-device"
        write_json(
            other_data / "config.json",
            self.fixture.config,
        )
        other_engine = vault_sync.SyncEngine(
            self.fixture.config,
            other_data,
        )
        restarted = other_engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=self.fixture.projectless,
            )
        )
        self.assertNotIn(
            "MEMORY_VAULT_ROUTING",
            json.dumps(restarted, ensure_ascii=False),
        )
        other_identity = vault_sync.resolve_source_identity(
            other_engine.git,
            session,
        )
        self.assertEqual(other_identity.binding_id, resolved.binding_id)

    def test_legacy_auto_route_can_be_corrected_to_another_task(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        session = "legacy-auto-wrong-target"
        engine, request_id, legacy_binding_id = (
            self.install_legacy_auto_route(session=session)
        )
        engine.session_start(
            self.fixture.session_input(
                session=session,
                workspace=self.fixture.projectless,
            )
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=topology["task_beta"],
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [topology["task_beta"]],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[topology["task_beta"]],
            ),
            engine,
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="legacy-auto-correct-target-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        vault_sync.confirm_routing_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=topology["task_beta"],
                user_decision_token=self.routing_decision_token(
                    submitted
                ),
            ),
            engine,
        )

        resolved = vault_sync.resolve_source_identity(engine.git, session)
        self.assertEqual(resolved.task_id, topology["task_beta"])
        replacement = engine.git.show_json(
            f"bindings/confirmed/{resolved.binding_id}.json"
        )
        self.assertEqual(
            replacement["supersedes_binding_id"],
            legacy_binding_id,
        )
        self.assertIn("route_correction", replacement)
        self.assertNotIn("route_revalidation", replacement)
        self.assertEqual(
            replacement["content_review_attestation"][
                "selected_task_id"
            ],
            topology["task_beta"],
        )
        routes = vault_sync._confirmed_primary_source_routes(
            engine.git,
            resolved.source_id,
        )
        old_route = next(
            item
            for item in routes
            if item.binding_id == legacy_binding_id
        )
        new_route = next(
            item
            for item in routes
            if item.binding_id == resolved.binding_id
        )
        self.assertEqual(
            old_route.source_sequence_from,
            new_route.source_sequence_from,
        )
        self.assertEqual(
            vault_sync._source_route_effective_end(
                routes,
                old_route,
            ),
            old_route.source_sequence_from - 1,
        )

    def test_routing_choice_needs_the_next_visible_user_turn(
        self,
    ) -> None:
        engine, started, request_id = self.start_unbound_routing(
            session="two-turn-routing-choice"
        )
        self.assertNotIn(
            "user_decision_token",
            json.dumps(started, ensure_ascii=False),
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        baseline_head = self.fixture.remote_head()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.confirm_routing_match_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                    user_decision_token=(
                        "mvrd_" + ("x" * 43)
                    ),
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), baseline_head)

        free_text_reply = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="two-turn-routing-choice",
                turn="two-turn-free-text",
                workspace=self.fixture.projectless,
                prompt="不要绑定，我还没有作出编号选择。",
            )
        )
        self.assertNotIn(
            "user_decision_token",
            json.dumps(free_text_reply, ensure_ascii=False),
        )
        self.assertEqual(self.fixture.remote_head(), baseline_head)

        first_reply = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="two-turn-routing-choice",
                turn="two-turn-first-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        stale_token = self.routing_decision_token(first_reply)
        second_reply = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="two-turn-routing-choice",
                turn="two-turn-revised-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        fresh_token = self.routing_decision_token(second_reply)
        self.assertNotEqual(stale_token, fresh_token)
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.confirm_routing_match_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                    user_decision_token=stale_token,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), baseline_head)
        confirmed = vault_sync.confirm_routing_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
                user_decision_token=fresh_token,
            ),
            engine,
        )
        self.assertEqual(confirmed["status"], "confirmed")

    def test_zero_choice_rejects_all_candidates_without_route(self) -> None:
        session = "routing-explicit-rejection"
        engine, _started, request_id = self.start_unbound_routing(
            session=session
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
            verdict="consistent",
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        baseline_head = self.fixture.remote_head()
        reply = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="routing-reject-all",
                workspace=self.fixture.projectless,
                prompt="0",
            )
        )
        rejected = vault_sync.reject_routing_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                user_decision_token=self.routing_decision_token(reply),
            ),
            engine,
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(self.fixture.remote_head(), baseline_head)
        engine.git.ensure()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.resolve_source_identity(engine.git, session)

    def test_routing_token_cannot_select_an_unpresented_task(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine, _started, request_id = self.start_unbound_routing(
            session="routing-shortlist-scope"
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="routing-shortlist-scope",
                turn="routing-shortlist-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        baseline_head = self.fixture.remote_head()
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.confirm_routing_match_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=topology["task_beta"],
                    user_decision_token=self.routing_decision_token(
                        submitted
                    ),
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), baseline_head)

    def test_routing_token_expires_when_remote_evidence_advances(
        self,
    ) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="routing-remote-advance"
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="routing-remote-advance",
                turn="routing-before-remote-advance",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        token = self.routing_decision_token(submitted)
        self.fixture.advance_remote("routing-evidence-advanced")
        advanced_head = self.fixture.remote_head()
        with self.assertRaises(vault_sync.ConflictError):
            vault_sync.confirm_routing_match_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                    user_decision_token=token,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), advanced_head)

    def test_expired_route_switch_request_does_not_block_a_bound_task(
        self,
    ) -> None:
        session = "expired-route-switch-bound"
        self.fixture.confirm_source_route(session)
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(session=session)
        )
        with vault_sync.FileLock(engine.lock_path):
            engine.git.ensure()
            routing = engine._ensure_routing_request(
                {
                    "session_id": session,
                    "cwd": str(self.fixture.workspace),
                }
            )
            self.assertIsNotNone(routing)
            assert routing is not None
            request = dict(routing[0])
            request["expires_at_epoch"] = 0
            vault_sync.atomic_write_json(
                vault_sync._routing_request_path(
                    self.fixture.data,
                    str(request["request_id"]),
                ),
                request,
            )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="after-expired-route-switch",
                prompt="继续正常工作。",
            )
        )
        self.assertNotIn(
            "invalid local task routing record",
            json.dumps(submitted, ensure_ascii=False),
        )
        device = vault_sync._device_state(self.fixture.data)
        loaded = vault_sync._load_session(
            self.fixture.data,
            device,
            session,
        )
        self.assertIsNotNone(loaded)
        assert loaded is not None
        turn_key = vault_sync._turn_key(
            device,
            session,
            "after-expired-route-switch",
        )
        self.assertTrue(
            vault_sync._prompt_path(
                self.fixture.data,
                loaded[0],
                turn_key,
            ).exists()
        )

    def test_bare_routing_capability_is_quarantined_from_assistant_output(
        self,
    ) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="routing-secret-source"
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="routing-secret-source",
                turn="routing-secret-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        secret = self.routing_decision_token(submitted)
        embedded_secret = "x" + secret + "_suffix"
        self.fixture.confirm_source_route("routing-secret-bound")
        engine.session_start(
            self.fixture.session_input(
                session="routing-secret-bound"
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session="routing-secret-bound",
                turn="routing-secret-echo",
                prompt="请给出普通结论。",
            )
        )
        baseline_head = self.fixture.remote_head()
        stopped = engine.stop(
            self.fixture.stop_input(
                session="routing-secret-bound",
                turn="routing-secret-echo",
                assistant=(
                    "最终结论如下，内部能力值为 " + embedded_secret
                ),
            )
        )
        self.assertEqual(self.fixture.remote_head(), baseline_head)
        self.assertIn(
            "quarantined",
            json.dumps(stopped, ensure_ascii=False),
        )
        quarantines = list(
            (self.fixture.data / "outbox" / "quarantine").glob("*.json")
        )
        self.assertTrue(quarantines)
        self.assertNotIn(
            secret,
            json.dumps(
                [
                    path.read_text(encoding="utf-8")
                    for path in quarantines
                ],
                ensure_ascii=False,
            ),
        )

    def test_routing_evidence_returns_verified_dialogue_and_artifact_facts(
        self,
    ) -> None:
        conversation_path = self.fixture.link_conversation_to_current(
            [
                {
                    "role": "user",
                    "text": (
                        "比较耐盐芽孢杆菌挥发物，并保留第二套对照设计。"
                    ),
                },
                {
                    "role": "assistant",
                    "phase": "final_answer",
                    "text": (
                        "已确定双对照设计；不要恢复已否决的单对照方案。"
                    ),
                },
            ],
            "content-evidence",
        )
        clone = self.fixture.clone_remote("artifact-content-evidence")
        run(["git", "config", "user.name", "Evidence fixture"], clone)
        run(
            ["git", "config", "user.email", "evidence@localhost"],
            clone,
        )
        current = json.loads(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest_path = str(current["manifest_path"])
        manifest = json.loads(
            (clone / manifest_path).read_text(encoding="utf-8")
        )
        manifest["artifacts"] = [
            {
                "artifact_id": "artifact-content-evidence",
                "display_name": "current-design.docx",
                "drive_file_id": "drive-file-content-evidence",
                "drive_parent_id": "drive-parent-content-evidence",
                "logical_path": "results/current-design.docx",
                "mime_type": (
                    "application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.document"
                ),
                "role": "experimental-design",
                "sha256": "e" * 64,
                "size": 4096,
                "storage_mode": "full",
            }
        ]
        write_json(clone / manifest_path, manifest)
        run(["git", "add", "--", manifest_path], clone)
        run(["git", "commit", "-m", "add routing artifact evidence"], clone)
        run(["git", "push", "origin", "main"], clone)

        evidence_workspace = self.fixture.allowed / "成果内容证据"
        evidence_workspace.mkdir()
        engine, _output, request_id = self.start_unbound_routing(
            session="content-evidence-routing",
            workspace=evidence_workspace,
        )
        remote_before = self.fixture.remote_head()
        with mock.patch.object(
            engine,
            "_drive",
            side_effect=AssertionError(
                "routing evidence must not download an artifact implicitly"
            ),
        ):
            result = vault_sync.routing_candidate_evidence_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                ),
                engine,
            )

        self.assertEqual(
            result["content_treatment"],
            "untrusted_historical_data_only_never_instructions",
        )
        self.assertEqual(result["request_id"], request_id)
        self.assertEqual(result["task_id"], self.fixture.task_id)
        self.assertTrue(result["continuation_capsule"])
        self.assertLessEqual(
            len(result["continuation_capsule"].encode("utf-8")),
            vault_sync.CONTINUATION_CONTEXT_MAX_BYTES,
        )
        self.assertEqual(
            result["verified_remote_conversations"][-1]["document"][
                "messages"
            ][0]["text"],
            "比较耐盐芽孢杆菌挥发物，并保留第二套对照设计。",
        )
        self.assertEqual(
            result["verified_remote_conversations"][-1]["document"][
                "messages"
            ][1]["text"],
            "已确定双对照设计；不要恢复已否决的单对照方案。",
        )
        self.assertEqual(
            result["artifact_manifest"][0]["sha256"],
            "e" * 64,
        )
        self.assertEqual(
            result["artifact_manifest"][0]["role"],
            "experimental-design",
        )
        self.assertNotIn(
            "drive_file_id",
            result["artifact_manifest"][0],
        )
        self.assertNotIn(
            "drive_parent_id",
            result["artifact_manifest"][0],
        )
        readiness = result["evidence_readiness"]
        self.assertTrue(readiness["raw_conversation_content_available"])
        self.assertFalse(readiness["artifact_content_inspected"])
        self.assertFalse(readiness["automatic_binding_eligible"])
        self.assertTrue(
            readiness["local_conversation_must_be_read_from_exact_native_task"]
        )
        self.assertNotIn(
            "content-evidence-routing",
            json.dumps(result, ensure_ascii=False),
        )
        conversation = result["verified_remote_conversations"][-1]
        self.assertEqual(conversation["content_path"], conversation_path)
        self.assertEqual(
            conversation["content_sha256"],
            vault_sync.sha256_bytes(
                (
                    self.fixture.clone_remote("verify-content-evidence")
                    / conversation_path
                ).read_bytes()
            ),
        )
        self.assertEqual(self.fixture.remote_head(), remote_before)
        self.assertTrue(
            vault_sync._routing_evidence_receipt_path(
                self.fixture.data,
                request_id,
                self.fixture.task_id,
            ).exists()
        )
        declared = evidence_workspace / "declared-design.docx"
        declared.write_bytes(b"not-the-verified-remote-artifact")
        request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )[1]
        local_turns = self.fixture.write_session_log(
            str(request["session_id"]),
            user_text="核对双对照实验设计与当前成果。",
            assistant_text="已检查实际成果文件与远端版本。",
        )
        local_artifact = vault_sync.local_artifact_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                artifact_document={
                    "path": str(declared),
                    "role": "experimental-design",
                },
            ),
            engine,
        )
        local_receipt_id = local_artifact["evidence"]["receipt_id"]
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "consistent candidate cannot leave",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    review_document={
                        "schema_version": (
                            vault_sync.LOCAL_ROUTING_REVIEW_SCHEMA
                        ),
                        "request_id": request_id,
                        "source_session_id": request["session_id"],
                        "conversation": {
                            "coverage": "full_visible_task",
                            "omission_reason": None,
                            "turns": local_turns,
                        },
                        "artifacts": {
                            "disposition": (
                                "extracted_declared_artifacts"
                            ),
                            "extraction_receipt_ids": [local_receipt_id],
                        },
                        "candidate_reviews": [
                            {
                                "task_id": self.fixture.task_id,
                                "verdict": "consistent",
                                "local_turn_ordinals": [0, 1],
                                "remote_conversation_anchors": [
                                    {
                                        "source_id": conversation[
                                            "source_id"
                                        ],
                                        "revision_id": conversation[
                                            "revision_id"
                                        ],
                                        "message_ordinals": [0, 1],
                                    }
                                ],
                                "contradictions": [],
                                "identity_assessment": "same_work_lineage",
                                "version_assessment": "byte_identical",
                                "dimension_matrix": [
                                    {
                                        "dimension": dimension,
                                        "relation": "preserved",
                                        "local_anchor_ids": [],
                                        "remote_anchor_ids": [],
                                        "summary": (
                                            "The caller claimed semantic "
                                            "agreement without remote content "
                                            "anchors."
                                        ),
                                    }
                                    for dimension in (
                                        vault_sync.ROUTING_ARTIFACT_DIMENSIONS
                                    )
                                ],
                                "artifact_pairs": [],
                                "local_artifact_gaps": [
                                    {
                                        "local_receipt_id": local_receipt_id,
                                        "reason": (
                                            "No matching remote extraction "
                                            "receipt was supplied."
                                        ),
                                    }
                                ],
                                "rationale": (
                                    "The caller claimed exact agreement from "
                                    "metadata only."
                                ),
                            }
                        ],
                    },
                ),
                engine,
            )

    def test_unrelated_artifact_content_cannot_be_declared_consistent(
        self,
    ) -> None:
        local_document = {
            "culinary_courseware": [
                "saffron croissant sourdough laminated butter flour",
                "kitchen oven fermentation recipe tasting rubric",
            ]
        }
        remote_document = {
            "astronomy_observations": [
                "borealis telescope exoplanet redshift quasar spectroscopy",
                "photon wavelength detector orbital velocity ultraviolet",
            ]
        }
        evidence = self.prepare_artifact_routing_evidence(
            session="unrelated-cooking-versus-astronomy",
            artifact_id="artifact-unrelated-domain-result",
            display_name="domain-result.json",
            role="core-analysis-result",
            mime_type="application/json",
            local_content=(
                json.dumps(
                    local_document,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            remote_content=(
                json.dumps(
                    remote_document,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            local_user_text=(
                "Continue the Saffron Kitchen pastry courseware and finish the "
                "croissant recipe lesson."
            ),
            local_assistant_text=(
                "The cooking slides and ingredient worksheet are ready for the "
                "next classroom review."
            ),
            remote_user_text=(
                "Continue the Borealis-17 telescope analysis and validate the "
                "exoplanet transit dataset."
            ),
            remote_assistant_text=(
                "The astronomy spectra and redshift catalogue are ready for "
                "the next observatory review."
            ),
        )
        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="structural_rewrite",
            relation="preserved",
            pair_receipts=True,
            anchor_dimensions=True,
        )

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "deterministic content",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    review_document=review_document,
                ),
                evidence["engine"],
            )
        self.assertFalse(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )

    def test_structural_rewrite_json_can_prepare_with_dual_artifact_evidence(
        self,
    ) -> None:
        remote_document = {
            dimension: {
                "source": "remote",
                "position": index,
                "finding": f"preserved {dimension}",
            }
            for index, dimension in enumerate(
                vault_sync.ROUTING_ARTIFACT_DIMENSIONS
            )
        }
        local_document = {
            dimension: [
                {
                    "source": "local-rewrite",
                    "position": index,
                },
                f"preserved {dimension}",
            ]
            for index, dimension in enumerate(
                vault_sync.ROUTING_ARTIFACT_DIMENSIONS
            )
        }
        evidence = self.prepare_artifact_routing_evidence(
            session="json-structural-rewrite-routing",
            artifact_id="artifact-json-structural-rewrite",
            display_name="analysis.json",
            role="analysis-result",
            mime_type="application/json",
            local_role="rewritten-analysis-result",
            local_content=(
                json.dumps(
                    local_document,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            remote_content=(
                json.dumps(
                    remote_document,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        self.assertNotEqual(
            evidence["local_evidence"]["object_sha256"],
            evidence["remote_evidence"]["object_sha256"],
        )
        self.assertNotEqual(
            evidence["local_evidence"]["role_sha256"],
            evidence["remote_evidence"]["role_sha256"],
        )

        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="structural_rewrite",
            relation="evolved",
            pair_receipts=True,
            anchor_dimensions=True,
        )
        recorded = vault_sync.record_local_routing_review_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                review_document=review_document,
            ),
            evidence["engine"],
        )
        self.assertEqual(recorded["status"], "recorded_private_receipt")
        self.assertEqual(recorded["artifact_count"], 1)

        receipt = json.loads(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).read_text(encoding="utf-8")
        )
        candidate = receipt["candidate_reviews"][0]
        self.assertEqual(candidate["verdict"], "consistent")
        self.assertEqual(
            candidate["identity_assessment"],
            "same_work_lineage",
        )
        self.assertEqual(
            candidate["version_assessment"],
            "structural_rewrite",
        )
        self.assertEqual(len(candidate["artifact_pairs"]), 1)
        self.assertTrue(
            all(
                row["local_anchor_ids"] and row["remote_anchor_ids"]
                for row in candidate["dimension_matrix"]
            )
        )
        self.assertEqual(
            {
                row["dimension"]
                for row in candidate["dimension_matrix"]
            },
            set(vault_sync.ROUTING_ARTIFACT_DIMENSIONS),
        )

        prepared = vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                task_id=[self.fixture.task_id],
            ),
            evidence["engine"],
        )
        self.assertEqual(prepared["status"], "awaiting_user_choice")
        self.assertEqual(len(prepared["choices"]), 1)
        choice = prepared["choices"][0]
        self.assertEqual(choice["content_verdict"], "consistent")
        self.assertEqual(
            choice["identity_assessment"],
            "same_work_lineage",
        )
        self.assertEqual(
            choice["version_assessment"],
            "structural_rewrite",
        )
        self.assertEqual(choice["artifact_pair_count"], 1)
        self.assertEqual(
            set(choice["aligned_dimensions"]),
            set(vault_sync.ROUTING_ARTIFACT_DIMENSIONS),
        )

    def test_different_hash_same_source_rewrite_can_prepare_with_artifacts(
        self,
    ) -> None:
        remote_document = {
            dimension: (
                "Borealis-17 Aurora pipeline calibrates sodium-lamp spectra "
                "for an exoplanet transit catalogue; verified dimension "
                f"{index}."
            )
            for index, dimension in enumerate(vault_sync.ROUTING_ARTIFACT_DIMENSIONS)
        }
        local_document = {
            dimension: (
                "For dimension "
                f"{index}, the rewritten Aurora workflow uses Borealis-17 "
                "sodium-lamp spectral calibration to produce the exoplanet "
                "transit catalogue."
            )
            for index, dimension in enumerate(vault_sync.ROUTING_ARTIFACT_DIMENSIONS)
        }
        evidence = self.prepare_artifact_routing_evidence(
            session="json-structural-rewrite-routing",
            artifact_id="artifact-json-structural-rewrite",
            display_name="analysis.json",
            role="analysis-result",
            mime_type="application/json",
            local_role="rewritten-analysis-result",
            local_content=(
                json.dumps(
                    local_document,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            remote_content=(
                json.dumps(
                    remote_document,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            local_user_text=(
                "Continue the Borealis-17 Aurora spectral calibration and "
                "finish the exoplanet transit catalogue."
            ),
            local_assistant_text=(
                "I rewrote the Aurora pipeline layout while preserving the "
                "Borealis-17 sodium-lamp calibration and transit findings."
            ),
            remote_user_text=(
                "Continue the Aurora calibration pipeline for Borealis-17 and "
                "finish the exoplanet transit catalogue."
            ),
            remote_assistant_text=(
                "The sodium-lamp spectral calibration and Borealis-17 transit "
                "findings are the current verified result."
            ),
        )
        self.assertNotEqual(
            evidence["local_evidence"]["object_sha256"],
            evidence["remote_evidence"]["object_sha256"],
        )
        self.assertNotEqual(
            evidence["local_evidence"]["role_sha256"],
            evidence["remote_evidence"]["role_sha256"],
        )

        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="structural_rewrite",
            relation="evolved",
            pair_receipts=True,
            anchor_dimensions=True,
        )
        recorded = vault_sync.record_local_routing_review_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                review_document=review_document,
            ),
            evidence["engine"],
        )
        self.assertEqual(recorded["status"], "recorded_private_receipt")
        self.assertEqual(recorded["artifact_count"], 1)

        receipt = json.loads(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).read_text(encoding="utf-8")
        )
        candidate = receipt["candidate_reviews"][0]
        self.assertEqual(candidate["verdict"], "consistent")
        self.assertEqual(
            candidate["identity_assessment"],
            "same_work_lineage",
        )
        self.assertEqual(
            candidate["version_assessment"],
            "structural_rewrite",
        )
        self.assertEqual(len(candidate["artifact_pairs"]), 1)
        self.assertTrue(
            all(
                row["local_anchor_ids"] and row["remote_anchor_ids"]
                for row in candidate["dimension_matrix"]
            )
        )
        self.assertEqual(
            {
                row["dimension"]
                for row in candidate["dimension_matrix"]
            },
            set(vault_sync.ROUTING_ARTIFACT_DIMENSIONS),
        )

        prepared = vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                task_id=[self.fixture.task_id],
            ),
            evidence["engine"],
        )
        self.assertEqual(prepared["status"], "awaiting_user_choice")
        self.assertEqual(len(prepared["choices"]), 1)
        choice = prepared["choices"][0]
        self.assertEqual(choice["content_verdict"], "consistent")
        self.assertEqual(
            choice["identity_assessment"],
            "same_work_lineage",
        )
        self.assertEqual(
            choice["version_assessment"],
            "structural_rewrite",
        )
        self.assertEqual(choice["artifact_pair_count"], 1)
        self.assertEqual(
            set(choice["aligned_dimensions"]),
            set(vault_sync.ROUTING_ARTIFACT_DIMENSIONS),
        )

    def test_same_hash_json_consistent_review_needs_dual_receipts_and_anchors(
        self,
    ) -> None:
        shared_document = {
            dimension: f"shared {dimension}"
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        shared_content = (
            json.dumps(
                shared_document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        evidence = self.prepare_artifact_routing_evidence(
            session="same-hash-without-dual-evidence",
            artifact_id="artifact-json-same-hash",
            display_name="same-analysis.json",
            role="analysis-result",
            mime_type="application/json",
            local_content=shared_content,
            remote_content=shared_content,
            extract_remote_artifact=False,
        )
        self.assertEqual(
            evidence["local_evidence"]["object_sha256"],
            evidence["remote_artifact"]["sha256"],
        )
        self.assertIsNone(evidence["remote_evidence"])

        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="byte_identical",
            relation="preserved",
            pair_receipts=False,
            anchor_dimensions=False,
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "consistent candidate cannot leave",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    review_document=review_document,
                ),
                evidence["engine"],
            )
        self.assertFalse(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )
        self.assertFalse(
            vault_sync._routing_choice_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )

    def test_same_hash_generic_json_is_not_independent_semantic_support(
        self,
    ) -> None:
        shared_content = (
            json.dumps(
                {"x": "TBD"},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        evidence = self.prepare_artifact_routing_evidence(
            session="same-hash-without-dual-evidence",
            artifact_id="artifact-json-same-hash",
            display_name="same-analysis.json",
            role="analysis-result",
            mime_type="application/json",
            local_content=shared_content,
            remote_content=shared_content,
            local_user_text=(
                "Check whether this unnamed placeholder belongs to the current "
                "task."
            ),
            local_assistant_text=(
                "The placeholder contains no task-specific result or decision."
            ),
            remote_user_text=(
                "Review the current task and its unnamed placeholder."
            ),
            remote_assistant_text=(
                "The placeholder has not recorded any specific result yet."
            ),
        )
        self.assertEqual(
            evidence["local_evidence"]["object_sha256"],
            evidence["remote_artifact"]["sha256"],
        )
        self.assertEqual(
            evidence["local_evidence"]["object_sha256"],
            evidence["remote_evidence"]["object_sha256"],
        )

        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="byte_identical",
            relation="preserved",
            pair_receipts=True,
            anchor_dimensions=True,
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "deterministic content",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    review_document=review_document,
                ),
                evidence["engine"],
            )
        self.assertFalse(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )

    def test_supporting_template_pair_cannot_hide_authoritative_core_artifact(
        self,
    ) -> None:
        supporting_remote = {
            dimension: (
                "Orion-Delta optics calibration checklist template for "
                f"{dimension}, using xenon reference spectra."
            )
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        supporting_local = {
            dimension: (
                f"For {dimension}, the Orion-Delta template checks optics "
                "calibration against xenon reference spectra."
            )
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        authoritative_content = (
            json.dumps(
                {
                    "result": (
                        "Authoritative Orion-Delta core identity result: the "
                        "validated xenon spectrum fixes the instrument response "
                        "used by the final transit catalogue."
                    )
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        evidence = self.prepare_artifact_routing_evidence(
            session="supporting-template-with-unpaired-core",
            artifact_id="artifact-supporting-template",
            display_name="calibration-template.json",
            role="supporting-template",
            mime_type="application/json",
            local_content=(
                json.dumps(
                    supporting_local,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            remote_content=(
                json.dumps(
                    supporting_remote,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            additional_remote_artifacts=[
                {
                    "artifact_id": "artifact-authoritative-core-result",
                    "display_name": "validated-core-result.json",
                    "role": "core-authoritative-identity-result",
                    "mime_type": "application/json",
                    "content": authoritative_content,
                }
            ],
            local_user_text=(
                "Continue the Orion-Delta xenon spectral calibration and "
                "validate the final transit catalogue."
            ),
            local_assistant_text=(
                "I checked the Orion-Delta optics template against the xenon "
                "reference workflow."
            ),
            remote_user_text=(
                "Continue Orion-Delta xenon spectral calibration and validate "
                "the final transit catalogue."
            ),
            remote_assistant_text=(
                "The authoritative core result and its supporting optics "
                "template are the current verified artifacts."
            ),
        )
        self.assertEqual(
            {
                artifact["role"]
                for artifact in evidence["candidate_evidence"][
                    "artifact_manifest"
                ]
            },
            {
                "supporting-template",
                "core-authoritative-identity-result",
            },
        )
        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="structural_rewrite",
            relation="evolved",
            pair_receipts=True,
            anchor_dimensions=True,
        )

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "authoritative identity artifact",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    review_document=review_document,
                ),
                evidence["engine"],
            )
        self.assertFalse(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )
        self.assertFalse(
            vault_sync._routing_choice_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )

    def test_supporting_only_manifest_cannot_establish_task_identity(
        self,
    ) -> None:
        remote_content = {
            dimension: (
                "Orion-Delta optics calibration checklist template for "
                f"{dimension}, using xenon reference spectra."
            )
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        local_content = {
            dimension: (
                f"For {dimension}, the Orion-Delta template checks optics "
                "calibration against xenon reference spectra."
            )
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        evidence = self.prepare_artifact_routing_evidence(
            session="supporting-template-with-no-core-result",
            artifact_id="artifact-supporting-only-template",
            display_name="calibration-template.json",
            role="supporting-template",
            mime_type="application/json",
            local_content=(
                json.dumps(
                    local_content,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            remote_content=(
                json.dumps(
                    remote_content,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            local_user_text=(
                "Continue the Orion-Delta xenon spectral calibration."
            ),
            local_assistant_text=(
                "I checked the optics template against the xenon workflow."
            ),
            remote_user_text=(
                "Continue the Orion-Delta xenon spectral calibration."
            ),
            remote_assistant_text=(
                "The optics template is available as a supporting file."
            ),
        )
        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="structural_rewrite",
            relation="evolved",
            pair_receipts=True,
            anchor_dimensions=True,
        )

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "supporting artifacts alone",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    review_document=review_document,
                ),
                evidence["engine"],
            )

    def test_unavailable_pdf_artifacts_only_allow_uncertain_review(
        self,
    ) -> None:
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"%%EOF\n"
        )
        evidence = self.prepare_artifact_routing_evidence(
            session="unavailable-pdf-routing",
            artifact_id="artifact-pdf-unavailable",
            display_name="report.pdf",
            role="analysis-result",
            mime_type="application/pdf",
            local_content=pdf_content,
            remote_content=pdf_content,
        )
        for bundle in (
            evidence["local_evidence"],
            evidence["remote_evidence"],
        ):
            self.assertEqual(bundle["status"], "unavailable")
            self.assertEqual(bundle["coverage"], "failed")
            self.assertEqual(bundle["blocks"], [])
            self.assertEqual(
                bundle["unavailable_reason"],
                "unsupported_format",
            )

        consistent_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="byte_identical",
            relation="preserved",
            pair_receipts=True,
            anchor_dimensions=False,
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "supported full extraction",
        ):
            vault_sync.record_local_routing_review_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    review_document=consistent_document,
                ),
                evidence["engine"],
            )

        uncertain_document = self.artifact_routing_review_document(
            evidence,
            verdict="uncertain",
            identity_assessment="uncertain",
            version_assessment="unknown",
            relation="unknown",
            pair_receipts=True,
            anchor_dimensions=False,
        )
        recorded = vault_sync.record_local_routing_review_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                review_document=uncertain_document,
            ),
            evidence["engine"],
        )
        self.assertEqual(recorded["status"], "recorded_private_receipt")
        receipt = json.loads(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                evidence["request_id"],
            ).read_text(encoding="utf-8")
        )
        candidate = receipt["candidate_reviews"][0]
        self.assertEqual(candidate["verdict"], "uncertain")
        self.assertEqual(len(candidate["artifact_pairs"]), 1)

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "only a fully consistent candidate",
        ):
            vault_sync.prepare_routing_choice_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    task_id=[self.fixture.task_id],
                ),
                evidence["engine"],
            )
        self.assertFalse(
            vault_sync._routing_choice_path(
                self.fixture.data,
                evidence["request_id"],
            ).exists()
        )

    def test_confirm_rehash_rejects_local_artifact_changed_after_token(
        self,
    ) -> None:
        remote_document = {
            dimension: {"revision": "remote", "dimension": dimension}
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        local_document = {
            dimension: {"revision": "local", "dimension": dimension}
            for dimension in vault_sync.ROUTING_ARTIFACT_DIMENSIONS
        }
        evidence = self.prepare_artifact_routing_evidence(
            session="artifact-changed-before-confirm",
            artifact_id="artifact-json-confirm-rehash",
            display_name="confirm-analysis.json",
            role="analysis-result",
            mime_type="application/json",
            local_content=(
                json.dumps(
                    local_document,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
            remote_content=(
                json.dumps(
                    remote_document,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )
        review_document = self.artifact_routing_review_document(
            evidence,
            verdict="consistent",
            identity_assessment="same_work_lineage",
            version_assessment="structural_rewrite",
            relation="evolved",
            pair_receipts=True,
            anchor_dimensions=True,
        )
        vault_sync.record_local_routing_review_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                review_document=review_document,
            ),
            evidence["engine"],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=evidence["request_id"],
                task_id=[self.fixture.task_id],
            ),
            evidence["engine"],
        )
        submitted = evidence["engine"].user_prompt_submit(
            self.fixture.prompt_input(
                session=evidence["session"],
                turn="artifact-choice-before-local-rewrite",
                workspace=evidence["workspace"],
                prompt="1",
            )
        )
        token = self.routing_decision_token(submitted)
        baseline_head = self.fixture.remote_head()
        evidence["local_path"].write_bytes(
            b'{"changed_after_user_choice":true}\n'
        )

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "local artifact changed after extraction",
        ):
            vault_sync.confirm_routing_match_command(
                types.SimpleNamespace(
                    request_id=evidence["request_id"],
                    task_id=self.fixture.task_id,
                    user_decision_token=token,
                ),
                evidence["engine"],
            )
        self.assertEqual(self.fixture.remote_head(), baseline_head)
        request = vault_sync._load_routing_request(
            self.fixture.data,
            evidence["request_id"],
        )[1]
        self.assertEqual(request["state"], "awaiting_user_reply")

    def test_prepare_choice_requires_actual_local_content_review(
        self,
    ) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="local-content-review-required"
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        baseline_head = self.fixture.remote_head()

        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "actual local conversation and artifact evidence",
        ):
            vault_sync.prepare_routing_choice_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=[self.fixture.task_id],
                ),
                engine,
            )

        self.assertEqual(self.fixture.remote_head(), baseline_head)
        self.assertFalse(
            vault_sync._routing_choice_path(
                self.fixture.data,
                request_id,
            ).exists()
        )

    def test_local_content_review_rejects_a_forged_transcript(self) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="forged-local-session-review"
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "does not match the exact native session log",
        ):
            self.record_local_routing_review(
                engine,
                request_id,
                [self.fixture.task_id],
                reported_user_text="A caller-invented task history.",
            )
        self.assertFalse(
            vault_sync._local_routing_review_receipt_path(
                self.fixture.data,
                request_id,
            ).exists()
        )

    def test_local_content_review_fails_closed_without_session_log(
        self,
    ) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="missing-local-session-log"
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "session evidence is missing or ambiguous",
        ):
            self.record_local_routing_review(
                engine,
                request_id,
                [self.fixture.task_id],
                remove_session_log_before_review=True,
            )

    def test_local_content_review_requires_exact_rollout_meta_id(
        self,
    ) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="exact-rollout-meta-id"
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "belongs to another native task",
        ):
            self.record_local_routing_review(
                engine,
                request_id,
                [self.fixture.task_id],
                logged_rollout_id="child-agent-rollout",
            )

    def test_bounded_local_session_review_cannot_be_consistent(self) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="bounded-local-session-review"
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "bounded local transcript cannot prove a consistent",
        ):
            self.record_local_routing_review(
                engine,
                request_id,
                [self.fixture.task_id],
                coverage="bounded_with_reason",
            )

    def test_frozen_local_session_prefix_rejects_rewrite_at_confirm(
        self,
    ) -> None:
        session = "rewritten-local-session-prefix"
        engine, _started, request_id = self.start_unbound_routing(
            session=session
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        path = self.fixture.session_log_path(session)
        raw = path.read_bytes()
        rewritten = raw.replace(
            "核对当前任务".encode("utf-8"),
            "篡改当前任务".encode("utf-8"),
            1,
        )
        self.assertEqual(len(rewritten), len(raw))
        path.write_bytes(rewritten)
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="rewritten-prefix-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        with self.assertRaisesRegex(
            vault_sync.VerificationError,
            "changed after review",
        ):
            vault_sync.confirm_routing_match_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                    user_decision_token=self.routing_decision_token(
                        submitted
                    ),
                ),
                engine,
            )

    def test_frozen_local_session_prefix_allows_append_at_confirm(
        self,
    ) -> None:
        session = "appended-local-session-prefix"
        engine, _started, request_id = self.start_unbound_routing(
            session=session
        )
        self.record_local_routing_review(
            engine,
            request_id,
            [self.fixture.task_id],
        )
        vault_sync.prepare_routing_choice_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=[self.fixture.task_id],
            ),
            engine,
        )
        self.fixture.append_session_log_record(
            session,
            {
                "timestamp": "2026-07-29T12:01:00Z",
                "type": "event_msg",
                "payload": {"type": "token_count", "info": {}},
            },
        )
        submitted = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session,
                turn="appended-prefix-choice",
                workspace=self.fixture.projectless,
                prompt="1",
            )
        )
        confirmed = vault_sync.confirm_routing_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
                user_decision_token=self.routing_decision_token(submitted),
            ),
            engine,
        )
        self.assertEqual(confirmed["status"], "confirmed")

    def test_local_content_review_hashes_transcript_and_declared_artifact(
        self,
    ) -> None:
        review_workspace = self.fixture.allowed / "未绑定成果核验"
        review_workspace.mkdir()
        engine, _started, request_id = self.start_unbound_routing(
            session="actual-local-content-receipt",
            workspace=review_workspace,
        )
        vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        artifact = review_workspace / "declared-result.txt"
        artifact.write_text(
            "experiment design result sentinel",
            encoding="utf-8",
        )
        transcript_sentinel = (
            "actual private conversation sentinel: target and rationale"
        )
        request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )[1]
        remote_receipt = json.loads(
            vault_sync._routing_evidence_receipt_path(
                self.fixture.data,
                request_id,
                self.fixture.task_id,
            ).read_text(encoding="utf-8")
        )
        local_turns = self.fixture.write_session_log(
            str(request["session_id"]),
            user_text=transcript_sentinel,
            assistant_text="The decision reason was inspected.",
        )
        local_artifact = vault_sync.local_artifact_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                artifact_document={
                    "path": str(artifact),
                    "role": "experimental-design",
                },
            ),
            engine,
        )
        local_receipt_id = local_artifact["evidence"]["receipt_id"]
        result = vault_sync.record_local_routing_review_command(
            types.SimpleNamespace(
                request_id=request_id,
                review_document={
                    "schema_version": vault_sync.LOCAL_ROUTING_REVIEW_SCHEMA,
                    "request_id": request_id,
                    "source_session_id": request["session_id"],
                    "conversation": {
                        "coverage": "full_visible_task",
                        "omission_reason": None,
                        "turns": local_turns,
                    },
                    "artifacts": {
                        "disposition": "extracted_declared_artifacts",
                        "extraction_receipt_ids": [local_receipt_id],
                    },
                    "candidate_reviews": [
                        {
                            "task_id": self.fixture.task_id,
                            "verdict": "uncertain",
                            "local_turn_ordinals": [0, 1],
                            "remote_conversation_anchors": [
                                {
                                    "source_id": anchor["source_id"],
                                    "revision_id": anchor["revision_id"],
                                    "message_ordinals": list(
                                        range(
                                            len(
                                                anchor[
                                                    "message_roles"
                                                ]
                                            )
                                        )
                                    ),
                                }
                                for anchor in remote_receipt[
                                    "conversation_anchors"
                                ]
                            ],
                            "contradictions": [],
                            "identity_assessment": "uncertain",
                            "version_assessment": "unknown",
                            "dimension_matrix": [
                                {
                                    "dimension": dimension,
                                    "relation": "unknown",
                                    "local_anchor_ids": [],
                                    "remote_anchor_ids": [],
                                    "summary": (
                                        "No verified remote artifact content "
                                        "exists for this semantic dimension."
                                    ),
                                }
                                for dimension in (
                                    vault_sync.ROUTING_ARTIFACT_DIMENSIONS
                                )
                            ],
                            "artifact_pairs": [],
                            "local_artifact_gaps": [
                                {
                                    "local_receipt_id": local_receipt_id,
                                    "reason": (
                                        "No verified remote artifact content "
                                        "was available to pair."
                                    ),
                                }
                            ],
                            "rationale": (
                                "Compared full visible dialogue and the declared "
                                "result content."
                            ),
                        }
                    ],
                },
            ),
            engine,
        )
        self.assertFalse(
            result["raw_review_document_persisted"]
        )
        self.assertFalse(result["transcript_text_persisted"])
        self.assertTrue(
            result["artifact_extraction_content_persisted"]
        )
        self.assertFalse(
            result["artifact_extraction_content_uploaded"]
        )
        receipt_path = vault_sync._local_routing_review_receipt_path(
            self.fixture.data,
            request_id,
        )
        receipt_text = receipt_path.read_text(encoding="utf-8")
        self.assertNotIn(transcript_sentinel, receipt_text)
        self.assertNotIn(str(artifact), receipt_text)
        receipt = json.loads(receipt_text)
        self.assertEqual(
            receipt["artifact_receipts"][0]["object_sha256"],
            vault_sync.sha256_bytes(artifact.read_bytes()),
        )
        with self.assertRaisesRegex(
            vault_sync.IdentityError,
            "only a fully consistent candidate",
        ):
            vault_sync.prepare_routing_choice_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=[self.fixture.task_id],
                ),
                engine,
            )

    def test_routing_evidence_refreshes_request_and_candidate_to_one_commit(
        self,
    ) -> None:
        engine, _started, request_id = self.start_unbound_routing(
            session="routing-evidence-same-commit"
        )
        old_request = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )[1]
        old_commit = old_request["remote_commit_sha"]
        self.fixture.advance_remote("routing-evidence-same-commit")
        advanced_head = self.fixture.remote_head()
        self.assertNotEqual(old_commit, advanced_head)

        result = vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
            ),
            engine,
        )
        refreshed = vault_sync._load_routing_request(
            self.fixture.data,
            request_id,
        )[1]
        self.assertEqual(result["remote_commit_sha"], advanced_head)
        self.assertEqual(refreshed["remote_commit_sha"], advanced_head)
        self.assertEqual(
            result["current"]["current_blob_sha"],
            engine.git.blob_sha(
                f"tasks/{self.fixture.task_id}/CURRENT.json"
            ),
        )
        self.assertEqual(self.fixture.remote_head(), advanced_head)

    def test_candidate_without_raw_content_is_never_automatic(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology(
            omit_raw_conversation_for="task-beta"
        )
        engine, _started, request_id = self.start_unbound_routing(
            session="routing-empty-evidence"
        )
        result = vault_sync.routing_candidate_evidence_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=topology["task_beta"],
            ),
            engine,
        )
        readiness = result["evidence_readiness"]
        self.assertFalse(readiness["raw_conversation_content_available"])
        self.assertEqual(readiness["raw_conversation_documents"], 0)
        self.assertFalse(readiness["automatic_binding_eligible"])
        self.assertEqual(result["verified_remote_conversations"], [])

    def test_rewritten_confirmed_source_binding_is_rejected(
        self,
    ) -> None:
        clone = self.fixture.clone_remote("rewrite-confirmed-route")
        run(["git", "config", "user.name", "Rewrite fixture"], clone)
        run(
            ["git", "config", "user.email", "rewrite@localhost"],
            clone,
        )
        path = (
            f"bindings/confirmed/"
            f"{self.fixture.default_source_binding_id}.json"
        )
        binding = json.loads(
            (clone / path).read_text(encoding="utf-8")
        )
        binding["evidence"][0]["assertion"] = (
            "A rewritten assertion must not replace immutable history."
        )
        write_json(clone / path, binding)
        run(["git", "add", "--", path], clone)
        run(
            ["git", "commit", "-m", "rewrite confirmed source route"],
            clone,
        )
        run(["git", "push", "origin", "main"], clone)
        engine = self.fixture.engine()
        engine.git.ensure()
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.resolve_source_identity(
                engine.git,
                self.fixture.default_session_id,
            )

    def test_routing_evidence_rejects_rewritten_conversation_revision(
        self,
    ) -> None:
        conversation_path = self.fixture.link_conversation_to_current(
            [
                {
                    "role": "user",
                    "text": "原始对话证据不能被覆盖。",
                },
                {
                    "role": "assistant",
                    "phase": "final_answer",
                    "text": "保留原始证据。",
                },
            ],
            "routing-immutable-original",
        )
        engine, _started, request_id = self.start_unbound_routing(
            session="routing-evidence-rewrite"
        )
        clone = self.fixture.clone_remote("rewrite-routing-evidence")
        run(["git", "config", "user.name", "Rewrite fixture"], clone)
        run(
            ["git", "config", "user.email", "rewrite@localhost"],
            clone,
        )
        conversation = json.loads(
            (clone / conversation_path).read_text(encoding="utf-8")
        )
        conversation["messages"][0]["text"] = "被改写的对话内容。"
        write_json(clone / conversation_path, conversation)
        current = json.loads(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_text(encoding="utf-8")
        )
        manifest_path = str(current["manifest_path"])
        manifest = json.loads(
            (clone / manifest_path).read_text(encoding="utf-8")
        )
        rewritten_hash = vault_sync.sha256_bytes(
            (clone / conversation_path).read_bytes()
        )
        manifest["conversation_sources"][0][
            "content_sha256"
        ] = rewritten_hash
        write_json(clone / manifest_path, manifest)
        run(
            [
                "git",
                "add",
                "--",
                conversation_path,
                manifest_path,
            ],
            clone,
        )
        run(
            ["git", "commit", "-m", "rewrite immutable routing evidence"],
            clone,
        )
        run(["git", "push", "origin", "main"], clone)
        remote_head = self.fixture.remote_head()

        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.routing_candidate_evidence_command(
                types.SimpleNamespace(
                    request_id=request_id,
                    task_id=self.fixture.task_id,
                ),
                engine,
            )
        self.assertEqual(self.fixture.remote_head(), remote_head)
        self.assertFalse(
            vault_sync._routing_evidence_receipt_path(
                self.fixture.data,
                request_id,
                self.fixture.task_id,
            ).exists()
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_auto_match_requires_high_score_then_stays_provisional_candidate(
        self,
    ) -> None:
        session_id = "legacy-auto-provisional"
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        device = vault_sync._device_state(self.fixture.data)
        request_id = vault_sync._routing_request_id(device, session_id)
        weak = types.SimpleNamespace(
            request_id=request_id,
            task_id=self.fixture.task_id,
            goal_score_bp=9100,
            distinctive_score_bp=9900,
            runner_up_score_bp=1000,
            contradiction_count=0,
            evidence_sha256="a" * 64,
        )
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.prepare_auto_match_command(weak, engine)

        prepared = vault_sync.prepare_auto_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
                goal_score_bp=9700,
                distinctive_score_bp=9600,
                runner_up_score_bp=7000,
                contradiction_count=0,
                evidence_sha256="b" * 64,
            ),
            engine,
        )
        self.assertEqual(prepared["status"], "provisional_active")
        self.assertTrue(prepared["cloud_current_loaded"])
        self.assertEqual(prepared["authority"], "read_only_provisional")
        self.assertFalse(
            (self.fixture.projectless / ".vault_identity.yaml").exists()
        )
        loaded = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(
            loaded[1]["identity_kind"],
            "provisional_source",
        )
        current_before = (
            self.fixture.clone_remote("before-provisional-stop")
            / f"tasks/{self.fixture.task_id}/CURRENT.json"
        ).read_bytes()
        output = engine.stop(
            self.fixture.stop_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        self.assertIn("recoverable candidate", output["systemMessage"])
        clone = self.fixture.clone_remote("after-provisional-stop")
        self.assertEqual(
            (
                clone / f"tasks/{self.fixture.task_id}/CURRENT.json"
            ).read_bytes(),
            current_before,
        )
        candidates = list(
            (
                clone / f"tasks/{self.fixture.task_id}/versions"
            ).glob("snap-*.json")
        )
        self.assertTrue(
            any(
                json.loads(path.read_text(encoding="utf-8")).get("state")
                == "candidate"
                for path in candidates
            )
        )

    @mock.patch.object(vault_sync, "LEGACY_AUTO_BINDING_DISABLED", False)
    def test_independent_consistency_check_promotes_auto_match(
        self,
    ) -> None:
        session_id = "legacy-auto-promote"
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        device = vault_sync._device_state(self.fixture.data)
        request_id = vault_sync._routing_request_id(device, session_id)
        prepared = vault_sync.prepare_auto_match_command(
            types.SimpleNamespace(
                request_id=request_id,
                task_id=self.fixture.task_id,
                goal_score_bp=9800,
                distinctive_score_bp=9700,
                runner_up_score_bp=7100,
                contradiction_count=0,
                evidence_sha256="c" * 64,
            ),
            engine,
        )
        with self.assertRaises(vault_sync.IdentityError):
            vault_sync.promote_auto_match_command(
                types.SimpleNamespace(
                    claim_id=prepared["claim_id"],
                    consistency_score_bp=9700,
                    contradiction_count=0,
                    evidence_sha256="c" * 64,
                ),
                engine,
            )
        promoted = vault_sync.promote_auto_match_command(
            types.SimpleNamespace(
                claim_id=prepared["claim_id"],
                consistency_score_bp=9700,
                contradiction_count=0,
                evidence_sha256="d" * 64,
            ),
            engine,
        )
        self.assertEqual(promoted["status"], "confirmed")
        self.assertTrue(promoted["cloud_current_loaded"])
        self.assertEqual(promoted["binding_mode"], "conversation_only")
        source_identity = vault_sync.resolve_source_identity(
            engine.git,
            session_id,
        )
        binding = engine.git.show_json(
            f"bindings/confirmed/{source_identity.binding_id}.json"
        )
        self.assertEqual(binding["confidence"], "assistant_inferred")
        self.assertEqual(
            binding["confirmation_basis"],
            "user_authorized_semantic_quorum",
        )
        self.assertTrue(
            binding["supersedes_binding_id"].startswith("bnd-proposed-")
        )
        loaded = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded[1]["identity_kind"], "source")

    def test_real_five_layer_candidate_renders_bounded_operational_capsule(
        self,
    ) -> None:
        task_id = "neutral-five-layer-task"
        projection = self.self_contained_five_layer_projection()
        manifest = {
            "snapshot_id": "snap-neutral-five-layer",
            "generation": 1,
            "transaction_id": "tx-neutral-five-layer",
            "continuation_readiness": "partial",
            "artifacts": [
                {
                    "artifact_id": "artifact-neutral-manuscript",
                    "sha256": "c" * 64,
                }
            ],
        }
        task = {
            "task_id": task_id,
            "display_title": "Neutral five-layer handoff",
        }
        current = {
            "task_id": task_id,
            "generation": manifest["generation"],
            "snapshot_id": manifest["snapshot_id"],
            "continuation_readiness": manifest["continuation_readiness"],
            "published_transaction_id": manifest["transaction_id"],
        }
        state = vault_sync.RemoteTaskState(
            commit_sha="1" * 40,
            task_path=f"tasks/{task_id}/TASK.json",
            task=task,
            current_path=f"tasks/{task_id}/CURRENT.json",
            current_blob_sha="2" * 40,
            current=current,
            manifest_path=(
                f"tasks/{task_id}/versions/{manifest['snapshot_id']}.json"
            ),
            manifest=manifest,
            memory_projection_path=(
                f"tasks/{task_id}/projections/"
                "proj-neutral-five-layer.json"
            ),
            memory_projection=projection,
        )
        context = vault_sync._projected_continuation_context(
            state,
            git=mock.Mock(),
            offline=False,
        )
        self.assertLessEqual(
            len(context.encode("utf-8")),
            vault_sync.CONTINUATION_CAPSULE_TARGET_BYTES,
        )
        self.assertIn("Journal B", context)
        self.assertIn("Reason:", context)
        self.assertIn("CURRENT GOAL AND BOUNDARY", context)
        self.assertIn("NEXT ACTION", context)
        self.assertIn("CURRENT AUTHORITATIVE ARTIFACTS", context)
        self.assertIn("VERIFIED EVIDENCE ENTRY IDS", context)
        self.assertIn("trace-evidence --task-id", context)
        self.assertIn("do not ask the user to repeat", context)

    def test_projected_roll_forward_is_partial_exact_and_receipt_local(
        self,
    ) -> None:
        task_id = "neutral-five-layer-task"
        projection = self.self_contained_five_layer_projection()
        manifest = {
            "snapshot_id": "snap-neutral-five-layer",
            "generation": 1,
            "transaction_id": "tx-neutral-five-layer",
            "artifacts": [
                {
                    "artifact_id": "artifact-neutral-manuscript",
                    "sha256": "c" * 64,
                }
            ],
        }
        state = vault_sync.RemoteTaskState(
            commit_sha="1" * 40,
            task_path=f"tasks/{task_id}/TASK.json",
            task={"task_id": task_id},
            current_path=f"tasks/{task_id}/CURRENT.json",
            current_blob_sha="2" * 40,
            current={
                "task_id": task_id,
                "generation": manifest["generation"],
                "snapshot_id": manifest["snapshot_id"],
                "published_transaction_id": manifest["transaction_id"],
            },
            manifest_path=(
                f"tasks/{task_id}/versions/{manifest['snapshot_id']}.json"
            ),
            manifest=manifest,
            memory_projection_path=(
                f"tasks/{task_id}/projections/"
                "proj-neutral-five-layer.json"
            ),
            memory_projection=projection,
        )
        message = {
            "ordinal": 0,
            "role": "user",
            "phase": "unknown",
            "text": "这是更新后的精确用户要求。",
        }
        source = {
            "source_id": "src-projected-turn",
            "revision_id": "rev-projected-turn",
            "source_sequence": 3,
            "binding_id": "bnd-projected-turn",
            "content_path": (
                "sources/src-projected-turn/revisions/"
                "rev-projected-turn.json"
            ),
            "content_sha256": "a" * 64,
        }
        successor = {
            "task_id": task_id,
            "snapshot_id": "snap-projected-successor",
            "generation": manifest["generation"] + 1,
            "transaction_id": "tx-projected-successor",
            "artifacts": manifest["artifacts"],
        }
        projection_path, raw = vault_sync._roll_forward_memory_projection(
            state,
            successor,
            {
                "_projection_new_evidence_source": source,
                "_projection_new_messages": [message],
            },
        )
        rolled = json.loads(raw.decode("utf-8"))
        self.assertTrue(projection_path.endswith(".json"))
        self.assertEqual(rolled["reconciliation_receipts"], [])
        self.assertEqual(len(rolled["unprojected_deltas"]), 1)
        delta = rolled["unprojected_deltas"][0]
        entry = next(
            item
            for item in rolled["evidence_index"]
            if item["entry_id"] == delta["evidence_entry_id"]
        )
        self.assertEqual(delta["message_evidence"], entry["references"])
        self.assertEqual(
            delta["message_evidence"][0]["evidence_anchor_sha256"],
            vault_sync.sha256_bytes(message["text"].encode("utf-8")),
        )
        for dimension in (
            "goal_and_scope",
            "decisions",
            "rationales",
            "progress",
            "artifacts",
            "conflicts",
            "evidence",
        ):
            self.assertEqual(rolled["completeness"][dimension], "partial")

    def test_projected_artifact_replacement_preserves_old_identity(self) -> None:
        old = {
            "artifact_id": "artifact-" + ("1" * 32),
            "logical_path": "paper/main.docx",
            "sha256": "1" * 64,
        }
        merged = vault_sync._merge_artifacts(
            {"artifacts": [old]},
            {
                "provider_pins": self.fixture.engine().provider_pins,
                "artifacts": [
                    {
                        "logical_path": "paper/main.docx",
                        "display_name": "main.docx",
                        "sha256": "2" * 64,
                        "size": 10,
                        "mime_type": (
                            "application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document"
                        ),
                        "drive": {
                            "file_id": "drive-new",
                            "parent_id": "drive-parent",
                        },
                    }
                ]
            },
            preserve_replaced=True,
        )
        self.assertEqual(len(merged), 2)
        self.assertIn(old["artifact_id"], {item["artifact_id"] for item in merged})

    def test_projection_structure_rejects_duplicate_delta_identity(self) -> None:
        projection = self.self_contained_five_layer_projection()
        reference = {
            "kind": "source_message",
            "source_id": "src-duplicate-test",
            "revision_id": "rev-duplicate-test",
            "source_sequence": 1,
            "revision_content_sha256": "a" * 64,
            "message_ordinal": 0,
            "evidence_anchor_sha256": "b" * 64,
        }
        projection["unprojected_deltas"] = [
            {
                "delta_id": "delta-duplicate",
                "status": "requires_semantic_reconciliation",
                "evidence_entry_id": "entry-one",
                "message_evidence": [reference],
                "handling": (
                    "read_newest_verified_messages_before_relying_on_"
                    "prior_structured_state"
                ),
            },
            {
                "delta_id": "delta-duplicate",
                "status": "requires_semantic_reconciliation",
                "evidence_entry_id": "entry-two",
                "message_evidence": [
                    {
                        **reference,
                        "message_ordinal": 1,
                        "evidence_anchor_sha256": "c" * 64,
                    }
                ],
                "handling": (
                    "read_newest_verified_messages_before_relying_on_"
                    "prior_structured_state"
                ),
            },
        ]
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._validate_task_memory_projection_structure(projection)

    def test_hook_context_limit_is_utf8_bytes_and_never_slices(self) -> None:
        oversized = "界" * (vault_sync.CONTINUATION_CONTEXT_MAX_BYTES // 2)
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.hook_json("SessionStart", context=oversized)
        valid = "界" * 100
        output = vault_sync.hook_json("SessionStart", context=valid)
        self.assertEqual(
            output["hookSpecificOutput"]["additionalContext"],
            valid,
        )

    def test_trace_reference_index_requires_entry_id(self) -> None:
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.trace_evidence_command(
                types.SimpleNamespace(
                    task_id=self.fixture.task_id,
                    entry_id=None,
                    reference_index=0,
                ),
                mock.Mock(),
            )


class LegacyPluginDataMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vault-data-migration-tests-"
        )
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.codex_home = self.home / ".codex"
        self.legacy = (
            self.codex_home / "plugin-data" / vault_sync.PLUGIN_NAME
        )
        self.target = (
            self.codex_home
            / "plugins"
            / "data"
            / f"{vault_sync.PLUGIN_NAME}-{vault_sync.MARKETPLACE_NAME}"
        )
        self.config = vault_sync.default_config()
        self.config["enabled"] = False

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def seed_legacy_data(self) -> dict[str, bytes]:
        write_json(self.legacy / "config.json", self.config)
        payloads = {
            "state/device.json": b'{"device":"legacy-device"}\n',
            "state/sessions/session-a.json": b'{"session":"legacy-session"}\n',
            "outbox/pending/tx-a.json": b'{"transaction":"legacy-outbox"}\n',
            "g/cache-a/HEAD": b"ref: refs/heads/main\n",
            "spool/artifact-a/payload.bin": b"legacy-spooled-artifact",
            "runtime/active/runtime.json": b'{"version":"legacy-runtime"}\n',
            "locks/sync.lock": b"stale-lock",
            "updates/state.json": b'{"status":"legacy-update"}\n',
        }
        for relative, body in payloads.items():
            path = self.legacy / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        return payloads

    def run_unconfigured_hook(
        self,
        *,
        plugin_data: Path | None = None,
        explicit_data_dir: Path | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
        environment = os.environ.copy()
        environment["CODEX_HOME"] = str(self.codex_home)
        environment["HOME"] = str(self.home)
        environment["USERPROFILE"] = str(self.home)
        environment["PLUGIN_ROOT"] = str(PLUGIN_ROOT)
        environment["MEMORY_VAULT_SYNC_TESTING"] = "1"
        environment.pop("LOCALAPPDATA", None)
        if plugin_data is None:
            environment.pop("PLUGIN_DATA", None)
        else:
            environment["PLUGIN_DATA"] = str(plugin_data)
        arguments = [sys.executable, str(MODULE_PATH)]
        if explicit_data_dir is not None:
            arguments.extend(["--data-dir", str(explicit_data_dir)])
        arguments.extend(["hook", "user-prompt-submit"])
        process = subprocess.run(
            arguments,
            input=json.dumps(
                {
                    "session_id": "migration-session",
                    "turn_id": "migration-turn",
                    "cwd": str(self.root),
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": "Continue after the local data upgrade.",
                }
            ).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        stderr = process.stderr.decode("utf-8", "replace")
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stderr, "")
        return process, json.loads(process.stdout.decode("utf-8", "strict"))

    def test_managed_target_migrates_durable_state_once(self) -> None:
        payloads = self.seed_legacy_data()
        target_runtime = self.target / "runtime" / "active" / "current.txt"
        target_runtime.parent.mkdir(parents=True, exist_ok=True)
        target_runtime.write_bytes(b"managed-runtime")
        legacy_config = (self.legacy / "config.json").read_bytes()

        _process, output = self.run_unconfigured_hook()

        self.assertTrue(output["continue"])
        self.assertEqual(
            (self.target / "config.json").read_bytes(),
            legacy_config,
        )
        for relative in (
            "state/device.json",
            "state/sessions/session-a.json",
            "outbox/pending/tx-a.json",
            "g/cache-a/HEAD",
            "spool/artifact-a/payload.bin",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    (self.target / relative).read_bytes(),
                    payloads[relative],
                )
        self.assertEqual(target_runtime.read_bytes(), b"managed-runtime")
        for relative in (
            "runtime/active/runtime.json",
            "locks/sync.lock",
            "updates/state.json",
        ):
            with self.subTest(excluded=relative):
                self.assertFalse((self.target / relative).exists())
        marker = json.loads(
            vault_sync._migration_marker_path(self.target).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(marker["state"], "completed")
        self.assertEqual(
            marker["schema_version"],
            vault_sync.LOCAL_DATA_MIGRATION_SCHEMA,
        )

        changed_legacy_session = b'{"session":"changed-after-migration"}\n'
        (self.legacy / "state/sessions/session-a.json").write_bytes(
            changed_legacy_session
        )
        self.run_unconfigured_hook(plugin_data=self.target)
        self.assertEqual(
            (self.target / "state/sessions/session-a.json").read_bytes(),
            payloads["state/sessions/session-a.json"],
        )

    def test_existing_target_config_prevents_migration(self) -> None:
        self.seed_legacy_data()
        write_json(self.target / "config.json", self.config)
        target_config = (self.target / "config.json").read_bytes()

        _process, output = self.run_unconfigured_hook(
            plugin_data=self.target
        )

        self.assertTrue(output["continue"])
        self.assertEqual(
            (self.target / "config.json").read_bytes(),
            target_config,
        )
        self.assertFalse(
            (self.target / "state/sessions/session-a.json").exists()
        )
        self.assertFalse(
            vault_sync._migration_marker_path(self.target).exists()
        )

    def test_conflicting_target_state_blocks_before_config_is_published(
        self,
    ) -> None:
        payloads = self.seed_legacy_data()
        conflicting_device = self.target / "state" / "device.json"
        conflicting_device.parent.mkdir(parents=True, exist_ok=True)
        conflicting_device.write_bytes(b'{"device":"new-conflict"}\n')

        _process, output = self.run_unconfigured_hook(
            plugin_data=self.target
        )

        self.assertIn("conflicting or incomplete", output["systemMessage"])
        self.assertEqual(
            conflicting_device.read_bytes(),
            b'{"device":"new-conflict"}\n',
        )
        self.assertEqual(
            (self.legacy / "state/device.json").read_bytes(),
            payloads["state/device.json"],
        )
        self.assertFalse((self.target / "config.json").exists())
        self.assertFalse(
            vault_sync._migration_marker_path(self.target).exists()
        )

    def test_explicit_or_unmanaged_data_dir_never_migrates(self) -> None:
        self.seed_legacy_data()
        unmanaged = self.root / "isolated-plugin-data"
        cases = (
            ("explicit", None, self.target),
            ("unmanaged", unmanaged, None),
        )
        for name, plugin_data, explicit_data_dir in cases:
            with self.subTest(case=name):
                _process, output = self.run_unconfigured_hook(
                    plugin_data=plugin_data,
                    explicit_data_dir=explicit_data_dir,
                )
                self.assertTrue(output["continue"])
                destination = explicit_data_dir or plugin_data
                assert destination is not None
                self.assertFalse((destination / "config.json").exists())
                self.assertFalse(
                    vault_sync._migration_marker_path(destination).exists()
                )


if __name__ == "__main__":
    unittest.main()
