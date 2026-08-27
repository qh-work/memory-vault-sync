from __future__ import annotations

import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from test_vault_sync import VaultFixture, vault_sync, write_json


class FinalRoutingRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vault-final-routing-regressions-"
        )
        self.root = Path(self.temporary.name)
        self.previous_testing = os.environ.get("MEMORY_VAULT_SYNC_TESTING")
        os.environ["MEMORY_VAULT_SYNC_TESTING"] = "1"
        self.fixture = VaultFixture(self.root)

    def tearDown(self) -> None:
        if self.previous_testing is None:
            os.environ.pop("MEMORY_VAULT_SYNC_TESTING", None)
        else:
            os.environ["MEMORY_VAULT_SYNC_TESTING"] = self.previous_testing
        self.temporary.cleanup()

    def test_cached_offline_legacy_provisional_is_revoked_and_unbound(
        self,
    ) -> None:
        session_id = "offline-provisional-resume"
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=self.fixture.projectless,
            )
        )
        device = vault_sync._device_state(self.fixture.data)
        routing_record = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(routing_record)
        assert routing_record is not None
        with mock.patch.object(
            vault_sync,
            "LEGACY_AUTO_BINDING_DISABLED",
            False,
        ):
            prepared = vault_sync.prepare_auto_match_command(
                types.SimpleNamespace(
                    request_id=routing_record[1]["request_id"],
                    task_id=self.fixture.task_id,
                    goal_score_bp=9700,
                    distinctive_score_bp=9600,
                    runner_up_score_bp=7000,
                    contradiction_count=0,
                    evidence_sha256=vault_sync.sha256_bytes(
                        b"offline-provisional-evidence"
                    ),
                ),
                engine,
            )
        self.assertEqual(prepared["status"], "provisional_active")

        session_key = vault_sync._session_key(device, session_id)
        session_path = vault_sync._session_path(
            self.fixture.data,
            session_key,
        )
        session_path.unlink()
        claim_before = vault_sync._load_provisional_claim(
            self.fixture.data,
            session_key,
        )
        self.assertIsNotNone(claim_before)
        assert claim_before is not None
        self.assertEqual(claim_before[1]["state"], "provisional_active")

        with mock.patch.object(
            engine.git,
            "ensure",
            side_effect=vault_sync.OfflineError("deterministic offline"),
        ):
            output = engine.session_start(
                self.fixture.session_input(
                    session=session_id,
                    workspace=self.fixture.projectless,
                )
            )

        rendered = json.dumps(output, ensure_ascii=False)
        self.assertIn("MEMORY_VAULT_ROUTING", rendered)
        self.assertIn("unbound_pending_model", rendered)
        self.assertNotIn("provisional_consistency_check", rendered)
        self.assertIn("reference-only", output["systemMessage"])
        claim_after = vault_sync._load_provisional_claim(
            self.fixture.data,
            session_key,
        )
        self.assertIsNotNone(claim_after)
        assert claim_after is not None
        self.assertEqual(claim_after[1]["state"], "revoked")
        self.assertEqual(
            claim_after[1]["claim_id"],
            claim_before[1]["claim_id"],
        )

    def test_shared_identity_legacy_provisional_is_revoked_with_same_fingerprint(
        self,
    ) -> None:
        topology = self.fixture.install_split_topology()
        engine = self.fixture.engine()
        engine.git.ensure()
        single_marker = self.fixture.workspace / ".vault_identity.yaml"
        primary = json.loads(single_marker.read_text(encoding="utf-8"))
        secondary_task = topology["task_beta"]
        current_path = f"tasks/{secondary_task}/CURRENT.json"
        current = engine.git.show_json(current_path)
        secondary = dict(primary)
        secondary.update(
            {
                "binding_id": "bnd-workspace-beta-resume",
                "semantic_task_id": secondary_task,
                "workspace_lineage_id": "lineage-beta-resume",
                "base": {
                    "snapshot_id": current["snapshot_id"],
                    "manifest_sha256": vault_sync.sha256_bytes(
                        engine.git.show_bytes(current["manifest_path"])
                    ),
                    "current_blob_sha": engine.git.blob_sha(current_path),
                    "transaction_id": current["published_transaction_id"],
                },
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
        session_id = "shared-provisional-same-fingerprint"
        started = engine.session_start(
            self.fixture.session_input(session=session_id)
        )
        self.assertIn(
            "MEMORY_VAULT_ROUTING",
            started["hookSpecificOutput"]["additionalContext"],
        )
        device = vault_sync._device_state(self.fixture.data)
        route = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(route)
        assert route is not None
        fingerprint = route[1]["workspace_identity_fingerprint"]
        self.assertIsInstance(fingerprint, str)
        with mock.patch.object(
            vault_sync,
            "LEGACY_AUTO_BINDING_DISABLED",
            False,
        ):
            prepared = vault_sync.prepare_auto_match_command(
                types.SimpleNamespace(
                    request_id=route[1]["request_id"],
                    task_id=self.fixture.task_id,
                    goal_score_bp=9700,
                    distinctive_score_bp=9600,
                    runner_up_score_bp=7000,
                    contradiction_count=0,
                    evidence_sha256=vault_sync.sha256_bytes(
                        b"shared-same-fingerprint-evidence"
                    ),
                ),
                engine,
            )
        self.assertEqual(prepared["status"], "provisional_active")
        session_key = vault_sync._session_key(device, session_id)
        vault_sync._session_path(
            self.fixture.data,
            session_key,
        ).unlink()

        resumed = engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=self.fixture.workspace,
            )
        )

        rendered = json.dumps(resumed, ensure_ascii=False)
        self.assertIn("MEMORY_VAULT_ROUTING", rendered)
        self.assertIn("unbound_pending_model", rendered)
        self.assertNotIn("provisional_consistency_check", rendered)
        route_after = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(route_after)
        assert route_after is not None
        self.assertEqual(
            route_after[1]["workspace_identity_fingerprint"],
            fingerprint,
        )
        claim = vault_sync._load_provisional_claim(
            self.fixture.data,
            session_key,
        )
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim[1]["state"], "revoked")
        local_session = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNone(local_session)

    def test_prompt_in_different_workspace_cannot_reuse_pending_route(
        self,
    ) -> None:
        workspace_a = self.fixture.allowed / "routing-workspace-a"
        workspace_b = self.fixture.allowed / "routing-workspace-b"
        workspace_a.mkdir()
        workspace_b.mkdir()
        session_id = "same-session-different-workspace"
        turn_id = "first-turn-in-workspace-b"
        engine = self.fixture.engine()
        started = engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=workspace_a,
            )
        )
        self.assertIn(
            "MEMORY_VAULT_ROUTING",
            started["hookSpecificOutput"]["additionalContext"],
        )
        device = vault_sync._device_state(self.fixture.data)
        route_before = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(route_before)
        assert route_before is not None
        self.assertEqual(
            route_before[1]["workspace_root"],
            str(workspace_a.resolve()),
        )

        output = engine.user_prompt_submit(
            self.fixture.prompt_input(
                session=session_id,
                turn=turn_id,
                prompt="This prompt belongs only to workspace B.",
                workspace=workspace_b,
            )
        )

        rendered = json.dumps(output, ensure_ascii=False)
        self.assertNotIn("MEMORY_VAULT_ROUTING", rendered)
        self.assertIn(
            "no task route was changed",
            output["systemMessage"].lower(),
        )
        route_after = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(route_after)
        assert route_after is not None
        self.assertEqual(
            route_after[1]["workspace_root"],
            str(workspace_a.resolve()),
        )
        self.assertIsNone(route_after[1]["pending_turn_id"])
        self.assertIsNone(route_after[1]["pending_prompt"])
        session_key = vault_sync._session_key(device, session_id)
        turn_key = vault_sync._turn_key(device, session_id, turn_id)
        self.assertFalse(
            vault_sync._prompt_path(
                self.fixture.data,
                session_key,
                turn_key,
            ).exists()
        )
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session_id,
            )
        )

    def test_legacy_provisional_revocation_is_scoped_to_original_workspace(
        self,
    ) -> None:
        workspace_a = self.fixture.allowed / "provisional-workspace-a"
        workspace_b = self.fixture.allowed / "provisional-workspace-b"
        workspace_a.mkdir()
        workspace_b.mkdir()
        session_id = "provisional-cross-workspace-resume"
        engine = self.fixture.engine()
        engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=workspace_a,
            )
        )
        device = vault_sync._device_state(self.fixture.data)
        route = vault_sync._load_routing_request_for_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNotNone(route)
        assert route is not None
        with mock.patch.object(
            vault_sync,
            "LEGACY_AUTO_BINDING_DISABLED",
            False,
        ):
            prepared = vault_sync.prepare_auto_match_command(
                types.SimpleNamespace(
                    request_id=route[1]["request_id"],
                    task_id=self.fixture.task_id,
                    goal_score_bp=9700,
                    distinctive_score_bp=9600,
                    runner_up_score_bp=7000,
                    contradiction_count=0,
                    evidence_sha256=vault_sync.sha256_bytes(
                        b"workspace-scoped-provisional-evidence"
                    ),
                ),
                engine,
            )
        self.assertEqual(prepared["status"], "provisional_active")
        session_key = vault_sync._session_key(device, session_id)
        vault_sync._session_path(
            self.fixture.data,
            session_key,
        ).unlink()

        wrong_workspace = engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=workspace_b,
            )
        )

        wrong_rendered = json.dumps(wrong_workspace, ensure_ascii=False)
        self.assertNotIn("MEMORY_VAULT_ROUTING", wrong_rendered)
        self.assertNotIn("provisional_consistency_check", wrong_rendered)
        self.assertNotIn("[Private Memory Vault]", wrong_rendered)
        self.assertIsNone(
            vault_sync._load_session(
                self.fixture.data,
                device,
                session_id,
            )
        )
        claim_after_refusal = vault_sync._load_provisional_claim(
            self.fixture.data,
            session_key,
        )
        self.assertIsNotNone(claim_after_refusal)
        assert claim_after_refusal is not None
        self.assertEqual(
            claim_after_refusal[1]["state"],
            "provisional_active",
        )

        original_workspace = engine.session_start(
            self.fixture.session_input(
                session=session_id,
                workspace=workspace_a,
            )
        )

        original_rendered = json.dumps(
            original_workspace,
            ensure_ascii=False,
        )
        self.assertIn("MEMORY_VAULT_ROUTING", original_rendered)
        self.assertIn(
            "unbound_pending_model",
            original_rendered,
        )
        self.assertNotIn(
            "provisional_consistency_check",
            original_rendered,
        )
        claim_after_recovery = vault_sync._load_provisional_claim(
            self.fixture.data,
            session_key,
        )
        self.assertIsNotNone(claim_after_recovery)
        assert claim_after_recovery is not None
        self.assertEqual(
            claim_after_recovery[1]["state"],
            "revoked",
        )
        recovered_session = vault_sync._load_session(
            self.fixture.data,
            device,
            session_id,
        )
        self.assertIsNone(recovered_session)


class FinalMigrationRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="vault-final-migration-regressions-"
        )
        self.root = Path(self.temporary.name)
        self.config = vault_sync.default_config()
        self.config["enabled"] = False

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _managed_target(codex_home: Path) -> Path:
        return (
            codex_home
            / "plugins"
            / "data"
            / f"{vault_sync.PLUGIN_NAME}-{vault_sync.MARKETPLACE_NAME}"
        )

    @staticmethod
    def _legacy_root(codex_home: Path) -> Path:
        return codex_home / "plugin-data" / vault_sync.PLUGIN_NAME

    def _migration_environment(
        self,
        *,
        home: Path,
        codex_home: Path,
        local_app_data: Path | None = None,
    ) -> dict[str, str]:
        environment = {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "CODEX_HOME": str(codex_home),
            "MEMORY_VAULT_SYNC_TESTING": "1",
        }
        if local_app_data is not None:
            environment["LOCALAPPDATA"] = str(local_app_data)
        return environment

    def test_source_change_after_collection_never_publishes_migration(
        self,
    ) -> None:
        home = self.root / "home"
        codex_home = home / ".codex"
        legacy = self._legacy_root(codex_home)
        target = self._managed_target(codex_home)
        write_json(legacy / "config.json", self.config)
        changing_source = legacy / "state" / "device.json"
        changing_source.parent.mkdir(parents=True)
        changing_source.write_bytes(b'{"device":"before"}\n')
        stable_source = legacy / "state" / "sessions" / "session-a.json"
        stable_source.parent.mkdir(parents=True)
        stable_source.write_bytes(b'{"session":"stable"}\n')
        original_copy = vault_sync._copy_migration_file
        changed = False

        def copy_then_change(
            source: Path,
            destination: Path,
            expected_sha256: str,
            expected_size: int,
        ) -> None:
            nonlocal changed
            original_copy(
                source,
                destination,
                expected_sha256,
                expected_size,
            )
            if source.resolve() == changing_source.resolve() and not changed:
                changing_source.write_bytes(b'{"device":"after"}\n')
                changed = True

        environment = self._migration_environment(
            home=home,
            codex_home=codex_home,
        )
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(
                vault_sync,
                "_copy_migration_file",
                side_effect=copy_then_change,
            ),
            self.assertRaises(vault_sync.BusyError),
        ):
            vault_sync.migrate_legacy_plugin_data(target)

        self.assertTrue(changed)
        self.assertFalse((target / "config.json").exists())
        self.assertFalse(
            vault_sync._migration_marker_path(target).exists()
        )

    def test_existing_target_config_returns_before_migration_lock(
        self,
    ) -> None:
        home = self.root / "configured-target-home"
        codex_home = home / ".codex"
        legacy = self._legacy_root(codex_home)
        target = self._managed_target(codex_home)
        write_json(legacy / "config.json", self.config)
        write_json(target / "config.json", self.config)
        target_config_before = (target / "config.json").read_bytes()
        environment = self._migration_environment(
            home=home,
            codex_home=codex_home,
        )

        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(
                vault_sync,
                "FileLock",
                side_effect=AssertionError(
                    "configured target must not enter migration locking"
                ),
            ) as file_lock,
        ):
            result = vault_sync.migrate_legacy_plugin_data(target)

        self.assertIsNone(result)
        file_lock.assert_not_called()
        self.assertEqual(
            (target / "config.json").read_bytes(),
            target_config_before,
        )
        self.assertFalse(
            vault_sync._migration_marker_path(target).exists()
        )

    def test_unlisted_target_state_conflicts_without_deleting_it(
        self,
    ) -> None:
        extra_payload = b"must remain byte-for-byte intact"
        for state_root in ("g", "outbox", "spool", "state"):
            with self.subTest(state_root=state_root):
                case_root = self.root / f"extra-{state_root}"
                home = case_root / "home"
                codex_home = home / ".codex"
                legacy = self._legacy_root(codex_home)
                target = self._managed_target(codex_home)
                write_json(legacy / "config.json", self.config)
                source_state = legacy / "state" / "device.json"
                source_state.parent.mkdir(parents=True)
                source_state.write_bytes(b'{"device":"legacy"}\n')
                extra = target / state_root / "unlisted-local-state.bin"
                extra.parent.mkdir(parents=True)
                extra.write_bytes(extra_payload)
                environment = self._migration_environment(
                    home=home,
                    codex_home=codex_home,
                )

                with (
                    mock.patch.dict(os.environ, environment, clear=True),
                    self.assertRaises(vault_sync.ConflictError),
                ):
                    vault_sync.migrate_legacy_plugin_data(target)

                self.assertEqual(extra.read_bytes(), extra_payload)
                self.assertFalse((target / "config.json").exists())
                self.assertFalse(
                    vault_sync._migration_marker_path(target).exists()
                )

    def test_windows_localappdata_is_used_only_as_single_legacy_source(
        self,
    ) -> None:
        for case, add_codex_source in (
            ("single", False),
            ("multiple", True),
        ):
            with self.subTest(case=case):
                case_root = self.root / case
                home = case_root / "home"
                codex_home = home / ".codex"
                local_app_data = case_root / "LocalAppData"
                windows_legacy = (
                    local_app_data
                    / "OpenAI"
                    / "Codex"
                    / "plugin-data"
                    / vault_sync.PLUGIN_NAME
                )
                target = self._managed_target(codex_home)
                write_json(windows_legacy / "config.json", self.config)
                if add_codex_source:
                    write_json(
                        self._legacy_root(codex_home) / "config.json",
                        self.config,
                    )
                environment = self._migration_environment(
                    home=home,
                    codex_home=codex_home,
                    local_app_data=local_app_data,
                )
                with mock.patch.dict(
                    os.environ,
                    environment,
                    clear=True,
                ):
                    if add_codex_source:
                        with self.assertRaises(vault_sync.ConflictError):
                            vault_sync.migrate_legacy_plugin_data(target)
                    else:
                        result = vault_sync.migrate_legacy_plugin_data(
                            target
                        )
                        self.assertIsNotNone(result)

                if add_codex_source:
                    self.assertFalse((target / "config.json").exists())
                    self.assertFalse(
                        vault_sync._migration_marker_path(target).exists()
                    )
                else:
                    self.assertEqual(
                        (target / "config.json").read_bytes(),
                        (windows_legacy / "config.json").read_bytes(),
                    )
                    marker = json.loads(
                        vault_sync._migration_marker_path(
                            target
                        ).read_text(encoding="utf-8")
                    )
                    self.assertEqual(marker["state"], "completed")


if __name__ == "__main__":
    unittest.main()
