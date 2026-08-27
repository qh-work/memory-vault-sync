from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
ENTRYPOINT = SCRIPTS / "vault_sync.py"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from memory_vault_runtime import diagnostics  # noqa: E402
from memory_vault_runtime import core as vault_sync  # noqa: E402


class PrivateDiagnosticsTests(unittest.TestCase):
    def _record(
        self,
        root: Path,
        index: int = 0,
    ) -> dict:
        return diagnostics.record_private_diagnostic(
            root,
            correlation_id=f"diag-{index:032x}",
            occurred_at=f"2026-08-05T03:00:{index % 60:02d}Z",
            operation="hook.session-start",
            runtime_version=vault_sync.VERSION,
            error_category="unexpected-internal",
        )

    def test_record_is_exact_bounded_private_metadata(self) -> None:
        secret = "ghp_" + "S" * 36
        local_path = "/Users/example/private/work.txt"
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-"
        ) as temporary:
            root = Path(temporary)
            record = self._record(root)
            summary = diagnostics.diagnostics_summary(root, limit=10)
            self.assertEqual(summary["record_count"], 1)
            self.assertEqual(summary["corrupt_record_count"], 0)
            self.assertEqual(summary["recent_records"], [record])
            self.assertTrue(summary["private_local_only"])
            self.assertFalse(summary["captured_sensitive_content"])
            records = root / "diagnostics" / "records"
            raw = next(records.iterdir()).read_bytes()
            self.assertLessEqual(
                len(raw),
                diagnostics.MAX_DIAGNOSTIC_RECORD_BYTES,
            )
            self.assertNotIn(secret.encode(), raw)
            self.assertNotIn(local_path.encode(), raw)
            self.assertNotIn(b"traceback", raw.lower())
            self.assertNotIn(b"exception", raw.lower())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(records.stat().st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE(next(records.iterdir()).stat().st_mode),
                    0o600,
                )

    def test_rotation_keeps_at_most_sixty_four_records(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-rotation-"
        ) as temporary:
            root = Path(temporary)
            for index in range(70):
                self._record(root, index)
            summary = diagnostics.diagnostics_summary(root, limit=64)
            records = root / "diagnostics" / "records"
            self.assertEqual(summary["record_count"], 64)
            self.assertEqual(len(list(records.iterdir())), 64)
            self.assertLessEqual(
                sum(path.stat().st_size for path in records.iterdir()),
                diagnostics.MAX_DIAGNOSTIC_TOTAL_BYTES,
            )
            ids = {
                item["correlation_id"] for item in summary["recent_records"]
            }
            self.assertNotIn("diag-" + f"{0:032x}", ids)
            self.assertIn("diag-" + f"{69:032x}", ids)

    def test_corrupt_record_is_counted_without_echoing_its_content(self) -> None:
        secret = "github_pat_" + "X" * 40
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-corrupt-"
        ) as temporary:
            root = Path(temporary)
            self._record(root)
            path = next((root / "diagnostics" / "records").iterdir())
            path.write_text(json.dumps({"message": secret}), encoding="ascii")
            summary = diagnostics.diagnostics_summary(root, limit=10)
            self.assertEqual(summary["record_count"], 0)
            self.assertEqual(summary["corrupt_record_count"], 1)
            self.assertNotIn(secret, json.dumps(summary, sort_keys=True))

    @unittest.skipIf(os.name == "nt", "POSIX symbolic-link semantics")
    def test_symbolic_link_diagnostic_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-link-"
        ) as temporary:
            root = Path(temporary)
            target = root / "outside"
            target.mkdir()
            (root / "diagnostics").symlink_to(target, target_is_directory=True)
            with self.assertRaises(diagnostics.DiagnosticError):
                self._record(root)
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX hard-link and mode semantics")
    def test_unsafe_record_entries_fail_closed(self) -> None:
        cases = ("hard-link", "wide-mode", "unexpected", "oversize")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix=f"memory-vault-private-diagnostics-{case}-"
            ) as temporary:
                root = Path(temporary)
                self._record(root)
                records = root / "diagnostics" / "records"
                path = next(records.iterdir())
                if case == "hard-link":
                    os.link(path, root / "second-link.json")
                elif case == "wide-mode":
                    path.chmod(0o644)
                elif case == "unexpected":
                    (records / "README.txt").write_text(
                        "not a record",
                        encoding="ascii",
                    )
                else:
                    path.write_bytes(
                        b"x" * (diagnostics.MAX_DIAGNOSTIC_RECORD_BYTES + 1)
                    )
                    path.chmod(0o600)
                with self.assertRaises(diagnostics.DiagnosticError):
                    diagnostics.diagnostics_summary(root, limit=10)

    def test_exclusive_create_collision_does_not_delete_existing_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-collision-"
        ) as temporary:
            root = Path(temporary)
            existing = self._record(root)
            path = next((root / "diagnostics" / "records").iterdir())
            before = path.read_bytes()
            with self.assertRaises(diagnostics.DiagnosticError):
                diagnostics.record_private_diagnostic(
                    root,
                    correlation_id=existing["correlation_id"],
                    occurred_at="2026-08-05T04:00:00Z",
                    operation="hook.stop",
                    runtime_version=vault_sync.VERSION,
                    error_category="unexpected-internal",
                )
            self.assertTrue(path.is_file())
            self.assertEqual(path.read_bytes(), before)

    def test_unexpected_hook_failure_records_only_correlation_metadata(
        self,
    ) -> None:
        secret = "sk-private-hidden-value at /Users/example/private/task.txt"
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-hook-"
        ) as temporary:
            root = Path(temporary)
            output: list[dict] = []
            engine = mock.MagicMock()
            engine.session_start.side_effect = RuntimeError(secret)
            with (
                mock.patch.object(
                    vault_sync,
                    "_refresh_stable_runtime",
                    return_value={},
                ),
                mock.patch.object(
                    vault_sync,
                    "read_hook_input",
                    return_value={"source": "other"},
                ),
                mock.patch.object(
                    vault_sync,
                    "SyncEngine",
                    return_value=engine,
                ),
                mock.patch.object(
                    vault_sync,
                    "_print_json",
                    side_effect=output.append,
                ),
            ):
                self.assertEqual(
                    vault_sync._hook_dispatch(
                        "session-start",
                        vault_sync.default_config(),
                        root,
                    ),
                    0,
                )
            serialized = json.dumps(output, sort_keys=True)
            self.assertNotIn(secret, serialized)
            match = re.search(r"diag-[0-9a-f]{32}", serialized)
            self.assertIsNotNone(match)
            summary = diagnostics.diagnostics_summary(root, limit=10)
            self.assertEqual(summary["record_count"], 1)
            self.assertEqual(
                summary["recent_records"][0]["correlation_id"],
                match.group(0),
            )
            self.assertEqual(
                summary["recent_records"][0]["operation"],
                "hook.session-start",
            )
            for path in (root / "diagnostics").rglob("*"):
                if path.is_file():
                    self.assertNotIn(secret.encode(), path.read_bytes())

    def test_update_check_internal_failure_is_recorded_without_blocking_hook(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-update-"
        ) as temporary:
            root = Path(temporary)
            output: list[dict] = []
            engine = mock.MagicMock()
            engine.session_start.return_value = vault_sync.hook_json(
                "SessionStart"
            )
            updater = mock.MagicMock()
            updater.check.side_effect = RuntimeError("sensitive updater text")
            with (
                mock.patch.object(
                    vault_sync,
                    "_refresh_stable_runtime",
                    return_value={},
                ),
                mock.patch.object(
                    vault_sync,
                    "read_hook_input",
                    return_value={"source": "startup"},
                ),
                mock.patch.object(
                    vault_sync,
                    "PluginUpdater",
                    return_value=updater,
                ),
                mock.patch.object(
                    vault_sync,
                    "SyncEngine",
                    return_value=engine,
                ),
                mock.patch.object(
                    vault_sync,
                    "_print_json",
                    side_effect=output.append,
                ),
            ):
                vault_sync._hook_dispatch(
                    "session-start",
                    vault_sync.default_config(),
                    root,
                )
            summary = diagnostics.diagnostics_summary(root, limit=10)
            self.assertEqual(summary["record_count"], 1)
            self.assertEqual(
                summary["recent_records"][0]["operation"],
                "hook.session-start.update-check",
            )
            self.assertNotIn(
                "sensitive updater text",
                json.dumps(output, sort_keys=True),
            )

    def test_expected_update_outage_does_not_create_internal_diagnostic(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-expected-"
        ) as temporary:
            root = Path(temporary)
            engine = mock.MagicMock()
            engine.session_start.return_value = vault_sync.hook_json(
                "SessionStart"
            )
            updater = mock.MagicMock()
            updater.check.side_effect = vault_sync.OfflineError(
                "expected offline update check"
            )
            with (
                mock.patch.object(
                    vault_sync,
                    "_refresh_stable_runtime",
                    return_value={},
                ),
                mock.patch.object(
                    vault_sync,
                    "read_hook_input",
                    return_value={"source": "startup"},
                ),
                mock.patch.object(
                    vault_sync,
                    "PluginUpdater",
                    return_value=updater,
                ),
                mock.patch.object(
                    vault_sync,
                    "SyncEngine",
                    return_value=engine,
                ),
                mock.patch.object(vault_sync, "_print_json"),
            ):
                vault_sync._hook_dispatch(
                    "session-start",
                    vault_sync.default_config(),
                    root,
                )
            summary = diagnostics.diagnostics_summary(root, limit=10)
            self.assertEqual(summary["record_count"], 0)

    def test_unexpected_setup_failure_records_only_generic_reference(
        self,
    ) -> None:
        secret = "private setup exception content"
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-setup-"
        ) as temporary:
            root = Path(temporary)
            output: list[dict] = []
            with (
                mock.patch.object(
                    vault_sync,
                    "load_config",
                    side_effect=RuntimeError(secret),
                ),
                mock.patch.object(
                    vault_sync,
                    "read_hook_input",
                    return_value={},
                ),
                mock.patch.object(
                    vault_sync,
                    "_print_json",
                    side_effect=output.append,
                ),
            ):
                self.assertEqual(
                    vault_sync.main(
                        [
                            "--data-dir",
                            str(root),
                            "hook",
                            "stop",
                        ]
                    ),
                    0,
                )
            serialized = json.dumps(output, sort_keys=True)
            self.assertNotIn(secret, serialized)
            summary = diagnostics.diagnostics_summary(root, limit=10)
            self.assertEqual(summary["record_count"], 1)
            self.assertEqual(
                summary["recent_records"][0]["operation"],
                "hook.stop.setup",
            )
            self.assertIn(
                summary["recent_records"][0]["correlation_id"],
                serialized,
            )

    def test_status_and_doctor_report_diagnostic_health(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-status-"
        ) as temporary:
            root = Path(temporary)
            config = vault_sync.validate_config(vault_sync.default_config())
            engine = vault_sync.SyncEngine(config, root)
            status_value = engine.status()["private_diagnostics"]
            self.assertTrue(status_value["available"])
            self.assertEqual(status_value["record_count"], 0)
            checks = {
                item["name"]: item for item in engine.doctor()["checks"]
            }
            self.assertTrue(checks["private_diagnostics"]["ok"])

    def test_unconfigured_cli_can_list_private_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-cli-"
        ) as temporary:
            root = Path(temporary)
            self._record(root)
            process = subprocess.run(
                [
                    sys.executable,
                    str(ENTRYPOINT),
                    "--data-dir",
                    str(root),
                    "diagnostics",
                    "--limit",
                    "1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stderr, b"")
            result = json.loads(process.stdout.decode("utf-8"))
            self.assertEqual(
                result["schema_version"],
                diagnostics.DIAGNOSTIC_SUMMARY_SCHEMA,
            )
            self.assertEqual(result["record_count"], 1)
            self.assertEqual(len(result["recent_records"]), 1)

    def test_summary_limit_and_record_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-private-diagnostics-bounds-"
        ) as temporary:
            root = Path(temporary)
            for invalid in (-1, 65, True):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(diagnostics.DiagnosticError):
                        diagnostics.diagnostics_summary(root, limit=invalid)
            with self.assertRaises(diagnostics.DiagnosticError):
                diagnostics.diagnostic_record(
                    correlation_id="diag-invalid",
                    occurred_at="2026-08-05T03:00:00Z",
                    operation="hook.stop",
                    runtime_version=vault_sync.VERSION,
                    error_category="unexpected-internal",
                )


if __name__ == "__main__":
    unittest.main()
