"""Synthetic managed-installation cases for independent reviewers; not run here.

All packages contain inert synthetic source. No network, real keys, host setup
or private Vault is used. Execute only with the reviewing user's permission.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_install as install
import memory_vault_update as update
from memory_vault import MemoryError, canonical_bytes


def synthetic_stage(directory: Path, version: str = "0.25.0", *, marker: str = "first", mcp: str = "mcp") -> tuple[Path, str]:
    directory.mkdir(mode=0o700)
    prefix = f"memory-vault-client-v{version}/"
    plugin = prefix + "plugins/memory-vault-client/"
    files = {
        plugin + ".codex-plugin/plugin.json": canonical_bytes({"name": "memory-vault-client", "version": version, "mcpServers": "./.mcp.json"}),
        plugin + ".mcp.json": canonical_bytes({"mcpServers": {"synthetic": {"command": "python3", "args": [mcp]}}}),
        plugin + "hooks/hooks.json": canonical_bytes({"hooks": {}}),
        plugin + "scripts/launcher.py": b"# Inert synthetic package; never executed.\n",
        prefix + ".agents/plugins/marketplace.json": canonical_bytes({"name": "synthetic-review-only"}),
    }
    modules = {}
    for name in sorted(update._REQUIRED_RUNTIME | update._V025_RUNTIME):
        data = ("# Inert review fixture: " + marker + "/" + name + "\n").encode("utf-8")
        files[plugin + "runtime/" + name] = data
        modules[name] = hashlib.sha256(data).hexdigest()
    files[plugin + "runtime/MANIFEST.json"] = canonical_bytes({"schema_version": "memory-vault-client-runtime/v1", "modules": modules})
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    package = stream.getvalue()
    digest = hashlib.sha256(package).hexdigest()
    source_commit = "a" * 40
    manifest = {
        "schema_version": "memory-vault-release/v1", "version": version,
        "source_commit": source_commit,
        "source_url": "https://github.com/qh-work/memory-vault-sync/tree/" + source_commit,
        "private_state_included": False,
        "assets": [{"name": f"memory-vault-client-v{version}.zip", "bytes": len(package), "sha256": digest}],
    }
    update.write_file(directory / "PACKAGE.zip", package)
    update.write_file(directory / "RELEASE.json", canonical_bytes(manifest))
    return directory, digest


@unittest.skipUnless(os.name == "posix", "Synthetic POSIX fixture; native NTFS cases are separate")
class ManagedInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="memory-install-review-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "managed"
        self.stage, self.digest = synthetic_stage(self.base / "stage")

    def initialize(self) -> dict:
        return dict(install.initialize(self.root, self.stage, request_id="req_install_review_0001", expected_sha256=self.digest))

    def activate_second(self) -> tuple[Path, str]:
        stage, digest = synthetic_stage(self.base / "second", "0.25.1", marker="second")
        install.activate(self.root, stage, request_id="req_install_review_0002", expected_sha256=digest)
        return stage, digest

    def test_manual_install_requires_independent_digest(self) -> None:
        with self.assertRaisesRegex(MemoryError, "manual_install_requires_explicit_archive_digest"):
            install.initialize(self.root, self.stage, request_id="req_install_review_0001")
        self.assertFalse((self.root / "active.json").exists())

    def test_new_install_does_not_execute_code_or_connect_host(self) -> None:
        with mock.patch.object(install.subprocess, "Popen", side_effect=AssertionError("no process permitted")):
            receipt = self.initialize()
        self.assertFalse(receipt["code_executed"])
        self.assertFalse(receipt["host_connected"])
        self.assertFalse(receipt["host_permissions_changed"])
        self.assertEqual(install.status(self.root)["generation"], 1)
        self.assertFalse(list(self.root.rglob("*.sqlite3")))

    def test_bootstrap_pins_exact_native_helper_bytes(self) -> None:
        self.initialize()
        digest = hashlib.sha256((self.root / "managed_storage.py").read_bytes()).hexdigest()
        launcher = (self.root / "launcher.py").read_text(encoding="utf-8")
        self.assertIn('TRUSTED_STORAGE_SHA256 = "' + digest + '"', launcher)
        self.assertNotIn("TRUSTED_STORAGE_SHA256 = None", launcher)

    def test_existing_installation_is_not_overwritten(self) -> None:
        self.initialize()
        before = (self.root / "active.json").read_bytes()
        with self.assertRaisesRegex(MemoryError, "managed_installation_exists"):
            self.initialize()
        self.assertEqual((self.root / "active.json").read_bytes(), before)

    def test_exact_receipt_replay_does_not_reauthenticate_or_activate(self) -> None:
        self.initialize()
        self.activate_second()
        with mock.patch.object(install, "_candidate", side_effect=AssertionError("historical replay must not activate")):
            receipt = install.activate(self.root, self.stage, request_id="req_install_review_0001", expected_sha256=self.digest)
        self.assertEqual(receipt["historical_generation"], 1)
        self.assertEqual(receipt["current_generation"], 2)
        self.assertFalse(receipt["activated_now"])

    def test_current_target_does_not_erase_previous_version(self) -> None:
        self.initialize()
        stage, digest = self.activate_second()
        before = (self.root / "active.json").read_bytes()
        receipt = install.activate(self.root, stage, request_id="req_install_identical_0003", expected_sha256=digest)
        self.assertEqual(receipt["state"], "runtime_already_active")
        self.assertEqual((self.root / "active.json").read_bytes(), before)

    def test_same_version_substitution_is_refused(self) -> None:
        self.initialize()
        stage, digest = synthetic_stage(self.base / "replacement", marker="different")
        with self.assertRaisesRegex(MemoryError, "same_version_runtime_substitution"):
            install.activate(self.root, stage, request_id="req_install_changed_0002", expected_sha256=digest)

    def test_integration_contract_changes_require_separate_approval(self) -> None:
        self.initialize()
        stage, digest = synthetic_stage(self.base / "host-change", "0.25.1", mcp="new-operator-interface")
        with self.assertRaisesRegex(MemoryError, "managed_host_contract_needs_review"):
            install.activate(self.root, stage, request_id="req_contract_change_0002", expected_sha256=digest)
        receipt = install.activate(self.root, stage, request_id="req_contract_approved_0003", expected_sha256=digest,
                                   approve_host_contract_change=True)
        self.assertEqual(receipt["generation"], 2)
        self.assertFalse(receipt["host_permissions_changed"])

    def test_bytecode_cache_is_not_authenticated_by_source_hashes(self) -> None:
        self.initialize()
        active = install._active(self.root)
        runtime = self.root / "releases" / self.digest / "memory-vault-client-v0.25.0/plugins/memory-vault-client/runtime"
        (runtime / "__pycache__").mkdir()
        with self.assertRaisesRegex(MemoryError, "unexpected_managed_runtime_file"):
            install.verify_installed(self.root, active["current"])

    def test_changed_installed_source_is_refused(self) -> None:
        self.initialize()
        active = install._active(self.root)
        source = self.root / "releases" / self.digest / "memory-vault-client-v0.25.0/plugins/memory-vault-client/runtime/memory_vault.py"
        source.write_bytes(b"# changed synthetic fixture\n")
        with self.assertRaisesRegex(MemoryError, "managed_runtime_changed"):
            install.verify_installed(self.root, active["current"])

    def test_explicit_rollback_keeps_versions_and_pauses_automation(self) -> None:
        self.initialize()
        _, second_digest = self.activate_second()
        with self.assertRaisesRegex(MemoryError, "explicit_rollback_approval_required"):
            install.rollback(self.root, request_id="req_rollback_review_0001", expected_generation=2, approved=False)
        result = install.rollback(self.root, request_id="req_rollback_review_0001", expected_generation=2, approved=True)
        self.assertTrue(result["automatic_updates_paused"])
        self.assertEqual(install.status(self.root)["version"], "0.25.0")
        self.assertTrue((self.root / "releases" / second_digest).is_dir())
        replay = install.rollback(self.root, request_id="req_rollback_review_0001", expected_generation=2, approved=True)
        self.assertFalse(replay["activated_now"])

    def test_automatic_mode_cannot_use_checksums_as_publisher_trust(self) -> None:
        self.initialize()
        with self.assertRaisesRegex(MemoryError, "automatic_update_requires_publisher_trust"):
            install.configure_automatic(self.root, enabled=True)

    def test_disabled_automatic_path_never_fetches_release(self) -> None:
        self.initialize()
        with mock.patch.object(install, "check", side_effect=AssertionError("no network permitted")):
            result = install.apply_latest(self.root, automatic_worker=True)
        self.assertFalse(result["network_accessed"])

    def test_crash_after_pointer_before_receipt_recovers_once(self) -> None:
        self.initialize()
        stage, digest = synthetic_stage(self.base / "interrupted", "0.25.1")
        original = install.atomic_json
        failed = False

        def interrupted(path: Path, value: dict) -> None:
            nonlocal failed
            if path.parent.name == "activations" and value.get("state") == "committed" and not failed:
                failed = True
                raise OSError("synthetic crash")
            original(path, value)

        with mock.patch.object(install, "atomic_json", side_effect=interrupted):
            with self.assertRaises(OSError):
                install.activate(self.root, stage, request_id="req_install_interrupted_0002", expected_sha256=digest)
        self.assertEqual(install.status(self.root)["generation"], 2)
        result = install.activate(self.root, stage, request_id="req_install_interrupted_0002", expected_sha256=digest)
        self.assertEqual(result["historical_generation"], 2)
        self.assertEqual(result["state"], "activation_receipt_recovered")
        self.assertEqual(install._active(self.root)["previous"]["archive_sha256"], self.digest)

    def test_audit_capacity_keeps_existing_receipts_readable(self) -> None:
        with mock.patch.object(install, "MAX_RECEIPTS", 1):
            self.initialize()
            replay = install.activate(self.root, self.stage, request_id="req_install_review_0001", expected_sha256=self.digest)
            self.assertFalse(replay["activated_now"])
            with self.assertRaisesRegex(MemoryError, "activation_audit_requires_archival"):
                install.activate(self.root, self.stage, request_id="req_install_new_0002", expected_sha256=self.digest)


if __name__ == "__main__":
    unittest.main()
