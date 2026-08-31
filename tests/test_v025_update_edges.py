"""Independent update-control regression cases, authored but NOT executed.

Reuse only the public inert-package and fixed test-RSA fixtures. All control
files belong to a temporary directory; no real key, Vault, host or provider is
read. Launcher handoff is stubbed, so no packaged source or subprocess runs.
Execute this module only when the reviewing user permits tests.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
# Support both ``unittest discover -s tests`` and package-oriented collectors.
# Import fixture modules, not their TestCase classes, to avoid duplicate suites.
for path in (ROOT, Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import memory_vault_install as install
import memory_vault_update as update
import memory_vault_update_trust as signed
from memory_vault import MemoryError, canonical_bytes
import test_v025_install as package_fixtures
import test_v025_update_trust as trust_fixtures


def _source_module(source: Path, name: str, *, selected_file: Path | None = None) -> types.ModuleType:
    """Test-only source loader: define functions without calling a CLI main."""
    module = types.ModuleType(name)
    module.__file__ = str(selected_file or source)
    exec(compile(source.read_bytes(), str(source), "exec"), module.__dict__)
    return module


@unittest.skipUnless(os.name == "posix", "Synthetic POSIX fixtures; native NTFS validation is separate")
class UpdateControlEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-vault-update-edges-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def signed_stage(self, directory: Path, root: dict, *, version: str, sequence: int) -> tuple[Path, str]:
        stage, digest = package_fixtures.synthetic_stage(directory, version, marker=version)
        metadata = stage / "update-metadata"
        trust_fixtures._write_chain(metadata, root, candidate={
            "version": version, "bundle_sha256": digest,
            "bundle_length": (stage / "PACKAGE.zip").stat().st_size,
            "commit_sha": "a" * 40,
        }, versions={role: sequence for role in ("timestamp", "snapshot", "targets")})
        metadata.chmod(0o700)
        for path in metadata.iterdir():
            path.chmod(0o600)
        return stage, digest

    def test_expired_metadata_only_blocks_a_prepared_activation_that_has_not_happened(self) -> None:
        # The exact same signed metadata expires in both branches. The only
        # difference is whether active.json durably advanced before the crash.
        for pointer_committed in (False, True):
            with self.subTest(pointer_committed=pointer_committed):
                base = self.root / ("after-pointer" if pointer_committed else "before-pointer")
                base.mkdir(mode=0o700)
                envelope = trust_fixtures._root()
                raw = signed.metadata_bytes(envelope)
                root_file = base / "reviewed-root.json"
                update.write_file(root_file, raw)
                trust_path = base / "publisher-trust.json"
                managed = base / "managed"
                first, _ = self.signed_stage(base / "first", envelope, version="0.25.0", sequence=1)
                second, _ = self.signed_stage(base / "second", envelope, version="0.25.1", sequence=2)
                request_id = "req_expired_activation_0002"
                receipt_path = managed / "activations" / (install._hash(request_id) + ".json")
                original = install.atomic_json
                interrupted = False

                def interrupt_selected_write(path: Path, value: dict) -> None:
                    nonlocal interrupted
                    selected = (path == receipt_path and value.get("state") == "committed") if pointer_committed else path == managed / "active.json"
                    if selected and not interrupted:
                        interrupted = True
                        raise OSError("synthetic activation interruption")
                    original(path, value)

                with mock.patch.object(install.time, "time", return_value=trust_fixtures.NOW):
                    update.configure_trust(root_file, trust_path, hashlib.sha256(raw).hexdigest())
                    install.initialize(managed, first, request_id="req_expired_activation_0001", trust_store_path=trust_path)
                    with mock.patch.object(install, "atomic_json", side_effect=interrupt_selected_write):
                        with self.assertRaisesRegex(OSError, "synthetic activation interruption"):
                            install.activate(managed, second, request_id=request_id)
                self.assertTrue(interrupted)
                self.assertEqual(json.loads(receipt_path.read_bytes())["state"], "prepared")
                pointer_before = (managed / "active.json").read_bytes()
                trust_before = trust_path.read_bytes()
                generation = 2 if pointer_committed else 1
                self.assertEqual(json.loads(pointer_before)["generation"], generation)

                with mock.patch.object(install.time, "time", return_value=trust_fixtures.NOW + 2 * 86400):
                    if not pointer_committed:
                        with self.assertRaisesRegex(signed.SignedUpdateError, "timestamp metadata is expired"):
                            install.activate(managed, second, request_id=request_id)
                        self.assertEqual(json.loads(receipt_path.read_bytes())["state"], "prepared")
                    else:
                        def only_finalize_receipt(path: Path, value: dict) -> None:
                            self.assertEqual(path, receipt_path)
                            self.assertEqual(value["state"], "committed")
                            original(path, value)

                        with mock.patch.object(install, "_candidate", side_effect=AssertionError("historical completion must not authenticate a new activation")):
                            with mock.patch.object(install, "atomic_json", side_effect=only_finalize_receipt) as writes:
                                result = install.activate(managed, second, request_id=request_id)
                                self.assertEqual(writes.call_count, 1)
                            self.assertEqual(result["state"], "activation_receipt_recovered")
                            self.assertFalse(result["activated_now"])
                            self.assertFalse(result["historical_receipt_is_current_publisher_trust"])
                            self.assertEqual(result["historical_generation"], 2)
                            replay = install.activate(managed, second, request_id=request_id)
                            self.assertEqual(replay["state"], "activation_receipt_replayed")
                            self.assertFalse(replay["activated_now"])
                self.assertEqual((managed / "active.json").read_bytes(), pointer_before)
                self.assertEqual(trust_path.read_bytes(), trust_before)

    def test_v025_package_cannot_omit_the_converter_dependency_from_a_consistent_inventory(self) -> None:
        stage, _ = package_fixtures.synthetic_stage(self.root / "stage")
        with zipfile.ZipFile(stage / "PACKAGE.zip") as archive:
            files = {item.filename: archive.read(item) for item in archive.infolist()}
        prefix = "memory-vault-client-v0.25.0/plugins/memory-vault-client/runtime/"
        removed = "memory_vault_migrate.py"
        self.assertIn(prefix + removed, files)
        files.pop(prefix + removed)
        inventory = json.loads(files[prefix + "MANIFEST.json"])
        inventory["modules"].pop(removed)
        files[prefix + "MANIFEST.json"] = canonical_bytes(inventory)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(files.items()):
                archive.writestr(name, data)
        # This is not a stale checksum or extra-file failure: the ZIP and its
        # module inventory agree, but one mandatory dependency is absent.
        with self.assertRaisesRegex(MemoryError, "update_incomplete_v025_runtime"):
            update._archive_inventory(output.getvalue(), "0.25.0")
        normal = _source_module(ROOT / "plugins/memory-vault-client/scripts/launcher.py", "edge_normal_inventory")
        builder = _source_module(ROOT / "scripts/build_client_plugin.py", "edge_builder_inventory")
        self.assertIn(removed, normal.REQUIRED_MODULES)
        self.assertIn(removed, builder.REQUIRED_MODULES)
        self.assertNotIn(removed, builder.OPTIONAL_MODULES)

    def test_normal_and_managed_handoff_cannot_use_an_external_bytecode_prefix(self) -> None:
        stage, digest = package_fixtures.synthetic_stage(self.root / "stage")
        managed = self.root / "managed"
        install.initialize(managed, stage, request_id="req_cache_boundary_0001", expected_sha256=digest)
        package = managed / "releases" / digest / "memory-vault-client-v0.25.0/plugins/memory-vault-client"
        external_cache = self.root / "unchecked-external-cache"
        external_cache.mkdir(mode=0o700)
        sources = (
            (ROOT / "plugins/memory-vault-client/scripts/launcher.py", package / "scripts/launcher.py", False),
            (ROOT / "memory_vault_managed_launcher.py", managed / "launcher.py", True),
        )
        for source, selected_file, is_managed in sources:
            with self.subTest(managed=is_managed):
                with mock.patch.object(sys, "pycache_prefix", str(external_cache)), mock.patch.object(sys, "dont_write_bytecode", False):
                    with mock.patch.object(sys, "path", list(sys.path)), mock.patch.object(sys, "argv", [str(selected_file), "mcp"]):
                        with mock.patch.dict(os.environ, {}, clear=False):
                            module = _source_module(source, "edge_cache_launcher", selected_file=selected_file)
                            if is_managed:
                                # Bootstrap clears the prefix before it loads
                                # its native helper or the selected runtime.
                                self.assertIsNone(sys.pycache_prefix)
                                self.assertTrue(sys.dont_write_bytecode)

                            def inspect_handoff(path: str, *, run_name: str) -> dict:
                                self.assertIsNone(sys.pycache_prefix)
                                self.assertTrue(sys.dont_write_bytecode)
                                self.assertEqual(Path(path), package / "runtime/memory_vault_client.py")
                                self.assertEqual(run_name, "__main__")
                                return {}  # Never execute the packaged fixture.

                            with mock.patch.object(module.runpy, "run_path", side_effect=inspect_handoff) as handoff:
                                self.assertEqual(module.main(), 0)
                                handoff.assert_called_once()
        # This checks the application handoff, not Python's earlier startup or
        # site imports; those still require the documented isolated invocation.

    def test_rewrapped_one_physical_rsa_key_cannot_fill_a_quorum_or_another_role(self) -> None:
        source = trust_fixtures.TEST_KEYS[0]
        alias = copy.deepcopy(source["value"])
        body = "".join(alias["keyval"]["public"].splitlines()[1:-1])
        alias["keyval"]["public"] = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(
            body[offset:offset + 32] for offset in range(0, len(body), 32)
        ) + "\n-----END PUBLIC KEY-----\n"
        alias_id = signed.key_id(alias)
        self.assertNotEqual(alias_id, source["keyid"])
        self.assertEqual(signed._parse_rsa_public_key(alias["keyval"]["public"]),
                         signed._parse_rsa_public_key(source["value"]["keyval"]["public"]))
        for duplicate_use in ("root_threshold", "timestamp_role"):
            with self.subTest(duplicate_use=duplicate_use):
                root = copy.deepcopy(trust_fixtures._root()["signed"])
                root["keys"][alias_id] = alias
                if duplicate_use == "root_threshold":
                    root["roles"]["root"] = {"keyids": [source["keyid"], alias_id], "threshold": 2}
                else:
                    root["roles"]["timestamp"] = {"keyids": [alias_id], "threshold": 1}
                signature = trust_fixtures._sign(0, signed.jcs_json_bytes(root))
                signatures = [{"keyid": source["keyid"], "sig": signature}]
                if duplicate_use == "root_threshold":
                    signatures.append({"keyid": alias_id, "sig": signature})
                raw = signed.metadata_bytes({"signed": root, "signatures": signatures})
                with self.assertRaisesRegex(signed.SignedUpdateError, "physical RSA key"):
                    signed.import_trusted_root(raw, now_epoch=trust_fixtures.NOW)


if __name__ == "__main__":
    unittest.main()
