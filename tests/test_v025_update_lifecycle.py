"""One bounded, synthetic controlled-update lifecycle; execution tracked separately.

Only inert package bytes and the existing fixed, public test-RSA integers are
used. The downloader returns explicit fixture bytes; signature verification,
staging, file publication, activation and rollback use production functions.
No packaged code, host installation, subprocess, provider, account, real key or
Vault is opened. A caught partial-write exception is NOT a process/power crash.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, Path(__file__).resolve().parent):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import memory_vault_install as install
import memory_vault_update as update
import memory_vault_update_trust as signed
from memory_vault import MemoryError, canonical_bytes
import test_v025_install as package_fixtures
import test_v025_update_trust as trust_fixtures


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"),
                     "requires an authorized macOS/Linux temporary-directory fixture")
class ControlledUpdateLifecycleTests(unittest.TestCase):
    def test_pinned_signed_stage_install_partial_write_retry_and_explicit_rollback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-v025-controlled-update-synthetic-") as temporary:
            base = Path(temporary).resolve()
            managed = base / "managed"
            trust_path = base / "publisher-trust.json"
            root_file = base / "reviewed-root.json"
            root = trust_fixtures._root()
            root_bytes = signed.metadata_bytes(root)
            update.write_file(root_file, root_bytes)
            transport_bytes = {}
            absent_roots = set()
            package_digests = {}
            package_sources = {}

            for version, sequence, invalid_signer in (("0.25.0", 1, False), ("0.25.1", 2, False),
                                                       ("0.25.2", 3, True)):
                publication, digest = package_fixtures.synthetic_stage(base / ("publication-" + version),
                                                                       version, marker=version)
                package_digests[version] = digest
                package_sources[version] = publication
                metadata = publication / "metadata"
                trust_fixtures._write_chain(metadata, root, candidate={
                    "version": version, "bundle_sha256": digest,
                    "bundle_length": (publication / "PACKAGE.zip").stat().st_size,
                    "commit_sha": "a" * 40,
                }, versions={role: sequence for role in ("timestamp", "snapshot", "targets")},
                    signature_overrides={"targets": (4,)} if invalid_signer else None)
                release_base = update.DOWNLOAD + "v" + version + "/"
                transport_bytes[update.API + "tags/v" + version] = canonical_bytes({
                    "tag_name": "v" + version, "draft": False, "prerelease": False,
                })
                transport_bytes[release_base + "release-manifest.json"] = (publication / "RELEASE.json").read_bytes()
                transport_bytes[release_base + "memory-vault-client-v" + version + ".zip"] = (publication / "PACKAGE.zip").read_bytes()
                for name in ("timestamp.json", "snapshot.json", "targets.json"):
                    transport_bytes[release_base + name] = (metadata / name).read_bytes()
                absent_roots.add(release_base + "2.root.json")

            requests = []

            def fixture_download(url, maximum, *, deadline=None):
                # Only transport is substituted. No verifier, trust object,
                # inventory checker or activation/rollback function is mocked.
                self.assertIsNotNone(deadline)
                requests.append(url)
                if url in absent_roots:
                    raise update._DownloadNotFound()
                self.assertIn(url, transport_bytes)
                payload = transport_bytes[url]
                self.assertLessEqual(len(payload), maximum)
                return payload

            with mock.patch.object(update, "_download", side_effect=fixture_download), \
                    mock.patch.object(update.time, "time", return_value=trust_fixtures.NOW), \
                    mock.patch.object(install.subprocess, "Popen", side_effect=AssertionError("no subprocess permitted")):
                with self.assertRaisesRegex(MemoryError, "update_initial_root_digest_mismatch"):
                    update.configure_trust(root_file, trust_path, "0" * 64)
                self.assertFalse(trust_path.exists())
                self.assertFalse(managed.exists())
                pinned = update.configure_trust(root_file, trust_path, hashlib.sha256(root_bytes).hexdigest())
                self.assertFalse(pinned["private_keys_imported"])
                self.assertFalse(pinned["network_accessed"])

                first = base / "staged-first"
                staged = update.stage(first, version="0.25.0", trust_store_path=trust_path)
                self.assertTrue(staged["publisher_signature_verified"])
                self.assertFalse(staged["activated"])
                self.assertFalse(staged["code_executed"])
                self.assertFalse(managed.exists())
                initial = install.initialize(managed, first, request_id="req_signed_lifecycle_first_0001",
                                             trust_store_path=trust_path)
                self.assertTrue(initial["publisher_signature_verified"])
                self.assertFalse(initial["host_connected"])
                self.assertFalse(initial["code_executed"])
                self.assertFalse(initial["host_permissions_changed"])
                self.assertEqual(install.status(managed)["generation"], 1)
                first_pointer = (managed / "active.json").read_bytes()

                trusted_before_bad_stage = trust_path.read_bytes()
                bad_stage = base / "bad-signature-stage"
                with self.assertRaises(signed.SignedUpdateError):
                    update.stage(bad_stage, version="0.25.2", trust_store_path=trust_path)
                self.assertFalse((bad_stage / "STAGED.json").exists())
                self.assertEqual(trust_path.read_bytes(), trusted_before_bad_stage)
                self.assertEqual((managed / "active.json").read_bytes(), first_pointer)

                second = base / "staged-second"
                update.stage(second, version="0.25.1", trust_store_path=trust_path)
                second_request = "req_signed_lifecycle_second_0002"
                with self.assertRaisesRegex(MemoryError, "managed_expected_digest_mismatch"):
                    install.activate(managed, second, request_id=second_request, expected_sha256="0" * 64)
                self.assertEqual((managed / "active.json").read_bytes(), first_pointer)

                member = "memory-vault-client-v0.25.1/plugins/memory-vault-client/runtime/memory_vault.py"
                with zipfile.ZipFile(package_sources["0.25.1"] / "PACKAGE.zip") as archive:
                    interrupted_bytes = archive.read(member)
                destination = managed / "releases" / package_digests["0.25.1"] / member
                original_fdopen = os.fdopen
                injected = False

                class FailOneWrite:
                    def __init__(self, stream):
                        self.stream = stream

                    def __enter__(self):
                        self.stream.__enter__()
                        return self

                    def __exit__(self, *exception):
                        return self.stream.__exit__(*exception)

                    def __getattr__(self, name):
                        return getattr(self.stream, name)

                    def write(self, payload):
                        nonlocal injected
                        if payload == interrupted_bytes and not injected:
                            injected = True
                            self.stream.write(payload[:7])
                            self.stream.flush()
                            raise OSError(errno.EIO, "synthetic partial member write")
                        return self.stream.write(payload)

                def intercept_fdopen(descriptor, *args, **kwargs):
                    stream = original_fdopen(descriptor, *args, **kwargs)
                    mode = args[0] if args else kwargs.get("mode", "r")
                    return FailOneWrite(stream) if mode == "wb" else stream

                with mock.patch.object(os, "fdopen", side_effect=intercept_fdopen):
                    with self.assertRaisesRegex(OSError, "synthetic partial member write"):
                        install.activate(managed, second, request_id=second_request)
                self.assertTrue(injected)
                self.assertFalse(destination.exists(), "a handled partial write poisoned the immutable member")
                self.assertEqual(list(destination.parent.glob(".memory-*.tmp")), [])
                self.assertFalse((managed / "activations" / (install._hash(second_request) + ".json")).exists())
                self.assertEqual((managed / "active.json").read_bytes(), first_pointer)

                activated = install.activate(managed, second, request_id=second_request)
                self.assertEqual(activated["generation"], 2)
                self.assertTrue(activated["publisher_signature_verified"])
                self.assertEqual(destination.read_bytes(), interrupted_bytes)
                install.verify_installed(managed, install._active(managed)["current"])
                self.assertEqual(json.loads(trust_path.read_bytes())["last_target"]["plugin_version"], "0.25.1")
                trust_floor_before_rollback = trust_path.read_bytes()
                pointer_before_rollback = (managed / "active.json").read_bytes()
                install.configure_automatic(managed, enabled=True)
                with self.assertRaisesRegex(MemoryError, "explicit_rollback_approval_required"):
                    install.rollback(managed, request_id="req_signed_lifecycle_rollback_0003", expected_generation=2,
                                     approved=False)
                self.assertEqual((managed / "active.json").read_bytes(), pointer_before_rollback)
                rolled_back = install.rollback(managed, request_id="req_signed_lifecycle_rollback_0003",
                                               expected_generation=2, approved=True)
                self.assertTrue(rolled_back["automatic_updates_paused"])
                self.assertEqual(install.status(managed)["version"], "0.25.0")
                self.assertEqual(install.status(managed)["generation"], 3)
                self.assertFalse(install.status(managed)["automatic"])
                self.assertEqual(trust_path.read_bytes(), trust_floor_before_rollback)
                for digest in package_digests.values():
                    if digest != package_digests["0.25.2"]:
                        self.assertTrue((managed / "releases" / digest).is_dir())

                # Deliberately selecting retained code did not lower publisher
                # floors or turn its past receipt into new authorization.
                with self.assertRaises(signed.SignedUpdateError):
                    install.activate(managed, first, request_id="req_signed_lifecycle_old_again_0004")
                historical = install.activate(managed, first, request_id="req_signed_lifecycle_first_0001")
                self.assertFalse(historical["activated_now"])
                self.assertFalse(historical["historical_receipt_is_current_publisher_trust"])
                self.assertEqual(historical["current_generation"], 3)
                self.assertEqual(trust_path.read_bytes(), trust_floor_before_rollback)
                self.assertFalse(list(base.rglob("*.sqlite3")))
                self.assertTrue(requests)


if __name__ == "__main__":
    unittest.main()
