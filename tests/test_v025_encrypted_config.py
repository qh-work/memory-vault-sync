"""One opt-in actual-rclone configuration check, never a cloud-sync test.

Requires an explicitly selected rclone executable and its independently checked
SHA256. Only the OS credential lookup is replaced, with a synthetic password.
The real binary creates synthetic encrypted configs and runs ``config dump``;
no backend command, cloud account, private Vault, or actual keychain is used.
Fixture creation intentionally starts with disposable synthetic plaintext; the
production adapter must not create plaintext configurations when unlocking it.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_vault import MemoryError
import memory_vault_remote as remote
import memory_vault_storage as storage


@unittest.skipUnless(os.environ.get("MEMORY_VAULT_ENCRYPTED_CONFIG_SMOKE") == "1",
                     "explicit synthetic actual-rclone opt-in required")
class EncryptedConfigTests(unittest.TestCase):
    def test_actual_encrypted_config_unlock_revalidation_and_plaintext_compatibility(self) -> None:
        executable = Path(os.environ["MEMORY_VAULT_RCLONE_EXECUTABLE"])
        expected_hash = os.environ["MEMORY_VAULT_RCLONE_SHA256"]
        self.assertEqual(remote.executable_sha256(executable), expected_hash)
        password = "synthetic-config-only-v025-fixture-password"
        reference = {"kind": "macos-generic", "service": "synthetic-rclone-fixture", "account": "synthetic"}
        first = b"[fixture]\ntype = drive\nclient_id = synthetic-only\ntoken = synthetic-initial-token\n"
        changed = first.replace(b"synthetic-initial-token", b"synthetic-replaced-token")
        unsafe = first + b"token_command = /synthetic-helper-must-never-run\n"
        with tempfile.TemporaryDirectory(prefix="encrypted-config-fixture-") as temporary:
            root = Path(temporary).resolve()
            work = root / "work"
            for path in (work, work / "cache", work / "tmp"):
                path.mkdir(mode=0o700)

            def encrypt(name: str, contents: bytes) -> Path:
                path = root / name
                storage.atomic_write(path, contents, replace=False)
                # rclone v1.75.0 ChangeConfigPasswordAndSave calls
                # ChangePassword, which reads the new password twice. There is
                # no menu selection and RCLONE_CONFIG_PASS is not a new-password
                # setter. Send only the two synthetic lines through stdin.
                result = subprocess.run([str(executable), "config", "encryption", "set",
                    "--config", str(path), "--ask-password=false", "--password-command=",
                    "--cache-dir", str(work / "cache"), "--temp-dir", str(work / "tmp"),
                    "--log-level", "ERROR"], input=((password + "\n") * 2).encode(),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
                # Never attach subprocess output/configuration to an assertion.
                self.assertEqual(result.returncode, 0, "synthetic config encryption failed")
                encrypted = path.read_bytes()
                self.assertIn(b"RCLONE_ENCRYPT_V0:", encrypted)
                self.assertNotIn(b"synthetic-initial-token", encrypted)
                self.assertNotIn(b"synthetic-replaced-token", encrypted)
                self.assertNotIn(password.encode(), encrypted)
                return path

            selected = encrypt("selected.conf", first)
            replacement = encrypt("replacement.conf", changed)
            dangerous = encrypt("dangerous.conf", unsafe)
            original_ciphertext = selected.read_bytes()
            replacement_ciphertext = replacement.read_bytes()
            dangerous_ciphertext = dangerous.read_bytes()
            baseline_files = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}

            def backend(path: Path, *, with_reference: bool = True) -> remote.RcloneBackend:
                specification = {"kind": "rclone", "executable": str(executable),
                    "executable_sha256": expected_hash, "config_file": str(path),
                    "remote": "fixture:synthetic-memory-prefix", "peers": []}
                if with_reference:
                    specification["config_password_ref"] = reference
                budget = remote.Budget(seconds=30, maximum_bytes=8 * 1024 * 1024, maximum_files=2)
                return remote.RcloneBackend(specification, work_directory=work, budget=budget,
                                            active_check=lambda: budget.remaining())

            with mock.patch.object(remote, "config_password", return_value=password) as lookup:
                instance = backend(selected)
                self.assertEqual(lookup.call_count, 1)
                self.assertEqual(instance.budget.commands, 1)  # actual decrypted config dump
                instance._ensure_config()
                self.assertEqual(instance.budget.commands, 1)  # unchanged config uses cache
                decoded = json.loads(instance._run(["config", "dump"], output_limit=remote.MAX_CONFIG_DUMP_BYTES))
                self.assertEqual(decoded["fixture"]["token"], "synthetic-initial-token")
                self.assertEqual(selected.read_bytes(), original_ciphertext)
                self.assertEqual({str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()},
                                 baseline_files)

                # Simulate a legitimate encrypted configuration replacement,
                # not an actual OAuth refresh or provider request.
                previous_commands = instance.budget.commands
                storage.atomic_write(selected, replacement_ciphertext, replace=True)
                instance._ensure_config()
                self.assertEqual(instance.budget.commands, previous_commands + 1)
                self.assertEqual(lookup.call_count, 1)
                decoded = json.loads(instance._run(["config", "dump"], output_limit=remote.MAX_CONFIG_DUMP_BYTES))
                self.assertEqual(decoded["fixture"]["token"], "synthetic-replaced-token")
                self.assertEqual(selected.read_bytes(), replacement_ciphertext)

                # Changing an already validated encrypted config to a helper
                # is rejected after actual decryption, before any backend use.
                storage.atomic_write(selected, dangerous_ciphertext, replace=True)
                previous_commands = instance.budget.commands
                with self.assertRaisesRegex(MemoryError, "^remote_commands_forbidden$"):
                    instance._ensure_config()
                self.assertEqual(instance.budget.commands, previous_commands + 1)
                with self.assertRaisesRegex(MemoryError, "^remote_commands_forbidden$"):
                    backend(dangerous)
                self.assertEqual(dangerous.read_bytes(), dangerous_ciphertext)

            with mock.patch.object(remote, "config_password", return_value="synthetic-wrong-password") as lookup:
                with self.assertRaisesRegex(MemoryError, "^rclone_config_unlock_failed$"):
                    backend(replacement)
                self.assertEqual(lookup.call_count, 1)
                self.assertEqual(replacement.read_bytes(), replacement_ciphertext)

            plaintext = root / "legacy-plaintext.conf"
            storage.atomic_write(plaintext, first, replace=False)
            with mock.patch.object(remote, "config_password", side_effect=AssertionError("unexpected OS lookup")) as lookup:
                legacy = backend(plaintext, with_reference=False)
                self.assertEqual(legacy.budget.commands, 0)
                with self.assertRaisesRegex(MemoryError, "^rclone_config_encryption_required$"):
                    backend(plaintext)
                with self.assertRaisesRegex(MemoryError, "^rclone_config_password_reference_required$"):
                    backend(replacement, with_reference=False)
                lookup.assert_not_called()
                self.assertEqual(plaintext.read_bytes(), first)
            self.assertFalse((root / "synthetic-helper-must-never-run").exists())


def _run_one() -> int:
    """Explicit standalone evidence runner; no unittest discovery."""
    evidence = Path(os.environ["MEMORY_VAULT_ENCRYPTED_CONFIG_EVIDENCE"]).resolve(strict=True)
    source = Path(__file__).resolve().parents[1]
    executable = Path(os.environ["MEMORY_VAULT_RCLONE_EXECUTABLE"]).resolve(strict=True)
    tempfile.tempdir = str(evidence)
    paths = [source / name for name in ("memory_vault_credentials.py", "memory_vault_remote.py", "memory_vault_sync.py")]
    paths.append(Path(__file__).resolve())

    def hashes() -> dict[str, str]:
        return {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}

    before = hashes()
    (evidence / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
    violations: list[str] = []
    commands: list[list[str]] = []

    def inside(path: str | bytes) -> bool:
        return Path(os.fsdecode(path)).resolve().is_relative_to(evidence)

    def guard(event: str, args: tuple) -> None:
        prohibited = event.startswith("socket.") or event in {"os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty"}
        if event == "subprocess.Popen":
            arguments = args[1]
            allowed = (args[0] == str(executable) and isinstance(arguments, list)
                       and (arguments[1:4] == ["config", "encryption", "set"] or arguments[1:3] == ["config", "dump"]))
            if allowed:
                index = arguments.index("--config") if "--config" in arguments else -1
                allowed = index >= 0 and inside(arguments[index + 1]) and "--password-command=" in arguments
            prohibited = not allowed
            if allowed:
                commands.append(arguments[1:4] if arguments[1:4] == ["config", "encryption", "set"] else arguments[1:3])
        if event == "open" and not isinstance(args[0], int):
            mode, flags = args[1], args[2]
            writing = ((isinstance(mode, str) and any(character in mode for character in "wax+"))
                       or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)))
            # subprocess.DEVNULL opens the OS null device O_RDWR; it is not a
            # filesystem artifact or private user-data destination.
            prohibited |= bool(writing and os.fsdecode(args[0]) != os.devnull and not inside(args[0]))
        if event == "sqlite3.connect":
            prohibited = True  # no Vault/database is needed
        if prohibited:
            violations.append(event)
            raise PermissionError("encrypted-config fixture boundary: " + event)

    sys.addaudithook(guard)
    method = "test_actual_encrypted_config_unlock_revalidation_and_plaintext_compatibility"
    suite = unittest.TestSuite([EncryptedConfigTests(method)])
    output = io.StringIO()
    started = time.monotonic()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    after = hashes()
    report = {"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "seconds": round(time.monotonic() - started, 6),
              "source_files_sha256": before, "source_unchanged": before == after,
              "rclone_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
              "commands": commands, "boundary_violations": violations,
              "credential_getter_mocked": True, "cloud_sync_tested": False,
              "real_oauth_refresh_tested": False, "real_keychain_tested": False, "full_suite_run": False}
    (evidence / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (evidence / "output.log").write_text(output.getvalue())
    print(output.getvalue())
    print(json.dumps({key: value for key, value in report.items() if key != "source_files_sha256"}, sort_keys=True))
    return 0 if result.wasSuccessful() and result.testsRun == 1 and not result.skipped and before == after and not violations else 1


if __name__ == "__main__":
    raise SystemExit(_run_one())
