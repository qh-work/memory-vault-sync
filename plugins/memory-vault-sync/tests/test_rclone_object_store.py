from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    PLUGIN_ROOT / "scripts" / "memory_vault_runtime" / "core.py"
)
SPEC = importlib.util.spec_from_file_location("memory_vault_sync_rclone", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
vault_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = vault_sync
SPEC.loader.exec_module(vault_sync)


def rclone_config() -> dict:
    config = vault_sync.default_config()
    profile = vault_sync._provider_profile(config)
    drive = profile["object_stores"][0]
    drive["role"] = "archive"
    drive["access"] = "read_only"
    profile["object_stores"].append(
        {
            "store_id": "rclone-crypt-primary",
            "driver": "rclone-crypt",
            "adapter_config_ref": "adapter-config:rclone-crypt-primary",
            "credential_ref": "credential:rclone-crypt-primary",
            "scope_fingerprint": "0" * 64,
            "role": "primary",
            "access": "read_write",
        }
    )
    config["adapter_configs"]["adapter-config:rclone-crypt-primary"] = {
        "executable": "/opt/rclone/rclone",
        "executable_sha256": "1" * 64,
        "config_path": "/private/rclone.conf",
        "remote_name": "vault_crypt",
        "remote_fingerprint": "2" * 64,
        "minimum_version": "1.70.0",
        "verified_version": "1.74.4",
    }
    config["credential_bindings"]["credential:rclone-crypt-primary"] = {
        "helper_host": "rclone-config.memory-vault-sync.local"
    }
    vault_sync._refresh_provider_scope_fingerprints(config)
    return config


class RcloneConfigTests(unittest.TestCase):
    def test_chunking_is_backward_compatible_opt_in_with_strict_bounds(
        self,
    ) -> None:
        legacy = vault_sync.default_config()
        legacy["sync"].pop("chunked_artifacts_enabled")
        legacy["sync"].pop("chunked_artifact_min_bytes")
        validated = vault_sync.validate_config(legacy)
        self.assertFalse(validated["sync"]["chunked_artifacts_enabled"])
        self.assertEqual(
            validated["sync"]["chunked_artifact_min_bytes"],
            vault_sync.DEFAULT_CHUNK_MINIMUM_BYTES,
        )
        for value in (
            True,
            vault_sync.CHUNK_SIZE_BYTES - 1,
            vault_sync.CHUNK_SIZE_BYTES * vault_sync.MAX_CHUNK_COUNT + 1,
        ):
            with self.subTest(value=value):
                invalid = vault_sync.default_config()
                invalid["sync"]["chunked_artifact_min_bytes"] = value
                with self.assertRaises(vault_sync.ConfigurationError):
                    vault_sync.validate_config(invalid)
        wrong_backend = vault_sync.default_config()
        wrong_backend["sync"]["chunked_artifacts_enabled"] = True
        with self.assertRaises(vault_sync.ConfigurationError):
            vault_sync.validate_config(wrong_backend)

    def test_rclone_crypt_primary_is_pinned_without_local_paths(self) -> None:
        config = vault_sync.validate_config(rclone_config())
        pins = vault_sync._provider_transaction_pins(config)

        self.assertEqual(pins["object_store"]["driver"], "rclone-crypt")
        self.assertEqual(
            pins["object_store"]["store_id"], "rclone-crypt-primary"
        )
        serialized = vault_sync.canonical_json_bytes(pins).decode("utf-8")
        self.assertNotIn("/opt/rclone", serialized)
        self.assertNotIn("/private/rclone.conf", serialized)
        self.assertNotIn("vault_crypt", serialized)

    def test_rclone_config_rejects_missing_or_unpinned_boundary(self) -> None:
        for key in (
            "executable_sha256",
            "remote_fingerprint",
            "verified_version",
        ):
            with self.subTest(key=key):
                config = rclone_config()
                del config["adapter_configs"][
                    "adapter-config:rclone-crypt-primary"
                ][key]
                vault_sync._refresh_provider_scope_fingerprints(config)
                with self.assertRaises(vault_sync.ConfigurationError):
                    vault_sync.validate_config(config)

    def test_engine_routes_current_and_historical_storage_references(self) -> None:
        config = vault_sync.validate_config(rclone_config())
        with tempfile.TemporaryDirectory() as temporary:
            engine = vault_sync.SyncEngine(config, Path(temporary))
            current = mock.Mock(
                store_id=vault_sync.RCLONE_OBJECT_STORE_ID,
                driver=vault_sync.RCLONE_OBJECT_STORE_DRIVER,
            )
            historical = mock.Mock(
                store_id=vault_sync.DEFAULT_OBJECT_STORE_ID,
                driver="google-drive-v3",
            )
            engine.drive = current
            engine.object_stores[vault_sync.DEFAULT_OBJECT_STORE_ID] = historical
            digest = "a" * 64
            current_artifact = {
                "sha256": digest,
                "size": 1,
                "mime_type": "application/octet-stream",
                "storage_ref": {
                    "schema_version": vault_sync.ARTIFACT_STORAGE_REF_SCHEMA,
                    "store_id": vault_sync.RCLONE_OBJECT_STORE_ID,
                    "driver": vault_sync.RCLONE_OBJECT_STORE_DRIVER,
                    "object_id": f"sha256-{digest}",
                    "container_id": "rclone-" + "2" * 32,
                    "verification_level": "rclone-crypt-download-sha256",
                },
            }
            historical_artifact = {
                "sha256": digest,
                "size": 1,
                "mime_type": "application/octet-stream",
                "storage_ref": {
                    "schema_version": vault_sync.ARTIFACT_STORAGE_REF_SCHEMA,
                    "store_id": vault_sync.DEFAULT_OBJECT_STORE_ID,
                    "driver": "google-drive-v3",
                    "object_id": "drive-object-a",
                    "container_id": "drive-parent-a",
                    "verification_level": "drive-download-sha256",
                },
            }
            legacy_artifact = {
                "sha256": digest,
                "size": 1,
                "mime_type": "application/octet-stream",
                "drive_file_id": "legacy-drive-object",
                "drive_parent_id": "legacy-drive-parent",
            }

            self.assertIs(engine._artifact_store(current_artifact), current)
            self.assertIs(
                engine._artifact_store(historical_artifact),
                historical,
            )
            self.assertIs(engine._artifact_store(legacy_artifact), historical)


class RcloneConfigurationCommandTests(unittest.TestCase):
    def _arguments(self, executable: Path, config_path: Path) -> argparse.Namespace:
        return argparse.Namespace(
            rclone_executable=str(executable),
            rclone_config=str(config_path),
            rclone_remote="vault_crypt",
            config_password_stdin=False,
            no_initialize_root=False,
        )

    def _probe(self, executable_sha256: str) -> dict[str, str]:
        return {
            "executable_sha256": executable_sha256,
            "verified_version": "1.74.4",
            "minimum_version": vault_sync.RCLONE_MINIMUM_VERSION,
            "remote_fingerprint": "2" * 64,
            "backend_type": "s3",
        }

    def test_configure_archives_drive_and_keeps_password_out_of_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            executable = data_dir / "rclone"
            executable.write_bytes(b"pinned-rclone")
            config_path = data_dir / "rclone.conf"
            config_path.write_bytes(b"encrypted-config")
            if os.name != "nt":
                executable.chmod(0o700)
                config_path.chmod(0o600)
            executable_sha256 = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
            with (
                mock.patch.object(
                    vault_sync,
                    "_read_rclone_config_password",
                    return_value="temporary-test-password",
                ),
                mock.patch.object(
                    vault_sync,
                    "_probe_rclone_boundary",
                    return_value=self._probe(executable_sha256),
                ),
                mock.patch.object(vault_sync, "credential_store") as store,
                mock.patch.object(
                    vault_sync.RcloneCryptAdapter,
                    "initialize_private_root",
                    return_value={
                        "marker_created": True,
                        "encrypted_root_verified": True,
                    },
                ),
                mock.patch.object(
                    vault_sync,
                    "_refresh_stable_runtime",
                    return_value={
                        "plugin_version": vault_sync.VERSION,
                        "updated": False,
                    },
                ),
            ):
                result = vault_sync.configure_rclone_store_command(
                    self._arguments(executable, config_path),
                    data_dir,
                )

            configured = vault_sync.validate_config(
                vault_sync.load_json(data_dir / "config.json")
            )
            profile = vault_sync._provider_profile(configured)
            stores = {
                item["store_id"]: item for item in profile["object_stores"]
            }
            self.assertEqual(
                stores[vault_sync.DEFAULT_OBJECT_STORE_ID]["role"],
                "archive",
            )
            self.assertEqual(
                stores[vault_sync.DEFAULT_OBJECT_STORE_ID]["access"],
                "read_only",
            )
            self.assertEqual(
                stores[vault_sync.RCLONE_OBJECT_STORE_ID]["role"],
                "primary",
            )
            serialized = json.dumps(configured, sort_keys=True)
            self.assertNotIn("temporary-test-password", serialized)
            store.assert_called_once_with(
                vault_sync.RCLONE_CONFIG_CREDENTIAL_HOST,
                vault_sync.RCLONE_OBJECT_STORE_ID,
                "temporary-test-password",
            )
            self.assertTrue(result["encrypted_config_verified"])
            self.assertTrue(result["encrypted_root_verified"])

    def test_switch_refuses_unfinished_outbox_before_secret_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            pending = data_dir / "outbox" / "pending"
            pending.mkdir(parents=True)
            (pending / "tx.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(
                vault_sync,
                "_read_rclone_config_password",
            ) as password_reader:
                with self.assertRaises(vault_sync.BusyError):
                    vault_sync.configure_rclone_store_command(
                        argparse.Namespace(
                            rclone_executable="/missing/rclone",
                            rclone_config="/missing/rclone.conf",
                            rclone_remote="vault_crypt",
                            config_password_stdin=False,
                            no_initialize_root=False,
                        ),
                        data_dir,
                    )
            password_reader.assert_not_called()

    def test_switch_rechecks_outbox_after_secret_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            executable = data_dir / "rclone"
            executable.write_bytes(b"pinned-rclone")
            config_path = data_dir / "rclone.conf"
            config_path.write_bytes(b"encrypted-config")
            if os.name != "nt":
                executable.chmod(0o700)
                config_path.chmod(0o600)

            def prompt_then_queue_work(_args: argparse.Namespace) -> str:
                pending = data_dir / "outbox" / "pending"
                pending.mkdir(parents=True)
                (pending / "tx.json").write_text("{}", encoding="utf-8")
                return "temporary-test-password"

            with (
                mock.patch.object(
                    vault_sync,
                    "_read_rclone_config_password",
                    side_effect=prompt_then_queue_work,
                ),
                mock.patch.object(vault_sync, "_probe_rclone_boundary") as probe,
            ):
                with self.assertRaises(vault_sync.BusyError):
                    vault_sync.configure_rclone_store_command(
                        self._arguments(executable, config_path),
                        data_dir,
                    )
            probe.assert_not_called()

    def test_failed_config_commit_erases_new_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            executable = data_dir / "rclone"
            executable.write_bytes(b"pinned-rclone")
            config_path = data_dir / "rclone.conf"
            config_path.write_bytes(b"encrypted-config")
            if os.name != "nt":
                executable.chmod(0o700)
                config_path.chmod(0o600)
            executable_sha256 = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
            with (
                mock.patch.object(
                    vault_sync,
                    "_read_rclone_config_password",
                    return_value="temporary-test-password",
                ),
                mock.patch.object(
                    vault_sync,
                    "_probe_rclone_boundary",
                    return_value=self._probe(executable_sha256),
                ),
                mock.patch.object(
                    vault_sync.RcloneCryptAdapter,
                    "initialize_private_root",
                    return_value={
                        "marker_created": True,
                        "encrypted_root_verified": True,
                    },
                ),
                mock.patch.object(
                    vault_sync,
                    "_refresh_stable_runtime",
                    return_value={
                        "plugin_version": vault_sync.VERSION,
                        "updated": False,
                    },
                ),
                mock.patch.object(
                    vault_sync,
                    "atomic_write_json",
                    side_effect=OSError("simulated config commit failure"),
                ),
                mock.patch.object(vault_sync, "credential_store") as store,
                mock.patch.object(vault_sync, "credential_erase") as erase,
            ):
                with self.assertRaises(vault_sync.ConfigurationError):
                    vault_sync.configure_rclone_store_command(
                        self._arguments(executable, config_path),
                        data_dir,
                    )

            store.assert_called_once_with(
                vault_sync.RCLONE_CONFIG_CREDENTIAL_HOST,
                vault_sync.RCLONE_OBJECT_STORE_ID,
                "temporary-test-password",
            )
            erase.assert_called_once_with(
                vault_sync.RCLONE_CONFIG_CREDENTIAL_HOST,
                vault_sync.RCLONE_OBJECT_STORE_ID,
            )
            self.assertFalse((data_dir / "config.json").exists())

    def test_parser_exposes_rclone_lifecycle_commands(self) -> None:
        parser = vault_sync.build_parser()
        configure = parser.parse_args(
            [
                "configure-rclone-store",
                "--rclone-executable",
                "/opt/rclone",
                "--rclone-config",
                "/private/rclone.conf",
                "--rclone-remote",
                "vault_crypt",
                "--config-password-stdin",
            ]
        )
        self.assertEqual(configure.command, "configure-rclone-store")
        self.assertTrue(configure.config_password_stdin)
        self.assertEqual(
            parser.parse_args(["auth-rclone"]).command,
            "auth-rclone",
        )
        self.assertEqual(
            parser.parse_args(["init-object-store"]).command,
            "init-object-store",
        )
        chunking = parser.parse_args(
            ["configure-chunking", "--enable", "--minimum-bytes", "16777216"]
        )
        self.assertEqual(chunking.command, "configure-chunking")
        self.assertTrue(chunking.enable)

    def test_chunking_opt_in_and_out_are_reversible_without_deletion(
        self,
    ) -> None:
        config = vault_sync.validate_config(rclone_config())
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            vault_sync.atomic_write_json(data_dir / "config.json", config)
            engine = vault_sync.SyncEngine(config, data_dir)
            adapter = MemoryRcloneAdapter(config, data_dir=data_dir)
            adapter.initialize_private_root(data_dir)
            engine.drive = adapter
            with mock.patch.object(
                vault_sync,
                "_refresh_stable_runtime",
                return_value={
                    "plugin_version": vault_sync.VERSION,
                    "updated": False,
                },
            ):
                enabled = vault_sync.configure_chunking_command(
                    argparse.Namespace(
                        enable=True,
                        disable=False,
                        minimum_bytes=vault_sync.CHUNK_SIZE_BYTES,
                    ),
                    engine,
                )
                remote_after_enable = dict(adapter.remote_objects)
                disabled = vault_sync.configure_chunking_command(
                    argparse.Namespace(
                        enable=False,
                        disable=True,
                        minimum_bytes=None,
                    ),
                    engine,
                )

            persisted = vault_sync.load_config(data_dir)
            self.assertIsNotNone(persisted)
            assert persisted is not None
            self.assertFalse(
                persisted["sync"]["chunked_artifacts_enabled"]
            )
            self.assertTrue(enabled["enabled"])
            self.assertFalse(disabled["enabled"])
            self.assertFalse(enabled["remote_deletion_performed"])
            self.assertFalse(disabled["remote_deletion_performed"])
            self.assertEqual(adapter.remote_objects, remote_after_enable)

    def test_chunking_configuration_refuses_unfinished_outbox(self) -> None:
        config = vault_sync.validate_config(rclone_config())
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            vault_sync.atomic_write_json(data_dir / "config.json", config)
            pending = data_dir / "outbox" / "pending"
            pending.mkdir(parents=True)
            (pending / "tx.json").write_text("{}", encoding="utf-8")
            engine = vault_sync.SyncEngine(config, data_dir)
            engine.drive = mock.Mock()
            with self.assertRaises(vault_sync.BusyError):
                vault_sync.configure_chunking_command(
                    argparse.Namespace(
                        enable=True,
                        disable=False,
                        minimum_bytes=vault_sync.CHUNK_SIZE_BYTES,
                    ),
                    engine,
                )
            engine.drive.initialize_chunk_policy.assert_not_called()

    def test_status_and_online_doctor_expose_verified_chunk_policy(
        self,
    ) -> None:
        config = rclone_config()
        config["sync"]["chunked_artifacts_enabled"] = True
        config["sync"]["chunked_artifact_min_bytes"] = (
            vault_sync.CHUNK_SIZE_BYTES
        )
        config = vault_sync.validate_config(config)
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            engine = vault_sync.SyncEngine(config, data_dir)
            adapter = MemoryRcloneAdapter(config, data_dir=data_dir)
            adapter.initialize_private_root(data_dir)
            adapter.initialize_chunk_policy()
            engine.drive = adapter
            status = engine.status()
            self.assertEqual(
                status["artifact_chunking"],
                {
                    "enabled": True,
                    "reader_protocol": vault_sync.CHUNK_READER_PROTOCOL,
                    "algorithm": vault_sync.CHUNK_ALGORITHM,
                    "encryption_policy": (
                        vault_sync.CHUNK_ENCRYPTION_POLICY
                    ),
                    "chunk_size": vault_sync.CHUNK_SIZE_BYTES,
                    "maximum_chunks": vault_sync.MAX_CHUNK_COUNT,
                    "minimum_artifact_bytes": (
                        vault_sync.CHUNK_SIZE_BYTES
                    ),
                    "remote_deletion_enabled": False,
                },
            )
            with mock.patch.object(engine.git, "ensure"):
                doctor = engine.doctor(online=True)
            policy_check = next(
                item
                for item in doctor["checks"]
                if item["name"] == "encrypted_chunk_policy"
            )
            self.assertTrue(policy_check["ok"])
            self.assertIn("policy verified", policy_check["detail"])


class RcloneRedactedConfigTests(unittest.TestCase):
    CRYPT = """\
[vault_crypt]
type = crypt
remote = base:memory-vault/private
password = XXX
password2 = XXX
filename_encryption = standard
directory_name_encryption = true
strict_names = true
pass_bad_blocks = false
"""

    def test_supported_wrapped_backends_are_accepted(self) -> None:
        backends = {
            "s3": "provider = Minio\nendpoint = https://s3.example.test\n",
            "webdav": "url = https://dav.example.test/private\nauth_redirect = false\n",
            "sftp": (
                "host = storage.example.test\nport = 22\nuser = vault\n"
                "known_hosts_file = /private/known_hosts\n"
            ),
            "local": "copy_links = false\n",
        }
        fingerprints: set[str] = set()
        for backend, fields in backends.items():
            with self.subTest(backend=backend):
                result = vault_sync._validate_rclone_redacted_sections(
                    remote_name="vault_crypt",
                    crypt_raw=self.CRYPT.encode("utf-8"),
                    base_raw=(f"[base]\ntype = {backend}\n{fields}").encode(
                        "utf-8"
                    ),
                )
                self.assertEqual(result["backend_type"], backend)
                self.assertRegex(result["remote_fingerprint"], r"^[0-9a-f]{64}$")
                fingerprints.add(result["remote_fingerprint"])
        self.assertEqual(len(fingerprints), len(backends))

    def test_unsafe_crypt_or_transport_settings_fail_closed(self) -> None:
        cases = {
            "plaintext_names": self.CRYPT.replace(
                "filename_encryption = standard", "filename_encryption = off"
            ),
            "weak_salt": self.CRYPT.replace("password2 = XXX\n", ""),
            "bad_blocks": self.CRYPT.replace(
                "pass_bad_blocks = false", "pass_bad_blocks = true"
            ),
        }
        for name, crypt in cases.items():
            with self.subTest(name=name), self.assertRaises(
                vault_sync.PrivacyError
            ):
                vault_sync._validate_rclone_redacted_sections(
                    remote_name="vault_crypt",
                    crypt_raw=crypt.encode("utf-8"),
                    base_raw=(
                        b"[base]\ntype = s3\nendpoint = https://s3.example.test\n"
                    ),
                )

        unsafe_bases = (
            b"[base]\ntype = webdav\nurl = http://dav.example.test\n",
            b"[base]\ntype = webdav\nurl = https://dav.example.test\nauth_redirect = true\n",
            b"[base]\ntype = webdav\nurl = https://dav.example.test\nheaders = Authorization,secret\n",
            b"[base]\ntype = webdav\nurl = https://dav.example.test\nunix_socket = /tmp/dav.sock\n",
            b"[base]\ntype = dropbox\ntoken = XXX\n",
            b"[base]\ntype = s3\nendpoint = https://s3.example.test\nsecret_access_key = visible-secret\n",
            b"[base]\ntype = s3\nenv_auth = true\n",
            b"[base]\ntype = s3\nendpoint = https://s3.example.test\nsts_endpoint = http://sts.example.test\n",
            b"[base]\ntype = sftp\nhost = storage.example.test\n",
            (
                b"[base]\ntype = sftp\nhost = storage.example.test\n"
                b"known_hosts_file = /private/known_hosts\n"
                b"ssh = ssh -o StrictHostKeyChecking=no\n"
            ),
            (
                b"[base]\ntype = sftp\nhost = storage.example.test\n"
                b"known_hosts_file = /private/known_hosts\n"
                b"server_command = sudo /usr/libexec/sftp-server\n"
            ),
            (
                b"[base]\ntype = sftp\nhost = storage.example.test\n"
                b"known_hosts_file = /private/known_hosts\n"
                b"ciphers = aes128-cbc\n"
            ),
        )
        for base in unsafe_bases:
            with self.subTest(base=base), self.assertRaises(
                vault_sync.PrivacyError
            ):
                vault_sync._validate_rclone_redacted_sections(
                    remote_name="vault_crypt",
                    crypt_raw=self.CRYPT.encode("utf-8"),
                    base_raw=base,
                )

    def test_absolute_wrapped_path_is_reserved_for_local_backend(self) -> None:
        absolute_crypt = self.CRYPT.replace(
            "base:memory-vault/private",
            "base:/private/memory-vault",
        ).encode("utf-8")
        accepted = vault_sync._validate_rclone_redacted_sections(
            remote_name="vault_crypt",
            crypt_raw=absolute_crypt,
            base_raw=b"[base]\ntype = local\n",
        )
        self.assertEqual(accepted["backend_type"], "local")
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._validate_rclone_redacted_sections(
                remote_name="vault_crypt",
                crypt_raw=absolute_crypt,
                base_raw=(
                    b"[base]\ntype = s3\n"
                    b"endpoint = https://s3.example.test\n"
                ),
            )
        root_crypt = self.CRYPT.replace(
            "base:memory-vault/private",
            "base:/",
        ).encode("utf-8")
        with self.assertRaises(vault_sync.PrivacyError):
            vault_sync._validate_rclone_redacted_sections(
                remote_name="vault_crypt",
                crypt_raw=root_crypt,
                base_raw=b"[base]\ntype = local\n",
            )


class RcloneBoundaryProbeTests(unittest.TestCase):
    def test_environment_is_minimal_and_password_never_enters_arguments(
        self,
    ) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "RCLONE_CONFIG_EVIL_TYPE": "local",
                "UNRELATED_SECRET": "do-not-inherit",
                "HTTPS_PROXY": "http://127.0.0.1:7897",
                "SSH_AUTH_SOCK": "/private/agent.sock",
            },
            clear=True,
        ):
            environment = vault_sync._rclone_environment("config-password")

        self.assertEqual(
            environment["RCLONE_CONFIG_PASS"], "config-password"
        )
        self.assertEqual(environment["HTTPS_PROXY"], "http://127.0.0.1:7897")
        self.assertEqual(environment["SSH_AUTH_SOCK"], "/private/agent.sock")
        self.assertNotIn("RCLONE_CONFIG_EVIL_TYPE", environment)
        self.assertNotIn("UNRELATED_SECRET", environment)

    def test_probe_pins_executable_version_encrypted_config_and_remote(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / ("rclone.exe" if os.name == "nt" else "rclone")
            executable.write_bytes(b"fixed fake rclone binary")
            if os.name != "nt":
                executable.chmod(0o700)
            config_path = root / "rclone.conf"
            config_path.write_bytes(b"encrypted-rclone-config")
            if os.name != "nt":
                config_path.chmod(0o600)
            expected_executable_sha = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
            calls: list[tuple[list[str], dict[str, str]]] = []

            def run_control(
                arguments: list[str],
                *,
                environment: dict[str, str],
                timeout: float,
            ) -> subprocess.CompletedProcess[bytes]:
                calls.append((list(arguments), dict(environment)))
                joined = " ".join(arguments)
                if joined.endswith(" version"):
                    stdout = b"rclone v1.74.4\n- os/version: test\n"
                elif joined.endswith(" config encryption check"):
                    stdout = b"Configuration is encrypted.\n"
                elif joined.endswith(" config redacted vault_crypt"):
                    stdout = RcloneRedactedConfigTests.CRYPT.encode("utf-8")
                elif joined.endswith(" config redacted base"):
                    stdout = (
                        b"[base]\ntype = s3\nprovider = Minio\n"
                        b"endpoint = https://s3.example.test\n"
                        b"access_key_id = XXX\nsecret_access_key = XXX\n"
                    )
                else:
                    raise AssertionError(f"unexpected rclone command: {arguments}")
                return subprocess.CompletedProcess(arguments, 0, stdout, b"")

            with mock.patch.object(
                vault_sync,
                "_run_rclone_control",
                side_effect=run_control,
            ):
                probe = vault_sync._probe_rclone_boundary(
                    executable=executable,
                    expected_executable_sha256=expected_executable_sha,
                    config_path=config_path,
                    remote_name="vault_crypt",
                    config_password="config-password",
                )

        self.assertEqual(probe["verified_version"], "1.74.4")
        self.assertEqual(probe["backend_type"], "s3")
        self.assertRegex(probe["remote_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(calls), 4)
        for arguments, environment in calls:
            self.assertNotIn("config-password", arguments)
            self.assertIn("--ask-password=false", arguments)
            if "version" not in arguments:
                self.assertEqual(
                    environment["RCLONE_CONFIG_PASS"], "config-password"
                )

    def test_sftp_known_hosts_content_is_part_of_remote_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / ("rclone.exe" if os.name == "nt" else "rclone")
            executable.write_bytes(b"fixed fake rclone binary")
            config_path = root / "rclone.conf"
            config_path.write_bytes(b"encrypted-rclone-config")
            known_hosts_a = root / "known_hosts-a"
            known_hosts_b = root / "known_hosts-b"
            known_hosts_a.write_bytes(
                b"storage.example.test ssh-ed25519 AAAA\n"
            )
            known_hosts_b.write_bytes(known_hosts_a.read_bytes())
            if os.name != "nt":
                executable.chmod(0o700)
                config_path.chmod(0o600)
                known_hosts_a.chmod(0o600)
                known_hosts_b.chmod(0o600)
            executable_sha = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
            selected_known_hosts = known_hosts_a

            def run_control(
                arguments: list[str],
                *,
                environment: dict[str, str],
                timeout: float,
            ) -> subprocess.CompletedProcess[bytes]:
                joined = " ".join(arguments)
                if joined.endswith(" version"):
                    stdout = b"rclone v1.74.4\n"
                elif joined.endswith(" config encryption check"):
                    stdout = b"Configuration is encrypted.\n"
                elif joined.endswith(" config redacted vault_crypt"):
                    stdout = RcloneRedactedConfigTests.CRYPT.encode("utf-8")
                elif joined.endswith(" config redacted base"):
                    stdout = (
                        "[base]\ntype = sftp\n"
                        "host = storage.example.test\n"
                        f"known_hosts_file = {selected_known_hosts}\n"
                    ).encode("utf-8")
                else:
                    raise AssertionError(arguments)
                return subprocess.CompletedProcess(arguments, 0, stdout, b"")

            with mock.patch.object(
                vault_sync,
                "_run_rclone_control",
                side_effect=run_control,
            ):
                first = vault_sync._probe_rclone_boundary(
                    executable=executable,
                    expected_executable_sha256=executable_sha,
                    config_path=config_path,
                    remote_name="vault_crypt",
                    config_password="config-password",
                )
                selected_known_hosts = known_hosts_b
                same_key_different_path = vault_sync._probe_rclone_boundary(
                    executable=executable,
                    expected_executable_sha256=executable_sha,
                    config_path=config_path,
                    remote_name="vault_crypt",
                    config_password="config-password",
                )
                known_hosts_b.write_bytes(
                    b"storage.example.test ssh-ed25519 BBBB\n"
                )
                changed_key = vault_sync._probe_rclone_boundary(
                    executable=executable,
                    expected_executable_sha256=executable_sha,
                    config_path=config_path,
                    remote_name="vault_crypt",
                    config_password="config-password",
                )

        self.assertEqual(
            first["remote_fingerprint"],
            same_key_different_path["remote_fingerprint"],
        )
        self.assertNotEqual(
            same_key_different_path["remote_fingerprint"],
            changed_key["remote_fingerprint"],
        )

    def test_verified_config_change_is_detected_before_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "rclone.conf"
            config_path.write_bytes(b"encrypted-config-a")
            adapter = object.__new__(vault_sync.RcloneCryptAdapter)
            adapter.config_path = config_path
            adapter._config_sha256 = hashlib.sha256(
                config_path.read_bytes()
            ).hexdigest()
            adapter._local_trust_file_sha256 = {}
            adapter._assert_local_boundary_unchanged()
            config_path.write_bytes(b"encrypted-config-b")
            with self.assertRaisesRegex(
                vault_sync.VerificationError,
                "encrypted config changed",
            ):
                adapter._assert_local_boundary_unchanged()

    def test_stream_timeout_cancels_the_child_process(self) -> None:
        with self.assertRaises(vault_sync.OfflineError):
            vault_sync._stream_rclone_stdout(
                [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(10)",
                ],
                environment={},
                timeout=0.05,
                maximum_bytes=1,
            )


class InMemoryRcloneAdapter:
    """Exercise adapter semantics while replacing only the provider process."""

    def _install_memory_transport(self) -> None:
        self.remote_objects: dict[str, bytes] = {}
        self.transport_lock = threading.Lock()
        self.chunk_uploaded_bytes = 0
        self.chunk_downloaded_bytes = 0
        self.chunk_upload_batches = 0
        self.chunk_download_batches = 0
        self.chunk_cryptcheck_batches = 0
        self.cryptcheck_supported = True
        self.fail_chunk_upload_before_copy = False
        self.fail_chunk_upload_after_files: int | None = None

    def _probe_current(self) -> None:
        return None

    def _base_ciphertext_entry_count(self) -> int:
        return len(
            {
                path.partition("/")[0]
                for path in self.remote_objects
                if path
            }
        )

    def _list_names(self, parent: str) -> list[str]:
        prefix = f"{parent}/" if parent else ""
        names: set[str] = set()
        with self.transport_lock:
            for path in self.remote_objects:
                if not path.startswith(prefix):
                    continue
                remainder = path[len(prefix) :]
                head, separator, _tail = remainder.partition("/")
                names.add(f"{head}/" if separator else head)
        return sorted(names)

    def _stream_remote(
        self,
        relative_path: str,
        *,
        expected_size: int,
        output_stream=None,
    ) -> tuple[str, int]:
        try:
            payload = self.remote_objects[relative_path]
        except KeyError as exc:
            raise vault_sync.OfflineError("simulated missing object") from exc
        if len(payload) > expected_size:
            raise vault_sync.VerificationError("simulated size mismatch")
        if output_stream is not None:
            output_stream.write(payload)
        return hashlib.sha256(payload).hexdigest(), len(payload)

    def _copyto(self, source: Path, relative_path: str, size: int) -> None:
        payload = source.read_bytes()
        if len(payload) != size:
            raise vault_sync.VerificationError("simulated local size mismatch")
        with self.transport_lock:
            existing = self.remote_objects.get(relative_path)
            if existing is not None and existing != payload:
                raise vault_sync.VerificationError("immutable object mismatch")
            self.remote_objects[relative_path] = payload

    def _list_remote_chunk_ids(
        self,
        policy: dict,
        content_ids: set[str],
    ) -> set[str]:
        return {
            content_id
            for content_id in content_ids
            if vault_sync.chunk_relative_path(policy, content_id)
            in self.remote_objects
        }

    def _copy_chunk_files(
        self,
        staging_root: Path,
        policy: dict,
        sizes: dict[str, int],
    ) -> None:
        self.chunk_upload_batches += 1
        if self.fail_chunk_upload_before_copy:
            self.fail_chunk_upload_before_copy = False
            raise vault_sync.OfflineError("simulated interrupted chunk upload")
        for index, (content_id, size) in enumerate(sizes.items(), start=1):
            source = staging_root / content_id[:2] / content_id
            self._copyto(
                source,
                vault_sync.chunk_relative_path(policy, content_id),
                size,
            )
            self.chunk_uploaded_bytes += size
            if self.fail_chunk_upload_after_files == index:
                self.fail_chunk_upload_after_files = None
                raise vault_sync.OfflineError(
                    "simulated interrupted partial chunk upload"
                )

    def _fetch_chunk_files(
        self,
        policy: dict,
        sizes: dict[str, int],
        destination: Path,
    ) -> None:
        self.chunk_download_batches += 1
        vault_sync.ensure_private_dir(destination)
        for content_id, size in sizes.items():
            relative = vault_sync.chunk_relative_path(policy, content_id)
            try:
                payload = self.remote_objects[relative]
            except KeyError as exc:
                raise vault_sync.OfflineError(
                    "simulated missing chunk"
                ) from exc
            target = destination / content_id[:2] / content_id
            vault_sync.ensure_private_dir(target.parent)
            target.write_bytes(payload)
            if os.name != "nt":
                target.chmod(0o600)
            self.chunk_downloaded_bytes += len(payload)

    def _cryptcheck_chunk_files(
        self,
        root: Path,
        policy: dict,
        sizes: dict[str, int],
    ) -> bool:
        self.chunk_cryptcheck_batches += 1
        if not self.cryptcheck_supported:
            return False
        self._verify_chunk_files(root, sizes)
        for content_id, size in sizes.items():
            relative = vault_sync.chunk_relative_path(policy, content_id)
            payload = self.remote_objects.get(relative)
            source = root / content_id[:2] / content_id
            if (
                payload is None
                or len(payload) != size
                or payload != source.read_bytes()
            ):
                return False
        return True


class MemoryRcloneAdapter(
    InMemoryRcloneAdapter,
    # The production adapter remains the implementation under test; this
    # mixin replaces only the external rclone process and remote bytes.
    vault_sync.RcloneCryptAdapter,
):
    def __init__(self, config: dict, data_dir: Path | None = None) -> None:
        vault_sync.RcloneCryptAdapter.__init__(
            self,
            config,
            data_dir=data_dir,
        )
        self._install_memory_transport()


class RcloneAdapterTests(unittest.TestCase):
    def test_chunk_control_batches_keep_windows_command_lines_bounded(
        self,
    ) -> None:
        values = [f"{index:064x}" for index in range(4096)]
        batches = list(vault_sync.RcloneCryptAdapter._chunk_batches(values))
        self.assertEqual(len(batches), 32)
        self.assertTrue(all(len(batch) == 128 for batch in batches))
        self.assertEqual([item for batch in batches for item in batch], values)

    def test_cryptcheck_requires_one_exact_match_receipt_per_chunk(self) -> None:
        config = vault_sync.validate_config(rclone_config())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = MemoryRcloneAdapter(config, data_dir=root / "data")
            payload = b"verified chunk payload"
            hasher = vault_sync.new_chunk_hasher()
            hasher.update(payload)
            content_id = hasher.hexdigest()
            staging = root / "staging"
            target = staging / content_id[:2] / content_id
            target.parent.mkdir(parents=True)
            target.write_bytes(payload)
            policy = {"key_epoch": "3" * 64}
            exact = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=f"= {content_id[:2]}/{content_id}\n".encode(),
                stderr=b"",
            )
            with mock.patch.object(
                adapter,
                "_run_command",
                return_value=exact,
            ):
                self.assertTrue(
                    vault_sync.RcloneCryptAdapter._cryptcheck_chunk_files(
                        adapter,
                        staging,
                        policy,
                        {content_id: len(payload)},
                    )
                )
            for stdout in (
                b"",
                f"= {content_id[:2]}/{content_id}\n".encode() * 2,
                f"+ {content_id[:2]}/{content_id}\n".encode(),
            ):
                with self.subTest(stdout=stdout), mock.patch.object(
                    adapter,
                    "_run_command",
                    return_value=subprocess.CompletedProcess(
                        args=[],
                        returncode=0,
                        stdout=stdout,
                        stderr=b"",
                    ),
                ):
                    self.assertFalse(
                        vault_sync.RcloneCryptAdapter._cryptcheck_chunk_files(
                            adapter,
                            staging,
                            policy,
                            {content_id: len(payload)},
                        )
                    )

    def test_encrypted_transfer_limit_covers_crypt_format_and_headroom(self) -> None:
        self.assertEqual(
            vault_sync.RcloneCryptAdapter._encrypted_transfer_limit(1),
            65_585,
        )
        self.assertEqual(
            vault_sync.RcloneCryptAdapter._encrypted_transfer_limit(
                1024 * 1024
            ),
            1_114_400,
        )
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync.RcloneCryptAdapter._encrypted_transfer_limit(0)

    def test_missing_content_prefix_is_empty_but_missing_root_fails(self) -> None:
        adapter = object.__new__(vault_sync.RcloneCryptAdapter)
        adapter.remote_name = "vault_crypt"
        adapter._run_command = mock.Mock(
            return_value=subprocess.CompletedProcess([], 3, b"", b"")
        )
        self.assertEqual(adapter._list_names("objects/sha256/aa"), [])
        with self.assertRaises(vault_sync.OfflineError):
            adapter._list_names("")

    def test_initialize_upload_reuse_download_and_tamper_detection(self) -> None:
        config = vault_sync.validate_config(rclone_config())
        adapter = MemoryRcloneAdapter(config)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initialized = adapter.initialize_private_root(root)
            self.assertTrue(initialized["encrypted_root_verified"])
            adapter.assert_private()

            source = root / "artifact.bin"
            source.write_bytes(b"provider-neutral encrypted payload")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            verified = adapter.upload_and_verify(
                source,
                digest,
                source.stat().st_size,
                "application/octet-stream",
            )
            self.assertEqual(verified.driver, "rclone-crypt")
            self.assertEqual(
                verified.verification_level,
                "rclone-crypt-download-sha256",
            )
            self.assertEqual(
                adapter.find_verified(
                    digest,
                    source.stat().st_size,
                    "application/octet-stream",
                ),
                verified,
            )
            artifact = {
                "sha256": digest,
                "size": source.stat().st_size,
                "mime_type": "application/octet-stream",
                "storage_ref": vault_sync._storage_ref_from_verified(verified),
            }
            destination = root / "restored" / "artifact.bin"
            adapter.download_and_verify(artifact, destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())

            object_path = adapter._object_relative_path(digest)
            adapter.remote_objects[object_path] = b"x" * source.stat().st_size
            adapter._verified_lookup_cache.clear()
            with self.assertRaises(vault_sync.VerificationError):
                adapter.find_verified(
                    digest,
                    source.stat().st_size,
                    "application/octet-stream",
                )

    def test_missing_or_changed_encrypted_root_marker_fails_closed(self) -> None:
        adapter = MemoryRcloneAdapter(
            vault_sync.validate_config(rclone_config())
        )
        with self.assertRaises(vault_sync.PrivacyError):
            adapter.assert_private()
        adapter.remote_objects[vault_sync.RCLONE_ROOT_MARKER_PATH] = b"{}"
        with self.assertRaises(vault_sync.PrivacyError):
            adapter.assert_private()

    def test_hidden_ciphertext_prevents_initializing_with_a_changed_key(self) -> None:
        adapter = MemoryRcloneAdapter(
            vault_sync.validate_config(rclone_config())
        )
        adapter.remote_objects["opaque-ciphertext-name"] = b"ciphertext"
        adapter._list_names = mock.Mock(return_value=[])
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                vault_sync.PrivacyError,
                "ciphertext root is not empty",
            ):
                adapter.initialize_private_root(Path(temporary))

    def test_concurrent_same_object_copy_error_converges_by_exact_bytes(self) -> None:
        adapter = MemoryRcloneAdapter(
            vault_sync.validate_config(rclone_config())
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter.initialize_private_root(root)
            source = root / "artifact.bin"
            source.write_bytes(b"same immutable bytes from another device")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            original_copy = adapter._copyto

            def concurrent_copy(path: Path, relative: str, size: int) -> None:
                original_copy(path, relative, size)
                raise vault_sync.OfflineError("simulated ambiguous copy result")

            adapter._copyto = concurrent_copy
            verified = adapter.upload_and_verify(
                source,
                digest,
                source.stat().st_size,
                "application/octet-stream",
            )
            self.assertEqual(verified.sha256, digest)
            self.assertEqual(verified.store_id, adapter.store_id)


class ChunkedRcloneAdapterTests(unittest.TestCase):
    @staticmethod
    def _chunked_config() -> dict:
        config = rclone_config()
        config["sync"]["chunked_artifacts_enabled"] = True
        config["sync"]["chunked_artifact_min_bytes"] = (
            vault_sync.CHUNK_SIZE_BYTES
        )
        return vault_sync.validate_config(config)

    @staticmethod
    def _write_fixture(
        path: Path,
        *,
        changed_second_chunk: bool,
    ) -> tuple[str, int]:
        mebibyte = 1024 * 1024
        digest = hashlib.sha256()
        size = 0
        with path.open("wb", buffering=0) as stream:
            for _ in range(16):
                block = b"A" * mebibyte
                stream.write(block)
                digest.update(block)
                size += len(block)
            for index in range(16):
                block = (
                    b"C" * mebibyte
                    if changed_second_chunk and index == 0
                    else b"B" * mebibyte
                )
                stream.write(block)
                digest.update(block)
                size += len(block)
        return digest.hexdigest(), size

    def test_cold_upload_delta_reuse_atomic_restore_and_tamper_refusal(
        self,
    ) -> None:
        config = self._chunked_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "plugin-data"
            adapter = MemoryRcloneAdapter(config, data_dir=data_dir)
            adapter.initialize_private_root(data_dir)
            policy_result = adapter.initialize_chunk_policy()
            self.assertEqual(
                policy_result["algorithm"],
                vault_sync.CHUNK_ALGORITHM,
            )

            first = root / "first.bin"
            first_sha, first_size = self._write_fixture(
                first,
                changed_second_chunk=False,
            )
            first_verified = adapter.upload_and_verify(
                first,
                first_sha,
                first_size,
                "application/octet-stream",
            )
            self.assertEqual(first_verified.storage_mode, "chunked-v1")
            self.assertRegex(
                first_verified.file_id,
                r"^chunk-manifest-[0-9a-f]{64}$",
            )
            self.assertEqual(adapter.chunk_uploaded_bytes, first_size)
            self.assertEqual(adapter.chunk_downloaded_bytes, 0)
            self.assertEqual(adapter.chunk_upload_batches, 1)
            self.assertEqual(adapter.chunk_download_batches, 0)
            self.assertEqual(adapter.chunk_cryptcheck_batches, 1)

            adapter.chunk_uploaded_bytes = 0
            adapter.chunk_downloaded_bytes = 0
            adapter.chunk_upload_batches = 0
            adapter.chunk_download_batches = 0
            adapter.chunk_cryptcheck_batches = 0
            second = root / "second.bin"
            second_sha, second_size = self._write_fixture(
                second,
                changed_second_chunk=True,
            )
            second_verified = adapter.upload_and_verify(
                second,
                second_sha,
                second_size,
                "application/octet-stream",
            )
            self.assertEqual(second_verified.storage_mode, "chunked-v1")
            self.assertEqual(
                adapter.chunk_uploaded_bytes,
                vault_sync.CHUNK_SIZE_BYTES,
            )
            self.assertEqual(
                adapter.chunk_downloaded_bytes,
                0,
            )
            self.assertEqual(adapter.chunk_upload_batches, 1)
            self.assertEqual(adapter.chunk_download_batches, 0)
            self.assertEqual(adapter.chunk_cryptcheck_batches, 1)

            artifact = {
                "storage_mode": "chunked-v1",
                "sha256": second_sha,
                "size": second_size,
                "mime_type": "application/octet-stream",
                "storage_ref": vault_sync._storage_ref_from_verified(
                    second_verified
                ),
            }
            config["sync"]["chunked_artifacts_enabled"] = False
            self.assertFalse(adapter.should_chunk(second_size))
            destination = root / "restored" / "second.bin"
            adapter.download_and_verify(artifact, destination)
            self.assertEqual(
                hashlib.sha256(destination.read_bytes()).hexdigest(),
                second_sha,
            )
            self.assertEqual(destination.stat().st_size, second_size)

            policy = adapter._chunk_policy()
            manifest_id = second_verified.file_id.removeprefix(
                "chunk-manifest-"
            )
            manifest = adapter._read_chunk_manifest(
                policy,
                manifest_id,
                artifact_sha256=second_sha,
                artifact_size=second_size,
                mime_type="application/octet-stream",
            )
            first_chunk = manifest["chunks"][0]["content_id"]
            adapter.remote_objects[
                vault_sync.chunk_relative_path(policy, first_chunk)
            ] = b"X" * vault_sync.CHUNK_SIZE_BYTES
            refused_destination = root / "restored" / "tampered.bin"
            with self.assertRaises(vault_sync.VerificationError):
                adapter.download_and_verify(artifact, refused_destination)
            self.assertFalse(refused_destination.exists())

    def test_enabling_chunks_keeps_historical_whole_objects_readable(
        self,
    ) -> None:
        config = vault_sync.validate_config(rclone_config())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = MemoryRcloneAdapter(config, data_dir=root / "data")
            adapter.initialize_private_root(root / "data")
            source = root / "historical.bin"
            source.write_bytes(b"historical whole object")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            verified = adapter.upload_and_verify(
                source,
                digest,
                source.stat().st_size,
                "application/octet-stream",
            )
            self.assertEqual(verified.storage_mode, "full")

            config["sync"]["chunked_artifacts_enabled"] = True
            config["sync"]["chunked_artifact_min_bytes"] = (
                vault_sync.CHUNK_SIZE_BYTES
            )
            adapter.initialize_chunk_policy()
            destination = root / "restored.bin"
            adapter.download_and_verify(
                {
                    "storage_mode": "full",
                    "sha256": digest,
                    "size": source.stat().st_size,
                    "mime_type": "application/octet-stream",
                    "storage_ref": vault_sync._storage_ref_from_verified(
                        verified
                    ),
                },
                destination,
            )
            self.assertEqual(destination.read_bytes(), source.read_bytes())

    def test_concurrent_chunk_uploads_converge_on_shared_content(self) -> None:
        config = self._chunked_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = MemoryRcloneAdapter(config, data_dir=root / "data")
            adapter.initialize_private_root(root / "data")
            adapter.initialize_chunk_policy()
            first = root / "first.bin"
            first_sha, first_size = self._write_fixture(
                first,
                changed_second_chunk=False,
            )
            second = root / "second.bin"
            second_sha, second_size = self._write_fixture(
                second,
                changed_second_chunk=True,
            )
            inputs = (
                (first, first_sha, first_size),
                (second, second_sha, second_size),
            )
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=2
            ) as executor:
                results = list(
                    executor.map(
                        lambda item: adapter.upload_and_verify(
                            item[0],
                            item[1],
                            item[2],
                            "application/octet-stream",
                        ),
                        inputs,
                    )
                )
            self.assertTrue(
                all(item.storage_mode == "chunked-v1" for item in results)
            )
            chunk_paths = {
                path
                for path in adapter.remote_objects
                if path.startswith(vault_sync.CHUNK_ROOT + "/")
            }
            self.assertEqual(len(chunk_paths), 3)
            for path in chunk_paths:
                content_id = path.rsplit("/", 1)[-1]
                hasher = vault_sync.new_chunk_hasher()
                hasher.update(adapter.remote_objects[path])
                self.assertEqual(hasher.hexdigest(), content_id)
                self.assertRegex(content_id, r"^[0-9a-f]{64}$")

    def test_interrupted_upload_retries_without_manifest_or_deletion(
        self,
    ) -> None:
        config = self._chunked_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "plugin-data"
            adapter = MemoryRcloneAdapter(config, data_dir=data_dir)
            adapter.initialize_private_root(data_dir)
            adapter.initialize_chunk_policy()
            source = root / "artifact.bin"
            digest, size = self._write_fixture(
                source,
                changed_second_chunk=False,
            )
            baseline_paths = set(adapter.remote_objects)
            adapter.fail_chunk_upload_after_files = 1
            with self.assertRaises(vault_sync.OfflineError):
                adapter.upload_and_verify(
                    source,
                    digest,
                    size,
                    "application/octet-stream",
                )
            paths_after_interruption = set(adapter.remote_objects)
            self.assertTrue(baseline_paths.issubset(paths_after_interruption))
            self.assertEqual(
                len(paths_after_interruption - baseline_paths),
                1,
            )
            self.assertFalse(
                any(
                    path.startswith(vault_sync.CHUNK_MANIFEST_ROOT + "/")
                    for path in paths_after_interruption
                )
            )

            adapter.chunk_uploaded_bytes = 0
            verified = adapter.upload_and_verify(
                source,
                digest,
                size,
                "application/octet-stream",
            )
            self.assertEqual(verified.storage_mode, "chunked-v1")
            self.assertTrue(baseline_paths.issubset(adapter.remote_objects))
            self.assertEqual(
                adapter.chunk_uploaded_bytes,
                vault_sync.CHUNK_SIZE_BYTES,
            )

    def test_new_device_uses_cryptcheck_or_bounded_download_before_reuse(
        self,
    ) -> None:
        config = self._chunked_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = MemoryRcloneAdapter(config, data_dir=root / "device-a")
            first.initialize_private_root(root / "device-a")
            first.initialize_chunk_policy()
            source = root / "artifact.bin"
            digest, size = self._write_fixture(
                source,
                changed_second_chunk=False,
            )
            first.upload_and_verify(
                source,
                digest,
                size,
                "application/octet-stream",
            )

            second = MemoryRcloneAdapter(config, data_dir=root / "device-b")
            second.remote_objects = first.remote_objects
            second.transport_lock = first.transport_lock
            second.upload_and_verify(
                source,
                digest,
                size,
                "application/octet-stream",
            )
            self.assertEqual(second.chunk_uploaded_bytes, 0)
            self.assertEqual(second.chunk_downloaded_bytes, 0)
            self.assertEqual(second.chunk_cryptcheck_batches, 1)

            fallback = MemoryRcloneAdapter(config, data_dir=root / "device-c")
            fallback.remote_objects = first.remote_objects
            fallback.transport_lock = first.transport_lock
            fallback.cryptcheck_supported = False
            fallback.upload_and_verify(
                source,
                digest,
                size,
                "application/octet-stream",
            )
            self.assertEqual(fallback.chunk_uploaded_bytes, 0)
            self.assertEqual(fallback.chunk_downloaded_bytes, size)
            downloads_after_receipt = fallback.chunk_downloaded_bytes
            fallback.upload_and_verify(
                source,
                digest,
                size,
                "application/octet-stream",
            )
            self.assertEqual(
                fallback.chunk_downloaded_bytes,
                downloads_after_receipt,
            )

            tampered = MemoryRcloneAdapter(
                config,
                data_dir=root / "device-d",
            )
            tampered.remote_objects = dict(first.remote_objects)
            policy = tampered._chunk_policy()
            chunk_path = next(
                path
                for path in tampered.remote_objects
                if path.startswith(vault_sync.CHUNK_ROOT + "/")
            )
            tampered.remote_objects[chunk_path] = (
                b"X" * vault_sync.CHUNK_SIZE_BYTES
            )
            with self.assertRaises(vault_sync.VerificationError):
                tampered.upload_and_verify(
                    source,
                    digest,
                    size,
                    "application/octet-stream",
                )
            self.assertEqual(
                policy["key_epoch"],
                tampered._chunk_policy()["key_epoch"],
            )

    def test_tampered_policy_or_manifest_fails_before_publication(self) -> None:
        config = self._chunked_config()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = MemoryRcloneAdapter(config, data_dir=root / "device-a")
            adapter.initialize_private_root(root / "device-a")
            policy = adapter._chunk_policy(initialize=True)
            source = root / "artifact.bin"
            digest, size = self._write_fixture(
                source,
                changed_second_chunk=False,
            )
            verified = adapter.upload_and_verify(
                source,
                digest,
                size,
                "application/octet-stream",
            )
            artifact = {
                "storage_mode": "chunked-v1",
                "sha256": digest,
                "size": size,
                "mime_type": "application/octet-stream",
                "storage_ref": vault_sync._storage_ref_from_verified(
                    verified
                ),
            }
            manifest_id = verified.file_id.removeprefix("chunk-manifest-")
            manifest_path = vault_sync.chunk_manifest_relative_path(
                policy,
                manifest_id,
            )
            original_manifest = adapter.remote_objects[manifest_path]
            adapter.remote_objects[manifest_path] = original_manifest + b" "
            destination = root / "tampered-manifest.bin"
            with self.assertRaises(vault_sync.VerificationError):
                adapter.download_and_verify(artifact, destination)
            self.assertFalse(destination.exists())

            changed_policy = dict(policy)
            changed_policy["algorithm"] = "whole-object-v1"
            adapter.remote_objects[vault_sync.CHUNK_POLICY_PATH] = (
                vault_sync.canonical_json_bytes(changed_policy)
            )
            fresh = MemoryRcloneAdapter(config, data_dir=root / "device-b")
            fresh.remote_objects = adapter.remote_objects
            fresh.transport_lock = adapter.transport_lock
            with self.assertRaises(vault_sync.VerificationError):
                fresh._chunk_policy()

    def test_merge_preserves_chunk_storage_mode_and_exact_reference(self) -> None:
        config = self._chunked_config()
        digest = "a" * 64
        manifest_id = "b" * 64
        merged = vault_sync._merge_artifacts(
            {"artifacts": []},
            {
                "provider_pins": vault_sync._provider_transaction_pins(
                    config
                ),
                "artifacts": [
                    {
                        "logical_path": "outputs/archive.bin",
                        "display_name": "archive.bin",
                        "sha256": digest,
                        "size": vault_sync.CHUNK_SIZE_BYTES,
                        "mime_type": "application/octet-stream",
                        "storage": {
                            "store_id": vault_sync.RCLONE_OBJECT_STORE_ID,
                            "driver": vault_sync.RCLONE_OBJECT_STORE_DRIVER,
                            "file_id": f"chunk-manifest-{manifest_id}",
                            "parent_id": "rclone-" + "2" * 32,
                            "sha256": digest,
                            "size": vault_sync.CHUNK_SIZE_BYTES,
                            "mime_type": "application/octet-stream",
                            "verification_level": (
                                "rclone-crypt-chunk-manifest-sha256"
                            ),
                            "storage_mode": "chunked-v1",
                        },
                    }
                ],
            },
            preserve_replaced=False,
        )
        self.assertEqual(merged[0]["storage_mode"], "chunked-v1")
        vault_sync._validate_artifact(merged[0])

    def test_chunked_manifest_requires_exact_encrypted_storage_reference(
        self,
    ) -> None:
        digest = "a" * 64
        artifact = {
            "artifact_id": "artifact-chunked",
            "display_name": "artifact.bin",
            "logical_path": "artifact.bin",
            "mime_type": "application/octet-stream",
            "role": "workspace-artifact",
            "sha256": digest,
            "size": vault_sync.CHUNK_SIZE_BYTES,
            "storage_mode": "chunked-v1",
            "storage_ref": {
                "schema_version": vault_sync.ARTIFACT_STORAGE_REF_SCHEMA,
                "store_id": vault_sync.RCLONE_OBJECT_STORE_ID,
                "driver": vault_sync.RCLONE_OBJECT_STORE_DRIVER,
                "object_id": f"sha256-{digest}",
                "container_id": "rclone-" + "2" * 32,
                "verification_level": "rclone-crypt-download-sha256",
            },
        }
        with self.assertRaises(vault_sync.VerificationError):
            vault_sync._validate_artifact(artifact)


@unittest.skipUnless(
    os.environ.get("MEMORY_VAULT_RCLONE_BIN"),
    "set MEMORY_VAULT_RCLONE_BIN for live encrypted-backend acceptance",
)
class RcloneLiveAcceptanceTests(unittest.TestCase):
    def test_local_crypt_large_round_trip_and_ciphertext_tamper(self) -> None:
        executable = Path(os.environ["MEMORY_VAULT_RCLONE_BIN"]).resolve(
            strict=True
        )
        setup_executable = Path(
            os.environ.get(
                "MEMORY_VAULT_RCLONE_SETUP_BIN",
                str(executable),
            )
        ).resolve(strict=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            storage = root / "encrypted-storage"
            wrapped = storage / "memory-vault" / "private"
            wrapped.mkdir(parents=True)
            config_path = root / "rclone.conf"
            config_password = secrets.token_hex(32)

            def invoke(
                *arguments: str,
                input_bytes: bytes | None = None,
                environment: dict[str, str] | None = None,
            ) -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(
                    [str(setup_executable), *arguments],
                    input=input_bytes,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    env=environment,
                    timeout=30,
                )

            def obscured_config_value() -> str:
                # An obscured value may randomly start with "-". The rclone
                # config CLI then treats that positional value as an option,
                # so retry the disposable fixture value rather than making
                # live acceptance flaky.
                for _attempt in range(32):
                    value = invoke(
                        "--config",
                        os.devnull,
                        "obscure",
                        "-",
                        input_bytes=(secrets.token_hex(32) + "\n").encode(),
                    ).stdout.decode("ascii").strip()
                    if value and not value.startswith("-"):
                        return value
                self.fail("could not create a CLI-safe obscured fixture value")

            crypt_password = obscured_config_value()
            crypt_salt = obscured_config_value()
            invoke(
                "--config",
                str(config_path),
                "config",
                "create",
                "base",
                "local",
            )
            invoke(
                "--config",
                str(config_path),
                "config",
                "create",
                "vault_crypt",
                "crypt",
                "remote",
                f"base:{wrapped.as_posix()}",
                "password",
                crypt_password,
                "password2",
                crypt_salt,
                "filename_encryption",
                "standard",
                "directory_name_encryption",
                "true",
                "strict_names",
                "true",
                "pass_bad_blocks",
                "false",
                "--no-obscure",
            )
            del crypt_password, crypt_salt
            invoke(
                "--config",
                str(config_path),
                "config",
                "encryption",
                "set",
                input_bytes=(
                    f"{config_password}\n{config_password}\n".encode()
                ),
            )
            if os.name != "nt":
                config_path.chmod(0o600)
            executable_sha256 = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
            probe = vault_sync._probe_rclone_boundary(
                executable=executable,
                expected_executable_sha256=executable_sha256,
                config_path=config_path,
                remote_name="vault_crypt",
                config_password=config_password,
            )
            config = rclone_config()
            config["adapter_configs"][
                vault_sync.RCLONE_OBJECT_ADAPTER_REF
            ] = {
                "executable": str(executable),
                "executable_sha256": executable_sha256,
                "config_path": str(config_path),
                "remote_name": "vault_crypt",
                "remote_fingerprint": probe["remote_fingerprint"],
                "minimum_version": probe["minimum_version"],
                "verified_version": probe["verified_version"],
            }
            vault_sync._refresh_provider_scope_fingerprints(config)
            config = vault_sync.validate_config(config)
            with mock.patch.object(
                vault_sync,
                "credential_get",
                return_value={"password": config_password},
            ):
                plugin_data = root / "plugin-data"
                adapter = vault_sync.RcloneCryptAdapter(
                    config,
                    data_dir=plugin_data,
                )
                adapter.initialize_private_root(plugin_data)
                payload = (
                    b"large-rclone-live-acceptance\0" * 300_000
                    + os.urandom(4099)
                )
                source = root / "large-source.bin"
                source.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                verified = adapter.upload_and_verify(
                    source,
                    digest,
                    len(payload),
                    "application/octet-stream",
                )
                artifact = {
                    "sha256": digest,
                    "size": len(payload),
                    "mime_type": "application/octet-stream",
                    "storage_ref": vault_sync._storage_ref_from_verified(
                        verified
                    ),
                }
                destination = root / "large-restored.bin"
                adapter.download_and_verify(artifact, destination)
                self.assertEqual(
                    hashlib.sha256(destination.read_bytes()).hexdigest(),
                    digest,
                )
                encrypted_files = [
                    path for path in wrapped.rglob("*") if path.is_file()
                ]
                self.assertGreaterEqual(len(encrypted_files), 2)
                relative_names = "\n".join(
                    path.relative_to(wrapped).as_posix()
                    for path in encrypted_files
                )
                self.assertNotIn("objects", relative_names)
                self.assertNotIn(digest, relative_names)
                for path in encrypted_files:
                    self.assertNotIn(payload[:64], path.read_bytes())
                encrypted_object = max(
                    encrypted_files,
                    key=lambda path: path.stat().st_size,
                )
                ciphertext = encrypted_object.read_bytes()
                encrypted_object.write_bytes(
                    ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
                )
                adapter._verified_lookup_cache.clear()
                with self.assertRaises(vault_sync.VaultSyncError):
                    adapter.download_and_verify(
                        artifact,
                        root / "tampered-download.bin",
                    )

                # Chunking is a separate explicit policy. The same encrypted
                # remote keeps historical whole objects readable while new
                # versions reuse only locally verified plaintext chunks.
                config["sync"]["chunked_artifacts_enabled"] = True
                config["sync"]["chunked_artifact_min_bytes"] = (
                    vault_sync.CHUNK_SIZE_BYTES
                )
                adapter.initialize_chunk_policy()
                first_chunked = root / "first-chunked.bin"
                first_sha, first_size = (
                    ChunkedRcloneAdapterTests._write_fixture(
                        first_chunked,
                        changed_second_chunk=False,
                    )
                )
                with mock.patch.object(
                    adapter,
                    "_fetch_chunk_files",
                    side_effect=AssertionError(
                        "local backend must use ciphertext cryptcheck"
                    ),
                ):
                    first_chunked_verified = adapter.upload_and_verify(
                        first_chunked,
                        first_sha,
                        first_size,
                        "application/octet-stream",
                    )
                self.assertEqual(
                    first_chunked_verified.storage_mode,
                    "chunked-v1",
                )
                second_chunked = root / "second-chunked.bin"
                second_sha, second_size = (
                    ChunkedRcloneAdapterTests._write_fixture(
                        second_chunked,
                        changed_second_chunk=True,
                    )
                )
                with mock.patch.object(
                    adapter,
                    "_fetch_chunk_files",
                    side_effect=AssertionError(
                        "delta upload must not re-download verified chunks"
                    ),
                ):
                    second_chunked_verified = adapter.upload_and_verify(
                        second_chunked,
                        second_sha,
                        second_size,
                        "application/octet-stream",
                    )
                    retry_verified = adapter.upload_and_verify(
                        second_chunked,
                        second_sha,
                        second_size,
                        "application/octet-stream",
                    )
                self.assertEqual(
                    retry_verified.file_id,
                    second_chunked_verified.file_id,
                )
                chunked_artifact = {
                    "storage_mode": "chunked-v1",
                    "sha256": second_sha,
                    "size": second_size,
                    "mime_type": "application/octet-stream",
                    "storage_ref": vault_sync._storage_ref_from_verified(
                        second_chunked_verified
                    ),
                }
                restored_chunked = root / "restored-chunked.bin"
                adapter.download_and_verify(
                    chunked_artifact,
                    restored_chunked,
                )
                self.assertEqual(
                    hashlib.sha256(restored_chunked.read_bytes()).hexdigest(),
                    second_sha,
                )
                encrypted_names_after_chunks = "\n".join(
                    path.relative_to(wrapped).as_posix()
                    for path in wrapped.rglob("*")
                )
                self.assertNotIn("chunks", encrypted_names_after_chunks)
                self.assertNotIn(second_sha, encrypted_names_after_chunks)
if __name__ == "__main__":
    unittest.main()
