from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = PLUGIN_ROOT / "scripts" / "vault_sync.py"
MANIFEST = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"


def load_entrypoint() -> object:
    spec = importlib.util.spec_from_file_location(
        "memory_vault_sync_module_contract",
        ENTRYPOINT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RuntimeModuleContractTests(unittest.TestCase):
    """Characterize public behavior before the runtime is split."""

    def test_entrypoint_version_matches_manifest(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        process = subprocess.run(
            [sys.executable, str(ENTRYPOINT), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, b"")
        self.assertEqual(
            process.stdout.decode("utf-8", "strict").strip(),
            manifest["version"],
        )

    def test_entrypoint_preserves_required_cli_commands(self) -> None:
        process = subprocess.run(
            [sys.executable, str(ENTRYPOINT), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, b"")
        help_text = process.stdout.decode("utf-8", "strict")
        for command in (
            "configure",
            "configure-rclone-store",
            "auth-control",
            "auth-drive",
            "auth-rclone",
            "init-object-store",
            "configure-chunking",
            "diagnostics",
            "configure-update-trust",
            "update-trust-status",
            "recall",
            "views",
            "pack-network",
            "import-pack",
            "copy-pack",
            "checkpoint-pack",
            "verify-checkpoint",
            "share-network",
            "verify-share-envelope",
            "trust-init",
            "trust-status",
            "export-network",
            "import-network",
            "remember",
            "flush",
            "host-adapter",
            "status",
            "update",
            "doctor",
            "hook",
        ):
            with self.subTest(command=command):
                self.assertIn(command, help_text)
        for retired in (
            "legacy-bind",
            "routing-candidates",
            "confirm-routing-match",
            "prepare-native-handoff",
            "switch-task-route",
            "show-memory-projection",
            "reconcile-memory",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, help_text)

    def test_protocol_hash_bytes_are_unchanged(self) -> None:
        runtime = load_entrypoint()
        value = {
            "emoji": "记忆🔐",
            "nested": [None, True, False, 7],
            "order": {"z": 1, "a": 2},
        }
        expected = (
            '{"emoji":"记忆🔐","nested":[null,true,false,7],'
            '"order":{"a":2,"z":1}}'
        ).encode("utf-8")
        self.assertEqual(runtime.jcs_json_bytes(value), expected)
        self.assertEqual(
            runtime.sha256_jcs(value),
            hashlib.sha256(expected).hexdigest(),
        )

    def test_unconfigured_session_hook_json_matches_network_identity(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-module-contract-"
        ) as temporary:
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = str(Path(temporary) / "plugin data")
            environment["MEMORY_VAULT_SYNC_TESTING"] = "1"
            process = subprocess.run(
                [
                    sys.executable,
                    str(ENTRYPOINT),
                    "hook",
                    "session-start",
                ],
                input=json.dumps(
                    {
                        "session_id": "session-characterization",
                        "cwd": str(Path(temporary) / "workspace"),
                        "hook_event_name": "SessionStart",
                        "source": "startup",
                    }
                ).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, b"")
        self.assertEqual(
            json.loads(process.stdout.decode("utf-8", "strict")),
            {
                "continue": True,
                "systemMessage": (
                    "Private Memory Network is installed, but this client has "
                    "not completed its local setup or legacy-data migration."
                ),
            },
        )

    def test_unconfigured_host_capabilities_are_strict_and_network_free(
        self,
    ) -> None:
        request = {
            "schema_version": "memory-vault-host-request/v1",
            "protocol_version": "1.0",
            "request_id": "module-capabilities-001",
            "operation": "capabilities",
            "adapter": {
                "id": "generic-stdio",
                "version": "0.21.0",
                "host_family": "local-model",
            },
            "payload": {},
        }
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-host-contract-"
        ) as temporary:
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = str(Path(temporary) / "plugin data")
            process = subprocess.run(
                [
                    sys.executable,
                    str(ENTRYPOINT),
                    "host-adapter",
                    "--request-stdin",
                ],
                input=json.dumps(request).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, b"")
        response = json.loads(process.stdout.decode("utf-8", "strict"))
        self.assertEqual(response["status"], "accepted_local")
        self.assertIn(
            "turn.input", response["result"]["network_free_operations"]
        )
        self.assertIn(
            "turn.commit", response["result"]["network_free_operations"]
        )
        self.assertFalse(response["authority"]["instruction_eligible"])
        self.assertFalse(response["authority"]["authorization_eligible"])
        self.assertFalse(response["authority"]["execution_eligible"])

    def test_host_stdio_rejects_duplicate_json_keys_without_traceback(self) -> None:
        duplicate = (
            '{"schema_version":"memory-vault-host-request/v1",'
            '"protocol_version":"1.0","request_id":"duplicate-001",'
            '"request_id":"duplicate-002","operation":"capabilities",'
            '"adapter":{"id":"generic-stdio","version":"0.21.0",'
            '"host_family":"local-model"},"payload":{}}'
        ).encode("utf-8")
        with tempfile.TemporaryDirectory(
            prefix="memory-vault-host-invalid-"
        ) as temporary:
            environment = os.environ.copy()
            environment["PLUGIN_DATA"] = str(Path(temporary) / "plugin data")
            process = subprocess.run(
                [
                    sys.executable,
                    str(ENTRYPOINT),
                    "host-adapter",
                    "--request-stdin",
                ],
                input=duplicate,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, b"")
        response = json.loads(process.stdout.decode("utf-8", "strict"))
        self.assertEqual(response["status"], "rejected")
        self.assertEqual(response["error"]["code"], "host_protocol")
        self.assertNotIn("message", response["error"])


if __name__ == "__main__":
    unittest.main()
