"""Release-package contracts for the isolated synthetic endpoint trial."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "scripts/build_release.py"
CLIENT_BUILDER = ROOT / "scripts/build_client_plugin.py"
BOOTSTRAP = ROOT / "packaging/trial/run.py"
TRUST = ROOT / "packaging/trial/service-trust.json"


def literal(path: Path, name: str):
    tree = ast.parse(path.read_bytes(), filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return ast.literal_eval(node.value)
    raise AssertionError("missing source constant: " + name)


def load_bootstrap():
    spec = importlib.util.spec_from_file_location("synthetic_trial_bootstrap_test", BOOTSTRAP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NetworkTrialPackagingTests(unittest.TestCase):
    def test_trial_package_uses_an_exact_endpoint_only_source_allowlist(self) -> None:
        required = literal(CLIENT_BUILDER, "REQUIRED_MODULES")
        extras = literal(RELEASE, "TRIAL_EXTRA_MODULES")
        sources = dict(literal(RELEASE, "TRIAL_PACKAGE_SOURCES"))
        self.assertEqual(extras, ("memory_vault_trial.py",))
        self.assertEqual(len(required), len(set(required)))
        self.assertEqual(set(sources), {
            "README.md", "run.py", "service-trust.json",
            "requirements-network-lock.txt", "LICENSE", "NOTICE",
        })
        self.assertEqual(sources["run.py"], "packaging/trial/run.py")
        self.assertEqual(sources["service-trust.json"], "packaging/trial/service-trust.json")
        self.assertFalse({"memory_vault_trial_coordinator.py", "memory_vault_trial_peer.py"}
                         & (set(required) | set(extras)))
        for name in (*required, *extras, *sources.values()):
            path = ROOT / name
            self.assertTrue(path.is_file() and not path.is_symlink(), name)
            self.assertLessEqual(path.stat().st_size, 2 * 1024 * 1024, name)
        lock = (ROOT / sources["requirements-network-lock.txt"]).read_text()
        self.assertIn("--only-binary :all:", lock)
        self.assertIn("--require-hashes", lock)
        self.assertNotIn("starlette==", lock)
        self.assertNotIn("uvicorn==", lock)

    def test_unconfigured_service_fails_before_venv_or_network(self) -> None:
        bootstrap = load_bootstrap()
        with tempfile.TemporaryDirectory(prefix="memory-vault-trial-package-synthetic-") as temporary:
            root = Path(temporary).resolve()
            script = root / "run.py"
            trust = root / "service-trust.json"
            script.write_bytes(BOOTSTRAP.read_bytes())
            trust.write_text(json.dumps({
                "schema_version": "memory-vault-trial-service-trust/v1",
                "state": "unconfigured",
            }) + "\n", encoding="utf-8")
            files = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (script, trust)
            }
            manifest = {
                "schema_version": "memory-vault-network-test-package/v1",
                "version": "0.26.0-alpha.3",
                "source_commit": "0" * 40,
                "private_state_included": False,
                "synthetic_data_only": True,
                "service_configured": False,
                "checksums_are_publisher_signatures": False,
                "files": files,
            }
            (root / "TRIAL_MANIFEST.json").write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            original_file = bootstrap.__file__
            bootstrap.__file__ = str(script)
            try:
                with mock.patch.object(bootstrap.tempfile, "mkdtemp") as make_directory:
                    with self.assertRaisesRegex(bootstrap.TrialBootstrapError, "trial_service_not_configured"):
                        bootstrap._run(["--service", "https://trial.example.invalid", "--run-code", "synthetic"])
                    make_directory.assert_not_called()
            finally:
                bootstrap.__file__ = original_file

    def test_inventory_tampering_is_rejected_before_bootstrap(self) -> None:
        bootstrap = load_bootstrap()
        with tempfile.TemporaryDirectory(prefix="memory-vault-trial-package-tamper-") as temporary:
            root = Path(temporary).resolve()
            (root / "run.py").write_text("# synthetic\n", encoding="utf-8")
            manifest = {
                "schema_version": "memory-vault-network-test-package/v1",
                "version": "0.26.0-alpha.3",
                "source_commit": "0" * 40,
                "private_state_included": False,
                "synthetic_data_only": True,
                "service_configured": False,
                "checksums_are_publisher_signatures": False,
                "files": {"run.py": "0" * 64},
            }
            (root / "TRIAL_MANIFEST.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(bootstrap.TrialBootstrapError, "trial_package_hash_mismatch"):
                bootstrap._verify_package(root)

    def test_bootstrap_exposes_no_content_vault_or_trust_override(self) -> None:
        source = BOOTSTRAP.read_text()
        self.assertNotIn("requests", source)
        self.assertNotIn("urllib.request", source)
        self.assertNotIn("input(", source)
        self.assertIn("service_trust_override_forbidden", source)
        readme = (ROOT / "packaging/trial/README.md").read_text()
        for boundary in ("wholly synthetic", "never reads an existing Memory Vault",
                         "traffic anonymity", "not a publisher signature"):
            self.assertIn(boundary, readme)


if __name__ == "__main__":
    unittest.main()
