from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "scripts" / "export_open_source_bundle.py"
EXPORTER_SPEC = importlib.util.spec_from_file_location(
    "memory_vault_source_exporter",
    EXPORTER,
)
assert EXPORTER_SPEC is not None and EXPORTER_SPEC.loader is not None
source_exporter = importlib.util.module_from_spec(EXPORTER_SPEC)
EXPORTER_SPEC.loader.exec_module(source_exporter)


class OpenSourceExportTests(unittest.TestCase):
    def test_maintained_public_license_is_apache_2_0(self) -> None:
        license_path = ROOT / "open_source/LICENSE"
        if not license_path.is_file():
            # A generated public tree has already promoted the reviewed
            # source license to the repository root.
            license_path = ROOT / "LICENSE"
        license_text = license_path.read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("Grant of Patent License", license_text)

    def test_committed_chunk_benchmark_covers_release_acceptance_sizes(
        self,
    ) -> None:
        evidence = json.loads(
            (ROOT / "benchmarks/chunk-protocol-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            evidence["schema_version"],
            "memory-vault-chunk-benchmark/v1",
        )
        scenarios = {
            item["artifact_mib"]: item for item in evidence["scenarios"]
        }
        self.assertEqual(set(scenarios), {100, 1024})
        for size_mib, scenario in scenarios.items():
            with self.subTest(size_mib=size_mib):
                self.assertEqual(scenario["change_ratio"], 0.01)
                self.assertEqual(
                    scenario["one_percent_change"]["changed_chunk_count"],
                    1,
                )
                self.assertEqual(
                    scenario["one_percent_change"]["transferred_bytes"],
                    16 * 1024 * 1024,
                )
                self.assertEqual(
                    scenario["interrupted_retry"][
                        "retry_transferred_bytes"
                    ],
                    0,
                )
                self.assertFalse(
                    scenario["interrupted_retry"][
                        "remote_deletion_performed"
                    ]
                )
                self.assertTrue(
                    scenario["restore"]["final_sha256_verified"]
                )

    def test_rebrand_target_may_contain_the_source_display_name(self) -> None:
        source = source_exporter.PRIVATE_MARKETPLACE_DISPLAY_NAME
        target = f"Fixture {source}"
        transformed = source_exporter._transform_text(
            f"display={source}\n".encode("utf-8"),
            ((source, target),),
        ).decode("utf-8")
        self.assertEqual(transformed, f"display={target}\n")

    def test_export_is_allow_listed_rebranded_and_private_state_free(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-vault-public-export-") as raw:
            temporary = Path(raw)
            target_author = "fixture-public-org"
            if target_author == source_exporter.PRIVATE_AUTHOR:
                target_author = "fixture-public-alt"
            target_repository_id = f"{target_author}/team/memory-vault-sync"
            target_repository_url = (
                f"https://gitlab.com/{target_repository_id}.git"
            )
            target_marketplace = f"{target_author}-memory"
            # Keep the end-to-end leak assertion unambiguous: a separate unit
            # test above covers targets that intentionally contain the source
            # display label.
            target_marketplace_display = "Fixture Sync Package"
            if (
                target_marketplace_display
                == source_exporter.PRIVATE_MARKETPLACE_DISPLAY_NAME
            ):
                target_marketplace_display = "Alternate Memory Vault"
            license_file = temporary / "LICENSE.input"
            license_file.write_text(
                "Example permissive license for an isolated test.\n",
                encoding="utf-8",
            )
            destination = temporary / "public-source"
            result = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--destination",
                    str(destination),
                    "--repository-id",
                    target_repository_id,
                    "--repository-url",
                    target_repository_url,
                    "--author",
                    target_author,
                    "--marketplace-name",
                    target_marketplace,
                    "--marketplace-display-name",
                    target_marketplace_display,
                    "--license-file",
                    str(license_file),
                ],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            manifest = json.loads(result.stdout)
            self.assertTrue(manifest["ok"])
            self.assertFalse(manifest["private_state_included"])
            self.assertEqual(
                manifest["control_privacy_verifier"],
                "gitlab-private-v1",
            )
            self.assertEqual(manifest["control_credential_host"], "gitlab.com")
            self.assertTrue((destination / "LICENSE").is_file())
            self.assertTrue((destination / "README.md").is_file())
            self.assertTrue((destination / "STATUS.md").is_file())
            self.assertTrue((destination / "ROADMAP.md").is_file())
            self.assertTrue((destination / "CHANGELOG.md").is_file())
            self.assertTrue((destination / "CONTRIBUTING.md").is_file())
            self.assertTrue((destination / "AGENTS.md").is_file())
            self.assertTrue((destination / "CLAUDE.md").is_file())
            self.assertTrue((destination / "GEMINI.md").is_file())
            self.assertTrue((destination / "llms.txt").is_file())
            self.assertTrue((destination / "CODE_OF_CONDUCT.md").is_file())
            self.assertTrue((destination / "NOTICE").is_file())
            self.assertTrue((destination / "SUPPORT.md").is_file())
            self.assertTrue((destination / "CHUNK_PROTOCOL.md").is_file())
            self.assertTrue(
                (destination / "HOST_ADAPTER_PROTOCOL.md").is_file()
            )
            self.assertTrue(
                (destination / "schemas/memory_host_request.schema.json").is_file()
            )
            self.assertTrue(
                (destination / "schemas/memory_host_response.schema.json").is_file()
            )
            self.assertTrue(
                (
                    destination
                    / "plugins/memory-vault-sync/adapters/tests/test_reference_adapters.py"
                ).is_file()
            )
            self.assertTrue(
                (destination / "PRIVATE_DIAGNOSTICS.md").is_file()
            )
            self.assertTrue(
                (destination / "SIGNED_UPDATES.md").is_file()
            )
            self.assertTrue(
                (destination / "benchmarks/chunk-protocol-v1.json").is_file()
            )
            benchmark_script = (
                destination / "scripts/benchmark_chunk_protocol.py"
            )
            self.assertTrue(benchmark_script.is_file())
            public_workflow = (
                destination / ".github/workflows/memory-vault-sync.yml"
            )
            self.assertTrue(public_workflow.is_file())
            self.assertTrue((destination / ".github/CODEOWNERS").is_file())
            self.assertTrue(
                (destination / ".github/ISSUE_TEMPLATE/bug_report.yml").is_file()
            )
            self.assertTrue(
                (destination / ".github/ISSUE_TEMPLATE/feature_request.yml").is_file()
            )
            self.assertTrue(
                (destination / ".github/pull_request_template.md").is_file()
            )
            self.assertNotIn(
                "Validate complete vault layout",
                public_workflow.read_text(encoding="utf-8"),
            )
            self.assertTrue(
                (destination / "plugins/memory-vault-sync/scripts/vault_sync.py").is_file()
            )
            for forbidden in (
                "bindings",
                "handoffs",
                "instances",
                "memory",
                "migration",
                "sources",
                "tasks",
            ):
                self.assertFalse((destination / forbidden).exists())
            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in destination.rglob("*")
                if path.is_file()
                and path.name != "LICENSE"
                and path.suffix not in {".pyc"}
            )
            for source_identity in (
                source_exporter.PRIVATE_REPOSITORY_ID,
                source_exporter.PRIVATE_REPOSITORY_URL,
                source_exporter.PRIVATE_AUTHOR,
                source_exporter.PRIVATE_MARKETPLACE,
                source_exporter.PRIVATE_MARKETPLACE_DISPLAY_NAME,
            ):
                self.assertNotIn(source_identity, combined)
            self.assertIn(target_repository_id, combined)
            self.assertIn(target_marketplace_display, combined)
            issue_config = (
                destination / ".github/ISSUE_TEMPLATE/config.yml"
            ).read_text(encoding="utf-8")
            self.assertIn(
                f"https://gitlab.com/{target_repository_id}",
                issue_config,
            )
            self.assertNotIn(
                source_exporter.PUBLIC_RELEASE_REPOSITORY_ID,
                issue_config,
            )
            marketplace_document = json.loads(
                (
                    destination / ".agents/plugins/marketplace.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                marketplace_document["interface"]["displayName"],
                target_marketplace_display,
            )
            runtime = (
                destination
                / "plugins/memory-vault-sync/scripts/memory_vault_runtime/core.py"
            ).read_text(encoding="utf-8")
            self.assertIn(
                'DEPLOYMENT_CONTROL_PRIVACY_VERIFIER = "gitlab-private-v1"',
                runtime,
            )
            self.assertIn(
                'DEPLOYMENT_CONTROL_CREDENTIAL_HOST = "gitlab.com"',
                runtime,
            )
            module_path = (
                destination
                / "plugins/memory-vault-sync/scripts/vault_sync.py"
            )
            spec = importlib.util.spec_from_file_location(
                "public_export_vault_sync",
                module_path,
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            private_runtime_modules = {
                name: loaded
                for name, loaded in sys.modules.items()
                if name == "memory_vault_runtime"
                or name.startswith("memory_vault_runtime.")
            }
            for name in private_runtime_modules:
                sys.modules.pop(name, None)
            sys.modules[spec.name] = module
            try:
                spec.loader.exec_module(module)
                exported_config = module.validate_config(
                    module.default_config()
                )
            finally:
                sys.modules.pop(spec.name, None)
                for name in tuple(sys.modules):
                    if name == "memory_vault_runtime" or name.startswith(
                        "memory_vault_runtime."
                    ):
                        sys.modules.pop(name, None)
                sys.modules.update(private_runtime_modules)
            control = module._control_plane_config(exported_config)
            self.assertEqual(control["privacy_verifier"], "gitlab-private-v1")
            self.assertEqual(control["credential_host"], "gitlab.com")
            benchmark = subprocess.run(
                [
                    sys.executable,
                    str(benchmark_script),
                    "--size-mib",
                    "32",
                ],
                cwd=str(destination),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(
                benchmark.returncode,
                0,
                benchmark.stderr or benchmark.stdout,
            )
            benchmark_result = json.loads(benchmark.stdout)
            self.assertEqual(
                benchmark_result["schema_version"],
                "memory-vault-chunk-benchmark/v1",
            )
            self.assertTrue(
                benchmark_result["scenarios"][0]["restore"][
                    "final_sha256_verified"
                ]
            )

    def test_export_refuses_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-vault-public-export-") as raw:
            temporary = Path(raw)
            license_file = temporary / "LICENSE.input"
            license_file.write_text("test license\n", encoding="utf-8")
            destination = temporary / "existing"
            destination.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--destination",
                    str(destination),
                    "--repository-id",
                    "example-org/memory-vault-sync",
                    "--repository-url",
                    "https://example.com/example-org/memory-vault-sync.git",
                    "--author",
                    "example-org",
                    "--marketplace-name",
                    "example-memory",
                    "--marketplace-display-name",
                    "Example Memory Vault",
                    "--license-file",
                    str(license_file),
                ],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("destination already exists", result.stdout)

    def test_export_refuses_host_without_bundled_privacy_verifier(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-vault-public-export-") as raw:
            temporary = Path(raw)
            license_file = temporary / "LICENSE.input"
            license_file.write_text("test license\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--destination",
                    str(temporary / "unsupported-host"),
                    "--repository-id",
                    "example-org/memory-vault-sync",
                    "--repository-url",
                    "https://example.com/example-org/memory-vault-sync.git",
                    "--author",
                    "example-org",
                    "--marketplace-name",
                    "example-memory",
                    "--marketplace-display-name",
                    "Example Memory Vault",
                    "--license-file",
                    str(license_file),
                ],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("support GitHub.com or GitLab.com", result.stdout)

    def test_export_refuses_nested_github_repository_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-vault-public-export-") as raw:
            temporary = Path(raw)
            license_file = temporary / "LICENSE.input"
            license_file.write_text("test license\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--destination",
                    str(temporary / "nested-github"),
                    "--repository-id",
                    "example-org/team/memory-vault-sync",
                    "--repository-url",
                    "https://github.com/example-org/team/memory-vault-sync.git",
                    "--author",
                    "example-org",
                    "--marketplace-name",
                    "example-memory",
                    "--marketplace-display-name",
                    "Example Memory Vault",
                    "--license-file",
                    str(license_file),
                ],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("exactly owner/repository", result.stdout)


if __name__ == "__main__":
    unittest.main()
