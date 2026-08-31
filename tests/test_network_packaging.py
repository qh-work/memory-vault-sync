"""Scoped packaging contracts, without release creation or installation.

Read explicit source lists, then exercise the real launcher in a disposable
runtime assembled for this test only. No ReleaseSource check is bypassed and
no release builder runs. The temporary runtime is not a verified release.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build_client_plugin.py"
RELEASE = ROOT / "scripts/build_release.py"
LAUNCHER = ROOT / "plugins/memory-vault-client/scripts/launcher.py"
NEW_MODULES = {"memory_vault_nodes.py", "memory_vault_node.py", "memory_vault_network_recovery.py", "memory_vault_node_transfer.py",
               "memory_vault_topics.py", "memory_vault_topic_store.py"}
TS_NETWORK = {"clients/typescript/network/" + name for name in
              ("README.md", "crypto.ts", "control.ts", "package.json", "package-lock.json",
               "io.ts", "nodes.ts", "peer.ts", "records.ts", "transport.ts", "vault.ts", "setup.ts",
               "agent.ts", "retrieval.ts", "retrieval_text.ts", "ranking_math.ts", "topics.ts")}
TS_ENDPOINT_TESTS = {"tests/test_network_typescript_" + name + ".py" for name in
                     ("nodes", "records", "vault", "peer", "peer_race", "transport", "setup",
                      "retrieval_text", "retrieval", "agent", "agent_network", "topics")}


def literal(path, name):
    tree = ast.parse(path.read_bytes(), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return ast.literal_eval(node.value)
    raise AssertionError("missing source constant: " + name)


class NetworkPackagingTests(unittest.TestCase):
    def test_runtime_allowlists_include_new_import_closure(self):
        required = literal(BUILDER, "REQUIRED_MODULES")
        optional = literal(BUILDER, "OPTIONAL_MODULES")
        allowed = literal(LAUNCHER, "ALLOWED_MODULES")
        self.assertEqual(len(required), len(set(required)))
        self.assertEqual(set(required) | set(optional), allowed)
        self.assertEqual(len(allowed), 46)
        self.assertTrue(NEW_MODULES <= allowed)
        for name in allowed:
            path = ROOT / name
            self.assertTrue(path.is_file() and not path.is_symlink(), name)
            self.assertLessEqual(path.stat().st_size, 1024 * 1024, name)
            # Local imports, including lazy server/control imports, must resolve
            # inside the same flat runtime after leaving the source checkout.
            tree = ast.parse(path.read_bytes(), filename=name)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            missing = {module + ".py" for module in imported if module.startswith("memory_vault")
                       and "." not in module} - allowed
            self.assertFalse(missing, (name, sorted(missing)))

    def test_new_sdk_docs_and_review_fixtures_are_explicit_public_paths(self):
        documents = literal(BUILDER, "PACKAGE_DOCUMENTS")
        protocol = literal(RELEASE, "PROTOCOL_DOCUMENTS")
        review = literal(RELEASE, "NETWORK_REVIEW_TESTS")
        self.assertEqual(len(documents), len(set(documents)))
        self.assertEqual(len(review), len(set(review)))
        self.assertEqual(len(review), 36)
        self.assertEqual(len(TS_NETWORK), 17)
        self.assertTrue(TS_NETWORK <= set(documents))
        self.assertTrue(TS_ENDPOINT_TESTS <= set(review))
        self.assertIn("docs/NETWORK_TYPESCRIPT.md", documents)
        self.assertIn("docs/NETWORK_TYPESCRIPT.md", protocol)
        self.assertIn("docs/RETRIEVAL_V2.md", documents)
        self.assertIn("docs/RETRIEVAL_V2.md", protocol)
        self.assertIn("docs/NETWORK_TOPICS.md", documents)
        self.assertIn("docs/NETWORK_TOPICS.md", protocol)
        self.assertTrue({"tests/test_network_topics.py", "tests/test_network_topic_store.py",
                         "tests/test_network_topic_http.py"} <= set(review))
        self.assertTrue({"tests/test_network_ranking_v2.py", "tests/test_network_storage_receipts.py"} <= set(review))
        self.assertIn("docs/NETWORK_RECOVERY.md", documents)
        self.assertIn("docs/NETWORK_RECOVERY.md", protocol)
        self.assertIn("docs/NETWORK_NODE_TRANSFER.md", documents)
        self.assertIn("docs/NETWORK_NODE_TRANSFER.md", protocol)
        self.assertTrue({"tests/test_network_client_race.py", "tests/test_network_nodes.py", "tests/test_network_node_runtime.py",
                         "tests/test_network_node_setup.py", "tests/test_network_node_transfer.py",
                         "tests/test_network_recovery.py", "tests/test_network_replica_repair.py", "tests/test_network_typescript_crypto.py",
                         "tests/test_network_typescript_control.py", "tests/test_network_packaging.py"} <= set(review))
        # Public client material uses a fixed file list, never a recursive SDK
        # directory copy that could accidentally include installed dependencies.
        listed_sdk = {name for name in documents if name.startswith("clients/typescript/network/")}
        self.assertEqual(listed_sdk, TS_NETWORK)
        # All local native SDK imports must survive the explicit-file package.
        # This does not invoke a compiler, dependency installer or application.
        for name in listed_sdk:
            if not name.endswith(".ts"):
                continue
            source = (ROOT / name).read_text()
            for relative in re.findall(r"\b(?:from|import)\s*['\"](\./[^'\"]+)['\"]", source):
                imported = (Path(name).parent / relative).as_posix()
                self.assertIn(imported, listed_sdk, (name, relative))
        forbidden = {"node_modules", "__pycache__", ".git", ".env", "client.json", "rclone.conf"}
        for name in set(documents) | set(protocol) | set(review):
            path = ROOT / name
            self.assertTrue(path.is_file() and not path.is_symlink(), name)
            self.assertFalse(set(Path(name).parts) & forbidden, name)
            self.assertNotIn(path.suffix, {".db", ".sqlite", ".sqlite3", ".pyc", ".pyo"}, name)
        self.assertFalse({Path(name).suffix for name in protocol} & {".py", ".ts", ".js"})
        source = RELEASE.read_text()
        self.assertNotIn('.glob("test_network_*.py")', source)
        self.assertIn("paths.extend(ROOT / name for name in NETWORK_REVIEW_TESTS)", source)
        # Parse package/lock metadata from public source, without invoking npm.
        for name in listed_sdk:
            if name.endswith(".json"):
                self.assertIsInstance(json.loads((ROOT / name).read_bytes()), dict)

    def test_ordinary_client_profiles_do_not_install_server_dependencies(self):
        def dependencies(relative, seen=None):
            seen = set() if seen is None else seen
            if relative in seen:
                return set()
            seen.add(relative)
            path = ROOT / relative
            found = set()
            for line in path.read_text().splitlines():
                line = line.strip()
                if line.startswith("-r "):
                    child = (path.parent / line[3:].strip()).relative_to(ROOT).as_posix()
                    found.update(dependencies(child, seen))
                matched = re.match(r"([A-Za-z0-9_.-]+)(?:==|>=|~=)", line)
                if matched:
                    found.add(matched.group(1).lower().replace("_", "-"))
            return found
        for profile in ("requirements-network.txt", "requirements-network-lock.txt"):
            self.assertFalse(dependencies(profile) & {"starlette", "uvicorn", "click"}, profile)
        self.assertTrue({"starlette", "uvicorn"} <= dependencies("requirements-network-server.txt"))
        http_sdk = json.loads((ROOT / "clients/typescript/package.json").read_bytes())
        crypto_sdk = json.loads((ROOT / "clients/typescript/network/package.json").read_bytes())
        self.assertFalse(http_sdk.get("dependencies"))
        self.assertEqual(crypto_sdk.get("dependencies"), {"jose": "6.2.10"})
        self.assertFalse(set(crypto_sdk.get("scripts", {})) & {"preinstall", "install", "postinstall", "prepare"})

    def test_isolated_source_runtime_launcher_and_strict_inventory(self):
        modules = literal(BUILDER, "REQUIRED_MODULES")
        with tempfile.TemporaryDirectory(prefix="memory-packaging-contract-synthetic-") as temporary:
            root = Path(temporary).resolve()
            runtime, scripts = root / "runtime", root / "scripts"
            runtime.mkdir()
            scripts.mkdir()
            launcher = scripts / "launcher.py"
            launcher.write_bytes(LAUNCHER.read_bytes())
            hashes = {}
            for name in modules:
                data = (ROOT / name).read_bytes()
                (runtime / name).write_bytes(data)
                hashes[name] = hashlib.sha256(data).hexdigest()
            (runtime / "MANIFEST.json").write_text(json.dumps({"schema_version": "memory-vault-client-runtime/v1", "modules": hashes}))
            config = root / "must-not-be-created.json"
            command = [sys.executable, "-I", "-S", "-B", str(launcher), "--config", str(config), "agent", "request"]
            def launch():
                return subprocess.run(command, input=b'{"op":"discover"}\n', stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, cwd=root, timeout=20)
            result = launch()
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b"")
            answer = json.loads(result.stdout)
            self.assertTrue(answer["ok"], answer)
            self.assertFalse(answer["result"]["network_accessed"])
            self.assertFalse(config.exists())
            # The packaged client's new recovery command must be reachable
            # without reading a config or installing network/server extras.
            help_result = subprocess.run(command[:-2] + ["network-recovery", "--help"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, timeout=20)
            self.assertEqual(help_result.returncode, 0, help_result.stderr.decode())
            self.assertEqual(help_result.stderr, b"")
            self.assertIn(b"backup", help_result.stdout)
            self.assertIn(b"restore", help_result.stdout)
            self.assertFalse(config.exists())
            probe = """import importlib,json,sys
sys.path.insert(0,sys.argv[1])
for name in ('memory_vault_nodes','memory_vault_node','memory_vault_network_recovery','memory_vault_node_transfer'):
    importlib.import_module(name)
print(json.dumps({'optional_loaded': sorted(set(sys.modules)&{'cryptography','joserfc','httpx','starlette','uvicorn'})}))
"""
            imported = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", probe, str(runtime)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, timeout=20)
            self.assertEqual(imported.returncode, 0, imported.stderr.decode())
            self.assertEqual(json.loads(imported.stdout)["optional_loaded"], [])
            for name in ("node_modules", "__pycache__", "client.json"):
                extra = runtime / name
                if name.endswith(".json"):
                    extra.write_text('{"synthetic":true}')
                else:
                    extra.mkdir()
                try:
                    self.assertEqual(launch().returncode, 1, name)
                finally:
                    extra.unlink() if extra.is_file() else extra.rmdir()
            target = runtime / "memory_vault_network_recovery.py"
            data = target.read_bytes()
            target.write_bytes(data + b"\n# Synthetic tampering for inventory verification.\n")
            self.assertEqual(launch().returncode, 1)
            target.unlink()
            self.assertEqual(launch().returncode, 1)
            self.assertFalse(config.exists())
            self.assertFalse(list(root.rglob("__pycache__")))
            self.assertFalse(list(root.rglob("*.sqlite3")))


if __name__ == "__main__":
    unittest.main()
