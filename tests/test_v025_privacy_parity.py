"""Small synthetic v0.21 publication-guard parity workflow, not real secrets.

The old scanner families are source-derived, not a claim of comprehensive DLP.
All values below are deliberately fake and all records are local temporary
fixtures. No credentials, provider, network, host or default Vault are used.
Execution evidence, if any, is recorded separately in docs/VALIDATION.md.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_vault import MemoryError, Vault, canonical_bytes
from memory_vault_privacy import assert_publishable, review_records


class PrivacyParityTests(unittest.TestCase):
    def test_old_guard_families_block_publication_without_rewriting_local_memory(self) -> None:
        secrets = (
            "github_pat_" + "x" * 20,
            "sk-ant-api03-" + "x" * 20,
            "sk-proj-" + "x" * 20,
            "AIza" + "x" * 20,
            "ASIA" + "A" * 16,
            "ya29." + "x" * 20,
            "GOCSPX-" + "x" * 20,
            "eyJ" + "A" * 8 + "." + "B" * 8 + "." + "C" * 8,
            "Bearer " + "x" * 20,
            "xapp-" + "x" * 10,
            "xoxb-" + "x" * 10,
            "glpat-" + "x" * 20,
            "glrt-" + "x" * 20,
            "gloas-" + "x" * 20,
            "npm_" + "x" * 30,
            "pypi-" + "x" * 20,
            "hf_" + "x" * 30,
            "rk_test_" + "x" * 16,
            "SG." + "x" * 16 + "." + "y" * 16,
            "12345678:" + "x" * 30,
            "dop_v1_" + "a" * 64,
            "sq0atp-" + "x" * 20,
            "Cookie: synthetic=yes",
            "-----BEGIN PRIVATE KEY----- synthetic fixture",
            "--session-token " + "a" * 43,
            "memory-vault-handoff: " + "a" * 43,
            "mvrd_" + "a" * 43,
            "passwd=" + "x" * 12,
            "api-token=" + "x" * 12,
            "webhook-secret=" + "x" * 12,
            "Authorization: Basic " + "x" * 12,
            "Authorization: Basic " + "x" * 11 + "e\u0301",
            "ghp_" + "x" * 19 + "e\u0301",
            "https://synthetic:fixture@example.invalid/",
        )
        paths = ("/root/synthetic", "/mnt/synthetic", "/etc/synthetic", "/workspace/synthetic",
                 "/usr/local/synthetic", "D:\\synthetic", "\\\\synthetic-host\\synthetic-share", "~/synthetic")
        with tempfile.TemporaryDirectory(prefix="memory-vault-v025-privacy-parity-") as temporary:
            vault = Vault(Path(temporary).resolve() / "synthetic.sqlite3")
            saved: dict[str, bytes] = {}
            for value in (*secrets, *paths):
                with self.subTest(family_index=len(saved)):
                    written = vault.handle({"op": "remember", "kind": "fact", "text": "Synthetic only: " + value})
                    self.assertTrue(written["ok"], written)
                    identifier = written["result"]["memory_id"]
                    original = vault.handle({"op": "get", "memory_id": identifier})["result"]["record"]
                    saved[identifier] = canonical_bytes(original)
                    reason = "publication_secret_detected" if value in secrets else "publication_local_path_detected"
                    findings = review_records([original])
                    self.assertEqual(findings[0]["memory_id"], identifier)
                    self.assertIn(reason, findings[0]["reasons"])
                    self.assertNotIn(value, canonical_bytes(findings).decode())
                    with self.assertRaises(MemoryError) as caught:
                        assert_publishable([original])
                    self.assertEqual(caught.exception.code, reason)
                    if value in secrets:
                        with self.assertRaises(MemoryError) as caught:
                            assert_publishable([original], allow_local_paths=True)
                        self.assertEqual(caught.exception.code, "publication_secret_detected")
                    else:
                        assert_publishable([original], approved_local_path_ids=[identifier])
                    restored = vault.handle({"op": "get", "memory_id": identifier})["result"]["record"]
                    self.assertEqual(canonical_bytes(restored), saved[identifier])
            self.assertEqual(vault.handle({"op": "status"})["result"]["records"], len(saved))
            assert_publishable([{"text": "Synthetic documentation: https://example.invalid/guide and relative/file.txt"}])
            # No token is present; whitespace branches must not be nested in
            # the restored pattern. This checks behavior, not a CPU benchmark.
            assert_publishable([{"text": "--session-token" + " " * 4096 + "!"}])


if __name__ == "__main__":
    unittest.main()
