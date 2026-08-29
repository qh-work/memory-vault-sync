from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "memory_vault.py"


class UniversalMemoryTests(unittest.TestCase):
    def request(self, database: Path, value: dict[str, object]) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--vault", str(database)],
            input=(json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout.decode("utf-8"))

    def command(self, database: Path, *arguments: str) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--vault",
                str(database),
                *arguments,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout.decode("utf-8"))

    def test_capabilities_are_zero_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "vault.sqlite3"
            response = self.request(database, {"op": "capabilities"})
            self.assertTrue(response["ok"])
            self.assertFalse(database.exists())
            identified = self.request(
                database,
                {"op": "capabilities", "request_id": "req_capability_0001"},
            )
            self.assertTrue(identified["ok"])
            self.assertEqual(identified["request_id"], "req_capability_0001")
            self.assertFalse(database.exists())
            result = response["result"]
            self.assertFalse(result["plugin_required"])
            self.assertFalse(result["git_required"])
            self.assertFalse(result["network_required"])

    def test_goal_crosses_independent_agent_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "vault.sqlite3"
            episode = self.request(
                database,
                {
                    "op": "observe",
                    "request_id": "req_goal_evidence_0001",
                    "user": "让目标可以跨模型接力",
                    "assistant": "记录可见证据，再记录目标",
                },
            )
            self.assertTrue(episode["ok"])
            stored = self.request(
                database,
                {
                    "op": "remember",
                    "request_id": "req_cross_model_goal_0001",
                    "kind": "goal",
                    "text": "让不同 AI 模型共同完成通用外部记忆协议",
                    "entities": ["外部记忆", "cross-model"],
                    "relations": [
                        {
                            "type": "derived_from",
                            "target": episode["result"]["memory_id"],
                        }
                    ],
                },
            )
            self.assertTrue(stored["ok"])
            self.assertEqual(stored["request_id"], "req_cross_model_goal_0001")
            distractor = self.request(
                database,
                {
                    "op": "remember",
                    "kind": "fact",
                    "text": "zebra-only semantic match",
                },
            )
            self.assertTrue(distractor["ok"])
            recalled = self.request(
                database,
                {
                    "op": "handoff",
                    "query": "zebra-only semantic match",
                    "limit": 1,
                },
            )
            self.assertTrue(recalled["ok"])
            hits = recalled["result"]["hits"]
            self.assertEqual(hits[0]["kind"], "goal")
            self.assertIn("通用外部记忆协议", hits[0]["text"])
            self.assertFalse(recalled["authority"]["execution_eligible"])

    def test_request_retry_is_exact_and_conflict_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "vault.sqlite3"
            request = {
                "op": "remember",
                "request_id": "req_exact_retry_0001",
                "kind": "decision",
                "text": "Use one taskless Vault",
            }
            first = self.request(database, request)
            second = self.request(database, request)
            self.assertEqual(first, second)
            self.assertEqual(first["request_id"], "req_exact_retry_0001")
            conflict = self.request(database, {**request, "text": "Changed bytes"})
            self.assertFalse(conflict["ok"])
            self.assertEqual(conflict["error"]["code"], "request_id_conflict")
            status = self.request(database, {"op": "status"})
            self.assertEqual(status["result"]["records"], 1)

    def test_bundle_transfers_memory_to_another_vault(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_database = root / "first.sqlite3"
            second_database = root / "second.sqlite3"
            bundle = root / "memory.ndjson"
            observed = self.request(
                first_database,
                {
                    "op": "observe",
                    "request_id": "req_visible_turn_0001",
                    "user": "Remember the portable handoff",
                    "assistant": "The next agent can import the NDJSON bundle",
                },
            )
            self.assertTrue(observed["ok"])
            exported = self.command(first_database, "--export", str(bundle))
            self.assertTrue(exported["ok"])
            imported = self.command(second_database, "--import", str(bundle))
            self.assertTrue(imported["ok"])
            recalled = self.request(
                second_database,
                {"op": "recall", "query": "portable NDJSON handoff", "limit": 4},
            )
            self.assertTrue(recalled["ok"])
            self.assertIn("NDJSON bundle", recalled["result"]["hits"][0]["text"])

    def test_authority_shaped_provenance_is_refused_without_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "vault.sqlite3"
            secret = "synthetic-secret-value"
            response = self.request(
                database,
                {
                    "op": "remember",
                    "kind": "fact",
                    "text": "Synthetic safe text",
                    "provenance": {"token": secret},
                },
            )
            self.assertFalse(response["ok"])
            self.assertEqual(
                response["error"]["code"], "forbidden_provenance_field"
            )
            self.assertNotIn(secret, json.dumps(response))
            forged = self.request(
                database,
                {
                    "op": "remember",
                    "kind": "fact",
                    "text": "Synthetic safe text",
                    "provenance": {"authorization_eligible": "true"},
                },
            )
            self.assertFalse(forged["ok"])
            self.assertEqual(
                forged["error"]["code"], "forbidden_provenance_field"
            )


if __name__ == "__main__":
    unittest.main()
