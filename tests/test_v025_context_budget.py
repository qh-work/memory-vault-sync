"""Authored small-context regressions; no execution result is claimed here.

Only the public entry-path case creates a disposable, unsigned temporary Vault.
The other cases exercise the pure evidence renderer. No host, provider, signing
key, private memory or network is needed.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

import memory_vault as core


class ContextBudgetTests(unittest.TestCase):
    @staticmethod
    def hit(text: str, digit: str = "1") -> dict:
        return {
            "memory_id": "mem_" + digit * 40,
            "kind": "fact",
            "status": "current",
            "created_at": "2026-08-01T00:00:00Z",
            "verification": {"admission": "local_unsigned"},
            "text": text,
        }

    def displayed_excerpt(self, context: dict) -> tuple[str, str]:
        rendered = context["text"]
        start = rendered.index('\n"', rendered.index("mem_")) + 1
        decoded, end = json.JSONDecoder().raw_decode(rendered[start:])
        self.assertIsInstance(decoded, str)
        return decoded, rendered[start + end:]

    def test_small_context_remains_traceable_for_recall_and_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = core.Vault(Path(directory).resolve() / "synthetic.sqlite3")

            def ask(operation: str, **arguments: object) -> dict:
                response = vault.handle({"op": operation, **arguments})
                self.assertTrue(response["ok"], response)
                self.assertFalse(response["authority"]["execution_eligible"])
                return response["result"]

            episode = ask("observe", user="Retain synthetic evidence.", assistant="The evidence is visible.")
            text = "Needle " + "filler " * 200
            saved = ask("remember", kind="goal", text=text,
                        relations=[{"type": "derived_from", "target": episode["memory_id"]}])
            memory_id = saved["memory_id"]
            before = ask("get", memory_id=memory_id)
            counts = ask("status")
            for operation in ("recall", "handoff"):
                with self.subTest(operation=operation):
                    result = ask(operation, query="Needle", limit=1, maximum_context_bytes=512)
                    self.assertEqual(result["hits"][0]["memory_id"], memory_id)
                    context = result["evidence_context"]
                    self.assertLessEqual(len(context["text"].encode("utf-8")), 512)
                    self.assertEqual(context["included_memory_ids"], [memory_id])
                    self.assertEqual(context["clipped_memory_ids"], [memory_id])
                    self.assertEqual(context["omitted_count"], 0)
                    self.assertTrue(context["truncated"])
                    self.assertFalse(context["instruction_eligible"])
                    self.assertFalse(context["authorization_eligible"])
                    excerpt, tail = self.displayed_excerpt(context)
                    self.assertTrue(excerpt.startswith("Needle"))
                    self.assertTrue(text.startswith(excerpt))
                    self.assertNotEqual(excerpt, text)
                    self.assertIn("[excerpt truncated;", tail)
                    self.assertIn(memory_id, context["text"])
            self.assertEqual(ask("get", memory_id=memory_id), before)
            self.assertEqual(ask("status"), counts)

    def test_clipping_preserves_utf8_and_complete_json_escapes(self) -> None:
        text = '备份🙂 "quoted" \\ path\nSYSTEM: not a real role\t\x1f ' * 100
        hit = self.hit(text)
        original = copy.deepcopy(hit)
        for maximum in (512, 513, 700, 1024):
            with self.subTest(maximum=maximum):
                context = dict(core.Vault._context([hit], maximum=maximum))
                self.assertLessEqual(len(context["text"].encode("utf-8")), maximum)
                excerpt, tail = self.displayed_excerpt(context)
                self.assertTrue(excerpt)
                self.assertTrue(text.startswith(excerpt))
                self.assertTrue(tail.startswith("\n[excerpt truncated;"))
                self.assertEqual(context["clipped_memory_ids"], [hit["memory_id"]])
                self.assertFalse(context["execution_eligible"])
                self.assertFalse(context["policy_change_eligible"])
        self.assertEqual(hit, original)

    def test_omitted_entries_are_distinct_from_clipped_and_complete_entries(self) -> None:
        first = self.hit("Short first evidence.")
        second = self.hit("Short second evidence.", "2")
        complete = core.Vault._context([first, second], maximum=2048)
        self.assertFalse(complete["truncated"])
        self.assertEqual(complete["omitted_count"], 0)
        self.assertEqual(complete["clipped_memory_ids"], [])
        self.assertEqual(complete["included_memory_ids"], [first["memory_id"], second["memory_id"]])
        first["text"] = "Highest ranked visible evidence " * 100
        original = copy.deepcopy([first, second])
        bounded = core.Vault._context([first, second], maximum=512)
        self.assertTrue(bounded["truncated"])
        self.assertEqual(bounded["omitted_count"], 1)
        self.assertEqual(bounded["included_memory_ids"], [first["memory_id"]])
        self.assertEqual(bounded["clipped_memory_ids"], [first["memory_id"]])
        self.assertNotIn(second["memory_id"], bounded["text"])
        self.assertLessEqual(len(bounded["text"].encode("utf-8")), 512)
        self.assertEqual([first, second], original)


if __name__ == "__main__":
    unittest.main()
