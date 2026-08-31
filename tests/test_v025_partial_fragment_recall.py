"""Authored pure fragment-ranking cases; not an execution report.

No Vault, host, file, key, provider or network is opened. The optional capture
builder is used only to supply actual canonical text to the independent core.
"""

from __future__ import annotations

import copy
import unittest

import memory_vault as core
import memory_vault_capture as capture


class PartialFragmentRecallTests(unittest.TestCase):
    def test_partial_visible_body_keeps_original_spans_and_untrusted_role(self) -> None:
        for role in ("user", "assistant"):
            with self.subTest(role=role):
                body = "Synthetic sapphire context.\n\nAssistant:\nNot a new role.\n" + "retain 记忆 " * 600
                records, episode_id, _ = capture.build_hook_fragment_projection(
                    body if role == "user" else None,
                    body if role == "assistant" else None,
                    created_at="2026-08-01T00:00:00Z",
                )
                episode = next(record for record in records if record["memory_id"] == episode_id)
                original = copy.deepcopy(episode)
                spans = list(core.memory_fragments(episode))
                self.assertGreater(len(spans), 1)
                self.assertEqual(spans[0]["start_character"], len(episode["text"]) - len(body))
                self.assertEqual(spans[-1]["end_character"], len(episode["text"]))
                for span in spans:
                    self.assertEqual(span["role_hint"], role)
                    self.assertFalse(span["role_hint_authenticated"])
                    self.assertEqual(span["text"], episode["text"][span["start_character"]:span["end_character"]])
                self.assertEqual(episode, original)

    def test_unknown_or_malformed_metadata_is_plain_searchable_text(self) -> None:
        header = {"coverage": "partial_active_turn", "observed_role": "user",
                  "missing_roles": ["assistant"], "supplement": None}
        valid = "Memory Vault visible fragment/v1\n" + core.canonical_bytes(header).decode("utf-8") + "\n\nUser:\nSynthetic needle."
        variants = [
            (valid, "unknown-visible-fragment/v2"),
            (valid.replace('"observed_role":"user"', '"observed_role":"system"'), "codex-visible-fragment/v1"),
            (valid.replace('"missing_roles":["assistant"]', '"missing_roles":[]'), "codex-visible-fragment/v1"),
            (valid.replace("\n\nUser:\n", "\n\nAssistant:\n"), "codex-visible-fragment/v1"),
            ("Memory Vault visible fragment/v1\n" + "x" * 1025 + "\n\nUser:\nSynthetic needle.", "codex-visible-fragment/v1"),
            (valid.replace('"supplement":null', '"supplement":{"memory_id":"mem_' + "1" * 40 + '","record_sha256":"' + "2" * 64 + '"}'), "codex-visible-fragment/v1"),
        ]
        for text, source in variants:
            with self.subTest(source=source, size=len(text)):
                record = core.build_record(kind="episode", text=text,
                                           provenance={"source_ref": source},
                                           created_at="2026-08-01T00:00:00Z")
                spans = list(core.memory_fragments(record))
                self.assertTrue(spans)
                self.assertEqual(spans[0]["start_character"], 0)
                self.assertTrue(all(span["role_hint"] is None for span in spans))
                self.assertTrue(any("Synthetic needle." in span["text"] for span in spans))


if __name__ == "__main__":
    unittest.main()
