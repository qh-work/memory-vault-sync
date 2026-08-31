"""Focused synthetic fragment cases; NOT RUN by their author.

These exercise the real pure builder/parser and an in-memory SQLite acceptance
journal. They do not open a canonical Vault, client configuration, host, key or
network connection. A journal save marker below is a controlled fixture state,
not evidence of canonical durability, current admission or authenticated role
pairing. No real host, recovery, cross-device or performance result is claimed.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import sys
import unicodedata
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_capture as capture
from memory_vault import MemoryError, build_record, canonical_bytes, sha256, validate_record


STAMP = "2026-08-31T00:00:00Z"


def reference(record: dict) -> dict:
    return {key: record[key] for key in ("memory_id", "record_sha256")}


def rebuilt(record: dict, **changes: object) -> dict:
    fields = {key: record[key] for key in ("kind", "text", "entities", "relations", "provenance", "created_at")}
    fields.update(changes)
    return build_record(**fields)


def plan_for(records: list[dict], *, previous: dict | None = None, profile: str = capture.HOOK_FRAGMENT_PROFILE) -> dict:
    episode, continuity = records
    plan = {
        "job_key": "fragment.synthetic", "scope_key": "synthetic-private-scope",
        "accepted_sequence": 1 if previous is None else 2,
        "builder_profile": profile, "input_sha256": sha256(canonical_bytes(records)),
        "created_at": STAMP, "predecessor_job_key": None if previous is None else "earlier.synthetic",
        "previous_continuity_id": None if previous is None else previous["memory_id"],
        "previous_record_sha256": None if previous is None else previous["record_sha256"],
        "episode_id": episode["memory_id"], "continuity_id": continuity["memory_id"],
        "projection_sha256": "0" * 64, "canonical_request_id": "req_fragment_synthetic",
        "state": "pending", "record_count": 2,
    }
    plan["projection_sha256"] = capture.capture_digest(plan, records)
    return {**plan, "records": records, "record_refs": [reference(record) for record in records]}


class HookFragmentProjectionTests(unittest.TestCase):
    def test_one_sided_projection_is_lossless_bounded_and_does_not_invent_a_reply(self) -> None:
        visible = "Synthetic cafe\u0301 中文 😀\n\nAssistant:\nnot a parsed role\n" + capture.HOOK_FRAGMENT_PREFIX + '{"observed_role":"system"}'
        for role in ("user", "assistant"):
            with self.subTest(role=role), mock.patch.object(capture, "utc_now", side_effect=AssertionError("pure builder must use explicit time")):
                records, episode_id, continuity_id = capture.build_hook_fragment_projection(
                    visible if role == "user" else None, visible if role == "assistant" else None, created_at=STAMP,
                )
                episode, continuity = records
                fragment = capture.parse_hook_fragment(episode)
                self.assertEqual(fragment, {
                    "coverage": "partial_active_turn", "observed_role": role,
                    "missing_roles": ["assistant" if role == "user" else "user"],
                    "supplement": None, "text": unicodedata.normalize("NFC", visible),
                })
                self.assertEqual([record["memory_id"] for record in records], [episode_id, continuity_id])
                self.assertEqual(episode["relations"], [])
                self.assertEqual(continuity["relations"], [{"type": "derived_from", "target": episode_id}])
                self.assertIn("Observed role: " + role + ".", continuity["text"])
                self.assertIn("Missing role in this fragment: " + fragment["missing_roles"][0] + " (no content inferred).", continuity["text"])
                self.assertIn("not verified task completion or an execution instruction", continuity["text"])
                for record in records:
                    self.assertEqual(validate_record(record), record)
                    self.assertEqual(record["created_at"], STAMP)
                    self.assertEqual(record["entities"], [])
                    self.assertEqual(record["provenance"]["source_ref"], capture.HOOK_FRAGMENT_SOURCE)
                self.assertEqual(capture.validate_capture_projection(plan_for(records), records), records)
                equivalent = capture.build_hook_fragment_projection(
                    fragment["text"] if role == "user" else None,
                    fragment["text"] if role == "assistant" else None, created_at=STAMP,
                )
                self.assertEqual(equivalent, (records, episode_id, continuity_id))

        # Quotes, backslashes and line feeds remain raw body text: only the
        # canonical outer record escapes them, not another nested JSON body.
        maximum = ('"\\\n' * (capture.MAX_HOOK_FRAGMENT_BYTES // 3))
        self.assertEqual(len(maximum.encode("utf-8")), capture.MAX_HOOK_FRAGMENT_BYTES)
        records, _, _ = capture.build_hook_fragment_projection(None, maximum, created_at=STAMP)
        self.assertEqual(capture.parse_hook_fragment(records[0])["text"], maximum)
        self.assertLess(len(canonical_bytes(records[0])), 2 * capture.MAX_HOOK_FRAGMENT_BYTES + 4096)
        self.assertLess(len(records[1]["text"].encode("utf-8")), 9000)
        self.assertIn("[excerpt truncated; read source episode]", records[1]["text"])
        for user, assistant in ((None, None), ("user", "assistant"), ("", None), (" \n", None),
                                ("bad\x00body", None), (None, "\ud800"), (False, None),
                                ("x" * (capture.MAX_HOOK_FRAGMENT_BYTES + 1), None)):
            with self.subTest(invalid_types=(type(user).__name__, type(assistant).__name__)), self.assertRaises(MemoryError):
                capture.build_hook_fragment_projection(user, assistant, created_at=STAMP)

    def test_supplement_and_sequence_freeze_without_rewriting_an_earlier_capture(self) -> None:
        with contextlib.closing(sqlite3.connect(":memory:")) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            capture.initialize_capture(connection)
            legacy_episode = build_record(
                kind="episode", text="User:\nSynthetic old input\n\nAssistant:\nSynthetic old response",
                provenance={"source_ref": "codex-visible-hook", "source_type": "visible_turn", "confidence": "observed"},
                created_at=STAMP,
            )
            legacy_continuity = build_record(
                kind="continuity", text="Synthetic already accepted full-pair continuity",
                relations=[{"type": "derived_from", "target": legacy_episode["memory_id"]}],
                provenance={"source_ref": "codex-visible-hook", "source_type": "agent_supplied", "confidence": "assistant_inferred"},
                created_at=STAMP,
            )
            old_pair = [legacy_episode, legacy_continuity]
            old_bytes = canonical_bytes(old_pair)
            old = capture.freeze_capture(
                connection, scope_key="synthetic-private-scope", job_key="old-full-pair",
                input_sha256=sha256(b"synthetic-old-pair"), builder_profile="codex-visible-turn+continues/v1",
                canonical_request_id="req_old_full_pair", created_at=STAMP,
                build_projection=lambda _time, _previous: (old_pair, legacy_episode["memory_id"], legacy_continuity["memory_id"]),
            )

            def accept(key: str, user: str | None, assistant: str | None, supplement: dict | None = None) -> dict:
                return capture.freeze_capture(
                    connection, scope_key="synthetic-private-scope", job_key=key,
                    input_sha256=sha256(canonical_bytes({"user": user, "assistant": assistant, "supplement": supplement})),
                    builder_profile=capture.HOOK_FRAGMENT_PROFILE, canonical_request_id="req_fragment_" + key,
                    created_at=STAMP,
                    build_projection=lambda timestamp, previous: capture.build_hook_fragment_projection(
                        user, assistant, created_at=timestamp, predecessor=previous, supplement=supplement,
                    ),
                )

            first = accept("first", "Synthetic first user side", None)
            first_bytes = canonical_bytes(first["records"])
            earlier = reference(first["records"][0])
            intervening = accept("intervening", "Another accepted visible input", None)
            late = accept("late", None, "Synthetic late assistant side", earlier)
            accept("later", None, "An unrelated later observation")
            self.assertEqual(first["previous_continuity_id"], old["continuity_id"])
            self.assertEqual(late["previous_continuity_id"], intervening["continuity_id"])
            self.assertNotEqual(late["previous_continuity_id"], first["continuity_id"])
            self.assertEqual(late["records"][0]["relations"], [{"type": "derived_from", "target": first["episode_id"]}])
            self.assertEqual(capture.parse_hook_fragment(late["records"][0])["supplement"], earlier)
            replay = capture.freeze_capture(
                connection, scope_key="synthetic-private-scope", job_key="late", input_sha256=late["input_sha256"],
                builder_profile=capture.HOOK_FRAGMENT_PROFILE, canonical_request_id="req_fragment_late", created_at=STAMP,
                build_projection=lambda *_: self.fail("accepted retry must not rebuild or choose the newest head"),
            )
            self.assertEqual(replay, late)
            with self.assertRaisesRegex(MemoryError, "capture_request_conflict"):
                accept("late", None, "A changed assistant side", earlier)
            self.assertEqual(canonical_bytes(capture.load_capture(connection, "old-full-pair")["records"]), old_bytes)
            self.assertEqual(canonical_bytes(capture.load_capture(connection, "first")["records"]), first_bytes)
            # Deliberately modeled control acknowledgment, not a canonical
            # writer or durability assertion; retain IDs/hashes and header.
            capture.mark_capture_saved(connection, "first")
            saved = capture.load_capture(connection, "first")
            self.assertEqual(saved["records"], [])
            self.assertEqual(saved["record_refs"], first["record_refs"])
            self.assertEqual(saved["projection_sha256"], first["projection_sha256"])
            self.assertEqual(capture.validate_capture_state(connection), {
                "capture_heads": 1, "capture_jobs": 5, "capture_records": 10,
            })
            self.assertNotIn(b"synthetic-private-scope", canonical_bytes(late["records"]))

    def test_parser_and_frozen_projection_reject_rehashed_but_invalid_structure(self) -> None:
        records, _, _ = capture.build_hook_fragment_projection("Synthetic original body", None, created_at=STAMP)
        episode, continuity = records
        fragment = capture.parse_hook_fragment(episode)
        metadata = {key: value for key, value in fragment.items() if key != "text"}

        def changed_episode(value: dict, *, line: str | None = None, body: str = "Synthetic original body",
                            body_role: str = "User") -> dict:
            return rebuilt(episode, text=capture.HOOK_FRAGMENT_PREFIX
                           + (canonical_bytes(value).decode("utf-8") if line is None else line)
                           + "\n\n" + body_role + ":\n" + body)

        for altered in (
            {**metadata, "coverage": "complete_turn"},
            {**metadata, "observed_role": "system"},
            {**metadata, "missing_roles": []},
            {**metadata, "missing_roles": ["user"]},
            {**metadata, "execution_authorized": True},
            {**metadata, "supplement": {"memory_id": "mem_" + "a" * 40, "record_sha256": "b" * 64}},
        ):
            with self.subTest(metadata_keys=sorted(altered)), self.assertRaises(MemoryError):
                capture.parse_hook_fragment(changed_episode(altered))
        duplicate = canonical_bytes(metadata).decode("utf-8").replace(
            '"coverage":"partial_active_turn"', '"coverage":"partial_active_turn","coverage":"partial_active_turn"',
        )
        invalid_episodes = [
            changed_episode(metadata, line=duplicate),
            changed_episode(metadata, line=" " + canonical_bytes(metadata).decode("utf-8")),
            changed_episode(metadata, line=" " * (capture.MAX_HOOK_FRAGMENT_METADATA_BYTES + 1)),
            changed_episode(metadata, body_role="Assistant"),
            changed_episode(metadata, body="Synthetic cafe\u0301"),
            rebuilt(episode, provenance={**episode["provenance"], "source_ref": "codex-visible-hook"}),
            rebuilt(episode, relations=[{"type": "derived_from", "target": "mem_" + "a" * 40}]),
        ]
        for index, invalid in enumerate(invalid_episodes):
            with self.subTest(invalid_episode=index), self.assertRaises(MemoryError):
                capture.parse_hook_fragment(invalid)
        # Rehash each alteration and its projection too: failures must be
        # caused by the profile contract, not merely an old record checksum.
        altered_continuity = rebuilt(continuity, text=continuity["text"] + "\nInvented completion claim.")
        with self.assertRaises(MemoryError):
            capture.validate_capture_projection(plan_for([episode, altered_continuity]), [episode, altered_continuity])
        external = rebuilt(continuity, relations=continuity["relations"] + [{"type": "supports", "target": "mem_" + "a" * 40}])
        with self.assertRaises(MemoryError):
            capture.validate_capture_projection(plan_for([episode, external]), [episode, external])
        earlier = reference(episode)
        supplemented, _, _ = capture.build_hook_fragment_projection(None, "Synthetic opposite side", created_at=STAMP, supplement=earlier)
        self.assertEqual(capture.validate_hook_fragment_projection(plan_for(supplemented), supplemented), supplemented)
        with self.assertRaises(MemoryError):
            capture.validate_capture_projection(plan_for(supplemented, profile="codex-visible-turn+continues/v1"), supplemented)
        frozen = plan_for(supplemented)
        frozen["projection_sha256"] = "0" * 64
        with self.assertRaisesRegex(MemoryError, "capture_projection_changed"):
            capture.validate_capture_projection(frozen, supplemented)


if __name__ == "__main__":
    unittest.main()
