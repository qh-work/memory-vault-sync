"""Synthetic single-sided native-hook workflows; authored, NOT RUN here.

Only temporary unsigned Vaults and explicitly created local configurations are
used. Canonical writes, source files, frozen journals and their retries are real.
Exception injection models preparation/completion windows, not physical process
crashes. One controlled callback changes configuration immediately after a real
journal lock is acquired; it is not an operating-system concurrency test. The
quota case deliberately lowers a test-only threshold and is not a 32 MiB load
or performance benchmark. No host, signing key, provider, child or network is used.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unicodedata
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import memory_vault_capture as capture
import memory_vault_client as client
import memory_vault_storage as storage
from memory_vault import MemoryError, canonical_bytes, failure, strict_json_loads


class PartialHookCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="memory-v025-partial-hook-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config_path = self.root / "control" / "client.json"
        self.vault_path = self.root / "vault.sqlite3"
        self.configure(True)

    def configure(self, enabled: bool) -> client.ClientConfig:
        storage.atomic_write(self.config_path, canonical_bytes({
            "schema_version": client.CONFIG_SCHEMA, "vault_path": str(self.vault_path),
            "capture_visible_turns": enabled,
        }) + b"\n", replace=self.config_path.exists())
        return client.ClientConfig.load(self.config_path)

    def config(self) -> client.ClientConfig:
        return client.ClientConfig.load(self.config_path)

    def journal(self) -> capture.HookCaptureJournal:
        chosen = self.config()
        return capture.HookCaptureJournal(chosen.state_path, chosen.vault_path)

    @staticmethod
    def event(turn: str, **fields: object) -> dict:
        return {"session_id": "synthetic-local-scope", "turn_id": turn, **fields}

    def key(self, turn: str) -> str:
        return client._turn_key(self.event(turn))

    def prompt(self, turn: str, text: str) -> dict:
        return dict(client.handle_hook(self.config(), "user-prompt-submit", self.event(
            turn, hook_event_name="UserPromptSubmit", prompt=text,
        )))

    def stop(self, turn: str, text: str | None = None, **fields: object) -> dict:
        return dict(client.handle_hook(self.config(), "stop", self.event(
            turn, hook_event_name="Stop", last_assistant_message=text, **fields,
        )))

    def maybe_plan(self, key: str) -> dict | None:
        with self.journal().transaction(writable=False) as connection:
            return capture.load_capture(connection, key) if connection is not None else None

    def plan(self, key: str) -> dict:
        result = self.maybe_plan(key)
        self.assertIsNotNone(result)
        return dict(result)

    def records(self) -> dict[str, dict]:
        if not self.vault_path.exists():
            return {}
        with contextlib.closing(sqlite3.connect(self.vault_path.as_uri() + "?mode=ro", uri=True)) as connection:
            values = [strict_json_loads(row[0]) for row in connection.execute("SELECT record_json FROM memories ORDER BY ingest_seq")]
        return {value["memory_id"]: value for value in values}

    @staticmethod
    def reference(plan: dict) -> dict:
        return next(dict(item) for item in plan["record_refs"] if item["memory_id"] == plan["episode_id"])

    @contextlib.contextmanager
    def existing_acceptance_only(self):
        original_freeze = capture.freeze_capture

        def retry(*args: object, **kwargs: object) -> dict:
            # Existing freeze must not select a new timestamp/head through
            # this callback. The strict validator is still allowed to rebuild
            # an expected pair from the already-frozen bytes and parameters.
            kwargs["build_projection"] = mock.Mock(side_effect=AssertionError("no new acceptance projection"))
            return original_freeze(*args, **kwargs)

        with mock.patch.object(capture, "freeze_capture", side_effect=retry):
            yield

    def test_real_hooks_save_both_partial_orders_and_keep_the_original_pair_profile(self) -> None:
        assistant = "Synthetic assistant-first cafe\u0301 output."
        self.assertIn("saved_local", self.stop("assistant-first", assistant)["systemMessage"])
        first_key = self.key("assistant-first")
        first = self.plan(first_key)
        original = self.records()
        self.assertEqual(len(original), 2)
        self.assertEqual(first["builder_profile"], capture.HOOK_FRAGMENT_PROFILE)
        fragment = capture.parse_hook_fragment(original[first["episode_id"]])
        self.assertEqual(fragment, {
            "coverage": "partial_active_turn", "observed_role": "assistant", "missing_roles": ["user"],
            "supplement": None, "text": unicodedata.normalize("NFC", assistant),
        })

        # A different completed turn advances the same local continuity head.
        # Its old pair profile and decomposed raw text must remain unchanged.
        paired_user = "Synthetic full cafe\u0301 input."
        paired_assistant = "Synthetic full cafe\u0301 output."
        self.prompt("interleaved", paired_user)
        self.stop("interleaved", paired_assistant)
        paired = self.plan(self.key("interleaved"))
        self.assertEqual(paired["builder_profile"], client.HOOK_CAPTURE_PROFILE)
        self.assertEqual(self.records()[paired["episode_id"]]["text"],
                         "User:\n" + paired_user + "\n\nAssistant:\n" + paired_assistant)
        state = client.HookState(self.config())
        self.assertEqual(state.read("done", self.key("interleaved"))["user_sha256"], client._digest(paired_user))

        late_user = "Synthetic later cafe\u0301 user input."
        self.assertIn("supplement", self.prompt("assistant-first", late_user)["systemMessage"])
        supplement_key = client.hook_supplement_key(first_key)
        supplement = self.plan(supplement_key)
        after = self.records()
        self.assertEqual(len(after), 6)
        self.assertTrue(all(after[key] == record for key, record in original.items()))
        late = capture.parse_hook_fragment(after[supplement["episode_id"]])
        self.assertEqual(late["observed_role"], "user")
        self.assertEqual(late["text"], unicodedata.normalize("NFC", late_user))
        self.assertEqual(late["supplement"], self.reference(first))
        self.assertEqual(supplement["previous_continuity_id"], paired["continuity_id"])
        self.assertEqual(supplement["accepted_sequence"], paired["accepted_sequence"] + 1)
        self.assertEqual(after[supplement["episode_id"]]["relations"], [{"type": "derived_from", "target": first["episode_id"]}])
        self.assertIn({"type": "continues", "target": paired["continuity_id"]}, after[supplement["continuity_id"]]["relations"])
        self.assertIsNone(state.read("done", first_key)["user_sha256"])
        self.assertIsNone(state.read("done", supplement_key)["assistant_sha256"])

        # Both slots are immutable. Exact saved callbacks validate the actual
        # canonical receipt without accepting a new projection or announcing
        # sync progress. Pure validation of frozen parameters remains enabled.
        with self.existing_acceptance_only(), \
                mock.patch.object(client, "notify_sync", side_effect=AssertionError("no new progress")):
            self.stop("assistant-first", assistant)
            self.prompt("assistant-first", late_user)
        for action in (lambda: self.stop("assistant-first", assistant + " changed"),
                       lambda: self.prompt("assistant-first", late_user + " changed")):
            with self.assertRaisesRegex(MemoryError, "hook_event_conflict"):
                action()
        self.assertEqual(self.records(), after)
        self.assertEqual(self.plan(first_key)["record_refs"], first["record_refs"])
        self.assertEqual(self.plan(supplement_key)["record_refs"], supplement["record_refs"])

        # The opposite arrival order starts from a raw v2 prompt. Stop lacks
        # an assistant field entirely; stop_hook_active is not cancellation.
        user = "Synthetic user-first cafe\u0301 input."
        user_key = self.key("user-first")
        self.prompt("user-first", user)
        self.assertEqual(state.read("prompts", user_key)["user"], user)
        response = client.handle_hook(self.config(), "stop", self.event(
            "user-first", hook_event_name="Stop", stop_hook_active=True,
        ))
        self.assertIn("saved_local", response["systemMessage"])
        user_first = self.plan(user_key)
        self.assertEqual(capture.parse_hook_fragment(self.records()[user_first["episode_id"]])["text"], unicodedata.normalize("NFC", user))
        self.assertIsNone(state.read("prompts", user_key), "NFC fragment cleanup must accept the original decomposed prompt")
        self.stop("user-first", "Synthetic later assistant cafe\u0301 output.")
        user_supplement = self.plan(client.hook_supplement_key(user_key))
        self.assertEqual(capture.parse_hook_fragment(self.records()[user_supplement["episode_id"]])["supplement"], self.reference(user_first))
        final = self.records()
        self.assertEqual(len(final), 10)
        self.assertIn("no_visible_content", self.stop("no-content")["systemMessage"])
        self.assertIsNone(self.maybe_plan(self.key("no-content")))
        self.assertEqual(self.records(), final)
        canonical = canonical_bytes(list(final.values())).decode("utf-8")
        for local_only in ("synthetic-local-scope", first_key, client._hook_scope(self.event("assistant-first"))):
            self.assertNotIn(local_only, canonical)

    def test_prepare_freeze_and_done_boundaries_replay_exactly_before_one_supplement(self) -> None:
        turn, assistant, user = "interrupted", "Synthetic first assistant.", "Synthetic later user."
        key = self.key(turn)
        supplement_key = client.hook_supplement_key(key)
        state = client.HookState(self.config())
        # Publishing an immutable source and freezing it are separate. This
        # first injection leaves only a valid, unaccepted primary outbox.
        with mock.patch.object(capture, "freeze_capture", side_effect=MemoryError("synthetic_before_accept")):
            with self.assertRaisesRegex(MemoryError, "synthetic_before_accept"):
                self.stop(turn, assistant)
        self.assertIsNotNone(state.read("outbox", key))
        self.assertIsNone(self.maybe_plan(key))
        self.assertEqual(self.records(), {})
        original_prepare = client._prepare_hook_outbox
        observed_primary = []

        def inspect_committed_primary(connection: sqlite3.Connection, selected: client.HookState,
                                      selected_key: str, value: dict) -> dict:
            if value.get("supplement") is not None:
                # A separate real read connection can only see a committed
                # primary, even though the supplement's transaction holds its
                # own writer lock. No thread/process timing is simulated here.
                committed = self.plan(key)
                self.assertEqual(value["supplement"], self.reference(committed))
                observed_primary.append(committed)
                raise MemoryError("synthetic_after_primary_commit")
            return original_prepare(connection, selected, selected_key, value)

        with mock.patch.object(client, "_prepare_hook_outbox", side_effect=inspect_committed_primary):
            with self.assertRaisesRegex(MemoryError, "synthetic_after_primary_commit"):
                self.prompt(turn, user)
        self.assertEqual(len(observed_primary), 1)
        frozen = self.plan(key)
        self.assertEqual(frozen["state"], "pending")
        self.assertIsNone(state.read("outbox", supplement_key))
        self.assertIsNone(self.maybe_plan(supplement_key))
        self.assertEqual(self.records(), {})

        # Next acceptance includes the supplement. Canonical primary + done
        # succeed, then only its journal acknowledgement is interrupted.
        with mock.patch.object(capture, "mark_capture_saved", side_effect=MemoryError("synthetic_after_done")):
            with self.assertRaisesRegex(MemoryError, "synthetic_after_done"):
                self.prompt(turn, user)
        child = self.plan(supplement_key)
        self.assertEqual(child["state"], "pending")
        self.assertEqual(len(self.records()), 2)
        self.assertEqual(self.plan(key), frozen)
        self.assertIsNone(state.read("outbox", key))
        self.assertIsNotNone(state.read("done", key))
        self.assertIsNotNone(state.read("outbox", supplement_key))
        with self.existing_acceptance_only():
            retried = client.retry_pending(self.config(), limit=2)
        self.assertTrue(retried["ok"], retried)
        self.assertEqual((retried["result"]["processed"], retried["result"]["saved"], retried["result"]["failed"]), (2, 2, 0))
        self.assertFalse(retried["result"]["network_accessed"])
        self.assertEqual(len(self.records()), 4)
        for selected_key, before in ((key, frozen), (supplement_key, child)):
            saved = self.plan(selected_key)
            self.assertEqual(saved["state"], "saved")
            self.assertEqual(saved["records"], [])
            for field in ("record_refs", "created_at", "projection_sha256", "input_sha256"):
                self.assertEqual(saved[field], before[field])
            self.assertIsNone(state.read("outbox", selected_key))
            self.assertIsNotNone(state.read("done", selected_key))
        self.assertEqual(client.retry_pending(self.config(), limit=2)["result"]["processed"], 0)

    def test_new_preparation_limits_do_not_block_accepted_or_legacy_exact_retry(self) -> None:
        with mock.patch.object(client, "save_turn_projection", return_value=failure("synthetic_pre_save", retryable=True)):
            pending = self.stop("accepted", "Synthetic accepted single side.")
        self.assertIn("pending_retry", pending["systemMessage"])
        key = self.key("accepted")
        frozen = self.plan(key)
        state = client.HookState(self.config())
        legacy_key = self.key("legacy-pending")
        state.prompt(legacy_key, "Synthetic old input.")
        state.once("outbox", legacy_key, {"user": "Synthetic old input.", "assistant": "Synthetic old output."})
        unknown = state.root / "prompts" / "unrecognized.txt"
        storage.atomic_write(unknown, b"synthetic unknown preparation entry\n", replace=False)
        with self.assertRaisesRegex(MemoryError, "invalid_hook_preparation_entry"):
            self.prompt("refused-unknown", "Synthetic new input must be refused.")
        self.assertIsNone(state.read("prompts", self.key("refused-unknown")))
        unknown.unlink()  # Only this fixture's precisely named synthetic file.
        # This reduced test-only limit makes the existing collection excessive
        # without generating 32 MiB. Acceptance is blocked, not exact replay.
        with mock.patch.object(capture, "MAX_CAPTURE_PENDING_BYTES", 1):
            with self.assertRaisesRegex(MemoryError, "hook_preparation_limit"):
                self.prompt("refused-budget", "Synthetic new input over test quota.")
            self.assertIsNone(state.read("prompts", self.key("refused-budget")))
            with self.existing_acceptance_only(), \
                    mock.patch.object(client, "build_turn_projection", side_effect=AssertionError("legacy replay")):
                retried = client.retry_pending(self.config(), limit=4)
            self.assertTrue(retried["ok"], retried)
            self.assertEqual((retried["result"]["processed"], retried["result"]["saved"], retried["result"]["failed"]), (2, 2, 0))
            with mock.patch.object(client, "notify_sync", side_effect=AssertionError("saved retry is not new progress")):
                self.stop("accepted", "Synthetic accepted single side.")
        self.assertEqual(self.plan(key)["record_refs"], frozen["record_refs"])
        self.assertIsNone(self.maybe_plan(legacy_key), "old v1 jobs keep their original receipts, not a new causal head")
        self.assertEqual(state.read("done", legacy_key)["schema_version"], client.STATE_SCHEMA)
        self.assertEqual(len(self.records()), 4)

        # Old v2 could publish many sources before any freeze committed. Three
        # valid prepared files exceed this test-only count of two, yet each
        # bounded recovery may freeze/save one without weakening the pending
        # plan ceiling. New preparation is still refused over that ceiling.
        old_prepared = []
        for number in range(3):
            old_key = self.key("old-prepared-" + str(number))
            state.once("outbox", old_key, {"schema_version": client.CHAIN_STATE_SCHEMA,
                       "scope_key": client._hook_scope(self.event("old-prepared")),
                       "user": "Synthetic old prepared user " + str(number),
                       "assistant": "Synthetic old prepared assistant " + str(number)})
            old_prepared.append(old_key)
        self.assertTrue(all(self.maybe_plan(old_key) is None for old_key in old_prepared))
        with mock.patch.object(capture, "MAX_CAPTURE_PENDING_JOBS", 2):
            with self.assertRaisesRegex(MemoryError, "hook_preparation_limit"):
                self.prompt("refused-old-count", "Synthetic new source over test count.")
            resumed = client.retry_pending(self.config(), limit=4)
        self.assertTrue(resumed["ok"], resumed)
        self.assertEqual((resumed["result"]["processed"], resumed["result"]["saved"], resumed["result"]["failed"]), (3, 3, 0))
        self.assertTrue(all(self.plan(old_key)["state"] == "saved" for old_key in old_prepared))
        self.assertEqual(len(self.records()), 10)

    def test_opt_out_and_lock_boundary_disable_never_accept_new_partial_or_legacy_work(self) -> None:
        self.stop("disabled-late", "Synthetic already visible assistant.")
        key = self.key("disabled-late")
        stale = self.config()
        self.configure(False)
        # SQLite may create WAL/SHM coordination files for mode=ro. Establish
        # that read baseline before asserting the disabled hook changes none
        # of the existing files or canonical records.
        self.records()
        before = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        with mock.patch.object(client, "_prepare_hook_event", side_effect=AssertionError("capture disabled")), \
                mock.patch.object(client, "notify_sync", side_effect=AssertionError("no worker")), \
                mock.patch.object(client, "save_turn_projection", side_effect=AssertionError("no save")):
            client.handle_hook(stale, "user-prompt-submit", self.event(
                "disabled-late", hook_event_name="UserPromptSubmit", prompt="Synthetic currently uncaptured late user.",
            ))
            self.assertEqual(client.handle_hook(stale, "stop", self.event(
                "disabled-late", hook_event_name="Stop", last_assistant_message="Synthetic changed while disabled.",
            )), {})
        self.assertEqual({str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}, before)
        self.assertIsNone(self.maybe_plan(client.hook_supplement_key(key)))
        state = client.HookState(self.config())
        original_transaction = capture.HookCaptureJournal.transaction

        @contextlib.contextmanager
        def disable_after_acquisition(journal: capture.HookCaptureJournal, *, writable: bool = True):
            with original_transaction(journal, writable=writable) as connection:
                self.configure(False)
                yield connection

        # This is one deterministic lock-boundary injection, not a claim to
        # have tested concurrent host processes or a physical race window.
        self.configure(True)
        with mock.patch.object(capture.HookCaptureJournal, "transaction", new=disable_after_acquisition), \
                mock.patch.object(capture, "freeze_capture", side_effect=AssertionError("must recheck first")):
            with self.assertRaisesRegex(MemoryError, "automatic_capture_disabled"):
                self.prompt("locked-prompt", "Synthetic must not stage after lock wait.")
        self.assertIsNone(state.read("prompts", self.key("locked-prompt")))

        for schema in (client.FRAGMENT_STATE_SCHEMA, client.STATE_SCHEMA):
            with self.subTest(schema=schema):
                config = self.configure(True)
                queued_key = self.key("locked-retry-" + schema)
                job = ({"schema_version": schema, "scope_key": client._hook_scope(self.event("queued")),
                        "turn_key": queued_key, "supplement": None, "user": None,
                        "assistant": "Synthetic unaccepted fragment."} if schema == client.FRAGMENT_STATE_SCHEMA
                       else {"schema_version": schema, "user": "Synthetic legacy pending user.",
                             "assistant": "Synthetic legacy pending assistant."})
                state.once("outbox", queued_key, job)
                original_source = state.path("outbox", queued_key).read_bytes()
                with mock.patch.object(capture.HookCaptureJournal, "transaction", new=disable_after_acquisition), \
                        mock.patch.object(capture, "freeze_capture", side_effect=AssertionError("no new acceptance")), \
                        mock.patch.object(client, "observe_turn", side_effect=AssertionError("no stale legacy writer")):
                    with self.assertRaisesRegex(MemoryError, "automatic_capture_disabled"):
                        client._persist_job(config, state, queued_key, job)
                self.assertEqual(state.path("outbox", queued_key).read_bytes(), original_source)
                self.assertIsNone(self.maybe_plan(queued_key))
        self.assertEqual(len(self.records()), 2)


if __name__ == "__main__":
    unittest.main()
