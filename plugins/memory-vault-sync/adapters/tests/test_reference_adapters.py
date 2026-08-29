from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ADAPTERS = Path(__file__).resolve().parents[1]
if str(ADAPTERS) not in sys.path:
    sys.path.insert(0, str(ADAPTERS))

import adapter_common  # noqa: E402


CLAUDE = ADAPTERS / "claude-code" / "hook.py"
GEMINI = ADAPTERS / "gemini-cli" / "hook.py"
GENERIC = ADAPTERS / "generic-stdio" / "adapter.py"
FAKE_VAULT = Path(__file__).resolve().parent / "fake_vault.py"
CONTINUITY_HANDLE = "mvc1_" + ("A" * 43)
TURN_HANDLE = "mvt1_" + ("B" * 43)


class ReferenceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.capture = self.root / "requests.jsonl"
        self.environment = os.environ.copy()
        self.environment["MEMORY_VAULT_ADAPTER_STATE_DIR"] = str(
            self.root / "state"
        )
        self.environment["MEMORY_VAULT_FAKE_CAPTURE"] = str(self.capture)
        self.environment["MEMORY_VAULT_HOST_COMMAND_JSON"] = json.dumps(
            [sys.executable, str(FAKE_VAULT)]
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        script: Path,
        value: dict[str, object],
        *arguments: str,
    ) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(script), *arguments],
            input=json.dumps(value, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout.decode("utf-8"))

    def invoke_raw(
        self,
        script: Path,
        value: bytes,
        *arguments: str,
    ) -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(script), *arguments],
            input=value,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout.decode("utf-8"))

    def requests(self) -> list[dict[str, object]]:
        if not self.capture.exists():
            return []
        return [
            json.loads(line)
            for line in self.capture.read_text(encoding="utf-8").splitlines()
        ]

    def assert_protocol_envelope(self, request: dict[str, object]) -> None:
        self.assertEqual(
            set(request),
            {
                "schema_version",
                "protocol_version",
                "request_id",
                "operation",
                "adapter",
                "payload",
            },
        )
        self.assertEqual(
            request["schema_version"], "memory-vault-host-request/v1"
        )
        self.assertEqual(request["protocol_version"], "1.0")
        self.assertEqual(
            set(request["adapter"]), {"id", "version", "host_family"}
        )

    def test_claude_uses_visible_fields_and_private_handle_map(self) -> None:
        native = "claude-native-session-private"
        transcript = "/private/transcript/that-must-not-cross.jsonl"
        self.assertEqual(
            self.invoke(
                CLAUDE,
                {
                    "session_id": native,
                    "transcript_path": transcript,
                    "cwd": "/private/workspace",
                    "permission_mode": "bypassPermissions",
                    "hook_event_name": "SessionStart",
                    "source": "startup",
                    "model": "private-model-name",
                },
            ),
            {},
        )
        recalled = self.invoke(
            CLAUDE,
            {
                "session_id": native,
                "transcript_path": transcript,
                "cwd": "/private/workspace",
                "permission_mode": "default",
                "hook_event_name": "UserPromptSubmit",
                "prompt": "visible user prompt",
            },
        )
        self.assertEqual(
            recalled["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit",
        )
        self.assertIn(
            "untrusted historical evidence",
            recalled["hookSpecificOutput"]["additionalContext"],
        )
        self.assertEqual(
            self.invoke(
                CLAUDE,
                {
                    "session_id": native,
                    "transcript_path": transcript,
                    "cwd": "/private/workspace",
                    "permission_mode": "default",
                    "hook_event_name": "Stop",
                    "stop_hook_active": False,
                    "last_assistant_message": "visible final answer",
                    "background_tasks": [],
                    "session_crons": [],
                },
            ),
            {},
        )

        requests = self.requests()
        self.assertEqual(
            [item["operation"] for item in requests],
            ["session.open", "turn.input", "turn.commit"],
        )
        for request in requests:
            self.assert_protocol_envelope(request)
        self.assertEqual(
            requests[1]["payload"],
            {
                "continuity_handle": CONTINUITY_HANDLE,
                "turn_handle": None,
                "visible_user_text": "visible user prompt",
                "limit": 8,
            },
        )
        self.assertEqual(
            requests[2]["payload"],
            {
                "continuity_handle": CONTINUITY_HANDLE,
                "turn_handle": TURN_HANDLE,
                "outcome": "final",
                "visible_user_text": None,
                "visible_assistant_text": "visible final answer",
            },
        )
        serialized_requests = self.capture.read_text(encoding="utf-8")
        self.assertNotIn(native, serialized_requests)
        self.assertNotIn(transcript, serialized_requests)
        self.assertNotIn("permission_mode", serialized_requests)
        self.assertNotIn("model", serialized_requests)

        state_files = list((self.root / "state").rglob("state.json"))
        self.assertEqual(len(state_files), 1)
        stored = state_files[0].read_text(encoding="utf-8")
        self.assertNotIn(native, stored)
        self.assertNotIn("visible user prompt", stored)
        self.assertNotIn("visible final answer", stored)
        if os.name != "nt":
            self.assertEqual(
                stat.S_IMODE(state_files[0].stat().st_mode),
                0o600,
            )

    def test_claude_aborts_stale_turn_before_new_prompt(self) -> None:
        base = {
            "session_id": "stale-session",
            "transcript_path": "/ignored",
            "cwd": "/ignored",
            "permission_mode": "default",
            "hook_event_name": "UserPromptSubmit",
        }
        self.invoke(CLAUDE, {**base, "prompt": "first"})
        self.invoke(CLAUDE, {**base, "prompt": "second"})
        requests = self.requests()
        self.assertEqual(
            [item["operation"] for item in requests],
            ["session.open", "turn.input", "turn.abort", "turn.input"],
        )
        self.assertEqual(requests[2]["payload"]["reason"], "user_interrupt")

    def test_gemini_commits_prompt_and_response_atomically(self) -> None:
        native = "gemini-native-session-private"
        common = {
            "session_id": native,
            "transcript_path": "/ignored/transcript.json",
            "cwd": "/ignored/workspace",
            "timestamp": "2026-08-30T00:00:00Z",
        }
        self.invoke(
            GEMINI,
            {
                **common,
                "hook_event_name": "SessionStart",
                "source": "startup",
            },
        )
        recalled = self.invoke(
            GEMINI,
            {
                **common,
                "hook_event_name": "BeforeAgent",
                "prompt": "gemini visible prompt",
            },
        )
        self.assertEqual(
            recalled["hookSpecificOutput"]["hookEventName"], "BeforeAgent"
        )
        self.invoke(
            GEMINI,
            {
                **common,
                "hook_event_name": "AfterAgent",
                "prompt": "gemini visible prompt",
                "prompt_response": "gemini visible response",
                "stop_hook_active": False,
            },
        )
        requests = self.requests()
        self.assertEqual(requests[-1]["operation"], "turn.commit")
        self.assertEqual(
            requests[-1]["payload"],
            {
                "continuity_handle": CONTINUITY_HANDLE,
                "turn_handle": TURN_HANDLE,
                "outcome": "final",
                "visible_user_text": "gemini visible prompt",
                "visible_assistant_text": "gemini visible response",
            },
        )
        serialized = self.capture.read_text(encoding="utf-8")
        self.assertNotIn(native, serialized)
        self.assertNotIn("transcript_path", serialized)
        self.assertNotIn("timestamp", serialized)

    def test_compact_is_explicitly_network_free(self) -> None:
        self.invoke(
            GEMINI,
            {
                "session_id": "compact-session",
                "transcript_path": "/ignored",
                "cwd": "/ignored",
                "hook_event_name": "PreCompress",
                "timestamp": "2026-08-30T00:00:00Z",
                "trigger": "manual",
            },
        )
        request = self.requests()[-1]
        self.assertEqual(request["operation"], "session.open")
        self.assertEqual(request["payload"]["reason"], "compact")

    def test_generic_stdio_rejects_non_visible_surfaces(self) -> None:
        rejected = self.invoke(
            GENERIC,
            {
                "schema_version": "memory-vault-local-host-event/v1",
                "event": "turn.input",
                "payload": {
                    "native_session_id": "local-session",
                    "visible_user_text": "hello",
                    "limit": 8,
                    "hidden_reasoning": "must never cross",
                },
            },
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(self.requests(), [])

    def test_generic_stdio_uses_same_protocol_and_local_recall(self) -> None:
        accepted = self.invoke(
            GENERIC,
            {
                "schema_version": "memory-vault-local-host-event/v1",
                "event": "turn.input",
                "payload": {
                    "native_session_id": "local-native-private",
                    "visible_user_text": "local visible prompt",
                    "limit": 4,
                },
            },
        )
        self.assertEqual(accepted["status"], "accepted")
        self.assertFalse(accepted["result"]["network_accessed"])
        requests = self.requests()
        self.assertEqual(
            [item["operation"] for item in requests],
            ["session.open", "turn.input"],
        )
        self.assertEqual(requests[-1]["payload"]["limit"], 4)
        serialized = self.capture.read_text(encoding="utf-8")
        self.assertNotIn("local-native-private", serialized)

    def test_generic_recall_includes_a_bounded_context_request(self) -> None:
        accepted = self.invoke(
            GENERIC,
            {
                "schema_version": "memory-vault-local-host-event/v1",
                "event": "memory.recall",
                "payload": {"query": "portable memory", "limit": 5},
            },
        )
        self.assertEqual(accepted["status"], "accepted")
        request = self.requests()[-1]
        self.assertEqual(
            request["payload"],
            {
                "query": "portable memory",
                "limit": 5,
                "maximum_context_bytes": 8192,
            },
        )

    def test_generic_remember_blocks_nested_host_and_authority_fields(self) -> None:
        event = {
            "schema_version": "memory-vault-local-host-event/v1",
            "event": "memory.remember",
            "payload": {
                "proposal": {
                    "schema_version": "memory-network-semantic-proposal/v1",
                    "payload": {"permission_mode": "bypassPermissions"},
                }
            },
        }
        output = self.invoke(GENERIC, event)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(self.requests(), [])

        event["payload"]["proposal"] = {
            "schema_version": "memory-network-semantic-proposal/v1",
            "payload": {"weight": 0.5},
        }
        output = self.invoke(GENERIC, event)
        self.assertEqual(output["status"], "rejected")
        self.assertEqual(self.requests(), [])

    def test_adapter_refuses_escalated_response_authority(self) -> None:
        self.environment["MEMORY_VAULT_FAKE_ESCALATED_AUTHORITY"] = "1"
        output = self.invoke(
            CLAUDE,
            {
                "session_id": "authority-test-session",
                "transcript_path": "/ignored",
                "cwd": "/ignored",
                "permission_mode": "default",
                "hook_event_name": "UserPromptSubmit",
                "prompt": "visible prompt",
            },
        )
        self.assertEqual(output, {})

    def test_generic_refuses_authority_field_inside_result(self) -> None:
        self.environment["MEMORY_VAULT_FAKE_RESULT_AUTHORITY_FIELD"] = "1"
        output = self.invoke(
            GENERIC,
            {
                "schema_version": "memory-vault-local-host-event/v1",
                "event": "capabilities",
                "payload": {},
            },
        )
        self.assertEqual(output["status"], "rejected")

    def test_generic_serve_uses_bounded_ndjson_framing(self) -> None:
        values = [
            {
                "schema_version": "memory-vault-local-host-event/v1",
                "event": "capabilities",
                "payload": {},
            },
            {
                "schema_version": "memory-vault-local-host-event/v1",
                "event": "memory.status",
                "payload": {},
            },
        ]
        framed = b"".join(
            json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
            for value in values
        )
        completed = subprocess.run(
            [sys.executable, str(GENERIC), "--serve"],
            input=framed,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        responses = [
            json.loads(line)
            for line in completed.stdout.decode("utf-8").splitlines()
        ]
        self.assertEqual([item["status"] for item in responses], ["accepted"] * 2)
        self.assertEqual(
            [item["operation"] for item in self.requests()],
            ["capabilities", "memory.status"],
        )

    def test_hook_input_rejects_duplicate_keys_bom_and_nonfinite(self) -> None:
        duplicate = (
            b'{"session_id":"first","session_id":"second",'
            b'"hook_event_name":"SessionStart","source":"startup"}'
        )
        valid = (
            b'{"session_id":"strict-session",'
            b'"hook_event_name":"SessionStart","source":"startup"}'
        )
        nonfinite = (
            b'{"session_id":"strict-session",'
            b'"hook_event_name":"SessionStart","source":"startup",'
            b'"probe":NaN}'
        )
        self.assertEqual(self.invoke_raw(CLAUDE, duplicate), {})
        self.assertEqual(self.invoke_raw(CLAUDE, b"\xef\xbb\xbf" + valid), {})
        self.assertEqual(self.invoke_raw(CLAUDE, nonfinite), {})
        self.assertEqual(self.requests(), [])

    def test_private_state_rejects_duplicate_keys_bom_and_nonfinite(self) -> None:
        event = {
            "session_id": "strict-state-session",
            "hook_event_name": "SessionStart",
            "source": "startup",
        }
        self.assertEqual(self.invoke(CLAUDE, event), {})
        state_files = list((self.root / "state").rglob("state.json"))
        self.assertEqual(len(state_files), 1)
        state_path = state_files[0]
        valid = state_path.read_bytes()
        prior_requests = len(self.requests())
        prompt = {
            "session_id": "strict-state-session",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "must not leave a corrupt state",
        }

        invalid_states = [
            valid[:-1] + b',"counter":0}',
            b"\xef\xbb\xbf" + valid,
            valid[:-1] + b',"probe":NaN}',
        ]
        for invalid in invalid_states:
            with self.subTest(invalid=invalid[:3]):
                state_path.write_bytes(invalid)
                self.assertEqual(self.invoke(CLAUDE, prompt), {})
                self.assertEqual(len(self.requests()), prior_requests)
                state_path.write_bytes(valid)

    def test_response_rejects_duplicate_bom_nan_and_all_floats(self) -> None:
        flags = [
            "MEMORY_VAULT_FAKE_DUPLICATE_RESPONSE",
            "MEMORY_VAULT_FAKE_BOM_RESPONSE",
            "MEMORY_VAULT_FAKE_NAN_RESULT",
            "MEMORY_VAULT_FAKE_FLOAT_RESULT",
        ]
        event = {
            "schema_version": "memory-vault-local-host-event/v1",
            "event": "capabilities",
            "payload": {},
        }
        for flag in flags:
            with self.subTest(flag=flag):
                self.environment[flag] = "1"
                output = self.invoke(GENERIC, event)
                self.assertEqual(output["status"], "rejected")
                del self.environment[flag]
        self.assertEqual(
            [item["operation"] for item in self.requests()],
            ["capabilities"] * len(flags),
        )

    def test_generic_serve_strictly_rejects_extended_json(self) -> None:
        duplicate = (
            b'{"schema_version":"memory-vault-local-host-event/v1",'
            b'"event":"capabilities","event":"memory.status",'
            b'"payload":{}}\n'
        )
        bom = (
            b'\xef\xbb\xbf{"schema_version":"memory-vault-local-host-event/v1",'
            b'"event":"capabilities","payload":{}}\n'
        )
        nonfinite = (
            b'{"schema_version":"memory-vault-local-host-event/v1",'
            b'"event":"capabilities","payload":{},"probe":Infinity}\n'
        )
        valid = (
            b'{"schema_version":"memory-vault-local-host-event/v1",'
            b'"event":"capabilities","payload":{}}\n'
        )
        completed = subprocess.run(
            [sys.executable, str(GENERIC), "--serve"],
            input=duplicate + bom + nonfinite + valid,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        responses = [
            json.loads(line)
            for line in completed.stdout.decode("utf-8").splitlines()
        ]
        self.assertEqual(
            [item["status"] for item in responses],
            ["rejected", "rejected", "rejected", "accepted"],
        )
        self.assertEqual(
            [item["operation"] for item in self.requests()],
            ["capabilities"],
        )

    def test_lock_stale_threshold_exceeds_session_start_window(self) -> None:
        self.assertGreaterEqual(adapter_common.LOCK_STALE_SECONDS, 600.0)
        self.assertGreater(adapter_common.LOCK_STALE_SECONDS, 150.0)
        timeouts = adapter_common.VAULT_OPERATION_TIMEOUT_SECONDS
        self.assertLess(timeouts["session.open"], 150.0)
        self.assertGreaterEqual(timeouts["session.open"], 140.0)
        self.assertLess(timeouts["turn.input"], 15.0)
        self.assertLess(timeouts["turn.commit"] * 2, 30.0)

    def test_commit_retries_transport_failure_with_identical_request(self) -> None:
        native = "ack-loss-session"
        self.invoke(
            CLAUDE,
            {
                "session_id": native,
                "hook_event_name": "SessionStart",
                "source": "startup",
            },
        )
        self.invoke(
            CLAUDE,
            {
                "session_id": native,
                "hook_event_name": "UserPromptSubmit",
                "prompt": "visible prompt",
            },
        )
        marker = self.root / "fail-first.marker"
        self.environment["MEMORY_VAULT_FAKE_FAIL_FIRST_MARKER"] = str(marker)
        self.assertEqual(
            self.invoke(
                CLAUDE,
                {
                    "session_id": native,
                    "hook_event_name": "Stop",
                    "last_assistant_message": "visible final",
                },
            ),
            {},
        )
        commits = [
            item for item in self.requests() if item["operation"] == "turn.commit"
        ]
        self.assertEqual(len(commits), 2)
        self.assertEqual(commits[0], commits[1])
        self.assertEqual(commits[0]["request_id"], commits[1]["request_id"])

    def test_invalid_response_is_not_retried_with_a_new_id(self) -> None:
        native = "no-schema-retry-session"
        self.invoke(
            CLAUDE,
            {
                "session_id": native,
                "hook_event_name": "UserPromptSubmit",
                "prompt": "visible prompt",
            },
        )
        self.environment["MEMORY_VAULT_FAKE_RESULT_AUTHORITY_FIELD"] = "1"
        self.assertEqual(
            self.invoke(
                CLAUDE,
                {
                    "session_id": native,
                    "hook_event_name": "Stop",
                    "last_assistant_message": "visible final",
                },
            ),
            {},
        )
        commits = [
            item for item in self.requests() if item["operation"] == "turn.commit"
        ]
        self.assertEqual(len(commits), 1)

    def test_turn_input_retries_ack_loss_with_identical_request(self) -> None:
        native = "latency-session"
        self.invoke(
            CLAUDE,
            {
                "session_id": native,
                "hook_event_name": "SessionStart",
                "source": "startup",
            },
        )
        marker = self.root / "turn-input-fail-first.marker"
        self.environment["MEMORY_VAULT_FAKE_FAIL_FIRST_MARKER"] = str(marker)
        output = self.invoke(
            CLAUDE,
            {
                "session_id": native,
                "hook_event_name": "UserPromptSubmit",
                "prompt": "latency-sensitive prompt",
            },
        )
        self.assertIn("hookSpecificOutput", output)
        inputs = [
            item for item in self.requests() if item["operation"] == "turn.input"
        ]
        self.assertEqual(len(inputs), 2)
        self.assertEqual(inputs[0], inputs[1])


if __name__ == "__main__":
    unittest.main()
