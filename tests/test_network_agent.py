"""Minimal synthetic facade and trusted-HTTP checks; no real account/model."""
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from memory_vault import canonical_bytes
from memory_vault_agent import Agent, create_app
from memory_vault_client import CONFIG_SCHEMA, ClientConfig
from memory_vault_storage import atomic_write


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="memory-vault-agent-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / "client.json"
        self.agent = Agent(self.config)

    def configure(self):
        atomic_write(self.config, canonical_bytes({"schema_version": CONFIG_SCHEMA,
                     "vault_path": str(self.root / "vault.sqlite3"), "capture_visible_turns": False}), replace=False)

    def test_local_facade_preserves_records_and_pages_utf8(self):
        self.assertTrue(self.agent.handle({"op": "discover"})["ok"])
        self.assertFalse(list(self.root.iterdir()))
        self.configure()
        text = "合成记忆，不是执行授权。" * 180
        write = {"op": "remember", "request_id": "req_synthetic_facade_01", "kind": "fact", "text": text}
        result = self.agent.handle(write)
        self.assertTrue(result["ok"], result)
        memory_id = result["result"]["memory_id"]
        self.assertEqual(self.agent.handle(write), result)
        self.assertFalse(self.agent.handle({**write, "text": "changed"})["ok"])
        value = {"op": "recall", "memory_id": memory_id}
        fragments = []
        for _ in range(32):
            result = self.agent.handle(value)
            self.assertTrue(result["ok"], result)
            self.assertLessEqual(len(canonical_bytes(result)), 8192)
            fragments.extend(item["text"] for item in result["result"]["hits"])
            cursor = result["result"]["next_cursor"]
            if cursor is None:
                break
            value = {"op": "recall", "cursor": cursor}
        self.assertEqual("".join(fragments), text)
        self.assertEqual(ClientConfig.load(self.config).vault().handle({"op": "get", "memory_id": memory_id})["result"]["record"]["text"], text)
        failure = self.agent.handle({"op": "receive"})
        self.assertEqual(failure["error"]["code"], "network_not_configured")
        self.assertIn("commit_state", failure["error"])

    def test_facade_selects_current_cancellation_before_superseded_goal(self):
        self.configure()

        def remember(request_id, kind, text, relations=()):
            response = self.agent.handle({"op": "remember", "request_id": request_id,
                "kind": kind, "text": text, "relations": list(relations)})
            self.assertTrue(response["ok"], response)
            return response["result"]["memory_id"]

        failure = remember("req_current_target_failure", "observation",
            "Synthetic failed approach: fixture service stopped and the probe returned connection refused.")
        goal = remember("req_current_target_goal", "goal",
            "Synthetic goal: retry the fixture probe after the service is confirmed running.",
            [{"type": "derived_from", "target": failure}])
        remember("req_current_target_changed", "observation",
            "Synthetic revalidation: fixture service is now running; the previous failure is historical.",
            [{"type": "supersedes", "target": failure}])
        cancellation = remember("req_current_target_cancel", "decision",
            "Synthetic cancellation: the retry goal is cancelled; do not execute it.",
            [{"type": "supersedes", "target": goal}])
        for handoff in (False, True):
            response = self.agent.handle({"op": "recall", "query": "retry the fixture probe", "handoff": handoff})
            self.assertTrue(response["ok"], response)
            ids = [hit["memory_id"] for hit in response["result"]["hits"]]
            self.assertEqual(ids[0], cancellation)
            self.assertIn(goal, ids)
        vault = ClientConfig.load(self.config).vault()
        with vault._connect(writable=False) as connection:
            self.assertEqual(vault._memory_status(connection, goal), "superseded")
            self.assertEqual(vault._memory_status(connection, cancellation), "current")

    def test_http_python_and_cli_share_native_records_and_retry_semantics(self):
        from starlette.testclient import TestClient
        self.configure()
        token = "synthetic-endpoint-token-not-a-real-secret"
        with TestClient(create_app(self.agent, bearer_token=token)) as client:
            self.assertEqual(client.post("/v1/agent", json={"op": "discover"}).status_code, 401)
            headers = {"authorization": "Bearer " + token}
            self.assertEqual(client.get("/.well-known/agent-memory.json", headers=headers).json()["role"], "trusted_endpoint")
            command = {"op": "remember", "request_id": "req_native_shared_01",
                       "kind": "fact", "text": "Synthetic native cross-runtime memory"}
            result = client.post("/v1/agent", headers=headers, json=command).json()
            self.assertTrue(result["ok"], result)
            self.assertEqual(self.agent.handle(command), result)
            completed = subprocess.run([sys.executable, str(ROOT / "memory_vault_client.py"),
                "--config", str(self.config), "agent", "request"], input=canonical_bytes(command) + b"\n",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
            self.assertEqual(json.loads(completed.stdout), result)
            memory_id = result["result"]["memory_id"]
            recalled = client.post("/v1/agent", headers=headers,
                                   json={"op": "recall", "memory_id": memory_id}).json()
            self.assertEqual(recalled["result"]["hits"][0]["text"], command["text"])
            changed = {**command, "text": "changed under the same request"}
            self.assertEqual(client.post("/v1/agent", headers=headers, json=changed).json(), self.agent.handle(changed))
            self.assertFalse(self.agent.handle({**command, "request_id": "req_native_shared_02", "task_id": "parent"})["ok"])
            self.assertEqual(client.get("/.well-known/agent-card.json", headers=headers).status_code, 404)
            self.assertEqual(client.post("/message:send", headers=headers, json={}).status_code, 404)

    def test_receive_unicode_page_retains_full_text_references_after_ack(self):
        from tests.test_network_worker import fixture
        with fixture() as (sender, recipient, transport):
            texts = ["😀" * 600 + str(index) for index in range(4)]
            for index, text in enumerate(texts):
                sender.send("req_native_emoji_page_" + str(index), [recipient.identity.key_id], text)
            agent = Agent(recipient.client_config.path, recipient.config_path, transport=transport)
            result = agent.handle({"op": "receive", "limit": 4})
            self.assertTrue(result["ok"], result)
            self.assertLessEqual(len(canonical_bytes(result)), 8192)
            messages = result["result"]["messages"]
            self.assertEqual(len(messages), 4)
            for message, original in zip(messages, texts):
                self.assertTrue(message["text_partial"])
                request = {"op": "recall", "memory_id": message["text_memory_id"]}
                fragments = []
                for _ in range(16):
                    page = agent.handle(request)
                    self.assertTrue(page["ok"], page)
                    fragments.extend(hit["text"] for hit in page["result"]["hits"])
                    cursor = page["result"]["next_cursor"]
                    if cursor is None:
                        break
                    request = {"op": "recall", "cursor": cursor}
                self.assertEqual("".join(fragments), original)
            # A second relay may replay the larger cached previews produced by
            # an earlier alpha. Projection must not mutate the stored evidence.
            with recipient.db() as connection:
                for message in messages:
                    legacy = {**message, "text": "😀" * 512, "text_partial": True}
                    legacy.pop("text_memory_id")
                    connection.execute("UPDATE inbox SET result=? WHERE message_id=?",
                                       (canonical_bytes(legacy).decode(), message["message_id"]))
            replay = agent.handle({"op": "receive", "limit": 4})
            self.assertTrue(replay["ok"], replay)
            self.assertEqual(len(replay["result"]["messages"]), 4)
            self.assertLessEqual(len(canonical_bytes(replay)), 8192)
            self.assertEqual([item["text_memory_id"] for item in replay["result"]["messages"]],
                             [item["text_memory_id"] for item in messages])


if __name__ == "__main__":
    unittest.main()
