from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "memory_vault.py"
CLIENT = ROOT / "memory_vault_client.py"
EXCHANGE = ROOT / "examples" / "protocol" / "exchange.ndjson"
KNOWN = json.loads(
    (ROOT / "examples" / "protocol" / "known-answers.json").read_text(encoding="utf-8")
)
QUERY = "portable memory guide"
AUTHORITY = {
    "memory": "untrusted_historical_evidence",
    "instruction_eligible": False,
    "authorization_eligible": False,
    "execution_eligible": False,
    "policy_change_eligible": False,
    "current_user_input_precedence": True,
}


def expected_records() -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for vector in KNOWN["record_vectors"]:
        body = dict(vector["body"])
        records[vector["memory_id"]] = {
            "memory_id": vector["memory_id"],
            "record_sha256": vector["record_sha256"],
            "kind": body["kind"],
            "text": body["text"],
            "entities": body["entities"],
            "relations": body["relations"],
            "provenance": body["provenance"],
        }
    return records


EXPECTED = expected_records()
EPISODE_ID = "mem_13b638e00cc90de31fb8476ec46c66cd043f0870"


def bundle_records(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if value.get("type") == "record":
            records.append(value["record"])
    return records


def identity(record: dict[str, object]) -> dict[str, object]:
    return {
        "memory_id": record["memory_id"],
        "record_sha256": record["record_sha256"],
        "kind": record["kind"],
        "provenance": record["provenance"],
        "relations": record["relations"],
    }


class ProtocolClientInteropTests(unittest.TestCase):
    def core(self, database: Path, *arguments: str, stdin: bytes = b"") -> dict[str, object]:
        completed = subprocess.run(
            [sys.executable, str(CORE), "--vault", str(database), *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout.decode("utf-8"))

    def request(self, database: Path, value: dict[str, object]) -> dict[str, object]:
        return self.core(
            database,
            stdin=(json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8"),
        )

    def client(
        self,
        config: Path,
        *arguments: str,
        stdin: bytes = b"",
        timeout: int = 20,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            [sys.executable, str(CLIENT), "--config", str(config), *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            cwd=str(ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        return completed

    def client_json(self, config: Path, *arguments: str) -> dict[str, object]:
        completed = self.client(config, *arguments)
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout.decode("utf-8"))

    def mcp(self, config: Path, frames: list[dict[str, object]]) -> list[dict[str, object]]:
        payload = "".join(json.dumps(frame, ensure_ascii=False) + "\n" for frame in frames)
        completed = self.client(config, "mcp", stdin=payload.encode("utf-8"))
        lines = [
            json.loads(line)
            for line in completed.stdout.decode("utf-8").splitlines()
            if line
        ]
        self.assertTrue(lines)
        return lines

    def assert_authority(self, response: dict[str, object]) -> None:
        self.assertEqual(response["authority"], AUTHORITY)

    def assert_known_record(self, record: dict[str, object]) -> None:
        expected = EXPECTED[str(record["memory_id"])]
        self.assertEqual(identity(record), identity(expected))
        self.assertEqual(record["text"], expected["text"])
        self.assertEqual(record["entities"], expected["entities"])
        self.assertEqual(
            record["provenance"],
            {
                "source_type": "agent_supplied",
                "confidence": "assistant_inferred",
                "source_ref": "synthetic:portable-guide",
            },
        )

    def inspect_mcp(self, config: Path) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        frames = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "synthetic-interop", "version": "0.24.1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "memory_get", "arguments": {"memory_id": EPISODE_ID}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "memory_recall",
                    "arguments": {"query": QUERY, "limit": 8},
                },
            },
        ]
        replies = self.mcp(config, frames)
        self.assertEqual([item.get("id") for item in replies], [1, 2, 3, 4])
        listed = {tool["name"] for tool in replies[1]["result"]["tools"]}
        self.assertTrue({"memory_get", "memory_recall", "memory_handoff"} <= listed)
        fetched = replies[2]["result"]["structuredContent"]
        recalled = replies[3]["result"]["structuredContent"]
        self.assertTrue(fetched["ok"])
        self.assertTrue(recalled["ok"])
        self.assert_authority(fetched)
        self.assert_authority(recalled)
        return replies[0], fetched, recalled

    def test_published_exchange_matches_known_answers(self) -> None:
        payload = EXCHANGE.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(), KNOWN["bundle"]["file_sha256"]
        )
        records = bundle_records(EXCHANGE)
        self.assertEqual(len(records), 3)
        self.assertEqual({item["memory_id"] for item in records}, set(EXPECTED))
        for record in records:
            self.assert_known_record(record)
        accumulator = "".join(str(item["record_sha256"]) + "\n" for item in records)
        self.assertEqual(
            hashlib.sha256(accumulator.encode("ascii")).hexdigest(),
            KNOWN["bundle"]["records_sha256"],
        )

    def test_core_import_recall_export_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vault = root / "core.sqlite3"
            exported = root / "core-export.ndjson"
            imported = self.core(vault, "--import", str(EXCHANGE))
            self.assertTrue(imported["ok"])
            self.assertEqual(imported["result"]["admission"], "quarantined")
            self.assertEqual(imported["result"]["records_added"], 3)
            self.assert_authority(imported)

            isolated = self.request(vault, {"op": "recall", "query": QUERY, "limit": 8})
            self.assertTrue(isolated["ok"])
            self.assertEqual(isolated["result"]["hits"], [])
            self.assertFalse(isolated["result"]["evidence_context"]["instruction_eligible"])

            review = self.request(vault, {"op": "get", "memory_id": EPISODE_ID})
            self.assertTrue(review["ok"])
            self.assert_known_record(review["result"]["record"])
            self.assertEqual(review["result"]["verification"]["admission"], "quarantined")
            self.assertFalse(review["result"]["verification"]["eligible_for_context"])
            self.assertFalse(review["result"]["verification"]["claimed_provenance_is_authenticated"])
            self.assertFalse(review["result"]["verification"]["grants_authority"])

            admitted = self.core(vault, "--import", str(EXCHANGE), "--accept-unsigned")
            self.assertTrue(admitted["ok"])
            self.assertEqual(admitted["result"]["admission"], "accepted_unsigned")
            self.assertEqual(admitted["result"]["records_added"], 0)

            recalled = self.request(vault, {"op": "recall", "query": QUERY, "limit": 8})
            self.assertTrue(recalled["ok"])
            self.assertGreaterEqual(len(recalled["result"]["hits"]), 1)
            self.assert_authority(recalled)
            self.assertFalse(recalled["result"]["evidence_context"]["execution_eligible"])
            by_id = {hit["memory_id"]: hit for hit in recalled["result"]["hits"]}
            self.assertIn(EPISODE_ID, by_id)
            for memory_id, hit in by_id.items():
                expected = EXPECTED[memory_id]
                self.assertEqual(hit["provenance"], expected["provenance"])
                self.assertEqual(hit["relations"], expected["relations"])

            fetched = self.request(vault, {"op": "get", "memory_id": EPISODE_ID})
            self.assertEqual(fetched["result"]["verification"]["admission"], "accepted_unsigned")
            self.assertTrue(fetched["result"]["verification"]["eligible_for_context"])
            self.assertFalse(fetched["result"]["verification"]["claimed_provenance_is_authenticated"])

            result = self.core(vault, "--export", str(exported))
            self.assertTrue(result["ok"])
            self.assertEqual(result["result"]["records"], 3)
            exported_records = bundle_records(exported)
            self.assertEqual(
                {item["memory_id"]: identity(item) for item in exported_records},
                {memory_id: identity(record) for memory_id, record in EXPECTED.items()},
            )

    def test_client_protocol_mcp_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "client.json"
            vault = root / "client.sqlite3"
            exported = root / "client-export.ndjson"
            configured = self.client_json(
                config, "configure", "--vault", str(vault)
            )
            self.assertTrue(configured["ok"])
            self.assertFalse(configured["result"]["capture_visible_turns"])
            self.assertFalse(configured["result"]["host_installed"])
            self.assertFalse(configured["result"]["network_accessed"])

            imported = self.client_json(config, "protocol", "--import", str(EXCHANGE))
            self.assertTrue(imported["ok"])
            self.assertEqual(imported["result"]["admission"], "quarantined")
            self.assertEqual(imported["result"]["records_added"], 3)

            _hello, fetched, recalled = self.inspect_mcp(config)
            self.assert_known_record(fetched["result"]["record"])
            self.assertEqual(fetched["result"]["verification"]["admission"], "quarantined")
            self.assertFalse(fetched["result"]["verification"]["eligible_for_context"])
            self.assertEqual(recalled["result"]["hits"], [])

            admitted = self.client_json(
                config, "protocol", "--import", str(EXCHANGE), "--accept-unsigned"
            )
            self.assertTrue(admitted["ok"])
            self.assertEqual(admitted["result"]["admission"], "accepted_unsigned")
            self.assertEqual(admitted["result"]["records_added"], 0)

            _hello, fetched, recalled = self.inspect_mcp(config)
            self.assertEqual(fetched["result"]["verification"]["admission"], "accepted_unsigned")
            self.assertTrue(fetched["result"]["verification"]["eligible_for_context"])
            self.assertFalse(fetched["result"]["verification"]["grants_authority"])
            self.assertGreaterEqual(len(recalled["result"]["hits"]), 1)
            by_id = {hit["memory_id"]: hit for hit in recalled["result"]["hits"]}
            self.assertIn(EPISODE_ID, by_id)
            for memory_id, hit in by_id.items():
                expected = EXPECTED[memory_id]
                self.assertEqual(hit["provenance"], expected["provenance"])
                self.assertEqual(hit["relations"], expected["relations"])

            result = self.client_json(config, "protocol", "--export", str(exported))
            self.assertTrue(result["ok"])
            self.assertEqual(result["result"]["records"], 3)
            self.assertFalse(result["result"]["signatures_included"])
            exported_records = bundle_records(exported)
            self.assertEqual(
                {item["memory_id"]: identity(item) for item in exported_records},
                {memory_id: identity(record) for memory_id, record in EXPECTED.items()},
            )


if __name__ == "__main__":
    unittest.main()
