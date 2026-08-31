"""Synthetic request-local index-state cases; authored, not executed.

Only disposable fixture Vaults are used. Query-call counts are regression
assertions, not performance measurements or evidence of a passed run.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import memory_vault as core


class RequestLocalIndexStateTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.vault = core.Vault(Path(temporary.name) / "synthetic.sqlite3")

    def ask(self, operation: str, **arguments: object) -> dict:
        response = self.vault.handle({"op": operation, **arguments})
        self.assertTrue(response["ok"], response)
        return dict(response["result"])

    def remember(self, number: int, *, claim: bool = True) -> str:
        return str(self.ask(
            "remember", kind="fact", text=f"Synthetic independent matter {number}",
            entities=[f"claim:synthetic-index-{number}"] if claim else [],
        )["memory_id"])

    def test_multiple_claims_share_one_index_check_in_one_read_transaction(self) -> None:
        identifiers = {self.remember(number) for number in range(4)}
        original = core.Vault._retrieval_index_state
        snapshots: list[int | None] = []

        def inspect(connection, *, through=None):
            self.assertTrue(connection.in_transaction)
            snapshots.append(through)
            return original(connection, through=through)

        with mock.patch.object(core.Vault, "_retrieval_index_state", side_effect=inspect):
            result = self.ask("memory.views", limit=8)
        self.assertEqual(snapshots, [result["through"]])
        self.assertEqual(len(result["views"]), 4)
        self.assertEqual({
            item["memory_id"] for view in result["views"] for item in view["timeline"]
        }, identifiers)
        self.assertFalse(result["records_changed"])

    def test_same_snapshot_is_rechecked_after_index_damage_and_repair(self) -> None:
        identifiers = [self.remember(number) for number in range(3)]
        original = core.Vault._retrieval_index_state
        with mock.patch.object(core.Vault, "_retrieval_index_state", wraps=original) as inspect:
            first = self.ask("memory.views")
            self.assertEqual(inspect.call_count, 1)
            # Only fixture-derived metadata changes, not canonical memory.
            with contextlib.closing(self.vault._connect()) as connection, connection:
                connection.execute("DELETE FROM retrieval_index WHERE memory_id=?", (identifiers[-1],))
            failed = self.vault.handle({"op": "memory.views", "through": first["through"]})
            self.assertFalse(failed["ok"])
            self.assertEqual(failed["error"]["code"], "retrieval_index_required")
            self.assertEqual(inspect.call_count, 2)
        self.assertTrue(self.ask("memory.reindex")["complete"])
        with mock.patch.object(core.Vault, "_retrieval_index_state", wraps=original) as inspect:
            repaired = self.ask("memory.views", through=first["through"])
            self.assertEqual(inspect.call_count, 1)
        self.assertEqual(repaired["through"], first["through"])
        self.assertEqual(repaired["views"], first["views"])

    def test_plain_graph_views_do_not_eagerly_check_entity_indexes(self) -> None:
        memory_id = self.remember(0, claim=False)
        with mock.patch.object(core.Vault, "_retrieval_index_state") as inspect:
            result = self.ask("memory.views", memory_id=memory_id)
            inspect.assert_not_called()
        self.assertEqual(result["views"][0]["current_memory_ids"], [memory_id])


if __name__ == "__main__":
    unittest.main()
