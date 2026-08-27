import unittest

from memory_vault_runtime import graph_views


def event(event_id, claim_key="memory-preference", captured_at="2026-01-01T00:00:00Z", kind="user_preference"):
    return graph_views.EventRecord(
        event_id=event_id,
        claim_key=claim_key,
        kind=kind,
        source_id="src-a",
        revision_id="ep-a",
        captured_at=captured_at,
    )


class GraphViewTests(unittest.TestCase):
    def test_current_view_preserves_superseded_timeline_and_proposal(self):
        events = [
            event("evt-old", captured_at="2026-01-01T00:00:00Z"),
            event("evt-new", captured_at="2026-01-02T00:00:00Z", kind="correction"),
        ]
        views = graph_views.build_claim_views(
            events,
            [("evt-new", "evt-old", "supersedes")],
        )
        self.assertEqual(len(views), 1)
        self.assertEqual(views[0].state, "current")
        self.assertEqual(views[0].current_event_ids, ("evt-new",))
        self.assertEqual(
            [(item.event_id, item.state) for item in views[0].timeline],
            [("evt-old", "superseded"), ("evt-new", "current")],
        )
        proposals = graph_views.build_consolidation_proposals(views)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0].status, "proposal_only")
        self.assertEqual(
            proposals[0].evidence_event_ids,
            ("evt-old", "evt-new"),
        )

    def test_unresolved_conflict_remains_visible(self):
        views = graph_views.build_claim_views(
            [event("evt-a"), event("evt-b", captured_at="2026-01-02T00:00:00Z")],
            [("evt-b", "evt-a", "conflicts_with")],
        )
        self.assertEqual(views[0].state, "conflicted")
        self.assertEqual(
            {item.state for item in views[0].timeline},
            {"conflicted"},
        )
        self.assertIn("unresolved_conflict_visible", views[0].explanation)

    def test_resolution_is_anchored_and_old_events_remain(self):
        events = [
            event("evt-a"),
            event("evt-b", captured_at="2026-01-02T00:00:00Z"),
            event("evt-r", captured_at="2026-01-03T00:00:00Z", kind="conflict_resolved"),
        ]
        views = graph_views.build_claim_views(
            events,
            [
                ("evt-b", "evt-a", "conflicts_with"),
                ("evt-r", "evt-a", "resolves"),
                ("evt-r", "evt-b", "resolves"),
            ],
        )
        self.assertEqual(views[0].state, "current")
        self.assertEqual(views[0].current_event_ids, ("evt-r",))
        self.assertEqual(
            {item.event_id for item in views[0].timeline if item.state == "resolved"},
            {"evt-a", "evt-b"},
        )

    def test_same_claim_only_proposals_prevent_false_merge(self):
        events = [event("evt-a", claim_key="memory-a"), event("evt-b", claim_key="memory-b")]
        views = graph_views.build_claim_views(events, [])
        self.assertEqual({view.claim_key for view in views}, {"memory-a", "memory-b"})
        self.assertEqual(graph_views.build_consolidation_proposals(views), ())

    def test_traversal_is_bounded_and_detects_cycle(self):
        result = graph_views.traverse_graph(
            "evt-a",
            [
                ("evt-a", "evt-b", "parents"),
                ("evt-b", "evt-c", "supersedes"),
                ("evt-c", "evt-a", "resolves"),
            ],
            maximum_depth=8,
            maximum_nodes=8,
        )
        self.assertTrue(result.cycle_detected)
        self.assertEqual(result.event_ids, ("evt-a", "evt-b", "evt-c"))
        self.assertFalse(result.truncated)

    def test_traversal_rejects_unbounded_dos_request(self):
        with self.assertRaises(graph_views.GraphViewError):
            graph_views.traverse_graph("evt-a", [], maximum_nodes=513)
        with self.assertRaises(graph_views.GraphViewError):
            graph_views.build_claim_views([], [], maximum_events=4097)

    def test_rebuild_bytes_are_order_independent(self):
        events = [event("evt-a"), event("evt-b", captured_at="2026-01-02T00:00:00Z")]
        edges = [("evt-b", "evt-a", "supersedes")]
        first = graph_views.build_claim_views(events, edges)
        second = graph_views.build_claim_views(reversed(events), reversed(edges))
        self.assertEqual(
            graph_views.view_bytes(first, graph_views.build_consolidation_proposals(first)),
            graph_views.view_bytes(second, graph_views.build_consolidation_proposals(second)),
        )

    def test_owner_fields_and_invalid_relation_fail_closed(self):
        with self.assertRaises(graph_views.GraphViewError):
            graph_views.build_claim_views(
                [
                    {
                        "event_id": "evt-a",
                        "claim_key": "task-owner",
                        "kind": "decision",
                        "source_id": "src-a",
                        "revision_id": "ep-a",
                        "captured_at": "2026-01-01T00:00:00Z",
                    }
                ],
                [],
            )
        with self.assertRaises(graph_views.GraphViewError):
            graph_views.build_claim_views([event("evt-a")], [("evt-a", "evt-a", "owns")])

    def test_view_document_exposes_reasons_not_hidden_model_reasoning(self):
        views = graph_views.build_claim_views(
            [event("evt-a"), event("evt-b", captured_at="2026-01-02T00:00:00Z")],
            [("evt-b", "evt-a", "supersedes")],
        )
        document = graph_views.view_document(views, graph_views.build_consolidation_proposals(views))
        self.assertEqual(document["schema_version"], graph_views.GRAPH_VIEW_SCHEMA)
        self.assertIn("newest_unretired_evidence", document["claims"][0]["explanation"])
        self.assertIn("reason", document["consolidation_proposals"][0])


if __name__ == "__main__":
    unittest.main()
