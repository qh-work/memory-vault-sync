"""Deterministic, bounded views over the taskless memory-event graph.

The durable episode/event files remain authoritative.  Everything in this
module is a disposable projection: it can be rebuilt from indexed event
fragments and relation edges, and it never assigns a task, conversation, or
device as a memory owner.
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections import defaultdict, deque
from typing import Any, Iterable, Mapping, Sequence

from memory_vault_runtime.protocol import jcs_json_bytes


GRAPH_VIEW_SCHEMA = "memory-network-views/v1"
GRAPH_VIEW_CONTRACT = "memory-network-current-view/v1"
MAX_CLAIMS = 256
MAX_EVENTS = 4096
MAX_EDGES = 16384
MAX_TRAVERSAL_DEPTH = 8
MAX_TRAVERSAL_NODES = 512
MAX_PROPOSALS = 64
_RELATIONS = frozenset({"parents", "supersedes", "conflicts_with", "resolves"})
_STATES = frozenset({"current", "superseded", "conflicted", "resolved"})


class GraphViewError(ValueError):
    """The derived graph view cannot be safely or deterministically built."""


@dataclasses.dataclass(frozen=True)
class EventRecord:
    """Small event projection extracted from immutable indexed evidence."""

    event_id: str
    claim_key: str
    kind: str
    source_id: str
    revision_id: str | None
    captured_at: str


@dataclasses.dataclass(frozen=True)
class TimelineEntry:
    event_id: str
    claim_key: str
    kind: str
    state: str
    source_id: str
    revision_id: str | None
    captured_at: str
    relation_reasons: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ClaimView:
    claim_key: str
    state: str
    current_event_ids: tuple[str, ...]
    timeline: tuple[TimelineEntry, ...]
    explanation: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ConsolidationProposal:
    proposal_id: str
    claim_key: str
    action: str
    status: str
    evidence_event_ids: tuple[str, ...]
    reason: str


@dataclasses.dataclass(frozen=True)
class TraversalResult:
    root_event_id: str
    event_ids: tuple[str, ...]
    edges: tuple[tuple[str, str, str], ...]
    depth_reached: int
    cycle_detected: bool
    truncated: bool


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise GraphViewError(f"{label} is invalid")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for character in value):
        raise GraphViewError(f"{label} is invalid")
    return value


def _claim_key(value: Any) -> str:
    key = _identifier(value, "claim key")
    if key.startswith(("task-", "conversation-", "device-", "workspace-")):
        raise GraphViewError("claim key cannot encode an owner")
    return key


def _event_record(value: EventRecord | Mapping[str, Any]) -> EventRecord:
    if isinstance(value, EventRecord):
        record = value
    elif isinstance(value, Mapping):
        allowed = {
            "event_id",
            "claim_key",
            "kind",
            "source_id",
            "revision_id",
            "captured_at",
        }
        if set(value) != allowed:
            raise GraphViewError("event projection fields are invalid")
        record = EventRecord(
            event_id=value["event_id"],
            claim_key=value["claim_key"],
            kind=value["kind"],
            source_id=value["source_id"],
            revision_id=value.get("revision_id"),
            captured_at=value["captured_at"],
        )
    else:
        raise GraphViewError("event projection is invalid")
    if (
        not isinstance(record.captured_at, str)
        or not record.captured_at
        or len(record.captured_at) > 64
    ):
        raise GraphViewError("captured at is invalid")
    return EventRecord(
        event_id=_identifier(record.event_id, "event id"),
        claim_key=_claim_key(record.claim_key),
        kind=_identifier(record.kind, "event kind"),
        source_id=_identifier(record.source_id, "source id"),
        revision_id=(
            _identifier(record.revision_id, "revision id")
            if record.revision_id is not None
            else None
        ),
        captured_at=record.captured_at,
    )


def _edge(value: Sequence[Any]) -> tuple[str, str, str]:
    if not isinstance(value, (tuple, list)) or len(value) != 3:
        raise GraphViewError("graph edge is invalid")
    source = _identifier(value[0], "edge source")
    target = _identifier(value[1], "edge target")
    relation = _identifier(value[2], "edge relation")
    if relation not in _RELATIONS:
        raise GraphViewError("graph relation is invalid")
    return source, target, relation


def _canonical_event_order(record: EventRecord) -> tuple[str, str]:
    return record.captured_at, record.event_id


def _event_state(
    event_id: str,
    incoming: Mapping[str, Sequence[tuple[str, str]]],
    outgoing: Mapping[str, Sequence[tuple[str, str]]],
) -> tuple[str, tuple[str, ...]]:
    incoming_relations = tuple(sorted(relation for _source, relation in incoming.get(event_id, ())))
    outgoing_relations = tuple(sorted(relation for _target, relation in outgoing.get(event_id, ())))
    if "resolves" in incoming_relations:
        return "resolved", ("resolved_by_later_event",)
    if "supersedes" in incoming_relations:
        return "superseded", ("superseded_by_later_event",)
    if "conflicts_with" in incoming_relations or "conflicts_with" in outgoing_relations:
        return "conflicted", ("conflict_relation_present",)
    return "current", ("no_later_resolution_or_supersession",)


def build_claim_views(
    events: Iterable[EventRecord | Mapping[str, Any]],
    edges: Iterable[Sequence[Any]],
    *,
    claim_key: str | None = None,
    maximum_claims: int = MAX_CLAIMS,
    maximum_events: int = MAX_EVENTS,
    maximum_edges: int = MAX_EDGES,
) -> tuple[ClaimView, ...]:
    """Build byte-stable claim timelines from bounded derived inputs."""

    if not isinstance(maximum_claims, int) or isinstance(maximum_claims, bool) or not 1 <= maximum_claims <= MAX_CLAIMS:
        raise GraphViewError("claim view bound is invalid")
    if not isinstance(maximum_events, int) or isinstance(maximum_events, bool) or not 1 <= maximum_events <= MAX_EVENTS:
        raise GraphViewError("event view bound is invalid")
    if not isinstance(maximum_edges, int) or isinstance(maximum_edges, bool) or not 1 <= maximum_edges <= MAX_EDGES:
        raise GraphViewError("edge view bound is invalid")
    selected_claim = _claim_key(claim_key) if claim_key is not None else None
    by_event: dict[str, EventRecord] = {}
    for raw in events:
        if len(by_event) >= maximum_events:
            raise GraphViewError("event view exceeds its bound")
        record = _event_record(raw)
        previous = by_event.get(record.event_id)
        if previous is not None and previous != record:
            raise GraphViewError("event projection identity is inconsistent")
        by_event[record.event_id] = record
    if selected_claim is not None:
        by_event = {
            event_id: record
            for event_id, record in by_event.items()
            if record.claim_key == selected_claim
        }
    edge_list: list[tuple[str, str, str]] = []
    for raw_edge in edges:
        if len(edge_list) >= maximum_edges:
            raise GraphViewError("graph edges exceed their bound")
        edge_list.append(_edge(raw_edge))
    edge_list = sorted(set(edge_list))
    known_ids = set(by_event)
    outgoing: dict[str, list[tuple[str, str]]] = defaultdict(list)
    incoming: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for source, target, relation in edge_list:
        if source in known_ids:
            outgoing[source].append((target, relation))
        if target in known_ids:
            incoming[target].append((source, relation))
    grouped: dict[str, list[EventRecord]] = defaultdict(list)
    for record in by_event.values():
        grouped[record.claim_key].append(record)
    if len(grouped) > maximum_claims:
        raise GraphViewError("claim view exceeds its bound")
    views: list[ClaimView] = []
    for key in sorted(grouped):
        timeline: list[TimelineEntry] = []
        for record in sorted(grouped[key], key=_canonical_event_order):
            state, reasons = _event_state(record.event_id, incoming, outgoing)
            timeline.append(
                TimelineEntry(
                    event_id=record.event_id,
                    claim_key=record.claim_key,
                    kind=record.kind,
                    state=state,
                    source_id=record.source_id,
                    revision_id=record.revision_id,
                    captured_at=record.captured_at,
                    relation_reasons=reasons,
                )
            )
        current = tuple(item.event_id for item in timeline if item.state == "current")
        has_conflict = any(item.state == "conflicted" for item in timeline)
        has_resolution = any(item.state == "resolved" for item in timeline)
        if has_conflict and not has_resolution:
            state = "conflicted"
        elif current:
            state = "current"
        elif has_resolution:
            state = "resolved"
        else:
            state = "superseded"
        explanation = [f"claim_key:{key}", f"timeline_events:{len(timeline)}"]
        if state == "conflicted":
            explanation.append("unresolved_conflict_visible")
        elif state == "resolved":
            explanation.append("later_resolution_is_anchored")
        elif state == "current":
            explanation.append("newest_unretired_evidence")
        else:
            explanation.append("all_evidence_is_historical")
        views.append(
            ClaimView(
                claim_key=key,
                state=state,
                current_event_ids=current,
                timeline=tuple(timeline),
                explanation=tuple(explanation),
            )
        )
    return tuple(views)


def traverse_graph(
    root_event_id: str,
    edges: Iterable[Sequence[Any]],
    *,
    maximum_depth: int = MAX_TRAVERSAL_DEPTH,
    maximum_nodes: int = MAX_TRAVERSAL_NODES,
) -> TraversalResult:
    """Return a deterministic, bounded neighborhood with cycle evidence."""

    root = _identifier(root_event_id, "root event id")
    if not isinstance(maximum_depth, int) or isinstance(maximum_depth, bool) or not 0 <= maximum_depth <= MAX_TRAVERSAL_DEPTH:
        raise GraphViewError("traversal depth is invalid")
    if not isinstance(maximum_nodes, int) or isinstance(maximum_nodes, bool) or not 1 <= maximum_nodes <= MAX_TRAVERSAL_NODES:
        raise GraphViewError("traversal node bound is invalid")
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    normalized_edges = sorted({_edge(edge) for edge in edges})
    for source, target, relation in normalized_edges:
        adjacency[source].append((target, relation))
        adjacency[target].append((source, relation))
    queue: deque[tuple[str, int, tuple[str, ...]]] = deque([(root, 0, (root,))])
    seen: set[str] = {root}
    result_edges: set[tuple[str, str, str]] = set()
    cycle = False
    truncated = False
    depth_reached = 0
    while queue:
        current, depth, path = queue.popleft()
        depth_reached = max(depth_reached, depth)
        if depth >= maximum_depth:
            continue
        for neighbor, relation in sorted(adjacency.get(current, ())):
            edge = (current, neighbor, relation) if current <= neighbor else (neighbor, current, relation)
            result_edges.add(edge)
            if neighbor in path:
                cycle = True
                continue
            if neighbor in seen:
                continue
            if len(seen) >= maximum_nodes:
                truncated = True
                continue
            seen.add(neighbor)
            queue.append((neighbor, depth + 1, (*path, neighbor)))
    return TraversalResult(
        root_event_id=root,
        event_ids=tuple(sorted(seen)),
        edges=tuple(sorted(result_edges)),
        depth_reached=depth_reached,
        cycle_detected=cycle,
        truncated=truncated,
    )


def build_consolidation_proposals(
    views: Iterable[ClaimView],
    *,
    maximum: int = MAX_PROPOSALS,
) -> tuple[ConsolidationProposal, ...]:
    """Suggest evidence-preserving consolidation; never mutate an event."""

    if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= MAX_PROPOSALS:
        raise GraphViewError("proposal bound is invalid")
    proposals: list[ConsolidationProposal] = []
    for view in sorted(views, key=lambda item: item.claim_key):
        historical = tuple(
            item.event_id for item in view.timeline if item.state != "current"
        )
        if len(view.timeline) < 2 or not view.current_event_ids or not historical:
            continue
        evidence = tuple(item.event_id for item in view.timeline)
        domain = {
            "schema_version": GRAPH_VIEW_SCHEMA,
            "claim_key": view.claim_key,
            "action": "retain_current_with_historical_evidence",
            "evidence_event_ids": list(evidence),
        }
        proposal_id = "proposal-" + hashlib.sha256(jcs_json_bytes(domain)).hexdigest()[:40]
        proposals.append(
            ConsolidationProposal(
                proposal_id=proposal_id,
                claim_key=view.claim_key,
                action="retain_current_with_historical_evidence",
                status="proposal_only",
                evidence_event_ids=evidence,
                reason="semantic publication must cite every retained event; no automatic rewrite",
            )
        )
        if len(proposals) >= maximum:
            break
    return tuple(proposals)


def view_document(
    views: Iterable[ClaimView],
    proposals: Iterable[ConsolidationProposal] = (),
) -> dict[str, Any]:
    """Serialize a projection with stable ordering and no hidden reasoning."""

    ordered_views = sorted(views, key=lambda item: item.claim_key)
    ordered_proposals = sorted(proposals, key=lambda item: item.proposal_id)
    return {
        "schema_version": GRAPH_VIEW_SCHEMA,
        "contract": GRAPH_VIEW_CONTRACT,
        "claims": [
            {
                "claim_key": view.claim_key,
                "state": view.state,
                "current_event_ids": list(view.current_event_ids),
                "timeline": [
                    {
                        "event_id": item.event_id,
                        "claim_key": item.claim_key,
                        "kind": item.kind,
                        "state": item.state,
                        "source_id": item.source_id,
                        "revision_id": item.revision_id,
                        "captured_at": item.captured_at,
                        "relation_reasons": list(item.relation_reasons),
                    }
                    for item in view.timeline
                ],
                "explanation": list(view.explanation),
            }
            for view in ordered_views
        ],
        "consolidation_proposals": [
            {
                "proposal_id": proposal.proposal_id,
                "claim_key": proposal.claim_key,
                "action": proposal.action,
                "status": proposal.status,
                "evidence_event_ids": list(proposal.evidence_event_ids),
                "reason": proposal.reason,
            }
            for proposal in ordered_proposals
        ],
    }


def view_bytes(
    views: Iterable[ClaimView],
    proposals: Iterable[ConsolidationProposal] = (),
) -> bytes:
    """Return canonical bytes for rebuild-equivalence tests and caches."""

    return jcs_json_bytes(view_document(views, proposals))
