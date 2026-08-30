# Dynamic claim timelines and bounded graphs

`memory.views` and `memory.graph` are optional local cognitive-view operations.
They read the same taskless canonical records used by both protocol and full
client modes. They never create Task directories, own memories, alter records,
or execute proposed next actions.

The operations are implemented in the single standard-library core. Public
synthetic cases are supplied in `tests/test_v025_retrieval_views.py`. Two
retrieval-only cases from that file passed at source
`ecb83fdc3045545c9cfd1a07ea312dfadf8f314d` in the limited
[offline synthetic follow-up](V0_25_FOLLOWUP_SMOKE.md); they do not exercise or
validate the `memory.views` or `memory.graph` operations described here.
The actual graph/view cases and the expanded current-trust revocation case
remain unexecuted. The earlier twelve-case smoke run at `066cd56` does not
cover the later retrieval changes either. This document is not graph/view
acceptance evidence or a deployment, cryptographic or real-host certification.

## A claim is an association, not a container

An exact entity label can associate revisions of one matter. Compatibility
conversion uses `claim:v021:<claim_key>` and preserves the old semantic kind as
`semantic:v021:<kind>`. Overflow relation projections may also use
`claim:v021:projection:<digest>`; an original claim label takes precedence when
both exist. These are ordinary untrusted associations in the existing
`entities` array, not schema-mandated ownership fields.

```json
{"op":"memory.views","entity":"claim:v021:synthetic-storage-choice","maximum_nodes":128}
```

Alternatively select a `memory_id` or a free-text `query`. These selectors
are mutually exclusive. A selected record's claim label retrieves that exact
entity timeline. Without a claim label, only effective `supersedes`,
`conflicts_with` and `resolves` edges build a semantic component.

Sharing an episode, a source, a Task reference, `derived_from`, `supports`,
`related_to` or `continues` does **not** merge two matters. Task/project/model/
conversation references never select, partition or authorize a view.
Identical entity text is itself an association claim, not proof that two facts
are true or that two memories have the same owner.

## View result

Each view contains:

- a derived `view_id`, grouping description and optional entity label;
- `timeline`, ordered by the real UTC instant and record ID, with bounded
  original excerpts, verification, per-record status and typed state reasons;
- `current_memory_ids` and a derived current/superseded/conflicted/resolved
  state;
- `truncated`, `has_more`, `earlier_pages_omitted`,
  `state_is_page_local`, `external_state_relations` and `next_request`.

The current-state calculation keeps the existing admission-strength boundary:
unsigned content cannot retire a verified record. A signature is not proof of
truth; the ranking only prevents a weaker relation from overriding a stronger
admission. Quarantined/currently revoked endpoints do not contribute context
or state effects. Effective incoming resolution takes precedence over
supersession, then unresolved conflict, then current state; no timestamp elects
a winning fact. Historical records are never silently erased.

At most eight state-reason edges are included per timeline entry; a separate
flag marks omitted reasons. Per-entry text/entity display is also bounded.
Use `get` for the full immutable record and `memory.graph` for a selected
neighborhood. The global node budget is at most 512 per request, with at most
32 views. Each selected component/entity page reads at most 8 MiB of canonical
records. Bounds are disclosed, not presented as a complete-Vault scan.

## Full timelines with explicit paging

An exact entity timeline uses the disposable entity index. An old/incomplete
index returns `retrieval_index_required`; first use the explicit, paginated
`memory.reindex` described in [RETRIEVAL.md](RETRIEVAL.md). A view never rebuilds
the index on its read path.

If one entity has more records than a page can hold, follow the view's
`next_request` exactly. It includes the entity, `after_memory_id` and a local
`through` ingestion snapshot. The next page uses the cursor's normalized UTC
instant plus record ID, so whole-second and microsecond timestamps paginate
correctly. Keep previously returned timeline entries and combine them by
record ID; no page rewrites a previous memory.

`through` freezes the eligible **record set**, not authority. Current trust
and state are rechecked on each page. If trust changes during enumeration,
restart to obtain a coherent newly admitted view; an old cursor cannot
re-admit revoked content. New records arriving after `through` are visible on
a new scan, not silently mixed into the old pagination snapshot.

The last page can still say `truncated: true` because earlier pages were omitted
from that individual response. `has_more: false` and `next_request: null` mean
the current entity enumeration has reached its end. A page-local state must
not be presented as the global latest claim without gathering its other pages.

Without a selector, views enumerate admitted seeds by local ingestion sequence.
Raw episode records are omitted as default claim seeds; they remain accessible
through `get`, retrieval and explicit graph selection.
Follow the top-level `next_request` to scan further seeds. Multiple seed pages
may rediscover one claim; use its `view_id`/entity to deduplicate and the
entity-specific pagination to collect its full timeline. A bounded query view
is a search result, not an enumeration of every matching matter.

## Suggestions never execute

A complete, unconflicted view that includes current and historical evidence can
produce `consolidation_proposals`. Each proposal explicitly has:

```json
{"status":"proposal_only","executable":false,"authority":"none","action":"retain_current_with_historical_evidence"}
```

The actual result also includes every selected evidence ID, the current IDs
and historical IDs. Partial/paged views and views with external state reasons
do not generate a misleading complete-history proposal. A later agent may
separately propose a summary under the current user's intent, retaining the
evidence references. This operation itself performs no summary write,
deletion, policy change, tool call or agent execution.

## Bounded graph traversal

```json
{"op":"memory.graph","memory_id":"mem_0000000000000000000000000000000000000000","maximum_depth":4,"maximum_nodes":128,"maximum_edges":1024}
```

Replace the synthetic ID with an admitted record ID. The operation follows
both incoming and outgoing references for neighborhood discovery but preserves
each edge's original source, target and type. All seven record/v1 relation
types can be inspected. `state_effective` separately tells whether a semantic
edge meets the existing admission-strength rule; other displayed references
do not acquire state-changing power.

Traversal has hard depth/node/edge/record-byte bounds and reports reasons,
frontier IDs, frontier truncation and observed depth. Select an admitted
frontier ID for another bounded neighborhood if needed. This is not a promise
that arbitrary oversized graphs can be exhaustively returned in one request.
`cycle_detected` concerns the directed edges in the returned subgraph only;
false does not prove the rest of a truncated graph acyclic.

Every result retains the fixed untrusted-memory authority envelope and reports
`network_accessed: false`, `records_changed: false` and `authority: none`.
Neither recalled instructions nor entity labels can alter these boundaries.
