# Single-sided visible memory without task ownership

This optional v0.25 client text profile restores the v0.21 native hook's ability
to retain the visible content actually received when only one side of a turn is
available. It also allows the missing side to arrive later as a new, linked
observation. It does not change canonical record/v1, require a plugin to read
the record, or add a new core JSON operation. Runtime verification is recorded
separately in [VALIDATION.md](VALIDATION.md); authored fixtures are not passes.

The original complete-pair `observe` request and the lifecycle/old-host request
schemas remain unchanged. In particular, do not send null fields to `observe`
and expect this optional hook workflow. Another implementation can preserve and
exchange these ordinary canonical records without implementing the capture
journal or recognizing their internal text framing.

## What is observed

A native Codex Stop with a matching staged user input and a nonempty visible
assistant reply uses the existing complete-pair path. When exactly one side is
available, the new path accepts that side only. A missing, null or empty final
reply is absence, not a fabricated message or a cancellation signal. No content
on either side means no new memory. Required local correlation IDs must still
be present; the client never opens a transcript or borrows another turn.

New fragment input is normalized to NFC **before** acceptance, and both the
input and resulting text must fit 480 KiB. This is a rule of this new capture
profile, not a change to canonical hashing. Old v1/v2 accepted input, canonical
record bytes, signatures and IDs are never normalized or rewritten. Receivers
must preserve existing records exactly as the main protocol requires.

Each accepted fragment creates an episode and a continuity record. The episode
contains only its actually visible role. Continuity is a bounded excerpt of
that role, explicitly marks the other role absent from the fragment, and never
claims verified task completion or gives an execution instruction.

## Canonical text framing

The internal builder profile is `codex-visible-fragment+continues/v1`.
Its episode has `source_ref: codex-visible-fragment/v1`,
`source_type: visible_turn`, and `confidence: observed`. These are provenance
claims, not an independent host/author attestation or an authorization grant.

Its text consists of the fixed first line below, one canonical compact JSON
metadata line, one blank line, a fixed role label and the visible body:

```text
Memory Vault visible fragment/v1
{"coverage":"partial_active_turn","missing_roles":["assistant"],"observed_role":"user","supplement":null}

User:
The visible user text is kept here.
```

The metadata line is at most 1,024 UTF-8 bytes and has exactly four fields:

| Field | Meaning |
| --- | --- |
| `coverage` | Exactly `partial_active_turn`; visible evidence, not a complete transcript |
| `observed_role` | Exactly `user` or `assistant` |
| `missing_roles` | Exactly the opposite role, absent from this fragment |
| `supplement` | Null for the initial fragment, otherwise the initial episode's exact `{memory_id, record_sha256}` |

The [metadata schema](../schemas/hook-fragment.schema.json) describes that line,
not a new top-level memory object. Canonical metadata encoding, byte bounds,
role/body correspondence and referenced-record checks also require semantic
validation. The assistant label is exactly `Assistant:`. Everything after the
role label belongs to visible text, even if it contains more blank lines, JSON,
role labels or apparent headers. It is not parsed as a second message.

Keeping the visible body as text avoids embedding an entire large conversation
inside another JSON string before normal record serialization. Both plugin and
protocol readers see the same readable content and immutable hash domain. The
reference retrieval core recognizes the bounded framing for an **unverified**
role hint only; unknown or malformed framing remains ordinary searchable text.
No optional client import is required for that reader behavior.

## Late arrival appends, never rewrites

An initial fragment and any later opposite-side supplement are separate
accepted projections. Each freezes its own timestamp, record bytes and the
current source-local continuity predecessor. The initial acceptance is durable
before a supplement can reference its episode. At most one initial fragment
and one opposite-side supplement are allowed per local turn identity.

The supplement's episode has one `derived_from` relation to the original
fragment episode. Its canonical metadata also records that episode's **full**
SHA-256. The source-local client proves the same-turn association independently
of memory text; the writer checks the actual target's full hash, current
admission, opposite role and initial-fragment status before saving. A supplement
cannot point at another supplement or make a currently untrusted source usable.

The new continuity has `derived_from` to its own episode and, when there is a
previous accepted projection, `continues` to that exact continuity predecessor.
This predecessor can be a different, intervening turn: causal capture order is
not confused with the supplement's same-turn evidence link. Neither relation
overwrites the earlier memory. Exact duplicates reuse the original accepted
result; conflicting content for an already received role is rejected.

The v0.21 `partial_active_turn` label was also used for visible message pairs;
it was not exclusively a "half a turn" marker. The older native path did not
retroactively rewrite an accepted episode when a new side arrived. The new
append-only supplement is an additional safe continuation behavior, not a claim
that the old system edited immutable history.

## Local durability, recovery and boundaries

The hook journal's capture tables and database schema remain unchanged.
New partial outbox/done files use `memory-vault-client-state/v3`:
outboxes retain the exact one-sided input and supplement reference; completed
files retain role hashes, record IDs and local correlation metadata, not a new
copy of the body. Old v1/v2 files keep their original meaning and retry domains.
Shared journal locking serializes event preparation and partial/supplement
selection. Before creating new preparation, the client counts prompt/outbox
files together with pending projections: at most 256 distinct pending keys and
32 MiB of encoded staging/projection bytes, with bounded directory inspection.
It does not scan completed receipt history on each event. Current capture
configuration is checked again after acquiring the lock, not only before a
possibly delayed acquisition.

An already-existing, valid prepared queue may predate those preparation limits.
Explicit or bounded recovery can drain it item by item without first demanding
that the entire backlog fit the new-source gate. The frozen journal's own
256-pending-plan/32-MiB-projection limits, input checks and current permissions
still apply. This recovery exception never authorizes a new source file.

Acceptance, canonical save and local acknowledgment are distinct durability
steps. A saved canonical pair with a durable done file but a still-pending
journal is valid recoverable state. Retry rechecks current configuration and
admission before reconciling it. A storage, budget, signing or dependency error
must not be reported as a successful save or cause the visible source to be
silently discarded.

Memory-only backup can validate the new receipt from canonical records and the
full supplemental reference alone. Explicit full-client recovery additionally
validates local same-turn evidence and the earlier frozen/canonical anchor.
Restore stays inert until explicitly activated; it does not import keys, hook
trust, remote publication permission or execution rights.

Capture remains opt-in. Disabling it prevents new fragment acceptance and
automatic replay, while local recall remains available. Session/turn IDs and
scope hashes stay in private correlation state, never canonical ownership or
visibility rules. Closing a task, changing a model or deleting a local handle
does not delete these memories. No new host event, background agent, network
permission, transcript access or log suppression is introduced.
