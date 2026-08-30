# Local retrieval and the disposable index

The standard-library core implements local fragment BM25, the ten small
Chinese/English concept groups from the former taskless runtime, polarity
hints, evidence diversity and explainable ranking. It imports no old runtime,
Git integration, model, embedding library or external service.

This is a source capability description. The public synthetic cases in
`tests/test_v025_retrieval_views.py` have been added for independent review;
they were not executed during this implementation.

## Request and compatibility

```json
{"op":"recall","query":"不要把备份和同步绑到任务","limit":8,"maximum_context_bytes":8192}
```

Existing `recall` and `handoff` request fields and result fields remain. The
optional `semantic: false` disables the deterministic concept bridge; local
lexical matching, graph neighbors and the existing dynamic handoff remain.
`capabilities` advertises the profile and the new view/index operations.

Each hit still has `memory_id`, `kind`, `text`, `text_truncated`, `entities`,
`relations`, provenance, verification, status, `score_milli` and
`matched_tokens`. It additionally contains:

- `fragment`: an exact substring with `start_character` and `end_character`
  offsets into the canonical record text, a record-local fragment identifier,
  and an explicitly unauthenticated role hint;
- `score_components`: integer thousandths for lexical/concept/entity/phrase/
  graph contributions and role/kind/state/recency factors;
- `explanation`: fixed interpretation labels, not new facts or instructions.

`text` is now the best matching original-text fragment instead of necessarily
the beginning of a long record. `text_truncated` says that it is not the full
canonical text. Use the existing `get` operation with the record ID to inspect
the full evidence. Character offsets are Unicode code-point offsets, not
UTF-8 byte offsets. No fragment changes the canonical record, ID or signature.

The top-level `retrieval` result reports the profile, index completeness,
candidate/fragment/byte bounds and whether a working-set bound truncated the
search. Results are not an exhaustive enumeration of the Vault.

## Ranking stages

1. Use the existing indexed CJK/Latin tokens, expanded with fixed bilingual
   groups for backup, transfer, performance, memory, removal, conflict,
   preference, correction, local/offline and privacy/encryption. Latin words
   match whole words; CJK terms match normalized phrases.
2. Select at most 512 indexed candidate records, plus at most 128 related
   admitted records from a bounded relation query. Current injected trust is
   checked before a record or a graph neighbor can enter this working set.
3. Read at most 8 MiB of canonical candidate record bytes and score at most
   4096 original-text fragments. Fragments use at most 1600 characters, prefer
   newline boundaries and overlap by up to 128 characters.
4. Compute BM25 (`k1=1.35`, `b=0.72`) over the **bounded candidate fragment
   corpus**. Its document frequencies and average lengths are local reranking
   statistics, not a claim to global full-Vault BM25. Scores from different
   queries are not calibrated or comparable probabilities.
5. Add concept Jaccard similarity and entity/phrase/related-evidence hints.
   A negation mismatch reduces concept similarity to one quarter; it does not
   delete opposing evidence. The ten hand-authored groups are not semantic
   understanding, a learned model or a universal translator.
6. Apply soft role, kind, graph-state and recency factors. Superseded/resolved
   evidence remains eligible but is de-emphasized. Return the strongest
   fragment per record and suppress identical excerpt/kind/state duplicates.

The episode record currently stores conventional `User:` / `Assistant:` text,
not separately authenticated role segments. Parsing those labels is only a
ranking heuristic. The `role_hint_authenticated` field is always false. An
embedded label, a high score, a recent timestamp or even a valid signature
does not prove what a user said or create authorization.

Retrieval never performs automatic semantic extraction. Decisions, constraints
or summaries still have to be supplied explicitly as evidence-backed memory by
the host/agent. The old taskless implementation also did not automatically
generate such semantic claims from each visible turn.

## Existing 0.24 indexes and explicit repair

The former reference core indexed only the first 4096 tokens per record. New
writes index the bounded full canonical text and exact entity labels. This is
a **derived index improvement**, not a record-format migration.

Existing `remember`, `get`, import and lexical recall remain usable. If the
old index has not been rebuilt, recall says `retrieval.index.complete: false`;
long-record tail matches may remain unavailable. Exact entity/claim timelines
refuse an incomplete index with the content-free error
`retrieval_index_required`, rather than pretending a partial timeline is full.
No read-only request silently creates tables or rebuilds the database.

The explicit maintenance operation processes a bounded page:

```json
{"op":"memory.reindex","after":0,"limit":32,"request_id":"req_synthetic_reindex_page_0001"}
```

Copy the returned `through` snapshot and `next_after` into the next request,
using a fresh request ID for that page. Stop when `next_after` is null, and
check `index.complete` (not only `range_complete`). An arbitrary cursor that
skips older unindexed records cannot falsely make the index complete. A later
old-version writer can add unindexed records; run another explicit pass then.
New native writes index themselves inside the same local transaction.

`memory.reindex` changes only disposable index rows and its own exact-effect
request receipt. It does not update memory text, record IDs, relations,
admissions, attestations, existing receipts or delivery cursors. It does not
publish a memory delta or grant any permission.

The optional SQLite tables are:

```text
memory_entities(entity, memory_id)             primary key (entity,memory_id)
retrieval_index(memory_id, profile, token_count, timeline_key)
```

`timeline_key` is a derived fixed-microsecond UTC sort key. The index profile is
`full-record-terms+entities/v1`. The canonical database version remains v2;
these tables are rebuildable accelerators, never a second memory authority.
The in-process helpers `Vault.ensure_retrieval_tables(connection)` and
`Vault.rebuild_record_index(connection, validated_record)` let an authorized
backup/restore tool rebuild the same index inside its own transaction.

## Trust and performance limits

All context candidates use the same admission/current-trust checks as the
existing core. Quarantined or currently revoked records cannot appear as
retrieval fragments or admitted neighbors. A lower-admission relation cannot
retire a higher-admission record. The surviving evidence remains untrusted
history, never permission or an instruction.

Bounds limit the data reranked in Python; they are not a latency benchmark.
Indexed term selection, index-completeness metadata checks and SQLite work
still depend on database size and storage. No online service, secret model
call or background rebuild is hidden in this path. A complete index is not
proof of complete recall quality, and no runtime performance claim is made
without external measurements.
