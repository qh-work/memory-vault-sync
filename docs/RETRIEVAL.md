# Local retrieval and the disposable index

The standard-library core implements local fragment BM25, the ten small
Chinese/English concept groups from the former taskless runtime, polarity
hints, evidence diversity and explainable ranking. It imports no old runtime,
Git integration, model, embedding library or external service.

This is a source capability description with limited execution evidence. At
source `ecb83fdc3045545c9cfd1a07ea312dfadf8f314d`, two selected retrieval
regressions passed as part of the six-case
[offline synthetic follow-up](V0_25_FOLLOWUP_SMOKE.md): protecting a direct
match with a unique query word from concept expansion, and retrieving the
tails of seven roughly 1-MiB records without spending full-scoring slots on
unrelated prefixes. The latter is a functional synthetic check, not a scale,
throughput or latency benchmark.

The other four new retrieval regressions, the expanded current-trust
revocation case and the actual graph/view cases in
`tests/test_v025_retrieval_views.py` remain unexecuted. The full test file was
not run. The earlier twelve-case smoke run at `066cd56` does not cover these
retrieval changes; neither report establishes full retrieval parity or
performance certification.

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
search. It distinguishes cheap span inspection from full scoring:

- `fragment_spans_examined`: original-text spans checked by the lightweight
  normalized token/phrase locator, before full tokenization or concept scoring;
- `fragments_scanned`: spans actually tokenized and included in the BM25 and
  concept-scoring corpus, never more than 4096;
- `record_bytes_scanned`: canonical record bytes read for reranking, never
  more than 8 MiB.

`fragment_spans_examined` can exceed 4096 when long records contain unrelated
prefixes. Those spans do not consume full-scoring slots, but their inspection
still costs work inside the same byte-bounded records. These counters are not
wall-clock measurements. Results are not an exhaustive enumeration of the
Vault.

## Ranking stages

1. Use the existing indexed CJK/Latin tokens, expanded with fixed bilingual
   groups for backup, transfer, performance, memory, removal, conflict,
   preference, correction, local/offline and privacy/encryption. Latin words
   match whole words; CJK terms match normalized phrases.
2. Select at most 512 indexed candidate records (the request-specific limit
   can be lower). Original query-token matches take the first slots, ordered
   by matched query tokens, frequency and the existing timestamp/ID ties.
   Concept-only matches fill remaining slots without duplicating direct
   candidates; they share the same limit. A one-row lookahead detects overflow.
   If direct matches fill the limit, unused concept expansion is reported as
   truncated rather than claimed to be searched. Add at most 128 related
   admitted records from the existing bounded relation query. Current injected
   trust and any applicable snapshot boundary are checked for both routes.
3. Read at most 8 MiB of canonical candidate record bytes. Locate potentially
   matching original-text spans using the same NFKC normalization, case folding,
   Latin token chunks and CJK runs as tokenization, plus the existing exact
   normalized-query phrase signal. Fragments use at most 1600 characters,
   prefer newline boundaries and overlap by up to 128 characters. Unrelated
   prefixes do not receive full tokenization or concept extraction. Matching
   spans take the first scoring slots; entity-concept-only and related-evidence
   candidates retain a first-fragment fallback when slots remain. At most
   4096 selected spans undergo full scoring. Reaching a byte, candidate or
   scoring bound still reports truncation; arbitrarily many relevant spans
   cannot all be returned within these limits.
4. Compute BM25 (`k1=1.35`, `b=0.72`) over the **selected, bounded scoring
   fragment corpus**, not over every inspected span. Its document frequencies
   and average lengths are local reranking statistics, not a claim to global
   full-Vault BM25. Candidate and span selection can change scores; different
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
