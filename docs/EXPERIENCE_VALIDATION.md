# Experience Core: implementation and validation evidence

This implements the first Experience Semantics / Provenance phase on the
existing `v0.26.0-alpha.3` source (`3592b96`), on local branch
`feat/experience-epistemic-core`. It does not implement or claim global P2P,
a new consensus system, a second memory database or an Internet-scale test.
At the end of the initial implementation phase (`70985ea`), no release, push,
plugin replacement or modification of the original working copy had been
performed. The following evidence records that phase. The owner subsequently
authorized publishing this work as `v0.26.0-alpha.4` with the disclosed limits;
publication and artifact verification are recorded separately by its release
manifest/body. The original checkout's network/recovery edits remain untouched.

## Delivered behavior

- Optional `experience` on remember, `include_experience` on get/recall/handoff
  and the six-operation Agent recall. Capability/discovery advertises
  `experience_profile: "experience-v1"`.
- Eight recognized types: observation, experiment, inference, hearsay,
  speculation, summary, external_source, unspecified. Legacy records remain
  unspecified. Low-confidence reports are legal; metadata never grants rights.
- Optional fields: epistemic_type, context, evidence_refs, origin_class,
  observed_under, applicability, freshness, observed_at, retry_predicate,
  source_agent, source_memory_refs, relations. Unknown metadata is preserved.
- Typed relations: heard_from, derived_from, independently_confirms,
  contradicts, summarizes, applies_to, fails_under, proposes_supersession.
  The original relation enum is unchanged; the typed relations use safe
  existing graph/sharing edges. Native derived_from also participates.
- Local bounded provenance summaries distinguish propagation from declared
  independent confirmation/counterevidence; duplicate paths and imports do
  not multiply evidence. Missing data/cycles/bounds are explicit.
- Foreign supersedes/resolves remain visible proposals without target state
  adoption. First locally known signed identity is pinned in the existing
  metadata table so a later attester cannot take over that local state right.

## Compatibility and canonical impact

There is **no change to the record/v1 fields, canonical encoder, hash profile,
record-ID algorithm or Ed25519 algorithm**. No existing record is rewritten.
New Experience records include an encoded metadata string in the existing
provenance.source_ref field and projected existing relations; their IDs
naturally cover those newly created bytes. Fixed legacy bytes, ID and
signature assertions pass, and an actual old `3592b96` validator, Vault reader
and bundle exporter preserve the new records.

The complete metadata wrapper is limited to 2,048 UTF-8 bytes. An old node can
preserve the record but does not accept new request options or show new typed
views. Old requests remain valid. There is no required bulk migration or new
SQLite schema version. Rolling back preserves record readability but loses
new semantic views and cross-author state protection. See
[Experience Semantics](EXPERIENCE_SEMANTICS.md) for local pin and historical
proof limitations.

Intentional policy change: accepted_unsigned imports and unrelated signed
attestations no longer imply common authorship for destructive state edges.
Relevant legacy tests now assert that safety boundary, while retaining
same-signer and local_unsigned correction coverage.

Existing mechanisms were reused: `Vault._remember`, `build_record` and
`validate_record`; `_graph_rows` and the existing relation/admission tables;
Agent `_evidence_metadata`/`EVIDENCE_USAGE`; original sharing verification,
record preservation and network encrypted delivery/receipts/recovery.
Python, the trusted HTTP endpoint, MCP, and TypeScript use these same
semantics. No A2A adapter exists in this baseline, and none was invented.

## Actual results (2026-09-07)

| Run | Actual result |
| --- | --- |
| New Experience, edge-case, Python/TypeScript differential and cross-author tests | **37 passed**, 6.511 seconds; no skips |
| Selected existing retrieval, network, compatibility, sharing, recovery, packaging/update tests | **132 passed; 5 blocked by sandbox localhost bind**, 137 attempted, 19.791 seconds |
| A/B/C/D synthetic logical-Agent demo | Passed; 4 records, propagation 1, origins 3, confirmation claims 1, counterclaims 1; V1/V2 remain distinct |
| Schema files | JSON parsing checked; a Draft 2020-12 validator was unavailable, so full schema validation is not claimed |
| Working diff | `git diff --check` passed |

The five blocked regression tests are the four `StorageReceiptHTTPTests`
methods in `test_network_storage_receipts.py` and
`RankingV2AgentTests.test_real_http_query_and_cross_language_cursor_preserve_metadata`.
They fail while binding localhost with `PermissionError`, before the feature
flow. The separately attempted `test_network_http.py` live-socket test and
TypeScript Agent live HTTP test hit the same sandbox restriction. They are
**not** reported as passed or replaced with a claim about real networking.

The existing encrypted two-node journey in `test_network_client.py` did pass
using the actual ASGI application handlers through an in-process transport.
Its fixture now carries Experience metadata and malicious instruction text,
checks retained original bytes/signer and typed hearsay at the recipient,
checks the authority remains false, and checks relay files lack plaintext.
This is different evidence from real sockets or independent physical hosts.

A wider prior TypeScript compatibility run also found a Unicode U+1E030
normalization difference between the installed Python and Node runtimes.
The same single failure was reproduced in a separate `git archive 3592b96`
baseline. It is pre-existing and was not changed in this phase. No claim is
made that the entire repository test suite is green.

## Reproduce

Use Python with the repository network/server dependencies and Node >=22.19
with the locked `jose` dependency. These tests used Python 3.12.0b4 and Node
22.19.0. Set `MEMORY_VAULT_NODE` to the Node executable and
`MEMORY_VAULT_JOSE_MODULE` to the installed `jose/dist/webapi/index.js` when
these are not discovered by the existing test harness. No external reporter
script or real private memory is used.

New phase tests (run in a Git source checkout containing `3592b96`, used by the old-reader test):

```sh
PYTHONPATH=tests python3 -m unittest \
  test_experience test_experience_edges test_experience_typescript \
  test_cross_author_state -v
```

The 137-case selected existing regression run (requires permission to bind
localhost for its five socket cases):

```sh
PYTHONPATH=tests python3 -m unittest \
  test_memory_vault test_network_agent test_network_client test_network_crypto \
  test_network_recovery test_network_relay test_network_storage_receipts \
  test_network_ranking_v2 test_network_packaging test_network_trial_packaging \
  test_v025_retrieval_views test_v025_retrieval_diversity \
  test_v025_entity_retrieval test_v025_conflict_resolution \
  test_v025_legacy_workflow test_v025_sharing test_v025_device_trust \
  test_v025_signed_recovery_workflow test_v025_protocol_client_interop \
  test_v025_mcp_workflow test_v025_update_edges -q
```

Demonstration:

```sh
python3 scripts/demo_experience.py
```

The 37 new tests cover source attribution on both write and independently
verified import, new experimental confirmation, 100 retellings, repeated
imports, diamond paths, same-signer repetition, source-derived inference,
contradictions, stale conditions, unknown metadata, relation/byte/depth bounds,
cycles/missing sources, old-reader round trip and a fixed Ed25519 vector,
malicious text without authority, HTTP/MCP/Python consistency, both retrieval
profiles, limits 1/4, recall/handoff/Agent handoff, evidence-context order and
cross-runtime cursor continuation. The live transfer fixture adds encrypted
network-handler coverage without claiming a real model experiment.

## Modified files

Core and interfaces:

- `memory_vault_experience.py` (new)
- `memory_vault.py`
- `memory_vault_agent.py`
- `memory_vault_client.py`
- `clients/typescript/index.ts`
- `clients/typescript/network/records.ts`
- `clients/typescript/network/retrieval.ts`
- `clients/typescript/network/vault.ts`
- `clients/typescript/network/agent.ts`

Runtime packaging (include the one new Python module and public docs/demo/tests):

- `memory_vault_update.py`
- `plugins/memory-vault-client/scripts/launcher.py`
- `scripts/build_client_plugin.py`
- `scripts/build_release.py`

Protocol, schema and demonstration:

- `PROTOCOL.md`
- `AI_START_HERE.md`
- `schemas/README.md`
- `schemas/request.schema.json`
- `schemas/result.schema.json`
- `schemas/experience.schema.json` (new)
- `docs/EXPERIENCE_SEMANTICS.md` (new)
- `docs/EXPERIENCE_VALIDATION.md` (new)
- `scripts/demo_experience.py` (new)

Tests:

- `tests/test_experience.py` (new, 12 tests)
- `tests/test_experience_edges.py` (new, 9 tests)
- `tests/test_experience_typescript.py` (new, 9 tests)
- `tests/test_cross_author_state.py` (new, 7 tests)
- `tests/test_network_client.py`
- `tests/test_network_packaging.py`
- `tests/test_network_typescript_retrieval.py`
- `tests/test_v025_conflict_resolution.py`
- `tests/test_v025_legacy_workflow.py`
- `tests/test_v025_retrieval_diversity.py`

## Remaining limits and next phase

Alpha.4 packaging preparation ran
`PYTHONPATH=tests python3 -m unittest test_network_packaging test_network_trial_packaging -v`:
**9 passed in 1.035 seconds**. This checks the isolated launcher/import closure,
public Experience document/demo allowlists and fail-closed unconfigured trial
service; it does not build or publish an archive or validate an operated service.

Counts represent declared local evidence, not experimentally verified
independence or Sybil-resistant trust. An author can omit a source or lie about
an experiment. Contradictions require explicit links; semantic truth and
condition equivalence are not inferred. Local summaries are bounded, not a
network search or consensus. Local first-signer pins cannot recover proofs
already discarded by old versions and are not a globally portable author
registry. No global P2P, DHT, public index, automatic execution/update or
large-scale benchmark was added.

Next: Memory Hint and authorized Experience Discovery, followed by controlled
peer exchange and Topic Gossip. Reuse these record/epistemic/provenance
semantics. Keep chat/group-chat transient by default, and require explicit
remember for durable memory. The blocked socket tests still require a permitted
environment; their status remains unverified in this authorized preview release.
Source/archive privacy and dependency checks apply separately at publication.
No release archive was built during the initial implementation/test phase.
