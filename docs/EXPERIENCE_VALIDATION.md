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


## Post-alpha.4 repair: local validation complete, independent re-review pending

The actual 6 Pro review of source `ee95be7eced3bd346a756058eb5ba0ea663d331a`
returned **`CHANGES_REQUESTED`**, not approval or a next-feature instruction.
The repair starts from published main `665a88175dd7c79028c35655069b978e66bfbff8`.
The exact repair SHA is supplied by the candidate manifest and pull request.
Local combined validation is complete; independent review of the resulting
commit and any subsequent release remain pending.
The initial implementation results below remain historical evidence and must
not be reused as a pass for these fixes.

The review identified two blockers:

1. Two P-authored experiment records could be counted as one origin, then as
   two after P was revoked and B/C independently re-attested their unchanged
   bytes. Both first-known local pins still named P; the summary incorrectly
   used current attesters for deduplication.
2. Python-accepted int64 metadata, including `9223372036854775807` inside
   `observed_under`, caused the TypeScript experience decoder to discard known
   experiment/relationship semantics. The repair now preserves exact int64
   metadata through native TypeScript and the lightweight HTTP SDK.

### Stable-origin repair and focused actual results

`memory_vault_experience.py` now distinguishes the current admission attester
from the stable first-known local signer. `Vault._experience_view` supplies the
existing `state_author:<id>` value only to the derived summary; general
verification, current trust, canonical records and source signatures do not
change. A valid pin remains the counting clue after explicit unsigned
re-admission. Missing signed pins and malformed existing pins are conservatively
uncounted and make the summary incomplete. Never-pinned unsigned records retain
record-level declared counts. The pin does not restore a revoked key, grant
state-adoption rights, prove original authorship across nodes or verify an
experiment.

New public summary fields are `origin_identity_basis` (fixed to
`local_first_verified_signer_or_unsigned_record`), `origin_identity_incomplete`
and `unattributed_evidence_count`. An attribution gap also sets `truncated`.
An affected record linked through both counterevidence and confirmation counts
once as unattributed. The internal `local_origin_key_id` /
`local_origin_key_present` input is not a new portable proof or canonical field.

Using the existing Python 3.12.0b4 test environment and wholly synthetic keys,
records and temporary private directories:

| Run | Actual result |
| --- | --- |
| New confirmation and contradiction re-attestation regressions on unmodified `665a881` | **2 failures**, 0.100 seconds; both reproduced `2 != 1` after replacing attestations |
| New origin-identity module plus existing Python Experience, edge and cross-author modules after the focused Python fix | **38 passed**, 1.361 seconds; 10 new tests and 28 existing tests |
| Focused core diff whitespace check | Passed |
| Combined selected Python/TypeScript, retrieval, canonical and packaging regression run | **127 passed**, 29.532 seconds; no skips |

Reproduce the focused Python run:

```sh
python -m unittest tests.test_experience_origin_identity tests.test_experience \
  tests.test_experience_edges tests.test_cross_author_state
```

The ten tests in `tests/test_experience_origin_identity.py` cover:

- Confirmation and contradiction re-attestation, including duplicate import,
  original bytes/IDs and first-known pins preserved, and live revocation.
- Missing signed pins are uncounted without a read-time write; admission updates
  retain a still-available old signer before replacing its proof.
- Explicit unsigned re-admission retains a known pin, while never-signed local
  and accepted unsigned records keep their record-level claim semantics.
- Invalid existing pins cannot become unsigned fallback identities; one unknown
  record with both evidence edge types is not double counted.
- A pin cannot override ineligible or quarantined admission.
- Both ranking profiles, limits 1/4, ordinary recall, handoff and Agent paging
  expose the same stable-origin summary.

The corresponding TypeScript origin module passed **5 tests in 3.727 seconds**
with the actual Node 22.19.0 / locked JOSE runtime. The two revoked-origin
regressions failed against the unchanged baseline before repair. The native
int64 module passed **6 tests in 8.672 seconds**; its original decoder probe
reproduced the silent `unspecified` downgrade before repair. The HTTP module
adds **8 tests** and also reproduces rounding before repair. These focused
counts overlap the combined run and must not be added to it.

The final selected run used Python 3.12.0b4 and Node 22.19.0 with the real locked
JOSE dependency; it passed **127 tests in 29.532 seconds, no skips**:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest \
  tests.test_experience tests.test_experience_edges tests.test_experience_typescript \
  tests.test_cross_author_state tests.test_experience_origin_identity \
  tests.test_experience_origin_typescript tests.test_experience_int64 \
  tests.test_experience_http_int64 tests.test_v025_conflict_resolution \
  tests.test_v025_retrieval_views tests.test_v025_retrieval_diversity \
  tests.test_v025_entity_retrieval tests.test_network_packaging \
  tests.test_network_trial_packaging tests.test_network_typescript \
  tests.test_memory_vault -q
```

Set `MEMORY_VAULT_NODE` and `MEMORY_VAULT_JOSE_MODULE` to installed runtime paths
as described below. This includes both ranking profiles, limits 1/4,
get/recall/handoff, Agent paging, evidence views, signature and byte preservation,
and the two existing real loopback HTTP SDK integration tests. The old-reader
case requires a Git checkout containing `3592b96`; the review ZIP alone does not
provide Git history.

A separate broader existing TypeScript regression run attempted 61 tests:
**59 passed, 1 expected failure, 1 failure**. The failure is the existing
U+1E030 normalization mismatch between the installed Python Unicode 15 runtime
and TypeScript's fixed Unicode 14 normalization. It was independently reproduced
with the corresponding source files restored from unchanged `665a881` in a
temporary fixture. It is not fixed or counted as a pass. This is not a claim
that the full repository suite is green.

New files are `tests/test_experience_origin_identity.py`,
`tests/test_experience_origin_typescript.py`, `tests/test_experience_int64.py`
and `tests/test_experience_http_int64.py`; release-review packaging includes all
four. The codec accepts exact signed int64 Experience values while retaining
safe-integer limits for network/control data. No record bytes, IDs, signatures,
trust grants or database schemas are changed by these repairs.

This is a bounded repair batch, not Memory Hint, global discovery, chat/P2P,
migration tooling or an approved new release. Source and final archive privacy
checks remain separate publication gates.

## Initial alpha.4 delivered behavior

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

## Historical initial results (2026-09-07)

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

Planned only after the current repair receives independent approval: Memory
Hint and authorized Experience Discovery, followed by controlled peer exchange
and Topic Gossip. Reuse these record/epistemic/provenance
semantics. Keep chat/group-chat transient by default, and require explicit
remember for durable memory. The blocked socket tests still require a permitted
environment; their status remains unverified in this authorized preview release.
Source/archive privacy and dependency checks apply separately at publication.
No release archive was built during the initial implementation/test phase.

## HTTP SDK lossless-response follow-up

A separate local probe confirmed the dependency-free HTTP SDK was another
rounding boundary: its ordinary `JSON.parse` changed int64 minimum/maximum in a
synthetic Agent Experience response to rounded values. The new preservation
regression failed on the previous SDK in **0.100 seconds**. This probe used a
real Web `Response` stream at the fetch boundary; it is not an external HTTP or
real-model test.

The repair in `clients/typescript/index.ts` preserves exact int64 literals only
inside successful recall Experience subtrees, leaves safe integers as numbers,
and rejects unsupported runtimes or unsafe numbers outside that scope. It
imports no native crypto or JOSE code. No network/control numeric range is
widened. See [the exact SDK boundary](EXPERIENCE_SEMANTICS.md#dependency-free-http-sdk-integer-boundary).

Executed with Node 22.19.0 and the existing Python 3.12.0b4 test environment:

```sh
python -m unittest tests.test_experience_http_int64 tests.test_network_typescript
```

**10 tests passed, 3.954 seconds:** 8 new parsing/round-trip cases and 2 existing
HTTP SDK integration cases. New cases cover int64 minimum/maximum, safe-number
boundaries, nested unknown fields and observed context, forbidden locations and
operations, invalid/oversized numeric tokens, depth-limited traversal, missing
runtime support, actual Python Agent query/handoff/exact-ID/cursor response
preservation, and raw-JSON requests versus
rejected unwrapped BigInt requests. The tested bytes and credentials are wholly
synthetic. The new file is `tests/test_experience_http_int64.py`; this ten-case
run is separate from the earlier 38-case Python source-identity run and must
not be added twice when reporting a combined run.
