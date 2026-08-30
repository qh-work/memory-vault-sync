# v0.25: complete the full client without sacrificing the independent protocol

Status: **in development; not a completed release or a runtime certification**.

The requested outcome is the useful, actually exposed v0.21 feature set plus an
independent lightweight protocol, not a small subset relabeled as a full client.
The baseline is the immutable `v0.21.0` source tag, commit
`030ed411ed9ddb969a03f0b5caec87dac9b0dd57`. Work starts from v0.24.1 commit
`de349ef8453b0aa0ebf68ae18484d0c1355cf91b`.

## Non-negotiable architecture

- Memory outlives tasks, projects, sessions, models, devices and runtimes. Those
  identifiers are optional provenance or references, never memory containers,
  visibility rules, retention rules or permission grants.
- The full client and independent protocol operate on one canonical record
  contract. A bare protocol implementation needs neither our plugin, Python,
  SQLite, an account nor a network service.
- Restore useful workflows without reinstating the mandatory Git control plane,
  Task directories or the old monolithic runtime. These exclusions are explicit
  user requirements, not a reason to omit retrieval or operational features.
- Memory is evidence, not instruction or authorization. No remembered goal can
  install code, enroll trust, activate a host hook or start an agent.
- Existing canonical records, signatures and identifiers remain valid. A wire
  compatibility adapter must state its mappings rather than pretend old and new
  identities are identical.

## Requirement ledger

Every row needs source/interface evidence and proportionate verification before
the whole goal can be declared complete. An implemented function, a fixture file
or a parsed archive alone does not prove its runtime behavior. This ledger stays
open until evidence is recorded; it is not shortened to match finished work.

| ID | Required outcome | v0.21 baseline / current gap | Completion evidence |
| --- | --- | --- | --- |
| P01 | Taskless immutable memory with facts, observations, decisions, artifacts, relations, provenance and dynamic continuity | v0.21 episode/event graph; v0.24 shared record core | Existing records remain readable with identical IDs; both modes describe the same contract; no task-owned storage |
| P02 | Local visible-turn capture with durable acknowledgment, exact retry, cancellation and interrupted-turn recovery | v0.21 hooks and host protocol; v0.24 lifecycle modules | Synthetic event/replay/cancel cases, including missing and reordered events; no transcript discovery or prompt-path network |
| P03 | Full local retrieval, including CJK/Latin tokenization, fragments, BM25, cross-language concept expansion, polarity and explained ranking | v0.21 retrieval.py and memory_network.py; v0.24 simplified matching | Deterministic synthetic synonym, negation, long-fragment, role and graph-state cases plus bounded index work |
| P04 | Current/superseded/conflicted/resolved claim views, evidence timelines, graph traversal and non-executing consolidation proposals | v0.21 graph_views.py and memory_network_views | Complete bounded timelines with continuation/truncation information, trust-aware edges and traceable proposal evidence |
| P05 | Cross-host protocol compatibility and a complete current MCP entry | v0.21 closed host envelopes; v0.24 new lifecycle envelopes | All old production operations have explicit adapters and exact retry behavior; the same configured Vault/trust is used |
| P06 | Bounded incremental send/receive, offline retention, fork/rollback rejection and resumable delivery | v0.21 Git commit cursor; v0.24 signed stream replacement | Directory/transport synthetic cases for additions, concurrency, replay, interruption and explicit receive/flush; no network in ordinary recall |
| P07 | A usable review/recovery workflow for privacy-blocked sends | v0.21 rejects a single turn before publication; v0.24 can block an entire durable capsule | Read-only review plus explicit, idempotent inclusion/exclusion/requeue; signed dispositions and preservation of original local evidence |
| P08 | Cloud transport and large-transfer functionality without a Git prerequisite | v0.21 pack/object capabilities; v0.24 optional directory/rclone | Scoped backends, bounded listing/read/write, integrity verification, interrupted copy recovery and declared backend limits |
| P09 | Complete portable graph export/import, old export conversion, pack/checkpoint compatibility | v0.21 network bundle and memory packs; v0.24 only specified ZIP conversion | Synthetic old fixtures convert without silently losing visible text, relations or claim grouping; inventories/checkpoints are verified |
| P10 | Diagnostics, index recovery and recoverable client state | v0.21 private doctor/outbox/index recovery; v0.24 memory-only snapshot | A memory snapshot and a separately explicit full-client recovery path; no implicit key/credential/permission transfer; exact queue handling and new-store identity rules |
| P11 | Controlled installation/update and publisher verification capability | v0.21 optional RSA-PSS metadata and configured auto-install; v0.24 check/stage only | Independent pinned trust, metadata expiry/rollback checks, verified staged runtime, explicit install/activation and rollback boundary |
| P12 | Selective sharing, trust lifecycle and fail-closed encryption/provider boundaries | v0.21 selector/envelope/device contracts were not a provisioned production ceremony | Actual supported profiles and implementation boundaries exposed honestly; key enrollment never comes from memory or an incoming packet |
| P13 | macOS/Linux/Windows coverage equivalent to the supported old standard-library paths | v0.21 portable runtime; v0.24 protected paths POSIX-only | Native file/lock/permission adapters where needed; unsupported protection is never silently treated as secure |
| P14 | Two complete distributions and usable integration/contribution documentation | Full authorized plugin plus independent protocol | Manifest/runtime allowlists, consistent version, synthetic conformance material, static/plugin/archive checks and independently retrievable public assets |

## Baseline distinctions that must not be lost

- v0.21 automatic capture created an episode and a fixed continuity checkpoint.
  It did **not** automatically infer decisions and constraints from every turn;
  semantic claims were explicit proposals. Do not invent an old capability.
- Its accepted host intent also froze the source sequence and preceding episode
  reference. Current automatic capture has not restored that cross-turn edge.
  Local control correlation may select a predecessor; it must not turn sessions
  into memory owners or change a previously accepted projection on retry.
- v0.21 ordinary memory records were hash-addressed, not individually signed.
  v0.24 Ed25519 attestations are an additional capability to retain.
- v0.21 optional encrypted sharing/device-recovery providers failed closed when
  unconfigured. Restoring an interface is not proof of deployed encryption or a
  completed multi-device ceremony.
- v0.21 had real optional software-update verification code, but its production
  signing channel was not provisioned. Restore verification capability without
  claiming that a release checksum is a publisher signature.
- Old Task artifact-hydration branches were not the v0.21 taskless production
  capture path. Useful file carriage can remain independent of memory ownership;
  Task directories must not be resurrected to recover it.

## Current source coverage and scoped evidence

The following map records concrete implementation and authored review material.
It does **not** close the full requirements in the ledger above. The
[validation index](VALIDATION.md) records each narrow campaign on its own exact
source. Results do not apply retroactively to a different source or combine
into a whole-suite pass. Paths describe
the development source, not the already published v0.24.1 artifact.

| ID | Implementation / contract | Authored review evidence and remaining work |
| --- | --- | --- |
| P01 | `memory_vault.py`, `PROTOCOL.md`, `schemas/record.schema.json` | Four vector/unsigned core-client-MCP exchange cases passed in the initial scoped report. Automatic cross-turn continuity edges are still missing; independent implementation and full parity acceptance remain pending |
| P02 | `memory_vault_client.py`, `memory_vault_lifecycle.py`, `memory_vault_hosts.py` | Selected publication and confirmed-cancellation cases passed in the recovery campaign, including one controlled child exit and disabled-capture cleanup. Automatic capture still lacks the v0.21 predecessor chain; live-host and complete crash/race evidence remain pending |
| P03 | Core full-record terms, fragments, concept expansion and ranking; `docs/RETRIEVAL.md` | Two follow-up cases passed: unique direct-token retention against backup/archive/save distractors and seven large-record tail matches within existing budgets. The other retrieval/index/graph methods, comparative ranking and scale/performance acceptance remain pending |
| P04 | Core `memory.views`, `memory.graph`, `memory.reindex`; `docs/GRAPH_VIEWS.md` | Bounded timelines/frontiers and repair cases in retrieval tests; runtime trust/pagination evidence pending |
| P05 | `memory_vault_compat.py`, eleven-tool MCP, separate host schemas; stateless capability discovery with strict request validation | Selected unsigned MCP read/write and mocked lazy-configuration cases passed in the older campaign. Four follow-up cases passed for shared semantic retries, first-write fixture threads, injected post-commit interruption and receipt tampering. Complete eleven-tool, old-host and live-host acceptance remain pending |
| P06 | `memory_vault_sync.py`, `memory_vault_transfer.py`, chained v2 streams | `test_v025_sync_review.py` plus existing delivery cases. The recursive dependency feed needs bounded receiver-known handling before automatic long continuity chains are added; process/concurrent-writer and interruption execution pending |
| P07 | Sync review/resolve/requeue and `memory_vault_privacy.py` | One core blocked-dependency/requeue regression passed; this is not the signed sync review/resolution campaign. No real content scanned or uploaded |
| P08 | `memory_vault_remote.py`, signed fragment groups, `memory_vault_pack.py` | Review fixtures for directory/rclone/fragment recovery; real provider, near-limit and platform trials pending |
| P09 | `memory_vault_legacy_pack.py`, required `memory_vault_migrate.py`, checked compat aliases | `test_v025_legacy_pack.py`, `test_v025_legacy_pack_edges.py`, `test_v025_portable_packs.py`; independent old-format/2 GiB scale run pending |
| P10 | `memory_vault_recovery.py`, `memory_vault_backup.py`, `memory_vault_manage.py`; independent recovery commands do not require a lost old configuration | The earlier mocked routing case and later exact cancelled-host cleanup/unsigned hooks backup→restore→activate→retry have separate passing evidence. Other components, signed recovery and complete crash/concurrency/native acceptance remain pending |
| P11 | `memory_vault_update_trust.py`, `memory_vault_update.py`, `memory_vault_install.py`, pinned managed launcher | `test_v025_update_trust.py`, `test_v025_install.py`, `test_v025_update_edges.py`; no production publisher root or runtime verification performed |
| P12 | `memory_vault_sharing.py`, `memory_vault_crypto.py`, `memory_vault_device_trust.py`, `memory_vault_encrypted_replication.py`; explicit `device-trust init/status` and `envelope verify` operator entries | Three explicit-path/legacy-frame/tamper metadata cases passed with synthetic opaque bytes; no author signatures, key possession, provider encryption or recovery ceremony was verified |
| P13 | `memory_vault_storage.py` and configured client/transfer/recovery/pack/update consumers | Three focused publication cases passed on macOS, including a controlled child exit, no-clobber/alias checks and mocked unsupported-helper failure. Native Windows/Linux, actual unsupported filesystems and other independent hard-link publishers remain outside this verification; existing aliases are not auto-repaired |
| P14 | Allowlisted build scripts, current docs/schema discovery, separate protocol/client/review packages | Packaging can establish source inventory and bytes only; exact artifact manifest is the record of completed static checks. Public availability and runtime acceptance must be recorded separately |

The review kit includes executable cases separately from the documentation-only
protocol. Execution is limited to the exact methods and source versions in the
validation index; remaining authored cases stay unrun. See
[REVIEW_HANDOFF.md](REVIEW_HANDOFF.md) for
bounded campaigns and evidence fields. Restore/install examples have not been
executed against any real Vault or installed client. No advertised data-transfer
receipt proves that another model read or adopted the memory.

The [external contribution intake](REVIEW_HANDOFF.md#external-contribution-intake-pr-11)
records a contributor's three-case v0.24.1 report separately from the later
maintainer v0.25 campaigns. These results do not close this full ledger.

## Verification and release gate

The owner previously requested no test execution, then explicitly allowed the
minimal temporary-directory offline validation used for the campaigns above,
without a one-time or 12-case limit. This was not permission for full-suite
discovery, networking, installation, live hosts, cloud CI or release publication.
Source, schema, package and archive inspection are still separate from tests.
No live/private Vault, credential, signing key, host installation or remote
account is used for development verification without separate authorization.

Runtime verification is **partial and narrowly scoped**, not complete. Unrun
requirements stay pending rather than being marked successful or dropped. Protected main and
already published tags remain unchanged while this work is incomplete.

For each delivered slice, record the exact source paths, synthetic fixtures,
verification actually performed, and remaining failures/unknowns. Publish a
finished v0.25 only after this full ledger withstands a completion audit; a
preview must be labeled as a preview.
