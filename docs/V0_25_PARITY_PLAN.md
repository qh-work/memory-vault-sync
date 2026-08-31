# v0.25: complete the full client without sacrificing the independent protocol

Status: **v0.25.0 published; v0.25.1 capacity-patch source; full-goal acceptance
is not established by publication or limited runtime checks**.

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
- Its native Stop path could save only the user or assistant side when that was
  all the visible content actually received (`partial_active_turn`). That is a
  separate capability from recovering a partially written complete turn. The
  new [single-sided profile](VISIBLE_FRAGMENTS.md) restores this capability and
  adds an immutable later supplement. Missing content must never be guessed
  from a transcript or another turn. Selected native partial/complete and
  recovery methods now have [source-pinned evidence](V0_25_RELEASE_MINIMAL.md);
  unrun authoring/recovery fixtures and old partial-write results alone do not
  prove partial coverage.
- Its accepted host intent also froze the source sequence and preceding episode
  reference. New automatic capture restores that causal behavior with frozen
  projections and a `continues` relation between continuity records. Local
  correlation does not turn sessions into owners or change accepted bytes on
  retry. Old pending records retain their original profile rather than having a
  guessed predecessor appended retroactively.
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

The [minimal release campaign](V0_25_RELEASE_MINIMAL.md) selected six distinct
methods. On `82ae4ac468007eed4555ea6f04a3a933899171df`, five passed and partial
full-client recovery errored in fixture setup. A fixture-only `replace=False`
correction in `cb477db6fd1f8a34671a5d8045f313ef6dfac15c` preceded the sole
recovery-method rerun, which passed; runtime source hashes were unchanged.
The first five methods were not rerun. These two runs do not constitute a
whole-suite pass; no network, child process, private Vault or installed host
was used.

| ID | Implementation / contract | Authored review evidence and remaining work |
| --- | --- | --- |
| P01 | `memory_vault.py`, `PROTOCOL.md`, `schemas/record.schema.json`; shared canonical `continues` records | Earlier core/client cases and the latest selected source-local chain case have separate evidence. Source handles do not enter canonical records as owners; independent implementation and full parity acceptance remain pending |
| P02 | `memory_vault_capture.py`, `memory_vault_client.py`, `memory_vault_lifecycle.py`, `memory_vault_hosts.py`; [one-sided fragments](VISIBLE_FRAGMENTS.md) | Earlier capture/recovery evidence remains source-pinned. At `82ae4ac`, one synthetic native-hook method passes both single-sided arrival orders, late supplements and the complete-pair path. Other fragment methods, including lock-boundary opt-out and prepared-queue draining, remain unrun; live-host and complete crash/race coverage remain pending |
| P03 | Core full-record terms, fragments, concept expansion and ranking; `docs/RETRIEVAL.md` | Earlier direct-token, long-tail, entity and scoring-slot cases remain source-pinned. At `82ae4ac`, one small-context traceability method and one near-duplicate retrieval method pass. Other retrieval/index methods, comparative ranking and scale/performance acceptance remain pending |
| P04 | Core `memory.views`, `memory.graph`, `memory.reindex`; `docs/GRAPH_VIEWS.md` | Earlier handoff/graph/timeline/reindex evidence remains separate. At `82ae4ac`, one endpoint-specific conflict-resolution/history method passes. Complete trust/frontier/pagination coverage and scale remain pending |
| P05 | `memory_vault_compat.py`, eleven-tool MCP, separate host schemas; stateless capability discovery with strict request validation | The workflow campaign at `c65fd82` passes one integrated eleven-tool MCP case and one ten-operation old-envelope case. At `82ae4ac`, one capture-disabled old/native recall method passes. Complete schema/error combinations, physical journal recovery for this route and real-host acceptance remain pending |
| P06 | `memory_vault_sync.py`, `memory_vault_transfer.py`, `memory_vault_dependency.py`; self-contained v2 plus stream-proven v3 | Earlier signed directory/dependency evidence stays separate. The `fc35885` default two-fragment workflow adds exact upload/read resume, pre-admission cancellation and durable remote admission counts through a head-file rejection. Only provider commands are simulated. First-use/invalidated closure budgets stay explicit; live remote, near-limit group/scale/concurrent-writer acceptance remains pending |
| P07 | Sync review/resolve/requeue and `memory_vault_privacy.py` | The `c65fd82` signed workflow passes content-free review, explicit keep/exclude, retained original evidence, signed dispositions, exact retry/requeue and receiver-side forwarding checks. A separate method passes 42 fake secret/path vectors. This is not exhaustive DLP, group recovery or real-user-data acceptance; no real content was scanned or uploaded |
| P08 | `memory_vault_remote.py`, signed fragment groups, `memory_vault_pack.py` | Earlier small pack copy/resume/unpack evidence stays separate. The `fc35885` signed group covers real default splitting, constructor pins/config validation, exact member paths and read-back, with only the provider command runner replaced. Actual rclone process/network/per-command checks, near-limit groups and native platforms remain pending |
| P09 | `memory_vault_legacy_pack.py`, required `memory_vault_migrate.py`, checked compat aliases | Earlier 20,001-message and publication cases remain separate. At `76b8c8b`, one independently encoded old-wire fixture passes a two-pack/checkpoint chain, repack/conversion, eight old-ID mappings, raw evidence, typed claim timeline and old-ID continuation. Other malformed graphs/checkpoints, actual old-runtime exports, independent consumers and 2 GiB acceptance remain pending |
| P10 | `memory_vault_recovery.py`, `memory_vault_backup.py`, `memory_vault_manage.py`; v1/v2 control and frozen hook journal recovery | Earlier unsigned and `fc35885` tiny signed staged-group recovery stay source-pinned. At `cb477db`, the selected partial-fragment full-client recovery method passes after its fixture-only setup repair; no runtime change or rerun of the five earlier passing methods. Other components, complete crash/concurrency/near-limit/native acceptance remain pending |
| P11 | `memory_vault_update_trust.py`, `memory_vault_update.py`, `memory_vault_install.py`, pinned managed launcher | The unchanged integrated update method passes on `0be4c6d` after its initial runtime error: real public-test-root verification, stage/install, caught partial-write retry and explicit rollback. Other trust/install/edge methods remain unrun unless separately recorded. No production publisher root, actual download, host worker or hard-kill acceptance |
| P12 | `memory_vault_sharing.py`, `memory_vault_crypto.py`, `memory_vault_device_trust.py`, `memory_vault_encrypted_replication.py`; explicit `device-trust init/status` and `envelope verify` operator entries | Earlier metadata/publication cases stay separate. The `fc35885` selective-share workflow uses two fresh Ed25519 keys for actual signed export/quarantine/independent trust/import/forward/replay/revocation and current-proof restoration without changing canonical bytes or old receipts. Key identity is not original authorship; full trust lifecycle, provider encryption and production/device-recovery ceremonies remain pending |
| P13 | `memory_vault_storage.py` and configured client/transfer/recovery/pack/update consumers | Publication repairs include three controlled macOS child exits and in-process failures without tightening explicit POSIX parent modes. The separate update repair passes protected intermediate-directory creation and caught write retry. Native Windows/Linux, actual unsupported filesystems and the independent core exporter remain outside this verification; existing private aliases are not auto-repaired |
| P14 | Allowlisted build scripts, current docs/schema discovery, separate protocol/client/review packages | Packaging can establish source inventory and bytes only; exact artifact manifest is the record of completed static checks. Public availability and runtime acceptance must be recorded separately |

Post-publication P08 correction: the v0.25.0 file-pack profile's 512 MiB source
limit was narrower than the old taskless 2 GiB data range. The v0.25.1 patch
raises the explicit source-file limit to 2 GiB without enlarging per-chunk work
or ordinary sync. One [516 MiB resumed copy/unpack case](V0_25_PACK_CAPACITY_SMOKE.md)
passes at `2f67a70`; full 2 GiB transfer and the old copy helper's unbounded
file-size behavior are not thereby established.

P14 publication evidence for v0.25.0: [PR #12](https://github.com/qh-work/memory-vault-sync/pull/12)
merged as `7f27953b27b9ecd453be19084808357c89731d20`. Its three-platform eight-case
base workflow passed on the PR and merged main. All seven public release assets
were downloaded and compared byte-for-byte with the source-checked build;
350 archive members matched the Git tree and the two generated inventories
were verified. The plugin structure validator passed. The v0.25.1 publication
is separate and must not overwrite that immutable tag or its assets.

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

The owner previously requested no test execution, then allowed minimal
temporary-directory offline validation. On 2026-08-31 the owner explicitly
requested minimal necessary tests and prompt v0.25 publication. This latest
instruction permits publication with the exact validation limits disclosed;
it does not authorize arbitrary full-suite discovery, private-account testing,
installation or live-host changes. The existing protected-main CI requirement
of eight base tests on three platforms remains pending and must not be bypassed.
Source, schema, package and archive inspection are still separate from tests.
No live/private Vault, real credential/signing key, host installation or remote
account is used for development verification without separate authorization.

Runtime verification is **partial and narrowly scoped**, not complete. Unrun
requirements stay pending rather than being marked successful or dropped.
Protected-main rules and already published tags are preserved; this ledger
does not assert that v0.25 is already public.

For each delivered slice, record the exact source paths, synthetic fixtures,
verification actually performed, and remaining failures/unknowns. The authorized
v0.25 publication is distinct from full-goal completion: only the latter requires
this entire ledger to withstand a completion audit. Neither a release tag nor
the six selected methods closes unverified requirements.
