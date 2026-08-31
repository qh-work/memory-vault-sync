# Memory Vault development status

Current source: **0.26.0-alpha.1**. The optional communication-memory network
has a six-operation endpoint, independent issuer control, signed invitations,
JWE encryption, two-node delivery, durable retries and endpoint receipts.
Existing core records, personal backups, handoff packages and plugin entrypoints
remain. Native encrypted Drive is wired to the existing queue; live cloud
credentials/upload/readback remain unverified. See
[current alpha evidence](RELEASE_NOTES_V0_26_ALPHA.md) and
[network setup](NETWORK_QUICKSTART.md). No real-model or scale acceptance is claimed.

The takeover iteration preserves existing code and configuration, removes
unshipped external network adapters, separates new issuer/member keys, fixes
recovery receipt progress and bounds rejected-content handling. Its final
16-test targeted campaign passed, including real loopback relay processes;
see the [current baseline](V0_26_PLAN.md). Subsequent committed checkpoints add
full endpoint recovery, authenticated node migration and separately verified
candidate archives. Current source also includes an independent TypeScript
persistent endpoint and native six-operation facade with bounded retrieval and
dynamic handoff. [Its scope](NETWORK_TYPESCRIPT.md) still excludes complete old
graph/cloud-worker parity and scale certification. No public alpha publication
or general installation claim is made by this source document. Actual package
and local upgrade evidence is separate. Historical reports below do not become
current-version validation by inclusion here.

## Historical v0.25.1 capacity-patch status

Source target: **0.25.1**, a bounded file-pack capacity patch. The previous
[v0.25.0 release](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.0)
was published at `7f27953b27b9ecd453be19084808357c89731d20` and remains immutable.
This document does not assert that v0.25.1 assets are already uploaded or that
the new required CI has passed. No private installation, real Vault, key or
remote account is changed by preparing these sources.

The target is the full useful v0.21 taskless feature set plus an independent
lightweight protocol. See [the complete requirement ledger](V0_25_PARITY_PLAN.md)
and [old/new capability mapping](PARITY.md), not a smaller renamed subset.

## Capacity correction and bounded evidence

The optional file-pack source limit rises from the published v0.25.0 ceiling of
512 MiB to 2 GiB. Chunks remain 4 MiB, with at most 512 descriptors; copy still
defaults to 32 uncached chunks per call and accepts an explicit maximum of 512.
This restores the old taskless export byte range, not arbitrarily large copies,
new record-size limits or a complete parity certification.

One explicitly opted-in 516 MiB synthetic create/one-chunk-copy/four 32-chunk
resumes/repeat/unpack/hash case passed in 3.891763 seconds on
`2f67a7099e9eba0effb3483ed3a9ba3bf2f90f80`. Source bytes remained unchanged.
A 2 GiB/512-entry manifest was accepted and a sparse 2 GiB + 1 byte source was
rejected by its size before output. These boundary checks are **not a full
2 GiB transfer**. No keys, network, private Vault or child processes were used;
the timing is not a throughput benchmark. See the
[capacity report](V0_25_PACK_CAPACITY_SMOKE.md) and
[patch notes](RELEASE_NOTES_V0_25_1.md). Earlier reports below keep their original
source pins and are not reclassified as patch validation.

## Implemented source

- Shared immutable records, existing IDs/attestations and SQLite v2 remain the
  common foundation. The single-file core still imports no optional client.
- Full local retrieval adds fragments, bounded BM25, bilingual concepts,
  polarity/explanations and explicit paginated reindex. Graph/claim views expose
  timelines, conflicts, supersession and non-executing proposals. Ordinary entity
  labels do not require a concept-group match; structural handoff filters relation
  targets with the same current admission checks as ordinary recall.
- Eleven MCP tools, direct protocol, visible-event adapters, the new lifecycle
  profile and a separate ten-operation v0.21 wire adapter share one Vault/trust.
- New automatic captures freeze their time, complete record projection and
  source-local predecessor at acceptance, then append an ordinary `continues`
  relation. Exact retry does not choose a new predecessor or become a task-owned
  memory. Previously pending v1 captures retain their original behavior.
- Native Codex capture can now retain either visible side by itself. A late
  opposite side appends a linked supplement, never edits the initial episode.
  The [optional fragment profile](VISIBLE_FRAGMENTS.md) remains ordinary
  canonical memory, readable without a plugin or source-session handles.
- Signed chained synchronization includes receive-only/flush, reviewed
  exclusions, requeue, complete resumable fragment groups and directory/rclone
  backends. Optional v3 dependency reuse requires actual prior published members,
  current trust and the receiving Vault's atomic prefix receipt. Public `changes`
  and v2 remain self-contained. Prompt/save/recall paths do not perform remote delivery.
  A local publication-review block no longer prevents bounded incoming delivery;
  durable received batches remain counted if the next read fails. The original
  outgoing review error and frozen evidence remain visible.
- Memory snapshots and separately selected full-client recovery preserve
  evidence. Reactivation is explicit, uses a new configuration and does not
  restore keys, remote publication permission or host trust.
- Real v0.21 packs/ZIPs and checkpoint chains can be inspected/repacked and
  converted through a disk index into complete split canonical parts with
  original-byte evidence and validated old-ID mappings. Full conversation imports
  use checked member-byte bounds instead of the small converter's message cap.
- Content-selected sharing preserves complete dependency closure and optional
  proofs. Imports default to quarantine; verified import uses independent
  current trust. Encryption/device/catalog contracts remain external-provider
  APIs whose unconfigured defaults refuse work.
- Publisher verification, isolated managed installation, journaled activation,
  retained rollback and separately opted-in finite automatic updates are
present. A production publisher root/channel is not provisioned.
- Native Windows local-fixed-NTFS protection is implemented alongside POSIX
  protection. It does not isolate a hostile process running as the same user.
- Client control, transfer, sharing, pack, migration and backup publication use
  a single exclusive rename on supported macOS/Linux filesystems. This avoids
  leaving a complete file linked to its temporary name and unreadable on retry.
  Explicit output-directory contracts are preserved. Existing private aliases
  remain rejected; the independent core's raw bundle exporter is a separate
  path. See [the platform limits](PLATFORMS.md).
- Host recovery can finish interrupted cleanup only after verifying the exact
  lifecycle cancellation receipt and pending requests. Cleanup is bounded and
  does not count as a successful memory save. Disabling capture still blocks
  new commits; the operator can reconcile already confirmed cancellation.
  Explicit old-host `sync.flush` can recover existing local SQLite journals
  after rechecking current capture permission/configuration; ordinary reads do
  not silently acquire this recovery permission.

## Latest guarded workflows

The current source also contains four later behavior repairs: traceable excerpts
when a whole hit exceeds a small context budget; bounded near-duplicate/source
diversity; endpoint-specific conflict resolution with current-trust witnesses;
and local recall while automatic capture is disabled, including valid but
noncommittable old-host handles. The corresponding fixtures are
`test_v025_context_budget.py`, `test_v025_retrieval_diversity.py`,
`test_v025_conflict_resolution.py` and `test_v025_capture_disabled_recall.py`.
The [minimal release campaign](V0_25_RELEASE_MINIMAL.md) selected one method
from each, and all four passed on
`82ae4ac468007eed4555ea6f04a3a933899171df`. This covers small-context
traceability, near-duplicate retrieval, endpoint-specific resolution/history
and capture-disabled old/native recall, not every case in those files. Older
campaigns and packages built from `91111c518d62` do not validate these repairs.

The additional v0.21 single-sided native Stop gap has also been implemented:
new frozen fragments, append-only late supplementation, the shared untrusted
retrieval role hint, memory-only receipt validation and full-client recovery.
Normal complete pairs and old accepted v1/v2 identities remain unchanged.
Lock acquisition rechecks capture permission; existing prepared queues can be
recovered one item at a time even if they exceed the new preparation budget.
The same initial minimal run passed one native-hook method covering both
single-sided arrival orders, late supplementation and the complete-pair path
with synthetic visible events. Its sixth selected method, partial-fragment
full-client recovery, errored in fixture setup because `atomic_write` lacked
the required `replace` argument. Only the fixture changed to `replace=False`
in `cb477db6fd1f8a34671a5d8045f313ef6dfac15c`; only that recovery method was
rerun, and it passed in 0.106540 seconds. Runtime source hashes were unchanged.
These are **six distinct methods across two runs: five passes and one setup
error, then one recovery-only pass**, not a whole-suite pass on either source.
Other fragment methods remain unrun. No network, child process, private Vault
or installed host was used. Visible input coverage and interrupted persistence
remain different requirements; the older partial-**write** campaign alone did
not establish the former.

The [workflow report](V0_25_WORKFLOW_SMOKE.md) records four passing methods on
`c65fd82f863e4e05d9ec53622eceb584525fb52e`: all eleven embedded MCP tools, all ten
old host operations, signed directory review/resolve/requeue with independent
receiving, and 42 synthetic privacy vectors. Old secret/path families are
restored as publication detection, not task routing or execution permissions.

The fifth method exposed a real update extraction defect: newly created
intermediate directories were not all private. After repairing that runtime
path, only the unchanged update method was rerun on
`0be4c6dbf6d7d3eb477ed807e15c3659f38776c8` and passed. It exercised real test-RSA
verification, staging, inert installation, caught partial-write retry and
explicit rollback. Existing modes are preserved; unknown leftovers after a hard
kill still cause a visible refusal. These are separate runs, not a five-method
pass on the newer source. No full-suite, live-host/provider or production-key
acceptance follows, and the full ledger remains open.

## Fragmented transport, signed recovery and old-format continuation

The [next workflow report](V0_25_TRANSPORT_RECOVERY_SMOKE.md) records three
passing methods on `fc3588556b976665c547ab3fc26c8f26f54bbb20`: the real default
two-fragment splitter and signed sync using a simulated provider command runner,
a tiny signed v3 staged-group snapshot/restore/import, and selective sharing
with current-trust re-admission and revocation. Remote progress survives a
post-admission head-file failure, and cancellation is checked before admission.
Verified share retry can restore currently acceptable proof without rewriting
canonical memory or old receipts; default/unsigned retries cannot do so.

One old-format method separately passed on
`76b8c8bfaed5b4d73d0ffd647dc8cd6286ba0fa7`, which only added that fixture. It
checks two distinct packs/checkpoints, original-byte preservation, typed claim
relations, old-ID mapping and continued semantic writes. The first three methods
were not rerun. Actual rclone processes, live accounts/devices, near-limit scale,
native Windows/Linux and full recovery/compatibility acceptance remain pending.

## Evidence actually available

Source review and independent static cross-reviews identified concrete
integration, trust, alias, closure, recovery and packaging issues and led to
source fixes. Python AST and JSON parsing were performed without importing the
application. These checks prove only the parsed source/format properties.

The [validation index](VALIDATION.md) records each executed campaign with its
exact source, selected methods and limitations. The initial unsigned exchange
and metadata campaign and the later retrieval/shared-retry campaign are separate
results, not one passing suite on current source. Build/inventory checks remain
separate evidence in their original manifests. Existing artifacts are unchanged.

The [publication and recovery campaign](V0_25_RECOVERY_SMOKE.md) now records seven
passing cases on its pinned source, including one controlled child-process exit
and one actual unsigned hooks backup/restore/activation/retry path. A separate
pre-fix run of the same publication case reproduced the exact double-link
failure. Remaining retrieval, compatibility and other authored cases stay unrun
unless the index links an actual execution report.

## Automatic cross-turn continuity and dependency reuse

The formerly missing v0.21 source-local predecessor behavior is implemented by
frozen plans in `memory_vault_capture.py` and the hook/lifecycle/compatibility
entries. The [capture campaign](V0_25_CAPTURE_SMOKE.md) records twelve passing
methods on its exact source, including unchanged legacy partial-write identities,
bounded predecessor completion, restore from a done-before-ack window and one
real temporary SQLite hot-journal process exit. The initial fixture errors are
retained separately; they are not silently counted as passes.

Only canonical relations travel. Private source correlation does not decide
memory ownership, lifetime, visibility or authorization. New captures do not
guess predecessors from a global latest record, and old pending jobs are not
retroactively given a new history.

The new v3 transfer path can omit dependencies actually published on the exact
stream, with current trust/epoch validation and receiving-store receipt checks.
The small signed fixture confirms four pages of a 32-record chain and rejects
copied heads or newly untrusted ancestors. This is not a throughput benchmark:
cache loss and trust changes can still require bounded full revalidation and
return `dependency_revalidation_required`. First-use near-limit closures, large
fragment groups, real remote providers and independent receivers remain
unverified; the later workflow covers a small default-split signed group only.

## Still unverified / release gate

The scoped campaigns did not cover live capture, installed-host compatibility,
device/power-loss recovery, complete process/concurrency recovery, cryptographic
interoperability, Windows/Linux native behavior, full 2 GiB transfer, throughput,
two-device delivery or a cross-language round trip. Earlier configuration/recovery
routing used mocks; the later actual unsigned hooks recovery case does not
establish every restore component or real-installation recovery. Metadata checks
do not authenticate an author or verify an encryption provider. The retrieval
follow-up used fixture threads and an injected exception; its roughly 7 MiB
long-tail fixture is not a scale or performance certification. The later
publication case used one real temporary child exit, not a power-loss trial.
The newer hot-journal case likewise does not simulate device power loss; the
small signed directory fixtures use the same reference implementation at both ends.

The [parity-repair campaign](V0_25_PARITY_REPAIR_SMOKE.md) separately records twelve
passing methods on `9d98ce0d56394adc275915a0ea1fd39b6ca06254`: entity recall,
handoff relation filtering, a 20,001-message old export, selected publication
interruptions/rollback and POSIX directory compatibility. Only three tiny
publication children exited; the other failures were injected in-process. The
backup case exercised its file publisher, not a complete snapshot/restore. No
keys or providers were used. The five new modules contain ten additional methods
that were not selected, and the whole ledger remains open.

The work also does not establish native Work automatic events, production
encryption/recovery ceremonies, a security audit, vendor certification or
independent adoption. A matching host must actually expose the integration.

On 2026-08-31 the owner explicitly authorized minimal necessary verification
and prompt v0.25 publication with its limits disclosed. Publication does not
close the requirement-by-requirement completion audit. The v0.25.0 protected-main
requirement (eight base tests on each of three platforms) passed in
[PR CI 33374601764](https://github.com/qh-work/memory-vault-sync/actions/runs/33374601764)
and [main CI 33374661273](https://github.com/qh-work/memory-vault-sync/actions/runs/33374661273).
The new v0.25.1 required CI is pending; earlier passes do not validate the patch.
Branch protection and the published v0.25.0 tag remain unchanged.
See [release scope](RELEASE.md), the
[minimal campaign](V0_25_RELEASE_MINIMAL.md) and [review handoff](REVIEW_HANDOFF.md).
