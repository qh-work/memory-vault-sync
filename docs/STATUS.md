# v0.25 development status

Source version: **0.25.0** on `feat/v0.25-parity`.
This is development source, not a completed/public v0.25 release or a runtime
certification. Previously published v0.24.1 does not contain the additions below.
Existing private installations, real Vaults, keys, remote accounts and protected
main have not been changed by this development work.

The target is the full useful v0.21 taskless feature set plus an independent
lightweight protocol. See [the complete requirement ledger](V0_25_PARITY_PLAN.md)
and [old/new capability mapping](PARITY.md), not a smaller renamed subset.

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
interoperability, Windows/Linux native behavior, 2 GiB operation, throughput,
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

Stable publication and the full completion claim remain gated on the
requirement-by-requirement audit and adequate evidence. Existing branch
protection is not weakened or bypassed. A review snapshot must be labeled as
development with its exact partial evidence; see [release scope](RELEASE.md) and
[review handoff](REVIEW_HANDOFF.md).
