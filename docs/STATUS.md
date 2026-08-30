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
  timelines, conflicts, supersession and non-executing proposals.
- Eleven MCP tools, direct protocol, visible-event adapters, the new lifecycle
  profile and a separate ten-operation v0.21 wire adapter share one Vault/trust.
- Signed chained synchronization includes receive-only/flush, reviewed
  exclusions, requeue, complete resumable fragment groups and directory/rclone
  backends. Prompt/save/recall paths do not perform remote delivery.
- Memory snapshots and separately selected full-client recovery preserve
  evidence. Reactivation is explicit, uses a new configuration and does not
  restore keys, remote publication permission or host trust.
- Real v0.21 packs/ZIPs and checkpoint chains can be inspected/repacked and
  converted through a disk index into complete split canonical parts with
  original-byte evidence and validated old-ID mappings.
- Content-selected sharing preserves complete dependency closure and optional
  proofs. Imports default to quarantine; verified import uses independent
  current trust. Encryption/device/catalog contracts remain external-provider
  APIs whose unconfigured defaults refuse work.
- Publisher verification, isolated managed installation, journaled activation,
  retained rollback and separately opted-in finite automatic updates are
  present. A production publisher root/channel is not provisioned.
- Native Windows local-fixed-NTFS protection is implemented alongside POSIX
  protection. It does not isolate a hostile process running as the same user.
- Client private-state publication now uses a single exclusive rename on
  supported macOS/Linux filesystems. A process exit can no longer leave that
  newly published file linked to its temporary name and unreadable on retry.
  Existing aliases remain rejected; other independent publishers are not all
  migrated by this change. See [the platform limits](PLATFORMS.md).
- Host recovery can finish interrupted cleanup only after verifying the exact
  lifecycle cancellation receipt and pending requests. Cleanup is bounded and
  does not count as a successful memory save. Disabling capture still blocks
  new commits; the operator can reconcile already confirmed cancellation.

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

## Known implementation gap: automatic cross-turn continuity

The v0.21 host path froze a source sequence and previous episode reference when
accepting a turn. Current automatic capture saves an episode and its associated
continuity record, but does not link that continuity to the preceding turn.
This is missing behavior under P01/P02/P05, **not just missing test evidence**.

The replacement must use ordinary canonical relations, not a Task/session-owned
memory hierarchy. Its accepted predecessor, timestamp and complete projection
must survive retry and recovery unchanged. A copied local head or the globally
newest memory cannot silently become a predecessor. The existing incremental
feed recursively carries relation dependencies; naively adding an ever-growing
`continues` chain would repeatedly send the entire history. P06 therefore also
needs an explicit bounded dependency-transfer design before the new chain can
be claimed efficient. Existing records and signatures must remain valid.

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

The work also does not establish native Work automatic events, production
encryption/recovery ceremonies, a security audit, vendor certification or
independent adoption. A matching host must actually expose the integration.

Stable publication and the full completion claim remain gated on the
requirement-by-requirement audit and adequate evidence. Existing branch
protection is not weakened or bypassed. A review snapshot must be labeled
unverified; see [release scope](RELEASE.md) and [review handoff](REVIEW_HANDOFF.md).
