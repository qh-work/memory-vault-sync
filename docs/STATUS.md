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

## Evidence actually available

Source review and independent static cross-reviews identified concrete
integration, trust, alias, closure, recovery and packaging issues and led to
source fixes. Python AST and JSON parsing were performed without importing the
application. These checks prove only the parsed source/format properties.

On 2026-08-31 (Asia/Shanghai), the owner authorized a minimal offline synthetic
campaign: **12 selected cases passed, 0 failures/errors/skips**, on source
`066cd5629e690e6b38ab9c0bf43badafe4ef7a1b`. See the
[exact cases, environment and limits](V0_25_SCOPED_SMOKE.md). This includes an
actual core → configured client/MCP write → new-core exchange, not a second
implementation or cross-model certification. The other authored cases remain
unrun. Build/inventory checks are separate evidence in their original manifests;
those immutable artifacts have not been relabeled as runtime-tested builds.

Subsequent source review identified and repaired three additional omissions:
concept-expanded candidates could evict a direct query match; irrelevant long
record prefixes could exhaust the fragment scoring budget before later tail
matches; and two client configurations sharing one Vault could permanently
conflict when saving the same semantic proposal with different attempt times.
The retrieval changes preserve the existing candidate/byte/scoring limits and
report lightweight span inspection separately. Semantic retries now reuse the
shared first canonical projection only after checking its complete bytes,
receipt binding and current evidence admission. These post-smoke changes and
their newly authored regression cases **have not been executed**. The report
above remains evidence for its pinned source only, not for this newer runtime.

The post-smoke slice changes only the core retrieval and old-host compatibility
runtime modules, plus their documentation and review material. Independent
static cross-review, Python AST/JSON parsing, local-link inspection and diff
checks were performed without importing the application. Six retrieval and
ten compatibility test methods were authored, with two existing cases extended;
none of those new or expanded cases has execution evidence.

## Still unverified / release gate

The scoped campaign did not cover live capture, installed-host compatibility,
crash/concurrency recovery, cryptographic interoperability, Windows native
behavior, 2 GiB operation, throughput, two-device delivery or a cross-language
round trip. Configuration/recovery routing used mocks; it does not establish
actual restore correctness. Metadata checks do not authenticate an author or
verify an encryption provider. Do not infer these outcomes from source presence
or the 12 passing cases.

The work also does not establish native Work automatic events, production
encryption/recovery ceremonies, a security audit, vendor certification or
independent adoption. A matching host must actually expose the integration.

Stable publication and the full completion claim remain gated on the
requirement-by-requirement audit and adequate evidence. Existing branch
protection is not weakened or bypassed. A review snapshot must be labeled
unverified; see [release scope](RELEASE.md) and [review handoff](REVIEW_HANDOFF.md).
