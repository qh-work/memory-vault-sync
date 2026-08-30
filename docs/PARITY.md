# v0.25: v0.21 workflows plus an independent lightweight protocol

This development branch is restoring the useful, actually exposed v0.21 taskless
workflows around the current canonical record contract. It is not a rollback
to the old monolith. Both usage modes are first-class: a full authorized
client, or an independent implementation of the open protocol.

The baseline is v0.21.0 commit
`030ed411ed9ddb969a03f0b5caec87dac9b0dd57`; the starting release was v0.24.1
commit `de349ef8453b0aa0ebf68ae18484d0c1355cf91b`.
The [full completion ledger](V0_25_PARITY_PLAN.md) is the acceptance scope.
**Source present does not mean a test passed, a host was installed or v0.25
was publicly released.** The [validation index](VALIDATION.md) identifies the
limited offline synthetic evidence and its exact source commits; results do not
transfer between versions. Full P01–P14 acceptance remains open. The exercised
paths share one Python reference, not independent implementations or models, and
do not certify real hosts, signing/encryption, cloud, cross-device behavior,
native Windows or performance. Recorded checks installed no host plugin and
accessed no private memory. This table is not production certification.

## Capability mapping

| Capability | Independent protocol / core | Authorized full client in v0.25 | v0.21 mapping and limits |
| --- | --- | --- | --- |
| Persistent memory | Canonical taskless records, immutable IDs, provenance and relations | All entries use the same configured Vault | Preserves useful memory; no Task/Project owner |
| Goal continuity | Dynamic recall/handoff over evidence | MCP, protocol and host entry points | A goal is a record; host coordination is not ownership |
| Visible-turn capture | Caller decides what to append | Opt-in Codex/Claude/Gemini/generic adapters, durable staging and exact retry | Per-turn episode and continuity excerpt implemented; automatic cross-turn `continues` chain still missing. Neither old nor new automatically infers every semantic claim |
| Local retrieval | CJK/Latin terms, full-text fragments, bounded BM25/concept/polarity explanations | Same retrieval through every entry | Explicit paginated reindex for preexisting short indexes; not a global exhaustive ranking or a measured speed claim |
| Claim and graph views | `memory.views`, `memory.graph`, non-executing proposals | Same core through MCP; source/claim timelines | Current/superseded/conflicted/resolved state with bounded continuation and trust-aware edges |
| Old host operations | Optional separate wire profile | `compat`: the ten production v0.21 operations, durable handles/receipts and old-ID mapping | Not the new lifecycle envelope; no fabricated Git commit or original author identity |
| Record attribution | Optional Ed25519 record/message proofs | Independent public-key registry, explicit enrollment, revocation-aware reads | Additional to v0.21's ordinary hash-only records; signatures are not truth or execution rights |
| Incremental transfer | Logical records and signed transfer profile | Chained v2 streams, receive-only/flush, current trust, replay/fork/gap handling | Replaces mandatory Git, not memory semantics; v1 heads require explicit anchoring when evidence is missing |
| Privacy-blocked delivery | Local records remain unchanged | Read-only review, explicit keep/exclude, idempotent decisions, signed dispositions, requeue | An exclusion means not delivered; original pending evidence is retained |
| Large transfer | Complete dependency closure | Signed resumable fragment groups up to the core's 64 MiB / 100,000 records | Receiver commits only a complete validated group; no size-only silent skip |
| Cloud carriage | Implementation chooses permitted transport | Directory or explicitly pinned/configured rclone remote and crypt | Replaces old native Drive/Git control-plane machinery; no credentials acquired automatically |
| Diagnosis/reindex | Content-free status; explicit index repair | Doctor, scoped retry and bounded state summaries | Does not search private conversations or mutate canonical history |
| Memory-only recovery | Portable bundles | Consistent snapshot, current-trust restore into a new Vault identity | No in-place data rollback or copied replication identity |
| Full client recovery | Optional operator workflow | Quiesced selected-state snapshot, inert evidence restore, explicit local reactivation and reverified received capsules | No inherited keys, sync publication permission or host hook trust; no false global multi-file atomicity |
| Old export/pack/checkpoint | Explicit compatibility/conversion profile | Real old pack/ZIP repack, checkpoint chains, 2 GiB / 250,000-object conversion, split canonical parts and mapping | Preserves original bytes/evidence and relationships; cyclic old graphs and invalid formats fail explicitly |
| File packs | Optional byte carriage | Compression, resumable copy and verified new-path unpack | Separate from old pack wire compatibility, which is provided by `legacy-pack` |
| Selected sharing | Content selectors and complete portable shares | Review/export/import preserving canonical bytes and proofs; quarantine by default | Selected roots plus all reachable dependencies, not a Task-owned export |
| Software updates | Follow compatible protocol revisions | Independently pinned RSA-PSS metadata, bounded stage, isolated activation journal, retained rollback, separately opted-in finite updater | Real old verifier capability restored without Git; no production signing channel provisioned by default |
| Encryption/device contracts | Optional transport metadata profiles | Explicit device metadata init/status and new/old envelope inspection; fail-closed providers, device transitions and key-bound signed ciphertext catalogs | Restores old operator and provider boundaries; old envelope inspection is hash-only, not new-format decryption or a deployed cipher/recovery service |
| Platforms | Language/OS independent; single-file standard-library reference | POSIX private modes and native Windows local-fixed-NTFS handles/ACLs/locks | Native implementation present, not Windows runtime certification |
| Distributions | No-executable protocol ZIP and readable agreement | Complete built client, local catalog and explicit setup instructions | No runtime build or repository login after a built client download; host installation remains authorized |

## Known capture gap: cross-turn continuity

Automatic capture links a continuity excerpt to its own episode but does not
append a `continues` reference to the preceding captured turn. v0.21 emitted a
source-local predecessor chain. This is an implementation gap in P02/P05, not
merely missing execution evidence; explicit `continues` relations are already
supported by the core. Completing automatic chaining requires immutable
acceptance-time projections, consistent retry/recovery and efficient incremental
handling of long dependency chains. Memory references must not become Session,
Task or Project ownership. See the [completion ledger](V0_25_PARITY_PLAN.md).

## Architecture that must not return

Task, Project, conversation, model, device and runtime IDs are optional
references/provenance, not a memory's parent, retention rule, visibility boundary
or authorization source. Finishing or deleting a task does not delete memory.

There is no mandatory Git repository, login, task directory, hidden transcript
discovery, permissionless installation, key auto-enrollment, policy change from
memory, log suppression or agent spawning. These are explicit architectural
exclusions, not unfinished features to reintroduce.

The optional lifecycle and old compatibility handles coordinate calls only.
Restore does not import execution permissions; signed update metadata does not
approve a new host integration contract; a content selector is not an access
control list.

## Read the actual boundary

- [Retrieval](RETRIEVAL.md) and [graph views](GRAPH_VIEWS.md)
- [Old host compatibility](COMPATIBILITY.md) and [lifecycle](LIFECYCLE.md)
- [Sync](SYNC.md), [transfer](TRANSFER.md) and [backends](REMOTE_BACKENDS.md)
- [Recovery](BACKUP.md), [operations](OPERATIONS.md) and [old packs](LEGACY_PACKS.md)
- [Sharing](SHARING.md), [encryption contracts](ENCRYPTION.md), [updates](UPDATES.md)
- [Platforms](PLATFORMS.md) and [independent review handoff](REVIEW_HANDOFF.md)

Ordinary NDJSON intentionally omits proofs; signed transfer and selected shares
preserve them. A cryptographic proof identifies an enrolled key, not an original
human/model or a true statement. Transport receipts do not establish that
another AI read or used a memory. No independent adoption claim follows from
source, visits, stars, forks or downloads.
