# v0.25: v0.21 workflows plus an independent lightweight protocol

The next v0.25 patch restores original-file resumed copying, but the requested
full-client delivery is not complete: real cloud setup, migration and verified
upload/receive remain a required gap. It is not a rollback to the old
monolith. Both usage modes are first-class: a full authorized client, or an
independent implementation of the open protocol.

The baseline is v0.21.0 commit
`030ed411ed9ddb969a03f0b5caec87dac9b0dd57`; the starting release was v0.24.1
commit `de349ef8453b0aa0ebf68ae18484d0c1355cf91b`.
The [complete ledger](V0_25_PARITY_PLAN.md) records implementation coverage,
proportionate evidence and the remaining deployment-verification limits for
P01–P14. A source/interface mapping missed the user-facing cloud deployment
gap and must not be presented as completion. **Cloud backend code and mocked
transport do not establish usable cloud synchronization.** The [validation index](VALIDATION.md)
identifies the limited offline evidence and its exact source commits; results
do not transfer between versions. The exercised paths share one Python
reference, not independent implementations or models, and do not certify real
hosts, production signing/encryption, cloud, cross-device behavior, native
protected storage or performance. Recorded checks installed no host plugin and
accessed no private memory. v0.25.0 and v0.25.1 are published; the next patch's
release is paused while the authorized local cloud migration is completed.

## Capability mapping

| Capability | Independent protocol / core | Authorized full client in v0.25 | v0.21 mapping and limits |
| --- | --- | --- | --- |
| Persistent memory | Canonical taskless records, immutable IDs, provenance and relations | All entries use the same configured Vault | Preserves useful memory; no Task/Project owner |
| Goal continuity | Dynamic recall/handoff over evidence | MCP, protocol and host entry points | A goal is a record; host coordination is not ownership |
| Visible-turn capture | Caller decides what to append and may explicitly reference earlier records | Opt-in Codex/Claude/Gemini/generic adapters, frozen acceptance, durable staging and exact retry; native Codex one-sided fragments and append-only late supplements | New per-turn episode/continuity captures retain a source-local `continues` edge; old pending jobs preserve their original identity. Neither old nor new automatically infers every semantic claim |
| Local retrieval | CJK/Latin terms, full-text fragments, bounded BM25/concept/polarity explanations | Same retrieval through every entry | Explicit paginated reindex for preexisting short indexes; not a global exhaustive ranking or a measured speed claim |
| Claim and graph views | `memory.views`, `memory.graph`, non-executing proposals | Same core through MCP; source/claim timelines | Current/superseded/conflicted/resolved state with bounded continuation and trust-aware edges |
| Old host operations | Optional separate wire profile | `compat`: the ten production v0.21 operations, durable handles/receipts and old-ID mapping | Not the new lifecycle envelope; no fabricated Git commit or original author identity |
| Record attribution | Optional Ed25519 record/message proofs | Independent public-key registry, explicit enrollment, revocation-aware reads | Additional to v0.21's ordinary hash-only records; signatures are not truth or execution rights |
| Incremental transfer | Logical records and signed transfer profile | Self-contained v2 and stream-proven v3 dependencies, receive-only/flush, current trust, replay/fork/gap handling | Replaces mandatory Git, not memory semantics; a cursor alone never proves possession. Old heads require explicit anchoring when evidence is missing |
| Privacy-blocked delivery | Local records remain unchanged | Read-only review, explicit keep/exclude, idempotent decisions, signed dispositions, requeue | An exclusion means not delivered; original pending evidence is retained |
| Large transfer | Complete dependency closure | Signed resumable fragment groups up to the core's 64 MiB / 100,000 records | Receiver commits only a complete validated group; no size-only silent skip |
| Cloud carriage | Implementation chooses permitted transport | Directory or explicitly pinned/configured rclone remote and crypt; development source restores explicit encrypted-config unlock, old artifact catalogs and native Drive file retrieval | Memory transport no longer requires Git. Native Drive integration with the memory queue, local login and real cloud round-trip acceptance remain incomplete; no credentials acquired automatically |
| Diagnosis/reindex | Content-free status; explicit index repair | Doctor, scoped retry and bounded state summaries | Does not search private conversations or mutate canonical history |
| Memory-only recovery | Portable bundles | Consistent snapshot, current-trust restore into a new Vault identity | No in-place data rollback or copied replication identity |
| Full client recovery | Optional operator workflow | Quiesced selected-state snapshot, inert evidence restore, explicit local reactivation and reverified received capsules | No inherited keys, sync publication permission or host hook trust; no false global multi-file atomicity |
| Old export/pack/checkpoint | Explicit compatibility/conversion profile | Real old pack/ZIP repack, checkpoint chains, 2 GiB / 250,000-object conversion, split canonical parts and mapping | Preserves original bytes/evidence and relationships; cyclic old graphs and invalid formats fail explicitly |
| File packs | Optional byte carriage | Compression, resumable copy and verified new-path unpack | Separate from old pack wire compatibility, which is provided by `legacy-pack` |
| Original-file copying | Optional opaque byte carriage | Config-free `copy-pack --pack --output --journal`, bounded resume and verified old five-field journal migration | No repackaging or application total-file-size ceiling; explicit private output/journal paths, hashes are integrity checks rather than authentication |
| Selected sharing | Content selectors and complete portable shares | Review/export/import preserving canonical bytes and proofs; quarantine by default | Selected roots plus all reachable dependencies, not a Task-owned export |
| Software updates | Follow compatible protocol revisions | Independently pinned RSA-PSS metadata, bounded stage, isolated activation journal, retained rollback, separately opted-in finite updater | Real old verifier capability restored without Git; no production signing channel provisioned by default |
| Encryption/device contracts | Optional transport metadata profiles | Explicit device metadata init/status and new/old envelope inspection; fail-closed providers, device transitions and key-bound signed ciphertext catalogs | Restores old operator and provider boundaries; old envelope inspection is hash-only, not new-format decryption or a deployed cipher/recovery service |
| Platforms | Language/OS independent; single-file standard-library reference | POSIX private modes and native Windows local-fixed-NTFS handles/ACLs/locks | Native implementation present, not Windows runtime certification |
| Distributions | No-executable protocol ZIP and readable agreement | Complete built client, local catalog and explicit setup instructions | No runtime build or repository login after a built client download; host installation remains authorized |

## Restored capture behavior: cross-turn continuity

v0.21 froze a source-local preceding episode reference. New automatic capture
preserves that causal intent with an ordinary `continues` edge to the preceding
continuity, alongside `derived_from` to its own episode. Complete canonical
bytes, timestamps and the predecessor's full hash are frozen when a new job is
accepted. Local scope/handle tables are correlation, never Session, Task or
Project ownership. Old accepted queues without plans retain their original
write domains and are not assigned guessed historical edges.

The native v0.21 Stop path also accepted either visible side on its own. The
new [visible-fragment profile](VISIBLE_FRAGMENTS.md) restores that distinct
capability and adds a later opposite-side supplement without rewriting the
initial episode. It does not confuse partial **input coverage** with an
interrupted database write. Canonical records and signatures remain shared
with protocol-only readers; only the producing client needs its local journal.

The [twelve-case capture report](V0_25_CAPTURE_SMOKE.md) covers selected retry,
recovery and signed-directory dependency behavior, not full P02/P05/P06
acceptance. v3 transfer avoids resending a proven prefix when current trust still
allows it; cache invalidation can require bounded revalidation. There is no
arbitrary-scale or independent-implementation performance claim. See the
[completion ledger](V0_25_PARITY_PLAN.md).

The subsequent [parity-repair report](V0_25_PARITY_REPAIR_SMOKE.md) records a
separate source and twelve selected methods. It covers ordinary entity lookup,
handoff target filtering, complete old-format short-message histories and
selected crash-safe output paths without tightening explicit POSIX directory
contracts. These fixes apply to the shared reference/client implementation;
they add no task ownership and do not convert narrow verification into complete
release acceptance.

The [full-client workflow report](V0_25_WORKFLOW_SMOKE.md) adds four passing
methods on `c65fd82`: all eleven embedded MCP tools, all ten old host operations,
real signed directory review/resolve/requeue and 42 synthetic privacy vectors.
The fifth method first exposed a runtime directory-permission defect. After
repair, the unchanged update-only method passed on `0be4c6d`, including real
public-test-root verification, inert install, caught write-failure retry and
explicit rollback. That rerun does not retest the first four workflows or
establish production publisher trust, live hosts, cloud carriage or full parity.

The [transport/recovery/continuation report](V0_25_TRANSPORT_RECOVERY_SMOKE.md)
adds three passing workflows at `fc35885` and one separate old-format workflow
at `76b8c8b`. It covers default two-fragment signed sync over simulated provider
commands, tiny signed recovery into a new store, current-trust selective sharing
and old checkpoint/graph/ID continuation. Only the last fixture was added in the
second source; these are not a combined current-source suite or a real cloud,
cross-device, independent-consumer or full-parity result.

The [original-file copy report](V0_25_RAW_COPY_SMOKE.md) closes the concrete raw
byte-carriage gap. One selected method passed at
`7bd190471d3b7328961899b2cf13a5c72a666c28`: an actual 2 GiB + 4 MiB sparse source
was copied through the client entry without repackaging, first 4 MiB then eight
256 MiB resumptions, with an independent final hash and a zero-write completed
retry. The same method checks old five-field journal migration and unchanged
refusal of unknown or corrupt completed outputs. This is not a throughput,
cloud or native-platform certification. The copy budget limits writes, not
whole-file integrity reads: first use, changed-source or old-journal acceptance
requires a full source hash, and completion verifies the full destination.

The encrypted-rclone-config repair is committed at
`427ab1df56d786600520e0946c0fc2cdb8712e90`, not yet published or installed.
One actual-rclone configuration case passed with synthetic credentials and an
OS-lookup substitute. It checks decryption, wrong-password refusal, selected
helper rejection, changed-config revalidation and plaintext compatibility.
It does not exercise a cloud transfer, real credential store or OAuth refresh;
see [the precise scope](REMOTE_BACKENDS.md#encrypted-configuration-validation).
Development source now adds old artifact-catalog conversion, canonical artifact
and location records, and explicit native Drive file-ID retrieval with bounded
resume and final SHA-256 verification. Two synthetic methods exercise catalog
conversion and the fetch path with only provider responses and credential
lookup substituted; see [ARTIFACTS.md](ARTIFACTS.md#minimal-development-evidence).
The converter neither opens a Vault nor changes old cloud objects. This closes
the source-entry gap, not the end-to-end cloud requirement: native Drive still
needs memory-queue integration, a configured local login and a real verified
upload/receive. The new source has not been published or installed; see
[MIGRATION.md](MIGRATION.md).

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
