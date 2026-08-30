# Lightweight and full-mode capability matrix

Both modes use the same independent Memory Record model. A Task, Project,
conversation, device or model is optional provenance, never a parent container,
lifecycle owner or source of execution permission. "Full" means the optional
operational integrations around that core; it does not mean the old monolithic
plugin or all external services have been recreated.

This matrix describes source capabilities, **not executed acceptance tests**.
The owner requested no test execution. Each host, signing, sync and recovery
path still needs independent synthetic and consenting real-host validation.

| Capability | Independent/light path | Optional full path | Old v0.21 comparison |
| --- | --- | --- | --- |
| Persistent taskless records | Portable specification and small reference core | Same records and same selected Vault | Preserves the taskless direction; does not restore Task owners |
| Facts/decisions/goals/continuity | Explicit remember/observe/recall/handoff | MCP, direct protocol, lifecycle and host adapters | Dynamic context replaces fixed Task directories |
| Cross-model/client access | Any implementation of the record/protocol contract | Ready-made optional local client integrations | No requirement to use one vendor or one plugin |
| Automatic visible-turn capture | Caller controls when to save | Opt-in host-visible adapters, staging and retries | Restores an integration workflow, not silent permissionless capture |
| Crash/idempotency handling | Canonical stable-request write receipts | Durable lifecycle phases and explicit local queues | Implemented with smaller control modules, not legacy task binding |
| Per-record signing | Optional profile; unsigned mode labeled | Ed25519 attestations and explicit current trust | **New actual record-signing path**; v0.21 ordinary records were hash-only |
| Trust revocation | Runtime may supply independent trust checks | Configured client excludes currently untrusted signers | Replaces external-provider-only device-trust scaffolding; not a complete multi-device key ceremony |
| Incremental logical transfer | Portable interchange, no built-in account service | Signed directory batches, explicit sync coordination and optional external transport | Replaces mandatory Git transport rather than requiring it again |
| Drive/cloud carriage | External transport choice | Optional rclone-compatible carriage where configured | Not a reimplementation of the former native Drive-specific subsystem |
| Diagnostics | Core capabilities/status | Content-free doctor, queue/lifecycle/trust/sync summaries | Restores operator visibility without scanning conversations |
| Retry | Same request and arguments | Bounded explicit hook retry; lifecycle/host exact-request recovery | Does not automatically resolve incompatible events |
| Memory backup | Unsigned logical NDJSON for interchange | Consistent SQLite snapshot with signatures and write receipts | Real memory recovery; explicitly excludes unsnapshotted live client queues |
| Restore | Import reviewed records | Restore to a new database, rebuild index, current trust decision, new replication identity | No silent in-place rollback of live stores/cursors |
| Compression/chunk carriage | An optional byte-pack profile | New bounded compressed chunks, resumable copy and new-output unpack | Not old v0.21 memory-pack wire compatibility |
| Updates | Review a new protocol/source revision | Explicit check/stage workflow; activation remains a separate operator choice | Does not claim old signed-update production channel existed or silently reinstall hooks |
| Old memory conversion | Supported explicit export conversion | Same conversion tool included with client | One-way migration, not retained legacy execution paths |
| Artifact/file data | Independent artifact records/references | External file transfer/backup chosen separately | Not the complete old artifact hydration/object-store subsystem |
| Multi-signature/key recovery | Specification can evolve independently | Not a completed multi-signature history or automated recovery quorum | Old state-machine interfaces were not a deployed production key ceremony |
| Windows | Unsigned standard-library core | Protected signing/recovery require native ACL support | Do not label POSIX-only protected storage as universally deployed |

## What was actually lost and what should return

The v0.23 cut removed more than Task/Git coupling: host lifecycle integration,
durable client queues, operational diagnosis/recovery, optional signed-update
verification and staged security modules went with the old runtime. A lightweight
core alone did not replace those user-facing workflows. The full mode restores
concrete integrations as optional modules while keeping the lightweight route
independently usable.

The comparison must also avoid inflating the old baseline:

- v0.21 ordinary memory records/checkpoints used canonical hashes and source
  pseudonyms, not per-record cryptographic author signatures.
- Ordinary Git writes disabled commit signing and used a generic client author.
  Repository identity/private-access checks were not original-author proofs.
- Device trust, encrypted sharing and signed replication catalogs exposed
  external-provider contracts whose default production providers refused work.
- RSA-PSS software-update verification was real code, but separate from memory
  authorship; the documented production release-signing channel was not provisioned.

That is why simply restoring every old file would neither prove identity nor
finish an interoperable full product. Current record attestations, explicit
trust and actual recovery paths need their own evidence.

## Deliberate exclusions, not missing tasks to recreate

- No mandatory Git repository/login for owning or saving memory.
- No `Project -> Task -> Memory` hierarchy or lifetime coupling.
- No automatic enrollment of packet-contained keys, policy changes from memory,
  permission creation, hidden persistence, log suppression or agent spawning.
- No claim that a hash manifest proves a publisher, a valid signature proves a
  statement true, or a successful transfer proves another AI read the record.
- No claim that Work supports automatic hooks merely because an MCP or plugin
  package exists. Actual host event delivery must be independently established.

## Operational references

Use [OPERATIONS.md](OPERATIONS.md) for diagnosis/retry,
[BACKUP.md](BACKUP.md) for memory-only snapshots and new-copy recovery,
[CLIENTS.md](CLIENTS.md) and [LIFECYCLE.md](LIFECYCLE.md) for integration boundaries,
and [TRANSFER.md](TRANSFER.md) for signed incremental delivery.

Capabilities implemented in source, capabilities enabled on an installation,
and capabilities validated by execution are separate facts. This matrix must
not be used as evidence that private data was migrated, a client was installed,
a signing key was generated, a network account was connected, or tests passed.
