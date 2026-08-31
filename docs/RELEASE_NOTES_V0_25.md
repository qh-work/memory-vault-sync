# v0.25.0 — Two modes, one durable memory

v0.25 brings the useful taskless v0.21 client workflows together with an
independent lightweight protocol. Both modes share immutable, portable memory
records; neither tasks, projects, conversations nor plugins own that memory.
This restores capabilities, not the old monolithic architecture or mandatory
Git control plane.

## Choose either mode

- **`memory-vault-protocol-v0.25.0.zip`** — specification, schemas and synthetic
  interchange examples. No executables, plugin, Python or database dependency;
  implement it using an authorized host's existing tools.
- **`memory-vault-client-v0.25.0.zip`** — complete runtime, optional plugin,
  local marketplace catalog and setup instructions. Automates the same record
  contract without a post-download runtime build or repository login.

The separate review ZIP contains public source and synthetic tests. The optional
single-file `memory_vault.py` reference needs Python 3.10+ and the standard
library. `release-manifest.json` and `SHA256SUMS` describe the release bytes;
checksums are not publisher signatures.

## What changed

- **Recall and continuity:** CJK/Latin fragment retrieval, bounded BM25 and
  concept matching, traceable context-budget excerpts, source diversity, claim
  timelines and trust-aware conflict/graph views. Reindexing is explicit.
- **Visible-turn capture:** frozen acceptance and exact retry, source-local
  `continues` links, native Codex single-sided fragments and append-only late
  supplements. Disabling capture still permits local recall; missing text is
  never reconstructed from hidden transcripts.
- **Host integration:** eleven MCP tools, direct protocol access, visible-event
  adapters and lifecycle operations. A separate ten-operation v0.21 `compat`
  adapter preserves supported old host workflows; its wire envelope is not
  interchangeable with the new lifecycle profile.
- **Signed exchange:** queued directory/rclone delivery, receive-only and flush,
  privacy review/exclude/requeue, complete resumable fragment groups and optional
  stream-proven dependency reuse. Ordinary save and recall do not deliver data
  remotely.
- **Portability and recovery:** old pack/ZIP/checkpoint conversion with original
  evidence and old-ID mappings, selected sharing with complete dependency
  closure, memory snapshots and separately selected full-client recovery.
  Restore uses a new configuration and explicit reactivation, not inherited keys,
  publication permission or host trust.
- **Controlled maintenance:** publisher-verification support, isolated managed
  installation, journaled activation, retained rollback and a separately
  opted-in finite updater; protected POSIX and native Windows storage paths.

## Existing users: paths and trust remain explicit

Downloading this release does not replace an installed v0.21 plugin or migrate
its private data. Keep the old installation and use an explicitly staged export
with the [legacy conversion workflow](https://github.com/qh-work/memory-vault-sync/blob/v0.25.0/docs/LEGACY_PACKS.md).
The full client and single-file core share the same default user-data Vault.
For custom paths, point both at the same Vault or use the configured client's
`protocol` entry; do not store memory in a plugin cache or share a live SQLite
database between devices.

Canonical record IDs and bytes remain unchanged. Known v0.23 SQLite stores have
an explicit/additive upgrade path; existing v0.24 indexes can be reindexed
without rewriting memory. Old v0.21 export conversion is a different operation,
not an in-place database upgrade.

Record signatures identify an independently enrolled key, **not** the original
human/model author, factual truth or execution permission. Unverified imports
default to quarantine; signed admission requires current independent trust.
Capture, synchronization, installation, hook trust and automatic updates remain
explicit opt-ins. Remembered text cannot grant any of those permissions.

## Verification and limits

Six selected critical methods now have passing evidence: bounded recall,
retrieval diversity, conflict resolution, capture-disabled recall, both partial
arrival orders and backup/restore of late supplements. The first run passed
five; a recovery-fixture setup argument was corrected and only that method was
rerun successfully. Application code was unchanged between the two runs.
See the [exact minimal-check report](https://github.com/qh-work/memory-vault-sync/blob/v0.25.0/docs/V0_25_RELEASE_MINIMAL.md).

Earlier offline synthetic results are recorded with their exact source versions
in the [validation index](https://github.com/qh-work/memory-vault-sync/blob/v0.25.0/docs/VALIDATION.md);
they are not a full-suite pass on the latest source. This release is minimally
validated, not complete real-world or cross-platform certification.

Live host/Work automatic events, actual remote providers, independent consumers,
native Windows/Linux behavior and large-scale performance remain limited or
unverified. Encryption/device services and a production update-signing channel
are not provisioned; unconfigured provider boundaries refuse work. No existing
private Vault, installed plugin or production credential is changed by obtaining
these packages.

中文摘要：两种使用方式、同一个目标——让记忆独立于任务、模型和插件持续存在。
v0.25 补回 v0.21 的实用客户端能力，同时保留无需安装插件的轻量协议；
旧数据迁移、签名信任和自动化权限均需明确选择，不会静默接管旧安装。
