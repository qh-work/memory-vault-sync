# Memory Vault client — v0.25 development

In a source checkout this directory is a **build template**, not an installed
runtime. The release builder assembles the complete optional client from public
source allowlists and writes its runtime inventory last.

The full client and independent protocol share one canonical taskless memory
model. There is no separate plugin Vault or Task/Project owner.

- Eleven MCP memory tools, local retrieval/graph views and explicit writes.
- Direct protocol, lifecycle and ten-operation v0.21 `compat` entry points.
- Opt-in visible-turn capture, host adapters and durable local recovery.
- Independently configured signed sync, privacy review and resumable groups.
- Diagnosis, snapshots, full-client recovery, old packs and selected sharing.
- Explicit stage/managed activation/rollback; automatic updates require a
  separately opted-in managed installation and pinned publisher trust.

The launcher checks exactly the listed source files and refuses extra runtime
modules or bytecode caches. It suppresses new cache writes; inventory checks are
not publisher signatures or isolation from a hostile same-user process.
MCP/hook templates use isolated Python startup and retain separate host approval.

The packaged [validation index](docs/VALIDATION.md) records limited offline
synthetic evidence pinned to exact source commits; match each report to the
artifact instead of transferring results between versions. The exercised entry
paths share one Python reference, not independent implementations or models.
Full P01–P14, signing/encryption, cloud, real-host/cross-device, native Windows
and performance acceptance remain open. Recorded checks installed no host plugin
and accessed no private memory. v0.25 remains unreleased development source;
Work automatic lifecycle delivery is not established.

Read the packaged `docs/CLIENTS.md`, `docs/COMPATIBILITY.md`,
`docs/PARITY.md` and `docs/REVIEW_HANDOFF.md`. In a checkout, those files live
at the repository root rather than inside this unbuilt template directory.
