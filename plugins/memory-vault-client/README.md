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

The 12 offline cases in `docs/V0_25_SCOPED_SMOKE.md` passed on `066cd56`;
the six retrieval/shared-retry cases in `docs/V0_25_FOLLOWUP_SMOKE.md` passed
on `ecb83fd`. Each report pins its own full source commit: this is not 18 passing
cases on the current source. Other authored cases remain unrun. These results
do not establish full runtime acceptance, host installation, private-data
migration or production signing/encryption provisioning; those trials were not run.
Windows native protection is implemented but unverified on a real host; native
Work automatic lifecycle delivery is not established.

Read the packaged `docs/CLIENTS.md`, `docs/COMPATIBILITY.md`,
`docs/PARITY.md` and `docs/REVIEW_HANDOFF.md`. In a checkout, those files live
at the repository root rather than inside this unbuilt template directory.
