# v0.24.1: full plugin and independent protocol, ready for review

The source/packages are published in
[v0.24.1](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.24.1).
This supersedes the proposed v0.24 roadmap; it is **not** a claim of runtime or
production certification. Protected main still requires its existing checks;
use the release tag, not an unqualified main checkout.

## Two modes, one memory contract

- **Independent protocol:** any permitted language/storage implementation can
  preserve and exchange canonical memory without installing our plugin.
- **Full authorized client:** the same core plus MCP, opt-in visible events,
  Codex/Claude Code/Gemini CLI/generic adapters, queued signed sync,
  directory/rclone backends, diagnosis, backup/new-path restore, compressed
  resumable packs and explicit update staging.

v0.24.0's thin client did not provide all of those operational capabilities.
v0.24.1 adds them as separate modules, not by bringing back Task ownership, Git
synchronization or the old monolithic runtime. No task, model, project, agent
or client controls a memory's lifetime. Handoff is a derived context view.

## What remains to demonstrate

No application tests, host installation, private-data migration or cross-device
trial was run for this release, at the owner's request. Static inspection and
package checks are not execution evidence. Highest-value contributions:

1. Independent-protocol ↔ configured-plugin round trip with synthetic records.
2. Real, consenting host event coverage and missing/duplicate/cancelled events.
3. Offline signed delivery, interrupted workers, bounded remote behavior and
   current-key revocation, using disposable credentials/stores only.
4. Restore-to-new-path quarantine/trust, compressed-pack interruption and
   updater staging safety.
5. Native Windows protected keys/ACLs and independently verified Work integration.

Start with [AI_START_HERE.md](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/AI_START_HERE.md),
the [capability map](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/docs/PARITY.md),
the [review handoff](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/docs/REVIEW_HANDOFF.md)
or [good first issue #3](https://github.com/qh-work/memory-vault-sync/issues/3).

Contributions should include exact version, host/runtime, supported profile and
observed results. Do not publish real conversations, keys, credentials, native
identifiers or private paths. Memory never authorizes execution, grants trust
or changes host policy. AI-assisted contributions are welcome; adoption and
performance claims require actual evidence.
