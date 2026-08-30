# v0.24 implementation status

Version: **0.24.0-alpha.1**, source preview. Stable v0.23 and the user's installed
private client are unchanged. This table describes code present in this branch,
not a claim of runtime or production validation.

| Capability | Implementation present | Not established |
| --- | --- | --- |
| Lightweight core | Single standard-library file, taskless records, recall/handoff, append-only SQLite | Runtime regression/performance results for v0.24 |
| Shared client entry | Eight stdio MCP tools; same Vault/core; explicit configuration | Every vendor/model host can install/use it unchanged |
| Optional automatic save | Reviewed Codex hook template, opt-in visible event capture, private retry state | Live host capture or native Work automatic lifecycle |
| Signing and admission | Ed25519 provider, explicit independent trust, quarantine, revocation-aware views | Security audit, multi-signature history, hostile same-user isolation |
| Incremental sharing | Bounded signed directory batches, closure, blocked dispositions, requeue, receipts | Network backend, remote consumption acknowledgment, throughput benchmark |
| Old data conversion | One-way supported v0.21 export ZIP conversion, mapping/loss report, dry-run | Arbitrary legacy formats or a real private-data migration |
| Portability | Standard-library core and unsigned client paths | Native Windows protected signing/ACL adapter |
| Packaging | Optional source template and no-overwrite builder sharing authoritative modules | Installed package, marketplace activation or host hook trust |

## What this change deliberately does not do

- Reintroduce Task, Project, conversation or model ownership of memory.
- Restore the old monolithic runtime or Git authentication/synchronization.
- Install, replace or remove the user's existing plugin or private data.
- Enable capture, generate keys, enroll a sender or activate hooks automatically.
- Hide persistence, erase logs, acquire permissions, spawn agents or run goals
  merely because memory contains a proposed next action.
- Claim signatures prove truth or that a remote agent read a delivered batch.
- Publish a production-ready release without integration evidence.

## Review performed and remaining work

Implementation work included source inspection, official host/protocol/provider
documentation checks and independent static cross-reviews of the client,
signing, storage and transfer interfaces. Those reviews identified and corrected
several concrete retry/trust/queue issues. They are not substitutes for execution.
All eight Python source/specification files were parsed as syntax without
importing the application or executing tests; the three plugin JSON files were
parsed, and whitespace/error checks were performed on the patch.

At the owner's request, **tests were not run**. No live capture, dependency
installation, runtime migration, key generation, benchmark, plugin installation,
or cross-device trial was performed. Follow [REVIEW_HANDOFF.md](REVIEW_HANDOFF.md)
for independent synthetic checks before treating this as a stable release.

Next release priorities are evidence from a real consenting local client,
signed two-device interoperability and crash-recovery checks, Windows protected
key storage, more complete key-rotation/multiple-proof recovery, and safe
operator UX for blocked batches. The light core remains independently usable
throughout; no migration back to Task-centric ownership is planned.
