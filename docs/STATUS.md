# v0.24.1 release status

Version: **0.24.1**, full-client + independent-protocol source/package release. The protocol-only archive
and the complete optional plugin archive are distributed together. The protected
main branch and the maintainer's installed private client are unchanged.
Implementation and packaging are not claims of runtime or production validation.

| Capability | Implementation present | Not established |
| --- | --- | --- |
| Independent protocol | Language/storage-neutral specification, JSON Schemas, synthetic NDJSON and canonical hash material | An independent implementation's successful conformance run |
| Lightweight core | Single standard-library file, taskless records, recall/handoff, append-only SQLite | Runtime regression/performance results for v0.24 |
| Shared client entry | Eight stdio MCP tools; same Vault/core; explicit configuration | Every vendor/model host can install/use it unchanged |
| Direct client protocol | Uses the configured Vault and trust settings; single requests, stdio and portable export/import | A live cross-implementation round trip |
| Lifecycle profile | New explicit session/turn profile, durable commit, exact retries and cancellation boundary | Old v0.21 wire compatibility or an executed crash/cancel suite |
| Optional automatic save | Codex hooks, Claude Code/Gemini CLI/generic visible-event adapters, private retry state | Live host capture, all vendor versions or native Work automatic lifecycle |
| Signing and admission | Ed25519 provider, explicit independent trust, quarantine, revocation-aware views | Security audit, multi-signature history, hostile same-user isolation |
| Automatic incremental sharing | Bounded signed batches, coalesced queue, finite opted-in worker, closure, retry and content-free receipts | Always-on delivery, remote consumption acknowledgment, throughput benchmark |
| Remote backends | Explicit directory or pinned rclone/config/peer streams; Drive/S3/WebDAV/SFTP/crypt through rclone | Every backend/provider's live behavior; native direct Drive API parity |
| Diagnosis and recovery | Read-only doctor, bounded replay, consistent snapshot and restore-to-new-path with current trust | A complete old-client settings/queue migration or executed crash-recovery suite |
| Large exports/snapshots | Bounded compressed chunk packs, cached resumable copy, full verification on unpack | Old pack wire compatibility, object-store byte-range resume, benchmark |
| Controlled updates | Explicit stable-release check, bounded verified stage to new path, no downloaded-code execution | Publisher signature, auto-install, marketplace certification or host activation |
| Old data conversion | One-way supported v0.21 export ZIP conversion, mapping/loss report, dry-run | Arbitrary legacy formats or a real private-data migration |
| Portability | Standard-library core and unsigned client paths | Native Windows protected signing/ACL adapter |
| Packaging | Complete source-built plugin, local catalog, protocol-only ZIP, source/JSON parsing and byte inventories | Desktop installation, marketplace activation or host hook trust |

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
Public Python files are parsed as syntax without importing the application or
executing tests; public JSON and synthetic NDJSON are structurally parsed.
The release builder verifies stored archive bytes against the build inputs and
emits file counts, asset hashes and limitations in `release-manifest.json`.
Independent static review also covered commit/cancel state and read-only receipt
replay after capture is disabled. These are not runtime test results.

At the owner's request, **tests were not run**. No live capture, dependency
installation, runtime migration, key generation, benchmark, plugin installation,
or cross-device trial was performed. Follow [REVIEW_HANDOFF.md](REVIEW_HANDOFF.md)
for independent synthetic checks before treating this as a stable release.

Full mode restores these product capabilities as separate modules, not by
reintroducing the old monolith. [PARITY.md](PARITY.md) records deliberate
replacements and remaining differences. The lightweight core does not import
the optional runtime or acquire its dependencies.

Next release priorities are evidence from a real consenting local client,
signed two-device interoperability and crash-recovery checks, Windows protected
key storage, more complete key-rotation/multiple-proof recovery, and safe
operator UX for blocked batches. The light core remains independently usable
throughout; no migration back to Task-centric ownership is planned.

See [release scope](RELEASE.md) for the tag-versus-main distinction and
[independent implementation](IMPLEMENTERS.md) for a route that does not require
our Python implementation, SQLite or a plugin.
