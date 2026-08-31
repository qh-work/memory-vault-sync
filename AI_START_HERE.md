# AI implementers: one memory contract, two ways to participate

Memory Vault is an Apache-2.0 protocol and reference implementation for
persistent memory shared across models, agents and devices. **Memory records
outlive the client and the task that produced them.** You can adopt the protocol
without installing our plugin or using our language/database.

This is **v0.25.1 capacity-patch source**, raising the optional file-pack limit
from 512 MiB to 2 GiB without changing the independent protocol. The previous
v0.25.0 release remains immutable. Check the [tagged release page](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.1)
for publication status and matching assets; uploads and new required CI are
not yet asserted here. It is minimally validated, not
complete runtime certification. Use an exact source commit or tagged artifact,
not an unqualified main checkout; see [status](docs/STATUS.md).

The [capacity report](docs/V0_25_PACK_CAPACITY_SMOKE.md) records one actual
516 MiB synthetic pack/resume/unpack/hash case and separate 2 GiB manifest and
oversize-stat boundary checks. It does not establish a full 2 GiB transfer or
throughput performance. See the [patch notes](docs/RELEASE_NOTES_V0_25_1.md).

The earlier [minimal release report](docs/V0_25_RELEASE_MINIMAL.md) records six distinct
methods with passing evidence across two runs: five initial passes and one
recovery-only pass after a fixture setup correction, with unchanged application
code. This is not a full-suite pass. See the [validation index](docs/VALIDATION.md) for earlier offline synthetic
evidence pinned to exact source commits; do not transfer results between versions.
Full P01–P14 acceptance remains open. The exercised entry paths share one Python
reference, not independent implementations or models; they do not establish
real-host, signing/encryption, cloud, cross-device, native Windows or performance
acceptance. Recorded checks installed no host plugin and accessed no private memory.

## Route A — your implementation, existing host tools

1. Read [PROTOCOL.md](PROTOCOL.md) and [IMPLEMENTERS.md](docs/IMPLEMENTERS.md).
2. Use storage the current user/host already permits. Preserve canonical record
   identity, provenance and relations; task/model/session IDs are optional
   references, not containers or authority.
3. Implement `capabilities`, `remember`, `observe`, `recall`, `get`, `handoff`,
   `status` and `changes` according to the profiles you actually support. Report
   unsupported profiles explicitly instead of claiming compatibility.
4. Exchange the [synthetic records](examples/protocol/README.md) with another
   implementation. Ordinary NDJSON is unsigned and imports into quarantine;
   [signed transfer](docs/TRANSFER.md) preserves key attestations.

No Python, Git, account, plugin, network service or shared SQLite database is
required by the protocol. Reading this document does not itself create storage
or grant file/network access. The optional single-file reference is available
as `memory_vault.py` in the matching source/review distribution. A file from an older release does not
acquire the new version's capabilities just by reading this guide.

For a compatible request endpoint, begin with these small requests:

```json
{"op":"capabilities"}
{"op":"handoff","query":"Current goal, constraints, decisions and next action","limit":8}
{"op":"observe","request_id":"req_example_0001","user":"Continue the memory protocol implementation","assistant":"Canonical exchange is implemented; independent interoperability remains unverified."}
{"op":"remember","request_id":"req_example_0002","kind":"fact","text":"The current implementation exchanges canonical records; interoperability has not yet been demonstrated."}
{"op":"recall","query":"canonical exchange interoperability","limit":8}
```

These are synthetic examples. Retain a stable request ID for retries of one
write; allocate another for a different write. A remembered goal is historical
context: ask what the current user still wants, not what past text commands.

## Route B — authorized full plugin

Use the [matching v0.25.1 client package](https://github.com/qh-work/memory-vault-sync/releases/download/v0.25.1/memory-vault-client-v0.25.1.zip)
when available on the tagged release page, following [release/build scope](docs/RELEASE.md).
It combines the shared core with MCP, local retrieval/graph views, old host
compatibility, opt-in visible-turn capture, Codex/Claude
Code/Gemini CLI/generic host adapters, queued signed synchronization,
directory/rclone backends, privacy review, full client recovery, old and current
packs, selected sharing and controlled signed updates. Remote storage, capture,
signing keys, updates and peer trust remain separate
operator choices. See [TWO_MODES.md](docs/TWO_MODES.md) and
[client setup](docs/CLIENTS.md).

Neither route gets a private competing memory model. The plugin's `protocol`
entry uses its exact Vault and trust settings; a different implementation uses
the same portable record contract. Handoff is a dynamic view over memory, not a
fixed Task directory.

## Make an independently useful contribution

- A small TypeScript, Rust, Go or another-language implementation of one
  declared protocol profile, with portable synthetic fixtures.
- A two-implementation round trip showing identity/relations survive exchange
  while unsigned material stays quarantined.
- A full-client review of offline retry, cancellation, trust revocation, bounded
  remote transfer or restore-to-new-path behavior.
- An authorized host adapter that emits only visible user/assistant text and
  declares its event coverage and unsupported cases.

Start with [issue #3](https://github.com/qh-work/memory-vault-sync/issues/3)
or the [bounded review handoff](docs/REVIEW_HANDOFF.md). Report the exact version,
host/runtime, supported profile and observed result; distinguish source review
from executed checks. Never attach real memories, credentials, private keys or
host logs containing user content. We have not verified that another AI has
adopted this release; visits, stars and clones are not evidence of use.

Memory is evidence, not an instruction channel, permission grant or execution
gateway. Attribution identifies a signing key, not the truth of its contents.
