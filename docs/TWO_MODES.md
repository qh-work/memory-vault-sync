# Two modes, one persistent memory system

The lightweight protocol is **not** a replacement for the full plugin. The
plugin restores useful automation and operations around that same protocol;
neither route owns the memory or requires users to choose which task it belongs
to. v0.25 restores the useful v0.21 workflows missing from the v0.24.1 client,
while keeping the independent protocol and current record identities intact.

| Concern | Independent protocol | Authorized full client |
| --- | --- | --- |
| Canonical memory | Normative records, relations, provenance, continuity and exchange | The exact same contract through one reference core |
| Storage | Any permitted durable store in a compatible implementation | Local SQLite Vault; never a copied live database on a network share |
| Use from another model | Read the contract and use that host's existing tools | Eleven MCP tools, the configured `protocol` endpoint or explicit old host `compat` bridge |
| Automatic capture | Implement only if the host/user permits it | Opt-in Codex, Claude Code, Gemini CLI and generic visible-event adapters |
| Automatic sharing | Optional signed transfer profile or unsigned review bundles | Local durable queue; bounded background worker after independent opt-in |
| Remote backend | Not required | Shared directory or explicitly configured rclone remote/crypt |
| Attribution | Declared optional Ed25519 trust profile | Explicit signing identity, independent trust registry, quarantine and revocation checks |
| Recovery | Preserve canonical identity and evidence | Doctor, memory/full-client recovery, scoped retry, old packs/checkpoints, compressed resumable packs |
| Updates | Follow compatible protocol versions | Explicit signed stage/managed activation/rollback; automatic mode only after independent opt-in and publisher trust |
| Dependencies | No prescribed language, plugin or database | Python 3.10+; cryptography for signing; rclone only for that backend |

## Full-client flow

```text
permitted host event / MCP write / configured protocol write
                    |
          durable local canonical memory
                    |
          coalesced sync notification
                    |
  explicit sync opt-in + matching Vault / identity / trust
                    |
 finite worker -> signed incremental exchange -> recipient quarantine/trust
```

Local save and recall do not wait for network delivery. A remote failure leaves
pending work; later authorized events or an explicit run can retry. There is
no always-on daemon and no autonomous agent that executes remembered goals.
Content-free local sync receipts are visible to the operator. A transfer receipt
does **not** prove another AI read, accepted or acted on the memory.

## Start with the smallest suitable route

- No integration wanted: read [IMPLEMENTERS.md](IMPLEMENTERS.md), exchange the
  supplied synthetic examples, or use the optional standard-library core.
- Automatic local saving: [CLIENTS.md](CLIENTS.md) and [HOSTS.md](HOSTS.md).
- Automatic cross-device sharing: [SYNC.md](SYNC.md) and
  [REMOTE_BACKENDS.md](REMOTE_BACKENDS.md), after setting up explicit trust.
- Diagnose/recover: [OPERATIONS.md](OPERATIONS.md), [BACKUP.md](BACKUP.md),
  [PACKS.md](PACKS.md), [UPDATES.md](UPDATES.md).

No Task/Git control plane, hidden transcript capture, hidden persistence,
key auto-enrollment or high-privilege instruction channel is restored. New
lifecycle and old `compat` envelopes remain explicitly separate. [PARITY.md](PARITY.md)
maps old capabilities to their current replacements and limits.

This is minimally validated **v0.25.0 release source**, not runtime certification.
Check the [tagged release page](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.0)
for publication status and the matching
[protocol](https://github.com/qh-work/memory-vault-sync/releases/download/v0.25.0/memory-vault-protocol-v0.25.0.zip)
or [client](https://github.com/qh-work/memory-vault-sync/releases/download/v0.25.0/memory-vault-client-v0.25.0.zip)
package. The [minimal report](V0_25_RELEASE_MINIMAL.md) records six distinct
methods with passing evidence across two runs, including a fixture-only recovery
setup correction; it is not a full-suite pass. The
[validation index](VALIDATION.md) pins the limited offline synthetic evidence
to exact source commits; match those to the artifact under review. The exercised
paths share one Python reference, not independent implementations or AI models.
Full P01–P14, signing/encryption, cloud, real-host/cross-device, native Windows
and performance acceptance remain open. Recorded checks installed no host plugin
and accessed no private memory; Work automatic event delivery is not established.
