# Memory Vault v0.28.0-alpha.0.33 — authorized full client

Python and native TypeScript Agents can locate an independently retained original
ACK receipt through an explicitly selected directory using
`connect/recover_discovered_receipt`. The directory provides signed location
metadata; the owner performs a separate authorized source read and confirms only
the actual recipient receipt bound to the original message and ciphertext.
Directory and source identities, storage epochs, leases, revision floors and
custody remain checked. Missing facts and mismatched custody cannot confirm a send.

New opt-in `receipt-index` sources fund the complete bind, return, publication and
owner-read workflow with up to 256 shared requests. Existing signed grants and
node policies keep their original limits. Directory publication and source
preparation still require Python and independent consent. Recovery does not
select replacement directories or republish lost entries. See
`docs/OPEN_ACK_DIRECTORY.md` for the closed invitation shape.

Native TypeScript Agents can confirm a stored send through its independently
selected original ACK source while the delivery node is offline. An explicit
`connect/recover_receipt` uses the existing owner invitation; repeating the
unchanged original `send` uses a successful preparation already in protected
state. Fresh source identity, origin, epoch and revision floors remain checked.
Confirmed repeats stay local, and signed refusal history is shared with Python
across restart. Automatic recovery has twenty seconds within the existing
sixty-second send deadline. No Python subprocess or new permission is created.
ACK source preparation, receipt return and replica workflows still use Python.
See `docs/OPEN_ACK_PROVISIONING.md`.

Authorized maintainers can retain exact mailbox copy bundles and resume them
through a finite worker after source loss, lost commit replies or restart.
The worker reuses the original upload journal, selected destination and grants;
refusal, expiry and exhausted limits stop for attention. It does not choose
replacement nodes or create independent read permissions.

A sender can register an independently authorized ACK replica. Repeating its
unchanged original send then confirms the actual recipient receipt even after
the original delivery and ACK sources stop. The current replica key, origin,
storage epoch and original owner/recipient bindings remain checked. Confirmed
repeats stay local; removing a selection preserves authenticated revocations.
See `docs/OPEN_ACK_RECOVERY.md` and `docs/OPEN_ACK_PROVISIONING.md`.

Python recipients can retain an independently selected ACK destination for an
exact message with `register_mailbox_receipt_return`. Ordinary `receive` then
returns its actual saved receipt using the original authority, retaining
exact requests across lost replies and restarts. Expired uncertain uploads
stop for reconciliation; completed returns are not transmitted again.

When the sender repeats its original stored send, a matching earlier ACK
preparation can recover the independent receipt automatically. The current
source key/epoch, original READ grant, message and ciphertext must match.
Changed requests are refused before source access, and confirmed repeats
use local history. These steps share the ordinary operations' network
deadlines and do not create new source or memory permissions. See
`docs/OPEN_ACK_PROVISIONING.md`.

Python recipients can register an already authorized message replica through
`connect` with `action: register_replica`. Ordinary `receive` then polls the
retained selection, including after restart, using the existing original keys,
read permissions and durable memory inbox. Current destination identity and
storage epoch must match. Saved/rejected ciphertext is not downloaded again;
removing a selection preserves received memory and authenticated denials.

This adds bounded polling of explicitly selected copies. It does not create
replacement copies or exchange permission automatically; receipt return still
requires its separate original authority. See `docs/OPEN_ACK_RECOVERY.md`.

This candidate adds participant-local mailbox reservation consent and maintainer
assembly commands. Each owner/sender uses only its own existing keys, checks its
independently retained exact destination selection, and keeps retry/denial state
in the existing protected transport database. See `docs/OPEN_ACK_RECOVERY.md`.

This version adds `copy-reserve-root`, `copy-reserve-feed` and
`copy-reserve-message`: existing client identities reserve real replica capacity
and retain exact offers and assignments across restart. Original owner and sender
consents, destination opt-in, and separate upload/return permissions remain
required. See `docs/OPEN_ACK_RECOVERY.md` and the release notes.

This candidate adds independently reserved mailbox directory, feed and encrypted
message replicas. Python recipients can receive a copied message after the
original node stops, durably import its selected memory and retain their signed
receipt for independent return. Existing keys, author trust, original grants and
remembered revocations remain in force. Exact upload requests survive lost
responses and restarts. See the mailbox replica guide and release notes for
commands, authority requirements and source-bound acceptance.

This candidate connects ACK-bearing mailbox retention to explicit cold-recipient
receipt return. See the [receipt guide](plugins/memory-vault-client/docs/OPEN_ACK_PROVISIONING.md)
for `ack_request_id` and `return_mailbox_receipt`. Participants keep independent
read/write grants and verify the selected source before publishing a saved receipt.


This candidate adds Agent mailbox configuration inspection/restoration and
receiver-issued sender authorization from an already approved local contact.
Exact destination/status originals survive retries and restarts. Paged replies
stay within the Agent output limit, while completed message retries use actual
signature accounting. Existing retained ciphertext, selected-memory recovery
and independent ACK operations remain available with separate original grants.

Use the [open-network quickstart](plugins/memory-vault-client/docs/OPEN_NETWORK_QUICKSTART.md)
and [mailbox guide](plugins/memory-vault-client/docs/OPEN_NETWORK_CONTACT.md).
Nodes explicitly enable finite remote setup; participants keep their own Vault,
identities and author-trust policies. Contact or mailbox permission alone does
not authorize execution or enrolling an author as trusted.

Python hosts the complete new mailbox workflow; native TypeScript retains its
existing independent networking and includes mailbox wire/proof support.
Automatic replacement-node message repair and full native mailbox-client parity
remain unfinished. There is no project-operated public seed or verified
thousand-agent/global-availability result. Use the source-bound release record
for actual validation and compare archive bytes with published checksums.

This full-client package targets **v0.28.0-alpha.0.33 open-delivery source**,
not a stable-release or complete runtime-certification claim. Existing published
versions remain immutable. Match the artifact's source and hashes to its
manifest; this README does not establish installation or publication. The plugin is under
`plugins/memory-vault-client`; the local marketplace catalog is
`.agents/plugins/marketplace.json`. All required runtime source modules listed
in `runtime/MANIFEST.json` under the plugin are included. No Git checkout or
runtime build is needed to use the archive.

Python 3.10+ is required for the Python client. A host supporting local stdio
MCP is needed only for that existing interface; native agent operations do not
require MCP. The ordinary unsigned memory path uses only the standard library. Optional record signing requires
the separately installed integration dependency, explicit keys and independent
public-key trust. No production publisher/encryption/recovery provider is
provisioned by this package.

The optional native network uses the client-only, hash-locked dependency profile;
relay, authority and trusted HTTP services use the separate server lock. See
[dependency and platform limits](plugins/memory-vault-client/docs/DEPENDENCIES_NETWORK.md)
and [explicit setup](plugins/memory-vault-client/docs/NETWORK_QUICKSTART.md).
Extracting this package installs none of those dependencies or services.

Retained from alpha.5: the reviewed experience-exchange flow: chat does not
implicitly become memory; authorized Hint queries return up to four frozen
pages of four hints; explicit selections transfer one to four roots and their
complete permitted dependency union. Cancellation stops pending query work.
Already accepted batches remain available through local
`recall(received_batch_message_id=...)` with current trust annotations, original
sources, environment and counterevidence. See
[Hint v4](plugins/memory-vault-client/docs/NETWORK_HINTS_V4.md) and
[local batch reads](plugins/memory-vault-client/docs/RECEIVED_BATCH_RECALL.md).

This is an open-delivery preview with a retained private messaging profile.
It is not a complete global communication network or unlimited-capacity claim.
Current controls use Hint v4 and content/v2; old preview forms are not replayed
or silently migrated. Extraction does not replace an installed plugin or
private state. The separate no-Docker synthetic trial has unconfigured service
trust; it needs operator provisioning, not an assumed available relay/authority.

## Explicit setup

1. Extract into a location you control and keep it there.
2. Create a new private configuration; existing configuration is not overwritten:

   ```bash
   python3 -I -B plugins/memory-vault-client/scripts/launcher.py configure --vault /absolute/private/vault.sqlite3
   ```

   Omit `--vault` to use the reference default. Configuration does not create a
   Vault or install a host. Add `--capture-visible-turns` only to explicitly
   enable visible-turn capture; host hook approval remains separate.
3. For a compatible Codex installation, add the extracted **root directory** as
   a local marketplace source, then review and install `memory-vault-client`
   from `Memory Vault — Protocol and Client`. Review hooks separately. This
   package is not a listing in a universal public plugin directory.
4. For another local MCP host, use your Python executable with arguments
   `-I -B /absolute/path/to/plugins/memory-vault-client/scripts/launcher.py mcp`.
   Add `--config /absolute/private/client.json` before `mcp` when needed.

On Windows use `py -3 -I -B` or the absolute installed Python executable.
The packaged default command is `python3`; adapt the host command if it is not
available. Native protected storage/locking supports local fixed NTFS under
the documented owner/DACL rules. UNC, unsupported volumes, reparse points and
unverified permissions fail closed. **Real Windows behavior was not tested.**

## One Vault through either route

The same configured storage and trust work without MCP:

```bash
python3 -I -B plugins/memory-vault-client/scripts/launcher.py protocol --serve
```

An independent implementation can instead follow the documentation-only UAMP
protocol using another language or storage engine. Both exchange the same
canonical records; neither a task, session nor a plugin owns them.

The full client additionally includes:

- Eleven MCP tools, local visible-turn lifecycle and Codex/Claude Code/Gemini
  CLI/generic adapters. Host support requires actual approved event delivery.
- An explicit `compat` entry for the ten v0.21 production host operations;
  legacy handles are local correlations, not new memory owners.
- Full-record CJK/Latin retrieval, deterministic concept expansion, explained
  BM25 ranking, derived claim views, graphs and repairable indexes.
- Durable signed sync, explicit receive/flush, blocked-send review and selected
  resolution, directory/rclone backends and resumable large-transfer fragments.
- Memory snapshots plus separately explicit full-client recovery to new paths;
  no silent key, permission or remote-delivery trust transplant.
- Native portable chunks and v0.21 ZIP/pack/checkpoint verification/conversion,
  preserving original evidence and graph/alias mappings.
- Content-selected sharing, independent trust lifecycle and fail-closed
  externally provided encryption/catalog contracts; explicit device metadata
  init/status and new/old envelope inspection without a configured Vault.
- Controlled update staging, independently pinned publisher verification,
  isolated managed activation/rollback and separately opted-in finite updates.
- Six native agent operations over the same Vault, independently issued member
  identities, encrypted selected-memory delivery, bounded rejection and explicit
  one-pass `network-pump` retries. There is no new external-protocol adapter or
  automatic background network service.

See `plugins/memory-vault-client/docs/CLIENTS.md`, `COMPATIBILITY.md`,
`PARITY.md`, `PLATFORMS.md` and the full `V0_25_PARITY_PLAN.md` ledger.
Operational commands never derive permissions from memory. Ordinary recall and
local saves do not wait for network. No host setting, private installation,
startup service or real Vault is changed by extracting this package.

## Evidence and independent review

Prior results and this release preparation are distinguished in the
[release scope](plugins/memory-vault-client/docs/RELEASE.md). The 94-test
developer result belongs to reviewed source `c473d23`, not a new test run
triggered by extracting this archive.

The [capacity report](plugins/memory-vault-client/docs/V0_25_PACK_CAPACITY_SMOKE.md)
records one opted-in actual 516 MiB synthetic create/copy/resume/repeat/unpack/hash
case, a 2 GiB/512-entry manifest check and rejection of a sparse 2 GiB + 1 byte
source before output. No full 2 GiB transfer or throughput benchmark was run.
The file-pack limit is now 2 GiB; 4 MiB chunks and the default 32-uncached-chunk
copy budget remain unchanged. This is earlier capacity evidence, not validation
of the current network alpha. See the historical
[capacity patch notes](plugins/memory-vault-client/docs/RELEASE_NOTES_V0_25_1.md).

Historical private-profile [alpha evidence](plugins/memory-vault-client/docs/RELEASE_NOTES_V0_26_ALPHA.md)
separates temporary synthetic checks, independent crypto frames and loopback
process recovery from real-model, real-cloud and deployment acceptance. The
alpha's bounded queues and 256-member roster do not satisfy the planned
1,000-active-agent gate. Its explicit pump is not automatic replica repair.

The earlier [minimal release report](plugins/memory-vault-client/docs/V0_25_RELEASE_MINIMAL.md)
records six distinct methods with passing evidence across two source-pinned
runs: five initial passes, then one recovery-only pass after a fixture setup
correction; application code was unchanged. This is not a full-suite pass.
The packaged [validation index](plugins/memory-vault-client/docs/VALIDATION.md)
pins limited offline synthetic evidence to exact source commits. Match those
reports to this artifact; results from other versions do not certify its paths.
Those earlier entry paths share one Python reference; they do not establish
independent implementations or models for this alpha. Full P01–P14,
signing/encryption, cloud, real-host/cross-device, native Windows and performance
acceptance remain open; recorded checks installed no host plugin and accessed
no private memory. The separate review kit supplies synthetic cases and bounded
instructions for reviewers using their own authorization and disposable data.

Only allowlisted public source is packaged. No real memory, credentials, keys
or local user configuration is included. Inventory/archive checks establish
bytes, not publisher identity or production security.
