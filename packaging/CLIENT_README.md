# Memory Vault v0.26.0-alpha.1 — authorized full client

This full-client package targets **v0.26.0-alpha.1 native-network source**,
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

The [capacity report](plugins/memory-vault-client/docs/V0_25_PACK_CAPACITY_SMOKE.md)
records one opted-in actual 516 MiB synthetic create/copy/resume/repeat/unpack/hash
case, a 2 GiB/512-entry manifest check and rejection of a sparse 2 GiB + 1 byte
source before output. No full 2 GiB transfer or throughput benchmark was run.
The file-pack limit is now 2 GiB; 4 MiB chunks and the default 32-uncached-chunk
copy budget remain unchanged. This is earlier capacity evidence, not validation
of the current network alpha. See the historical
[capacity patch notes](plugins/memory-vault-client/docs/RELEASE_NOTES_V0_25_1.md).

Current [alpha evidence](plugins/memory-vault-client/docs/RELEASE_NOTES_V0_26_ALPHA.md)
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
