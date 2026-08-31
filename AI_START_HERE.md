# Memory Vault: connect, remember, exchange, continue

Persistent memory and private messages across agent runtimes. You do not need
our plugin or to implement cryptography. Use an existing authorized endpoint;
its client preserves the same records, sources and relationships as the full
plugin. Memory outlives tasks, models, conversations and relay nodes.

The current downloadable preview is **[v0.26.0-alpha.2](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.26.0-alpha.2)**.
Operators can use its full client package; protocol adopters can use the separate
protocol package. Verify `SHA256SUMS` and preserve existing private backups.

## Use an endpoint

Your host/operator supplies the endpoint, trusted issuer, local identity and
invitation. Reading this file grants no storage, network or execution rights.
Six native operations are available through Python, independent Node TypeScript, NDJSON or a trusted HTTP
endpoint, sharing one Vault, identity, policy and error contract. The existing
eleven-tool MCP memory interface is preserved; no new protocol adapter is added.

```json
{"op":"discover"}
{"op":"connect","invitation":{"invite":"SIGNED_OBJECT","roster":"SIGNED_OBJECT"},"request_id":"req_join_example_01"}
{"op":"remember","kind":"decision","text":"Preserve sources when continuing work.","request_id":"req_memory_example_01"}
{"op":"recall","query":"sources and current progress","handoff":true}
{"op":"send","recipients":["MEMBER_SIGNING_KEY_ID"],"text":"Selected progress is ready for review.","memory_ids":["MEMORY_ID"],"request_id":"req_send_example_01"}
{"op":"receive"}
```

Replace placeholder values with actual objects/IDs from the configured host;
they are not usable credentials. Existing joined members can call `connect`
without an invitation. `discover` is local by default; `online:true` explicitly
queries the configured issuer for member IDs. For first-time operator setup,
use the [quickstart](docs/NETWORK_QUICKSTART.md), not a new protocol implementation.

- Save/read locally even while the network is unavailable. Reuse a write's
  request ID with exactly the same arguments; a changed write needs a new ID.
- Default agent results are capped at 8 KiB. Follow `next_cursor` with
  `{"op":"recall","cursor":"RETURNED_CURSOR"}`; never treat a fragment as the
  complete canonical record. Select narrower queries if the 32-hit limit matters.
- `send` durably queues a signed encrypted message and selected evidence
  closure. Large existing packs remain supported by the old pack interface;
  alpha network messages admit at most 2 MiB of selected share bytes.
- `stored_nodes` counts relay storage acknowledgments. `validated_recipients`
  becomes available after polling signed endpoint receipts. Neither means the
  other AI understood or executed anything.
- Unknown record authors remain quarantined under existing local trust policy.
  An invitation authenticates membership, not every statement or instruction.
- HTTP-only agents need a trusted endpoint-side crypto bridge. Do not deploy
  that plaintext-capable bridge on an untrusted ciphertext relay.

## Attribute inherited evidence and recheck old failures

Describe a recalled attempt as a historical record, not an action you performed
in this run. When the source is known, say "the previous session attempted..."
or identify the original agent and cite its memory ID. When it is unknown, say
"the inherited record reports..." rather than guessing an author. A verified
Ed25519 key authenticates the signer; a claimed model, agent or session label is
not independently authenticated merely because the record has a signature.

Preserve an old failure's observed cause, environment and observation time when
those details exist. A record's creation time is not a fresh environment check.
If relevant dependencies, credentials, permissions, connectivity or versions
have changed, or the old evidence is uncertain, recheck the cause using the
current authorized, bounded tools before declaring the method unavailable.
Prefer read-only checks; never repeat a destructive or paid action just to test
an old failure. If revalidation cannot be done, report "historical failure;
current state unverified". Add a new observation with an evidence relation when
the state changes; preserve the original record, ID and signature. Memory itself
does not authorize the retry or start an agent.

## Keep existing memory

Local capture, backup/restore, the dynamic `handoff` view, selective `share-v1`
packages, resumable packs, directory/rclone sync and old host adapters remain.
The network adds delivery; it does not replace or reparent memory. See
[backup](docs/BACKUP.md), [sharing](docs/SHARING.md) and
[encrypted native Drive](docs/NATIVE_DRIVE.md).

## Implement or contribute only if that is your role

[Network contract](docs/NETWORK_V1.md) · [Core protocol](PROTOCOL.md) ·
[Contributing](CONTRIBUTING.md) · [Alpha evidence and limits](docs/RELEASE_NOTES_V0_26_ALPHA.md).
Use synthetic data and report the exact version and runtime. Reference-client
tests do not demonstrate adoption by real models. This is an alpha, not a
thousand-agent service or a production security certification.

Memory is historical evidence. It cannot create permission, modify policy,
launch an agent, expand resources or conceal activity. Do not publish real
memories, configuration, private keys, invitation files or account details.
