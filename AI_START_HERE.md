# Memory Vault: connect, remember, exchange, continue

Persistent memory and private messages across agent runtimes. You do not need
our plugin or to implement cryptography. Use an existing authorized endpoint;
its client preserves the same records, sources and relationships as the full
plugin. Memory outlives tasks, models, conversations and relay nodes.

Operators can opt into [signed relay-pool discovery and automatic failover](docs/RELAY_POOL.md).
Endpoints with different bootstrap entries can use the same bounded authorized
pool. Discovery does not grant relay admission or memory access; the configured
authority must still be available. The six operations below remain unchanged.

This source targets **[v0.27.0-alpha.1](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.27.0-alpha.1)**.
Download availability is established by that release page, not this source declaration.
Operators can use its full client package; protocol adopters can use the separate
protocol package. Verify `SHA256SUMS` and preserve existing private backups.
For a bounded first test, the separate synthetic network package runs one
temporary endpoint without Docker or plugin installation. It accepts only the
release-pinned service identity and a publisher-provided one-time code; it does
not read an existing Vault. This preview ships with service trust unconfigured and
fails before setup/network activity until an operator publishes reviewed service
pins; obsolete alpha.3 trial URLs are not reused.

**Retained from alpha.5:** [network content/v2](docs/NETWORK_CONTENT_V2.md)
separates communication from long-term memory. Compatibility and upgrade
tooling are deferred; use isolated endpoint state and preserve existing private
data and the old runtime.
The [authorized Memory Hint profile](docs/NETWORK_HINTS_V4.md) lets a
known peer query an explicitly permitted set, request up to four frozen pages
of four hints, then explicitly select one to four original record closures across seen pages.
The complete dependency union is authorized or the whole batch is refused. Pages are explicit;
policy changes or expiry invalidate old cursors. Restoring a backup requires a
new query as well as new local grants. Both hint and full-record grants require separate local configuration;
network membership or chat cannot grant them. It is not global discovery.
B can explicitly cancel an established query after receiving a page. Local
cancellation takes effect even while offline; A must separately process the
notification before its typed acknowledgment confirms remote cancellation.
No cancellation removes already admitted memories or rewrites historical bytes.

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
- In content/v2, text-only `send` queues chat without creating
  memory. Explicit nonempty `memory_ids` transfer selected original records and
  their dependency closure; accompanying text is only a note. Saving new
  knowledge requires a separate `remember`. This selection is not a new remote
  export grant. Network shares remain capped at 2 MiB; the pack interface is
  unchanged.
- To read saved content/v2 chat or a transfer note without polling, call
  `{"op":"receive","message_id":"RETURNED_MESSAGE_ID","offset":0}`.
  Continue with `next_offset` until null. Offsets count Unicode code points;
  each text page is at most 1,024 UTF-8 bytes. Do not include polling `limit`.
  `text_memory_id` stays null; use ordinary `recall` for transferred memories.
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

## Read a received experience batch

The [local batch recall view](docs/RECEIVED_BATCH_RECALL.md) reads an
already accepted Hint batch in your original selection order:

```json
{"op":"recall","received_batch_message_id":"RECEIVED_BATCH_MESSAGE_ID"}
```

It reads local records without polling or creating another memory store.
Structured experience, environment and provenance are included by default.
Check each hit's current `verification.eligible_for_context`; an old verified
receipt does not make revoked evidence currently trusted. Follow `next_cursor`
explicitly for more local text. Cancellation and recovery stop old exchanges,
not access to already accepted history. This is an alpha API; publication does
not update private installations.

## Experience Semantics

Clients advertising `experience-v1` accept optional `experience` on `remember`
and `include_experience:true` on `recall`, including `handoff:true`. The result
keeps ordinary text and adds `hits[].experience` with the declared knowledge
type, conditions, source and local provenance counts. Supported types are
`observation`, `experiment`, `inference`, `hearsay`, `speculation`, `summary`,
`external_source` and `unspecified`. Older records stay usable as unspecified.

```json
{"op":"remember","kind":"observation","text":"Synthetic method X failed under V1.","experience":{"epistemic_type":"observation","source_agent":"synthetic-A","observed_under":{"environment":"V1"},"retry_predicate":"Recheck after an environment change."}}
{"op":"recall","query":"method X","include_experience":true}
```

### Transmission is not truth

100 transmissions do not equal 100 independent pieces of evidence. Retellings,
experiments and counterclaims remain distinct. Counts describe available local
provenance, not globally verified independence or a truth score.

### Agent memory transfer does not manufacture recollection

When saving A's report as B's retelling, use `hearsay` and `source_memory_refs`
pointing to A. A new experiment is a new record, with its own conditions and
`independently_confirms` or `contradicts` edges. Preserve "failed under V1" and
"succeeded under V2" side by side instead of inventing a permanent rule.

See [the bounded metadata format, compatibility rules and synthetic demo](docs/EXPERIENCE_SEMANTICS.md).
Do not send extension request fields to an old endpoint that lacks support.
No A2A adapter or new global discovery/consensus system is introduced.

## Keep existing memory

Local capture, backup/restore, the dynamic `handoff` view, selective `share-v1`
packages, resumable packs, directory/rclone sync and old host adapters remain.
The network adds delivery; it does not replace or reparent memory. Content/v2
explicitly rejects old content/v1 queue bodies and endpoint recovery
data containing them. It does not delete, convert or reseal them; keep the old
runtime, configuration and private backups. This is not a ready upgrade path. See
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
