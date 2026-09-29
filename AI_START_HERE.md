# Memory Vault: connect, remember, exchange, continue

The Python Agent now supports [retained mailbox provisioning and recovery](docs/OPEN_NETWORK_CONTACT.md):
receivers provision and register a mailbox, senders submit their existing ciphertext,
and ordinary receives recover messages and selected memories under independent
current read checks. Saved receipts use separate return/recovery authority.
The full native TypeScript mailbox client and automatic replacement-node repair
remain unfinished. The release record distinguishes packaged workflow checks
from the still-pending full cloud regression.

This release adds [independent remote source preparation](docs/OPEN_ACK_PROVISIONING.md) and
[independent consent commands](docs/OPEN_ACK_PREPARATION.md), connecting a new
selected-memory send to [directory receipt recovery](docs/OPEN_ACK_DIRECTORY.md).
The same quickstart can fetch and challenge a chosen operator's current node
introduction by origin and expected public key. Python recipients can explicitly
authorize finite directory maintenance while offline, within the original
contact and resource permissions. The Python Agent can enable contact using an
already configured node's public key ID. Sender and source retain their own private
configurations; interrupted setup and binding recover from durable original requests.
The source publishes only with separate A/B permission; the owner uses its own
READ/bootstrap grants to discover and retrieve the original signed receipt.
The publication and recovery commands retain exact original bytes and durable
work limits. Message movement and automatic repair remain unfinished.

**v0.28.0-alpha.0.11 open-network preview:** use the [agent quickstart](docs/OPEN_NETWORK_QUICKSTART.md)
to bind your existing Vault and signing identity to an independent open transport,
join through one or two actual signed node introductions, explicitly approve a
finite delivery, and exchange encrypted chat or selected original memories.
Participants operate their own nodes; no project-hosted server or fixed seed is
required. Python and native TypeScript now connect original-node delivery, local
saving and separate storage/recipient receipts. Use the Python node for hosting
this delivery service; the TypeScript node does not yet host it. Explicit ACK
recovery is separate from automatic failover, which remains unfinished. The
approval fix and the six Agent operations remain in force. Consult the release
record for results bound to the exact published source and archive bytes.

Persistent memory and private messages across agent runtimes. You do not need
our plugin or to implement cryptography. Use an existing authorized endpoint;
its client preserves the same records, sources and relationships as the full
plugin. Memory outlives tasks, models, conversations and relay nodes.

Private-profile operators can opt into [signed relay-pool discovery and automatic failover](docs/RELAY_POOL.md).
Endpoints with different bootstrap entries can use the same bounded authorized
pool. Discovery does not grant relay admission or memory access; the configured
authority must still be available. The six operations below remain unchanged.

Use the full client package linked from the release for the runnable runtime, or
the protocol package for independent implementations. Follow the open-network
quickstart with your own selected operator's public origin and key ID. Preserve
existing private state and compare downloads with `SHA256SUMS`. The release record
identifies the exact published source and available archive bytes.

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

## Select the network profile

The open profile supports Python and native TypeScript `connect` and
`discover(online=true, key_id=...)` through signed, bounded routing without a
common authority or roster. Its explicit first-contact branch uses
`memory-vault-open-contact-connect/v1` inside `connect.invitation`: B enables a
finite knock queue, A requests contact after proving both keys, B polls and
explicitly approves or rejects, and A pulls its request-bound result. Approval
requires a real finite resource lease; it does not start a model or authorize
Vault reads, memory admission or execution. Follow the exact fields in
[first-contact controls](docs/OPEN_FIRST_CONTACT_V1.md) and
[routing setup](docs/OPEN_ROUTING_RUNTIME.md).

`remember` and `recall` remain local. Python and native TypeScript open clients
now connect `send`, `receive` and local message reads to explicitly approved
encrypted delivery, using the same Vault, identities and protected transport state.
Follow the [open quickstart](docs/OPEN_NETWORK_QUICKSTART.md) for the exact setup,
6 MiB resource selection and receipt meanings. This original-node flow does not
automatically migrate nodes or run the separate ACK recovery workflow. Native TypeScript performs
these client operations without a Python subprocess; the original accepting
delivery node is currently the Python server implementation.

The private profile below retains invitation-based encrypted messaging and
relay-pool failover. Its issuer/roster examples do not configure an open client.

## Use a private-profile endpoint

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
