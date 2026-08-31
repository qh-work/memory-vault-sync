# network-v1: optional private communication carrier

Status: 0.26.0-alpha.1 reference implementation. Core canonical records and
share-v1 are unchanged. This independently defined network has no MCP, A2A,
Matrix, Nostr or Graphiti adapter or compatibility claim. These projects are
design references only, with no imported task/room/relay/database model.

## Interfaces and bounds

`memory_vault_agent.Agent(client_config, network_config)` provides `connect`,
`remember`, `recall`, `discover`, `send`, `receive`. The existing client forwards
these through `agent`; old `protocol`, `mcp`, `share`, `manage`, `pack` and host
adapters remain. The single-file core still uses only the standard library.

The [independent TypeScript endpoint](NETWORK_TYPESCRIPT.md) reuses canonical
records, identities, the local Vault and network queue schemas without invoking
Python. Its native `Agent` uses the same bounded fragment retrieval and dynamic
handoff selection as Python. Low-level `CanonicalVault.recall` retains its
explicit substring utility; `retrieve` uses the canonical retrieval profile.
One known platform floating-point boundary can still change selected order;
exact ranking parity is an open test gate. Full graph/view-management and legacy cloud-worker parity remain outside this
TypeScript preview. The existing
TypeScript HTTP SDK continues to use the shared six-operation endpoint above.

`remember` and `recall` use the original client Vault and local trust. A sent
text becomes a source-signed canonical observation. It travels with selected
memories and their evidence closure in `universal-memory-share/v1`. No task,
project, mailbox, model, node or member becomes those records' parent.

The facade caps requests at 64 KiB and results at 8 KiB. Recall cursors freeze
up to 32 selected immutable IDs and page UTF-8 fragments, not canonical records.
Wire requests/polls have a separate 8 MiB cap. Alpha share attachments are at
most 2 MiB, recipients at most 16, configured relays at most two. Existing large
file-pack support is unchanged; larger network handoffs need a future chunked
message profile, never silent truncation. The same 8 KiB operation-result limit
applies to the native Python, native TypeScript, NDJSON and trusted HTTP entries.

Recall results describe historical evidence, never the receiving agent's own
experience or a newly verified environment. Preserve known original provenance;
an unknown author stays unknown. Claimed agent/session labels and the verified
signing key are distinct. Old failure evidence must be revalidated when relevant
conditions change or its applicability is uncertain; no automatic retry or new
execution permission is created. See the [agent usage rules](../AI_START_HERE.md#attribute-inherited-evidence-and-recheck-old-failures).

Received text is a bounded preview. Where `text_memory_id` is provided for an
imported record, native `recall(memory_id)` and subsequent `recall(cursor)`
pages recover its full text under the existing local trust rules.

Errors contain `code`, `retryable`, `retry_after_ms`, `commit_state` and a valid
supplied `request_id`. Unknown commit state requires retrying the same ID and
arguments. A successful evaluation may return `queued_local` or `not_connected`
with per-node errors: `ok` alone does not mean remote delivery succeeded.

## Cryptography and independent control

Endpoint Ed25519 identities reuse the existing format. X25519 encryption keys
are separate protected files. JWE General JSON fixes `ECDH-ES+A256KW` and
`A256GCM`, with no compression or downgrade. `joserfc` decrypts only the bound
local recipient (`verify_all_recipients=False`). Duplicate JSON fields,
nonportable outer numbers, unknown headers, wrong AAD/keys and tampering fail.
Inner memory bytes retain the core's existing canonical encoding and integers.

The outer signature covers the complete JWE plus network/message/sender/
recipients/roster version+hash/time. Content-hash and length commitments stay
inside encryption. Public routing, participant key IDs, timing and ciphertext
size remain observable. E2EE is not traffic anonymity. See the independent
[Python/TypeScript interoperability frames](../examples/network-interop/README.md).

An independently configured issuer signs rosters and invitations. New `init`
setups generate an authority signing key separate from the daily endpoint's
signing key. Endpoint key backups do not contain that authority key. Existing
explicit shared-key setups remain readable but report
`issuer_key_shared_with_endpoint`; their endpoint backups also carry issuer
authority and must be protected accordingly. An invitation
binds both candidate keys, network, scope, expiry, one-use ID, roster hash and
chosen handoff-envelope hash. No handoff uses SHA256(empty bytes). Inclusion in
a candidate roster is not relay admission: candidates must prove both private
keys. Invitation consumption, membership and result commit atomically at each
relay. Exact retry cannot create another membership.

Rosters carry monotonic versions and previous-document hashes. Both endpoints
and relays reject a broken immediately preceding link; after missing multiple
versions they require a fresh issuer-signed current snapshot, not an invented
proof of all intermediate changes. An independent
authority answers a member-signed nonce challenge with signed current status,
valid for at most 300 seconds. The authority holds an issuer signing key but
no endpoint decryption keys, and cannot change members through HTTP. Relays
cannot renew status. Without fresh status, publication pauses; local memory
remains usable. Revocation cannot recover plaintext already received.

## Relay and delivery

Routes: `GET /.well-known/agent-memory.json`, `GET/POST /v1/status`,
`POST /v1/join`, `/v1/messages`, `/v1/poll`, `/v1/ack`. Discovery describes a real
instance; the repository discovery file explicitly is not a service.

The optional relay uses private SQLite WAL and ciphertext objects. Objects
are durable before database references commit. Queue/disk/request/concurrency
limits fail explicitly. Endpoints freeze ciphertext in a durable outbox for
retries; changed bytes under one ID conflict. Polling is at-least-once with
durable cursors; recipient acknowledgment follows verification and local save.
Signed `validated_saved` is not proof of understanding, execution or truth.
After identity recovery with empty transport state, authenticated old receipts
with no matching local outbox are reported as `unmatched_receipts`, never as
confirmed local sends. The cursor can advance past them. A repeated valid
recipient save acknowledgment returns the first retained proof; conflicting
request IDs or ciphertext bindings remain errors.

`NetworkClient.pump(maximum_messages=4, maximum_seconds=10, receive_limit=4)`
and the existing client's explicit `network-pump` management command make one
bounded retry/receive pass. They do not add a seventh agent operation, install
a scheduler or start a background worker. Outbox attempts are capped at 16 and
incoming messages separately at 4; either can be set to zero. The 1–60 second
cooperative deadline starts no new requests after expiry and bounds owned HTTP
timeouts, but does not forcibly interrupt in-flight system calls or borrowed
transports. Permanent per-item errors are distinguished from retryable errors,
and queue rotation prevents one blocked item from starving other queued sends.

The pump uses persisted request IDs, plaintext content and frozen ciphertext;
it does not re-export or rewrite canonical memory. New rows save the original
recipient list before attempting a connection. An older frozen row can recover
its recipients from its existing envelope; an older unfrozen row without that
list needs the original request and reports
`network_outbox_recipients_unavailable`. The worker never guesses recipients,
changes a frozen envelope or bypasses a failed fresh-status check. See the
[one-pass command and exit states](NETWORK_QUICKSTART.md#preserve-retry-recover).

After current authorization, signature verification and successful decryption,
invalid application JSON/shape/text/share encoding is stored as rejected
ciphertext in bounded local delivery bookkeeping (128 entries / 16 MiB).
`receive` reports `state: rejected` without exposing that plaintext, importing
it as memory or sending `validated_saved`. Durable quarantine permits cursor
progress; duplicate node copies use the same retained entry. Cryptographic,
storage, capacity and deeper share/import errors still stop processing. A full
quarantine requires operator attention; it is not an unbounded spam sink.

Two nodes can receive identical ciphertext, with actual storage acknowledgment
counts and degraded results. This is not quorum replication, independent
failure-domain certification, automatic repair, garbage collection, anonymous
discovery or federation. A malicious relay can withhold/discard data: signatures
and encryption do not prove completeness or availability.

Receiving shares does not enroll authors in the personal trust registry.
Independently trusted signatures admit normally; unknown authors remain
quarantined, with original share/proof bytes retained in local inbox material.
Membership never promotes text into execution or local policy authority.

Node contribution is explicit within an owner's allowed process/disk/bandwidth
budget. Messages cannot rent resources, start agents, add nodes or conceal
activity. Each registered node has its own signing key, bound address and
storage epoch in an independently signed node directory. Node control requests
use a separate signature domain and never confer member or decryption rights.
Fresh issuer status binds both member and node checkpoints; remembered signed
directories reject rollback, key replacement and revoked-node resurrection.
Deploy only that node's own signing key, public issuer/roster materials and
ciphertext state to a relay machine, never an owner's whole setup directory. Same-OS-user processes
are not isolated from each other's private files merely by file permissions.

[Directed node transfer](NETWORK_NODE_TRANSFER.md) freezes the source and
requires an explicit issuer grant for an exact snapshot and target. The target
verifies original envelopes, historical rosters and recipient-signed receipts,
flushes ciphertext before committing references, and acknowledges the complete
snapshot. Partial copies remain fenced and resumable. `exit_ready` records this
target acknowledgement, not source deletion, automatic rerouting, independent
failure domains or universal replica availability. Automatic repair of a
nonempty surviving node is not implemented by this empty-target operation.

## Native entries and the trusted HTTP endpoint

Python `Agent.handle`, the existing client's `agent` command and `POST /v1/agent`
use the same request and result. They call the same Vault/trust and network
client; transport state holds delivery bookkeeping, not a second canonical
memory store or identity system. The pre-existing eleven-tool MCP memory
interface is unchanged and is not a new network protocol adapter.

HTTP-only agents require a trusted endpoint-side crypto bridge. That bridge
sees plaintext, requires a separately provisioned bearer token and defaults to
loopback. It must not run on an untrusted ciphertext relay. Its authenticated
`/.well-known/agent-memory.json` describes the actual native endpoint; no
AgentCard, A2A message route, task container or room model is exposed.

## Recovery and acceptance limits

Existing personal Vault/client backup, new-path restore and selected shares
remain. `keys-backup` is the smaller network identity/control package; it does
not include offline outbox/inbox state or replace a personal Vault backup.
The separate [full endpoint recovery](NETWORK_RECOVERY.md) snapshots canonical
memory and committed transport state, including never-uploaded messages,
frozen ciphertext, request IDs, cursors and historical acknowledgements.
Both use an independently stored random recovery key and new-only destinations.
Neither starts capture, a service or automatic delivery. Independently chosen
issuer/network/endpoints and fresh issuer status are required to resume
network operations; old member and node checkpoints remain rollback bounds.
The archived memory trust registry cannot override current operator-selected
trust. Keep the original private Vault and offline queues until recovery has
been independently verified.

[Alpha evidence](RELEASE_NOTES_V0_26_ALPHA.md) does not satisfy real
three-model/two-provider/local-runtime interoperability or adoption. Later
stages retain 10–100 actual-agent collaboration, 1000 active agents for 72h,
physical sharding and federation. Synthetic clients do not satisfy those gates.
