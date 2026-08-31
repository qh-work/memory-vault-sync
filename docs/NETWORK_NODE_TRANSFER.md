# Directed ciphertext node migration (0.26 alpha)

Migration is an explicit operator action from a frozen source node to one
independently authorized, empty target node. It preserves committed ciphertext
bytes, message IDs, original recipient sets, historical signed rosters, consumed
invitation records, and original recipient-signed acknowledgements. It does not
transfer endpoint private keys, decrypt messages, create a second memory model,
or grant nodes access to agent mailboxes.

The older relay database does not retain the complete original invitation and
dual-key join proof. Therefore its member table is **not sufficient authority**
to admit members at another node. The issuer must explicitly approve a directed
migration grant after reviewing the complete frozen snapshot and its member
state. This offline grant binds the exact snapshot hash, source and target node
keys, addresses and storage epochs, current member/node policy checkpoints,
counts, transfer ID, and a validity period of at most 300 seconds. The normal
status service does not sign migration grants or bless source-supplied members.

## Operator sequence

Provision the target with its own node signing identity, a new storage epoch,
and an empty state directory. Register it in the independently signed node
directory with `import` and `node.status` rights. The source needs `export` and
`node.status`. The source may be active or draining; the target must be active.
Initial target members may already exist only when they match the source's
explicitly authorized member state. Ordinary nonempty target nodes cannot be
overwritten or merged by this first implementation.

Use the configured, hash-locked server environment described in
[NETWORK_QUICKSTART.md](NETWORK_QUICKSTART.md). Replace all absolute example
paths, identifiers and addresses with explicitly selected values.

First freeze the source and write its signed snapshot to a new private file:

```sh
python -m memory_vault_node --config /private/example/source-relay.json \
  prepare-export --transfer-id example-transfer-001 \
  --output /private/example/review/source-snapshot.json --maximum-seconds 60
```

Preparing a snapshot persists the source's draining fence. New joins, messages
and acknowledgements are rejected; exact previously successful requests remain
lookups under current authorization. Subsequent prepares for the same transfer
ID return the frozen snapshot, not a new view of live data. A different ID cannot
silently replace it. Snapshot and object validation run under the relay's actual
cross-process transaction lock. Expired join challenges and transient status
nonces are not migrated; consumed invitation history is retained.

Review the source descriptor, member admissions and scopes, consumed invitation
records, message/receipt counts, total ciphertext size and snapshot hash before
issuer approval. Move the signed snapshot to the issuer over an approved
channel. This contains membership and delivery metadata, so protect it even
though message bodies remain encrypted and travel separately.

The issuer then creates a new private grant file with the explicit
`node-transfer-authorize` administration command, selecting the target node key
from its own signed node directory:

```sh
python -m memory_vault_network_admin node-transfer-authorize \
  --authority-config /private/example/issuer/authority.json \
  --snapshot /private/example/review/source-snapshot.json \
  --target-node-key-id ed25519_REPLACE_WITH_REGISTERED_TARGET_KEY_ID \
  --output /private/example/review/transfer-grant.json
```

The approval covers the exact historical admission state, not all future source
claims. Current policy files may retain their original expired validity window:
the issuer explicitly chooses those files, and the subsequent online operation
still requires fresh signed status for their exact hashes. Equal-version forks
and incorrect adjacent-version chains are rejected. A gap of several versions
requires a new explicit issuer decision; no intermediate chain is invented.

Run one bounded transfer pass from the source:

```sh
python -m memory_vault_node --config /private/example/source-relay.json \
  transfer --grant /private/example/review/transfer-grant.json \
  --maximum-objects 4 --maximum-seconds 10
```

The transfer CLI returns exit code `0` only for `exit_ready`; an incomplete pass
or a structured rejection returns `2`. Configuration/argument failures can
return `1`. Repeating the same command resumes
the target's signed, durable object progress. A network interruption or either
process restarting does not change the frozen bytes or message IDs. If the
grant expires, or current policy changes, obtain another explicit grant for the
same snapshot and same target. No background worker starts automatically.

The source first refreshes its own independent node status and authenticates
the target's signed nonce challenge against the exact granted key, address and
storage epoch, before disclosing the snapshot. The issuer supplies fresh status
for the target nonce. Both nodes enforce current policy, source export/target
import scope, and the exact grant checkpoint on transfer requests. Source
requests sign `begin`, `object` and `commit` control bindings using the native
node request format. There is no generic remote object-read API.

## Completion and safe handling

On the target, begin creates a persistent import fence. Incoming objects are
independently checked against the snapshot, original message signature,
historical roster and exact encryption recipient keys. Original historical
data is retained even if a member has since been revoked; current relay
authorization still prevents delivery to that member. Untrusted imported
SQLite schemas are never executed: fixed local SQL rebuilds the supported
tables only after every object has passed validation and durability barriers.

Objects are flushed and atomically published before any database reference is
committed. An already matching orphan is republished through the same storage
barriers, rather than treating its presence as proof of durable publication.
Commit verifies and flushes every object again before signing the complete
snapshot receipt. A failed flush does not advance object progress or create
message rows, and reports a retryable storage error. Capacity includes unrelated crash-orphan files, not just objects
already referenced by the database.

Only after the source verifies and saves the target's signed completion receipt
does it report `exit_ready`. This means the selected target acknowledged the
complete snapshot. Results always retain `source_data_deleted=false` and
`safe_to_remove=false`: the command never deletes data, stops a service, revokes
a source node, or proves independence of disks, hosts or failure domains.
Routing clients to the target, observing availability, retaining rollback data,
and approving source retirement remain separate operator decisions.

## Limits and API

The signed snapshot is limited to 6 MiB, 4,096 messages, 256 members and consumed
invitations, 131,072 acknowledgements, and 256 MiB referenced ciphertext. The
destination's configured lower limits also apply. Each pass uploads at most
0–16 objects, default 4, with a cooperative 1–60 second budget, default 10.
Prepare uses a 1–60 second budget; each receiving operation has a 10 second
budget. Operating-system calls already in progress are not forcibly killed.
Oversized snapshots or exhausted storage fail explicitly; they are not
partially truncated. An incomplete target remains fenced for a later retry.

Python entry points in `memory_vault_node_transfer.py` are `prepare_export`,
`issue_transfer_grant`, `receive_transfer`, and `transfer`. The relay route is
`POST /v1/node-transfer`. Persistence uses only the relay's existing metadata
table (`node_transfer_export`, `node_transfer_import`) and existing message
objects/tables. There is no alternate memory database or external protocol
adapter. This candidate's automated evidence is synthetic loopback process,
restart, signature and storage-failure testing; it is not a public deployment,
real-model test, TLS audit, or cross-failure-domain migration guarantee.
