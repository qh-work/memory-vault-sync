# Bounded ACK source recovery

The Python and native TypeScript clients can recover a previously committed **unbound ACK source**
over the fixed `/open/v1/repair/bootstrap` route. It verifies both parties'
Ed25519/X25519 possession, the original source event, every referenced original,
and the source's current authorization before returning a complete result.
Use the same agent signing/encryption identities and protected transport state
as the ordinary open client. The command never opens or imports into the Vault.

This is the pre-message ACK phase. It does not confirm a recipient save, recover
a message, create an empty or occupied receipt slot, or move a source to a new
node. Those later transitions remain required for independent receipt recovery.
The alpha.0.6 quickstart retains original-node messaging; this separate operator
recovery entry adds the unbound ACK phase.

## Source operator

For a new node, explicitly enable the finite service:

```sh
python -B memory_vault_open_setup.py --directory /absolute/private/new-node --base-url "$MV_NODE_ORIGIN" --enable-repair
python -B memory_vault_open_node.py --config /absolute/private/new-node/node-config.json
```

Forward the printed HTTPS paths, including `/open/v1/repair/bootstrap`, to the
local listener. Existing node configuration stays unchanged. The service is
closed unless `repair_policy.enabled` is exactly `true`; it also requires that
node's existing encryption identity. Enabling the route creates no authority
and offers no public allocation, activation, or arbitrary object-read RPC.

An operator integration must already have used `RepairAckState.allocate`,
`activate`, and `finalize_unbound` to reserve shared node capacity and commit the
complete authorized source originals in that node's `network.sqlite3`.
The service never treats a presented hash as a read capability. Status floors,
revocations, challenges, one-use requests and work budgets survive a restart.
Admitted attempts, including failed attempts, consume their actual verification
work. Caller authentication before admission and local node-descriptor
verification are outside this grant ledger. A crash
with unsettled work keeps its reservation charged. No automatic ACK-state
garbage collection is implemented in this development slice.

The default local ceilings include an 8 KiB probe, 256 KiB cumulative proof,
64 requests and 512 signature checks per grant. An actual owner grant must fit
both its original parent budgets and those ceilings. The client also applies
its independent finite parsing and verification limits. Exhaustion reports an
error; it does not establish that a slot is empty.

## Owner recovery command

Prepare a private UTF-8 JSON request from the owner's retained originals:

| Field | Value |
| --- | --- |
| `schema_version` | `memory-vault-open-ack-recovery-request/v1` |
| `target` | Independently known source `{signing_key,encryption_key}` public descriptors |
| `ack_slot` | The exact retained AckSlot |
| `node` | Current signed source node descriptor as an original entry |
| `root`, `read`, `bootstrap` | The owner's exact retained original entries |
| `known_statuses` | Array of previously observed signed status original entries; empty only if none are known |
| `archive_statuses` | Optional on the first run; on later runs, copy the complete array from the previous evidence file to retain older conflict witnesses |

Each original entry is exactly `{raw_base64url,ref}`. `raw_base64url` is unpadded
Base64url of the original bytes. `ref` is the complete retained
`{namespace,key,raw_sha256,size}`; preserve opaque keys even when they differ
from the content digest. Never reserialize a historical original to build the
entry. Keep the request file private with mode `0600` on POSIX.

```sh
python -B memory_vault_open_repair_admin.py recover-ack \
  --network-config /absolute/private/open-agent/open-config.json \
  --request /absolute/private/ack-recovery-request.json \
  --output /absolute/private/new-ack-evidence.json
```

The command loads the existing open client configuration, checks its own
authority and the signed source endpoint, performs the actual possession
exchange, and fetches each unique original with bounded signed range requests.
It reassembles and verifies the whole source event before creating the new
private evidence file. Existing output files are rejected before networking.
The output contains exact originals and their references, the signed response
handle, its manifest, current signed statuses and finite work counts. It
contains no private keys. The printed summary reports
`ack_unbound_source_recovered` and `recipient_saved:false`.

The programmatic entry is `AckOwnerRecoveryClient.recover` in Python's
`memory_vault_open_repair_client` or TypeScript's `open-repair-client.ts`.
The TypeScript client uses its native crypto and pinned HTTP transport without
delegating to Python; the source service is hosted by the Python node.
Supply independently
held original arguments, `known_statuses`, and a timeout no greater than 60
seconds. The command keeps supplied, historical and current status originals in
`archive_statuses`. It also provides a smaller `known_statuses` array: an older
original leaves this array only when a retained original from the same issuer
and root covers all its scopes, revision floors and revoked operation bits.
An active status cannot erase a remembered revocation. For the next request,
retain and supply **both arrays**; the full archive preserves conflicts at older
revisions even when the current floor has advanced. Both clients authenticate
their union with one verification budget before accepting a recovery.

The finite input limits are 16 known entries and 32 archive entries, with at
most 32 distinct originals in their union. Output exceeding either retained
limit reports `repair_status_history_capacity` without writing an output. Keep
previous evidence files; expiration alone does not permit deleting conflict
witnesses. This development client does not maintain
a separate persistent recipient-side status database automatically. Source-side
floors are durable in the existing protected transport database.
