# Bounded ACK source recovery

The fixed `/open/v1/repair/bootstrap` service supports explicit unbound,
message-bound empty, and occupied ACK recovery. It verifies both parties'
Ed25519/X25519 possession, the source event, every referenced original and
current permission. The occupied phase returns B's original signed saved-message
receipt only with B's explicit disclosure permission and A's separate READ.
Use the same signing/encryption identities and protected transport state as the
ordinary open client. The recovery command never imports into the Vault.

Remote binding and receipt upload are Python client APIs. Source history
verification and owner recovery are available to Python and native TypeScript.
These operations require an already allocated, authorized source. They do not
move the message itself to another node or automatically publish ACK heads.

## Source operator

For a new node, explicitly enable the finite service:

```sh
python -B memory_vault_open_setup.py --directory /absolute/private/new-node --base-url "$MV_NODE_ORIGIN" --enable-repair
python -B memory_vault_open_node.py --config /absolute/private/new-node/node-config.json
```

For a new source intended to complete remote binding, receipt upload and owner
recovery, add `--repair-profile receipt` to setup. This explicit finite profile
allows up to 2,048 cumulative signature checks and 1 MiB of proof per resource.
It retains the 64-check limit for each source operation. The actual allocation,
owner root/read and bootstrap grants must reserve matching capacity before they
are signed. Existing configurations and signed grants stay unchanged.

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

## Message-bound empty recovery

The source supports an empty ACK slot bound to one receipt writer, message and
envelope. `OwnerAckBindClient.bind` preflights the existing unbound source and
remotely commits the original write grant, offer bootstrap grant and current
statuses. The local operator entry is `RepairAckEmptyState.bind`.
Recovery does not create this binding or prove
that a receipt does not exist elsewhere.

Use `recover-empty` with the same arguments as `recover-ack`. Its request uses
schema `memory-vault-open-ack-empty-recovery-request/v1` and adds three required
fields: `receipt_writer` (independently known signing/encryption public
descriptors), `message_id`, and the complete original `envelope_ref`. Obtain
these expected values from the sender's retained originals, never from the
source response being checked. The other fields and private-file rules are
unchanged.

The programmatic entries are Python `recover_empty` and native TypeScript
`recoverEmpty`. They independently verify both unbound and empty historical
generations, the original binding, exact envelope/message/writer tuple, current
owner READ authorization and signed source head. The wire service profile
remains `ack_owner_service_v1`; the caller's expected source phase selects the
closed child set. Writer ADMIT permission does not grant or replace owner READ.

The command reports `ack_empty_source_recovered` with `recipient_saved:false`.
Its new evidence file preserves status originals from both historical
generations plus all supplied and current statuses. Retain both output status
arrays for the next cold run. A slot's transition or a READ revocation during
recovery invalidates the current proof; it does not return a partial success.
Receipt admission and occupied recovery use the separate operations below.

## Original saved-message receipt recovery

`AckReceiptClient.put` first completes the recipient's independent `ack_offer`
preflight, uploads the existing delivery receipt with B's signed disclosure and
put request, and independently verifies the returned three-generation commit.
The receipt keeps its original bytes and full object reference. The client uses
one finite 96-signature workflow budget; each source operation keeps the
64-signature ceiling. A 64-signature client policy is refused before private
receipt upload when the remaining allowance cannot verify the response.

`AckOwnerRecoveryClient.recover_occupied` and the Python operator command
`recover-occupied` retrieve that exact receipt. The request has the same fields
as `recover-empty`, with schema
`memory-vault-open-ack-occupied-recovery-request/v1`. The output includes
`recipient_receipt`, its exact object reference, and the authenticated status
originals from all three generations. `recipient_saved: true` means B signed the
existing `validated_saved` delivery receipt; it does not assert understanding
or future availability. The command does not open or modify the local Vault.

Full return requires B to newly sign the exact four-role bootstrap disclosure:
`ack.disclosure`, `ack.put`, `authority.status.disclosure`, `recipient.receipt`.
An existing two-role consent keeps its narrower meaning and cannot authorize
this full return. Revoking B's later upload permission does not itself revoke
A's separately granted READ; withdrawing B's disclosure READ does.

Reserve sufficient finite capacity before signing the original source grants.
A source configured only for 512 cumulative signature checks can run out while
serving three generations. The occupied command accepts original grants up to
2,048 checks and 1 MiB of cumulative proof; it never enlarges an existing
signed grant, changes node policy, or clears usage. A joint bind/upload/recovery
workflow must budget every admitted attempt against the same persistent source
ledger. A committed local head publication job is still pending work, not proof
of publication to additional nodes.

## Publish a receipt from an actually saved inbox

After the ordinary `receive` operation durably saves a message or selected
memory transfer, the Python open client exposes an explicit opt-in:

```python
from pathlib import Path
from memory_vault_open_client import OpenNetworkClient

with OpenNetworkClient(Path("/absolute/private/open-config.json")) as network:
    published = network.publish_saved_ack(ack_source_url, retained_ack_request)
```

`retained_ack_request` is a closed local object containing `message_id`,
`envelope_ref`, `ack_slot`, `owner`, `target`, `target_node_entry`, `root_entry`,
`write_entry`, `bootstrap_entry`, `binding_entry`, `current_statuses`,
`read_until`, and `retain_until`. Each original entry is `{raw, ref}` with exact
bytes and its full original reference. Use the original binding returned by
`OwnerAckBindClient.bind`; do not construct a binding from a response label.

The method reads the existing protected inbox and its saved receipt. A supplied
`saved` flag or receipt body is not accepted. It verifies the sender, recipient,
message and envelope, newly signs B's bounded four-role return consent, then
runs the actual preflight/upload client. Calling `receive` alone never shares
this receipt through an additional ACK source. An unsaved or mismatched message
is refused before upload. The original delivery node need not be online after
B's actual save. No memory content is included in this receipt publication.

B's exact receipt, consent and put originals are journaled in the existing
protected transport database. `from_local_history: true` identifies a verified
previous result; it does not claim a fresh network read or renewed permission.

If the node accepted a receipt but the caller lost the response, repeat the same
explicit publication request. Before any upload, the client journals the exact
signed carrier and its authenticated preflight originals. A retry revalidates
that journal and the caller's retained status observations, then replays the
same carrier while its original use/handle remains valid. It does not probe for
an empty slot again, generate new consent, or clear the source's budget. After
that window expires it reports that reconciliation is required; A can use the
independent occupied recovery path instead of assuming the upload failed.
