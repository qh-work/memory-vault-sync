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

For a newly authorized source also intended for one explicit directory
publication, the source checkout provides `--repair-profile receipt-index`:
4,096 cumulative signature checks, 4 MiB of proof, 128 requests and 256 replay
records. Each source operation still has a 64-check limit. The original
allocation and signed grants must fund that work from the start; selecting this
profile later never enlarges an older grant or resets used work. The recovery
commands and `publish_saved_ack(..., repair_profile="receipt-index")` accept the
same explicit client ceiling. Directory publication still needs its own A/B
consents and an actual directory allocation.

Forward the printed HTTPS paths, including `/open/v1/repair/bootstrap`, to the
local listener. Existing node configuration stays unchanged. The service is
closed unless `repair_policy.enabled` is exactly `true`; it also requires that
node's existing encryption identity. Enabling the route creates no authority
and offers no public allocation, activation, or arbitrary object-read RPC.

The [source provisioning commands](OPEN_ACK_PROVISIONING.md) use an operator's
existing local sender and source configurations to prepare a new message before
upload, then return the private A/B request bundles. Integrations can instead
use `RepairAckState.allocate`,
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

## Development: reading an unbound replacement replica

The source checkout can serve an already committed unbound ACK replica through
the same protected HTTP route. The replacement operator initializes
`ReplicaReadService(state)` and calls `configure(resource_id, context=...,
consents=..., current_statuses=...)` locally in the node's existing protected
transport database. The context contains independently held `expected_ack_slot`,
`expected_owner`, `expected_source`, `source_storage_epoch`, and
`expected_maintainer`. Configuration contains public signed originals only.

The owner, original source and maintainer must each sign a separate
`ack.replica_return_consent` for the exact replacement keys/epoch, assignment,
original source custody and bootstrap grant. Each consent permits only that
issuer's exact originals and named status scopes. Existing COPY or directory
permission does not supply this return permission. These consents can be
prepared before the copy commitment without contacting their issuers again
within the original finite authorization windows.

The response explicitly identifies `replica_unbound`; it cannot be accepted as
an original source or a bound/occupied replica. Both signing and encryption key
possession are checked before proof publication. Full original bytes, replica
custody, return consents and current statuses are available through authenticated
range reads. Challenges, responses, replay records, status floors and actual
work charges survive restart in the same database and capacity reservation.
Remembered revocation prevents an old handle from continuing to read.

The Python `AckOwnerRecoveryClient.recover_replica` method consumes this explicit
profile. Along with the same `base_url`, `target_node_entry`, `expected_target`,
`expected_ack_slot`, `root_entry`, `read_entry` and `bootstrap_entry` as ordinary
recovery, supply independently held `expected_source`, `source_storage_epoch`
and `expected_maintainer`. The target is the replacement; the source is the
original custody issuer. The method authenticates the endpoint, completes both
key-possession checks, fetches exact originals, reconstructs the original and
replica storage events and verifies all three return consents and current READ.
Its `replica` result preserves both events; an unbound result is not a saved
recipient receipt.

Supply previous `known_statuses` and `archive_statuses` on subsequent calls.
The returned `archive_statuses` includes authenticated historical, copy-time,
retained and current observations, bounded to 32 distinct originals. Convert each
entry to `{raw: item.raw, ref: item.ref.as_dict()}` for the next call and persist
those exact bytes in the caller's existing protected state. Expiration does not
remove a remembered revocation or revision floor. The optional `status_observer`
is called with authenticated current observations before a later denial, so
integrations can retain them even when recovery fails. The client creates no
separate local database and never imports these originals into the Vault.

This operator API, HTTP service and Python client are development functionality.
The post-alpha.0.16 recovery command is described below. Native TypeScript
replica recovery, first-receipt admission on a replacement, occupied replica
recovery and automatic replacement selection remain unfinished. Explicit Python
remote reservation and copy upload are available in the alpha.0.16 candidate;
published alpha.0.14 archives do not include these features.

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

## Maintainer copy commands (development after alpha.0.16)

`copy-reserve` and `copy-upload` use the maintainer's existing open-client identity
and protected transport journal. They never open the content Vault. Both accept
`--network-config`, `--request`, `--output`, `--timeout` (at most 60 seconds), and
an explicit `--repair-profile receipt-index` when the original grants fund that
ceiling. Requests and new-only results are private JSON files. A failed or lost
reply can be retried with the same request and journal inside the original
permission window; restarting does not renew a grant.

```sh
python -B memory_vault_open_repair_admin.py copy-reserve \
  --network-config /absolute/private/maintainer/open-config.json \
  --request /absolute/private/copy-reservation.json \
  --output /absolute/private/new-reservation-result.json --repair-profile receipt-index
python -B memory_vault_open_repair_admin.py copy-upload \
  --network-config /absolute/private/maintainer/open-config.json \
  --request /absolute/private/copy-upload.json \
  --output /absolute/private/new-copy-result.json --repair-profile receipt-index
```

Both requests use `schema_version: memory-vault-open-ack-copy-request/v1`.
They have these exact fields:

| Field | Value |
| --- | --- |
| `operation` | `reserve` or `upload`, matching the command |
| `node` | Independently held signed replacement-node original |
| `ack_slot`, `owner`, `source`, `source_storage_epoch` | Independently held original source expectations; owner/source contain both public key descriptors |
| `manifest`, `custody` | Original unbound source manifest and source custody entries |
| `reservation` | Owner's exact signed reservation disclosure consent |
| `intent` | Complete explicit copy intent, including the selected destination's keys and storage epoch |
| `originals` | Up to 64 exact packed source originals, as `{raw_base64url,ref}` |
| `current_statuses` | Up to 16 signed current authority-status original entries |

Every original entry uses `{raw_base64url,ref}` with the full opaque reference.
`copy-reserve` authenticates the destination, reserves actual capacity, verifies
the signed offer, and creates the maintainer's durable original assignment. Its
`capacity_reserved_and_assigned` result contains `allocation`, `offer`, and
`assignment`; it has not uploaded or committed a replica.

An upload request additionally contains those three exact entries plus separately
signed `owner_disclosure` and `source_disclosure` entries for that assignment.
The command rechecks their originals and current authority, verifies destination
possession before disclosure, uploads the packed originals, commits, and verifies
the returned manifest/custody chain. `replica_committed` exports both full entries.
Neither result is a saved-message receipt or READ permission. The owner, source
and maintainer must still supply separate return consents to configure recovery.
Automatic destination selection and occupied/empty replica copies remain open.

## Unbound replica command (development after alpha.0.16)

A new replacement node can explicitly accept finite remote copy reservations:

```sh
python -B memory_vault_open_setup.py --directory /absolute/private/new-replacement \
  --base-url "$MV_NODE_ORIGIN" --enable-repair --repair-profile receipt-index \
  --enable-remote-copy
```

Setup writes a new private configuration; start the node separately as above.
`--enable-remote-copy` requires `--enable-repair` and is off by default. Its
per-caller limits persist across restarts; capacity reservation still requires
separate signed COPY/disclosure and READ/return permissions.

`recover-replica` uses the existing owner's network configuration to recover an
explicitly authorized replacement copy. This command is later than the immutable
alpha.0.16 candidate. Its private request uses
`memory-vault-open-ack-replica-unbound-recovery-request/v1` and the unbound fields
above, with `target`/`node` naming replacement P. Add `source` (original R's
independently held signing/encryption descriptors), `source_storage_epoch`, and
`maintainer` (M's independently held descriptors). Root/read/bootstrap remain
A's original grants. The response cannot supply these trusted expectations.
A/R/M/P must be distinct as required by the replica READ profile.

```sh
python -B memory_vault_open_repair_admin.py recover-replica \
  --network-config /absolute/private/open-agent/open-config.json \
  --request /absolute/private/replica-recovery-request.json \
  --output /absolute/private/new-replica-evidence.json \
  --repair-profile receipt-index
```

The explicit profile is a client acceptance ceiling; it does not enlarge the
source's signed grants. The command performs the real possession exchange,
fetches originals, checks the complete original and replacement custody chains,
and verifies current return authority. Its private new-only output includes
`replica_custody`, both source/replacement bindings, full original references and
status archives. `ack_replica_unbound_source_recovered` has
`recipient_saved:false`: an unbound replacement is not a received message.
Existing files are never overwritten, and the content Vault is not opened.

For this command, authenticated status observations also persist in the existing
protected transport database, including observations from rejected recoveries.
The journal is keyed by the owner's root, not the output filename or replacement
URL. Subsequent commands reuse relevant A/R/M/P observations and verify them
again. It preserves opaque full status references and caps history at 16 roots,
32 originals and 256 KiB per root. Capacity exhaustion refuses further recovery;
it does not discard remembered revocations. Continue retaining exported evidence
and supply any additional independently held status originals in the request.

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
