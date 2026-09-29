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

## Reading an unbound replacement replica

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
The alpha.0.19 candidate recovery command is described below. Native TypeScript
replica recovery, first-receipt admission on a replacement, occupied replica
recovery and automatic replacement selection remain unfinished. Explicit Python
remote reservation and copy upload are available in the alpha.0.16 candidate;
published alpha.0.14 archives do not include these features.

## Development after alpha.0.18: reuse packed replica originals

The Python replica recovery client fetches the proof's exact history manifest and
packs first. It reuses their validated full original references for matching
proof children, avoiding a second network download of the same bytes. Every
advertised original still counts toward the logical proof-byte ceiling, and the
complete source/copy/custody chain, independent return consents, current statuses
and deadline checks remain required. Opaque reference keys are preserved; a
matching digest alone is insufficient. This optimization is later than the
immutable alpha.0.18 candidate.

## Bound-empty replica copying and recovery (source after alpha.0.23)

A bound-empty ACK slot already identifies the recipient, message and envelope,
but has no saved-message receipt. The Python maintainer can copy both original
history generations to an explicitly selected replacement. The owner can then
recover the exact binding from that replacement while the original node is
unavailable. The original keys, opaque references and signed bytes are preserved.

The four commands use the same existing private configurations, original
permissions and new-only result files as their unbound counterparts:

| Command | Private request schema | Additional bindings |
| --- | --- | --- |
| `copy-reserve-empty` | `memory-vault-open-ack-copy-empty-request/v1` | `receipt_writer`, `message_id`, `envelope_ref` |
| `copy-upload-empty` | `memory-vault-open-ack-copy-empty-request/v1` | The same three bindings |
| `configure-replica-empty` | `memory-vault-open-ack-replica-empty-read-config/v1` | Add `expected_receipt_writer`, `expected_message_id`, `expected_envelope_ref` inside `context` |
| `recover-replica-empty` | `memory-vault-open-ack-replica-empty-recovery-request/v1` | `receipt_writer`, `message_id`, `envelope_ref`, plus the existing replica source and maintainer fields |

For both copy requests, `manifest` and `custody` are the original **empty** source
entries. The explicit intent uses `scope.kind: ack_empty` and the exact original
`ack_slot`, `grant_ref` and `binding_ref`. Include the original packs for both the
unbound and empty history. Reservation disclosure binds that exact intent; upload
still requires separate owner/source disclosures for the resulting assignment.
The allocation, offer, assignment and transfer requests survive lost replies and
restart in the maintainer's existing transport journal. Retry the same request
inside its original window with a new output path.

Read configuration still needs the independent owner, original-source and
maintainer return consents. The replacement's COPY assignment remains
COPY/READ/RETAIN only. Its committed empty copy does not authorize receiving a
first receipt, and does not turn the replacement into the original node.
Revoked write/bootstrap grants and remembered revision floors continue to apply.

```sh
python -B memory_vault_open_repair_admin.py recover-replica-empty \
  --network-config /absolute/private/owner/open-config.json \
  --request /absolute/private/empty-replica-recovery.json \
  --output /absolute/private/new-empty-replica-evidence.json \
  --repair-profile receipt-index --timeout 60
```

The response has an explicit `replica_empty` proof profile. The owner independently
checks both source generations, the replacement custody, exact message/recipient
binding, all return consents and current READ authority. An exact metadata pack
reduces network round trips; each advertised original still counts toward the
proof-byte ceiling. Unexpected pack members or a different proof phase are
rejected. Upload, configuration and reads share the existing finite resource
work limits, so the initial signed grants must fund the complete operation.
Selecting a larger client profile never renews or enlarges an existing grant.

`ack_replica_empty_source_recovered` retains `recipient_saved:false`. It exports
originals and retained statuses into a private evidence file and does not import
anything into the Vault. For an existing saved receipt, use the occupied-copy commands below.
Replacement selection remains explicit, and native Node replica recovery is unfinished.

## Copy and recover an existing saved receipt

An occupied ACK source contains the recipient's actual signed saved-message
receipt. Python maintainers can copy that exact receipt and all three original
history generations to an explicitly selected replacement. After the original
source stops, the owner can recover the original receipt from that replacement.
The original sender, recipient, message and envelope bindings remain unchanged.

The original root must already permit COPY and name the chosen maintainer.
For a new Agent-prepared message, explicitly choose the optional
[`copy_maintainer`](OPEN_ACK_PROVISIONING.md#optional-replica-maintenance-for-a-new-message)
with the finite `receipt-index` profile. Existing roots that did not grant COPY
cannot acquire it through recovery or a new client setting.

Use the same private configurations and result-file rules as the empty-replica
commands, with these explicit occupied schemas:

| Command | Private request schema | Required additions |
| --- | --- | --- |
| `copy-reserve-occupied` | `memory-vault-open-ack-copy-occupied-request/v1` | `receipt_writer`, `message_id`, `envelope_ref`, `recipient_reservation` |
| `copy-upload-occupied` | The same occupied copy schema | The same fields, plus `recipient_disclosure` |
| `configure-replica-occupied` | `memory-vault-open-ack-replica-occupied-read-config/v1` | All three expected bindings inside `context`; `consents.recipient` as well as owner, source and maintainer consents |
| `recover-replica-occupied` | `memory-vault-open-ack-replica-occupied-recovery-request/v1` | All three bindings and the original source and maintainer fields |

The source `manifest` is the original `ack_occupied_inputs` history and `custody`
is its original `ack.commit`. The explicit intent uses `scope.kind: ack_occupied`
with the original `ack_slot`, `grant_ref`, `binding_ref`, `receipt_ref` and
`original_ack_commit_ref`. Include the exact packs for the unbound, empty and
occupied generations. Each encoded original uses `raw_base64url` and its complete
`ref`, preserving opaque reference keys.

Before reservation, the recipient independently signs
`ack.copy_recipient_reservation_consent`. It has the same closed fields as the
owner's `ack.copy_reservation_consent`: the exact root, source commit, history,
maintainer, replacement and storage epoch, with the exact intent digest and a
finite disclosure deadline. Its current recipient status must authorize COPY.
The owner cannot supply this permission on the recipient's behalf. Allocation
discloses receipt associations even before the receipt bytes are transferred.

Upload additionally needs the recipient's `ack.copy_disclosure` with
`variant: recipient`, alongside the existing owner and source disclosures. Each
issuer approves its exact original bytes and whole status scopes for the same
assignment. The original recipient receipt disclosure must still permit READ.
The destination reconstructs and verifies the complete original receipt event
before committing custody. Packed originals are transferred once; exact replay
requests, used work and denied authorization observations survive restart.

Read configuration requires independent `ack.replica_return_consent` documents
with variants `owner`, `source`, `maintainer` and `recipient`, plus current statuses
for those four parties and the replacement resource. The read service requires
five distinct signing identities. COPY permission alone never supplies return
permission. Revoking old receipt-writing ADMIT does not revoke READ of an already
saved receipt; revoking the original recipient disclosure or current return
permission does. Remembered revocations cannot be erased by restarting or
replaying older status documents.

```sh
python -B memory_vault_open_repair_admin.py recover-replica-occupied \
  --network-config /absolute/private/owner/open-config.json \
  --request /absolute/private/occupied-replica-recovery.json \
  --output /absolute/private/new-occupied-replica-evidence.json \
  --repair-profile receipt-index --timeout 60
```

The explicit `replica_occupied` response cannot be downgraded to an original
source, unbound replica or empty replica. Every advertised original counts toward
the logical proof-byte ceiling even when its exact bytes come from a pack.
Upload, read configuration and recovery share the originally signed finite
resource budget. Reserve enough metadata for all three histories, independent
consents, current statuses and durable transfer/read records before signing the
original grants; a client profile cannot enlarge them afterward. The per-operation
64-signature and per-replica 64-work limits remain in force.

`ack_replica_occupied_source_recovered` includes `recipient_saved: true` only
after verifying the original receipt. The private evidence file includes that
`recipient_receipt`, original source commit and independent replacement custody.
It does not modify the content Vault. Reservation, upload and configuration
results continue to report `recipient_saved: false`; copying is not a new save.
Replacement selection remains explicit. Native Node understands the proof
grammar but does not yet provide occupied-replica copy or recovery commands.

### Confirm the original send through the Agent

Python agents can update the original send directly using `connect` with
`schema_version: memory-vault-open-ack-connect/v1` and
`action: recover_replica_receipt`. Supply the replacement's `base_url`, the
originally funded `repair_profile`, and a `request` with:

- `target_node_entry`, `expected_target`, `expected_ack_slot`, `root_entry`,
  `read_entry`, and `bootstrap_entry`;
- `expected_receipt_writer`, `expected_message_id`, and `expected_envelope_ref`;
- `expected_source`, `source_storage_epoch`, and `expected_maintainer`.

Original entries use `{raw: <original UTF-8 JSON text>, ref: <complete reference>}`
as in the existing Agent ACK invitations. An optional `known_statuses` array uses
the same encoding. Each selected source and replacement is identified by its
independently supplied signing and encryption keys.

An owner can reuse its exported `owner_invitation` without signing a new READ
grant. The replacement operator must already have installed the four valid
return consents. With the independently selected replacement and maintainer keys:

```python
import copy
import json

invitation = copy.deepcopy(owner_invitation)
invitation["action"] = "recover_replica_receipt"
request = invitation["request"]
request["expected_source"] = request["expected_target"]
request["source_storage_epoch"] = json.loads(
    request["target_node_entry"]["raw"]
)["payload"]["storage_epoch"]
request["expected_target"] = replacement_keys
request["expected_maintainer"] = maintainer_keys
request["target_node_entry"] = replacement_node_entry
invitation["base_url"] = json.loads(
    replacement_node_entry["raw"]
)["payload"]["base_url"]
result = agent.handle({"op": "connect", "invitation": invitation})
```

Keep the original repair profile and grants. Selecting a replica does not extend
their deadlines or remaining resources. A discovered descriptor by itself does
not authorize trusting either the replacement or the maintainer.

The Agent verifies the complete replica and current return permissions, retains
signed status observations in its existing transport database, then independently
matches the recipient receipt to its actual outbox message and envelope. It
returns `validated_saved`, the original `commit_ref` and the independent
`replica_custody_ref`. Repeating the original `send` after restart reports
`endpoint_validated: true` even when the original delivery and ACK nodes are
offline. Unknown local messages and conflicting receipts refuse this update.
The action does not create a new send, renew permission or import a memory.


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
witnesses. Development after alpha.0.18 also persists authenticated owner/source
status originals for `recover-ack`, `recover-empty`, and `recover-occupied` in
the existing protected transport database. These commands share one original-source
journal per root; the replica journal remains separate because its typed disclosure
scopes differ. A failed command retains authenticated revocations before refusing
access, and a subsequent command loads them even when its request omits the prior
arrays. Existing whole-document scope checks remain in force; retained originals
with incompatible scopes cause refusal rather than being silently projected or
discarded. The shared journal capacity is 16 root/domain records, 32 originals and
256 KiB per record; exhaustion refuses further recovery. Programmatic Python and
TypeScript callers must still retain and supply both arrays themselves. Source-side
floors are also durable in the existing protected transport database.

## Native recovery commands (development after alpha.0.19)

The source checkout now includes a native Node command for original-source
`recover-ack`, `recover-empty`, and `recover-occupied`. From
`clients/typescript/network`, install the locked dependencies with
`npm ci --ignore-scripts`, then use Node 22.19 or later:

```sh
node --experimental-strip-types open-repair-admin.ts recover-occupied \
  --network-config /absolute/private/open-agent/open-config.json \
  --request /absolute/private/occupied-request.json \
  --output /absolute/private/new-occupied-evidence.json \
  --repair-profile receipt --timeout 60
```

Use the same private request schemas and exact originals as the Python command
for the selected phase. The native command uses the existing identity and
protected transport database. It performs native signature verification and
HTTP requests, and does not launch Python or open the content Vault. It exports
an actual recipient receipt only for an authenticated occupied source; empty
and unbound results report `recipient_saved:false`.

Both command implementations share the original-source status journal and its
capacity limits described above. Authenticated revocations survive a failed
command, process restart, and switching between Python and Node. Unauthenticated
status documents cannot enter that journal. Output must name a new file;
existing files are preserved. The optional profiles and 60-second timeout
ceiling match Python and cannot enlarge signed grants. Programmatic callers
can supply a synchronous `statusObserver` to persist authenticated observations
before access refusal; it supplies observations, never authorization.

These native commands are included in the alpha.0.20 candidate source, but not
in the frozen alpha.0.19 archives.
Replica recovery and maintainer copy commands remain Python-only.

## Maintainer copy commands (alpha.0.20 candidate)

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
Bound-empty copy commands are described below. Automatic destination selection
and occupied replica copies remain open.

### Enable separately authorized replica reads

On the existing replacement node, install the independently signed return
permissions using its private node configuration:

```sh
python -B memory_vault_open_repair_admin.py configure-replica \
  --node-config /absolute/private/replacement/node-config.json \
  --request /absolute/private/replica-read-config.json \
  --output /absolute/private/new-config-result.json
```

The private request has exactly `schema_version` (value
`memory-vault-open-ack-replica-read-config/v1`), `resource_id`, `context`,
`consents`, and `current_statuses`. The context contains independently held
`expected_ack_slot`, `expected_owner`, `expected_source`, `source_storage_epoch`
and `expected_maintainer`. `consents` contains `owner`, `source`, and `maintainer`
return-consent original entries; `current_statuses` contains up to 16 signed
status originals. Entries use `{raw_base64url,ref}`. The resource must already
contain the committed replica and match every binding in the original grants.

This local command starts no listener and preserves the node's keys and config.
It verifies current READ authority before persisting the service configuration;
a later invocation can install newly signed statuses without discarding remembered
revocations. An existing output is refused before any state change. `configured`
is local service readiness, not proof of an owner's successful recovery.

## Unbound replica command (alpha.0.19 candidate)

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
  --repair-profile receipt-index --timeout 60
```

The explicit profile is a client acceptance ceiling; it does not enlarge the
source's signed grants. The command performs the real possession exchange,
fetches originals, checks the complete original and replacement custody chains,
and verifies current return authority. Its private new-only output includes
`replica_custody`, both source/replacement bindings, full original references and
status archives. `ack_replica_unbound_source_recovered` has
`recipient_saved:false`: an unbound replacement is not a received message.
Existing files are never overwritten, and the content Vault is not opened.

For this command, authenticated status observations persist in the existing
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

## Mailbox directory replica commands (development after alpha.0.25)

The Python client can upload an explicitly selected mailbox directory replica,
install its independent return consents, and recover the original directory
after the source goes offline. These commands use existing identities and
protected transport storage. They do not open the content Vault. A directory
contains catalog and slot references; it does not contain a copied message feed
or authorize reading message ciphertexts.

The destination must already have the exact mailbox copy reservation. Remote
mailbox reservations require the separate `--enable-remote-mailbox-copy` node
option alongside enabled repair/provider services. An ACK copy reservation or
directory lease cannot substitute for that reservation. The upload bundle must
contain the real destination offer, maintainer assignment, and independently
signed owner/source disclosures; this command does not create those permissions.

```sh
python -B memory_vault_open_repair_admin.py copy-upload-root \
  --network-config /absolute/private/maintainer/open.json \
  --request /absolute/private/root-copy.json \
  --output /absolute/private/root-copy-result.json --repair-profile receipt-index

python -B memory_vault_open_repair_admin.py configure-replica-root \
  --node-config /absolute/private/replica/node.json \
  --request /absolute/private/root-return.json \
  --output /absolute/private/root-return-result.json

python -B memory_vault_open_repair_admin.py recover-replica-root \
  --network-config /absolute/private/recipient/open.json \
  --request /absolute/private/root-recovery.json \
  --output /absolute/private/root-originals.json --repair-profile receipt-index
```

Each original entry is `{ "raw_base64url": "...", "ref": RawRef }`. Requests are
private JSON files. Outputs are new private files, never overwritten. The
explicit client profile is an acceptance ceiling and cannot enlarge signed
source limits, resource budgets, or permission windows.

| Command | Request schema and required fields |
| --- | --- |
| `copy-upload-root` | `memory-vault-open-mailbox-root-copy-request/v1`: `node`, `root_key`, `owner`, `source`, `source_storage_epoch`, `target`, `target_storage_epoch`, `manifest`, `custody`, `allocation`, `offer`, `assignment`, `reservation`, `owner_disclosure`, `source_disclosure`, `originals` (source history packs), `current_statuses` |
| `configure-replica-root` | `memory-vault-open-mailbox-root-replica-read-config/v1`: `resource_id`, `context`, `consents` (`owner`, `source`, `maintainer`), `current_statuses`. Context contains `expected_root`, `expected_owner`, `expected_source`, `source_storage_epoch`, `expected_maintainer`; each consent is an independently signed `mailbox.replica_return_consent` original. |
| `recover-replica-root` | `memory-vault-open-mailbox-root-replica-recovery-request/v1`: `node`, `root_key`, `target`, `source`, `source_storage_epoch`, `maintainer`, original owner `root`, `read`, `bootstrap`, `known_statuses`, `archive_statuses` |

Upload verifies the destination's signing and encryption key possession before
disclosing originals. Its durable journal replays exact requests after a lost
reply and restart, within the original finite window. The destination commits
the whole authenticated directory graph and actual reserved storage before
issuing custody. Recovery independently verifies that graph, original owner
authority, current READ permissions and all three return consents. Revocations
and status revision floors remain in the recipient's transport database across
failed recovery and restart. `mailbox_root_replica_recovered` means the exact
directory originals were recovered; it is not a saved-message receipt.

## Message index replica commands (development after alpha.0.25)

`copy-upload-feed`, `configure-replica-feed`, and `recover-replica-feed` provide
the same explicit destination workflow for one complete nonempty feed prefix.
Recovery verifies the original admission history and decrypts its sealed index
for the existing recipient. It works after the original node goes offline and
the replica restarts. The original message ciphertexts have separate resources
and permissions; these commands do not copy or recover their bodies.

Use `--repair-profile mailbox` for these client commands and for new nodes that
accept complete feed proofs. This explicit ceiling allows 128 proof items,
4 MiB of proof bytes, 4,096 signature checks and 128 requests. Existing signed
grants still impose their own smaller limits. In particular, a previously
signed 64-item bootstrap grant cannot serve a larger closure merely because
the client or node selects this profile. Fund the complete original bootstrap
and resource budgets when establishing the mailbox.

The exact private bundle schemas are:

| Command | Request fields |
| --- | --- |
| `copy-upload-feed` | `memory-vault-open-mailbox-feed-copy-request/v1`; the root-copy fields above plus `slot_key`, `sender`, `sender_reservation`, `sender_disclosure`. The manifest/custody are the original feed's, and `originals` contains its complete feed and member history packs. |
| `configure-replica-feed` | `memory-vault-open-mailbox-feed-replica-read-config/v1`; `resource_id`, `context`, `consents`, `current_statuses`. Context uses `expected_slot` and `expected_sender` instead of `expected_root`, alongside owner/source/epoch/maintainer fields. Consents contain independently signed `owner`, `source`, `maintainer`, and `sender` entries. |
| `recover-replica-feed` | `memory-vault-open-mailbox-feed-replica-recovery-request/v1`; `node`, `root_key`, `slot_key`, `sender`, `target`, `source`, `source_storage_epoch`, `maintainer`, `slot_entries` (original `slot`, `read`, `maintenance`, `bootstrap` entries), `known_statuses`, `archive_statuses`. |

B's selected-slot maintenance root delegates the exact existing feed scope to
P with COPY/READ/RETAIN only. Independent B and A
`mailbox.feed_copy_reservation_consent` originals bind the exact reservation
intent before disclosure. B, original source S and A each sign
`mailbox.feed_copy_disclosure` over their complete exact original/ref inventory
and permitted status scopes after the real offer and assignment exist. Every
original message consent in the prefix must still permit COPY. Directory
authority cannot replace any of these selected-slot or sender permissions.

The upload profile is `mailbox_copy_feed`; completion returns the compact
`mailbox.feed_copy_committed` carrier with `manifest_ref` and the signed custody
original. The sender reconstructs the entire canonical manifest from its
verified upload originals, including every dependency edge, and independently
verifies the custody signature and exact manifest hash. This keeps completion
within the unchanged control-message limit. A lost completion response replays
the exact committed event after both sides restart.

Reading is separate: the four `mailbox.feed_replica_return_consent` originals
permit returning this exact graph to B. Current selected-slot and A READ
authority, M's assignment, P's actual retained resource and its status must all
remain valid. The explicit `replica_feed` proof profile preserves the original
source identity and epoch even though the serving node is P. Authenticated
revocations survive denial and restart. The private output contains the exact
originals and decrypted member references; it neither imports memories nor
claims a saved-message receipt. Automatic target selection and partial-range
replication remain separate work.

## Receive messages and shared memories from a replica (development after alpha.0.25)

The Python commands can copy one exact encrypted message and receive it after
the original node stops. The complete original feed prefix and admission graph
travel with that message; the recipient keeps its existing keys and trust rules.
The destination retains ciphertext in separately reserved live storage and
charges its proof metadata and upload journal separately. A feed reservation
cannot pay for or authorize a message copy.

```sh
python -B memory_vault_open_repair_admin.py copy-upload-message \
  --network-config /absolute/private/maintainer/open.json \
  --request /absolute/private/message-copy.json \
  --output /absolute/private/message-copy-result.json --repair-profile mailbox --timeout 60

python -B memory_vault_open_repair_admin.py configure-replica-message \
  --node-config /absolute/private/replica/node.json \
  --request /absolute/private/message-return.json \
  --output /absolute/private/message-return-result.json

python -B memory_vault_open_repair_admin.py receive-replica-message \
  --network-config /absolute/private/recipient/open.json \
  --request /absolute/private/message-recovery.json \
  --output /absolute/private/message-received.json --repair-profile mailbox --timeout 60
```

| Command | Private request |
| --- | --- |
| `copy-upload-message` | `memory-vault-open-mailbox-message-copy-request/v1`; the feed-copy fields plus `envelope`, an exact `{raw_base64url,ref}` entry. The separate allocation, offer, assignment, reservations and disclosures must all bind this message and its original `message.custody`. |
| `configure-replica-message` | `memory-vault-open-mailbox-message-replica-read-config/v1`; the feed-return fields, with `context.expected_envelope_ref` and four independent message return consents. |
| `receive-replica-message` | `memory-vault-open-mailbox-message-replica-recovery-request/v1`; the feed-recovery fields plus `envelope_ref`, matching the selected original message. |

B and A sign `mailbox.message_copy_reservation_consent`; B, S and A sign
`mailbox.message_copy_disclosure`. These bind the selected message, complete
original graph, original message custody, independent resource and current
status scopes. COPY, READ and RETAIN remain distinct. The four B/S/M/A
`mailbox.message_replica_return_consent` originals independently authorize
return to B. The proof profile is `replica_message`; it carries metadata, while
protected body requests retrieve the exact ciphertext under the same finite
bootstrap handle and current permissions.

Successful reception verifies original signatures and custody, decrypts the
message, and uses the normal durable inbox. A shared-memory payload is imported
only under the recipient's existing import policy. Staged reception resumes
after restart without another network read; repeated processing does not import
the same memory twice. The result reports `mailbox_message_replica_received`,
the actual saved result, and a recipient-signed receipt. That receipt is retained
for the existing independent return workflow; this command does not claim it
has reached the sender. A failed permission check retains authenticated status
observations and cannot import a memory.

Upload retries replay the same persisted requests and completion after either
side restarts. The receipt is issued only after exact ciphertext and all
required originals commit atomically. Existing original grants still bound the
entire recovery; neither selecting the mailbox profile nor restarting renews
them. Automatic destination selection, consent exchange and replacement remain
separate work. Native TypeScript supports the proof/status wire profiles, but
these mailbox copy and receive commands currently require Python.

The existing Python Agent also accepts this recovery through `connect`:

```python
agent.handle({"op": "connect", "invitation": {
    "schema_version": "memory-vault-open-mailbox-connect/v1",
    "action": "receive_replica", "base_url": selected_replica_url,
    "repair_profile": "mailbox", "request": recovery_request,
}})
```

`recovery_request` contains `expected_slot`, `expected_sender`, `expected_target`
(the replica), `expected_source`, `source_storage_epoch`, `expected_maintainer`,
`expected_envelope_ref`, `target_node_entry`, `slot_entries`, `known_statuses`
and `archive_statuses`. Entries here use `{raw,ref}`, where `raw` is the exact
original UTF-8 string; `slot_entries` contains `slot`, `read`, `maintenance` and
`bootstrap`. These are the same retained grants and selections as the command,
without a private output file. The Agent returns the ordinary inbox result and
retains authenticated status observations in its existing protected database.
Repeated recovery preserves the saved receipt and does not import memory twice.
