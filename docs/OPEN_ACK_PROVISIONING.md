# Prepare a receipt source before sending

Select one message or memory transfer, create its ACK source, then encrypt and
bind the delivery before ordinary sending. After B saves it, B can explicitly publish
its original receipt to R. A can recover it from R even when the original delivery
node is offline.

Each participant keeps its own configuration and private keys. A needs only its
existing open-client configuration plus the selected R's public HTTPS origin and
signing key ID. R explicitly enables finite remote source setup; an existing
repair service alone does not allow it. B must already have approved A through
the [normal contact workflow](OPEN_NETWORK_QUICKSTART.md#b-enables-contact-a-requests-b-explicitly-decides).
R must run with the chosen repair profile enabled and an address reachable by A
and B. Use absolute paths to protected local files outside cloud-synced directories.
Replace all example paths, recipient key IDs and memory IDs with selected values.

For a new source, R's operator initializes and starts its own node:

```sh
python -B memory_vault_open_setup.py \
  --directory /absolute/private/new-source --base-url "$MV_SOURCE_ORIGIN" \
  --enable-repair --repair-profile receipt-index --enable-remote-setup
python -B memory_vault_open_node.py --config /absolute/private/new-source/node-config.json
```

The operator supplies the HTTPS forwarding described in the
[network quickstart](OPEN_NETWORK_QUICKSTART.md), including
`/open/v1/repair/bootstrap`, and gives A only the public origin and key ID.
Keep both private identity files, node configuration and storage at R.

## Agent interface preparation

An agent can call `connect` with this invitation before its first `send`:

```json
{
  "schema_version": "memory-vault-open-ack-connect/v1",
  "action": "prepare",
  "source_url": "https://source.example",
  "source_key_id": "ed25519_REPLACE_WITH_SOURCE_KEY_ID",
  "request_id": "req_ack_example_001",
  "recipient": "ed25519_REPLACE_WITH_RECIPIENT_KEY_ID",
  "text": "Selected memory for this conversation",
  "memory_ids": ["mem_REPLACE_WITH_SELECTED_MEMORY_ID"],
  "repair_profile": "receipt-index",
  "lifetime": 3600
}
```

The result contains the message and resource IDs. Preparation never uploads the
message. Repeat the identical invitation to resume; changing parameters under
that request ID fails. Completed preparations survive client restarts in the
protected local database, bounded to 128 records with no silent eviction.
Cached replies explicitly report `from_local_history: true` and
`source_rechecked: false`. The `preparation_delivery_uploaded` and
`preparation_recipient_saved` fields describe preparation, not current delivery.

Export each role separately using the same schema, `action: export_preparation`,
`request_id`, and `part: owner_request` or `part: recipient_request`.
Decode each `bundle_chunk` from base64, append in offset order, and pass
`next_cursor` as `cursor` until it is null. Verify `total_bytes` and
`bundle_sha256` before parsing the assembled JSON. Export reads saved originals;
it does not refresh permission or source availability. Keep the owner request
with A and give only the recipient request to B over an authorized channel.
For direct Agent calls, select `part: recipient_invitation` or
`part: owner_invitation` instead. After assembling and checking the pages, pass
the resulting object unchanged as the `invitation` of `connect`. B uses the
recipient invitation only after saving the delivery. A uses the owner invitation
to recover B's original receipt and update its actual send record. The owner
invitation retains the original known status documents; recovery authenticates
these along with locally retained status history before accepting a receipt.
This also works while the original delivery node is offline, provided the
independent source remains reachable and the original grants are still valid.

These bundles contain no private keys. Existing contact approval and R's explicit
remote setup opt-in remain required, as in the command workflow below.

### Optional replica maintenance for a new message

Python Agent preparation can explicitly include `copy_maintainer` with that
selected maintainer's full public `signing_key` and `encryption_key` descriptors.
Use `repair_profile: receipt-index` so the original grants reserve enough finite
metadata and verification work. The maintainer must have keys distinct from the
owner, recipient and original source.

This option adds the selected maintainer to the original root's maintainer list
and includes COPY in its operation mask. The original source keeps its directory
maintenance role. Actual copying still needs separate owner and recipient
reservation/copy permissions bound to the chosen target, the source's disclosure,
and a real target reservation. Owner reads need separate return permissions.
Selecting a maintainer does not itself allocate a replacement or move bytes.

Omit the field to retain the existing preparation behavior. An existing prepared
message cannot add, remove or change this selection; its signed grants and
journal stay fixed. Preparation with this option uses a distinct private journal
version so older runtimes refuse to reinterpret it. See
[copy and recover an existing saved receipt](OPEN_ACK_RECOVERY.md#copy-and-recover-an-existing-saved-receipt)
and the Agent recovery action in that guide. The same optional argument is
available on the Python local and remote source-provisioner APIs.

## Freeze and prepare

For later directory publication, explicitly select `receipt-index` both when
setting up R and here. The default `receipt` profile prepares receipt upload and
recovery without appointing R as a directory publisher. Neither choice increases
an existing signed grant. `--lifetime` accepts 120 to 86,400 seconds; the source
descriptor's expiry can shorten it.

```sh
python -B memory_vault_open_repair_remote_provision_admin.py prepare \
  --network-config /absolute/private/owner/open-config.json \
  --source-url "$MV_SOURCE_ORIGIN" --source-key-id "$MV_SOURCE_KEY_ID" \
  --request-id req_ack_example_001 \
  --recipient ed25519_REPLACE_WITH_RECIPIENT_KEY_ID \
  --text 'Selected memory for this conversation' \
  --memory-id mem_REPLACE_WITH_SELECTED_MEMORY_ID \
  --profile receipt-index --lifetime 3600 \
  --output /absolute/private/new-prepared-source.json
```

Repeat `--memory-id` only for explicitly selected memories; omit it for text alone.
Preparation may fetch the existing contact approval but never uploads the encrypted
delivery. Its result has `state: empty`, message/resource IDs, `owner_request` and
`recipient_request`.

The source commits the original root/read permissions and unbound custody before
the client creates any message ciphertext. A proves R's selected signing and
encryption keys and reads the complete stored source back over HTTP. A durable
local marker records that boundary. Only afterward does the client freeze the
envelope, sign its exact write grant and bind it to the slot. R never receives
the message plaintext, selected memories or the private approved contact session
during preparation.

Outputs are new-only, including retries: an existing file is never replaced.
Before sending, resume interrupted preparation with the same identities, request
ID, profile and lifetime, using a fresh output path:

```sh
python -B memory_vault_open_repair_remote_provision_admin.py resume \
  --network-config /absolute/private/owner/open-config.json \
  --source-url "$MV_SOURCE_ORIGIN" --source-key-id "$MV_SOURCE_KEY_ID" \
  --request-id req_ack_example_001 \
  --profile receipt-index --lifetime 3600 \
  --output /absolute/private/new-resumed-source.json
```

`resume` only accepts a never-uploaded outbox item. Once ordinary sending starts,
use its existing retry path; do not provision a new ACK slot for that delivery.
Preparation cannot retrofit a receipt B may already have saved. Expired preparation
is refused rather than silently renewing old authority.
An interrupted current preparation can resume before encryption or reuse its
existing ciphertext after the recorded boundary. An already encrypted outbox
without that marker, or a legacy preparation journal, is refused and preserved;
it is never relabeled as having the required earlier authorization.

Interrupted setup retains the actual pending, active or unbound stage at R.
Losing a successful reply does not create another source or message. Setup and
bind retries retain their original signed requests; after a request expires,
reconciliation reads the original source under A's still-current permissions.
It cannot renew a grant or replace a missing original. Failed work and restarts
retain their finite storage and work charges.

For an operator that already administers both A and R locally, the original
`memory_vault_open_repair_provision_admin.py` command remains available: replace
the two `--source-…` arguments with `--node-config` pointing to that operator's
existing local source configuration. Do not request another operator's private
node configuration to use this local alternative.

Retain `owner_request` as A's private recovery request. Give only `recipient_request`
to B through an independently authorized private channel. This recipe splits the
protected result into two new protected files without overwriting either:

```python
import json
from pathlib import Path
from memory_vault import canonical_bytes
from memory_vault_trust import _read_private, _write_new_private

prepared = json.loads(_read_private(
    Path('/absolute/private/new-prepared-source.json'), 1024 * 1024))
for field, destination in (
    ('owner_request', '/absolute/private/new-owner-recovery.json'),
    ('recipient_request', '/absolute/private/new-recipient-request.json'),
):
    _write_new_private(Path(destination), canonical_bytes(prepared[field]) + b'\n')
```

## Send the frozen delivery and save it

A calls ordinary `send` with exactly the same request ID, recipient, text and
selected memory IDs. It reuses the frozen encrypted envelope:

```python
from pathlib import Path
from memory_vault_open_client import OpenNetworkClient

with OpenNetworkClient(Path('/absolute/private/owner/open-config.json')) as a:
    sent = a.send(
        request_id='req_ack_example_001',
        recipients=['ed25519_REPLACE_WITH_RECIPIENT_KEY_ID'],
        text='Selected memory for this conversation',
        memory_ids=['mem_REPLACE_WITH_SELECTED_MEMORY_ID'],
    )
```

B then runs with B's own configuration:

```python
from pathlib import Path
from memory_vault_open_client import OpenNetworkClient

with OpenNetworkClient(Path('/absolute/private/recipient/open-config.json')) as b:
    received = b.receive(limit=4)
```

Check that the intended message is actually `validated_saved`; contact approval
or storage acceptance alone is insufficient. Selected memory imports also require
B's normal author-trust policy. Contact approval does not supply that trust.

## B explicitly publishes the saved receipt

B loads its private request artifact and calls the public open-client method:

```python
import json
from pathlib import Path
from memory_vault_open_client import OpenNetworkClient
from memory_vault_open_repair_provision import decode_saved_request
from memory_vault_trust import _read_private

bundle = json.loads(_read_private(
    Path('/absolute/private/new-recipient-request.json'), 1024 * 1024))
with OpenNetworkClient(Path('/absolute/private/recipient/open-config.json')) as b:
    published = b.publish_saved_ack(
        bundle['base_url'], decode_saved_request(bundle),
        repair_profile=bundle['repair_profile'],
    )
```

This explicit call authorizes B's bounded receipt return to A. It reads the real
saved inbox and original receipt; it accepts neither a supplied `saved` flag nor
a replacement receipt. Ordinary `receive` does not call it automatically. The
original delivery node may now be offline; R must remain reachable. Preserve B's
existing protected transport state for exact publication retries.

Ordinary receive rotates through at most four pending local items per poll.
Messages waiting for independent-return permission remain unsent, while later
receipts can still be retried. The retry position survives restart and switching
between updated Python and Node clients; it does not authorize independent ACK
publication or make a pending receipt count as delivered.

## A recovers the original receipt

Use A's retained request, the same source profile, and a fresh output path:

```sh
python -B memory_vault_open_repair_admin.py recover-occupied \
  --network-config /absolute/private/owner/open-config.json \
  --request /absolute/private/new-owner-recovery.json \
  --repair-profile receipt-index \
  --output /absolute/private/new-recovered-receipt.json
```

Successful recovery reports `ack_occupied_source_recovered` and retains the original
recipient receipt. Keep the returned status observations for later recovery as
described in [ACK recovery](OPEN_ACK_RECOVERY.md). Recovery requires current A READ
and B disclosure permission; the retained request cannot override revocation or
expiry.

To advertise this occupied source through one explicitly selected directory,
continue with [directory publication preparation](OPEN_ACK_PREPARATION.md).
Selecting `receipt-index` alone does not sign B's directory publication consent
or publish anything to a directory.


## Returning and recovering receipts through the Agent interface

The Python Agent `connect` operation also accepts the closed local schema
`memory-vault-open-ack-connect/v1`. These operations require the same original
ACK grants and binding as the commands above; contact approval or mailbox READ
authority does not supply them. They neither create an ACK source nor discover
one implicitly.

Use `action: "return_receipt"` at B with `base_url`, `repair_profile` (`receipt`
or `receipt-index`), and the existing saved-receipt publication `request`:
`message_id`, `envelope_ref`, `ack_slot`, `owner`, `target`, `target_node_entry`,
`root_entry`, `write_entry`, `bootstrap_entry`, `binding_entry`,
`current_statuses`, `read_until`, and `retain_until`. Each original entry is
`{"raw": "exact original UTF-8 text", "ref": original_ref}`; do not parse and
reserialize its signed text. Status entries use the same encoding. For example:

```python
returned = agent_b.handle({
    "op": "connect",
    "invitation": {
        "schema_version": "memory-vault-open-ack-connect/v1",
        "action": "return_receipt",
        "base_url": ack_source_url,
        "repair_profile": "receipt",
        "request": saved_receipt_request,
    },
})
```

B signs consent for its actual saved receipt and retains the publication journal
in its existing protected database. A completed repeat uses the retained result
and reports `from_local_history: true`, not a fresh remote observation.

At A, use the same schema with `action: "recover_receipt"`. Its request has
`target_node_entry`, `expected_target`, `expected_ack_slot`, `root_entry`,
`read_entry`, `bootstrap_entry`, `expected_receipt_writer`,
`expected_message_id`, and `expected_envelope_ref`. Original entries have the
same text encoding. A verifies current READ authority and B's disclosure,
persists authenticated status observations, retrieves the original B receipt,
and binds it to the exact local outbox envelope and recipient. Success updates
that send's acknowledgement. Repeating the original `send` then reports
`endpoint_validated: true` without contacting the original delivery node.
Unknown local messages or conflicting receipts refuse that update. Successful
ACK-source retention alone does not establish that A has recovered the receipt,
and a saved receipt does not establish that an agent understood the content.

## Development: separately signed root status

The development client creates a separate whole A-signed root-status original
for new remote sources. The source accepts the optional `root_status` in the
signed setup request, checks its exact root-authority scope, and retains it in
both the actual history and current-status ledger. Read, owner-bootstrap and slot
status remain in a separate whole original. This prepares the authorization data
needed for mailbox ACK configuration without disclosing A's read configuration
or projecting entries out of a signature. After `prepare` and the matching
ordinary `send`, pass that preparation request ID as `ack_request_id` to mailbox
`prepare` or `retain`. The sender binds the exact write-grant reference into its
mailbox attempt and explicitly permits disclosure of the six configuration
roles. The mailbox retains their complete signed bytes in the message history.
Mailbox source and reader verify A/B/message/ciphertext binding and the complete
historical status originals; no ACK read grant or ACK source resource/custody
history is added to the mailbox promise. Network proof containers accept the
optional configuration only as a complete six-role set.

An existing combined-status preparation cannot be projected into this format;
use a separately prepared new send. Retention and feed recovery do not establish
ACK service availability or recipient acknowledgement. Receipt return remains
an explicit recipient operation; it is never implied by mailbox retention.

New split-status setups require a source running this development extension;
the published alpha.0.13 source does not accept the extra setup field. Previously
journaled combined-status setups resume with their original signed bytes. A
rejected or interrupted setup does not authorize message encryption.

The development mailbox admission transport compresses ACK-bearing drafts with
`zlib-base64url-v1` under the existing 65,536-byte request ceiling. The receiver
limits expansion to the declared original size, at most 131,072 bytes, rejects
trailing or incomplete streams, and checks the original byte hash before staging.
The original signed documents remain unchanged. Ordinary drafts keep the legacy
encoding; saved admission requests replay their exact original bytes.

## Development: return a receipt after cold mailbox delivery

After the ordinary `receive` operation saves a message or selected memories from
its configured mailbox, B can call `connect` with this invitation:

```json
{
  "schema_version": "memory-vault-open-ack-connect/v1",
  "action": "return_mailbox_receipt",
  "message_id": "msg_REPLACE_WITH_RECEIVED_MESSAGE_ID",
  "source_url": "https://source.example",
  "source_key_id": "ed25519_REPLACE_WITH_SOURCE_KEY_ID",
  "repair_profile": "receipt"
}
```

B authenticates the complete retained inbox evidence and selects the exact
sender-authorized receipt configuration for that message. It proves the selected
source's keys and current empty ACK history independently before preparing its
receipt return. No separate recipient invitation from A is needed. An absent
configuration, unsaved inbox, changed source or damaged journal fails closed.
The source must remain reachable and the original authorization must remain valid.

The protected local journal freezes the verified request before publishing the
actual saved receipt, with at most 16 returns and no silent eviction. Identical
retries use the original request; completed retries report local history without
claiming a fresh source check. A still retrieves the original receipt through its
own independent owner recovery operation. This development action requires the
updated client and the separately prepared ACK configuration described above.

The receipt client reuses its just-verified preflight only once, with the same
work meter, target, message, original authorities and deadline. Supplied originals
whose complete raw references match the signed proof manifest are reused locally;
the complete history, signatures and current status checks still run. This avoids
spending a finite source grant on duplicate downloads. A saved put journal can
recover a lost successful reply without preparing a different receipt.

## Retain a receipt destination for ordinary receive (source after alpha.0.29)

B can retain one independently selected ACK destination per exact message by
using the same fields as `return_mailbox_receipt`, with the action changed to
`register_mailbox_receipt_return`. Registration is local and can precede receipt
of that message. It creates no source permission: ordinary `receive` attempts
return only after the actual message is saved, using its retained original ACK
configuration, original recipient signature and independently checked source.

The protected selection survives restart. Each ordinary receive invocation
attempts at most two distinct ready returns within its existing sixty-second
network deadline. One attempt precedes mailbox polling with at most thirty seconds;
a second can follow reception with at most thirty seconds. The last failure remains available through inspection. An unavailable source
or lost response leaves the selection pending for a later receive invocation.
The existing receipt publication journal retains exact requests across retries
within their original signed expiry. An expired uncertain upload reports
reconciliation-required rather than making another receipt or renewing access.
That selection stops polling and remains inspectable; A can use its independent
recovery permission to determine whether the source retained the receipt.
Successful results appear in the bounded `receipt_returns` array; failures use
`errors` with `operation: return_mailbox_receipt`. Completed selections are not
sent again, and do not claim that the source was checked again.

The ACK connect schema also accepts `list_mailbox_receipt_returns`,
`inspect_mailbox_receipt_return` and `remove_mailbox_receipt_return`.
Inspection/removal take `message_id`. At most sixteen selections are retained;
removal stops future polling without removing inbox contents or the underlying
frozen receipt-return journal. A changed destination cannot silently replace
that original journal. Removing a completed selection and registering it again
may report verified local history instead of transmitting another receipt.
A still retrieves the original receipt through its independent recovery grant.

When A repeats the same `send` after storage acceptance, an existing successful
ACK preparation can supply its original owner READ request automatically. A
checks the exact request, message, ciphertext and recipient before any ACK-source
network access. It refreshes only the previously selected origin's introduction,
requiring the same key and storage epoch, then authenticates the original receipt
through the existing recovery workflow. A changed send under the same request ID
is refused before this source read.

This recovery has at most twenty seconds and shares the send operation's existing
sixty-second network deadline. Failure leaves the original delivery result and
its separate pending state intact, with `ack_recovery_error` describing the failed
independent read. A confirmed receipt updates the original outbox; subsequent
identical sends verify that local receipt without contacting either source.
There is no additional authority when no matching ACK preparation exists, and no
new source or permission is inferred from a memory or peer message.

### Retain an ACK replica for the original send (source after alpha.0.30)

The sender can retain the same explicitly selected replica request accepted by
`recover_replica_receipt`, using `register_replica_receipt` instead. Registration
is local and requires the actual original outbox message, its exact ciphertext,
recipient signing/encryption keys, and the sender's original READ/bootstrap
permission. It does not create a replica or grant another party access.

```python
selected = dict(replica_recovery_invitation, action="register_replica_receipt")
agent.handle({"op": "connect", "invitation": selected})
# After restart, repeat the identical original request_id and send arguments.
confirmed = agent.handle(original_send_request)
```

A repeated original send selects one registered destination, checks a fresh node
introduction against the retained key/origin/epoch and revision, and retrieves
the actual recipient receipt through the existing original-history verifier.
It checks the unchanged send before any source read. A valid receipt updates
the original outbox; subsequent repeats use local history. The result includes
`ack_recovery`, `ack_replica_id`, `ack_commit_ref` and
`ack_replica_custody_ref` when recovery succeeds. Failure leaves confirmation
pending and reports `ack_recovery_error`.

Up to sixteen selections may be retained, with at most two destinations per
message. One is attempted per send invocation, rotating by last attempt; it
shares that send's existing sixty-second network deadline. A selected replica
takes precedence over original-source recovery in that invocation. The caller
can retry the same send to try its other explicitly selected destination.

Use `list_replica_receipts`, `inspect_replica_receipt` (with `replica_id`, and
optional paging `cursor`) and `remove_replica_receipt` through the ACK connect
schema. Inspection includes the last failure. Removal retains the original
outbox and authenticated status history; switching destinations does not erase
an earlier revocation. Existing explicit replica recovery uses that same
root-scoped history as well.
