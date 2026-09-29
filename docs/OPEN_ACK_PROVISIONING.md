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
