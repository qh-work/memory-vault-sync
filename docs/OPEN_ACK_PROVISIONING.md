# Prepare a receipt source before sending

Freeze one explicitly selected message or memory transfer, create its ACK source,
then use ordinary delivery. After B saves the delivery, B can explicitly publish
its original receipt to R. A can recover it from R even when the original delivery
node is offline.

The preparation operator must have A's existing open-client configuration and
R's existing local node configuration. This is local A/R administration; it does
not enroll an independently operated remote R. B keeps its private keys. B must
already have approved A through the [normal contact workflow](OPEN_NETWORK_CONTACT.md).
R must run with the chosen repair profile enabled and an address reachable by A
and B. Use absolute paths to protected local files outside cloud-synced directories.
Replace all example paths, recipient key IDs and memory IDs with selected values.

## Freeze and prepare

For later directory publication, explicitly select `receipt-index` both when
setting up R and here. The default `receipt` profile prepares receipt upload and
recovery without appointing R as a directory publisher. Neither choice increases
an existing signed grant. `--lifetime` accepts 120 to 86,400 seconds; the source
descriptor's expiry can shorten it.

```sh
python -B memory_vault_open_repair_provision_admin.py prepare \
  --network-config /absolute/private/owner/open-config.json \
  --node-config /absolute/private/source/node-config.json \
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

Outputs are new-only, including retries: an existing file is never replaced.
Before sending, resume interrupted preparation with the same identities, request
ID, profile and lifetime, using a fresh output path:

```sh
python -B memory_vault_open_repair_provision_admin.py resume \
  --network-config /absolute/private/owner/open-config.json \
  --node-config /absolute/private/source/node-config.json \
  --request-id req_ack_example_001 \
  --profile receipt-index --lifetime 3600 \
  --output /absolute/private/new-resumed-source.json
```

`resume` only accepts a never-uploaded outbox item. Once ordinary sending starts,
use its existing retry path; do not provision a new ACK slot for that delivery.
Preparation cannot retrofit a receipt B may already have saved. Expired preparation
is refused rather than silently renewing old authority.

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
