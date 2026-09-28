# Prepare an ACK directory publication

This source workflow prepares the private request consumed by the
[directory publication command](OPEN_ACK_DIRECTORY.md). It uses an existing
occupied ACK source: B has already saved the message and explicitly shared its
original receipt with R. R must already be an authorized publisher in A's root.

For a new delivery, first follow [prepare a receipt source before sending](OPEN_ACK_PROVISIONING.md)
with the explicit `receipt-index` profile. That guide covers freezing the selected
content, ordinary delivery, B's saved-receipt publication and A's recovery.

R exports one plan. A and B verify that plan and sign separate consents using
their own existing open-client configurations. The assembled request can then
be sent to the selected directory. These preparation commands perform no network
request and do not open a Vault.

Keep every plan, consent and expectation file private. Transfer each only through
an independently authorized private channel. A bundle containing source originals
does not itself authorize forwarding those originals. Neither participant sends
its private identity or open-client configuration to R or to the other signer.

## R exports the plan

Prepare a private JSON export request with these exact fields:

| Field | Value |
| --- | --- |
| `schema_version` | `memory-vault-open-ack-index-export-request/v1` |
| `resource_id` | The existing occupied source resource |
| `directory` | The independently selected D's full public signing and encryption descriptors |
| `directory_node` | D's current signed node original as `{raw_base64url,ref}` |
| `allocation_id`, `job_id` | Stable opaque identifiers for this single publication |
| `budget_limits` | The finite directory allocation budget, within the original A root budget |
| `windows` | The finite directory allocation windows, within the original A root windows |
| `current_statuses` | Optional original entries; otherwise use R's retained source statuses |

The budget has the same fields as the original resource budget, with
`max_live_bytes: 0`: this directory stores metadata. Expiry and budget cannot be
increased by editing an old signed grant. The source independently revalidates
its committed originals, current permissions and the selected directory.
Choose `max_items` between 1 and 64, and `max_meta_bytes` between 16 KiB and
2 MiB, while remaining within the original root limits. A source's larger
storage budget is not the directory allocation budget.

```sh
python -B memory_vault_open_repair_index_prepare_admin.py export \
  --node-config /absolute/private/source/node-config.json \
  --request /absolute/private/directory-export-request.json \
  --output /absolute/private/new-directory-plan.json
```

Retain the same request and identifiers for retries. Outputs are new-only; use
a new output path when recovering a previously prepared result.

## A and B each sign locally

Each signer supplies an independent private expectation file. It is a JSON
object with the following exact fields, retained from the actual message and
source relationship, plus the explicitly selected directory:

| Field | Value |
| --- | --- |
| `expected_ack_slot` | The original ACK slot |
| `expected_owner` | A's full public signing and encryption descriptors |
| `expected_receipt_writer` | B's full public signing and encryption descriptors |
| `expected_message_id` | The original message ID |
| `expected_envelope_ref` | The complete original encrypted envelope reference |
| `expected_source`, `source_storage_epoch` | R's independently known full public keys and epoch |
| `expected_directory`, `directory_storage_epoch` | D's independently selected full public keys and epoch |

Do not copy these values from an untrusted plan just to make validation pass.
The command verifies the original source history against the independently held
values before signing. A uses `--variant owner`; B separately uses
`--variant receipt_writer` with B's own files:

```sh
python -B memory_vault_open_repair_index_prepare_admin.py sign \
  --network-config /absolute/private/owner/open-config.json \
  --bundle /absolute/private/directory-plan.json \
  --expected /absolute/private/independent-expectations.json \
  --variant owner \
  --output /absolute/private/new-owner-consent.json
```

If explicitly renewing the signer's existing source status, add
`--renew-source-status`. This preserves the already authorized source scopes,
permission bits and revision floors. The directory-only consent status is signed
separately so the original READ path does not have to disclose a directory-only
scope. Known revocations and conflicts remain refusals. Supply retained status
originals with `--known-statuses /absolute/private/known-statuses.json` when
available; that file is an object with one `known_statuses` array of original
entries.

The existing protected transport database retains signing revisions and exact
retry results. Preserve that database across restarts. Recreating a transport
directory is not a way to retry this operation.

## Assemble, publish and independently read

The assembler validates the original plan and both signed results against the
independent expectations. It does not sign for either party:

```sh
python -B memory_vault_open_repair_index_prepare_admin.py assemble \
  --bundle /absolute/private/directory-plan.json \
  --owner-consent /absolute/private/owner-consent.json \
  --recipient-consent /absolute/private/recipient-consent.json \
  --expected /absolute/private/independent-expectations.json \
  --output /absolute/private/new-publication-request.json
```

Pass the resulting request to `memory_vault_open_repair_index_admin.py publish`
using R's existing node configuration. A then uses the separate `recover`
command with its retained READ/bootstrap grants. Preparation and publication do
not report the receipt usable; that result requires A's actual authorized read.
