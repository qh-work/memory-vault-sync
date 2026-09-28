# Explicit ACK directory publication and owner recovery

This source checkout adds one-directory publication for an already committed
original ACK receipt. These commands are newer than the alpha.0.7 release.
Use the matching source or a release whose notes include this capability.

These commands consume an already provisioned ACK source and independently
signed authority bundles. This version does not yet generate the complete
publication plan or A/B consents for a fresh agent. Integrators must construct
them using the public signing and validation APIs before invoking `publish`.

The recipient B has already saved the message and shared its original receipt
with source R. R is an owner-authorized maintainer. The directory D receives only
the exact source history covered by separate A and B publication consents.
Public directory queries return an opaque provider fact, source introduction
and directory lease. They do not return the receipt or private grants.

The source first proves D's signing and encryption keys, obtains an independent
directory reservation, and uploads bounded proof frames. Its existing protected
`network.sqlite3` retains exact requests and used work across retries. A lost
response never permits a new signed request under the same step. An expired
exchange needs reconciliation; restarting does not reset its budget.

## Source publication

Use the existing source node configuration and private consent bundle:

```sh
python -B memory_vault_open_repair_index_admin.py publish \
  --node-config /absolute/private/source/node-config.json \
  --request /absolute/private/index-publication.json \
  --output /absolute/private/new-publication-result.json
```

The closed request has these fields:

| Field | Value |
| --- | --- |
| `schema_version` | `memory-vault-open-ack-index-publication-request/v1` |
| `resource_id` | Existing occupied ACK source resource ID |
| `directory` | Independently selected D `{signing_key,encryption_key}` public descriptors |
| `node` | D's current signed public node descriptor as an original entry |
| `fact` | R's signed `provider.fact`, naming the root's opaque anchor and exact original ACK commit |
| `intent` | Exact `resource.index_intent` authorized by both publication consents |
| `owner_consent`, `recipient_consent` | Separate A/B signed `ack.index_consent` original entries |
| `current_statuses` | All required current signed status original entries, at most 16 |
| `allocation` | Optional exact allocation original already signed by R; normally R creates and journals it |

An original entry is `{raw_base64url,ref}`: unpadded Base64url of the original
bytes and the full `{namespace,key,raw_sha256,size}` reference. Preserve original
bytes, namespaces and opaque keys; do not replace them with reserialized JSON.

The consents bind this D, storage epoch, complete source commit, intent digest,
exact disclosed originals, full status scopes and expiry. An old receipt-return
consent or a directory lease cannot replace them. The Python authorization
helpers are in `memory_vault_open_repair_index.py`; callers sign only for their
own identity. Publication never requests an absent A or B private key.

Successful publication returns `state: advertised` and the actual D lease. It
does not claim that A has read the receipt. Repeat a failed command with the
same request; the durable journal recovers the existing exchange. Output files
are private and new-only. For a fresh larger workflow, see the explicit
`receipt-index` profile in [ACK recovery](OPEN_ACK_RECOVERY.md). Existing signed
source ceilings still apply.

## Independent owner discovery and read

A uses its ordinary open-client configuration, retained READ/bootstrap grants,
and independently known R/B/D identities:

```sh
python -B memory_vault_open_repair_index_admin.py recover \
  --network-config /absolute/private/owner/open-network.json \
  --request /absolute/private/index-recovery.json \
  --output /absolute/private/new-recovered-receipt.json
```

The recovery request has these fields:

| Field | Value |
| --- | --- |
| `schema_version` | `memory-vault-open-ack-index-recovery-request/v1` |
| `directory`, `directory_node` | Independently selected D full public keys and signed node original |
| `target`, `source_epoch` | Independently known original R full public keys and storage epoch |
| `ack_slot` | Exact original ACK slot |
| `root`, `read`, `bootstrap` | A's retained original authority entries |
| `receipt_writer` | Independently known B full public keys |
| `message_id`, `envelope_ref` | Original message ID and complete envelope reference |
| `known_statuses` | Retained signed status entries, at most 16; empty only when none are known |
| `archive_statuses` | Optional first time; reuse the complete previous result archive on later runs |

The client contacts the selected D directly, follows bounded directory pages,
proves the source keys, then performs A's separate authorized occupied-source
read. `state: usable` requires the recovered original commit to match the
directory fact. The result includes B's exact receipt and original references;
it never imports into A's Vault. Offline, expired, mismatched or unauthorized
sources do not produce a usable result.

Python callers can use `OpenNetworkClient.recover_indexed_ack(...)` with the
independent expected values and raw original entries. The lower-level async API
is `DiscoveredAckRecoveryClient.recover`. The source API is
`AckIndexPublicationClient.publish`. The operation remains one original source
and one explicitly authorized directory; it does not migrate the message,
create replicas, automatically renew authority, or prove global availability.
