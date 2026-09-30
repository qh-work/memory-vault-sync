# Explicit ACK directory publication and owner recovery

These commands publish an already committed original ACK receipt to one
directory and independently recover it. First use the
[source provisioning commands](OPEN_ACK_PROVISIONING.md) to prepare a new
source before sending, or retain an existing authorized source. After B saves
and shares its receipt, the [preparation commands](OPEN_ACK_PREPARATION.md)
export the plan and let A and B sign their own directory consents.

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

## Agent directory recovery (development after alpha.0.32)

Python and native TypeScript accept the same explicit `connect` invitation:
`schema_version: memory-vault-open-ack-connect/v1`,
`action: recover_discovered_receipt`, `repair_profile: receipt-index`, and
`request`. There is no top-level `base_url`; the independently selected signed
`expected_directory_node` supplies the directory address. The directory supplies
the source introduction only after authenticating its provider record.

The request has these exact fields:

- `expected_directory_node`: the selected directory's signed node document.
- `expected_directory`: its independently held public signing and encryption keys.
- `expected_target` and `expected_source_epoch`: the authorized ACK source's
  public signing/encryption keys and storage epoch.
- `expected_ack_slot`, `expected_receipt_writer`, `expected_message_id`, and
  `expected_envelope_ref`: the original send's independent bindings.
- `root_entry`, `read_entry`, and `bootstrap_entry`: original grants, each as
  `{raw, ref}` where `raw` is the exact UTF-8 original string.
- Optional `known_statuses`: at most sixteen original `{raw, ref}` entries.

The client queries that exact directory, proves the advertised source's two
keys, and independently retrieves the signed receipt under the original owner
READ/bootstrap grants. It checks the actual receipt commit against the directory
fact before updating the original outbox. An index lease never substitutes for
READ permission. Missing records, mismatched custody, expired observations and
retained revocations cannot confirm a send. If the original send is absent,
recovery cannot manufacture an outbox entry.

The whole call retains a thirty-second deadline, with at most ten seconds for
directory lookup and the remaining time for the source read. Existing bounded
provider revision floors and original-root status journals are reused across
restart and client-language changes. This operation does not select replacement
directories, sign publication consent, or republish a lost directory.

New `receipt-index` sources reserve up to 256 shared requests for the complete
bind, receipt-return, directory-publication and independent-read workflow. The
previous 128-request preparation can exhaust its allowance during final receipt
retrieval. Existing signed grants and node policies keep their original limits;
this update does not renew or enlarge an existing authorization. Operators must
explicitly enable the profile when preparing a new source.

## Publish through another directory (development after alpha.0.33)

The original source can prepare another explicitly selected directory by using
new `allocation_id` and `job_id` values with the existing export, separate owner
and receipt-writer signing, assemble and publish commands above. Both principals
must consent to the new exact directory, fact and allocation. An old consent is
not transferable. Existing signed source permissions, expiry and shared resource
limits continue to apply; an exhausted source refuses further publication.

Publication history is retained for each job. Its exact requests, response-loss
charges, signing revisions and results survive restart without replacing earlier
jobs. All retained jobs share the original source's request, signature, transfer
and job-storage allowance, with at most sixteen histories and no increase to an
existing signed job-count limit. Retrying an earlier job selects its earlier
history and deadline. Unknown provider fact histories still refuse preparation.

After publication, the owner supplies the new directory's signed introduction
and full keys in `connect/recover_discovered_receipt`. The client independently
reads the same original ACK source and checks the actual receipt against the
original send. This explicit workflow works after the old directory stops. It
does not automatically choose directories, obtain consent, or extend old grants.
