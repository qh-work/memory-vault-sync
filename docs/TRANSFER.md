# Incremental signed directory transfer

`memory_vault_transfer.py` publishes and receives bounded signed batches through
an explicitly selected directory. It does not open sockets, log into accounts,
start a sync service, schedule itself or install anything. If another approved
service carries that directory between devices, it provides the remote delivery.

Local save/recall never waits for this adapter. The canonical SQLite records and
delivery log are the local durable source; pending batches and small cursor
receipts are retry state, not another memory database or Task system. The code
has not undergone runtime testing; no performance or end-to-end delivery result
is claimed.

## Setup

Use the [trust setup](TRUST.md) to create an identity explicitly and register the
public descriptors of the publisher and each record signer on the recipient.
Do not auto-enroll a key contained in a packet. The publisher registers its own
key locally too. Private keys never go into the Vault, capsule or exchange folder.

Select four separate paths: a local Vault file, private trust/control files,
a private transfer-state directory, and the exchange directory. Trust/identity/
Vault files must not live inside the exchange or transfer-state directory.
Do not use a multi-device synced SQLite file; synchronize logical batches.
This adapter and protected signing storage currently require POSIX; native
Windows signing/ACL support is not implemented.

Commands below are examples for an authorized operator, not commands run while
preparing this release. All paths must be absolute, without symlink components.

Publisher:

```bash
python3 /absolute/source/memory_vault_transfer.py publish \
  --vault /absolute/private/memory/vault.sqlite3 \
  --exchange /absolute/shared/memory-exchange \
  --state-directory /absolute/private/send-state \
  --trust-store /absolute/private/control/trust.json \
  --identity /absolute/private/control/identity.json
```

Recipient:

```bash
python3 /absolute/source/memory_vault_transfer.py receive \
  --vault /absolute/private/memory/receiving.sqlite3 \
  --exchange /absolute/shared/memory-exchange \
  --state-directory /absolute/private/receive-state \
  --trust-store /absolute/private/control/trust.json
```

The exchange is plaintext, including signed content. Signatures are not
encryption. Decide its ACLs, encryption and audience through the external
transport; the adapter does not widen them. Public key descriptors can be
shared, but keep trust policy and private signing files local and protected.

## What is sent

Each file is `{ "payload": ..., "proof": ... }`. The exact payload has:

- `schema_version`: `universal-memory-delta/v1`;
- `source_store_id`: persistent random identity of the source Vault;
- `sender_key_id`: the registered envelope signer, which may relay other signers;
- `after`, `cursor`: a contiguous source delivery-log interval;
- `records`: canonical v1 records, including their dependency closure;
- `attestations`: one record proof per included memory ID;
- `blocked`: explicit `{memory_id, sequence, reason}` dispositions for selected
  roots that cannot currently be delivered.

The message signature covers the entire payload under a separate domain from
record signatures. Each included record's proof is also independently checked.
The recipient trusts neither filenames, source labels, claimed models nor an
unregistered public key. Transport source/store IDs track replication only;
they never own, hide or delete the memories.

Default publication requires verified records and dependencies. A local
unsigned record is reported blocked rather than blocking all other records.
An operator can explicitly use `--attest-unsigned` to attest the exact bytes of
unsigned records. That makes this key an attester, **not the original author**,
and does not change historical provenance or grant authority. Previously
blocked records must be requeued first if the source cursor has passed them.

## Bounded work and blocked records

Publication defaults to 100 delivery events and a 256 KiB core response budget;
`--limit` allows 1–256 and `--maximum-bytes` allows 4 KiB–3 MiB. Dependency closure
can add records but never more than 1,024 total. The final signed file is bounded
to 4 MiB. The MCP changes tool uses a smaller 1 MiB ceiling to fit its envelope.

A missing/revoked dependency, unsigned dependency or closure too large for one
batch produces a `blocked` disposition. The cursor advances over that explicit
disposition so unrelated records can proceed. It does **not** mean the blocked
record was copied. Its canonical bytes remain in the local Vault. Re-admitting
an existing dependency requeues admitted dependent records in one transaction.
After increasing the batch budget or repairing independent trust policy, an
operator can explicitly requeue an identified record:

```bash
python3 /absolute/source/memory_vault.py \
  --vault /absolute/private/memory/vault.sqlite3 \
  --requeue mem_0123456789abcdef0123456789abcdef01234567
```

The ID is an example; use the actual blocked ID. This changes delivery metadata,
not memory contents. It does not trust a key or admit quarantined memory. Repeat
publication with the appropriate budget after repair. Deep/large relation
graphs may need explicit larger-bundle review; this release does not fragment a
single oversized dependency closure across independently admitted packets.

Reception defaults to 16 batches per invocation (`--maximum-batches` up to 256),
and bounds discovery to 256 peers/20,000 directory entries and 256 candidate
checks. Old committed ranges are skipped without rehashing all history. These
are operational bounds, not a guarantee against denial of service on a hostile
filesystem. No benchmark result is asserted.

## Crash recovery and trust changes

The publisher saves exact signed pending bytes locally before publication, then
atomically publishes a no-overwrite file, then commits its cursor. A retry uses
those bytes rather than signing a different payload for the same interval.
While the publisher key remains trusted, already committed pending bytes can
be cleaned up even if a different, inner record signer has since been revoked;
the stored receipt is checked before current record-key verification.

The receiver verifies all signatures before an atomic record/receipt commit.
Its small cursor file is updated after the database commit. If interrupted
between those steps, replay finds the database receipt: records are not added
twice and `receipt_replays` increases instead of falsely counting new records.
Unknown senders and invalid candidates are rejected; within the candidate
budget, invalid filenames do not block a later valid candidate at the same prefix. Two different, valid signed
payloads at one prefix are a fork and require operator resolution. No prefix
gap is silently skipped.

If an inner record's trust changes for an **uncommitted** pending batch while
the publisher remains trusted, publication pauses with `pending_trust_changed`.
Never rewrite its bytes or blindly delete its state:
the old batch might already have reached the exchange. If the identical file
is present, `acknowledge-published` with the same path arguments explicitly
records that observed publication without sending it again or trusting its
records. Otherwise restore the correct transport/state evidence or start an
explicitly provisioned new publisher identity and fresh state directory;
retain the old pending evidence for reconciliation. This release does not automate
cross-recipient key rotation or cancellation of an uncertain prior publication.
If the publisher key itself is revoked (including when it also signed a record),
publication and acknowledgment fail closed; retain the old evidence and use the
explicit new-identity/new-state recovery path rather than re-trusting it implicitly.

Revocation changes future admission and current trust-aware views, not every
offline recipient's policy. A recipient cannot admit a batch containing an
unregistered/revoked record key merely because its relay is registered; the
missing trust decision is explicit and may block that authenticated stream.
Other independent senders can continue. Do not bypass this by auto-registering
keys from a packet. Source/database identity changes and missing publisher
state likewise require reconciliation, not an automatic cursor reset.

## Meaning of success

`stored` / `saved_local` means local durable memory. `published` means an
immutable exchange file exists. `received` reports this recipient's commits.
`published_with_blocked`, nonempty `rejected`, gaps or candidate limits require
inspection; they are not a complete synchronization claim. None of these
states proves a remote AI has read the record, agrees with it or is authorized
to execute a remembered next action.
