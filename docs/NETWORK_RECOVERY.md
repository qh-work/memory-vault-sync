# Full endpoint recovery (0.26.0-alpha.1)

This is an explicit native management operation. It snapshots the existing
canonical Vault and the endpoint's committed transport state: signing and
encryption identity, unfrozen offline outbox, frozen envelope bytes, request
IDs, inbox cache, delivery acknowledgements, rejected ciphertext, relay cursors,
and previously verified member/node checkpoints. It does not create another
memory model or give memories a task, session, or project owner.

`keys-backup` remains a smaller identity/control backup. It does **not** include
offline outbox messages. Use the full endpoint operation below when those
messages must survive losing the original endpoint directory.

## Create an encrypted package

Use the configured Python environment and the hash-locked client dependencies
from [NETWORK_QUICKSTART.md](NETWORK_QUICKSTART.md). All example paths must be
replaced with absolute paths. The output directory and secret file must not
already exist. Their parent directories must be private and must exist.

```sh
python -m memory_vault_network_recovery backup \
  --network-config /private/example/agent/network.json \
  --output /private/example/backups/endpoint-001 \
  --secret-file /private/example/recovery-keys/endpoint-001.json \
  --timeout 60
```

The recovery secret is a new random 256-bit key, not an account password, an
identity key, or a reusable shared network key. Keep it separately from the
encrypted package. Anyone possessing both can recover the endpoint identity
and its private memories. An endpoint explicitly sharing the issuer's signing
key also backs up issuer authority; the result reports that condition.

The package uses AES-256-GCM from `cryptography`. Each file is encrypted in
1 MiB chunks with unique nonces and authenticated package, file and chunk
bindings. The encrypted manifest commits the exact file set, lengths and
hashes. Ciphertext parts without the final manifest are an incomplete backup.
Metadata outside the encryption identifies the network and package, algorithm,
chunk size and chunk count; it does not contain memory text or keys.

No network request occurs during backup. The source configuration is not
modified. The canonical Vault uses the existing SQLite backup implementation.
Both the Vault and transport database hold SQLite `BEGIN IMMEDIATE` write
reservations while the snapshots are made. These are actual cross-process
locks, so concurrent writers may need to retry. Config and key files are read
and rechecked; they are not globally locked. This is a snapshot of committed
data, not a claim that every host process or an in-progress application call
has stopped. Encryption runs after the source database locks are released.

## Restore to a new, inactive endpoint

Select the issuer public key, authority address and relay addresses from an
independent trusted source. The encrypted package cannot choose them. Restore
only into a new directory; the command never replaces an existing Vault,
endpoint configuration, or identity.

```sh
python -m memory_vault_network_recovery restore \
  --package /private/example/backups/endpoint-001 \
  --secret-file /private/example/recovery-keys/endpoint-001.json \
  --directory /private/example/restored-agent \
  --confirm-network-id example-network \
  --issuer-public /private/example/current-trust/issuer-public.json \
  --authority-url https://authority.example.invalid \
  --relay https://relay-a.example.invalid \
  --relay https://relay-b.example.invalid \
  --memory-trust /private/example/current-trust/memory-trust.json \
  --timeout 60
```

The example domains are placeholders, not running services. One or two relays
may be selected. The restored canonical database is under `vault/`; the same
signing/encryption identity and new capture-off configuration are under
`endpoint/`. Canonical record IDs and bytes and write-idempotency receipts are
retained. The local Vault store identity and derived indexes are rebuilt by the
existing restore implementation; old Vault transfer cursors are not reused.
Network outbox/inbox state is a separate transport ledger, not a second memory
store.

Recovery retains the original member identity. It is not a way to provision an
additional independent agent. Decide which copy will resume work; do not let
old and restored copies concurrently invent new requests under the same
identity. This command does not stop or revoke an old process on another host.

`--memory-trust` is optional and must name independently selected current Vault
trust. Without it, restored signed records remain quarantined. The archived
trust registry does not decide admission during restore or future runtime
admission. A private snapshot of the selected registry is used for both; its
missing or revoked entries are not silently enrolled. Without a selected
registry, the new client trusts only its explicitly restored identity for local
writes, and remote authors require new operator enrollment. `--accept-unsigned`
explicitly permits previously admitted unsigned records; it does not make an
unverified signature trusted. Cached inbox results and old acknowledgements
remain historical evidence and do not grant fresh member or node permissions.

Restore starts no service, hook, synchronization job, or pump, and performs no
network request. Automatic capture and automatic sending remain disabled. To
resume deliberately, run one bounded pass:

```sh
python -m memory_vault_network_worker \
  --network-config /private/example/restored-agent/endpoint/network.json \
  --maximum-messages 4 --maximum-seconds 10 --receive-limit 4
```

Before a network send or receive, the normal client must obtain a fresh signed
issuer status and satisfy the restored monotonic checkpoints. An expired or
unavailable authority, revoked member, invalid key binding, or invalid node
state stops delivery. Local Vault access remains independent. Resending keeps
the original request/message IDs and frozen ciphertext; the two relays dedupe
the same message. Existing cached `text_memory_id` references still point to
the canonical Vault; use native `recall` and its cursor to read text beyond the
bounded receive preview.

## Limits and failure handling

The encrypted package contains exactly five logical files, at most 4,096
chunks and 4 GiB plaintext in total. The Vault snapshot remains capped at
2 GiB; transport data at 1.5 GiB; other individual files at 2 MiB. Transport
limits are 1,024 outbox rows, 4,096 inbox rows, 16,384 acknowledgements, 128
quarantined envelopes and 16,384 state entries. Rows and cells are also bounded.
The original 256 MiB outbox/inbox and 16 MiB rejected-ciphertext limits still
apply to their corresponding data.
The time budget is 1–300 seconds, default 60. Budget checks occur between
bounded operations; an in-flight OS file operation is not forcibly killed.

Transport SQLite files and executable schemas are never imported. Bounded
transport data is parsed into fixed, locally defined tables with parameterized
inserts. Unknown tables, state keys, fields, malformed receipts, broken bindings
and memory references fail closed. The canonical SQLite snapshot uses the
existing closed-schema validator and rebuild path. Authentication failures,
unexpected files, resource limits, and I/O errors do not silently drop rows.

A failed operation may leave its newly created output directory or ciphertext
parts for inspection. It never overwrites the old endpoint. Do not treat a
failed restore as a successful recovery; choose another new destination for a
retry. This backup excludes host permissions, installed plugins, automatic
capture queues, sync configuration, artifacts, and operating-system settings.
It does not promise arbitrary-size backups, zero interruption to writers, a
running background worker, real-model validation, or public deployment.
