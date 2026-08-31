# Native Drive: encrypted, bounded memory synchronization

The development source supports `sync configure --backend native-drive` without
rclone or Git. It carries the existing signed incremental capsules and exact
group-fragment bytes; canonical records, share-v1, dynamic handoff, raw `copy-pack`,
and the existing personal [backup/restore](BACKUP.md) interfaces are unchanged.
This is an additional transport, not a migration of an existing rclone remote,
a whole-machine backup, or a replacement for the [light protocol](../PROTOCOL.md).

## Explicit prerequisites

Choose an existing dedicated Drive folder, a protected Drive configuration,
an independently registered signing identity/trust store, and a separate local
X25519 encryption identity. Install the optional dependencies declared in
`requirements-network.txt` in the chosen runtime. No command here installs a
plugin, discovers accounts, creates a Drive root, performs OAuth enrollment, or
reads an existing rclone configuration.

The Drive configuration has this exact shape. Every value below is a placeholder:

```json
{
  "schema_version": "memory-vault-drive-config/v1",
  "root_folder_id": "EXPLICIT_DEDICATED_FOLDER_ID",
  "oauth_client_id": "OPERATOR_SELECTED_OAUTH_CLIENT_ID",
  "credential_ref": {
    "kind": "macos-generic",
    "service": "operator-selected-service",
    "account": "operator-selected-account"
  }
}
```

The explicitly selected OS credential contains JSON with `refresh_token` and,
only when needed, `client_secret`. Neither value belongs in this configuration,
a command argument, memory, source control, or an exported example. The existing
Windows Credential Manager and Linux Secret Service reference profiles are also
accepted. Missing/locked credentials stop with `drive_credential_unavailable`;
there is no alternate account, ambient-token or plaintext fallback.

Existing encryption keys can be reused only by explicit choice. To create a
**new** separate backup encryption identity through the supported Python API,
run this from the source directory after choosing protected, non-existing output
paths. This does not enroll it as a signing identity or contact the network:

```python
from pathlib import Path
from memory_vault import canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_storage import atomic_write

key = EncryptionIdentity.generate()
key.save(Path("/absolute/private/cloud/encryption.json"))
atomic_write(Path("/absolute/private/cloud/encryption-public.json"),
             canonical_bytes(key.public_descriptor()) + b"\n", replace=False)
```

Keep the private key independently recoverable and private. Each recipient file
must contain one public `memory-vault-network-encryption-key/v1` descriptor, not
a private key or combined network-member document. Include the local identity
and every intended backup recipient; verify other devices' public keys outside
memory content. A newly added recipient cannot decrypt previously sealed history
unless it was already included. Existing ciphertext is never silently rewritten.

## Configure and run

All paths below are placeholders, not discovered user settings. Existing private
files require owner-only permissions or the supported native Windows ACL profile.
The cloud config, keys, Vault, sync config and state directory must not overlap.

```sh
python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/native-sync.json configure \
  --vault /absolute/private/data/memory.sqlite3 \
  --identity /absolute/private/signing/identity.json \
  --trust-store /absolute/private/signing/trust.json \
  --state-directory /absolute/private/native-sync-state \
  --backend native-drive \
  --drive-config /absolute/private/cloud/drive.json \
  --encryption-key /absolute/private/cloud/encryption.json \
  --recipient-key /absolute/private/cloud/encryption-public.json

python3 /absolute/source/memory_vault_sync.py \
  --config /absolute/private/control/native-sync.json flush --maximum-seconds 30
```

Repeat `--recipient-key PATH` for another intended decryption recipient. Add
`--peer SIGNING_KEY_ID/STORE_ID` for each independently trusted incoming stream;
an empty peer list sends only. The receiving device configures its own encryption
private key and public descriptor. `receive` is receive-only; it needs the
decryption key but does not load the private signing key. `status` needs neither
private key and performs no network operation. See [SYNC.md](SYNC.md) for client
binding, optional automatic triggers, stopping, trust and publication review.

`configure` reads the explicitly selected Drive configuration/public descriptors,
but not the encryption private key or OS credential. A worker requires the
matching local recipient key before constructing its Drive client. The explicit
root is frozen in the sync binding; changing the destination or encryption-key
path requires a new state directory. Existing rclone `crypt` and encrypted
configuration/password-reference behavior remain unchanged.

## Confidentiality, retries and recovery boundaries

HTTPS protects the connection, **not stored content**. This backend additionally
uses JWE General JSON (`ECDH-ES+A256KW`, `A256GCM`) from the network crypto module.
Its authenticated backup context is independent of network rosters and binds
opaque bucket/object labels, part and content type. It encrypts complete original
bytes and an independent locator; cloud names never contain raw local paths or
memory text. Ciphertext sizes, object count and opaque routing labels remain
visible. No old share-format encryption provider is substituted.

Each original is at most 4 MiB; its bounded JWE is at most 6 MiB and uses at most
two 4 MiB ciphertext blobs. An encrypted-locator commit manifest is published
last. Duplicate/ambiguous cloud names fail closed. Upload success requires exact
remote read-back, decryption and original-byte equality before the existing
signed queue advances. Partial/uncertain uploads retain a private ciphertext-only
retry stage; immutable chunks are reconciled on the next explicit window. The
usual local exchange still holds protected plaintext signed capsules/fragments.

Defaults remain 16 file operations, 32 MiB and 45 seconds per window. Native Drive
requires at least 8 file operations and 24 MiB to accommodate a maximal object's
upload and read-backs. It also uses the provider's 256-request/deadline cap.
Metadata traffic is not included in the payload-byte accounting. A completed
window is not eventual-delivery, continuing cloud availability or remote-AI-use
proof, and it never deletes cloud history.

Offline client-state backup accepts `native-drive/` as a protected **excluded
transport cache**, like rclone cache/tmp. Retry ciphertext is not archived or
activated; a newly authorized stream rebuilds it from selected canonical memory.
Old client-backup exclusion manifests remain readable. Memory-only snapshots
and current client-state snapshots do not automatically capture network-v1
outbox/inbox state, encryption keys or credentials. They are not complete endpoint
recovery packages. Restore still creates a new Vault/store identity and requires
new sync state; do not attach old send cursors to the restored copy.

## Evidence scope

`tests/test_network_cloud_compat.py` uses temporary keys and synthetic data with
real JWE and signed admission, replacing only Drive HTTP. Its three selected
cases cover interrupted upload/resume and another recipient's exact recovery,
4 MiB splitting and tamper refusal, missing/locked credentials or keys, fixed
root binding, and preservation of rclone config/binding. It also checks that the
existing offline backup inventory excludes native ciphertext staging. This is
not real OAuth, real cloud upload/download, private backup access, power-loss,
Windows-device, throughput, installation or full-suite validation.
