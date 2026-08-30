# External encryption, device trust and ciphertext catalogs

These restore the taskless v0.21 provider boundaries. **No production encryption
provider, device authority, recovery ceremony or encrypted replication service
is configured by default.** The normal canonical records and signed delta
transfer work independently of these optional contracts.

The provider boundaries are in-process APIs for an operator's reviewed integration:

- memory_vault_crypto: authenticated file encryption/decryption boundary;
- memory_vault_device_trust: enrollment, revocation, key epochs and recovery
  threshold transitions;
- memory_vault_encrypted_replication: externally signed, chained ciphertext
  catalogs and a bounded ciphertext-only receiver.

They are not memory tools. There is no provider to import from a packet, code
downloader, automatically generated production key or memory-based policy
command. The integration supplies independently reviewed provider objects.
Default unconfigured providers fail closed.

## Explicit metadata commands

The full client also restores v0.21's operator-facing trust initialization,
trust status and envelope inspection. These commands are separate from MCP
memory tools and do not resolve a client configuration or a default Vault:

```bash
python3 /absolute/path/memory-vault-sync/memory_vault_client.py device-trust init \
  --state /absolute/private/device/state.json \
  --installation-fingerprint lab-installation \
  --device-fingerprint lab-device --public-key-fingerprint lab-public-key
python3 /absolute/path/memory-vault-sync/memory_vault_client.py device-trust status \
  --state /absolute/private/device/state.json
python3 /absolute/path/memory-vault-sync/memory_vault_client.py envelope capabilities
python3 /absolute/path/memory-vault-sync/memory_vault_client.py envelope verify \
  --source /absolute/private/exchange/share.envelope
python3 /absolute/path/memory-vault-sync/memory_vault_client.py envelope verify \
  --source /absolute/private/exchange/old-share.envelope --legacy-v021
```

These are setup/review examples, not executed release evidence. `init` requires
an explicit new private state path and opaque operator-supplied fingerprints;
it never replaces existing state, generates a key, proves key possession,
enrolls a record signer, configures a TrustAuthority or grants host permission.
`status` validates the protected file and reports its state hash, generation,
epochs and device counts without creating or changing any file. The local
metadata file is bounded to 1 MiB. Neither command transfers memory.

`verify` streams and checks the selected frame and complete ciphertext hash,
not encryption authenticity. It invokes no provider and opens no plaintext.
The result explicitly reports `authenticated: false`, `provider_invoked: false`
and `memory_changed: false`. A valid frame alone does not show that it contains
real encrypted data. `--maximum-seconds` bounds inspection to 1–300 seconds
(300 by default); file/OS calls are not hard-real-time deadlines.

Without `--legacy-v021`, only `universal-memory-share-envelope/v1` is accepted.
The explicit old mode checks the actual eight-field `memory-share-envelope/v1`
format, including its 2 GiB ciphertext bound and old zero-size/zero-epoch
metadata range. Old envelopes have no authenticated plaintext binding; this
compatibility reader is never used for new decryption or ciphertext-catalog
admission. The legacy inspection preserves the old integer epoch range and is
an operator result, not a canonical memory record.

## Authenticated encryption

CryptoProvider declares a profile, version and recipient fingerprint. Its two
file methods take an explicit key epoch and associated_data bytes. A real
provider must authenticate both ciphertext and those exact bytes with a
reviewed construction. It supplies secure key storage, resource limits and
failure handling. An interface cannot certify an arbitrary Python callback.

seal_with_provider verifies a complete share, then binds its plaintext
hash/size, selector hash, provider/version, recipient and epoch. After provider
encryption, it publishes a new universal-memory-share-envelope/v1 file with
only a bounded header and ciphertext. No plaintext fallback exists.

open_with_provider verifies the ciphertext, invokes the independently selected
matching provider, decrypts privately, checks the full share and every binding,
then atomically publishes a new plaintext file. It never automatically imports
or admits the memory. read_envelope checks framing/ciphertext identity only;
it cannot establish encryption authenticity, recipient possession or truth.

The retained capability_scope_sha256 name means **content selector hash**, not
an execution capability, permission, Task owner or access-control list. This
new envelope requires authenticated associated data. Old memory-share-envelope/v1
providers are not silently treated as wire-compatible. Beyond the metadata-only
inspection above, a separately reviewed old integration must decrypt and verify
old shares before explicit record conversion and resealing; the new provider API
does not perform that migration. v0.21's default production
provider was unconfigured; no deployed encryption service is invented here.

## Device trust and recovery

The retained memory-device-trust/v1 state machine concerns transport keys, not
ownership of memories. Enrollment, revocation, key-epoch rotation and recovery
threshold changes require a proof and an explicitly supplied TrustAuthority.
The default rejects every change. Transitions bind previous state/hash and
generation. Neither a memory nor an incoming catalog can alter this authority.
Revocation limits future admission/publication, not an offline user's policy
or the lifetime of historical memory.

Recovery descriptors describe an external ceremony; they are not recovery
secrets or a working recovery service. A descriptor or remembered goal cannot
enroll a new device. The ordinary [Ed25519 record registry](TRUST.md) remains a
separate, usable local trust mechanism.

## Ciphertext catalogs

universal-memory-encrypted-catalog/v1 requires an independently supplied
CatalogSigner. Its independently configured `public_key_fingerprint` must
match the enrolled public key for the claimed publisher; an active device label
cannot legitimize another or revoked signing key. It binds exact header and
ciphertext hashes, current external trust state,
publisher, increasing generation and previous hash. Unknown publishers,
profile mismatches, replay, broken chains and missing signing providers fail
closed. A catalog checksum is not a signature.

The metadata budget defaults to 64 MiB, separately from the 2 GiB total
ciphertext and one-million-entry bounds. An operator can explicitly raise
`maximum_metadata_bytes` up to 2 GiB, with the associated memory cost: this
external signing API still receives canonical metadata bytes, not a streaming
cryptographic API. `maximum_seconds` defaults to 300 (1–3600) and covers directory
hash/copy work across entries. The embedding integration must bound a synchronous
external signer/provider itself; the library cannot forcibly interrupt it.
Paths are portable, distinct and cannot collide with the receipt or each other
as file/directory prefixes. Noncanonical Base64 signatures are rejected.

The receiver copies checked ciphertext to a content-addressed catalog
directory without replacing different existing bytes. RECEIVED.json is
written last; partial directories remain retryable, not complete receipts.
It opens no plaintext and carries no private keys. Its receipt/head is
process-local, as in the v0.21 provider contract: the embedding runtime must
persist it independently. Do not confuse this optional contract with the full
client's durable [sync queue](SYNC.md).

Memory is not Instruction; Instruction is not Authorization; Authorization is
not Execution. Provider proofs cannot create an execution channel. Public
synthetic acceptance material is provided; no live provider test, production
key ceremony or cross-device success is claimed from source inspection.
