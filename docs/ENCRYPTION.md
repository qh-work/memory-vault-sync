# External encryption, device trust and ciphertext catalogs

These restore the taskless v0.21 provider boundaries. **No production encryption
provider, device authority, recovery ceremony or encrypted replication service
is configured by default.** The normal canonical records and signed delta
transfer work independently of these optional contracts.

The modules are in-process APIs for an operator's reviewed integration:

- memory_vault_crypto: authenticated file encryption/decryption boundary;
- memory_vault_device_trust: enrollment, revocation, key epochs and recovery
  threshold transitions;
- memory_vault_encrypted_replication: externally signed, chained ciphertext
  catalogs and a bounded ciphertext-only receiver.

They are not memory tools. There is no provider to import from a packet, code
downloader, automatically generated production key or memory-based policy
command. The integration supplies independently reviewed provider objects.
Default unconfigured providers fail closed.

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
providers are not silently treated as wire-compatible: explicitly decrypt and
verify old shares, convert records, then reseal. v0.21's default production
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
