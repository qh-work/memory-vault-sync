# Independent identities and memory trust

The lightweight core and optional trusted integrations use the same independent
memory records. A signature is additional evidence about a signing key; it is
not a memory owner, task binding, instruction, policy, or execution permission.

`memory_vault_trust.py` adds Ed25519 record attestations, separately scoped
message signatures, and an explicitly administered public-key registry. The
core remains standard-library-only. This module uses the maintained
[PyCA cryptography Ed25519 implementation](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/),
not handwritten cryptography. It imports that dependency only when needed and
fails closed if it is missing. Nothing installs packages, generates an identity,
or registers a key merely by being imported or reading a memory.

The optional dependency range starts at the published
[cryptography 50.0.1 release](https://pypi.org/project/cryptography/50.0.1/),
released August 25, 2026, with Python 3.9+ metadata and macOS ARM64 wheels. The
release and provider API were checked read-only on August 30, 2026. The upper
major-version bound is not an audited lockfile or a guarantee about future
dependency updates; no dependency was installed during this implementation.

## Scope and limits

- A verified signature establishes that a registered key signed the exact
  canonical record digest or message digest. It does not establish who controls
  the key, that a claimed model name is genuine, or that the content is true.
- Register public keys after comparing their full `key_id` through a separate
  trusted channel. An incoming memory, attachment, message, or embedded public
  key cannot enroll itself. There is no trust-on-first-use fallback.
- A trusted key must still be treated as a possible source of mistaken or
  malicious evidence. Historical text never becomes an instruction or permission.
- The trust registry and identity are separate files, outside the memory
  database. The database, bundle importer, and model-generated provenance must
  not be used to overwrite or configure them.
- Private files must belong to the current OS user, have mode `0600`, and be
  regular files with one hard link. Symbolic links in selected paths are rejected.
  New parent directories are created as `0700`; existing parents must not be
  writable by another user. Ancestors may only belong to the current user or
  root; a root-owned sticky ancestor is allowed, but the immediate parent must
  be owned by the current user and not writable by others.
- On Windows, the full client uses a separate native storage adapter for local
  fixed NTFS, protected DACLs, verified handles and nonblocking file locks.
  It does not treat `chmod(0600)` as a Windows ACL, fix existing permissions,
  accept reparse/cloud placeholders or elevate. See [PLATFORMS.md](PLATFORMS.md).
  This native path has not been verified by execution on a real Windows host.
- File permissions **do not isolate code running under the same OS account**.
  A compromised same-user agent can read the signing key or edit the trust
  store. For mutually hostile agents, place signing/administration under a
  separately protected OS identity, hardware key service, or constrained broker.
  This module is not that broker and must not be advertised as one.
- Keys are stored unencrypted in the protected identity file. They never enter
  bundles, memory records, normal responses, or logs. Python does not promise
  reliable memory zeroization. Use platform disk encryption and separate key
  protection where the threat model requires it.
- Signatures do not encrypt memory or transport. Keep private content on a
  separately authorized, appropriately protected transport.

## Explicit setup

The following are instructions for the operator. They are not executed during
installation, by a hook, or because another agent asks through a memory record.
Use absolute paths beneath a private directory you control, outside the memory
database directory and any incoming bundle/synchronization folder.

Install the optional requirements in the Python environment selected for the
trusted integration:

```sh
python3 -m pip install -r requirements-integrations.txt
```

Generate a new identity once. This refuses to replace an existing file and
prints only the public descriptor; it never prints the private key:

```sh
python3 memory_vault_trust.py identity-create --identity /absolute/private/identity.json
```

Obtain the same public descriptor later:

```sh
python3 memory_vault_trust.py identity-public --identity /absolute/private/identity.json
```

Save a verified public descriptor as a plain JSON file in a directory you
control. Explicitly register it before accepting signatures from that key:

```sh
python3 memory_vault_trust.py trust-add --trust-store /absolute/private/trust.json --public-key-file /absolute/private/peer-public.json --label reviewed-peer
python3 memory_vault_trust.py trust-status --trust-store /absolute/private/trust.json
```

The local writer's public key must also be explicitly registered by its trusted
integration; possession of a private identity does not automatically enroll it.
Labels are local administrative notes, not authenticated model/human identities.
Status returns only counts and policy flags, without labels, content, or paths.
Validated public-key metadata is reused while the protected registry file's
identity and modification metadata remain unchanged; each lookup still checks
that metadata, so an administrative replacement invalidates the cache. A batch
therefore does not repeatedly parse every enrolled public key for every record.

All CLI errors are JSON with content-free codes. No automatic fallback creates
an identity or writes unsigned records when trusted operation was requested.
`identity-create` and `identity-public` produce the exact public descriptor as
their JSON output; the other commands use a small result envelope. `--help`
also produces JSON, with no environment-derived paths.

## Wire formats

All fields are mandatory and unknown fields are rejected. Base64 uses the
standard alphabet, padding, no whitespace, and the single canonical encoding.
Private/public keys are 32 bytes; signatures are 64 bytes. The key identifier is
`ed25519_` followed by the lowercase SHA-256 hex digest of the raw public key.

Public descriptor:

```json
{
  "schema_version": "universal-memory-public-key/v1",
  "algorithm": "Ed25519",
  "key_id": "ed25519_<64 lowercase hex digits>",
  "public_key": "<canonical Base64 of 32 raw public bytes>"
}
```

Record attestation:

```json
{
  "schema_version": "universal-memory-attestation/v1",
  "key_id": "ed25519_<64 lowercase hex digits>",
  "record_sha256": "<the complete canonical memory-record digest>",
  "signature": "<canonical Base64 of 64 signature bytes>"
}
```

The record must first pass the core's exact schema and hash validation and must
already be in its canonical structural form. The full record hash binds the
text, kind, timestamp, entities, relations, provenance, and hash profile, not
just the visible text. Its memory ID is deterministically derived from this
hash. List normalization or ignored extra data is not accepted during signing
or verification.

The signed record bytes are:

```text
UTF8("UniversalAgentMemory\0record-attestation\0v1\0")
+ canonical_bytes({schema_version, key_id, record_sha256})
```

`canonical_bytes` is the same `canonical-json+sha256/v1` profile as the core:
UTF-8 JSON, sorted string keys, no insignificant spaces, no NaN/infinities,
unescaped Unicode. It is not a claim of RFC 8785/JCS compliance. Other language
implementations must implement this profile exactly, including JSON number
representation; using strings or integers avoids cross-runtime float ambiguity.

Message signatures use a different schema, digest field, and domain:

```json
{
  "schema_version": "universal-memory-message-signature/v1",
  "key_id": "ed25519_<64 lowercase hex digits>",
  "payload_sha256": "<SHA-256 of the entire canonical payload object>",
  "signature": "<canonical Base64 of 64 signature bytes>"
}
```

```text
UTF8("UniversalAgentMemory\0message-signature\0v1\0")
+ canonical_bytes({schema_version, key_id, payload_sha256})
```

A record attestation cannot be reused as a message signature or vice versa.
A forwarding agent's transport signature is not the original record author's
signature. Keep both proofs when forwarding so receivers can check them
independently. The library refuses records above 2 MiB, messages above 64 MiB,
proofs above 2 KiB, excessively deep JSON, malformed IDs, alternate encodings,
and unsupported versions.

## Library boundary

```python
from pathlib import Path
from memory_vault_trust import Identity, TrustStore, TrustError

identity = Identity.load(Path("/absolute/private/identity.json"))
trust = TrustStore(Path("/absolute/private/trust.json"))
trust.require_trusted(identity.key_id)

# record is already a complete current-schema memory record.
attestation = identity.sign_record(record)
signer_key_id = trust.verify_record(record, attestation)

# payload is an application-defined JSON object, separate from its proof.
proof = identity.sign_message(payload)
sender_key_id = trust.verify_message(payload, proof)
```

`verify_record` and `verify_message` both consult the locally administered store
and return the verified key ID. Unknown and revoked keys raise `TrustError`.
Every expected error exposes a content-free `.code`. Reading, loading, status,
and verification do not create trust files or register keys. The constructor
does not create a file either. Administrative writes use an independent
nonblocking lock, a private temporary file, file synchronization, and atomic
replacement. A busy writer returns `trust_store_busy` instead of waiting
indefinitely. The `.lock` file contains no key or memory content.

An adapter may pass `admission="verified"` to the core only after every required
author attestation has been checked against the current independent trust
policy. It must not take that admission label from an incoming payload. Unknown,
unsigned, or invalid records must be refused or quarantined and excluded from
trusted current-state generation; an imported `observed` label is not evidence
of authentication. Calling the low-level Python API directly under the same
account is outside this trust isolation boundary.

## Rotation, revocation, and replay

Rotate by creating a new identity, distributing and explicitly registering its
public descriptor through the trusted administrative channel, then revoking the
old key where appropriate:

```sh
python3 memory_vault_trust.py trust-revoke --trust-store /absolute/private/trust.json --key-id REPLACE_WITH_FULL_OLD_KEY_ID
```

Revoked keys remain as tombstones. `trust-add` cannot reactivate a revoked key.
Verification checks current trust on every call, including for old signatures.
Revocation is therefore conservative: it rejects future admissions from that key
without guessing whether a claimed timestamp predates compromise.

This library does not retrospectively delete or rewrite records already
admitted by a caller. Trusted adapters must pass
`trust_check=trust.require_trusted` when opening the shared core. That connection
filters revoked/unknown signing keys in its views without rewriting history;
an already-open connection may retain its checked-key cache until it reconnects.
Without this callback, a lightweight core can only describe the signature's
trust **at admission**, not current trust. Explicit quarantine is separate
maintenance. `trust-revoke` does not search for or modify every offline vault,
and it is not a network-wide retraction; other receivers must update their own
independently administered trust stores.

Content-addressed memory can make identical-record replay idempotent, but a valid
signature by itself does **not** prove freshness, ordering, completeness, or
protection against rollback. A transport that promises those properties must
bind transfer identity, sequence, predecessor digest, and relevant recipient
scope into its signed message and persist receiver checkpoints separately from
incoming memory. The JSON trust-store revision supports administrative change
detection only; it is not an external anti-rollback anchor. Restoring the whole
local store from an old snapshot also restores that revision.

## Validation status

This implementation was written from the official provider API and statically
reviewed. At the user's request, no test suite, key generation, signing exercise,
private-memory inspection, dependency installation, or live migration was run
as part of this change. It is not an independent security audit. Downstream
review should cover altered record fields and relations, mismatched key IDs,
unknown/revoked keys, replay, cross-domain signatures, unsafe file modes,
symlink/hard-link targets, concurrent administrative writes, interrupted writes,
missing dependencies, malformed/oversized inputs, and platform-specific storage.
