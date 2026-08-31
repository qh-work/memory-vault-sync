# Independent network-v1 cryptography and control candidate

This optional Node TypeScript package implements the existing Memory Vault
network-v1 envelope without invoking Python. It is separate from the zero
dependency HTTP SDK in the parent directory. It uses `jose` 6.2.10 for X25519
ECDH-ES+A256KW / A256GCM JWE and Node's crypto provider for Ed25519 signatures,
SHA256 and private/public key pair checks. It has no Python bridge or protocol
adapter and does not create identities, files, databases or network connections.

These are components for a future independent peer, **not a complete
independent peer or relay/storage client**. It is not an external security audit.
The host must supply already provisioned keys in memory and authenticated trust
and recipient associations. It must integrate the control checks into operation
authorization and enforce enrollment, nonce freshness, replay/idempotency,
quotas, durable state and relay authentication. Successful decryption is not permission to execute memory
content. Plaintext and keys remain in the host process; JavaScript garbage
collection cannot guarantee erasure or protect against a compromised host.

## Use

The package is private and unpublished. Install its exact dependency in an
isolated checkout with `npm ci --ignore-scripts --no-audit --no-fund`; the lock
contains the official npm artifact and SHA512 integrity. It adds no dependency
to the separate HTTP SDK. Source runs on Node 22.19+ with built-in TypeScript
stripping (`node --experimental-strip-types` where required). Consumers that
compile TypeScript need their own compiler and Node type declarations; this
package does not bundle a build toolchain. Browser, Deno and Bun support is not
claimed or tested because this implementation uses Node's crypto provider.

```ts
import { seal, verify, open, canonicalBytes } from './crypto.ts';

// All four values below come from the host's authenticated provisioning/control:
// signingIdentity: existing universal-memory-identity/v1 private document
// encryptionIdentity: existing memory-vault-network-encryption-identity/v1
// trustedSigningKeys: explicit universal-memory-public-key/v1 descriptors
// recipients: [{ signing_key_id, encryption_key }] selected from current roster
const envelope = await seal(originalMemoryBytes, {
  signer: signingIdentity, network_id: 'example-network', message_id: 'message-1',
  recipients, roster_version: 1, roster_sha256: authenticatedRosterHash,
  created_at: hostUnixSeconds,
});
const wire = canonicalBytes(envelope);
verify(wire, {
  network_id: 'example-network', trusted_signers: trustedSigningKeys,
  recipient_bindings: recipients,
});
const unchangedBytes = await open(wire, {
  network_id: 'example-network', trusted_signers: trustedSigningKeys,
  recipient_bindings: recipients, identity: encryptionIdentity,
});
```

`seal`, `open`, `encryptBytes` and `decryptBytes` are asynchronous. `verify`,
`document`, `documentSha256`, `canonicalBytes`, `validateJwe`,
`validateSigningPublic` and `validateEncryptionPublic` are synchronous. The shared
`signMessage` / `verifyMessage` functions provide the same existing Ed25519
message-proof domain for both envelopes and control documents.
`verify` returns the checked route and JWE without the proof, matching the Python
core's verified payload. It verifies the signature using only `trusted_signers`.
It does not discover or enroll a signer. `recipient_bindings`, when supplied,
checks the exact signing-recipient and encryption-recipient sets against the
host-supplied associations. Without it, verification checks the signed route and
recipient counts only, matching Python's crypto layer; the caller must perform
the roster association check before accepting a delivery. A caller-supplied
association is not itself proof that a roster is authentic or current.

Use raw UTF-8 `Uint8Array` input for received JSON documents. Passing a document
through `JSON.parse` first loses evidence of duplicate keys or unsafe integers;
no downstream validator can recover that evidence. For in-memory host objects,
only plain, dense JSON data is accepted (no getters, symbols, prototypes, sparse
arrays or `toJSON` conversion). Inputs are copied before asynchronous provider
calls. Output is a fresh document/byte array; the host owns its subsequent use.
`NetworkCryptoError.code` is content-free and suitable for controlled error
mapping; provider errors, keys and plaintext are not included. This package
does not log or retry.

## Byte and validation contract

* Ed25519 signing and X25519 encryption keys have distinct existing schema/key
  IDs. Signing descriptors use canonical padded standard Base64; encryption
  descriptors use canonical unpadded Base64url. Private documents must derive
  the advertised public key. Supplying an unrelated public key is rejected.
* General JSON JWE uses only ECDH-ES+A256KW and A256GCM, with the exact protected
  header, external authenticated route, unique recipients and strict field sets.
  The Ed25519 outer proof covers the full JWE and route. Unknown fields,
  compression, different algorithms, malformed encodings and duplicate names
  are rejected. Public routing metadata and recipient count are not confidential.
  jose 6.2.10 places an ephemeral key in the protected header on its single
  recipient shortcut. To preserve network-v1's fixed protected header, this
  module uses the public multi-recipient builder with two wraps to the **same**
  authorized public key, then discards the redundant wrap before validation and
  the outer signature. No extra destination is introduced and authenticated
  ciphertext/AAD are not rewritten. This adds one wrap for single-recipient sends
  and is a workaround for this [library version's implementation](https://github.com/panva/jose/blob/v6.2.10/src/jwe/general/encrypt.ts),
  not an additional requirement of network-v1.
* Plaintext is an opaque byte array, at most 4 MiB, framed with the existing
  magic, unsigned 64-bit big-endian length and SHA256. It is never decoded or
  recanonicalized. Signed/unsigned 64-bit numbers inside memory bytes therefore
  survive unchanged. The length is read and compared using `BigInt`.
* Outer/control JSON retains the Python canonical profile: ASCII object keys,
  ordinal key ordering, unescaped UTF-8 Unicode, no normalization, and safe
  integer numbers only (±9007199254740991). Decimal/exponent forms in raw JSON,
  unsafe integers, invalid UTF-8, BOM, lone surrogates and nesting over 24 are
  rejected. This is not RFC 8785/JCS and does not change inner memory canonical
  rules. Negative zero in an integer token canonicalizes to zero.
* Limits match the Python carrier: 6 MiB serialized envelope, 16 KiB context,
  1 KiB protected header, 1–32 recipients; fixed IV/tag/wrapped-key/curve sizes.

## Reproducible synthetic verification

Run `tests/test_network_typescript_crypto.py` with the repository's optional
Python network dependencies and Node available. The test uses an already
installed `jose` in this package, or the explicit
`MEMORY_VAULT_JOSE_MODULE=/absolute/path/to/jose/dist/webapi/index.js` test setting.
It copies this module into a private temporary fixture and links that existing
dependency there; production code never loads dependencies from this variable.
No package is installed by the test and no real identity or memory is read.

The test must report a skip when its explicit Node/jose prerequisites are absent;
a skip is not interoperation evidence. It checks actual Python→TypeScript and
TypeScript→Python signed, multi-recipient encryption, unchanged binary/Unicode
and 64-bit memory bytes, full-size payloads, key-pair mismatch, signature/route
tampering, untrusted signers, malformed JWE, duplicate fields, unsafe integers,
and authenticated invalid byte frames. Runtime evidence does not constitute a
static TypeScript compiler check or validation of another operating system.

Validation on 2026-08-31 used macOS arm64, Node 22.19.0 and CPython 3.11.4:
all 8 tests in the new module fixture passed; running them alongside the original
crypto/interop fixture passed all 9 tests. The official jose tarball's SHA512
matched the lock and registry metadata, and its 90 files matched the installed
dependency used by the tests. No package install or runtime upgrade was performed.
The tarball SHA256 was
`6a081a81561122e7184ed7ec956d02441c0a568e2fb33209247c070dad12a136`.

Dependency source: [jose 6.2.10 official registry metadata](https://registry.npmjs.org/jose/6.2.10)
and [upstream project](https://github.com/panva/jose).

## Native control module

Import `./control.ts` directly or the package's `./control` export. The default
package export remains the crypto module, and the sole dependency remains the
locked `jose` version. Control imports the same strict JSON, descriptor and
signature implementation from `crypto.ts`; it has no Python subprocess or bridge.

The API deliberately matches `memory_vault_network_control.py` and the actual
Python client/relay checks:

| API | Verified condition |
| --- | --- |
| `verifyRoster`, `validateMember` | Pinned issuer signature, exact schema, network, genesis/previous hash, version, sorted unique Ed25519 members and unique X25519 keys, active/revoked status and sorted send/receive scopes |
| `verifyStatus` | Pinned issuer signature, exact expected nonce, roster document hash/version, maximum 300-second interval and expiry, at most 30 seconds future clock skew |
| `verifyCurrentRoster(roster, status, options)` | Both signatures plus fresh status binding; optional persisted/recovery lower bounds reject rollback, same-version forks and wrong immediately consecutive hash links; optional local identity must match both public keys of an active member |
| `authorizedMember(current, keyId, action, { now, expected_identity? })` | Active membership, send/receive scope, unexpired status and optional exact local dual-key association |
| `verifyInvite`, `verifyInvitationPackage` | Issuer, network, candidate dual keys, scope, at most seven-day invite interval, roster and handoff commitments; package verification also checks candidate membership in the invited roster and optionally the verified current roster |
| `signRequest`, `verifyRequest` | Existing signed join/messages/poll/ack/status request schema, network/action/request ID/body and 300-second maximum interval |
| `openJoinChallenge`, `verifyJoinProof` | Existing encrypted 32-byte X25519 challenge, network/invitation/challenge binding and candidate Ed25519 request signature; answer commitment is SHA256 of its ASCII Base64url form |

All clocks, issuer keys, local keys, request IDs, and expected nonces are supplied
explicitly by the host. An incoming member descriptor never becomes an issuer.
An issuer key must be pinned by independent trusted provisioning; a signature
does not establish whether the host selected the right issuer.

```ts
import { verifyCurrentRoster, authorizedMember, signRequest } from './control.ts';

const current = verifyCurrentRoster(receivedRoster, receivedStatus, {
  network_id: networkId, issuers: pinnedIssuerKeys, nonce: outstandingFreshNonce,
  now: hostUnixSeconds, previous_roster: persistedSignedRoster,
  local_identity: { signing_key: localSigningPublic, encryption_key: localEncryptionPublic },
});
const peer = authorizedMember(current, recipientSigningId, 'receive', { now: hostUnixSeconds });
const poll = signRequest({
  signer: localSigningIdentity, network_id: networkId, action: 'poll',
  request_id: hostRequestId, body: { cursor: 0, receipt_cursor: 0, limit: 1, maximum_bytes: 8192 },
  issued_at: hostUnixSeconds, expires_at: hostUnixSeconds + 60,
});
```

`verifyCurrentRoster` returns a deeply frozen in-memory verified snapshot.
`authorizedMember` accepts only a snapshot produced by this module instance;
serializing and reparsing it loses that verification capability. Persist the
signed roster/status documents and independently verify them again with a new
nonce when refreshing. Expired rosters may remain current only when separately
attested by fresh issuer status. Low-level `verifyRoster(..., {allow_expired:true, ...})`
is for inert inspection and is not active authorization.

For roster transitions the Python client rejects lower versions, any different
signed document at the same version, and a wrong previous hash when advancing
exactly one version. A fresh issuer status may advance across a larger version
gap; this is the existing rule, not a claim that every missing chain link was
downloaded or verified. A recovery anchor contains the existing
`minimum_roster_version`, `last_verified_roster` and `last_roster_sha256` fields;
it is checked but never activates restored keys or changes host recovery flags.

The host must generate unpredictable fresh nonces and atomically compare/store
the previous roster, replace old current snapshots, and consume nonce and
invitation/challenge state. This stateless module cannot detect reuse across
processes, concurrent rollback races, or replay of an exact previously consumed
invite. It deliberately rejects expired invites/requests: the Python relay's
successful exact-retry receipt lookup belongs in durable peer/relay storage,
not in a permissive verification flag. Revocation/scope changes apply through
the latest verified current snapshot; do not keep authorizing with older snapshots.

Invitation package verification returns decrypted handoff bytes only; it neither
imports them into a Vault nor grants execution rights or admits the member. Node
directories, node incarnations, HTTP transport, quotas, replay databases and
atomic admission are outside this control module and must be checked by the
complete peer. Limits remain the current Python profile (1 MiB control document,
512 KiB request body, 1–256 roster members); this does not claim a 1,000-member
network, unlimited collective storage, or a complete independently running peer.

`tests/test_network_typescript_control.py` uses the same explicit installed-jose
test setting as the crypto tests. It checks Python-signed valid and adversarial
control documents in the TS implementation, signed requests in the reverse
direction, nonce/clock boundaries, 256-member limits, revocation/dual-key changes,
fork/rollback/recovery anchors, invite/handoff and encrypted join proofs. No keys
or real memory are discovered, and no dependencies are installed by the test.
On 2026-08-31 the 7 control tests and existing 8 independent crypto tests passed
together (15 tests, macOS arm64 / Node 22.19.0 / CPython 3.11.4). This is runtime
interop evidence, not a static TypeScript compiler check or an external audit.
