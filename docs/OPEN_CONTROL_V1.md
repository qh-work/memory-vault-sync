# Open control v1: signed routing and finite contact leases

Status: initial implementation contract, **not a completed open communication
network or Internet-scale validation**. This batch implements control discovery
and public contact indexing. Mailbox admission, first-contact knocks, message
delivery and enumeration repair remain separate work. The released private
network profile remains unchanged.

## Common encoding and meaning

Every signed document is exactly `{payload, proof}`. `proof` is the existing
Ed25519 message proof over the existing canonical payload encoding. Signature
verification checks the key descriptor and proof; it neither enrolls the key
in Vault trust nor grants access. A signed contact's X25519 key is a signed
binding, not proof that its signer currently possesses that private key.

Use the existing strict network JSON parser: reject duplicate fields, floats,
out-of-range control integers, unknown fields and excessive nesting. Safe
integers exclude booleans. The complete signed node/contact/lease is at most
4,096 bytes; the complete signed request/response is at most 65,536 bytes.
Every URL is at most 512 characters, contains no credentials/query/fragment,
and uses HTTPS except explicit loopback HTTP. Permission to dial an address
still belongs to the caller's destination policy; parsing a signed URL does
not authorize a connection or an HTTP redirect.

Routing coordinates are hexadecimal SHA-256 of UTF-8
`memory-vault-open-routing/v1`, a zero byte and the full existing lowercase
Ed25519 key ID. Contact lookup keys use the distinct domain
`memory-vault-open-contact/v1`, then the same zero byte and key ID.
Neither derivation creates a new identity. Distances use full 256-bit arithmetic.

## Descriptors

The payload schema is `memory-vault-open-control/v1`. All fields listed for a
kind are required; no other fields are accepted.

| Kind | Payload fields in addition to `schema_version` and `kind` |
| --- | --- |
| `node` | `signing_key`, derived `coordinate`, `base_url`, `storage_epoch`, `roles`, `revision`, `status`, `issued_at`, `expires_at` |
| `contact` | `signing_key`, `encryption_key`, `revision`, `status`, `allow_discovery`, `endpoints`, `issued_at`, `expires_at` |

Signing and encryption descriptors retain their existing formats. Revisions
start at 1. Status is `active` or `revoked`. Node roles are a nonempty sorted,
unique subset of `directory`, `router`; they are self-declarations, not leases.
Each contact has at most four unique endpoints. Each endpoint is exactly
`{kind: "node", node_key_id, base_url, storage_epoch}`. It names a possible
node, not a mailbox, delivery grant or permission to read memory. Future pointer
kinds are unsupported. No free-form body, memory ID, evidence, invitation,
execution instruction or private key is part of this index schema.

Descriptor validity is at most 3,600 seconds. A verifier uses its own clock,
allows at most 30 seconds of future clock skew, and rejects `expires_at <= now`.
Copying never extends owner validity. `allow_discovery` must be a boolean;
only active opted-in contacts can be returned publicly. A signed withdrawal
or revocation can advance the local security checkpoint without exposing its
contact body through public GET.

## Requests, challenge responses and exact action bodies

Request payload schema: `memory-vault-open-request/v1`. Exact fields:
`schema_version`, `action`, `request_id`, `signer`, `node_key_id`,
`storage_epoch`, `issued_at`, `expires_at`, `body`.
`signer` is the requester's existing public Ed25519 descriptor. The intended
node key and persisted storage incarnation are mandatory. Request IDs are
bounded existing opaque identifiers; callers generate fresh unpredictable
IDs for live possession challenges. Validity is at most 60 seconds.

| Action | Exact request body | Successful response body |
| --- | --- | --- |
| `hello` | `{node: signed_node_or_null}` | `{node: signed_node}` |
| `find` | `{target: hex64, view: "general" or "directory"}` | `{nodes: [signed_node, ...]}`, at most eight unique node keys |
| `get` | `{key: contact_lookup_hex64}` | `{state: "found", contact, lease}` or `{state: "not_found" or "revoked" or "conflict"}` |
| `put` | `{contact: signed_contact, lease_seconds}` | `{lease: signed_lease}` |
| `renew` | `{contact: signed_contact, lease_id, lease_seconds}` | `{lease: signed_lease}` |

An advertised hello node must be signed by the requester itself. Incoming
advertisements and signed find candidates are introductions only. Active
routing admission requires the caller's separate live signed response check;
hello handling must not create an automatic reciprocal callback loop.

Response payload schema: `memory-vault-open-response/v1`. Exact fields:
`schema_version`, `request_id`, `request_sha256`, `node_key_id`,
`storage_epoch`, `issued_at`, `expires_at`, `body`.
The digest covers the **complete original signed request**, including its
proof. Verification requires that request and the expected signed node. The
response must match request ID, digest, node key and incarnation; use the
local clock, a maximum 60-second window and no expiry beyond the request.
This challenge proves current Ed25519 signing ability, not X25519 possession,
honesty, a unique person or independence of an operator.

Failure bodies are exactly `{error: {code, retryable}}`: bounded lowercase
machine codes and a boolean, without exception text or private diagnostics.
Unknown actions, body fields and future opaque record kinds are rejected.

## Node-local durable index obligations

The index is explicitly enabled by its operator and otherwise closed. It uses
namespaced `open_*` tables in a caller-provided existing transport SQLite
connection, not a new Memory, identity or experience database. The node key and
storage incarnation are persisted and must agree on restart. No network I/O
runs inside the index's short writer transaction.

PUT and RENEW requesters must be the signed contact owner. Renewal requires
the existing unexpired lease ID and identical signed contact bytes; a changed
contact uses PUT. Each signed lease payload has schema
`memory-vault-open-index-lease/v1` and exactly `node_key_id`, `storage_epoch`,
`owner_key_id`, `contact_sha256`, `contact_revision`, `lease_id`, `request_id`,
`request_sha256`, `issued_at`, `expires_at` in addition to its schema field.
The node signs its own finite storage obligation only. Lease validity is at
most 600 seconds and cannot exceed the owner's contact expiry. A checkpoint
lease for a revoked/withdrawn contact is not evidence of public availability.

Default explicit-enabled quotas are 128 retained owner checkpoints, 2 MiB of
charged/reserved metadata, 512 recent mutation requests and a maximum
600-second lease. These are node-local configurable allocations, not global
population limits. Quota includes original signed contacts, signed receipts,
replay results and security checkpoints. Reserve two maximum-size descriptor
slots per owner so a same-revision fork can be durably blocked even when
unreserved capacity is full; report reservation separately from physical bytes.
Capacity failure rolls the entire attempted mutation back, never saves only
part of its advertised obligation. Retried identical requests reuse the exact
signed lease; same requester/request ID with different bytes is rejected.

Local highest owner revisions outlive expired public leases. Same-revision
different signed bytes retain both bounded originals and block public lookup;
no arrival-order winner. A subsequent higher owner-signed revision does not
automatically resolve an observed fork during its retained security horizon.
Revocation and withdrawal remove public lookup
while retaining the signed checkpoint. Floors are retained for at least
3,690 seconds after observation, covering the maximum descriptor validity,
request window and clock allowance; they cannot be evicted as ordinary cache
entries. Expired replay rows and leases can be reclaimed independently.
This is a local observation floor, not proof of a globally latest record.
Loss or restoration of security state needs separate freshness handling; this
batch does not add an open-profile backup/restore activation mechanism.

Clients and HTTP nodes use `OpenCheckpoints` on that same transport connection
for node/contact observation floors, separately from ordinary route caches.
Its hard limits are 4,096 retained floors and at most 64 MiB reserved metadata.
Each floor reserves both original signed records so full capacity cannot hide
a newly observed fork. `accept()` verifies the descriptor and returns an active
nonconflicting payload; a valid revocation or first fork is committed before
its typed refusal. Restart preserves lower-revision rejection. Neither cache
eviction nor a merely higher revision clears a retained fork. This local
security observation still does not establish trust or global freshness.

## Interfaces and verification

Python control exports `issue_node`, `verify_node`, `issue_contact`,
`verify_contact`, `sign_request`, `verify_request`, `sign_response`,
`verify_response`, `issue_lease`, `verify_lease`, `coordinate`, `contact_key`.
Verification returns the checked payload. The index exposes
`OpenIndex(connection, signer, node, enabled=False, ...)`, `initialize()` and
`handle(signed_request, now=None)`, returning the strict response body. It owns
its transaction; do not invoke it inside another active writer transaction.
The HTTP owner signs the response only after the durable transaction returns.

Native TypeScript exposes the equivalent control operations from
`clients/typescript/network/open-control.ts` and `OpenCheckpoints` / `OpenIndex`
from `open-state.ts`. Both state classes receive the caller's existing
`DatabaseSync` connection and use the same `open_*` tables as Python. Their
`accept(document, {now})` and `handle(request, {now})` methods retain the same
transaction, error and signed-byte semantics. This is not a TypeScript HTTP
server or an open messaging implementation; no subprocess or new dependency
is required by the native state module.

Focused synthetic checks belong to `tests/test_open_control.py` and
`tests/test_open_index.py` and `tests/test_open_state.py`; run them with the
existing network dependencies. `tests/test_open_typescript_state.py` alternates
both implementations against one protected transport database and checks
restart, retained forks, exact leases, quotas and atomic rollback.
Record actual results in the implementation validation report. These unit
tests alone do not establish multi-hop routing, three replicas, cross-model
communication, sustained-load performance or Internet-scale operation.
