# Explicit first contact control

Implementation candidate, pending independent review and source-bound cloud
evidence. This document does not supersede the complete open-network acceptance
contract. Open encrypted message transmission remains unsupported in this slice.

The profile `memory-vault-open-contact-control/v1` is independent of directory
index leases and the private network profile. Python and native TypeScript use
the existing Ed25519 identities, independent X25519 keys, actual mature JWE
implementations, existing bounded HTTP transport and protected `network.sqlite3`.
No Vault record, author trust, acknowledgement or model execution is created.

## Explicit flow and authority

1. An already-running B explicitly requests a finite knock resource lease from
   owner-enabled R. B signs an active policy binding its two keys, R/epoch,
   concrete lease/resource, revision, expiry and pending capacity, and publishes
   its chosen public contact endpoint. B can then go offline.
2. A created afterward discovers B through response-derived signed routing.
   It resolves R's signed descriptor through that same bounded overlay and
   checks the endpoint against B's signature before fetching the knock policy.
   Neither B's contact nor a directory lease is resource or delivery authority.
3. A signs a fixed `contact.request` with no free text, attachment, Memory,
   callback, arbitrary encrypted payload or tool instruction. The only current
   request class is `message`. R encrypts a random 32-byte challenge to A's
   X25519 key with `ECDH-ES+A256KW` / `A256GCM`. The signed challenge and its
   authenticated context bind the original request, purpose, A/B, R/epoch and
   policy. The submitting RPC also requires A's Ed25519 signature.
4. R commits the request, result reservation and replay identity together.
   `contact_queued` means R stored a control request. It does not mean B read,
   accepted, understood or received a message. Replays use the logical request
   digest; each fresh 60-second RPC envelope is independently bound.
5. B explicitly polls up to four requests while already running. Approval
   requires a separately allocated delivery resource lease. R reserves its real
   finite item/byte budget, and a decision transaction binds that reservation
   exclusively to one request. A rejected request contains no grant.
6. A obtains a fresh purpose-specific challenge and pulls its own result. It
   verifies B's signature, original request and both subjects' keys, exact
   resource node/epoch, resource, `message.store` operation and deadlines. R
   rechecks its current lease before returning an approval. No reverse chat
   grant or callback is needed. A valid grant remains separate from a supported
   message carrier: `send` and `receive` still return `open_messaging_unsupported`.

The grant's concrete resource lease is a finite reservation, not a wildcard or
placeholder identifier. In this initial slice it belongs to the same discovered
resource node as the knock queue. A later message implementation must debit that
reservation and independently verify the grant; this profile alone does not
store ciphertext or prove delivery. It does not confer Vault access or trust.

## Wire contract

Every document has exactly `payload` and `proof`, and every payload has a fixed
field set. The common fields are `schema_version`, `kind`, `signing_key`,
`issued_at`, `expires_at`. Unknown fields, duplicate JSON keys, unsafe or boolean
control integers, invalid key descriptors, signature domains and deadlines are
rejected. Existing canonical Memory bytes and int64 semantics are unaffected.

| Kind | Purpose and required binding |
| --- | --- |
| `resource.lease` | R signs owner dual keys, node/epoch, unique allocation/resource, `knock` or `delivery`, item/byte limits and time window. |
| `contact.policy` | B signs knock lease ID/digest, resource, epoch, encryption key, revision, active/revoked and max pending. |
| `contact.request` | A signs request ID, its dual keys, B dual key IDs, lease/resource/node/epoch, policy digest and fixed request class. |
| `contact.challenge` | R signs request ID/digest, A/B, policy, node/epoch, challenge ID, `submit` or `result` purpose, and bounded JWE. |
| `contact.grant` | B signs original request ID/digest, A dual keys, B encryption key, concrete resource/node/epoch, fixed operation and embedded resource lease. |
| `contact.decision` | B signs original request/A/B/node/epoch/policy, approved/rejected, fixed reason (`accepted`, `declined`, `unavailable`) and grant or null. |
| `contact.rpc` | Caller signs fresh request ID, node/epoch, action and strictly structured body. |
| `contact.response` | R signs RPC ID/digest, node/epoch and action-specific result or bounded typed error. |

RPC actions are `lease`, `policy.put`, `policy.get`, `challenge`, `submit`,
`poll`, `decide` and `result`. All run through the existing `/open/v1/rpc` path.
The exact field lists and validators are in the two native `open_contact` /
`open-contact` modules. There is no general-purpose payload slot.

## Local accounting, restart and failure

| Bound | Current limit |
| --- | --- |
| Logical request / decision | 4 KiB / 8 KiB |
| Request-result-replay reservation | 12,800 bytes per knock slot |
| Lease / request window | At most 24 hours; policy/request/grant cannot exceed their parents |
| Challenge and RPC window | At most 60 seconds |
| Node resource leases | At most 128 retained leases |
| Knock reservations | At most 1,024 slots / 16 MiB; each lease at most 32 slots |
| Delivery reservations | At most 1,024 items / 64 MiB; each lease at most 32 items / 16 MiB |
| Challenges | At most 128 records / 1 MiB; submit uses at most 75% of each global budget; four per subject with at most three submit records; per-owner submit count at most the smaller of 16 and policy pending capacity |
| Challenge encryption | One submit and one result operation concurrently per process; each has a separate admission slot |
| Owner poll | At most four requests / 16 KiB of request documents |
| Local client controls | At most 128 records, each at most 24 KiB |
| GC | Indexed batches of at most 128 per state table; validity plus 30 seconds retained |

All values are local resource budgets, never global population limits. Nodes
default closed and can choose smaller limits. The node owner explicitly enables
`contact_policy` in its existing node configuration; no remote caller can enable
it, renew an expired promise, wake B, start a model or buy resources.

Short SQLite write transactions re-read actual time after acquiring the writer
lock, and recheck the current persisted epoch, lease, policy and capacity.
Real challenge encryption happens outside the transaction and is followed by a
new check before commit. No native transaction spans an asynchronous wait.
An exact request retry has one record and one reservation; a changed digest
conflicts. One A/B pair can have at most one live pending request. Decided and
expired retained requests still occupy their promised slot until collection.
Owner decisions consume reserved result space and remain possible when request
admission is full. Closing new admission does not itself revoke existing leases.
Consumed challenges still count until collection. Result challenges have reserved
global and per-subject space, and do not compete with submit encryption for the
same process slot. A node configured with only one challenge record intentionally
cannot admit a submit challenge. These are bounded state and encryption guarantees;
the existing shared HTTP admission limits are unchanged and do not promise
availability under an unlimited network flood.

Policies retain revision/withdrawal/conflict state. A new or revoked policy
invalidates requests bound to the previous policy digest; this is an explicit
fail-closed boundary, not automatic migration. GC never deletes long-term Vault
records. A lost state binding requires a different resource epoch and new
permission; restoring old authorizations is unsupported.

Owner poll checks the current policy and lease in the same state transaction,
then examines at most the existing 32 retained requests per lease before
selecting up to four valid requests within 16 KiB. Requests invalidated by a
policy update do not occupy the returned page, but retain their original bytes,
capacity charge and replay obligations until their normal collection boundary.
They cannot be approved under the new policy.

Clients persist the exact logical request and explicit decision before sending.
They atomically reserve the local records needed for each phase before creating
remote resource obligations. Outgoing requests reserve their eventual result
record; approvals reserve both the decision and allocation records. Invalid
controls or insufficient local capacity cause no remote allocation. Exact enable
retries reuse the persisted allocation and policy even when the local 128-record
budget is full; changed revision or allocation parameters require a distinct
explicit operation and are rejected as a conflict for that retry identity.
B can refuse to start a decision when its own local control-record budget is
full. The result reservation guarantees R's storage and A's eventual local save;
it does not guarantee that an owner with no local capacity can begin a decision.
The delivery allocation body is also persisted before RPC, so a crash after R
allocates capacity cannot change the retry digest or double-reserve space.
Owner decision references use the full request digest, avoiding collisions when
two independent senders choose the same request ID.

## Six-operation facade

`connect` retains normal overlay join when no invitation is supplied. The
explicit control branch takes an `invitation` with
`schema_version: memory-vault-open-contact-connect/v1`, one action and its exact
fields:

| Action | Additional fields |
| --- | --- |
| `enable` | `node`, `allocation_id`, `max_pending`, `lease_seconds`, `revision` |
| `request` | `recipient_key_id`; use the outer `connect.request_id` for retries |
| `poll` | `lease_id` |
| `decide` | `request_ref`, `decision`, `max_items`, `max_bytes` |
| `result` | `request_id` |

Every call is explicit. There is no automatic retry daemon, reverse permission,
message delivery or model wakeup. Low-level native APIs expose the same finite
operations for owners that run their own application loop. Unreachable routes,
expired/withdrawn policy, capacity, pending and rejected outcomes remain distinct
from a verified approval.

## Evidence boundary

The new tests exercise strict controls, real dual-key challenge, transactional
rollback/races, restart, result substitution and real local HTTP. Test counts and
source hashes belong to the actual run reports, not this draft contract. Full
encrypted delivery, receipts, sender-offline repair, unknown-person discovery,
independent resource growth, hostile-network availability, real-model continuity,
cross-region fault domains and long-run acceptance remain separate unmet gates.
Local cryptography, sockets and cloud CI do not prove those gates.
