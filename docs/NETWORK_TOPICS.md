# Topic control contract (development, not delivered topic transport)

Topics reference existing network signing identities and select encrypted
recipients. They do not own, partition, delete or rename canonical memories.
No model, task, room or external protocol identity is introduced. This document
defines the control foundation; the six-operation facade, encrypted topic
carrier, relay polling, recovery and node transfer still need integration.
Direct envelope/v1 remains unchanged and must never be relabelled as a topic.
The Python control API is `memory_vault_topics`; its independent TypeScript
counterpart is exported as `memory-vault-network-crypto/topics`. The optional
Python `TopicAuthorityStore` shares the protected authority configuration.
These are low-level control building blocks, not a second set of high-level
agent operations or an assertion that `send` can already deliver to topics.

## Signed documents

Every document uses the existing `{payload,proof}` Ed25519 message wrapper,
strict JSON and existing hash-derived key IDs. Hashes below cover the complete
signed document in existing canonical JSON. No new cryptographic algorithm,
identity file or memory database is defined. Verification pins the expected
issuer key ID supplied from independent configuration; a document cannot
choose its own trusted issuer, even among several configured trusted roots.

All timestamps are nonnegative JSON safe-integer epoch seconds. Signed windows
are 1–300 seconds with the existing maximum 30-second future-clock allowance.
Historical signature inspection may allow expiry, but cannot authorize online
use without a fresh nonce-bound joint status. Signed policy and snapshot each
have a 128 KiB limit; subscription change and topic status each have a 16 KiB
limit. Limits count the signature wrapper and incoming serialized bytes.
Counts and byte limits apply simultaneously, not as capacity guarantees.

Common policy/snapshot fields are `schema_version`, `network_id`, `topic_id`,
`issuer_key_id`, `version`, `previous_sha256`, `issued_at`, `expires_at`.
Version starts at 1 with a 64-zero previous digest. Every later version has
a nonzero previous digest. Same-version differences and rollback are rejected;
an adjacent version must name the full previous document hash. Version gaps
require a newly verified nonce status, never an unsigned caller claim.

`memory-vault-topic-policy/v1` adds `status` (`active` or `revoked`),
`publishers` and `subscriber_grants`. Each grant is exactly
`{member_key_id,grant_id,status}`. Across both lists there are at most 256
grants and all grant IDs are unique. Each list is sorted by the ASCII tuple
`(member_key_id,grant_id)`; each role/member has at most one active grant.
All previous grants remain in later policies with the same role and member.
Revoked grants and revoked topics cannot be revived. Regrant uses a new ID
and requires new subscriber consent; no tombstones are automatically pruned.

`memory-vault-topic-subscription-change/v1` is signed by the member and has
exact fields `schema_version`, `network_id`, `topic_id`, `member_key_id`,
`member_signing_key`, `grant_id`, `revision`, `previous_change_sha256`, `state`,
`request_id`, `issued_at`, `expires_at`. State is `subscribed` or `unsubscribed`.
Revision/previous digest use the same genesis rule. The public descriptor is
the existing public-key format, with its derived key ID equal to the payload,
proof and grant member. It is only historical signature evidence; it never
adds a trusted identity or grants current membership. Accepting a new change
also requires the exact current roster key, active membership with receive
scope and the corresponding active subscriber grant.
Revision and the previous-change digest define order. The member's timestamps
need not increase across revisions: correcting a clock within the permitted
skew must not prevent withdrawal. Each change still passes its own validity
window, and the authority's committed clock cannot move backward.

`memory-vault-topic-snapshot/v1` adds `policy_version`, `policy_sha256` and
`subscriptions`. That array contains exactly one entry for **every** policy
subscriber grant, in the same order, including revoked grants. Each entry is
exactly `{member_key_id,grant_id,change}`, with `change` either null or the
latest complete signed change. Non-null changes cannot become null. Relative
to a previous snapshot, revisions cannot go backward or change bytes at the
same revision; adjacent changes must link to their predecessor. A first-seen
snapshot may contain later revisions, because its completeness/currentness
comes from the independently pinned issuer, not a fabricated chain of changes.

`memory-vault-topic-status/v1` has exact fields `schema_version`, `network_id`,
`topic_id`, `issuer_key_id`, `nonce`, `policy_version`, `policy_sha256`,
`snapshot_version`, `snapshot_sha256`, `roster_version`, `roster_sha256`,
`issued_at`, `expires_at`. The joint member response has exactly
`{roster,status,policy,snapshot,topic_status}`; the existing roster status and
topic status use the same nonce and exact roster. Persisted previous policy,
snapshot and status timestamps form rollback checkpoints. Optional node proof
integration must separately validate the existing node domain, not treat a
member's proof as storage-node authority.

## Selection and frozen-message rules

An effective subscriber is the intersection of active policy grant, latest
member-signed `subscribed` change, and current active roster receive permission.
Its descriptor must equal the current roster signing descriptor. At most 16
effective recipients are permitted; overflow is rejected without batching or
truncation. An empty set is valid discovery state but cannot send a message.
A publisher needs an active publisher grant and current network send scope.

A future frozen topic carrier must bind the original policy, complete snapshot,
publisher grant, roster, ordered recipient IDs and each recipient's grant and
signed-change digest into its signed routing and JWE AAD (proof bodies remain
separate bounded attachments). A retry preserves the original ciphertext.
Current validation must retain the original publisher grant and all frozen
recipients, with their original key pairs, grant IDs and **exact subscription
change hashes**. Any later change by an original subscriber blocks that old
message, including unsubscribe followed by resubscribe. Only new subscribers
outside the frozen set do not block it; they never acquire its old wrapped key.
This conservative rule avoids reactivating old delivery across a checkpoint
gap without inventing a hidden subscription epoch. Explicit new sends use new
request/message IDs. Delivered plaintext cannot be cryptographically recalled.

Complete proofs disclose grant lists, subscription decisions and retained
revocations to authorized participants that verify them, including recipients.
The future topic envelope also exposes its routing recipient set. This design
does not hide group membership or subscription relationships from those readers.

## Bounded authority persistence

An optional `topic_state_path` in the existing private authority configuration
selects one private control JSON file, not a second identity or memory store.
The current state schema is `memory-vault-topic-authority-state/v1`, with
`network_id`, `issuer_key_id`, `last_clock`, `roster_checkpoint`, `topics`, and
`requests`. The roster checkpoint is exactly `{version,sha256,issued_at}` and
records the complete signed roster hash. Restoring an older roster while this
state survives cannot renew removed membership: lower version/time or a
same-version conflict is rejected, and an adjacent version must name its
predecessor. A gap may use the explicit operator-selected current roster, but
never lower the retained checkpoint. Every successful new commit/status saves
the current roster checkpoint with its other state.
`topics` maps opaque IDs to `{policy,snapshot}`. `requests` maps request IDs to
`{change_sha256,receipt}`. There are at most 32 topics, 1,024 request-cache
entries and 4 MiB serialized state. Cache/tombstones are never auto-evicted;
capacity exhaustion rejects new changes, while exact existing retries remain
available. Future compaction requires a separate replay-horizon design.
This includes rejecting a new unsubscribe when its durable request cannot fit;
no success is returned for an uncommitted withdrawal. An owner must be able to
stop the authority from issuing fresh topic status while resolving capacity.
Already issued status lasts at most five minutes. Increasing capacity, pruning
history and restoring an old state are not automatic remedies.

An accepted subscription produces an issuer-signed
`memory-vault-topic-subscription-receipt/v1` with `network_id`, `topic_id`,
`issuer_key_id`, `member_key_id`, `grant_id`, `request_id`, `revision`,
`change_sha256`, `snapshot_version`, `snapshot_sha256`, `committed_at` and
`state: "committed"`. This receipt is a historical commit assertion, not fresh
permission or proof of message delivery. Exact canonical signed-request bytes
under the same ID return the same committed receipt, even after expiry or
revocation; different bytes conflict. New requests must pass current validity,
grant/membership and revision compare-and-swap checks. Duplicate retries never
create a fresh status or restore a revoked permission.

Policy, complete snapshot, latest changes, monotonic clock and request cache
commit together under existing private-file locks and atomic replacement.
Locks covering current roster/trust and the topic file use a fixed sorted order;
no network call occurs while held. Response follows durable commit. Failure
after rename may have an unknown commit state: retrying the exact request can
observe the cache and complete the durability barrier, never create a second
change. HTTP handlers must move this synchronous transaction to a worker thread.
No startup service, resource purchase or change to actual user configuration is
implied by defining or importing these modules.

The optional authority HTTP routes are `POST /v1/topic-status`, with exact body
`{network_id,topic_id,nonce,request}`, and `POST /v1/topic-subscriptions`, with
exact body `{network_id,change}`. The former uses the existing signed `status`
request domain with exact body `{nonce,topic_id}`; it returns the five-document
joint response. The latter returns `{receipt}` only after the subscription
transaction commits. The entire HTTP request is capped at 20 KiB; the embedded
signed change retains its 16 KiB canonical document limit. Direct binary
document inputs also reject oversized incoming serialization. Both routes use
the existing protected authority configuration and explicitly initialized
topic state; neither creates a topic or enrolls a new network member remotely.
Topic routes require JSON with identity content encoding, permit at most eight
concurrent requests per app instance and allow ten seconds to receive a body.
They never queue unbounded work behind the file locks. Errors use
`{error:{code,retryable}}`: admission/lock contention returns 429, body timeout
408, and an uncertain durable commit returns 503 with retryable true. Retrying
an uncertain commit requires the exact original signed change. Existing
non-topic authority response shapes are unchanged.

No persisted online lease cache is defined here. A verified current-topic
capability is bound to its current process and a monotonic deadline as well as
the signed wall-clock window; clock rollback cannot extend it. A process
restart must obtain a new nonce response before authorizing topic operations.

This preview cannot survive undetected rollback of an entire authority plus
every independent checkpoint. Authority disaster recovery needs an independently
retained checkpoint/epoch before activation; merely restoring an old control
file and signing new status is not a secure recovery procedure.
