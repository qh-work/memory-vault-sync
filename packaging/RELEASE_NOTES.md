# Memory Vault v0.28.0-alpha.0.26 — receive shared memory after mailbox source loss

This candidate adds separately reserved mailbox directory, complete feed-prefix
and encrypted-message replicas. A Python recipient can recover the exact original
message from an explicitly selected independent node after the source stops,
using its existing keys and import policy. The ordinary durable inbox imports
selected memory once, resumes after interruption and retains a recipient-signed
receipt for the independent return workflow.

Messages carrying their original independent ACK configuration can complete
`return_mailbox_receipt` and sender `recover_receipt` after replica reception.
Repeated historical status roles reuse exact authenticated results only within
the same invocation and identical checks. Changed bytes, references, scopes,
issuers or deadlines are verified again; work and authority limits are retained.

`copy-upload-root`, `copy-upload-feed` and `copy-upload-message` verify real
reserved capacity, exact original graphs and independent copy permissions before
transfer. Upload journals replay exact requests and completion after lost replies
or restart. `configure-replica-root`, `configure-replica-feed` and
`configure-replica-message` install separately signed return permissions.
`recover-replica-root`, `recover-replica-feed` and `receive-replica-message` use
protected reads with the original owner authority. The Python Agent also accepts
`connect` with the mailbox `receive_replica` action and retains authenticated
status observations across operations and restarts.

Message ciphertext occupies live storage; proof metadata and staged work have
separate finite charges. A directory/feed lease cannot authorize copying a
message. Original owner, sender, source and maintainer permissions remain
independent, and observed revocations cannot be erased by retrying. The explicit
`mailbox` profile is a bounded ceiling for new full proofs; it does not enlarge
existing signed grants. Repair HTTP replies now use the caller's remaining
absolute deadline after connecting, avoiding premature connection-timeout errors
while still bounding slow headers.

Exact-source cloud regression, supported Python 3.10, extracted-client checks and
final public-archive review are pending for this candidate. Prior releases'
results do not validate these bytes. Local synthetic checks exercise actual HTTP,
source shutdown, replica restart, durable inbox resumption, memory import and
receipt generation; they do not establish independent adoption or global scale.

Destination selection and permission exchange remain explicit. Automatic
replacement and native TypeScript mailbox client parity remain unfinished.
TypeScript recognizes the mailbox replica proof and status profiles. Participants
operate their own authorized nodes; no central authority or project-operated
public seed is required or provided.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.26/docs/OPEN_NETWORK_QUICKSTART.md)
and [mailbox replica guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.26/docs/OPEN_ACK_RECOVERY.md#receive-messages-and-shared-memories-from-a-replica-development-after-alpha025).
Preserve existing identity and state files when installing. The archives contain
implementation, public documentation and wholly synthetic fixtures only.
