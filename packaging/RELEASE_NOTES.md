# Memory Vault v0.28.0-alpha.0.30 — complete independent receipts through ordinary operations

Python recipients can retain an independently selected ACK destination for an
exact message with `register_mailbox_receipt_return`. Ordinary `receive` then
returns its actual saved receipt using the original authority, retaining
exact requests across lost replies and restarts. Expired uncertain uploads
stop for reconciliation; completed returns are not transmitted again.

When the sender repeats its original stored send, a matching earlier ACK
preparation can recover the independent receipt automatically. The current
source key/epoch, original READ grant, message and ciphertext must match.
Changed requests are refused before source access, and confirmed repeats
use local history. These steps share the ordinary operations' network
deadlines and do not create new source or memory permissions. See
`docs/OPEN_ACK_PROVISIONING.md`.

Python recipients can register an already authorized message replica through
`connect` with `action: register_replica`. Ordinary `receive` then polls the
retained selection, including after restart, using the existing original keys,
read permissions and durable memory inbox. Current destination identity and
storage epoch must match. Saved/rejected ciphertext is not downloaded again;
removing a selection preserves received memory and authenticated denials.

This adds bounded polling of explicitly selected copies. It does not create
replacement copies or exchange permission automatically; receipt return still
requires its separate original authority. See `docs/OPEN_ACK_RECOVERY.md`.

The owner and sender can now independently sign a mailbox reservation plan with
`memory_vault_open_repair_mailbox_consent.py sign`, using their existing protected
configuration and an independently retained exact selection. The maintainer's
`assemble` command turns those separate outputs into the existing real-capacity
reservation request. No participant supplies another participant's private key.

Source history, current status, destination, budgets and original permission
windows are checked before signing. Exact consent bytes and issuer revisions
survive restart; reused IDs cannot change the selection. Authenticated revocations
survive later malformed inputs and refuse cached output. The commands use new
private files and never fetch or modify the Vault. See the new preparation section
in `docs/OPEN_ACK_RECOVERY.md`.

The new `copy-reserve-root`, `copy-reserve-feed` and `copy-reserve-message`
commands obtain real destination capacity using the maintainer's existing client
configuration. Independent owner and sender consent must bind the exact intent
before transmission. The destination must opt in to remote mailbox reservation.
The client verifies its keys and epoch, saves the real offer and signs the matching
COPY/READ/RETAIN assignment. Lost replies and restarts reuse the same reservation;
authenticated revocations remain effective. Private outputs never replace existing
files, and reservation does not modify the Vault. See the reservation section in
`docs/OPEN_ACK_RECOVERY.md` for input fields and the upload sequence.

The mailbox replica capabilities from alpha.0.26 remain available below.

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
while still bounding slow headers. Nodes retain the three-second complete-input
deadline, then bound repair response processing separately at sixty seconds;
slower proof construction no longer closes a valid exchange after three seconds.

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

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.30/docs/OPEN_NETWORK_QUICKSTART.md)
and [mailbox replica guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.30/docs/OPEN_ACK_RECOVERY.md#receive-messages-and-shared-memories-from-a-replica-development-after-alpha025).
Preserve existing identity and state files when installing. The archives contain
implementation, public documentation and wholly synthetic fixtures only.
