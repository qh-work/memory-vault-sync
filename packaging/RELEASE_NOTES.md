# Memory Vault v0.28.0-alpha.0.35 — native saved receipt return and restart recovery

Native TypeScript recipients can return an actually saved message or memory
receipt through the existing `connect/return_receipt` invitation. The protected
inbox supplies the exact original receipt. Independent return consent, source
binding and current permissions are checked before upload. The request is
persisted first; restart or switching from Python replays the same carrier while
its original use remains valid. Completed retries read authenticated local
history without claiming current source availability. The sender can separately
recover that receipt and confirm its original send while the delivery node is
offline. Preparation and complete native mailbox/replica orchestration remain
unfinished. See `docs/OPEN_ACK_PROVISIONING.md`.

Original ACK sources can publish the same retained receipt location through
another explicitly selected independent directory with new owner and recipient
consent. Each publication keeps its exact requests and history across restart;
all histories share the original resource limits. Earlier jobs and deadlines
remain intact, with at most sixteen retained histories and no implicit renewal.

Python and native TypeScript Agents also support `connect/recover_routed_receipt`.
The client discovers directories through its configured seeds and retained
routing state, then independently reads the exact originally authorized source.
The recovery invitation needs no directory address. A directory lease still
cannot grant READ access or replace the actual recipient receipt. Source keys,
epochs, original send bindings, revocations and bounded deadlines remain checked.
This supports recovery through another router after the earlier directory stops;
publication consent and source replacement remain explicit. See
`docs/OPEN_ACK_DIRECTORY.md`.

Python and native TypeScript Agents can locate an independently retained original
ACK receipt through an explicitly selected directory using
`connect/recover_discovered_receipt`. The directory provides signed location
metadata; the owner performs a separate authorized source read and confirms only
the actual recipient receipt bound to the original message and ciphertext.
Directory and source identities, storage epochs, leases, revision floors and
custody remain checked. Missing facts and mismatched custody cannot confirm a send.

New opt-in `receipt-index` sources fund the complete bind, return, publication and
owner-read workflow with up to 256 shared requests. Existing signed grants and
node policies keep their original limits. Directory publication and source
preparation still require Python and independent consent. Recovery does not
select replacement directories or republish lost entries. See
`docs/OPEN_ACK_DIRECTORY.md` for the closed invitation shape.

Native TypeScript Agents can confirm a stored send through its independently
selected original ACK source while the delivery node is offline. An explicit
`connect/recover_receipt` uses the existing owner invitation; repeating the
unchanged original `send` uses a successful preparation already in protected
state. Fresh source identity, origin, epoch and revision floors remain checked.
Confirmed repeats stay local, and signed refusal history is shared with Python
across restart. Automatic recovery has twenty seconds within the existing
sixty-second send deadline. No Python subprocess or new permission is created.
ACK source preparation and replica workflows still use Python.
See `docs/OPEN_ACK_PROVISIONING.md`.

Authorized maintainers can retain exact mailbox copy bundles and resume them
through a finite worker after source loss, lost commit replies or restart.
The worker reuses the original upload journal, selected destination and grants;
refusal, expiry and exhausted limits stop for attention. It does not choose
replacement nodes or create independent read permissions.

A sender can register an independently authorized ACK replica. Repeating its
unchanged original send then confirms the actual recipient receipt even after
the original delivery and ACK sources stop. The current replica key, origin,
storage epoch and original owner/recipient bindings remain checked. Confirmed
repeats stay local; removing a selection preserves authenticated revocations.
See `docs/OPEN_ACK_RECOVERY.md` and `docs/OPEN_ACK_PROVISIONING.md`.

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

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.35/docs/OPEN_NETWORK_QUICKSTART.md)
and [mailbox replica guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.35/docs/OPEN_ACK_RECOVERY.md#receive-messages-and-shared-memories-from-a-replica-development-after-alpha025).
Preserve existing identity and state files when installing. The archives contain
implementation, public documentation and wholly synthetic fixtures only.
