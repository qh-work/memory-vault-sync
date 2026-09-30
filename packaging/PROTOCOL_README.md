# Memory Vault v0.28.0-alpha.0.38 — independent protocol

Native TypeScript recipients can issue an original mailbox destination from
an explicitly approved contact and a registered mailbox. The receiver signs with
its own existing identity and exports bounded authorization pages for sender
admission. Python and native clients reopen the same persisted signed originals;
conflicting selections and stale revisions fail. Both clients enforce retained
parent/resource revocations before cached or fresh authorization, even after the
status expires. Authorization creates no new storage or receipt-return grants.
See `clients/typescript/network/README.md` and `docs/OPEN_NETWORK_CONTACT.md`.

Native TypeScript recipients can retain an independently authorized receipt
return for a cold-mailbox message. Ordinary Agent `receive` then returns the
actual durably saved receipt, keeping the exact upload across lost replies and
process restarts. Python and TypeScript share the same retained jobs, pending
requests and completed history. The sender can independently recover that
receipt and confirm its original send. Observed revocations block retries;
expired uncertain uploads stop for reconciliation. No new permission or source
selection is created by retrying. See `clients/typescript/network/README.md`.

Native TypeScript recipients can register an explicitly authorized ordinary
mailbox and recover messages and selected memories with normal Agent `receive`,
even after the old delivery records and leases are gone. The client verifies
original owner/contact/storage authority, the complete encrypted feed, current
READ permissions and the exact ciphertext before importing through its durable
inbox. Retained revocations survive restart. Python and TypeScript share receiver
configuration, status history and saved inbox evidence; either can resume an
interrupted import. The native path performs its own HTTP and cryptography.
Saved receipts remain available through independently authorized return requests.
Native provisioning and replica inbox recovery remain unfinished. See
`clients/typescript/network/README.md` and `docs/OPEN_NETWORK_CONTACT.md`.

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

This candidate adds participant-local mailbox reservation consent and maintainer
assembly commands. Each owner/sender uses only its own existing keys, checks its
independently retained exact destination selection, and keeps retry/denial state
in the existing protected transport database. See `docs/OPEN_ACK_RECOVERY.md`.

This candidate adds Python commands to reserve, copy and recover a message-bound
empty ACK replica with the exact original recipient/message binding and both
history generations. Independent return consents and current permissions remain
required; COPY grants no first-receipt admission. See the ACK recovery guide and
release notes for the command schemas and current acceptance record.

This alpha.0.10 candidate adds independent remote source preparation using
only the sender's configuration and a selected public origin/key, plus durable
setup and bind recovery across lost replies. The Python Agent can enable contact
using an already configured node's public key ID. These workflows connect
ordinary memory delivery to independent original-receipt recovery. Source
requests, used work, authority observations and exact retry responses survive
restart. Separate A/B publication consents are required; a directory lease alone
is never a read capability. See the [directory guide](docs/OPEN_ACK_DIRECTORY.md).
Message movement, automatic repair and global reliability remain unfinished.
The earlier encrypted delivery, selected-memory sharing and current-fact scorer
are retained. Exact validation belongs to the source-bound release record.

The Python and native TypeScript open clients add encrypted messages and selected original
memory sharing after explicit first-contact approval. Recipient-saved receipts
follow local validation and durable save. Participants operate their own finite
nodes and exchange signed introductions; no central service or project-operated
public seed is supplied. Node and agent setup commands are included in the full
client archive. Ordinary clients need no public listener.

Messages use the original approved delivery node. The separate, explicitly
authorized ACK source retains original saved-message receipts for independent
recovery. Replacement-node message repair remains unfinished. Both clients
share the same wire protocol and existing Vault. The Python node hosts delivery
and ACK recovery; the native TypeScript node hosts routing and first contact.
Validation results and their exact source bindings are in the release record. Memory content never grants execution authority or automatically
enrolls an author as trusted.

[Open-network quickstart](docs/OPEN_NETWORK_QUICKSTART.md).

This archive is an agreement and implementation material, not an installed
program. No Python, database, plugin, account or network service is required
to read or implement it. It contains **no executable code**.

1. Read `docs/IMPLEMENTERS.md`, then the normative `PROTOCOL.md`.
2. Use `schemas/` and `examples/protocol/` for structural contracts and
   synthetic known-answer material. Schema matches do not prove hashes,
   relation closure, current trust, durable writes or interoperability.
3. Implement the core with your host's existing permitted storage/JSON/hash
   capabilities; choose your own language and storage layout.
4. Exchange canonical records with another conforming implementation, including
   the full client. Unknown evidence stays quarantined unless independently
   admitted under the explicit unsigned or verified profile.

Canonical record/v1 and its hash domain remain unchanged. Retrieval/graph,
lifecycle, the **separate** old-host compatibility bridge, signed streaming
transfer and selective sharing are optional extensions, not prerequisites
for the core agreement. Device trust, encryption and publisher verification
require independently configured providers; reading metadata cannot grant
authority or enroll keys.

The complete Python client and executable synthetic review kit are separate
artifacts described in `docs/RELEASE.md`. This package targets v0.28.0-alpha.0.38;
previous published versions remain immutable. The optional native network adds
communication around existing records without changing canonical record/v1 or
share-v1. It has no MCP, A2A, Matrix, Nostr or Graphiti adapter or compatibility
claim. Reading its specification does not install a client, provision keys or
join a service. Verify exact source, bytes and validation scope in the artifact
manifest; this document does not establish installation or publication.

Retained from alpha.5: source-preserving Experience views, message/memory
separation, authorized frozen Hint pages, explicit complete one-to-four-root
batches, query cancellation and local inspection of accepted batches. Current
profiles are content/v2 and Hint v4; older preview forms are rejected by the
current implementation. This archive is not a private-state migration tool.
See [Hint v4](docs/NETWORK_HINTS_V4.md) and
[accepted-batch inspection](docs/RECEIVED_BATCH_RECALL.md). A message or hint
cannot grant permission, prove truth, or turn a predecessor's observation into
the reader's own experience. No global P2P or scale certification is included.

The [capacity report](docs/V0_25_PACK_CAPACITY_SMOKE.md) records one 516 MiB
synthetic client pack round trip and separate 2 GiB boundary checks, not a full
2 GiB transfer, benchmark or independent protocol implementation. This historical
evidence and its [patch notes](docs/RELEASE_NOTES_V0_25_1.md) do not certify the
current alpha.

See [network-v1](docs/NETWORK_V1.md) and the version-specific
[alpha evidence](docs/RELEASE_NOTES_V0_26_ALPHA.md) for historical private-profile scope and open
gates. Synthetic interoperability frames are not real-model adoption or
thousand-agent performance acceptance.

The earlier [minimal release report](docs/V0_25_RELEASE_MINIMAL.md) records six distinct
methods with passing evidence across two source-pinned runs, including a
fixture-only recovery setup correction. This is not a full-suite pass.
The [validation index](docs/VALIDATION.md) records minimal offline synthetic
evidence with exact source pins; do not transfer results between versions.
The earlier exercised paths share one Python reference, not independent
implementations or AI models. Full P01–P14, signing/encryption, cloud, real-host/cross-device,
native Windows and performance acceptance remain open. Recorded checks installed
no host plugin and accessed no private memory. Release publication does not
establish runtime certification.

Reading this agreement alone cannot create persistent storage, suppress logs,
bypass permissions or prove another agent read a memory. Memory outlives tasks,
projects, models, devices and clients.

Apache-2.0; see LICENSE and NOTICE.
