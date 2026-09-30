# Memory Vault v0.28.0-alpha.0.31 — independent protocol

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
artifacts described in `docs/RELEASE.md`. This package targets v0.28.0-alpha.0.31;
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
