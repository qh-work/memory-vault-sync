# Memory Vault v0.28.0-alpha.0.12 — durable mailbox authorization exchange

The receiver can now inspect and restore its signed mailbox configuration and
prepare sender authorization through the Agent `connect` interface using an
already approved local contact. Results are paged within the Agent output limit
and bound to the exact bundle digest. Destination and owner-status originals are
saved before return; retries and reopened clients reuse the same signed bytes.
Changed inputs under one status revision and local revision rollback are rejected.
Owners still coordinate status revisions across devices. Authorization creation
is local and does not claim that a remote source is online or currently accepts it.

Completed source-message retries now charge their actual signature work instead
of an entire admission-phase maximum. Request/byte budgets and current authority
checks remain in force. Full cloud and packaged validation of this new candidate
must be established from its own source-bound release record.

The Python Agent can provision a receiver mailbox, verify its original source
proof, and register it for ordinary receive calls. A sender can prepare its
already sent ciphertext for that mailbox and submit it over HTTP. Exact requests,
resource charges and storage stages survive interrupted operations. Two-message
recovery covers the case where a later message advances the index before an
earlier admission finishes publishing its original prefix.

Receivers enumerate the encrypted index, authenticate the complete original
history and current READ permissions, and retrieve the retained ciphertext
without the original delivery lease. Explicitly shared memories use the existing
trust and import checks. A durably staged receive can resume locally after a
restart without contacting the old delivery node. Messages and memories retain
their original provenance; content is never execution authority.

The existing Agent connect operation also returns saved receipts to an
independently authorized ACK source and recovers receipts into the sender's
actual outbox. Mailbox storage success does not claim recipient acknowledgement.
Mailbox READ permission does not grant receipt publication or recovery.

See the [mailbox and contact guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.12/docs/OPEN_NETWORK_CONTACT.md)
and [independent receipt guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.12/docs/OPEN_ACK_PROVISIONING.md).
Use the client archive with the published checksums and source-bound validation
record. This candidate is not a claim of a completed public release until that
record and downloadable assets are available.

Participants operate reachable nodes and explicitly fund finite resources; no
project-operated public seed is supplied. Full-prefix histories need budgets
for every covered message. Replacement-node copy/repair, scalable partial feed
recovery and mailbox attempts with a non-null ACK graph remain unfinished.
Python hosts the new mailbox workflow. Native TypeScript includes mailbox wire,
probe and proof support, but does not yet implement the full provisioning and
feed client. Synthetic HTTP checks do not establish external adoption, global
availability or thousand-agent capacity.
