# Memory Vault v0.28.0-alpha.0.13 — Agent mailbox retention and independent receipts

The sender can submit `connect` with mailbox action `retain` and the receiver's
exported authorization. This prepares and admits the exact existing ciphertext
using the persistent admission journal. A lost successful HTTP reply can be
retried without replacing the message or duplicating its storage history.
Retention does not imply that the receiver saved or acknowledged the message.

Agents can now prepare an independent ACK source before first encryption using
`connect`, then export separate receiver and sender invitations. B can pass its
invitation directly to `connect` after saving the message. A can use its own
invitation to recover the original saved receipt into its actual send record,
even with the original delivery node offline. Original grants, known status
records and locally retained status history remain independently verified.

Preparation stores its exact result in the protected local database. Reopening
the client and retrying identical inputs returns that history without claiming
a fresh source check; changed inputs under the same request ID fail. Export is
paged within the Agent output limit and binds each page to the bundle digest.
Owner and recipient material are selected separately, and no private keys are
exported. R still explicitly enables finite remote setup, and B must approve A.

Full cloud and packaged validation must be established from this candidate's
own source-bound release record.

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

See the [mailbox and contact guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.13/docs/OPEN_NETWORK_CONTACT.md)
and [independent receipt guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.13/docs/OPEN_ACK_PROVISIONING.md).
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
