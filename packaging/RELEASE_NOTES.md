# Memory Vault v0.28.0-alpha.0.24 — recover message-bound ACK replicas

Python maintainers can reserve destination capacity and copy a bound-empty ACK
slot while retaining its original recipient, message, envelope and both source
history generations. The `copy-reserve-empty` and `copy-upload-empty` commands
resume exact requests after lost successful replies and process or node restart.
The destination reserves shared capacity and commits the replica atomically.

After the owner, original source and maintainer supply independent signed return
consents, `configure-replica-empty` enables protected READ on that replacement.
The owner uses `recover-replica-empty` to reconstruct the original binding and
both custody chains after the original node goes offline. The explicit
`replica_empty` proof preserves full opaque references and current status floors.
Its bounded metadata pack reduces network requests without reducing the logical
proof-byte charge or enlarging any original grant. Unexpected packed originals,
wrong bindings and remembered revocations are refused.

COPY/READ/RETAIN assignments grant no first-receipt admission. An empty replica
is not a recipient-saved receipt; output remains a new private evidence file and
does not import content into the Vault. Existing unbound replica commands remain
available. These new replica commands require Python; native Node verifies the
new proof-container profile but does not yet implement a replica recovery client.

This candidate retains approved encrypted messaging, selected original-memory
sharing, Python cold mailboxes and independent signed saved-receipt recovery.
Python and native Node agents can select a configured contact node by public key
and authorize finite offline contact registration by supporting Python nodes.
The quickstart includes native Node first installation without Python. Native
routing/contact hosts retain signed introduction renewal and shared process
ownership; Python nodes host delivery, directory maintenance and receipt services.

Twelve focused synthetic state, HTTP, command and Python/Node proof-profile cases
passed during development. Source and extracted-package acceptance for this
candidate are recorded separately in the public release when complete. Older
release results do not certify this candidate. The release manifest identifies
the exact source and archive inventory.

No project-operated public seed is supplied. Operators provide authorized nodes
and HTTPS termination. Automatic replacement selection, occupied replica transfer,
first receipt admission on replacements and complete native mailbox/replica
workflows remain unfinished. Global availability, thousand-agent capacity and
independent external adoption are not established.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.24/docs/OPEN_NETWORK_QUICKSTART.md)
and [ACK guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.24/docs/OPEN_ACK_RECOVERY.md).
Release files contain generic implementation, public docs and synthetic fixtures.
