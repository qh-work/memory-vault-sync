# Memory Vault v0.28.0-alpha.0.23 — native offline contact registration

Native TypeScript agents now accept `node_key_id` and `maintain_directory:true`
through the same six-operation Agent interface as Python. The selected node is
refreshed at its configured origin and challenged before allocation. A separate
bounded signed grant lets a supporting Python node keep the unchanged public
contact registered while the recipient is offline. Exact enrollment bytes and
used work survive a lost reply, restart and Python/Node switching. Parent
permissions and expiry remain unchanged; native Node hosts explicitly refuse
this directory worker until hosting support is implemented.

This candidate includes approved encrypted communication and selected original
memory sharing, Python cold-mailbox delivery and independently authorized saved
receipt recovery, plus Python/native original-source ACK recovery commands.

Pending receipt work now rotates through a durable position shared by Python
and Node, with at most four pending attempts per poll. Older unavailable or
independently authorized receipts remain pending without blocking later saved
receipts. No independent-return permission is inferred and no receipt is marked
sent without its existing authenticated result. Restart and language switching
preserve progress.

A five-message real-HTTP regression failed before this fix: the fifth receipt
stayed unsent after two restarted polls. Python and native Node now complete its
actual return, and the sender validates the original saved receipt; the four
blocked receipts remain unsent. Alpha.0.21 is held unpublished because its
previous packaged checks did not cover this scheduling failure.

Native routing/contact nodes now serve `GET /open/v1/node`, allowing clients to
refresh expired fixed-key introductions before authenticated endpoint checks.
Nodes renew their descriptor within five minutes of expiry, preserving the key,
storage epoch, endpoint and roles. Expired startup state recovers, and the same
persisted original survives restart or switching between Python and Node.
Config, authenticated version floor and public introduction are saved in order;
conflicting signed originals stop publication. Protected config changes outside
the descriptor require restart. Existing directory/contact state is retained.

Python and Node share a separate process-ownership lock beside the protected
config. It releases on normal exit or process death and does not lock message
storage. Python retains its existing file lock. Use the updated runtimes when
switching; older runtimes do not all participate in this shared coordination.

Thirty-three focused native contact, real-HTTP and offline directory cases
passed against development source, including lost enrollment replies, a node
restart, Python takeover, later first contact and expiry of the original grant.
The release manifest pins this package to its source. Full
cloud and extracted-package acceptance must be checked in the published release
record; local results alone do not establish that acceptance.

No project-operated public seed is supplied. Operators provide their authorized
nodes and HTTPS termination. Complete native mailbox/replica workflows,
automatic replacement selection, occupied/empty replica transfer and first
receipt admission on replacements remain unfinished. Global availability,
thousand-agent capacity and independent external adoption are not established.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.23/docs/OPEN_NETWORK_QUICKSTART.md),
[native guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.23/docs/NATIVE_OPEN_HTTP.md)
and [ACK guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.23/docs/OPEN_ACK_RECOVERY.md).
Release files contain generic implementation, public docs and synthetic fixtures.
Existing private Vaults, identities and immutable published archives are preserved.
