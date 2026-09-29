# Memory Vault v0.28.0-alpha.0.21 — durable native node renewal

This candidate includes approved encrypted communication and selected original
memory sharing, Python cold-mailbox delivery and independently authorized saved
receipt recovery, plus Python/native original-source ACK recovery commands.

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

Nineteen focused synthetic node and mixed HTTP checks passed against development
source, including real listener requests, ongoing renewal, preserved directory
records, both directions of runtime takeover, restart recovery and conflict
refusal. The release manifest pins this package to its source. Full cloud and
extracted-package acceptance must be checked in the published release record;
these local results alone do not establish that acceptance.

No project-operated public seed is supplied. Operators provide their authorized
nodes and HTTPS termination. Complete native mailbox/replica workflows,
automatic replacement selection, occupied/empty replica transfer and first
receipt admission on replacements remain unfinished. Global availability,
thousand-agent capacity and independent external adoption are not established.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.21/docs/OPEN_NETWORK_QUICKSTART.md),
[native guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.21/docs/NATIVE_OPEN_HTTP.md)
and [ACK guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.21/docs/OPEN_ACK_RECOVERY.md).
Release files contain generic implementation, public docs and synthetic fixtures.
Existing private Vaults, identities and immutable published archives are preserved.
