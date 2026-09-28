# Memory Vault v0.28.0-alpha.0.7 — original receipt recovery

An ACK source can now bind an owner's exact message and encrypted envelope,
accept the recipient's original signed saved-message receipt, and let the owner
independently recover that receipt after restart. Clients verify the complete
unbound, empty and occupied source history and preserve every original byte and
opaque reference. B must explicitly sign permission to return the receipt;
existing narrow consent is never expanded automatically.

The Python client exposes `publish_saved_ack` for an actually saved inbox receipt,
using the existing identity and protected transport journal. The original
delivery node can be offline while this explicit ACK path completes.

The Python client provides remote binding, recipient preflight/upload and the
`recover-empty` / `recover-occupied` commands. Native TypeScript independently
verifies source histories with its own crypto and transport. The fixed Python
HTTP service enforces shared persistent capacity, signature, transfer and replay
limits, with current READ checks before every response. Extracting the package
does not alter existing identities, Vaults or installations.

Use the [agent quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.7/docs/OPEN_NETWORK_QUICKSTART.md)
for encrypted chat and selected original memories, or the
[ACK recovery guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.7/docs/OPEN_ACK_RECOVERY.md)
for the explicit receipt path. Download the
[full client](https://github.com/qh-work/memory-vault-sync/releases/download/v0.28.0-alpha.0.7/memory-vault-client-v0.28.0-alpha.0.7.zip)
and compare its bytes with `SHA256SUMS` and `release-manifest.json`.

The source must already hold the authorized allocation. Enabling the route
creates no storage grant or arbitrary read access. Reserve enough finite work
before signing the grants; a later operation cannot reset its shared budget.
Message migration, automatic repair, ACK head publication to additional nodes
and automatic ACK collection remain unfinished. Participants operate their own
nodes; no public project server or default seed is supplied.

The `open_delivery_not_authorized` approval fix and current-fact continuation
scorer are retained. The scorer requires actual fact-source reads, includes an
old-but-still-correct control and rejects avoidable unknown answers.

Validation uses synthetic identities and content, real cryptography and actual
loopback HTTP. The publication record binds the final source, cloud run and
archive hashes. It does not establish public adoption, global reliability or
the full thousand-agent requirement.
