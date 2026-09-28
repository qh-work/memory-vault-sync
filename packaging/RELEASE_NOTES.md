# Memory Vault v0.28.0-alpha.0.9 — prepare, share and recover selected memories

Agents can now prepare the complete ACK path through production commands.
An operator uses its existing sender and source configurations to freeze an
explicit message or memory selection, allocate the source and bind the original
envelope. Ordinary send and receive then save the selected originals. B shares
its own saved receipt, and A can recover it with the original delivery node
offline.

The source exports a private directory plan. A and B independently verify and
sign their own publication consents; an assembler produces the request for the
existing publish command. Identities, original references and exact retries are
retained in the existing protected transport databases. These commands replace
the need for an integrator to hand-build the source and directory authority
bundles. The initial source command requires operator-owned local A/R configs;
it does not administer an unrelated remote node.

An original ACK source can now publish its receipt commitment to one explicitly
authorized directory. The owner can discover that source and independently
retrieve the same signed saved-message receipt. Directory publication requires
separate A/B consent; an index lease never grants READ. The client reports
`usable` only after an actual authorized read matches the advertised commit.

The source proves both directory keys before disclosing its bounded descriptor,
reserves real directory capacity, and uploads the complete authorized history in
16 KiB frames. Exact requests, failed work, used budgets and signed permission
observations survive restart. A lost response reuses the same request. Shared
conflict floors prevent either directory API from reviving a conflicting fact.

The Python client exposes `publish_saved_ack` for an actually saved inbox receipt,
using the existing identity and protected transport journal. The original
delivery node can be offline while this explicit ACK path completes.

The Python `memory_vault_open_repair_index_admin.py publish` and `recover`
commands use existing source and owner identities. The Python client also
provides `recover_indexed_ack`. Native TypeScript retains independent provider
discovery and direct ACK recovery with its own crypto and transport; the new
combined publication/recovery command runs in Python. Directory and source
hosting use the Python node. Extracting the package changes no existing identity,
Vault or installation.

Use the [agent quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.9/docs/OPEN_NETWORK_QUICKSTART.md)
for encrypted chat and selected original memories, or the
[source setup guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.9/docs/OPEN_ACK_PROVISIONING.md)
and [independent consent guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.9/docs/OPEN_ACK_PREPARATION.md)
to prepare the complete receipt path. Use the
[ACK directory guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.9/docs/OPEN_ACK_DIRECTORY.md)
for publication and independent receipt recovery. Download the
[full client](https://github.com/qh-work/memory-vault-sync/releases/download/v0.28.0-alpha.0.9/memory-vault-client-v0.28.0-alpha.0.9.zip)
and compare its bytes with `SHA256SUMS` and `release-manifest.json`.

The source must already hold the authorized allocation. Enabling the route
creates no storage grant or arbitrary read access. Reserve enough finite work
before signing the grants; a later operation cannot reset its shared budget.
Message migration, automatic repair, replicated directory publication
and automatic ACK collection remain unfinished. Participants operate their own
nodes; no public project server or default seed is supplied.

The `open_delivery_not_authorized` approval fix and current-fact continuation
scorer are retained. The scorer requires actual fact-source reads, includes an
old-but-still-correct control and rejects avoidable unknown answers.

Validation uses synthetic identities and content, real cryptography and actual
loopback HTTP. The publication record binds the final source, cloud run and
archive hashes. It does not establish public adoption, global reliability or
the full thousand-agent requirement.
