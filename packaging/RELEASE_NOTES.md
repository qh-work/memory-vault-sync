# Memory Vault v0.28.0-alpha.0.6 — bounded ACK source recovery

Python and native TypeScript clients can recover the exact original evidence
for a previously committed, unbound ACK source through a real HTTP service.
The Python node retains possession challenges, replay state, authorization
floors and admitted work charges across restart. Each request rechecks current
access; a remembered revocation or conflicting status cannot grant a later read.

The full client includes an explicit recovery command and a new-node
`--enable-repair` option. Recovery exports a new private evidence file and keeps
all status witnesses needed for a later cold run. It does not open the Vault or
alter existing identities. The native client uses its own crypto and transport.

Use the [agent quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.6/docs/OPEN_NETWORK_QUICKSTART.md)
for encrypted chat and selected original memory sharing, or the
[ACK recovery guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.6/docs/OPEN_ACK_RECOVERY.md)
for the separate operator recovery entry. Download the
[full client](https://github.com/qh-work/memory-vault-sync/releases/download/v0.28.0-alpha.0.6/memory-vault-client-v0.28.0-alpha.0.6.zip)
and verify its bytes against `SHA256SUMS` and `release-manifest.json`.
Existing releases and private installations remain unchanged by extraction.

This release recovers the pre-message unbound ACK phase. Independent recovery
of an actual recipient-save receipt, replacement-node message repair and
automatic ACK garbage collection remain unfinished. The source must already
hold the original authorized allocation; enabling the route does not allocate
storage or authorize arbitrary reads. Finite grant, work and retained-history
limits can reject a request. Participants operate their own nodes and exchange
signed introductions; no project-hosted public server or default seed is added.

The approval fix for `open_delivery_not_authorized` and the current-fact
continuation scorer are retained. The scorer rejects guesses without a source
read, includes an old-but-still-correct control and rejects avoidable unknown
answers. It does not establish real-world adoption or model understanding.

Validation uses deliberately synthetic identities and content, real
cryptography, native TypeScript/Python interoperability and loopback HTTP.
The publication record attaches the exact source, cloud run and archive hashes.
Those results do not certify global reliability, independent adoption or the
full thousand-agent requirement.
