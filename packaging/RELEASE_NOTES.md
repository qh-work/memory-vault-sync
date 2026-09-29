# Memory Vault v0.28.0-alpha.0.15 — mailbox fixes and explicit replica reads

This is a release candidate until the release record and downloadable assets
confirm publication and exact-source validation.

Cold-mailbox recovery now reuses exact packed originals instead of downloading
them twice. The focused two-message ACK feed uses 10 requests instead of 60;
original proof-byte, permission and deadline checks remain active. The strict
installed-runtime launcher now includes the same copy modules as the builder.
Long synthetic mailbox scenarios have realistic authority windows; production
reservation and possession deadlines are unchanged.

The Python replacement operator can configure a committed unbound ACK replica
for protected HTTP reads. Separate owner, original-source and maintainer return
consents bind the exact destination, assignment, original custody and bootstrap
grant. Both key-possession checks precede disclosure. Status floors, replay
records, original bytes and actual work charges survive restart. The Python
`AckOwnerRecoveryClient.recover_replica` independently reconstructs both storage
events, verifies current READ and returns a bounded status archive for later
calls. An unbound replica is not a saved recipient receipt.

The continuation trial now requires a fresh per-read nonce in the structured
answer. Correct facts without that live value fail; old-but-still-correct facts
also require a current read. Cross-case/run nonces fail. Reports use version 2;
prior reports are not silently upgraded. Returning the nonce proves possession
of a live value, not that a model understood or used every retrieved fact.

The copy staging wire has a separate explicit consumer, closed original roles
and the existing bounded chunk exchange. This is protocol support only: remote
copy upload, automatic replacement selection, first-receipt admission on a
replacement and occupied replica recovery remain unfinished. The standard replica
recovery command and native TypeScript replica client are not implemented.

Existing approved-agent encrypted communication, selected-memory sharing,
retained mailbox provisioning/recovery and independent saved-receipt return
remain available. Operators supply reachable nodes and explicitly authorize
finite resources; the project supplies no public seed. Complete native
TypeScript mailbox parity, scalable partial feeds, external adoption and
thousand-agent capacity remain unverified or unfinished.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.15/docs/OPEN_NETWORK_QUICKSTART.md),
[mailbox guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.15/docs/OPEN_NETWORK_CONTACT.md)
and [ACK recovery guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.15/docs/OPEN_ACK_RECOVERY.md).
Published alpha.0.14 archives stay unchanged. Its full cloud failure is historical;
follow-up success does not retroactively validate those old bytes.
