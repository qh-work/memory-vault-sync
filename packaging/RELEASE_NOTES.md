# Memory Vault v0.28.0-alpha.0.18 — replica creation and recovery commands

The alpha.0.16 full run was incomplete: one long mailbox fixture attempted to
sign a child request after its short handle expired, and the growing suite later
hit its 40-minute CI wall limit. Alpha.0.17 retained those same test/CI inputs and
its full run was cancelled after that diagnosis; both remain unpublished. The
fixture now performs a fresh, charged possession exchange before its independent
revocation check and reports only the current request's server errors. CI allows
55 minutes inside a 60-minute job; protocol deadlines and grants are unchanged.
Alpha.0.17 did pass 14 extracted-runtime workflows and supported Python 3.10.
Those results do not relabel either older candidate as a full-suite pass. This
alpha.0.18 candidate requires separate exact-source acceptance.

This candidate adds explicit `copy-reserve`, `copy-upload`, `configure-replica`,
and `recover-replica` commands. They use existing local identities and protected
transport state, preserve exact retry requests, and keep return permissions
separate from copy custody. Owner recovery remembers authenticated status facts
across failed commands and restarts. New-node setup can explicitly enable finite
remote copy reservations. No command opens the private content Vault. The replica
recovery example explicitly selects the existing 60-second client ceiling for
slower supported Python runtimes; signed deadlines and resource budgets remain
unchanged. These additions are later than the immutable alpha.0.16 candidate.

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

A maintainer can now request actual remote copy capacity, retain the signed
offer, prepare its original assignment and upload an explicitly authorized
unbound replica over HTTP. The client verifies the destination's signing and
encryption keys before disclosure, journals every outgoing request, resumes
exact requests after lost replies and independently verifies signed custody.
Owner/source disclosure and later READ consents remain separate requirements.
Remote admission is operator-enabled with persistent finite caller/work limits
and shared capacity accounting. Restart never renews permission or clears usage.

The full alpha.0.15 candidate regression exposed a fixture argument mismatch and
cleanup registered too late after failed initialization. Both are corrected; the
21 affected workflows pass sequentially on later source. The immutable alpha.0.15
candidate remains unpublished and failed, rather than being relabeled as passing.
This alpha.0.18 candidate requires its own exact-source full result.

Automatic replacement selection, first-receipt admission on a replacement,
occupied/empty replica transfer and the complete native TypeScript replica client
remain unfinished.

Existing approved-agent encrypted communication, selected-memory sharing,
retained mailbox provisioning/recovery and independent saved-receipt return
remain available. Operators supply reachable nodes and explicitly authorize
finite resources; the project supplies no public seed. Complete native
TypeScript mailbox parity, scalable partial feeds, external adoption and
thousand-agent capacity remain unverified or unfinished.

Use the [quickstart](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.18/docs/OPEN_NETWORK_QUICKSTART.md),
[mailbox guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.18/docs/OPEN_NETWORK_CONTACT.md)
and [ACK recovery guide](https://github.com/qh-work/memory-vault-sync/blob/v0.28.0-alpha.0.18/docs/OPEN_ACK_RECOVERY.md).
Published alpha.0.14 archives stay unchanged. Its full cloud failure is historical;
follow-up success does not retroactively validate those old bytes.
