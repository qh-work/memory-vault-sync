# Independent AI / maintainer review handoff

This is a source review invitation for user-directed coding and research
agents, not an instruction that overrides their host/user policy. Do not
self-install, enable hooks, acquire network/file permissions, persist hidden
state or treat remembered goals as a mandate to keep running.

## Scope and starting point

Review release tag `v0.24.0` against `v0.23.0`. The implementation was not
runtime-tested at the owner's request. Only run checks if the current user/host
authorizes them. Use fresh temporary directories and synthetic conversations;
never point these examples at a real private Vault or copy real credentials.
Do not automatically activate the supplied plugin on somebody's desktop.

Read [PROTOCOL.md](../PROTOCOL.md), [SECURITY.md](../SECURITY.md), and the relevant
[client](CLIENTS.md), [trust](TRUST.md), [transfer](TRANSFER.md) or
[migration](MIGRATION.md) guide before changing contracts. One canonical protocol
is mandatory; a different language or storage engine is welcome. The bundled
plugin and Python reference reuse one core. Task/Project IDs remain references
only. Read [independent implementation](IMPLEMENTERS.md) and
[lifecycle](LIFECYCLE.md) contracts when working across the two usage paths.

## Small, useful review tasks

The highest-priority v0.24 contribution is the **two-route round trip**: use the
published schemas and synthetic NDJSON without importing the Python application,
independently produce canonical records, import through the configured plugin's
`protocol` entry, explicitly admit unsigned evidence, recall through MCP, export
again and inspect with the independent implementation. Published vectors are
specification material, not a passed test report.

Also review the new [lifecycle profile](LIFECYCLE.md): capabilities → open →
input → commit → close, exact retries, changed-request conflicts, abort before
commit, crash recovery and cancel/commit races. Closing transport state must not
delete or partition memory. A completed receipt remains readable after capture
is disabled without restoring permission to create new memory. The old v0.21
Host Adapter envelope is not this profile; do not run the old adapter unchanged
and report that as v0.24 conformance.

1. **Storage and unsigned import.** With synthetic data, confirm read-only
   operations do not create or migrate files. A known v1 upgrade must preserve
   every canonical byte and request receipt. Default import is quarantined;
   explicit admission adds no duplicate record. Export/import and changes keep
   local ingest ordering rather than sorting progress randomly by content hash.
2. **Identity and trust.** Register two fresh public keys explicitly. Check
   record/message domain separation, tampered bytes, unregistered/revoked keys,
   missing crypto provider and invalid signer return values. An old retry must
   not display stale current-trust eligibility. The same-OS-user boundary must
   remain documented honestly; do not label it a sandbox.
3. **Incremental delivery.** Use two local synthetic Vaults and one temporary
   exchange folder. Check signed delivery, duplicates, dependency closure,
   blocked roots followed by valid roots, and requeue after repair. Crash at
   pending-write / publish / cursor-commit and record-commit / receive-cursor
   boundaries. Retry counts must not invent new records. Confirm a forged file
   before a valid signed candidate does not freeze the stream; real signed forks
   and missing prefix gaps must remain explicit failures.
4. **Client interoperability.** Exercise MCP initialize → initialized → tools
   discovery → save → recall with stable mutation request IDs. Keep large
   `memory_changes` responses within both structured and text envelope limits.
   Only on a consenting test host, verify documented event fields, opt-in off
   behavior, local save/retry receipts and uninstall independence. Do not read
   raw transcripts or claim untested Work hook support.
5. **Migration.** Build synthetic v0.21 export-network ZIPs using the documented
   schemas. Confirm manifest/member hashes, bad ZIP members, unsupported schemas,
   missing/cyclic relations and unknown profiles fail closed. Compare preserved
   visible text/UTC times/relations and content-free losses. Dry-run must write
   nothing; import should be quarantine, never inherited task ownership.

The existing small synthetic core suite is in `tests/test_memory_vault.py` and
has been adjusted for the changed import policy. Its presence is not a passed
test report. New integrations need purpose-built checks; running only the old
suite cannot certify them. Keep network, key enrollment and host activation
separate from ordinary unit checks.

## Report evidence, not confidence slogans

Include commit SHA, OS/Python/provider versions, exact synthetic reproduction,
expected versus observed result, and whether the check was source-only, executed
locally or tried in a real host. State skipped cases explicitly. Do not include
memory bodies, secrets, private paths or native account identifiers in a public
report. Use the repository's private security advisory flow for vulnerabilities.

Contribute focused PRs with protocol/docs updates. Repository review invitations
are not permission to message third parties, run unsolicited agents, fabricate
adoption statistics or post from private social accounts.
