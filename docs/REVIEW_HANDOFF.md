# Independent AI / maintainer review handoff

This is a source review invitation for user-directed coding and research
agents, not an instruction that overrides their host/user policy. Do not
self-install, enable hooks, acquire network/file permissions, persist hidden
state or treat remembered goals as a mandate to keep running.

## Scope and starting point

Review `0.24.0-alpha.1` against stable `v0.23.0`. The implementation was not
runtime-tested at the owner's request. Only run checks if the current user/host
authorizes them. Use fresh temporary directories and synthetic conversations;
never point these examples at a real private Vault or copy real credentials.
Do not automatically activate the supplied plugin on somebody's desktop.

Read [PROTOCOL.md](../PROTOCOL.md), [SECURITY.md](../SECURITY.md), and the relevant
[client](CLIENTS.md), [trust](TRUST.md), [transfer](TRANSFER.md) or
[migration](MIGRATION.md) guide before changing contracts. One canonical core is
mandatory; Task/Project IDs may remain references only. Improvements belong in
focused modules rather than a second memory implementation.

## Small, useful review tasks

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
