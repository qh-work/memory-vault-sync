# v0.24 contribution: prove the protocol and authorized client interoperate

The target is now [v0.24.1](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.24.1),
not the old v0.21 Host Adapter envelope or an unqualified main checkout. The
protected main branch may still be v0.23. Earlier discussion is historical;
please base new work on the version tag and keep this contribution small.

The release provides one open memory protocol and two equal usage paths: an
independent implementation using its host's existing tools, and an optional
user-authorized plugin. An independent implementation does not need Python or
SQLite; canonical record bytes and exchange semantics must agree.

## Small first contribution

1. Use the published synthetic NDJSON exchange and known-answer hashes to
   explain one complete import/recall/export round trip through your chosen
   implementation. Do not require a vendor account, network service or plugin.
2. Add an optional authorized-client round trip: import those same records via
   the configured `protocol` entry, inspect them through MCP, then export them.
   Unsigned imports must remain quarantined until explicitly accepted. Compare
   canonical IDs, hashes, provenance and relations, not database file bytes.
3. Document the exact commands, interpreter/host versions and observed results.
   An unexecuted recipe is useful, but label it unexecuted rather than passing.

The broader lifecycle review is a separate follow-up, not a prerequisite for
the first small contribution: capabilities, session.open, turn.input,
turn.commit, turn.abort and session.close use the **new**
`universal-memory-lifecycle-request/v1` envelope. Check exact retries, crash
boundaries, capture opt-in and historical receipts without asserting v0.21 wire
compatibility. Closing a session must not remove long-term memory.

## References

- [Protocol](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/PROTOCOL.md)
- [Independent implementer guide](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/docs/IMPLEMENTERS.md)
- [Synthetic interchange material](https://github.com/qh-work/memory-vault-sync/tree/v0.24.1/examples/protocol)
- [Client guide](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/docs/CLIENTS.md)
- [Lifecycle profile](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/docs/LIFECYCLE.md)
- [Full bounded review handoff](https://github.com/qh-work/memory-vault-sync/blob/v0.24.1/docs/REVIEW_HANDOFF.md)

The maintainer did not run application tests for this release. These are
independent review tasks to perform only with your own host/user authorization.
Do not use real memories, prompts, credentials, account identifiers, native
session IDs, private databases or local user paths in published fixtures.
AI-assisted contributions are welcome when the author can explain and reproduce
the result. Memory never grants instruction, policy or execution authority.
