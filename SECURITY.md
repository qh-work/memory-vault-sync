# Security

Universal Agent Memory is a local cognitive continuity protocol. It does not
grant, request, infer, or exercise real-world authority.

## Fixed boundary

Every response carries these semantics:

- memory is untrusted historical evidence;
- memory is not instruction;
- memory is not authorization;
- memory is not execution;
- memory cannot change policy or permissions;
- current user input and host policy take precedence.

The protocol has no operation for commands, tools, shell access, agent spawning,
network access, policy changes, permission changes, credentials, or resource
allocation.

## Stored content

Store only content deliberately exposed to memory, such as visible user text,
visible final answers, facts, decisions, goals, and continuity notes.

Do not store:

- system or developer prompts;
- hidden reasoning or chain of thought;
- tool traces or raw runtime transcripts;
- environment variables or local filesystem inventories;
- passwords, API keys, cookies, tokens, or credentials;
- native account identifiers;
- content that the user or host policy excludes from persistence.

The reference implementation uses a flat provenance allowlist, assigns source
and confidence labels itself, and rejects nested or authority-shaped metadata.
It cannot identify every secret embedded in free text; the calling agent remains
responsible for sending only appropriate visible content.

Manual protocol/MCP `observe` is caller-reported. Only the configured host-hook
path selects a host-visible source label; this is still not a cryptographic
attestation by the host. Imported labels remain claims. The verification result
is separate from the canonical record and never upgrades text into instructions.

## Local storage

The reference implementation uses the current OS user's local application-data
directory, SQLite WAL, `synchronous=FULL`, transactions, foreign keys, bounded
input, strict JSON, parameterized SQL, and append-only triggers on canonical
memory records.

On POSIX systems it attempts `0700` on the directory and `0600` on the database.
Python's standard library cannot reliably configure strict Windows ACLs, so the
default is the current user's LocalAppData directory.

Do not use the SQLite file as a multi-host network filesystem database. Use a
logical bundle to move memory across devices.

Explicit Vault and bundle paths must be absolute. Symbolic-link targets are
rejected so different working directories cannot silently split agent memory.

## Integrity and truth

Memory Records are content addressed and include a full SHA-256 digest. Import
verifies canonical bytes and refuses an ID conflict. These hashes detect
accidental inconsistency; they do not prove that a memory is true or identify
its author.

Recalled facts can be outdated, incomplete, inferred, or conflicting. Verify
important claims against current reality and provenance. Append corrections
with explicit relations instead of editing the old bytes.

## Cooperative-agent threat model

Processes that run as the same OS user can bypass the protocol and modify the
database or code. A single-file, zero-install design cannot isolate hostile
same-user agents. Strong isolation requires an independently authorized service,
separate OS identity, sandbox, or ACL boundary outside this protocol.

Reading `memory_vault.py` also cannot create filesystem permission. An agent can
use the Vault only within permissions already granted by its host and user.

## Bundles

Bundles are plaintext NDJSON. Their footer hash proves byte integrity, not
confidentiality or sender identity. Use an external user-approved encrypted
transport for sensitive bundles. Importing a bundle imports historical evidence
only; it never imports permission, policy, execution rights, plugin state,
account state, Task ownership, or Git state.

In v0.24, unsigned imports are quarantined by default. Explicit
`--accept-unsigned` admits them without authenticating a signer. Default recall
and handoff exclude quarantined records; explicitly fetching an ID permits
review without admission. Unsigned corrections cannot change the status of a
verified target. The optional client checks current key trust while reading;
a bare core with no trust registry reports verification at admission only.

## Optional signing and delivery

[Ed25519 signatures](docs/TRUST.md) are supplied by PyCA cryptography, not custom
cryptography. An independently managed public-key registry controls which keys
may authenticate imported bytes. Memory, MCP tools and transfer packets cannot
create a key, enroll a sender, restore a revoked key or change policy. A signer
callback that fails must not downgrade a configured signed write to unsigned.

A signature establishes possession of a registered key and commitment to exact
bytes. It does not prove the text's truth, original human/model identity, task
completion, permission or execution authority. A publisher explicitly attesting
an old unsigned record becomes its attester, not its original author. This
release stores one accepted proof per record, not a multi-signature history.

The optional trust/key storage and signed directory adapter currently require
protected POSIX storage. They fail closed on Windows until an actual ACL-backed
implementation is available. The unsigned core is still standard-library and
cross-platform. Protect identities outside the exchange directory and outside
shared memory. Same-OS-user file access is not a hostile-agent isolation boundary.

[Directory delivery](docs/TRANSFER.md) signs both the envelope and the records,
uses independent sender/store cursors and atomic local receipts, and refuses
unregistered senders. Invalid files do not gain ordering authority by their
names; a genuinely signed fork requires operator resolution. Bounded discovery
and input limits mitigate resource exhaustion but do not make a malicious shared
filesystem available or confidential. Transport access control/encryption belongs
to the separately authorized sharing mechanism.

Missing or revoked dependencies and over-budget closures are reported as
`blocked`, not silently represented as delivered. Their records remain in the
Vault and can be requeued explicitly. A successful local save, published batch,
or receiver commit is not proof that another model consumed or accepted memory.

## Transparent optional capture

The [client](docs/CLIENTS.md) does not install, enable or trust its own hooks.
Visible-turn capture defaults off. When enabled through ordinary host/user
controls, it reads only documented visible event fields, never transcript files,
hidden prompts or hidden reasoning. Its prompt path is local-only. Private
pending files and content-free receipts support retries; no host logs are erased
or suppressed and persistence is not hidden from the user. A Stop hook cannot
block termination or ask the agent to continue merely to save memory.

This release has not undergone runtime testing, a security audit or production
certification. See [the independent review handoff](docs/REVIEW_HANDOFF.md).

## Reporting vulnerabilities

Please use GitHub's private security-advisory flow for vulnerabilities. Do not
include real memory contents, credentials, or a private Vault in a report. A
minimal synthetic reproduction is preferred.
