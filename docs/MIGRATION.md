# Retained small-ZIP migration tool

For v0.25's complete v0.21 pack/network migration path, start with
[LEGACY_PACKS.md](LEGACY_PACKS.md). That separate implementation handles actual
`memory-pack/v1`, the 2 GiB/250,000-document source envelope, lossless evidence,
large visible records and ordered multipart bundles. The small tool documented
here remains available for callers using its original single-bundle/report
interface; its narrower limits and listed metadata losses are **not** the
v0.25 parity implementation.

`memory_vault_migrate.py` is a one-way, offline converter from the exact v0.21
`export-network` ZIP format to the shared core's current
`universal-memory-bundle/v1` NDJSON format. It is not a plugin upgrade, a Git
client, a database reader, or a background migration. It never discovers or
reads application data automatically, writes into the old installation, enrolls
a signer, or imports its output into a live vault.

The source contract was read directly from the published
[v0.21 export/import implementation](https://github.com/qh-work/memory-vault-sync/blob/v0.21.0/plugins/memory-vault-sync/scripts/memory_vault_runtime/core.py),
[episode/event writer](https://github.com/qh-work/memory-vault-sync/blob/v0.21.0/plugins/memory-vault-sync/scripts/memory_vault_runtime/memory_network.py),
and [integer-only JCS encoder](https://github.com/qh-work/memory-vault-sync/blob/v0.21.0/plugins/memory-vault-sync/scripts/memory_vault_runtime/protocol.py).
Only the schemas actually defined there are supported. No old runtime is loaded
to perform conversion.

## Operator-controlled workflow

1. Keep the old installation and its data. Use its existing, authorized
   `export-network --output ...` operation to make a separate export ZIP.
   That old export command may contact its configured Git transport; the new
   converter itself never does. Do not point the converter at a cache, runtime
   transcript, repository directory, SQLite database, or signing identity.
2. Select absolute paths for that source ZIP, a **new** NDJSON output, and a
   **new** JSON mapping report. Both destination paths must be absent and
   different from the source. Put outputs in a private directory outside your
   incoming/synchronization folder. The archive and its visible text remain
   private user data, not files to commit to the public source repository.
3. Optionally request a dry run, which validates and constructs the proposed
   conversion in memory and prints only a hash/count summary. It creates no
   output, report, directories, keys, or database:

```sh
python3 memory_vault_migrate.py --source /absolute/private/old-export.zip --output /absolute/private/converted.ndjson --report /absolute/private/migration-report.json --dry-run
```

4. After reviewing the summary, invoke the same command without `--dry-run`:

```sh
python3 memory_vault_migrate.py --source /absolute/private/old-export.zip --output /absolute/private/converted.ndjson --report /absolute/private/migration-report.json
```

5. Inspect the report and keep the source ZIP. Import into a separately chosen
   current vault only as an explicit second step. The new core quarantines
   unsigned bundles by default. An operator who has reviewed the migration may
   explicitly select the core's `--accept-unsigned` import option. Doing so is a
   local decision to use historical evidence, **not** recovery of an old author's
   signature. Do not present converted records as authenticated original authors.

No source file is modified or deleted. Outputs use private temporary files,
POSIX `0600` modes or native Windows private ACLs, file synchronization, and
no-replacement publication. A successful bundle has its separately published
report. There is no cross-directory atomic
transaction: interruption can leave a report alone, which can be inspected and
retained before choosing fresh output paths. Normal caught failures remove only
outputs created by that invocation; they never delete pre-existing files.

Protected output creation supports POSIX/macOS/Linux and the shared native
Windows local-fixed-NTFS profile. On Windows it checks the real source handle,
rejects reparse points and hard links, creates private output directories and
files with native ACLs, and publishes same-volume temporary files without
replacement. It never substitutes `chmod(0600)` for an ACL or silently repairs
existing permissions. Source reads retain one checked descriptor and compare
the final descriptor/path identity and change metadata before publication.
The paired report/output is still not a cross-directory atomic transaction;
see [PLATFORMS.md](PLATFORMS.md) for the platform boundary.

## Accepted input, exactly

The source must be a ZIP made with the `memory-network-bundle/v1` manifest and
`memory-network-graph/v1` network contract. Its privacy flags must declare no
native conversation IDs or credentials. These declarations are checked for
format, not treated as proof that natural-language messages contain no secrets.

The converter reads members directly from the ZIP; it never extracts filenames
onto the filesystem. It verifies the manifest's integer-only JCS hash, exact
member list, sorted unique paths, each member's length and SHA-256, the episode
and event hashes, semantic event identities, and each event's included evidence
anchor. No float values or unknown manifest/profile/schema fields are accepted.

Supported visible members:

| Old schema | Conversion |
|---|---|
| `memory-episode/v1` | One independent `episode` with visible message order, role, phase, text, and time preserved. Parent episodes become `continues` edges. |
| `memory-event/v2`, episodic checkpoint profile | A `continuity` record containing the checkpoint metadata, `derived_from` its exact imported episode, with checkpoint parents mapped to `continues`. |
| `memory-event/v2`, semantic profile | A typed record preserving the entire structured claim as JSON text, explicitly labeled with its old kind, and anchored to its imported episode. |
| `conversation-export/v1` | One independent visible snapshot per revision, retaining title, coverage, message order, phase, text, and capture time. Overlapping snapshots are not silently merged. |

Semantic kinds are mapped conservatively:

| Old kind | Current kind |
|---|---|
| `decision` | `decision` |
| `constraint`, `progress`, `hypothesis`, `correction`, `user_preference` | `observation` |
| `next_action`, `checkpoint_note` | `continuity` |
| `artifact_created`, `artifact_verified` | `artifact` |
| `conflict_declared`, `conflict_resolved` | `relation` |

`supersedes`, `conflicts_with`, and `resolves` are retained as explicit edges to
the corresponding newly content-addressed records. General semantic `parents`
become the conservative `related_to` relation; the report states this projection
instead of inventing a stronger causal/continuation meaning. Nothing executes an
old next action, resurrects an old task, or makes a task/project a memory owner.

## Re-keying, privacy, and explicit losses

Every output record uses `source_type="imported"` and `confidence="imported"`.
There is no automatic promotion of old `source_explicit`, `artifact_verified`,
or model-generated claims into new trusted observations. New IDs are constructed
by the current core from the full new record and new relation targets.

The output provenance uses a canonical source-document hash, not the original
source, task, conversation, runtime, project, or device identifier. The report
maps `SHA256(old schema + NUL + old identity)` to each new `memory_id`, and carries
the old archive member hash so the operator can locate the source evidence
without copying private identifiers into the report. For conversation snapshots,
the old identity is `conversation:` followed by its exact ZIP member path.
These hashes are pseudonyms, not anonymization guarantees; somebody with the
original archive can correlate them.

Known metadata that does not survive as a direct field is listed per record in
`uncarried_metadata_fields`, including original source pseudonyms, source sequence,
claim key, confidence, and included/excluded-content labels. Episode coverage
is already restricted to the known `partial_active_turn` contract. Timestamps
are normalized to UTC without changing their represented instant. Visible title,
message text, semantic claim content, and explicitly supported relations are not
silently truncated or summarized.

Output records are ordered dependency-first, with the preserved timestamp as the
tie-breaker between currently independent nodes. A content-hash sort would
otherwise randomize the ingest order that current-state views use. The report
includes each record's output ordinal. This is a reproducible historical
reconstruction, not proof that different devices' clocks were synchronized or
that the claimed timestamps are true.

Semantic claims containing recognized structured private-identifier or credential
fields are refused instead of being blindly copied or silently redacted. This
is deliberately conservative; inspect and export an explicitly reviewed subset
when such data needs a separate policy. The converter does **not** scrub private
information written inside ordinary human message strings or strings inside a
claim. Preserving visible evidence is not permission to publish it.

## Refusals and bounds

- No old `memory-event/v1`, Task/Project directory hierarchy, source registry,
  artifact binary, index, hook state, runtime transcript, current-state file,
  encrypted share, memory pack, loose folder, or arbitrary JSON export is accepted.
- Any unknown member, record field, event profile, kind, message role, or visible
  schema aborts conversion. In particular, an unexpected export member is not
  quietly omitted from the new bundle.
- All referenced nodes must exist in the selected archive. Missing references
  and cycles abort conversion; they are not silently replaced with guessed edges.
  Content-addressed records cannot represent mutually recursive IDs by assuming
  the old unrelated identifiers are still valid.
- The archive is limited to 64 MiB, expanded contents to 64 MiB, 10,000 members,
  2 MiB per member, and 4 MiB for the manifest. Encrypted entries, directory or
  special-file entries, duplicate names, unsafe paths, unsupported compression,
  and expansion ratios above 250:1 are rejected.
- For this retained tool, the new core's stricter limits still apply: a visible
  record must fit its text and record limits, a record may have at most 256 relations, and the complete
  output must fit 64 MiB. Oversized history is refused instead of truncated. Use
  [the complete legacy-pack converter](LEGACY_PACKS.md) for bounded lossless
  fragmentation and ordered multiple parts instead of silently shrinking history.
- The report is bounded at 16 MiB. Standard output contains only counts, hashes,
  schema names, known metadata field names, and content-free error codes. Member
  errors can include a SHA-256 fingerprint, never the original path, identity,
  credential, or message text.

Historical checksum verification detects mismatches but is not author
authentication. A malicious party can recompute an unsigned legacy manifest.
The converter does not claim provenance stronger than the source format or
recover evidence that the old export command never included.

## Validation status

This converter was implemented after statically reading the v0.21 writers and
validators plus the current bundle reader. At the user's request it was not run:
no private export was opened, no dry run, conversion, import, migration, test
suite, or signing exercise was performed. It is not a claim that a specific
user's old vault has been migrated or a guarantee of security audit completion.

Reviewers should exercise known synthetic schema fixtures, JCS Unicode-key
ordering, changed member bytes, malformed anchors, duplicate/unknown ZIP members,
missing/cyclic relations, re-keyed graphs, private-field refusal, oversize inputs,
interrupted output publication, idempotent subsequent import, and quarantine
behavior before using this path for irreplaceable data. Native routing and
private paired-output cases are supplied in `tests/test_v025_portable_packs.py`;
these too are authored, not executed. Windows support is implemented source,
not a claim of a completed native-platform validation run.
