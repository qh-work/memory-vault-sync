# Independent artifact records and explicit original-file retrieval

An artifact has a content hash and size. A cloud location is separate source
evidence related to that artifact, not its owner or execution permission. These
optional full-client operations do not change the lightweight memory protocol,
ordinary recall, host hooks, or canonical record schemas.

This is development-source functionality, not a claim that the current public
release or an installed client has completed a user's cloud migration. Live
OAuth and cloud transfer acceptance remain separate release requirements.

## Migrate the old catalogs without Git or Task ownership

Use explicit, privately exported JSON files from the old deployment. Supported
input schemas are `artifact-backup-index/v1` and `drive-import/v1`. Exporting
those files from an old repository is an operator action; the converter itself
does not invoke Git, inspect application data, use a cloud account or open a
Vault.

```sh
python3 memory_vault_client.py artifact migrate \
  --source /absolute/private/migration/backup-index.json \
  --source /absolute/private/migration/drive-import.json \
  --output /absolute/private/migration/artifacts.ndjson \
  --report /absolute/private/migration/artifact-map.json \
  --dry-run
```

Remove `--dry-run` to produce two new private files. Nothing overwrites or
removes an existing output. The report is published first; interruption can
leave it without a bundle, which is not a completed paired export. Keep all
old sources and cloud objects until reconciliation and actual retrieval pass.

The bundle contains ordinary canonical records with JSON text profiles:

- `universal-memory-artifact-descriptor/v1`: independent content hash and size;
- `universal-memory-artifact-location/v1`: provider/file identity, historical
  parent, safe display aliases and source-entry/catalog hashes, related to the
  descriptor;
- `universal-memory-artifact-catalog-entry/v1`: source evidence, historical
  verification claims and unresolved information.

All are imported evidence, not authenticated authors or fresh cloud checks.
The shared entity `artifact:sha256:<digest>` relates observations of the same
content across catalogs. Within one conversion, descriptions use the earliest
actual source timestamp. No invented epoch, rewritten record ID or Task parent
is needed. Equal filenames do not imply equal content; one content hash may
have several preserved Drive IDs. Conflicting sizes for one hash, or different
content identities for one Drive ID, are rejected.

Logical-path ambiguity is retained without hiding an otherwise exact file ID,
hash and size. Missing hashes/IDs remain unresolved, searchable evidence rather
than fabricated download targets. Full original entries, old task labels and
source paths are kept in the **private mapping report**, not as ownership rules.
The resulting bundle is also private: filenames and cloud object IDs can reveal
personal information. Neither file belongs in a public repository, example
directory, source review kit or software release. Import into an explicitly
chosen Vault is a separate reviewed action; this converter does not auto-import.

## Select and fetch an original file

Select one location record by its canonical memory ID:

```sh
python3 memory_vault_client.py artifact select \
  --bundle /absolute/private/migration/artifacts.ndjson \
  --memory-id mem_<40-hex-characters> \
  --output /absolute/private/download/location.json
```

The entire bundle's integrity is checked without importing it or authenticating
an author. The location may instead be an explicitly saved canonical location
record from an authorized recall/export. No URL in memory text is followed.

Supply a **separate local** `memory-vault-drive-config/v1` configuration with
an operator-selected root, OAuth client ID and an existing OS credential
reference. The illustrative values below are invented, not a working account:

```json
{
  "schema_version": "memory-vault-drive-config/v1",
  "root_folder_id": "synthetic_root_replace_locally",
  "oauth_client_id": "synthetic-client.apps.googleusercontent.com",
  "credential_ref": {
    "kind": "macos-internet",
    "server": "synthetic-vault.example.invalid",
    "account": "oauth",
    "protocol": "https",
    "path": "",
    "port": 0
  }
}
```

The selected OS item contains the old compatible JSON fields `refresh_token`
and optional `client_secret`. The OAuth client ID is configured separately;
an old default credential reference does not establish that the item exists.
The client does not extract a connector/browser login, create an account,
change permissions, or run a credential helper chosen by memory. Normal OS
credential access controls apply. Keep all real values outside the source tree.

```sh
python3 memory_vault_client.py artifact fetch \
  --drive-config /absolute/private/provider/drive.json \
  --locator /absolute/private/download/location.json \
  --output /absolute/private/download/original.bin \
  --journal /absolute/private/download/download-journal.json
```

Only the root selected by that configuration is accessible. The current Drive
ancestry is checked independently; a historical parent in the catalog is not
an access grant. Moving an object within the authorized root does not require
rewriting its old memory. Shortcuts, trashed objects, native Google document
export and objects outside the root are refused.

One call downloads at most 128 MiB by default, in at most 4 MiB requests.
`--maximum-bytes` selects 1 byte through 256 MiB; `--maximum-seconds` selects
1 through 300 seconds. Repeat the identical request after a partial result.
The ordinary retry checks private file identity and does not re-download the
already committed prefix. Changed local staging must match its recorded chunk
hashes; a crash tail is fetched again and flushed before acknowledgment. A
budget smaller than that tail is explicitly refused rather than exceeded.
The bounded private journal supports at most 150,000 committed chunks and
16 MiB of metadata; very small per-call budgets consume that capacity faster.

The output name is published without replacement **only after** a full local
SHA-256 check against the selected content identity. Partial bytes stay in a
private sibling staging file. The byte budget limits downloaded payload, not
all metadata, local hash reads, provider wire overhead or wall-clock OS delays.
A final hash can therefore need an additional retry window. Provider version
changes and bad bytes do not publish an apparently complete output. A completed
unchanged local retry performs no cloud operation; it does not prove that the
cloud still has that object today. No downloaded file is imported or executed.

## Native provider boundary

`memory_vault_drive.py` supplies bounded metadata, explicit-root pagination,
range reads, folder creation and new-object multipart uploads for integrations.
It uses fixed Google HTTPS endpoints, rejects redirects, scopes objects through
their parents, and never issues a file overwrite/delete. Credentials and token
responses stay in process memory rather than configuration logs or memory
records. A lost POST response is an uncertain outcome that needs reconciliation;
Drive names are not a uniqueness transaction and concurrent creators may race.
An upload response is not a verified readback or an acknowledged memory cursor.

This provider API alone does **not** wire the full memory-sync queue to Drive
or configure a user's login. Until those steps and a real minimal round trip
are delivered, the cloud-sync requirement remains incomplete.

## Minimal development evidence

Two targeted synthetic methods passed on 2026-08-31 using Python 3.12.13 on
macOS: catalog conversion and the integrated migrated-location fetch path.
The final combined invocation ran two methods in 0.077 seconds. Only HTTP
responses and the OS credential getter are substituted; canonical conversion,
provider validation, local journal/resume, final hashes and no-replace output
publication run as implemented.

The cases preserve multiple locations and unresolved/ambiguous evidence,
exercise two-window retrieval and a zero-network completed retry, and check
crash-tail adoption/budget, changed local bytes, changed remote version, bad
content, existing output and outside-root refusal. A small synthetic native
upload framing/readback is also covered. An earlier fetch invocation failed
because its fixture expected a removed result field; only that expectation was
corrected before the passing rerun. This was not a product cloud failure or a
real network test.

Tested production and fixture bytes are identified independently of a future
release tag:

| File | SHA-256 |
| --- | --- |
| `memory_vault_artifact_catalog.py` | `088736802f913304a4dbd653d0d27f556997e7e83e9324e998722e12a8680d28` |
| `memory_vault_artifacts.py` | `95fd2a8b73c5a43e961c350a622e0c9c60e1660b85c3dda78312460eb72a9851` |
| `memory_vault_drive.py` | `d2d47a17b7fcb6a4535fa1ce8379005d72b702b3fc85c10d9b568bbdcba20a2c` |
| `tests/test_v025_artifact_catalog.py` | `5e3da1baa0fa223cba02158e71260211e000ebf2543dcf12e37c85de442bf6a1` |
| `tests/test_v025_artifact_fetch.py` | `e2ab7d7b196f32c93461ad25c4aef2caedf5aadb538d9cfe72c047461169b056` |

This is not live OAuth, Keychain access, a cloud upload/download, a physical
crash experiment, native-platform certification, installed-client acceptance
or a completed memory-queue integration. No private memory, real catalog,
cloud ID or account credential is included in these fixtures or this report.
