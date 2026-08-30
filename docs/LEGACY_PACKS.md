# v0.21 memory packs, checkpoints and lossless conversion

`memory_vault_legacy_pack.py` implements the **actual v0.21 production wire
format**, separately from the new [chunk-transfer pack profile](PACKS.md).
It is an offline converter and integrity checker, not a resurrected runtime.
It never opens Git, downloads a provider, contacts a remote, launches an agent,
or imports a selected file merely because a remembered instruction says to.

The implementation and the supplied synthetic tests received source/AST review
only in this development session. Applications, migrations, generated signing
keys, tests and a 2 GiB stress workload were **not run**. Format support and
bounded algorithms are implemented; these are not measured speed, platform or
production-validation claims.

## What the old code actually wrote

The references below name files at the public `v0.21.0` tag, not the deleted
task-centric compatibility layer.

| Format | Production boundary | What its verification proves |
| --- | --- | --- |
| `memory-pack/v1` | `plugins/memory-vault-sync/scripts/memory_vault_runtime/packs.py`: magic, independent zlib records, indexed offsets, footer | Member byte identity, size, path/index consistency and object-root checksum |
| `memory-network-bundle/v1` | `core.py: export_memory_network` / `import_memory_network`: ZIP with `MANIFEST.json` and taskless objects | Catalog/each document hash, included evidence anchors and graph closure |
| `memory-network-checkpoint/v1` | `checkpoint.py` and `core.py: checkpoint_memory_pack` | Hash of object root, count, generation, predecessor and historical Git commit metadata |

An old pack starts with `memory-pack/v1\n`. Each record consists of a big-endian
4-byte JSON-header length, the header (`compressed_size`, `path`, `raw_size`,
`sha256`) and exactly one zlib stream. Its final JSON index is
`memory-pack-index/v1`, followed by a big-endian 8-byte index length and
`memory-pack-index/v1\n`. Indexed offsets must match the actual record stream;
duplicate paths, trailing compressed data, truncated frames and mismatched
sizes/hashes are rejected. ZIP members are never extracted to supplied paths.

The taskless network catalog contains only:

- `memory/episodes/<shard>/ep-<40 hex>.json` (`memory-episode/v1`);
- `memory/events/[<shard>/]evt-<40 hex>.json` (`memory-event/v2`);
- `sources/<source>/revisions/<revision>.json` (`conversation-export/v1`,
  visible messages only);
- `MANIFEST.json`, covering the exact member names, sizes and SHA-256 values.

`memory-network-index/v1` is accepted as the older catalog contract label,
provided the objects themselves satisfy the same taskless production profiles.
Task-scoped `memory-event/v1`, arbitrary filesystem snapshots, credentials,
hooks, caches and task directories are not accepted as this format.

The similarly named historical `schemas/memory_checkpoint.schema.json`
describes a **different** `memory-checkpoint/v1` task/vault cache. It is not the
taskless pack checkpoint and is not imported here.

**The old pack/checkpoint is hash-only, not author-signed.** Old encrypted-share,
device/catalog signing interfaces depended on externally configured providers;
an unconfigured provider or a test double is not evidence of a deployed
cryptographic capability. This converter does not invent keys or decrypt an
unknown envelope. A trusted checkpoint hash must come from an independent,
operator-chosen source. It pins bytes, not the truth or authority of their text.

## Commands

Use absolute paths; outputs must not exist. The full client routes these
operations through `memory_vault_client.py legacy-pack`; the standalone script
is the direct interface:

```text
python memory_vault_legacy_pack.py verify --source /private/export/old.pack
python memory_vault_legacy_pack.py repack --source /private/export/old.pack --output /private/export/restored.zip --format zip
python memory_vault_legacy_pack.py repack --source /private/export/old.zip --output /private/export/restored.pack --format pack
python memory_vault_legacy_pack.py checkpoint --source /private/export/old.pack --output /private/export/checkpoint.json --generation 0
python memory_vault_legacy_pack.py verify --source /private/export/old.pack --checkpoint /private/export/checkpoint.json --trusted-checkpoint-sha256 CHECKPOINT_SHA256
python memory_vault_legacy_pack.py verify-chain --chain /private/export/checkpoint-0.json /private/export/checkpoint-1.json --trusted-checkpoint-sha256 FIRST_CHECKPOINT_SHA256
python memory_vault_legacy_pack.py convert --source /private/export/old.pack --output /private/export/converted.zip --dry-run
python memory_vault_legacy_pack.py convert --source /private/export/old.pack --output /private/export/converted.zip
python memory_vault_legacy_pack.py extract --source /private/export/converted.zip --part 1 --output /private/export/part-1.ndjson
python memory_vault_legacy_pack.py extract --source /private/export/converted.zip --original --output /private/export/exact-original.pack
```

For a subsequent checkpoint, pass `--previous-checkpoint-sha256` and the next
`--generation`. Creation takes historical commit metadata from the verified
bundle, never a live Git checkout. The original checkpoint grammar supports a
40-hex Git object label; a bundle using a 64-hex label cannot be written into
that old checkpoint grammar. Labels are metadata, not a Git-signature check.
`verify-chain` checks consecutive generations and exact predecessor hashes;
use `verify --checkpoint LAST_FILE` separately to bind its final checkpoint to
the selected pack. No predecessor file is fetched implicitly.

`repack` preserves every original member byte; archive compression/ZIP headers
may differ. `extract --original` restores the **exact selected source file
bytes**, including original ZIP/pack representation. It never overwrites the
original file. Extract verifies the selected member checksum, not a claim that
every other capsule member has already been consumed or trusted.

`verify` and `repack` check graph closure and evidence anchors, not acyclicity.
An original closed cyclic graph can be retained/repacked without losing bytes.
`convert` (including its dry run) additionally requires a dependency-first
acyclic projection; a cycle fails conversion before any output is published.

## The conversion capsule

Conversion produces a single new ZIP with profile
`memory-vault-v021-conversion/v1`:

```text
MANIFEST.json
source/original.pack                 # or original.zip; exact input bytes
source/checkpoint.json               # optional; exact selected checkpoint
records/000001.ndjson
records/000002.ndjson                # additional parts when required
mappings/000001.ndjson
...
```

The manifest enumerates every part, its byte size, SHA-256, record/mapping
count and global ordinal range. It also identifies original evidence hashes,
the conversion profile, unsigned admission, and the dependency-order rule.
It is a checksum catalog, **not a signature**.

Each record part is a complete `universal-memory-bundle/v1` NDJSON stream with
its own header and footer. Import **all parts in increasing numerical order**
using the ordinary core/client import operation. A later part may depend on
any earlier part; parts are individually well-formed but are not advertised as
independently complete memory selections. Every relation target is emitted
before its referring record, so this declared prefix closure is sufficient.
Missing earlier targets are rejected by the ordinary importer.

Unsigned imports default to quarantine. Opting into unsigned admission is a
separate operator choice under the current store's trust policy, not something
the capsule, old confidence label or old checkpoint can request. Conversion
does not sign someone else's old text as that person's authorship.

`--dry-run` validates and computes the entire projection using disposable
private temporary indexing. It does **not** create output files, touch a Vault
or mean “zero temporary filesystem activity.” Large processing can require
several times the source size in temporary/output disk space. Insufficient
space fails; it does not silently omit old records.

## Exactly what is retained

Each old document maps to a new content-addressed record. IDs are **not**
claimed to be wire-compatible across the two hash/schema domains.

- Every old visible message is preserved with role, ordinal, phase and exact
  text. Large rendered bodies are losslessly quoted in numbered fragments and
  connected to an anchor. Fragments are data/provenance, not extra decisions.
- Every original document byte is additionally preserved in bounded base64
  provenance fragments carrying document SHA-256, offset, size and total size.
  These fragments also travel in normal new-protocol exports, so preserving
  evidence does not depend on keeping the capsule nearby.
- `claim_key` becomes `claim:v021:<key>`. The twelve old semantic kinds remain
  in `semantic:v021:<kind>`; concepts are also available as indexed entities.
- Old confidence, source pseudonym, source sequence, coverage and included/
  excluded-content descriptions remain in the original evidence and mapping.
  They do not become current author verification or authorization.
- Episode parents become `continues`; semantic event parents become
  `derived_from`; episodic event parents remain `continues`; `supersedes`,
  `conflicts_with` and `resolves` retain their exact directed types.
- The old event's episode evidence anchor is verified against its exact
  episode ID, source pseudonym, source sequence and episode hash before
  conversion. Semantic event IDs are checked against the original JCS domain.
- Up to four lists of 256 relations are retained. If the new record's 256-edge
  cap is exceeded, explicit bounded relation projections retain all edges;
  the anchor and projections share the claim/projection entity. The mapping
  lists those records. Nothing is collapsed into generic `related_to` edges.

The same best-effort publication scanner checks both the original JSON spelling
and every decoded field before encoding it as base64 evidence. JSON Unicode
escapes cannot bypass that decoded scan. Known secrets/forbidden local paths
cannot be hidden from scanning by this conversion. A rejected document causes the conversion
to fail, not be silently scrubbed or skipped. No claim of comprehensive DLP
or universally safe public disclosure is made; the original selected archive
and the converted capsule are private data unless independently reviewed.

### Reusing original IDs with the host bridge

After the ordinary import, the operator may register a bounded mapping part:

```text
python memory_vault_legacy_pack.py register-aliases --source /private/export/converted.zip --part 1 --config /private/client/client.json
```

Repeat for all `mapping_parts`. Registration checks the selected part hash,
the imported record's actual ID/hash/legacy-identity markers, and reconstructs
the original document fragments to check their hash/source/anchor. It then uses
the same deterministic converter to reconstruct the complete canonical anchor,
all visible/evidence fragments and exact typed relations. Every reconstructed
record must already match its imported canonical bytes. A relationship fragment
cannot replace the full anchor, even when both have the `relation` kind and the
same legacy labels. The bridge then stores the checked local alias; current
admission is independently
checked on **every use**. Registering a quarantined record does not admit it.
Partial registration after an unrelated storage failure is safe to retry:
equal aliases are idempotent and conflicts are rejected. No source/claim/task
identifier owns the memory or decides its lifetime, visibility or permissions.

The operator registration API is not exposed as a memory text instruction or
old host request. Conversion contains no old opaque host handles or pending
session queue. Whole-client control recovery is a separate explicit workflow.

## Bounds and remaining hard boundaries

The network production range is retained: source and expanded input up to
2 GiB, up to 250,000 documents, each up to 2 MiB, plus a manifest within the
overall expansion limit. ZIP manifests can be up to 64 MiB. Original pack
objects, including its manifest, are capped at 16 MiB by the **old pack
format**; a larger valid ZIP catalog cannot be repacked into that old format.
That incompatibility is explicit rather than a truncated export.

The complete converter does not inherit the small ZIP converter's 20,000-message
limit. A `conversation-export/v1` member may contain any nonempty message list
that fits the checked 2 MiB member and existing structural budgets. The count
bound comes from the actual decoded member bytes, not an untrusted manifest
claim. Every ordinal, role, phase and visible text is still validated, and all
messages retain their original bytes and ordered visible projection.

Pack indexes are parsed entry-by-entry, into temporary SQLite, up to the old
128 MiB index bound. Bodies and graph work lists are disk-indexed; at most one
ordinary document is decoded at a time. Standard-library ZIP central-directory
metadata is bounded before opening (256 MiB, 250,001 members); it is not a
whole-body in-memory loader. SQLite uses an 8 MiB page-cache target; sort/key
metadata and the single bounded manifest also require memory, so this is not
a claim of an 8 MiB total process working set.

Output record parts are at most 32 MiB/100,000 records; mapping parts at most
4 MiB; at most 4,096 parts of each type are allowed. The full record projection
is capped at 16 GiB and 8,000,000 records, and the capsule at 24 GiB. These
limits are applied during staging and never result in partial success. All
parts and original evidence are published together in one no-clobber atomic
file publication after source-fingerprint checks. A killed process can leave
a private temporary file/directory requiring explicit cleanup, not a valid
completed capsule. Temporary cleanup is limited to this invocation's paths.

Legacy episodic cycles cannot be directly represented as a closed cycle of
new content-addressed record IDs. Such a graph fails before publication with
`cyclic_legacy_graph_requires_explicit_resolution`; `verify`/`repack` can still
check and preserve the original valid graph. No edge or node is dropped to
pretend conversion succeeded. Unknown encrypted envelopes and task-scoped
legacy caches require an explicit different migration, not provider stubs.

Private outputs use POSIX ownership/modes or the shared Windows local fixed
NTFS native-ACL profile. Windows temporary indexing also requires a private
local temporary directory. Unsupported ACLs, symlinks/reparse points, unsafe
members, existing destinations and silent fallback to weaker permissions are
rejected. No execution, policy, enrollment or compute-resource permission is
restored by any of these operations.
