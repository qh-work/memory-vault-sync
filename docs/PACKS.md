# Compressed packs and resumable copy

The full client can pack one explicitly selected portable export or consistent
backup snapshot into bounded compressed chunks. This is a new optional file
transport profile, **not** the old v0.21 pack format or a Task artifact store.
It leaves canonical memory records and the lightweight protocol unchanged.
To verify/convert actual v0.21 `memory-pack/v1` or large network ZIP evidence,
use [LEGACY_PACKS.md](LEGACY_PACKS.md); this file-byte profile does not reinterpret
those old semantic formats.

From the packaged plugin root:

```bash
python3 scripts/launcher.py pack create --source /absolute/export.ndjson --out /absolute/new/export-pack
python3 scripts/launcher.py pack copy --source /absolute/new/export-pack --out /absolute/other-device/copied-pack
python3 scripts/launcher.py pack unpack --source /absolute/other-device/copied-pack --out /absolute/new/received.ndjson
```

`create` reads a regular, explicitly selected file of at most 2 GiB, splits it
into 4 MiB chunks and compresses each independently. It records compressed and
uncompressed hashes, chunk order, total bytes and a whole-file digest. The
manifest contains no source filename or private local path. Source mutation
during packing aborts completion. A new directory may remain for inspection;
existing files are never replaced.

Reads retain the checked file descriptor through each operation and verify its
identity, size and change metadata afterward. Symlinks/reparse points and files
with multiple hard links are refused; choosing a hard-linked source requires
making an ordinary separate copy first.

`copy` operates between selected local/mounted directories. It processes at most
32 uncached chunks by default; repeat the exact command for the next bounded
portion, or select `--maximum-chunks` up to 512. Completed chunks are retained;
the destination manifest is published only after all chunks are present. Its
private `COPY_STATE.json` caches verified file metadata so unchanged chunks do
not need repeated hashing on every retry. This cache assumes the operator's
filesystem is trusted; it is **not an authentication boundary**.

The 2 GiB limit restores byte-carriage capacity for the old taskless exports;
the published v0.25.0 client was limited to 512 MiB. This is an unreleased
capacity correction, not a rewrite of that release. Existing file-pack/v1
manifests and chunk hashes are unchanged. The implementation still reads and
compresses only one 4 MiB chunk at a time, has at most 512 chunk descriptors,
and keeps the default 32-uncached-chunk copy budget. Canonical record sizes and
signed synchronization limits do not change. This is a bounded capacity
contract, not a performance claim or support for arbitrarily large files.

`unpack` always verifies every compressed hash, bounded decompression, plaintext
chunk hash and final file hash. It publishes only to a **new file** after full
verification. Unpacking does not import records, trust a sender, decrypt data or
execute the output. For a memory export, follow the ordinary quarantine/import
flow; for a backup, follow [BACKUP.md](BACKUP.md).

`pack inspect --source /absolute/pack` reads only manifest metadata and reports
that file bytes have not been verified. It does not create state.

On Windows, the same create/copy/unpack operations use the shared native storage
profile: local fixed NTFS, checked process-user private ACLs on new output/state
directories, no reparse paths, and same-volume no-replacement publication. The
CRT receives ownership of a checked native handle; no `chmod`, POSIX hard-link
publication or silent permission repair is substituted. Existing directories
with incompatible ACLs are refused. On supported macOS/Linux filesystems,
private chunks/manifests and explicit unpack outputs use a single exclusive
rename: a published chunk can be verified on retry without waiting for removal
of a temporary hard-link alias. POSIX unpack retains the caller-selected parent
permissions, while new output bytes remain private and single-linked. Existing
outputs are never overwritten. See [PLATFORMS.md](PLATFORMS.md).

Packs have no network client; the selected mount may perform network I/O under
the OS. [SYNC.md](SYNC.md) instead uses small signed incremental memory batches
and optional rclone transport; it does not repack the entire history per turn.
Compression is not encryption and a hash is not an author's signature. Use a
private destination or a separately configured encrypted transport for private
memory. Public synthetic cases in `tests/test_v025_portable_packs.py` cover the
native routing, unchanged bounds, resumable copies and unsafe-file refusals;
those methods were authored but **not run**. Selected publication cases in
`tests/test_v025_transport_publication.py` have their execution recorded
separately in [VALIDATION.md](VALIDATION.md). No native Windows or performance
certification is claimed.
