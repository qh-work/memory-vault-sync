# Compressed packs and resumable copy

The full client can pack one explicitly selected portable export or consistent
backup snapshot into bounded compressed chunks. This is a new optional file
transport profile, **not** the old v0.21 pack format or a Task artifact store.
It leaves canonical memory records and the lightweight protocol unchanged.

From the packaged plugin root:

```bash
python3 scripts/launcher.py pack create --source /absolute/export.ndjson --out /absolute/new/export-pack
python3 scripts/launcher.py pack copy --source /absolute/new/export-pack --out /absolute/other-device/copied-pack
python3 scripts/launcher.py pack unpack --source /absolute/other-device/copied-pack --out /absolute/new/received.ndjson
```

`create` reads a regular, explicitly selected file of at most 512 MiB, splits it
into 4 MiB chunks and compresses each independently. It records compressed and
uncompressed hashes, chunk order, total bytes and a whole-file digest. The
manifest contains no source filename or private local path. Source mutation
during packing aborts completion. A new directory may remain for inspection;
existing files are never replaced.

`copy` operates between selected local/mounted directories. It processes at most
32 uncached chunks by default; repeat the exact command for the next bounded
portion, or select `--maximum-chunks` up to 128. Completed chunks are retained;
the destination manifest is published only after all chunks are present. Its
private `COPY_STATE.json` caches verified file metadata so unchanged chunks do
not need repeated hashing on every retry. This cache assumes the operator's
filesystem is trusted; it is **not an authentication boundary**.

`unpack` always verifies every compressed hash, bounded decompression, plaintext
chunk hash and final file hash. It publishes only to a **new file** after full
verification. Unpacking does not import records, trust a sender, decrypt data or
execute the output. For a memory export, follow the ordinary quarantine/import
flow; for a backup, follow [BACKUP.md](BACKUP.md).

`pack inspect --source /absolute/pack` reads only manifest metadata and reports
that file bytes have not been verified. It does not create state.

Packs have no network client; the selected mount may perform network I/O under
the OS. [SYNC.md](SYNC.md) instead uses small signed incremental memory batches
and optional rclone transport; it does not repack the entire history per turn.
Compression is not encryption and a hash is not an author's signature. Use a
private destination or a separately configured encrypted transport for private
memory. No performance benchmark or interruption test was run for this release.
