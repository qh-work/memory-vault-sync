# v0.25.1 capacity-patch source

This patch corrects the optional file pack's 512 MiB source ceiling in the
published v0.25.0 client. The source limit is now 2 GiB, matching the byte range
of the old taskless exports. This is a capacity correction, not a new feature
set, a protocol change or a claim that the full parity goal is complete.

## Unchanged boundaries

- Chunks remain 4 MiB, with at most 512 manifest descriptors.
- Copy still defaults to 32 uncached chunks per call; the explicit maximum is
  512. Repeat the same command to continue a bounded copy.
- Existing file-pack/v1 manifests and chunk hashes remain compatible. Canonical
  record limits, signed-sync limits and the independent lightweight protocol
  are unchanged.
- Output remains no-overwrite; source mutation and unsafe file identities are
  refused. No Task/Git ownership or permissions from recalled memory return.
- This does not provide arbitrarily large files or restore unbounded copying.

## Evidence actually obtained

On source `2f67a7099e9eba0effb3483ed3a9ba3bf2f90f80`, one explicitly opted-in
case passed in **3.891763 seconds** using an actual 516 MiB synthetic file:
create the pack, copy one chunk, resume four times at 32 chunks, repeat the
completed copy, unpack and compare the final hash. The source bytes remained
unchanged. No keys, network, private Vault or child processes were used.

Separate checks accepted a 2 GiB/512-entry manifest and rejected a sparse
2 GiB + 1 byte source by stat before output. **A full 2 GiB create/copy/unpack
transfer was not run.** The recorded time is not a throughput benchmark.
See the [exact capacity report](V0_25_PACK_CAPACITY_SMOKE.md) and
[validation index](VALIDATION.md). Earlier source-pinned reports remain
historical evidence; they were not rerun or renamed as patch results.

## Publication and remaining limits

The previous [v0.25.0 release](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.0)
at `7f27953b27b9ecd453be19084808357c89731d20` remains immutable. Its required
baseline CI passed in
[PR run 33374601764](https://github.com/qh-work/memory-vault-sync/actions/runs/33374601764)
and [main run 33374661273](https://github.com/qh-work/memory-vault-sync/actions/runs/33374661273):
eight base tests on each of three platforms, not the full v0.25 suite.
The new v0.25.1 required CI is pending; those earlier results do not cover this
patch. Check the [v0.25.1 release page](https://github.com/qh-work/memory-vault-sync/releases/tag/v0.25.1)
for publication status and matching assets. This source does not assert that
the patch has already been uploaded.

Full P01–P14 acceptance, full 2 GiB transfer, native-platform behavior,
real-host/cross-device delivery, production signing/encryption/recovery and
performance acceptance remain open. Publication does not certify those paths,
authorize tests against private data or change an installed client.
