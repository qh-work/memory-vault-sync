# Targeted file-pack capacity correction

After v0.25.0 publication, source comparison found a concrete byte-carriage
restriction: its optional compressed file pack rejected sources above 512 MiB,
while the old taskless export workflow had a 2 GiB data range. The correction
raises the explicit source-file bound to 2 GiB and the descriptor bound to 512.
It does not change the 4 MiB chunks, default 32-uncached-chunk copy window,
canonical records, signatures, or signed synchronization group limits.

The v0.21 baseline is `030ed411ed9ddb969a03f0b5caec87dac9b0dd57`:
`memory_vault_runtime/core.py` exposes `copy_memory_pack` through `copy-pack`,
and `memory_vault_runtime/transport.py` performs streaming byte copying. That
old helper itself had no total byte ceiling; the old pack's 2 GiB bound is a
raw-object bound, not a promise about every possible container's encoded size.
This correction supports files up to 2 GiB. It is not a claim of unbounded
copy parity or arbitrary-size memory synchronization.

## Exactly one executed method

Source: `2f67a7099e9eba0effb3483ed3a9ba3bf2f90f80`.

`tests.test_v025_pack_capacity.PackCapacityTests.test_old_export_capacity_and_resumed_copy_preserve_complete_bytes`

Result: **one pass**, no failures, errors, skips or boundary violations;
elapsed runner time **3.891763 seconds**, macOS/Python 3.12.13. Source-file
hashes were identical before and after execution. No suite discovery or other
new runtime methods were executed in this correction's local acceptance.
The later release-version change from 0.25.0 to 0.25.1 is metadata only; the
pack implementation remains exactly the source exercised above.

The method used actual pack/copy/unpack operations, not mocked source sizes or
mocked storage results:

1. Accepted a real 512-descriptor manifest representing exactly 2 GiB and
   verified it fits the existing 128 KiB manifest limit. Its intentionally
   synthetic chunk hashes are framing input, not proof of 2 GiB of data.
2. Rejected an actual sparse file of 2 GiB + 1 byte before creating output.
3. Created a sparse **516 MiB** synthetic source with 129 distinct chunk
   prefixes, streamed its digest, and packed every byte through the real
   compressor. The input really exceeds the published v0.25.0 bound.
4. Copied one chunk, confirmed the destination manifest was not yet published,
   then resumed through four default 32-chunk windows. No call exceeded that
   work budget. The final copied manifest exactly matched the original.
5. Repeated the completed copy with zero copied/rehashed chunks, unpacked to a
   new 516 MiB file, and independently streamed its SHA-256 to compare with the
   original. An attempted overwrite was refused.

## Resource and trust limits

All source, chunks, receipts and output files were synthetic and confined to
one temporary directory. The sparse source was not read from user memory or
an old private pack. One unpacked 516 MiB output existed temporarily; fixture
cleanup removed its own data after the run. The retained runner/report/log
contain no memory content. Audit guards refused network/child-process events,
writes outside the evidence root, and SQLite outside that root. None occurred.

The fixture requires explicit `MEMORY_VAULT_LARGE_PACK_SMOKE=1`, so ordinary
discovery does not unexpectedly perform this disk-consuming check. It needs
roughly 600 MiB of free space. This case does not establish a full 2 GiB
transfer, real cloud throughput, power-loss recovery, Windows native file-pack
behavior, publisher authentication or unbounded copying. The elapsed time is
not a benchmark. Existing broad limitations remain in [VALIDATION.md](VALIDATION.md).

Independent metadata-size arithmetic found a maximal generated 512-entry
manifest of 112,740 bytes. A copy receipt using conservative signed 128-bit
filesystem metadata fields fits in 123,537 bytes. Both remain below 128 KiB;
no control-file or per-chunk memory bound was relaxed.

## Retained raw evidence

The local `memory-vault-v025-pack-capacity.K1egQm` directory retains these
files; the JSON report includes exact method/source-file hashes. Local machine
paths are not included in the public distribution.

| File | SHA-256 |
| --- | --- |
| `run_capacity.py` | `c1c16ad2a84edbf5a71240e047edf6de7bf811afb16c2d1146bc7008927253b3` |
| `capacity-result.json` | `0679b2232c59fc986b8cfecf0df02503265f5c452a9c5004dcc10926b1432fe5` |
| `capacity-output.log` | `b3fef82d1be8d4c49cd20a07bc88d8059c3ca15b179add93029c259ea642d00e` |
