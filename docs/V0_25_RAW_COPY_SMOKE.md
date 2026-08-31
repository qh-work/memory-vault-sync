# Original-file continuation: one selected offline check

This report concerns an unreleased raw-copy correction, not completion of cloud
synchronization or the full v0.25 goal. Publication was paused when the owner
identified missing usable cloud setup and requested migration of the installed
client plus real cloud upload/receive testing.

## Exact execution

- Source: `7bd190471d3b7328961899b2cf13a5c72a666c28`.
- Method: `test_v025_raw_copy.RawCopyTests.test_original_large_bytes_and_legacy_resume_preserve_data`.
- One method passed in 10.817239 seconds; zero failures, errors or skips.
- Python 3.12.13 on macOS; all 29 runtime source hashes remained unchanged.
- Ordinary discovery skips the fixture. Explicit opt-in is
  `MEMORY_VAULT_RAW_COPY_SMOKE=1`; allow about 2.2 GiB of temporary disk space.

The real client `copy-pack` command copied the first 4 MiB of a sparse synthetic
2 GiB + 4 MiB original file. Eight calls then copied 256 MiB each, without
repackaging. The final output length and independently streamed SHA-256 matched
the source; repeating a completed copy wrote zero bytes and reverified output.

The same method independently encoded v0.21's five-field journal and checked
migration of a small committed prefix plus matching unacknowledged tail. It
also verified that a corrupt completed output and an unrelated existing output
were refused without changing their bytes or the existing progress receipt.

No mocked I/O result, network, child process, Vault, private data or key was
used. A runner audit guard rejected network/child creation and writes outside
the disposable evidence directory; no boundary violations occurred. This is
not a throughput benchmark, arbitrary-size certification, live cloud transfer,
Windows run or a full test suite.

## Contract limits

The direct byte-copy path has no application total-file-size ceiling. Its
default write budget is 128 MiB, selectable from 1 byte through 256 MiB, with
4 MiB chunks. That budget limits writes, not all reads or elapsed time. First
use, changed-source metadata and legacy acceptance hash the full source;
completion hashes the full destination. Private metadata caches are not
authentication. Copying imports no memory and verifies no publisher signature.

Output/journal files and parents must meet the private storage profile. Old
world-readable outputs require an explicit operator permissions correction;
the copy command does not silently chmod them or overwrite unknown outputs.

## Retained raw evidence hashes

| Evidence | SHA-256 |
| --- | --- |
| Runner | `5940f99e128bc2ce514fe0ff4ff49bbdae47f77281187bed0f12f221d6240af8` |
| Structured result | `5e23c03d18d46bcc33dd9ea51067d32318b02669932e6ca449afaaccb151c4a9` |
| Test output | `4b1c5a5be58385d5b9a9eb759e97494d6fc407a1cfa5096bde13990a30500efb` |

Other runtime and cloud checks remain unexecuted unless separately recorded.
