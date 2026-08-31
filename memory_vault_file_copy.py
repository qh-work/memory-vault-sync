#!/usr/bin/env python3
"""Explicit, bounded, resumable copying of an original file without repacking.

The source has no application-level total size ceiling. A call writes at most
its selected byte budget in 4 MiB chunks. Initial source hashing, changed-file
prefix validation and final destination verification may read the whole file.
Private stat caches avoid repeated work; they are not authentication or an
isolation boundary against the same account. Nothing imports or executes bytes.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, BinaryIO, Iterator, Mapping, Sequence

from memory_vault import MemoryError, canonical_bytes, failure, strict_json_loads, success, write_response
import memory_vault_storage as protected_storage


JOURNAL_SCHEMA = "memory-vault-file-copy-journal/v1"
LEGACY_JOURNAL_SCHEMA = "memory-network-publication-journal/v1"
RESULT_SCHEMA = "memory-network-pack-copy-result/v1"
CHUNK_BYTES = 4 * 1024 * 1024
DEFAULT_MAXIMUM_BYTES = 128 * 1024 * 1024
MAXIMUM_BYTES = 256 * 1024 * 1024
MAX_JOURNAL_BYTES = 16 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")
_LEGACY_FIELDS = {"schema_version", "source_sha256", "source_bytes", "offset", "complete"}
_FIELDS = _LEGACY_FIELDS | {
    "source_path_sha256", "destination_path_sha256", "journal_path_sha256",
    "source_fingerprint", "destination_fingerprint",
}


def _fingerprint(info: os.stat_result) -> list[int]:
    # On Windows the shared native helper checks ACLs through the live handle.
    mode = stat.S_IFMT(info.st_mode) if os.name == "nt" else info.st_mode
    return [info.st_dev, info.st_ino, mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def _path_digest(path: Path) -> str:
    return hashlib.sha256(os.fsencode(os.path.normcase(str(path)))).hexdigest()


def _stable(path: Path, stream: BinaryIO, expected: list[int], *, private: bool = False) -> None:
    current = protected_storage.check_fd(stream.fileno(), private=private)
    protected_storage.validate_path(path)
    if _fingerprint(current) != expected or _fingerprint(path.lstat()) != expected:
        raise MemoryError("file_copy_file_changed")


@contextlib.contextmanager
def _open_checked(path: Path, *, writable: bool = False, create: bool = False,
                  private: bool = False) -> Iterator[tuple[BinaryIO, list[int]]]:
    before = None if create else path.lstat()
    flags = os.O_RDWR if writable else os.O_RDONLY
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = protected_storage.open_file(path, flags, private=private)
    with os.fdopen(descriptor, "r+b" if writable else "rb") as stream:
        fingerprint = _fingerprint(protected_storage.check_fd(stream.fileno(), private=private))
        if before is not None and _fingerprint(before) != fingerprint:
            raise MemoryError("file_copy_file_changed")
        _stable(path, stream, fingerprint, private=private)
        yield stream, fingerprint
        if not writable:
            _stable(path, stream, fingerprint, private=private)


def _read_journal(path: Path) -> dict[str, Any] | None:
    try:
        with _open_checked(path, private=True) as (stream, fingerprint):
            if fingerprint[4] > MAX_JOURNAL_BYTES:
                raise MemoryError("file_copy_invalid_journal")
            raw = stream.read(MAX_JOURNAL_BYTES + 1)
            _stable(path, stream, fingerprint, private=True)
    except FileNotFoundError:
        return None
    if len(raw) > MAX_JOURNAL_BYTES:
        raise MemoryError("file_copy_invalid_journal")
    value = strict_json_loads(raw)
    if not isinstance(value, dict):
        raise MemoryError("file_copy_invalid_journal")
    legacy = value.get("schema_version") == LEGACY_JOURNAL_SCHEMA
    if set(value) != (_LEGACY_FIELDS if legacy else _FIELDS) or (
            not legacy and value.get("schema_version") != JOURNAL_SCHEMA):
        raise MemoryError("file_copy_invalid_journal")
    if (not isinstance(value["source_sha256"], str) or _SHA.fullmatch(value["source_sha256"]) is None
            or type(value["source_bytes"]) is not int or value["source_bytes"] < 0
            or type(value["offset"]) is not int or not 0 <= value["offset"] <= value["source_bytes"]
            or type(value["complete"]) is not bool
            or value["complete"] and value["offset"] != value["source_bytes"]):
        raise MemoryError("file_copy_invalid_journal")
    if not legacy:
        for key in ("source_path_sha256", "destination_path_sha256", "journal_path_sha256"):
            if not isinstance(value[key], str) or _SHA.fullmatch(value[key]) is None:
                raise MemoryError("file_copy_invalid_journal")
        for key, size in (("source_fingerprint", value["source_bytes"]),
                          ("destination_fingerprint", value["offset"])):
            item = value[key]
            if (not isinstance(item, list) or len(item) != 7 or any(type(part) is not int for part in item)
                    or not stat.S_ISREG(item[2]) or item[3] != 1 or item[4] != size):
                raise MemoryError("file_copy_invalid_journal")
    return value


def _write_journal(path: Path, value: Mapping[str, Any], *, replace: bool) -> None:
    encoded = canonical_bytes(value) + b"\n"
    if len(encoded) > MAX_JOURNAL_BYTES:
        raise MemoryError("file_copy_invalid_journal")
    protected_storage.atomic_write(path, encoded, replace=replace)


def _hash(stream: BinaryIO, size: int) -> str:
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = stream.read(min(CHUNK_BYTES, remaining))
        if not chunk:
            raise MemoryError("file_copy_file_changed")
        digest.update(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise MemoryError("file_copy_file_changed")
    return digest.hexdigest()


def _verify_prefix(source: BinaryIO, destination: BinaryIO, size: int) -> None:
    source.seek(0)
    destination.seek(0)
    remaining = size
    while remaining:
        length = min(CHUNK_BYTES, remaining)
        expected, actual = source.read(length), destination.read(length)
        if len(expected) != length or actual != expected:
            raise MemoryError("file_copy_destination_conflict")
        remaining -= length


def _sync_parent(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            protected_storage.check_fd(descriptor, private=True, directory=True)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _result(source_sha256: str, source_bytes: int, offset: int, *, resumed: bool,
            copied_this_call: int) -> Mapping[str, Any]:
    return {"schema_version": RESULT_SCHEMA, "source_sha256": source_sha256,
            "source_bytes": source_bytes, "copied_bytes": offset, "resumed": resumed,
            "complete": offset == source_bytes, "copied_this_call": copied_this_call,
            "publisher_signature_verified": False, "memory_imported": False}


def _copy_locked(source: Path, destination: Path, journal: Path, maximum_bytes: int) -> Mapping[str, Any]:
    state = _read_journal(journal)
    resumed = state is not None
    legacy = state is not None and state["schema_version"] == LEGACY_JOURNAL_SCHEMA
    bindings = {"source_path_sha256": _path_digest(source),
                "destination_path_sha256": _path_digest(destination),
                "journal_path_sha256": _path_digest(journal)}
    if state is not None and not legacy and any(state[key] != value for key, value in bindings.items()):
        raise MemoryError("file_copy_journal_path_conflict")
    try:
        destination.lstat()
        destination_exists = True
    except FileNotFoundError:
        destination_exists = False
    if state is None and destination_exists:
        raise MemoryError("file_copy_output_exists_without_journal")
    if state is not None and not destination_exists and (not legacy or state["offset"] != 0):
        raise MemoryError("file_copy_destination_missing")

    with _open_checked(source) as (source_stream, source_fingerprint):
        source_bytes = source_fingerprint[4]
        if state is not None and state["source_bytes"] != source_bytes:
            raise MemoryError("file_copy_source_conflict")
        if state is not None and not legacy and state["source_fingerprint"] == source_fingerprint:
            source_sha256 = state["source_sha256"]
        else:
            source_sha256 = _hash(source_stream, source_bytes)
            _stable(source, source_stream, source_fingerprint)
            if state is not None and source_sha256 != state["source_sha256"]:
                raise MemoryError("file_copy_source_conflict")
        with _open_checked(destination, writable=True, create=not destination_exists,
                           private=True) as (destination_stream, destination_fingerprint):
            offset = state["offset"] if state is not None else 0
            existing_bytes = destination_fingerprint[4]
            if not offset <= existing_bytes <= source_bytes:
                raise MemoryError("file_copy_destination_conflict")
            if state is not None and (legacy or state["destination_fingerprint"] != destination_fingerprint):
                # The legacy journal has no path or inode binding. Even its
                # completed flag and committed offset require byte evidence.
                # Also prove any unacknowledged crash tail before adopting it;
                # never truncate or overwrite an unknown or mismatching tail.
                _verify_prefix(source_stream, destination_stream, existing_bytes)
                _stable(source, source_stream, source_fingerprint)
                _stable(destination, destination_stream, destination_fingerprint, private=True)
                offset = existing_bytes
            current = {"schema_version": JOURNAL_SCHEMA, **bindings,
                       "source_sha256": source_sha256, "source_bytes": source_bytes,
                       "source_fingerprint": source_fingerprint,
                       "destination_fingerprint": destination_fingerprint,
                       "offset": offset, "complete": False}

            def commit(*, complete: bool = False, replace: bool = True) -> None:
                nonlocal destination_fingerprint
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
                _stable(source, source_stream, source_fingerprint)
                observed = _fingerprint(protected_storage.check_fd(destination_stream.fileno(), private=True))
                _stable(destination, destination_stream, observed, private=True)
                if observed[4] != offset:
                    raise MemoryError("file_copy_destination_conflict")
                if complete:
                    if _hash(destination_stream, source_bytes) != source_sha256:
                        raise MemoryError("file_copy_destination_conflict")
                    _stable(source, source_stream, source_fingerprint)
                    _stable(destination, destination_stream, observed, private=True)
                destination_fingerprint = observed
                current.update(destination_fingerprint=observed, offset=offset, complete=complete)
                _write_journal(journal, current, replace=replace)

            if not destination_exists:
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
                _sync_parent(destination)
            # Persist ownership before any data write. A crash before this
            # first receipt can leave an empty orphan, which is refused rather
            # than silently adopted by a later new job.
            if offset == source_bytes:
                commit(complete=True, replace=state is not None)
                _stable(source, source_stream, source_fingerprint)
                _stable(destination, destination_stream, destination_fingerprint, private=True)
                return _result(source_sha256, source_bytes, offset, resumed=resumed, copied_this_call=0)
            commit(replace=state is not None)
            copied = 0
            while offset < source_bytes and copied < maximum_bytes:
                _stable(source, source_stream, source_fingerprint)
                _stable(destination, destination_stream, destination_fingerprint, private=True)
                source_stream.seek(offset)
                chunk = source_stream.read(min(CHUNK_BYTES, source_bytes - offset, maximum_bytes - copied))
                if not chunk:
                    raise MemoryError("file_copy_file_changed")
                _stable(source, source_stream, source_fingerprint)
                destination_stream.seek(offset)
                if destination_stream.write(chunk) != len(chunk):
                    raise MemoryError("file_copy_write_incomplete", retryable=True)
                offset += len(chunk)
                copied += len(chunk)
                # Bytes reach durable storage before the atomic progress
                # receipt. If the receipt fails, retry proves the crash tail.
                commit(complete=offset == source_bytes)
            _stable(source, source_stream, source_fingerprint)
            _stable(destination, destination_stream, destination_fingerprint, private=True)
            return _result(source_sha256, source_bytes, offset, resumed=resumed, copied_this_call=copied)


def resumable_copy(source: Path, destination: Path, journal: Path, *,
                   maximum_bytes: int = DEFAULT_MAXIMUM_BYTES) -> Mapping[str, Any]:
    """Copy explicit original bytes, safely resuming new or v0.21 journals.

    All paths must be absolute and link-free. Output and journal parents must
    be private (missing parents are created privately, existing ACLs/modes are
    never repaired). A pre-existing output requires a valid matching journal.
    Repeat the same call while complete is false; no network or Vault opens.
    """
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAXIMUM_BYTES:
        raise MemoryError("file_copy_invalid_byte_budget")
    try:
        source, destination, journal = (
            protected_storage.validate_path(Path(path).expanduser()) for path in (source, destination, journal)
        )
        lock = journal.with_name(journal.name + ".lock")
        paths = (source, destination, journal, lock)
        if len(set(paths)) != len(paths) or any(first in second.parents for first in paths for second in paths):
            raise MemoryError("file_copy_paths_must_be_separate")
        protected_storage.private_directory(journal.parent)
        protected_storage.private_directory(destination.parent)
        with protected_storage.file_lock(lock, busy_code="file_copy_busy"):
            return _copy_locked(source, destination, journal, maximum_bytes)
    except protected_storage.StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, required=True, help="absolute original source file; no repackage")
    parser.add_argument("--output", type=Path, required=True, help="absolute private destination file")
    parser.add_argument("--journal", type=Path, required=True, help="absolute private progress journal")
    parser.add_argument("--maximum-bytes", type=int, default=DEFAULT_MAXIMUM_BYTES,
                        help="bytes written this call: 1..268435456; default 134217728")
    args = parser.parse_args(argv)
    try:
        write_response(success(resumable_copy(args.pack, args.output, args.journal, maximum_bytes=args.maximum_bytes)))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except Exception:
        write_response(failure("file_copy_unavailable", retryable=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
