#!/usr/bin/env python3
"""Optional compressed file packs and resumable local/shared-directory copying.

Packs transport an explicitly selected export or snapshot as bytes. Their hash
manifest is not a signature, admission policy, network transport or permission
to execute the unpacked file. Nothing discovers transcripts or old task paths.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, BinaryIO, Iterator, Mapping, Sequence
import uuid
import zlib

from memory_vault import MemoryError, canonical_bytes, failure, strict_json_loads, success, write_response
from memory_vault_client import _absolute, _private_directory, _read_json, _write_once
import memory_vault_storage as protected_storage


SCHEMA = "memory-vault-file-pack/v1"
COPY_SCHEMA = "memory-vault-pack-copy/v1"
CHUNK_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_COMPRESSED_BYTES = CHUNK_BYTES + 64 * 1024
MAX_CHUNKS = MAX_SOURCE_BYTES // CHUNK_BYTES
MAX_MANIFEST_BYTES = 128 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    # Native access control is checked through the handle, not synthesized
    # POSIX permission bits from a Windows pathname/stat implementation.
    mode = stat.S_IFMT(info.st_mode) if os.name == "nt" else info.st_mode
    return (info.st_dev, info.st_ino, mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextlib.contextmanager
def _source_stream(path: Path, maximum: int, *, private: bool = False) -> Iterator[BinaryIO]:
    """Keep the validated descriptor for the entire read; never follow links."""
    selected = _absolute(path)
    before = selected.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise MemoryError("pack_unsafe_or_oversized_file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = (protected_storage.open_file(selected, flags, private=private) if os.name == "nt"
                  else os.open(selected, flags))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum
                or _fingerprint(info) != _fingerprint(before)):
            raise MemoryError("pack_unsafe_or_oversized_file")
        yield stream
        if _fingerprint(os.fstat(stream.fileno())) != _fingerprint(info) or _fingerprint(selected.lstat()) != _fingerprint(info):
            raise MemoryError("pack_source_changed_retry_new_output")


def _read(path: Path, maximum: int) -> bytes:
    with _source_stream(path, maximum) as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise MemoryError("pack_file_limit")
    return data


def _signature(path: Path) -> list[int]:
    with _source_stream(path, MAX_COMPRESSED_BYTES, private=True) as stream:
        info = os.fstat(stream.fileno())
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _atomic_state(path: Path, value: Mapping[str, Any]) -> None:
    """Replace only the reserved copy receipt in this selected private pack."""
    _absolute(path)
    _private_directory(path.parent)
    if path.exists():
        _read_json(path, maximum=MAX_MANIFEST_BYTES)
    if os.name == "nt":
        protected_storage.atomic_write(path, canonical_bytes(value) + b"\n", replace=True)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".pack-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


def _new_bytes(path: Path, data: bytes) -> None:
    """No-clobber publication of complete bytes, including the final manifest."""
    _absolute(path)
    try:
        if os.name == "nt":
            protected_storage.atomic_write(path, data, replace=False)
            return
        descriptor, temporary = tempfile.mkstemp(prefix=".pack-write-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # A copied chunk is either absent or has one complete name, even
            # when interrupted before the copy receipt has been committed.
            protected_storage.publish_file(Path(temporary), path, replace=False)
        finally:
            with contextlib.suppress(FileNotFoundError):
                Path(temporary).unlink()
    except protected_storage.StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None


def _new_directory(path: Path) -> None:
    """Create one new private pack root; do not adopt an existing directory."""
    if os.name == "nt":
        protected_storage.private_directory(path.parent)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700)
    if os.name == "nt":
        protected_storage.check_private_directory(path)
    (path / "chunks").mkdir(mode=0o700)
    if os.name == "nt":
        protected_storage.check_private_directory(path / "chunks")


def _manifest(directory: Path) -> tuple[Mapping[str, Any], bytes]:
    data = _read(_absolute(directory) / "MANIFEST.json", MAX_MANIFEST_BYTES)
    value = strict_json_loads(data)
    if not isinstance(value, dict) or set(value) != {"schema_version", "source_bytes", "source_sha256", "chunk_bytes", "compression", "chunks"}:
        raise MemoryError("invalid_pack_manifest")
    if value["schema_version"] != SCHEMA or value["chunk_bytes"] != CHUNK_BYTES or value["compression"] != "zlib":
        raise MemoryError("unsupported_pack_format")
    if (type(value["source_bytes"]) is not int or not 0 <= value["source_bytes"] <= MAX_SOURCE_BYTES
            or not isinstance(value["source_sha256"], str) or _SHA.fullmatch(value["source_sha256"]) is None):
        raise MemoryError("invalid_pack_manifest")
    chunks = value["chunks"]
    if not isinstance(chunks, list) or len(chunks) > MAX_CHUNKS:
        raise MemoryError("pack_chunk_limit")
    total = 0
    for index, chunk in enumerate(chunks):
        if not isinstance(chunk, dict) or set(chunk) != {"index", "bytes", "sha256", "compressed_bytes", "compressed_sha256"}:
            raise MemoryError("invalid_pack_chunk")
        if (type(chunk["index"]) is not int or chunk["index"] != index
                or type(chunk["bytes"]) is not int or not 1 <= chunk["bytes"] <= CHUNK_BYTES
                or type(chunk["compressed_bytes"]) is not int or not 1 <= chunk["compressed_bytes"] <= MAX_COMPRESSED_BYTES
                or any(not isinstance(chunk[name], str) or _SHA.fullmatch(chunk[name]) is None for name in ("sha256", "compressed_sha256"))):
            raise MemoryError("invalid_pack_chunk")
        if index + 1 < len(chunks) and chunk["bytes"] != CHUNK_BYTES:
            raise MemoryError("invalid_pack_chunk_order")
        total += chunk["bytes"]
    if total != value["source_bytes"] or bool(chunks) != bool(total):
        raise MemoryError("pack_size_mismatch")
    return value, data


def _chunk_path(directory: Path, chunk: Mapping[str, Any]) -> Path:
    return _absolute(directory / "chunks" / (chunk["compressed_sha256"] + ".z"))


def create(source: Path, output: Path) -> Mapping[str, Any]:
    source, output = _absolute(source), _absolute(output)
    if output.exists():
        raise MemoryError("pack_output_exists")
    with _source_stream(source, MAX_SOURCE_BYTES) as stream:
        info = os.fstat(stream.fileno())
        _new_directory(output)
        chunks: list[Mapping[str, Any]] = []
        whole = hashlib.sha256()
        total = 0
        while True:
            data = stream.read(CHUNK_BYTES)
            if not data:
                break
            total += len(data)
            if total > MAX_SOURCE_BYTES or len(chunks) >= MAX_CHUNKS:
                raise MemoryError("pack_source_limit")
            whole.update(data)
            compressed = zlib.compress(data, level=6)
            chunk = {"index": len(chunks), "bytes": len(data), "sha256": _digest(data),
                     "compressed_bytes": len(compressed), "compressed_sha256": _digest(compressed)}
            target = _chunk_path(output, chunk)
            if target.exists():
                if _read(target, MAX_COMPRESSED_BYTES) != compressed:
                    raise MemoryError("pack_chunk_conflict")
            else:
                _new_bytes(target, compressed)
            chunks.append(chunk)
        after = os.fstat(stream.fileno())
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or total != info.st_size:
            raise MemoryError("pack_source_changed_retry_new_output")
    manifest = {"schema_version": SCHEMA, "source_bytes": total, "source_sha256": whole.hexdigest(),
                "chunk_bytes": CHUNK_BYTES, "compression": "zlib", "chunks": chunks}
    _write_once(output / "MANIFEST.json", manifest)
    return {"state": "packed", "source_bytes": total, "chunks": len(chunks),
            "compressed_bytes": sum(item["compressed_bytes"] for item in chunks),
            "publisher_signature_verified": False, "network_accessed": False}


def copy(source: Path, output: Path, *, maximum_chunks: int = 32) -> Mapping[str, Any]:
    if type(maximum_chunks) is not int or not 1 <= maximum_chunks <= MAX_CHUNKS:
        raise MemoryError("invalid_pack_copy_limit")
    source, output = _absolute(source), _absolute(output)
    if source == output or source in output.parents or output in source.parents:
        raise MemoryError("pack_copy_paths_overlap")
    manifest, encoded = _manifest(source)
    manifest_hash = _digest(encoded)
    state_path = output / "COPY_STATE.json"
    if not output.exists():
        _new_directory(output)
        _write_once(state_path, {"schema_version": COPY_SCHEMA, "manifest_sha256": manifest_hash, "verified": {}})
    _private_directory(output)
    _private_directory(output / "chunks")
    state = _read_json(state_path, maximum=MAX_MANIFEST_BYTES)
    if (not isinstance(state, dict) or set(state) != {"schema_version", "manifest_sha256", "verified"}
            or state["schema_version"] != COPY_SCHEMA or state["manifest_sha256"] != manifest_hash
            or not isinstance(state["verified"], dict) or len(state["verified"]) > MAX_CHUNKS):
        raise MemoryError("pack_copy_state_conflict")
    copied = cached = checked = 0
    for chunk in manifest["chunks"]:
        target = _chunk_path(output, chunk)
        digest = chunk["compressed_sha256"]
        if target.exists() and state["verified"].get(digest) == _signature(target):
            cached += 1
            continue
        if checked >= maximum_chunks:
            break
        checked += 1
        if target.exists():
            signature = _signature(target)
            data = _read(target, MAX_COMPRESSED_BYTES)
            if signature != _signature(target) or len(data) != chunk["compressed_bytes"] or _digest(data) != digest:
                raise MemoryError("pack_existing_chunk_conflict")
        else:
            data = _read(_chunk_path(source, chunk), MAX_COMPRESSED_BYTES)
            if len(data) != chunk["compressed_bytes"] or _digest(data) != digest:
                raise MemoryError("pack_source_chunk_mismatch")
            # Publish only a complete chunk. Interrupted copies can therefore
            # retry without overwriting or mistaking a partial file for data.
            _new_bytes(target, data)
            copied += 1
        state["verified"][digest] = _signature(target)
        _atomic_state(state_path, state)
    complete = all(
        _chunk_path(output, item).exists()
        and state["verified"].get(item["compressed_sha256"]) == _signature(_chunk_path(output, item))
        for item in manifest["chunks"]
    )
    if complete:
        target_manifest = output / "MANIFEST.json"
        if target_manifest.exists():
            if _read(target_manifest, MAX_MANIFEST_BYTES) != encoded:
                raise MemoryError("pack_destination_manifest_conflict")
        else:
            _new_bytes(target_manifest, encoded)
    return {"state": "copy_complete" if complete else "copy_pending_repeat_same_command",
            "copied_chunks": copied, "unchanged_chunks_skipped": cached,
            "chunks_checked_this_run": checked, "total_chunks": len(manifest["chunks"]),
            "resume_cache_is_authentication": False, "network_accessed_by_process": False}


def unpack(source: Path, output: Path) -> Mapping[str, Any]:
    source, output = _absolute(source), _absolute(output)
    if output.exists() or source == output or source in output.parents:
        raise MemoryError("pack_unpack_requires_new_external_file")
    manifest, _ = _manifest(source)
    if os.name == "nt":
        protected_storage.private_directory(output.parent)
        temporary = output.parent / (".memory-unpack-" + uuid.uuid4().hex)
        descriptor = protected_storage.open_file(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".memory-unpack-", dir=output.parent)
    whole = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "wb") as stream:
            for chunk in manifest["chunks"]:
                compressed = _read(_chunk_path(source, chunk), MAX_COMPRESSED_BYTES)
                if len(compressed) != chunk["compressed_bytes"] or _digest(compressed) != chunk["compressed_sha256"]:
                    raise MemoryError("pack_chunk_hash_mismatch")
                decoder = zlib.decompressobj()
                data = decoder.decompress(compressed, chunk["bytes"] + 1)
                if (len(data) != chunk["bytes"] or not decoder.eof or decoder.unused_data
                        or decoder.unconsumed_tail or _digest(data) != chunk["sha256"]):
                    raise MemoryError("pack_decompression_mismatch")
                stream.write(data)
                whole.update(data)
            if whole.hexdigest() != manifest["source_sha256"]:
                raise MemoryError("pack_source_hash_mismatch")
            stream.flush()
            os.fsync(stream.fileno())
        # A selected unpack destination is not a private control directory on
        # POSIX. Keep its existing sharing permissions without weakening the
        # new file's 0600/single-link checks or the native private profile.
        protected_storage.publish_file(Path(temporary), output, replace=False, private_parent=os.name == "nt")
    except protected_storage.StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()
    return {"state": "unpacked_not_imported", "bytes": manifest["source_bytes"],
            "source_sha256": whole.hexdigest(), "publisher_signature_verified": False}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "copy", "unpack", "inspect"):
        entry = sub.add_parser(command)
        entry.add_argument("--source", type=Path, required=True)
        if command != "inspect":
            entry.add_argument("--out", type=Path, required=True)
        if command == "copy":
            entry.add_argument("--maximum-chunks", type=int, default=32)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            result = create(args.source, args.out)
        elif args.command == "copy":
            result = copy(args.source, args.out, maximum_chunks=args.maximum_chunks)
        elif args.command == "unpack":
            result = unpack(args.source, args.out)
        else:
            value, _ = _manifest(args.source)
            result = {"state": "manifest_read_only", "source_bytes": value["source_bytes"],
                      "chunks": len(value["chunks"]), "file_bytes_verified": False,
                      "publisher_signature_verified": False}
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except Exception:
        write_response(failure("pack_unavailable", retryable=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
