"""Bounded streaming packs for canonical taskless memory objects.

Packs are an acceleration layer only.  Each member keeps its canonical
repository path, byte size, and SHA-256 identity; readers can verify and
restore the original bytes without trusting the pack container.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import struct
import tempfile
import zlib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable, Iterator, Mapping

from memory_vault_runtime.protocol import jcs_json_bytes, strict_json_loads


PACK_SCHEMA = "memory-pack/v1"
INDEX_SCHEMA = "memory-pack-index/v1"
MAGIC = b"memory-pack/v1\n"
FOOTER_MAGIC = b"memory-pack-index/v1\n"
MAX_OBJECTS = 1_000_000
MAX_OBJECT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_INDEX_BYTES = 128 * 1024 * 1024


class PackError(ValueError):
    """Pack structure, size, identity, or path validation failed."""


@dataclasses.dataclass(frozen=True)
class PackEntry:
    path: str
    sha256: str
    raw_size: int
    offset: int
    compressed_size: int


@dataclasses.dataclass(frozen=True)
class PackSummary:
    path: str
    object_count: int
    raw_bytes: int
    pack_bytes: int
    sha256: str
    object_root_sha256: str


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise PackError("pack path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PackError("pack path is unsafe")
    if "\\" in value:
        raise PackError("pack path must use POSIX separators")
    return path.as_posix()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _object_root(entries: Iterable[PackEntry]) -> str:
    domain = [
        {"path": item.path, "raw_size": item.raw_size, "sha256": item.sha256}
        for item in sorted(entries, key=lambda value: value.path)
    ]
    return _sha256(jcs_json_bytes(domain))


def _positive_int(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise PackError(f"{label} is invalid")
    return value


def _entry(value: Mapping[str, Any]) -> PackEntry:
    if set(value) != {"path", "sha256", "raw_size", "offset", "compressed_size"}:
        raise PackError("pack index entry fields are invalid")
    path = _safe_path(value["path"])
    sha256 = value["sha256"]
    if not isinstance(sha256, str) or len(sha256) != 64 or any(
        character not in "0123456789abcdef" for character in sha256
    ):
        raise PackError("pack object hash is invalid")
    raw_size = _positive_int(value["raw_size"], "pack raw size", MAX_OBJECT_BYTES)
    offset = _positive_int(value["offset"], "pack offset", MAX_TOTAL_BYTES)
    compressed_size = _positive_int(
        value["compressed_size"], "pack compressed size", MAX_TOTAL_BYTES
    )
    return PackEntry(path, sha256, raw_size, offset, compressed_size)


class PackWriter:
    """Write one independently compressed object record at a time."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if self.path.exists():
            raise PackError("pack destination already exists")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("xb")
        self._file.write(MAGIC)
        self._index = tempfile.TemporaryFile(dir=str(self.path.parent))
        self._count = 0
        self._raw_bytes = 0
        self._closed = False
        self._paths: set[str] = set()

    def add(self, path: str, raw: bytes) -> PackEntry:
        if self._closed:
            raise PackError("pack writer is closed")
        path = _safe_path(path)
        if path in self._paths:
            raise PackError("pack path is duplicated")
        if not isinstance(raw, bytes) or len(raw) > MAX_OBJECT_BYTES:
            raise PackError("pack object is too large")
        if self._count >= MAX_OBJECTS or self._raw_bytes + len(raw) > MAX_TOTAL_BYTES:
            raise PackError("pack bounds exceeded")
        compressed = zlib.compress(raw, level=6)
        entry = PackEntry(
            path=path,
            sha256=_sha256(raw),
            raw_size=len(raw),
            offset=self._file.tell(),
            compressed_size=len(compressed),
        )
        header = jcs_json_bytes(
            {
                "compressed_size": entry.compressed_size,
                "path": entry.path,
                "raw_size": entry.raw_size,
                "sha256": entry.sha256,
            }
        )
        if len(header) > MAX_HEADER_BYTES:
            raise PackError("pack record header is too large")
        self._file.write(struct.pack(">I", len(header)))
        self._file.write(header)
        self._file.write(compressed)
        index_value = jcs_json_bytes(dataclasses.asdict(entry))
        if self._count:
            self._index.write(b",")
        self._index.write(index_value)
        self._paths.add(path)
        self._count += 1
        self._raw_bytes += len(raw)
        return entry

    def finish(self) -> PackSummary:
        if self._closed:
            raise PackError("pack writer is closed")
        self._index.flush()
        self._index.seek(0)
        index_prefix = b'{"entries":['
        index_suffix = b'],"schema_version":"' + INDEX_SCHEMA.encode("ascii") + b'"}'
        index_length = len(index_prefix) + self._index.seek(0, os.SEEK_END) + len(index_suffix)
        self._index.seek(0)
        self._file.write(index_prefix)
        while True:
            chunk = self._index.read(1024 * 1024)
            if not chunk:
                break
            self._file.write(chunk)
        self._file.write(index_suffix)
        self._file.write(struct.pack(">Q", index_length))
        self._file.write(FOOTER_MAGIC)
        self._file.flush()
        os.fsync(self._file.fileno())
        self._file.close()
        self._index.close()
        self._closed = True
        digest = _file_sha256(self.path)
        self.path.chmod(0o600)
        return PackSummary(
            path=str(self.path),
            object_count=self._count,
            raw_bytes=self._raw_bytes,
            pack_bytes=self.path.stat().st_size,
            sha256=digest,
            object_root_sha256="",
        )

    def abort(self) -> None:
        if not self._closed:
            self._closed = True
            self._file.close()
            self._index.close()
            self.path.unlink(missing_ok=True)

    def __enter__(self) -> "PackWriter":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self.finish()
        else:
            self.abort()


class PackReader:
    """Verify a pack footer and stream independently compressed records."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if not self.path.is_file() or self.path.is_symlink():
            raise PackError("pack source is not a regular file")
        self._file = self.path.open("rb")
        self._size = self.path.stat().st_size
        if self._size < len(MAGIC) + len(FOOTER_MAGIC) + 8:
            raise PackError("pack is truncated")
        if self._file.read(len(MAGIC)) != MAGIC:
            raise PackError("pack magic is invalid")
        self._file.seek(-len(FOOTER_MAGIC), os.SEEK_END)
        if self._file.read(len(FOOTER_MAGIC)) != FOOTER_MAGIC:
            raise PackError("pack footer is invalid")
        self._file.seek(-len(FOOTER_MAGIC) - 8, os.SEEK_END)
        index_length = struct.unpack(">Q", self._file.read(8))[0]
        if not 1 <= index_length <= MAX_INDEX_BYTES:
            raise PackError("pack index size is invalid")
        self._index_start = self._size - len(FOOTER_MAGIC) - 8 - index_length
        if self._index_start < len(MAGIC):
            raise PackError("pack index offset is invalid")
        self._file.seek(self._index_start)
        index_raw = self._file.read(index_length)
        try:
            index_value = strict_json_loads(index_raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PackError("pack index JSON is invalid") from exc
        if not isinstance(index_value, Mapping) or set(index_value) != {
            "entries", "schema_version"
        } or index_value["schema_version"] != INDEX_SCHEMA:
            raise PackError("pack index schema is invalid")
        entries = index_value["entries"]
        if not isinstance(entries, list) or len(entries) > MAX_OBJECTS:
            raise PackError("pack index entries are invalid")
        self._entries = tuple(_entry(item) for item in entries if isinstance(item, Mapping))
        if len(self._entries) != len(entries) or len({item.path for item in self._entries}) != len(self._entries):
            raise PackError("pack index identity is invalid")
        self._by_path = {item.path: item for item in self._entries}

    @property
    def entries(self) -> tuple[PackEntry, ...]:
        return self._entries

    def iter_objects(self) -> Iterator[tuple[PackEntry, bytes]]:
        self._file.seek(len(MAGIC))
        seen: set[str] = set()
        while self._file.tell() < self._index_start:
            offset = self._file.tell()
            raw_header_length = self._file.read(4)
            if len(raw_header_length) != 4:
                raise PackError("pack record header is truncated")
            header_length = struct.unpack(">I", raw_header_length)[0]
            if not 1 <= header_length <= MAX_HEADER_BYTES:
                raise PackError("pack record header length is invalid")
            raw_header = self._file.read(header_length)
            if len(raw_header) != header_length:
                raise PackError("pack record header is truncated")
            try:
                header_value = strict_json_loads(raw_header.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise PackError("pack record header JSON is invalid") from exc
            if not isinstance(header_value, Mapping) or set(header_value) != {
                "compressed_size", "path", "raw_size", "sha256"
            }:
                raise PackError("pack record header fields are invalid")
            header = _entry(
                {
                    **header_value,
                    "offset": offset,
                }
            )
            indexed = self._by_path.get(header.path)
            if indexed != header:
                raise PackError("pack record does not match its index")
            if header.path in seen:
                raise PackError("pack record path is duplicated")
            compressed = self._file.read(header.compressed_size)
            if len(compressed) != header.compressed_size:
                raise PackError("pack record payload is truncated")
            try:
                decompressor = zlib.decompressobj()
                raw = decompressor.decompress(compressed, header.raw_size + 1)
                if len(raw) <= header.raw_size:
                    raw += decompressor.flush(header.raw_size + 1 - len(raw))
            except zlib.error as exc:
                raise PackError("pack record compression is invalid") from exc
            if (
                len(raw) != header.raw_size
                or not decompressor.eof
                or decompressor.unused_data
                or _sha256(raw) != header.sha256
            ):
                raise PackError("pack record hash is invalid")
            seen.add(header.path)
            yield header, raw
        if self._file.tell() != self._index_start or seen != set(self._by_path):
            raise PackError("pack records do not match the index")

    def verify(self) -> PackSummary:
        raw_bytes = 0
        count = 0
        for entry, raw in self.iter_objects():
            count += 1
            raw_bytes += len(raw)
        digest = _file_sha256(self.path)
        return PackSummary(
            str(self.path),
            count,
            raw_bytes,
            self._size,
            digest,
            _object_root(self._entries),
        )

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> "PackReader":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def pack_zip_archive(source: Path, output: Path) -> PackSummary:
    """Convert a verified ZIP bundle to a streaming pack one member at a time."""

    if not source.is_file() or source.is_symlink():
        raise PackError("source bundle is not a regular file")
    writer = PackWriter(output)
    try:
        with zipfile.ZipFile(source, "r") as archive:
            infos = sorted(archive.infolist(), key=lambda item: item.filename)
            for info in infos:
                if info.is_dir():
                    raise PackError("pack source contains a directory")
                if info.file_size > MAX_OBJECT_BYTES:
                    raise PackError("pack source member is too large")
                with archive.open(info, "r") as handle:
                    raw = handle.read(MAX_OBJECT_BYTES + 1)
                if len(raw) != info.file_size:
                    raise PackError("pack source member size is invalid")
                writer.add(info.filename, raw)
        writer.finish()
        try:
            with PackReader(output) as reader:
                return reader.verify()
        except Exception:
            output.unlink(missing_ok=True)
            raise
    except Exception:
        writer.abort()
        raise


def unpack_to_zip(source: Path, output: Path) -> PackSummary:
    """Verify a pack while restoring its canonical bytes to a ZIP bundle."""

    if output.exists():
        raise PackError("ZIP destination already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with PackReader(source) as reader:
        with zipfile.ZipFile(
            output,
            "x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            for entry, raw in reader.iter_objects():
                archive.writestr(entry.path, raw)
        summary = reader.verify()
    output.chmod(0o600)
    return summary
