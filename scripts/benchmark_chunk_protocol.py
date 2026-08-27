#!/usr/bin/env python3
"""Reproducible local transfer-plan benchmark for encrypted chunk protocol v1.

The benchmark uses the production scanner, selective stager, manifest codec,
and chunk verifier. It deliberately replaces only the provider transport with
an ephemeral local content-addressed directory, so no credential or network
speed enters the result. The live rclone/crypt acceptance test separately
proves ciphertext behavior at the external process boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SCRIPTS = (
    REPOSITORY_ROOT / "plugins" / "memory-vault-sync" / "scripts"
)

if str(PLUGIN_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SCRIPTS))

from memory_vault_runtime.chunks import (  # noqa: E402
    CHUNK_ALGORITHM,
    CHUNK_READER_PROTOCOL,
    CHUNK_SIZE_BYTES,
    manifest_bytes,
    manifest_document,
    manifest_id,
    policy_document,
)
from memory_vault_runtime.core import (  # noqa: E402
    RcloneCryptAdapter,
    stable_hash_file,
)


MEBIBYTE = 1024 * 1024
BENCHMARK_SCHEMA = "memory-vault-chunk-benchmark/v1"


def _seconds(started: float) -> float:
    return round(time.perf_counter() - started, 6)


def _write_deterministic_fixture(path: Path, size: int) -> str:
    digest = hashlib.sha256()
    block_size = MEBIBYTE
    written = 0
    index = 0
    with path.open("xb", buffering=0) as stream:
        while written < size:
            length = min(block_size, size - written)
            seed = hashlib.sha256(
                f"memory-vault-benchmark-v1:{size}:{index}".encode("ascii")
            ).digest()
            block = (seed * ((length + len(seed) - 1) // len(seed)))[:length]
            stream.write(block)
            digest.update(block)
            written += length
            index += 1
        stream.flush()
        os.fsync(stream.fileno())
    return digest.hexdigest()


def _mutate_one_percent_inside_one_chunk(path: Path, size: int) -> int:
    changed = max(1, (size + 99) // 100)
    if changed >= CHUNK_SIZE_BYTES:
        raise ValueError("benchmark change must fit inside one fixed chunk")
    chunk_index = max(1, (size // CHUNK_SIZE_BYTES) // 2)
    chunk_start = chunk_index * CHUNK_SIZE_BYTES
    offset = chunk_start + MEBIBYTE
    if offset + changed > min(size, chunk_start + CHUNK_SIZE_BYTES):
        offset = chunk_start
    if offset + changed > size:
        raise ValueError("benchmark artifact is too small for mutation")
    block = b"\xa5" * MEBIBYTE
    remaining = changed
    with path.open("r+b", buffering=0) as stream:
        stream.seek(offset)
        while remaining:
            payload = block[: min(len(block), remaining)]
            stream.write(payload)
            remaining -= len(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return changed


def _sizes(descriptors: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for descriptor in descriptors:
        content_id = str(descriptor["content_id"])
        size = int(descriptor["size"])
        previous = result.setdefault(content_id, size)
        if previous != size:
            raise ValueError("content identity has conflicting sizes")
    return result


def _store_paths(root: Path) -> set[str]:
    return {
        path.name
        for path in root.rglob("*")
        if path.is_file()
    }


def _commit_staging(
    staging: Path,
    store: Path,
    sizes: Mapping[str, int],
) -> int:
    transferred = 0
    for content_id, size in sizes.items():
        source = staging / content_id[:2] / content_id
        destination = store / content_id[:2] / content_id
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if (
                RcloneCryptAdapter._stable_chunk_content_id(destination, size)
                != content_id
            ):
                raise ValueError("stored content-addressed chunk was changed")
            continue
        os.replace(source, destination)
        transferred += size
    return transferred


def _restore(
    manifest: Mapping[str, Any],
    store: Path,
    destination: Path,
) -> tuple[str, int]:
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".restore",
        dir=str(destination.parent),
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(fd, "wb", buffering=0) as output:
            fd = -1
            for descriptor in manifest["chunks"]:
                content_id = str(descriptor["content_id"])
                size = int(descriptor["size"])
                source = store / content_id[:2] / content_id
                if (
                    RcloneCryptAdapter._stable_chunk_content_id(source, size)
                    != content_id
                ):
                    raise ValueError("restore source failed chunk verification")
                remaining = size
                with source.open("rb", buffering=0) as stream:
                    while remaining:
                        block = stream.read(min(MEBIBYTE, remaining))
                        if not block:
                            raise ValueError("restore source ended early")
                        output.write(block)
                        digest.update(block)
                        total += len(block)
                        remaining -= len(block)
                    if stream.read(1):
                        raise ValueError("restore source exceeds manifest size")
            output.flush()
            os.fsync(output.fileno())
        if (
            digest.hexdigest() != manifest["artifact_sha256"]
            or total != manifest["artifact_size"]
        ):
            raise ValueError("restored artifact failed final identity")
        os.replace(temporary, destination)
        return digest.hexdigest(), total
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def benchmark_size(size: int, root: Path) -> dict[str, Any]:
    if size < 2 * CHUNK_SIZE_BYTES:
        raise ValueError("benchmark size must be at least two chunks")
    if size > CHUNK_SIZE_BYTES * 64:
        raise ValueError("benchmark size is capped at 1 GiB")
    scenario = root / f"scenario-{size}"
    scenario.mkdir()
    source = scenario / "artifact.bin"
    store = scenario / "store"
    store.mkdir()

    generation_started = time.perf_counter()
    initial_sha = _write_deterministic_fixture(source, size)
    generation_seconds = _seconds(generation_started)

    cold_scan_started = time.perf_counter()
    initial_descriptors, initial_snapshot = (
        RcloneCryptAdapter._scan_local_chunks(source, initial_sha, size)
    )
    cold_scan_seconds = _seconds(cold_scan_started)
    initial_sizes = _sizes(initial_descriptors)
    cold_stage = scenario / "cold-stage"
    cold_stage_started = time.perf_counter()
    staged = RcloneCryptAdapter._stage_missing_chunks(
        source,
        initial_descriptors,
        set(initial_sizes),
        cold_stage,
        initial_snapshot,
    )
    cold_stage_seconds = _seconds(cold_stage_started)
    cold_commit_started = time.perf_counter()
    cold_bytes = _commit_staging(cold_stage, store, staged)
    cold_commit_seconds = _seconds(cold_commit_started)

    policy = policy_document(
        vault_id="codex-memory-vault",
        store_id="rclone-crypt-primary",
        container_id="rclone-" + "2" * 32,
        remote_fingerprint="2" * 64,
        key_epoch="3" * 64,
    )
    initial_manifest = manifest_document(
        policy=policy,
        artifact_sha256=initial_sha,
        artifact_size=size,
        mime_type="application/octet-stream",
        chunks=initial_descriptors,
    )

    changed_bytes = _mutate_one_percent_inside_one_chunk(source, size)
    preflight_started = time.perf_counter()
    changed_sha, changed_size = stable_hash_file(source, inspect_text=False)
    preflight_seconds = _seconds(preflight_started)
    if changed_size != size:
        raise ValueError("benchmark mutation changed artifact size")
    delta_scan_started = time.perf_counter()
    changed_descriptors, changed_snapshot = (
        RcloneCryptAdapter._scan_local_chunks(source, changed_sha, size)
    )
    delta_scan_seconds = _seconds(delta_scan_started)
    changed_sizes = _sizes(changed_descriptors)
    before = _store_paths(store)
    missing = set(changed_sizes) - before
    delta_stage = scenario / "delta-stage"
    delta_stage_started = time.perf_counter()
    staged_delta = RcloneCryptAdapter._stage_missing_chunks(
        source,
        changed_descriptors,
        missing,
        delta_stage,
        changed_snapshot,
    )
    delta_stage_seconds = _seconds(delta_stage_started)

    # Simulate a process losing acknowledgement after immutable chunks reached
    # the provider but before the manifest was published. The retry lists the
    # same content-addressed paths and therefore transfers zero chunk bytes.
    interrupted_bytes = _commit_staging(delta_stage, store, staged_delta)
    retry_scan_started = time.perf_counter()
    retry_descriptors, _retry_snapshot = RcloneCryptAdapter._scan_local_chunks(
        source,
        changed_sha,
        size,
    )
    retry_scan_seconds = _seconds(retry_scan_started)
    retry_sizes = _sizes(retry_descriptors)
    retry_missing = set(retry_sizes) - _store_paths(store)
    retry_bytes = sum(retry_sizes[item] for item in retry_missing)
    changed_manifest = manifest_document(
        policy=policy,
        artifact_sha256=changed_sha,
        artifact_size=size,
        mime_type="application/octet-stream",
        chunks=retry_descriptors,
    )
    changed_manifest_id = manifest_id(changed_manifest)
    changed_manifest_raw = manifest_bytes(changed_manifest)

    destination = scenario / "restored.bin"
    restore_started = time.perf_counter()
    restored_sha, restored_size = _restore(
        changed_manifest,
        store,
        destination,
    )
    restore_seconds = _seconds(restore_started)
    destination.unlink()

    return {
        "artifact_bytes": size,
        "artifact_mib": size // MEBIBYTE,
        "fixture_generation_seconds": generation_seconds,
        "change_bytes": changed_bytes,
        "change_ratio": round(changed_bytes / size, 6),
        "cold_upload": {
            "chunk_count": len(initial_descriptors),
            "unique_chunk_count": len(initial_sizes),
            "scan_seconds": cold_scan_seconds,
            "selective_stage_seconds": cold_stage_seconds,
            "local_commit_seconds": cold_commit_seconds,
            "transferred_bytes": cold_bytes,
            "transfer_ratio": round(cold_bytes / size, 6),
            "manifest_bytes": len(manifest_bytes(initial_manifest)),
        },
        "one_percent_change": {
            "preflight_sha256_seconds": preflight_seconds,
            "scan_seconds": delta_scan_seconds,
            "selective_stage_seconds": delta_stage_seconds,
            "changed_chunk_count": len(missing),
            "transferred_bytes": interrupted_bytes,
            "transfer_ratio": round(interrupted_bytes / size, 6),
        },
        "interrupted_retry": {
            "interruption_point": "chunks_committed_before_manifest",
            "first_attempt_transferred_bytes": interrupted_bytes,
            "retry_scan_seconds": retry_scan_seconds,
            "retry_missing_chunk_count": len(retry_missing),
            "retry_transferred_bytes": retry_bytes,
            "manifest_id": changed_manifest_id,
            "manifest_bytes": len(changed_manifest_raw),
            "remote_deletion_performed": False,
        },
        "restore": {
            "seconds": restore_seconds,
            "restored_bytes": restored_size,
            "final_sha256_verified": restored_sha == changed_sha,
            "atomic_publish": True,
        },
    }


def run_benchmark(sizes_mib: Sequence[int]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="memory-vault-chunk-benchmark-"
    ) as temporary:
        root = Path(temporary)
        scenarios = [
            benchmark_size(int(size_mib) * MEBIBYTE, root)
            for size_mib in sizes_mib
        ]
    return {
        "schema_version": BENCHMARK_SCHEMA,
        "reader_protocol": CHUNK_READER_PROTOCOL,
        "algorithm": CHUNK_ALGORITHM,
        "chunk_size_bytes": CHUNK_SIZE_BYTES,
        "transport_model": (
            "production scan/stage/manifest/restore with ephemeral local "
            "content-addressed provider substitute"
        ),
        "network_timing_claimed": False,
        "scenarios": scenarios,
    }


def _write_output(path: Path, value: Mapping[str, Any]) -> None:
    raw = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="benchmark encrypted fixed-chunk transfer planning"
    )
    parser.add_argument(
        "--size-mib",
        type=int,
        action="append",
        dest="sizes_mib",
        help="artifact size in MiB; repeat for multiple scenarios",
    )
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = run_benchmark(args.sizes_mib or [100, 1024])
    if args.output is not None:
        _write_output(args.output, result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
