"""Declarative inventory for the verified, upgrade-safe runtime bundle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from memory_vault_runtime.protocol import sha256_bytes


@dataclass(frozen=True)
class RuntimeFileSpec:
    path: str
    maximum_bytes: int
    mode: int
    label: str


RUNTIME_FILE_SPECS = (
    RuntimeFileSpec(
        "scripts/vault_sync.py",
        256 * 1024,
        0o700,
        "stable runtime entrypoint",
    ),
    RuntimeFileSpec(
        "scripts/windows_launcher.ps1",
        4 * 1024 * 1024,
        0o600,
        "stable Windows launcher",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/__init__.py",
        256 * 1024,
        0o600,
        "stable runtime package initializer",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/bundle.py",
        256 * 1024,
        0o600,
        "stable runtime bundle policy",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/checkpoint.py",
        256 * 1024,
        0o600,
        "taskless hash checkpoint verifier",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/chunks.py",
        256 * 1024,
        0o600,
        "stable encrypted chunk protocol",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/crypto_adapter.py",
        256 * 1024,
        0o600,
        "external encrypted-share provider boundary",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/device_trust.py",
        256 * 1024,
        0o600,
        "external device trust and recovery boundary",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/diagnostics.py",
        256 * 1024,
        0o600,
        "bounded private diagnostics",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/encrypted_replication.py",
        256 * 1024,
        0o600,
        "ciphertext-only replication catalog",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/memory_network.py",
        512 * 1024,
        0o600,
        "taskless associative memory network",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/packs.py",
        256 * 1024,
        0o600,
        "bounded streaming memory packs",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/retrieval.py",
        256 * 1024,
        0o600,
        "versioned local retrieval adapters",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/sharing.py",
        256 * 1024,
        0o600,
        "taskless selective share closure",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/signed_updates.py",
        256 * 1024,
        0o600,
        "signed update verification policy",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/transport.py",
        256 * 1024,
        0o600,
        "crash-safe resumable pack transport",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/core.py",
        4 * 1024 * 1024,
        0o600,
        "stable runtime core",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/errors.py",
        256 * 1024,
        0o600,
        "stable runtime errors",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/graph_views.py",
        256 * 1024,
        0o600,
        "rebuildable taskless current graph views",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/host_adapter.py",
        256 * 1024,
        0o600,
        "model-neutral local host adapter protocol",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/protocol.py",
        256 * 1024,
        0o600,
        "stable runtime protocol primitives",
    ),
    RuntimeFileSpec(
        "scripts/memory_vault_runtime/privacy.py",
        256 * 1024,
        0o600,
        "stable runtime privacy policy",
    ),
)

RUNTIME_FILE_PATHS = tuple(spec.path for spec in RUNTIME_FILE_SPECS)


def inventory_for(files: Mapping[str, bytes]) -> list[dict[str, Any]]:
    """Return the exact ordered inventory persisted in runtime metadata."""

    if set(files) != set(RUNTIME_FILE_PATHS):
        raise ValueError("runtime bundle does not match the fixed file policy")
    return [
        {
            "path": spec.path,
            "sha256": sha256_bytes(files[spec.path]),
            "size": len(files[spec.path]),
        }
        for spec in RUNTIME_FILE_SPECS
    ]


def inventory_matches(value: Any, files: Mapping[str, bytes]) -> bool:
    """Require an exact inventory: no missing, reordered, or extra modules."""

    if not isinstance(value, list):
        return False
    expected = inventory_for(files)
    if len(value) != len(expected):
        return False
    for observed, required in zip(value, expected):
        if (
            not isinstance(observed, Mapping)
            or set(observed) != {"path", "sha256", "size"}
            or dict(observed) != required
        ):
            return False
    return True
