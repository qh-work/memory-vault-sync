"""Taskless hash checkpoints for first-device bootstrap verification.

This module deliberately provides a canonical hash catalog and verifier only.
Production signatures, offline key ceremonies, and trusted fingerprint
distribution remain external release gates.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

from memory_vault_runtime.protocol import jcs_json_bytes


CHECKPOINT_SCHEMA = "memory-network-checkpoint/v1"
NETWORK_CONTRACT = "memory-network-checkpoint-catalog/v1"


class CheckpointError(ValueError):
    """Checkpoint fields, chain, or explicit trust anchor are invalid."""


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        c not in "0123456789abcdef" for c in value
    ):
        raise CheckpointError(f"{label} is invalid")
    return value


def _commit(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 40 or any(
        c not in "0123456789abcdef" for c in value
    ):
        raise CheckpointError("remote commit is invalid")
    return value


def _generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
        raise CheckpointError("checkpoint generation is invalid")
    return value


def build_checkpoint(
    *,
    object_root_sha256: str,
    remote_commit_sha: str,
    generation: int,
    object_count: int,
    previous_checkpoint_sha256: str | None = None,
) -> dict[str, Any]:
    root = _sha(object_root_sha256, "object root")
    commit = _commit(remote_commit_sha)
    generation = _generation(generation)
    if isinstance(object_count, bool) or not isinstance(object_count, int) or not 0 <= object_count <= 1_000_000:
        raise CheckpointError("checkpoint object count is invalid")
    if previous_checkpoint_sha256 is not None:
        previous_checkpoint_sha256 = _sha(previous_checkpoint_sha256, "previous checkpoint")
    domain = {
        "generation": generation,
        "network_contract": NETWORK_CONTRACT,
        "object_count": object_count,
        "object_root_sha256": root,
        "previous_checkpoint_sha256": previous_checkpoint_sha256,
        "remote_commit_sha": commit,
        "schema_version": CHECKPOINT_SCHEMA,
    }
    return {**domain, "checkpoint_sha256": hashlib.sha256(jcs_json_bytes(domain)).hexdigest()}


def verify_checkpoint(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "checkpoint_sha256", "generation", "network_contract", "object_count",
        "object_root_sha256", "previous_checkpoint_sha256", "remote_commit_sha",
        "schema_version",
    }:
        raise CheckpointError("checkpoint fields are invalid")
    expected = build_checkpoint(
        object_root_sha256=value["object_root_sha256"],
        remote_commit_sha=value["remote_commit_sha"],
        generation=value["generation"],
        object_count=value["object_count"],
        previous_checkpoint_sha256=value["previous_checkpoint_sha256"],
    )
    if value != expected:
        raise CheckpointError("checkpoint hash or fields do not match")
    return expected


def verify_chain(
    checkpoints: Iterable[Mapping[str, Any]],
    *,
    trusted_checkpoint_sha256: str | None = None,
) -> tuple[dict[str, Any], ...]:
    ordered = tuple(verify_checkpoint(item) for item in checkpoints)
    if not ordered:
        raise CheckpointError("checkpoint chain is empty")
    if trusted_checkpoint_sha256 is not None:
        trusted = _sha(trusted_checkpoint_sha256, "trusted checkpoint")
        if ordered[0]["checkpoint_sha256"] != trusted:
            raise CheckpointError("checkpoint does not match explicit trust anchor")
    for previous, current in zip(ordered, ordered[1:]):
        if current["generation"] != previous["generation"] + 1:
            raise CheckpointError("checkpoint generation is not monotonic")
        if current["previous_checkpoint_sha256"] != previous["checkpoint_sha256"]:
            raise CheckpointError("checkpoint predecessor is invalid")
    return ordered

