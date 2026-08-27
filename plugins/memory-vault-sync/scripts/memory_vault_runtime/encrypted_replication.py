"""Ciphertext-only replication catalog and receiver.

The catalog carries opaque envelope metadata and an externally signed
append-only generation.  It never opens a memory share or exposes plaintext.
Signature verification, device keys, and key rotation are supplied by
``device_trust``/an audited external signer; the default signer refuses to
publish production catalogs.
"""

from __future__ import annotations

import base64
import dataclasses
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence

from memory_vault_runtime import crypto_adapter, device_trust
from memory_vault_runtime.protocol import jcs_json_bytes, sha256_bytes


CATALOG_SCHEMA = "memory-replication-catalog/v1"
CATALOG_NETWORK_CONTRACT = "memory-replication/v1"
MAX_CATALOG_ENTRIES = 1_000_000
MAX_CATALOG_BYTES = 2 * 1024 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class ReplicationError(ValueError):
    """Catalog, receiver, or ciphertext admission failed."""


class SignerUnavailable(ReplicationError):
    """No external checkpoint/signature provider is configured."""


@dataclasses.dataclass(frozen=True)
class SignerInfo:
    profile: str
    version: str
    identity: str


class CatalogSigner(Protocol):
    info: SignerInfo

    def sign(self, payload: bytes) -> bytes:
        """Sign canonical catalog bytes using an external key."""

    def verify(self, payload: bytes, signature: bytes) -> None:
        """Verify canonical catalog bytes using an external key."""


class UnconfiguredCatalogSigner:
    """Production default until a real signing ceremony is installed."""

    info = SignerInfo(
        profile="unconfigured-catalog-signer-v1",
        version="0",
        identity="unconfigured",
    )

    def sign(self, payload: bytes) -> bytes:
        raise SignerUnavailable(
            "no external catalog signer is configured; ciphertext catalog not published"
        )

    def verify(self, payload: bytes, signature: bytes) -> None:
        raise SignerUnavailable(
            "no external catalog signer is configured; catalog not trusted"
        )


@dataclasses.dataclass(frozen=True)
class CatalogSummary:
    catalog_sha256: str
    generation: int
    entry_count: int
    ciphertext_bytes: int
    signer_profile: str
    signer_identity: str


def _opaque(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE.fullmatch(value) is None:
        raise ReplicationError(f"{label} is invalid")
    lowered = value.casefold()
    if any(token in lowered for token in ("task", "conversation", "owner", "local_path", "workspace")):
        raise ReplicationError(f"{label} cannot be a memory owner or task identity")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ReplicationError(f"{label} is invalid")
    return value


def _counter(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
        raise ReplicationError(f"{label} is invalid")
    return value


def _safe_relative(value: Any, label: str = "catalog path") -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise ReplicationError(f"{label} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReplicationError(f"{label} is unsafe")
    return path.as_posix()


def _signature_info(signer: CatalogSigner) -> SignerInfo:
    info = getattr(signer, "info", None)
    if not isinstance(info, SignerInfo):
        raise SignerUnavailable("external catalog signer identity is invalid")
    _opaque(info.profile, "signer profile")
    _opaque(info.version, "signer version")
    _opaque(info.identity, "signer identity")
    return info


def _unsigned_domain(
    entries: Sequence[Mapping[str, Any]],
    *,
    trust_state_sha256: str,
    trust_generation: int,
    generation: int,
    previous_catalog_sha256: str,
    publisher_fingerprint: str,
) -> dict[str, Any]:
    return {
        "catalog_generation": generation,
        "entries": list(entries),
        "network_contract": CATALOG_NETWORK_CONTRACT,
        "previous_catalog_sha256": previous_catalog_sha256,
        "publisher_fingerprint": _opaque(
            publisher_fingerprint,
            "publisher fingerprint",
        ),
        "schema_version": CATALOG_SCHEMA,
        "trust_generation": trust_generation,
        "trust_state_sha256": trust_state_sha256,
    }


def _entry_from_envelope(path: str, envelope: Path) -> dict[str, Any]:
    safe_path = _safe_relative(path)
    try:
        header, epoch = crypto_adapter.read_envelope(envelope)
    except crypto_adapter.CryptoError as exc:
        raise ReplicationError("replication input envelope is invalid") from exc
    return {
        "capability_scope_sha256": header["capability_scope_sha256"],
        "ciphertext_bytes": header["ciphertext_bytes"],
        "ciphertext_sha256": header["ciphertext_sha256"],
        "key_epoch": epoch,
        "path": safe_path,
        "recipient_fingerprint": header["recipient_fingerprint"],
    }


def build_catalog(
    envelopes: Mapping[str, Path],
    state: device_trust.TrustState,
    *,
    publisher_fingerprint: str,
    generation: int,
    previous_catalog_sha256: str,
    signer: CatalogSigner,
) -> dict[str, Any]:
    """Build and externally sign a ciphertext-only catalog."""

    device_trust.assert_can_publish(
        state,
        publisher_fingerprint,
        key_epoch=state.key_epoch,
    )
    catalog_generation = _counter(generation, "catalog generation")
    if catalog_generation <= 0:
        raise ReplicationError("catalog generation must be positive")
    previous = _hash(previous_catalog_sha256, "previous catalog hash")
    if len(envelopes) > MAX_CATALOG_ENTRIES:
        raise ReplicationError("replication catalog has too many entries")
    entries = [_entry_from_envelope(path, Path(envelopes[path])) for path in envelopes]
    entries.sort(key=lambda item: item["path"])
    if len({item["path"] for item in entries}) != len(entries):
        raise ReplicationError("replication catalog paths are duplicated")
    total = sum(int(item["ciphertext_bytes"]) for item in entries)
    if total > MAX_CATALOG_BYTES:
        raise ReplicationError("replication catalog exceeds the size bound")
    info = _signature_info(signer)
    domain = _unsigned_domain(
        entries,
        trust_state_sha256=state.sha256,
        trust_generation=state.generation,
        generation=catalog_generation,
        previous_catalog_sha256=previous,
        publisher_fingerprint=publisher_fingerprint,
    )
    signed_domain = {
        **domain,
        "signer_identity": info.identity,
        "signer_profile": info.profile,
        "signer_version": info.version,
    }
    payload = jcs_json_bytes(signed_domain)
    signature = signer.sign(payload)
    if not isinstance(signature, (bytes, bytearray)) or not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise ReplicationError("catalog signature is invalid")
    result = {
        **signed_domain,
        "signature_b64": base64.b64encode(bytes(signature)).decode("ascii"),
    }
    result["catalog_sha256"] = sha256_bytes(jcs_json_bytes(result))
    return result


def verify_catalog(
    value: Any,
    state: device_trust.TrustState,
    *,
    signer: CatalogSigner,
    last_catalog_sha256: str | None = None,
    last_generation: int = 0,
) -> CatalogSummary:
    """Verify signature, trust generation, and append-only catalog order."""

    fields = {
        "schema_version",
        "network_contract",
        "trust_state_sha256",
        "trust_generation",
        "catalog_generation",
        "previous_catalog_sha256",
        "publisher_fingerprint",
        "entries",
        "signer_identity",
        "signer_profile",
        "signer_version",
        "signature_b64",
        "catalog_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ReplicationError("replication catalog fields are invalid")
    if value.get("schema_version") != CATALOG_SCHEMA or value.get("network_contract") != CATALOG_NETWORK_CONTRACT:
        raise ReplicationError("replication catalog schema is invalid")
    trust_hash = _hash(value.get("trust_state_sha256"), "trust state hash")
    if trust_hash != state.sha256:
        raise ReplicationError("replication catalog is for another trust state")
    trust_generation = _counter(value.get("trust_generation"), "trust generation")
    if trust_generation != state.generation:
        raise ReplicationError("replication catalog trust generation is stale")
    publisher = _opaque(value.get("publisher_fingerprint"), "publisher fingerprint")
    try:
        device_trust.assert_can_publish(
            state,
            publisher,
            key_epoch=state.key_epoch,
        )
    except device_trust.DeviceTrustError as exc:
        raise ReplicationError("replication catalog publisher is not trusted") from exc
    generation = _counter(value.get("catalog_generation"), "catalog generation")
    if generation <= last_generation:
        raise ReplicationError("replication catalog generation is a replay")
    previous = _hash(value.get("previous_catalog_sha256"), "previous catalog hash")
    if last_catalog_sha256 is None and previous != "0" * 64:
        raise ReplicationError("first replication catalog requires a trusted anchor")
    if last_catalog_sha256 is not None and previous != _hash(last_catalog_sha256, "last catalog hash"):
        raise ReplicationError("replication catalog chain is broken")
    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_CATALOG_ENTRIES:
        raise ReplicationError("replication catalog entries are invalid")
    previous_path: str | None = None
    total = 0
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {
            "path",
            "ciphertext_sha256",
            "ciphertext_bytes",
            "recipient_fingerprint",
            "key_epoch",
            "capability_scope_sha256",
        }:
            raise ReplicationError("replication catalog entry fields are invalid")
        path = _safe_relative(entry.get("path"))
        if previous_path is not None and path <= previous_path:
            raise ReplicationError("replication catalog entries are not sorted")
        previous_path = path
        _hash(entry.get("ciphertext_sha256"), "ciphertext hash")
        _hash(entry.get("capability_scope_sha256"), "capability scope hash")
        _opaque(entry.get("recipient_fingerprint"), "recipient fingerprint")
        key_epoch = _counter(entry.get("key_epoch"), "key epoch")
        if key_epoch <= 0 or key_epoch > state.key_epoch:
            raise ReplicationError("catalog key epoch is invalid")
        size = entry.get("ciphertext_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_CATALOG_BYTES:
            raise ReplicationError("ciphertext size is invalid")
        total += size
        if total > MAX_CATALOG_BYTES:
            raise ReplicationError("replication catalog exceeds the size bound")
    domain = dict(value)
    signature_b64 = domain.pop("signature_b64")
    observed_hash = domain.pop("catalog_sha256")
    if not isinstance(signature_b64, str) or not signature_b64 or len(signature_b64) > MAX_SIGNATURE_BYTES * 2:
        raise ReplicationError("catalog signature encoding is invalid")
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ReplicationError("catalog signature encoding is invalid") from exc
    if not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise ReplicationError("catalog signature is invalid")
    if not isinstance(observed_hash, str) or observed_hash != sha256_bytes(jcs_json_bytes({**domain, "signature_b64": signature_b64})):
        raise ReplicationError("replication catalog hash is invalid")
    info = _signature_info(signer)
    if value.get("signer_profile") != info.profile or value.get("signer_version") != info.version or value.get("signer_identity") != info.identity:
        raise ReplicationError("replication catalog signer identity is invalid")
    signed_domain = dict(value)
    signed_domain.pop("signature_b64")
    signed_domain.pop("catalog_sha256")
    signer.verify(jcs_json_bytes(signed_domain), signature)
    return CatalogSummary(observed_hash, generation, len(entries), total, info.profile, info.identity)


@dataclasses.dataclass
class ReplicationReceiver:
    """A process-local append-only receiver; persist its receipt externally."""

    state: device_trust.TrustState
    last_catalog_sha256: str | None = None
    last_generation: int = 0

    def accept_catalog(
        self,
        catalog: Mapping[str, Any],
        source_root: Path,
        destination_root: Path,
        *,
        signer: CatalogSigner,
    ) -> CatalogSummary:
        summary = verify_catalog(
            catalog,
            self.state,
            signer=signer,
            last_catalog_sha256=self.last_catalog_sha256,
            last_generation=self.last_generation,
        )
        source = Path(source_root).expanduser().resolve()
        destination = Path(destination_root).expanduser().resolve()
        if source == destination or not source.is_dir():
            raise ReplicationError("replication source directory is invalid")
        destination.mkdir(parents=True, exist_ok=True)
        entries = catalog["entries"]
        staged: list[tuple[Path, Path]] = []
        try:
            for entry in entries:
                relative = _safe_relative(entry["path"])
                source_path = source / relative
                target_path = destination / relative
                if source_path.is_symlink() or not source_path.is_file():
                    raise ReplicationError("replication source envelope is not a regular file")
                header, _ = crypto_adapter.read_envelope(source_path)
                if header["ciphertext_sha256"] != entry["ciphertext_sha256"] or header["ciphertext_bytes"] != entry["ciphertext_bytes"]:
                    raise ReplicationError("replication source envelope does not match catalog")
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if target_path.exists() or target_path.is_symlink():
                    raise ReplicationError("replication destination already contains an entry")
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{target_path.name}.", suffix=".tmp", dir=str(target_path.parent)
                )
                os.close(descriptor)
                temporary = Path(temporary_name)
                shutil.copyfile(source_path, temporary)
                temporary.chmod(0o600)
                staged.append((temporary, target_path))
            for temporary, target_path in staged:
                os.replace(temporary, target_path)
        finally:
            for temporary, _ in staged:
                temporary.unlink(missing_ok=True)
        self.last_catalog_sha256 = summary.catalog_sha256
        self.last_generation = summary.generation
        return summary
