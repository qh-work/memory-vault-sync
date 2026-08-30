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
import time
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence

import memory_vault_crypto as crypto_adapter
import memory_vault_device_trust as device_trust
from memory_vault_metadata import jcs_json_bytes, sha256_bytes
from memory_vault_client import _absolute, _private_directory
from memory_vault_sharing import _new_output


CATALOG_SCHEMA = "universal-memory-encrypted-catalog/v1"
CATALOG_NETWORK_CONTRACT = "universal-memory-encrypted-replication/v1"
MAX_CATALOG_ENTRIES = 1_000_000
MAX_CATALOG_BYTES = 2 * 1024 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
DEFAULT_METADATA_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024 * 1024
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
    public_key_fingerprint: str | None = None


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
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 9_007_199_254_740_991:
        raise ReplicationError(f"{label} is invalid")
    return value


def _budget(maximum_metadata_bytes: int, maximum_seconds: int) -> float:
    if (type(maximum_metadata_bytes) is not int or not 1024 * 1024 <= maximum_metadata_bytes <= MAX_METADATA_BYTES
            or type(maximum_seconds) is not int or not 1 <= maximum_seconds <= 3600):
        raise ReplicationError("invalid catalog work budget")
    return time.monotonic() + maximum_seconds


def _time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ReplicationError("catalog work budget exhausted; no head was advanced")


def _safe_relative(value: Any, label: str = "catalog path") -> str:
    if (not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or ":" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ReplicationError(f"{label} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} or part.endswith((" ", "."))
            or re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
            for part in value.split("/")):
        raise ReplicationError(f"{label} is unsafe")
    if path.parts[0].casefold() == "received.json":
        raise ReplicationError("catalog path collides with receiver receipt")
    return path.as_posix()


def _distinct_paths(paths: Sequence[str]) -> None:
    """Use portable case-folded names; files cannot also be parent directories."""
    names = {path.casefold() for path in paths}
    if len(names) != len(paths):
        raise ReplicationError("catalog paths collide on a supported filesystem")
    for name in names:
        parts = name.split("/")
        if any("/".join(parts[:index]) in names for index in range(1, len(parts))):
            raise ReplicationError("catalog file path is another file's parent")


def _signature_info(signer: CatalogSigner) -> SignerInfo:
    info = getattr(signer, "info", None)
    if not isinstance(info, SignerInfo):
        raise SignerUnavailable("external catalog signer identity is invalid")
    _opaque(info.profile, "signer profile")
    _opaque(info.version, "signer version")
    _opaque(info.identity, "signer identity")
    if isinstance(signer, UnconfiguredCatalogSigner):
        raise SignerUnavailable("external catalog signer is not configured")
    _opaque(info.public_key_fingerprint, "signer public key fingerprint")
    return info


def _bound_signer(signer: CatalogSigner, state: device_trust.TrustState, publisher: str) -> SignerInfo:
    info = _signature_info(signer)
    # An active publisher label alone cannot legitimize a revoked signer's key.
    # The provider must identify the independently enrolled verification key.
    if info.public_key_fingerprint != state.device(publisher).public_key_fingerprint:
        raise ReplicationError("catalog signer key is not the publisher's enrolled key")
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


def _entry_from_envelope(path: str, envelope: Path, *, deadline: float | None = None) -> dict[str, Any]:
    safe_path = _safe_relative(path)
    try:
        header, epoch = crypto_adapter.read_envelope(envelope, deadline=deadline)
    except crypto_adapter.CryptoError as exc:
        raise ReplicationError("replication input envelope is invalid") from exc
    return {
        "capability_scope_sha256": header["capability_scope_sha256"],
        "envelope_header_sha256": sha256_bytes(crypto_adapter.canonical_bytes(header)),
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
    maximum_metadata_bytes: int = DEFAULT_METADATA_BYTES,
    maximum_seconds: int = 300,
) -> dict[str, Any]:
    """Build and externally sign a ciphertext-only catalog."""

    deadline = _budget(maximum_metadata_bytes, maximum_seconds)
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
    info = _bound_signer(signer, state, publisher_fingerprint)
    entries = []
    metadata_bytes = MAX_SIGNATURE_BYTES * 2 + 16384
    total = 0
    for path in envelopes:
        _time(deadline)
        entry = _entry_from_envelope(path, Path(envelopes[path]), deadline=deadline)
        if entry["key_epoch"] > state.key_epoch:
            raise ReplicationError("catalog key epoch is invalid")
        metadata_bytes += len(jcs_json_bytes(entry)) + 1
        total += entry["ciphertext_bytes"]
        if metadata_bytes > maximum_metadata_bytes or total > MAX_CATALOG_BYTES:
            raise ReplicationError("catalog metadata or ciphertext budget exceeded")
        entries.append(entry)
    entries.sort(key=lambda item: item["path"])
    if len({item["path"] for item in entries}) != len(entries):
        raise ReplicationError("replication catalog paths are duplicated")
    _distinct_paths([item["path"] for item in entries])
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
        "signer_public_key_fingerprint": info.public_key_fingerprint,
    }
    payload = jcs_json_bytes(signed_domain)
    _time(deadline)
    signature = signer.sign(payload)
    if not isinstance(signature, (bytes, bytearray)) or not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise ReplicationError("catalog signature is invalid")
    result = {
        **signed_domain,
        "signature_b64": base64.b64encode(bytes(signature)).decode("ascii"),
    }
    result["catalog_sha256"] = sha256_bytes(jcs_json_bytes(result))
    _time(deadline)
    return result


def verify_catalog(
    value: Any,
    state: device_trust.TrustState,
    *,
    signer: CatalogSigner,
    last_catalog_sha256: str | None = None,
    last_generation: int = 0,
    maximum_metadata_bytes: int = DEFAULT_METADATA_BYTES,
    maximum_seconds: int = 300,
    _deadline: float | None = None,
) -> CatalogSummary:
    """Verify signature, trust generation, and append-only catalog order."""

    deadline = _budget(maximum_metadata_bytes, maximum_seconds)
    if _deadline is not None:
        deadline = min(deadline, _deadline)
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
        "signer_public_key_fingerprint",
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
    last_generation = _counter(last_generation, "last catalog generation")
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
    metadata_bytes = MAX_SIGNATURE_BYTES * 2 + 16384
    for entry in entries:
        _time(deadline)
        if not isinstance(entry, Mapping) or set(entry) != {
            "path",
            "ciphertext_sha256",
            "ciphertext_bytes",
            "recipient_fingerprint",
            "key_epoch",
            "capability_scope_sha256",
            "envelope_header_sha256",
        }:
            raise ReplicationError("replication catalog entry fields are invalid")
        path = _safe_relative(entry.get("path"))
        if previous_path is not None and path <= previous_path:
            raise ReplicationError("replication catalog entries are not sorted")
        previous_path = path
        _hash(entry.get("ciphertext_sha256"), "ciphertext hash")
        _hash(entry.get("envelope_header_sha256"), "envelope header hash")
        _hash(entry.get("capability_scope_sha256"), "capability scope hash")
        _opaque(entry.get("recipient_fingerprint"), "recipient fingerprint")
        key_epoch = _counter(entry.get("key_epoch"), "key epoch")
        if key_epoch <= 0 or key_epoch > state.key_epoch:
            raise ReplicationError("catalog key epoch is invalid")
        size = entry.get("ciphertext_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_CATALOG_BYTES:
            raise ReplicationError("ciphertext size is invalid")
        total += size
        if total > MAX_CATALOG_BYTES:
            raise ReplicationError("replication catalog exceeds the size bound")
        metadata_bytes += len(jcs_json_bytes(entry)) + 1
        if metadata_bytes > maximum_metadata_bytes:
            raise ReplicationError("catalog metadata budget exceeded")
    _distinct_paths([entry["path"] for entry in entries])
    domain = dict(value)
    signature_b64 = domain.pop("signature_b64")
    observed_hash = domain.pop("catalog_sha256")
    if not isinstance(signature_b64, str) or not signature_b64 or len(signature_b64) > MAX_SIGNATURE_BYTES * 2:
        raise ReplicationError("catalog signature encoding is invalid")
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ReplicationError("catalog signature encoding is invalid") from exc
    if not signature or len(signature) > MAX_SIGNATURE_BYTES or base64.b64encode(signature).decode("ascii") != signature_b64:
        raise ReplicationError("catalog signature is invalid")
    if not isinstance(observed_hash, str) or observed_hash != sha256_bytes(jcs_json_bytes({**domain, "signature_b64": signature_b64})):
        raise ReplicationError("replication catalog hash is invalid")
    info = _bound_signer(signer, state, publisher)
    if (value.get("signer_profile") != info.profile or value.get("signer_version") != info.version
            or value.get("signer_identity") != info.identity
            or value.get("signer_public_key_fingerprint") != info.public_key_fingerprint):
        raise ReplicationError("replication catalog signer identity is invalid")
    signed_domain = dict(value)
    signed_domain.pop("signature_b64")
    signed_domain.pop("catalog_sha256")
    signer.verify(jcs_json_bytes(signed_domain), signature)
    _time(deadline)
    return CatalogSummary(observed_hash, generation, len(entries), total, info.profile, info.identity)


@dataclasses.dataclass
class ReplicationReceiver:
    """Explicit ciphertext receiver. Persist its verified head independently.

    The head is process-local, as in the v0.21 provider contract; this is not the
    full client's durable plaintext sync queue. Each catalog gets its own new
    content-addressed directory. Complete bytes may be resumed, never replaced;
    a RECEIVED.json marker is published last. No plaintext or key is opened.
    """

    state: device_trust.TrustState
    last_catalog_sha256: str | None = None
    last_generation: int = 0

    def accept_catalog(
        self, catalog: Mapping[str, Any], source_root: Path, destination_root: Path, *,
        signer: CatalogSigner,
        maximum_metadata_bytes: int = DEFAULT_METADATA_BYTES,
        maximum_seconds: int = 300,
    ) -> CatalogSummary:
        deadline = _budget(maximum_metadata_bytes, maximum_seconds)
        summary = verify_catalog(catalog, self.state, signer=signer,
                                 last_catalog_sha256=self.last_catalog_sha256,
                                 last_generation=self.last_generation,
                                 maximum_metadata_bytes=maximum_metadata_bytes,
                                 maximum_seconds=maximum_seconds, _deadline=deadline)
        source, destination = _absolute(source_root), _absolute(destination_root)
        if source == destination or source in destination.parents or destination in source.parents or not source.is_dir():
            raise ReplicationError("replication directories must be separate")
        _private_directory(destination)
        directory = destination / summary.catalog_sha256
        _private_directory(directory)
        for entry in catalog["entries"]:
            _time(deadline)
            relative = _safe_relative(entry["path"])
            source_path = _absolute(source / relative)
            target_path = _absolute(directory / relative)
            header, _ = crypto_adapter.read_envelope(source_path, deadline=deadline)
            names = ("ciphertext_sha256", "ciphertext_bytes", "recipient_fingerprint", "key_epoch", "capability_scope_sha256")
            if any(header[key] != entry[key] for key in names):
                raise ReplicationError("ciphertext envelope does not match signed catalog")
            if sha256_bytes(crypto_adapter.canonical_bytes(header)) != entry["envelope_header_sha256"]:
                raise ReplicationError("ciphertext envelope header does not match signed catalog")
            _private_directory(target_path.parent)
            if target_path.exists():
                observed, _ = crypto_adapter.read_envelope(target_path, deadline=deadline)
                if observed != header:
                    raise ReplicationError("existing ciphertext differs; never overwrite it")
                continue
            with _new_output(target_path) as target, crypto_adapter._read(
                source_path, crypto_adapter.MAX_ENVELOPE_BYTES + crypto_adapter.MAX_HEADER_BYTES + len(crypto_adapter.ENVELOPE_MAGIC) + 4
            ) as opened:
                current = crypto_adapter._header(opened)
                if current != header:
                    raise ReplicationError("ciphertext source changed")
                encoded = crypto_adapter.canonical_bytes(header)
                target.write(crypto_adapter.ENVELOPE_MAGIC + len(encoded).to_bytes(4, "big") + encoded)
                digest, size = crypto_adapter._stream_digest(opened, crypto_adapter.MAX_ENVELOPE_BYTES, target=target, deadline=deadline)
                if digest != entry["ciphertext_sha256"] or size != entry["ciphertext_bytes"]:
                    raise ReplicationError("ciphertext source changed")
        receipt = {
            "schema_version": "universal-memory-encrypted-receipt/v1",
            "catalog_sha256": summary.catalog_sha256, "generation": summary.generation,
            "entries": summary.entry_count, "ciphertext_bytes": summary.ciphertext_bytes,
            "plaintext_opened": False, "execution_authority_granted": False,
        }
        marker = directory / "RECEIVED.json"
        from memory_vault_update import read_file
        encoded = jcs_json_bytes(receipt) + b"\n"
        _time(deadline)
        if marker.exists():
            if read_file(marker, 16 * 1024) != encoded:
                raise ReplicationError("ciphertext receipt conflict")
        else:
            with _new_output(marker) as stream:
                stream.write(encoded)
        self.last_catalog_sha256 = summary.catalog_sha256
        self.last_generation = summary.generation
        return summary
