"""External-provider boundary for selective encrypted memory shares.

The runtime does not implement cryptography.  A provider must be selected,
audited, pinned and supplied by the deployment before plaintext can be sealed.
This module only validates a versioned envelope and guarantees atomic
decrypt-then-verify import.  ``UnconfiguredCryptoProvider`` is intentionally
the production default and always fails closed.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import struct
import tempfile
from pathlib import Path
from typing import Any, Protocol

from memory_vault_runtime.protocol import jcs_json_bytes, strict_json_loads
from memory_vault_runtime.sharing import ShareError, ShareSummary, verify_share_bundle


ENVELOPE_SCHEMA = "memory-share-envelope/v1"
ENVELOPE_MAGIC = b"memory-share-envelope/v1\n"
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class CryptoError(ValueError):
    """Envelope or provider contract failure."""


class CryptoUnavailable(CryptoError):
    """No audited, configured encryption provider is available."""


@dataclasses.dataclass(frozen=True)
class ProviderInfo:
    profile: str
    version: str
    recipient_fingerprint: str


class CryptoProvider(Protocol):
    """Minimal file-to-file contract for an audited external provider."""

    info: ProviderInfo

    def encrypt_to_file(
        self,
        plaintext: Path,
        ciphertext: Path,
        *,
        key_epoch: int,
    ) -> None:
        """Encrypt one private plaintext file into a private ciphertext file."""

    def decrypt_to_file(
        self,
        ciphertext: Path,
        plaintext: Path,
        *,
        key_epoch: int,
    ) -> None:
        """Decrypt one ciphertext file into a private plaintext file."""


class UnconfiguredCryptoProvider:
    """Safe production default; never treats a test transform as encryption."""

    info = ProviderInfo(
        profile="unconfigured-external-provider-v1",
        version="0",
        recipient_fingerprint="unconfigured",
    )

    def encrypt_to_file(self, plaintext: Path, ciphertext: Path, *, key_epoch: int) -> None:
        raise CryptoUnavailable(
            "no audited external encryption provider is configured; plaintext remains local"
        )

    def decrypt_to_file(self, ciphertext: Path, plaintext: Path, *, key_epoch: int) -> None:
        raise CryptoUnavailable(
            "no audited external encryption provider is configured; encrypted share was not opened"
        )


@dataclasses.dataclass(frozen=True)
class EnvelopeSummary:
    path: str
    ciphertext_bytes: int
    ciphertext_sha256: str
    recipient_fingerprint: str
    key_epoch: int
    capability_scope_sha256: str
    crypto_profile: str
    provider_version: str


def _plain_file(path: Path, label: str) -> None:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise CryptoError(f"{label} is unavailable") from exc
    if path.is_symlink() or not path.is_file() or getattr(observed, "st_nlink", 1) != 1:
        raise CryptoError(f"{label} is not a regular private file")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ENVELOPE_BYTES:
                raise CryptoError("encrypted share exceeds the size bound")
            digest.update(chunk)
    return digest.hexdigest(), total


def _opaque(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE.fullmatch(value) is None:
        raise CryptoError(f"{label} is invalid")
    lowered = value.casefold()
    if any(token in lowered for token in ("task", "conversation", "owner", "local_path")):
        raise CryptoError(f"{label} cannot be a memory owner or task identity")
    return value


def validate_recipient_fingerprint(value: Any) -> str:
    """Validate an opaque provider key fingerprint without accepting an owner."""

    return _opaque(value, "recipient fingerprint")


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise CryptoError(f"{label} is invalid")
    return value


def _epoch(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
        raise CryptoError("key epoch is invalid")
    return value


def _write_envelope_file(output: Path, header: dict[str, Any], ciphertext: Path) -> EnvelopeSummary:
    _plain_file(ciphertext, "ciphertext")
    digest, size = _sha256_file(ciphertext)
    header = {
        "capability_scope_sha256": _hash(header.get("capability_scope_sha256"), "capability scope"),
        "ciphertext_bytes": size,
        "ciphertext_sha256": digest,
        "crypto_profile": _opaque(header.get("crypto_profile"), "crypto profile"),
        "key_epoch": _epoch(header.get("key_epoch")),
        "provider_version": _opaque(header.get("provider_version"), "provider version"),
        "recipient_fingerprint": _opaque(header.get("recipient_fingerprint"), "recipient fingerprint"),
        "schema_version": ENVELOPE_SCHEMA,
    }
    raw_header = jcs_json_bytes(header)
    if len(raw_header) > MAX_HEADER_BYTES:
        raise CryptoError("encrypted share header is too large")
    if output.exists() or output.is_symlink():
        raise CryptoError("encrypted share destination already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=str(output.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with temporary.open("wb") as handle, ciphertext.open("rb") as source:
            handle.write(ENVELOPE_MAGIC)
            handle.write(struct.pack(">I", len(raw_header)))
            handle.write(raw_header)
            while chunk := source.read(1024 * 1024):
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, output)
        output.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return EnvelopeSummary(
        path=str(output),
        ciphertext_bytes=size,
        ciphertext_sha256=digest,
        recipient_fingerprint=header["recipient_fingerprint"],
        key_epoch=header["key_epoch"],
        capability_scope_sha256=header["capability_scope_sha256"],
        crypto_profile=header["crypto_profile"],
        provider_version=header["provider_version"],
    )


def read_envelope(path: Path) -> tuple[dict[str, Any], int]:
    """Validate envelope header/ciphertext identity without decrypting."""

    source = Path(path).expanduser()
    _plain_file(source, "encrypted share")
    if source.stat().st_size > MAX_ENVELOPE_BYTES + MAX_HEADER_BYTES + len(ENVELOPE_MAGIC) + 4:
        raise CryptoError("encrypted share is too large")
    try:
        with source.open("rb") as handle:
            if handle.read(len(ENVELOPE_MAGIC)) != ENVELOPE_MAGIC:
                raise CryptoError("encrypted share magic is invalid")
            raw_length = handle.read(4)
            if len(raw_length) != 4:
                raise CryptoError("encrypted share header is truncated")
            header_length = struct.unpack(">I", raw_length)[0]
            if not 1 <= header_length <= MAX_HEADER_BYTES:
                raise CryptoError("encrypted share header length is invalid")
            raw_header = handle.read(header_length)
            if len(raw_header) != header_length:
                raise CryptoError("encrypted share header is truncated")
            try:
                value = strict_json_loads(raw_header.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise CryptoError("encrypted share header is invalid JSON") from exc
            if not isinstance(value, dict) or set(value) != {
                "capability_scope_sha256",
                "ciphertext_bytes",
                "ciphertext_sha256",
                "crypto_profile",
                "key_epoch",
                "provider_version",
                "recipient_fingerprint",
                "schema_version",
            }:
                raise CryptoError("encrypted share header fields are invalid")
            if value["schema_version"] != ENVELOPE_SCHEMA:
                raise CryptoError("encrypted share schema is invalid")
            _hash(value["capability_scope_sha256"], "capability scope")
            _hash(value["ciphertext_sha256"], "ciphertext hash")
            _opaque(value["crypto_profile"], "crypto profile")
            _opaque(value["provider_version"], "provider version")
            _opaque(value["recipient_fingerprint"], "recipient fingerprint")
            epoch = _epoch(value["key_epoch"])
            size = value["ciphertext_bytes"]
            if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_ENVELOPE_BYTES:
                raise CryptoError("ciphertext size is invalid")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise CryptoError("encrypted share ciphertext is truncated")
                remaining -= len(chunk)
                digest.update(chunk)
            if handle.read(1):
                raise CryptoError("encrypted share has trailing bytes")
    except OSError as exc:
        raise CryptoError("encrypted share could not be read") from exc
    if digest.hexdigest() != value["ciphertext_sha256"]:
        raise CryptoError("encrypted share ciphertext hash is invalid")
    return value, epoch


def seal_with_provider(
    plaintext: Path,
    output: Path,
    provider: CryptoProvider,
    *,
    capability_scope_sha256: str,
    key_epoch: int,
) -> EnvelopeSummary:
    """Encrypt a share through an external provider, then atomically wrap it."""

    _plain_file(Path(plaintext), "share plaintext")
    _hash(capability_scope_sha256, "capability scope")
    _epoch(key_epoch)
    destination = Path(output).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.ciphertext.", suffix=".tmp", dir=str(destination.parent)
    )
    os.close(descriptor)
    ciphertext = Path(temporary_name)
    try:
        provider.encrypt_to_file(Path(plaintext), ciphertext, key_epoch=key_epoch)
        info = provider.info
        if not isinstance(info, ProviderInfo):
            raise CryptoError("crypto provider identity is invalid")
        return _write_envelope_file(
            destination,
            {
                "capability_scope_sha256": capability_scope_sha256,
                "crypto_profile": info.profile,
                "key_epoch": key_epoch,
                "provider_version": info.version,
                "recipient_fingerprint": info.recipient_fingerprint,
            },
            ciphertext,
        )
    finally:
        ciphertext.unlink(missing_ok=True)


def open_with_provider(
    envelope: Path,
    output_plaintext: Path,
    provider: CryptoProvider,
) -> ShareSummary:
    """Decrypt to a private temp file, verify closure, and atomically publish."""

    header, epoch = read_envelope(Path(envelope).expanduser())
    if provider.info.recipient_fingerprint != header["recipient_fingerprint"]:
        raise CryptoError("crypto provider recipient does not match envelope")
    source = Path(envelope).expanduser()
    destination = Path(output_plaintext).expanduser()
    if destination.exists() or destination.is_symlink():
        raise CryptoError("share plaintext destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    ciphertext_descriptor, ciphertext_name = tempfile.mkstemp(
        prefix=f".{destination.name}.ciphertext.", suffix=".tmp", dir=str(destination.parent)
    )
    plaintext_descriptor, plaintext_name = tempfile.mkstemp(
        prefix=f".{destination.name}.plaintext.", suffix=".tmp", dir=str(destination.parent)
    )
    os.close(ciphertext_descriptor)
    os.close(plaintext_descriptor)
    ciphertext = Path(ciphertext_name)
    plaintext = Path(plaintext_name)
    try:
        with source.open("rb") as source_handle, ciphertext.open("wb") as target:
            source_handle.seek(len(ENVELOPE_MAGIC))
            raw_header_length = source_handle.read(4)
            if len(raw_header_length) != 4:
                raise CryptoError("encrypted share header is truncated")
            header_length = struct.unpack(">I", raw_header_length)[0]
            source_handle.seek(len(ENVELOPE_MAGIC) + 4 + header_length)
            remaining = header["ciphertext_bytes"]
            while remaining:
                chunk = source_handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise CryptoError("encrypted share ciphertext is truncated")
                target.write(chunk)
                remaining -= len(chunk)
            target.flush()
            os.fsync(target.fileno())
        provider.decrypt_to_file(ciphertext, plaintext, key_epoch=epoch)
        _plain_file(plaintext, "decrypted share")
        summary = verify_share_bundle(plaintext)
        plaintext.chmod(0o600)
        os.replace(plaintext, destination)
        destination.chmod(0o600)
        return dataclasses.replace(summary, path=str(destination))
    finally:
        ciphertext.unlink(missing_ok=True)
        plaintext.unlink(missing_ok=True)
