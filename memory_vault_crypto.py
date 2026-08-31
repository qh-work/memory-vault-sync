"""Fail-closed external encryption boundary for content-selected memory shares.

No cipher, key generation, provider download, dynamic plugin loading or remote
execution is implemented here. A deployment passes its independently audited
provider object explicitly. The provider must authenticate the associated-data
binding, including the exact plaintext and selector hashes. Memory cannot pick
a provider, recipient, key, policy, or execution capability.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import time
from typing import Any, Iterator, Mapping, Protocol, Sequence

from memory_vault import MemoryError, canonical_bytes, sha256, strict_json_loads
from memory_vault_client import _absolute, _private_directory
from memory_vault_sharing import MAX_SHARE_BYTES, ShareSummary, _named_matches, _new_output, verify_share_bundle


ENVELOPE_SCHEMA = "universal-memory-share-envelope/v1"
ENVELOPE_MAGIC = b"universal-memory-share-envelope/v1\n"
LEGACY_ENVELOPE_SCHEMA = "memory-share-envelope/v1"
LEGACY_ENVELOPE_MAGIC = b"memory-share-envelope/v1\n"
MAX_HEADER_BYTES = 16 * 1024
MAX_ENVELOPE_BYTES = MAX_SHARE_BYTES + 16 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")
_OPAQUE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")


class CryptoError(MemoryError):
    pass


class CryptoUnavailable(CryptoError):
    pass


@dataclass(frozen=True)
class ProviderInfo:
    profile: str
    version: str
    recipient_fingerprint: str


class CryptoProvider(Protocol):
    info: ProviderInfo

    def encrypt_to_file(self, plaintext: Path, ciphertext: Path, *, key_epoch: int, associated_data: bytes) -> None:
        """Write a NEW private ciphertext file and authenticate associated_data."""

    def decrypt_to_file(self, ciphertext: Path, plaintext: Path, *, key_epoch: int, associated_data: bytes) -> None:
        """Authenticate ciphertext AND associated_data before producing plaintext."""


class UnconfiguredCryptoProvider:
    info = ProviderInfo("unconfigured-external-provider-v1", "0", "unconfigured")

    def encrypt_to_file(self, plaintext: Path, ciphertext: Path, *, key_epoch: int, associated_data: bytes) -> None:
        raise CryptoUnavailable("encryption_provider_not_configured")

    def decrypt_to_file(self, ciphertext: Path, plaintext: Path, *, key_epoch: int, associated_data: bytes) -> None:
        raise CryptoUnavailable("encryption_provider_not_configured")


@dataclass(frozen=True)
class EnvelopeSummary:
    path: str
    ciphertext_bytes: int
    ciphertext_sha256: str
    recipient_fingerprint: str
    key_epoch: int
    capability_scope_sha256: str
    crypto_profile: str
    provider_version: str


def _opaque(value: Any) -> str:
    if not isinstance(value, str) or _OPAQUE.fullmatch(value) is None:
        raise CryptoError("invalid_encryption_provider_identity")
    return value


def _hash(value: Any) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise CryptoError("invalid_envelope_hash")
    return value


def _epoch(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 9_007_199_254_740_991:
        raise CryptoError("invalid_encryption_key_epoch")
    return value


def _provider(provider: CryptoProvider) -> ProviderInfo:
    info = getattr(provider, "info", None)
    if not isinstance(info, ProviderInfo):
        raise CryptoError("invalid_encryption_provider")
    for value in (info.profile, info.version, info.recipient_fingerprint):
        _opaque(value)
    if isinstance(provider, UnconfiguredCryptoProvider) or info.profile == "unconfigured-external-provider-v1":
        raise CryptoUnavailable("encryption_provider_not_configured")
    return info


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextlib.contextmanager
def _read(path: Path, maximum: int) -> Iterator[Any]:
    source = _absolute(path)
    if os.name == "nt":
        from memory_vault_storage import open_file
        descriptor = open_file(source, os.O_RDONLY)
    else:
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum
                or not _named_matches(source.lstat(), before)):
            raise CryptoError("unsafe_envelope_file")
        yield stream
        if (_fingerprint(os.fstat(stream.fileno())) != _fingerprint(before)
                or not _named_matches(source.lstat(), before)):
            raise CryptoError("envelope_file_changed")


def _stream_digest(stream: Any, maximum: int, *, target: Any = None, deadline: float | None = None) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    deadline = min(time.monotonic() + 300, deadline) if deadline is not None else time.monotonic() + 300
    while True:
        if time.monotonic() >= deadline:
            raise CryptoError("envelope_io_time_limit", retryable=True)
        chunk = stream.read(min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise CryptoError("envelope_byte_limit")
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    return digest.hexdigest(), total


def _binding(value: Mapping[str, Any]) -> dict[str, Any]:
    names = {"schema_version", "crypto_profile", "provider_version", "recipient_fingerprint", "key_epoch",
             "capability_scope_sha256", "plaintext_sha256", "plaintext_bytes"}
    if not names.issubset(value) or value["schema_version"] != ENVELOPE_SCHEMA:
        raise CryptoError("invalid_envelope_binding")
    for name in ("crypto_profile", "provider_version", "recipient_fingerprint"):
        _opaque(value[name])
    _epoch(value["key_epoch"])
    _hash(value["capability_scope_sha256"])
    _hash(value["plaintext_sha256"])
    if type(value["plaintext_bytes"]) is not int or not 1 <= value["plaintext_bytes"] <= MAX_SHARE_BYTES:
        raise CryptoError("invalid_envelope_plaintext_size")
    return {name: value[name] for name in names}


def _header(stream: Any) -> dict[str, Any]:
    if stream.read(len(ENVELOPE_MAGIC)) != ENVELOPE_MAGIC:
        raise CryptoError("unsupported_share_envelope")
    raw_length = stream.read(4)
    if len(raw_length) != 4:
        raise CryptoError("invalid_envelope_header")
    length = struct.unpack(">I", raw_length)[0]
    if not 1 <= length <= MAX_HEADER_BYTES:
        raise CryptoError("invalid_envelope_header")
    raw = stream.read(length)
    value = strict_json_loads(raw)
    if (not isinstance(value, dict) or len(raw) != length or canonical_bytes(value) != raw
            or set(value) != {"schema_version", "crypto_profile", "provider_version", "recipient_fingerprint", "key_epoch",
                              "capability_scope_sha256", "plaintext_sha256", "plaintext_bytes", "ciphertext_sha256", "ciphertext_bytes"}):
        raise CryptoError("invalid_envelope_header")
    _binding(value)
    _hash(value["ciphertext_sha256"])
    if type(value["ciphertext_bytes"]) is not int or not 1 <= value["ciphertext_bytes"] <= MAX_ENVELOPE_BYTES:
        raise CryptoError("invalid_envelope_ciphertext_size")
    return value


def read_envelope(path: Path, *, deadline: float | None = None) -> tuple[dict[str, Any], int]:
    """Read/hash only ciphertext. No decryption, provider invocation or trust."""
    with _read(path, MAX_ENVELOPE_BYTES + MAX_HEADER_BYTES + len(ENVELOPE_MAGIC) + 4) as stream:
        header = _header(stream)
        digest, size = _stream_digest(stream, MAX_ENVELOPE_BYTES, deadline=deadline)
        if digest != header["ciphertext_sha256"] or size != header["ciphertext_bytes"]:
            raise CryptoError("envelope_ciphertext_mismatch")
        return header, header["key_epoch"]


def read_legacy_envelope(path: Path, *, deadline: float | None = None) -> tuple[dict[str, Any], int]:
    """Inspect the real v0.21 framing only; never feed it to current decryption.

    Old headers have no authenticated plaintext binding. Byte/hash validity is
    not evidence that a cipher was used, a recipient owns a key, or a claim is
    trusted. Preserve the old zero-size/zero-epoch metadata range for reading.
    """
    with _read(path, MAX_SHARE_BYTES + MAX_HEADER_BYTES + len(LEGACY_ENVELOPE_MAGIC) + 4) as stream:
        if stream.read(len(LEGACY_ENVELOPE_MAGIC)) != LEGACY_ENVELOPE_MAGIC:
            raise CryptoError("unsupported_legacy_share_envelope")
        raw_length = stream.read(4)
        if len(raw_length) != 4:
            raise CryptoError("invalid_legacy_envelope_header")
        length = struct.unpack(">I", raw_length)[0]
        if not 1 <= length <= MAX_HEADER_BYTES:
            raise CryptoError("invalid_legacy_envelope_header")
        raw = stream.read(length)
        value = strict_json_loads(raw)
        fields = {"schema_version", "crypto_profile", "provider_version", "recipient_fingerprint",
                  "key_epoch", "capability_scope_sha256", "ciphertext_sha256", "ciphertext_bytes"}
        if (len(raw) != length or not isinstance(value, dict) or set(value) != fields
                or value["schema_version"] != LEGACY_ENVELOPE_SCHEMA):
            raise CryptoError("invalid_legacy_envelope_header")
        for name in ("crypto_profile", "provider_version", "recipient_fingerprint"):
            text = _opaque(value[name])
            if any(token in text for token in ("task", "conversation", "owner", "local_path")):
                raise CryptoError("invalid_legacy_envelope_identity")
        _hash(value["ciphertext_sha256"])
        _hash(value["capability_scope_sha256"])
        if type(value["key_epoch"]) is not int or not 0 <= value["key_epoch"] <= 2**63 - 1:
            raise CryptoError("invalid_legacy_envelope_epoch")
        if type(value["ciphertext_bytes"]) is not int or not 0 <= value["ciphertext_bytes"] <= MAX_SHARE_BYTES:
            raise CryptoError("invalid_legacy_envelope_size")
        digest, size = _stream_digest(stream, MAX_SHARE_BYTES, deadline=deadline)
        if size != value["ciphertext_bytes"] or digest != value["ciphertext_sha256"]:
            raise CryptoError("legacy_envelope_ciphertext_mismatch")
        return value, value["key_epoch"]


def verify_envelope(path: Path, *, legacy_v021: bool = False,
                    maximum_seconds: int = 300) -> Mapping[str, Any]:
    """A usable operator inspection endpoint, without configuration or secrets."""
    if type(legacy_v021) is not bool or type(maximum_seconds) is not int or not 1 <= maximum_seconds <= 300:
        raise CryptoError("invalid_envelope_inspection_option")
    reader = read_legacy_envelope if legacy_v021 else read_envelope
    header, epoch = reader(path, deadline=time.monotonic() + maximum_seconds)
    return {
        "schema_version": "universal-memory-envelope-inspection/v1",
        "envelope_schema": header["schema_version"], "valid": True,
        "crypto_profile": header["crypto_profile"], "provider_version": header["provider_version"],
        "recipient_fingerprint": header["recipient_fingerprint"], "key_epoch": epoch,
        "ciphertext_bytes": header["ciphertext_bytes"], "ciphertext_sha256": header["ciphertext_sha256"],
        "capability_scope_sha256": header["capability_scope_sha256"],
        "plaintext_binding_present": not legacy_v021, "ciphertext_identity_checked": True,
        "authenticated": False, "plaintext_opened": False, "provider_invoked": False,
        "memory_changed": False, "keys_enrolled": False, "network_accessed": False,
    }


def seal_with_provider(plaintext: Path, output: Path, provider: CryptoProvider, *,
                       capability_scope_sha256: str, key_epoch: int) -> EnvelopeSummary:
    """Seal a verified share using explicitly provided, independently trusted code.

    capability_scope_sha256 is a retained historical field name: it commits to
    the *content selector*, never an execution capability or authorization.
    """
    info = _provider(provider)
    _epoch(key_epoch)
    _hash(capability_scope_sha256)
    summary = verify_share_bundle(plaintext)
    if summary.selector_sha256 != capability_scope_sha256:
        raise CryptoError("encryption_selector_mismatch")
    destination = _absolute(output)
    if os.path.lexists(destination):
        raise CryptoError("envelope_output_exists")
    _private_directory(destination.parent)
    binding = {"schema_version": ENVELOPE_SCHEMA, "crypto_profile": info.profile,
               "provider_version": info.version, "recipient_fingerprint": info.recipient_fingerprint,
               "key_epoch": key_epoch, "capability_scope_sha256": capability_scope_sha256,
               "plaintext_sha256": summary.sha256, "plaintext_bytes": summary.raw_bytes}
    # Only this newly created temporary directory is ever cleaned up.
    with tempfile.TemporaryDirectory(prefix=".memory-seal-", dir=destination.parent) as temporary:
        private = Path(temporary)
        _private_directory(private)
        ciphertext = private / "ciphertext.bin"
        provider.encrypt_to_file(_absolute(plaintext), ciphertext, key_epoch=key_epoch, associated_data=canonical_bytes(binding))
        with _read(ciphertext, MAX_ENVELOPE_BYTES) as stream:
            digest, size = _stream_digest(stream, MAX_ENVELOPE_BYTES)
        with _read(plaintext, MAX_SHARE_BYTES) as stream:
            plain_digest, plain_size = _stream_digest(stream, MAX_SHARE_BYTES)
        if plain_digest != summary.sha256 or plain_size != summary.raw_bytes:
            raise CryptoError("share_plaintext_changed")
        header = {**binding, "ciphertext_sha256": digest, "ciphertext_bytes": size}
        raw = canonical_bytes(header)
        if len(raw) > MAX_HEADER_BYTES:
            raise CryptoError("envelope_header_limit")
        with _new_output(destination) as target, _read(ciphertext, MAX_ENVELOPE_BYTES) as source:
            target.write(ENVELOPE_MAGIC + struct.pack(">I", len(raw)) + raw)
            copied_digest, copied_size = _stream_digest(source, MAX_ENVELOPE_BYTES, target=target)
            if (copied_digest, copied_size) != (digest, size):
                raise CryptoError("envelope_ciphertext_changed")
    return EnvelopeSummary(str(destination), size, digest, info.recipient_fingerprint, key_epoch,
                           capability_scope_sha256, info.profile, info.version)


def open_with_provider(envelope: Path, output_plaintext: Path, provider: CryptoProvider) -> ShareSummary:
    """Authenticate/decrypt/verify privately; publish only complete plaintext."""
    info = _provider(provider)
    header, epoch = read_envelope(envelope)
    if (header["crypto_profile"] != info.profile or header["provider_version"] != info.version
            or header["recipient_fingerprint"] != info.recipient_fingerprint):
        raise CryptoError("encryption_provider_or_recipient_mismatch")
    destination = _absolute(output_plaintext)
    if os.path.lexists(destination):
        raise CryptoError("share_plaintext_output_exists")
    _private_directory(destination.parent)
    with tempfile.TemporaryDirectory(prefix=".memory-open-", dir=destination.parent) as temporary:
        private = Path(temporary)
        _private_directory(private)
        ciphertext, plaintext = private / "ciphertext.bin", private / "plaintext.ndjson"
        with _read(envelope, MAX_ENVELOPE_BYTES + MAX_HEADER_BYTES + len(ENVELOPE_MAGIC) + 4) as source, _new_output(ciphertext) as target:
            current = _header(source)
            if current != header:
                raise CryptoError("envelope_header_changed")
            digest, size = _stream_digest(source, MAX_ENVELOPE_BYTES, target=target)
            if digest != header["ciphertext_sha256"] or size != header["ciphertext_bytes"]:
                raise CryptoError("envelope_ciphertext_changed")
        provider.decrypt_to_file(ciphertext, plaintext, key_epoch=epoch, associated_data=canonical_bytes(_binding(header)))
        summary = verify_share_bundle(plaintext)
        if (summary.sha256 != header["plaintext_sha256"] or summary.raw_bytes != header["plaintext_bytes"]
                or summary.selector_sha256 != header["capability_scope_sha256"]):
            raise CryptoError("decrypted_share_binding_mismatch")
        with _new_output(destination) as target, _read(plaintext, MAX_SHARE_BYTES) as source:
            digest, size = _stream_digest(source, MAX_SHARE_BYTES, target=target)
            if digest != summary.sha256 or size != summary.raw_bytes:
                raise CryptoError("decrypted_share_changed")
        return replace(summary, path=str(destination))


def capabilities() -> Mapping[str, Any]:
    return {"envelope_schema": ENVELOPE_SCHEMA, "provider_configured_by_default": False,
            "metadata_inspection_schemas": [ENVELOPE_SCHEMA, LEGACY_ENVELOPE_SCHEMA],
            "decryption_envelope_schemas": [ENVELOPE_SCHEMA],
            "requires_audited_authenticated_encryption_provider": True,
            "associated_data_required": True, "memory_can_select_provider": False,
            "encryption_is_authorization": False, "production_key_ceremony_verified": False}


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    from memory_vault import failure, success, write_response
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("capabilities", help="describe optional contracts without reading a file or configuring a provider")
    inspect = commands.add_parser("verify", help="check an explicit envelope's framing/hash, not encryption authenticity")
    inspect.add_argument("--source", type=Path, required=True)
    inspect.add_argument("--legacy-v021", action="store_true", help="inspect the separate old framing; never treat it as new authenticated data")
    inspect.add_argument("--maximum-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        result = capabilities() if args.action == "capabilities" else verify_envelope(
            args.source, legacy_v021=args.legacy_v021, maximum_seconds=args.maximum_seconds)
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except (OSError, ValueError):
        write_response(failure("envelope_inspection_unavailable"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
