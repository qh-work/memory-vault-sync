"""TUF-style signed update metadata for the Memory Vault plugin.

This is a deliberately narrow verification profile, not a general TUF client.
It implements the four top-level roles, threshold signatures, incremental root
rotation, expiry, and rollback/mix-and-match checks for one deterministic
virtual plugin bundle.  It never signs metadata and never accepts private keys.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Any, Mapping

from memory_vault_runtime.protocol import (
    ProtocolValueError,
    jcs_json_bytes,
    persisted_json_bytes,
    sha256_bytes,
    strict_json_loads,
)


SIGNED_UPDATE_PROFILE = "memory-vault-tuf-style-rsa-pss/v1"
TRUST_STORE_SCHEMA = "memory-vault-update-trust-store/v1"
TRUST_SUMMARY_SCHEMA = "memory-vault-update-trust-summary/v1"
TARGET_CUSTOM_SCHEMA = "memory-vault-update-target/v1"
SPEC_VERSION = "1.0.0"
TARGET_PATH = "plugins/memory-vault-sync.bundle"
CURRENT_PROTOCOL_GENERATION = 1

MAX_METADATA_BYTES = 128 * 1024
MAX_TRUST_STORE_BYTES = 512 * 1024
MAX_ROOT_ROTATIONS_PER_CHECK = 32
MAX_KEYS = 32
MAX_SIGNATURES = 64
MAX_RELEASE_NOTES_BYTES = 4 * 1024
MAX_VIRTUAL_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_VERSION = 2_147_483_647
MAX_CLOCK_SKEW_SECONDS = 5 * 60
MAX_EPOCH = 253_402_300_799

_MAX_LIFETIME_SECONDS = {
    "root": 366 * 24 * 60 * 60,
    "targets": 366 * 24 * 60 * 60,
    "snapshot": 7 * 24 * 60 * 60,
    "timestamp": 2 * 24 * 60 * 60,
}
_ROLE_NAMES = ("root", "targets", "snapshot", "timestamp")
_TRACKED_METADATA_ROLES = ("timestamp", "snapshot", "targets")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_KEY_ID_RE = _SHA256_RE
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{512,1024}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_ROOT_NAME_RE = re.compile(r"^[1-9][0-9]{0,9}\.root\.json$")
_PLUGIN_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_RSA_ENCRYPTION_ALGORITHM = bytes.fromhex(
    "300d06092a864886f70d0101010500"
)


class SignedUpdateError(ValueError):
    """Signed update metadata is malformed, stale, or untrusted."""


def metadata_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the exact persisted metadata bytes hashed by parent roles."""

    try:
        raw = persisted_json_bytes(value)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SignedUpdateError("signed update metadata is not encodable") from exc
    if len(raw) > MAX_METADATA_BYTES:
        raise SignedUpdateError("signed update metadata exceeds its byte bound")
    return raw


def _is_reparse_point(observed: os.stat_result) -> bool:
    attributes = int(getattr(observed, "st_file_attributes", 0))
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400))
    return bool(attributes & flag)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    left_inode = int(getattr(left, "st_ino", 0))
    right_inode = int(getattr(right, "st_ino", 0))
    if left_inode and right_inode:
        return (
            int(getattr(left, "st_dev", 0))
            == int(getattr(right, "st_dev", 0))
            and left_inode == right_inode
        )
    return True


def _stable_observations_match(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return _same_identity(left, right) and all(
        int(getattr(left, field, 0)) == int(getattr(right, field, 0))
        for field in ("st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _validate_regular_file(
    observed: os.stat_result,
    *,
    maximum_bytes: int,
    require_private_mode: bool = False,
) -> None:
    unsafe_mode = (
        require_private_mode
        and os.name != "nt"
        and bool(stat.S_IMODE(observed.st_mode) & 0o077)
    )
    if (
        not stat.S_ISREG(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or _is_reparse_point(observed)
        or int(getattr(observed, "st_nlink", 1)) != 1
        or not 1 <= int(observed.st_size) <= maximum_bytes
        or unsafe_mode
    ):
        raise SignedUpdateError("signed update metadata file is unsafe")


def _read_bounded_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    require_private_mode: bool = False,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        named = path.lstat()
        _validate_regular_file(
            opened,
            maximum_bytes=maximum_bytes,
            require_private_mode=require_private_mode,
        )
        _validate_regular_file(
            named,
            maximum_bytes=maximum_bytes,
            require_private_mode=require_private_mode,
        )
        if not _stable_observations_match(opened, named):
            raise SignedUpdateError(
                "signed update metadata changed before reading"
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        opened_again = os.fstat(descriptor)
        named_again = path.lstat()
        _validate_regular_file(
            opened_again,
            maximum_bytes=maximum_bytes,
            require_private_mode=require_private_mode,
        )
        _validate_regular_file(
            named_again,
            maximum_bytes=maximum_bytes,
            require_private_mode=require_private_mode,
        )
        if (
            len(raw) != int(opened.st_size)
            or not _stable_observations_match(opened, opened_again)
            or not _stable_observations_match(opened_again, named_again)
        ):
            raise SignedUpdateError(
                "signed update metadata changed while reading"
            )
        return raw
    except OSError as exc:
        raise SignedUpdateError(
            "signed update metadata could not be read safely"
        ) from exc
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def read_metadata_file(path: Path) -> bytes:
    """Read one bounded regular metadata file through a stable descriptor."""

    return _read_bounded_regular_file(path, maximum_bytes=MAX_METADATA_BYTES)


def read_trust_store_file(path: Path) -> bytes:
    """Read the larger local trust store with the same link/race policy."""

    return _read_bounded_regular_file(
        path,
        maximum_bytes=MAX_TRUST_STORE_BYTES,
        require_private_mode=True,
    )


def _optional_metadata_file(directory: Path, name: str) -> bytes | None:
    if _ROOT_NAME_RE.fullmatch(name) is None:
        raise SignedUpdateError("signed root metadata name is invalid")
    path = directory / name
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SignedUpdateError(
            "signed root metadata identity is unavailable"
        ) from exc
    return read_metadata_file(path)


def _load_envelope(raw: bytes) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SignedUpdateError("signed metadata must be UTF-8 without BOM")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise SignedUpdateError("signed update metadata is invalid JSON") from exc
    if (
        not isinstance(value, Mapping)
        or set(value) != {"signatures", "signed"}
        or not isinstance(value.get("signed"), Mapping)
        or not isinstance(value.get("signatures"), list)
        or not 1 <= len(value["signatures"]) <= MAX_SIGNATURES
    ):
        raise SignedUpdateError("signed metadata envelope fields are invalid")
    signatures: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value["signatures"]:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"keyid", "sig"}
            or not isinstance(item.get("keyid"), str)
            or _KEY_ID_RE.fullmatch(item["keyid"]) is None
            or not isinstance(item.get("sig"), str)
            or _SIGNATURE_RE.fullmatch(item["sig"]) is None
            or item["keyid"] in seen
        ):
            raise SignedUpdateError("signed metadata signature is invalid")
        seen.add(item["keyid"])
        signatures.append(
            {"keyid": str(item["keyid"]), "sig": str(item["sig"])}
        )
    normalized = {
        "signatures": signatures,
        "signed": dict(value["signed"]),
    }
    if metadata_bytes(normalized) != raw:
        raise SignedUpdateError("signed metadata bytes are not canonical")
    return normalized


def _parse_utc(value: Any, label: str) -> int:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise SignedUpdateError(f"{label} is not canonical UTC")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SignedUpdateError(f"{label} is invalid") from exc
    return int(parsed.replace(tzinfo=dt.timezone.utc).timestamp())


def _validate_epoch(value: Any, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_EPOCH
    ):
        raise SignedUpdateError(f"{label} is invalid")
    return int(value)


def _validate_version(value: Any, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_VERSION
    ):
        raise SignedUpdateError(f"{label} version is invalid")
    return int(value)


def _validate_role_lifetime(
    signed: Mapping[str, Any],
    role: str,
) -> tuple[int, int]:
    issued = _parse_utc(signed.get("issued_at"), f"{role} issued_at")
    expires = _parse_utc(signed.get("expires"), f"{role} expires")
    if expires <= issued:
        raise SignedUpdateError(f"{role} metadata lifetime is invalid")
    if expires - issued > _MAX_LIFETIME_SECONDS[role]:
        raise SignedUpdateError(f"{role} metadata lifetime is too long")
    return issued, expires


def _validate_role_time(
    signed: Mapping[str, Any],
    role: str,
    now_epoch: int,
    *,
    allow_expired: bool = False,
) -> None:
    now_epoch = _validate_epoch(now_epoch, "verification time")
    issued, expires = _validate_role_lifetime(signed, role)
    if issued > now_epoch + MAX_CLOCK_SKEW_SECONDS:
        raise SignedUpdateError(f"{role} metadata is from the future")
    if not allow_expired and expires <= now_epoch:
        raise SignedUpdateError(f"{role} metadata is expired")


def _read_der_length(raw: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(raw):
        raise SignedUpdateError("RSA public key DER is truncated")
    first = raw[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(raw):
        raise SignedUpdateError("RSA public key DER length is invalid")
    if raw[offset] == 0:
        raise SignedUpdateError("RSA public key DER length is not minimal")
    length = int.from_bytes(raw[offset : offset + count], "big")
    if length < 0x80:
        raise SignedUpdateError("RSA public key DER length is not minimal")
    return length, offset + count


def _read_der_value(
    raw: bytes,
    offset: int,
    expected_tag: int,
) -> tuple[bytes, int]:
    if offset >= len(raw) or raw[offset] != expected_tag:
        raise SignedUpdateError("RSA public key DER tag is invalid")
    length, content_offset = _read_der_length(raw, offset + 1)
    end = content_offset + length
    if end > len(raw):
        raise SignedUpdateError("RSA public key DER value is truncated")
    return raw[content_offset:end], end


def _parse_positive_der_integer(raw: bytes) -> int:
    if not raw or raw[0] & 0x80:
        raise SignedUpdateError("RSA public key integer is not positive")
    if len(raw) > 1 and raw[0] == 0 and raw[1] & 0x80 == 0:
        raise SignedUpdateError("RSA public key integer is not minimal")
    return int.from_bytes(raw, "big")


def _parse_rsa_public_key(public_pem: Any) -> tuple[int, int]:
    try:
        encoded_pem = public_pem.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        raise SignedUpdateError("RSA public key PEM is invalid") from None
    if (
        not isinstance(public_pem, str)
        or "PRIVATE KEY" in public_pem
        or "\r" in public_pem
        or not public_pem.endswith("\n")
        or len(encoded_pem) > 8 * 1024
    ):
        raise SignedUpdateError("RSA public key PEM is invalid")
    lines = public_pem.splitlines()
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[-1] != "-----END PUBLIC KEY-----"
        or any(not line or len(line) > 64 for line in lines[1:-1])
    ):
        raise SignedUpdateError("RSA public key PEM boundary is invalid")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignedUpdateError("RSA public key PEM body is invalid") from exc
    outer, outer_end = _read_der_value(der, 0, 0x30)
    if outer_end != len(der):
        raise SignedUpdateError("RSA public key DER has trailing bytes")
    algorithm, offset = _read_der_value(outer, 0, 0x30)
    if algorithm != _RSA_ENCRYPTION_ALGORITHM[2:]:
        raise SignedUpdateError("RSA public key algorithm is unsupported")
    bit_string, offset = _read_der_value(outer, offset, 0x03)
    if offset != len(outer) or not bit_string or bit_string[0] != 0:
        raise SignedUpdateError("RSA public key bit string is invalid")
    rsa_sequence, rsa_end = _read_der_value(bit_string[1:], 0, 0x30)
    if rsa_end != len(bit_string) - 1:
        raise SignedUpdateError("RSA public key value has trailing bytes")
    modulus_raw, integer_offset = _read_der_value(rsa_sequence, 0, 0x02)
    exponent_raw, integer_offset = _read_der_value(
        rsa_sequence,
        integer_offset,
        0x02,
    )
    if integer_offset != len(rsa_sequence):
        raise SignedUpdateError("RSA public key integers have trailing bytes")
    modulus = _parse_positive_der_integer(modulus_raw)
    exponent = _parse_positive_der_integer(exponent_raw)
    if not 2048 <= modulus.bit_length() <= 4096 or exponent != 65537:
        raise SignedUpdateError("RSA public key strength or exponent is invalid")
    return modulus, exponent


def _mgf1(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _verify_rsa_pss(public_pem: str, message: bytes, signature_hex: str) -> bool:
    try:
        modulus, exponent = _parse_rsa_public_key(public_pem)
        signature = bytes.fromhex(signature_hex)
    except (SignedUpdateError, ValueError):
        return False
    modulus_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != modulus_bytes:
        return False
    signature_number = int.from_bytes(signature, "big")
    if signature_number >= modulus:
        return False
    encoded_full = pow(signature_number, exponent, modulus).to_bytes(
        modulus_bytes,
        "big",
    )
    digest_size = hashlib.sha256().digest_size
    salt_size = digest_size
    encoded_bits = modulus.bit_length() - 1
    encoded_length = (encoded_bits + 7) // 8
    if len(encoded_full) == encoded_length:
        encoded = encoded_full
    elif (
        len(encoded_full) == encoded_length + 1
        and encoded_full[0] == 0
    ):
        encoded = encoded_full[1:]
    else:
        return False
    if encoded_length < digest_size + salt_size + 2:
        return False
    if encoded[-1] != 0xBC:
        return False
    masked_db = encoded[: encoded_length - digest_size - 1]
    digest = encoded[encoded_length - digest_size - 1 : -1]
    unused_bits = 8 * encoded_length - encoded_bits
    if unused_bits and masked_db[0] >> (8 - unused_bits):
        return False
    db_mask = _mgf1(digest, len(masked_db))
    database = bytearray(
        left ^ right for left, right in zip(masked_db, db_mask)
    )
    if unused_bits:
        database[0] &= 0xFF >> unused_bits
    padding_length = encoded_length - digest_size - salt_size - 2
    if (
        any(database[:padding_length])
        or database[padding_length] != 0x01
    ):
        return False
    salt = bytes(database[-salt_size:])
    message_hash = hashlib.sha256(message).digest()
    expected = hashlib.sha256(b"\0" * 8 + message_hash + salt).digest()
    return hmac.compare_digest(digest, expected)


def _validated_key(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"keytype", "scheme", "keyval"}
        or value.get("keytype") != "rsa"
        or value.get("scheme") != "rsassa-pss-sha256"
        or not isinstance(value.get("keyval"), Mapping)
        or set(value["keyval"]) != {"public"}
    ):
        raise SignedUpdateError("signed update public key fields are invalid")
    public = value["keyval"].get("public")
    _parse_rsa_public_key(public)
    return {
        "keytype": "rsa",
        "scheme": "rsassa-pss-sha256",
        "keyval": {"public": str(public)},
    }


def key_id(value: Mapping[str, Any]) -> str:
    normalized = _validated_key(value)
    try:
        return sha256_bytes(jcs_json_bytes(normalized))
    except (ProtocolValueError, UnicodeEncodeError) as exc:
        raise SignedUpdateError("signed update public key is not canonical") from exc


def _validate_root(envelope: Mapping[str, Any]) -> dict[str, Any]:
    signed = envelope.get("signed")
    if (
        not isinstance(signed, Mapping)
        or set(signed)
        != {
            "_type",
            "spec_version",
            "version",
            "expires",
            "issued_at",
            "consistent_snapshot",
            "keys",
            "roles",
        }
        or signed.get("_type") != "root"
        or signed.get("spec_version") != SPEC_VERSION
        or signed.get("consistent_snapshot") is not False
        or not isinstance(signed.get("keys"), Mapping)
        or not 4 <= len(signed["keys"]) <= MAX_KEYS
        or not isinstance(signed.get("roles"), Mapping)
        or set(signed["roles"]) != set(_ROLE_NAMES)
    ):
        raise SignedUpdateError("signed root metadata fields are invalid")
    _validate_version(signed.get("version"), "root")
    _validate_role_lifetime(signed, "root")
    keys: dict[str, dict[str, Any]] = {}
    for observed_id, raw_key in signed["keys"].items():
        if not isinstance(observed_id, str) or _KEY_ID_RE.fullmatch(observed_id) is None:
            raise SignedUpdateError("signed root key ID is invalid")
        normalized_key = _validated_key(raw_key)
        if key_id(normalized_key) != observed_id:
            raise SignedUpdateError("signed root key ID does not match its key")
        keys[observed_id] = normalized_key
    roles: dict[str, dict[str, Any]] = {}
    assigned: set[str] = set()
    for role in _ROLE_NAMES:
        raw_role = signed["roles"].get(role)
        if (
            not isinstance(raw_role, Mapping)
            or set(raw_role) != {"keyids", "threshold"}
            or not isinstance(raw_role.get("keyids"), list)
            or not raw_role["keyids"]
            or len(raw_role["keyids"]) > MAX_KEYS
            or any(
                not isinstance(keyid, str)
                or _KEY_ID_RE.fullmatch(keyid) is None
                for keyid in raw_role["keyids"]
            )
            or len(set(raw_role["keyids"])) != len(raw_role["keyids"])
            or any(keyid not in keys for keyid in raw_role["keyids"])
            or any(keyid in assigned for keyid in raw_role["keyids"])
            or not isinstance(raw_role.get("threshold"), int)
            or isinstance(raw_role.get("threshold"), bool)
            or not 1 <= raw_role["threshold"] <= len(raw_role["keyids"])
        ):
            raise SignedUpdateError(
                "signed root role keys or threshold are invalid"
            )
        assigned.update(str(keyid) for keyid in raw_role["keyids"])
        roles[role] = {
            "keyids": [str(keyid) for keyid in raw_role["keyids"]],
            "threshold": int(raw_role["threshold"]),
        }
    return {
        "signatures": [dict(item) for item in envelope["signatures"]],
        "signed": {
            "_type": "root",
            "spec_version": SPEC_VERSION,
            "version": int(signed["version"]),
            "expires": str(signed["expires"]),
            "issued_at": str(signed["issued_at"]),
            "consistent_snapshot": False,
            "keys": keys,
            "roles": roles,
        },
    }


def _verify_role_signatures(
    envelope: Mapping[str, Any],
    root: Mapping[str, Any],
    role: str,
) -> None:
    root_signed = root["signed"]
    role_value = root_signed["roles"][role]
    authorized = set(role_value["keyids"])
    threshold = int(role_value["threshold"])
    try:
        message = jcs_json_bytes(envelope["signed"])
    except (ProtocolValueError, UnicodeEncodeError) as exc:
        raise SignedUpdateError("signed role bytes are not canonical") from exc
    verified: set[str] = set()
    for signature in envelope["signatures"]:
        keyid = signature["keyid"]
        if keyid not in authorized or keyid in verified:
            continue
        public = root_signed["keys"][keyid]["keyval"]["public"]
        if _verify_rsa_pss(public, message, signature["sig"]):
            verified.add(keyid)
    if len(verified) < threshold:
        raise SignedUpdateError(f"{role} signature threshold was not met")


def _metadata_entry(value: Any, label: str) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"version", "length", "hashes"}
        or not isinstance(value.get("length"), int)
        or isinstance(value.get("length"), bool)
        or not 1 <= int(value["length"]) <= MAX_METADATA_BYTES
        or not isinstance(value.get("hashes"), Mapping)
        or set(value["hashes"]) != {"sha256"}
        or not isinstance(value["hashes"].get("sha256"), str)
        or _SHA256_RE.fullmatch(value["hashes"]["sha256"]) is None
    ):
        raise SignedUpdateError(f"{label} metadata descriptor is invalid")
    return {
        "version": _validate_version(value.get("version"), label),
        "length": int(value["length"]),
        "hashes": {"sha256": str(value["hashes"]["sha256"])},
    }


def _validate_timestamp(
    envelope: Mapping[str, Any],
    now_epoch: int,
) -> dict[str, Any]:
    signed = envelope.get("signed")
    if (
        not isinstance(signed, Mapping)
        or set(signed)
        != {"_type", "spec_version", "version", "expires", "issued_at", "meta"}
        or signed.get("_type") != "timestamp"
        or signed.get("spec_version") != SPEC_VERSION
        or not isinstance(signed.get("meta"), Mapping)
        or set(signed["meta"]) != {"snapshot.json"}
    ):
        raise SignedUpdateError("timestamp metadata fields are invalid")
    _validate_version(signed.get("version"), "timestamp")
    _validate_role_time(signed, "timestamp", now_epoch)
    _metadata_entry(signed["meta"]["snapshot.json"], "snapshot")
    return dict(signed)


def _validate_snapshot(
    envelope: Mapping[str, Any],
    now_epoch: int,
) -> dict[str, Any]:
    signed = envelope.get("signed")
    if (
        not isinstance(signed, Mapping)
        or set(signed)
        != {"_type", "spec_version", "version", "expires", "issued_at", "meta"}
        or signed.get("_type") != "snapshot"
        or signed.get("spec_version") != SPEC_VERSION
        or not isinstance(signed.get("meta"), Mapping)
        or set(signed["meta"]) != {"targets.json"}
    ):
        raise SignedUpdateError("snapshot metadata fields are invalid")
    _validate_version(signed.get("version"), "snapshot")
    _validate_role_time(signed, "snapshot", now_epoch)
    _metadata_entry(signed["meta"]["targets.json"], "targets")
    return dict(signed)


def _validate_release_notes(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise SignedUpdateError("signed release notes are invalid")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SignedUpdateError("signed release notes are invalid") from exc
    if len(raw) > MAX_RELEASE_NOTES_BYTES or any(
        character not in {"\n", "\t"}
        and unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in value
    ):
        raise SignedUpdateError("signed release notes exceed their safe domain")
    return value


def _validate_targets(
    envelope: Mapping[str, Any],
    now_epoch: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    signed = envelope.get("signed")
    if (
        not isinstance(signed, Mapping)
        or set(signed)
        != {"_type", "spec_version", "version", "expires", "issued_at", "targets"}
        or signed.get("_type") != "targets"
        or signed.get("spec_version") != SPEC_VERSION
        or not isinstance(signed.get("targets"), Mapping)
        or set(signed["targets"]) != {TARGET_PATH}
    ):
        raise SignedUpdateError("targets metadata fields are invalid")
    _validate_version(signed.get("version"), "targets")
    _validate_role_time(signed, "targets", now_epoch)
    target = signed["targets"][TARGET_PATH]
    if (
        not isinstance(target, Mapping)
        or set(target) != {"length", "hashes", "custom"}
        or not isinstance(target.get("length"), int)
        or isinstance(target.get("length"), bool)
        or not 1 <= int(target["length"]) <= MAX_VIRTUAL_BUNDLE_BYTES
        or not isinstance(target.get("hashes"), Mapping)
        or set(target["hashes"]) != {"sha256"}
        or not isinstance(target["hashes"].get("sha256"), str)
        or _SHA256_RE.fullmatch(target["hashes"]["sha256"]) is None
        or not isinstance(target.get("custom"), Mapping)
    ):
        raise SignedUpdateError("signed plugin target descriptor is invalid")
    custom = target["custom"]
    if (
        set(custom)
        != {
            "schema_version",
            "plugin_name",
            "plugin_version",
            "marketplace_commit_sha",
            "protocol",
            "release_notes",
        }
        or custom.get("schema_version") != TARGET_CUSTOM_SCHEMA
        or not isinstance(custom.get("plugin_name"), str)
        or _PLUGIN_NAME_RE.fullmatch(custom["plugin_name"]) is None
        or not isinstance(custom.get("plugin_version"), str)
        or not 1 <= len(custom["plugin_version"]) <= 128
        or custom["plugin_version"] != custom["plugin_version"].strip()
        or not isinstance(custom.get("marketplace_commit_sha"), str)
        or _GIT_SHA_RE.fullmatch(custom["marketplace_commit_sha"]) is None
        or set(custom["marketplace_commit_sha"]) == {"0"}
        or not isinstance(custom.get("protocol"), Mapping)
        or set(custom["protocol"]) != {"minimum", "maximum"}
        or not isinstance(custom["protocol"].get("minimum"), int)
        or isinstance(custom["protocol"].get("minimum"), bool)
        or not isinstance(custom["protocol"].get("maximum"), int)
        or isinstance(custom["protocol"].get("maximum"), bool)
        or not 1 <= custom["protocol"]["minimum"] <= custom["protocol"]["maximum"] <= 1000
    ):
        raise SignedUpdateError("signed plugin target custom fields are invalid")
    release_notes = _validate_release_notes(custom.get("release_notes"))
    normalized_target = {
        "length": int(target["length"]),
        "hashes": {"sha256": str(target["hashes"]["sha256"])},
        "custom": {
            "schema_version": TARGET_CUSTOM_SCHEMA,
            "plugin_name": str(custom["plugin_name"]),
            "plugin_version": str(custom["plugin_version"]),
            "marketplace_commit_sha": str(custom["marketplace_commit_sha"]),
            "protocol": {
                "minimum": int(custom["protocol"]["minimum"]),
                "maximum": int(custom["protocol"]["maximum"]),
            },
            "release_notes": release_notes,
        },
    }
    return dict(signed), normalized_target


def _initial_metadata_state() -> dict[str, dict[str, Any]]:
    return {
        role: {"version": 0, "sha256": None}
        for role in _TRACKED_METADATA_ROLES
    }


def _validate_metadata_state(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != set(_TRACKED_METADATA_ROLES):
        raise SignedUpdateError("trusted metadata version state is invalid")
    result: dict[str, dict[str, Any]] = {}
    for role in _TRACKED_METADATA_ROLES:
        item = value.get(role)
        if (
            not isinstance(item, Mapping)
            or set(item) != {"version", "sha256"}
            or not isinstance(item.get("version"), int)
            or isinstance(item.get("version"), bool)
            or not 0 <= item["version"] <= MAX_VERSION
            or (
                item["version"] == 0
                and item.get("sha256") is not None
            )
            or (
                item["version"] > 0
                and (
                    not isinstance(item.get("sha256"), str)
                    or _SHA256_RE.fullmatch(item["sha256"]) is None
                )
            )
        ):
            raise SignedUpdateError("trusted role version state is invalid")
        result[role] = {
            "version": int(item["version"]),
            "sha256": item.get("sha256"),
        }
    return result


def _validate_last_target(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    expected = {
        "plugin_name",
        "plugin_version",
        "bundle_sha256",
        "bundle_length",
        "marketplace_commit_sha",
        "protocol_minimum",
        "protocol_maximum",
        "release_notes",
        "targets_version",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != expected
        or not isinstance(value.get("plugin_name"), str)
        or _PLUGIN_NAME_RE.fullmatch(value["plugin_name"]) is None
        or not isinstance(value.get("plugin_version"), str)
        or not 1 <= len(value["plugin_version"]) <= 128
        or value["plugin_version"] != value["plugin_version"].strip()
        or not isinstance(value.get("bundle_sha256"), str)
        or _SHA256_RE.fullmatch(value["bundle_sha256"]) is None
        or not isinstance(value.get("bundle_length"), int)
        or isinstance(value.get("bundle_length"), bool)
        or not 1 <= value["bundle_length"] <= MAX_VIRTUAL_BUNDLE_BYTES
        or not isinstance(value.get("marketplace_commit_sha"), str)
        or _GIT_SHA_RE.fullmatch(value["marketplace_commit_sha"]) is None
        or set(value["marketplace_commit_sha"]) == {"0"}
        or not isinstance(value.get("protocol_minimum"), int)
        or isinstance(value.get("protocol_minimum"), bool)
        or not isinstance(value.get("protocol_maximum"), int)
        or isinstance(value.get("protocol_maximum"), bool)
        or not 1
        <= value["protocol_minimum"]
        <= value["protocol_maximum"]
        <= 1000
        or not isinstance(value.get("targets_version"), int)
        or isinstance(value.get("targets_version"), bool)
        or not 1 <= value["targets_version"] <= MAX_VERSION
    ):
        raise SignedUpdateError("last trusted update target is invalid")
    release_notes = _validate_release_notes(value.get("release_notes"))
    return {
        "plugin_name": str(value["plugin_name"]),
        "plugin_version": str(value["plugin_version"]),
        "bundle_sha256": str(value["bundle_sha256"]),
        "bundle_length": int(value["bundle_length"]),
        "marketplace_commit_sha": str(value["marketplace_commit_sha"]),
        "protocol_minimum": int(value["protocol_minimum"]),
        "protocol_maximum": int(value["protocol_maximum"]),
        "release_notes": release_notes,
        "targets_version": int(value["targets_version"]),
    }


def validate_trust_store(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "schema_version",
            "profile",
            "trusted_root",
            "trusted_root_sha256",
            "metadata",
            "last_target",
            "last_verified_at",
        }
        or value.get("schema_version") != TRUST_STORE_SCHEMA
        or value.get("profile") != SIGNED_UPDATE_PROFILE
        or not isinstance(value.get("trusted_root"), Mapping)
        or not isinstance(value.get("trusted_root_sha256"), str)
        or _SHA256_RE.fullmatch(value["trusted_root_sha256"]) is None
        or (
            value.get("last_verified_at") is not None
            and (
                not isinstance(value.get("last_verified_at"), str)
                or _UTC_RE.fullmatch(value["last_verified_at"]) is None
            )
        )
    ):
        raise SignedUpdateError("signed update trust store fields are invalid")
    if value.get("last_verified_at") is not None:
        _parse_utc(value["last_verified_at"], "last verified time")
    root_raw = metadata_bytes(value["trusted_root"])
    root = _validate_root(_load_envelope(root_raw))
    if sha256_bytes(root_raw) != value["trusted_root_sha256"]:
        raise SignedUpdateError("trusted root hash does not match")
    _verify_role_signatures(root, root, "root")
    metadata_state = _validate_metadata_state(value.get("metadata"))
    last_target = _validate_last_target(value.get("last_target"))
    if last_target is None:
        if (
            value.get("last_verified_at") is not None
            or any(item["version"] != 0 for item in metadata_state.values())
        ):
            raise SignedUpdateError("trusted update state is incomplete")
    elif (
        value.get("last_verified_at") is None
        or any(item["version"] == 0 for item in metadata_state.values())
        or last_target["targets_version"]
        != metadata_state["targets"]["version"]
    ):
        raise SignedUpdateError("trusted update state is inconsistent")
    return {
        "schema_version": TRUST_STORE_SCHEMA,
        "profile": SIGNED_UPDATE_PROFILE,
        "trusted_root": root,
        "trusted_root_sha256": str(value["trusted_root_sha256"]),
        "metadata": metadata_state,
        "last_target": last_target,
        "last_verified_at": value.get("last_verified_at"),
    }


def import_trusted_root(raw: bytes, *, now_epoch: int) -> dict[str, Any]:
    now_epoch = _validate_epoch(now_epoch, "verification time")
    envelope = _validate_root(_load_envelope(raw))
    _verify_role_signatures(envelope, envelope, "root")
    _validate_role_time(envelope["signed"], "root", now_epoch)
    return {
        "schema_version": TRUST_STORE_SCHEMA,
        "profile": SIGNED_UPDATE_PROFILE,
        "trusted_root": envelope,
        "trusted_root_sha256": sha256_bytes(raw),
        "metadata": _initial_metadata_state(),
        "last_target": None,
        "last_verified_at": None,
    }


def _apply_root_rotations(
    metadata_directory: Path,
    root: dict[str, Any],
    metadata_state: dict[str, dict[str, Any]],
    *,
    now_epoch: int,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], int]:
    rotations = 0
    current = root
    state = {
        role: dict(metadata_state[role])
        for role in _TRACKED_METADATA_ROLES
    }
    while rotations < MAX_ROOT_ROTATIONS_PER_CHECK:
        next_version = int(current["signed"]["version"]) + 1
        raw = _optional_metadata_file(
            metadata_directory,
            f"{next_version}.root.json",
        )
        if raw is None:
            break
        candidate = _validate_root(_load_envelope(raw))
        if int(candidate["signed"]["version"]) != next_version:
            raise SignedUpdateError("root rotation version is not sequential")
        _verify_role_signatures(candidate, current, "root")
        _verify_role_signatures(candidate, candidate, "root")
        # Expired intermediate roots are required for clients that missed
        # rotations, but their lifetime and issue time must still be valid.
        _validate_role_time(
            candidate["signed"],
            "root",
            now_epoch,
            allow_expired=True,
        )
        current = candidate
        rotations += 1
    if rotations == MAX_ROOT_ROTATIONS_PER_CHECK:
        next_version = int(current["signed"]["version"]) + 1
        if _optional_metadata_file(
            metadata_directory,
            f"{next_version}.root.json",
        ) is not None:
            raise SignedUpdateError("too many root rotations in one check")
    return current, state, rotations


def _match_metadata_descriptor(
    raw: bytes,
    envelope: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    label: str,
) -> None:
    signed = envelope.get("signed")
    if not isinstance(signed, Mapping):
        raise SignedUpdateError(f"{label} metadata signed body is invalid")
    observed_version = _validate_version(signed.get("version"), label)
    if (
        len(raw) != int(descriptor["length"])
        or sha256_bytes(raw) != descriptor["hashes"]["sha256"]
        or observed_version != int(descriptor["version"])
    ):
        raise SignedUpdateError(f"{label} metadata does not match its parent")


def _advance_metadata_state(
    previous: Mapping[str, Any],
    role: str,
    version: int,
    digest: str,
) -> dict[str, Any]:
    previous_version = int(previous["version"])
    previous_digest = previous.get("sha256")
    if version < previous_version:
        raise SignedUpdateError(f"{role} metadata rollback was refused")
    if version == previous_version and digest != previous_digest:
        raise SignedUpdateError(f"{role} same-version metadata changed")
    return {"version": version, "sha256": digest}


def _validate_candidate(candidate: Any) -> dict[str, Any]:
    if (
        not isinstance(candidate, Mapping)
        or not isinstance(candidate.get("version"), str)
        or not isinstance(candidate.get("bundle_sha256"), str)
        or _SHA256_RE.fullmatch(candidate["bundle_sha256"]) is None
        or not isinstance(candidate.get("bundle_length"), int)
        or isinstance(candidate.get("bundle_length"), bool)
        or not 1 <= candidate["bundle_length"] <= MAX_VIRTUAL_BUNDLE_BYTES
        or not isinstance(candidate.get("commit_sha"), str)
        or _GIT_SHA_RE.fullmatch(candidate["commit_sha"]) is None
    ):
        raise SignedUpdateError("marketplace update candidate is invalid")
    return {
        "version": str(candidate["version"]),
        "bundle_sha256": str(candidate["bundle_sha256"]),
        "bundle_length": int(candidate["bundle_length"]),
        "commit_sha": str(candidate["commit_sha"]),
    }


def verify_update_chain(
    metadata_directory: Path,
    trust_store: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    plugin_name: str,
    now_epoch: int,
) -> dict[str, Any]:
    """Verify root/timestamp/snapshot/targets and one plugin candidate."""

    now_epoch = _validate_epoch(now_epoch, "verification time")
    try:
        directory_stat = metadata_directory.lstat()
    except OSError as exc:
        raise SignedUpdateError(
            "signed update metadata directory is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or stat.S_ISLNK(directory_stat.st_mode)
        or _is_reparse_point(directory_stat)
    ):
        raise SignedUpdateError("signed update metadata directory is unsafe")
    trusted = validate_trust_store(trust_store)
    previous_verified_epoch = (
        _parse_utc(trusted["last_verified_at"], "last verified time")
        if trusted["last_verified_at"] is not None
        else None
    )
    if (
        previous_verified_epoch is not None
        and now_epoch + MAX_CLOCK_SKEW_SECONDS < previous_verified_epoch
    ):
        raise SignedUpdateError("local clock rollback was refused")
    current_root, metadata_state, rotations = _apply_root_rotations(
        metadata_directory,
        trusted["trusted_root"],
        trusted["metadata"],
        now_epoch=now_epoch,
    )
    _validate_role_time(current_root["signed"], "root", now_epoch)

    timestamp_raw = read_metadata_file(metadata_directory / "timestamp.json")
    timestamp = _load_envelope(timestamp_raw)
    timestamp_signed = _validate_timestamp(timestamp, now_epoch)
    _verify_role_signatures(timestamp, current_root, "timestamp")
    timestamp_digest = sha256_bytes(timestamp_raw)
    timestamp_state = _advance_metadata_state(
        metadata_state["timestamp"],
        "timestamp",
        int(timestamp_signed["version"]),
        timestamp_digest,
    )

    snapshot_raw = read_metadata_file(metadata_directory / "snapshot.json")
    snapshot = _load_envelope(snapshot_raw)
    snapshot_descriptor = _metadata_entry(
        timestamp_signed["meta"]["snapshot.json"],
        "snapshot",
    )
    _match_metadata_descriptor(
        snapshot_raw,
        snapshot,
        snapshot_descriptor,
        "snapshot",
    )
    snapshot_signed = _validate_snapshot(snapshot, now_epoch)
    _verify_role_signatures(snapshot, current_root, "snapshot")
    snapshot_digest = sha256_bytes(snapshot_raw)
    snapshot_state = _advance_metadata_state(
        metadata_state["snapshot"],
        "snapshot",
        int(snapshot_signed["version"]),
        snapshot_digest,
    )

    targets_raw = read_metadata_file(metadata_directory / "targets.json")
    targets = _load_envelope(targets_raw)
    targets_descriptor = _metadata_entry(
        snapshot_signed["meta"]["targets.json"],
        "targets",
    )
    _match_metadata_descriptor(
        targets_raw,
        targets,
        targets_descriptor,
        "targets",
    )
    targets_signed, target = _validate_targets(targets, now_epoch)
    _verify_role_signatures(targets, current_root, "targets")
    targets_digest = sha256_bytes(targets_raw)
    targets_state = _advance_metadata_state(
        metadata_state["targets"],
        "targets",
        int(targets_signed["version"]),
        targets_digest,
    )

    observed = _validate_candidate(candidate)
    custom = target["custom"]
    protocol = custom["protocol"]
    if (
        custom["plugin_name"] != plugin_name
        or custom["plugin_version"] != observed["version"]
        or target["hashes"]["sha256"] != observed["bundle_sha256"]
        or int(target["length"]) != observed["bundle_length"]
        or not (
            int(protocol["minimum"])
            <= CURRENT_PROTOCOL_GENERATION
            <= int(protocol["maximum"])
        )
    ):
        raise SignedUpdateError(
            "signed target does not match the marketplace plugin bundle"
        )
    last_target = {
        "plugin_name": plugin_name,
        "plugin_version": observed["version"],
        "bundle_sha256": observed["bundle_sha256"],
        "bundle_length": observed["bundle_length"],
        "marketplace_commit_sha": custom["marketplace_commit_sha"],
        "protocol_minimum": int(protocol["minimum"]),
        "protocol_maximum": int(protocol["maximum"]),
        "release_notes": custom["release_notes"],
        "targets_version": int(targets_signed["version"]),
    }
    updated_store = {
        "schema_version": TRUST_STORE_SCHEMA,
        "profile": SIGNED_UPDATE_PROFILE,
        "trusted_root": current_root,
        "trusted_root_sha256": sha256_bytes(metadata_bytes(current_root)),
        "metadata": {
            "timestamp": timestamp_state,
            "snapshot": snapshot_state,
            "targets": targets_state,
        },
        "last_target": last_target,
        "last_verified_at": dt.datetime.fromtimestamp(
            max(now_epoch, previous_verified_epoch or now_epoch),
            tz=dt.timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return {
        "trust_store": updated_store,
        "target": last_target,
        "root_rotations": rotations,
        "observed_marketplace_head": observed["commit_sha"],
    }


def trust_summary(
    value: Mapping[str, Any] | None,
    *,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    if now_epoch is not None:
        now_epoch = _validate_epoch(now_epoch, "status time")
    if value is None:
        return {
            "schema_version": TRUST_SUMMARY_SCHEMA,
            "required": False,
            "profile": None,
            "mode": "exact-repository-bundle-and-commit-identity",
            "valid": True,
            "root_version": None,
            "root_sha256": None,
            "root_expires": None,
            "root_expired": False,
            "metadata_versions": None,
            "last_target": None,
            "last_verified_at": None,
            "private_keys_imported": False,
        }
    trusted = validate_trust_store(value)
    root_expires = str(trusted["trusted_root"]["signed"]["expires"])
    return {
        "schema_version": TRUST_SUMMARY_SCHEMA,
        "required": True,
        "profile": SIGNED_UPDATE_PROFILE,
        "mode": "signed-metadata-required-no-legacy-bypass",
        "valid": True,
        "root_version": int(trusted["trusted_root"]["signed"]["version"]),
        "root_sha256": trusted["trusted_root_sha256"],
        "root_expires": root_expires,
        "root_expired": (
            _parse_utc(root_expires, "root expires") <= now_epoch
            if now_epoch is not None
            else None
        ),
        "metadata_versions": {
            role: int(trusted["metadata"][role]["version"])
            for role in _TRACKED_METADATA_ROLES
        },
        "last_target": trusted["last_target"],
        "last_verified_at": trusted["last_verified_at"],
        "private_keys_imported": False,
    }
