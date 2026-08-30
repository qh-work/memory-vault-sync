#!/usr/bin/env python3
"""Optional Ed25519 identities and an independently administered trust store.

The standard-library-only memory core does not import this module. Importing
this module does not install dependencies, create keys, or trust a sender.
Only explicit administration may change the private identity or trust store;
memory records and incoming transport messages are never trust configuration.

Signatures identify a key, not a human, a model, an owner, or an execution
permission. They do not establish that the signed evidence is true.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Mapping
from contextlib import contextmanager
import copy
import datetime as dt
import errno
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Iterator

_SOURCE_DIRECTORY = str(Path(__file__).resolve().parent)
if _SOURCE_DIRECTORY not in sys.path:
    sys.path.insert(0, _SOURCE_DIRECTORY)

from memory_vault import MemoryError as VaultError  # noqa: E402
from memory_vault import canonical_bytes, sha256, validate_record  # noqa: E402


IDENTITY_SCHEMA = "universal-memory-identity/v1"
PUBLIC_KEY_SCHEMA = "universal-memory-public-key/v1"
TRUST_STORE_SCHEMA = "universal-memory-trust-store/v1"
ATTESTATION_SCHEMA = "universal-memory-attestation/v1"
MESSAGE_SIGNATURE_SCHEMA = "universal-memory-message-signature/v1"
TRUST_RESULT_SCHEMA = "universal-memory-trust-result/v1"
ALGORITHM = "Ed25519"

MAX_IDENTITY_BYTES = 4096
MAX_PUBLIC_KEY_BYTES = 2048
MAX_PROOF_BYTES = 2048
MAX_TRUST_STORE_BYTES = 2 * 1024 * 1024
MAX_TRUSTED_KEYS = 1024
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 2_000_000

_KEY_ID = re.compile(r"ed25519_[0-9a-f]{64}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z"
)
_RECORD_DOMAIN = b"UniversalAgentMemory\x00record-attestation\x00v1\x00"
_MESSAGE_DOMAIN = b"UniversalAgentMemory\x00message-signature\x00v1\x00"


class TrustError(ValueError):
    """A content-free failure suitable for a protocol response."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _crypto() -> tuple[Any, Any, Any, Any, Any]:
    """Load the vetted provider only for cryptographic operations."""
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError:
        raise TrustError("cryptography_unavailable") from None
    return (
        Ed25519PrivateKey,
        Ed25519PublicKey,
        serialization,
        InvalidSignature,
        UnsupportedAlgorithm,
    )


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise TrustError("invalid_trust_store")
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise TrustError("invalid_trust_store") from None
    return value


def _object(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise TrustError(code)
    return dict(value)


def _json_bytes(value: Any, *, maximum: int) -> bytes:
    """Bound traversal and accept only plain, unambiguous JSON value types."""
    nodes = 0
    text_bytes = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal nodes, text_bytes
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise TrustError("json_structure_too_large")
        if isinstance(item, str):
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                raise TrustError("invalid_json_value") from None
            if text_bytes > maximum:
                raise TrustError("payload_too_large")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TrustError("invalid_json_value")
                walk(key, depth + 1)
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
        elif item is None or isinstance(item, (bool, int, float)):
            pass
        else:
            raise TrustError("invalid_json_value")

    walk(value, 0)
    try:
        encoded = canonical_bytes(value)
    except (VaultError, UnicodeError, OverflowError):
        raise TrustError("invalid_json_value") from None
    if len(encoded) > maximum:
        raise TrustError("payload_too_large")
    return encoded


def _json_loads(data: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise TrustError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise TrustError("invalid_json_value")

    if data.startswith(b"\xef\xbb\xbf"):
        raise TrustError("invalid_json_value")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError):
        raise TrustError("invalid_json_value") from None


def _base64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unbase64(value: Any, length: int, code: str) -> bytes:
    if not isinstance(value, str) or len(value) != ((length + 2) // 3) * 4:
        raise TrustError(code)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        raise TrustError(code) from None
    if len(decoded) != length or _base64(decoded) != value:
        raise TrustError(code)
    return decoded


def _key_id(value: Any) -> str:
    if not isinstance(value, str) or _KEY_ID.fullmatch(value) is None:
        raise TrustError("invalid_key_id")
    return value


def _descriptor(value: Any) -> dict[str, str]:
    raw = _object(
        value,
        {"schema_version", "algorithm", "key_id", "public_key"},
        "invalid_public_descriptor",
    )
    if raw["schema_version"] != PUBLIC_KEY_SCHEMA or raw["algorithm"] != ALGORITHM:
        raise TrustError("unsupported_public_key_schema")
    public_bytes = _unbase64(raw["public_key"], 32, "invalid_public_key")
    key_id = _key_id(raw["key_id"])
    if key_id != "ed25519_" + sha256(public_bytes):
        raise TrustError("key_id_mismatch")
    _json_bytes(raw, maximum=MAX_PUBLIC_KEY_BYTES)
    return raw


def _record_digest(record: Any) -> str:
    if not isinstance(record, Mapping):
        raise TrustError("invalid_record")
    raw_bytes = _json_bytes(dict(record), maximum=MAX_RECORD_BYTES)
    try:
        checked = validate_record(record)
    except VaultError as exc:
        raise TrustError(exc.code) from None
    except (TypeError, ValueError, RecursionError):
        raise TrustError("invalid_record") from None
    # The core validator normalizes some lists. Do not allow unbound, ignored
    # variations to survive an author-signature verification.
    if raw_bytes != _json_bytes(checked, maximum=MAX_RECORD_BYTES):
        raise TrustError("non_canonical_record")
    return checked["record_sha256"]


def _message_digest(payload: Any) -> str:
    if not isinstance(payload, Mapping):
        raise TrustError("invalid_message")
    return sha256(_json_bytes(dict(payload), maximum=MAX_MESSAGE_BYTES))


def _proof_body(schema: str, key_id: str, digest_field: str, digest: str) -> dict[str, str]:
    return {"schema_version": schema, "key_id": key_id, digest_field: digest}


def _proof(
    value: Any, *, schema: str, digest_field: str, expected_digest: str
) -> tuple[dict[str, str], bytes]:
    raw = _object(
        value,
        {"schema_version", "key_id", digest_field, "signature"},
        "invalid_signature_proof",
    )
    if raw["schema_version"] != schema:
        raise TrustError("unsupported_signature_schema")
    _key_id(raw["key_id"])
    digest = raw[digest_field]
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise TrustError("invalid_signature_digest")
    if digest != expected_digest:
        raise TrustError("signature_digest_mismatch")
    signature = _unbase64(raw["signature"], 64, "invalid_signature")
    _json_bytes(raw, maximum=MAX_PROOF_BYTES)
    return _proof_body(schema, raw["key_id"], digest_field, digest), signature


def _absolute_path(value: Path) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError):
        raise TrustError("invalid_path") from None
    if not path.is_absolute():
        raise TrustError("absolute_path_required")
    if ".." in path.parts or not path.name or "\x00" in str(path):
        raise TrustError("invalid_path")
    return path


def _require_protected_storage() -> None:
    # chmod(0600) does not establish a Windows ACL. Do not silently claim it
    # does: that platform needs a separately reviewed native storage adapter.
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise TrustError("protected_storage_unavailable")


def _safe_parent(path: Path, *, create: bool) -> bool:
    _require_protected_storage()
    current = Path(path.anchor)
    uid = os.getuid()
    for part in path.parts[1:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                return False
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError:
                raise TrustError("storage_unavailable") from None
            try:
                info = current.lstat()
            except OSError:
                raise TrustError("storage_unavailable") from None
        except OSError:
            raise TrustError("storage_unavailable") from None
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise TrustError("unsafe_storage_parent")
        if info.st_uid not in {0, uid}:
            raise TrustError("unsafe_storage_parent")
        writable_by_others = stat.S_IMODE(info.st_mode) & 0o022
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if writable_by_others and not sticky_root:
            raise TrustError("unsafe_storage_parent")
    try:
        parent = path.parent.lstat()
    except OSError:
        raise TrustError("storage_unavailable") from None
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise TrustError("unsafe_storage_parent")
    return True


def _check_file(info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise TrustError("unsafe_private_file")


def _open_existing(path: Path, flags: int) -> int:
    try:
        before = path.lstat()
        _check_file(before)
        fd = os.open(path, flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            after = os.fstat(fd)
            _check_file(after)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise TrustError("storage_changed")
        except BaseException:
            os.close(fd)
            raise
        return fd
    except FileNotFoundError:
        raise
    except OSError:
        raise TrustError("storage_unavailable") from None


def _open_new(path: Path, flags: int) -> int:
    try:
        fd = os.open(
            path,
            flags | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError:
        raise TrustError("file_already_exists") from None
    except OSError:
        raise TrustError("storage_unavailable") from None
    try:
        os.fchmod(fd, 0o600)
        _check_file(os.fstat(fd))
    except OSError:
        os.close(fd)
        raise TrustError("storage_unavailable") from None
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_private(path: Path, maximum: int) -> bytes | None:
    if not _safe_parent(path, create=False):
        return None
    try:
        fd = _open_existing(path, os.O_RDONLY)
    except FileNotFoundError:
        return None
    try:
        with os.fdopen(fd, "rb") as stream:
            if os.fstat(stream.fileno()).st_size > maximum:
                raise TrustError("private_file_too_large")
            data = stream.read(maximum + 1)
    except OSError:
        raise TrustError("storage_unavailable") from None
    if len(data) > maximum:
        raise TrustError("private_file_too_large")
    return data


def _sync_parent(path: Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(fd)


def _write_new_private(path: Path, data: bytes) -> None:
    _safe_parent(path, create=True)
    fd = _open_new(path, os.O_WRONLY)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _sync_parent(path)
    except OSError:
        # Remove only the just-created, incomplete identity, never an existing
        # identity or a path replaced by another process.
        try:
            current = path.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                path.unlink()
        except OSError:
            pass
        raise TrustError("storage_unavailable") from None


def _atomic_write_private(path: Path, data: bytes) -> None:
    _safe_parent(path, create=True)
    temporary: Path | None = None
    try:
        try:
            _check_file(path.lstat())
        except FileNotFoundError:
            pass
        fd, name = tempfile.mkstemp(prefix=".memory-trust-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            _check_file(os.fstat(stream.fileno()))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-account code can change both memory and trust files; permissions
        # intentionally do not claim isolation from a compromised OS account.
        os.replace(temporary, path)
        temporary = None
        _sync_parent(path)
    except OSError:
        raise TrustError("storage_unavailable") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


@contextmanager
def _exclusive_store(path: Path) -> Iterator[None]:
    _safe_parent(path, create=True)
    lock_path = path.with_name(path.name + ".lock")
    try:
        fd = _open_existing(lock_path, os.O_RDWR)
    except FileNotFoundError:
        try:
            fd = _open_new(lock_path, os.O_RDWR)
        except TrustError as exc:
            if exc.code != "file_already_exists":
                raise
            try:
                fd = _open_existing(lock_path, os.O_RDWR)
            except FileNotFoundError:
                raise TrustError("storage_changed") from None
    try:
        import fcntl

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise TrustError("trust_store_busy") from None
            raise TrustError("storage_unavailable") from None
        yield
    finally:
        os.close(fd)  # Closing also releases the advisory lock.


class Identity:
    """A private signing key loaded only from an explicitly selected file."""

    __slots__ = ("_private_key", "_public")

    def __init__(self, private_key: Any):
        _, _, serialization, _, unsupported = _crypto()
        try:
            public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except (ValueError, unsupported):
            raise TrustError("invalid_private_key") from None
        self._private_key = private_key
        self._public = {
            "schema_version": PUBLIC_KEY_SCHEMA,
            "algorithm": ALGORITHM,
            "key_id": "ed25519_" + sha256(public),
            "public_key": _base64(public),
        }

    @classmethod
    def generate(cls, path: Path) -> Identity:
        """Explicit provisioning; never called by load, sign, or verification."""
        selected = _absolute_path(path)
        _require_protected_storage()
        try:
            selected.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            raise TrustError("storage_unavailable") from None
        else:
            raise TrustError("file_already_exists")
        private_type, _, serialization, _, unsupported = _crypto()
        try:
            private_key = private_type.generate()
            secret = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        except unsupported:
            raise TrustError("ed25519_unavailable") from None
        result = cls(private_key)
        stored = {
            **result.public_descriptor(),
            "schema_version": IDENTITY_SCHEMA,
            "private_key": _base64(secret),
        }
        _write_new_private(selected, _json_bytes(stored, maximum=MAX_IDENTITY_BYTES) + b"\n")
        return result

    @classmethod
    def load(cls, path: Path) -> Identity:
        data = _read_private(_absolute_path(path), MAX_IDENTITY_BYTES)
        if data is None:
            raise TrustError("identity_not_found")
        raw = _object(
            _json_loads(data),
            {"schema_version", "algorithm", "key_id", "public_key", "private_key"},
            "invalid_identity",
        )
        if raw["schema_version"] != IDENTITY_SCHEMA:
            raise TrustError("unsupported_identity_schema")
        public = _descriptor({
            "schema_version": PUBLIC_KEY_SCHEMA,
            "algorithm": raw["algorithm"],
            "key_id": raw["key_id"],
            "public_key": raw["public_key"],
        })
        secret = _unbase64(raw["private_key"], 32, "invalid_private_key")
        private_type, _, _, _, unsupported = _crypto()
        try:
            result = cls(private_type.from_private_bytes(secret))
        except (ValueError, unsupported):
            raise TrustError("invalid_private_key") from None
        if result.public_descriptor() != public:
            raise TrustError("identity_public_key_mismatch")
        return result

    @property
    def key_id(self) -> str:
        return self._public["key_id"]

    def public_descriptor(self) -> dict[str, str]:
        return dict(self._public)

    def _sign(self, body: dict[str, str], domain: bytes) -> dict[str, str]:
        _, _, _, _, unsupported = _crypto()
        try:
            signature = self._private_key.sign(
                domain + _json_bytes(body, maximum=MAX_PROOF_BYTES)
            )
        except (ValueError, unsupported):
            raise TrustError("signing_failed") from None
        return {**body, "signature": _base64(signature)}

    def sign_record(self, record: Mapping[str, Any]) -> dict[str, str]:
        return self._sign(
            _proof_body(ATTESTATION_SCHEMA, self.key_id, "record_sha256", _record_digest(record)),
            _RECORD_DOMAIN,
        )

    def sign_message(self, payload: Mapping[str, Any]) -> dict[str, str]:
        return self._sign(
            _proof_body(
                MESSAGE_SIGNATURE_SCHEMA, self.key_id, "payload_sha256", _message_digest(payload)
            ),
            _MESSAGE_DOMAIN,
        )


class TrustStore:
    """Public keys authorized by explicit local administration, not memory."""

    def __init__(self, path: Path):
        self.path = _absolute_path(path)
        self._cache_token: tuple[int, int, int, int, int] | None = None
        self._cache_state: dict[str, Any] | None = None

    def _snapshot_token(self) -> tuple[int, int, int, int, int] | None:
        if not _safe_parent(self.path, create=False):
            return None
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise TrustError("storage_unavailable") from None
        _check_file(info)
        return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, info.st_size)

    def _read(self) -> dict[str, Any]:
        token = self._snapshot_token()
        if token is not None and token == self._cache_token and self._cache_state is not None:
            return self._cache_state
        data = _read_private(self.path, MAX_TRUST_STORE_BYTES)
        if data is None:
            self._cache_token = None
            self._cache_state = None
            return {"schema_version": TRUST_STORE_SCHEMA, "revision": 0, "keys": {}}
        raw = _object(_json_loads(data), {"schema_version", "revision", "keys"}, "invalid_trust_store")
        if raw["schema_version"] != TRUST_STORE_SCHEMA:
            raise TrustError("unsupported_trust_store_schema")
        if type(raw["revision"]) is not int or not 0 <= raw["revision"] < 2**63:
            raise TrustError("invalid_trust_store")
        keys = raw["keys"]
        if not isinstance(keys, dict) or len(keys) > MAX_TRUSTED_KEYS:
            raise TrustError("invalid_trust_store")
        for key_id, value in keys.items():
            _key_id(key_id)
            entry = _object(
                value,
                {"descriptor", "label", "state", "added_at", "revoked_at"},
                "invalid_trust_store",
            )
            if _descriptor(entry["descriptor"])["key_id"] != key_id:
                raise TrustError("invalid_trust_store")
            self._label(entry["label"])
            _timestamp(entry["added_at"])
            if entry["state"] == "trusted" and entry["revoked_at"] is None:
                continue
            if entry["state"] == "revoked":
                _timestamp(entry["revoked_at"])
                continue
            raise TrustError("invalid_trust_store")
        _json_bytes(raw, maximum=MAX_TRUST_STORE_BYTES)
        # Reuse validated public metadata while its protected file is unchanged;
        # do not reparse every registered key for each record in a large batch.
        # Atomic registry replacement changes the inode and invalidates this.
        if token is not None and token == self._snapshot_token():
            self._cache_token = token
            self._cache_state = raw
        else:
            self._cache_token = None
            self._cache_state = None
        return raw

    @staticmethod
    def _label(label: Any) -> str:
        if not isinstance(label, str):
            raise TrustError("invalid_trust_label")
        try:
            length = len(label.encode("utf-8"))
        except UnicodeError:
            raise TrustError("invalid_trust_label") from None
        if length > 256 or any(ord(char) < 32 for char in label):
            raise TrustError("invalid_trust_label")
        return label

    def _write(self, state: dict[str, Any]) -> None:
        if state["revision"] >= 2**63 - 1:
            raise TrustError("trust_store_revision_exhausted")
        state["revision"] += 1
        try:
            _atomic_write_private(
                self.path, _json_bytes(state, maximum=MAX_TRUST_STORE_BYTES) + b"\n"
            )
        finally:
            self._cache_token = None
            self._cache_state = None

    def add(self, descriptor: Mapping[str, Any], label: str = "") -> str:
        public = _descriptor(descriptor)
        label = self._label(label)
        _, public_type, _, _, unsupported = _crypto()
        try:
            public_type.from_public_bytes(_unbase64(public["public_key"], 32, "invalid_public_key"))
        except (ValueError, unsupported):
            raise TrustError("invalid_public_key") from None
        key_id = public["key_id"]
        with _exclusive_store(self.path):
            state = copy.deepcopy(self._read())
            previous = state["keys"].get(key_id)
            if previous is not None:
                if previous["state"] == "revoked":
                    raise TrustError("key_revoked")
                if previous["descriptor"] != public:
                    raise TrustError("key_id_conflict")
                if previous["label"] == label:
                    return key_id
                previous["label"] = label
            else:
                if len(state["keys"]) >= MAX_TRUSTED_KEYS:
                    raise TrustError("trust_store_full")
                state["keys"][key_id] = {
                    "descriptor": public,
                    "label": label,
                    "state": "trusted",
                    "added_at": _now(),
                    "revoked_at": None,
                }
            self._write(state)
        return key_id

    def revoke(self, key_id: str) -> None:
        key_id = _key_id(key_id)
        with _exclusive_store(self.path):
            state = copy.deepcopy(self._read())
            previous = state["keys"].get(key_id)
            if previous is None:
                raise TrustError("unknown_key")
            if previous["state"] == "revoked":
                return
            previous["state"] = "revoked"
            previous["revoked_at"] = _now()
            self._write(state)

    def require_trusted(self, key_id: str) -> dict[str, str]:
        entry = self._read()["keys"].get(_key_id(key_id))
        if entry is None:
            raise TrustError("unknown_key")
        if entry["state"] != "trusted":
            raise TrustError("key_revoked")
        return dict(entry["descriptor"])

    def _verify(self, body: dict[str, str], signature: bytes, domain: bytes) -> str:
        descriptor = self.require_trusted(body["key_id"])
        _, public_type, _, invalid_signature, unsupported = _crypto()
        try:
            public_type.from_public_bytes(
                _unbase64(descriptor["public_key"], 32, "invalid_public_key")
            ).verify(signature, domain + _json_bytes(body, maximum=MAX_PROOF_BYTES))
        except invalid_signature:
            raise TrustError("signature_invalid") from None
        except (ValueError, unsupported):
            raise TrustError("ed25519_unavailable") from None
        return descriptor["key_id"]

    def verify_record(self, record: Mapping[str, Any], attestation: Mapping[str, Any]) -> str:
        body, signature = _proof(
            attestation,
            schema=ATTESTATION_SCHEMA,
            digest_field="record_sha256",
            expected_digest=_record_digest(record),
        )
        return self._verify(body, signature, _RECORD_DOMAIN)

    def verify_message(self, payload: Mapping[str, Any], proof: Mapping[str, Any]) -> str:
        body, signature = _proof(
            proof,
            schema=MESSAGE_SIGNATURE_SCHEMA,
            digest_field="payload_sha256",
            expected_digest=_message_digest(payload),
        )
        return self._verify(body, signature, _MESSAGE_DOMAIN)

    def status(self) -> dict[str, Any]:
        state = self._read()
        trusted = sum(entry["state"] == "trusted" for entry in state["keys"].values())
        return {
            "schema_version": TRUST_STORE_SCHEMA,
            "revision": state["revision"],
            "total_keys": len(state["keys"]),
            "trusted_keys": trusted,
            "revoked_keys": len(state["keys"]) - trusted,
            "algorithm": ALGORITHM,
            "automatic_enrollment": False,
            "execution_authority": False,
        }


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise TrustError("invalid_arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("identity-create", "identity-public"):
        command = commands.add_parser(name, add_help=False)
        command.add_argument("--identity", type=Path, required=True)
    command = commands.add_parser("trust-add", add_help=False)
    command.add_argument("--trust-store", type=Path, required=True)
    command.add_argument("--public-key-file", type=Path, required=True)
    command.add_argument("--label", default="")
    command = commands.add_parser("trust-revoke", add_help=False)
    command.add_argument("--trust-store", type=Path, required=True)
    command.add_argument("--key-id", required=True)
    command = commands.add_parser("trust-status", add_help=False)
    command.add_argument("--trust-store", type=Path, required=True)
    return parser


def _read_public_descriptor(path: Path) -> dict[str, str]:
    # Public descriptors need not be secret, but use the same safe parent and
    # no-symlink rules. No other files in this directory are searched or read.
    path = _absolute_path(path)
    if not _safe_parent(path, create=False):
        raise TrustError("public_key_file_not_found")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise TrustError("unsafe_public_key_file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            after = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(after.st_mode)
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or after.st_size > MAX_PUBLIC_KEY_BYTES
                or after.st_uid != os.getuid()
                or stat.S_IMODE(after.st_mode) & 0o022
            ):
                raise TrustError("unsafe_public_key_file")
            data = stream.read(MAX_PUBLIC_KEY_BYTES + 1)
    except FileNotFoundError:
        raise TrustError("public_key_file_not_found") from None
    except OSError:
        raise TrustError("storage_unavailable") from None
    if len(data) > MAX_PUBLIC_KEY_BYTES:
        raise TrustError("public_key_file_too_large")
    return _descriptor(_json_loads(data))


def _emit(value: Any) -> None:
    try:
        sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
        sys.stdout.flush()
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        if arguments in (["--help"], ["-h"]):
            _emit({
                "schema_version": TRUST_RESULT_SCHEMA,
                "ok": True,
                "commands": {
                    "identity-create": ["--identity ABSOLUTE_PATH"],
                    "identity-public": ["--identity ABSOLUTE_PATH"],
                    "trust-add": ["--trust-store ABSOLUTE_PATH", "--public-key-file ABSOLUTE_PATH", "--label LABEL (optional)"],
                    "trust-revoke": ["--trust-store ABSOLUTE_PATH", "--key-id KEY_ID"],
                    "trust-status": ["--trust-store ABSOLUTE_PATH"],
                },
                "automatic_enrollment": False,
            })
            return 0
        args = _parser().parse_args(arguments)
        if args.command == "identity-create":
            result = Identity.generate(args.identity).public_descriptor()
        elif args.command == "identity-public":
            result = Identity.load(args.identity).public_descriptor()
        elif args.command == "trust-add":
            key_id = TrustStore(args.trust_store).add(
                _read_public_descriptor(args.public_key_file), args.label
            )
            result = {"schema_version": TRUST_RESULT_SCHEMA, "ok": True, "key_id": key_id, "state": "trusted"}
        elif args.command == "trust-revoke":
            TrustStore(args.trust_store).revoke(args.key_id)
            result = {"schema_version": TRUST_RESULT_SCHEMA, "ok": True, "key_id": args.key_id, "state": "revoked"}
        else:
            result = {"schema_version": TRUST_RESULT_SCHEMA, "ok": True, "status": TrustStore(args.trust_store).status()}
        _emit(result)
        return 0
    except TrustError as exc:
        error: dict[str, Any] = {"code": exc.code}
        if exc.code == "cryptography_unavailable":
            error["hint"] = "Install the optional requirements-integrations.txt in your selected Python environment."
        elif exc.code == "protected_storage_unavailable":
            error["hint"] = "Protected identities currently require POSIX storage; the lightweight memory core remains platform independent."
        _emit({"schema_version": TRUST_RESULT_SCHEMA, "ok": False, "error": error})
        return 2
    except KeyboardInterrupt:
        _emit({"schema_version": TRUST_RESULT_SCHEMA, "ok": False, "error": {"code": "interrupted"}})
        return 130
    except Exception:
        # Never echo an exception carrying a selected path, record, or key.
        _emit({"schema_version": TRUST_RESULT_SCHEMA, "ok": False, "error": {"code": "operation_failed"}})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
