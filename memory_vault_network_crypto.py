"""Optional interoperable E2EE carrier; canonical memory bytes stay unchanged.

Dependencies load only during explicit crypto operations. No network, key
discovery, enrollment or process launch occurs here. Signing and encryption
keys are independent. Public routing metadata is not confidential.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path
import re
import time
from typing import Any, Mapping, Sequence

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_trust import Identity, TrustStore, TrustError, _absolute_path, _descriptor, _read_private, _write_new_private

KEY_SCHEMA = "memory-vault-network-encryption-key/v1"
PRIVATE_KEY_SCHEMA = "memory-vault-network-encryption-identity/v1"
ENVELOPE_SCHEMA = "memory-vault-network-envelope/v1"
BYTES_SCHEMA = "memory-vault-network-bytes/v1"
MAGIC = (BYTES_SCHEMA + "\n").encode("ascii")
MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_BYTES = 6 * 1024 * 1024
MAX_RECIPIENTS = 32
ALG = "ECDH-ES+A256KW"
ENC = "A256GCM"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_HASH = re.compile(r"[0-9a-f]{64}")
_B64 = re.compile(r"[A-Za-z0-9_-]*")


class NetworkCryptoError(MemoryError):
    pass


def object_fields(value: Any, names: set[str], code: str = "network_invalid_document") -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise NetworkCryptoError(code)
    return dict(value)


def opaque(value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise NetworkCryptoError("network_invalid_identifier")
    return value


def digest(value: Any) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise NetworkCryptoError("network_invalid_digest")
    return value


def integer(value: Any, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 9_007_199_254_740_991:
        raise NetworkCryptoError("network_invalid_integer")
    return value


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64url(value: Any, *, maximum: int, size: int | None = None) -> bytes:
    if (not isinstance(value, str) or len(value) > (maximum * 4 + 2) // 3
            or _B64.fullmatch(value) is None):
        raise NetworkCryptoError("network_invalid_base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        raise NetworkCryptoError("network_invalid_base64url") from None
    if len(raw) > maximum or (size is not None and len(raw) != size) or b64url(raw) != value:
        raise NetworkCryptoError("network_invalid_base64url")
    return raw


def _portable(value: Any, depth: int = 0) -> None:
    # Network/control objects deliberately exclude floats. Inner memory bytes
    # remain opaque and retain the existing canonical profile unchanged.
    if depth > 24:
        raise NetworkCryptoError("network_json_depth")
    if value is None or type(value) is bool or isinstance(value, str):
        return
    if type(value) is int:
        if not -9_007_199_254_740_991 <= value <= 9_007_199_254_740_991:
            raise NetworkCryptoError("network_invalid_integer")
        return
    if isinstance(value, list):
        for item in value:
            _portable(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) and key.isascii() for key in value):
        for item in value.values():
            _portable(item, depth + 1)
        return
    raise NetworkCryptoError("network_nonportable_json")


def document(value: Mapping[str, Any] | bytes, *, maximum: int = MAX_ENVELOPE_BYTES) -> dict[str, Any]:
    if isinstance(value, bytes):
        if len(value) > maximum:
            raise NetworkCryptoError("network_document_too_large")
        value = strict_json_loads(value)
    if not isinstance(value, Mapping):
        raise NetworkCryptoError("network_invalid_document")
    result = dict(value)
    _portable(result)
    if len(canonical_bytes(result)) > maximum:
        raise NetworkCryptoError("network_document_too_large")
    return result


def document_sha256(value: Mapping[str, Any] | bytes) -> str:
    return hashlib.sha256(canonical_bytes(document(value))).hexdigest()


def public_signing_key(value: Mapping[str, Any]) -> dict[str, str]:
    try:
        return _descriptor(value)
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None


class PublicKeyTrust(TrustStore):
    """An explicit immutable key set supplied by trusted configuration/control.

    This does not enroll incoming memory keys or write a trust registry. A
    caller must authenticate any control document before constructing this.
    """
    def __init__(self, descriptors: Sequence[Mapping[str, Any]]):
        checked = [public_signing_key(value) for value in descriptors]
        self._keys = {value["key_id"]: value for value in checked}
        if len(self._keys) != len(checked):
            raise NetworkCryptoError("network_duplicate_signer")

    def require_trusted(self, key_id: str) -> dict[str, str]:
        if key_id not in self._keys:
            raise TrustError("unknown_key")
        return dict(self._keys[key_id])


def encryption_public_descriptor(value: Mapping[str, Any]) -> dict[str, str]:
    raw = object_fields(value, {"schema_version", "algorithm", "key_id", "public_key"})
    if raw["schema_version"] != KEY_SCHEMA or raw["algorithm"] != "X25519":
        raise NetworkCryptoError("network_unsupported_encryption_key")
    public = unb64url(raw["public_key"], maximum=32, size=32)
    if raw["key_id"] != "x25519_" + hashlib.sha256(public).hexdigest():
        raise NetworkCryptoError("network_encryption_key_mismatch")
    return raw


def _providers() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from joserfc import jwe
        from joserfc.jwk import OKPKey
    except ImportError:
        raise NetworkCryptoError("network_crypto_dependency_unavailable") from None
    return X25519PrivateKey, serialization, jwe, OKPKey


class EncryptionIdentity:
    """Explicit X25519 key, separate from the existing Ed25519 identity."""
    def __init__(self, private_key: Any):
        self._private_key = private_key
        _, serialization, _, _ = _providers()
        public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._public = {"schema_version": KEY_SCHEMA, "algorithm": "X25519",
                        "key_id": "x25519_" + hashlib.sha256(public).hexdigest(), "public_key": b64url(public)}

    @classmethod
    def generate(cls) -> EncryptionIdentity:
        private_type, _, _, _ = _providers()
        return cls(private_type.generate())

    @classmethod
    def from_private_document(cls, value: Mapping[str, Any]) -> EncryptionIdentity:
        raw = object_fields(value, {"schema_version", "algorithm", "key_id", "public_key", "private_key"})
        if raw["schema_version"] != PRIVATE_KEY_SCHEMA:
            raise NetworkCryptoError("network_unsupported_private_key")
        public = encryption_public_descriptor({key: raw[key] for key in ("algorithm", "key_id", "public_key")} | {"schema_version": KEY_SCHEMA})
        private_type, _, _, _ = _providers()
        result = cls(private_type.from_private_bytes(unb64url(raw["private_key"], maximum=32, size=32)))
        if result.public_descriptor() != public:
            raise NetworkCryptoError("network_private_key_mismatch")
        return result

    @classmethod
    def load(cls, path: Path) -> EncryptionIdentity:
        raw = _read_private(_absolute_path(path), 4096)
        if raw is None:
            raise NetworkCryptoError("network_encryption_identity_missing")
        return cls.from_private_document(document(raw, maximum=4096))

    def save(self, path: Path) -> None:
        _write_new_private(_absolute_path(path), canonical_bytes(self.private_document()) + b"\n")

    @property
    def key_id(self) -> str:
        return self._public["key_id"]

    def public_descriptor(self) -> dict[str, str]:
        return dict(self._public)

    def private_document(self) -> dict[str, str]:
        """Explicit recovery/provisioning export; never a normal response."""
        _, serialization, _, _ = _providers()
        secret = self._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return {**self._public, "schema_version": PRIVATE_KEY_SCHEMA, "private_key": b64url(secret)}

    def _jwk(self) -> dict[str, str]:
        value = self.private_document()
        return {"kty": "OKP", "crv": "X25519", "x": value["public_key"], "d": value["private_key"], "kid": self.key_id}


def _context(value: Mapping[str, Any]) -> bytes:
    return canonical_bytes(document(value, maximum=16 * 1024))


def _registry(jwe: Any) -> Any:
    result = jwe.JWERegistry(algorithms=[ALG, ENC], verify_all_recipients=False, max_recipients=MAX_RECIPIENTS)
    result.max_ciphertext_length = MAX_ENVELOPE_BYTES
    return result


def validate_jwe(value: Mapping[str, Any] | bytes, *, context: Mapping[str, Any]) -> dict[str, Any]:
    raw = object_fields(document(value), {"protected", "recipients", "aad", "iv", "ciphertext", "tag"})
    protected = document(unb64url(raw["protected"], maximum=1024), maximum=1024)
    if protected != {"enc": ENC, "typ": BYTES_SCHEMA}:
        raise NetworkCryptoError("network_jwe_profile_mismatch")
    if unb64url(raw["aad"], maximum=16 * 1024) != _context(context):
        raise NetworkCryptoError("network_context_mismatch")
    unb64url(raw["iv"], maximum=12, size=12)
    unb64url(raw["tag"], maximum=16, size=16)
    encrypted = unb64url(raw["ciphertext"], maximum=MAX_PLAINTEXT_BYTES + len(MAGIC) + 40)
    if len(encrypted) < len(MAGIC) + 40:
        raise NetworkCryptoError("network_ciphertext_truncated")
    recipients = raw["recipients"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise NetworkCryptoError("network_recipient_limit")
    seen = set()
    for item in recipients:
        entry = object_fields(item, {"header", "encrypted_key"})
        header = object_fields(entry["header"], {"alg", "kid", "epk"})
        if header["alg"] != ALG or not isinstance(header["kid"], str) or not re.fullmatch(r"x25519_[0-9a-f]{64}", header["kid"]):
            raise NetworkCryptoError("network_jwe_algorithm_rejected")
        if header["kid"] in seen:
            raise NetworkCryptoError("network_duplicate_recipient")
        seen.add(header["kid"])
        ephemeral = object_fields(header["epk"], {"kty", "crv", "x"})
        if ephemeral["kty"] != "OKP" or ephemeral["crv"] != "X25519":
            raise NetworkCryptoError("network_ephemeral_key_rejected")
        unb64url(ephemeral["x"], maximum=32, size=32)
        unb64url(entry["encrypted_key"], maximum=40, size=40)
    return raw


def encrypt_bytes(plaintext: bytes, recipients: Sequence[Mapping[str, Any]], *, context: Mapping[str, Any]) -> dict[str, Any]:
    """JWE General JSON; exact raw bytes/hash are inside authenticated ciphertext."""
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise NetworkCryptoError("network_plaintext_limit")
    if not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise NetworkCryptoError("network_recipient_limit")
    keys = [encryption_public_descriptor(value) for value in recipients]
    if len({key["key_id"] for key in keys}) != len(keys):
        raise NetworkCryptoError("network_duplicate_recipient")
    frame = MAGIC + len(plaintext).to_bytes(8, "big") + hashlib.sha256(plaintext).digest() + plaintext
    _, _, jwe, okp = _providers()
    try:
        obj = jwe.GeneralJSONEncryption({"enc": ENC, "typ": BYTES_SCHEMA}, frame, aad=_context(context))
        for key in sorted(keys, key=lambda entry: entry["key_id"]):
            imported = okp.import_key({"kty": "OKP", "crv": "X25519", "x": key["public_key"], "kid": key["key_id"]})
            obj.add_recipient({"alg": ALG, "kid": key["key_id"]}, imported)
        result = jwe.encrypt_json(obj, None, registry=_registry(jwe))
    except MemoryError:
        raise
    except Exception:
        raise NetworkCryptoError("network_encryption_failed") from None
    return validate_jwe(result, context=context)


def decrypt_bytes(value: Mapping[str, Any] | bytes, identity: EncryptionIdentity, *, context: Mapping[str, Any]) -> bytes:
    raw = validate_jwe(value, context=context)
    if identity.key_id not in {item["header"]["kid"] for item in raw["recipients"]}:
        raise NetworkCryptoError("network_not_a_recipient")
    _, _, jwe, okp = _providers()
    try:
        key = okp.import_key(identity._jwk())
        result = jwe.decrypt_json(raw, key, registry=_registry(jwe))
        frame = result.plaintext
    except Exception:
        raise NetworkCryptoError("network_decryption_failed") from None
    if not isinstance(frame, bytes) or not frame.startswith(MAGIC) or len(frame) < len(MAGIC) + 40:
        raise NetworkCryptoError("network_plaintext_frame_invalid")
    size = int.from_bytes(frame[len(MAGIC):len(MAGIC) + 8], "big")
    expected = frame[len(MAGIC) + 8:len(MAGIC) + 40]
    plaintext = frame[len(MAGIC) + 40:]
    if size != len(plaintext) or size > MAX_PLAINTEXT_BYTES or not hmac.compare_digest(expected, hashlib.sha256(plaintext).digest()):
        raise NetworkCryptoError("network_plaintext_integrity_failed")
    return plaintext


def _routing(raw: Mapping[str, Any]) -> dict[str, Any]:
    names = {"schema_version", "network_id", "message_id", "sender_key_id", "recipient_key_ids", "roster_version", "roster_sha256", "created_at"}
    result = {name: raw[name] for name in names}
    if result["schema_version"] != ENVELOPE_SCHEMA:
        raise NetworkCryptoError("network_envelope_schema_mismatch")
    opaque(result["network_id"])
    opaque(result["message_id"])
    if not isinstance(result["sender_key_id"], str) or not re.fullmatch(r"ed25519_[0-9a-f]{64}", result["sender_key_id"]):
        raise NetworkCryptoError("network_invalid_sender")
    recipients = result["recipient_key_ids"]
    if (not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS
            or any(not isinstance(key, str) or not re.fullmatch(r"ed25519_[0-9a-f]{64}", key) for key in recipients)
            or recipients != sorted(set(recipients))):
        raise NetworkCryptoError("network_invalid_recipients")
    integer(result["roster_version"], minimum=1)
    digest(result["roster_sha256"])
    integer(result["created_at"])
    return result


def seal(plaintext: bytes, *, signer: Identity, network_id: str, message_id: str,
         recipients: Sequence[Mapping[str, Any]], roster_version: int, roster_sha256: str,
         created_at: int | None = None) -> dict[str, Any]:
    checked = [object_fields(item, {"signing_key_id", "encryption_key"}) for item in recipients]
    route = _routing({"schema_version": ENVELOPE_SCHEMA, "network_id": network_id, "message_id": message_id,
                      "sender_key_id": signer.key_id, "recipient_key_ids": sorted(item["signing_key_id"] for item in checked),
                      "roster_version": roster_version, "roster_sha256": roster_sha256,
                      "created_at": int(time.time()) if created_at is None else created_at})
    payload = {**route, "jwe": encrypt_bytes(plaintext, [item["encryption_key"] for item in checked], context=route)}
    return document({**payload, "proof": signer.sign_message(payload)})


def verify_envelope(value: Mapping[str, Any] | bytes, trust: TrustStore, *, network_id: str) -> dict[str, Any]:
    raw = object_fields(document(value), {"schema_version", "network_id", "message_id", "sender_key_id", "recipient_key_ids",
                                          "roster_version", "roster_sha256", "created_at", "jwe", "proof"})
    route = _routing(raw)
    if route["network_id"] != network_id:
        raise NetworkCryptoError("network_wrong_network")
    validate_jwe(raw["jwe"], context=route)
    if len(raw["jwe"]["recipients"]) != len(route["recipient_key_ids"]):
        raise NetworkCryptoError("network_recipient_binding_mismatch")
    payload = {key: val for key, val in raw.items() if key != "proof"}
    try:
        signer = trust.verify_message(payload, raw["proof"])
    except TrustError as exc:
        raise NetworkCryptoError(exc.code) from None
    if signer != route["sender_key_id"]:
        raise NetworkCryptoError("network_sender_signature_mismatch")
    return payload


def open_envelope(value: Mapping[str, Any] | bytes, identity: EncryptionIdentity, trust: TrustStore, *, network_id: str) -> bytes:
    payload = verify_envelope(value, trust, network_id=network_id)
    return decrypt_bytes(payload["jwe"], identity, context=_routing(payload))


def envelope_sha256(value: Mapping[str, Any] | bytes) -> str:
    return document_sha256(value)
