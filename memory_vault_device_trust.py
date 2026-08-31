"""Taskless device trust state machine for encrypted replication.

This module records *which opaque device key may publish future ciphertext*;
it does not create keys, sign checkpoints, or encrypt recovery material.  The
authority and recovery-provider protocols are deliberately external so a
deployment must select audited key storage, signature verification, and a
real recovery ceremony before it can claim production device trust.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
import re
from typing import Any, Mapping, Protocol, Sequence

from memory_vault_metadata import jcs_json_bytes, sha256_bytes


TRUST_SCHEMA = "memory-device-trust/v1"
TRANSITION_SCHEMA = "memory-device-trust-transition/v1"
RECOVERY_DESCRIPTOR_SCHEMA = "memory-device-recovery-descriptor/v1"
MAX_PROOF_BYTES = 64 * 1024
MAX_DEVICES = 1024
MAX_STATE_BYTES = 1024 * 1024
_OPAQUE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_TOKENS = (
    "task",
    "conversation",
    "owner",
    "local_path",
    "workspace",
    "current",
)


# Retained from the public v0.21 provider contract (Apache-2.0), independent
# of Task, Git, the record store, a host plugin, or a configured key ceremony.
class DeviceTrustError(ValueError):
    """A trust state, transition, or recovery descriptor is invalid."""


class TrustUnavailable(DeviceTrustError):
    """No external authority is configured to approve a transition."""


@dataclasses.dataclass(frozen=True)
class AuthorityInfo:
    profile: str
    version: str
    identity: str


class TrustAuthority(Protocol):
    info: AuthorityInfo

    def verify_transition(
        self,
        transition: Mapping[str, Any],
        proof: bytes,
    ) -> None:
        """Verify a transition using an external signature/key ceremony."""


class UnconfiguredTrustAuthority:
    """Production default: trust changes fail closed until configured."""

    info = AuthorityInfo(
        profile="unconfigured-device-authority-v1",
        version="0",
        identity="unconfigured",
    )

    def verify_transition(
        self,
        transition: Mapping[str, Any],
        proof: bytes,
    ) -> None:
        raise TrustUnavailable(
            "no external device-trust authority is configured"
        )


@dataclasses.dataclass(frozen=True)
class DeviceEntry:
    device_fingerprint: str
    public_key_fingerprint: str
    status: str
    key_epoch: int
    enrolled_generation: int
    revoked_generation: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_fingerprint": self.device_fingerprint,
            "enrolled_generation": self.enrolled_generation,
            "key_epoch": self.key_epoch,
            "public_key_fingerprint": self.public_key_fingerprint,
            "revoked_generation": self.revoked_generation,
            "status": self.status,
        }


@dataclasses.dataclass(frozen=True)
class TrustState:
    installation_fingerprint: str
    generation: int
    key_epoch: int
    recovery_threshold: int
    recovery_epoch: int
    devices: tuple[DeviceEntry, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "devices": [item.as_dict() for item in self.devices],
            "generation": self.generation,
            "installation_fingerprint": self.installation_fingerprint,
            "key_epoch": self.key_epoch,
            "recovery_epoch": self.recovery_epoch,
            "recovery_threshold": self.recovery_threshold,
            "schema_version": TRUST_SCHEMA,
        }

    @property
    def sha256(self) -> str:
        return sha256_bytes(jcs_json_bytes(self.as_dict()))

    def device(self, fingerprint: str) -> DeviceEntry:
        for item in self.devices:
            if item.device_fingerprint == fingerprint:
                return item
        raise DeviceTrustError("device is not enrolled")

    @classmethod
    def from_value(cls, value: Any) -> "TrustState":
        if not isinstance(value, Mapping) or set(value) != {
            "schema_version",
            "installation_fingerprint",
            "generation",
            "key_epoch",
            "recovery_threshold",
            "recovery_epoch",
            "devices",
        }:
            raise DeviceTrustError("device trust state fields are invalid")
        if value.get("schema_version") != TRUST_SCHEMA:
            raise DeviceTrustError("device trust state schema is invalid")
        installation = _opaque(value.get("installation_fingerprint"), "installation fingerprint")
        generation = _counter(value.get("generation"), "generation")
        key_epoch = _positive_counter(value.get("key_epoch"), "key epoch")
        threshold = _positive_counter(value.get("recovery_threshold"), "recovery threshold")
        recovery_epoch = _counter(value.get("recovery_epoch"), "recovery epoch")
        raw_devices = value.get("devices")
        if not isinstance(raw_devices, list) or not raw_devices or len(raw_devices) > MAX_DEVICES:
            raise DeviceTrustError("device trust device list is invalid")
        devices: list[DeviceEntry] = []
        previous: str | None = None
        for raw in raw_devices:
            if not isinstance(raw, Mapping) or set(raw) != {
                "device_fingerprint",
                "public_key_fingerprint",
                "status",
                "key_epoch",
                "enrolled_generation",
                "revoked_generation",
            }:
                raise DeviceTrustError("device trust entry fields are invalid")
            fingerprint = _opaque(raw.get("device_fingerprint"), "device fingerprint")
            if previous is not None and fingerprint <= previous:
                raise DeviceTrustError("device trust entries are not sorted")
            previous = fingerprint
            public_key = _opaque(raw.get("public_key_fingerprint"), "public key fingerprint")
            status = raw.get("status")
            if status not in {"active", "revoked"}:
                raise DeviceTrustError("device trust status is invalid")
            entry_epoch = _positive_counter(raw.get("key_epoch"), "device key epoch")
            enrolled = _counter(raw.get("enrolled_generation"), "enrolled generation")
            revoked = raw.get("revoked_generation")
            if revoked is not None:
                revoked = _counter(revoked, "revoked generation")
            if enrolled > generation or entry_epoch > key_epoch:
                raise DeviceTrustError("device trust entry is from the future")
            if status == "active" and (revoked is not None or entry_epoch != key_epoch):
                raise DeviceTrustError("active device must use the current epoch without revocation")
            if status == "revoked" and revoked is None:
                raise DeviceTrustError("revoked device has no revoked generation")
            if revoked is not None and (revoked <= enrolled or revoked > generation):
                raise DeviceTrustError("revoked generation is not monotonic")
            devices.append(DeviceEntry(fingerprint, public_key, status, entry_epoch, enrolled, revoked))
        if threshold > len(devices):
            raise DeviceTrustError("recovery threshold exceeds enrolled devices")
        return cls(installation, generation, key_epoch, threshold, recovery_epoch, tuple(devices))


def _opaque(value: Any, label: str) -> str:
    if not isinstance(value, str) or _OPAQUE.fullmatch(value) is None:
        raise DeviceTrustError(f"{label} is invalid")
    lowered = value.casefold()
    if any(token in lowered for token in _FORBIDDEN_TOKENS):
        raise DeviceTrustError(f"{label} cannot be a memory owner or task identity")
    return value


def _counter(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 9_007_199_254_740_991:
        raise DeviceTrustError(f"{label} is invalid")
    return value


def _positive_counter(value: Any, label: str) -> int:
    result = _counter(value, label)
    if result < 1:
        raise DeviceTrustError(f"{label} must be positive")
    return result


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise DeviceTrustError(f"{label} is invalid")
    return value


def new_trust_state(
    installation_fingerprint: str,
    device_fingerprint: str,
    public_key_fingerprint: str,
    *,
    key_epoch: int = 1,
    recovery_threshold: int = 1,
) -> TrustState:
    """Create a local bootstrap state; approving other devices remains external."""

    installation = _opaque(installation_fingerprint, "installation fingerprint")
    device = _opaque(device_fingerprint, "device fingerprint")
    public_key = _opaque(public_key_fingerprint, "public key fingerprint")
    epoch = _positive_counter(key_epoch, "key epoch")
    threshold = _positive_counter(recovery_threshold, "recovery threshold")
    if threshold != 1:
        raise DeviceTrustError("bootstrap recovery threshold must be one device")
    return TrustState(
        installation,
        generation=0,
        key_epoch=epoch,
        recovery_threshold=threshold,
        recovery_epoch=0,
        devices=(DeviceEntry(device, public_key, "active", epoch, 0),),
    )


def _authority_verify(authority: TrustAuthority, transition: Mapping[str, Any], proof: bytes) -> None:
    if not isinstance(proof, (bytes, bytearray)) or not proof or len(proof) > MAX_PROOF_BYTES:
        raise DeviceTrustError("trust transition proof is invalid")
    info = getattr(authority, "info", None)
    if not isinstance(info, AuthorityInfo):
        raise TrustUnavailable("external trust authority identity is invalid")
    _opaque(info.profile, "authority profile")
    _opaque(info.version, "authority version")
    _opaque(info.identity, "authority identity")
    authority.verify_transition(transition, bytes(proof))


def _base_transition(state: TrustState, operation: str) -> dict[str, Any]:
    return {
        "next_generation": _positive_counter(state.generation + 1, "next generation"),
        "operation": operation,
        "previous_state_sha256": state.sha256,
        "schema_version": TRANSITION_SCHEMA,
    }


def _apply_transition(
    state: TrustState,
    transition: Mapping[str, Any],
    proof: bytes,
    authority: TrustAuthority,
) -> TrustState:
    if not isinstance(transition, Mapping):
        raise DeviceTrustError("trust transition is not an object")
    operation = transition.get("operation")
    expected_fields = {
        "enroll": {"schema_version", "operation", "previous_state_sha256", "next_generation", "device_fingerprint", "public_key_fingerprint", "key_epoch"},
        "revoke": {"schema_version", "operation", "previous_state_sha256", "next_generation", "device_fingerprint"},
        "rotate": {"schema_version", "operation", "previous_state_sha256", "next_generation", "key_epoch"},
        "set_threshold": {"schema_version", "operation", "previous_state_sha256", "next_generation", "recovery_threshold"},
    }.get(operation)
    if expected_fields is None or set(transition) != expected_fields:
        raise DeviceTrustError("trust transition fields are invalid")
    if transition.get("schema_version") != TRANSITION_SCHEMA:
        raise DeviceTrustError("trust transition schema is invalid")
    if transition.get("previous_state_sha256") != state.sha256:
        raise DeviceTrustError("trust transition does not extend the current state")
    if _positive_counter(transition.get("next_generation"), "next generation") != state.generation + 1:
        raise DeviceTrustError("trust transition generation is not monotonic")
    _authority_verify(authority, transition, proof)
    devices = {item.device_fingerprint: item for item in state.devices}
    if operation == "enroll":
        fingerprint = _opaque(transition.get("device_fingerprint"), "device fingerprint")
        public_key = _opaque(transition.get("public_key_fingerprint"), "public key fingerprint")
        epoch = _positive_counter(transition.get("key_epoch"), "device key epoch")
        if fingerprint in devices or epoch != state.key_epoch:
            raise DeviceTrustError("device enrollment is invalid")
        if len(devices) >= MAX_DEVICES:
            raise DeviceTrustError("device trust device limit exceeded")
        devices[fingerprint] = DeviceEntry(fingerprint, public_key, "active", epoch, state.generation + 1)
    elif operation == "revoke":
        fingerprint = _opaque(transition.get("device_fingerprint"), "device fingerprint")
        entry = devices.get(fingerprint)
        if entry is None or entry.status != "active":
            raise DeviceTrustError("only an active device can be revoked")
        devices[fingerprint] = dataclasses.replace(entry, status="revoked", revoked_generation=state.generation + 1)
    elif operation == "rotate":
        epoch = _positive_counter(transition.get("key_epoch"), "key epoch")
        if epoch != state.key_epoch + 1:
            raise DeviceTrustError("key rotation must advance exactly one epoch")
        devices = {
            fingerprint: dataclasses.replace(entry, key_epoch=epoch)
            if entry.status == "active" else entry
            for fingerprint, entry in devices.items()
        }
    else:
        threshold = _positive_counter(
            transition.get("recovery_threshold"),
            "recovery threshold",
        )
        if threshold > len(devices):
            raise DeviceTrustError("recovery threshold exceeds enrolled devices")
    return TrustState(
        state.installation_fingerprint,
        state.generation + 1,
        transition.get("key_epoch", state.key_epoch) if operation == "rotate" else state.key_epoch,
        transition.get("recovery_threshold", state.recovery_threshold)
        if operation == "set_threshold"
        else state.recovery_threshold,
        state.recovery_epoch,
        tuple(sorted(devices.values(), key=lambda item: item.device_fingerprint)),
    )


def enroll_device(state: TrustState, device_fingerprint: str, public_key_fingerprint: str, *, proof: bytes, authority: TrustAuthority) -> TrustState:
    transition = _base_transition(state, "enroll")
    transition.update({
        "device_fingerprint": _opaque(device_fingerprint, "device fingerprint"),
        "public_key_fingerprint": _opaque(public_key_fingerprint, "public key fingerprint"),
        "key_epoch": state.key_epoch,
    })
    return _apply_transition(state, transition, proof, authority)


def revoke_device(state: TrustState, device_fingerprint: str, *, proof: bytes, authority: TrustAuthority) -> TrustState:
    transition = _base_transition(state, "revoke")
    transition["device_fingerprint"] = _opaque(device_fingerprint, "device fingerprint")
    return _apply_transition(state, transition, proof, authority)


def rotate_key_epoch(state: TrustState, *, proof: bytes, authority: TrustAuthority) -> TrustState:
    transition = _base_transition(state, "rotate")
    transition["key_epoch"] = state.key_epoch + 1
    return _apply_transition(state, transition, proof, authority)


def set_recovery_threshold(
    state: TrustState,
    recovery_threshold: int,
    *,
    proof: bytes,
    authority: TrustAuthority,
) -> TrustState:
    """Change the recovery quorum only after an external approval."""

    threshold = _positive_counter(recovery_threshold, "recovery threshold")
    if threshold > len(state.devices):
        raise DeviceTrustError("recovery threshold exceeds enrolled devices")
    transition = _base_transition(state, "set_threshold")
    transition["recovery_threshold"] = threshold
    return _apply_transition(state, transition, proof, authority)


def assert_can_publish(state: TrustState, device_fingerprint: str, *, key_epoch: int) -> None:
    """Allow only active enrolled devices to publish current-epoch ciphertext."""

    device = state.device(_opaque(device_fingerprint, "device fingerprint"))
    if device.status != "active":
        raise DeviceTrustError("revoked device cannot publish future ciphertext")
    if _positive_counter(key_epoch, "key epoch") != state.key_epoch or device.key_epoch != state.key_epoch:
        raise DeviceTrustError("publisher must use the current key epoch")


def assert_catalog_generation(state: TrustState, *, generation: int, previous_state_sha256: str) -> None:
    """Reject replayed/rolled-back trust catalog metadata before payload use."""

    if _counter(generation, "catalog generation") < state.generation:
        raise DeviceTrustError("replication catalog is a rollback or replay")
    _hash(previous_state_sha256, "previous trust state hash")
    if generation == state.generation and previous_state_sha256 != state.sha256:
        raise DeviceTrustError("replication catalog trust state does not match")


def recovery_descriptor(
    state: TrustState,
    *,
    encrypted_package_sha256: str,
    encrypted_package_bytes: int,
    authority: TrustAuthority,
    proof: bytes,
) -> dict[str, Any]:
    """Describe an encrypted recovery package without accepting plaintext keys."""

    package_hash = _hash(encrypted_package_sha256, "encrypted recovery package hash")
    if isinstance(encrypted_package_bytes, bool) or not isinstance(encrypted_package_bytes, int) or not 1 <= encrypted_package_bytes <= 2 * 1024 * 1024 * 1024:
        raise DeviceTrustError("encrypted recovery package size is invalid")
    descriptor: dict[str, Any] = {
        "encrypted_package_bytes": encrypted_package_bytes,
        "encrypted_package_sha256": package_hash,
        "recovery_epoch": _positive_counter(state.recovery_epoch + 1, "recovery epoch"),
        "required_devices": state.recovery_threshold,
        "schema_version": RECOVERY_DESCRIPTOR_SCHEMA,
        "trust_state_sha256": state.sha256,
    }
    _authority_verify(authority, descriptor, proof)
    return descriptor


def validate_recovery_descriptor(value: Any, state: TrustState) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "encrypted_package_sha256",
        "encrypted_package_bytes",
        "recovery_epoch",
        "required_devices",
        "trust_state_sha256",
    }:
        raise DeviceTrustError("recovery descriptor fields are invalid")
    if value.get("schema_version") != RECOVERY_DESCRIPTOR_SCHEMA:
        raise DeviceTrustError("recovery descriptor schema is invalid")
    descriptor = dict(value)
    _hash(descriptor["encrypted_package_sha256"], "encrypted recovery package hash")
    _hash(descriptor["trust_state_sha256"], "trust state hash")
    if descriptor["trust_state_sha256"] != state.sha256:
        raise DeviceTrustError("recovery descriptor is for another trust state")
    if _positive_counter(descriptor["recovery_epoch"], "recovery epoch") != state.recovery_epoch + 1:
        raise DeviceTrustError("recovery descriptor epoch is not next")
    if _positive_counter(descriptor["required_devices"], "required devices") != state.recovery_threshold:
        raise DeviceTrustError("recovery descriptor threshold is invalid")
    if isinstance(descriptor["encrypted_package_bytes"], bool) or not isinstance(descriptor["encrypted_package_bytes"], int) or not 1 <= descriptor["encrypted_package_bytes"] <= 2 * 1024 * 1024 * 1024:
        raise DeviceTrustError("encrypted recovery package size is invalid")
    return descriptor


def _state_summary(state: TrustState, path: Path, *, created: bool) -> dict[str, Any]:
    """Opaque transport metadata, never a proof of key possession or authority."""
    return {
        "schema_version": "memory-device-trust-status/v1",
        "state_path": str(path), "state_sha256": state.sha256,
        "installation_fingerprint": state.installation_fingerprint,
        "generation": state.generation, "key_epoch": state.key_epoch,
        "recovery_epoch": state.recovery_epoch,
        "recovery_threshold": state.recovery_threshold,
        "device_count": len(state.devices),
        "active_device_count": sum(item.status == "active" for item in state.devices),
        "revoked_device_count": sum(item.status == "revoked" for item in state.devices),
        "device_fingerprints": [item.device_fingerprint for item in state.devices],
        "created": created, "external_authority_configured": False,
        "private_keys_present": False, "key_possession_verified": False,
        "record_signing_registry_changed": False, "memory_changed": False,
        "network_accessed": False, "execution_authority_granted": False,
    }


def initialize_state(path: Path, *, installation_fingerprint: str,
                     device_fingerprint: str, public_key_fingerprint: str,
                     key_epoch: int = 1) -> Mapping[str, Any]:
    """Explicitly bootstrap one NEW private transport-metadata file.

    This restores v0.21's operator initialization without a plugin-owned data
    root. It creates no key, enrolls no record signer and grants no host or
    device authority. Existing state is never overwritten, including on retry.
    """
    from memory_vault_storage import atomic_write, validate_path
    selected = validate_path(path)
    state = new_trust_state(installation_fingerprint, device_fingerprint,
                            public_key_fingerprint, key_epoch=key_epoch)
    encoded = jcs_json_bytes(state.as_dict()) + b"\n"
    if len(encoded) > MAX_STATE_BYTES:
        raise DeviceTrustError("device trust state exceeds the local byte bound")
    if os.path.lexists(selected):
        raise DeviceTrustError("device trust state already exists")
    atomic_write(selected, encoded, replace=False)
    return _state_summary(state, selected, created=True)


def status(path: Path) -> Mapping[str, Any]:
    """Validate one explicit private state file without creating anything."""
    from memory_vault import strict_json_loads
    from memory_vault_storage import check_private_directory, open_file, validate_path
    selected = validate_path(path)
    check_private_directory(selected.parent)
    descriptor = open_file(selected, os.O_RDONLY, private=True)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not 1 <= before.st_size <= MAX_STATE_BYTES:
            raise DeviceTrustError("device trust state exceeds the local byte bound")
        raw = stream.read(MAX_STATE_BYTES + 1)
        after, named = os.fstat(stream.fileno()), selected.lstat()
        def fingerprint(item: os.stat_result) -> tuple[int, int, int, int, int]:
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns

        # Native open_file already pins/checks the Windows path. CRT fstat
        # timestamps can differ from path stat, so compare its full fingerprint
        # with itself before/after, and the named file's identity and size only.
        named_matches = (fingerprint(after)[:3] == fingerprint(named)[:3] if os.name == "nt"
                         else fingerprint(after) == fingerprint(named))
        if (len(raw) != before.st_size or fingerprint(before) != fingerprint(after)
                or not named_matches):
            raise DeviceTrustError("device trust state changed while reading")
    state = TrustState.from_value(strict_json_loads(raw))
    return _state_summary(state, selected, created=False)


def main(argv: Sequence[str] | None = None) -> int:
    """Operator-only metadata commands; never infer a path from a Vault/config."""
    import argparse
    from memory_vault import MemoryError, failure, success, write_response
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    initialize = commands.add_parser("init", help="create new opaque device metadata; no key or permission creation")
    initialize.add_argument("--state", type=Path, required=True)
    initialize.add_argument("--installation-fingerprint", required=True)
    initialize.add_argument("--device-fingerprint", required=True)
    initialize.add_argument("--public-key-fingerprint", required=True)
    initialize.add_argument("--key-epoch", type=int, default=1)
    inspect = commands.add_parser("status", help="validate and summarize one explicit private state file")
    inspect.add_argument("--state", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = status(args.state) if args.action == "status" else initialize_state(
            args.state, installation_fingerprint=args.installation_fingerprint,
            device_fingerprint=args.device_fingerprint,
            public_key_fingerprint=args.public_key_fingerprint, key_epoch=args.key_epoch)
        write_response(success(result))
        return 0
    except DeviceTrustError:
        write_response(failure("invalid_device_trust_metadata"))
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except OSError:
        write_response(failure("device_trust_state_unavailable"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
