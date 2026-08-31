"""Explicit user-level setup for private network-v1; no hand-written JSON needed.

All setup paths are new-only. No daemon is started, no remote endpoint is
contacted, no existing memory is read, and candidate private keys never leave
their own identity command. Publish only public descriptors/invitation packages,
never the complete owner directory.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from typing import Any, Mapping, Sequence
from urllib.parse import quote

from memory_vault import MemoryError, canonical_bytes, success, failure, write_response
from memory_vault_client import ClientConfig, CONFIG_SCHEMA as CLIENT_SCHEMA
from memory_vault_storage import atomic_write, open_file, private_directory
from memory_vault_trust import Identity, TrustStore, TrustError, _absolute_path, _exclusive_store, _read_private, _safe_parent, _write_new_private
from memory_vault_update import read_file
from memory_vault_network_crypto import (
    EncryptionIdentity, NetworkCryptoError, PublicKeyTrust, document, document_sha256,
    object_fields, opaque, public_signing_key, verify_envelope,
)
from memory_vault_network_control import (
    export_recovery, generate_recovery_secret, import_recovery,
    issue_roster, issue_invite, verify_roster, member,
)

KEY_BACKUP_SCHEMA = "memory-vault-network-key-backup/v1"
KEY_SECRET_SCHEMA = "memory-vault-network-recovery-secret/v1"
RESTORED_STATE_SCHEMA = "memory-vault-network-restored-state/v1"


def _path(value: str | Path) -> Path:
    return _absolute_path(Path(value))


def _read(path: str | Path, *, private: bool = False, maximum: int = 1024 * 1024) -> dict[str, Any]:
    selected = _path(path)
    raw = _read_private(selected, maximum) if private else read_file(selected, maximum)
    if raw is None:
        raise NetworkCryptoError("network_admin_file_missing")
    return document(raw, maximum=maximum)


def _new(path: Path, value: Mapping[str, Any]) -> None:
    _write_new_private(_path(path), canonical_bytes(value) + b"\n")


def _new_directory(path: Path) -> Path:
    selected = _path(path)
    if os.path.lexists(selected):
        raise NetworkCryptoError("network_setup_directory_exists")
    if not _safe_parent(selected, create=False):
        raise NetworkCryptoError("network_setup_parent_missing")
    selected.mkdir(mode=0o700)
    private_directory(selected)
    return selected


def _identity(directory: Path, *, issuer_public: Mapping[str, Any] | None = None) -> dict[str, Any]:
    identity = Identity.generate(directory / "identity.json")
    trust = TrustStore(directory / "trust.json")
    trust.add(identity.public_descriptor())
    encryption = EncryptionIdentity.generate()
    encryption.save(directory / "encryption.json")
    public = {"signing_key": identity.public_descriptor(), "encryption_key": encryption.public_descriptor(),
              "status": "active", "scope": ["receive", "send"]}
    _new(directory / "member-public.json", public)
    _new(directory / "issuer-public.json", identity.public_descriptor() if issuer_public is None else issuer_public)
    _new(directory / "client.json", {"schema_version": CLIENT_SCHEMA, "vault_path": str(directory / "vault" / "memory.sqlite3"),
         "capture_visible_turns": False, "identity_path": str(directory / "identity.json"), "trust_path": str(directory / "trust.json")})
    return {"identity": identity, "encryption": encryption, "member": public}


def create_identity(directory: Path) -> Mapping[str, Any]:
    selected = _new_directory(directory)
    result = _identity(selected)
    return {"state": "identity_created", "member_key_id": result["identity"].key_id,
            "public_member_file": str(selected / "member-public.json"), "client_config": str(selected / "client.json"),
            "encryption_key": str(selected / "encryption.json"), "capture_visible_turns": False,
            "vault_created": False, "network_accessed": False, "services_started": False}


def configure_network(*, client_config: Path, encryption_key: Path, issuer_public: Path, network_id: str,
                      authority_url: str, relays: Sequence[str], output: Path) -> Mapping[str, Any]:
    from memory_vault_network import origin, CONFIG_SCHEMA
    client_path, encryption_path, out = _path(client_config), _path(encryption_key), _path(output)
    if os.path.lexists(out):
        raise NetworkCryptoError("network_config_exists")
    client = ClientConfig.load(client_path)
    if client.identity_path is None or client.trust_path is None:
        raise NetworkCryptoError("network_signing_identity_required")
    signer = Identity.load(client.identity_path)
    TrustStore(client.trust_path).require_trusted(signer.key_id)
    EncryptionIdentity.load(encryption_path)
    issuer = public_signing_key(_read(issuer_public, maximum=16 * 1024))
    if not 1 <= len(relays) <= 2:
        raise NetworkCryptoError("network_one_or_two_relays_required")
    destinations = [origin(value) for value in relays]
    if len(set(destinations)) != len(destinations):
        raise NetworkCryptoError("network_duplicate_relay")
    state = out.parent / (out.stem + "-state")
    paths = [out, client.path, client.identity_path, client.trust_path, encryption_path, client.vault_path]
    if len(set(paths)) != len(paths) or any(state == path or state in path.parents or path in state.parents for path in paths):
        raise NetworkCryptoError("network_configuration_path_conflict")
    _new(out, {"schema_version": CONFIG_SCHEMA, "network_id": opaque(network_id), "client_config_path": str(client_path),
              "state_directory": str(state), "encryption_key_path": str(encryption_path), "issuer_public_key": issuer,
              "relays": destinations, "authority_url": origin(authority_url)})
    return {"state": "network_configured", "config": str(out), "member_key_id": signer.key_id,
            "issuer_key_shared_with_endpoint": signer.key_id == issuer["key_id"],
            "network_accessed": False, "keys_enrolled": False, "services_started": False}


def initialize(directory: Path, *, network_id: str, relay_url: str = "http://127.0.0.1:8765",
               authority_url: str = "http://127.0.0.1:8767") -> Mapping[str, Any]:
    from memory_vault_network import origin
    network_id = opaque(network_id)
    relay_url, authority_url = origin(relay_url), origin(authority_url)
    selected = _new_directory(directory)
    # The ordinary endpoint must never hold its issuer's signing credential.
    # These separate files still need separate OS/storage access at deployment;
    # a single setup directory is not a process-isolation boundary.
    issuer = Identity.generate(selected / "authority-identity.json")
    issuer_trust = TrustStore(selected / "authority-trust.json")
    issuer_trust.add(issuer.public_descriptor())
    created = _identity(selected, issuer_public=issuer.public_descriptor())
    now = int(time.time())
    roster = issue_roster(issuer, network_id=network_id, version=1, previous_sha256="0" * 64,
                          members=[created["member"]], issued_at=now, expires_at=now + 300)
    _new(selected / "roster.json", roster)
    _new(selected / "authority.json", {"schema_version": "memory-vault-network-authority-config/v1", "network_id": network_id,
         "identity_path": str(selected / "authority-identity.json"), "trust_store_path": str(selected / "authority-trust.json"), "roster_path": str(selected / "roster.json")})
    # No content or issuer private key paths enter this configuration. Deploy
    # just this config and the public signed roster to a separate relay host;
    # same-OS-user processes are not a key isolation boundary.
    _new(selected / "relay.json", {"schema_version": "memory-vault-relay-config/v1", "network_id": network_id,
         "issuer_public_key": issuer.public_descriptor(), "roster_path": str(selected / "roster.json"),
         "state_directory": str(selected / "relay-state"), "base_url": relay_url, "authority_url": authority_url,
         "init_member_key_ids": [created["identity"].key_id], "require_join_key_ids": []})
    configure_network(client_config=selected / "client.json", encryption_key=selected / "encryption.json",
                      issuer_public=selected / "issuer-public.json", network_id=network_id, authority_url=authority_url,
                      relays=[relay_url], output=selected / "network.json")
    return {"state": "network_initialized", "network_id": network_id, "owner_key_id": created["identity"].key_id,
            "issuer_key_id": issuer.key_id, "issuer_key_shared_with_endpoint": False,
            "network_config": str(selected / "network.json"), "authority_config": str(selected / "authority.json"),
            "relay_config": str(selected / "relay.json"), "public_issuer_file": str(selected / "issuer-public.json"),
            "capture_visible_turns": False, "vault_created": False, "network_accessed": False,
            "services_started": False, "deployment_requires_separate_issuer_and_relay_key_storage": True}


def invite_candidate(*, authority_config: Path, candidate: Path, output: Path,
                     handoff_envelope: Path | None = None, scope: Sequence[str] = ("receive", "send"),
                     lifetime_seconds: int = 86400) -> Mapping[str, Any]:
    config = object_fields(_read(authority_config, private=True, maximum=16 * 1024),
                           {"schema_version", "network_id", "identity_path", "trust_store_path", "roster_path"})
    if config["schema_version"] != "memory-vault-network-authority-config/v1":
        raise NetworkCryptoError("network_authority_configuration_invalid")
    network_id = opaque(config["network_id"])
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 7 * 86400:
        raise NetworkCryptoError("network_invalid_invite_lifetime")
    out = _path(output)
    if os.path.lexists(out):
        raise NetworkCryptoError("network_invitation_output_exists")
    candidate_member = member(_read(candidate, maximum=16 * 1024))
    # Public candidate preference is not policy. This explicit command chooses
    # the allowed scope; the issuer's signature grants network membership only.
    candidate_member = member({**candidate_member, "status": "active", "scope": sorted(scope)})
    issuer = Identity.load(_path(config["identity_path"]))
    trusted = TrustStore(_path(config["trust_store_path"]))
    trusted.require_trusted(issuer.key_id)
    roster_path = _path(config["roster_path"])
    if out in {roster_path, _path(authority_config), _path(config["identity_path"]), _path(config["trust_store_path"])}:
        raise NetworkCryptoError("network_invitation_path_conflict")
    with _exclusive_store(roster_path):
        previous_document = _read(roster_path, private=True)
        previous = verify_roster(previous_document, trusted, network_id=network_id, allow_expired=True)
        if any(entry["signing_key"]["key_id"] == candidate_member["signing_key"]["key_id"]
               or entry["encryption_key"]["key_id"] == candidate_member["encryption_key"]["key_id"] for entry in previous["members"]):
            raise NetworkCryptoError("network_candidate_already_listed")
        now = int(time.time())
        roster = issue_roster(issuer, network_id=network_id, version=previous["version"] + 1,
                              previous_sha256=document_sha256(previous_document), members=[*previous["members"], candidate_member],
                              issued_at=now, expires_at=now + 300)
        handoff = None
        if handoff_envelope is not None:
            handoff = _read(handoff_envelope, maximum=6 * 1024 * 1024)
            senders = PublicKeyTrust([entry["signing_key"] for entry in previous["members"] if entry["status"] == "active"])
            payload = verify_envelope(handoff, senders, network_id=network_id)
            if (candidate_member["signing_key"]["key_id"] not in payload["recipient_key_ids"]
                    or candidate_member["encryption_key"]["key_id"] not in {entry["header"]["kid"] for entry in payload["jwe"]["recipients"]}):
                raise NetworkCryptoError("network_handoff_wrong_recipient")
        signed = issue_invite(issuer, network_id=network_id, invite_id="invite_" + secrets.token_hex(24),
                              candidate_signing_key=candidate_member["signing_key"], candidate_encryption_key=candidate_member["encryption_key"],
                              scope=candidate_member["scope"], handoff_sha256=document_sha256(handoff) if handoff else hashlib.sha256(b"").hexdigest(),
                              roster_sha256=document_sha256(roster), issued_at=now, expires_at=now + lifetime_seconds)
        package = {"invite": signed, "roster": roster}
        if handoff is not None:
            package["handoff"] = handoff
        # Publish package first. If the subsequent roster commit fails, fresh
        # issuer status cannot authorize it; caller must not distribute a failed
        # operation's package. Neither failure grants candidate relay access.
        _new(out, package)
        try:
            atomic_write(roster_path, canonical_bytes(roster) + b"\n", replace=True)
        except Exception:
            raise NetworkCryptoError("network_invite_roster_commit_failed") from None
    return {"state": "invitation_created", "invitation_file": str(out), "roster_version": roster["payload"]["version"],
            "candidate_key_id": candidate_member["signing_key"]["key_id"], "candidate_must_prove_both_keys": True,
            "candidate_private_key_received": False, "network_accessed": False, "services_started": False}


def _checkpoint(client: Any) -> dict[str, Any]:
    """Read only three indexed control values, never queue/message bodies."""
    result: dict[str, Any] = {"last_verified_roster": None, "delivery_cursors": {}}
    database = _path(client.directory / "network.sqlite3")
    if not os.path.lexists(database):
        return result
    fd = open_file(database, os.O_RDONLY, private=True)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise NetworkCryptoError("network_checkpoint_storage_invalid")
        for suffix in ("-wal", "-shm", "-journal"):
            sibling = Path(str(database) + suffix)
            if os.path.lexists(sibling):
                sidecar = open_file(sibling, os.O_RDONLY, private=True)
                os.close(sidecar)
        uri = "file:" + quote(str(database), safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=1)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            deadline = time.monotonic() + 2
            connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            connection.execute("BEGIN")
            for key in ["roster", *("cursor:" + relay for relay in client.relays)]:
                # substr(BLOB) bounds allocation even if a local control value
                # is corrupt. No SELECT from outbox/inbox/acknowledgements.
                row = connection.execute("SELECT substr(CAST(value AS BLOB),1,1048577) FROM state WHERE key=?", (key,)).fetchone()
                if row is None:
                    continue
                value = document(bytes(row[0]), maximum=1024 * 1024)
                if key == "roster":
                    verify_roster(value, client.issuers, network_id=client.network_id, allow_expired=True)
                    result["last_verified_roster"] = value
                else:
                    result["delivery_cursors"][key[len("cursor:"):]] = value
        finally:
            connection.close()
        current = database.lstat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise NetworkCryptoError("network_checkpoint_file_changed")
    except sqlite3.Error:
        raise NetworkCryptoError("network_checkpoint_unavailable") from None
    finally:
        os.close(fd)
    return result


def backup_keys(*, network_config: Path, output: Path, secret_file: Path) -> Mapping[str, Any]:
    """Encrypt bounded identity/control state, explicitly not a full backup."""
    from memory_vault_network import NetworkClient
    config_path, package_path, secret_path = _path(network_config), _path(output), _path(secret_file)
    if package_path == secret_path or package_path in secret_path.parents or secret_path in package_path.parents:
        raise NetworkCryptoError("network_recovery_secret_must_be_separate")
    if os.path.lexists(package_path) or os.path.lexists(secret_path):
        raise NetworkCryptoError("network_recovery_output_exists")
    client = NetworkClient(config_path)
    config = _read(config_path, private=True, maximum=64 * 1024)
    signing = _read(client.client_config.identity_path, private=True, maximum=4096)
    expected_public = {key: signing[key] for key in ("algorithm", "key_id", "public_key")}
    if expected_public != {key: client.identity.public_descriptor()[key] for key in expected_public}:
        raise NetworkCryptoError("network_recovery_identity_changed")
    # The existing validator checks the complete private registry. Its contents
    # remain inside the encrypted payload; nothing is enrolled or rewritten.
    registry = TrustStore(client.client_config.trust_path)._read()
    payload = {"schema_version": KEY_BACKUP_SCHEMA, "network_config": config,
               "signing_identity": signing, "encryption_identity": client.encryption.private_document(),
               "trust_registry": registry, "checkpoint": _checkpoint(client),
               "vault_included": False, "inbox_included": False, "outbox_included": False}
    document(payload, maximum=1024 * 1024)
    recovery_secret = generate_recovery_secret()
    package = export_recovery(payload, recovery_secret=recovery_secret, network_id=client.network_id)
    _new(secret_path, {"schema_version": KEY_SECRET_SCHEMA, "network_id": client.network_id, "secret": recovery_secret})
    _new(package_path, package)
    shared_issuer = client.identity.key_id == config["issuer_public_key"]["key_id"]
    return {"state": "identity_control_backup_created", "package": str(package_path), "secret_file": str(secret_path),
            "keep_secret_separately": True, "vault_included": False, "inbox_included": False, "outbox_included": False,
            "issuer_key_shared_with_endpoint": shared_issuer,
            "offline_unsent_messages_not_backed_up": True, "network_accessed": False,
            "warning": "Identity/control recovery only. Keep the recovery secret separately. Use the existing Vault backup for memories; offline unsent outbox messages are not included."
                       + (" This explicitly configured endpoint shares the issuer signing key; its backup also contains issuer authority." if shared_issuer else "")}


def restore_keys(*, package: Path, secret_file: Path, directory: Path, vault: Path,
                 confirm_network_id: str, issuer_public: Path, authority_url: str,
                 relays: Sequence[str]) -> Mapping[str, Any]:
    """Restore inert keys to a new directory; all paths/origins are local choices."""
    from memory_vault_network import origin
    network_id = opaque(confirm_network_id)
    secret = object_fields(_read(secret_file, private=True, maximum=4096), {"schema_version", "network_id", "secret"})
    if secret["schema_version"] != KEY_SECRET_SCHEMA or secret["network_id"] != network_id:
        raise NetworkCryptoError("network_recovery_secret_binding_mismatch")
    recovered = import_recovery(_read(package, private=True, maximum=2 * 1024 * 1024), recovery_secret=secret["secret"], network_id=network_id)
    payload = object_fields(recovered["payload"], {"schema_version", "network_config", "signing_identity", "encryption_identity", "trust_registry",
                                                  "checkpoint", "vault_included", "inbox_included", "outbox_included"})
    if (payload["schema_version"] != KEY_BACKUP_SCHEMA or recovered["activation_disabled"] is not True
            or any(payload[key] is not False for key in ("vault_included", "inbox_included", "outbox_included"))):
        raise NetworkCryptoError("network_recovery_package_invalid")
    old_config = payload["network_config"]
    if not isinstance(old_config, dict) or old_config.get("network_id") != network_id:
        raise NetworkCryptoError("network_recovery_binding_mismatch")
    independent_issuer = public_signing_key(_read(issuer_public, maximum=16 * 1024))
    if old_config.get("issuer_public_key") != independent_issuer:
        raise NetworkCryptoError("network_recovery_issuer_mismatch")
    # The package never chooses the Vault, destination, endpoint or trusted key.
    # Validate all operator-supplied origins before creating any recovery files.
    authority_url = origin(authority_url)
    if not 1 <= len(relays) <= 2:
        raise NetworkCryptoError("network_one_or_two_relays_required")
    destinations = [origin(value) for value in relays]
    if len(set(destinations)) != len(destinations):
        raise NetworkCryptoError("network_duplicate_relay")
    selected, existing_vault = _path(directory), _path(vault)
    if selected == existing_vault or selected in existing_vault.parents or existing_vault in selected.parents:
        raise NetworkCryptoError("network_recovery_vault_must_be_separate")
    descriptor = open_file(existing_vault, os.O_RDONLY, private=True)
    try:
        vault_info = os.fstat(descriptor)
        if not stat.S_ISREG(vault_info.st_mode) or os.read(descriptor, 16) != b"SQLite format 3\x00":
            raise NetworkCryptoError("network_recovery_existing_vault_required")
    finally:
        os.close(descriptor)
    checkpoint = object_fields(payload["checkpoint"], {"last_verified_roster", "delivery_cursors"})
    previous_roster = checkpoint["last_verified_roster"]
    minimum_version, previous_hash = 0, None
    if previous_roster is not None:
        checked = verify_roster(previous_roster, PublicKeyTrust([independent_issuer]), network_id=network_id, allow_expired=True)
        minimum_version, previous_hash = checked["version"], document_sha256(previous_roster)
    encryption = EncryptionIdentity.from_private_document(payload["encryption_identity"])
    selected = _new_directory(selected)
    _new(selected / "identity.json", payload["signing_identity"])
    restored_identity = Identity.load(selected / "identity.json")
    _new(selected / "trust.json", payload["trust_registry"])
    TrustStore(selected / "trust.json").require_trusted(restored_identity.key_id)
    encryption.save(selected / "encryption.json")
    _new(selected / "issuer-public.json", independent_issuer)
    _new(selected / "member-public.json", {"signing_key": restored_identity.public_descriptor(), "encryption_key": encryption.public_descriptor(),
         "status": "active", "scope": ["receive", "send"]})
    _new(selected / "client.json", {"schema_version": CLIENT_SCHEMA, "vault_path": str(existing_vault), "capture_visible_turns": False,
         "identity_path": str(selected / "identity.json"), "trust_path": str(selected / "trust.json")})
    _new(selected / "recovery-state.json", {"schema_version": RESTORED_STATE_SCHEMA, "network_id": network_id,
         "activation_disabled": True, "requires_fresh_issuer_status": True, "minimum_roster_version": minimum_version,
         "last_verified_roster": previous_roster, "last_roster_sha256": previous_hash,
         "old_delivery_cursors_restored": False, "offline_outbox_restored": False, "vault_restored_by_this_command": False})
    configure_network(client_config=selected / "client.json", encryption_key=selected / "encryption.json",
                      issuer_public=selected / "issuer-public.json", network_id=network_id, authority_url=authority_url,
                      relays=destinations, output=selected / "network.json")
    return {"state": "identity_control_restored_inactive", "network_config": str(selected / "network.json"),
            "activation_disabled": True, "requires_fresh_issuer_status": True, "network_state_started_empty": True,
            "vault_changed": False, "offline_outbox_restored": False, "network_accessed": False,
            "warning": "Not a full backup. Existing Vault was not modified; offline unsent messages were not restored. Re-fetch retained relay copies only after fresh independent issuer authorization."}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    identity = commands.add_parser("identity", help="create keys and capture-off client on the candidate's own device")
    identity.add_argument("--directory", type=Path, required=True)
    init = commands.add_parser("init", help="create new owner, private network and foreground-service configurations")
    init.add_argument("--directory", type=Path, required=True)
    init.add_argument("--network-id", required=True)
    init.add_argument("--relay-url", default="http://127.0.0.1:8765")
    init.add_argument("--authority-url", default="http://127.0.0.1:8767")
    invite = commands.add_parser("invite", help="explicitly authorize a candidate public descriptor; never generates their key")
    invite.add_argument("--authority-config", type=Path, required=True)
    invite.add_argument("--candidate", type=Path, required=True)
    invite.add_argument("--output", type=Path, required=True)
    invite.add_argument("--handoff-envelope", type=Path)
    invite.add_argument("--scope", choices=["send", "receive"], action="append")
    invite.add_argument("--lifetime-seconds", type=int, default=86400)
    configure = commands.add_parser("configure", help="reuse this device's existing signed client and encryption identity")
    configure.add_argument("--client-config", type=Path, required=True)
    configure.add_argument("--encryption-key", type=Path, required=True)
    configure.add_argument("--issuer-public", type=Path, required=True)
    configure.add_argument("--network-id", required=True)
    configure.add_argument("--authority-url", required=True)
    configure.add_argument("--relay", action="append", required=True)
    configure.add_argument("--output", type=Path, required=True)
    backup = commands.add_parser("keys-backup", aliases=["backup"], help="encrypt identity/control metadata only, not the Vault or offline outbox")
    backup.add_argument("--network-config", type=Path, required=True)
    backup.add_argument("--output", type=Path, required=True)
    backup.add_argument("--secret-file", type=Path, required=True)
    restore = commands.add_parser("keys-restore", aliases=["restore"], help="restore inactive keys; choose all destinations and issuer anchor explicitly")
    restore.add_argument("--package", type=Path, required=True)
    restore.add_argument("--secret-file", type=Path, required=True)
    restore.add_argument("--directory", type=Path, required=True)
    restore.add_argument("--vault", type=Path, required=True)
    restore.add_argument("--confirm-network-id", required=True)
    restore.add_argument("--issuer-public", type=Path, required=True)
    restore.add_argument("--authority-url", required=True)
    restore.add_argument("--relay", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "identity":
            result = create_identity(args.directory)
        elif args.action == "init":
            result = initialize(args.directory, network_id=args.network_id, relay_url=args.relay_url, authority_url=args.authority_url)
        elif args.action == "invite":
            result = invite_candidate(authority_config=args.authority_config, candidate=args.candidate, output=args.output,
                                       handoff_envelope=args.handoff_envelope, scope=args.scope or ["receive", "send"], lifetime_seconds=args.lifetime_seconds)
        elif args.action == "configure":
            result = configure_network(client_config=args.client_config, encryption_key=args.encryption_key, issuer_public=args.issuer_public,
                                        network_id=args.network_id, authority_url=args.authority_url, relays=args.relay, output=args.output)
        elif args.action in {"keys-backup", "backup"}:
            result = backup_keys(network_config=args.network_config, output=args.output, secret_file=args.secret_file)
        else:
            result = restore_keys(package=args.package, secret_file=args.secret_file, directory=args.directory, vault=args.vault,
                                   confirm_network_id=args.confirm_network_id, issuer_public=args.issuer_public, authority_url=args.authority_url, relays=args.relay)
        write_response(success(result))
        return 0
    except (MemoryError, TrustError) as exc:
        write_response(failure(exc.code, retryable=getattr(exc, "retryable", False)))
    except (OSError, ValueError):
        write_response(failure("network_setup_unavailable"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
