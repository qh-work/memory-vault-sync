#!/usr/bin/env python3
"""Explicit, versioned full-client installation with recoverable activation.

This manages only a newly chosen installation directory. It never edits Codex,
Claude, Gemini, OS startup, a marketplace, memory, credentials or hook trust.
The operator points an authorized host at the stable managed launcher once.
Future signed runtime updates may be enabled independently; they run in finite
event-triggered workers, never from a remembered instruction.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

_SOURCE_DIRECTORY = str(Path(__file__).resolve().parent)
if _SOURCE_DIRECTORY not in sys.path:
    sys.path.insert(0, _SOURCE_DIRECTORY)

from memory_vault import MemoryError, canonical_bytes, failure, strict_json_loads, success, write_response
from memory_vault_client import _absolute, _private_directory, _read_json, _write_once
from memory_vault_update import (
    MAX_ARCHIVE, MAX_FILE, MAX_METADATA, REPOSITORY, _archive_inventory,
    atomic_json, check, read_file, stage, state_lock, write_file,
)


CONFIG_SCHEMA = "memory-vault-managed-install/v1"
ACTIVE_SCHEMA = "memory-vault-managed-active/v1"
INVENTORY_SCHEMA = "memory-vault-managed-inventory/v1"
JOURNAL_SCHEMA = "memory-vault-managed-activation/v1"
_SHA = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
_REQUEST = re.compile(r"req_[A-Za-z0-9_-]{8,96}")
MAX_RECEIPTS = 4096
MAX_LOG_BYTES = 512 * 1024


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _config(root: Path) -> dict[str, Any]:
    root = _absolute(root)
    value = _read_json(root / "install.json", maximum=16 * 1024)
    if (not isinstance(value, dict)
            or set(value) != {"schema_version", "repository", "trust_store_path", "automatic"}
            or value["schema_version"] != CONFIG_SCHEMA or value["repository"] != REPOSITORY
            or type(value["automatic"]) is not bool):
        raise MemoryError("invalid_managed_installation")
    trusted = value["trust_store_path"]
    if trusted is not None:
        path = _absolute(trusted)
        if path == root or root in path.parents:
            raise MemoryError("update_trust_must_remain_outside_installation")
    elif value["automatic"]:
        raise MemoryError("automatic_update_requires_publisher_trust")
    return value


def _active(root: Path) -> dict[str, Any] | None:
    path = _absolute(root / "active.json")
    if not path.exists():
        return None
    value = _read_json(path, maximum=64 * 1024)
    return _active_value(value)


def _active_value(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != {"schema_version", "generation", "current", "previous"}
            or value["schema_version"] != ACTIVE_SCHEMA or type(value["generation"]) is not int
            or not 1 <= value["generation"] <= 2_147_483_647):
        raise MemoryError("invalid_managed_active_state")
    _descriptor(value["current"])
    if value["previous"] is not None:
        _descriptor(value["previous"])
    return value


def _descriptor(value: Any) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or set(value) != {"version", "archive_sha256", "inventory_sha256", "source_commit", "host_contract_sha256", "publisher_verified"}
            or not isinstance(value["version"], str) or _VERSION.fullmatch(value["version"]) is None
            or any(not isinstance(value[key], str) or _SHA.fullmatch(value[key]) is None
                   for key in ("archive_sha256", "inventory_sha256", "host_contract_sha256"))
            or not isinstance(value["source_commit"], str)
            or re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is None
            or type(value["publisher_verified"]) is not bool):
        raise MemoryError("invalid_managed_runtime_descriptor")
    return value


def _host_contract(archive: Any, version: str) -> str:
    prefix = "memory-vault-client-v" + version + "/plugins/memory-vault-client/"
    manifest = strict_json_loads(archive.read(prefix + ".codex-plugin/plugin.json"))
    # Branding/version changes don't change a host's requested integration.
    # New MCP/configuration/skill/hook declarations require explicit review.
    shape = {key: manifest.get(key) for key in ("name", "skills", "apps", "mcpServers", "hooks")}
    shape["mcp_sha256"] = hashlib.sha256(archive.read(prefix + ".mcp.json")).hexdigest()
    shape["hooks_sha256"] = hashlib.sha256(archive.read(prefix + "hooks/hooks.json")).hexdigest()
    return _hash(shape)


def _candidate(staged: Path, config: Mapping[str, Any], expected: str | None) -> tuple[Any, list[Any], dict[str, Any], dict[str, Any] | None]:
    staged = _absolute(staged)
    data = read_file(staged / "PACKAGE.zip", MAX_ARCHIVE)
    digest = hashlib.sha256(data).hexdigest()
    manifest = strict_json_loads(read_file(staged / "RELEASE.json", MAX_METADATA))
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != "memory-vault-release/v1"
            or manifest.get("private_state_included") is not False
            or not isinstance(manifest.get("version"), str) or _VERSION.fullmatch(manifest["version"]) is None
            or not isinstance(manifest.get("source_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]) is None):
        raise MemoryError("invalid_managed_release_manifest")
    version = manifest["version"]
    if manifest.get("source_url") != "https://github.com/" + REPOSITORY + "/tree/" + manifest["source_commit"]:
        raise MemoryError("managed_release_source_mismatch")
    assets = manifest.get("assets")
    if not isinstance(assets, list) or not 1 <= len(assets) <= 16:
        raise MemoryError("invalid_managed_release_assets")
    candidates = [item for item in assets if isinstance(item, dict)
                  and item.get("name") == "memory-vault-client-v" + version + ".zip"]
    if len(candidates) != 1 or candidates[0].get("sha256") != digest or candidates[0].get("bytes") != len(data):
        raise MemoryError("managed_archive_hash_mismatch")
    if expected is not None and (not isinstance(expected, str) or _SHA.fullmatch(expected) is None or expected != digest):
        raise MemoryError("managed_expected_digest_mismatch")
    signed = None
    if config["trust_store_path"] is not None:
        from memory_vault_update_trust import read_trust_store_file, verify_update_chain
        signed = verify_update_chain(staged / "update-metadata",
            strict_json_loads(read_trust_store_file(_absolute(config["trust_store_path"]))), {
                "version": version, "bundle_sha256": digest, "bundle_length": len(data),
                "commit_sha": manifest["source_commit"],
            }, plugin_name="memory-vault-client", now_epoch=int(time.time()))
    elif expected is None:
        raise MemoryError("manual_install_requires_explicit_archive_digest")
    archive, members = _archive_inventory(data, version)
    try:
        descriptor = {"version": version, "archive_sha256": digest,
                      "inventory_sha256": "0" * 64, "source_commit": manifest["source_commit"],
                      "host_contract_sha256": _host_contract(archive, version),
                      "publisher_verified": signed is not None}
    except BaseException:
        archive.close()
        raise
    return archive, members, descriptor, signed


def verify_installed(root: Path, descriptor: Mapping[str, Any]) -> dict[str, Any]:
    descriptor = _descriptor(dict(descriptor))
    directory = _absolute(root / "releases" / descriptor["archive_sha256"])
    raw = read_file(directory / "INVENTORY.json", MAX_METADATA)
    if hashlib.sha256(raw).hexdigest() != descriptor["inventory_sha256"]:
        raise MemoryError("managed_inventory_changed")
    value = strict_json_loads(raw)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "archive_sha256", "files"}
            or value["schema_version"] != INVENTORY_SCHEMA
            or value["archive_sha256"] != descriptor["archive_sha256"]
            or not isinstance(value["files"], dict) or not 1 <= len(value["files"]) <= 512):
        raise MemoryError("invalid_managed_inventory")
    prefix = "memory-vault-client-v" + descriptor["version"] + "/"
    total = 0
    for name, digest in value["files"].items():
        if (not isinstance(name, str) or not name.startswith(prefix)
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or "\\" in name or ":" in name or not isinstance(digest, str) or _SHA.fullmatch(digest) is None):
            raise MemoryError("invalid_managed_inventory_entry")
        content = read_file(directory.joinpath(*name.split("/")), MAX_FILE)
        total += len(content)
        if total > MAX_ARCHIVE or hashlib.sha256(content).hexdigest() != digest:
            raise MemoryError("managed_runtime_changed")
    runtime_prefix = prefix + "plugins/memory-vault-client/runtime/"
    if runtime_prefix + "memory_vault_client.py" not in value["files"]:
        raise MemoryError("managed_client_entry_missing")
    runtime = directory.joinpath(*runtime_prefix.rstrip("/").split("/"))
    expected = {name[len(runtime_prefix):] for name in value["files"] if name.startswith(runtime_prefix)}
    if {path.name for path in runtime.iterdir()} != expected:
        raise MemoryError("unexpected_managed_runtime_file")
    return value


def _materialize(root: Path, archive: Any, members: list[Any], descriptor: dict[str, Any]) -> dict[str, Any]:
    directory = _absolute(root / "releases" / descriptor["archive_sha256"])
    files = {item.filename: hashlib.sha256(archive.read(item)).hexdigest() for item in members}
    inventory = {"schema_version": INVENTORY_SCHEMA, "archive_sha256": descriptor["archive_sha256"], "files": files}
    encoded = canonical_bytes(inventory) + b"\n"
    result = {**descriptor, "inventory_sha256": hashlib.sha256(encoded).hexdigest()}
    if directory.exists():
        # Recovery from a crash before the manifest was published is possible
        # only when every existing byte matches this exact reviewed archive.
        for name, digest in files.items():
            target = _absolute(directory.joinpath(*name.split("/")))
            if target.exists() and hashlib.sha256(read_file(target, MAX_FILE)).hexdigest() != digest:
                raise MemoryError("managed_partial_install_changed")
        # No extra executable/module may ride along in a resumed installation.
        allowed = set(files) | {"INVENTORY.json"}
        count = 0
        for existing in directory.rglob("*"):
            count += 1
            if count > 2048 or existing.is_symlink():
                raise MemoryError("managed_partial_install_unsafe")
            if existing.is_file() and existing.relative_to(directory).as_posix() not in allowed:
                raise MemoryError("managed_partial_install_has_unlisted_file")
    else:
        _private_directory(directory)
    for item in members:
        target = _absolute(directory.joinpath(*item.filename.split("/")))
        if not target.exists():
            write_file(target, archive.read(item))
    inventory_file = directory / "INVENTORY.json"
    if not inventory_file.exists():
        write_file(inventory_file, encoded)
    verify_installed(root, result)
    return result


def _request_path(root: Path, request_id: str) -> Path:
    if not isinstance(request_id, str) or _REQUEST.fullmatch(request_id) is None:
        raise MemoryError("invalid_activation_request_id")
    directory = root / "activations"
    _private_directory(directory)
    path = directory / (_hash(request_id) + ".json")
    # Filling the audit budget must not prevent exact completed receipts from
    # being read, nor permit one new receipt beyond the documented bound.
    existing = path.exists()
    with os.scandir(directory) as entries:
        for count, _ in enumerate(entries, 1):
            if not existing and count >= MAX_RECEIPTS:
                raise MemoryError("activation_audit_requires_archival")
            if existing and count > MAX_RECEIPTS + 1:
                break
    return path


def _commit_activation(root: Path, request_id: str, request: Mapping[str, Any], target: Mapping[str, Any]) -> Mapping[str, Any]:
    receipt_path = _request_path(root, request_id)
    fingerprint = _hash(dict(request))
    active = _active(root)
    if receipt_path.exists():
        journal = _read_json(receipt_path, maximum=128 * 1024)
        if (not isinstance(journal, dict) or set(journal) != {"schema_version", "request_sha256", "before", "after", "state"}
                or journal["schema_version"] != JOURNAL_SCHEMA or journal["request_sha256"] != fingerprint
                or journal["state"] not in {"prepared", "committed"}):
            raise MemoryError("activation_request_conflict")
        if journal["state"] == "committed":
            return {"state": "activation_receipt_replayed", "historical_generation": journal["after"]["generation"],
                    "current_generation": active["generation"] if active else 0, "activated_now": False}
        if active not in (journal["before"], journal["after"]):
            raise MemoryError("activation_state_advanced")
        if journal["after"]["current"] != target:
            raise MemoryError("activation_target_changed")
    else:
        after = active if active is not None and active["current"] == target else {
            "schema_version": ACTIVE_SCHEMA, "generation": active["generation"] + 1 if active else 1,
            "current": dict(target), "previous": active["current"] if active else None}
        _active_value(after)  # Refuse exhausted generations before persisting a pointer or intent.
        journal = {"schema_version": JOURNAL_SCHEMA, "request_sha256": fingerprint,
                   "before": active, "after": after, "state": "prepared"}
        _write_once(receipt_path, journal)
    verify_installed(root, target)
    atomic_json(root / "active.json", journal["after"])
    atomic_json(receipt_path, {**journal, "state": "committed"})
    changed = journal["before"] != journal["after"]
    return {"state": "runtime_activated_for_next_invocation" if changed else "runtime_already_active", "version": target["version"],
            "generation": journal["after"]["generation"], "archive_sha256": target["archive_sha256"],
            "publisher_signature_verified": target["publisher_verified"], "code_executed": False,
            "activated_now": changed,
            "existing_processes_unchanged": True, "host_permissions_changed": False,
            "old_version_retained": journal["before"] is not None}


def _committed_replay(root: Path, request_id: str, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Read/recover a historical receipt without re-activating expired code."""
    path = _request_path(root, request_id)
    if not path.exists():
        return None
    journal = _read_json(path, maximum=128 * 1024)
    if (not isinstance(journal, dict) or set(journal) != {"schema_version", "request_sha256", "before", "after", "state"}
            or journal["schema_version"] != JOURNAL_SCHEMA or journal["request_sha256"] != _hash(dict(request))
            or journal["state"] not in {"prepared", "committed"}):
        raise MemoryError("activation_request_conflict")
    after = _active_value(journal["after"])
    before = _active_value(journal["before"]) if journal["before"] is not None else None
    if after != before and after["generation"] != (before["generation"] + 1 if before is not None else 1):
        raise MemoryError("invalid_activation_receipt")
    if request["operation"] == "activate" and after["current"]["archive_sha256"] != request["archive_sha256"]:
        raise MemoryError("activation_target_changed")
    active = _active(root)
    recovered = False
    if journal["state"] == "prepared":
        if active != after:
            if active != before:
                raise MemoryError("activation_state_advanced")
            # The pointer has not moved: current publisher trust is still
            # required before an actual future activation may be completed.
            return None
        verify_installed(root, after["current"])
        # The exact already-active pointer and installed bytes prove the local
        # effect happened. Expired metadata must not prevent finalizing this
        # historical audit receipt. Never rewrite active.json in this path.
        atomic_json(path, {**journal, "state": "committed"})
        recovered = True
    return {"state": "activation_receipt_recovered" if recovered else "activation_receipt_replayed",
            "historical_generation": after["generation"],
            "current_generation": active["generation"] if active else 0, "activated_now": False,
            "historical_receipt_is_current_publisher_trust": False, "network_accessed": False}


def activate(installation: Path, staged: Path, *, request_id: str, expected_sha256: str | None = None,
             approve_host_contract_change: bool = False, require_automatic: bool = False) -> Mapping[str, Any]:
    root = _absolute(installation)
    if type(approve_host_contract_change) is not bool or type(require_automatic) is not bool:
        raise MemoryError("invalid_activation_option")
    with state_lock(root):
        config = _config(root)
        if require_automatic and not config["automatic"]:
            return {"state": "automatic_update_cancelled_before_activation", "activated": False}
        archive_digest = hashlib.sha256(read_file(_absolute(staged) / "PACKAGE.zip", MAX_ARCHIVE)).hexdigest()
        if expected_sha256 is not None and expected_sha256 != archive_digest:
            raise MemoryError("managed_expected_digest_mismatch")
        request = {"operation": "activate", "archive_sha256": archive_digest,
                   "host_contract_approved": approve_host_contract_change}
        replay = _committed_replay(root, request_id, request)
        if replay is not None:
            return replay
        trust_path = _absolute(config["trust_store_path"]) if config["trust_store_path"] is not None else None
        with state_lock(trust_path.parent) if trust_path is not None else contextlib.nullcontext():
            archive, members, descriptor, signed = _candidate(staged, config, expected_sha256)
            try:
                if descriptor["archive_sha256"] != archive_digest:
                    raise MemoryError("managed_stage_changed")
                active = _active(root)
                if active is not None:
                    prior = active["current"]
                    if tuple(map(int, descriptor["version"].split("."))) < tuple(map(int, prior["version"].split("."))):
                        raise MemoryError("use_explicit_managed_rollback")
                    if descriptor["version"] == prior["version"] and descriptor["archive_sha256"] != prior["archive_sha256"]:
                        raise MemoryError("same_version_runtime_substitution")
                    if descriptor["host_contract_sha256"] != prior["host_contract_sha256"] and not approve_host_contract_change:
                        raise MemoryError("managed_host_contract_needs_review")
                target = _materialize(root, archive, members, descriptor)
                if signed is not None:
                    atomic_json(trust_path, signed["trust_store"])
                return _commit_activation(root, request_id, request, target)
            finally:
                archive.close()


def initialize(installation: Path, staged: Path, *, request_id: str, expected_sha256: str | None = None,
               trust_store_path: Path | None = None, automatic: bool = False) -> Mapping[str, Any]:
    root = _absolute(installation)
    if type(automatic) is not bool:
        raise MemoryError("invalid_automatic_update_option")
    if root.exists():
        raise MemoryError("managed_installation_exists")
    if automatic and trust_store_path is None:
        raise MemoryError("automatic_update_requires_publisher_trust")
    trusted = _absolute(trust_store_path) if trust_store_path is not None else None
    if trusted is not None and (trusted == root or root in trusted.parents):
        raise MemoryError("update_trust_must_remain_outside_installation")
    launcher_source = Path(__file__).resolve().parent / "memory_vault_managed_launcher.py"
    launcher_bytes = read_file(launcher_source, MAX_FILE)
    storage_bytes = read_file(launcher_source.with_name("memory_vault_storage.py"), MAX_FILE)
    marker = b"TRUSTED_STORAGE_SHA256 = None"
    if launcher_bytes.count(marker) != 1:
        raise MemoryError("managed_bootstrap_storage_marker_missing")
    launcher_bytes = launcher_bytes.replace(marker, b'TRUSTED_STORAGE_SHA256 = "' + hashlib.sha256(storage_bytes).hexdigest().encode("ascii") + b'"')
    _private_directory(root)
    _write_once(root / "install.json", {"schema_version": CONFIG_SCHEMA, "repository": REPOSITORY,
                                        "trust_store_path": str(trusted) if trusted is not None else None,
                                        "automatic": automatic})
    write_file(root / "managed_storage.py", storage_bytes)
    write_file(root / "launcher.py", launcher_bytes)
    result = activate(root, staged, request_id=request_id, expected_sha256=expected_sha256)
    return {**result, "installation_created": True, "host_connected": False,
            "next_action": "Point an authorized host at this installation's launcher.py using its normal setup and hook-review flow."}


def rollback(installation: Path, *, request_id: str, expected_generation: int, approved: bool) -> Mapping[str, Any]:
    root = _absolute(installation)
    _config(root)
    if approved is not True or type(expected_generation) is not int or expected_generation < 1:
        raise MemoryError("explicit_rollback_approval_required")
    with state_lock(root):
        active = _active(root)
        if active is None or active["previous"] is None:
            raise MemoryError("previous_managed_runtime_unavailable")
        request = {"operation": "rollback", "expected_generation": expected_generation}
        replay = _committed_replay(root, request_id, request)
        if replay is not None:
            return replay
        # A deliberate rollback must not be immediately undone by the next
        # automatic check. This never lowers cryptographic anti-rollback floors.
        config = _config(root)
        receipt_path = _request_path(root, request_id)
        if receipt_path.exists():
            saved = _read_json(receipt_path, maximum=128 * 1024)
            target = saved.get("after", {}).get("current")
            _descriptor(target)
            atomic_json(root / "install.json", {**config, "automatic": False})
            return {**_commit_activation(root, request_id, request, target), "automatic_updates_paused": True}
        if active["generation"] != expected_generation:
            raise MemoryError("rollback_generation_changed")
        atomic_json(root / "install.json", {**config, "automatic": False})
        return {**_commit_activation(root, request_id, request, active["previous"]), "automatic_updates_paused": True}


def status(installation: Path) -> Mapping[str, Any]:
    root = _absolute(installation)
    config = _config(root)
    active = _active(root)
    return {"state": "ready" if active is not None else "activation_incomplete",
            "automatic": config["automatic"], "signed_updates_required": config["trust_store_path"] is not None,
            "generation": active["generation"] if active else 0,
            "version": active["current"]["version"] if active else None,
            "rollback_available": active is not None and active["previous"] is not None,
            "runtime_files_verified": False, "network_accessed": False, "host_permissions_changed": False}


def configure_automatic(installation: Path, *, enabled: bool) -> Mapping[str, Any]:
    root = _absolute(installation)
    if type(enabled) is not bool:
        raise MemoryError("invalid_automatic_update_option")
    with state_lock(root):
        config = _config(root)
        if enabled and config["trust_store_path"] is None:
            raise MemoryError("automatic_update_requires_publisher_trust")
        atomic_json(root / "install.json", {**config, "automatic": enabled})
    return {"automatic": enabled, "state": "managed_update_preference_saved", "network_accessed": False}


def apply_latest(installation: Path, *, automatic_worker: bool = False) -> Mapping[str, Any]:
    root = _absolute(installation)
    config = _config(root)
    if automatic_worker and not config["automatic"]:
        return {"state": "automatic_updates_disabled", "network_accessed": False}
    if config["trust_store_path"] is None:
        raise MemoryError("automatic_update_requires_publisher_trust")
    active = _active(root)
    if active is None:
        raise MemoryError("managed_installation_incomplete")
    candidate = check()
    if tuple(map(int, candidate["version"].split("."))) <= tuple(map(int, active["current"]["version"].split("."))):
        return {"state": "no_newer_release", "version": active["current"]["version"], "network_accessed": True}
    staging_root = root / "staging"
    _private_directory(staging_root)
    # A fresh explicit stage avoids silently reusing partial or stale metadata.
    import tempfile
    staging_parent = Path(tempfile.mkdtemp(prefix="update-", dir=staging_root))
    staged = staging_parent / "package"
    staged_receipt = stage(staged, version=candidate["version"], trust_store_path=_absolute(config["trust_store_path"]))
    if automatic_worker and not _config(root)["automatic"]:
        return {"state": "automatic_update_cancelled_after_stage", "activated": False}
    # A rollback followed by a deliberate re-enable is a new logical update,
    # while retries from the same starting generation retain their request ID.
    request_key = [active["generation"], candidate["version"], staged_receipt["archive_sha256"]]
    return activate(root, staged, request_id="req_auto_update_" + _hash(request_key)[:32],
                    require_automatic=automatic_worker)


def notify(installation: Path, runtime_entry: Path) -> Mapping[str, Any]:
    """One opted-in finite worker on a host event; no sleep or self-relaunch."""
    root = _absolute(installation)
    config = _config(root)
    if not config["automatic"]:
        return {"state": "automatic_updates_disabled", "network_accessed": False}
    with state_lock(root):
        if not _config(root)["automatic"]:
            return {"state": "automatic_updates_disabled", "network_accessed": False}
        active = _active(root)
        if active is None:
            raise MemoryError("managed_installation_incomplete")
        expected_entry = root / "releases" / active["current"]["archive_sha256"] / (
            "memory-vault-client-v" + active["current"]["version"]) / "plugins/memory-vault-client/runtime/memory_vault_install.py"
        if _absolute(runtime_entry) != _absolute(expected_entry):
            raise MemoryError("update_worker_runtime_mismatch")
        verify_installed(root, active["current"])
        timer_path = root / "update-trigger.json"
        now = int(time.time())
        if timer_path.exists():
            timer = _read_json(timer_path, maximum=4096)
            if (not isinstance(timer, dict) or set(timer) != {"next_check_at"}
                    or type(timer["next_check_at"]) is not int
                    or not 0 <= timer["next_check_at"] <= now + 86400):
                raise MemoryError("invalid_update_trigger")
            if now < timer["next_check_at"]:
                return {"state": "update_check_coalesced", "network_accessed": False}
        atomic_json(timer_path, {"next_check_at": now + 3600})
        log_path = _absolute(root / "update-events.ndjson")
        if os.name == "nt":
            from memory_vault_storage import open_file
            descriptor = open_file(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, private=True)
        else:
            descriptor = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_LOG_BYTES:
                raise MemoryError("update_log_requires_review")
            env = {key: value for key, value in os.environ.items()
                   if key in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "LOCALAPPDATA", "LANG", "LC_ALL"}
                   or key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
            subprocess.Popen([sys.executable, "-I", "-B", str(runtime_entry), "--installation", str(root), "auto"],
                             stdin=subprocess.DEVNULL, stdout=descriptor, stderr=descriptor,
                             env=env, close_fds=True, cwd=str(runtime_entry.parent),
                             start_new_session=os.name != "nt")
        finally:
            os.close(descriptor)
    return {"state": "bounded_update_worker_started", "network_accessed": False}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("initialize", "activate"):
        command = sub.add_parser(name)
        command.add_argument("--staged", required=True, type=Path)
        command.add_argument("--request-id", required=True)
        command.add_argument("--expected-sha256")
        if name == "initialize":
            command.add_argument("--trust-store", type=Path)
            command.add_argument("--automatic", action="store_true")
        else:
            command.add_argument("--approve-host-contract-change", action="store_true")
    undo = sub.add_parser("rollback")
    undo.add_argument("--request-id", required=True)
    undo.add_argument("--expected-generation", required=True, type=int)
    undo.add_argument("--approve-rollback", action="store_true")
    automatic = sub.add_parser("automatic")
    automatic.add_argument("--enabled", choices=("yes", "no"), required=True)
    sub.add_parser("status")
    sub.add_parser("apply")
    sub.add_parser("auto", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.command == "initialize":
            result = initialize(args.installation, args.staged, request_id=args.request_id,
                                expected_sha256=args.expected_sha256, trust_store_path=args.trust_store, automatic=args.automatic)
        elif args.command == "activate":
            result = activate(args.installation, args.staged, request_id=args.request_id,
                              expected_sha256=args.expected_sha256, approve_host_contract_change=args.approve_host_contract_change)
        elif args.command == "rollback":
            result = rollback(args.installation, request_id=args.request_id,
                              expected_generation=args.expected_generation, approved=args.approve_rollback)
        elif args.command == "automatic":
            result = configure_automatic(args.installation, enabled=args.enabled == "yes")
        elif args.command == "status":
            result = status(args.installation)
        else:
            result = apply_latest(args.installation, automatic_worker=args.command == "auto")
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except Exception:
        write_response(failure("managed_installation_unavailable", retryable=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
