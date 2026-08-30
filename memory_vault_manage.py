#!/usr/bin/env python3
"""Operator-visible diagnostics, bounded local retry and memory-only recovery.

No command installs a host, enrolls keys, starts another agent or reads host
transcripts. ``doctor`` selects aggregate metadata, never memory bodies; all
mutations have separately named explicit commands.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Mapping, Sequence

from memory_vault import MemoryError, failure, success, write_response


DOCTOR_SCHEMA = "universal-memory-doctor/v1"
MAX_DISCOVERY = 5000
MAX_DIAGNOSIS_SECONDS = 5
_QUEUE_NAME = re.compile(r"[0-9a-f]{64}\.json")


def _config(path: Path) -> Any:
    # Loaded only when an operator/client invokes this module, avoiding client
    # import cycles and never replacing the client's configuration parser.
    from memory_vault_client import ClientConfig
    return ClientConfig.load(path)


def _path(path: Path) -> Path:
    from memory_vault_client import _absolute
    return _absolute(path)


def _file_metadata(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"configured": False, "exists": False}
    selected = _path(path)
    try:
        info = selected.lstat()
    except FileNotFoundError:
        return {"configured": True, "exists": False}
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return {"configured": True, "exists": True, "regular_private_file": False}
    protected = None if os.name != "posix" else info.st_uid == os.getuid() and not info.st_mode & 0o077
    return {"configured": True, "exists": True, "bytes": info.st_size,
            "regular_private_file": protected, "contents_read": False}


def _queue_directory(path: Path, budget: list[int]) -> dict[str, Any]:
    selected = _path(path)
    if not selected.exists():
        return {"exists": False, "files": 0, "bytes": 0, "bounded": True}
    info = selected.lstat()
    if not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise MemoryError("unsafe_operator_queue")
    files = size = unsafe = unexpected = 0
    latest_ns = 0
    truncated = False
    with os.scandir(selected) as entries:
        for entry in entries:
            budget[0] += 1
            if budget[0] > MAX_DISCOVERY:
                truncated = True
                break
            item = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                unsafe += 1
                continue
            if not _QUEUE_NAME.fullmatch(entry.name):
                unexpected += 1
                continue
            if os.name == "posix" and (item.st_uid != os.getuid() or item.st_mode & 0o077):
                unsafe += 1
                continue
            files += 1
            size += item.st_size
            latest_ns = max(latest_ns, item.st_mtime_ns)
    return {"exists": True, "files": files, "bytes": size, "unsafe_entries": unsafe,
            "unexpected_entries": unexpected, "latest_modified_ns": latest_ns or None,
            "truncated": truncated, "bounded": True, "contents_read": False}


def _host_queues(root: Path, budget: list[int]) -> dict[str, Any]:
    """Count only the documented hosts-v1/<host>/<hash>/pending control layout."""
    root = _path(root)
    if not root.exists():
        return {"exists": False, "pending_files": 0, "contents_read": False}
    if not root.is_dir():
        raise MemoryError("unsafe_host_queue")
    pending = bytes_pending = sessions = unsafe = 0
    truncated = False
    with os.scandir(root) as hosts:
        for host in hosts:
            budget[0] += 1
            if budget[0] > MAX_DISCOVERY:
                truncated = True
                break
            if not host.is_dir(follow_symlinks=False):
                unsafe += 1
                continue
            with os.scandir(host.path) as entries:
                for session in entries:
                    budget[0] += 1
                    if budget[0] > MAX_DISCOVERY:
                        truncated = True
                        break
                    if not session.is_dir(follow_symlinks=False):
                        unsafe += 1
                        continue
                    sessions += 1
                    detail = _queue_directory(Path(session.path) / "pending", budget)
                    pending += detail["files"]
                    bytes_pending += detail["bytes"]
                    unsafe += detail.get("unsafe_entries", 0)
                    truncated = truncated or detail.get("truncated", False)
            if truncated:
                break
    return {"exists": True, "sessions": sessions, "pending_files": pending,
            "pending_bytes": bytes_pending, "unsafe_entries": unsafe,
            "truncated": truncated, "contents_read": False}


def _lifecycle_status(config: Any) -> Mapping[str, Any]:
    path = _path(config.state_path / "lifecycle-v1.sqlite3")
    if not path.exists():
        return {"exists": False, "pending_turns": 0, "contents_read": False}
    from memory_vault_backup import readonly_database
    deadline = time.monotonic() + MAX_DIAGNOSIS_SECONDS
    with readonly_database(path, deadline) as connection:
        if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise MemoryError("unsupported_lifecycle_state")
        meta = dict(connection.execute("SELECT key,value FROM meta"))
        from memory_vault_client import _digest
        if meta.get("schema_version") != "universal-memory-lifecycle-state/v1" or meta.get("vault_path_sha256") != _digest(str(config.vault_path)):
            raise MemoryError("lifecycle_vault_changed")
        sessions = {str(row[0]): int(row[1]) for row in connection.execute("SELECT state,COUNT(*) FROM sessions GROUP BY state")}
        turns = {str(row[0]): int(row[1]) for row in connection.execute("SELECT phase,COUNT(*) FROM turns GROUP BY phase")}
        if set(sessions) - {"open", "closed"} or set(turns) - {"staged", "committing", "committed", "aborted"}:
            raise MemoryError("invalid_lifecycle_state")
        return {"exists": True, "sessions": sessions, "turns": turns,
                "pending_turns": turns.get("staged", 0) + turns.get("committing", 0),
                "unfinished_commit_receipts": int(connection.execute("SELECT COUNT(*) FROM requests WHERE response_json IS NULL").fetchone()[0]),
                "recovery": "retry_exact_original_commit_or_explicit_abort_before_commit",
                "contents_read": False}


def _trust_status(config: Any) -> Mapping[str, Any]:
    identity = _file_metadata(config.identity_path)
    metadata = _file_metadata(config.trust_path)
    result: dict[str, Any] = {
        "identity": identity, "registry": metadata,
        "provider_package_discoverable": importlib.util.find_spec("cryptography") is not None,
        "private_key_loaded": False, "record_signatures_reverified": False,
    }
    if config.trust_path is not None and metadata["exists"]:
        from memory_vault_trust import TrustError, TrustStore
        try:
            result["registry_summary"] = TrustStore(config.trust_path).status()
        except TrustError as exc:
            raise MemoryError(exc.code) from None
    return result


def _database_status(config: Any) -> Mapping[str, Any]:
    path = _path(config.vault_path)
    if not path.exists():
        return {"state": "not_initialized", "records": 0, "memory_bodies_read": False}
    from memory_vault_backup import database_summary, readonly_database
    deadline = time.monotonic() + MAX_DIAGNOSIS_SECONDS
    with readonly_database(path, deadline) as connection:
        summary = database_summary(connection)
        # These are present-day registry checks of previously admitted signer
        # IDs, not cryptographic re-verification of unseen memory bodies.
        active = blocked = 0
        if config.trust_path is not None:
            from memory_vault_trust import TrustError, TrustStore
            store = TrustStore(config.trust_path)
            for row in connection.execute("SELECT signer_key_id,COUNT(*) FROM record_admissions WHERE state='verified' GROUP BY signer_key_id"):
                try:
                    store.require_trusted(row[0])
                    active += int(row[1])
                except TrustError:
                    blocked += int(row[1])
        return {"state": "metadata_readable", **summary,
                "records": summary["counts"]["memories"],
                "derived_index": {"present": True, "terms": summary["counts"]["terms"],
                                  "content_consistency_checked": False},
                "currently_registered_verified_records": active if config.trust_path is not None else None,
                "currently_blocked_verified_records": blocked if config.trust_path is not None else None,
                "current_registry_checked": config.trust_path is not None,
                "signature_crypto_rechecked": False, "memory_bodies_read": False,
                "integrity_scan_run": False, "database_modified": False}


def doctor(config_path: Path) -> Mapping[str, Any]:
    """Read selected configuration, aggregate metadata and queue inventories.

    This does not call Vault._connect/handle, initialize or upgrade a database,
    read an identity, parse queue bodies, repair anything or contact a network.
    SQLite mode=ro still uses ordinary database read locks/WAL coordination.
    """
    result: dict[str, Any] = {"schema_version": DOCTOR_SCHEMA, "state": "ok",
        "read_only": True, "memory_bodies_read": False, "private_keys_loaded": False,
        "database_modified": False, "network_accessed": False, "issues": []}
    try:
        config = _config(_path(config_path))
    except (MemoryError, OSError) as exc:
        result["state"] = "attention_required"
        result["issues"].append({"component": "configuration", "code": getattr(exc, "code", "configuration_unavailable")})
        return result
    result["configuration"] = {"loaded": True, "capture_visible_turns": config.capture_visible_turns,
                               "signing_configured": config.identity_path is not None,
                               "trust_configured": config.trust_path is not None}
    for component, operation in (("database", _database_status), ("signing", _trust_status), ("lifecycle", _lifecycle_status)):
        try:
            result[component] = operation(config)
        except (MemoryError, OSError, sqlite3.Error, ValueError) as exc:
            code = getattr(exc, "code", "metadata_unavailable")
            result[component] = {"state": "unavailable", "code": code}
            result["issues"].append({"component": component, "code": code})
    signing = result.get("signing", {})
    for name in ("identity", "registry"):
        entry = signing.get(name, {})
        if entry.get("configured") and (not entry.get("exists") or entry.get("regular_private_file") is False):
            result["issues"].append({"component": "signing", "code": "configured_" + name + "_unavailable"})
    if config.identity_path is not None and signing.get("provider_package_discoverable") is False:
        result["issues"].append({"component": "signing", "code": "signing_dependency_unavailable"})
    budget = [0]
    queues: dict[str, Any] = {}
    for group in ("prompts", "outbox", "conflicts", "done"):
        try:
            queues[group] = _queue_directory(config.state_path / group, budget)
            if queues[group].get("unsafe_entries") or queues[group].get("unexpected_entries") or queues[group].get("truncated"):
                result["issues"].append({"component": "queues", "code": "queue_inventory_needs_review", "group": group})
        except (MemoryError, OSError) as exc:
            queues[group] = {"state": "unavailable"}
            result["issues"].append({"component": "queues", "code": getattr(exc, "code", "queue_unavailable"), "group": group})
    try:
        result["host_queues"] = _host_queues(config.state_path / "hosts-v1", budget)
        if result["host_queues"].get("unsafe_entries") or result["host_queues"].get("truncated"):
            result["issues"].append({"component": "host_queues", "code": "host_queue_inventory_needs_review"})
    except (MemoryError, OSError) as exc:
        result["issues"].append({"component": "host_queues", "code": getattr(exc, "code", "queue_unavailable")})
    result["queues"] = queues
    if queues.get("outbox", {}).get("files"):
        result["issues"].append({"component": "queues", "code": "visible_turn_retry_pending"})
    if queues.get("conflicts", {}).get("files"):
        result["issues"].append({"component": "queues", "code": "visible_turn_conflict_requires_review"})
    sync_path = getattr(config, "sync_config_path", None)
    if sync_path is None:
        result["sync"] = {"configured": False, "network_accessed": False}
    else:
        try:
            from memory_vault_client import bound_sync_config
            from memory_vault_sync import status
            bound_sync_config(config)
            result["sync"] = status(sync_path)
        except (ImportError, MemoryError, OSError, ValueError) as exc:
            result["sync"] = {"configured": True, "state": "unavailable", "network_accessed": False}
            result["issues"].append({"component": "sync", "code": getattr(exc, "code", "sync_metadata_unavailable")})
    if result["issues"]:
        result["state"] = "attention_required"
    return result


def retry(config_path: Path, *, limit: int = 16) -> Mapping[str, Any]:
    """Explicitly retry only the documented local hook outbox, not conflicts."""
    if type(limit) is not int or not 1 <= limit <= 64:
        raise MemoryError("invalid_retry_limit")
    config = _config(_path(config_path))
    inventory = _queue_directory(config.state_path / "outbox", [0])
    if inventory.get("truncated") or inventory.get("unsafe_entries") or inventory.get("unexpected_entries"):
        raise MemoryError("outbox_requires_explicit_review")
    from memory_vault_client import retry_pending
    response = retry_pending(config, limit=limit)
    if response.get("ok"):
        result = dict(response["result"])
        result.update(scope="local_hook_outbox_only", conflicts_resolved=False,
                      lifecycle_requests_replayed=False, remote_delivery_confirmed=False)
        return result
    problem = response.get("error", {})
    raise MemoryError(problem.get("code", "outbox_retry_failed"), retryable=problem.get("retryable", False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="existing selected client configuration")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("doctor", help="read aggregate state only; never repair or connect")
    retry_parser = commands.add_parser("retry", help="explicitly retry the bounded local hook outbox")
    retry_parser.add_argument("--limit", type=int, default=16)
    backup_parser = commands.add_parser("backup", help="new memory-only SQLite snapshot directory; no keys/client queues")
    backup_parser.add_argument("--output", type=Path, required=True)
    backup_parser.add_argument("--timeout", type=int, default=60)
    restore_parser = commands.add_parser("restore", help="restore only to a NEW Vault file with a NEW replication identity")
    restore_parser.add_argument("--backup", type=Path, required=True)
    restore_parser.add_argument("--output", type=Path, required=True)
    restore_parser.add_argument("--trust-store", type=Path, help="independent current public-key registry for signature re-verification")
    restore_parser.add_argument("--accept-unsigned", action="store_true", help="explicitly accept previously local/accepted unsigned records, not invalid signatures")
    restore_parser.add_argument("--timeout", type=int, default=60)
    return parser


def main(argv: Sequence[str] | None = None, *, config_path: Path | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from memory_vault_client import default_config_path
        if config_path is not None and args.config is not None and _path(config_path) != _path(args.config):
            raise MemoryError("operator_config_conflict")
        selected = _path(config_path or args.config or default_config_path())
        if args.action == "doctor":
            result = doctor(selected)
        elif args.action == "retry":
            result = retry(selected, limit=args.limit)
        elif args.action == "backup":
            from memory_vault_backup import backup_database
            config = _config(selected)
            output = _path(args.output)
            if output == config.state_path or config.state_path in output.parents:
                raise MemoryError("backup_must_not_be_client_state")
            result = backup_database(config.vault_path, output, timeout=args.timeout)
        else:
            from memory_vault_backup import restore_database
            # Recovery does not require a surviving old config, and never
            # changes it. Current trust is used only when explicitly selected.
            result = restore_database(args.backup, args.output, trust_store=args.trust_store,
                                      accept_unsigned=args.accept_unsigned, timeout=args.timeout)
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except sqlite3.Error:
        write_response(failure("operator_database_unavailable", retryable=True))
    except (ImportError, OSError, ValueError):
        write_response(failure("operator_action_unavailable"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
