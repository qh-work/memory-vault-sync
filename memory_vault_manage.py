#!/usr/bin/env python3
"""Operator-visible diagnostics, bounded local retry and explicit recovery.

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
    if os.name == "nt":
        from memory_vault_storage import open_file
        try:
            descriptor = open_file(selected, os.O_RDONLY, private=True)
            os.close(descriptor)
            protected = True
        except OSError:
            protected = False
    return {"configured": True, "exists": True, "bytes": info.st_size,
            "regular_private_file": protected, "contents_read": False}


def _queue_directory(path: Path, budget: list[int]) -> dict[str, Any]:
    selected = _path(path)
    if not selected.exists():
        return {"exists": False, "files": 0, "bytes": 0, "bounded": True}
    info = selected.lstat()
    if not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise MemoryError("unsafe_operator_queue")
    if os.name == "nt":
        from memory_vault_storage import check_private_directory
        check_private_directory(selected)
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
            if os.name == "nt" and _file_metadata(Path(entry.path))["regular_private_file"] is not True:
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
    from memory_vault_storage import check_private_directory
    check_private_directory(root)
    pending = bytes_pending = sessions = unsafe = 0
    truncated = False
    with os.scandir(root) as hosts:
        for host in hosts:
            budget[0] += 1
            if budget[0] > MAX_DISCOVERY:
                truncated = True
                break
            if not host.is_dir(follow_symlinks=False) or host.name not in {"generic", "claude-code", "gemini-cli"}:
                unsafe += 1
                continue
            check_private_directory(Path(host.path))
            with os.scandir(host.path) as entries:
                for session in entries:
                    budget[0] += 1
                    if budget[0] > MAX_DISCOVERY:
                        truncated = True
                        break
                    if not session.is_dir(follow_symlinks=False) or re.fullmatch(r"[0-9a-f]{64}", session.name) is None:
                        unsafe += 1
                        continue
                    check_private_directory(Path(session.path))
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


def retry_compat(config_path: Path, *, limit: int = 4) -> Mapping[str, Any]:
    """Retry preserved exact compatibility intents, without a sync window."""
    if type(limit) is not int or not 1 <= limit <= 16:
        raise MemoryError("invalid_retry_limit")
    from memory_vault_compat import flush_local
    result = dict(flush_local(_path(config_path), limit=limit))
    result.update(scope="local_compat_intents_only", conflicts_resolved=False,
                  semantic_proposals_reconstructed=False, worker_started=False,
                  remote_delivery_confirmed=False)
    return result


def retry_host(config_path: Path, *, host: str, session_key: str) -> Mapping[str, Any]:
    """Resume one explicitly selected hashed host session's exact saved jobs."""
    from memory_vault_hosts import HOST_EVENTS, HostSession
    if host not in HOST_EVENTS or not isinstance(session_key, str) or re.fullmatch(r"[0-9a-f]{64}", session_key) is None:
        raise MemoryError("explicit_host_session_required")
    config = _config(_path(config_path))
    if not config.capture_visible_turns:
        raise MemoryError("automatic_capture_disabled")
    session = HostSession(config, host, session_key)
    if not session.root.exists():
        raise MemoryError("host_recovery_session_missing")
    with session.locked():
        result = dict(session.recover())
    result.update(scope="one_local_host_session", input_without_final_invented=False,
                  network_accessed=False, background_sync_may_run=config.sync_config_path is not None,
                  remote_delivery_confirmed=False)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="existing selected client configuration")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("doctor", help="read aggregate state only; never repair or connect")
    retry_parser = commands.add_parser("retry", help="explicitly retry the bounded local hook outbox")
    retry_parser.add_argument("--limit", type=int, default=16)
    retry_parser.add_argument("--scope", choices=("hooks", "compat", "hosts"), default="hooks")
    retry_parser.add_argument("--host", choices=("generic", "claude-code", "gemini-cli"))
    retry_parser.add_argument("--session-key", help="explicit local hashed session from the recovery inventory")
    backup_parser = commands.add_parser("backup", help="new memory-only SQLite snapshot directory; no keys/client queues")
    backup_parser.add_argument("--output", type=Path, required=True)
    backup_parser.add_argument("--timeout", type=int, default=60)
    restore_parser = commands.add_parser("restore", help="restore only to a NEW Vault file with a NEW replication identity")
    restore_parser.add_argument("--backup", type=Path, required=True)
    restore_parser.add_argument("--output", type=Path, required=True)
    restore_parser.add_argument("--trust-store", type=Path, help="independent current public-key registry for signature re-verification")
    restore_parser.add_argument("--accept-unsigned", action="store_true", help="explicitly accept previously local/accepted unsigned records, not invalid signatures")
    restore_parser.add_argument("--timeout", type=int, default=60)
    client_backup = commands.add_parser("backup-client", help="explicitly selected offline client snapshot; no keys or execution authority")
    client_backup.add_argument("--output", type=Path, required=True)
    client_backup.add_argument("--include", nargs="+", choices=("hooks", "lifecycle", "hosts", "compat", "sync"), required=True)
    client_backup.add_argument("--quiesced", action="store_true", help="operator confirms all client/Vault writers and workers have been stopped")
    client_backup.add_argument("--timeout", type=int, default=60)
    client_restore = commands.add_parser("restore-client", help="restore memory and inert client evidence to a NEW directory; no pending replay")
    client_restore.add_argument("--backup", type=Path, required=True)
    client_restore.add_argument("--output", type=Path, required=True)
    client_restore.add_argument("--trust-store", type=Path, help="independent current public-key registry, never an archived policy")
    client_restore.add_argument("--accept-unsigned", action="store_true")
    client_restore.add_argument("--timeout", type=int, default=60)
    inspection = commands.add_parser("review-recovery", help="bounded content-free inventory of restored evidence; never approval or replay")
    inspection.add_argument("--recovery", type=Path, required=True)
    inspection.add_argument("--component", choices=("memory", "hooks", "lifecycle", "hosts", "compat", "sync"))
    inspection.add_argument("--offset", type=int, default=0)
    inspection.add_argument("--limit", type=int, default=50)
    inspection.add_argument("--timeout", type=int, default=60)
    activation = commands.add_parser("activate-recovery", help="explicitly prepare NEW local-only capture state; does not invoke pending work")
    activation.add_argument("--recovery", type=Path, required=True)
    activation.add_argument("--output", type=Path, required=True, help="NEW client configuration file, with a NEW sibling .state directory")
    activation.add_argument("--include", nargs="+", choices=("hooks", "lifecycle", "hosts", "compat"), required=True)
    activation.add_argument("--authorize-local-resume", action="store_true", help="independent operator opt-in to subsequent local capture/retry")
    activation.add_argument("--identity", type=Path, help="independently selected signing identity; never copied or read during activation")
    activation.add_argument("--trust-store", type=Path)
    activation.add_argument("--allow-unsigned-local", action="store_true", help="explicitly permit unsigned new local saves if the old client used signing")
    activation.add_argument("--timeout", type=int, default=60)
    memory_import = commands.add_parser("import-recovery", help="reverify one complete archived signed capsule/group and admit locally; no old sync permission")
    memory_import.add_argument("--recovery", type=Path, required=True)
    memory_import.add_argument("--entry-id", required=True, help="exact signed-capsule candidate from review-recovery")
    memory_import.add_argument("--trust-store", type=Path, required=True)
    memory_import.add_argument("--authorize-memory-import", action="store_true")
    memory_import.add_argument("--timeout", type=int, default=60)
    return parser


def main(argv: Sequence[str] | None = None, *, config_path: Path | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from memory_vault_client import default_config_path
        if config_path is not None and args.config is not None and _path(config_path) != _path(args.config):
            raise MemoryError("operator_config_conflict")
        # Restore/review/import must work after loss of the old configuration,
        # including a stale default-config environment variable. Only commands
        # operating on an existing selected client resolve that default.
        selected = _path(config_path or args.config or default_config_path()) if args.action in {"doctor", "retry", "backup", "backup-client"} else None
        if args.action == "doctor":
            result = doctor(selected)
        elif args.action == "retry":
            if args.scope == "compat":
                result = retry_compat(selected, limit=args.limit)
            elif args.scope == "hosts":
                result = retry_host(selected, host=args.host, session_key=args.session_key)
            else:
                result = retry(selected, limit=args.limit)
        elif args.action == "backup":
            from memory_vault_backup import backup_database
            config = _config(selected)
            output = _path(args.output)
            if output == config.state_path or config.state_path in output.parents:
                raise MemoryError("backup_must_not_be_client_state")
            result = backup_database(config.vault_path, output, timeout=args.timeout)
        elif args.action == "restore":
            from memory_vault_backup import restore_database
            # Recovery does not require a surviving old config, and never
            # changes it. Current trust is used only when explicitly selected.
            result = restore_database(args.backup, args.output, trust_store=args.trust_store,
                                      accept_unsigned=args.accept_unsigned, timeout=args.timeout)
        else:
            import memory_vault_recovery as recovery
            if args.action == "backup-client":
                result = recovery.backup_client(selected, args.output, include=args.include, quiesced=args.quiesced, timeout=args.timeout)
            elif args.action == "restore-client":
                result = recovery.restore_client(args.backup, args.output, trust_store=args.trust_store,
                                                 accept_unsigned=args.accept_unsigned, timeout=args.timeout)
            elif args.action == "review-recovery":
                result = recovery.review_recovery(args.recovery, component=args.component, offset=args.offset, limit=args.limit, timeout=args.timeout)
            elif args.action == "activate-recovery":
                result = recovery.activate_recovery(args.recovery, args.output, include=args.include,
                    authorize_local_resume=args.authorize_local_resume, identity=args.identity,
                    trust_store=args.trust_store, allow_unsigned_local=args.allow_unsigned_local, timeout=args.timeout)
            elif args.action == "import-recovery":
                result = recovery.import_recovery(args.recovery, entry_id=args.entry_id, trust_store=args.trust_store,
                    authorize_memory_import=args.authorize_memory_import, timeout=args.timeout)
            else:
                raise MemoryError("unsupported_operator_action")
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except sqlite3.Error:
        write_response(failure("operator_database_unavailable", retryable=True))
    except OSError as exc:
        write_response(failure(getattr(exc, "code", "operator_action_unavailable"), retryable=getattr(exc, "retryable", False)))
    except (ImportError, ValueError, KeyError, TypeError) as exc:
        # TrustError is a content-free ValueError with a documented code.
        write_response(failure(getattr(exc, "code", "operator_action_unavailable")))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
