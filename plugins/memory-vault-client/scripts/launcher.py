#!/usr/bin/env python3
"""Launch only the source-built, inventory-checked local client runtime."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys


ALLOWED_MODULES = {
    "memory_vault.py", "memory_vault_client.py", "memory_vault_lifecycle.py", "memory_vault_trust.py",
    "memory_vault_transfer.py", "memory_vault_migrate.py",
    "memory_vault_sync.py", "memory_vault_remote.py", "memory_vault_privacy.py",
    "memory_vault_hosts.py", "memory_vault_manage.py", "memory_vault_backup.py",
    "memory_vault_update.py", "memory_vault_pack.py",
    "memory_vault_update_trust.py", "memory_vault_install.py", "memory_vault_managed_launcher.py",
    "memory_vault_compat.py",
    "memory_vault_recovery.py", "memory_vault_legacy_pack.py", "memory_vault_metadata.py", "memory_vault_storage.py",
    "memory_vault_sharing.py", "memory_vault_crypto.py", "memory_vault_device_trust.py", "memory_vault_encrypted_replication.py",
    "memory_vault_capture.py", "memory_vault_dependency.py",
    "memory_vault_credentials.py", "memory_vault_file_copy.py", "memory_vault_artifact_catalog.py",
    "memory_vault_artifacts.py", "memory_vault_drive.py",
    "memory_vault_agent.py", "memory_vault_network.py", "memory_vault_network_crypto.py",
    "memory_vault_network_control.py", "memory_vault_network_admin.py", "memory_vault_relay.py",
    "memory_vault_network_worker.py", "memory_vault_nodes.py", "memory_vault_node.py",
    "memory_vault_network_recovery.py", "memory_vault_node_transfer.py",
    "memory_vault_topics.py", "memory_vault_topic_store.py",
}
REQUIRED_MODULES = ALLOWED_MODULES
MAX_MODULE_BYTES = 1024 * 1024


def _regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents)


def _read(path: Path, maximum: int) -> bytes:
    if not _regular(path):
        raise ValueError("invalid_runtime_file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
            raise ValueError("invalid_runtime_file")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        named = path.lstat()
        if (len(data) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or (named.st_dev, named.st_ino, named.st_size) != (before.st_dev, before.st_ino, before.st_size)
                or not stat.S_ISREG(named.st_mode)):
            raise ValueError("runtime_file_changed")
        return data


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_inventory_key")
        result[key] = value
    return result


def main() -> int:
    root = Path(__file__).absolute().parent.parent
    runtime = root / "runtime"
    manifest = runtime / "MANIFEST.json"
    try:
        if not _regular(Path(__file__).absolute()):
            raise ValueError("runtime_not_built")
        inventory = json.loads(_read(manifest, 16 * 1024).decode("utf-8"), object_pairs_hook=_unique)
        if not isinstance(inventory, dict) or set(inventory) != {"schema_version", "modules"} or inventory["schema_version"] != "memory-vault-client-runtime/v1":
            raise ValueError("invalid_runtime_inventory")
        modules = inventory["modules"]
        if not isinstance(modules, dict) or not REQUIRED_MODULES.issubset(modules) or set(modules) - ALLOWED_MODULES:
            raise ValueError("invalid_runtime_modules")
        # Source hashes do not authenticate an unchecked bytecode cache or an
        # extra module. A source-built runtime has exactly this flat inventory.
        if {path.name for path in runtime.iterdir()} != set(modules) | {"MANIFEST.json"}:
            raise ValueError("unexpected_runtime_file")
        for name, expected in modules.items():
            path = runtime / name
            if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                raise ValueError("invalid_runtime_hash")
            if hashlib.sha256(_read(path, MAX_MODULE_BYTES)).hexdigest() != expected:
                raise ValueError("runtime_hash_mismatch")
        entry = runtime / "memory_vault_client.py"
        sys.dont_write_bytecode = True
        sys.pycache_prefix = None
        sys.path.insert(0, str(runtime))
        sys.argv[0] = str(entry)
        runpy.run_path(str(entry), run_name="__main__")
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        # Inventory hashes catch accidental packaging drift. They are not a
        # publisher signature and cannot authenticate a malicious replacement.
        print("Memory Vault client runtime unavailable; build/review the plugin package first.", file=sys.stderr)
        if "hook" in sys.argv[1:]:
            print(json.dumps({"systemMessage": "Memory Vault runtime unavailable; no capture confirmation."}))
            return 0
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
