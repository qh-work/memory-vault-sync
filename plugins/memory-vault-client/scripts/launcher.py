#!/usr/bin/env python3
"""Launch only the source-built, inventory-checked local client runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import runpy
import sys


ALLOWED_MODULES = {
    "memory_vault.py", "memory_vault_client.py", "memory_vault_lifecycle.py", "memory_vault_trust.py",
    "memory_vault_transfer.py", "memory_vault_migrate.py",
    "memory_vault_sync.py", "memory_vault_remote.py", "memory_vault_privacy.py",
    "memory_vault_hosts.py", "memory_vault_manage.py", "memory_vault_backup.py",
    "memory_vault_update.py", "memory_vault_pack.py",
}
REQUIRED_MODULES = ALLOWED_MODULES - {"memory_vault_migrate.py"}
MAX_MODULE_BYTES = 1024 * 1024


def _regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents)


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
        if not _regular(Path(__file__).absolute()) or not _regular(manifest) or manifest.stat().st_size > 16 * 1024:
            raise ValueError("runtime_not_built")
        inventory = json.loads(manifest.read_text(encoding="utf-8"), object_pairs_hook=_unique)
        if not isinstance(inventory, dict) or set(inventory) != {"schema_version", "modules"} or inventory["schema_version"] != "memory-vault-client-runtime/v1":
            raise ValueError("invalid_runtime_inventory")
        modules = inventory["modules"]
        if not isinstance(modules, dict) or not REQUIRED_MODULES.issubset(modules) or set(modules) - ALLOWED_MODULES:
            raise ValueError("invalid_runtime_modules")
        for name, expected in modules.items():
            path = runtime / name
            if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                raise ValueError("invalid_runtime_hash")
            if not _regular(path) or path.stat().st_size > MAX_MODULE_BYTES:
                raise ValueError("invalid_runtime_file")
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("runtime_hash_mismatch")
        entry = runtime / "memory_vault_client.py"
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
