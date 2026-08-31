#!/usr/bin/env python3
"""Stable, standard-library bootstrap for an explicitly managed installation.

Copied once to the chosen installation root as launcher.py. It never downloads,
installs, enrolls trust or alters host permissions. Each invocation selects one
locally activated, inventory-checked immutable runtime. Hooks still require the
host's ordinary trust review.
"""

from __future__ import annotations

import sys

# Even a caller that omitted -I/-B must not redirect later runtime imports to
# an unchecked external bytecode cache. This does not undo Python startup/site
# code; the documented invocation still uses isolated -I -B startup.
sys.dont_write_bytecode = True
sys.pycache_prefix = None

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import types


MAX_FILE = 2 * 1024 * 1024
MAX_PACKAGE = 32 * 1024 * 1024
TRUSTED_STORAGE_SHA256 = None
_NATIVE_STORAGE = None


def _plain(path: Path) -> None:
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("symlink_in_managed_runtime")
    item = path.lstat()
    if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
            or (os.name != "nt" and (item.st_uid != os.geteuid() or item.st_mode & 0o077))):
        raise ValueError("unsafe_managed_runtime_file")
    if int(getattr(item, "st_file_attributes", 0)) & 0x0400:
        raise ValueError("reparse_point_in_managed_runtime")


def _read(path: Path, maximum: int) -> bytes:
    _plain(path)
    if os.name == "nt" and _NATIVE_STORAGE is not None:
        descriptor = _NATIVE_STORAGE.open_file(path, os.O_RDONLY, private=True)
    else:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        named = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError("managed_file_changed")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size
                or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise ValueError("managed_file_changed")
    return data


def _load_native_storage(root: Path) -> None:
    """Load only the source hash pinned by the explicit initializer.

    No search path/import cache, active pointer, packet or release metadata can
    select this bootstrap dependency. It is copied from the reviewed installer
    once; bootstrap upgrades require an explicit new managed installation.
    """
    global _NATIVE_STORAGE
    if os.name != "nt":
        return
    if not isinstance(TRUSTED_STORAGE_SHA256, str) or re.fullmatch(r"[0-9a-f]{64}", TRUSTED_STORAGE_SHA256) is None:
        raise ValueError("managed_native_storage_not_pinned")
    path = root / "managed_storage.py"
    raw = _read(path, MAX_FILE)
    if hashlib.sha256(raw).hexdigest() != TRUSTED_STORAGE_SHA256:
        raise ValueError("managed_native_storage_changed")
    module = types.ModuleType("_memory_vault_bootstrap_storage")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    module.check_private_directory(root)
    descriptor = module.open_file(path, os.O_RDONLY, private=True)
    os.close(descriptor)
    _NATIVE_STORAGE = module


def _json(raw: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("duplicate_managed_state_key")
            value[key] = child
        return value
    def reject_constant(_value: str) -> None:
        raise ValueError("invalid_managed_json")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)


def main() -> int:
    root = Path(__file__).absolute().parent
    try:
        _load_native_storage(root)
        _plain(Path(__file__).absolute())
        if os.name == "nt":
            descriptor = _NATIVE_STORAGE.open_file(Path(__file__).absolute(), os.O_RDONLY, private=True)
            os.close(descriptor)
        active = _json(_read(root / "active.json", 64 * 1024))
        if (not isinstance(active, dict) or set(active) != {"schema_version", "generation", "current", "previous"}
                or active["schema_version"] != "memory-vault-managed-active/v1"
                or type(active["generation"]) is not int or active["generation"] < 1):
            raise ValueError("invalid_managed_activation")
        current = active["current"]
        if (not isinstance(current, dict)
                or set(current) != {"version", "archive_sha256", "inventory_sha256", "source_commit", "host_contract_sha256", "publisher_verified"}
                or not isinstance(current["version"], str)
                or re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", current["version"]) is None
                or any(not isinstance(current[key], str) or re.fullmatch(r"[0-9a-f]{64}", current[key]) is None
                       for key in ("archive_sha256", "inventory_sha256", "host_contract_sha256"))
                or not isinstance(current["source_commit"], str)
                or re.fullmatch(r"[0-9a-f]{40}", current["source_commit"]) is None
                or type(current["publisher_verified"]) is not bool):
            raise ValueError("invalid_managed_target")
        directory = root / "releases" / current["archive_sha256"]
        raw = _read(directory / "INVENTORY.json", 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != current["inventory_sha256"]:
            raise ValueError("managed_inventory_changed")
        inventory = _json(raw)
        if (not isinstance(inventory, dict) or set(inventory) != {"schema_version", "archive_sha256", "files"}
                or inventory["schema_version"] != "memory-vault-managed-inventory/v1"
                or inventory["archive_sha256"] != current["archive_sha256"]
                or not isinstance(inventory["files"], dict) or not 1 <= len(inventory["files"]) <= 512):
            raise ValueError("invalid_managed_inventory")
        prefix = "memory-vault-client-v" + current["version"] + "/"
        total = 0
        for name, digest in inventory["files"].items():
            if (not isinstance(name, str) or not name.startswith(prefix) or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                    or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
                raise ValueError("invalid_managed_inventory_entry")
            content = _read(directory.joinpath(*name.split("/")), MAX_FILE)
            total += len(content)
            if total > MAX_PACKAGE or hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("managed_runtime_changed")
        runtime_relative = prefix + "plugins/memory-vault-client/runtime/"
        entry_relative = runtime_relative + "memory_vault_client.py"
        if entry_relative not in inventory["files"]:
            raise ValueError("managed_client_entry_missing")
        runtime = directory.joinpath(*runtime_relative.rstrip("/").split("/"))
        expected_runtime = {name[len(runtime_relative):] for name in inventory["files"]
                            if name.startswith(runtime_relative)}
        # dont_write_bytecode does not disable *reading* cached code. Refuse
        # unlisted cache directories too; never execute unchecked pyc bytes.
        if {path.name for path in runtime.iterdir()} != expected_runtime:
            raise ValueError("unexpected_managed_runtime_file")
        # A locally approved active pointer grants no new process permissions.
        # The runtime sees this only to honor an independently enabled updater.
        os.environ["MEMORY_VAULT_MANAGED_ROOT"] = str(root)
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(runtime))
        entry = runtime / "memory_vault_client.py"
        sys.argv[0] = str(entry)
        runpy.run_path(str(entry), run_name="__main__")
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print("Memory Vault managed runtime unavailable; inspect the installation or select a retained version.", file=sys.stderr)
        if "hook" in sys.argv[1:]:
            print(json.dumps({"systemMessage": "Memory Vault managed runtime unavailable; no capture confirmation."}))
            return 0
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
