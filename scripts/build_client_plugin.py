#!/usr/bin/env python3
"""Build a new optional client plugin from authoritative source; never install it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys


REQUIRED_MODULES = (
    "memory_vault.py", "memory_vault_client.py", "memory_vault_lifecycle.py", "memory_vault_trust.py",
    "memory_vault_transfer.py", "memory_vault_sync.py", "memory_vault_remote.py",
    "memory_vault_hosts.py", "memory_vault_manage.py", "memory_vault_backup.py",
    "memory_vault_update.py", "memory_vault_pack.py", "memory_vault_privacy.py",
)
OPTIONAL_MODULES = ("memory_vault_migrate.py",)
PACKAGE_DOCUMENTS = (
    "LICENSE", "NOTICE", "SECURITY.md", "PROTOCOL.md", "requirements-integrations.txt",
    "docs/CLIENTS.md", "docs/LIFECYCLE.md", "docs/IMPLEMENTERS.md", "docs/TRUST.md",
    "docs/TRANSFER.md", "docs/MIGRATION.md", "docs/STATUS.md", "docs/RELEASE.md",
    "docs/REVIEW_HANDOFF.md", "AI_START_HERE.md", "llms.txt", ".well-known/agent-memory.json",
    "docs/TWO_MODES.md", "docs/SYNC.md", "docs/REMOTE_BACKENDS.md", "docs/HOSTS.md",
    "docs/OPERATIONS.md", "docs/BACKUP.md", "docs/PARITY.md", "docs/UPDATES.md", "docs/PACKS.md",
)
TEMPLATE_FILES = (
    ".codex-plugin/plugin.json", ".mcp.json", "hooks/hooks.json",
    "scripts/launcher.py", "README.md",
)


def plain(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents)


def build(output: Path) -> Path:
    root = Path(__file__).absolute().parent.parent
    template = root / "plugins" / "memory-vault-client"
    destination = output.expanduser()
    if not destination.is_absolute() or ".." in destination.parts or destination.name != "memory-vault-client":
        raise ValueError("output_must_be_new_absolute_memory_vault_client_directory")
    if any(path.is_symlink() for path in (destination, *destination.parents)):
        raise ValueError("symlink_output_forbidden")
    if destination.exists():
        raise ValueError("output_exists")
    modules = list(REQUIRED_MODULES)
    if any(not plain(root / name) for name in modules):
        raise ValueError("required_source_module_missing")
    for name in OPTIONAL_MODULES:
        if (root / name).exists():
            if not plain(root / name):
                raise ValueError("unsafe_source_module")
            modules.append(name)
    # Copy the release allowlist, never arbitrary files from a working folder.
    source_files = [(template / name, Path(name)) for name in TEMPLATE_FILES]
    if any(not plain(source) for source, _ in source_files):
        raise ValueError("required_template_file_missing")
    for name in PACKAGE_DOCUMENTS:
        if not plain(root / name):
            raise ValueError("required_package_document_missing")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o755)  # exclusive: never replace another package
    # If interrupted, the directory is intentionally retained for inspection.
    # The launcher refuses an incomplete runtime (MANIFEST.json is written last).
    for source, relative in source_files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for name in PACKAGE_DOCUMENTS:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
    for directory in ("schemas", "examples/protocol", "adapters"):
        for source in sorted((root / directory).rglob("*")):
            if source.is_dir() and not source.is_symlink():
                continue
            if not plain(source) or source.suffix not in {".json", ".ndjson", ".md"}:
                raise ValueError("unsafe_protocol_document")
            if source.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("protocol_document_too_large")
            target = destination / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    runtime = destination / "runtime"
    runtime.mkdir()
    hashes = {}
    for name in modules:
        data = (root / name).read_bytes()
        if len(data) > 1024 * 1024:
            raise ValueError("source_module_too_large")
        with (runtime / name).open("xb") as stream:
            stream.write(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    inventory = {"schema_version": "memory-vault-client-runtime/v1", "modules": hashes}
    with (runtime / "MANIFEST.json").open("x", encoding="utf-8") as stream:
        json.dump(inventory, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new absolute directory ending in memory-vault-client")
    args = parser.parse_args()
    try:
        path = build(args.output)
    except (OSError, ValueError):
        print("Plugin build failed. Existing paths are never replaced; inspect any new incomplete output before retrying.", file=sys.stderr)
        return 1
    print(json.dumps({"state": "built_not_installed", "path": str(path), "runtime_inventory_is_publisher_signature": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
