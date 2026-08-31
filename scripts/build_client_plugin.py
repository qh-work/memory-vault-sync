#!/usr/bin/env python3
"""Build a new optional client plugin from authoritative source; never install it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from release_source import ReleaseSource


REQUIRED_MODULES = (
    "memory_vault.py", "memory_vault_client.py", "memory_vault_lifecycle.py", "memory_vault_trust.py",
    "memory_vault_transfer.py", "memory_vault_sync.py", "memory_vault_remote.py", "memory_vault_credentials.py",
    "memory_vault_hosts.py", "memory_vault_manage.py", "memory_vault_backup.py",
    "memory_vault_update.py", "memory_vault_pack.py", "memory_vault_file_copy.py", "memory_vault_privacy.py",
    "memory_vault_update_trust.py", "memory_vault_install.py", "memory_vault_managed_launcher.py",
    "memory_vault_compat.py",
    "memory_vault_recovery.py", "memory_vault_legacy_pack.py", "memory_vault_metadata.py", "memory_vault_storage.py",
    "memory_vault_sharing.py", "memory_vault_crypto.py", "memory_vault_device_trust.py", "memory_vault_encrypted_replication.py",
    "memory_vault_migrate.py",
    "memory_vault_capture.py", "memory_vault_dependency.py",
    "memory_vault_artifact_catalog.py", "memory_vault_artifacts.py", "memory_vault_drive.py",
    "memory_vault_agent.py", "memory_vault_network.py", "memory_vault_network_crypto.py",
    "memory_vault_network_control.py", "memory_vault_network_admin.py", "memory_vault_relay.py",
    "memory_vault_network_worker.py", "memory_vault_nodes.py", "memory_vault_node.py",
    "memory_vault_network_recovery.py", "memory_vault_node_transfer.py",
)
OPTIONAL_MODULES: tuple[str, ...] = ()
PACKAGE_DOCUMENTS = (
    "LICENSE", "NOTICE", "SECURITY.md", "PROTOCOL.md", "requirements-integrations.txt",
    "docs/CLIENTS.md", "docs/LIFECYCLE.md", "docs/IMPLEMENTERS.md", "docs/TRUST.md",
    "docs/TRANSFER.md", "docs/MIGRATION.md", "docs/STATUS.md", "docs/RELEASE.md",
    "docs/REVIEW_HANDOFF.md", "AI_START_HERE.md", "llms.txt", ".well-known/agent-memory.json",
    "docs/TWO_MODES.md", "docs/SYNC.md", "docs/REMOTE_BACKENDS.md", "docs/HOSTS.md",
    "docs/OPERATIONS.md", "docs/BACKUP.md", "docs/PARITY.md", "docs/UPDATES.md", "docs/PACKS.md",
    "docs/RETRIEVAL.md", "docs/GRAPH_VIEWS.md", "docs/COMPATIBILITY.md",
    "docs/LEGACY_PACKS.md", "docs/SHARING.md", "docs/ENCRYPTION.md", "docs/PLATFORMS.md",
    "docs/V0_25_PARITY_PLAN.md", "docs/V0_25_SCOPED_SMOKE.md", "docs/V0_25_FOLLOWUP_SMOKE.md", "docs/V0_25_RECOVERY_SMOKE.md", "docs/V0_25_CAPTURE_SMOKE.md", "docs/V0_25_PARITY_REPAIR_SMOKE.md", "docs/V0_25_WORKFLOW_SMOKE.md", "docs/VALIDATION.md",
    "docs/V0_25_TRANSPORT_RECOVERY_SMOKE.md",
    "docs/VISIBLE_FRAGMENTS.md",
    "docs/V0_25_RELEASE_MINIMAL.md", "docs/RELEASE_NOTES_V0_25.md",
    "docs/V0_25_PACK_CAPACITY_SMOKE.md", "docs/RELEASE_NOTES_V0_25_1.md",
    "docs/ARTIFACTS.md", "docs/V0_25_RAW_COPY_SMOKE.md",
    "requirements-network.txt", "requirements-network-server.txt", "docs/NETWORK_V1.md", "docs/NETWORK_QUICKSTART.md",
    "docs/NATIVE_DRIVE.md", "docs/RELEASE_NOTES_V0_26_ALPHA.md",
    "docs/V0_26_PLAN.md",
    "requirements-network-lock.txt", "requirements-network-server-lock.txt", "docs/DEPENDENCIES_NETWORK.md",
    "docs/NETWORK_RECOVERY.md", "docs/NETWORK_NODE_TRANSFER.md", "docs/NETWORK_TYPESCRIPT.md",
    "clients/typescript/index.ts", "clients/typescript/README.md", "clients/typescript/package.json",
    "clients/typescript/network/README.md", "clients/typescript/network/crypto.ts",
    "clients/typescript/network/control.ts", "clients/typescript/network/package.json",
    "clients/typescript/network/package-lock.json",
    "clients/typescript/network/io.ts", "clients/typescript/network/nodes.ts",
    "clients/typescript/network/peer.ts", "clients/typescript/network/records.ts",
    "clients/typescript/network/transport.ts", "clients/typescript/network/vault.ts",
    "clients/typescript/network/setup.ts",
)
TEMPLATE_FILES = (
    ".codex-plugin/plugin.json", ".mcp.json", "hooks/hooks.json",
    "scripts/launcher.py", "README.md",
)


def plain(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents)


def build(output: Path, *, source_tree: ReleaseSource | None = None) -> Path:
    root = Path(__file__).absolute().parent.parent
    verified = source_tree if source_tree is not None else ReleaseSource(root)
    if verified.root != root:
        raise ValueError("release_source_root_mismatch")
    # Build code is part of the declared source boundary too, even when these
    # helpers are not included inside the optional runtime package.
    verified.read(root / "scripts/build_client_plugin.py")
    verified.read(root / "scripts/release_source.py")
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
    protocol_sources = []
    for directory in ("schemas", "examples/protocol", "adapters"):
        for source in sorted((root / directory).rglob("*")):
            if source.is_dir() and not source.is_symlink():
                continue
            if not plain(source) or source.suffix not in {".json", ".ndjson", ".md"}:
                raise ValueError("unsafe_protocol_document")
            # This checks tracked membership before reading a candidate. An
            # ignored or untracked .ndjson is not a public example by default.
            verified.read(source)
            protocol_sources.append(source)
    for source in [*(path for path, _ in source_files), *(root / name for name in PACKAGE_DOCUMENTS),
                   *(root / name for name in modules)]:
        verified.read(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o755)  # exclusive: never replace another package
    # If interrupted, the directory is intentionally retained for inspection.
    # The launcher refuses an incomplete runtime (MANIFEST.json is written last).
    for source, relative in source_files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(verified.read(source))
    for name in PACKAGE_DOCUMENTS:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(verified.read(root / name))
    for source in protocol_sources:
        target = destination / source.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(verified.read(source))
    runtime = destination / "runtime"
    runtime.mkdir()
    hashes = {}
    for name in modules:
        data = verified.read(root / name)
        if len(data) > 1024 * 1024:
            raise ValueError("source_module_too_large")
        with (runtime / name).open("xb") as stream:
            stream.write(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    verified.assert_current()
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
    print(json.dumps({"state": "built_not_installed", "path": str(path),
                      "source_commit_verified": True, "source_tree_matching": True,
                      "runtime_inventory_is_publisher_signature": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
