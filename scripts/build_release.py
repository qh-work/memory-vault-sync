#!/usr/bin/env python3
"""Package the public protocol and optional client without running the application."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Mapping
import zipfile

from build_client_plugin import (
    OPTIONAL_MODULES,
    PACKAGE_DOCUMENTS,
    REQUIRED_MODULES,
    TEMPLATE_FILES,
    build as build_plugin,
    plain,
)
from release_source import ReleaseSource, SourceError


ROOT = Path(__file__).absolute().parent.parent
PROTOCOL_DOCUMENTS = (
    "LICENSE", "NOTICE", "PROTOCOL.md", "docs/IMPLEMENTERS.md",
    "docs/LIFECYCLE.md", "docs/TRUST.md", "docs/TRANSFER.md", "SECURITY.md",
    "docs/CLIENTS.md", "docs/MIGRATION.md", "docs/REVIEW_HANDOFF.md",
    "AI_START_HERE.md", "llms.txt", ".well-known/agent-memory.json", "docs/TWO_MODES.md",
    "docs/STATUS.md", "docs/RELEASE.md", "docs/SYNC.md", "docs/REMOTE_BACKENDS.md",
    "docs/HOSTS.md", "docs/OPERATIONS.md", "docs/BACKUP.md", "docs/PARITY.md",
    "docs/UPDATES.md", "docs/PACKS.md",
    "docs/RETRIEVAL.md", "docs/GRAPH_VIEWS.md", "docs/COMPATIBILITY.md",
    "docs/LEGACY_PACKS.md", "docs/SHARING.md", "docs/ENCRYPTION.md", "docs/PLATFORMS.md",
    "docs/V0_25_PARITY_PLAN.md", "docs/V0_25_SCOPED_SMOKE.md", "docs/V0_25_FOLLOWUP_SMOKE.md", "docs/V0_25_RECOVERY_SMOKE.md", "docs/V0_25_CAPTURE_SMOKE.md", "docs/V0_25_PARITY_REPAIR_SMOKE.md", "docs/V0_25_WORKFLOW_SMOKE.md", "docs/VALIDATION.md",
    "docs/V0_25_TRANSPORT_RECOVERY_SMOKE.md",
    "docs/VISIBLE_FRAGMENTS.md",
    "docs/V0_25_RELEASE_MINIMAL.md", "docs/RELEASE_NOTES_V0_25.md",
    "docs/V0_25_PACK_CAPACITY_SMOKE.md", "docs/RELEASE_NOTES_V0_25_1.md",
    "docs/ARTIFACTS.md", "docs/V0_25_RAW_COPY_SMOKE.md",
    "docs/NETWORK_V1.md", "docs/NETWORK_QUICKSTART.md", "docs/NATIVE_DRIVE.md", "docs/RELEASE_NOTES_V0_26_ALPHA.md",
    "docs/V0_26_PLAN.md",
    "docs/DEPENDENCIES_NETWORK.md",
    "docs/NETWORK_RECOVERY.md", "docs/NETWORK_NODE_TRANSFER.md",
)
# Each executable network review fixture is selected deliberately. A matching
# filename alone never enrolls a new local test into the public review kit.
NETWORK_REVIEW_TESTS = (
    "tests/test_network_agent.py", "tests/test_network_admin.py", "tests/test_network_client.py",
    "tests/test_network_cloud_compat.py", "tests/test_network_crypto.py", "tests/test_network_http.py",
    "tests/test_network_node_runtime.py", "tests/test_network_node_setup.py", "tests/test_network_node_transfer.py",
    "tests/test_network_nodes.py", "tests/test_network_packaging.py",
    "tests/test_network_recovery.py", "tests/test_network_relay.py", "tests/test_network_typescript.py",
    "tests/test_network_typescript_crypto.py", "tests/test_network_typescript_control.py",
    "tests/test_network_worker.py",
)
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_BYTES = 32 * 1024 * 1024


def read_public(path: Path, *, source_tree: ReleaseSource | None = None) -> bytes:
    if source_tree is not None:
        return source_tree.read(path)
    if not plain(path) or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("unsafe_or_oversized_public_source")
    return path.read_bytes()


def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def parse_json(data: bytes) -> object:
    def invalid_constant(value: str) -> None:
        raise ValueError("non_json_constant")
    return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates,
                      parse_constant=invalid_constant)


def public_protocol_files(source_tree: ReleaseSource) -> list[Path]:
    files: list[Path] = []
    for name in ("schemas", "examples/protocol", "adapters"):
        directory = ROOT / name
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError("missing_protocol_material")
        for source in sorted(directory.rglob("*")):
            if source.is_symlink():
                raise ValueError("symlink_protocol_material")
            if source.is_dir():
                continue
            if source.suffix not in {".json", ".md", ".ndjson"}:
                raise ValueError("unexpected_protocol_material")
            read_public(source, source_tree=source_tree)
            files.append(source)
    if not any(path.suffix == ".ndjson" for path in files):
        raise ValueError("missing_synthetic_interchange_example")
    return files


def review_sources(material: list[Path], source_tree: ReleaseSource) -> list[Path]:
    """A separate, explicitly executable review kit; never part of protocol-only."""
    paths = [ROOT / name for name in (*REQUIRED_MODULES, *OPTIONAL_MODULES)]
    paths.extend(ROOT / name for name in set(PROTOCOL_DOCUMENTS) | set(PACKAGE_DOCUMENTS))
    paths.extend(ROOT / "plugins/memory-vault-client" / name for name in TEMPLATE_FILES)
    paths.extend(ROOT / name for name in (
        "scripts/build_client_plugin.py", "scripts/build_release.py", "scripts/release_source.py",
        "scripts/verify_client_package.py",
        "packaging/marketplace.json", "packaging/PROTOCOL_README.md", "packaging/CLIENT_README.md",
        "tests/test_memory_vault.py", "tests/test_release_source_gate.py", "packaging/REVIEW_README.md",
    ))
    paths.extend(sorted((ROOT / "tests").glob("test_v025_*.py")))
    paths.extend(ROOT / name for name in NETWORK_REVIEW_TESTS)
    paths.extend(ROOT / "examples/network-interop" / name for name in ("README.md", "package.json", "package-lock.json", "interop.ts"))
    paths.extend(material)
    result = sorted(set(paths))
    if not any(path.name == "test_v025_install.py" for path in result):
        raise ValueError("missing_v025_review_material")
    for source in result:
        read_public(source, source_tree=source_tree)
    return result


def inspect_sources(material: list[Path], review: list[Path], source_tree: ReleaseSource) -> tuple[str, dict[str, int]]:
    modules = [ROOT / name for name in (*REQUIRED_MODULES, *OPTIONAL_MODULES)]
    modules.extend(sorted((ROOT / "scripts").glob("*.py")))
    modules.append(ROOT / "plugins/memory-vault-client/scripts/launcher.py")
    modules.extend(path for path in review if path.suffix == ".py")
    python_count = json_count = frame_count = 0
    version = None
    for source in dict.fromkeys(modules):
        tree = ast.parse(read_public(source, source_tree=source_tree), filename=source.name)
        python_count += 1
        if source == ROOT / "memory_vault.py":
            for node in tree.body:
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == "VERSION"
                    for target in node.targets
                ) and isinstance(node.value, ast.Constant):
                    version = node.value.value
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("invalid_release_version")
    json_sources = [
        ROOT / "packaging/marketplace.json",
        ROOT / ".well-known/agent-memory.json",
        *(ROOT / "plugins/memory-vault-client" / name for name in TEMPLATE_FILES if name.endswith(".json")),
        *(path for path in material if path.suffix == ".json"),
        *sorted((ROOT / "adapters").rglob("*.json")),
        *(path for path in review if path.suffix == ".json"),
    ]
    for source in dict.fromkeys(json_sources):
        value = parse_json(read_public(source, source_tree=source_tree))
        json_count += 1
        if source.name == "plugin.json" and (
            not isinstance(value, dict) or value.get("version") != version
        ):
            raise ValueError("plugin_version_mismatch")
    for source in material:
        if source.suffix != ".ndjson":
            continue
        data = read_public(source, source_tree=source_tree)
        if not data or not data.endswith(b"\n"):
            raise ValueError("invalid_example_framing")
        for line in data.splitlines():
            if not isinstance(parse_json(line), dict):
                raise ValueError("invalid_example_frame")
            frame_count += 1
    return version, {
        "python_files_parsed": python_count,
        "json_files_parsed": json_count,
        "synthetic_ndjson_frames_parsed": frame_count,
    }


def copy_public(source: Path, destination: Path, source_tree: ReleaseSource) -> str:
    data = read_public(source, source_tree=source_tree)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    return hashlib.sha256(data).hexdigest()


def client_inventory(source_tree: ReleaseSource, material: list[Path]) -> dict[str, str]:
    """Independent expected hashes, never inferred from the staged plugin."""
    prefix = "plugins/memory-vault-client/"
    sources = {
        "README.md": ROOT / "packaging/CLIENT_README.md",
        ".agents/plugins/marketplace.json": ROOT / "packaging/marketplace.json",
        **{prefix + name: ROOT / "plugins/memory-vault-client" / name for name in TEMPLATE_FILES},
        **{prefix + name: ROOT / name for name in PACKAGE_DOCUMENTS},
        **{prefix + path.relative_to(ROOT).as_posix(): path for path in material},
    }
    modules = [*REQUIRED_MODULES, *(name for name in OPTIONAL_MODULES if (ROOT / name).exists())]
    sources.update({prefix + "runtime/" + name: ROOT / name for name in modules})
    expected = {name: hashlib.sha256(source_tree.read(source)).hexdigest() for name, source in sources.items()}
    inventory = {"schema_version": "memory-vault-client-runtime/v1",
                 "modules": {name: expected[prefix + "runtime/" + name] for name in modules}}
    encoded = (json.dumps(inventory, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    expected[prefix + "runtime/MANIFEST.json"] = hashlib.sha256(encoded).hexdigest()
    return expected


def archive(directory: Path, output: Path, expected: Mapping[str, str]) -> dict[str, object]:
    """Archive only declared source/generated bytes; reject staging pollution."""
    expected = dict(expected)
    if not 1 <= len(expected) <= 512 or any(
        not isinstance(name, str) or not name or PurePosixPath(name).is_absolute()
        or any(char in name for char in "\\:\x00") or any(part in {"", ".", ".."} for part in name.split("/"))
        or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        for name, digest in expected.items()
    ):
        raise ValueError("invalid_release_inventory")

    def check_members() -> None:
        observed = set()
        for source in directory.rglob("*"):
            if source.is_symlink():
                raise ValueError("symlink_in_release")
            if source.is_dir():
                continue
            name = source.relative_to(directory).as_posix()
            if name not in expected:
                # Do not open an unexpected file, even just to hash it.
                raise ValueError("unexpected_release_member")
            observed.add(name)
        if observed != set(expected):
            raise ValueError("missing_release_member")

    check_members()
    total = files = 0
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name, digest in sorted(expected.items()):
            data = read_public(directory / name)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("release_member_source_mismatch")
            total += len(data)
            files += 1
            if total > MAX_PACKAGE_BYTES or files > 512:
                raise ValueError("release_inventory_too_large")
            info = zipfile.ZipInfo(directory.name + "/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(info, data, compresslevel=9)
    check_members()
    # The independent declaration remains authoritative even if staging bytes
    # change after their read. Never compare an archive only to mutable staging.
    with zipfile.ZipFile(output) as package:
        names = [directory.name + "/" + name for name in expected]
        if len(package.infolist()) != len(names) or set(package.namelist()) != set(names):
            raise ValueError("archive_inventory_mismatch")
        for member in package.infolist():
            name = member.filename[len(directory.name) + 1:]
            if hashlib.sha256(package.read(member)).hexdigest() != expected[name]:
                raise ValueError("archive_byte_mismatch")
    data = output.read_bytes()
    return {"name": output.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "files": files}


def build(output: Path, source_commit: str) -> dict[str, object]:
    destination = output.expanduser()
    if not destination.is_absolute() or ".." in destination.parts:
        raise ValueError("output_must_be_new_absolute_directory")
    if any(path.is_symlink() for path in (destination, *destination.parents)):
        raise ValueError("symlink_output_forbidden")
    if destination.exists():
        raise ValueError("output_exists")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SourceError("release_source_commit_not_current_head")
    source_tree = ReleaseSource(ROOT, source_commit)
    material = public_protocol_files(source_tree)
    review_material = review_sources(material, source_tree)
    version, checks = inspect_sources(material, review_material, source_tree)
    for name in set(PROTOCOL_DOCUMENTS) | set(PACKAGE_DOCUMENTS) | {
        "packaging/PROTOCOL_README.md", "packaging/CLIENT_README.md",
        "packaging/marketplace.json",
    }:
        read_public(ROOT / name, source_tree=source_tree)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o755)
    protocol = destination / f"memory-vault-protocol-v{version}"
    client = destination / f"memory-vault-client-v{version}"
    review = destination / f"memory-vault-review-v{version}"
    protocol.mkdir()
    client.mkdir()
    review.mkdir()
    protocol_expected: dict[str, str] = {}
    review_expected: dict[str, str] = {}
    client_expected = client_inventory(source_tree, material)
    for name in PROTOCOL_DOCUMENTS:
        protocol_expected[name] = copy_public(ROOT / name, protocol / name, source_tree)
    for source in material:
        name = source.relative_to(ROOT).as_posix()
        protocol_expected[name] = copy_public(source, protocol / name, source_tree)
    protocol_expected["README.md"] = copy_public(ROOT / "packaging/PROTOCOL_README.md", protocol / "README.md", source_tree)
    build_plugin(client / "plugins/memory-vault-client", source_tree=source_tree)
    copy_public(ROOT / "packaging/CLIENT_README.md", client / "README.md", source_tree)
    copy_public(ROOT / "packaging/marketplace.json", client / ".agents/plugins/marketplace.json", source_tree)
    for source in review_material:
        name = source.relative_to(ROOT).as_posix()
        review_expected[name] = copy_public(source, review / name, source_tree)
    review_expected["README.md"] = copy_public(ROOT / "packaging/REVIEW_README.md", review / "README.md", source_tree)
    review_manifest = {
        "schema_version": "memory-vault-review-kit/v1", "version": version,
        "source_commit": source_commit, "private_state_included": False,
        "source_commit_verified": True, "source_tree_matching": True,
        "private_state_exclusion_scope": "selected_public_source_paths_only_not_content_privacy_proof",
        "tests_executed_by_builder": False, "automatic_execution": False,
        "files": dict(review_expected),
    }
    review_encoded = (json.dumps(review_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with (review / "REVIEW_MANIFEST.json").open("xb") as stream:
        stream.write(review_encoded)
    review_expected["REVIEW_MANIFEST.json"] = hashlib.sha256(review_encoded).hexdigest()
    if any(path.suffix == ".py" for path in protocol.rglob("*")):
        raise ValueError("executable_in_protocol_only_package")
    assets = [archive(protocol, destination / (protocol.name + ".zip"), protocol_expected),
              archive(client, destination / (client.name + ".zip"), client_expected),
              archive(review, destination / (review.name + ".zip"), review_expected)]
    for name in ("memory_vault.py", "PROTOCOL.md"):
        target = destination / name
        digest = copy_public(ROOT / name, target, source_tree)
        data = target.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("release_member_source_mismatch")
        assets.append({"name": name, "bytes": len(data), "sha256": digest})
    source_tree.assert_current()
    manifest = {
        "schema_version": "memory-vault-release/v1",
        "version": version,
        "source_commit": source_commit,
        "source_commit_is_caller_supplied": True,
        "source_commit_verified": True,
        "source_tree_matching": True,
        "source_url": "https://github.com/qh-work/memory-vault-sync/tree/" + source_commit,
        "private_state_included": False,
        "private_state_exclusion_scope": "selected_public_source_paths_only_not_content_privacy_proof",
        "checksums_are_publisher_signatures": False,
        "validation": {
            **checks, "archive_bytes_verified": True, "archive_inventory_verified": True,
            "application_imported_or_executed": False,
            "tests_run": False, "host_installation_tested": False,
            "cross_device_interoperability_tested": False,
        },
        "assets": assets,
    }
    manifest_path = destination / "release-manifest.json"
    encoded = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with manifest_path.open("xb") as stream:
        stream.write(encoded)
    lines = [f"{item['sha256']}  {item['name']}" for item in assets]
    lines.append(hashlib.sha256(encoded).hexdigest() + "  release-manifest.json")
    with (destination / "SHA256SUMS").open("x", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        manifest = build(args.output, args.source_commit)
    except (OSError, ValueError, SyntaxError, zipfile.BadZipFile) as exc:
        code = str(exc) if isinstance(exc, SourceError) else "release_source_or_package_invalid"
        print("Release packaging failed: " + code, file=sys.stderr)
        print("Existing paths are not overwritten; inspect any incomplete new output before retrying.", file=sys.stderr)
        return 1
    print(json.dumps({"state": "packaged_not_installed_or_tested", "version": manifest["version"], "assets": manifest["assets"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
