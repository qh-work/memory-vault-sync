#!/usr/bin/env python3
"""Package the public protocol and optional client without running the application."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import zipfile

from build_client_plugin import (
    OPTIONAL_MODULES,
    PACKAGE_DOCUMENTS,
    REQUIRED_MODULES,
    TEMPLATE_FILES,
    build as build_plugin,
    plain,
)


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
    "docs/V0_25_PARITY_PLAN.md",
)
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_BYTES = 32 * 1024 * 1024


def read_public(path: Path) -> bytes:
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


def public_protocol_files() -> list[Path]:
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
            read_public(source)
            files.append(source)
    if not any(path.suffix == ".ndjson" for path in files):
        raise ValueError("missing_synthetic_interchange_example")
    return files


def review_sources(material: list[Path]) -> list[Path]:
    """A separate, explicitly executable review kit; never part of protocol-only."""
    paths = [ROOT / name for name in (*REQUIRED_MODULES, *OPTIONAL_MODULES)]
    paths.extend(ROOT / name for name in set(PROTOCOL_DOCUMENTS) | set(PACKAGE_DOCUMENTS))
    paths.extend(ROOT / "plugins/memory-vault-client" / name for name in TEMPLATE_FILES)
    paths.extend(ROOT / name for name in (
        "scripts/build_client_plugin.py", "scripts/build_release.py",
        "packaging/marketplace.json", "packaging/PROTOCOL_README.md", "packaging/CLIENT_README.md",
        "tests/test_memory_vault.py", "packaging/REVIEW_README.md",
    ))
    paths.extend(sorted((ROOT / "tests").glob("test_v025_*.py")))
    paths.extend(material)
    result = sorted(set(paths))
    if not any(path.name == "test_v025_install.py" for path in result):
        raise ValueError("missing_v025_review_material")
    for source in result:
        read_public(source)
    return result


def inspect_sources(material: list[Path], review: list[Path]) -> tuple[str, dict[str, int]]:
    modules = [ROOT / name for name in (*REQUIRED_MODULES, *OPTIONAL_MODULES)]
    modules.extend(sorted((ROOT / "scripts").glob("*.py")))
    modules.append(ROOT / "plugins/memory-vault-client/scripts/launcher.py")
    modules.extend(path for path in review if path.suffix == ".py")
    python_count = json_count = frame_count = 0
    version = None
    for source in dict.fromkeys(modules):
        tree = ast.parse(read_public(source), filename=source.name)
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
    ]
    for source in json_sources:
        value = parse_json(read_public(source))
        json_count += 1
        if source.name == "plugin.json" and (
            not isinstance(value, dict) or value.get("version") != version
        ):
            raise ValueError("plugin_version_mismatch")
    for source in material:
        if source.suffix != ".ndjson":
            continue
        data = read_public(source)
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


def copy_public(source: Path, destination: Path) -> None:
    data = read_public(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)


def archive(directory: Path, output: Path) -> dict[str, object]:
    total = files = 0
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for source in sorted(directory.rglob("*")):
            if source.is_symlink():
                raise ValueError("symlink_in_release")
            if source.is_dir():
                continue
            data = read_public(source)
            total += len(data)
            files += 1
            if total > MAX_PACKAGE_BYTES or files > 512:
                raise ValueError("release_inventory_too_large")
            info = zipfile.ZipInfo(source.relative_to(directory.parent).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(info, data, compresslevel=9)
    # Inspect every stored member against its build input. This is archive-byte
    # verification, not application execution or an interoperability test.
    with zipfile.ZipFile(output) as package:
        for member in package.infolist():
            expected = directory.parent / member.filename
            if package.read(member) != read_public(expected):
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
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("source_commit_must_be_full_sha")
    material = public_protocol_files()
    review_material = review_sources(material)
    version, checks = inspect_sources(material, review_material)
    for name in set(PROTOCOL_DOCUMENTS) | set(PACKAGE_DOCUMENTS) | {
        "packaging/PROTOCOL_README.md", "packaging/CLIENT_README.md",
        "packaging/marketplace.json",
    }:
        read_public(ROOT / name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o755)
    protocol = destination / f"memory-vault-protocol-v{version}"
    client = destination / f"memory-vault-client-v{version}"
    review = destination / f"memory-vault-review-v{version}"
    protocol.mkdir()
    client.mkdir()
    review.mkdir()
    for name in PROTOCOL_DOCUMENTS:
        copy_public(ROOT / name, protocol / name)
    for source in material:
        copy_public(source, protocol / source.relative_to(ROOT))
    copy_public(ROOT / "packaging/PROTOCOL_README.md", protocol / "README.md")
    build_plugin(client / "plugins/memory-vault-client")
    copy_public(ROOT / "packaging/CLIENT_README.md", client / "README.md")
    copy_public(ROOT / "packaging/marketplace.json", client / ".agents/plugins/marketplace.json")
    for source in review_material:
        copy_public(source, review / source.relative_to(ROOT))
    copy_public(ROOT / "packaging/REVIEW_README.md", review / "README.md")
    review_manifest = {
        "schema_version": "memory-vault-review-kit/v1", "version": version,
        "source_commit": source_commit, "private_state_included": False,
        "tests_executed_by_builder": False, "automatic_execution": False,
        "files": {
            **{source.relative_to(ROOT).as_posix(): hashlib.sha256(read_public(review / source.relative_to(ROOT))).hexdigest()
               for source in review_material},
            "README.md": hashlib.sha256(read_public(review / "README.md")).hexdigest(),
        },
    }
    with (review / "REVIEW_MANIFEST.json").open("x", encoding="utf-8") as stream:
        json.dump(review_manifest, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")
    if any(path.suffix == ".py" for path in protocol.rglob("*")):
        raise ValueError("executable_in_protocol_only_package")
    assets = [archive(protocol, destination / (protocol.name + ".zip")),
              archive(client, destination / (client.name + ".zip")),
              archive(review, destination / (review.name + ".zip"))]
    for name in ("memory_vault.py", "PROTOCOL.md"):
        target = destination / name
        copy_public(ROOT / name, target)
        data = target.read_bytes()
        assets.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {
        "schema_version": "memory-vault-release/v1",
        "version": version,
        "source_commit": source_commit,
        "source_commit_is_caller_supplied": True,
        "source_url": "https://github.com/qh-work/memory-vault-sync/tree/" + source_commit,
        "private_state_included": False,
        "checksums_are_publisher_signatures": False,
        "validation": {
            **checks, "archive_bytes_verified": True,
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
        print("Release packaging failed: " + str(exc), file=sys.stderr)
        print("Existing paths are not overwritten; inspect any incomplete new output before retrying.", file=sys.stderr)
        return 1
    print(json.dumps({"state": "packaged_not_installed_or_tested", "version": manifest["version"], "assets": manifest["assets"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
