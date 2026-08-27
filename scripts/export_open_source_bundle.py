#!/usr/bin/env python3
"""Create a clean, rebranded source bundle without private vault state.

The exporter uses an allow-list instead of copying the repository and then
trying to delete private data. The destination must not already exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Iterable


PRIVATE_REPOSITORY_ID = "qh-work/memory-vault-sync"
PRIVATE_REPOSITORY_URL = (
    "https://github.com/qh-work/memory-vault-sync.git"
)
PRIVATE_AUTHOR = "qh-work"
PRIVATE_MARKETPLACE = "memory-vault-public"
PRIVATE_MARKETPLACE_DISPLAY_NAME = "Memory Vault"
PUBLIC_RELEASE_REPOSITORY_ID = "qh-work/memory-vault-sync"
PUBLIC_RELEASE_REPOSITORY_URL = (
    "https://github.com/qh-work/memory-vault-sync"
)
FORBIDDEN_TOP_LEVEL = frozenset(
    {
        "bindings",
        "handoffs",
        "instances",
        "memory",
        "migration",
        "sources",
        "tasks",
    }
)
COPY_ITEMS = (
    ".agents/plugins/marketplace.json",
    ".codex/skills/sync-memory-vault",
    ".gitattributes",
    ".gitignore",
    "ARCHITECTURE.md",
    "CHUNK_PROTOCOL.md",
    "CLIENT_SYNC_CONTRACT.md",
    "DEVELOPMENT.md",
    "MEMORY_NETWORK.md",
    "RELEASE.md",
    "RUNTIME_MODULES.md",
    "SECURITY.md",
    "ADAPTER_CONTRACT.md",
    "DESIGN_BENCHMARKS.md",
    "OPEN_SOURCE_READINESS.md",
    "PRIVATE_DIAGNOSTICS.md",
    "SIGNED_UPDATES.md",
    "benchmarks",
    "plugins/memory-vault-sync",
    "schemas",
    "scripts/benchmark_chunk_protocol.py",
    "scripts/benchmark_memory_network.py",
    "scripts/export_open_source_bundle.py",
    "scripts/memory_vault_validator",
    "scripts/validate_layout_v1.py",
    "tests/test_export_open_source_bundle.py",
    "tests/test_validate_layout_v1.py",
)
SPECIAL_DESTINATIONS = {
    "open_source/memory-vault-sync.yml": ".github/workflows/memory-vault-sync.yml",
    "open_source/CODEOWNERS": ".github/CODEOWNERS",
    "open_source/bug_report.yml": ".github/ISSUE_TEMPLATE/bug_report.yml",
    "open_source/config.yml": ".github/ISSUE_TEMPLATE/config.yml",
    "open_source/feature_request.yml": ".github/ISSUE_TEMPLATE/feature_request.yml",
    "open_source/pull_request_template.md": ".github/pull_request_template.md",
    "open_source/CODE_OF_CONDUCT.md": "CODE_OF_CONDUCT.md",
    "open_source/CONTRIBUTING.md": "CONTRIBUTING.md",
    "open_source/NOTICE": "NOTICE",
    "open_source/SUPPORT.md": "SUPPORT.md",
    "open_source/README.md": "README.md",
    "open_source/STATUS.md": "STATUS.md",
    "open_source/ROADMAP.md": "ROADMAP.md",
    "open_source/CHANGELOG.md": "CHANGELOG.md",
}
SECRET_VALUE_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


class ExportError(RuntimeError):
    pass


def _repository_id(value: str) -> str:
    if len(value) > 512 or not re.fullmatch(
        r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+",
        value,
    ):
        raise ExportError("repository id must be an owner or group path plus name")
    if any(component in {".", ".."} for component in value.split("/")):
        raise ExportError("repository id contains an unsafe path component")
    return value


def _repository_url(value: str, repository_id: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ExportError("repository URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise ExportError("repository URL must be credential-free HTTPS")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if path.lower() != repository_id.lower():
        raise ExportError("repository URL path does not match repository id")
    host = str(parsed.hostname).lower()
    return f"https://{host}/{repository_id}.git"


def _deployment_control_defaults(
    repository_url: str,
    repository_id: str,
) -> tuple[str, str]:
    host = (urllib.parse.urlsplit(repository_url).hostname or "").lower()
    if host == "github.com":
        if repository_id.count("/") != 1:
            raise ExportError(
                "GitHub repository id must contain exactly owner/repository"
            )
        return "github-private-v1", "github.com"
    if host == "gitlab.com":
        return "gitlab-private-v1", "gitlab.com"
    raise ExportError(
        "public deployment defaults currently support GitHub.com or GitLab.com"
    )


def _safe_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}", value):
        raise ExportError(f"{label} is invalid")
    return value


def _display_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{1,63}", value):
        raise ExportError("marketplace display name is invalid")
    return value


def _iter_files(root: Path) -> Iterable[tuple[Path, PurePosixPath]]:
    sources = [*COPY_ITEMS, *SPECIAL_DESTINATIONS]
    seen: set[PurePosixPath] = set()
    for relative_text in sources:
        source = root / PurePosixPath(relative_text)
        if not source.exists() and relative_text in SPECIAL_DESTINATIONS:
            # A previously exported public tree intentionally has no private
            # `open_source/` template directory. Its already-generated public
            # root file is the safe source for a later fork/rebrand export.
            source = root / PurePosixPath(SPECIAL_DESTINATIONS[relative_text])
        if source.is_symlink() or not source.exists():
            raise ExportError(f"required source is missing or linked: {relative_text}")
        candidates = [source] if source.is_file() else sorted(source.rglob("*"))
        for candidate in candidates:
            if candidate.is_dir():
                continue
            if candidate.is_symlink() or not candidate.is_file():
                raise ExportError(f"source bundle contains a linked file: {candidate}")
            if "__pycache__" in candidate.parts or candidate.suffix == ".pyc":
                continue
            relative = PurePosixPath(candidate.relative_to(root).as_posix())
            destination = PurePosixPath(
                SPECIAL_DESTINATIONS.get(relative.as_posix(), relative.as_posix())
            )
            if destination in seen:
                raise ExportError(f"duplicate export destination: {destination}")
            seen.add(destination)
            yield candidate, destination


def _transform_text(raw: bytes, replacements: tuple[tuple[str, str], ...]) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExportError("the public source allow-list contains non-UTF-8 data") from exc
    # Rebrand in two phases. Direct sequential replacement can rewrite a
    # target value again when it contains the source label (for example,
    # rebranding "Memory Vault" to "Fixture Memory Vault"). Placeholders
    # prevent that cascade and let us prove every source identity disappeared
    # before any target identity is inserted.
    if "\x1e" in text or "\x1f" in text:
        raise ExportError("the public source contains reserved control bytes")
    staged: list[tuple[str, str]] = []
    for index, (before, after) in enumerate(replacements):
        if not before or any(
            marker in before + after for marker in ("\x1e", "\x1f")
        ):
            raise ExportError("the rebranding map contains an unsafe value")
        marker = f"\x1e{index:02d}\x1f"
        text = text.replace(before, marker)
        staged.append((marker, after))
    if any(
        private in text
        for private in (
            PRIVATE_REPOSITORY_ID,
            PRIVATE_REPOSITORY_URL,
            PRIVATE_AUTHOR,
            PRIVATE_MARKETPLACE,
            PRIVATE_MARKETPLACE_DISPLAY_NAME,
        )
    ):
        raise ExportError("private deployment identity remains after rebranding")
    for marker, after in staged:
        text = text.replace(marker, after)
    if "\x1e" in text or "\x1f" in text:
        raise ExportError("rebranding placeholders were not fully resolved")
    if SECRET_VALUE_RE.search(text):
        raise ExportError("a credential-shaped value remains in the source bundle")
    return text.encode("utf-8")


def export_bundle(args: argparse.Namespace) -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    destination = args.destination.expanduser()
    if destination.exists() or destination.is_symlink():
        raise ExportError("destination already exists")
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    repository_id = _repository_id(args.repository_id)
    repository_url = _repository_url(args.repository_url, repository_id)
    repository_web_url = repository_url.removesuffix(".git")
    control_verifier, control_credential_host = _deployment_control_defaults(
        repository_url,
        repository_id,
    )
    author = _safe_name(args.author, "author")
    marketplace = _safe_name(args.marketplace_name, "marketplace name")
    marketplace_display_name = _display_name(args.marketplace_display_name)
    license_input = args.license_file.expanduser()
    if license_input.is_symlink():
        raise ExportError("license file must be a regular file, not a link")
    license_path = license_input.resolve(strict=True)
    if not license_path.is_file():
        raise ExportError("license file must be a regular file")
    license_raw = license_path.read_bytes()
    if not license_raw or len(license_raw) > 256 * 1024:
        raise ExportError("license file size is invalid")
    try:
        license_text = license_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExportError("license file must be UTF-8") from exc
    if SECRET_VALUE_RE.search(license_text):
        raise ExportError("license file contains a credential-shaped value")

    replacements = (
        (
            'DEPLOYMENT_CONTROL_PRIVACY_VERIFIER = "github-private-v1"',
            "DEPLOYMENT_CONTROL_PRIVACY_VERIFIER = "
            f'"{control_verifier}"',
        ),
        (
            'DEPLOYMENT_CONTROL_CREDENTIAL_HOST = "github.com"',
            "DEPLOYMENT_CONTROL_CREDENTIAL_HOST = "
            f'"{control_credential_host}"',
        ),
        (PUBLIC_RELEASE_REPOSITORY_URL, repository_web_url),
        (PUBLIC_RELEASE_REPOSITORY_ID, repository_id),
        (PRIVATE_REPOSITORY_URL, repository_url),
        (PRIVATE_REPOSITORY_ID, repository_id),
        (PRIVATE_MARKETPLACE_DISPLAY_NAME, marketplace_display_name),
        (PRIVATE_MARKETPLACE, marketplace),
        (PRIVATE_AUTHOR, author),
    )
    prepared: list[tuple[PurePosixPath, bytes, int]] = []
    exported: list[dict[str, object]] = []
    total_bytes = 0
    for source, relative in _iter_files(root):
        if relative.parts and relative.parts[0] in FORBIDDEN_TOP_LEVEL:
            raise ExportError(f"private state path entered the allow-list: {relative}")
        raw = _transform_text(source.read_bytes(), replacements)
        prepared.append((relative, raw, source.stat().st_mode & 0o777))
        total_bytes += len(raw)
        exported.append(
            {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
    exported.append(
        {
            "path": "LICENSE",
            "sha256": hashlib.sha256(license_raw).hexdigest(),
            "size": len(license_raw),
        }
    )
    total_bytes += len(license_raw)
    exported.sort(key=lambda item: str(item["path"]))
    manifest = {
        "schema_version": "memory-vault-open-source-export/v1",
        "repository_id": repository_id,
        "repository_url": repository_url,
        "author": author,
        "marketplace_name": marketplace,
        "marketplace_display_name": marketplace_display_name,
        "control_privacy_verifier": control_verifier,
        "control_credential_host": control_credential_host,
        "private_state_included": False,
        "file_count": len(exported),
        "total_bytes": total_bytes,
        "files": exported,
    }
    destination.mkdir(mode=0o700)
    try:
        for relative, raw, mode in prepared:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(raw)
            os.chmod(target, mode)
        license_target = destination / "LICENSE"
        license_target.write_bytes(license_raw)
        os.chmod(license_target, 0o644)
        (destination / ".open-source-export.json").write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n",
            encoding="utf-8",
        )
    except BaseException:
        # The destination was created by this invocation with mode 0700. Do
        # not leave a partial tree that could be mistaken for a safe export.
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="export a rebranded Memory Vault plugin source tree"
    )
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--author", required=True)
    parser.add_argument("--marketplace-name", required=True)
    parser.add_argument("--marketplace-display-name", required=True)
    parser.add_argument("--license-file", type=Path, required=True)
    return parser


def main() -> int:
    try:
        manifest = export_bundle(build_parser().parse_args())
    except (ExportError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, **manifest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
