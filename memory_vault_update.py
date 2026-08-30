#!/usr/bin/env python3
"""Operator-invoked release inspection and staging; never install or activate.

This module is not called by hooks, MCP tools or the sync worker. HTTPS and
checksums protect transport/consistency, not against a compromised publisher.
Downloaded code is inspected as bytes only and never imported or executed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
from typing import Any, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from memory_vault import VERSION, MemoryError, canonical_bytes, failure, strict_json_loads, success, write_response
from memory_vault_client import _absolute, _write_once


REPOSITORY = "qh-work/memory-vault-sync"
API = "https://api.github.com/repos/" + REPOSITORY + "/releases/"
DOWNLOAD = "https://github.com/" + REPOSITORY + "/releases/download/"
MAX_METADATA = 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_MEMBERS = 512
_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
_SHA = re.compile(r"[0-9a-f]{64}")
_DOWNLOAD_HOSTS = {"api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
_REQUIRED_RUNTIME = {
    "memory_vault.py", "memory_vault_client.py", "memory_vault_lifecycle.py",
    "memory_vault_trust.py", "memory_vault_transfer.py", "memory_vault_sync.py", "memory_vault_remote.py",
    "memory_vault_hosts.py", "memory_vault_manage.py", "memory_vault_backup.py",
    "memory_vault_update.py", "memory_vault_pack.py", "memory_vault_privacy.py",
}


def _url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname not in _DOWNLOAD_HOSTS
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in {None, 443} or parsed.fragment):
        raise MemoryError("update_url_not_allowed")
    if parsed.hostname == "api.github.com" and not parsed.path.startswith("/repos/" + REPOSITORY + "/releases/"):
        raise MemoryError("update_url_not_allowed")
    if parsed.hostname == "github.com" and not parsed.path.startswith("/" + REPOSITORY + "/releases/download/"):
        raise MemoryError("update_url_not_allowed")
    return value


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        return super().redirect_request(req, fp, code, msg, headers, _url(newurl))


def _download(url: str, maximum: int) -> bytes:
    """Bounded, anonymous, certificate-verified HTTPS; no credentials loaded."""
    opener = urllib.request.build_opener(_Redirect())
    request = urllib.request.Request(_url(url), headers={
        "User-Agent": "memory-vault-release-stager/" + VERSION,
        "Accept": "application/vnd.github+json" if url.startswith(API) else "application/octet-stream",
        "Accept-Encoding": "identity",
    })
    deadline = time.monotonic() + 90
    try:
        with opener.open(request, timeout=15) as response:
            _url(response.geturl())
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > maximum):
                raise MemoryError("update_download_limit")
            data = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise MemoryError("update_download_timeout", retryable=True)
                part = response.read(min(64 * 1024, maximum + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
                if len(data) > maximum:
                    raise MemoryError("update_download_limit")
            if length is not None and len(data) != int(length):
                raise MemoryError("update_download_incomplete", retryable=True)
            return bytes(data)
    except MemoryError:
        raise
    except (urllib.error.URLError, OSError, ValueError):
        # No URL, proxy credentials, network response text or memory appears
        # in an error. Operator can retry; no installation has taken place.
        raise MemoryError("update_download_unavailable", retryable=True) from None


def _release(version: str | None) -> Mapping[str, Any]:
    if version is not None and _VERSION.fullmatch(version) is None:
        raise MemoryError("invalid_update_version")
    suffix = "latest" if version is None else "tags/v" + version
    value = strict_json_loads(_download(API + suffix, MAX_METADATA))
    if not isinstance(value, dict) or value.get("draft") is not False or value.get("prerelease") is not False:
        raise MemoryError("update_not_stable_release")
    tag = value.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("v") or _VERSION.fullmatch(tag[1:]) is None:
        raise MemoryError("invalid_update_version")
    if version is not None and tag != "v" + version:
        raise MemoryError("update_version_mismatch")
    return {"version": tag[1:], "tag": tag,
            "release_url": "https://github.com/" + REPOSITORY + "/releases/tag/" + tag}


def check(version: str | None = None) -> Mapping[str, Any]:
    candidate = _release(version)
    newer = tuple(map(int, candidate["version"].split("."))) > tuple(map(int, VERSION.split(".")))
    return {**candidate, "installed_code_version": VERSION, "newer_release": newer,
            "state": "release_metadata_read", "files_written": False,
            "activated": False, "publisher_signature_verified": False}


def _archive_inventory(data: bytes, version: str) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = archive.infolist()
        if not 1 <= len(members) <= MAX_MEMBERS:
            raise MemoryError("update_archive_limit")
        root = "memory-vault-client-v" + version
        seen: set[str] = set()
        total = 0
        for member in members:
            name = member.filename
            parts = name.split("/")
            mode = member.external_attr >> 16
            if (name in seen or "\\" in name or "\x00" in name or ":" in name
                    or len(parts) < 2 or parts[0] != root
                    or any(part in {"", ".", ".."} or part.endswith((" ", "."))
                           or re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
                           for part in parts)
                    or PurePosixPath(name).is_absolute() or member.is_dir()
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                    or member.flag_bits & 1
                    or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
                raise MemoryError("update_unsafe_archive_member")
            if member.file_size > MAX_FILE or member.file_size > max(1024, member.compress_size * 500):
                raise MemoryError("update_archive_limit")
            total += member.file_size
            if total > MAX_ARCHIVE:
                raise MemoryError("update_archive_limit")
            seen.add(name)
        base = root + "/plugins/memory-vault-client/"
        required = {base + suffix for suffix in (
            ".codex-plugin/plugin.json", ".mcp.json", "hooks/hooks.json", "scripts/launcher.py", "runtime/MANIFEST.json",
        )} | {root + "/.agents/plugins/marketplace.json"}
        if not required.issubset(seen):
            raise MemoryError("update_incomplete_plugin")
        plugin = strict_json_loads(archive.read(base + ".codex-plugin/plugin.json"))
        if not isinstance(plugin, dict) or plugin.get("version") != version or plugin.get("name") != "memory-vault-client":
            raise MemoryError("update_plugin_manifest_mismatch")
        inventory = strict_json_loads(archive.read(base + "runtime/MANIFEST.json"))
        if not isinstance(inventory, dict) or inventory.get("schema_version") != "memory-vault-client-runtime/v1":
            raise MemoryError("update_invalid_runtime_inventory")
        modules = inventory.get("modules")
        if not isinstance(modules, dict) or not _REQUIRED_RUNTIME.issubset(modules):
            raise MemoryError("update_incomplete_runtime")
        actual = {name[len(base + "runtime/"):] for name in seen if name.startswith(base + "runtime/")}
        if actual != set(modules) | {"MANIFEST.json"}:
            raise MemoryError("update_runtime_inventory_mismatch")
        for name, digest in modules.items():
            if (not isinstance(name, str) or re.fullmatch(r"memory_vault(?:_[a-z_]+)?\.py", name) is None
                    or not isinstance(digest, str) or _SHA.fullmatch(digest) is None
                    or hashlib.sha256(archive.read(base + "runtime/" + name)).hexdigest() != digest):
                raise MemoryError("update_runtime_hash_mismatch")
        return archive, members
    except (zipfile.BadZipFile, KeyError, UnicodeError, ValueError, OSError):
        raise MemoryError("update_invalid_archive") from None


def stage(output: Path, *, version: str | None = None) -> Mapping[str, Any]:
    destination = _absolute(output)
    if destination.exists():
        raise MemoryError("update_output_exists")
    release = _release(version)
    version = release["version"]
    base = DOWNLOAD + release["tag"] + "/"
    manifest = strict_json_loads(_download(base + "release-manifest.json", MAX_METADATA))
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != "memory-vault-release/v1"
            or manifest.get("version") != version or not isinstance(manifest.get("source_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]) is None):
        raise MemoryError("update_invalid_release_manifest")
    expected_source = "https://github.com/" + REPOSITORY + "/tree/" + manifest["source_commit"]
    if manifest.get("source_url") != expected_source:
        raise MemoryError("update_source_mismatch")
    assets = manifest.get("assets")
    if not isinstance(assets, list) or not 1 <= len(assets) <= 16:
        raise MemoryError("update_invalid_asset_inventory")
    asset_name = "memory-vault-client-v" + version + ".zip"
    selected = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == asset_name]
    if len(selected) != 1:
        raise MemoryError("update_full_client_asset_missing")
    asset = selected[0]
    size, digest = asset.get("bytes"), asset.get("sha256")
    if (not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_ARCHIVE
            or not isinstance(digest, str) or _SHA.fullmatch(digest) is None):
        raise MemoryError("update_invalid_asset_inventory")
    data = _download(base + asset_name, size)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise MemoryError("update_asset_hash_mismatch")
    archive, members = _archive_inventory(data, version)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)
        for member in members:
            target = _absolute(destination.joinpath(*member.filename.split("/")))
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(archive.read(member))
                stream.flush()
                os.fsync(stream.fileno())
        receipt = {
            "schema_version": "memory-vault-update-stage/v1", **release,
            "source_commit": manifest["source_commit"], "archive_sha256": digest,
            "state": "staged_not_installed", "activated": False,
            "code_executed": False, "publisher_signature_verified": False,
            "existing_plugin_unchanged": True, "private_state_included": False,
        }
        _write_once(destination / "STAGED.json", receipt)
        return {**receipt, "next_action": "Review this new package, then use the host's normal user-approved installation. Keep the previous plugin for rollback."}
    finally:
        archive.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("check", help="read public release metadata only")
    inspect.add_argument("--version", help="exact stable version without v; omitted: latest release")
    staging = sub.add_parser("stage", help="download and inspect into a new directory; never activate")
    staging.add_argument("--version", required=True, help="exact stable version without v")
    staging.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = check(args.version) if args.command == "check" else stage(args.out, version=args.version)
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except Exception:
        write_response(failure("update_unavailable", retryable=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
