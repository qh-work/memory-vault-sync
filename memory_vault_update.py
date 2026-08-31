#!/usr/bin/env python3
"""Operator-invoked release inspection, authenticated staging and installation.

Memory text, MCP tools and synchronization cannot change update trust. Signed
mode uses an independently pinned root, role thresholds and monotonic metadata.
Staging inspects downloaded code as bytes only; managed installation/activation
is a separate, explicitly configured operator workflow.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time
from typing import Any, Iterator, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from memory_vault import VERSION, MemoryError, canonical_bytes, failure, strict_json_loads, success, write_response
from memory_vault_client import _absolute, _private_directory, _write_once


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
_V025_RUNTIME = {
    "memory_vault_update_trust.py", "memory_vault_install.py", "memory_vault_managed_launcher.py",
    "memory_vault_compat.py", "memory_vault_recovery.py", "memory_vault_legacy_pack.py",
    "memory_vault_metadata.py", "memory_vault_storage.py", "memory_vault_sharing.py",
    "memory_vault_crypto.py", "memory_vault_device_trust.py", "memory_vault_encrypted_replication.py",
    "memory_vault_migrate.py",
    "memory_vault_capture.py", "memory_vault_dependency.py",
}


class _DownloadNotFound(MemoryError):
    def __init__(self) -> None:
        super().__init__("update_metadata_not_found")


def read_file(path: Path, maximum: int) -> bytes:
    """Read one bounded, link-free stable file; never resolve a host transcript."""
    selected = _absolute(path)
    if os.name == "nt":
        from memory_vault_storage import open_file
        descriptor = open_file(selected, os.O_RDONLY)
    else:
        descriptor = os.open(selected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        named = selected.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or not 1 <= before.st_size <= maximum):
            raise MemoryError("unsafe_update_file")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        named_after = selected.lstat()
        if (len(data) != before.st_size or len(data) > maximum
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino, after.st_size)
                != (named_after.st_dev, named_after.st_ino, named_after.st_size)):
            raise MemoryError("update_file_changed")
        return data


def write_file(path: Path, data: bytes) -> None:
    selected = _absolute(path)
    _private_directory(selected.parent)
    # Preserve the POSIX no-clobber error even for a pre-existing public file;
    # no existing bytes or permissions are adopted, repaired or overwritten.
    if os.name == "posix" and os.path.lexists(selected):
        raise FileExistsError(errno.EEXIST, "update_output_exists")
    from memory_vault_storage import StorageError, atomic_write
    try:
        # A handled write failure must not leave a truncated immutable member
        # which _materialize would correctly refuse on an exact install retry.
        atomic_write(selected, data, replace=False)
    except StorageError as exc:
        raise MemoryError(exc.code, retryable=exc.retryable) from None


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    """Replace only an explicitly selected private control file, never a Vault."""
    selected = _absolute(path)
    _private_directory(selected.parent)
    if os.name == "nt":
        from memory_vault_storage import atomic_write
        atomic_write(selected, canonical_bytes(value) + b"\n", replace=True)
        return
    if selected.exists():
        info = selected.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
            raise MemoryError("unsafe_update_state")
    descriptor, temporary = tempfile.mkstemp(prefix=".update-state-", dir=selected.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, selected)
        if os.name != "nt":
            directory = os.open(selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


@contextlib.contextmanager
def state_lock(directory: Path) -> Iterator[None]:
    """Nonblocking process lock shared by bootstrap, stage and activation."""
    _private_directory(_absolute(directory))
    lock = directory / ".update.lock"
    if os.name == "nt":
        from memory_vault_storage import file_lock
        with file_lock(lock, busy_code="update_busy"):
            yield
        return
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
            raise MemoryError("unsafe_update_lock")
        try:
            if os.name == "nt":
                import msvcrt
                if info.st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise MemoryError("update_busy", retryable=True) from None
        yield
    finally:
        os.close(descriptor)


def configure_trust(root_file: Path, store_path: Path, expected_sha256: str) -> Mapping[str, Any]:
    """Explicit first trust; never download or overwrite an initial root."""
    from memory_vault_update_trust import import_trusted_root, trust_summary
    destination = _absolute(store_path)
    if not isinstance(expected_sha256, str) or _SHA.fullmatch(expected_sha256) is None:
        raise MemoryError("update_independent_root_digest_required")
    raw = read_file(root_file, MAX_METADATA)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise MemoryError("update_initial_root_digest_mismatch")
    trusted = import_trusted_root(raw, now_epoch=int(time.time()))
    with state_lock(destination.parent):
        if destination.exists():
            raise MemoryError("update_trust_already_configured")
        _write_once(destination, trusted)
    return {"state": "update_root_pinned", **trust_summary(trusted, now_epoch=int(time.time())),
            "private_keys_imported": False, "network_accessed": False}


def trust_status(store_path: Path) -> Mapping[str, Any]:
    from memory_vault_update_trust import read_trust_store_file, trust_summary
    selected = _absolute(store_path)
    value = strict_json_loads(read_trust_store_file(selected)) if selected.exists() else None
    return trust_summary(value, now_epoch=int(time.time()))


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


def _download(url: str, maximum: int, *, deadline: float | None = None) -> bytes:
    """Bounded, anonymous, certificate-verified HTTPS; no credentials loaded."""
    opener = urllib.request.build_opener(_Redirect())
    request = urllib.request.Request(_url(url), headers={
        "User-Agent": "memory-vault-release-stager/" + VERSION,
        "Accept": "application/vnd.github+json" if url.startswith(API) else "application/octet-stream",
        "Accept-Encoding": "identity",
    })
    deadline = min(time.monotonic() + 90, deadline) if deadline is not None else time.monotonic() + 90
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise MemoryError("update_download_timeout", retryable=True)
        with opener.open(request, timeout=min(15, remaining)) as response:
            _url(response.geturl())
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > maximum):
                raise MemoryError("update_download_limit")
            data = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise MemoryError("update_download_timeout", retryable=True)
                # read1 returns after a single underlying read, so a stream of
                # small chunks cannot indefinitely postpone the deadline check.
                read = getattr(response, "read1", response.read)
                part = read(min(64 * 1024, maximum + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
                if len(data) > maximum:
                    raise MemoryError("update_download_limit")
            if length is not None and len(data) != int(length):
                raise MemoryError("update_download_incomplete", retryable=True)
            return bytes(data)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _DownloadNotFound() from None
        raise MemoryError("update_download_unavailable", retryable=True) from None
    except MemoryError:
        raise
    except (urllib.error.URLError, OSError, ValueError):
        # No URL, proxy credentials, network response text or memory appears
        # in an error. Operator can retry; no installation has taken place.
        raise MemoryError("update_download_unavailable", retryable=True) from None


def _release(version: str | None, *, deadline: float | None = None) -> Mapping[str, Any]:
    if version is not None and _VERSION.fullmatch(version) is None:
        raise MemoryError("invalid_update_version")
    suffix = "latest" if version is None else "tags/v" + version
    value = strict_json_loads(_download(API + suffix, MAX_METADATA, deadline=deadline))
    if not isinstance(value, dict) or value.get("draft") is not False or value.get("prerelease") is not False:
        raise MemoryError("update_not_stable_release")
    tag = value.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("v") or _VERSION.fullmatch(tag[1:]) is None:
        raise MemoryError("invalid_update_version")
    if version is not None and tag != "v" + version:
        raise MemoryError("update_version_mismatch")
    return {"version": tag[1:], "tag": tag,
            "release_url": "https://github.com/" + REPOSITORY + "/releases/tag/" + tag}


def check(version: str | None = None, *, deadline: float | None = None) -> Mapping[str, Any]:
    candidate = _release(version, deadline=deadline)
    installed_base = re.split(r"[-+]", VERSION, maxsplit=1)[0]
    newer = tuple(map(int, candidate["version"].split("."))) > tuple(map(int, installed_base.split(".")))
    return {**candidate, "installed_code_version": VERSION, "newer_release": newer,
            "state": "release_metadata_read", "files_written": False,
            "activated": False, "publisher_signature_verified": False}


def _archive_inventory(data: bytes, version: str) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    archive = None
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
        if tuple(map(int, version.split("."))) >= (0, 25, 0) and not _V025_RUNTIME.issubset(modules):
            raise MemoryError("update_incomplete_v025_runtime")
        actual = {name[len(base + "runtime/"):] for name in seen if name.startswith(base + "runtime/")}
        if actual != set(modules) | {"MANIFEST.json"}:
            raise MemoryError("update_runtime_inventory_mismatch")
        for name, digest in modules.items():
            if (not isinstance(name, str) or re.fullmatch(r"memory_vault(?:_[a-z_]+)?\.py", name) is None
                    or not isinstance(digest, str) or _SHA.fullmatch(digest) is None
                    or hashlib.sha256(archive.read(base + "runtime/" + name)).hexdigest() != digest):
                raise MemoryError("update_runtime_hash_mismatch")
        return archive, members
    except MemoryError:
        if archive is not None:
            archive.close()
        raise
    except (zipfile.BadZipFile, KeyError, UnicodeError, ValueError, OSError):
        if archive is not None:
            archive.close()
        raise MemoryError("update_invalid_archive") from None


def stage(output: Path, *, version: str | None = None, trust_store_path: Path | None = None,
          metadata_directory: Path | None = None, maximum_seconds: int = 120) -> Mapping[str, Any]:
    if type(maximum_seconds) is not int or not 1 <= maximum_seconds <= 300:
        raise MemoryError("invalid_update_time_budget")
    deadline = time.monotonic() + maximum_seconds
    if metadata_directory is not None and trust_store_path is None:
        raise MemoryError("update_metadata_requires_pinned_trust")
    if trust_store_path is None:
        return _stage(output, version=version, deadline=deadline)
    selected_trust = _absolute(trust_store_path)
    if not selected_trust.exists():
        raise MemoryError("update_trust_not_configured")
    with state_lock(selected_trust.parent):
        return _stage(output, version=version, trust_store_path=selected_trust,
                      metadata_directory=metadata_directory, deadline=deadline)


def _stage(output: Path, *, version: str | None = None, trust_store_path: Path | None = None,
           metadata_directory: Path | None = None, deadline: float | None = None) -> Mapping[str, Any]:
    destination = _absolute(output)
    if destination.exists():
        raise MemoryError("update_output_exists")
    release = _release(version, deadline=deadline)
    version = release["version"]
    base = DOWNLOAD + release["tag"] + "/"
    manifest_raw = _download(base + "release-manifest.json", MAX_METADATA, deadline=deadline)
    manifest = strict_json_loads(manifest_raw)
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != "memory-vault-release/v1"
            or manifest.get("version") != version or not isinstance(manifest.get("source_commit"), str)
            or manifest.get("private_state_included") is not False
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
    data = _download(base + asset_name, size, deadline=deadline)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise MemoryError("update_asset_hash_mismatch")
    archive, members = _archive_inventory(data, version)
    try:
        _private_directory(destination.parent)
        destination.mkdir(mode=0o700)
        # Keep the exact authenticated input, not just a self-asserted STAGED flag.
        write_file(destination / "PACKAGE.zip", data)
        write_file(destination / "RELEASE.json", manifest_raw)
        verified = None
        if trust_store_path is not None:
            from memory_vault_update_trust import (
                MAX_ROOT_ROTATIONS_PER_CHECK, read_trust_store_file,
                validate_trust_store, verify_update_chain,
            )
            trusted = validate_trust_store(strict_json_loads(read_trust_store_file(trust_store_path)))
            metadata_copy = destination / "update-metadata"
            _private_directory(metadata_copy)
            local = _absolute(metadata_directory) if metadata_directory is not None else None
            for name in ("timestamp.json", "snapshot.json", "targets.json"):
                if deadline is not None and time.monotonic() >= deadline:
                    raise MemoryError("update_stage_timeout", retryable=True)
                raw = read_file(local / name, MAX_METADATA) if local is not None else _download(base + name, MAX_METADATA, deadline=deadline)
                write_file(metadata_copy / name, raw)
            root_version = trusted["trusted_root"]["signed"]["version"]
            for offset in range(1, MAX_ROOT_ROTATIONS_PER_CHECK + 2):
                if deadline is not None and time.monotonic() >= deadline:
                    raise MemoryError("update_stage_timeout", retryable=True)
                name = str(root_version + offset) + ".root.json"
                if local is not None:
                    candidate_path = _absolute(local / name)
                    if not candidate_path.exists():
                        break
                    raw = read_file(candidate_path, MAX_METADATA)
                else:
                    try:
                        raw = _download(base + name, MAX_METADATA, deadline=deadline)
                    except _DownloadNotFound:
                        break
                write_file(metadata_copy / name, raw)
            verified = verify_update_chain(metadata_copy, trusted, {
                "version": version, "bundle_sha256": digest, "bundle_length": size,
                "commit_sha": manifest["source_commit"],
            }, plugin_name="memory-vault-client", now_epoch=int(time.time()))
        for member in members:
            if deadline is not None and time.monotonic() >= deadline:
                raise MemoryError("update_stage_timeout", retryable=True)
            target = _absolute(destination.joinpath(*member.filename.split("/")))
            write_file(target, archive.read(member))
        receipt = {
            "schema_version": "memory-vault-update-stage/v1", **release,
            "source_commit": manifest["source_commit"], "archive_sha256": digest,
            "state": "staged_not_installed", "activated": False,
            "code_executed": False, "publisher_signature_verified": verified is not None,
            "existing_plugin_unchanged": True, "private_state_included": False,
        }
        if verified is not None:
            receipt["signed_target"] = verified["target"]
            receipt["root_sha256"] = verified["trust_store"]["trusted_root_sha256"]
            receipt["root_rotations"] = verified["root_rotations"]
            # Advance anti-rollback floors only after all archive bytes were staged.
            # A crash before STAGED.json leaves an inspectable incomplete stage.
            atomic_json(trust_store_path, verified["trust_store"])
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
    staging.add_argument("--trust-store", type=Path, help="independently pinned update trust; missing metadata fails closed")
    staging.add_argument("--metadata-directory", type=Path, help="optional explicitly staged signed metadata instead of downloading it")
    staging.add_argument("--maximum-seconds", type=int, default=120, help="total staging budget, 1..300 seconds")
    pin = sub.add_parser("configure-trust", help="pin an independently reviewed public root; never enroll from memory")
    pin.add_argument("--root-file", required=True, type=Path)
    pin.add_argument("--trust-store", required=True, type=Path)
    pin.add_argument("--expected-sha256", required=True)
    state = sub.add_parser("trust-status", help="read public update-trust state without private keys or network")
    state.add_argument("--trust-store", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            result = check(args.version)
        elif args.command == "stage":
            result = stage(args.out, version=args.version, trust_store_path=args.trust_store,
                           metadata_directory=args.metadata_directory, maximum_seconds=args.maximum_seconds)
        elif args.command == "configure-trust":
            result = configure_trust(args.root_file, args.trust_store, args.expected_sha256)
        else:
            result = trust_status(args.trust_store)
        write_response(success(result))
        return 0
    except MemoryError as exc:
        write_response(failure(exc.code, retryable=exc.retryable))
    except Exception:
        write_response(failure("update_unavailable", retryable=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
