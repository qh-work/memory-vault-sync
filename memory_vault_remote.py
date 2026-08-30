#!/usr/bin/env python3
"""Bounded transport of exact signed capsules through an operator's rclone.

No installation, credential discovery, directory mirroring, remote deletion or
trust enrollment. This module is not imported by the standard-library core.
"""
from __future__ import annotations

import configparser
import contextlib
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from typing import Any, Callable, Mapping

from memory_vault import MemoryError
from memory_vault_transfer import MAX_CAPSULE_BYTES, _fragment_name, _group, _path
import memory_vault_storage as protected_storage

MAX_CONFIG_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_LIST_BYTES = 16 * 1024
MAX_PREFIX_CANDIDATES = 8
_REMOTE = re.compile(r"([A-Za-z][A-Za-z0-9_-]{0,63}):(.*)")
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_KEY = re.compile(r"ed25519_[0-9a-f]{64}")
_STORE = re.compile(r"store_[0-9a-f]{32}")
_NAME = re.compile(r"([0-9]{20})-([0-9]{20})-([0-9a-f]{64})\.json")


def remote_path(value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 1024:
        raise MemoryError("invalid_remote_path")
    match = _REMOTE.fullmatch(value)
    if match is None:
        raise MemoryError("invalid_remote_path")
    tail = match[2]
    if not tail and allow_empty:
        return value
    if not tail or any(_PART.fullmatch(part) is None for part in tail.split("/")):
        raise MemoryError("dedicated_remote_prefix_required")
    return value


def peer_value(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"key_id", "store_id"}:
        raise MemoryError("invalid_sync_peer")
    if (not isinstance(value["key_id"], str) or _KEY.fullmatch(value["key_id"]) is None
            or not isinstance(value["store_id"], str) or _STORE.fullmatch(value["store_id"]) is None):
        raise MemoryError("invalid_sync_peer")
    return dict(value)


def _plain_file(path: Path, *, private: bool, maximum: int) -> tuple[int, os.stat_result]:
    _path(path)
    if os.name == "nt":
        fd = protected_storage.open_file(path, os.O_RDONLY, private=private, trusted=True)
        info = os.fstat(fd)
        if info.st_size > maximum:
            os.close(fd)
            raise MemoryError("unsafe_remote_configuration")
        return fd, info
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_size > maximum
            or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022
            or (private and (info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1))):
        os.close(fd)
        raise MemoryError("unsafe_remote_configuration")
    return fd, info


def executable_sha256(path: Path) -> str:
    """Only explicit configuration/worker startup reads the selected binary."""
    fd, info = _plain_file(path, private=False, maximum=MAX_EXECUTABLE_BYTES)
    with os.fdopen(fd, "rb") as stream:
        if (os.name == "nt" and path.suffix.lower() != ".exe") or (os.name != "nt" and not info.st_mode & 0o111):
            raise MemoryError("remote_executable_not_executable")
        digest = hashlib.sha256()
        count = 0
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > MAX_EXECUTABLE_BYTES:
                raise MemoryError("remote_executable_too_large")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (info.st_size, info.st_mtime_ns, info.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise MemoryError("remote_executable_changed")
    return digest.hexdigest()


def validate_rclone_config(path: Path, remote: str) -> None:
    """Check only the explicitly selected existing config; never discover one.

    Arbitrary wrapper backends, credential helper commands and external SSH
    commands are not accepted. Actual credentials remain inside rclone.
    """
    fd, _ = _plain_file(path, private=True, maximum=MAX_CONFIG_BYTES)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise MemoryError("remote_config_too_large")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeError, configparser.Error):
        raise MemoryError("unsupported_rclone_configuration") from None
    if parser.defaults():
        raise MemoryError("unsupported_rclone_configuration")
    name = remote_path(remote).split(":", 1)[0]
    seen: set[str] = set()
    for _ in range(4):
        if name in seen or not parser.has_section(name):
            raise MemoryError("invalid_remote_configuration_chain")
        seen.add(name)
        section = dict(parser[name])
        kind = section.get("type")
        if kind not in {"drive", "s3", "webdav", "sftp", "crypt"}:
            raise MemoryError("unsupported_remote_backend")
        if any("command" in key or key in {"ssh", "proxy_command"} for key in section):
            raise MemoryError("remote_commands_forbidden")
        if section.get("env_auth", "false").lower() not in {"false", "0", ""}:
            raise MemoryError("implicit_remote_credentials_forbidden")
        if kind == "crypt":
            nested = remote_path(section.get("remote"), allow_empty=True)
            name = nested.split(":", 1)[0]
            continue
        if kind == "webdav" and not section.get("url", "").startswith("https://"):
            raise MemoryError("remote_https_required")
        if kind == "s3" and section.get("endpoint") and not section["endpoint"].startswith("https://"):
            raise MemoryError("remote_https_required")
        if kind == "sftp":
            known = section.get("known_hosts_file", "")
            if not known or not Path(known).is_absolute():
                raise MemoryError("remote_host_key_verification_required")
            fd, _ = _plain_file(Path(known), private=False, maximum=MAX_CONFIG_BYTES)
            os.close(fd)
        return
    raise MemoryError("remote_configuration_chain_too_deep")


class Budget:
    def __init__(self, *, seconds: int, maximum_bytes: int, maximum_files: int):
        self.deadline = time.monotonic() + seconds
        self.maximum_bytes = maximum_bytes
        self.maximum_files = maximum_files
        self.bytes = 0
        self.files = 0
        self.commands = 0

    def remaining(self) -> float:
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise MemoryError("sync_time_budget_exceeded", retryable=True)
        return value

    def transfer(self, size: int) -> None:
        self.remaining()
        if not 0 <= size <= MAX_CAPSULE_BYTES + 1:
            raise MemoryError("remote_capsule_too_large")
        if self.files + 1 > self.maximum_files or self.bytes + size > self.maximum_bytes:
            raise MemoryError("sync_transfer_budget_exceeded", retryable=True)
        self.files += 1
        self.bytes += size


class RcloneBackend:
    """Only exact cursor buckets and immutable signed files cross this boundary."""

    def __init__(
        self, specification: Mapping[str, Any], *, work_directory: Path,
        budget: Budget, active_check: Callable[[], None],
    ):
        self.spec = dict(specification)
        self.executable = _path(Path(self.spec["executable"]))
        self.config_file = _path(Path(self.spec["config_file"]))
        self.remote = remote_path(self.spec["remote"])
        self.work_directory = _path(work_directory)
        self.budget = budget
        self.active_check = active_check
        self.active_check()
        if executable_sha256(self.executable) != self.spec["executable_sha256"]:
            raise MemoryError("remote_executable_changed")
        self.executable_stat = self.executable.stat()
        validate_rclone_config(self.config_file, self.remote)

    def _run(self, arguments: list[str], *, output_limit: int, missing_ok: bool = False) -> bytes | None:
        self.active_check()
        self.budget.commands += 1
        if self.budget.commands > 128:
            raise MemoryError("sync_command_budget_exceeded", retryable=True)
        seconds = max(1, min(15, int(self.budget.remaining())))
        current = self.executable.stat()
        if (current.st_ino, current.st_size, current.st_mtime_ns) != (
                self.executable_stat.st_ino, self.executable_stat.st_size, self.executable_stat.st_mtime_ns):
            raise MemoryError("remote_executable_changed")
        validate_rclone_config(self.config_file, self.remote)
        command = [str(self.executable), *arguments,
                   "--config", str(self.config_file), "--ask-password=false", "--password-command=",
                   "--cache-dir", str(self.work_directory / "cache"), "--temp-dir", str(self.work_directory / "tmp"),
                   "--retries", "1", "--low-level-retries", "1", "--timeout", f"{seconds}s",
                   "--contimeout", "5s", "--max-duration", f"{seconds}s", "--checkers", "1",
                   "--transfers", "1", "--max-backlog", "8", "--buffer-size", "64Ki",
                   "--sftp-disable-hashcheck", "--sftp-ask-password=false", "--drive-skip-shortcuts",
                   "--stats", "0", "--log-level", "ERROR"]
        # Deliberately exclude RCLONE_*, cloud credential variables, SSH agent
        # sockets and inherited Python settings. Existing proxy routing survives.
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        if os.name == "nt":
            # Only the Windows runtime directory and private selected temporary
            # paths are added; no ambient cloud/rclone/SSH credentials return.
            import ctypes
            from ctypes import wintypes
            windows = ctypes.WinDLL("kernel32", use_last_error=True)
            get_directory = windows.GetWindowsDirectoryW
            get_directory.argtypes, get_directory.restype = [wintypes.LPWSTR, wintypes.UINT], wintypes.UINT
            buffer = ctypes.create_unicode_buffer(32768)
            length = get_directory(buffer, len(buffer))
            if not 1 <= length < len(buffer):
                raise MemoryError("remote_windows_runtime_unavailable")
            system = _path(Path(buffer.value))
            environment = {"SystemRoot": str(system), "WINDIR": str(system), "PATH": str(system / "System32"),
                           "TEMP": str(self.work_directory / "tmp"), "TMP": str(self.work_directory / "tmp"), "LANG": "C.UTF-8"}
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            if key in os.environ:
                environment[key] = os.environ[key]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=environment,
                                   start_new_session=os.name != "nt", close_fds=True)
        output = bytearray()
        error_bytes = 0
        finished = False
        deadline = min(self.budget.deadline, time.monotonic() + seconds + 1)

        def consume(label: str, data: bytes) -> None:
            nonlocal error_bytes
            if label == "out":
                output.extend(data)
                if len(output) > output_limit:
                    raise MemoryError("remote_output_limit")
            else:
                # Never persist arbitrary provider messages containing account
                # names, paths, URLs, credentials or content.
                error_bytes += len(data)
                if error_bytes > 16384:
                    raise MemoryError("remote_error_output_limit")

        try:
            if os.name == "nt":
                # Windows selectors cannot select anonymous subprocess pipes.
                # Peek first, then read at most that available count; one reader
                # owns each pipe and never performs a blind blocking read.
                import ctypes
                from ctypes import wintypes
                import msvcrt
                peek = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe
                peek.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
                peek.restype = wintypes.BOOL
                assert process.stdout is not None and process.stderr is not None
                streams = {"out": process.stdout, "error": process.stderr}
                while streams:
                    self.active_check()
                    if time.monotonic() >= deadline:
                        raise MemoryError("remote_timeout", retryable=True)
                    progressed = False
                    for label, stream in list(streams.items()):
                        available = wintypes.DWORD()
                        if not peek(msvcrt.get_osfhandle(stream.fileno()), None, 0, None, ctypes.byref(available), None):
                            if ctypes.get_last_error() not in {109, 232}:  # broken/disconnected pipe only
                                raise MemoryError("remote_pipe_unavailable")
                            del streams[label]
                            continue
                        if available.value:
                            data = os.read(stream.fileno(), min(65536, available.value))
                            if not data:
                                del streams[label]
                            else:
                                consume(label, data)
                            progressed = True
                        elif process.poll() is not None:
                            del streams[label]
                    if streams and not progressed:
                        time.sleep(min(0.02, max(0.001, deadline - time.monotonic())))
            else:
                with selectors.DefaultSelector() as selector:
                    assert process.stdout is not None and process.stderr is not None
                    selector.register(process.stdout, selectors.EVENT_READ, "out")
                    selector.register(process.stderr, selectors.EVENT_READ, "error")
                    while selector.get_map():
                        self.active_check()
                        if time.monotonic() >= deadline:
                            raise MemoryError("remote_timeout", retryable=True)
                        for key, _ in selector.select(timeout=min(0.2, max(0.001, deadline - time.monotonic()))):
                            data = os.read(key.fileobj.fileno(), 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            consume(key.data, data)
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if code == 3 and missing_ok:
                finished = True
                return None
            if code:
                raise MemoryError("remote_command_failed", retryable=True)
            finished = True
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise MemoryError("remote_timeout", retryable=True) from None
        finally:
            if not finished or process.poll() is None:
                try:
                    if os.name == "nt":
                        process.kill()  # Only this explicitly launched rclone process.
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # Bound cleanup as well; no caller waits indefinitely on a
                # provider process that ignores ordinary cancellation.
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=1)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def _bucket(self, key_id: str, store_id: str, after: int) -> str:
        peer_value({"key_id": key_id, "store_id": store_id})
        if not isinstance(after, int) or isinstance(after, bool) or not 0 <= after < 2**63:
            raise MemoryError("invalid_cursor")
        return f"{self.remote}/{key_id}/{store_id}/{after:020d}"

    def candidates(self, key_id: str, store_id: str, after: int) -> list[tuple[str, int]]:
        raw = self._run(["lsf", self._bucket(key_id, store_id, after), "--files-only",
                         "--max-depth", "1", "--disable", "ListR", "--format", "sp", "--separator", "\t"],
                        output_limit=MAX_LIST_BYTES, missing_ok=True)
        if raw is None:
            return []
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeError:
            raise MemoryError("invalid_remote_listing") from None
        if len(lines) > MAX_PREFIX_CANDIDATES:
            raise MemoryError("remote_candidate_limit")
        results: list[tuple[str, int]] = []
        seen: set[str] = set()
        for line in lines:
            fields = line.split("\t", 1)
            if len(fields) != 2 or not re.fullmatch(r"[0-9]{1,10}", fields[0]):
                raise MemoryError("invalid_remote_listing")
            name = fields[1]
            match = _NAME.fullmatch(name)
            if match is None or int(match[1]) != after or not after < int(match[2]) < 2**63:
                raise MemoryError("invalid_remote_capsule_name")
            size = int(fields[0])
            if size <= 0 or size > MAX_CAPSULE_BYTES or name in seen:
                raise MemoryError("invalid_remote_capsule_size")
            seen.add(name)
            results.append((name, size))
        return sorted(results)

    def download(self, key_id: str, store_id: str, after: int, name: str, size: int) -> bytes:
        match = _NAME.fullmatch(name)
        if match is None or int(match[1]) != after:
            raise MemoryError("invalid_remote_capsule_name")
        # A dishonest listing must not claim one byte and make us read the full
        # capsule ceiling repeatedly. Reserve/read only the expected size plus
        # one byte, which detects growth without defeating the window budget.
        maximum = size + 1
        self.budget.transfer(maximum)
        raw = self._run(["cat", self._bucket(key_id, store_id, after) + "/" + name,
                         "--head", str(maximum), "--max-depth", "1"],
                        output_limit=maximum)
        if raw is None or len(raw) != size:
            raise MemoryError("remote_capsule_size_changed")
        return raw

    def upload(self, source: Path, *, key_id: str, store_id: str, after: int, name: str, expected: bytes) -> None:
        match = _NAME.fullmatch(name)
        if match is None or int(match[1]) != after:
            raise MemoryError("invalid_remote_capsule_name")
        self.budget.transfer(len(expected))
        destination = self._bucket(key_id, store_id, after) + "/" + name
        self._run(["copyto", str(_path(source)), destination, "--immutable", "--no-traverse",
                   "--checksum", "--max-transfer", str(MAX_CAPSULE_BYTES + 64 * 1024),
                   "--cutoff-mode", "HARD"], output_limit=4096)
        # A successful copy command is not proof of exact content. Verify the
        # plaintext bytes even for crypt backends before advancing a send cursor.
        observed = self.download(key_id, store_id, after, name, len(expected))
        if observed != expected:
            raise MemoryError("remote_content_mismatch")

    def _fragment_path(self, key_id: str, store_id: str, group: Mapping[str, Any], fragment: Mapping[str, Any]) -> str:
        peer_value({"key_id": key_id, "store_id": store_id})
        validated = _group(dict(group))
        index = fragment.get("index")
        if type(index) is not int or not 0 <= index < len(validated["fragments"]) or validated["fragments"][index] != fragment:
            raise MemoryError("invalid_remote_group_fragment")
        return f"{self.remote}/{key_id}/{store_id}/groups/{validated['group_id']}/{_fragment_name(fragment)}"

    def download_fragment(self, key_id: str, store_id: str, group: Mapping[str, Any], fragment: Mapping[str, Any]) -> bytes:
        path = self._fragment_path(key_id, store_id, group, fragment)
        maximum = fragment["bytes"] + 1
        self.budget.transfer(maximum)
        raw = self._run(["cat", path, "--head", str(maximum), "--max-depth", "1"], output_limit=maximum)
        if raw is None or len(raw) != fragment["bytes"] or hashlib.sha256(raw).hexdigest() != fragment["sha256"]:
            raise MemoryError("remote_group_fragment_mismatch")
        return raw

    def upload_fragment(
        self, source: Path, *, key_id: str, store_id: str,
        group: Mapping[str, Any], fragment: Mapping[str, Any], expected: bytes,
    ) -> None:
        destination = self._fragment_path(key_id, store_id, group, fragment)
        if len(expected) != fragment["bytes"] or hashlib.sha256(expected).hexdigest() != fragment["sha256"]:
            raise MemoryError("local_group_fragment_mismatch")
        self.budget.transfer(len(expected))
        self._run(["copyto", str(_path(source)), destination, "--immutable", "--no-traverse", "--checksum",
                   "--max-transfer", str(MAX_CAPSULE_BYTES + 64 * 1024), "--cutoff-mode", "HARD"], output_limit=4096)
        if self.download_fragment(key_id, store_id, group, fragment) != expected:
            raise MemoryError("remote_group_fragment_mismatch")
