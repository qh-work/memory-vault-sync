#!/usr/bin/env python3
"""Bounded exact signed capsules through explicit rclone or encrypted Drive.

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

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_credentials import config_password, password_reference
from memory_vault_transfer import MAX_CAPSULE_BYTES, _fragment_name, _group, _path
import memory_vault_storage as protected_storage

MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_DUMP_BYTES = 8 * MAX_CONFIG_BYTES
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


def _config_bytes(path: Path) -> bytes:
    fd, before = _plain_file(path, private=True, maximum=MAX_CONFIG_BYTES)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > MAX_CONFIG_BYTES:
        raise MemoryError("remote_config_too_large")
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise MemoryError("remote_configuration_changed", retryable=True)
    return raw


def _encrypted_config(raw: bytes) -> bool:
    # Match rclone's first meaningful line, including its normal comment header.
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith((b"#", b";")):
            continue
        if line == b"RCLONE_ENCRYPT_V0:":
            return True
        if line.startswith(b"RCLONE_ENCRYPT_V"):
            raise MemoryError("unsupported_rclone_configuration_encryption")
        return False
    return False


def _plain_config(raw: bytes) -> dict[str, dict[str, str]]:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeError, configparser.Error):
        raise MemoryError("unsupported_rclone_configuration") from None
    if parser.defaults():
        raise MemoryError("unsupported_rclone_configuration")
    return {name: dict(parser[name]) for name in parser.sections()}


def _validate_config_sections(sections: Mapping[str, Any], remote: str) -> None:
    if (not isinstance(sections, dict) or any(not isinstance(name, str) or not isinstance(section, dict)
            or any(not isinstance(key, str) or not isinstance(value, str) for key, value in section.items())
            for name, section in sections.items())):
        raise MemoryError("unsupported_rclone_configuration")
    # rclone's INI loader can fall back to DEFAULT keys not enumerated in an
    # individual remote's dump. Keep the plaintext no-defaults rule here too.
    if sections.get("DEFAULT"):
        raise MemoryError("unsupported_rclone_configuration")
    name = remote_path(remote).split(":", 1)[0]
    seen: set[str] = set()
    for _ in range(4):
        if name in seen or name not in sections:
            raise MemoryError("invalid_remote_configuration_chain")
        seen.add(name)
        section = {key.lower(): value for key, value in sections[name].items()}
        if len(section) != len(sections[name]):
            raise MemoryError("unsupported_rclone_configuration")
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


def validate_rclone_config(path: Path, remote: str) -> None:
    """Validate a plaintext config without a subprocess or credential access.

    Encrypted configurations require the explicit credential reference and
    pinned rclone executor owned by RcloneBackend; they are never decrypted here.
    """
    raw = _config_bytes(path)
    if _encrypted_config(raw):
        raise MemoryError("rclone_config_password_reference_required")
    _validate_config_sections(_plain_config(raw), remote)


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
        reference = self.spec.get("config_password_ref")
        self.password_reference = None if reference is None else password_reference(reference)
        self._config_password: str | None = None
        self._validated_config_digest: bytes | None = None
        self._ensure_config()

    def _ensure_config(self) -> None:
        raw = _config_bytes(self.config_file)
        digest = hashlib.sha256(raw).digest()
        if digest == self._validated_config_digest:
            return
        if _encrypted_config(raw):
            if self.password_reference is None:
                raise MemoryError("rclone_config_password_reference_required")
            if self._config_password is None:
                self._config_password = config_password(self.password_reference,
                    deadline=min(self.budget.deadline, time.monotonic() + 10), active_check=self.active_check)
            try:
                # This command only reads/decrypts configuration. Do not create
                # a backend until its effective configuration has been checked.
                dumped = self._execute(["config", "dump"], output_limit=MAX_CONFIG_DUMP_BYTES)
                sections = strict_json_loads(dumped if dumped is not None else b"")
            except MemoryError as exc:
                if exc.code == "remote_command_failed":
                    raise MemoryError("rclone_config_unlock_failed") from None
                raise
            finally:
                # Never retain decoded configuration or include provider output
                # in status, diagnostics, errors, logs or a disk file.
                dumped = None
            _validate_config_sections(sections, self.remote)
            del sections
        else:
            if self.password_reference is not None:
                # An explicitly encrypted profile must not silently downgrade
                # after replacement of its selected configuration file.
                raise MemoryError("rclone_config_encryption_required")
            _validate_config_sections(_plain_config(raw), self.remote)
        if hashlib.sha256(_config_bytes(self.config_file)).digest() != digest:
            raise MemoryError("remote_configuration_changed", retryable=True)
        self._validated_config_digest = digest

    def _run(self, arguments: list[str], *, output_limit: int, missing_ok: bool = False) -> bytes | None:
        self._ensure_config()
        result = self._execute(arguments, output_limit=output_limit, missing_ok=missing_ok)
        # Drive may legitimately refresh and persist an OAuth token. Revalidate
        # the encrypted replacement before acknowledging remote publication.
        self._ensure_config()
        return result

    def _execute(self, arguments: list[str], *, output_limit: int, missing_ok: bool = False) -> bytes | None:
        self.active_check()
        self.budget.commands += 1
        if self.budget.commands > 128:
            raise MemoryError("sync_command_budget_exceeded", retryable=True)
        seconds = max(1, min(15, int(self.budget.remaining())))
        current = self.executable.stat()
        if (current.st_ino, current.st_size, current.st_mtime_ns) != (
                self.executable_stat.st_ino, self.executable_stat.st_size, self.executable_stat.st_mtime_ns):
            raise MemoryError("remote_executable_changed")
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
        if self._config_password is not None:
            environment["RCLONE_CONFIG_PASS"] = self._config_password
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, shell=False, env=environment,
                                       start_new_session=os.name != "nt", close_fds=True)
        finally:
            environment.pop("RCLONE_CONFIG_PASS", None)
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
            output[:] = b"\x00" * len(output)

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


def native_drive_specification(value: Mapping[str, Any]) -> dict[str, Any]:
    """Pure explicit configuration validation; no key, credential or cloud read."""
    from memory_vault_network_crypto import encryption_public_descriptor
    names = {"kind", "config_file", "root_folder_id", "encryption_key_path", "recipient_keys", "peers"}
    if not isinstance(value, dict) or set(value) != names or value["kind"] != "native-drive":
        raise MemoryError("invalid_native_drive_backend")
    if (not isinstance(value["root_folder_id"], str)
            or re.fullmatch(r"[A-Za-z0-9_-]{2,256}", value["root_folder_id"]) is None
            or value["root_folder_id"] == "root"):
        raise MemoryError("invalid_native_drive_root")
    recipients, peers = value["recipient_keys"], value["peers"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 32:
        raise MemoryError("native_drive_encryption_required")
    recipients = [encryption_public_descriptor(item) for item in recipients]
    if len({item["key_id"] for item in recipients}) != len(recipients):
        raise MemoryError("network_duplicate_recipient")
    if not isinstance(peers, list) or len(peers) > 16:
        raise MemoryError("invalid_sync_peers")
    peers = [peer_value(item) for item in peers]
    if len({(item["key_id"], item["store_id"]) for item in peers}) != len(peers):
        raise MemoryError("duplicate_sync_peer")
    return {**value, "recipient_keys": sorted(recipients, key=lambda item: item["key_id"]), "peers": peers}


class NativeDriveBackend:
    """The existing signed queue carried as JWE ciphertext, never as plaintext.

    A 4 MiB original capsule/fragment can become a 6 MiB JWE. Ciphertext is split
    into at most two immutable Drive blobs, with an encrypted locator and a
    commit manifest published last. A private ciphertext-only stage preserves
    randomized encryption across interrupted writes. No rclone configuration,
    old share envelope, memory record or signing identity is converted.
    """

    MANIFEST_SCHEMA = "memory-vault-drive-ciphertext-object/v1"
    STAGE_SCHEMA = "memory-vault-drive-ciphertext-stage/v1"
    MANIFEST_BYTES = 128 * 1024
    STAGE_BYTES = 7 * 1024 * 1024

    def __init__(self, specification: Mapping[str, Any], *, work_directory: Path,
                 budget: Budget, active_check: Callable[[], None]):
        from memory_vault_drive import DriveClient, DriveConfig
        import memory_vault_network_crypto as crypto
        self.spec = native_drive_specification(specification)
        self.budget, self.active_check, self.crypto = budget, active_check, crypto
        self.config_file = _path(Path(self.spec["config_file"]))
        self.key_file = _path(Path(self.spec["encryption_key_path"]))
        self.work_directory = _path(work_directory)
        self.active_check()
        # Failure/unlock/dependency errors precede construction of a Drive client.
        self.identity = crypto.EncryptionIdentity.load(self.key_file)
        self.recipients = self.spec["recipient_keys"]
        if self.identity.public_descriptor() not in self.recipients:
            raise MemoryError("native_drive_self_recipient_required")
        config_bytes = _config_bytes(self.config_file)
        config = DriveConfig.from_document(strict_json_loads(config_bytes))
        if config.root_folder_id != self.spec["root_folder_id"]:
            raise MemoryError("sync_configuration_changed")
        self._config_digest = hashlib.sha256(config_bytes).digest()
        key_bytes = _config_bytes(self.key_file)
        if crypto.EncryptionIdentity.from_private_document(strict_json_loads(key_bytes)).public_descriptor() != self.identity.public_descriptor():
            raise MemoryError("sync_configuration_changed")
        self._key_digest = hashlib.sha256(key_bytes).digest()
        self._manifests: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]] = {}
        self._active()
        self.client = DriveClient(config, deadline=budget.deadline, active_check=self._active)

    def _active(self) -> None:
        self.budget.remaining()
        self.active_check()
        if (hashlib.sha256(_config_bytes(self.config_file)).digest() != self._config_digest
                or hashlib.sha256(_config_bytes(self.key_file)).digest() != self._key_digest):
            raise MemoryError("sync_configuration_changed")

    @staticmethod
    def _opaque(value: Any) -> str:
        return hashlib.sha256(canonical_bytes(value)).hexdigest()

    def _context(self, bucket: str, name: str, part: str) -> dict[str, Any]:
        # Backup AAD is independent of a network/roster or share protocol. It
        # exposes opaque transport labels, not the original memory hash/text.
        return {"schema_version": "memory-vault-cloud-backup-context/v1",
                "bucket": bucket, "object": name, "part": part,
                "content_type": "application/json" if part == "locator" else "application/octet-stream"}

    def _bucket(self, key_id: str, store_id: str, after: int) -> str:
        peer_value({"key_id": key_id, "store_id": store_id})
        if type(after) is not int or not 0 <= after < 2**63:
            raise MemoryError("invalid_cursor")
        return "bucket-" + self._opaque(["capsules", key_id, store_id, after])

    @staticmethod
    def _name(name: str, after: int) -> None:
        match = _NAME.fullmatch(name) if isinstance(name, str) else None
        if match is None or int(match[1]) != after or not after < int(match[2]) < 2**63:
            raise MemoryError("invalid_remote_capsule_name")

    def _find(self, parent: str, name: str) -> dict[str, Any] | None:
        self._active()
        page = self.client.list_children(parent, name=name)
        if page["next_page_token"] is not None or len(page["files"]) > 1:
            raise MemoryError("native_drive_ambiguous_name")
        return page["files"][0] if page["files"] else None

    def _folder(self, parent: str, name: str, *, create: bool = False) -> str | None:
        from memory_vault_drive import FOLDER_MIME
        metadata = self._find(parent, name)
        if metadata is None and create:
            created = self.client.create_folder(parent, name)
            metadata = self._find(parent, name)
            if metadata is None or metadata["id"] != created["id"]:
                raise MemoryError("native_drive_ambiguous_name")
        if metadata is None:
            return None
        if metadata["mimeType"] != FOLDER_MIME:
            raise MemoryError("native_drive_object_conflict")
        return metadata["id"]

    def _read_bytes(self, metadata: Mapping[str, Any], maximum: int) -> bytes:
        self._active()
        value = metadata.get("size")
        if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,18}", value) is None or not int(value) <= maximum:
            raise MemoryError("native_drive_invalid_object_size")
        size = int(value)
        self.budget.transfer(size)
        raw = self.client.read_range(metadata["id"], 0, size)
        current = self.client.metadata(metadata["id"])
        if len(raw) != size or any(current.get(key) != metadata.get(key) for key in (
                "id", "name", "parents", "size", "version", "mimeType")):
            raise MemoryError("native_drive_object_changed")
        return raw

    def _put_bytes(self, parent: str, name: str, raw: bytes) -> None:
        metadata = self._find(parent, name)
        if metadata is None:
            self.budget.transfer(len(raw))
            created = self.client.upload_bytes(parent, name, raw)
            metadata = self._find(parent, name)
            if metadata is None or metadata["id"] != created["id"]:
                raise MemoryError("native_drive_ambiguous_name")
        if self._read_bytes(metadata, len(raw)) != raw:
            raise MemoryError("native_drive_object_conflict")

    def _manifest(self, bucket: str, object_name: str, folder: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        metadata = self._find(folder, "COMMIT.json")
        if metadata is None:
            return None  # Uncommitted encrypted chunks never advance a cursor.
        value = strict_json_loads(self._read_bytes(metadata, self.MANIFEST_BYTES))
        names = {"schema_version", "locator", "envelope_bytes", "envelope_sha256", "chunks"}
        if (not isinstance(value, dict) or set(value) != names or value["schema_version"] != self.MANIFEST_SCHEMA
                or type(value["envelope_bytes"]) is not int or not 1 <= value["envelope_bytes"] <= self.crypto.MAX_ENVELOPE_BYTES
                or not isinstance(value["envelope_sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", value["envelope_sha256"]) is None
                or not isinstance(value["chunks"], list) or not 1 <= len(value["chunks"]) <= 2):
            raise MemoryError("native_drive_invalid_manifest")
        total, seen = 0, set()
        for chunk in value["chunks"]:
            if (not isinstance(chunk, dict) or set(chunk) != {"name", "bytes", "sha256"}
                    or type(chunk["bytes"]) is not int or not 1 <= chunk["bytes"] <= MAX_CAPSULE_BYTES
                    or not isinstance(chunk["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", chunk["sha256"]) is None
                    or chunk["name"] != chunk["sha256"] + ".bin" or chunk["name"] in seen):
                raise MemoryError("native_drive_invalid_manifest")
            total += chunk["bytes"]
            seen.add(chunk["name"])
        if total != value["envelope_bytes"]:
            raise MemoryError("native_drive_invalid_manifest")
        raw = self.crypto.decrypt_bytes(value["locator"], self.identity, context=self._context(bucket, object_name, "locator"))
        if len(raw) > 1024:
            raise MemoryError("native_drive_invalid_locator")
        locator = strict_json_loads(raw)
        if (not isinstance(locator, dict) or set(locator) != {"name", "bytes"}
                or not isinstance(locator["name"], str) or len(locator["name"]) > 256
                or type(locator["bytes"]) is not int or not 1 <= locator["bytes"] <= MAX_CAPSULE_BYTES
                or object_name != "object-" + self._opaque(locator["name"])):
            raise MemoryError("native_drive_invalid_locator")
        self._manifests[(bucket, locator["name"])] = (folder, value, locator)
        return value, locator

    def _download_object(self, bucket: str, name: str, size: int) -> bytes:
        item = self._manifests.get((bucket, name))
        if item is None:
            parent = self._folder(self.spec["root_folder_id"], bucket)
            folder = None if parent is None else self._folder(parent, "object-" + self._opaque(name))
            if folder is None or self._manifest(bucket, "object-" + self._opaque(name), folder) is None:
                raise MemoryError("native_drive_object_missing")
            item = self._manifests[(bucket, name)]
        folder, manifest, locator = item
        if locator["bytes"] != size:
            raise MemoryError("remote_capsule_size_changed")
        parts = []
        for chunk in manifest["chunks"]:
            metadata = self._find(folder, chunk["name"])
            if metadata is None:
                raise MemoryError("native_drive_object_missing")
            raw = self._read_bytes(metadata, chunk["bytes"])
            if len(raw) != chunk["bytes"] or hashlib.sha256(raw).hexdigest() != chunk["sha256"]:
                raise MemoryError("native_drive_ciphertext_mismatch")
            parts.append(raw)
        encrypted = b"".join(parts)
        if hashlib.sha256(encrypted).hexdigest() != manifest["envelope_sha256"]:
            raise MemoryError("native_drive_ciphertext_mismatch")
        raw = self.crypto.decrypt_bytes(encrypted, self.identity,
            context=self._context(bucket, "object-" + self._opaque(name), "payload"))
        if len(raw) != size:
            raise MemoryError("remote_capsule_size_changed")
        self._active()
        return raw

    def candidates(self, key_id: str, store_id: str, after: int) -> list[tuple[str, int]]:
        from memory_vault_drive import FOLDER_MIME
        bucket = self._bucket(key_id, store_id, after)
        parent = self._folder(self.spec["root_folder_id"], bucket)
        if parent is None:
            return []
        page = self.client.list_children(parent)
        if page["next_page_token"] is not None or len(page["files"]) > MAX_PREFIX_CANDIDATES:
            raise MemoryError("remote_candidate_limit")
        result = []
        seen = set()
        for metadata in page["files"]:
            name = metadata["name"]
            if metadata["mimeType"] != FOLDER_MIME or re.fullmatch(r"object-[0-9a-f]{64}", name) is None or name in seen:
                raise MemoryError("native_drive_object_conflict")
            seen.add(name)
            item = self._manifest(bucket, name, metadata["id"])
            if item is not None:
                locator = item[1]
                self._name(locator["name"], after)
                result.append((locator["name"], locator["bytes"]))
        return sorted(result)

    def download(self, key_id: str, store_id: str, after: int, name: str, size: int) -> bytes:
        self._name(name, after)
        return self._download_object(self._bucket(key_id, store_id, after), name, size)

    def _upload_object(self, source: Path, bucket: str, name: str, expected: bytes) -> None:
        if not isinstance(expected, bytes) or not 1 <= len(expected) <= MAX_CAPSULE_BYTES:
            raise MemoryError("remote_capsule_too_large")
        fd, before = _plain_file(source, private=True, maximum=MAX_CAPSULE_BYTES)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_CAPSULE_BYTES + 1)
            after = os.fstat(stream.fileno())
            if raw != expected or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise MemoryError("local_remote_source_changed")
        object_name = "object-" + self._opaque(name)
        binding = self._opaque([self.spec["root_folder_id"], bucket, object_name, self.recipients, hashlib.sha256(expected).hexdigest()])
        protected_storage.private_directory(self.work_directory)
        stage = self.work_directory / (binding + ".json")
        locator = {"name": name, "bytes": len(expected)}
        if stage.exists():
            fd = protected_storage.open_file(stage, os.O_RDONLY, private=True)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(self.STAGE_BYTES + 1)
            if len(raw) > self.STAGE_BYTES:
                raise MemoryError("native_drive_invalid_stage")
            staged = strict_json_loads(raw)
            if not isinstance(staged, dict) or set(staged) != {"schema_version", "binding", "payload", "locator"}:
                raise MemoryError("native_drive_invalid_stage")
            if staged["schema_version"] != self.STAGE_SCHEMA or staged["binding"] != binding:
                raise MemoryError("native_drive_invalid_stage")
            if self.crypto.decrypt_bytes(staged["payload"], self.identity,
                    context=self._context(bucket, object_name, "payload")) != expected:
                raise MemoryError("native_drive_invalid_stage")
            if self.crypto.decrypt_bytes(staged["locator"], self.identity,
                    context=self._context(bucket, object_name, "locator")) != canonical_bytes(locator):
                raise MemoryError("native_drive_invalid_stage")
            for part in ("payload", "locator"):
                if {item["header"]["kid"] for item in staged[part]["recipients"]} != {item["key_id"] for item in self.recipients}:
                    raise MemoryError("native_drive_invalid_stage")
        else:
            staged = {"schema_version": self.STAGE_SCHEMA, "binding": binding,
                "payload": self.crypto.encrypt_bytes(expected, self.recipients, context=self._context(bucket, object_name, "payload")),
                "locator": self.crypto.encrypt_bytes(canonical_bytes(locator), self.recipients,
                    context=self._context(bucket, object_name, "locator"))}
            raw = canonical_bytes(staged)
            if len(raw) > self.STAGE_BYTES:
                raise MemoryError("native_drive_invalid_stage")
            protected_storage.atomic_write(stage, raw, replace=False)
        stage_bytes = raw
        encrypted = canonical_bytes(staged["payload"])
        chunks = [encrypted[offset:offset + MAX_CAPSULE_BYTES] for offset in range(0, len(encrypted), MAX_CAPSULE_BYTES)]
        manifest = {"schema_version": self.MANIFEST_SCHEMA, "locator": staged["locator"], "envelope_bytes": len(encrypted),
                    "envelope_sha256": hashlib.sha256(encrypted).hexdigest(), "chunks": [
                        {"name": hashlib.sha256(raw).hexdigest() + ".bin", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
                        for raw in chunks]}
        parent = self._folder(self.spec["root_folder_id"], bucket, create=True)
        assert parent is not None
        folder = self._folder(parent, object_name, create=True)
        assert folder is not None
        if self._manifest(bucket, object_name, folder) is None:
            for chunk, raw in zip(manifest["chunks"], chunks):
                self._put_bytes(folder, chunk["name"], raw)
            self._put_bytes(folder, "COMMIT.json", canonical_bytes(manifest))
            # _put_bytes read back the exact independently assembled commit.
            self._manifests[(bucket, name)] = (folder, manifest, locator)
        if self._download_object(bucket, name, len(expected)) != expected:
            raise MemoryError("remote_content_mismatch")
        # Only this exact, validated ciphertext cache is removed after success.
        fd = protected_storage.open_file(stage, os.O_RDONLY, private=True)
        with os.fdopen(fd, "rb") as stream:
            if stream.read(self.STAGE_BYTES + 1) != stage_bytes:
                raise MemoryError("native_drive_invalid_stage")
            selected = os.fstat(stream.fileno())
            named = stage.lstat()
            if (selected.st_dev, selected.st_ino) != (named.st_dev, named.st_ino):
                raise MemoryError("native_drive_invalid_stage")
        stage.unlink()

    def upload(self, source: Path, *, key_id: str, store_id: str, after: int, name: str, expected: bytes) -> None:
        self._name(name, after)
        self._upload_object(source, self._bucket(key_id, store_id, after), name, expected)

    def _fragment_bucket(self, key_id: str, store_id: str, group: Mapping[str, Any], fragment: Mapping[str, Any]) -> str:
        peer_value({"key_id": key_id, "store_id": store_id})
        validated = _group(dict(group))
        index = fragment.get("index")
        if type(index) is not int or not 0 <= index < len(validated["fragments"]) or validated["fragments"][index] != fragment:
            raise MemoryError("invalid_remote_group_fragment")
        return "group-" + self._opaque([key_id, store_id, validated["group_id"]])

    def download_fragment(self, key_id: str, store_id: str, group: Mapping[str, Any], fragment: Mapping[str, Any]) -> bytes:
        raw = self._download_object(self._fragment_bucket(key_id, store_id, group, fragment), _fragment_name(fragment), fragment["bytes"])
        if hashlib.sha256(raw).hexdigest() != fragment["sha256"]:
            raise MemoryError("remote_group_fragment_mismatch")
        return raw

    def upload_fragment(self, source: Path, *, key_id: str, store_id: str,
                        group: Mapping[str, Any], fragment: Mapping[str, Any], expected: bytes) -> None:
        if len(expected) != fragment["bytes"] or hashlib.sha256(expected).hexdigest() != fragment["sha256"]:
            raise MemoryError("local_group_fragment_mismatch")
        self._upload_object(source, self._fragment_bucket(key_id, store_id, group, fragment), _fragment_name(fragment), expected)
