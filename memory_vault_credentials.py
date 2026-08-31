#!/usr/bin/env python3
"""Read one explicitly referenced OS credential for an encrypted rclone config.

No password discovery, credential creation, shell, configurable helper command,
or secret file. References are local operator configuration, never memory data.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping

from memory_vault import MemoryError

MAX_PASSWORD_BYTES = 16 * 1024
MAX_REFERENCE_BYTES = 8 * 1024
_ATTRIBUTE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")


def _label(value: Any, *, empty: bool = False) -> str:
    if (not isinstance(value, str) or (not value and not empty)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise MemoryError("invalid_rclone_password_reference")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise MemoryError("invalid_rclone_password_reference") from None
    if size > 1024:
        raise MemoryError("invalid_rclone_password_reference")
    return value


def password_reference(value: Any) -> dict[str, Any]:
    """Validate metadata only; configuration/status never retrieves a secret."""
    if not isinstance(value, dict):
        raise MemoryError("invalid_rclone_password_reference")
    kind = value.get("kind")
    if kind == "macos-generic" and set(value) == {"kind", "service", "account"}:
        return {"kind": kind, "service": _label(value["service"]), "account": _label(value["account"])}
    if kind == "macos-internet" and set(value) == {"kind", "server", "account", "protocol", "path", "port"}:
        if (not isinstance(value["protocol"], str) or value["protocol"] not in {"http", "https"} or type(value["port"]) is not int
                or not 0 <= value["port"] <= 65535):
            raise MemoryError("invalid_rclone_password_reference")
        return {"kind": kind, "server": _label(value["server"]), "account": _label(value["account"]),
                "protocol": value["protocol"], "path": _label(value["path"], empty=True), "port": value["port"]}
    if kind == "windows-credential" and set(value) == {"kind", "target"}:
        return {"kind": kind, "target": _label(value["target"])}
    if kind == "linux-secret-service" and set(value) == {"kind", "attributes"}:
        attributes = value["attributes"]
        if (not isinstance(attributes, dict) or not 1 <= len(attributes) <= 8
                or any(not isinstance(key, str) or _ATTRIBUTE.fullmatch(key) is None for key in attributes)):
            raise MemoryError("invalid_rclone_password_reference")
        return {"kind": kind, "attributes": {key: _label(attributes[key]) for key in sorted(attributes)}}
    raise MemoryError("invalid_rclone_password_reference")


def _password(raw: bytes, *, encoding: str = "utf-8", terminal_newline: bool = False) -> str:
    if terminal_newline:
        # The fixed OS helpers add one terminal newline. Do not strip spaces
        # or arbitrary password characters as generic whitespace.
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
    if not 1 <= len(raw) <= MAX_PASSWORD_BYTES:
        raise MemoryError("rclone_config_password_unavailable")
    try:
        result = raw.decode(encoding)
    except UnicodeError:
        raise MemoryError("rclone_config_password_unavailable") from None
    if not result or any(character in result for character in ("\x00", "\r", "\n")):
        raise MemoryError("rclone_config_password_unavailable")
    return result


def _fixed_helper(arguments: list[str], *, deadline: float, active_check: Callable[[], None]) -> bytes:
    """Bound the two fixed POSIX credential utilities, capturing secrets privately."""
    executable = Path(arguments[0])
    try:
        info = executable.lstat()
    except OSError:
        raise MemoryError("rclone_password_provider_unavailable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise MemoryError("unsafe_rclone_password_provider")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    if arguments[0] == "/usr/bin/secret-tool":
        # Only the current desktop's Unix session bus, not command/password
        # variables or arbitrary provider credentials, reaches libsecret.
        address = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
        if address:
            if not address.startswith("unix:") or len(address) > 4096 or "\x00" in address:
                raise MemoryError("rclone_password_provider_unavailable")
            environment["DBUS_SESSION_BUS_ADDRESS"] = address
        runtime = os.environ.get("XDG_RUNTIME_DIR", "")
        if runtime and Path(runtime).is_absolute() and "\x00" not in runtime:
            environment["XDG_RUNTIME_DIR"] = runtime
    active_check()
    if time.monotonic() >= deadline:
        raise MemoryError("rclone_password_provider_timeout", retryable=True)
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=environment,
                                   close_fds=True, start_new_session=True)
    except OSError:
        raise MemoryError("rclone_password_provider_unavailable") from None
    output = bytearray()
    errors = 0
    finished = False
    try:
        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, "out")
            selector.register(process.stderr, selectors.EVENT_READ, "error")
            while selector.get_map():
                active_check()
                if time.monotonic() >= deadline:
                    raise MemoryError("rclone_password_provider_timeout", retryable=True)
                for key, _ in selector.select(timeout=min(0.1, max(0.001, deadline - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        selector.unregister(key.fileobj)
                    elif key.data == "out":
                        output.extend(data)
                        if len(output) > MAX_PASSWORD_BYTES + 2:
                            raise MemoryError("rclone_config_password_unavailable")
                    else:
                        errors += len(data)
                        if errors > MAX_PASSWORD_BYTES:
                            raise MemoryError("rclone_config_password_unavailable")
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if code:
            raise MemoryError("rclone_config_password_unavailable")
        finished = True
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise MemoryError("rclone_password_provider_timeout", retryable=True) from None
    finally:
        if not finished or process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=1)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        output[:] = b"\x00" * len(output)


def _windows_password(target: str) -> str:
    import ctypes
    from ctypes import wintypes

    class Credential(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                    ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                    ("UserName", wintypes.LPWSTR)]

    library = ctypes.WinDLL("advapi32", use_last_error=True)
    read = library.CredReadW
    read.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                     ctypes.POINTER(ctypes.POINTER(Credential))]
    read.restype = wintypes.BOOL
    release = library.CredFree
    release.argtypes, release.restype = [ctypes.c_void_p], None
    pointer = ctypes.POINTER(Credential)()
    if not read(target, 1, 0, ctypes.byref(pointer)):  # CRED_TYPE_GENERIC, exact target
        raise MemoryError("rclone_config_password_unavailable")
    try:
        value = pointer.contents
        if not 1 <= value.CredentialBlobSize <= MAX_PASSWORD_BYTES or not value.CredentialBlob:
            raise MemoryError("rclone_config_password_unavailable")
        return _password(ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize), encoding="utf-16-le")
    finally:
        release(pointer)


def config_password(reference: Mapping[str, Any], *, deadline: float,
                    active_check: Callable[[], None]) -> str:
    """Read one exact OS item for this window; never enroll or prompt for login."""
    selected = password_reference(reference)
    active_check()
    if time.monotonic() >= deadline:
        raise MemoryError("rclone_password_provider_timeout", retryable=True)
    kind = selected["kind"]
    if kind == "macos-generic" and sys.platform == "darwin":
        arguments = ["/usr/bin/security", "find-generic-password", "-s", selected["service"],
                     "-a", selected["account"], "-w"]
    elif kind == "macos-internet" and sys.platform == "darwin":
        arguments = ["/usr/bin/security", "find-internet-password", "-s", selected["server"],
                     "-a", selected["account"], "-r", "htps" if selected["protocol"] == "https" else "http",
                     "-p", selected["path"], "-P", str(selected["port"]), "-w"]
    elif kind == "linux-secret-service" and sys.platform.startswith("linux"):
        arguments = ["/usr/bin/secret-tool", "lookup", "--"]
        for key, value in selected["attributes"].items():
            arguments.extend((key, value))
    elif kind == "windows-credential" and os.name == "nt":
        result = _windows_password(selected["target"])
        active_check()
        if time.monotonic() >= deadline:
            raise MemoryError("rclone_password_provider_timeout", retryable=True)
        return result
    else:
        raise MemoryError("rclone_password_provider_unsupported")
    return _password(_fixed_helper(arguments, deadline=deadline, active_check=active_check), terminal_newline=True)
