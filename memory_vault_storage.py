"""Explicit protected local storage primitives, with no installation side effects.

Windows uses native handles and discretionary ACLs through the standard library,
not chmod, shell commands, privilege changes, or a claim of same-user isolation.
Only local fixed NTFS volumes are accepted by this initial native profile. New
private objects grant the process user and LocalSystem; existing ACLs are checked,
never silently repaired. POSIX callers can retain their stronger existing checks.

Importing this module does not load a Windows DLL, inspect an account, create a
directory, or touch a file. See docs/PLATFORMS.md for scope and validation status.
"""
from __future__ import annotations

import contextlib
import ctypes
import errno
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys
from typing import Any, Iterator
import uuid


class StorageError(OSError):
    """A content-free native-storage error, not raw account/path diagnostics."""

    def __init__(self, code: str, *, retryable: bool = False):
        self.code = code
        self.retryable = retryable
        super().__init__(code)


_SYSTEM = "S-1-5-18"
_ADMINISTRATORS = "S-1-5-32-544"
_TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_CREATOR_OWNER = "S-1-3-0"
_REPARSE = 0x400
_DIRECTORY = 0x10
_PUBLIC_READ_ACCESS = 0xA01200A9  # generic read/execute, READ_CONTROL, synchronize, file read/EA/attributes/execute
_WIN: Any = None


def _windows_path(value: str) -> str:
    """Pure syntax validation, independently testable without Windows calls."""
    if not isinstance(value, str) or not value or len(value) > 32700 or any(ord(char) < 32 for char in value):
        raise StorageError("invalid_native_storage_path")
    path = PureWindowsPath(value)
    if (not path.is_absolute() or re.fullmatch(r"[A-Za-z]:", path.drive) is None
            or path.root != "\\" or value.startswith(("\\\\", "//"))):
        raise StorageError("local_drive_storage_required")
    for part in path.parts[1:]:
        if (part in {"", ".", ".."} or part.endswith((" ", ".")) or ":" in part
                or any(char in part for char in '<>"|?*')
                or re.fullmatch(r"(?i)(?:con|prn|aux|nul|conin\$|conout\$|clock\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?", part)):
            raise StorageError("invalid_native_storage_path")
    # PureWindowsPath normalizes '.' components; reject them before that step.
    if any(part in {".", ".."} for part in value.replace("/", "\\").split("\\")):
        raise StorageError("invalid_native_storage_path")
    return str(path)


def _acl_allowed(owner: str, user: str, entries: list[tuple[int, int, int, str]], *,
                 private: bool, directory: bool, ancestor: bool = False) -> bool:
    """Conservative allow-list, not a general Windows effective-access engine.

    Unknown/callback/object ACEs fail closed. Deny ACEs cannot create access.
    Inherit-only entries matter for private directories (SQLite sidecars inherit
    permissions); on an ancestor they cannot mutate that already existing node.
    """
    administrators = {user, _SYSTEM, _ADMINISTRATORS}
    trusted = administrators | {_TRUSTED_INSTALLER}
    if (private and owner != user) or (not private and owner not in trusted):
        return False
    for kind, flags, mask, sid in entries:
        if kind not in {0, 1} or flags & ~0x1F or not 0 <= mask <= 0xFFFFFFFF:
            return False
        if kind == 1:
            continue
        inherit_only = bool(flags & 0x08)
        if inherit_only and not (private and directory):
            continue
        permitted = administrators if private else trusted
        if sid in permitted or (directory and inherit_only and sid == _CREATOR_OWNER):
            continue
        if private:
            if mask:
                return False
        else:
            # A volume root commonly lets Users create new subdirectories.
            # That does not let them replace existing protected children. All
            # opened ancestors are also held without delete sharing.
            allowed = _PUBLIC_READ_ACCESS | (0x04 if ancestor and directory else 0)
            if mask & ~allowed:
                return False
    return True


class _NativeWindows:
    """Lazy Win32 bindings; no subprocess, environment credential, or elevation."""

    def __init__(self) -> None:
        from ctypes import wintypes as w
        self.w = w
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]

        class FileInformation(ctypes.Structure):
            _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME), ("access", w.FILETIME),
                        ("write", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD),
                        ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]

        class SidAndAttributes(ctypes.Structure):
            _fields_ = [("sid", ctypes.c_void_p), ("attributes", w.DWORD)]

        class AclHeader(ctypes.Structure):
            _fields_ = [("revision", w.BYTE), ("reserved", w.BYTE), ("size", w.WORD),
                        ("count", w.WORD), ("reserved2", w.WORD)]

        class AceHeader(ctypes.Structure):
            _fields_ = [("kind", w.BYTE), ("flags", w.BYTE), ("size", w.WORD)]

        class Overlapped(ctypes.Structure):
            _fields_ = [("internal", ctypes.c_size_t), ("internal_high", ctypes.c_size_t),
                        ("offset", w.DWORD), ("offset_high", w.DWORD), ("event", w.HANDLE)]

        self.SecurityAttributes, self.FileInformation = SecurityAttributes, FileInformation
        self.SidAndAttributes, self.AclHeader, self.AceHeader, self.Overlapped = SidAndAttributes, AclHeader, AceHeader, Overlapped
        pointer = ctypes.c_void_p
        pp = ctypes.POINTER(pointer)

        def bind(library: Any, name: str, arguments: list[Any], result: Any) -> Any:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
            return function

        self.create_file = bind(self.kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, pointer, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
        self.create_directory = bind(self.kernel, "CreateDirectoryW", [w.LPCWSTR, pointer], w.BOOL)
        self.close = bind(self.kernel, "CloseHandle", [w.HANDLE], w.BOOL)
        self.local_free = bind(self.kernel, "LocalFree", [pointer], pointer)
        self.file_type = bind(self.kernel, "GetFileType", [w.HANDLE], w.DWORD)
        self.file_information = bind(self.kernel, "GetFileInformationByHandle", [w.HANDLE, ctypes.POINTER(FileInformation)], w.BOOL)
        self.final_name = bind(self.kernel, "GetFinalPathNameByHandleW", [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD], w.DWORD)
        self.drive_type = bind(self.kernel, "GetDriveTypeW", [w.LPCWSTR], w.UINT)
        self.volume_information = bind(self.kernel, "GetVolumeInformationW", [w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD),
            ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD], w.BOOL)
        self.get_process = bind(self.kernel, "GetCurrentProcess", [], w.HANDLE)
        self.get_thread = bind(self.kernel, "GetCurrentThread", [], w.HANDLE)
        self.open_process_token = bind(self.security, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
        self.open_thread_token = bind(self.security, "OpenThreadToken", [w.HANDLE, w.DWORD, w.BOOL, ctypes.POINTER(w.HANDLE)], w.BOOL)
        self.token_information = bind(self.security, "GetTokenInformation", [w.HANDLE, ctypes.c_int, pointer, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)
        self.sid_string = bind(self.security, "ConvertSidToStringSidW", [pointer, pp], w.BOOL)
        self.sid_valid = bind(self.security, "IsValidSid", [pointer], w.BOOL)
        self.sid_length = bind(self.security, "GetLengthSid", [pointer], w.DWORD)
        self.convert_descriptor = bind(self.security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, pp, ctypes.POINTER(w.DWORD)], w.BOOL)
        self.get_security = bind(self.security, "GetSecurityInfo", [w.HANDLE, ctypes.c_int, w.DWORD, pp, pp, pp, pp, pp], w.DWORD)
        self.get_control = bind(self.security, "GetSecurityDescriptorControl", [pointer, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)], w.BOOL)
        self.get_ace = bind(self.security, "GetAce", [pointer, w.DWORD, pp], w.BOOL)
        self.lock_file = bind(self.kernel, "LockFileEx", [w.HANDLE, w.DWORD, w.DWORD, w.DWORD, w.DWORD, ctypes.POINTER(Overlapped)], w.BOOL)
        self.unlock_file = bind(self.kernel, "UnlockFileEx", [w.HANDLE, w.DWORD, w.DWORD, w.DWORD, ctypes.POINTER(Overlapped)], w.BOOL)
        self.move_file = bind(self.kernel, "MoveFileExW", [w.LPCWSTR, w.LPCWSTR, w.DWORD], w.BOOL)
        self.user = self._process_user()

    @staticmethod
    def extended(path: Path) -> str:
        return "\\\\?\\" + _windows_path(str(path))

    def failure(self) -> None:
        code = ctypes.get_last_error()
        if code in {2, 3}:
            raise FileNotFoundError(errno.ENOENT, "native_storage_missing")
        if code in {80, 183}:
            raise FileExistsError(errno.EEXIST, "native_storage_exists")
        if code in {32, 33}:
            raise StorageError("native_storage_busy", retryable=True)
        raise StorageError("native_storage_unavailable")

    def string_sid(self, sid: Any) -> str:
        result = ctypes.c_void_p()
        if not sid or not self.sid_valid(sid) or not self.sid_string(sid, ctypes.byref(result)):
            raise StorageError("invalid_native_storage_sid")
        try:
            value = ctypes.wstring_at(result)
            if len(value) > 192 or re.fullmatch(r"S-[0-9]+(?:-[0-9]+)+", value) is None:
                raise StorageError("invalid_native_storage_sid")
            return value
        finally:
            self.local_free(result)

    def no_impersonation(self) -> None:
        token = self.w.HANDLE()
        if self.open_thread_token(self.get_thread(), 0x0008, True, ctypes.byref(token)):
            self.close(token)
            raise StorageError("impersonated_private_storage_unsupported")
        if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN only.
            self.failure()

    def _process_user(self) -> str:
        self.no_impersonation()
        token = self.w.HANDLE()
        if not self.open_process_token(self.get_process(), 0x0008, ctypes.byref(token)):
            self.failure()
        try:
            length = self.w.DWORD()
            self.token_information(token, 1, None, 0, ctypes.byref(length))
            if ctypes.get_last_error() != 122 or not 1 <= length.value <= 16384:
                raise StorageError("native_token_unavailable")
            buffer = ctypes.create_string_buffer(length.value)
            if not self.token_information(token, 1, buffer, len(buffer), ctypes.byref(length)):
                self.failure()
            return self.string_sid(ctypes.cast(buffer, ctypes.POINTER(self.SidAndAttributes)).contents.sid)
        finally:
            self.close(token)

    def volume(self, path: Path) -> None:
        root = str(PureWindowsPath(str(path)).anchor)
        if self.drive_type(root) != 3:  # DRIVE_FIXED; never follow a network mapping.
            raise StorageError("local_fixed_ntfs_required")
        filesystem = ctypes.create_unicode_buffer(32)
        flags = self.w.DWORD()
        if not self.volume_information(root, None, 0, None, None, ctypes.byref(flags), filesystem, len(filesystem)):
            self.failure()
        if filesystem.value.upper() != "NTFS" or not flags.value & 0x00000008:  # FILE_PERSISTENT_ACLS
            raise StorageError("local_fixed_ntfs_required")

    @contextlib.contextmanager
    def attributes(self, *, directory: bool) -> Iterator[Any]:
        descriptor = ctypes.c_void_p()
        inherit = "OICI" if directory else ""
        sddl = f"O:{self.user}D:P(A;{inherit};FA;;;{self.user})(A;{inherit};FA;;;SY)"
        if not self.convert_descriptor(sddl, 1, ctypes.byref(descriptor), None):
            self.failure()
        attributes = self.SecurityAttributes(ctypes.sizeof(self.SecurityAttributes), descriptor, False)
        try:
            yield ctypes.byref(attributes)
        finally:
            self.local_free(descriptor)

    def inspect(self, handle: Any, *, directory: bool, private: bool, trusted: bool = False,
                ancestor: bool = False) -> Any:
        information = self.FileInformation()
        if self.file_type(handle) != 1 or not self.file_information(handle, ctypes.byref(information)):
            raise StorageError("native_disk_file_required")
        if information.attributes & _REPARSE or bool(information.attributes & _DIRECTORY) != directory:
            raise StorageError("native_reparse_or_type_forbidden")
        if not directory and information.links != 1:
            raise StorageError("native_hardlink_forbidden")
        if not private and not trusted:
            return information
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        if self.get_security(handle, 1, 0x00000005, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) != 0:
            raise StorageError("native_acl_unavailable")
        try:
            control, revision = self.w.WORD(), self.w.DWORD()
            if not self.get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)) or not control.value & 0x0004 or not dacl:
                raise StorageError("native_private_dacl_required")
            header = ctypes.cast(dacl, ctypes.POINTER(self.AclHeader)).contents
            if header.revision not in {2, 4} or header.size < ctypes.sizeof(self.AclHeader) or header.count > 256:
                raise StorageError("unsupported_native_acl")
            entries = []
            for index in range(header.count):
                ace = ctypes.c_void_p()
                if not self.get_ace(dacl, index, ctypes.byref(ace)):
                    raise StorageError("unsupported_native_acl")
                body = ctypes.cast(ace, ctypes.POINTER(self.AceHeader)).contents
                offset = int(ace.value) - int(dacl.value)
                if (body.kind not in {0, 1} or body.size < 16 or offset < ctypes.sizeof(self.AclHeader)
                        or offset + body.size > header.size):
                    raise StorageError("unsupported_native_acl")
                sid = ctypes.c_void_p(int(ace.value) + 8)
                count = ctypes.c_ubyte.from_address(int(ace.value) + 9).value
                if (count > 15 or 16 + 4 * count > body.size
                        or not self.sid_valid(sid) or 8 + self.sid_length(sid) > body.size):
                    raise StorageError("unsupported_native_acl")
                mask = ctypes.cast(ctypes.c_void_p(int(ace.value) + 4), ctypes.POINTER(self.w.DWORD)).contents.value
                entries.append((int(body.kind), int(body.flags), int(mask), self.string_sid(sid)))
            if not _acl_allowed(self.string_sid(owner), self.user, entries, private=private, directory=directory, ancestor=ancestor):
                raise StorageError("unprotected_native_storage")
        finally:
            if descriptor:
                self.local_free(descriptor)
        return information

    def matches_path(self, handle: Any, path: Path) -> None:
        buffer = ctypes.create_unicode_buffer(32768)
        length = self.final_name(handle, buffer, len(buffer), 0)
        if not 1 <= length < len(buffer) or buffer.value.casefold() != self.extended(path).casefold():
            raise StorageError("native_storage_path_changed")

    def open(self, path: Path, *, desired: int, disposition: int = 3, attributes: Any = None,
             directory: bool = False, delete_sharing: bool = False) -> Any:
        flags = 0x00200000 | (0x02000000 if directory else 0x00000080)
        handle = self.create_file(self.extended(path), desired, 3 | (4 if delete_sharing else 0), attributes, disposition, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            self.failure()
        return handle


def _native() -> _NativeWindows:
    global _WIN
    if os.name != "nt":
        raise StorageError("native_windows_storage_unavailable")
    if _WIN is None:
        try:
            _WIN = _NativeWindows()
        except (AttributeError, ImportError, OSError) as exc:
            if isinstance(exc, StorageError):
                raise
            raise StorageError("native_windows_storage_unavailable") from None
    _WIN.no_impersonation()
    return _WIN


def require_supported_storage() -> None:
    if os.name == "nt":
        _native()
    elif os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise StorageError("protected_storage_unavailable")


def validate_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise StorageError("absolute_storage_path_required")
    if os.name == "nt":
        _windows_path(str(path))
        _native().volume(path)
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or int(getattr(info, "st_file_attributes", 0)) & _REPARSE:
            raise StorageError("storage_reparse_point_forbidden")
    return path


@contextlib.contextmanager
def _parents(path: Path, *, private: bool = False, trusted: bool = False) -> Iterator[None]:
    native = _native()
    handles = []
    try:
        for parent in reversed(path.parents):
            handle = native.open(parent, desired=0x00020080, directory=True)
            handles.append(handle)
            native.inspect(handle, directory=True, private=private and parent == path.parent,
                           trusted=private or trusted, ancestor=True)
            native.matches_path(handle, parent)
        yield
    finally:
        for handle in reversed(handles):
            native.close(handle)


def private_directory(path: Path, *, create: bool = True) -> None:
    require_supported_storage()
    path = validate_path(path)
    if os.name != "nt":
        if create:
            # Path.mkdir(parents=True, mode=...) applies its mode to the leaf
            # only. Every newly created private ancestor needs its own mode;
            # existing ancestors remain untouched, never silently chmod'd.
            current = Path(path.anchor)
            for part in path.parts[1:]:
                current = current / part
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                observed = current.lstat()
                if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
                    raise StorageError("unsafe_storage_parent")
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise StorageError("unprotected_private_directory")
        return
    native = _native()
    current = Path(path.anchor)
    handles = []
    try:
        for part in [None, *path.parts[1:]]:
            if part is not None:
                current = current / part
            try:
                handle = native.open(current, desired=0x00020080, directory=True)
            except FileNotFoundError:
                if not create:
                    raise
                with native.attributes(directory=True) as attributes:
                    if not native.create_directory(native.extended(current), attributes) and ctypes.get_last_error() != 183:
                        native.failure()
                handle = native.open(current, desired=0x00020080, directory=True)
            handles.append(handle)
            native.inspect(handle, directory=True, private=current == path, trusted=current != path, ancestor=current != path)
            native.matches_path(handle, current)
    finally:
        for handle in reversed(handles):
            native.close(handle)


def check_private_directory(path: Path) -> None:
    private_directory(path, create=False)


def check_fd(fd: int, *, private: bool = False, trusted: bool = False, directory: bool = False) -> os.stat_result:
    info = os.fstat(fd)
    if os.name == "nt":
        import msvcrt
        _native().inspect(msvcrt.get_osfhandle(fd), directory=directory, private=private, trusted=trusted)
    else:
        valid_kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not valid_kind or (not directory and info.st_nlink != 1):
            raise StorageError("unsafe_storage_file")
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise StorageError("unprotected_private_file")
        if trusted and (info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022):
            raise StorageError("untrusted_storage_file")
    return info


def open_file(path: Path, flags: int, *, private: bool = False, trusted: bool = False) -> int:
    require_supported_storage()
    path = validate_path(path)
    if flags & getattr(os, "O_TRUNC", 0):
        raise StorageError("unsafe_truncating_storage_open")
    if flags & os.O_CREAT:
        if not private:
            raise StorageError("explicit_private_creation_required")
        private_directory(path.parent)
    if os.name != "nt":
        fd = os.open(path, flags | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            check_fd(fd, private=private, trusted=trusted)
            return fd
        except BaseException:
            os.close(fd)
            raise
    native = _native()
    import msvcrt
    access = flags & (os.O_WRONLY | os.O_RDWR)
    if access not in {os.O_RDONLY, os.O_WRONLY, os.O_RDWR}:
        raise StorageError("invalid_storage_access_flags")
    desired = 0x00020080 | (0x80000000 if access != os.O_WRONLY else 0) | (0x40000000 if access != os.O_RDONLY else 0)
    disposition = 1 if flags & os.O_CREAT and flags & os.O_EXCL else 4 if flags & os.O_CREAT else 3
    with _parents(path, private=private, trusted=trusted):
        with native.attributes(directory=False) if flags & os.O_CREAT else contextlib.nullcontext() as attributes:
            handle = native.open(path, desired=desired, disposition=disposition, attributes=attributes)
        try:
            native.inspect(handle, directory=False, private=private, trusted=trusted)
            native.matches_path(handle, path)
            # Access rights belong to the CreateFile handle. Use the documented
            # CRT adoption flags, then explicitly select binary translation.
            fd = msvcrt.open_osfhandle(int(handle), getattr(os, "O_NOINHERIT", 0) | (flags & os.O_APPEND))
            handle = None  # The Python fd now owns and closes the native handle.
            try:
                msvcrt.setmode(fd, os.O_BINARY)
                os.set_inheritable(fd, False)
            except BaseException:
                os.close(fd)
                raise
            return fd
        finally:
            if handle is not None:
                native.close(handle)


def _rename_no_replace(temporary: Path, destination: Path) -> None:
    """One native rename, never a link/unlink crash window or overwrite fallback.

    Called only after publish_file checks sibling paths and the private source. Loading the
    current process's C symbols is lazy and needs no library search, executable,
    network or extra package. Unsupported kernels/filesystems fail closed.
    """
    if sys.platform == "darwin":
        symbol = "renamex_np"
        arguments = (os.fsencode(temporary), os.fsencode(destination), 0x00000004)  # RENAME_EXCL
        signature = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    elif sys.platform.startswith("linux"):
        symbol = "renameat2"
        arguments = (-100, os.fsencode(temporary), -100, os.fsencode(destination), 1)  # AT_FDCWD, RENAME_NOREPLACE
        signature = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    else:
        raise StorageError("atomic_no_replace_unavailable")
    try:
        library = ctypes.CDLL(None, use_errno=True)
        rename = getattr(library, symbol)
    except (AttributeError, OSError):
        raise StorageError("atomic_no_replace_unavailable") from None
    rename.argtypes = signature
    rename.restype = ctypes.c_int
    if rename(*arguments) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        # Callers compare the existing complete bytes on an exact retry.
        raise FileExistsError(error, "private_storage_exists")
    if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
        raise StorageError("atomic_no_replace_unavailable")
    if error == errno.EXDEV:
        raise StorageError("private_sibling_publication_required")
    raise StorageError("atomic_publication_failed", retryable=error in {errno.EINTR, errno.EAGAIN, errno.EBUSY})


def publish_file(
    temporary: Path, destination: Path, *, replace: bool = False, private_parent: bool = True,
) -> None:
    """Publish a caller-flushed private sibling without reading its contents.

    Fixed local NTFS, no COPY_ALLOWED fallback, exact before/after file identity.
    Parents are held without delete-sharing through the move; same-account or
    administrator tampering is not claimed to be an isolation boundary.
    On macOS/Linux, no-replace uses an exclusive rename so interruption cannot
    leave a published inode with a temporary hard-link alias. Existing aliases
    are still rejected; this is not automatic repair of an older damaged file.

    An explicit POSIX output publisher may select private_parent=False after
    its own parent-path checks, but only for no-replace output. The staged and
    newly published file remain private single-link files. Existing exchange
    bytes are never opened or repaired here: FileExistsError lets that caller
    enforce its own new-output or exact-overlap contract. Private state and
    all replacement/Windows publication retain the default strict profile.
    """
    temporary, destination = validate_path(temporary), validate_path(destination)
    if (type(replace) is not bool or type(private_parent) is not bool
            or temporary == destination or temporary.parent != destination.parent
            or not private_parent and (os.name != "posix" or replace)):
        raise StorageError("private_sibling_publication_required")
    if private_parent:
        check_private_directory(destination.parent)
    elif not destination.parent.is_dir():
        raise StorageError("invalid_storage_directory")
    source_fd = open_file(temporary, os.O_RDONLY, private=True)
    try:
        source_info = os.fstat(source_fd)
        if os.name == "nt":
            import msvcrt
            native = _native()
            before = native.inspect(msvcrt.get_osfhandle(source_fd), directory=False, private=True)
            identity = (before.volume, before.index_high, before.index_low)
    finally:
        os.close(source_fd)
    if destination.exists():
        if not private_parent:
            raise FileExistsError(errno.EEXIST, "private_storage_exists")
        check = open_file(destination, os.O_RDONLY, private=True)
        os.close(check)
        if not replace:
            raise FileExistsError(errno.EEXIST, "private_storage_exists")
    if os.name == "nt":
        with _parents(destination, private=True):
            if not native.move_file(native.extended(temporary), native.extended(destination), 0x8 | (0x1 if replace else 0)):
                native.failure()
        check = open_file(destination, os.O_RDONLY, private=True)
        try:
            after = native.inspect(msvcrt.get_osfhandle(check), directory=False, private=True)
            if identity != (after.volume, after.index_high, after.index_low):
                raise StorageError("native_publication_identity_changed")
        finally:
            os.close(check)
    else:
        if replace:
            os.replace(temporary, destination)
        else:
            _rename_no_replace(temporary, destination)
        check = open_file(destination, os.O_RDONLY, private=True)
        try:
            observed = os.fstat(check)
        finally:
            os.close(check)
        if (source_info.st_dev, source_info.st_ino) != (observed.st_dev, observed.st_ino):
            raise StorageError("publication_identity_changed")
        directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def atomic_write(path: Path, data: bytes, *, replace: bool) -> None:
    """Protected sibling temporary, flushed bytes, then no-copy atomic rename.

    Existing destination ACLs are checked, not repaired. NT MoveFileEx uses
    WRITE_THROUGH and never COPY_ALLOWED; rename/power-loss guarantees still
    depend on NTFS and the storage device. No recursive cleanup occurs.
    """
    if not isinstance(data, bytes) or type(replace) is not bool:
        raise StorageError("invalid_atomic_storage_write")
    path = validate_path(path)
    private_directory(path.parent)
    if path.exists():
        fd = open_file(path, os.O_RDONLY, private=True)
        os.close(fd)
        if not replace:
            raise FileExistsError(errno.EEXIST, "private_storage_exists")
    temporary = path.with_name(".memory-" + uuid.uuid4().hex + ".tmp")
    fd = open_file(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, private=True)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        publish_file(temporary, path, replace=replace)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


@contextlib.contextmanager
def file_lock(path: Path, *, create: bool = True, busy_code: str = "storage_busy") -> Iterator[None]:
    """One-byte native nonblocking lock; never wait or erase a lock file."""
    if create:
        private_directory(path.parent)
    fd = open_file(path, os.O_RDWR | (os.O_CREAT if create else 0), private=True)
    try:
        if os.name == "nt":
            import msvcrt
            native = _native()
            overlapped = native.Overlapped()
            handle = msvcrt.get_osfhandle(fd)
            if not native.lock_file(handle, 0x3, 0, 1, 0, ctypes.byref(overlapped)):
                if ctypes.get_last_error() in {32, 33, 158}:
                    raise StorageError(busy_code, retryable=True)
                native.failure()
            try:
                yield
            finally:
                native.unlock_file(handle, 0, 1, 0, ctypes.byref(overlapped))
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EAGAIN, errno.EACCES}:
                    raise StorageError(busy_code, retryable=True) from None
                raise
            yield
    finally:
        os.close(fd)
