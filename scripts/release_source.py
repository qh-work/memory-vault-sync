"""Bounded, content-free Git source gate shared by the public builders.

This proves selected source bytes match the current committed tree. It cannot
prove that committed prose/code is free of private content; release review and
private-value scanning remain independent mandatory publication gates.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
from typing import Sequence


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TREE_BYTES = 2 * 1024 * 1024
MAX_TREE_ENTRIES = 8192
MAX_SELECTED_FILES = 512
MAX_SELECTED_BYTES = 32 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 15
_SHA = re.compile(r"[0-9a-f]{40}")


class SourceError(ValueError):
    """A fixed error code only: never source names, values or Git stderr."""


def git_environment() -> dict[str, str]:
    # Do not let a caller redirect this read-only inspection to another index,
    # object directory, worktree or alternate repository through environment.
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1")
    return environment


class ReleaseSource:
    def __init__(self, root: Path, source_commit: str | None = None):
        self.root = Path(root).absolute()
        if (".." in self.root.parts or not self.root.is_dir()
                or any(path.is_symlink() for path in (self.root, *self.root.parents))):
            raise SourceError("release_source_root_invalid")
        observed_root = self._git(["rev-parse", "--show-toplevel"], maximum=32768).rstrip(b"\r\n")
        if Path(os.fsdecode(observed_root)) != self.root:
            raise SourceError("release_source_root_mismatch")
        self.commit = self._head()
        if source_commit is not None and (
                not isinstance(source_commit, str) or _SHA.fullmatch(source_commit) is None
                or source_commit != self.commit):
            raise SourceError("release_source_commit_not_current_head")
        raw = self._git(["ls-tree", "-r", "-z", "-l", self.commit], maximum=MAX_TREE_BYTES)
        self._entries: dict[str, tuple[str, int, str]] = {}
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                metadata, encoded_name = item.split(b"\t", 1)
                mode, kind, oid, encoded_size = metadata.split()
                name = os.fsdecode(encoded_name)
                size = int(encoded_size) if kind == b"blob" else -1
                entry = (oid.decode("ascii"), size, mode.decode("ascii"))
            except (ValueError, UnicodeError):
                raise SourceError("release_source_tree_invalid") from None
            if name in self._entries or _SHA.fullmatch(entry[0]) is None:
                raise SourceError("release_source_tree_invalid")
            self._entries[name] = entry
            if len(self._entries) > MAX_TREE_ENTRIES:
                raise SourceError("release_source_tree_limit")
        self._blobs: dict[str, bytes] = {}
        self._selected: set[str] = set()
        self._selected_bytes = 0

    def _git(self, arguments: Sequence[str], *, maximum: int) -> bytes:
        command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                   "-C", str(self.root), *arguments]
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, env=git_environment())
        except OSError:
            raise SourceError("release_source_git_unavailable") from None

        def stop() -> None:
            with contextlib.suppress(OSError):
                process.kill()

        timer = threading.Timer(GIT_TIMEOUT_SECONDS, stop)
        timer.daemon = True
        timer.start()
        try:
            assert process.stdout is not None
            data = process.stdout.read(maximum + 1)
            if len(data) > maximum:
                stop()
                raise SourceError("release_source_git_output_limit")
            if process.wait(timeout=GIT_TIMEOUT_SECONDS) != 0:
                raise SourceError("release_source_git_failed")
            return data
        except (OSError, subprocess.TimeoutExpired):
            raise SourceError("release_source_git_failed") from None
        finally:
            timer.cancel()
            stop()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=GIT_TIMEOUT_SECONDS)
            if process.stdout is not None:
                process.stdout.close()

    def _head(self) -> str:
        raw = self._git(["rev-parse", "--verify", "HEAD^{commit}"], maximum=128).strip()
        if re.fullmatch(rb"[0-9a-f]{40}", raw) is None:
            raise SourceError("release_source_head_invalid")
        return raw.decode("ascii")

    @staticmethod
    def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    def read(self, path: Path) -> bytes:
        """Reject untracked candidates before reading their possibly private bytes."""
        path = Path(path).absolute()
        try:
            name = path.relative_to(self.root).as_posix()
        except ValueError:
            raise SourceError("release_source_outside_root") from None
        if ".." in path.parts or name not in self._entries:
            raise SourceError("release_source_untracked_input")
        oid, size, mode = self._entries[name]
        if mode not in {"100644", "100755"} or not 0 <= size <= MAX_SOURCE_BYTES:
            raise SourceError("release_source_unsupported_input")
        if name not in self._selected:
            if len(self._selected) >= MAX_SELECTED_FILES or self._selected_bytes + size > MAX_SELECTED_BYTES:
                raise SourceError("release_source_selection_limit")
            self._selected.add(name)
            self._selected_bytes += size
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise SourceError("release_source_unsafe_input")
        try:
            before = path.lstat()
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != size
                    or int(getattr(before, "st_file_attributes", 0)) & 0x400):
                raise SourceError("release_source_changed_input")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if self._fingerprint(before) != self._fingerprint(opened):
                    raise SourceError("release_source_changed_input")
                data = stream.read(MAX_SOURCE_BYTES + 1)
                if (self._fingerprint(os.fstat(stream.fileno())) != self._fingerprint(opened)
                        or self._fingerprint(path.lstat()) != self._fingerprint(opened)):
                    raise SourceError("release_source_changed_input")
        except OSError:
            raise SourceError("release_source_unavailable_input") from None
        if oid not in self._blobs:
            committed = self._git(["show", "--no-ext-diff", "--no-textconv", oid], maximum=MAX_SOURCE_BYTES)
            if len(committed) != size:
                raise SourceError("release_source_blob_invalid")
            self._blobs[oid] = committed
        if data != self._blobs[oid]:
            raise SourceError("release_source_changed_input")
        return self._blobs[oid]

    def assert_current(self) -> None:
        """Recheck only selected inputs; unrelated dirty files do not block a build."""
        if self._head() != self.commit:
            raise SourceError("release_source_head_changed")
        for name in sorted(self._selected):
            self.read(self.root / name)
