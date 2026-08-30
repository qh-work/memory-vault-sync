"""Best-effort publication guard for the optional full client, not the protocol.

Local saving is deliberately unaffected. This guard is not a DLP guarantee,
an encryption layer or a substitute for choosing a private exchange destination.
It never echoes a matched value in an error or receipt.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from memory_vault import MemoryError


MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_SCAN_RECORDS = 4096
_SECRETS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255})\b"),
    re.compile(r"\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,255}|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{15,255}|AIza[A-Za-z0-9_-]{30,64})\b"),
    re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,1024}"),
    re.compile(r"(?i)\b(?:password|client_secret|refresh_token|access_token|api_key)\s*[=:]\s*[\"']?[^\s\"'<>]{16,256}"),
    re.compile(r"\bhttps?://[^\s/@:]{1,128}:[^\s/@]{1,256}@"),
)
_LOCAL_PATHS = (
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home|private|var|tmp|Volumes)/[^\s\"<>]+"),
    re.compile(r"(?i)\b[A-Z]:[\\/](?:Users|Documents and Settings)[\\/][^\r\n\"<>]+"),
)


def assert_publishable(records: Iterable[Mapping[str, Any]], *, allow_local_paths: bool = False) -> None:
    """Raise a content-free error before publishing a suspicious batch.

    Secret matches cannot be overridden here. Local-path detection can be
    disabled only by an explicit operator setting, never by a memory field.
    Arbitrary personal data and unknown credential formats may pass the scan.
    """
    remaining = MAX_SCAN_BYTES
    for count, record in enumerate(records, 1):
        if count > MAX_SCAN_RECORDS or not isinstance(record, Mapping):
            raise MemoryError("publication_scan_limit")
        pending: list[tuple[Any, int]] = [(record, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 32:
                raise MemoryError("publication_scan_limit")
            if isinstance(value, Mapping):
                pending.extend((part, depth + 1) for pair in value.items() for part in pair)
            elif isinstance(value, (list, tuple)):
                pending.extend((part, depth + 1) for part in value)
            elif isinstance(value, str):
                try:
                    remaining -= len(value.encode("utf-8"))
                except UnicodeError:
                    raise MemoryError("publication_invalid_text") from None
                if remaining < 0:
                    raise MemoryError("publication_scan_limit")
                if any(pattern.search(value) for pattern in _SECRETS):
                    raise MemoryError("publication_secret_detected")
                if not allow_local_paths and any(pattern.search(value) for pattern in _LOCAL_PATHS):
                    raise MemoryError("publication_local_path_detected")
