"""Best-effort publication guard for the optional full client, not the protocol.

Local saving is deliberately unaffected. This guard is not a DLP guarantee,
an encryption layer or a substitute for choosing a private exchange destination.
It never echoes a matched value in an error or receipt.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
import re
from typing import Any

from memory_vault import MAX_BUNDLE_BYTES, MAX_BUNDLE_RECORDS, MemoryError, canonical_bytes, validate_record


MAX_SCAN_BYTES = 2 * MAX_BUNDLE_BYTES
MAX_SCAN_RECORDS = MAX_BUNDLE_RECORDS
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


def _scan_records(records: Iterable[Mapping[str, Any]]) -> Iterator[tuple[Mapping[str, Any], set[str]]]:
    """Share one scanner between immutable review and content-only callers."""
    remaining = MAX_SCAN_BYTES
    remaining_nodes = MAX_SCAN_BYTES
    for count, record in enumerate(records, 1):
        if count > MAX_SCAN_RECORDS or not isinstance(record, Mapping):
            raise MemoryError("publication_scan_limit")
        reasons: set[str] = set()
        # Iterator frames bound scratch space even for a very wide collection.
        pending: list[tuple[Iterator[Any], int]] = [(iter((record,)), 0)]
        while pending:
            frame, depth = pending[-1]
            try:
                value = next(frame)
            except StopIteration:
                pending.pop()
                continue
            remaining_nodes -= 1
            if depth > 32 or remaining_nodes < 0:
                raise MemoryError("publication_scan_limit")
            if isinstance(value, Mapping):
                pending.append(((part for pair in value.items() for part in pair), depth + 1))
            elif isinstance(value, (list, tuple)):
                pending.append((iter(value), depth + 1))
            elif isinstance(value, str):
                try:
                    remaining -= len(value.encode("utf-8"))
                except UnicodeError:
                    raise MemoryError("publication_invalid_text") from None
                if remaining < 0:
                    raise MemoryError("publication_scan_limit")
                if any(pattern.search(value) for pattern in _SECRETS):
                    reasons.add("publication_secret_detected")
                if any(pattern.search(value) for pattern in _LOCAL_PATHS):
                    reasons.add("publication_local_path_detected")
        yield record, reasons


def review_records(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return bounded, content-free findings; never mutate memory or grant trust.

    A finding identifies immutable bytes, not the matched credential/path. The
    shared scanner also serves publication and legacy content-only callers, so
    this review cannot silently use a weaker scanner than the actual sender.
    It is not comprehensive DLP.
    """
    findings: list[dict[str, Any]] = []
    for record, reasons in _scan_records(records):
        memory_id = record.get("memory_id")
        digest = record.get("record_sha256")
        if (not isinstance(memory_id, str) or re.fullmatch(r"mem_[0-9a-f]{40}", memory_id) is None
                or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise MemoryError("publication_invalid_record_identity")
        relations = record.get("relations", [])
        targets = sorted({item["target"] for item in relations if isinstance(item, Mapping)
                          and isinstance(item.get("target"), str)
                          and re.fullmatch(r"mem_[0-9a-f]{40}", item["target"])})
        findings.append({"memory_id": memory_id, "record_sha256": digest,
                         "bytes": len(canonical_bytes(record)), "reasons": sorted(reasons),
                         "dependency_ids": targets})
    return findings


def assert_publishable(
    records: Iterable[Mapping[str, Any]], *, allow_local_paths: bool = False,
    approved_local_path_ids: Iterable[str] = (),
) -> None:
    """Check local operator approvals, never authority received inside memory.

    Secrets have no override. A caller may pass exact immutable record IDs only
    after validating an independently stored operator decision for this batch.
    Arbitrary personal data and unknown credential formats may pass the scan.
    """
    approved: set[str] = set()
    for count, value in enumerate(approved_local_path_ids, 1):
        if count > MAX_SCAN_RECORDS or not isinstance(value, str) or re.fullmatch(r"mem_[0-9a-f]{40}", value) is None:
            raise MemoryError("publication_invalid_approval")
        approved.add(value)
    for record, reasons in _scan_records(records):
        if "publication_secret_detected" in reasons:
            raise MemoryError("publication_secret_detected")
        if "publication_local_path_detected" in reasons and not allow_local_paths:
            memory_id = record.get("memory_id")
            if not isinstance(memory_id, str) or memory_id not in approved:
                raise MemoryError("publication_local_path_detected")
            # Content-only mappings remain a supported caller, but cannot
            # borrow an approved record ID to bypass the publication guard.
            try:
                validate_record(record)
            except (MemoryError, TypeError, ValueError):
                raise MemoryError("publication_invalid_record_identity") from None
