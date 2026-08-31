"""Best-effort publication guard for the optional full client, not the protocol.

Canonical local saving is deliberately unaffected. The v0.21 wire adapter also
uses this scanner for its historically restricted input/output envelopes; that
compatibility rule is not a restriction on ordinary core/MCP local persistence.
This guard is not a DLP guarantee, encryption or a substitute for choosing a
private exchange destination. It never echoes a matched value in an error.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
import re
import unicodedata
from typing import Any

from memory_vault import MAX_BUNDLE_BYTES, MAX_BUNDLE_RECORDS, MemoryError, canonical_bytes, validate_record


MAX_SCAN_BYTES = 2 * MAX_BUNDLE_BYTES
MAX_SCAN_RECORDS = MAX_BUNDLE_RECORDS
_SECRETS = (
    # Preserve the actual v0.21 publication scanner, including its minimum
    # lengths. Recognizing an old capability-shaped string does not restore
    # that capability or make memory an authorization source.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"(?<![A-Za-z0-9_])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"AIza[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:ya29\.|GOCSPX-)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(r"\bx(?:ox[baprs]|app)-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:glpat|glrt|gloas)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:npm_|hf_)[A-Za-z0-9]{30,}\b"),
    re.compile(r"\b(?:pypi-|sq0(?:atp|csp)-)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bdop_v1_[0-9a-fA-F]{64}\b"),
    re.compile(r"(?i)\b(?:Cookie|Set-Cookie)\s*:\s*\S+"),
    re.compile(r"(?i)(?:--session-token|session[_-]?token)(?:\s*[:=]\s*|\s+)[\"']?[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"),
    re.compile(r"(?i)(?:\[\[\s*)?memory-vault-handoff\s*:\s*[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"),
    re.compile(r"mvrd_[A-Za-z0-9_-]{43}"),
    re.compile(r"(?i)\b(?:password|passwd|api[_-]?(?:key|token)|access[_-]?token|refresh[_-]?token|oauth[_-]?token|session[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|webhook[_-]?secret)\s*[:=]\s*[\"']?[^\s\"']{12,}"),
    # This newer full-client check was not present in the v0.21 scanner.
    re.compile(r"\bhttps?://[^\s/@:]{1,128}:[^\s/@]{1,256}@"),
)
_LOCAL_PATHS = (
    # The first two patterns retain the newer anywhere-in-text checks; the
    # remaining patterns restore old path families at their original boundaries.
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home|private|var|tmp|Volumes)/[^\s\"<>]+"),
    re.compile(r"(?i)\b[A-Z]:[\\/](?:Users|Documents and Settings)[\\/][^\r\n\"<>]+"),
    re.compile(r"(?:^|[\s\"'(`])/(?:Users|home|root|tmp|var|private|Volumes|content|mnt|etc|opt|Applications|Library|System|bin|sbin|run|dev|proc|sys|srv|data|workspace|workspaces|project|projects|repo|repos|build|app|usr/(?:local|bin|sbin|share|lib|include))/"),
    re.compile(r"(?:^|[\s\"'(`])[A-Za-z]:[\\/]"),
    re.compile(r"(?:^|[\s\"'(`])\\\\[^\\\s]+\\[^\\\s]+"),
    re.compile(r"(?:^|[\s\"'(`])~[\\/]"),
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
                # Keep both original and legacy NFC scan semantics: composition
                # can hide an ASCII token suffix which matched in the original.
                # At most two projections; canonical bytes/IDs stay unchanged.
                normalized = unicodedata.normalize("NFC", value)
                scanned = (value,) if normalized == value else (value, normalized)
                if any(pattern.search(text) for text in scanned for pattern in _SECRETS):
                    reasons.add("publication_secret_detected")
                if any(pattern.search(text) for text in scanned for pattern in _LOCAL_PATHS):
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
