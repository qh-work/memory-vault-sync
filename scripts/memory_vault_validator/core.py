#!/usr/bin/env python3
"""Validate repository history, migration records, and memory-network objects.

``VAULT.yaml`` must declare the formally active ``five_layer_v1`` layout.

The validator deliberately uses only the Python standard library.  YAML input
is parsed with PyYAML when it is already available; otherwise a conservative
YAML subset parser is used.  JSON-compatible YAML is always supported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_RUNTIME_DIRECTORY = (
    REPOSITORY_ROOT
    / "plugins"
    / "memory-vault-sync"
    / "scripts"
)
if str(PLUGIN_RUNTIME_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(PLUGIN_RUNTIME_DIRECTORY))

from memory_vault_runtime.protocol import (  # noqa: E402
    ProtocolValueError,
    jcs_json_bytes as _protocol_jcs_json_bytes,
)


FIVE_LAYERS = ("tasks", "sources", "instances", "bindings", "memory")
TEXT_TREES = (*FIVE_LAYERS, "schemas")
LEGACY_COMMIT = "1b5710f802ab2efc56669a8f2ec80e9d2149b0cf"
LEGACY_BRANCH = "legacy/pre-rewrite-20260728"
BASELINE_PATH = Path("migration/legacy/BASELINE.json")

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
WINDOWS_RESERVED_IDS = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
PROJECTION_COMPLETENESS_DIMENSIONS = (
    "goal_and_scope",
    "decisions",
    "rationales",
    "progress",
    "artifacts",
    "conflicts",
    "evidence",
)
LEGACY_COMPLETENESS_BASIS_REASON = (
    "This immutable legacy projection predates per-dimension completeness "
    "bases. Treat the dimension as unknown and trace original evidence before "
    "claiming completeness."
)
ROLL_FORWARD_COMPLETENESS_BASIS_REASON = (
    "Newest verified visible messages have not yet been semantically "
    "reconciled into this dimension."
)

PORTABLE_REQUIRED = {
    "schema_version",
    "vault_id",
    "binding_id",
    "semantic_task_id",
    "workspace_lineage_id",
    "binding_state",
    "base",
}
PORTABLE_BASE_FIELDS = {
    "snapshot_id",
    "manifest_sha256",
    "current_blob_sha",
    "transaction_id",
}
PORTABLE_FORBIDDEN_KEY_PARTS = {
    "instance",
    "path",
    "device",
    "hostname",
    "host",
    "username",
    "user",
    "email",
    "secret",
    "token",
    "password",
    "passwd",
    "cookie",
    "credential",
    "private_key",
    "access_key",
}

BINDING_REQUIRED = {
    "schema_version",
    "binding_id",
    "subject",
    "targets",
    "effective_range",
    "state",
    "confidence",
    "confirmation_basis",
    "evidence",
    "created_at",
    "created_by",
}
STRONG_EVIDENCE_KINDS = {
    "user_confirmation",
    "user_policy_authorization",
    "portable_identity",
    "immutable_manifest_lineage",
    "legacy_record",
}
HASH_ONLY_EVIDENCE_KINDS = {
    "full_hash",
    "partial_hash",
}

EVENT_BASE_REQUIRED = {
    "schema_version",
    "memory_event_id",
    "kind",
    "confidence",
    "source",
    "claim_key",
    "parents",
    "supersedes",
    "conflicts_with",
    "resolves",
    "payload",
    "payload_sha256",
    "hash_profile",
    "event_sha256",
    "created_at",
}
EVENT_V1_REQUIRED = EVENT_BASE_REQUIRED | {"semantic_task_ids"}
EVENT_V2_REQUIRED = EVENT_BASE_REQUIRED
# Historical task projections are a v1 protocol and intentionally keep this
# alias. The active memory-network validator selects a field set by schema.
EVENT_REQUIRED = EVENT_V1_REQUIRED
EVENT_V2_KINDS = {
    "decision",
    "constraint",
    "progress",
    "next_action",
    "hypothesis",
    "artifact_created",
    "artifact_verified",
    "correction",
    "user_preference",
    "conflict_declared",
    "conflict_resolved",
    "checkpoint_note",
}
EVENT_V1_KINDS = EVENT_V2_KINDS | {"binding_decision"}
EPISODE_REQUIRED = {
    "schema_version",
    "episode_id",
    "source_id",
    "source_sequence",
    "parent_episode_ids",
    "captured_at",
    "coverage",
    "included_content",
    "excluded_content",
    "messages",
    "hash_profile",
    "created_at",
    "episode_sha256",
}
EPISODE_ID_RE = re.compile(r"^ep-[0-9a-f]{40}$")
EPISODE_SOURCE_ID_RE = re.compile(r"^src-[0-9a-f]{40}$")
FORBIDDEN_TOTAL_ORDER_KEYS = {
    "global_sequence",
    "global_order",
    "total_order",
    "chronological_rank",
    "timestamp_rank",
    "latest_by_time",
    "authoritative_latest",
    "authoritative_timestamp_order",
    "sort_by_created_at",
}
TIME_ORDER_VALUES = {
    "timestamp",
    "created_at",
    "latest_timestamp",
    "wall_clock",
    "wall_clock_time",
    "global_chronological",
}

CHECKPOINT_REQUIRED = {
    "schema_version",
    "checkpoint_id",
    "scope",
    "authority",
    "basis",
    "summary",
    "hash_profile",
    "created_at",
    "checkpoint_sha256",
}

DRIVE_IMPORT_REQUIRED = {
    "schema_version",
    "import_id",
    "drive_root_id",
    "recorded_at",
    "source_inventories",
    "objects",
    "summary",
}
DRIVE_IMPORT_OBJECT_REQUIRED = {
    "drive_file_id",
    "drive_parent_id",
    "display_name",
    "drive_name",
    "logical_path",
    "size",
    "mime_type",
    "sha256",
    "mapping_status",
    "source_inventory",
    "aliases",
}
DRIVE_IMPORT_SUMMARY_REQUIRED = {
    "total_objects",
    "uniquely_mapped_objects",
    "exact",
    "needs_hash_verification",
    "content_primary",
    "redundant_duplicate",
    "path_ambiguous_objects",
    "missing",
}
DRIVE_IMPORT_STATUSES = {
    "exact",
    "needs_hash_verification",
    "content_primary",
    "redundant_duplicate",
}
DRIVE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{2,256}$")
MIME_TYPE_RE = re.compile(r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")
SECRET_VALUE_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,})",
    re.IGNORECASE,
)
LOCAL_ABSOLUTE_PATH_RE = re.compile(
    r"(?:^|[\s\"'])(?:"
    r"/(?:Users|home|root|tmp|var|private|Volumes|content|mnt)/|"
    r"[A-Za-z]:[\\/]|"
    r"\\\\\\\\"
    r")"
)


@dataclass(frozen=True, order=True)
class Issue:
    code: str
    path: str
    message: str

    def render(self) -> str:
        return f"{self.path}: [{self.code}] {self.message}"


class DataError(ValueError):
    """Raised for an unsafe or unsupported machine-readable document."""


def _reject_json_constant(value: str) -> None:
    raise DataError(f"non-finite JSON number is forbidden: {value}")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DataError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    try:
        return json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_pairs_without_duplicates,
        )
    except (json.JSONDecodeError, TypeError) as exc:
        raise DataError(str(exc)) from exc


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "#" and depth == 0 and (
            index == 0 or value[index - 1].isspace()
        ):
            return value[:index].rstrip()
    return value.rstrip()


def _split_yaml_mapping(value: str) -> tuple[str, str] | None:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == ":" and depth == 0:
            if index + 1 == len(value) or value[index + 1].isspace():
                return value[:index].strip(), value[index + 1 :].strip()
    return None


def _yaml_scalar(value: str) -> Any:
    value = _strip_yaml_comment(value).strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith(('"', "[", "{")):
        return strict_json_loads(value)
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    if re.fullmatch(r"-?(?:0|[1-9]\d*)", value):
        return int(value)
    if re.fullmatch(
        r"-?(?:0|[1-9]\d*)\.\d+(?:[eE][+-]?\d+)?|"
        r"-?(?:0|[1-9]\d*)[eE][+-]?\d+",
        value,
    ):
        number = float(value)
        if not math.isfinite(number):
            raise DataError("non-finite YAML number is forbidden")
        return number
    if value in {"|", ">", "|-", ">-", "|+", ">+"}:
        raise DataError(
            "block scalars require PyYAML; use a quoted string or JSON-compatible YAML"
        )
    if value.startswith(("&", "*", "!", "<<:")):
        raise DataError("YAML anchors, aliases, tags, and merge keys are forbidden")
    return value


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    content: str
    number: int


class _SubsetYamlParser:
    def __init__(self, text: str):
        self.lines: list[_YamlLine] = []
        for number, raw in enumerate(text.splitlines(), 1):
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise DataError(f"line {number}: tabs are forbidden for indentation")
            content = _strip_yaml_comment(raw.lstrip())
            if not content or content in {"---", "..."}:
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            self.lines.append(_YamlLine(indent, content, number))

    def parse(self) -> Any:
        if not self.lines:
            return None
        if self.lines[0].indent != 0:
            raise DataError(
                f"line {self.lines[0].number}: top-level indentation must be zero"
            )
        value, index = self._parse_node(0, 0)
        if index != len(self.lines):
            line = self.lines[index]
            raise DataError(f"line {line.number}: unexpected indentation")
        return value

    def _parse_node(self, index: int, indent: int) -> tuple[Any, int]:
        if index >= len(self.lines):
            raise DataError("unexpected end of YAML document")
        line = self.lines[index]
        if line.indent != indent:
            raise DataError(f"line {line.number}: inconsistent indentation")
        if line.content == "-" or line.content.startswith("- "):
            return self._parse_sequence(index, indent)
        return self._parse_mapping(index, indent)

    def _parse_mapping(
        self, index: int, indent: int, initial: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], int]:
        result = {} if initial is None else initial
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent > indent:
                raise DataError(f"line {line.number}: unexpected indentation")
            if line.content == "-" or line.content.startswith("- "):
                break
            pair = _split_yaml_mapping(line.content)
            if pair is None:
                raise DataError(f"line {line.number}: expected 'key: value'")
            raw_key, raw_value = pair
            key = _yaml_scalar(raw_key)
            if not isinstance(key, str) or not key:
                raise DataError(f"line {line.number}: mapping key must be a string")
            if key in result:
                raise DataError(f"line {line.number}: duplicate YAML key: {key}")
            index += 1
            if raw_value:
                result[key] = _yaml_scalar(raw_value)
            elif index < len(self.lines) and self.lines[index].indent > indent:
                child_indent = self.lines[index].indent
                result[key], index = self._parse_node(index, child_indent)
            else:
                result[key] = None
        return result, index

    def _parse_sequence(self, index: int, indent: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent != indent:
                raise DataError(f"line {line.number}: unexpected list indentation")
            if not (line.content == "-" or line.content.startswith("- ")):
                break
            rest = line.content[1:].strip()
            index += 1
            if not rest:
                if index >= len(self.lines) or self.lines[index].indent <= indent:
                    result.append(None)
                else:
                    item, index = self._parse_node(index, self.lines[index].indent)
                    result.append(item)
                continue
            pair = _split_yaml_mapping(rest)
            if pair is None:
                result.append(_yaml_scalar(rest))
                if index < len(self.lines) and self.lines[index].indent > indent:
                    raise DataError(
                        f"line {self.lines[index].number}: scalar list item "
                        "cannot have nested content"
                    )
                continue

            raw_key, raw_value = pair
            key = _yaml_scalar(raw_key)
            if not isinstance(key, str) or not key:
                raise DataError(f"line {line.number}: mapping key must be a string")
            item: dict[str, Any] = {}
            if raw_value:
                item[key] = _yaml_scalar(raw_value)
            elif index < len(self.lines) and self.lines[index].indent > indent:
                child_indent = self.lines[index].indent
                item[key], index = self._parse_node(index, child_indent)
            else:
                item[key] = None

            if index < len(self.lines) and self.lines[index].indent > indent:
                continuation_indent = self.lines[index].indent
                if self.lines[index].content.startswith("-"):
                    raise DataError(
                        f"line {self.lines[index].number}: unexpected nested list"
                    )
                item, index = self._parse_mapping(
                    index, continuation_indent, initial=item
                )
            result.append(item)
        return result, index


def parse_yaml(text: str) -> Any:
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return strict_json_loads(text)
    try:
        import yaml  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return _SubsetYamlParser(text).parse()
    try:
        value = yaml.safe_load(text)
    except Exception as exc:
        raise DataError(str(exc)) from exc
    return value


def _load_document_bytes(raw: bytes, suffix: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise DataError("UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DataError(f"not valid UTF-8: {exc}") from exc
    if unicodedata.normalize("NFC", text) != text:
        raise DataError("text is not Unicode NFC")
    if suffix == ".json":
        return strict_json_loads(text)
    if suffix in {".yaml", ".yml"}:
        return parse_yaml(text)
    raise DataError(f"unsupported document extension: {suffix}")


def load_document(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DataError(str(exc)) from exc
    return _load_document_bytes(raw, path.suffix.lower())


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _iter_paths_without_following_symlinks(root: Path) -> Iterator[Path]:
    if not root.exists():
        return
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in list(dirnames):
            yield current_path / name
        for name in filenames:
            yield current_path / name


def _iter_documents(root: Path, tree: str) -> Iterator[Path]:
    base = root / tree
    if not base.exists():
        return
    for path in sorted(base.rglob("*")):
        if (
            path.is_file()
            and not path.is_symlink()
            and path.suffix.lower() in {".yaml", ".yml", ".json"}
        ):
            yield path


def _is_nfc_path(path: Path, base: Path) -> bool:
    relative = path.relative_to(base)
    return all(
        unicodedata.normalize("NFC", component) == component
        for component in relative.parts
    )


def _nested_keys(value: Any, prefix: tuple[str, ...] = ()) -> Iterator[tuple]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            current = (*prefix, key_text)
            yield current
            yield from _nested_keys(child, current)
    elif isinstance(value, list):
        for child in value:
            yield from _nested_keys(child, prefix)


def _walk_values(value: Any) -> Iterator[tuple[str | None, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield None, child
            yield from _walk_values(child)


def _required_mapping(
    value: Any,
    required: set[str],
    issues: list[Issue],
    path: str,
    code: str,
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        issues.append(Issue(code, path, "document root must be a mapping"))
        return None
    missing = sorted(required - set(value))
    if missing:
        issues.append(Issue(code, path, f"missing required fields: {', '.join(missing)}"))
    return value


def _exact_keys(
    value: Mapping[str, Any],
    allowed: set[str],
    issues: list[Issue],
    path: str,
    code: str,
    context: str,
) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        issues.append(
            Issue(
                code,
                path,
                f"{context} contains unexpected fields: {', '.join(extras)}",
            )
        )


def _valid_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(ID_RE.fullmatch(value))
        and value.lower() not in WINDOWS_RESERVED_IDS
    )


def _valid_rfc3339(value: Any) -> bool:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_contains_float(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_float(child) for child in value)
    return False


def canonical_json_bytes(value: Any) -> bytes:
    """Return the supported JCS domain.

    IEEE-754 rendering is the only part of RFC 8785 that the standard library
    cannot reproduce exactly for every number.  Vault hash domains therefore
    reject floating-point values and remain an unambiguous JCS subset.
    """
    try:
        return _protocol_jcs_json_bytes(value)
    except ProtocolValueError as exc:
        messages = {
            "integer_outside_ieee754_safe_range": (
                "integers outside the IEEE-754 safe range are forbidden "
                "in hashed JCS domains"
            ),
            "floating_point_forbidden": (
                "floating-point values are forbidden in hashed JCS domains"
            ),
            "non_string_object_key": "JCS object keys must be strings",
        }
        message = messages.get(
            exc.code,
            f"unsupported value in hashed JCS domain: {exc.value_type}",
        )
        raise DataError(message) from exc


def sha256_jcs(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _schema_json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's ``True == 1`` ambiguity."""

    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return (
            set(left) == set(right)
            and all(_schema_json_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _schema_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _resolve_local_schema_ref(
    root_schema: Mapping[str, Any], reference: str
) -> Mapping[str, Any] | None:
    """Resolve the local JSON Pointer references used by vault schemas."""

    if not reference.startswith("#/"):
        return None
    value: Any = root_schema
    for encoded_part in reference[2:].split("/"):
        part = encoded_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value if isinstance(value, Mapping) else None


def _json_schema_subset_errors(
    value: Any,
    schema: Mapping[str, Any],
    root_schema: Mapping[str, Any],
    context: str = "$",
) -> list[str]:
    """Validate the deterministic JSON Schema subset used by the vault.

    The repository validator intentionally has no third-party runtime
    dependency.  This evaluator covers the structural keywords used by the
    task memory projection contract and fails closed on an unresolved local
    reference.  Cross-document semantics remain explicit validator checks.
    """

    errors: list[str] = []

    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str):
            errors.append(f"{context}: $ref must be a string")
        else:
            resolved = _resolve_local_schema_ref(root_schema, reference)
            if resolved is None:
                errors.append(f"{context}: unresolved schema reference {reference!r}")
            else:
                errors.extend(
                    _json_schema_subset_errors(
                        value,
                        resolved,
                        root_schema,
                        context,
                    )
                )

    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for index, branch in enumerate(all_of):
            if not isinstance(branch, Mapping):
                errors.append(f"{context}: allOf[{index}] must be an object")
                continue
            errors.extend(
                _json_schema_subset_errors(value, branch, root_schema, context)
            )

    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        branch_results = [
            _json_schema_subset_errors(value, branch, root_schema, context)
            if isinstance(branch, Mapping)
            else [f"{context}: oneOf branch must be an object"]
            for branch in one_of
        ]
        matches = sum(not result for result in branch_results)
        if matches != 1:
            errors.append(
                f"{context}: must match exactly one oneOf branch, matched {matches}"
            )
            if matches == 0:
                for index, result in enumerate(branch_results):
                    if result:
                        errors.append(
                            f"{context}: oneOf[{index}] failed: {result[0]}"
                        )

    any_of = schema.get("anyOf")
    if isinstance(any_of, list):
        branch_results = [
            _json_schema_subset_errors(value, branch, root_schema, context)
            if isinstance(branch, Mapping)
            else [f"{context}: anyOf branch must be an object"]
            for branch in any_of
        ]
        if not any(not result for result in branch_results):
            errors.append(f"{context}: must match at least one anyOf branch")
            for index, result in enumerate(branch_results):
                if result:
                    errors.append(
                        f"{context}: anyOf[{index}] failed: {result[0]}"
                    )

    conditional = schema.get("if")
    if isinstance(conditional, Mapping):
        condition_matches = not _json_schema_subset_errors(
            value, conditional, root_schema, context
        )
        selected = schema.get("then" if condition_matches else "else")
        if isinstance(selected, Mapping):
            errors.extend(
                _json_schema_subset_errors(
                    value,
                    selected,
                    root_schema,
                    context,
                )
            )

    negated = schema.get("not")
    if isinstance(negated, Mapping) and not _json_schema_subset_errors(
        value, negated, root_schema, context
    ):
        errors.append(f"{context}: value matches a forbidden schema")

    if "const" in schema and not _schema_json_equal(value, schema["const"]):
        errors.append(f"{context}: value must equal {schema['const']!r}")

    enum = schema.get("enum")
    if isinstance(enum, list) and not any(
        _schema_json_equal(value, option) for option in enum
    ):
        errors.append(f"{context}: value is not in the allowed enum")

    expected_type = schema.get("type")
    type_matches = True
    if expected_type is not None:
        allowed_types = (
            expected_type if isinstance(expected_type, list) else [expected_type]
        )

        def matches_type(type_name: Any) -> bool:
            if type_name == "object":
                return isinstance(value, Mapping)
            if type_name == "array":
                return isinstance(value, list)
            if type_name == "string":
                return isinstance(value, str)
            if type_name == "integer":
                return isinstance(value, int) and not isinstance(value, bool)
            if type_name == "number":
                return isinstance(value, (int, float)) and not isinstance(value, bool)
            if type_name == "boolean":
                return isinstance(value, bool)
            if type_name == "null":
                return value is None
            return False

        type_matches = any(matches_type(type_name) for type_name in allowed_types)
        if not type_matches:
            errors.append(
                f"{context}: expected schema type {expected_type!r}, "
                f"found {type(value).__name__}"
            )

    if type_matches and isinstance(value, Mapping):
        required = schema.get("required")
        if isinstance(required, list):
            missing = sorted(
                item
                for item in required
                if isinstance(item, str) and item not in value
            )
            if missing:
                errors.append(
                    f"{context}: missing required fields: {', '.join(missing)}"
                )
        properties = schema.get("properties")
        property_schemas = properties if isinstance(properties, Mapping) else {}
        for key, child in value.items():
            child_schema = property_schemas.get(key)
            if isinstance(child_schema, Mapping):
                errors.extend(
                    _json_schema_subset_errors(
                        child,
                        child_schema,
                        root_schema,
                        f"{context}.{key}",
                    )
                )
            elif schema.get("additionalProperties") is False:
                errors.append(f"{context}: unexpected field {key!r}")

    if type_matches and isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            errors.append(
                f"{context}: requires at least {minimum_items} item(s)"
            )
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            errors.append(
                f"{context}: allows at most {maximum_items} item(s)"
            )
        if schema.get("uniqueItems") is True:
            for left_index, left in enumerate(value):
                if any(
                    _schema_json_equal(left, right)
                    for right in value[:left_index]
                ):
                    errors.append(f"{context}: array items must be unique")
                    break
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, child in enumerate(value):
                errors.extend(
                    _json_schema_subset_errors(
                        child,
                        item_schema,
                        root_schema,
                        f"{context}[{index}]",
                    )
                )

    if type_matches and isinstance(value, str):
        minimum_length = schema.get("minLength")
        maximum_length = schema.get("maxLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            errors.append(
                f"{context}: string is shorter than {minimum_length} character(s)"
            )
        if isinstance(maximum_length, int) and len(value) > maximum_length:
            errors.append(
                f"{context}: string is longer than {maximum_length} character(s)"
            )
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                pattern_matches = re.search(pattern, value) is not None
            except re.error as exc:
                errors.append(f"{context}: invalid schema pattern: {exc}")
            else:
                if not pattern_matches:
                    errors.append(f"{context}: string does not match required pattern")

    if (
        type_matches
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
    ):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{context}: value is below minimum {minimum}")
        maximum = schema.get("maximum")
        if isinstance(maximum, (int, float)) and value > maximum:
            errors.append(f"{context}: value is above maximum {maximum}")

    return errors


def validate_filesystem(root: Path, issues: list[Issue]) -> None:
    for name in FIVE_LAYERS:
        path = root / name
        if not path.is_dir() or path.is_symlink():
            issues.append(
                Issue(
                    "LAYOUT_MISSING",
                    name,
                    "required layer must be a real directory, not a symlink",
                )
            )

    for tree in TEXT_TREES:
        base = root / tree
        if not base.exists():
            if tree == "schemas":
                issues.append(
                    Issue(
                        "LAYOUT_MISSING",
                        tree,
                        "schemas must be a real directory, not a symlink",
                    )
                )
            continue
        if base.is_symlink():
            issues.append(Issue("SYMLINK", tree, "symlink is forbidden"))
            continue
        for path in _iter_paths_without_following_symlinks(base):
            relative = _relative(path, root)
            if path.is_symlink():
                issues.append(Issue("SYMLINK", relative, "symlink is forbidden"))
                continue
            if not _is_nfc_path(path, base):
                issues.append(Issue("PATH_NFC", relative, "path is not Unicode NFC"))
            if not path.is_file():
                continue
            try:
                raw = path.read_bytes()
            except OSError as exc:
                issues.append(Issue("FILE_READ", relative, str(exc)))
                continue
            if raw.startswith(b"\xef\xbb\xbf"):
                issues.append(Issue("UTF8_BOM", relative, "UTF-8 BOM is forbidden"))
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                issues.append(Issue("UTF8", relative, f"not valid UTF-8: {exc}"))
                continue
            if unicodedata.normalize("NFC", text) != text:
                issues.append(Issue("TEXT_NFC", relative, "text is not Unicode NFC"))


def validate_vault(root: Path, issues: list[Issue]) -> None:
    path = root / "VAULT.yaml"
    relative = _relative(path, root)
    try:
        value = load_document(path)
    except DataError as exc:
        issues.append(Issue("VAULT_PARSE", relative, str(exc)))
        return
    except FileNotFoundError:
        issues.append(Issue("VAULT_MISSING", relative, "VAULT.yaml is required"))
        return
    data = _required_mapping(
        value,
        {
            "schema_version",
            "vault_id",
            "active",
            "layout_state",
            "active_layout",
            "authority",
            "write_policy",
            "legacy_ref",
        },
        issues,
        relative,
        "VAULT_FORMAT",
    )
    if data is None:
        return
    expected = {
        "schema_version": "vault-layout/v1",
        "vault_id": "codex-memory-vault",
        "active": True,
        "layout_state": "active",
        "active_layout": "five_layer_v1",
    }
    for key, expected_value in expected.items():
        if data.get(key) != expected_value:
            issues.append(
                Issue(
                    "VAULT_STATE",
                    relative,
                    f"{key} must equal {expected_value!r}",
                )
            )
    authority = data.get("authority")
    expected_authority = {
        "memory_model": "taskless_associative",
        "memory_evidence": "memory/episodes/<shard>/<episode_id>.json",
        "memory_relations": "memory/events/<shard>/<event_id>.json",
        "legacy_task_records": "migration_history_only",
        "latest_by_timestamp": False,
    }
    if not isinstance(authority, Mapping) or any(
        authority.get(key) != expected_value
        for key, expected_value in expected_authority.items()
    ):
        issues.append(
            Issue(
                "VAULT_AUTHORITY",
                relative,
                "authority must declare the taskless associative memory "
                "network and legacy-only task records",
            )
        )
    write_policy = data.get("write_policy")
    expected_write_policy = {
        "authoritative_target": "taskless_memory_network",
        "memory_append_only": True,
        "task_binding_writable": False,
        "legacy_writable": False,
        "single_authoritative_write": True,
        "publication_strategy": (
            "immutable_additions_with_single_disjoint_replay"
        ),
    }
    if not isinstance(write_policy, Mapping) or any(
        write_policy.get(key) != expected_value
        for key, expected_value in expected_write_policy.items()
    ):
        issues.append(
            Issue(
                "VAULT_WRITE_POLICY",
                relative,
                "write_policy must make the taskless memory network "
                "append-only and task bindings read-only",
            )
        )
    for forbidden in ("cutover", "shadow_layout", "authoritative_layout"):
        if forbidden in data:
            issues.append(
                Issue(
                    "VAULT_STATE",
                    relative,
                    f"obsolete pre-cutover field is forbidden: {forbidden}",
                )
            )
    legacy_ref = data.get("legacy_ref")
    if not isinstance(legacy_ref, Mapping):
        issues.append(
            Issue("VAULT_LEGACY_REF", relative, "legacy_ref must be a mapping")
        )
    else:
        if legacy_ref.get("kind") != "git_branch":
            issues.append(
                Issue(
                    "VAULT_LEGACY_REF",
                    relative,
                    "legacy_ref.kind must equal 'git_branch'",
                )
            )
        if legacy_ref.get("ref") != LEGACY_BRANCH:
            issues.append(
                Issue(
                    "VAULT_LEGACY_REF",
                    relative,
                    f"legacy_ref.ref must equal {LEGACY_BRANCH!r}",
                )
            )
        if legacy_ref.get("commit_sha") != LEGACY_COMMIT:
            issues.append(
                Issue(
                    "VAULT_LEGACY_REF",
                    relative,
                    f"legacy_ref.commit_sha must equal {LEGACY_COMMIT}",
                )
            )


def validate_legacy_baseline(root: Path, issues: list[Issue]) -> None:
    path = root / BASELINE_PATH
    relative = _relative(path, root)
    try:
        value = load_document(path)
    except (DataError, FileNotFoundError) as exc:
        issues.append(Issue("LEGACY_BASELINE", relative, str(exc)))
        return
    data = _required_mapping(
        value,
        {
            "schema_version",
            "branch",
            "commit",
            "registry_blob_sha",
            "inventory",
            "rewrite_policy",
        },
        issues,
        relative,
        "LEGACY_BASELINE",
    )
    if data is None:
        return
    if data.get("schema_version") != "legacy-baseline/v1":
        issues.append(
            Issue(
                "LEGACY_BASELINE",
                relative,
                "schema_version must equal 'legacy-baseline/v1'",
            )
        )
    commit = data.get("commit")
    if not isinstance(commit, str) or not GIT_SHA_RE.fullmatch(commit):
        issues.append(
            Issue("LEGACY_BASELINE", relative, "legacy_git_commit must be a Git SHA")
        )
    elif commit != LEGACY_COMMIT:
        issues.append(
            Issue(
                "LEGACY_BASELINE",
                relative,
                f"legacy_git_commit must equal the frozen baseline {LEGACY_COMMIT}",
            )
        )
    if data.get("branch") != LEGACY_BRANCH:
        issues.append(
            Issue(
                "LEGACY_BASELINE",
                relative,
                f"branch must equal {LEGACY_BRANCH!r}",
            )
        )
    if data.get("registry_blob_sha") != "49a201269e2fe3217f6c2af01e01c0e1d84f6372":
        issues.append(
            Issue(
                "LEGACY_BASELINE",
                relative,
                "registry_blob_sha does not match the frozen legacy registry",
            )
        )
    inventory = data.get("inventory")
    if not isinstance(inventory, Mapping):
        issues.append(
            Issue("LEGACY_BASELINE", relative, "inventory must be a mapping")
        )
    else:
        expected_inventory = {
            "visible_records": 54,
            "registry_complete": False,
            "excluded_sensitive_records": 1,
        }
        for key, expected_value in expected_inventory.items():
            if inventory.get(key) != expected_value:
                issues.append(
                    Issue(
                        "LEGACY_BASELINE",
                        relative,
                        f"inventory.{key} must equal {expected_value!r}",
                    )
                )
        if inventory.get("identifiers_retained") is True:
            issues.append(
                Issue(
                    "LEGACY_BASELINE",
                    relative,
                    "sensitive excluded-record identifiers must not be retained",
                )
            )
    rewrite_policy = data.get("rewrite_policy")
    if not isinstance(rewrite_policy, Mapping):
        issues.append(
            Issue("LEGACY_BASELINE", relative, "rewrite_policy must be a mapping")
        )
    else:
        for key in (
            "automatic_alias_from_hash_forbidden",
            "automatic_task_promotion_from_artifact_presence_forbidden",
        ):
            if rewrite_policy.get(key) is not True:
                issues.append(
                    Issue(
                        "LEGACY_BASELINE",
                        relative,
                        f"rewrite_policy.{key} must be true",
                    )
                )

    for forbidden in (
        root / "legacy",
        root / "legacy_backup",
        root / "backup" / "legacy",
        root / "migration" / "legacy-content",
    ):
        if forbidden.exists() or forbidden.is_symlink():
            issues.append(
                Issue(
                    "LEGACY_ON_MAIN",
                    _relative(forbidden, root),
                    "legacy payload is forbidden on main; keep it on the backup branch",
                )
            )


def validate_schemas(root: Path, issues: list[Issue]) -> None:
    schema_root = root / "schemas"
    schema_paths = sorted(schema_root.rglob("*.schema.json"))
    if not schema_paths:
        issues.append(
            Issue(
                "SCHEMA_MISSING",
                "schemas",
                "at least one *.schema.json document is required",
            )
        )
        return
    for path in schema_paths:
        relative = _relative(path, root)
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("SCHEMA_JSON", relative, str(exc)))
            continue
        if not isinstance(value, Mapping):
            issues.append(
                Issue("SCHEMA_JSON", relative, "JSON Schema root must be an object")
            )
            continue
        if not isinstance(value.get("$schema"), str):
            issues.append(
                Issue("SCHEMA_JSON", relative, "JSON Schema must declare $schema")
            )


def _valid_safe_relative_path(value: Any, *, max_length: int = 1024) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value.startswith("/")
        or value.startswith("\\\\")
        or "\\" in value
        or re.match(r"^[A-Za-z]:[\\/]", value)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _valid_import_filename(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 255
        and "/" not in value
        and "\\" not in value
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _scan_drive_import_privacy(
    data: Mapping[str, Any], relative: str, issues: list[Issue]
) -> None:
    for _key, value in _walk_values(data):
        if not isinstance(value, str):
            continue
        if SECRET_VALUE_RE.search(value):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_PRIVACY",
                    relative,
                    "Drive import contains a credential-like value",
                )
            )
        if (
            value.startswith("/")
            or value.startswith("\\\\")
            or re.match(r"^[A-Za-z]:[\\/]", value)
            or LOCAL_ABSOLUTE_PATH_RE.search(value)
        ):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_PATH",
                    relative,
                    "Drive import contains a local absolute path",
                )
            )


def validate_drive_imports(root: Path, issues: list[Issue]) -> None:
    import_root = root / "migration" / "imported"
    if not import_root.exists():
        return
    for path in sorted(import_root.glob("drive-backup-*.json")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = _relative(path, root)
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("DRIVE_IMPORT_PARSE", relative, str(exc)))
            continue
        data = _required_mapping(
            value,
            DRIVE_IMPORT_REQUIRED,
            issues,
            relative,
            "DRIVE_IMPORT_FORMAT",
        )
        if data is None:
            continue
        _exact_keys(
            data,
            DRIVE_IMPORT_REQUIRED,
            issues,
            relative,
            "DRIVE_IMPORT_FORMAT",
            "Drive import",
        )
        if data.get("schema_version") != "drive-import/v1":
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "schema_version must equal 'drive-import/v1'",
                )
            )
        import_id = data.get("import_id")
        if not _valid_id(import_id) or import_id != path.stem:
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "import_id must be a safe id equal to the manifest filename",
                )
            )
        drive_root_id = data.get("drive_root_id")
        if not isinstance(drive_root_id, str) or not DRIVE_ID_RE.fullmatch(
            drive_root_id
        ):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "drive_root_id must be an opaque Drive id",
                )
            )
        if not _valid_rfc3339(data.get("recorded_at")):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "recorded_at must be an RFC 3339 timestamp",
                )
            )

        source_inventories_value = data.get("source_inventories")
        source_inventories: set[str] = set()
        if (
            not isinstance(source_inventories_value, list)
            or not source_inventories_value
        ):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "source_inventories must be a non-empty list",
                )
            )
        else:
            for index, source_inventory in enumerate(source_inventories_value):
                if (
                    not _valid_safe_relative_path(
                        source_inventory, max_length=512
                    )
                    or not source_inventory.startswith("migration/pending/")
                    or not source_inventory.endswith(".json")
                ):
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_PATH",
                            relative,
                            f"source_inventories[{index}] is not a safe "
                            "migration/pending JSON path",
                        )
                    )
                    continue
                if source_inventory in source_inventories:
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_DUPLICATE",
                            relative,
                            "source_inventories values must be unique",
                        )
                    )
                source_inventories.add(source_inventory)

        objects_value = data.get("objects")
        objects = objects_value if isinstance(objects_value, list) else []
        if not isinstance(objects_value, list):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "objects must be a list",
                )
            )
        if len(objects) != 121:
            issues.append(
                Issue(
                    "DRIVE_IMPORT_COUNT",
                    relative,
                    f"objects must contain exactly 121 entries, found {len(objects)}",
                )
            )

        seen_drive_ids: set[str] = set()
        seen_logical_paths: set[str] = set()
        status_counts = {status: 0 for status in DRIVE_IMPORT_STATUSES}
        for index, item in enumerate(objects):
            context = f"objects[{index}]"
            if not isinstance(item, Mapping):
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context} must be a mapping",
                    )
                )
                continue
            missing = sorted(DRIVE_IMPORT_OBJECT_REQUIRED - set(item))
            if missing:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context} missing fields: {', '.join(missing)}",
                    )
                )
            _exact_keys(
                item,
                DRIVE_IMPORT_OBJECT_REQUIRED,
                issues,
                relative,
                "DRIVE_IMPORT_FORMAT",
                context,
            )

            for field in ("drive_file_id", "drive_parent_id"):
                drive_id = item.get(field)
                if not isinstance(drive_id, str) or not DRIVE_ID_RE.fullmatch(
                    drive_id
                ):
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_FORMAT",
                            relative,
                            f"{context}.{field} must be an opaque Drive id",
                        )
                    )
            drive_file_id = item.get("drive_file_id")
            if isinstance(drive_file_id, str):
                if drive_file_id in seen_drive_ids:
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_DUPLICATE",
                            relative,
                            f"duplicate drive_file_id: {drive_file_id}",
                        )
                    )
                seen_drive_ids.add(drive_file_id)

            for field in ("display_name", "drive_name"):
                if not _valid_import_filename(item.get(field)):
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_PATH",
                            relative,
                            f"{context}.{field} must be a safe filename",
                        )
                    )

            logical_path = item.get("logical_path")
            if (
                not _valid_safe_relative_path(logical_path, max_length=512)
                or not isinstance(import_id, str)
                or not logical_path.startswith(f"imports/{import_id}/")
            ):
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_PATH",
                        relative,
                        f"{context}.logical_path must be a safe path below "
                        f"imports/{import_id}/",
                    )
                )
            if isinstance(logical_path, str):
                if logical_path in seen_logical_paths:
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_DUPLICATE",
                            relative,
                            f"duplicate logical_path: {logical_path}",
                        )
                    )
                seen_logical_paths.add(logical_path)

            size = item.get("size")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size < 1
            ):
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context}.size must be a positive integer",
                    )
                )
            mime_type = item.get("mime_type")
            if (
                not isinstance(mime_type, str)
                or len(mime_type) > 127
                or not MIME_TYPE_RE.fullmatch(mime_type)
            ):
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context}.mime_type is invalid",
                    )
                )
            sha256 = item.get("sha256")
            if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context}.sha256 must be a lowercase SHA-256",
                    )
                )

            mapping_status = item.get("mapping_status")
            if mapping_status not in DRIVE_IMPORT_STATUSES:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_STATUS",
                        relative,
                        f"{context}.mapping_status is invalid",
                    )
                )
            else:
                status_counts[str(mapping_status)] += 1

            source_inventory = item.get("source_inventory")
            if source_inventory not in source_inventories:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context}.source_inventory is not declared in "
                        "source_inventories",
                    )
                )

            aliases = item.get("aliases")
            if not isinstance(aliases, list) or not aliases:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"{context}.aliases must be a non-empty list",
                    )
                )
            else:
                seen_aliases: set[str] = set()
                for alias_index, alias in enumerate(aliases):
                    if not _valid_safe_relative_path(alias):
                        issues.append(
                            Issue(
                                "DRIVE_IMPORT_PATH",
                                relative,
                                f"{context}.aliases[{alias_index}] is not a "
                                "safe relative path",
                            )
                        )
                    if isinstance(alias, str) and alias in seen_aliases:
                        issues.append(
                            Issue(
                                "DRIVE_IMPORT_DUPLICATE",
                                relative,
                                f"{context}.aliases values must be unique",
                            )
                        )
                    if isinstance(alias, str):
                        seen_aliases.add(alias)

        summary = data.get("summary")
        if not isinstance(summary, Mapping):
            issues.append(
                Issue(
                    "DRIVE_IMPORT_FORMAT",
                    relative,
                    "summary must be a mapping",
                )
            )
        else:
            missing = sorted(DRIVE_IMPORT_SUMMARY_REQUIRED - set(summary))
            if missing:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_FORMAT",
                        relative,
                        f"summary missing fields: {', '.join(missing)}",
                    )
                )
            _exact_keys(
                summary,
                DRIVE_IMPORT_SUMMARY_REQUIRED,
                issues,
                relative,
                "DRIVE_IMPORT_FORMAT",
                "summary",
            )
            for field in DRIVE_IMPORT_SUMMARY_REQUIRED:
                count = summary.get(field)
                if (
                    not isinstance(count, int)
                    or isinstance(count, bool)
                    or count < 0
                ):
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_COUNT",
                            relative,
                            f"summary.{field} must be a non-negative integer",
                        )
                    )
            if summary.get("total_objects") != len(objects):
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_COUNT",
                        relative,
                        "summary.total_objects must equal the objects count",
                    )
                )
            if summary.get("total_objects") != 121:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_COUNT",
                        relative,
                        "summary.total_objects must equal 121",
                    )
                )
            for status, actual_count in status_counts.items():
                if summary.get(status) != actual_count:
                    issues.append(
                        Issue(
                            "DRIVE_IMPORT_STATUS",
                            relative,
                            f"summary.{status} must equal the number of "
                            f"{status!r} objects ({actual_count})",
                        )
                    )
            uniquely_mapped = (
                status_counts["exact"]
                + status_counts["needs_hash_verification"]
            )
            path_ambiguous = (
                status_counts["content_primary"]
                + status_counts["redundant_duplicate"]
            )
            if summary.get("uniquely_mapped_objects") != uniquely_mapped:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_STATUS",
                        relative,
                        "summary.uniquely_mapped_objects must equal exact plus "
                        "needs_hash_verification",
                    )
                )
            if summary.get("path_ambiguous_objects") != path_ambiguous:
                issues.append(
                    Issue(
                        "DRIVE_IMPORT_STATUS",
                        relative,
                        "summary.path_ambiguous_objects must equal "
                        "content_primary plus redundant_duplicate",
                    )
                )

        _scan_drive_import_privacy(data, relative, issues)


def _valid_optional_sha256(value: Any) -> bool:
    return value is None or (
        isinstance(value, str) and bool(SHA256_RE.fullmatch(value))
    )


def validate_sources(root: Path, issues: list[Issue]) -> None:
    source_root = root / "sources"
    if not source_root.exists():
        return
    for head in sorted(source_root.glob("*/HEAD.json")):
        issues.append(
            Issue(
                "SOURCE_SELECTOR",
                _relative(head, root),
                "HEAD.json is obsolete; SOURCE.json carries the revision selector",
            )
        )
    for directory in sorted(
        path for path in source_root.iterdir() if path.is_dir() and not path.is_symlink()
    ):
        relative_dir = _relative(directory, root)
        source_path = directory / "SOURCE.json"
        if not source_path.is_file() or source_path.is_symlink():
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative_dir,
                    "each source directory must contain one real SOURCE.json",
                )
            )
            continue
        relative = _relative(source_path, root)
        try:
            value = load_document(source_path)
        except DataError as exc:
            issues.append(Issue("SOURCE_PARSE", relative, str(exc)))
            continue
        required = {
            "schema_version",
            "source_id",
            "source_type",
            "external_source_key_sha256",
            "source_instance_id",
            "visibility",
            "sensitivity",
            "current_revision_id",
            "revisions",
            "created_at",
        }
        data = _required_mapping(
            value, required, issues, relative, "SOURCE_FORMAT"
        )
        if data is None:
            continue
        _exact_keys(
            data,
            required,
            issues,
            relative,
            "SOURCE_FORMAT",
            "source",
        )
        source_id = data.get("source_id")
        if data.get("schema_version") != "source/v1":
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "schema_version must equal 'source/v1'",
                )
            )
        if not _valid_id(source_id) or directory.name != source_id:
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "source_id must be portable and match its directory",
                )
            )
        if data.get("source_type") not in {
            "chat_thread",
            "codex_task",
            "workspace_import",
            "document",
            "artifact_manifest",
            "external_note",
            "legacy_record",
        }:
            issues.append(Issue("SOURCE_FORMAT", relative, "source_type is invalid"))
        if not _valid_optional_sha256(data.get("external_source_key_sha256")):
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "external_source_key_sha256 must be null or SHA-256",
                )
            )
        instance_id = data.get("source_instance_id")
        if instance_id is not None and not _valid_id(instance_id):
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "source_instance_id must be null or a portable identifier",
                )
            )
        if data.get("visibility") != "private":
            issues.append(
                Issue("SOURCE_PRIVACY", relative, "source visibility must be private")
            )
        if data.get("sensitivity") not in {
            "ordinary",
            "restricted",
            "encrypted",
            "credentials_excluded",
        }:
            issues.append(Issue("SOURCE_FORMAT", relative, "sensitivity is invalid"))
        current_revision_id = data.get("current_revision_id")
        if not _valid_id(current_revision_id):
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "current_revision_id is invalid",
                )
            )
        if not _valid_rfc3339(data.get("created_at")):
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "created_at must be an RFC 3339 timestamp",
                )
            )

        revisions = data.get("revisions")
        if not isinstance(revisions, list) or not revisions:
            issues.append(
                Issue(
                    "SOURCE_FORMAT",
                    relative,
                    "revisions must be a non-empty list",
                )
            )
            continue
        revision_ids: list[str] = []
        sequences: list[int] = []
        earlier_ids: set[str] = set()
        revision_required = {
            "revision_id",
            "previous_revision_id",
            "source_sequence",
            "captured_at",
            "coverage",
            "content_ref",
            "content_sha256",
            "redaction",
        }
        for index, revision in enumerate(revisions):
            context = f"revisions[{index}]"
            if not isinstance(revision, Mapping):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context} must be a mapping",
                    )
                )
                continue
            missing = sorted(revision_required - set(revision))
            if missing:
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context} missing fields: {', '.join(missing)}",
                    )
                )
            _exact_keys(
                revision,
                revision_required,
                issues,
                relative,
                "SOURCE_FORMAT",
                context,
            )
            revision_id = revision.get("revision_id")
            if not _valid_id(revision_id):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.revision_id is invalid",
                    )
                )
            else:
                revision_ids.append(revision_id)
            previous = revision.get("previous_revision_id")
            if previous is not None and not _valid_id(previous):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.previous_revision_id is invalid",
                    )
                )
            elif index == 0 and previous is not None:
                issues.append(
                    Issue(
                        "SOURCE_LINEAGE",
                        relative,
                        "the first revision must not have a previous revision",
                    )
                )
            elif previous is not None and previous not in earlier_ids:
                issues.append(
                    Issue(
                        "SOURCE_LINEAGE",
                        relative,
                        f"{context}.previous_revision_id must refer to an earlier revision",
                    )
                )
            sequence = revision.get("source_sequence")
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or sequence < 0
            ):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.source_sequence is invalid",
                    )
                )
            else:
                sequences.append(sequence)
            if not _valid_rfc3339(revision.get("captured_at")):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.captured_at must be RFC 3339",
                    )
                )
            if revision.get("coverage") not in {"full", "partial", "unknown"}:
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.coverage is invalid",
                    )
                )
            if not _valid_optional_sha256(revision.get("content_sha256")):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.content_sha256 must be null or SHA-256",
                    )
                )
            content_ref = revision.get("content_ref")
            if content_ref is not None:
                _validate_source_content_ref(
                    content_ref, relative, context, issues
                )
            redaction = revision.get("redaction")
            if not isinstance(redaction, Mapping):
                issues.append(
                    Issue(
                        "SOURCE_FORMAT",
                        relative,
                        f"{context}.redaction must be a mapping",
                    )
                )
            else:
                allowed_redaction = {
                    "credentials_scanned",
                    "content_removed",
                    "reason",
                }
                _exact_keys(
                    redaction,
                    allowed_redaction,
                    issues,
                    relative,
                    "SOURCE_FORMAT",
                    f"{context}.redaction",
                )
                for key in ("credentials_scanned", "content_removed"):
                    if not isinstance(redaction.get(key), bool):
                        issues.append(
                            Issue(
                                "SOURCE_FORMAT",
                                relative,
                                f"{context}.redaction.{key} must be boolean",
                            )
                        )
            if isinstance(revision_id, str):
                earlier_ids.add(revision_id)

        if len(revision_ids) != len(set(revision_ids)):
            issues.append(
                Issue(
                    "SOURCE_LINEAGE",
                    relative,
                    "revision_id values must be unique",
                )
            )
        if len(sequences) != len(set(sequences)) or sequences != sorted(sequences):
            issues.append(
                Issue(
                    "SOURCE_LINEAGE",
                    relative,
                    "source_sequence values must be unique and increasing",
                )
            )
        if current_revision_id not in set(revision_ids):
            issues.append(
                Issue(
                    "SOURCE_LINEAGE",
                    relative,
                    "current_revision_id must identify a listed revision",
                )
            )
        elif revision_ids and current_revision_id != revision_ids[-1]:
            issues.append(
                Issue(
                    "SOURCE_LINEAGE",
                    relative,
                    "current_revision_id must identify the last listed revision",
                )
            )


def _validate_source_content_ref(
    value: Any, relative: str, context: str, issues: list[Issue]
) -> None:
    required = {
        "storage",
        "object_id",
        "object_revision_id",
        "byte_size",
        "media_type",
    }
    if not isinstance(value, Mapping):
        issues.append(
            Issue(
                "SOURCE_FORMAT",
                relative,
                f"{context}.content_ref must be null or a mapping",
            )
        )
        return
    missing = sorted(required - set(value))
    if missing:
        issues.append(
            Issue(
                "SOURCE_FORMAT",
                relative,
                f"{context}.content_ref missing fields: {', '.join(missing)}",
            )
        )
    _exact_keys(
        value,
        required,
        issues,
        relative,
        "SOURCE_FORMAT",
        f"{context}.content_ref",
    )
    if value.get("storage") not in {
        "git_blob",
        "google_drive_file",
        "encrypted_object",
    }:
        issues.append(
            Issue(
                "SOURCE_FORMAT",
                relative,
                f"{context}.content_ref.storage is invalid",
            )
        )
    object_id = value.get("object_id")
    if not isinstance(object_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{2,256}", object_id
    ):
        issues.append(
            Issue(
                "SOURCE_PRIVACY",
                relative,
                f"{context}.content_ref.object_id must be opaque, not a path",
            )
        )
    object_revision_id = value.get("object_revision_id")
    if object_revision_id is not None and (
        not isinstance(object_revision_id, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", object_revision_id)
    ):
        issues.append(
            Issue(
                "SOURCE_FORMAT",
                relative,
                f"{context}.content_ref.object_revision_id is invalid",
            )
        )
    byte_size = value.get("byte_size")
    if (
        not isinstance(byte_size, int)
        or isinstance(byte_size, bool)
        or byte_size < 0
    ):
        issues.append(
            Issue(
                "SOURCE_FORMAT",
                relative,
                f"{context}.content_ref.byte_size is invalid",
            )
        )
    media_type = value.get("media_type")
    if not isinstance(media_type, str) or not re.fullmatch(
        r"[a-z0-9.+-]+/[a-z0-9.+-]+", media_type
    ):
        issues.append(
            Issue(
                "SOURCE_FORMAT",
                relative,
                f"{context}.content_ref.media_type is invalid",
            )
        )


def validate_portable_identities(root: Path, issues: list[Issue]) -> None:
    identity_paths: list[Path] = []
    root_identity = root / ".vault_identity.yaml"
    if root_identity.exists() and not root_identity.is_symlink():
        identity_paths.append(root_identity)
    for layer in FIVE_LAYERS:
        base = root / layer
        if base.exists():
            identity_paths.extend(
                path
                for path in base.rglob(".vault_identity.yaml")
                if not path.is_symlink()
            )
    for path in sorted(set(identity_paths)):
        relative = _relative(path, root)
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("IDENTITY_PARSE", relative, str(exc)))
            continue
        data = _required_mapping(
            value,
            PORTABLE_REQUIRED,
            issues,
            relative,
            "IDENTITY_FORMAT",
        )
        if data is None:
            continue
        _exact_keys(
            data,
            PORTABLE_REQUIRED,
            issues,
            relative,
            "IDENTITY_FORMAT",
            "portable identity",
        )
        if data.get("schema_version") != "portable-workspace-identity/v1":
            issues.append(
                Issue(
                    "IDENTITY_FORMAT",
                    relative,
                    "schema_version must equal 'portable-workspace-identity/v1'",
                )
            )
        if data.get("vault_id") != "codex-memory-vault":
            issues.append(
                Issue(
                    "IDENTITY_FORMAT",
                    relative,
                    "vault_id must equal 'codex-memory-vault'",
                )
            )
        if data.get("binding_state") != "confirmed":
            issues.append(
                Issue(
                    "IDENTITY_FORMAT",
                    relative,
                    "portable identity may only carry a confirmed binding",
                )
            )
        for key in ("binding_id", "semantic_task_id", "workspace_lineage_id"):
            if not _valid_id(data.get(key)):
                issues.append(
                    Issue(
                        "IDENTITY_FORMAT",
                        relative,
                        f"{key} must be a portable lowercase identifier",
                    )
                )
        for key_path in _nested_keys(data):
            normalized = key_path[-1].lower().replace("-", "_")
            if normalized in PORTABLE_FORBIDDEN_KEY_PARTS or any(
                part in normalized.split("_") for part in PORTABLE_FORBIDDEN_KEY_PARTS
            ):
                issues.append(
                    Issue(
                        "IDENTITY_PRIVATE_FIELD",
                        relative,
                        f"portable identity contains forbidden field: "
                        f"{'.'.join(key_path)}",
                    )
                )
        base = data.get("base")
        if not isinstance(base, Mapping):
            issues.append(Issue("IDENTITY_BASE", relative, "base must be a mapping"))
            continue
        if set(base) != PORTABLE_BASE_FIELDS:
            missing = sorted(PORTABLE_BASE_FIELDS - set(base))
            extras = sorted(set(base) - PORTABLE_BASE_FIELDS)
            detail = []
            if missing:
                detail.append(f"missing {', '.join(missing)}")
            if extras:
                detail.append(f"unexpected {', '.join(extras)}")
            issues.append(
                Issue(
                    "IDENTITY_BASE",
                    relative,
                    "base must contain exactly the four portable anchors: "
                    + "; ".join(detail),
                )
            )
        manifest_hash = base.get("manifest_sha256")
        if manifest_hash is not None and (
            not isinstance(manifest_hash, str)
            or not SHA256_RE.fullmatch(manifest_hash)
        ):
            issues.append(
                Issue(
                    "IDENTITY_BASE",
                    relative,
                    "base.manifest_sha256 must be null or a lowercase SHA-256",
                )
            )
        for key in ("snapshot_id", "transaction_id"):
            anchor_id = base.get(key)
            if anchor_id is not None and not _valid_id(anchor_id):
                issues.append(
                    Issue(
                        "IDENTITY_BASE",
                        relative,
                        f"base.{key} must be null or a portable identifier",
                    )
                )
        blob_sha = base.get("current_blob_sha")
        if blob_sha is not None and (
            not isinstance(blob_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", blob_sha)
        ):
            issues.append(
                Issue(
                    "IDENTITY_BASE",
                    relative,
                    "base.current_blob_sha must be null or a lowercase Git object hash",
                )
            )


def _evidence_kind(item: Mapping[str, Any]) -> str:
    value = item.get("kind")
    return value.lower().replace("-", "_") if isinstance(value, str) else ""


def _validate_evidence_item(
    item: Any, relative: str, index: int, issues: list[Issue]
) -> tuple[str, str]:
    if not isinstance(item, Mapping):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}] must be a mapping",
            )
        )
        return "", ""
    _exact_keys(
        item,
        {
            "evidence_id",
            "kind",
            "strength",
            "object_sha256",
            "assertion",
            "method",
            "score_basis_points",
            "input_digest_sha256",
            "independence_group",
        },
        issues,
        relative,
        "BINDING_EVIDENCE",
        f"evidence[{index}]",
    )
    kind = _evidence_kind(item)
    evidence_id = item.get("evidence_id")
    strength = item.get("strength")
    if not _valid_id(evidence_id):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].evidence_id must be a portable identifier",
            )
        )
    if not kind:
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].kind is required",
            )
        )
    elif kind not in {
        "user_confirmation",
        "portable_identity",
        "immutable_manifest_lineage",
        "git_ancestry",
        "full_hash",
        "partial_hash",
        "title_similarity",
        "content_similarity",
        "cloud_consistency_check",
        "user_policy_authorization",
        "legacy_record",
    }:
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].kind is invalid",
            )
        )
    if strength not in {"authoritative", "strong", "supporting", "weak"}:
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].strength is invalid",
            )
        )
        strength = ""
    object_hash = item.get("object_sha256")
    if object_hash is not None and (
        not isinstance(object_hash, str) or not SHA256_RE.fullmatch(object_hash)
    ):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].object_sha256 must be a lowercase SHA-256",
            )
        )
    if kind in HASH_ONLY_EVIDENCE_KINDS:
        digest = item.get("object_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            issues.append(
                Issue(
                    "BINDING_EVIDENCE",
                    relative,
                    f"evidence[{index}].object_sha256 is required for hash evidence",
                )
            )
    assertion = item.get("assertion")
    if assertion is not None and (
        not isinstance(assertion, str)
        or not assertion.strip()
        or len(assertion) > 1000
    ):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].assertion must be non-empty text",
            )
        )
    method = item.get("method")
    if method is not None and (
        not isinstance(method, str)
        or not method.strip()
        or len(method) > 100
    ):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].method must be short non-empty text",
            )
        )
    score = item.get("score_basis_points")
    if score is not None and (
        not isinstance(score, int)
        or isinstance(score, bool)
        or not 0 <= score <= 10000
    ):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].score_basis_points is invalid",
            )
        )
    input_digest = item.get("input_digest_sha256")
    if input_digest is not None and (
        not isinstance(input_digest, str)
        or not SHA256_RE.fullmatch(input_digest)
    ):
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].input_digest_sha256 is invalid",
            )
        )
    independence_group = item.get("independence_group")
    if independence_group is not None and independence_group not in {
        "visible_goal",
        "distinctive_context",
        "local_visible_task",
        "verified_cloud_checkpoint",
    }:
        issues.append(
            Issue(
                "BINDING_EVIDENCE",
                relative,
                f"evidence[{index}].independence_group is invalid",
            )
        )
    return kind, str(strength)


def _is_alias_binding(data: Mapping[str, Any]) -> bool:
    direct_values = [
        data.get("relation"),
        data.get("binding_type"),
        data.get("kind"),
    ]
    subject = data.get("subject")
    if isinstance(subject, Mapping):
        direct_values.extend(
            (subject.get("kind"), subject.get("relation"), subject.get("type"))
        )
    targets = data.get("targets")
    if isinstance(targets, list):
        for target in targets:
            if isinstance(target, Mapping):
                direct_values.extend(
                    (target.get("kind"), target.get("relation"), target.get("type"))
                )
    return "alias_of" in direct_values or "alias" in direct_values or "alias_of" in data


def _validate_route_correction(
    data: Mapping[str, Any],
    effective_range: Any,
    relative: str,
    issues: list[Issue],
) -> None:
    if "route_correction" not in data:
        return
    correction = data.get("route_correction")
    code = "BINDING_ROUTE_CORRECTION"
    supersedes = data.get("supersedes_binding_id")
    if not _valid_id(supersedes):
        issues.append(
            Issue(
                code,
                relative,
                "route_correction requires a valid supersedes_binding_id",
            )
        )
    elif supersedes == data.get("binding_id"):
        issues.append(
            Issue(
                code,
                relative,
                "route_correction cannot supersede its own binding_id",
            )
        )
    if not isinstance(correction, Mapping):
        issues.append(
            Issue(code, relative, "route_correction must be a mapping")
        )
        return
    fields = {
        "previous_task_id",
        "effective_source_sequence_from",
        "historical_content_review_required",
        "potentially_misrouted_sequence_count",
    }
    missing = sorted(fields - set(correction))
    if missing:
        issues.append(
            Issue(
                code,
                relative,
                "route_correction is missing required fields: "
                + ", ".join(missing),
            )
        )
    _exact_keys(
        correction,
        fields,
        issues,
        relative,
        code,
        "route_correction",
    )
    if not _valid_id(correction.get("previous_task_id")):
        issues.append(
            Issue(
                code,
                relative,
                "route_correction.previous_task_id is invalid",
            )
        )
    effective_from = correction.get("effective_source_sequence_from")
    valid_effective_from = (
        isinstance(effective_from, int)
        and not isinstance(effective_from, bool)
        and effective_from >= 0
    )
    if not valid_effective_from:
        issues.append(
            Issue(
                code,
                relative,
                "route_correction.effective_source_sequence_from is invalid",
            )
        )
    elif (
        not isinstance(effective_range, Mapping)
        or effective_range.get("source_sequence_from") != effective_from
    ):
        issues.append(
            Issue(
                code,
                relative,
                "route_correction effective sequence must match "
                "effective_range.source_sequence_from",
            )
        )
    count = correction.get("potentially_misrouted_sequence_count")
    valid_count = (
        isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
    )
    if not valid_count:
        issues.append(
            Issue(
                code,
                relative,
                "route_correction.potentially_misrouted_sequence_count "
                "is invalid",
            )
        )
    review_required = correction.get("historical_content_review_required")
    if not isinstance(review_required, bool):
        issues.append(
            Issue(
                code,
                relative,
                "route_correction.historical_content_review_required "
                "must be boolean",
            )
        )
    elif valid_count and review_required is not (count > 0):
        issues.append(
            Issue(
                code,
                relative,
                "route_correction historical review flag must equal "
                "(potentially_misrouted_sequence_count > 0)",
            )
        )


def validate_bindings(root: Path, issues: list[Issue]) -> None:
    binding_paths: list[Path] = []
    for collection in ("confirmed", "candidates"):
        base = root / "bindings" / collection
        if base.exists():
            binding_paths.extend(
                path
                for path in base.rglob("*")
                if path.is_file()
                and not path.is_symlink()
                and path.suffix.lower() in {".yaml", ".yml", ".json"}
                and not path.name.lower().startswith(("readme", "template"))
            )
    for path in sorted(binding_paths):
        relative = _relative(path, root)
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("BINDING_PARSE", relative, str(exc)))
            continue
        data = _required_mapping(
            value, BINDING_REQUIRED, issues, relative, "BINDING_FORMAT"
        )
        if data is None:
            continue
        _exact_keys(
            data,
            BINDING_REQUIRED
            | {
                "decision_event_id",
                "supersedes_binding_id",
                "proposal_assessment",
                "route_correction",
            },
            issues,
            relative,
            "BINDING_FORMAT",
            "binding",
        )
        if data.get("schema_version") != "binding/v1":
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "schema_version must equal 'binding/v1'",
                )
            )
        collection = path.relative_to(root / "bindings").parts[0]
        if collection == "confirmed" and data.get("state") != "confirmed":
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "files under bindings/confirmed must have state='confirmed'",
                )
            )
        if collection == "candidates" and data.get("state") != "proposed":
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "files under bindings/candidates must have state='proposed'",
                )
            )
        if not _valid_id(data.get("binding_id")):
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "binding_id must be a portable lowercase identifier",
                )
            )
        elif path.stem != data.get("binding_id"):
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "filename must equal binding_id",
                )
            )
        subject = data.get("subject")
        if not isinstance(subject, Mapping) or not {
            "kind",
            "id",
        }.issubset(subject):
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "subject must contain kind and id",
                )
            )
        elif (
            subject.get("kind")
            not in {"source", "workspace_lineage", "legacy_record"}
            or not _valid_id(subject.get("id"))
        ):
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "subject kind/id is invalid",
                )
            )
        elif set(subject) != {"kind", "id"}:
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "subject contains unexpected fields",
                )
            )
        targets = data.get("targets")
        if not isinstance(targets, list) or not targets:
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "targets must be a non-empty list",
                )
            )
        else:
            for index, target in enumerate(targets):
                if not isinstance(target, Mapping):
                    issues.append(
                        Issue(
                            "BINDING_FORMAT",
                            relative,
                            f"targets[{index}] must be a mapping",
                        )
                    )
                    continue
                if set(target) != {"semantic_task_id", "relation", "role"}:
                    issues.append(
                        Issue(
                            "BINDING_FORMAT",
                            relative,
                            f"targets[{index}] contains unexpected fields",
                        )
                    )
                if not _valid_id(target.get("semantic_task_id")):
                    issues.append(
                        Issue(
                            "BINDING_FORMAT",
                            relative,
                            f"targets[{index}].semantic_task_id is invalid",
                        )
                    )
                if target.get("relation") not in {
                    "source_for",
                    "workspace_for",
                    "legacy_record_of",
                    "alias_of",
                    "forked_from",
                    "related_to",
                }:
                    issues.append(
                        Issue(
                            "BINDING_FORMAT",
                            relative,
                            f"targets[{index}].relation is invalid",
                        )
                    )
                if target.get("role") not in {
                    "primary",
                    "supporting",
                    "coordination",
                    "reference",
                }:
                    issues.append(
                        Issue(
                            "BINDING_FORMAT",
                            relative,
                            f"targets[{index}].role is invalid",
                        )
                    )
        effective_range = data.get("effective_range")
        if not isinstance(effective_range, Mapping) or set(effective_range) != {
            "source_sequence_from",
            "source_sequence_to",
        }:
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "effective_range must contain source_sequence_from/to",
                )
            )
        else:
            start = effective_range.get("source_sequence_from")
            end = effective_range.get("source_sequence_to")
            if start is not None and (
                not isinstance(start, int)
                or isinstance(start, bool)
                or start < 0
            ):
                issues.append(
                    Issue(
                        "BINDING_FORMAT",
                        relative,
                        "effective_range.source_sequence_from is invalid",
                    )
                )
            if end is not None and (
                not isinstance(end, int)
                or isinstance(end, bool)
                or end < 0
            ):
                issues.append(
                    Issue(
                        "BINDING_FORMAT",
                        relative,
                        "effective_range.source_sequence_to is invalid",
                    )
                )
            if (
                isinstance(start, int)
                and not isinstance(start, bool)
                and isinstance(end, int)
                and not isinstance(end, bool)
                and end < start
            ):
                issues.append(
                    Issue(
                        "BINDING_FORMAT",
                        relative,
                        "effective range cannot end before it starts",
                    )
                )
            if (
                isinstance(subject, Mapping)
                and subject.get("kind") != "source"
                and (start is not None or end is not None)
            ):
                issues.append(
                    Issue(
                        "BINDING_FORMAT",
                        relative,
                        "non-source subjects must use a null effective range",
                    )
                )
        state = data.get("state")
        if state not in {"proposed", "confirmed", "rejected", "superseded"}:
            issues.append(
                Issue("BINDING_FORMAT", relative, "state is invalid")
            )
        if data.get("confidence") not in {
            "user_confirmed",
            "portable_identity_verified",
            "lineage_verified",
            "artifact_verified",
            "imported_unverified",
            "assistant_inferred",
        }:
            issues.append(
                Issue("BINDING_FORMAT", relative, "confidence is invalid")
            )
        confirmation_basis = data.get("confirmation_basis")
        if state == "confirmed" and confirmation_basis not in {
            "user_confirmation",
            "portable_identity",
            "verified_lineage",
            "legacy_authority",
            "user_authorized_semantic_quorum",
        }:
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "confirmed binding requires a valid confirmation_basis",
                )
            )
        if state in {"proposed", "rejected"} and confirmation_basis is not None:
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "proposed/rejected binding must not claim a confirmation basis",
                )
            )
        if not _valid_rfc3339(data.get("created_at")):
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "created_at must be an RFC 3339 timestamp",
                )
            )
        created_by = data.get("created_by")
        if (
            not isinstance(created_by, Mapping)
            or created_by.get("actor_kind")
            not in {"user_action", "migration", "client"}
            or not _valid_id(created_by.get("actor_id"))
        ):
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "created_by must contain a valid actor_kind and actor_id",
                )
            )
        elif set(created_by) != {"actor_kind", "actor_id"}:
            issues.append(
                Issue(
                    "BINDING_FORMAT",
                    relative,
                    "created_by contains unexpected fields",
                )
            )
        evidence = data.get("evidence")
        evidence_meta: list[tuple[str, str]] = []
        if not isinstance(evidence, list) or not evidence:
            issues.append(
                Issue(
                    "BINDING_EVIDENCE",
                    relative,
                    "evidence must be a non-empty list",
                )
            )
        else:
            evidence_meta = [
                _validate_evidence_item(item, relative, index, issues)
                for index, item in enumerate(evidence)
            ]
        strong_kinds = {
            kind
            for kind, strength in evidence_meta
            if kind in STRONG_EVIDENCE_KINDS
            and strength in {"authoritative", "strong"}
        }
        has_strong_evidence = bool(strong_kinds)
        basis_to_kind = {
            "user_confirmation": "user_confirmation",
            "user_authorized_semantic_quorum": "user_policy_authorization",
            "portable_identity": "portable_identity",
            "verified_lineage": "immutable_manifest_lineage",
            "legacy_authority": "legacy_record",
        }
        expected_kind = basis_to_kind.get(str(confirmation_basis))
        if state == "confirmed" and expected_kind not in strong_kinds:
            issues.append(
                Issue(
                    "BINDING_EVIDENCE",
                    relative,
                    "confirmation_basis must match authoritative/strong evidence",
                )
            )
        if data.get("state") == "confirmed" and not has_strong_evidence:
            issues.append(
                Issue(
                    "BINDING_HASH_ONLY",
                    relative,
                    "confirmed binding requires non-hash evidence",
                )
            )
        if _is_alias_binding(data) and not has_strong_evidence:
            issues.append(
                Issue(
                    "BINDING_HASH_ONLY",
                    relative,
                    "alias/alias_of binding cannot be established from hashes alone",
                )
            )
        for key in ("decision_event_id", "supersedes_binding_id"):
            reference_id = data.get(key)
            if reference_id is not None and not _valid_id(reference_id):
                issues.append(
                    Issue(
                        "BINDING_FORMAT",
                        relative,
                        f"{key} must be null or a portable identifier",
                    )
                )
        _validate_route_correction(
            data,
            effective_range,
            relative,
            issues,
        )
        proposal = data.get("proposal_assessment")
        if proposal is not None:
            expected_proposal_keys = {
                "policy_version",
                "goal_score_basis_points",
                "distinctive_score_basis_points",
                "runner_up_score_basis_points",
                "runner_up_margin_basis_points",
                "candidate_count",
                "independent_signal_groups",
                "contradiction_count",
                "evidence_digest_sha256",
                "basis_remote_commit_sha",
                "basis_current_blob_sha",
            }
            if not isinstance(proposal, Mapping):
                issues.append(
                    Issue(
                        "BINDING_PROPOSAL",
                        relative,
                        "proposal_assessment must be a mapping",
                    )
                )
            else:
                _exact_keys(
                    proposal,
                    expected_proposal_keys,
                    issues,
                    relative,
                    "BINDING_PROPOSAL",
                    "proposal_assessment",
                )
                if (
                    state != "proposed"
                    or data.get("confidence") != "assistant_inferred"
                    or confirmation_basis is not None
                    or collection != "candidates"
                ):
                    issues.append(
                        Issue(
                            "BINDING_PROPOSAL",
                            relative,
                            "semantic proposal may only be an assistant-inferred candidate",
                        )
                    )
                if (
                    proposal.get("policy_version")
                    != "user-authorized-semantic-quorum-v1"
                ):
                    issues.append(
                        Issue(
                            "BINDING_PROPOSAL",
                            relative,
                            "proposal policy_version is invalid",
                        )
                    )
                for key in (
                    "goal_score_basis_points",
                    "distinctive_score_basis_points",
                    "runner_up_score_basis_points",
                    "runner_up_margin_basis_points",
                ):
                    score_value = proposal.get(key)
                    if (
                        not isinstance(score_value, int)
                        or isinstance(score_value, bool)
                        or not 0 <= score_value <= 10000
                    ):
                        issues.append(
                            Issue(
                                "BINDING_PROPOSAL",
                                relative,
                                f"proposal_assessment.{key} is invalid",
                            )
                        )
                if proposal.get("independent_signal_groups") != 2:
                    issues.append(
                        Issue(
                            "BINDING_PROPOSAL",
                            relative,
                            "proposal requires exactly two initial signal groups",
                        )
                    )
                if proposal.get("contradiction_count") != 0:
                    issues.append(
                        Issue(
                            "BINDING_PROPOSAL",
                            relative,
                            "automatic proposal cannot contain a contradiction",
                        )
                    )
                if not isinstance(
                    proposal.get("candidate_count"), int
                ) or isinstance(proposal.get("candidate_count"), bool) or int(
                    proposal.get("candidate_count", 0)
                ) < 1:
                    issues.append(
                        Issue(
                            "BINDING_PROPOSAL",
                            relative,
                            "proposal candidate_count is invalid",
                        )
                    )
                if not isinstance(
                    proposal.get("evidence_digest_sha256"), str
                ) or not SHA256_RE.fullmatch(
                    str(proposal.get("evidence_digest_sha256"))
                ):
                    issues.append(
                        Issue(
                            "BINDING_PROPOSAL",
                            relative,
                            "proposal evidence digest is invalid",
                        )
                    )
                for key in (
                    "basis_remote_commit_sha",
                    "basis_current_blob_sha",
                ):
                    value = proposal.get(key)
                    if not isinstance(value, str) or not re.fullmatch(
                        r"[0-9a-f]{40}|[0-9a-f]{64}",
                        value,
                    ):
                        issues.append(
                            Issue(
                                "BINDING_PROPOSAL",
                                relative,
                                f"proposal_assessment.{key} is invalid",
                            )
                        )
        elif state == "proposed" and collection == "candidates":
            issues.append(
                Issue(
                    "BINDING_PROPOSAL",
                    relative,
                    "automatic candidate binding requires proposal_assessment",
                )
            )


def _check_time_total_order(
    data: Mapping[str, Any], relative: str, issues: list[Issue]
) -> None:
    for key, value in _walk_values(data):
        normalized_key = (key or "").lower().replace("-", "_")
        normalized_value = (
            value.lower().replace("-", "_") if isinstance(value, str) else ""
        )
        if (
            normalized_key in FORBIDDEN_TOTAL_ORDER_KEYS
            and value is not False
            and value is not None
        ):
            issues.append(
                Issue(
                    "EVENT_TOTAL_ORDER",
                    relative,
                    f"time/global total-order claim is forbidden: {key}",
                )
            )
        if normalized_key in {"ordering", "order_basis", "latest_basis"} and (
            normalized_value in TIME_ORDER_VALUES
        ):
            issues.append(
                Issue(
                    "EVENT_TOTAL_ORDER",
                    relative,
                    "wall-clock timestamps cannot define authoritative event order",
                )
            )


def validate_memory_episodes(root: Path, issues: list[Issue]) -> None:
    episode_root = root / "memory" / "episodes"
    if not episode_root.exists():
        return
    for path in sorted(episode_root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = _relative(path, root)
        match = re.fullmatch(
            r"memory/episodes/([0-9a-f]{2})/(ep-[0-9a-f]{40})\.json",
            relative,
        )
        if match is None or match.group(1) != match.group(2)[3:5]:
            issues.append(
                Issue(
                    "EPISODE_PATH",
                    relative,
                    "episode path must use its first two digest hex characters",
                )
            )
            continue
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("EPISODE_PARSE", relative, str(exc)))
            continue
        data = _required_mapping(
            value,
            EPISODE_REQUIRED,
            issues,
            relative,
            "EPISODE_FORMAT",
        )
        if data is None:
            continue
        _exact_keys(
            data,
            EPISODE_REQUIRED,
            issues,
            relative,
            "EPISODE_FORMAT",
            "memory episode",
        )
        episode_id = data.get("episode_id")
        if (
            data.get("schema_version") != "memory-episode/v1"
            or not isinstance(episode_id, str)
            or EPISODE_ID_RE.fullmatch(episode_id) is None
            or episode_id != match.group(2)
        ):
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "episode schema or identity is invalid",
                )
            )
        source_id = data.get("source_id")
        if (
            not isinstance(source_id, str)
            or EPISODE_SOURCE_ID_RE.fullmatch(source_id) is None
        ):
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "source_id must be an opaque source pseudonym",
                )
            )
        sequence = data.get("source_sequence")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
        ):
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "source_sequence must be a non-negative integer",
                )
            )
        parents = data.get("parent_episode_ids")
        if (
            not isinstance(parents, list)
            or len(parents) > 64
            or not all(
                isinstance(parent, str)
                and EPISODE_ID_RE.fullmatch(parent) is not None
                for parent in parents
            )
        ):
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "parent_episode_ids is invalid",
                )
            )
        elif len(parents) != len(set(parents)) or episode_id in parents:
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "episode parents repeat or contain a self-reference",
                )
            )
        if data.get("coverage") != "partial_active_turn":
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "coverage must equal partial_active_turn",
                )
            )
        for key in ("included_content", "excluded_content"):
            items = data.get(key)
            if (
                not isinstance(items, list)
                or not items
                or len(items) > 32
                or not all(isinstance(item, str) and item for item in items)
            ):
                issues.append(
                    Issue(
                        "EPISODE_FORMAT",
                        relative,
                        f"{key} must be a bounded non-empty text list",
                    )
                )
        created_at = data.get("created_at")
        if (
            not _valid_rfc3339(created_at)
            or data.get("captured_at") != created_at
        ):
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "captured_at and created_at must be the same RFC 3339 time",
                )
            )
        messages = data.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 2:
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "messages must contain one or two visible messages",
                )
            )
        else:
            for ordinal, message in enumerate(messages):
                if (
                    not isinstance(message, Mapping)
                    or set(message) != {"ordinal", "role", "phase", "text"}
                    or message.get("ordinal") != ordinal
                    or message.get("role") not in {"user", "assistant"}
                    or message.get("phase")
                    not in {"commentary", "final_answer", "unknown"}
                    or not isinstance(message.get("text"), str)
                    or not message["text"]
                    or len(message["text"].encode("utf-8")) > 2 * 1024 * 1024
                ):
                    issues.append(
                        Issue(
                            "EPISODE_FORMAT",
                            relative,
                            "visible message shape, order or bound is invalid",
                        )
                    )
                    continue
                text = str(message["text"])
                if SECRET_VALUE_RE.search(text):
                    issues.append(
                        Issue(
                            "EPISODE_PRIVACY",
                            relative,
                            "visible episode contains a credential-like value",
                        )
                    )
                if (
                    text.startswith(("/", "\\\\"))
                    or re.match(r"^[A-Za-z]:[\\/]", text)
                    or LOCAL_ABSOLUTE_PATH_RE.search(text)
                ):
                    issues.append(
                        Issue(
                            "EPISODE_PRIVACY",
                            relative,
                            "visible episode contains a local absolute path",
                        )
                    )
        if data.get("hash_profile") != "jcs-rfc8785+sha256/episode-v1":
            issues.append(
                Issue(
                    "EPISODE_FORMAT",
                    relative,
                    "memory episode hash profile is invalid",
                )
            )
        observed_hash = data.get("episode_sha256")
        try:
            domain = dict(data)
            domain.pop("episode_sha256", None)
            expected_hash = sha256_jcs(domain)
        except DataError as exc:
            issues.append(Issue("EPISODE_JCS", relative, str(exc)))
            continue
        if (
            not isinstance(observed_hash, str)
            or SHA256_RE.fullmatch(observed_hash) is None
            or observed_hash != expected_hash
        ):
            issues.append(
                Issue(
                    "EPISODE_HASH",
                    relative,
                    f"episode_sha256 mismatch; expected {expected_hash}",
                )
            )


def validate_memory_events(root: Path, issues: list[Issue]) -> None:
    event_root = root / "memory" / "events"
    seen_ids: dict[str, str] = {}
    v2_event_ids: set[str] = set()
    v2_relations: list[tuple[str, str, list[str]]] = []
    if not event_root.exists():
        return
    for path in sorted(event_root.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.suffix.lower() not in {".yaml", ".yml", ".json"}
            or path.name.lower().startswith(("readme", "template"))
        ):
            continue
        relative = _relative(path, root)
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("EVENT_PARSE", relative, str(exc)))
            continue
        schema = value.get("schema_version") if isinstance(value, Mapping) else None
        required_fields = (
            EVENT_V2_REQUIRED
            if schema == "memory-event/v2"
            else EVENT_V1_REQUIRED
        )
        data = _required_mapping(
            value, required_fields, issues, relative, "EVENT_FORMAT"
        )
        if data is None:
            continue
        _exact_keys(
            data,
            required_fields,
            issues,
            relative,
            "EVENT_FORMAT",
            "memory event",
        )
        if schema not in {"memory-event/v1", "memory-event/v2"}:
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "schema_version must equal 'memory-event/v1' or 'memory-event/v2'",
                )
            )
        event_id = data.get("memory_event_id")
        if not _valid_id(event_id):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "memory_event_id must be a portable lowercase identifier",
                )
            )
        elif event_id in seen_ids:
            issues.append(
                Issue(
                    "EVENT_DUPLICATE_ID",
                    relative,
                    f"memory_event_id already appears in {seen_ids[event_id]}",
                )
            )
        else:
            seen_ids[event_id] = relative
        if schema == "memory-event/v2" and (
            not isinstance(event_id, str)
            or re.fullmatch(r"evt-[0-9a-f]{40}", event_id) is None
        ):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "memory-event/v2 id must be content-addressed",
                )
            )
        elif schema == "memory-event/v2" and relative != (
            f"memory/events/{event_id[4:6]}/{event_id}.json"
        ):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "memory-event/v2 path must use its first two digest hex characters",
                )
            )
        elif schema == "memory-event/v2":
            v2_event_ids.add(str(event_id))
        if _valid_id(event_id) and path.stem != event_id:
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "filename must equal memory_event_id",
                )
            )
        allowed_kinds = (
            EVENT_V2_KINDS if schema == "memory-event/v2" else EVENT_V1_KINDS
        )
        if data.get("kind") not in allowed_kinds:
            issues.append(Issue("EVENT_FORMAT", relative, "kind is invalid"))
        allowed_confidences = (
            {
                "user_confirmed",
                "artifact_verified",
                "source_explicit",
                "imported_unverified",
                "assistant_inferred",
            }
            if schema == "memory-event/v1"
            else {"source_explicit", "assistant_inferred"}
        )
        if data.get("confidence") not in allowed_confidences:
            issues.append(Issue("EVENT_FORMAT", relative, "confidence is invalid"))
        if schema == "memory-event/v1":
            task_ids = data.get("semantic_task_ids")
            if not isinstance(task_ids, list) or not all(
                _valid_id(task_id) for task_id in task_ids
            ):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        "semantic_task_ids must be a list of portable identifiers",
                    )
                )
            elif len(task_ids) != len(set(task_ids)):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        "semantic_task_ids cannot contain duplicates",
                    )
                )
        v2_episode: Mapping[str, Any] | None = None
        source = data.get("source")
        if not isinstance(source, Mapping) or not source:
            issues.append(
                Issue("EVENT_FORMAT", relative, "source must be a non-empty mapping")
            )
        else:
            if set(source) != {
                "source_id",
                "revision_id",
                "source_sequence",
                "evidence_anchor_sha256",
            }:
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        "source contains missing or unexpected fields",
                    )
                )
            if not _valid_id(source.get("source_id")):
                issues.append(
                    Issue("EVENT_FORMAT", relative, "source.source_id is invalid")
                )
            if not _valid_id(source.get("revision_id")):
                issues.append(
                    Issue("EVENT_FORMAT", relative, "source.revision_id is invalid")
                )
            sequence = source.get("source_sequence")
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or sequence < 0
            ):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        "source.source_sequence must be a non-negative integer",
                    )
                )
            anchor = source.get("evidence_anchor_sha256")
            if schema == "memory-event/v2" and anchor is None:
                issues.append(
                    Issue(
                        "EVENT_EVIDENCE",
                        relative,
                        "v2 event requires an immutable episode evidence anchor",
                    )
                )
            elif anchor is not None and (
                not isinstance(anchor, str) or not SHA256_RE.fullmatch(anchor)
            ):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        "source.evidence_anchor_sha256 must be null or SHA-256",
                    )
                )
            if schema == "memory-event/v2":
                event_source_id = source.get("source_id")
                revision_id = source.get("revision_id")
                if (
                    not isinstance(event_source_id, str)
                    or EPISODE_SOURCE_ID_RE.fullmatch(event_source_id) is None
                    or not isinstance(revision_id, str)
                    or EPISODE_ID_RE.fullmatch(revision_id) is None
                ):
                    issues.append(
                        Issue(
                            "EVENT_EVIDENCE",
                            relative,
                            "v2 event must reference pseudonymous episode evidence",
                        )
                    )
                else:
                    episode_path = (
                        root
                        / "memory"
                        / "episodes"
                        / revision_id[3:5]
                        / f"{revision_id}.json"
                    )
                    try:
                        episode = load_document(episode_path)
                    except (DataError, OSError) as exc:
                        issues.append(
                            Issue(
                                "EVENT_EVIDENCE",
                                relative,
                                f"v2 event episode evidence is unavailable: {exc}",
                            )
                        )
                    else:
                        if (
                            not isinstance(episode, Mapping)
                            or episode.get("source_id") != event_source_id
                            or episode.get("episode_id") != revision_id
                            or episode.get("source_sequence") != sequence
                            or episode.get("episode_sha256") != anchor
                        ):
                            issues.append(
                                Issue(
                                    "EVENT_EVIDENCE",
                                    relative,
                                    "v2 event does not match its immutable episode",
                                )
                            )
                        else:
                            v2_episode = episode
        claim_key = data.get("claim_key")
        if claim_key is not None and not _valid_id(claim_key):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "claim_key must be null or a portable identifier",
                )
            )
        for key in ("parents", "supersedes", "conflicts_with", "resolves"):
            references = data.get(key)
            if not isinstance(references, list) or not all(
                _valid_id(item) for item in references
            ):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        f"{key} must be a list of event identifiers",
                    )
                )
            elif len(references) != len(set(references)):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        f"{key} cannot contain duplicate event identifiers",
                    )
                )
            elif event_id in references:
                issues.append(
                    Issue(
                        "EVENT_SELF_REFERENCE",
                        relative,
                        f"{key} cannot contain this event's own id",
                    )
                )
            elif schema == "memory-event/v2" and any(
                re.fullmatch(r"evt-[0-9a-f]{40}", str(item)) is None
                for item in references
            ):
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        f"{key} must contain taskless v2 event identifiers",
                    )
                )
            elif schema == "memory-event/v2":
                v2_relations.append((relative, key, list(references)))
        if (
            data.get("kind") == "conflict_declared"
            and isinstance(data.get("conflicts_with"), list)
            and len(data["conflicts_with"]) < 2
        ):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "conflict_declared requires at least two conflicts_with ids",
                )
            )
        if (
            data.get("kind") == "conflict_resolved"
            and isinstance(data.get("resolves"), list)
            and not data["resolves"]
        ):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "conflict_resolved requires at least one resolves id",
                )
            )
        payload = data.get("payload")
        if not isinstance(payload, Mapping):
            issues.append(
                Issue("EVENT_FORMAT", relative, "payload must be a mapping")
            )
        elif schema == "memory-event/v2":
            profile = payload.get("profile")
            if profile == "memory-network-episode-event/v1":
                roles = payload.get("roles")
                if (
                    set(payload)
                    != {
                        "memory_form",
                        "profile",
                        "message_count",
                        "roles",
                        "continuity",
                    }
                    or data.get("kind") != "checkpoint_note"
                    or data.get("confidence") != "source_explicit"
                    or data.get("claim_key") is not None
                    or payload.get("memory_form") != "episodic"
                    or not isinstance(roles, list)
                    or not 1 <= len(roles) <= 2
                    or any(role not in {"user", "assistant"} for role in roles)
                    or payload.get("message_count") != len(roles)
                    or payload.get("continuity") not in {"origin", "continues"}
                    or bool(data.get("parents"))
                    != (payload.get("continuity") == "continues")
                    or not isinstance(data.get("parents"), list)
                    or len(data["parents"]) > 1
                    or any(
                        data.get(key)
                        for key in ("supersedes", "conflicts_with", "resolves")
                    )
                ):
                    issues.append(
                        Issue(
                            "EVENT_FORMAT",
                            relative,
                            "episode event profile is invalid",
                        )
                    )
                elif v2_episode is not None:
                    episode_source = str(v2_episode["source_id"])
                    episode_id = str(v2_episode["episode_id"])
                    expected_id = "evt-" + hashlib.sha256(
                        f"episode\0{episode_source}\0{episode_id}".encode(
                            "utf-8"
                        )
                    ).hexdigest()[:40]
                    episode_parents = list(v2_episode["parent_episode_ids"])
                    expected_parents = []
                    if episode_parents:
                        expected_parents = [
                            "evt-"
                            + hashlib.sha256(
                                (
                                    f"episode\0{episode_source}\0"
                                    f"{episode_parents[-1]}"
                                ).encode("utf-8")
                            ).hexdigest()[:40]
                        ]
                    if (
                        event_id != expected_id
                        or data.get("parents") != expected_parents
                        or roles
                        != [
                            message["role"]
                            for message in v2_episode["messages"]
                        ]
                    ):
                        issues.append(
                            Issue(
                                "EVENT_EVIDENCE",
                                relative,
                                "episode continuity is not deterministic",
                            )
                        )
            elif profile == "memory-network-semantic/v1":
                if (
                    set(payload) != {"profile", "claim"}
                    or data.get("confidence") != "assistant_inferred"
                    or not isinstance(payload.get("claim"), Mapping)
                    or not payload["claim"]
                ):
                    issues.append(
                        Issue(
                            "EVENT_FORMAT",
                            relative,
                            "semantic event profile is invalid",
                        )
                    )
                elif v2_episode is not None:
                    identity_domain = {
                        "source_id": source["source_id"],
                        "episode_id": source["revision_id"],
                        "kind": data["kind"],
                        "claim_key": data["claim_key"],
                        "parents": data["parents"],
                        "supersedes": data["supersedes"],
                        "conflicts_with": data["conflicts_with"],
                        "resolves": data["resolves"],
                        "payload": payload,
                    }
                    expected_id = "evt-" + sha256_jcs(identity_domain)[:40]
                    if event_id != expected_id:
                        issues.append(
                            Issue(
                                "EVENT_EVIDENCE",
                                relative,
                                "semantic event identity is not content-addressed",
                            )
                        )
            else:
                issues.append(
                    Issue(
                        "EVENT_FORMAT",
                        relative,
                        "memory-event/v2 profile is invalid",
                    )
                )
        if not _valid_rfc3339(data.get("created_at")):
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    "created_at must be an RFC 3339 timestamp",
                )
            )
        expected_hash_profile = (
            "jcs-rfc8785+sha256/event-v2"
            if schema == "memory-event/v2"
            else "jcs-rfc8785+sha256/event-v1"
        )
        if data.get("hash_profile") != expected_hash_profile:
            issues.append(
                Issue(
                    "EVENT_FORMAT",
                    relative,
                    f"hash_profile must equal '{expected_hash_profile}'",
                )
            )
        _check_time_total_order(data, relative, issues)

        payload_hash = data.get("payload_sha256")
        event_hash = data.get("event_sha256")
        if not isinstance(payload_hash, str) or not SHA256_RE.fullmatch(payload_hash):
            issues.append(
                Issue(
                    "EVENT_HASH",
                    relative,
                    "payload_sha256 must be a lowercase SHA-256",
                )
            )
        if not isinstance(event_hash, str) or not SHA256_RE.fullmatch(event_hash):
            issues.append(
                Issue(
                    "EVENT_HASH",
                    relative,
                    "event_sha256 must be a lowercase SHA-256",
                )
            )
        try:
            expected_payload_hash = sha256_jcs(data.get("payload"))
            event_domain = dict(data)
            event_domain.pop("event_sha256", None)
            expected_event_hash = sha256_jcs(event_domain)
        except DataError as exc:
            issues.append(Issue("EVENT_JCS", relative, str(exc)))
            continue
        if payload_hash != expected_payload_hash:
            issues.append(
                Issue(
                    "EVENT_HASH",
                    relative,
                    f"payload_sha256 mismatch; expected {expected_payload_hash}",
                )
            )
        if event_hash != expected_event_hash:
            issues.append(
                Issue(
                    "EVENT_HASH",
                    relative,
                    f"event_sha256 mismatch; expected {expected_event_hash}",
                )
            )
    for relative, relation, targets in v2_relations:
        if set(targets) - v2_event_ids:
            issues.append(
                Issue(
                    "EVENT_EVIDENCE",
                    relative,
                    f"{relation} references an event outside the taskless v2 graph",
                )
            )


def _iter_projection_evidence(value: Any) -> Iterator[Mapping[str, Any]]:
    """Yield structured evidence references from a projection subtree."""

    if isinstance(value, Mapping):
        kind = value.get("kind")
        if kind in {"memory_event", "source_message", "artifact"}:
            yield value
            return
        for child in value.values():
            yield from _iter_projection_evidence(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_projection_evidence(child)


def _projection_source_revisions(
    root: Path,
    source_id: str,
) -> dict[str, Mapping[str, Any]]:
    source_path = root / "sources" / source_id / "SOURCE.json"
    try:
        value = load_document(source_path)
    except (DataError, FileNotFoundError):
        return {}
    if not isinstance(value, Mapping) or value.get("source_id") != source_id:
        return {}
    revisions = value.get("revisions")
    if not isinstance(revisions, list):
        return {}
    return {
        str(revision["revision_id"]): revision
        for revision in revisions
        if isinstance(revision, Mapping) and _valid_id(revision.get("revision_id"))
    }


def _projection_event_hash_is_valid(event: Mapping[str, Any]) -> bool:
    event_hash = event.get("event_sha256")
    if not isinstance(event_hash, str) or not SHA256_RE.fullmatch(event_hash):
        return False
    try:
        domain = dict(event)
        domain.pop("event_sha256", None)
        return event_hash == sha256_jcs(domain)
    except DataError:
        return False


def _projection_conversation_messages(
    value: Any,
    source_id: str,
    relative: str,
    context: str,
    issues: list[Issue],
) -> list[Mapping[str, Any]]:
    """Validate one immutable conversation export before using message evidence."""

    required = {
        "schema_version",
        "source_id",
        "title",
        "captured_at",
        "coverage",
        "included_content",
        "excluded_content",
        "messages",
    }
    if not isinstance(value, Mapping):
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_SOURCE",
                relative,
                f"{context} source revision is not a conversation export",
            )
        )
        return []
    if set(value) != required:
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_SOURCE",
                relative,
                f"{context} conversation export fields do not match the "
                "conversation-export/v1 contract",
            )
        )
    if (
        value.get("schema_version") != "conversation-export/v1"
        or value.get("source_id") != source_id
        or not isinstance(value.get("title"), str)
        or not value.get("title")
        or not _valid_rfc3339(value.get("captured_at"))
        or value.get("coverage") not in {"full", "partial", "partial_active_turn"}
    ):
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_SOURCE",
                relative,
                f"{context} conversation export identity or metadata is invalid",
            )
        )
    for field in ("included_content", "excluded_content"):
        items = value.get(field)
        if not isinstance(items, list) or any(
            not isinstance(item, str) or not item for item in items
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} conversation export {field} is invalid",
                )
            )

    raw_messages = value.get("messages")
    if not isinstance(raw_messages, list) or not raw_messages:
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_SOURCE",
                relative,
                f"{context} conversation export must contain messages",
            )
        )
        return []
    messages: list[Mapping[str, Any]] = []
    for index, message in enumerate(raw_messages):
        if not isinstance(message, Mapping):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} messages[{index}] is not a mapping",
                )
            )
            continue
        allowed = {"ordinal", "role", "phase", "text"}
        required_message = {"ordinal", "role", "text"}
        if (
            not required_message.issubset(message)
            or not set(message).issubset(allowed)
            or message.get("ordinal") != index
            or message.get("role") not in {"user", "assistant"}
            or (
                "phase" in message
                and message.get("phase")
                not in {"commentary", "final_answer", "unknown"}
            )
            or not isinstance(message.get("text"), str)
            or not message.get("text")
            or unicodedata.normalize("NFC", str(message.get("text")))
            != message.get("text")
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} messages[{index}] is invalid; ordinals must "
                    "be contiguous from zero and role/text must be valid",
                )
            )
        messages.append(message)
    return messages


def _projection_confirmed_binding(
    root: Path,
    reference: Mapping[str, Any],
    task_id: str,
    relative: str,
    context: str,
    issues: list[Issue],
) -> Mapping[str, Any] | None:
    """Resolve and scope one permanently pinned source revision to this task."""

    binding_id = reference.get("binding_id")
    source_id = reference.get("source_id")
    sequence = reference.get("source_sequence")
    if not _valid_id(binding_id):
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_BINDING",
                relative,
                f"{context} has no valid confirmed source binding id",
            )
        )
        return None
    candidates = [
        path
        for path in (root / "bindings" / "confirmed").glob(f"{binding_id}.*")
        if path.is_file()
        and not path.is_symlink()
        and path.suffix.lower() in {".json", ".yaml", ".yml"}
    ]
    if len(candidates) != 1:
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_BINDING",
                relative,
                f"{context} binding_id must resolve to exactly one confirmed "
                "binding document",
            )
        )
        return None
    try:
        binding = load_document(candidates[0])
    except DataError:
        binding = None
    subject = binding.get("subject") if isinstance(binding, Mapping) else None
    targets = binding.get("targets") if isinstance(binding, Mapping) else None
    effective_range = (
        binding.get("effective_range") if isinstance(binding, Mapping) else None
    )
    target_matches = [
        target
        for target in targets or []
        if isinstance(target, Mapping)
        and target.get("semantic_task_id") == task_id
        and target.get("relation") == "source_for"
    ] if isinstance(targets, list) else []
    start = (
        effective_range.get("source_sequence_from")
        if isinstance(effective_range, Mapping)
        else None
    )
    end = (
        effective_range.get("source_sequence_to")
        if isinstance(effective_range, Mapping)
        else None
    )
    range_covers = (
        isinstance(sequence, int)
        and not isinstance(sequence, bool)
        and (start is None or isinstance(start, int) and start <= sequence)
        and (end is None or isinstance(end, int) and sequence <= end)
    )
    if (
        not isinstance(binding, Mapping)
        or binding.get("schema_version") != "binding/v1"
        or binding.get("binding_id") != binding_id
        or binding.get("state") != "confirmed"
        or not isinstance(subject, Mapping)
        or subject.get("kind") != "source"
        or subject.get("id") != source_id
        or len(target_matches) != 1
        or not range_covers
    ):
        issues.append(
            Issue(
                "PROJECTION_EVIDENCE_BINDING",
                relative,
                f"{context} confirmed binding does not uniquely scope the "
                "source revision to this task and sequence",
            )
        )
        return None
    return binding


def _projection_pinned_source(
    manifest: Mapping[str, Any],
    source_id: Any,
    revision_id: Any,
) -> Mapping[str, Any] | None:
    evidence_sources = manifest.get("evidence_sources")
    matches = [
        candidate
        for candidate in evidence_sources or []
        if isinstance(candidate, Mapping)
        and candidate.get("source_id") == source_id
        and candidate.get("revision_id") == revision_id
    ] if isinstance(evidence_sources, list) else []
    return matches[0] if len(matches) == 1 else None


def _validate_projection_evidence(
    root: Path,
    manifest: Mapping[str, Any],
    task_id: str,
    events: Mapping[str, Mapping[str, Any]],
    reference: Mapping[str, Any],
    relative: str,
    context: str,
    issues: list[Issue],
    *,
    expected_claim_key: str | None = None,
) -> None:
    kind = reference.get("kind")
    if kind == "memory_event":
        event_id = reference.get("memory_event_id")
        event_hash = reference.get("event_sha256")
        if not _valid_id(event_id):
            return
        event = events.get(str(event_id))
        if event is None:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE",
                    relative,
                    f"{context} refers to missing memory event {event_id!r}",
                )
            )
            return
        if (
            not isinstance(event_hash, str)
            or event.get("event_sha256") != event_hash
            or not _projection_event_hash_is_valid(event)
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_HASH",
                    relative,
                    f"{context} does not match the verified hash of "
                    f"memory event {event_id!r}",
                )
            )
        semantic_task_ids = event.get("semantic_task_ids")
        if not isinstance(semantic_task_ids, list) or task_id not in semantic_task_ids:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_TASK",
                    relative,
                    f"{context} memory event {event_id!r} is not scoped to "
                    f"task {task_id!r}",
                )
            )
        event_source = event.get("source")
        pinned_source = (
            _projection_pinned_source(
                manifest,
                event_source.get("source_id"),
                event_source.get("revision_id"),
            )
            if isinstance(event_source, Mapping)
            else None
        )
        if pinned_source is None:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} memory event source revision is not permanently "
                    "pinned by this task version",
                )
            )
        elif (
            event_source.get("source_sequence")
            != pinned_source.get("source_sequence")
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} memory event source sequence is stale",
                )
            )
        else:
            _projection_confirmed_binding(
                root,
                pinned_source,
                task_id,
                relative,
                context,
                issues,
            )
            revision = _projection_source_revisions(
                root,
                str(event_source.get("source_id")),
            ).get(str(event_source.get("revision_id")))
            if (
                revision is None
                or revision.get("source_sequence")
                != event_source.get("source_sequence")
                or revision.get("content_sha256")
                != pinned_source.get("content_sha256")
            ):
                issues.append(
                    Issue(
                        "PROJECTION_EVIDENCE_SOURCE",
                        relative,
                        f"{context} memory event source revision cannot be "
                        "verified",
                    )
                )
            anchor = event_source.get("evidence_anchor_sha256")
            content_path_value = pinned_source.get("content_path")
            content_path = (
                root / content_path_value
                if isinstance(content_path_value, str)
                and _valid_safe_relative_path(content_path_value)
                else None
            )
            if (
                isinstance(anchor, str)
                and content_path is not None
                and content_path.is_file()
                and not content_path.is_symlink()
            ):
                try:
                    content = load_document(content_path)
                except DataError:
                    content = None
                messages = _projection_conversation_messages(
                    content,
                    str(event_source.get("source_id")),
                    relative,
                    context,
                    issues,
                )
                anchor_matches = [
                    message
                    for message in messages
                    if isinstance(message.get("text"), str)
                    and hashlib.sha256(
                        str(message["text"]).encode("utf-8")
                    ).hexdigest()
                    == anchor
                ]
                if len(anchor_matches) != 1:
                    issues.append(
                        Issue(
                            "PROJECTION_EVIDENCE_HASH",
                            relative,
                            f"{context} memory event message anchor cannot be "
                            "resolved uniquely in its raw source revision",
                        )
                    )
        event_claim_key = event.get("claim_key")
        if (
            expected_claim_key is not None
            and event_claim_key is not None
            and event_claim_key != expected_claim_key
        ):
            issues.append(
                Issue(
                    "PROJECTION_CLAIM_EVIDENCE",
                    relative,
                    f"{context} memory event claim_key {event_claim_key!r} "
                    f"does not match projected claim_key {expected_claim_key!r}",
                )
            )
        return

    if kind == "source_message":
        source_id = reference.get("source_id")
        revision_id = reference.get("revision_id")
        sequence = reference.get("source_sequence")
        revision_content_hash = reference.get("revision_content_sha256")
        message_ordinal = reference.get("message_ordinal")
        anchor = reference.get("evidence_anchor_sha256")
        if not _valid_id(source_id) or not _valid_id(revision_id):
            return
        matched_manifest_source = _projection_pinned_source(
            manifest,
            source_id,
            revision_id,
        )
        if matched_manifest_source is None:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} source revision is not permanently pinned by "
                    "this task version's evidence_sources",
                )
            )
            return
        _projection_confirmed_binding(
            root,
            matched_manifest_source,
            task_id,
            relative,
            context,
            issues,
        )
        if (
            matched_manifest_source.get("source_sequence") != sequence
            or matched_manifest_source.get("content_sha256")
            != revision_content_hash
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_HASH",
                    relative,
                    f"{context} source sequence or revision hash does not "
                    "match the task version",
                )
            )
        content_path_value = matched_manifest_source.get("content_path")
        content_path = (
            root / content_path_value
            if isinstance(content_path_value, str)
            and _valid_safe_relative_path(content_path_value)
            else None
        )
        if (
            content_path is None
            or not content_path.is_file()
            or content_path.is_symlink()
            or hashlib.sha256(content_path.read_bytes()).hexdigest()
            != revision_content_hash
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} source content path or exact content hash "
                    "cannot be verified",
                )
            )
        revision = _projection_source_revisions(root, str(source_id)).get(
            str(revision_id)
        )
        if revision is None:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} source revision cannot be resolved",
                )
            )
            return
        if (
            revision.get("source_sequence") != sequence
            or revision.get("content_sha256") != revision_content_hash
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} source sequence or evidence anchor is stale",
                )
            )
        if content_path is None or not content_path.is_file():
            return
        try:
            revision_content = load_document(content_path)
        except DataError:
            revision_content = None
        messages = _projection_conversation_messages(
            revision_content,
            str(source_id),
            relative,
            context,
            issues,
        )
        matching_messages = [
            message
            for message in messages
            if isinstance(message, Mapping)
            and message.get("ordinal") == message_ordinal
        ]
        if len(matching_messages) != 1 or not isinstance(
            matching_messages[0].get("text") if matching_messages else None,
            str,
        ):
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_SOURCE",
                    relative,
                    f"{context} message ordinal cannot be resolved uniquely",
                )
            )
            return
        message_text = str(matching_messages[0]["text"])
        expected_anchor = hashlib.sha256(message_text.encode("utf-8")).hexdigest()
        if anchor != expected_anchor:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_HASH",
                    relative,
                    f"{context} message evidence anchor mismatch; expected "
                    f"{expected_anchor}",
                )
            )
        return

    if kind == "artifact":
        artifact_id = reference.get("artifact_id")
        artifact_hash = reference.get("sha256")
        artifacts = manifest.get("artifacts")
        matched_artifact: Mapping[str, Any] | None = None
        if isinstance(artifacts, list):
            for candidate in artifacts:
                if (
                    isinstance(candidate, Mapping)
                    and candidate.get("artifact_id") == artifact_id
                ):
                    matched_artifact = candidate
                    break
        if matched_artifact is None:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_ARTIFACT",
                    relative,
                    f"{context} artifact {artifact_id!r} is not in this task version",
                )
            )
        elif matched_artifact.get("sha256") != artifact_hash:
            issues.append(
                Issue(
                    "PROJECTION_EVIDENCE_HASH",
                    relative,
                    f"{context} artifact hash does not match this task version",
                )
            )


def _validate_projection_precondition(
    root: Path,
    manifest: Mapping[str, Any],
    task_id: str,
    basis: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
) -> None:
    generation = basis.get("generation")
    precondition = basis.get("source_current_precondition")
    if not isinstance(generation, int) or isinstance(generation, bool):
        return
    if generation == 1:
        if precondition is not None:
            issues.append(
                Issue(
                    "PROJECTION_PRECONDITION",
                    relative,
                    "generation 1 must have a null source_current_precondition",
                )
            )
        return
    if not isinstance(precondition, Mapping):
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "generation after 1 requires the previous CURRENT precondition",
            )
        )
        return
    if precondition.get("generation") != generation - 1:
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source_current_precondition must identify the immediately "
                "preceding generation",
            )
        )
    previous_snapshot = precondition.get("snapshot_id")
    parents = manifest.get("parents")
    matching_parents = [
        parent
        for parent in parents or []
        if isinstance(parent, Mapping)
        and parent.get("snapshot_id") == previous_snapshot
    ] if isinstance(parents, list) else []
    if len(matching_parents) != 1:
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source_current_precondition must identify exactly one parent "
                "entry in this task version",
            )
        )
        return
    parent = matching_parents[0]
    parent_commit = parent.get("commit")
    parent_path = parent.get("path")
    if not isinstance(parent_commit, str) or not isinstance(parent_path, str):
        return

    exists = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{parent_commit}^{{commit}}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", parent_commit, "HEAD"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode != 0 or ancestor.returncode != 0:
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "parent commit is unavailable or is not an ancestor of HEAD",
            )
        )
        return

    previous_value = _git_show_document(
        root,
        parent_commit,
        parent_path,
        relative,
        "PROJECTION_PRECONDITION",
        issues,
    )
    expected = {
        "task_id": task_id,
        "snapshot_id": previous_snapshot,
        "generation": precondition.get("generation"),
        "transaction_id": precondition.get("transaction_id"),
    }
    if previous_value is None or any(
        previous_value.get(key) != value for key, value in expected.items()
    ):
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source_current_precondition identity does not match the "
                "parent task version at its declared commit",
            )
        )

    current_blob_sha = precondition.get("current_blob_sha")
    if not isinstance(current_blob_sha, str):
        return
    current_path = f"tasks/{task_id}/CURRENT.json"
    blob = subprocess.run(
        ["git", "-C", str(root), "rev-parse", f"{parent_commit}:{current_path}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    historical_blob = blob.stdout.strip()
    if blob.returncode != 0 or historical_blob != current_blob_sha:
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source_current_precondition blob must be the exact CURRENT "
                "blob at the declared parent commit and task path",
            )
        )
        return
    shown = subprocess.run(
        ["git", "-C", str(root), "show", f"{parent_commit}:{current_path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if shown.returncode != 0:
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source CURRENT is unavailable at the declared parent commit",
            )
        )
        return
    try:
        previous_current = _load_document_bytes(shown.stdout, ".json")
    except DataError:
        previous_current = None
    if not isinstance(previous_current, Mapping):
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source CURRENT blob is not a valid task pointer",
            )
        )
        return
    expected_current = {
        "task_id": task_id,
        "snapshot_id": previous_snapshot,
        "generation": precondition.get("generation"),
        "manifest_path": parent_path,
        "published_transaction_id": precondition.get("transaction_id"),
    }
    if any(
        previous_current.get(key) != value
        for key, value in expected_current.items()
    ):
        issues.append(
            Issue(
                "PROJECTION_PRECONDITION",
                relative,
                "source CURRENT blob identity does not match the precondition",
            )
        )


def _validate_projection_claims(
    projection: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
) -> None:
    effective_values = projection.get("effective_claims")
    contested_values = projection.get("contested_claims")
    superseded_values = projection.get("superseded_claims")
    effective = [
        item for item in effective_values or [] if isinstance(item, Mapping)
    ] if isinstance(effective_values, list) else []
    superseded = [
        item for item in superseded_values or [] if isinstance(item, Mapping)
    ] if isinstance(superseded_values, list) else []
    contested = [
        item for item in contested_values or [] if isinstance(item, Mapping)
    ] if isinstance(contested_values, list) else []

    all_claims: dict[str, Mapping[str, Any]] = {}
    effective_by_id: dict[str, Mapping[str, Any]] = {}
    contested_by_id: dict[str, Mapping[str, Any]] = {}
    superseded_by_id: dict[str, Mapping[str, Any]] = {}
    effective_keys: dict[str, str] = {}
    contested_by_key: dict[str, set[str]] = {}
    for collection_name, collection, target in (
        ("effective_claims", effective, effective_by_id),
        ("contested_claims", contested, contested_by_id),
        ("superseded_claims", superseded, superseded_by_id),
    ):
        for index, claim in enumerate(collection):
            claim_id = claim.get("claim_id")
            claim_key = claim.get("claim_key")
            if not _valid_id(claim_id):
                continue
            if claim_id in all_claims:
                issues.append(
                    Issue(
                        "PROJECTION_CLAIM",
                        relative,
                        f"claim_id {claim_id!r} appears more than once",
                    )
                )
                continue
            all_claims[str(claim_id)] = claim
            target[str(claim_id)] = claim
            if collection_name == "effective_claims" and _valid_id(claim_key):
                earlier = effective_keys.get(str(claim_key))
                if earlier is not None:
                    issues.append(
                        Issue(
                            "PROJECTION_CLAIM_CONFLICT",
                            relative,
                            f"effective claims {earlier!r} and {claim_id!r} "
                            f"share claim_key {claim_key!r}",
                        )
                    )
                effective_keys[str(claim_key)] = str(claim_id)
            elif collection_name == "contested_claims" and _valid_id(claim_key):
                contested_by_key.setdefault(str(claim_key), set()).add(str(claim_id))

    for claim_key, contested_ids in contested_by_key.items():
        if claim_key in effective_keys:
            issues.append(
                Issue(
                    "PROJECTION_CLAIM_CONFLICT",
                    relative,
                    f"contested claim_key {claim_key!r} cannot also have an "
                    "effective claim",
                )
            )
        conflicts = projection.get("blocking_conflicts")
        covered_together = False
        if isinstance(conflicts, list):
            for conflict in conflicts:
                if not isinstance(conflict, Mapping):
                    continue
                conflict_claims = set(conflict.get("claim_ids") or [])
                if contested_ids.issubset(conflict_claims):
                    covered_together = True
                    break
        if not covered_together:
            issues.append(
                Issue(
                    "PROJECTION_CLAIM_CONFLICT",
                    relative,
                    f"contested claims for {claim_key!r} must be covered "
                    "together by one blocking conflict",
                )
            )

    for claim_id, claim in effective_by_id.items():
        superseded_ids = claim.get("superseded_claim_ids")
        if not isinstance(superseded_ids, list):
            continue
        for old_id in superseded_ids:
            old_claim = superseded_by_id.get(str(old_id))
            if old_claim is None:
                issues.append(
                    Issue(
                        "PROJECTION_SUPERSEDES",
                        relative,
                        f"effective claim {claim_id!r} refers to unavailable "
                        f"superseded claim {old_id!r}",
                    )
                )
                continue
            if (
                old_claim.get("superseded_by_claim_id") != claim_id
                or old_claim.get("claim_key") != claim.get("claim_key")
            ):
                issues.append(
                    Issue(
                        "PROJECTION_SUPERSEDES",
                        relative,
                        f"supersedes relation {old_id!r} -> {claim_id!r} "
                        "is not bidirectionally consistent",
                    )
                )

    for old_id, old_claim in superseded_by_id.items():
        new_id = old_claim.get("superseded_by_claim_id")
        new_claim = effective_by_id.get(str(new_id))
        if (
            new_claim is None
            or old_id not in (new_claim.get("superseded_claim_ids") or [])
            or new_claim.get("claim_key") != old_claim.get("claim_key")
        ):
            issues.append(
                Issue(
                    "PROJECTION_SUPERSEDES",
                    relative,
                    f"superseded claim {old_id!r} has no consistent effective "
                    "successor",
                )
            )

    gaps = projection.get("known_gaps")
    gap_by_id = {
        str(gap["gap_id"]): gap
        for gap in gaps or []
        if isinstance(gap, Mapping) and _valid_id(gap.get("gap_id"))
    } if isinstance(gaps, list) else {}
    for claim_id, claim in all_claims.items():
        rationale = claim.get("rationale")
        if (
            isinstance(rationale, Mapping)
            and rationale.get("status") == "not_recovered"
        ):
            gap = gap_by_id.get(str(rationale.get("gap_id")))
            if gap is None or gap.get("area") != "rationale":
                issues.append(
                    Issue(
                        "PROJECTION_RATIONALE_GAP",
                        relative,
                        f"claim {claim_id!r} has an unresolved rationale "
                        "without a matching rationale gap",
                    )
                )

    actions = projection.get("next_actions")
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, Mapping):
                continue
            for claim_id in action.get("depends_on_claim_ids") or []:
                if claim_id not in effective_by_id:
                    issues.append(
                        Issue(
                            "PROJECTION_CLAIM_REFERENCE",
                            relative,
                            f"next action {action.get('action_id')!r} depends on "
                            f"non-effective claim {claim_id!r}",
                        )
                    )

    contradictions = projection.get("nonblocking_contradictions")
    if isinstance(contradictions, list):
        for contradiction in contradictions:
            if not isinstance(contradiction, Mapping):
                continue
            effective_id = contradiction.get("effective_claim_id")
            effective_claim = effective_by_id.get(str(effective_id))
            if effective_claim is None:
                issues.append(
                    Issue(
                        "PROJECTION_CLAIM_REFERENCE",
                        relative,
                        "nonblocking contradiction does not resolve to an "
                        "effective claim",
                    )
                )
                continue
            superseded_ids = set(effective_claim.get("superseded_claim_ids") or [])
            for historical_id in contradiction.get("historical_claim_ids") or []:
                if (
                    historical_id not in superseded_by_id
                    or historical_id not in superseded_ids
                ):
                    issues.append(
                        Issue(
                            "PROJECTION_SUPERSEDES",
                            relative,
                            f"nonblocking historical claim {historical_id!r} "
                            "has not been explicitly superseded",
                        )
                    )

    conflicts = projection.get("blocking_conflicts")
    conflicts_by_id = {
        str(conflict["conflict_id"]): conflict
        for conflict in conflicts or []
        if isinstance(conflict, Mapping) and _valid_id(conflict.get("conflict_id"))
    } if isinstance(conflicts, list) else {}
    if isinstance(conflicts, list):
        for conflict in conflicts:
            if not isinstance(conflict, Mapping):
                continue
            for claim_id in conflict.get("claim_ids") or []:
                if claim_id not in all_claims:
                    issues.append(
                        Issue(
                            "PROJECTION_CLAIM_REFERENCE",
                            relative,
                            f"blocking conflict refers to unknown claim "
                            f"{claim_id!r}",
                        )
                    )

    questions = projection.get("open_questions")
    if isinstance(questions, list):
        for question in questions:
            if not isinstance(question, Mapping):
                continue
            question_id = question.get("question_id")
            related_ids = question.get("related_claim_ids")
            if not isinstance(related_ids, list):
                related_ids = []
            for claim_id in related_ids:
                if claim_id not in all_claims:
                    issues.append(
                        Issue(
                            "PROJECTION_CLAIM_REFERENCE",
                            relative,
                            f"open question {question_id!r} refers to unknown "
                            f"claim {claim_id!r}",
                        )
                    )
            conflict_id = question.get("blocking_conflict_id")
            if question.get("blocking") is True:
                conflict = conflicts_by_id.get(str(conflict_id))
                if conflict is None:
                    issues.append(
                        Issue(
                            "PROJECTION_QUESTION",
                            relative,
                            f"blocking open question {question_id!r} must "
                            "identify an existing blocking conflict",
                        )
                    )
                elif related_ids and not (
                    set(related_ids) & set(conflict.get("claim_ids") or [])
                ):
                    issues.append(
                        Issue(
                            "PROJECTION_QUESTION",
                            relative,
                            f"blocking open question {question_id!r} is not "
                            "linked to a claim in its conflict",
                        )
                    )
            elif conflict_id is not None:
                issues.append(
                    Issue(
                        "PROJECTION_QUESTION",
                        relative,
                        f"nonblocking open question {question_id!r} cannot "
                        "claim a blocking conflict",
                    )
                )

            claim_key = question.get("claim_key")
            effective_id = effective_keys.get(str(claim_key))
            if effective_id is not None and conflict_id is None:
                effective_claim = effective_by_id[effective_id]
                if effective_claim.get("settled") is True:
                    issues.append(
                        Issue(
                            "PROJECTION_REASK",
                            relative,
                            f"open question {question_id!r} reopens settled "
                            f"claim_key {claim_key!r} without a blocking conflict",
                        )
                    )


def _projection_reachable_manifests(
    root: Path,
    manifest: Mapping[str, Any],
    task_id: str,
) -> dict[str, Mapping[str, Any]]:
    """Return the current manifest plus immutable ancestors reachable by parents."""

    result: dict[str, Mapping[str, Any]] = {}
    snapshot_id = manifest.get("snapshot_id")
    if _valid_id(snapshot_id):
        result[str(snapshot_id)] = manifest
    pending = list(manifest.get("parents") or [])
    visited_paths: set[str] = set()
    while pending:
        parent = pending.pop()
        if not isinstance(parent, Mapping):
            continue
        path_value = parent.get("path")
        if (
            not isinstance(path_value, str)
            or path_value in visited_paths
            or not _valid_safe_relative_path(path_value)
        ):
            continue
        visited_paths.add(path_value)
        try:
            value = load_document(root / path_value)
        except (DataError, FileNotFoundError):
            continue
        if (
            not isinstance(value, Mapping)
            or value.get("task_id") != task_id
            or value.get("snapshot_id") != parent.get("snapshot_id")
        ):
            continue
        parent_snapshot = value.get("snapshot_id")
        if _valid_id(parent_snapshot):
            result[str(parent_snapshot)] = value
        nested = value.get("parents")
        if isinstance(nested, list):
            pending.extend(nested)
    return result


def _validate_projection_artifacts(
    manifest: Mapping[str, Any],
    projection: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
    *,
    root: Path | None = None,
) -> None:
    manifest_artifacts = manifest.get("artifacts")
    artifacts_by_id: dict[str, Mapping[str, Any]] = {}
    if isinstance(manifest_artifacts, list):
        for artifact in manifest_artifacts:
            if not isinstance(artifact, Mapping):
                continue
            artifact_id = artifact.get("artifact_id")
            if not _valid_id(artifact_id):
                continue
            if artifact_id in artifacts_by_id:
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT",
                        relative,
                        f"task version contains duplicate artifact_id {artifact_id!r}",
                    )
                )
            artifacts_by_id[str(artifact_id)] = artifact

    authorities_value = projection.get("artifact_authorities")
    authorities = [
        item for item in authorities_value or [] if isinstance(item, Mapping)
    ] if isinstance(authorities_value, list) else []
    authority_by_id: dict[str, Mapping[str, Any]] = {}
    for authority in authorities:
        artifact_id = authority.get("artifact_id")
        if not _valid_id(artifact_id):
            continue
        if artifact_id in authority_by_id:
            issues.append(
                Issue(
                    "PROJECTION_ARTIFACT",
                    relative,
                    f"artifact authority {artifact_id!r} appears more than once",
                )
            )
            continue
        authority_by_id[str(artifact_id)] = authority
        manifest_artifact = artifacts_by_id.get(str(artifact_id))
        if (
            manifest_artifact is None
            or manifest_artifact.get("sha256") != authority.get("sha256")
        ):
            issues.append(
                Issue(
                    "PROJECTION_ARTIFACT",
                    relative,
                    f"artifact authority {artifact_id!r} does not match the "
                    "task version artifact and hash",
                )
            )
        if authority.get("authority_status") in {
            "current_authoritative",
            "current_companion",
        }:
            verification = authority.get("verification")
            checks = (
                verification.get("checks")
                if isinstance(verification, Mapping)
                else None
            )
            if (
                not isinstance(verification, Mapping)
                or verification.get("status") != "verified"
                or not isinstance(checks, list)
                or not checks
            ):
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_VERIFICATION",
                        relative,
                        f"current artifact {artifact_id!r} is not fully verified",
                    )
                )
        verification = authority.get("verification")
        if (
            isinstance(verification, Mapping)
            and verification.get("status") == "verified"
        ):
            checks = verification.get("checks")
            check_values = (
                [check for check in checks if isinstance(check, Mapping)]
                if isinstance(checks, list)
                else []
            )
            check_kinds = {check.get("kind") for check in check_values}
            evidence = verification.get("evidence")
            checks_have_evidence = all(
                isinstance(check.get("evidence"), list)
                and bool(check.get("evidence"))
                for check in check_values
            )
            if (
                not check_values
                or len(check_values) != len(checks or [])
                or any(check.get("result") != "passed" for check in check_values)
                or "sha256" not in check_kinds
                or not ({"remote_identity", "size"} & check_kinds)
                or not isinstance(evidence, list)
                or not evidence
                or not checks_have_evidence
            ):
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_VERIFICATION",
                        relative,
                        f"verified artifact {artifact_id!r} requires passed "
                        "sha256 and remote-identity/size checks with evidence",
                    )
                )

    completeness = projection.get("completeness")
    artifact_complete = (
        isinstance(completeness, Mapping)
        and completeness.get("artifacts") == "complete"
    )
    manifest_ids = set(artifacts_by_id)
    authority_ids = set(authority_by_id)
    if artifact_complete and manifest_ids != authority_ids:
        issues.append(
            Issue(
                "PROJECTION_COMPLETENESS",
                relative,
                "completeness.artifacts is complete but the artifact authority "
                "list does not classify every task-version artifact exactly once",
            )
        )
    elif manifest_ids != authority_ids:
        gaps = projection.get("known_gaps")
        has_artifact_gap = isinstance(gaps, list) and any(
            isinstance(gap, Mapping) and gap.get("area") == "artifact"
            for gap in gaps
        )
        if not has_artifact_gap:
            issues.append(
                Issue(
                    "PROJECTION_COMPLETENESS",
                    relative,
                    "an incomplete artifact authority list requires an explicit "
                    "artifact known_gap",
                )
            )

    if root is not None and _valid_id(manifest.get("task_id")):
        reachable = _projection_reachable_manifests(
            root,
            manifest,
            str(manifest["task_id"]),
        )
        for artifact_id, authority in authority_by_id.items():
            source_snapshot = authority.get("source_snapshot_id")
            source_manifest = reachable.get(str(source_snapshot))
            source_artifacts = (
                source_manifest.get("artifacts")
                if isinstance(source_manifest, Mapping)
                else None
            )
            source_match = next(
                (
                    artifact
                    for artifact in source_artifacts or []
                    if isinstance(artifact, Mapping)
                    and artifact.get("artifact_id") == artifact_id
                    and artifact.get("sha256") == authority.get("sha256")
                ),
                None,
            ) if isinstance(source_artifacts, list) else None
            if source_manifest is None or source_match is None:
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_LINEAGE",
                        relative,
                        f"artifact {artifact_id!r} source_snapshot_id must "
                        "identify the current version or a reachable ancestor "
                        "containing the same artifact and hash",
                    )
                )

    dependency_graph: dict[str, set[str]] = {
        artifact_id: set() for artifact_id in authority_by_id
    }
    conflicts = projection.get("blocking_conflicts")

    def conflict_covers(artifact_ids: set[str]) -> bool:
        if not artifact_ids or not isinstance(conflicts, list):
            return False
        return any(
            isinstance(conflict, Mapping)
            and artifact_ids.issubset(set(conflict.get("artifact_ids") or []))
            for conflict in conflicts
        )

    for artifact_id, authority in authority_by_id.items():
        for dependency in authority.get("dependencies") or []:
            if dependency == artifact_id or dependency not in authority_by_id:
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_RELATION",
                        relative,
                        f"artifact {artifact_id!r} has invalid dependency "
                        f"{dependency!r}",
                    )
                )
                continue
            dependency_graph[artifact_id].add(str(dependency))
        for relation in authority.get("relations") or []:
            if not isinstance(relation, Mapping):
                continue
            target = relation.get("target_artifact_id")
            if target == artifact_id or target not in authority_by_id:
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_RELATION",
                        relative,
                        f"artifact {artifact_id!r} has invalid relation target "
                        f"{target!r}",
                    )
                )
                continue
            kind = relation.get("kind")
            target_authority = authority_by_id[str(target)]
            source_status = authority.get("authority_status")
            target_status = target_authority.get("authority_status")
            current_statuses = {"current_authoritative", "current_companion"}
            if kind == "supersedes" and target_status in current_statuses:
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_RELATION",
                        relative,
                        f"artifact {artifact_id!r} supersedes {target!r}, so "
                        "the target cannot remain current",
                    )
                )
            elif kind == "rejected_in_favor_of" and (
                source_status != "rejected"
                or target_status not in current_statuses
            ):
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_RELATION",
                        relative,
                        "rejected_in_favor_of requires a rejected source and "
                        "a current target",
                    )
                )
            elif kind == "companion_to" and "current_companion" not in {
                source_status,
                target_status,
            }:
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_RELATION",
                        relative,
                        "companion_to requires at least one current_companion",
                    )
                )
            elif (
                kind == "alternative_to"
                and source_status in current_statuses
                and target_status in current_statuses
                and not conflict_covers({artifact_id, str(target)})
            ):
                issues.append(
                    Issue(
                        "PROJECTION_ARTIFACT_CONFLICT",
                        relative,
                        "simultaneously current alternative artifacts require "
                        "an explicit blocking conflict",
                    )
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(artifact_id: str) -> bool:
        if artifact_id in visiting:
            return True
        if artifact_id in visited:
            return False
        visiting.add(artifact_id)
        cyclic = any(visit(child) for child in dependency_graph[artifact_id])
        visiting.remove(artifact_id)
        visited.add(artifact_id)
        return cyclic

    if any(visit(artifact_id) for artifact_id in dependency_graph):
        issues.append(
            Issue(
                "PROJECTION_ARTIFACT_CYCLE",
                relative,
                "artifact dependencies must be acyclic",
            )
        )

    current_ids_by_role: dict[str, set[str]] = {}
    for artifact_id, authority in authority_by_id.items():
        if authority.get("authority_status") != "current_authoritative":
            continue
        role = authority.get("role")
        if not _valid_id(role):
            continue
        current_ids_by_role.setdefault(str(role), set()).add(artifact_id)
    for role, current_ids in current_ids_by_role.items():
        if len(current_ids) > 1 and not conflict_covers(current_ids):
            issues.append(
                Issue(
                    "PROJECTION_ARTIFACT_CONFLICT",
                    relative,
                    "multiple current authoritative artifacts in role "
                    f"{role!r} require one explicit blocking conflict covering "
                    "that authority slot",
                )
            )

    if isinstance(conflicts, list):
        for conflict in conflicts:
            if not isinstance(conflict, Mapping):
                continue
            for artifact_id in conflict.get("artifact_ids") or []:
                if artifact_id not in authority_by_id:
                    issues.append(
                        Issue(
                            "PROJECTION_ARTIFACT_RELATION",
                            relative,
                            f"blocking conflict refers to unknown artifact "
                            f"{artifact_id!r}",
                        )
                    )


def _projection_completeness_basis_for_audit(
    projection: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Return the durable basis, or the fail-closed legacy read view.

    Projection/v1 documents are immutable.  Early v1 projections therefore
    remain readable without ``completeness_basis``, but their old coverage
    labels cannot become an actionable basis merely because a newer validator
    is reading them.
    """

    basis = projection.get("completeness_basis")
    if isinstance(basis, Mapping):
        return {
            str(dimension): entry
            for dimension, entry in basis.items()
            if isinstance(entry, Mapping)
        }
    return {
        dimension: {
            "status": "unknown",
            "reason": LEGACY_COMPLETENESS_BASIS_REASON,
            "evidence": [],
        }
        for dimension in PROJECTION_COMPLETENESS_DIMENSIONS
    }


def _validate_projection_completeness_basis(
    projection: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
    *,
    required: bool,
) -> None:
    completeness = projection.get("completeness")
    basis = projection.get("completeness_basis")
    if basis is None:
        if required:
            issues.append(
                Issue(
                    "PROJECTION_COMPLETENESS_BASIS",
                    relative,
                    "a new or newly selected successor projection must persist "
                    "all seven completeness bases",
                )
            )
        return
    if required:
        for receipt in projection.get("reconciliation_receipts") or []:
            if (
                isinstance(receipt, Mapping)
                and "completeness_transitions" not in receipt
            ):
                issues.append(
                    Issue(
                        "PROJECTION_COMPLETENESS_BASIS",
                        relative,
                        "a new or newly selected successor receipt must "
                        "persist completeness_transitions, including an empty "
                        "list when no completeness basis changed",
                    )
                )
    expected_dimensions = set(PROJECTION_COMPLETENESS_DIMENSIONS)
    if not isinstance(basis, Mapping) or set(basis) != expected_dimensions:
        issues.append(
            Issue(
                "PROJECTION_COMPLETENESS_BASIS",
                relative,
                "completeness_basis must contain exactly the seven semantic "
                "dimensions",
            )
        )
        return
    for dimension in PROJECTION_COMPLETENESS_DIMENSIONS:
        entry = basis.get(dimension)
        if not isinstance(entry, Mapping):
            issues.append(
                Issue(
                    "PROJECTION_COMPLETENESS_BASIS",
                    relative,
                    f"completeness_basis.{dimension} must be a mapping",
                )
            )
            continue
        reason = entry.get("reason")
        evidence = entry.get("evidence")
        expected_status = (
            completeness.get(dimension)
            if isinstance(completeness, Mapping)
            else None
        )
        if (
            entry.get("status") != expected_status
            or not isinstance(reason, str)
            or not reason.strip()
            or not isinstance(evidence, list)
            or (
                entry.get("status") == "complete"
                and not evidence
            )
        ):
            issues.append(
                Issue(
                    "PROJECTION_COMPLETENESS_BASIS",
                    relative,
                    f"completeness_basis.{dimension} must match completeness, "
                    "retain a reason, and keep evidence for complete claims",
                )
            )


def _validate_projection_handoff_integrity(
    projection: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
    *,
    strict_successor: bool,
) -> None:
    """Keep handoff identities unambiguous and new checkpoints honest.

    Identifier ambiguity is unsafe even in a historical projection, so those
    checks always apply.  The next-action and empty-scope assertions apply only
    to projections introduced or newly selected by the compared successor.
    This preserves immutable early-v1 projections as fail-closed reference
    memory while preventing them from becoming newly actionable state.
    """

    def duplicate_identifiers(
        entries: list[tuple[str, Any]],
        label: str,
    ) -> None:
        seen: dict[str, str] = {}
        for location, identifier in entries:
            if not isinstance(identifier, str):
                continue
            previous = seen.get(identifier)
            if previous is not None:
                issues.append(
                    Issue(
                        "PROJECTION_IDENTIFIER_UNIQUENESS",
                        relative,
                        f"{label} identifier {identifier!r} appears in both "
                        f"{previous} and {location}",
                    )
                )
            else:
                seen[identifier] = location

    scope = projection.get("scope_boundaries")
    scope_entries: list[tuple[str, Any]] = []
    if isinstance(scope, Mapping):
        for direction in ("in_scope", "out_of_scope"):
            values = scope.get(direction)
            if not isinstance(values, list):
                continue
            scope_entries.extend(
                (
                    f"scope_boundaries.{direction}[{index}]",
                    item.get("boundary_id"),
                )
                for index, item in enumerate(values)
                if isinstance(item, Mapping)
            )
    duplicate_identifiers(scope_entries, "scope boundary")

    rejected = projection.get("rejected_options")
    if isinstance(rejected, list):
        duplicate_identifiers(
            [
                (f"rejected_options[{index}]", item.get("option_id"))
                for index, item in enumerate(rejected)
                if isinstance(item, Mapping)
            ],
            "rejected option",
        )

    progress_collections = (
        ("completed", "item_id"),
        ("in_progress", "item_id"),
        ("next_actions", "action_id"),
    )
    progress_by_bucket: dict[str, set[str]] = {}
    for collection_name, identifier_field in progress_collections:
        values = projection.get(collection_name)
        if not isinstance(values, list):
            continue
        entries = [
            (
                f"{collection_name}[{index}]",
                item.get(identifier_field),
            )
            for index, item in enumerate(values)
            if isinstance(item, Mapping)
        ]
        duplicate_identifiers(entries, f"{collection_name} progress item")
        progress_by_bucket[collection_name] = {
            identifier
            for _location, identifier in entries
            if isinstance(identifier, str)
        }

    claimed_progress_bucket: dict[str, str] = {}
    for collection_name, _identifier_field in progress_collections:
        for identifier in progress_by_bucket.get(collection_name, set()):
            previous = claimed_progress_bucket.get(identifier)
            if previous is not None:
                issues.append(
                    Issue(
                        "PROJECTION_PROGRESS_STATE",
                        relative,
                        f"progress identifier {identifier!r} appears in both "
                        f"{previous} and {collection_name}",
                    )
                )
            else:
                claimed_progress_bucket[identifier] = collection_name

    if not strict_successor:
        return

    gaps = projection.get("known_gaps")
    gap_areas = {
        gap.get("area")
        for gap in gaps or []
        if isinstance(gap, Mapping)
    } if isinstance(gaps, list) else set()
    completeness_basis = projection.get("completeness_basis")
    progress_basis = (
        completeness_basis.get("progress")
        if isinstance(completeness_basis, Mapping)
        else None
    )
    actions = projection.get("next_actions")
    goal = projection.get("current_goal")
    if (
        isinstance(goal, Mapping)
        and goal.get("status") == "active"
        and isinstance(actions, list)
        and not actions
        and "progress" not in gap_areas
        and not (
            isinstance(progress_basis, Mapping)
            and progress_basis.get("status") == "unknown"
        )
    ):
        issues.append(
            Issue(
                "PROJECTION_NEXT_ACTION",
                relative,
                "an active goal without a next action must retain either a "
                "progress known_gap or completeness_basis.progress=unknown",
            )
        )

    in_scope = scope.get("in_scope") if isinstance(scope, Mapping) else None
    out_of_scope = (
        scope.get("out_of_scope") if isinstance(scope, Mapping) else None
    )
    if (
        isinstance(in_scope, list)
        and isinstance(out_of_scope, list)
        and not in_scope
        and not out_of_scope
    ):
        if "goal_and_scope" not in gap_areas:
            issues.append(
                Issue(
                    "PROJECTION_SCOPE",
                    relative,
                    "an empty scope must retain an explicit goal_and_scope "
                    "known_gap",
                )
            )
        completeness = projection.get("completeness")
        if (
            isinstance(completeness, Mapping)
            and completeness.get("goal_and_scope") == "complete"
        ):
            issues.append(
                Issue(
                    "PROJECTION_SCOPE",
                    relative,
                    "an empty scope cannot declare goal_and_scope complete",
                )
            )


def _validate_projection_completeness(
    projection: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
) -> None:
    completeness = projection.get("completeness")
    gaps = projection.get("known_gaps")
    if not isinstance(completeness, Mapping) or not isinstance(gaps, list):
        return
    area_by_dimension = {
        "goal_and_scope": "goal_and_scope",
        "decisions": "decision",
        "rationales": "rationale",
        "progress": "progress",
        "artifacts": "artifact",
        "conflicts": "conflict",
        "evidence": "evidence",
    }
    gap_areas = {
        gap.get("area") for gap in gaps if isinstance(gap, Mapping)
    }
    for dimension, area in area_by_dimension.items():
        if completeness.get(dimension) == "complete" and area in gap_areas:
            issues.append(
                Issue(
                    "PROJECTION_COMPLETENESS",
                    relative,
                    f"completeness.{dimension} cannot be complete while a "
                    f"{area!r} gap remains",
                )
            )
    if completeness.get("overall") == "complete":
        incomplete = [
            dimension
            for dimension in area_by_dimension
            if completeness.get(dimension) != "complete"
        ]
        if incomplete or gaps:
            issues.append(
                Issue(
                    "PROJECTION_COMPLETENESS",
                    relative,
                    "overall completeness requires every dimension complete "
                    "and no known gaps",
                )
            )
    deltas = projection.get("unprojected_deltas")
    if isinstance(deltas, list) and deltas:
        unsafe_complete = [
            dimension
            for dimension in (
                "goal_and_scope",
                "decisions",
                "rationales",
                "progress",
                "artifacts",
                "conflicts",
                "evidence",
            )
            if completeness.get(dimension) == "complete"
        ]
        if completeness.get("overall") != "partial" or unsafe_complete:
            issues.append(
                Issue(
                    "PROJECTION_UNPROJECTED_DELTA",
                    relative,
                    "unprojected visible deltas require overall=partial and "
                    "every completeness dimension to be partial or unknown",
                )
            )


def _validate_projection_deltas(
    projection: Mapping[str, Any],
    relative: str,
    issues: list[Issue],
) -> None:
    """Require every unreconciled visible delta to have an exact trace entry."""

    deltas = projection.get("unprojected_deltas")
    index = projection.get("evidence_index")
    if not isinstance(deltas, list) or not isinstance(index, list):
        return
    entries = {
        str(entry["entry_id"]): entry
        for entry in index
        if isinstance(entry, Mapping) and _valid_id(entry.get("entry_id"))
    }
    seen_ids: set[str] = set()
    for delta in deltas:
        if not isinstance(delta, Mapping):
            continue
        delta_id = delta.get("delta_id")
        if _valid_id(delta_id):
            if str(delta_id) in seen_ids:
                issues.append(
                    Issue(
                        "PROJECTION_UNPROJECTED_DELTA",
                        relative,
                        f"unprojected delta_id {delta_id!r} is duplicated",
                    )
                )
            seen_ids.add(str(delta_id))
        entry_id = delta.get("evidence_entry_id")
        entry = entries.get(str(entry_id))
        message_refs = delta.get("message_evidence")
        entry_refs = entry.get("references") if isinstance(entry, Mapping) else None
        try:
            expected = {
                json.dumps(ref, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for ref in message_refs or []
                if isinstance(ref, Mapping)
            }
            actual = {
                json.dumps(ref, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for ref in entry_refs or []
                if isinstance(ref, Mapping)
            }
        except (TypeError, ValueError):
            expected = set()
            actual = set()
        if entry is None or not expected or expected != actual:
            issues.append(
                Issue(
                    "PROJECTION_UNPROJECTED_DELTA",
                    relative,
                    f"unprojected delta {delta_id!r} must point to one "
                    "evidence_index entry containing exactly its message evidence",
                )
            )


def _validate_projection_reconciliation_receipts(
    root: Path,
    manifest: Mapping[str, Any],
    projection: Mapping[str, Any],
    events: Mapping[str, Mapping[str, Any]],
    relative: str,
    issues: list[Issue],
) -> None:
    """Prove that every parent delta is either retained or semantically absorbed."""

    receipts_value = projection.get("reconciliation_receipts")
    deltas_value = projection.get("unprojected_deltas")
    evidence_index_value = projection.get("evidence_index")
    if (
        not isinstance(receipts_value, list)
        or not isinstance(deltas_value, list)
        or not isinstance(evidence_index_value, list)
    ):
        return

    def canonical(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def result_objects(
        value: Mapping[str, Any],
    ) -> dict[str, dict[str, Mapping[str, Any]]]:
        scope = value.get("scope_boundaries")
        scope_groups = (
            (
                scope.get("in_scope") or [],
                scope.get("out_of_scope") or [],
            )
            if isinstance(scope, Mapping)
            else ([], [])
        )

        def indexed(
            collection_name: str,
            id_field: str,
        ) -> dict[str, Mapping[str, Any]]:
            collection = value.get(collection_name)
            return {
                str(item[id_field]): item
                for item in collection or []
                if isinstance(item, Mapping) and _valid_id(item.get(id_field))
            } if isinstance(collection, list) else {}

        goal = value.get("current_goal")
        completeness_basis = _projection_completeness_basis_for_audit(value)
        return {
            "current_goal": (
                {"current_goal": goal}
                if isinstance(goal, Mapping)
                else {}
            ),
            "completeness": {
                dimension: {
                    "dimension": dimension,
                    "status": completeness_basis[dimension].get("status"),
                    "basis": completeness_basis[dimension],
                }
                for dimension in PROJECTION_COMPLETENESS_DIMENSIONS
                if dimension in completeness_basis
            },
            "scope_boundary": {
                str(item["boundary_id"]): {
                    "direction": direction,
                    "boundary": item,
                }
                for direction, group in (
                    ("in_scope", scope_groups[0]),
                    ("out_of_scope", scope_groups[1]),
                )
                for item in group
                if isinstance(item, Mapping)
                and _valid_id(item.get("boundary_id"))
            },
            "effective_claim": indexed("effective_claims", "claim_id"),
            "contested_claim": indexed("contested_claims", "claim_id"),
            "superseded_claim": indexed("superseded_claims", "claim_id"),
            "rejected_option": indexed("rejected_options", "option_id"),
            "artifact_authority": indexed(
                "artifact_authorities",
                "artifact_id",
            ),
            "completed_item": indexed("completed", "item_id"),
            "in_progress_item": indexed("in_progress", "item_id"),
            "next_action": indexed("next_actions", "action_id"),
            "open_question": indexed("open_questions", "question_id"),
            "risk": indexed("risks", "risk_id"),
            "blocking_conflict": indexed(
                "blocking_conflicts",
                "conflict_id",
            ),
            "nonblocking_contradiction": indexed(
                "nonblocking_contradictions",
                "contradiction_id",
            ),
            "known_gap": indexed("known_gaps", "gap_id"),
            "evidence_index_entry": indexed("evidence_index", "entry_id"),
        }

    current_delta_ids = {
        str(delta["delta_id"])
        for delta in deltas_value
        if isinstance(delta, Mapping) and _valid_id(delta.get("delta_id"))
    }
    evidence_entries = {
        str(entry["entry_id"]): entry
        for entry in evidence_index_value
        if isinstance(entry, Mapping) and _valid_id(entry.get("entry_id"))
    }
    current_result_objects = result_objects(projection)
    result_ids_by_kind = {
        kind: set(objects) for kind, objects in current_result_objects.items()
    }

    parent_projections: dict[str, Mapping[str, Any]] = {}
    parent_result_objects: dict[
        str,
        dict[str, dict[str, Mapping[str, Any]]],
    ] = {}
    parents = manifest.get("parents")
    for parent in parents or []:
        if not isinstance(parent, Mapping):
            continue
        parent_path_value = parent.get("path")
        if (
            not isinstance(parent_path_value, str)
            or not _valid_safe_relative_path(parent_path_value)
        ):
            continue
        parent_commit = parent.get("commit")
        if (
            not isinstance(parent_commit, str)
            or not GIT_SHA_RE.fullmatch(parent_commit)
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "a direct parent receipt source has no valid Git commit",
                )
            )
            continue
        shown_parent = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "show",
                f"{parent_commit}:{parent_path_value}",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        worktree_parent_path = root / parent_path_value
        if (
            shown_parent.returncode != 0
            or not worktree_parent_path.is_file()
            or worktree_parent_path.is_symlink()
            or worktree_parent_path.read_bytes() != shown_parent.stdout
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "the direct parent manifest must exist unchanged at its "
                    "declared Git commit",
                )
            )
            continue
        try:
            parent_manifest = _load_document_bytes(
                shown_parent.stdout,
                worktree_parent_path.suffix.lower(),
            )
        except DataError:
            parent_manifest = None
        reference = (
            parent_manifest.get("memory_projection")
            if isinstance(parent_manifest, Mapping)
            else None
        )
        if not isinstance(reference, Mapping):
            continue
        source_projection_id = reference.get("projection_id")
        source_path_value = reference.get("path")
        expected_hash = reference.get("content_sha256")
        expected_source_path = (
            f"tasks/{manifest.get('task_id')}/projections/"
            f"{source_projection_id}.json"
        )
        source_path = (
            root / source_path_value
            if isinstance(source_path_value, str)
            and _valid_safe_relative_path(source_path_value)
            else None
        )
        shown_source = (
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "show",
                    f"{parent_commit}:{source_path_value}",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if isinstance(source_path_value, str)
            and _valid_safe_relative_path(source_path_value)
            else None
        )
        if (
            not _valid_id(source_projection_id)
            or source_path_value != expected_source_path
            or source_path is None
            or not source_path.is_file()
            or source_path.is_symlink()
            or shown_source is None
            or shown_source.returncode != 0
            or not isinstance(expected_hash, str)
            or hashlib.sha256(shown_source.stdout).hexdigest() != expected_hash
            or source_path.read_bytes() != shown_source.stdout
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "a direct parent memory projection must exist unchanged at "
                    "the declared parent commit with its recorded hash",
                )
            )
            continue
        try:
            source_projection = _load_document_bytes(
                shown_source.stdout,
                source_path.suffix.lower(),
            )
        except DataError:
            source_projection = None
        if (
            not isinstance(source_projection, Mapping)
            or source_projection.get("projection_id") != source_projection_id
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "a direct parent memory projection has an invalid identity",
                )
            )
            continue
        previous_source_projection = parent_projections.get(
            str(source_projection_id)
        )
        if (
            previous_source_projection is not None
            and canonical(previous_source_projection)
            != canonical(source_projection)
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "direct parents reuse one projection ID for different "
                    "content",
                )
            )
            continue
        parent_projections[str(source_projection_id)] = source_projection
        parent_result_objects[str(source_projection_id)] = result_objects(
            source_projection
        )

    def linked_receipt_message_keys(
        result_object: Mapping[str, Any],
        receipt_messages: Mapping[str, Mapping[str, Any]],
    ) -> set[str]:
        linked: set[str] = set()
        for evidence in _iter_projection_evidence(result_object):
            evidence_kind = evidence.get("kind")
            if evidence_kind == "source_message":
                key = canonical(evidence)
                if key in receipt_messages:
                    linked.add(key)
                continue
            if evidence_kind != "memory_event":
                continue
            event_id = evidence.get("memory_event_id")
            event = events.get(str(event_id))
            if (
                not isinstance(event, Mapping)
                or event.get("event_sha256") != evidence.get("event_sha256")
            ):
                continue
            event_source = event.get("source")
            if not isinstance(event_source, Mapping):
                continue
            for key, message in receipt_messages.items():
                if (
                    message.get("kind") == "source_message"
                    and event_source.get("source_id") == message.get("source_id")
                    and event_source.get("revision_id")
                    == message.get("revision_id")
                    and event_source.get("source_sequence")
                    == message.get("source_sequence")
                    and event_source.get("evidence_anchor_sha256")
                    == message.get("evidence_anchor_sha256")
                ):
                    linked.add(key)
        return linked

    seen_receipt_ids: set[str] = set()
    resolved_by_source: dict[str, set[str]] = {}
    state_result_refs_by_source: dict[str, set[tuple[str, str]]] = {}
    retired_result_refs_by_source: dict[str, set[tuple[str, str]]] = {}
    receipt_outcomes_by_source: dict[str, set[str]] = {}
    for receipt in receipts_value:
        if not isinstance(receipt, Mapping):
            continue
        receipt_id = receipt.get("receipt_id")
        if _valid_id(receipt_id):
            if str(receipt_id) in seen_receipt_ids:
                issues.append(
                    Issue(
                        "PROJECTION_RECONCILIATION_RECEIPT",
                        relative,
                        f"reconciliation receipt_id {receipt_id!r} is duplicated",
                    )
                )
            seen_receipt_ids.add(str(receipt_id))

        source_projection_id = str(receipt.get("source_projection_id"))
        source_projection = parent_projections.get(source_projection_id)
        if source_projection is None:
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} must cite a verified direct-parent "
                    "projection",
                )
            )
            continue
        receipt_outcomes_by_source.setdefault(source_projection_id, set()).add(
            str(receipt.get("outcome"))
        )
        source_deltas = {
            str(delta["delta_id"]): delta
            for delta in source_projection.get("unprojected_deltas") or []
            if isinstance(delta, Mapping) and _valid_id(delta.get("delta_id"))
        }
        resolved_ids = {
            str(delta_id) for delta_id in receipt.get("resolved_delta_ids") or []
        }
        unknown_delta_ids = resolved_ids - set(source_deltas)
        if unknown_delta_ids:
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} resolves unknown parent delta IDs "
                    f"{sorted(unknown_delta_ids)!r}",
                )
            )
        overlap = resolved_ids & current_delta_ids
        if overlap:
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} marks deltas both resolved and "
                    f"unprojected: {sorted(overlap)!r}",
                )
            )
        previously_resolved = resolved_by_source.setdefault(
            source_projection_id,
            set(),
        )
        if previously_resolved & resolved_ids:
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} claims a parent delta already "
                    "resolved by another receipt",
                )
            )
        previously_resolved.update(resolved_ids)

        expected_message_evidence = {
            canonical(reference)
            for delta_id in resolved_ids
            for reference in (
                source_deltas.get(delta_id, {}).get("message_evidence") or []
            )
            if isinstance(reference, Mapping)
        }
        receipt_messages_by_key = {
            canonical(reference): reference
            for reference in receipt.get("message_evidence") or []
            if isinstance(reference, Mapping)
        }
        receipt_message_evidence = set(receipt_messages_by_key)
        if (
            not expected_message_evidence
            or receipt_message_evidence != expected_message_evidence
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} must preserve exactly the original "
                    "message evidence of its resolved parent deltas",
                )
            )

        evidence_entry_ids = {
            str(entry_id) for entry_id in receipt.get("evidence_entry_ids") or []
        }
        unknown_entry_ids = evidence_entry_ids - set(evidence_entries)
        covered_evidence = {
            canonical(reference)
            for entry_id in evidence_entry_ids
            for reference in (
                evidence_entries.get(entry_id, {}).get("references") or []
            )
            if isinstance(reference, Mapping)
        }
        if unknown_entry_ids or not receipt_message_evidence.issubset(
            covered_evidence
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} must retain every reconciled "
                    "message in its named evidence_index entries",
                )
            )

        source_completeness_basis = (
            _projection_completeness_basis_for_audit(source_projection)
        )
        successor_completeness_basis = (
            _projection_completeness_basis_for_audit(projection)
        )
        completeness_transitions = [
            transition
            for transition in receipt.get("completeness_transitions") or []
            if isinstance(transition, Mapping)
        ]
        transition_dimensions: set[str] = set()
        invalid_completeness_transition = False
        for transition in completeness_transitions:
            dimension = str(transition.get("dimension"))
            source_entry = source_completeness_basis.get(dimension)
            successor_entry = successor_completeness_basis.get(dimension)
            if (
                dimension not in PROJECTION_COMPLETENESS_DIMENSIONS
                or dimension in transition_dimensions
                or not isinstance(source_entry, Mapping)
                or not isinstance(successor_entry, Mapping)
            ):
                invalid_completeness_transition = True
                continue
            transition_dimensions.add(dimension)
            before = transition.get("before")
            after = transition.get("after")
            change_kind = transition.get("change_kind")
            transition_evidence = {
                canonical(reference)
                for reference in transition.get("evidence") or []
                if isinstance(reference, Mapping)
            }
            successor_evidence = {
                canonical(reference)
                for reference in successor_entry.get("evidence") or []
                if isinstance(reference, Mapping)
            }
            status_change_matches = (
                change_kind == "status_changed" and before != after
            ) or (
                change_kind == "basis_refreshed" and before == after
            )
            if (
                before != source_entry.get("status")
                or after != successor_entry.get("status")
                or transition.get("before_basis_sha256")
                != sha256_jcs(source_entry)
                or transition.get("after_basis_sha256")
                != sha256_jcs(successor_entry)
                or transition.get("before_basis_sha256")
                == transition.get("after_basis_sha256")
                or not status_change_matches
                or transition.get("reason") != successor_entry.get("reason")
                or transition_evidence != successor_evidence
                or not transition_evidence
                or not transition_evidence.issubset(receipt_message_evidence)
            ):
                invalid_completeness_transition = True

        result_refs = [
            result
            for result in receipt.get("result_refs") or []
            if isinstance(result, Mapping)
        ]
        invalid_results = [
            result
            for result in result_refs
            if str(result.get("id"))
            not in result_ids_by_kind.get(str(result.get("kind")), set())
        ]
        evidence_result_ids = {
            str(result.get("id"))
            for result in result_refs
            if result.get("kind") == "evidence_index_entry"
        }
        completeness_result_ids = {
            str(result.get("id"))
            for result in result_refs
            if result.get("kind") == "completeness"
        }
        if completeness_result_ids != transition_dimensions:
            invalid_completeness_transition = True
        retired_refs = [
            result
            for result in receipt.get("retired_refs") or []
            if isinstance(result, Mapping)
        ]
        invalid_retired_refs: list[Mapping[str, Any]] = []
        source_results_for_receipt = parent_result_objects.get(
            source_projection_id,
            {},
        )
        for retired in retired_refs:
            kind = str(retired.get("kind"))
            result_id = str(retired.get("id"))
            if (
                result_id
                not in source_results_for_receipt.get(kind, {})
                or result_id in current_result_objects.get(kind, {})
            ):
                invalid_retired_refs.append(retired)
                continue
            recorded_retired = retired_result_refs_by_source.setdefault(
                source_projection_id,
                set(),
            )
            if (kind, result_id) in recorded_retired:
                invalid_retired_refs.append(retired)
                continue
            recorded_retired.add((kind, result_id))
        retirement_message_evidence = {
            canonical(reference)
            for reference in receipt.get("retirement_message_evidence") or []
            if isinstance(reference, Mapping)
        }
        invalid_retirement_evidence = (
            not retirement_message_evidence.issubset(
                receipt_message_evidence
            )
            or bool(retired_refs) != bool(retirement_message_evidence)
        )
        outcome = receipt.get("outcome")
        non_evidence_results = [
            result
            for result in result_refs
            if result.get("kind") != "evidence_index_entry"
        ]
        changed_result_errors: list[str] = []
        linked_result_messages: set[str] = set()
        if outcome == "state_updated":
            source_results = parent_result_objects.get(
                source_projection_id,
                {},
            )
            for result in non_evidence_results:
                kind = str(result.get("kind"))
                result_id = str(result.get("id"))
                successor_object = current_result_objects.get(kind, {}).get(
                    result_id
                )
                if kind == "current_goal":
                    source_values = list(
                        source_results.get("current_goal", {}).values()
                    )
                    source_object = (
                        source_values[0] if len(source_values) == 1 else None
                    )
                else:
                    source_object = source_results.get(kind, {}).get(result_id)
                if (
                    not isinstance(successor_object, Mapping)
                    or (
                        isinstance(source_object, Mapping)
                        and canonical(successor_object)
                        == canonical(source_object)
                    )
                ):
                    changed_result_errors.append(f"{kind}:{result_id}")
                    continue
                linked = linked_receipt_message_keys(
                    successor_object,
                    receipt_messages_by_key,
                )
                if not linked:
                    changed_result_errors.append(f"{kind}:{result_id}")
                    continue
                linked_result_messages.update(linked)
                recorded_results = state_result_refs_by_source.setdefault(
                    source_projection_id,
                    set(),
                )
                if (kind, result_id) in recorded_results:
                    changed_result_errors.append(f"{kind}:{result_id}")
                    continue
                recorded_results.add((kind, result_id))
        if (
            invalid_results
            or invalid_retired_refs
            or invalid_retirement_evidence
            or invalid_completeness_transition
            or not result_refs
            or evidence_result_ids != evidence_entry_ids
            or (
                outcome == "state_updated"
                and (
                    not (non_evidence_results or retired_refs)
                    or changed_result_errors
                    or (
                        linked_result_messages
                        | retirement_message_evidence
                    )
                    != receipt_message_evidence
                )
            )
            or (
                outcome == "evidence_only_no_semantic_change"
                and (
                    non_evidence_results
                    or retired_refs
                    or retirement_message_evidence
                )
            )
        ):
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    f"receipt {receipt_id!r} must index existing semantic "
                    "results and exactly the named evidence entries; every "
                    "state result must be new or changed and preserve the "
                    "resolved message evidence",
                )
            )

    for source_projection_id, source_projection in parent_projections.items():
        parent_delta_ids = {
            str(delta["delta_id"])
            for delta in source_projection.get("unprojected_deltas") or []
            if isinstance(delta, Mapping) and _valid_id(delta.get("delta_id"))
        }
        accounted_for = current_delta_ids | resolved_by_source.get(
            source_projection_id,
            set(),
        )
        missing = parent_delta_ids - accounted_for
        if missing:
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "a successor projection must retain or explicitly reconcile "
                    f"every direct-parent delta; missing {sorted(missing)!r}",
                )
            )

        source_results = parent_result_objects.get(source_projection_id, {})
        changed_results: set[tuple[str, str]] = set()
        removed_results: set[tuple[str, str]] = set()
        for kind, successor_objects in current_result_objects.items():
            if kind == "evidence_index_entry":
                continue
            parent_objects = source_results.get(kind, {})
            if kind == "current_goal":
                successor_values = list(successor_objects.items())
                parent_values = list(parent_objects.values())
                if (
                    len(successor_values) == 1
                    and (
                        len(parent_values) != 1
                        or canonical(successor_values[0][1])
                        != canonical(parent_values[0])
                    )
                ):
                    changed_results.add((kind, successor_values[0][0]))
                continue
            for result_id, successor_object in successor_objects.items():
                parent_object = parent_objects.get(result_id)
                if (
                    parent_object is None
                    or canonical(successor_object) != canonical(parent_object)
                ):
                    changed_results.add((kind, result_id))
            removed_results.update(
                (kind, result_id)
                for result_id in set(parent_objects) - set(successor_objects)
            )

        outcomes = receipt_outcomes_by_source.get(source_projection_id, set())
        recorded_state_results = state_result_refs_by_source.get(
            source_projection_id,
            set(),
        )
        recorded_retired_results = retired_result_refs_by_source.get(
            source_projection_id,
            set(),
        )
        manifest_artifact_ids = {
            str(item["artifact_id"])
            for item in manifest.get("artifacts") or []
            if isinstance(item, Mapping) and _valid_id(item.get("artifact_id"))
        }
        authority_artifact_ids = set(
            current_result_objects.get("artifact_authority", {})
        )
        newly_appended_delta_ids = current_delta_ids - parent_delta_ids
        newly_appended_message_evidence = {
            canonical(reference)
            for delta in deltas_value
            if isinstance(delta, Mapping)
            and str(delta.get("delta_id")) in newly_appended_delta_ids
            for reference in delta.get("message_evidence") or []
            if isinstance(reference, Mapping)
        }
        successor_basis = _projection_completeness_basis_for_audit(projection)
        ordinary_rollforward_basis = (
            bool(newly_appended_delta_ids)
            and bool(newly_appended_message_evidence)
            and isinstance(projection.get("completeness"), Mapping)
            and projection["completeness"].get("overall") == "partial"
            and all(
                isinstance(successor_basis.get(dimension), Mapping)
                and successor_basis[dimension].get("status") == "partial"
                and successor_basis[dimension].get("reason")
                == ROLL_FORWARD_COMPLETENESS_BASIS_REASON
                and bool(successor_basis[dimension].get("evidence"))
                and {
                    canonical(reference)
                    for reference in (
                        successor_basis[dimension].get("evidence") or []
                    )
                    if isinstance(reference, Mapping)
                }.issubset(newly_appended_message_evidence)
                for dimension in PROJECTION_COMPLETENESS_DIMENSIONS
            )
        )

        def allowed_unreceipted_change(result_ref: tuple[str, str]) -> bool:
            kind, result_id = result_ref
            value = current_result_objects.get(kind, {}).get(result_id)
            if (
                kind == "completeness"
                and result_id in PROJECTION_COMPLETENESS_DIMENSIONS
            ):
                return ordinary_rollforward_basis
            basis = projection.get("basis")
            snapshot_id = (
                basis.get("snapshot_id")
                if isinstance(basis, Mapping)
                else None
            )
            transaction_id = (
                basis.get("transaction_id")
                if isinstance(basis, Mapping)
                else None
            )
            expected_gap_id = (
                "gap-artifact-rollforward-"
                + hashlib.sha256(
                    f"{snapshot_id}:{transaction_id}".encode("utf-8")
                ).hexdigest()[:24]
                if _valid_id(snapshot_id) and _valid_id(transaction_id)
                else None
            )
            expected_gap = {
                "gap_id": expected_gap_id,
                "area": "artifact",
                "statement": (
                    "This successor contains new or replaced artifacts that "
                    "remain reference-only until a later projection explicitly "
                    "classifies and verifies their authority."
                ),
                "trace_status": "not_attempted",
                "evidence": [],
            }
            return (
                kind == "known_gap"
                and isinstance(value, Mapping)
                and result_id == expected_gap_id
                and result_id not in source_results.get(kind, {})
                and canonical(value) == canonical(expected_gap)
                and bool(manifest_artifact_ids - authority_artifact_ids)
            )

        if not outcomes:
            invalid_unreceipted = {
                result_ref
                for result_ref in changed_results
                if not allowed_unreceipted_change(result_ref)
            }
            transition_invalid = bool(
                invalid_unreceipted or removed_results
            )
        else:
            transition_invalid = (
                changed_results != recorded_state_results
                or removed_results != recorded_retired_results
            )
        if transition_invalid:
            issues.append(
                Issue(
                    "PROJECTION_RECONCILIATION_RECEIPT",
                    relative,
                    "every semantic state change or retirement must be covered "
                    "exactly by direct-parent reconciliation receipts",
                )
            )


def _validate_projection_parents(
    root: Path,
    manifest: Mapping[str, Any],
    task_id: str,
    relative: str,
    issues: list[Issue],
) -> None:
    """Verify every declared version parent against its immutable Git commit."""

    parents = manifest.get("parents")
    generation = manifest.get("generation")
    if not isinstance(parents, list):
        return
    if generation == 1 and parents:
        issues.append(
            Issue(
                "PROJECTION_PARENT",
                relative,
                "generation 1 cannot declare a task-version parent",
            )
        )
    seen_snapshots: set[str] = set()
    for index, parent in enumerate(parents):
        context = f"parents[{index}]"
        if not isinstance(parent, Mapping):
            continue
        snapshot_id = parent.get("snapshot_id")
        commit = parent.get("commit")
        path_value = parent.get("path")
        if _valid_id(snapshot_id):
            if str(snapshot_id) in seen_snapshots:
                issues.append(
                    Issue(
                        "PROJECTION_PARENT",
                        relative,
                        f"{context} duplicates snapshot {snapshot_id!r}",
                    )
                )
            seen_snapshots.add(str(snapshot_id))
        if (
            not isinstance(commit, str)
            or not isinstance(path_value, str)
            or not _valid_safe_relative_path(path_value)
        ):
            continue
        exists = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ancestor = subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", commit, "HEAD"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if exists.returncode != 0 or ancestor.returncode != 0:
            issues.append(
                Issue(
                    "PROJECTION_PARENT",
                    relative,
                    f"{context} commit is unavailable or not an ancestor of HEAD",
                )
            )
            continue
        historical = _git_show_document(
            root,
            commit,
            path_value,
            relative,
            "PROJECTION_PARENT",
            issues,
        )
        if (
            historical is None
            or historical.get("task_id") != task_id
            or historical.get("snapshot_id") != snapshot_id
            or not isinstance(historical.get("generation"), int)
            or (
                isinstance(generation, int)
                and historical.get("generation") >= generation
            )
        ):
            issues.append(
                Issue(
                    "PROJECTION_PARENT",
                    relative,
                    f"{context} does not resolve to an older version of this task",
                )
            )
            continue
        worktree_parent = root / path_value
        if not worktree_parent.is_file() or worktree_parent.is_symlink():
            issues.append(
                Issue(
                    "PROJECTION_PARENT",
                    relative,
                    f"{context} immutable parent manifest is absent from the "
                    "current repository",
                )
            )
            continue
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{path_value}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if shown.returncode != 0 or shown.stdout != worktree_parent.read_bytes():
            issues.append(
                Issue(
                    "PROJECTION_PARENT",
                    relative,
                    f"{context} parent manifest was rewritten after its "
                    "declared commit",
                )
            )


def _validate_projection_basis(
    root: Path,
    manifest: Mapping[str, Any],
    manifest_path: Path,
    projection: Mapping[str, Any],
    task_id: str,
    relative: str,
    issues: list[Issue],
) -> None:
    basis = projection.get("basis")
    if not isinstance(basis, Mapping):
        return
    expected = {
        "task_id": task_id,
        "snapshot_id": manifest.get("snapshot_id"),
        "generation": manifest.get("generation"),
        "transaction_id": manifest.get("transaction_id"),
        "manifest_path": _relative(manifest_path, root),
    }
    for key, expected_value in expected.items():
        if basis.get(key) != expected_value:
            issues.append(
                Issue(
                    "PROJECTION_BASIS",
                    relative,
                    f"basis.{key} must equal task version value "
                    f"{expected_value!r}",
                )
            )

    _validate_projection_parents(root, manifest, task_id, relative, issues)

    current_path = root / "tasks" / task_id / "CURRENT.json"
    try:
        current = load_document(current_path)
    except (DataError, FileNotFoundError):
        current = None
    if (
        isinstance(current, Mapping)
        and current.get("manifest_path") == _relative(manifest_path, root)
    ):
        current_expected = {
            "task_id": task_id,
            "snapshot_id": manifest.get("snapshot_id"),
            "generation": manifest.get("generation"),
            "published_transaction_id": manifest.get("transaction_id"),
        }
        if any(
            current.get(key) != value
            for key, value in current_expected.items()
        ):
            issues.append(
                Issue(
                    "PROJECTION_BASIS",
                    relative,
                    "active CURRENT identity does not match the projected "
                    "task version",
                )
            )
    _validate_projection_precondition(
        root,
        manifest,
        task_id,
        basis,
        relative,
        issues,
    )


def _projection_paths_requiring_completeness_basis(
    root: Path,
    compare_ref: str | None,
) -> set[str]:
    """Identify successor projections introduced or newly selected by HEAD."""

    if not compare_ref:
        return set()
    exists = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{compare_ref}^{{commit}}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode != 0:
        return set()
    process = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--name-status",
            "--find-renames",
            compare_ref,
            "HEAD",
            "--",
            "tasks",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        return set()

    changed_paths: dict[str, str] = {}
    for line in process.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or parts[0].startswith("D"):
            continue
        changed_paths[parts[-1]] = parts[0]

    required: set[str] = {
        path
        for path in changed_paths
        if re.fullmatch(
            r"tasks/[a-z0-9][a-z0-9_-]{1,63}/projections/"
            r"[a-z0-9][a-z0-9_-]{1,63}\.json",
            path,
        )
    }

    def add_manifest_projection(manifest_path_value: Any) -> None:
        if (
            not isinstance(manifest_path_value, str)
            or not _valid_safe_relative_path(manifest_path_value)
        ):
            return
        manifest_path = root / manifest_path_value
        if not manifest_path.is_file() or manifest_path.is_symlink():
            return
        try:
            manifest = load_document(manifest_path)
        except DataError:
            return
        reference = (
            manifest.get("memory_projection")
            if isinstance(manifest, Mapping)
            else None
        )
        projection_path = (
            reference.get("path")
            if isinstance(reference, Mapping)
            else None
        )
        if (
            isinstance(projection_path, str)
            and _valid_safe_relative_path(projection_path)
        ):
            required.add(projection_path)

    def old_document(path: str) -> Mapping[str, Any] | None:
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{compare_ref}:{path}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if shown.returncode != 0:
            return None
        try:
            value = _load_document_bytes(
                shown.stdout,
                Path(path).suffix.lower(),
            )
        except DataError:
            return None
        return value if isinstance(value, Mapping) else None

    for path, status in changed_paths.items():
        if re.fullmatch(
            r"tasks/[a-z0-9][a-z0-9_-]{1,63}/versions/"
            r"[a-z0-9][a-z0-9_-]{1,63}\.json",
            path,
        ):
            add_manifest_projection(path)
            continue
        if not re.fullmatch(
            r"tasks/[a-z0-9][a-z0-9_-]{1,63}/CURRENT\.json",
            path,
        ):
            continue
        current_path = root / path
        if not current_path.is_file() or current_path.is_symlink():
            continue
        try:
            current = load_document(current_path)
        except DataError:
            continue
        if isinstance(current, Mapping):
            old_current = old_document(path)
            pointer_fields = (
                "manifest_path",
                "snapshot_id",
                "published_transaction_id",
            )
            if (
                not status.startswith("A")
                and isinstance(old_current, Mapping)
                and all(
                    old_current.get(field) == current.get(field)
                    for field in pointer_fields
                )
            ):
                continue
            add_manifest_projection(current.get("manifest_path"))
    return required


def validate_task_memory_projections(
    root: Path,
    issues: list[Issue],
    compare_ref: str | None = None,
) -> None:
    """Validate immutable task-version memory projections and their evidence."""

    basis_required_paths = _projection_paths_requiring_completeness_basis(
        root,
        compare_ref,
    )
    projected_manifests: list[tuple[Path, Mapping[str, Any]]] = []
    for manifest_path in sorted(root.glob("tasks/*/versions/*.json")):
        if not manifest_path.is_file() or manifest_path.is_symlink():
            continue
        try:
            value = load_document(manifest_path)
        except DataError:
            continue
        if isinstance(value, Mapping) and "memory_projection" in value:
            projected_manifests.append((manifest_path, value))
    if not projected_manifests:
        return

    task_version_schema_path = root / "schemas" / "task_version.schema.json"
    projection_schema_path = (
        root / "schemas" / "task_memory_projection.schema.json"
    )
    try:
        task_version_schema = load_document(task_version_schema_path)
        projection_schema = load_document(projection_schema_path)
    except (DataError, FileNotFoundError) as exc:
        issues.append(
            Issue(
                "PROJECTION_SCHEMA",
                _relative(projection_schema_path, root),
                str(exc),
            )
        )
        return
    if not isinstance(task_version_schema, Mapping) or not isinstance(
        projection_schema, Mapping
    ):
        issues.append(
            Issue(
                "PROJECTION_SCHEMA",
                "schemas",
                "task projection schemas must be mappings",
            )
        )
        return
    task_properties = task_version_schema.get("properties")
    projection_ref_schema = (
        task_properties.get("memory_projection")
        if isinstance(task_properties, Mapping)
        else None
    )
    if not isinstance(projection_ref_schema, Mapping):
        issues.append(
            Issue(
                "PROJECTION_SCHEMA",
                _relative(task_version_schema_path, root),
                "task version schema has no memory_projection contract",
            )
        )
        return

    events = _load_event_records(root)
    for manifest_path, manifest_value in projected_manifests:
        manifest_relative = _relative(manifest_path, root)
        reference = manifest_value.get("memory_projection")
        if reference is None:
            continue
        manifest_errors = _json_schema_subset_errors(
            manifest_value,
            task_version_schema,
            task_version_schema,
            "$",
        )
        for message in manifest_errors[:50]:
            issues.append(
                Issue("PROJECTION_MANIFEST_FORMAT", manifest_relative, message)
            )
        evidence_sources = manifest_value.get("evidence_sources")
        source_keys: set[tuple[str, str]] = set()
        if isinstance(evidence_sources, list):
            for index, source in enumerate(evidence_sources):
                if not isinstance(source, Mapping):
                    continue
                source_key = (
                    str(source.get("source_id")),
                    str(source.get("revision_id")),
                )
                if source_key in source_keys:
                    issues.append(
                        Issue(
                            "PROJECTION_EVIDENCE_SOURCE",
                            manifest_relative,
                            f"evidence_sources[{index}] duplicates source "
                            f"revision {source_key!r}",
                        )
                    )
                source_keys.add(source_key)
                expected_source_path = (
                    f"sources/{source.get('source_id')}/revisions/"
                    f"{source.get('revision_id')}.json"
                )
                if source.get("content_path") != expected_source_path:
                    issues.append(
                        Issue(
                            "PROJECTION_EVIDENCE_SOURCE",
                            manifest_relative,
                            f"evidence_sources[{index}].content_path must equal "
                            f"{expected_source_path!r}",
                        )
                    )
        reference_errors = _json_schema_subset_errors(
            reference,
            projection_ref_schema,
            task_version_schema,
            "$.memory_projection",
        )
        for message in reference_errors[:20]:
            issues.append(Issue("PROJECTION_REF", manifest_relative, message))
        if not isinstance(reference, Mapping):
            continue

        task_id = manifest_value.get("task_id")
        projection_id = reference.get("projection_id")
        path_value = reference.get("path")
        if not _valid_id(task_id) or not _valid_id(projection_id):
            continue
        expected_path = (
            f"tasks/{task_id}/projections/{projection_id}.json"
        )
        if path_value != expected_path:
            issues.append(
                Issue(
                    "PROJECTION_REF",
                    manifest_relative,
                    f"projection path must equal {expected_path!r}",
                )
            )
            continue
        projection_path = root / expected_path
        if not projection_path.is_file() or projection_path.is_symlink():
            issues.append(
                Issue(
                    "PROJECTION_REF",
                    manifest_relative,
                    "projection path must be an existing real file",
                )
            )
            continue
        raw = projection_path.read_bytes()
        actual_hash = hashlib.sha256(raw).hexdigest()
        if reference.get("content_sha256") != actual_hash:
            issues.append(
                Issue(
                    "PROJECTION_HASH",
                    manifest_relative,
                    f"projection content_sha256 mismatch; expected {actual_hash}",
                )
            )
        projection_relative = _relative(projection_path, root)
        try:
            projection_value = load_document(projection_path)
        except DataError as exc:
            issues.append(Issue("PROJECTION_PARSE", projection_relative, str(exc)))
            continue
        if not isinstance(projection_value, Mapping):
            issues.append(
                Issue(
                    "PROJECTION_FORMAT",
                    projection_relative,
                    "projection must be a mapping",
                )
            )
            continue
        structural_errors = _json_schema_subset_errors(
            projection_value,
            projection_schema,
            projection_schema,
        )
        for message in structural_errors[:50]:
            issues.append(Issue("PROJECTION_FORMAT", projection_relative, message))
        if projection_value.get("projection_id") != projection_id:
            issues.append(
                Issue(
                    "PROJECTION_REF",
                    projection_relative,
                    "projection_id disagrees with the version reference",
                )
            )

        _validate_projection_completeness_basis(
            projection_value,
            projection_relative,
            issues,
            required=projection_relative in basis_required_paths,
        )
        completeness_basis = projection_value.get("completeness_basis")
        if isinstance(completeness_basis, Mapping):
            for dimension in PROJECTION_COMPLETENESS_DIMENSIONS:
                entry = completeness_basis.get(dimension)
                if not isinstance(entry, Mapping):
                    continue
                for reference_value in _iter_projection_evidence(entry):
                    _validate_projection_evidence(
                        root,
                        manifest_value,
                        str(task_id),
                        events,
                        reference_value,
                        projection_relative,
                        f"completeness_basis.{dimension}",
                        issues,
                    )
        _validate_projection_basis(
            root,
            manifest_value,
            manifest_path,
            projection_value,
            str(task_id),
            projection_relative,
            issues,
        )
        _validate_projection_claims(projection_value, projection_relative, issues)
        _validate_projection_artifacts(
            manifest_value,
            projection_value,
            projection_relative,
            issues,
            root=root,
        )
        _validate_projection_handoff_integrity(
            projection_value,
            projection_relative,
            issues,
            strict_successor=projection_relative in basis_required_paths,
        )
        _validate_projection_completeness(
            projection_value,
            projection_relative,
            issues,
        )
        _validate_projection_deltas(
            projection_value,
            projection_relative,
            issues,
        )
        _validate_projection_reconciliation_receipts(
            root,
            manifest_value,
            projection_value,
            events,
            projection_relative,
            issues,
        )
        if (
            projection_value.get("unprojected_deltas")
            and manifest_value.get("continuation_readiness") == "ready"
        ):
            issues.append(
                Issue(
                    "PROJECTION_UNPROJECTED_DELTA",
                    projection_relative,
                    "a version with unprojected visible deltas cannot declare "
                    "continuation_readiness=ready",
                )
            )
        blocking_conflicts = projection_value.get("blocking_conflicts")
        readiness = manifest_value.get("continuation_readiness")
        if (
            isinstance(blocking_conflicts, list)
            and blocking_conflicts
            and readiness != "blocked"
        ):
            issues.append(
                Issue(
                    "PROJECTION_READINESS",
                    projection_relative,
                    "a projection with blocking conflicts must declare "
                    "continuation_readiness=blocked",
                )
            )
        if readiness == "ready" and (
            bool(projection_value.get("unprojected_deltas"))
            or bool(blocking_conflicts)
        ):
            issues.append(
                Issue(
                    "PROJECTION_READINESS",
                    projection_relative,
                    "continuation_readiness=ready requires no unprojected "
                    "deltas and no blocking conflicts",
                )
            )

        seen_evidence: set[str] = set()
        unique_evidence: list[Mapping[str, Any]] = []
        for evidence in _iter_projection_evidence(projection_value):
            try:
                key = json.dumps(
                    evidence,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            except (TypeError, ValueError):
                key = repr(evidence)
            if key in seen_evidence:
                continue
            seen_evidence.add(key)
            unique_evidence.append(evidence)
        for index, evidence in enumerate(unique_evidence):
            _validate_projection_evidence(
                root,
                manifest_value,
                str(task_id),
                events,
                evidence,
                projection_relative,
                f"evidence[{index}]",
                issues,
            )
        for collection_name in (
            "effective_claims",
            "contested_claims",
            "superseded_claims",
            "rejected_options",
        ):
            collection = projection_value.get(collection_name)
            if not isinstance(collection, list):
                continue
            for index, claim in enumerate(collection):
                if not isinstance(claim, Mapping):
                    continue
                claim_key = claim.get("claim_key")
                if not _valid_id(claim_key):
                    continue
                for evidence_index, evidence in enumerate(
                    _iter_projection_evidence(claim)
                ):
                    if evidence.get("kind") != "memory_event":
                        continue
                    event = events.get(str(evidence.get("memory_event_id")))
                    if (
                        isinstance(event, Mapping)
                        and event.get("claim_key") is not None
                        and event.get("claim_key") != claim_key
                    ):
                        issues.append(
                            Issue(
                                "PROJECTION_CLAIM_EVIDENCE",
                                projection_relative,
                                f"{collection_name}[{index}].evidence"
                                f"[{evidence_index}] memory event claim_key "
                                f"{event.get('claim_key')!r} does not match "
                                f"projected claim_key {claim_key!r}",
                            )
                        )


def _git_blob_sha(path: Path, algorithm: str = "sha1") -> str:
    raw = path.read_bytes()
    header = f"blob {len(raw)}\0".encode("ascii")
    digest = hashlib.new(algorithm)
    digest.update(header)
    digest.update(raw)
    return digest.hexdigest()


@dataclass(frozen=True)
class GitBasisResolution:
    """Trust state for one checkpoint's declared Git basis."""

    mode: str
    commit: str


def _resolve_checkpoint_git_basis(
    root: Path,
    commit: str,
    relative: str,
    issues: list[Issue],
    allow_exported_fallback: bool,
) -> GitBasisResolution:
    """Resolve a checkpoint basis without silently trusting missing history.

    Production validation requires a Git worktree.  The exported fallback
    exists only for isolated fixture validation where the caller explicitly
    opts in; it is not exposed by the command-line validator.  Inside a Git
    worktree, the declared commit must exist and be an ancestor of ``HEAD``;
    otherwise historical validation would be bypassed by a shallow clone, a
    fabricated hash, or an unrelated orphan commit.
    """

    try:
        worktree = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        worktree = None
    if (
        worktree is None
        or worktree.returncode != 0
        or worktree.stdout.strip() != "true"
    ):
        if allow_exported_fallback:
            return GitBasisResolution("exported", commit)
        issues.append(
            Issue(
                "CHECKPOINT_BASIS_HISTORY",
                relative,
                "checkpoint authority requires a complete Git worktree; "
                "an exported directory cannot prove historical basis commits",
            )
        )
        return GitBasisResolution("invalid", commit)

    exists = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode != 0:
        issues.append(
            Issue(
                "CHECKPOINT_BASIS_HISTORY",
                relative,
                f"basis commit {commit} is unavailable in this Git checkout; "
                "fetch complete history before validating",
            )
        )
        return GitBasisResolution("invalid", commit)

    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", commit, "HEAD"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ancestor.returncode != 0:
        issues.append(
            Issue(
                "CHECKPOINT_BASIS_HISTORY",
                relative,
                f"basis commit {commit} is not an ancestor of HEAD",
            )
        )
        return GitBasisResolution("invalid", commit)
    return GitBasisResolution("historical", commit)


def _load_event_records(root: Path) -> dict[str, Mapping[str, Any]]:
    records: dict[str, Mapping[str, Any]] = {}
    event_root = root / "memory" / "events"
    if not event_root.exists():
        return records
    for path in sorted(event_root.rglob("*")):
        if (
            not path.is_file()
            or path.is_symlink()
            or path.suffix.lower() not in {".json", ".yaml", ".yml"}
            or path.name.lower().startswith(("readme", "template"))
        ):
            continue
        try:
            value = load_document(path)
        except DataError:
            continue
        if isinstance(value, Mapping) and _valid_id(value.get("memory_event_id")):
            records[str(value["memory_event_id"])] = value
    return records


def _historical_event_integrity_is_valid(
    data: Mapping[str, Any],
    repository_path: str,
    commit: str,
    relative: str,
    issues: list[Issue],
) -> bool:
    """Re-authenticate an event read from a checkpoint's historical tree."""

    valid = True
    semantic_problems: list[str] = []
    schema = data.get("schema_version")
    required_fields = (
        EVENT_V2_REQUIRED if schema == "memory-event/v2" else EVENT_V1_REQUIRED
    )
    if set(data) != required_fields:
        missing = sorted(required_fields - set(data))
        extras = sorted(set(data) - required_fields)
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} has an invalid event field set at basis "
                f"commit {commit} (missing={missing}, extra={extras})",
            )
        )
        valid = False
    event_id = data.get("memory_event_id")
    if (
        schema not in {"memory-event/v1", "memory-event/v2"}
        or not _valid_id(event_id)
        or Path(repository_path).stem != event_id
    ):
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} has invalid event identity at basis "
                f"commit {commit}",
            )
        )
        valid = False
    if schema == "memory-event/v2" and (
        not isinstance(event_id, str)
        or re.fullmatch(r"evt-[0-9a-f]{40}", event_id) is None
        or repository_path
        != f"memory/events/{event_id[4:6]}/{event_id}.json"
    ):
        semantic_problems.append(
            "memory-event/v2 identity or content shard is invalid"
        )
    allowed_kinds = (
        EVENT_V2_KINDS if schema == "memory-event/v2" else EVENT_V1_KINDS
    )
    if data.get("kind") not in allowed_kinds:
        semantic_problems.append("kind is invalid")
    allowed_confidences = (
        {
            "user_confirmed",
            "artifact_verified",
            "source_explicit",
            "imported_unverified",
            "assistant_inferred",
        }
        if schema == "memory-event/v1"
        else {"source_explicit", "assistant_inferred"}
    )
    if data.get("confidence") not in allowed_confidences:
        semantic_problems.append("confidence is invalid")

    if schema == "memory-event/v1":
        task_ids = data.get("semantic_task_ids")
        if not isinstance(task_ids, list) or not all(
            _valid_id(task_id) for task_id in task_ids
        ):
            semantic_problems.append(
                "semantic_task_ids must be a list of portable identifiers"
            )
        elif len(task_ids) != len(set(task_ids)):
            semantic_problems.append(
                "semantic_task_ids cannot contain duplicates"
            )

    source = data.get("source")
    if not isinstance(source, Mapping) or not source:
        semantic_problems.append("source must be a non-empty mapping")
    else:
        if set(source) != {
            "source_id",
            "revision_id",
            "source_sequence",
            "evidence_anchor_sha256",
        }:
            semantic_problems.append(
                "source contains missing or unexpected fields"
            )
        if not _valid_id(source.get("source_id")):
            semantic_problems.append("source.source_id is invalid")
        if not _valid_id(source.get("revision_id")):
            semantic_problems.append("source.revision_id is invalid")
        if schema == "memory-event/v2" and (
            not isinstance(source.get("source_id"), str)
            or EPISODE_SOURCE_ID_RE.fullmatch(source["source_id"]) is None
            or not isinstance(source.get("revision_id"), str)
            or EPISODE_ID_RE.fullmatch(source["revision_id"]) is None
        ):
            semantic_problems.append(
                "memory-event/v2 evidence identity is invalid"
            )
        sequence = source.get("source_sequence")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
        ):
            semantic_problems.append(
                "source.source_sequence must be a non-negative integer"
            )
        anchor = source.get("evidence_anchor_sha256")
        if schema == "memory-event/v2" and anchor is None:
            semantic_problems.append(
                "memory-event/v2 requires an episode evidence anchor"
            )
        elif anchor is not None and (
            not isinstance(anchor, str) or not SHA256_RE.fullmatch(anchor)
        ):
            semantic_problems.append(
                "source.evidence_anchor_sha256 must be null or SHA-256"
            )

    claim_key = data.get("claim_key")
    if claim_key is not None and not _valid_id(claim_key):
        semantic_problems.append(
            "claim_key must be null or a portable identifier"
        )
    for key in ("parents", "supersedes", "conflicts_with", "resolves"):
        references = data.get(key)
        if not isinstance(references, list) or not all(
            _valid_id(item) for item in references
        ):
            semantic_problems.append(
                f"{key} must be a list of event identifiers"
            )
        elif len(references) != len(set(references)):
            semantic_problems.append(
                f"{key} cannot contain duplicate event identifiers"
            )
        elif event_id in references:
            semantic_problems.append(
                f"{key} cannot contain this event's own id"
            )
        elif schema == "memory-event/v2" and any(
            re.fullmatch(r"evt-[0-9a-f]{40}", str(item)) is None
            for item in references
        ):
            semantic_problems.append(
                f"{key} must contain taskless v2 event identifiers"
            )
    if (
        data.get("kind") == "conflict_declared"
        and isinstance(data.get("conflicts_with"), list)
        and len(data["conflicts_with"]) < 2
    ):
        semantic_problems.append(
            "conflict_declared requires at least two conflicts_with ids"
        )
    if (
        data.get("kind") == "conflict_resolved"
        and isinstance(data.get("resolves"), list)
        and not data["resolves"]
    ):
        semantic_problems.append(
            "conflict_resolved requires at least one resolves id"
        )
    payload = data.get("payload")
    if schema == "memory-event/v2" and isinstance(payload, Mapping):
        profile = payload.get("profile")
        if profile == "memory-network-episode-event/v1":
            source_id = source.get("source_id") if isinstance(source, Mapping) else None
            revision_id = source.get("revision_id") if isinstance(source, Mapping) else None
            expected_id = None
            if isinstance(source_id, str) and isinstance(revision_id, str):
                expected_id = "evt-" + hashlib.sha256(
                    f"episode\0{source_id}\0{revision_id}".encode("utf-8")
                ).hexdigest()[:40]
            roles = payload.get("roles")
            if (
                set(payload)
                != {
                    "memory_form",
                    "profile",
                    "message_count",
                    "roles",
                    "continuity",
                }
                or data.get("kind") != "checkpoint_note"
                or data.get("confidence") != "source_explicit"
                or data.get("claim_key") is not None
                or payload.get("memory_form") != "episodic"
                or not isinstance(roles, list)
                or not 1 <= len(roles) <= 2
                or any(role not in {"user", "assistant"} for role in roles)
                or payload.get("message_count") != len(roles)
                or payload.get("continuity") not in {"origin", "continues"}
                or bool(data.get("parents"))
                != (payload.get("continuity") == "continues")
                or not isinstance(data.get("parents"), list)
                or len(data["parents"]) > 1
                or any(
                    data.get(key)
                    for key in ("supersedes", "conflicts_with", "resolves")
                )
                or event_id != expected_id
            ):
                semantic_problems.append("episode event profile is invalid")
        elif profile == "memory-network-semantic/v1":
            if (
                set(payload) != {"profile", "claim"}
                or data.get("confidence") != "assistant_inferred"
                or not isinstance(payload.get("claim"), Mapping)
                or not payload["claim"]
            ):
                semantic_problems.append("semantic event profile is invalid")
            elif isinstance(source, Mapping):
                identity_domain = {
                    "source_id": source.get("source_id"),
                    "episode_id": source.get("revision_id"),
                    "kind": data.get("kind"),
                    "claim_key": data.get("claim_key"),
                    "parents": data.get("parents"),
                    "supersedes": data.get("supersedes"),
                    "conflicts_with": data.get("conflicts_with"),
                    "resolves": data.get("resolves"),
                    "payload": payload,
                }
                expected_id = "evt-" + sha256_jcs(identity_domain)[:40]
                if event_id != expected_id:
                    semantic_problems.append(
                        "semantic event identity is not content-addressed"
                    )
        else:
            semantic_problems.append("memory-event/v2 profile is invalid")
    expected_hash_profile = (
        "jcs-rfc8785+sha256/event-v2"
        if schema == "memory-event/v2"
        else "jcs-rfc8785+sha256/event-v1"
    )
    if (
        not isinstance(payload, Mapping)
        or data.get("hash_profile") != expected_hash_profile
        or not _valid_rfc3339(data.get("created_at"))
    ):
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} has invalid event integrity metadata at "
                f"basis commit {commit}",
            )
        )
        valid = False
    total_order_issues: list[Issue] = []
    _check_time_total_order(data, repository_path, total_order_issues)
    semantic_problems.extend(issue.message for issue in total_order_issues)
    for problem in semantic_problems:
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} violates event semantics at basis commit "
                f"{commit}: {problem}",
            )
        )
        valid = False

    payload_hash = data.get("payload_sha256")
    event_hash = data.get("event_sha256")
    try:
        expected_payload_hash = sha256_jcs(data.get("payload"))
        event_domain = dict(data)
        event_domain.pop("event_sha256", None)
        expected_event_hash = sha256_jcs(event_domain)
    except DataError as exc:
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} cannot be hashed at basis commit "
                f"{commit}: {exc}",
            )
        )
        return False
    if (
        not isinstance(payload_hash, str)
        or not SHA256_RE.fullmatch(payload_hash)
        or payload_hash != expected_payload_hash
    ):
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} payload_sha256 mismatch at basis commit "
                f"{commit}; expected {expected_payload_hash}",
            )
        )
        valid = False
    if (
        not isinstance(event_hash, str)
        or not SHA256_RE.fullmatch(event_hash)
        or event_hash != expected_event_hash
    ):
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                f"{repository_path} event_sha256 mismatch at basis commit "
                f"{commit}; expected {expected_event_hash}",
            )
        )
        valid = False
    return valid


def _load_event_records_at_git_commit(
    root: Path,
    commit: str,
    relative: str,
    issues: list[Issue],
) -> dict[str, Mapping[str, Any]]:
    """Load the event set visible at ``commit``.

    The caller must first resolve ``commit`` as trusted historical ancestry.
    Read failures are validation errors and never trigger a current-tree
    fallback.
    """

    listing = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            commit,
            "--",
            "memory/events",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if listing.returncode != 0:
        issues.append(
            Issue(
                "CHECKPOINT_EVENT_HISTORY",
                relative,
                listing.stderr.decode("utf-8", errors="replace").strip()
                or f"cannot list memory events at basis commit {commit}",
            )
        )
        return {}

    records: dict[str, Mapping[str, Any]] = {}
    for raw_path in listing.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            repository_path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_HISTORY",
                    relative,
                    f"non-UTF-8 event path at basis commit {commit}: {exc}",
                )
            )
            continue
        path = Path(repository_path)
        if (
            path.suffix.lower() not in {".json", ".yaml", ".yml"}
            or path.name.lower().startswith(("readme", "template"))
        ):
            continue
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{repository_path}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if shown.returncode != 0:
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_HISTORY",
                    relative,
                    shown.stderr.decode("utf-8", errors="replace").strip()
                    or f"cannot read {repository_path} at basis commit {commit}",
                )
            )
            continue
        try:
            value = _load_document_bytes(shown.stdout, path.suffix.lower())
        except DataError as exc:
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_HISTORY",
                    relative,
                    f"{repository_path} is invalid at basis commit {commit}: {exc}",
                )
            )
            continue
        if not isinstance(value, Mapping) or not _valid_id(
            value.get("memory_event_id")
        ):
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_HISTORY",
                    relative,
                    f"{repository_path} has no valid memory_event_id "
                    f"at basis commit {commit}",
                )
            )
            continue
        if not _historical_event_integrity_is_valid(
            value,
            repository_path,
            commit,
            relative,
            issues,
        ):
            continue
        event_id = str(value["memory_event_id"])
        if event_id in records:
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_HISTORY",
                    relative,
                    f"duplicate memory_event_id {event_id!r} "
                    f"at basis commit {commit}",
                )
            )
        records[event_id] = value
    return records


def _event_parent_closure(
    events: Mapping[str, Mapping[str, Any]],
    heads: Sequence[str],
    relative: str,
    issues: list[Issue],
) -> dict[str, Mapping[str, Any]]:
    """Return the explicit historical closure rooted at checkpoint heads."""

    closure: dict[str, Mapping[str, Any]] = {}
    pending = list(heads)
    while pending:
        event_id = pending.pop()
        if event_id in closure:
            continue
        event = events.get(event_id)
        if event is None:
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_SET",
                    relative,
                    f"event closure refers to missing event {event_id!r}",
                )
            )
            continue
        closure[event_id] = event
        parents = event.get("parents")
        if not isinstance(parents, list) or not all(
            isinstance(parent, str) and _valid_id(parent) for parent in parents
        ):
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_SET",
                    relative,
                    f"event {event_id!r} has an invalid parents list",
                )
            )
            continue
        pending.extend(parents)
    return closure


def _checkpoint_event_records(
    root: Path,
    current_events: Mapping[str, Mapping[str, Any]],
    basis: Mapping[str, Any],
    basis_resolution: GitBasisResolution,
    relative: str,
    issues: list[Issue],
) -> dict[str, Mapping[str, Any]]:
    """Resolve the immutable event set represented by one checkpoint."""

    if basis_resolution.mode == "historical":
        return _load_event_records_at_git_commit(
            root, basis_resolution.commit, relative, issues
        )
    if basis_resolution.mode == "invalid":
        return {}

    heads = basis.get("event_heads")
    if not isinstance(heads, list) or not all(
        isinstance(head, str) and _valid_id(head) for head in heads
    ):
        return {}
    return _event_parent_closure(current_events, heads, relative, issues)


def _event_frontier(
    events: Mapping[str, Mapping[str, Any]],
    relative: str,
    issues: list[Issue],
) -> set[str]:
    parent_ids: set[str] = set()
    for event_id, event in events.items():
        parents = event.get("parents")
        if not isinstance(parents, list):
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_SET",
                    relative,
                    f"event {event_id!r} has an invalid parents list",
                )
            )
            continue
        for parent in parents:
            if not isinstance(parent, str) or parent not in events:
                issues.append(
                    Issue(
                        "CHECKPOINT_EVENT_SET",
                        relative,
                        f"event {event_id!r} refers to parent {parent!r} "
                        "outside its historical event set",
                    )
                )
                continue
            parent_ids.add(parent)
    return set(events) - parent_ids


def _load_active_task_currents(
    root: Path, issues: list[Issue]
) -> dict[str, tuple[Mapping[str, Any], str]]:
    index_path = root / "tasks" / "INDEX.json"
    relative = _relative(index_path, root)
    try:
        value = load_document(index_path)
    except (DataError, FileNotFoundError) as exc:
        issues.append(Issue("TASK_INDEX", relative, str(exc)))
        return {}
    if not isinstance(value, Mapping) or not isinstance(value.get("tasks"), list):
        issues.append(
            Issue("TASK_INDEX", relative, "tasks/INDEX.json must contain a tasks list")
        )
        return {}
    result: dict[str, tuple[Mapping[str, Any], str]] = {}
    for index, entry in enumerate(value["tasks"]):
        if not isinstance(entry, Mapping) or entry.get("status") != "active":
            continue
        task_id = entry.get("task_id")
        current_ref = entry.get("current")
        if not _valid_id(task_id):
            issues.append(
                Issue(
                    "TASK_INDEX",
                    relative,
                    f"tasks[{index}].task_id is invalid",
                )
            )
            continue
        if (
            not isinstance(current_ref, str)
            or "\\" in current_ref
            or current_ref.startswith("/")
            or ".." in Path(current_ref).parts
        ):
            issues.append(
                Issue(
                    "TASK_INDEX",
                    relative,
                    f"tasks[{index}].current must be a safe POSIX repository path",
                )
            )
            continue
        current_path = root / current_ref
        try:
            current = load_document(current_path)
        except (DataError, FileNotFoundError) as exc:
            issues.append(
                Issue("TASK_CURRENT", _relative(current_path, root), str(exc))
            )
            continue
        if not isinstance(current, Mapping):
            issues.append(
                Issue(
                    "TASK_CURRENT",
                    _relative(current_path, root),
                    "CURRENT must be a mapping",
                )
            )
            continue
        if current.get("task_id") != task_id:
            issues.append(
                Issue(
                    "TASK_CURRENT",
                    _relative(current_path, root),
                    "CURRENT task_id does not match tasks/INDEX.json",
                )
            )
        if task_id in result:
            issues.append(
                Issue("TASK_INDEX", relative, f"duplicate active task: {task_id}")
            )
        result[str(task_id)] = (current, _git_blob_sha(current_path))
    return result


def _git_show_document(
    root: Path,
    commit: str,
    repository_path: str,
    relative: str,
    issue_code: str,
    issues: list[Issue],
) -> Mapping[str, Any] | None:
    shown = subprocess.run(
        ["git", "-C", str(root), "show", f"{commit}:{repository_path}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if shown.returncode != 0:
        issues.append(
            Issue(
                issue_code,
                relative,
                shown.stderr.decode("utf-8", errors="replace").strip()
                or f"cannot read {repository_path} at basis commit {commit}",
            )
        )
        return None
    suffix = Path(repository_path).suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        issues.append(
            Issue(
                issue_code,
                relative,
                f"{repository_path} has an unsupported document extension "
                f"at basis commit {commit}",
            )
        )
        return None
    try:
        value = _load_document_bytes(shown.stdout, suffix)
    except DataError as exc:
        issues.append(
            Issue(
                issue_code,
                relative,
                f"{repository_path} is invalid at basis commit {commit}: {exc}",
            )
        )
        return None
    if not isinstance(value, Mapping):
        issues.append(
            Issue(
                issue_code,
                relative,
                f"{repository_path} must contain a mapping at basis commit {commit}",
            )
        )
        return None
    return value


def _load_active_task_currents_at_git_commit(
    root: Path,
    commit: str,
    relative: str,
    issues: list[Issue],
) -> dict[str, tuple[Mapping[str, Any], str]]:
    """Load the active task set and exact CURRENT blobs at a trusted commit."""

    index_path = "tasks/INDEX.json"
    value = _git_show_document(
        root,
        commit,
        index_path,
        relative,
        "CHECKPOINT_TASK_HISTORY",
        issues,
    )
    if value is None:
        return {}
    entries = value.get("tasks")
    if not isinstance(entries, list):
        issues.append(
            Issue(
                "CHECKPOINT_TASK_HISTORY",
                relative,
                f"{index_path} has no tasks list at basis commit {commit}",
            )
        )
        return {}

    result: dict[str, tuple[Mapping[str, Any], str]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or entry.get("status") != "active":
            continue
        task_id = entry.get("task_id")
        current_ref = entry.get("current")
        context = f"{index_path} tasks[{index}]"
        if not _valid_id(task_id):
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_HISTORY",
                    relative,
                    f"{context}.task_id is invalid at basis commit {commit}",
                )
            )
            continue
        if (
            not isinstance(current_ref, str)
            or "\\" in current_ref
            or current_ref.startswith("/")
            or ".." in Path(current_ref).parts
        ):
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_HISTORY",
                    relative,
                    f"{context}.current is not a safe POSIX repository path "
                    f"at basis commit {commit}",
                )
            )
            continue
        current = _git_show_document(
            root,
            commit,
            current_ref,
            relative,
            "CHECKPOINT_TASK_HISTORY",
            issues,
        )
        if current is None:
            continue
        if current.get("task_id") != task_id:
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_HISTORY",
                    relative,
                    f"{current_ref} task_id does not match {index_path} "
                    f"at basis commit {commit}",
                )
            )
        blob = subprocess.run(
            ["git", "-C", str(root), "rev-parse", f"{commit}:{current_ref}"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        blob_sha = blob.stdout.strip()
        if (
            blob.returncode != 0
            or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", blob_sha)
        ):
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_HISTORY",
                    relative,
                    blob.stderr.strip()
                    or f"cannot resolve the blob for {current_ref} "
                    f"at basis commit {commit}",
                )
            )
            continue
        if str(task_id) in result:
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_HISTORY",
                    relative,
                    f"duplicate active task {task_id!r} at basis commit {commit}",
                )
            )
        result[str(task_id)] = (current, blob_sha)
    return result


def _validate_checkpoint_summary(
    summary: Any,
    relative: str,
    task_snapshots: Mapping[str, str],
    event_ids: set[str],
    issues: list[Issue],
) -> None:
    required = {
        "current_goal",
        "completed",
        "next_actions",
        "active_constraint_event_ids",
        "unresolved_conflict_event_ids",
        "candidate_artifact_ids",
        "task_continuations",
        "known_gaps",
    }
    if not isinstance(summary, Mapping):
        issues.append(
            Issue("CHECKPOINT_FORMAT", relative, "summary must be a mapping")
        )
        return
    missing = sorted(required - set(summary))
    if missing:
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                f"summary missing fields: {', '.join(missing)}",
            )
        )
    _exact_keys(
        summary,
        required,
        issues,
        relative,
        "CHECKPOINT_FORMAT",
        "summary",
    )
    goal = summary.get("current_goal")
    if goal is not None and (not isinstance(goal, str) or not goal.strip()):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                "summary.current_goal must be null or non-empty text",
            )
        )
    for key in ("completed", "next_actions", "known_gaps"):
        values = summary.get(key)
        if not isinstance(values, list) or not all(
            isinstance(item, str) and bool(item.strip()) for item in values
        ):
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    f"summary.{key} must be a list of non-empty strings",
                )
            )
    for key in (
        "active_constraint_event_ids",
        "unresolved_conflict_event_ids",
    ):
        values = summary.get(key)
        if not isinstance(values, list) or not all(_valid_id(item) for item in values):
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    f"summary.{key} must be a list of event ids",
                )
            )
        elif any(item not in event_ids for item in values):
            issues.append(
                Issue(
                    "CHECKPOINT_EVENT_SET",
                    relative,
                    f"summary.{key} refers to an event outside the checkpoint set",
                )
            )
    candidates = summary.get("candidate_artifact_ids")
    if not isinstance(candidates, list) or not all(
        _valid_id(item) for item in candidates
    ):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                "summary.candidate_artifact_ids must be a list of portable ids",
            )
        )
    continuations = summary.get("task_continuations")
    continuation_map: dict[str, str] = {}
    if not isinstance(continuations, list):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                "summary.task_continuations must be a list",
            )
        )
    else:
        for index, item in enumerate(continuations):
            if not isinstance(item, Mapping) or set(item) != {
                "semantic_task_id",
                "snapshot_id",
            }:
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        f"summary.task_continuations[{index}] is invalid",
                    )
                )
                continue
            task_id = item.get("semantic_task_id")
            snapshot_id = item.get("snapshot_id")
            if not _valid_id(task_id) or not _valid_id(snapshot_id):
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        f"summary.task_continuations[{index}] ids are invalid",
                    )
                )
                continue
            if task_id in continuation_map:
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        f"duplicate task continuation: {task_id}",
                    )
                )
            continuation_map[str(task_id)] = str(snapshot_id)
    if continuation_map != dict(task_snapshots):
        issues.append(
            Issue(
                "CHECKPOINT_TASK_BASIS",
                relative,
                "summary.task_continuations must exactly match checkpoint task currents",
            )
        )


def validate_memory_checkpoints(
    root: Path,
    issues: list[Issue],
    allow_exported_fallback: bool = False,
) -> None:
    events = _load_event_records(root)
    current_active_tasks = _load_active_task_currents(root, issues)

    checkpoint_root = root / "memory" / "checkpoints"
    if not checkpoint_root.is_dir() or checkpoint_root.is_symlink():
        issues.append(
            Issue(
                "CHECKPOINT_MISSING",
                "memory/checkpoints",
                "memory/checkpoints must be a real directory",
            )
        )
        return
    checkpoint_paths = sorted(
        path
        for path in checkpoint_root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.suffix.lower() in {".json", ".yaml", ".yml"}
        and not path.name.lower().startswith(("readme", "template"))
    )
    checkpoint_ids: set[str] = set()
    for path in checkpoint_paths:
        relative = _relative(path, root)
        checkpoint_event_ids: set[str] = set()
        try:
            value = load_document(path)
        except DataError as exc:
            issues.append(Issue("CHECKPOINT_PARSE", relative, str(exc)))
            continue
        data = _required_mapping(
            value,
            CHECKPOINT_REQUIRED,
            issues,
            relative,
            "CHECKPOINT_FORMAT",
        )
        if data is None:
            continue
        _exact_keys(
            data,
            CHECKPOINT_REQUIRED,
            issues,
            relative,
            "CHECKPOINT_FORMAT",
            "checkpoint",
        )
        checkpoint_id = data.get("checkpoint_id")
        if not _valid_id(checkpoint_id) or path.stem != checkpoint_id:
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    "checkpoint_id must be portable and match its filename",
                )
            )
        elif checkpoint_id in checkpoint_ids:
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    f"duplicate checkpoint_id: {checkpoint_id}",
                )
            )
        else:
            checkpoint_ids.add(str(checkpoint_id))
        if data.get("schema_version") != "memory-checkpoint/v1":
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    "schema_version must equal 'memory-checkpoint/v1'",
                )
            )
        if data.get("authority") != "cache_only":
            issues.append(
                Issue(
                    "CHECKPOINT_AUTHORITY",
                    relative,
                    "checkpoint authority must be cache_only",
                )
            )
        scope = data.get("scope")
        if (
            not isinstance(scope, Mapping)
            or set(scope) != {"type", "id"}
            or scope.get("type") not in {"task", "vault"}
            or not _valid_id(scope.get("id"))
        ):
            issues.append(
                Issue("CHECKPOINT_FORMAT", relative, "scope is invalid")
            )

        basis = data.get("basis")
        task_snapshots: dict[str, str] = {}
        if not isinstance(basis, Mapping):
            issues.append(
                Issue("CHECKPOINT_FORMAT", relative, "basis must be a mapping")
            )
        else:
            basis_required = {
                "git_commit_sha",
                "task_currents",
                "event_heads",
                "event_set_sha256",
            }
            missing = sorted(basis_required - set(basis))
            if missing:
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        f"basis missing fields: {', '.join(missing)}",
                    )
                )
            _exact_keys(
                basis,
                basis_required,
                issues,
                relative,
                "CHECKPOINT_FORMAT",
                "basis",
            )
            basis_commit = basis.get("git_commit_sha")
            valid_basis_commit = isinstance(basis_commit, str) and bool(
                re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", basis_commit)
            )
            if not valid_basis_commit:
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        "basis.git_commit_sha must be a Git object hash",
                    )
                )
                basis_resolution = GitBasisResolution("invalid", "")
            else:
                basis_resolution = _resolve_checkpoint_git_basis(
                    root,
                    str(basis_commit),
                    relative,
                    issues,
                    allow_exported_fallback,
                )
            if basis_resolution.mode == "historical":
                checkpoint_active_tasks = (
                    _load_active_task_currents_at_git_commit(
                        root,
                        basis_resolution.commit,
                        relative,
                        issues,
                    )
                )
            elif basis_resolution.mode == "exported":
                checkpoint_active_tasks = current_active_tasks
            else:
                checkpoint_active_tasks = {}
            task_currents = basis.get("task_currents")
            if not isinstance(task_currents, list):
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        "basis.task_currents must be a list",
                    )
                )
            else:
                for index, item in enumerate(task_currents):
                    _validate_checkpoint_task_current(
                        item,
                        index,
                        relative,
                        checkpoint_active_tasks,
                        task_snapshots,
                        issues,
                    )
            if isinstance(scope, Mapping) and scope.get("type") == "vault":
                if set(task_snapshots) != set(checkpoint_active_tasks):
                    missing_tasks = sorted(
                        set(checkpoint_active_tasks) - set(task_snapshots)
                    )
                    extra_tasks = sorted(
                        set(task_snapshots) - set(checkpoint_active_tasks)
                    )
                    issues.append(
                        Issue(
                            "CHECKPOINT_TASK_BASIS",
                            relative,
                            "vault checkpoint task set must equal active tasks "
                            f"(missing={missing_tasks}, extra={extra_tasks})",
                        )
                    )
            elif isinstance(scope, Mapping) and scope.get("type") == "task":
                if set(task_snapshots) != {scope.get("id")}:
                    issues.append(
                        Issue(
                            "CHECKPOINT_TASK_BASIS",
                            relative,
                            "task checkpoint must contain exactly its scoped task",
                        )
                    )
            event_heads = basis.get("event_heads")
            if not isinstance(event_heads, list) or not all(
                _valid_id(item) for item in event_heads
            ):
                issues.append(
                    Issue(
                        "CHECKPOINT_FORMAT",
                        relative,
                        "basis.event_heads must be a list of event ids",
                    )
                )
                checkpoint_events: dict[str, Mapping[str, Any]] = {}
            else:
                checkpoint_events = _checkpoint_event_records(
                    root,
                    events,
                    basis,
                    basis_resolution,
                    relative,
                    issues,
                )
                checkpoint_event_ids = set(checkpoint_events)
                expected_event_heads = _event_frontier(
                    checkpoint_events, relative, issues
                )
                if set(event_heads) != expected_event_heads:
                    issues.append(
                        Issue(
                            "CHECKPOINT_EVENT_SET",
                            relative,
                            "basis.event_heads does not match the historical "
                            "event DAG frontier",
                        )
                    )
            event_pairs = [
                {
                    "memory_event_id": event_id,
                    "event_sha256": event.get("event_sha256"),
                }
                for event_id, event in sorted(checkpoint_events.items())
            ]
            expected_event_set_sha = sha256_jcs(event_pairs)
            event_set_sha = basis.get("event_set_sha256")
            if event_set_sha == "0" * 64 or event_set_sha != expected_event_set_sha:
                issues.append(
                    Issue(
                        "CHECKPOINT_EVENT_SET",
                        relative,
                        f"basis.event_set_sha256 mismatch; expected "
                        f"{expected_event_set_sha}",
                    )
                )

        _validate_checkpoint_summary(
            data.get("summary"),
            relative,
            task_snapshots,
            checkpoint_event_ids,
            issues,
        )
        if data.get("hash_profile") != "jcs-rfc8785+sha256/checkpoint-v1":
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    "checkpoint hash_profile is invalid",
                )
            )
        if not _valid_rfc3339(data.get("created_at")):
            issues.append(
                Issue(
                    "CHECKPOINT_FORMAT",
                    relative,
                    "created_at must be an RFC 3339 timestamp",
                )
            )
        checkpoint_hash = data.get("checkpoint_sha256")
        domain = dict(data)
        domain.pop("checkpoint_sha256", None)
        try:
            expected_hash = sha256_jcs(domain)
        except DataError as exc:
            issues.append(Issue("CHECKPOINT_JCS", relative, str(exc)))
        else:
            if (
                not isinstance(checkpoint_hash, str)
                or not SHA256_RE.fullmatch(checkpoint_hash)
                or checkpoint_hash == "0" * 64
                or checkpoint_hash != expected_hash
            ):
                issues.append(
                    Issue(
                        "CHECKPOINT_HASH",
                        relative,
                        f"checkpoint_sha256 mismatch; expected {expected_hash}",
                    )
                )
    _validate_memory_current(root, checkpoint_ids, issues)


def _validate_checkpoint_task_current(
    value: Any,
    index: int,
    relative: str,
    active_tasks: Mapping[str, tuple[Mapping[str, Any], str]],
    task_snapshots: dict[str, str],
    issues: list[Issue],
) -> None:
    required = {
        "semantic_task_id",
        "current_blob_sha",
        "task_generation",
        "snapshot_id",
        "transaction_id",
    }
    context = f"basis.task_currents[{index}]"
    if not isinstance(value, Mapping):
        issues.append(
            Issue("CHECKPOINT_FORMAT", relative, f"{context} must be a mapping")
        )
        return
    missing = sorted(required - set(value))
    if missing:
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                f"{context} missing fields: {', '.join(missing)}",
            )
        )
    _exact_keys(
        value,
        required,
        issues,
        relative,
        "CHECKPOINT_FORMAT",
        context,
    )
    task_id = value.get("semantic_task_id")
    if not _valid_id(task_id):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                f"{context}.semantic_task_id is invalid",
            )
        )
        return
    if task_id in task_snapshots:
        issues.append(
            Issue(
                "CHECKPOINT_TASK_BASIS",
                relative,
                f"duplicate task current: {task_id}",
            )
        )
    snapshot_id = value.get("snapshot_id")
    if not _valid_id(snapshot_id):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                f"{context}.snapshot_id is invalid",
            )
        )
    else:
        task_snapshots[str(task_id)] = str(snapshot_id)
    actual_record = active_tasks.get(str(task_id))
    if actual_record is None:
        issues.append(
            Issue(
                "CHECKPOINT_TASK_BASIS",
                relative,
                f"{context} is not an active task",
            )
        )
        return
    current, expected_blob = actual_record
    generation = value.get("task_generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 0
    ):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                f"{context}.task_generation is invalid",
            )
        )
    expected = {
        "task_generation": current.get("generation"),
        "snapshot_id": current.get("snapshot_id"),
        "transaction_id": current.get("published_transaction_id"),
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_BASIS",
                    relative,
                    f"{context}.{key} must equal CURRENT value {expected_value!r}",
                )
            )
    blob_sha = value.get("current_blob_sha")
    if not isinstance(blob_sha, str) or not re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", blob_sha
    ):
        issues.append(
            Issue(
                "CHECKPOINT_FORMAT",
                relative,
                f"{context}.current_blob_sha is invalid",
            )
        )
    else:
        if blob_sha != expected_blob:
            issues.append(
                Issue(
                    "CHECKPOINT_TASK_BASIS",
                    relative,
                    f"{context}.current_blob_sha mismatch; expected {expected_blob}",
                )
            )


def _validate_memory_current(
    root: Path, checkpoint_ids: set[str], issues: list[Issue]
) -> None:
    path = root / "memory" / "CURRENT.json"
    relative = _relative(path, root)
    try:
        value = load_document(path)
    except (DataError, FileNotFoundError) as exc:
        issues.append(Issue("MEMORY_CURRENT", relative, str(exc)))
        return
    if not isinstance(value, Mapping):
        issues.append(
            Issue("MEMORY_CURRENT", relative, "memory CURRENT must be a mapping")
        )
        return
    checkpoint_id = value.get("checkpoint_id")
    if checkpoint_id not in checkpoint_ids:
        issues.append(
            Issue(
                "MEMORY_CURRENT",
                relative,
                "checkpoint_id must identify an existing validated checkpoint",
            )
        )
    checkpoint_path = value.get("checkpoint_path")
    if (
        not isinstance(checkpoint_path, str)
        or "\\" in checkpoint_path
        or checkpoint_path.startswith("/")
        or ".." in Path(checkpoint_path).parts
        or not (root / checkpoint_path).is_file()
    ):
        issues.append(
            Issue(
                "MEMORY_CURRENT",
                relative,
                "checkpoint_path must be a safe existing POSIX repository path",
            )
        )
    elif Path(checkpoint_path).stem != checkpoint_id:
        issues.append(
            Issue(
                "MEMORY_CURRENT",
                relative,
                "checkpoint_path and checkpoint_id disagree",
            )
        )
    authority = value.get("authority")
    if (
        not isinstance(authority, Mapping)
        or authority.get("timestamps_are_authoritative") is not False
    ):
        issues.append(
            Issue(
                "MEMORY_CURRENT",
                relative,
                "timestamps must not be authoritative",
            )
        )


def validate_append_only_git(
    root: Path, compare_ref: str | None, issues: list[Issue]
) -> None:
    if not compare_ref:
        return
    try:
        exists = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-e", f"{compare_ref}^{{commit}}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        issues.append(Issue("GIT_CHECK", ".", f"cannot run git: {exc}"))
        return
    if exists.returncode != 0:
        issues.append(
            Issue(
                "GIT_CHECK",
                ".",
                f"comparison ref is not available locally: {compare_ref}",
            )
        )
        return
    process = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--name-status",
            "--find-renames",
            compare_ref,
            "HEAD",
            "--",
            "memory/episodes",
            "memory/events",
            "memory/checkpoints",
            ":(glob)tasks/*/versions/*",
            ":(glob)tasks/*/projections/*",
            ":(glob)sources/*/revisions/*",
            ":(glob)bindings/confirmed/*",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        issues.append(Issue("GIT_CHECK", ".", process.stderr.strip() or "git diff failed"))
        return
    for line in process.stdout.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0]
        paths = parts[1:] or ["memory/events"]
        if status != "A":
            if any(path.startswith("memory/episodes/") for path in paths):
                code = "EPISODE_APPEND_ONLY"
            elif any(path.startswith("memory/events/") for path in paths):
                code = "EVENT_APPEND_ONLY"
            elif any(path.startswith("memory/checkpoints/") for path in paths):
                code = "CHECKPOINT_APPEND_ONLY"
            elif any("/versions/" in path for path in paths):
                code = "TASK_VERSION_APPEND_ONLY"
            elif any("/projections/" in path for path in paths):
                code = "PROJECTION_APPEND_ONLY"
            elif any(path.startswith("bindings/confirmed/") for path in paths):
                code = "BINDING_APPEND_ONLY"
            else:
                code = "SOURCE_REVISION_APPEND_ONLY"
            issues.append(
                Issue(
                    code,
                    " -> ".join(paths),
                    "immutable evidence, versions, and projections are "
                    "append-only; "
                    f"Git status {status} is forbidden",
                )
            )

    source_diff = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--name-status",
            compare_ref,
            "HEAD",
            "--",
            ":(glob)sources/*/SOURCE.json",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if source_diff.returncode != 0:
        issues.append(
            Issue(
                "GIT_CHECK",
                ".",
                source_diff.stderr.strip() or "git source diff failed",
            )
        )
        return
    for line in source_diff.stdout.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        status = parts[0]
        paths = parts[1:]
        if status == "A":
            continue
        if status != "M" or len(paths) != 1:
            issues.append(
                Issue(
                    "SOURCE_APPEND_ONLY",
                    " -> ".join(paths) or "sources/*/SOURCE.json",
                    "source identities cannot be deleted or renamed",
                )
            )
            continue
        path_value = paths[0]
        old = _git_show_document(
            root,
            compare_ref,
            path_value,
            path_value,
            "SOURCE_APPEND_ONLY",
            issues,
        )
        new = _git_show_document(
            root,
            "HEAD",
            path_value,
            path_value,
            "SOURCE_APPEND_ONLY",
            issues,
        )
        if old is None or new is None:
            continue
        immutable_keys = set(old) - {"current_revision_id", "revisions"}
        if set(new) - {"current_revision_id", "revisions"} != immutable_keys or any(
            old.get(key) != new.get(key) for key in immutable_keys
        ):
            issues.append(
                Issue(
                    "SOURCE_APPEND_ONLY",
                    path_value,
                    "source identity metadata is immutable; only revision "
                    "append and current_revision_id advancement are allowed",
                )
            )
        old_revisions = old.get("revisions")
        new_revisions = new.get("revisions")
        if (
            not isinstance(old_revisions, list)
            or not isinstance(new_revisions, list)
            or len(new_revisions) < len(old_revisions)
            or new_revisions[: len(old_revisions)] != old_revisions
        ):
            issues.append(
                Issue(
                    "SOURCE_APPEND_ONLY",
                    path_value,
                    "existing source revisions must remain byte-for-byte "
                    "equivalent and new revisions may only be appended",
                )
            )
        elif new_revisions:
            last_revision = new_revisions[-1]
            if (
                not isinstance(last_revision, Mapping)
                or new.get("current_revision_id")
                != last_revision.get("revision_id")
            ):
                issues.append(
                    Issue(
                        "SOURCE_APPEND_ONLY",
                        path_value,
                        "current_revision_id must advance to the final appended "
                        "revision",
                    )
                )


def validate_repository(
    root: Path,
    compare_ref: str | None = None,
    *,
    allow_exported_checkpoint_fallback: bool = False,
) -> list[Issue]:
    root = root.resolve()
    issues: list[Issue] = []
    validate_filesystem(root, issues)
    validate_vault(root, issues)
    validate_legacy_baseline(root, issues)
    validate_schemas(root, issues)
    validate_drive_imports(root, issues)
    validate_sources(root, issues)
    validate_portable_identities(root, issues)
    validate_bindings(root, issues)
    validate_memory_episodes(root, issues)
    validate_memory_events(root, issues)
    validate_task_memory_projections(root, issues, compare_ref)
    validate_memory_checkpoints(
        root,
        issues,
        allow_exported_checkpoint_fallback,
    )
    validate_append_only_git(root, compare_ref, issues)
    return sorted(set(issues))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate immutable repository history, legacy migration records, "
            "and associative memory-network objects."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    parser.add_argument(
        "--compare-ref",
        help=(
            "Git commit/ref used to enforce append-only evidence, source "
            "revisions, task versions, and projections"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    issues = validate_repository(args.root, args.compare_ref)
    if issues:
        print(f"layout/v1 validation failed with {len(issues)} issue(s):")
        for issue in issues:
            print(f"- {issue.render()}")
        return 1
    print("layout/v1 validation passed (history and memory network).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
