"""Taskless selective subgraph selection and closure verification.

This module deliberately stops before cryptography.  It selects only immutable
episode/event evidence from an already verified portable network bundle, adds
the complete relation/evidence closure, and produces a deterministic private
share bundle.  ``crypto_adapter`` is the separate boundary where an audited
external provider must encrypt that bundle before it may leave the device.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import hashlib
import re
import stat
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from memory_vault_runtime.protocol import jcs_json_bytes, sha256_bytes, strict_json_loads


SELECTION_SCHEMA = "memory-share-selection/v1"
SHARE_SCHEMA = "memory-share-bundle/v1"
SHARE_NETWORK_CONTRACT = "memory-share-graph/v1"
MAX_SELECTOR_BYTES = 16 * 1024
MAX_SELECTOR_ITEMS = 64
MAX_SHARE_ENTRIES = 1_000_000
MAX_SHARE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_SHARE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SHARE_MANIFEST_BYTES = 8 * 1024 * 1024
_EPISODE_ID = re.compile(r"^ep-[0-9a-f]{40}$")
_EVENT_ID = re.compile(r"^evt-[0-9a-f]{40}$")
_CLAIM_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_FORBIDDEN_KEYS = {
    "task",
    "task_id",
    "task_ids",
    "conversation_id",
    "native_conversation_id",
    "native_conversation_ids",
    "device_id",
    "owner",
    "owner_id",
    "workspace_id",
    "current_pointer",
}


class ShareError(ValueError):
    """Selection, closure, privacy, or share-bundle verification failed."""


@dataclasses.dataclass(frozen=True)
class ShareSelector:
    """A bounded content-level selector with no ownership axis."""

    evidence_ids: tuple[str, ...] = ()
    claim_keys: tuple[str, ...] = ()
    concepts: tuple[str, ...] = ()
    captured_after: str | None = None
    captured_before: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "captured_after": self.captured_after,
            "captured_before": self.captured_before,
            "claim_keys": list(self.claim_keys),
            "concepts": list(self.concepts),
            "evidence_ids": list(self.evidence_ids),
            "schema_version": SELECTION_SCHEMA,
        }

    @property
    def sha256(self) -> str:
        return sha256_bytes(jcs_json_bytes(self.as_dict()))


@dataclasses.dataclass(frozen=True)
class ShareSummary:
    path: str
    object_count: int
    episode_count: int
    event_count: int
    raw_bytes: int
    sha256: str
    selector_sha256: str
    source_network_sha256: str


@dataclasses.dataclass(frozen=True)
class _VerifiedBundle:
    files: Mapping[str, bytes]
    manifest: Mapping[str, Any]
    network_sha256: str


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ShareError("share path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ShareError("share path is unsafe")
    if "\\" in value:
        raise ShareError("share path must use POSIX separators")
    return path.as_posix()


def _plain_file(path: Path, *, label: str) -> None:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise ShareError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or getattr(observed, "st_nlink", 1) != 1
    ):
        raise ShareError(f"{label} is not a private regular file")


def _rfc3339(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ShareError(f"{label} is invalid")
    try:
        parsed = _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ShareError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ShareError(f"{label} has no timezone")
    return value


def _bounded_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _bounded_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _bounded_strings(item)


def _assert_taskless_value(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_KEYS:
                raise ShareError(f"{label} contains a forbidden owner field")
            _assert_taskless_value(item, label)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_taskless_value(item, label)


def parse_selector(value: Any) -> ShareSelector:
    """Parse a strict selector and reject task/device/owner fields."""

    if isinstance(value, (bytes, bytearray)):
        if len(value) > MAX_SELECTOR_BYTES:
            raise ShareError("share selector is too large")
        try:
            value = strict_json_loads(bytes(value).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ShareError("share selector is invalid JSON") from exc
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "evidence_ids",
        "claim_keys",
        "concepts",
        "captured_after",
        "captured_before",
    }:
        raise ShareError("share selector fields are invalid")
    if value.get("schema_version") != SELECTION_SCHEMA:
        raise ShareError("share selector schema is invalid")

    def bounded_list(raw: Any, label: str) -> tuple[str, ...]:
        if not isinstance(raw, list) or len(raw) > MAX_SELECTOR_ITEMS:
            raise ShareError(f"share selector {label} is invalid")
        if any(not isinstance(item, str) or not item or len(item) > 256 for item in raw):
            raise ShareError(f"share selector {label} is invalid")
        if len(set(raw)) != len(raw):
            raise ShareError(f"share selector {label} is duplicated")
        return tuple(raw)

    evidence_ids = bounded_list(value.get("evidence_ids"), "evidence_ids")
    for item in evidence_ids:
        if not (_EPISODE_ID.fullmatch(item) or _EVENT_ID.fullmatch(item)):
            raise ShareError("share selector evidence identity is invalid")
    claim_keys = bounded_list(value.get("claim_keys"), "claim_keys")
    if any(_CLAIM_KEY.fullmatch(item) is None for item in claim_keys):
        raise ShareError("share selector claim key is invalid")
    concepts = bounded_list(value.get("concepts"), "concepts")
    if any("\x00" in item or "\n" in item or "\r" in item for item in concepts):
        raise ShareError("share selector concept is invalid")
    concepts = tuple(item.casefold() for item in concepts)
    captured_after = value.get("captured_after")
    captured_before = value.get("captured_before")
    if captured_after is not None:
        captured_after = _rfc3339(captured_after, "share selector captured_after")
    if captured_before is not None:
        captured_before = _rfc3339(captured_before, "share selector captured_before")
    if captured_after and captured_before:
        if _datetime.datetime.fromisoformat(captured_after.replace("Z", "+00:00")) > _datetime.datetime.fromisoformat(captured_before.replace("Z", "+00:00")):
            raise ShareError("share selector time range is inverted")
    if not (evidence_ids or claim_keys or concepts or captured_after or captured_before):
        raise ShareError("share selector must specify content-level scope")
    return ShareSelector(
        evidence_ids=evidence_ids,
        claim_keys=claim_keys,
        concepts=concepts,
        captured_after=captured_after,
        captured_before=captured_before,
    )


def _read_json(raw: bytes, label: str) -> Mapping[str, Any]:
    if len(raw) > MAX_SHARE_MEMBER_BYTES:
        raise ShareError(f"{label} is too large")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ShareError(f"{label} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise ShareError(f"{label} is not an object")
    return value


def _verified_zip(path: Path, *, share: bool = False) -> _VerifiedBundle:
    _plain_file(path, label="share bundle")
    if path.stat().st_size > MAX_SHARE_TOTAL_BYTES:
        raise ShareError("share bundle is too large")
    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ShareError("share bundle is not a valid archive") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_SHARE_ENTRIES + 1:
            raise ShareError("share bundle entry count is invalid")
        files: dict[str, bytes] = {}
        total = 0
        for info in infos:
            name = _safe_path(info.filename)
            if name in files or info.is_dir():
                raise ShareError("share bundle entry is invalid")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ShareError("share bundle contains a symlink")
            limit = MAX_SHARE_MANIFEST_BYTES if name == "MANIFEST.json" else MAX_SHARE_MEMBER_BYTES
            if info.file_size < 0 or info.file_size > limit:
                raise ShareError("share bundle member is too large")
            if info.compress_size > 0 and info.file_size > info.compress_size * 250:
                raise ShareError("share bundle compression ratio is unsafe")
            raw = archive.read(info)
            if len(raw) != info.file_size:
                raise ShareError("share bundle member size is invalid")
            files[name] = raw
            total += len(raw)
            if total > MAX_SHARE_TOTAL_BYTES:
                raise ShareError("share bundle expands too large")
    if "MANIFEST.json" not in files:
        raise ShareError("share bundle manifest is missing")
    manifest = _read_json(files["MANIFEST.json"], "share bundle manifest")
    if share:
        expected_fields = {
            "schema_version",
            "network_contract",
            "selector_sha256",
            "source_network_sha256",
            "native_conversation_ids_included",
            "credentials_included",
            "task_fields_included",
            "episode_count",
            "event_count",
            "entries",
            "share_sha256",
        }
        if set(manifest) != expected_fields:
            raise ShareError("share manifest fields are invalid")
        if (
            manifest.get("schema_version") != SHARE_SCHEMA
            or manifest.get("network_contract") != SHARE_NETWORK_CONTRACT
            or manifest.get("native_conversation_ids_included") is not False
            or manifest.get("credentials_included") is not False
            or manifest.get("task_fields_included") is not False
        ):
            raise ShareError("share manifest privacy profile is invalid")
        for key in ("selector_sha256", "source_network_sha256", "share_sha256"):
            value = manifest.get(key)
            if not isinstance(value, str) or len(value) != 64 or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ShareError("share manifest hash is invalid")
        domain = dict(manifest)
        observed = domain.pop("share_sha256")
        if observed != sha256_bytes(jcs_json_bytes(domain)):
            raise ShareError("share manifest hash is invalid")
        entries = manifest.get("entries")
        if not isinstance(entries, list) or len(entries) != len(files) - 1:
            raise ShareError("share manifest entries are invalid")
        expected_names: set[str] = set()
        previous: str | None = None
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size"}:
                raise ShareError("share manifest entry is invalid")
            entry_path = _safe_path(entry.get("path"))
            if entry_path == "MANIFEST.json" or (previous is not None and entry_path <= previous):
                raise ShareError("share manifest entry order is invalid")
            previous = entry_path
            raw_hash = entry.get("sha256")
            if not isinstance(raw_hash, str) or len(raw_hash) != 64 or re.fullmatch(r"[0-9a-f]{64}", raw_hash) is None:
                raise ShareError("share manifest entry hash is invalid")
            size = entry.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_SHARE_MEMBER_BYTES:
                raise ShareError("share manifest entry size is invalid")
            if entry_path not in files or len(files[entry_path]) != size or sha256_bytes(files[entry_path]) != raw_hash:
                raise ShareError("share manifest entry bytes do not match")
            expected_names.add(entry_path)
        if expected_names != set(files) - {"MANIFEST.json"}:
            raise ShareError("share manifest entry closure is invalid")
    else:
        expected_fields = {
            "schema_version",
            "network_contract",
            "remote_commit_sha",
            "exported_at",
            "native_conversation_ids_included",
            "credentials_included",
            "entries",
            "network_sha256",
        }
        if set(manifest) != expected_fields or manifest.get("schema_version") != "memory-network-bundle/v1":
            raise ShareError("network bundle manifest is invalid")
        if manifest.get("network_contract") not in {"memory-network-graph/v1", "memory-network-index/v1"}:
            raise ShareError("network bundle contract is invalid")
        if manifest.get("native_conversation_ids_included") is not False or manifest.get("credentials_included") is not False:
            raise ShareError("network bundle privacy profile is invalid")
        domain = dict(manifest)
        observed = domain.pop("network_sha256")
        if not isinstance(observed, str) or len(observed) != 64 or observed != sha256_bytes(jcs_json_bytes(domain)):
            raise ShareError("network bundle hash is invalid")
        entries = manifest.get("entries")
        if not isinstance(entries, list) or len(entries) != len(files) - 1:
            raise ShareError("network bundle entries are invalid")
        expected_names: set[str] = set()
        previous = None
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size"}:
                raise ShareError("network bundle entry is invalid")
            entry_path = _safe_path(entry.get("path"))
            if entry_path == "MANIFEST.json" or (previous is not None and entry_path <= previous):
                raise ShareError("network bundle entry order is invalid")
            previous = entry_path
            raw_hash = entry.get("sha256")
            size = entry.get("size")
            if not isinstance(raw_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", raw_hash) or isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_SHARE_MEMBER_BYTES:
                raise ShareError("network bundle entry identity is invalid")
            if entry_path not in files or len(files[entry_path]) != size or sha256_bytes(files[entry_path]) != raw_hash:
                raise ShareError("network bundle entry bytes do not match")
            expected_names.add(entry_path)
        if expected_names != set(files) - {"MANIFEST.json"}:
            raise ShareError("network bundle entry closure is invalid")
    return _VerifiedBundle(files=files, manifest=manifest, network_sha256=str(manifest.get("network_sha256") or manifest.get("share_sha256")))


def _json_documents(bundle: _VerifiedBundle) -> tuple[dict[str, tuple[str, Mapping[str, Any]]], dict[str, tuple[str, Mapping[str, Any]]]]:
    episodes: dict[str, tuple[str, Mapping[str, Any]]] = {}
    events: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for path, raw in bundle.files.items():
        if path == "MANIFEST.json":
            continue
        if path.startswith("memory/episodes/"):
            value = _read_json(raw, "episode")
            _assert_taskless_value(value, "episode")
            episode_id = value.get("episode_id")
            if not isinstance(episode_id, str) or _EPISODE_ID.fullmatch(episode_id) is None or episode_id in episodes:
                raise ShareError("episode identity is invalid")
            episodes[episode_id] = (path, value)
        elif path.startswith("memory/events/"):
            value = _read_json(raw, "event")
            if value.get("schema_version") != "memory-event/v2":
                continue
            event_id = value.get("memory_event_id")
            _assert_taskless_value(value, "event")
            if not isinstance(event_id, str) or _EVENT_ID.fullmatch(event_id) is None or event_id in events:
                raise ShareError("event identity is invalid")
            events[event_id] = (path, value)
    return episodes, events


def _document_text(value: Mapping[str, Any]) -> str:
    return "\n".join(_bounded_strings(value)).casefold()


def _document_time(value: Mapping[str, Any]) -> str:
    raw = value.get("captured_at") or value.get("created_at")
    return _rfc3339(raw, "memory evidence time")


def _matches(selector: ShareSelector, episode_id: str, episode: Mapping[str, Any], event_id: str | None, event: Mapping[str, Any] | None) -> bool:
    observed = _document_time(event or episode)
    if selector.captured_after and observed < selector.captured_after:
        return False
    if selector.captured_before and observed > selector.captured_before:
        return False
    if episode_id in selector.evidence_ids or (event_id is not None and event_id in selector.evidence_ids):
        return True
    if event is not None and event.get("claim_key") in selector.claim_keys:
        return True
    text = (_document_text(episode) + "\n" + (_document_text(event) if event is not None else ""))
    if selector.concepts and any(concept in text for concept in selector.concepts):
        return True
    return bool(selector.captured_after or selector.captured_before)


def _write_zip(path: Path, files: Mapping[str, bytes]) -> None:
    if path.exists() or path.is_symlink():
        raise ShareError("share output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o600 << 16)
            archive.writestr(info, files[name])
    with contextlib_suppress_oserror():
        path.chmod(0o600)


class contextlib_suppress_oserror:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        return exc_type is OSError


def select_subgraph(source_bundle: Path, output_bundle: Path, selector: ShareSelector | Mapping[str, Any] | bytes) -> ShareSummary:
    """Select taskless evidence and write a deterministic closed share bundle."""

    parsed = selector if isinstance(selector, ShareSelector) else parse_selector(selector)
    source = Path(source_bundle).expanduser()
    output = Path(output_bundle).expanduser()
    network = _verified_zip(source, share=False)
    episodes, events = _json_documents(network)
    events_by_episode: dict[str, set[str]] = defaultdict(set)
    for event_id, (_, event) in events.items():
        source_value = event.get("source")
        if not isinstance(source_value, Mapping) or not isinstance(source_value.get("revision_id"), str):
            raise ShareError("event evidence source is invalid")
        revision_id = str(source_value["revision_id"])
        if revision_id not in episodes:
            raise ShareError("event evidence episode is missing")
        events_by_episode[revision_id].add(event_id)

    selected_episodes: set[str] = set()
    selected_events: set[str] = set()
    for episode_id, (_, episode) in episodes.items():
        attached = sorted(events_by_episode.get(episode_id, ()))
        if _matches(parsed, episode_id, episode, None, None):
            selected_episodes.add(episode_id)
        for event_id in attached:
            if _matches(parsed, episode_id, episode, event_id, events[event_id][1]):
                selected_events.add(event_id)
    if not selected_episodes and not selected_events:
        raise ShareError("share selector matched no immutable evidence")
    selected_episodes.update(
        str(events[event_id][1]["source"]["revision_id"]) for event_id in selected_events
    )
    # Selecting an episode carries every event anchored to that episode; this
    # includes continuity evidence and all semantic edges needed to explain it.
    for episode_id in tuple(selected_episodes):
        selected_events.update(events_by_episode.get(episode_id, ()))

    changed = True
    while changed:
        changed = False
        for event_id in tuple(selected_events):
            event = events[event_id][1]
            for relation in ("parents", "supersedes", "conflicts_with", "resolves"):
                targets = event.get(relation)
                if not isinstance(targets, list):
                    raise ShareError("event relation list is invalid")
                for target in targets:
                    if target not in events:
                        raise ShareError("selected relation closure is missing")
                    if target not in selected_events:
                        selected_events.add(target)
                        changed = True
                    revision_id = str(events[target][1]["source"]["revision_id"])
                    if revision_id not in selected_episodes:
                        selected_episodes.add(revision_id)
                        changed = True
        for episode_id in tuple(selected_episodes):
            before = len(selected_events)
            selected_events.update(events_by_episode.get(episode_id, ()))
            changed = changed or len(selected_events) != before

    selected_paths = {episodes[episode_id][0] for episode_id in selected_episodes}
    selected_paths.update(events[event_id][0] for event_id in selected_events)
    raw_files = {path: network.files[path] for path in sorted(selected_paths)}
    entries = [
        {"path": path, "sha256": sha256_bytes(raw_files[path]), "size": len(raw_files[path])}
        for path in sorted(raw_files)
    ]
    domain: dict[str, Any] = {
        "credentials_included": False,
        "entries": entries,
        "episode_count": len(selected_episodes),
        "event_count": len(selected_events),
        "native_conversation_ids_included": False,
        "network_contract": SHARE_NETWORK_CONTRACT,
        "schema_version": SHARE_SCHEMA,
        "selector_sha256": parsed.sha256,
        "source_network_sha256": network.network_sha256,
        "task_fields_included": False,
    }
    manifest = {**domain, "share_sha256": sha256_bytes(jcs_json_bytes(domain))}
    files = {"MANIFEST.json": jcs_json_bytes(manifest), **raw_files}
    _write_zip(output, files)
    verified = verify_share_bundle(output)
    return verified


def verify_share_bundle(path: Path) -> ShareSummary:
    """Verify share privacy and complete relation/evidence closure."""

    bundle = _verified_zip(Path(path).expanduser(), share=True)
    for member_path, raw in bundle.files.items():
        if member_path.startswith("memory/events/"):
            event = _read_json(raw, "share event")
            if event.get("schema_version") != "memory-event/v2":
                raise ShareError("share bundle contains a legacy event")
    episodes, events = _json_documents(bundle)
    if not episodes or not events:
        raise ShareError("share bundle has no taskless evidence")
    event_ids = set(events)
    for event_id, (_, event) in events.items():
        source_value = event.get("source")
        if not isinstance(source_value, Mapping) or source_value.get("revision_id") not in episodes:
            raise ShareError("share event evidence closure is incomplete")
        for relation in ("parents", "supersedes", "conflicts_with", "resolves"):
            targets = event.get(relation)
            if not isinstance(targets, list) or any(target not in event_ids for target in targets):
                raise ShareError("share relation closure is incomplete")
    if bundle.manifest.get("episode_count") != len(episodes) or bundle.manifest.get("event_count") != len(events):
        raise ShareError("share manifest counts are invalid")
    raw_bytes = sum(len(raw) for path, raw in bundle.files.items() if path != "MANIFEST.json")
    return ShareSummary(
        path=str(Path(path).expanduser()),
        object_count=len(episodes) + len(events),
        episode_count=len(episodes),
        event_count=len(events),
        raw_bytes=raw_bytes,
        sha256=sha256_bytes(Path(path).read_bytes()),
        selector_sha256=str(bundle.manifest["selector_sha256"]),
        source_network_sha256=str(bundle.manifest["source_network_sha256"]),
    )
