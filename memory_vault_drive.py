#!/usr/bin/env python3
"""Explicit-root Google Drive v3 objects, independent of Git, tasks and rclone.

One client is a sequential, deadline-bounded operation context. Credentials are
read only from an explicitly selected OS item; neither credentials nor API
bodies are written to disk or included in errors. This module does not enroll
an account, create a cloud project/root, follow shortcuts, overwrite an object,
or decide which memory should be published. Callers own publication permission,
durable journals, final content hashes and recovery after ambiguous writes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import math
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
from typing import Any, Callable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_credentials import MAX_PASSWORD_BYTES, config_password, password_reference
import memory_vault_storage as protected_storage

CONFIG_SCHEMA = "memory-vault-drive-config/v1"
API_ROOT = "https://www.googleapis.com/drive/v3"
UPLOAD_ROOT = "https://www.googleapis.com/upload/drive/v3"
TOKEN_URL = "https://oauth2.googleapis.com/token"
FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"
MAX_CONFIG_BYTES = 32 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_LIST_BYTES = 1024 * 1024
MAX_CHUNK_BYTES = 4 * 1024 * 1024
MAX_UPLOAD_BYTES = MAX_CHUNK_BYTES + 16 * 1024
MAX_ERROR_BYTES = 16 * 1024
MAX_REQUESTS = 256
MAX_ANCESTORS = 32
MAX_FOLDER_CACHE = 2048
FOLDER_CACHE_SECONDS = 30
_ID = re.compile(r"[A-Za-z0-9_-]{2,256}")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")
_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_MIME = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+")
_RANGE = re.compile(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)")
_FIELDS = "id,name,mimeType,size,parents,trashed,version,modifiedTime,sha256Checksum,md5Checksum,capabilities(canDownload)"


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None or value == "root":
        raise MemoryError("drive_invalid_file_id")
    return value


def _text(value: Any, *, maximum: int, empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not empty) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise MemoryError("drive_invalid_text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise MemoryError("drive_invalid_text") from None
    if size > maximum:
        raise MemoryError("drive_invalid_text")
    return value


def _number(value: Any) -> int:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None or int(value) >= 2**63:
        raise MemoryError("drive_invalid_metadata")
    return int(value)


@dataclass(frozen=True)
class DriveConfig:
    root_folder_id: str
    oauth_client_id: str
    credential_ref: Mapping[str, Any]

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> DriveConfig:
        if (not isinstance(value, dict)
                or set(value) != {"schema_version", "root_folder_id", "oauth_client_id", "credential_ref"}
                or value["schema_version"] != CONFIG_SCHEMA):
            raise MemoryError("drive_invalid_configuration")
        client = _text(value["oauth_client_id"], maximum=512)
        if re.fullmatch(r"[A-Za-z0-9._-]+", client) is None:
            raise MemoryError("drive_invalid_oauth_client_id")
        try:
            reference = password_reference(value["credential_ref"])
        except MemoryError:
            raise MemoryError("drive_invalid_credential_reference") from None
        return cls(_identifier(value["root_folder_id"]), client, reference)

    @classmethod
    def from_file(cls, path: Path) -> DriveConfig:
        """Read only the explicit protected file; no default-path discovery."""
        try:
            descriptor = protected_storage.open_file(path, os.O_RDONLY, private=True, trusted=True)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if before.st_size > MAX_CONFIG_BYTES:
                    raise MemoryError("drive_configuration_too_large")
                raw = stream.read(MAX_CONFIG_BYTES + 1)
                after = os.fstat(stream.fileno())
            if len(raw) > MAX_CONFIG_BYTES:
                raise MemoryError("drive_configuration_too_large")
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise MemoryError("drive_configuration_changed", retryable=True)
            return cls.from_document(strict_json_loads(raw))
        except protected_storage.StorageError as exc:
            raise MemoryError("drive_unprotected_configuration", retryable=exc.retryable) from None
        except (OSError, UnicodeError):
            raise MemoryError("drive_configuration_unavailable") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # No OAuth body or bearer header can be forwarded through a redirect.
        return None


class _HTTPStatus(Exception):
    def __init__(self, status: int, reason: str | None = None):
        self.status, self.reason = status, reason
        super().__init__("drive_http_status")


def _metadata(value: Any, *, expected_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MemoryError("drive_invalid_metadata")
    identifier = _identifier(value.get("id"))
    if expected_id is not None and identifier != expected_id:
        raise MemoryError("drive_object_identity_mismatch")
    name = _text(value.get("name"), maximum=1024, empty=True)
    mime = _text(value.get("mimeType"), maximum=255)
    if _MIME.fullmatch(mime) is None:
        raise MemoryError("drive_invalid_metadata")
    parents = value.get("parents", [])
    # Drive v3 exposes one parent per item. A multi-parent graph would need a
    # different, explicitly reviewed scope policy; never guess one safe parent.
    if not isinstance(parents, list) or len(parents) > 1:
        raise MemoryError("drive_invalid_metadata")
    parents = [_identifier(parent) for parent in parents]
    trashed = value.get("trashed", False)
    if type(trashed) is not bool:
        raise MemoryError("drive_invalid_metadata")
    result: dict[str, Any] = {"id": identifier, "name": name, "mimeType": mime,
                              "parents": parents, "trashed": trashed}
    for key in ("size", "version"):
        if key in value:
            _number(value[key])
            result[key] = value[key]
    if "modifiedTime" in value:
        result["modifiedTime"] = _text(value["modifiedTime"], maximum=64)
    for key, length in (("sha256Checksum", 64), ("md5Checksum", 32)):
        if key in value:
            checksum = value[key]
            if not isinstance(checksum, str) or re.fullmatch("[0-9a-fA-F]{" + str(length) + "}", checksum) is None:
                raise MemoryError("drive_invalid_metadata")
            result[key] = checksum.lower()
    capabilities = value.get("capabilities")
    if capabilities is not None:
        if not isinstance(capabilities, dict):
            raise MemoryError("drive_invalid_metadata")
        if "canDownload" in capabilities:
            if type(capabilities["canDownload"]) is not bool:
                raise MemoryError("drive_invalid_metadata")
            result["capabilities"] = {"canDownload": capabilities["canDownload"]}
    return result


def _live(value: Mapping[str, Any], *, folder: bool = False) -> None:
    if value["trashed"]:
        raise MemoryError("drive_object_trashed")
    if value["mimeType"] == SHORTCUT_MIME:
        raise MemoryError("drive_shortcuts_not_supported")
    if folder and value["mimeType"] != FOLDER_MIME:
        raise MemoryError("drive_folder_required")


class DriveClient:
    """Real bounded HTTP operations under one explicit, previously chosen root."""

    def __init__(self, config: DriveConfig, *, deadline: float,
                 active_check: Callable[[], None] = lambda: None):
        if not isinstance(config, DriveConfig):
            raise MemoryError("drive_invalid_configuration")
        self.config = DriveConfig.from_document({"schema_version": CONFIG_SCHEMA,
            "root_folder_id": config.root_folder_id, "oauth_client_id": config.oauth_client_id,
            "credential_ref": dict(config.credential_ref)})
        if not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not math.isfinite(deadline):
            raise MemoryError("drive_invalid_deadline")
        if not callable(active_check):
            raise MemoryError("drive_invalid_active_check")
        self.deadline = float(deadline)
        self.active_check = active_check
        self._token: str | None = None
        self._token_expiry = 0.0
        self._opener = None
        self._requests = 0
        self._folders: dict[str, tuple[float, dict[str, Any]]] = {}
        self._remaining()

    def _remaining(self) -> float:
        self.active_check()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise MemoryError("drive_deadline_exceeded", retryable=True)
        return remaining

    def _read_response(self, response, maximum: int) -> tuple[dict[str, str], bytes]:
        pairs = list(response.headers.items())
        if len(pairs) > 100 or sum(len(key) + len(value) for key, value in pairs) > 32 * 1024:
            raise MemoryError("drive_response_headers_too_large")
        headers: dict[str, str] = {}
        for key, value in pairs:
            key = key.lower()
            if key in headers and key in {"content-length", "content-range", "content-encoding"}:
                raise MemoryError("drive_invalid_response_headers")
            headers[key] = value
        if headers.get("content-encoding", "identity").lower() not in {"identity", ""}:
            raise MemoryError("drive_unexpected_content_encoding")
        length = headers.get("content-length")
        if length is not None and (not length.isascii() or not length.isdecimal() or len(length) > 20):
            raise MemoryError("drive_invalid_response_headers")
        if length is not None and int(length) > maximum:
            raise MemoryError("drive_response_too_large")
        output = bytearray()
        while True:
            remaining = self._remaining()
            # urllib's HTTPResponse exposes its connected socket through this
            # stdlib stream chain. Rebound each read to the remaining deadline.
            raw = getattr(getattr(response, "fp", None), "raw", None)
            connection = getattr(raw, "_sock", None)
            if connection is not None:
                connection.settimeout(min(15.0, remaining))
            data = response.read(min(64 * 1024, maximum + 1 - len(output)))
            if not data:
                break
            output.extend(data)
            if len(output) > maximum:
                raise MemoryError("drive_response_too_large")
        self._remaining()
        if length is not None and len(output) != int(length):
            raise MemoryError("drive_response_length_mismatch", retryable=True)
        return headers, bytes(output)

    def _wire(self, url: str, *, method: str, body: bytes | None, headers: Mapping[str, str],
              maximum: int) -> tuple[int, dict[str, str], bytes]:
        parsed = urllib.parse.urlsplit(url)
        api = (parsed.scheme == "https" and parsed.netloc == "www.googleapis.com"
               and (parsed.path == "/drive/v3/files" or parsed.path.startswith("/drive/v3/files/")
                    or parsed.path == "/upload/drive/v3/files"))
        if parsed.fragment or not (api or url == TOKEN_URL):
            raise MemoryError("drive_endpoint_forbidden")
        if method not in {"GET", "POST"} or (body is not None and (not isinstance(body, bytes) or len(body) > MAX_UPLOAD_BYTES)):
            raise MemoryError("drive_invalid_request")
        if type(maximum) is not int or not 0 <= maximum <= MAX_CHUNK_BYTES:
            raise MemoryError("drive_invalid_response_limit")
        self._requests += 1
        if self._requests > MAX_REQUESTS:
            raise MemoryError("drive_request_budget_exceeded", retryable=True)
        request_headers = {"Accept-Encoding": "identity", "User-Agent": "memory-vault-drive/1", **headers}
        if body is not None:
            request_headers["Content-Length"] = str(len(body))
        if self._opener is None:
            # Standard configured HTTPS proxy routing survives. No netrc,
            # browser cookie, account discovery or custom redirect handler.
            self._opener = urllib.request.build_opener(_NoRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request(url, data=body, method=method, headers=request_headers)
        try:
            with self._opener.open(request, timeout=min(15.0, self._remaining())) as response:
                status = response.status
                observed, raw = self._read_response(response, maximum)
                return status, observed, raw
        except urllib.error.HTTPError as exc:
            status = exc.code
            reason = None
            try:
                # Decode only a few known error reason labels, never return or
                # print arbitrary provider messages, URLs, account or file data.
                if status == 403:
                    _, raw = self._read_response(exc, MAX_ERROR_BYTES)
                    payload = strict_json_loads(raw)
                    errors = payload.get("error", {}).get("errors", []) if isinstance(payload, dict) else []
                    if isinstance(errors, list) and len(errors) <= 16:
                        for item in errors:
                            candidate = item.get("reason") if isinstance(item, dict) else None
                            if candidate in {"rateLimitExceeded", "userRateLimitExceeded", "downloadQuotaExceeded"}:
                                reason = "rate_limited"
                                break
            except MemoryError as parse_error:
                # Cancellation/deadline errors are control flow, not malformed
                # provider JSON. Do not hide them behind a permission error.
                if parse_error.code not in {"drive_response_too_large", "drive_response_headers_too_large",
                        "drive_invalid_response_headers", "drive_unexpected_content_encoding",
                        "drive_response_length_mismatch", "invalid_json", "json_bom_forbidden",
                        "duplicate_json_key", "non_finite_json_number", "json_too_deep"}:
                    raise
            except (AttributeError, TypeError, ValueError, OSError, http.client.HTTPException):
                pass
            finally:
                exc.close()
            raise _HTTPStatus(status, reason) from None
        except (urllib.error.URLError, socket.timeout, TimeoutError, OSError, http.client.HTTPException):
            raise MemoryError("drive_network_unavailable", retryable=True) from None

    @staticmethod
    def _status_error(error: _HTTPStatus, *, oauth: bool = False) -> MemoryError:
        status = error.status
        if 300 <= status < 400:
            return MemoryError("drive_redirect_forbidden")
        if status == 429 or error.reason == "rate_limited":
            return MemoryError("drive_rate_limited", retryable=True)
        if 500 <= status <= 599:
            return MemoryError("drive_service_unavailable", retryable=True)
        if oauth and status in {400, 401, 403}:
            return MemoryError("drive_oauth_reauthorization_required")
        codes = {400: "drive_request_rejected", 401: "drive_authorization_failed", 403: "drive_permission_denied",
                 404: "drive_object_not_found", 409: "drive_object_conflict", 412: "drive_object_changed",
                 416: "drive_range_not_satisfiable"}
        return MemoryError(codes.get(status, "drive_http_failure"))

    def _refresh(self) -> str:
        try:
            text = config_password(self.config.credential_ref,
                deadline=min(self.deadline, time.monotonic() + 10), active_check=self.active_check)
        except MemoryError as exc:
            raise MemoryError("drive_credential_unavailable", retryable=exc.retryable) from None
        try:
            if len(text.encode("utf-8")) > MAX_PASSWORD_BYTES:
                raise MemoryError("drive_invalid_credential")
            credential = strict_json_loads(text)
            if (not isinstance(credential, dict) or "refresh_token" not in credential
                    or set(credential) - {"refresh_token", "client_secret"}):
                raise MemoryError("drive_invalid_credential")
            refresh = _text(credential["refresh_token"], maximum=8192)
            secret = credential.get("client_secret")
            if secret is not None:
                secret = _text(secret, maximum=4096, empty=True)
            form = {"client_id": self.config.oauth_client_id, "refresh_token": refresh, "grant_type": "refresh_token"}
            if secret:
                form["client_secret"] = secret
            body = urllib.parse.urlencode(form).encode("ascii")
        except (MemoryError, UnicodeError):
            raise MemoryError("drive_invalid_credential") from None
        finally:
            text = None
        try:
            status, _, raw = self._wire(TOKEN_URL, method="POST", body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"}, maximum=MAX_METADATA_BYTES)
        except _HTTPStatus as exc:
            raise self._status_error(exc, oauth=True) from None
        if status != 200:
            raise MemoryError("drive_invalid_oauth_response")
        try:
            payload = strict_json_loads(raw)
            token = payload.get("access_token") if isinstance(payload, dict) else None
            expiry = payload.get("expires_in") if isinstance(payload, dict) else None
            kind = payload.get("token_type") if isinstance(payload, dict) else None
            if (not isinstance(token, str) or len(token) > 8192 or _TOKEN.fullmatch(token) is None
                    or type(expiry) is not int or not 1 <= expiry <= 86400
                    or not isinstance(kind, str) or kind.lower() != "bearer"):
                raise MemoryError("drive_invalid_oauth_response")
        except MemoryError:
            raise MemoryError("drive_invalid_oauth_response") from None
        self._token = token
        self._token_expiry = time.monotonic() + expiry - min(60, expiry / 10)
        return token

    def _api(self, url: str, *, method: str = "GET", body: bytes | None = None,
             headers: Mapping[str, str] | None = None, maximum: int = MAX_METADATA_BYTES,
             statuses: tuple[int, ...] = (200,)) -> tuple[int, dict[str, str], bytes]:
        for attempt in range(2):
            self._remaining()
            token = self._token if self._token and time.monotonic() < self._token_expiry else self._refresh()
            try:
                result = self._wire(url, method=method, body=body,
                    headers={**(headers or {}), "Authorization": "Bearer " + token}, maximum=maximum)
            except _HTTPStatus as exc:
                if exc.status == 401 and attempt == 0:
                    self._token = None
                    self._token_expiry = 0
                    continue  # one refresh/retry for an explicit 401 only
                raise self._status_error(exc) from None
            if result[0] not in statuses:
                raise MemoryError("drive_unexpected_response_status")
            return result
        raise MemoryError("drive_authorization_failed")

    def _get_metadata(self, file_id: str) -> dict[str, Any]:
        url = API_ROOT + "/files/" + _identifier(file_id) + "?" + urllib.parse.urlencode({"fields": _FIELDS, "supportsAllDrives": "true"})
        _, _, raw = self._api(url)
        return _metadata(strict_json_loads(raw), expected_id=file_id)

    def _cache_folder(self, metadata: Mapping[str, Any], checked: float) -> None:
        if len(self._folders) >= MAX_FOLDER_CACHE and metadata["id"] not in self._folders:
            root = self._folders.get(self.config.root_folder_id)
            self._folders.clear()
            if root is not None:
                self._folders[self.config.root_folder_id] = root
        self._folders[metadata["id"]] = (checked, dict(metadata))

    def _root(self) -> dict[str, Any]:
        self._remaining()
        cached = self._folders.get(self.config.root_folder_id)
        if cached is not None and time.monotonic() - cached[0] < FOLDER_CACHE_SECONDS:
            return dict(cached[1])
        metadata = self._get_metadata(self.config.root_folder_id)
        _live(metadata, folder=True)
        self._cache_folder(metadata, time.monotonic())
        return metadata

    def _scope(self, metadata: Mapping[str, Any]) -> None:
        _live(metadata)
        self._root()
        if metadata["id"] == self.config.root_folder_id:
            _live(metadata, folder=True)
            return
        seen = {metadata["id"]}
        folders = [metadata] if metadata["mimeType"] == FOLDER_MIME else []
        current = metadata
        for _ in range(MAX_ANCESTORS):
            self._remaining()
            parents = current["parents"]
            if len(parents) != 1:
                raise MemoryError("drive_object_outside_root")
            parent = parents[0]
            if parent in seen:
                raise MemoryError("drive_parent_cycle")
            seen.add(parent)
            cached = self._folders.get(parent)
            if cached is not None and time.monotonic() - cached[0] < FOLDER_CACHE_SECONDS:
                # Do not extend the original proof's lifetime by copying it to
                # another cached child; all inherited proofs expire together.
                for folder in folders:
                    self._cache_folder(folder, cached[0])
                return
            current = self._get_metadata(parent)
            _live(current, folder=True)
            folders.append(current)
        raise MemoryError("drive_ancestor_limit")

    def metadata(self, file_id: str) -> dict[str, Any]:
        selected = _identifier(file_id)
        root = self._root()
        if selected == self.config.root_folder_id:
            return root
        metadata = self._get_metadata(selected)
        self._scope(metadata)
        return metadata

    def read_range(self, file_id: str, offset: int, count: int) -> bytes:
        if type(offset) is not int or not 0 <= offset < 2**63 or type(count) is not int or not 0 <= count <= MAX_CHUNK_BYTES:
            raise MemoryError("drive_invalid_range")
        metadata = self.metadata(file_id)
        if metadata["mimeType"].startswith("application/vnd.google-apps.") or "size" not in metadata:
            raise MemoryError("drive_blob_required")
        if metadata.get("capabilities", {}).get("canDownload") is False:
            raise MemoryError("drive_download_not_permitted")
        size = _number(metadata["size"])
        if offset > size:
            raise MemoryError("drive_range_outside_file")
        expected = min(count, size - offset)
        if not expected:
            return b""
        end = offset + expected - 1
        url = API_ROOT + "/files/" + _identifier(file_id) + "?alt=media&supportsAllDrives=true"
        status, headers, data = self._api(url, headers={"Range": f"bytes={offset}-{end}"},
                                         maximum=expected, statuses=(200, 206))
        if status == 206:
            match = _RANGE.fullmatch(headers.get("content-range", ""))
            if match is None or tuple(int(value) for value in match.groups()) != (offset, end, size):
                raise MemoryError("drive_content_range_mismatch")
        elif offset != 0 or expected != size:
            raise MemoryError("drive_range_not_honored")
        if len(data) != expected:
            raise MemoryError("drive_range_length_mismatch", retryable=True)
        return data

    def list_children(self, parent_id: str, *, name: str | None = None,
                      page_token: str | None = None) -> dict[str, Any]:
        parent = self.metadata(parent_id)
        _live(parent, folder=True)
        query = "'" + parent["id"] + "' in parents and trashed = false and mimeType != '" + SHORTCUT_MIME + "'"
        if name is not None:
            name = _text(name, maximum=1024)
            query += " and name = '" + name.replace("\\", "\\\\").replace("'", "\\'") + "'"
        parameters = {"q": query, "pageSize": "100", "fields": "nextPageToken,incompleteSearch,files(" + _FIELDS + ")",
                      "spaces": "drive", "supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}
        if page_token is not None:
            parameters["pageToken"] = _text(page_token, maximum=4096)
        _, _, raw = self._api(API_ROOT + "/files?" + urllib.parse.urlencode(parameters), maximum=MAX_LIST_BYTES)
        payload = strict_json_loads(raw)
        if not isinstance(payload, dict) or type(payload.get("incompleteSearch", False)) is not bool:
            raise MemoryError("drive_invalid_listing")
        if payload.get("incompleteSearch", False):
            raise MemoryError("drive_incomplete_listing", retryable=True)
        values = payload.get("files", [])
        if not isinstance(values, list) or len(values) > 100:
            raise MemoryError("drive_invalid_listing")
        files, seen = [], {parent["id"]}
        for value in values:
            metadata = _metadata(value)
            _live(metadata)
            if metadata["parents"] != [parent["id"]] or metadata["id"] in seen or (name is not None and metadata["name"] != name):
                raise MemoryError("drive_listing_scope_mismatch")
            seen.add(metadata["id"])
            files.append(metadata)
        token = payload.get("nextPageToken")
        if token is not None:
            token = _text(token, maximum=4096)
        return {"files": files, "next_page_token": token}

    def _new_name(self, parent_id: str, name: str) -> tuple[str, str]:
        name = _text(name, maximum=1024)
        if name in {".", ".."} or "/" in name or "\\" in name:
            raise MemoryError("drive_invalid_object_name")
        parent = _identifier(parent_id)
        existing = self.list_children(parent, name=name)
        if existing["files"]:
            raise MemoryError("drive_name_exists")
        if existing["next_page_token"] is not None:
            raise MemoryError("drive_name_check_incomplete", retryable=True)
        return parent, name

    def _created(self, raw: bytes, *, parent_id: str, name: str, mime_type: str, size: int | None = None) -> dict[str, Any]:
        metadata = _metadata(strict_json_loads(raw))
        _live(metadata)
        if (metadata["parents"] != [parent_id] or metadata["name"] != name or metadata["mimeType"] != mime_type
                or (size is not None and ("size" not in metadata or _number(metadata["size"]) != size))):
            raise MemoryError("drive_created_object_mismatch")
        # The already checked parent proof plus the returned exact parent
        # establishes the new object's scope. Names are not unique in Drive;
        # concurrent creators can still race, so callers must retain this ID.
        if mime_type == FOLDER_MIME:
            cached = self._folders.get(parent_id)
            if cached is not None:
                self._cache_folder(metadata, cached[0])
        return metadata

    def create_folder(self, parent_id: str, name: str) -> dict[str, Any]:
        parent_id, name = self._new_name(parent_id, name)
        body = canonical_bytes({"name": name, "mimeType": FOLDER_MIME, "parents": [parent_id]})
        url = API_ROOT + "/files?" + urllib.parse.urlencode({"fields": _FIELDS, "supportsAllDrives": "true"})
        try:
            _, _, raw = self._api(url, method="POST", body=body, headers={"Content-Type": "application/json; charset=UTF-8"},
                                  statuses=(200, 201))
        except MemoryError as exc:
            if exc.code in {"drive_network_unavailable", "drive_deadline_exceeded", "drive_response_length_mismatch"}:
                # A lost response can follow a completed POST. Require an
                # explicit same-name/ID/content reconciliation before retry.
                raise MemoryError("drive_write_outcome_unknown") from None
            raise
        return self._created(raw, parent_id=parent_id, name=name, mime_type=FOLDER_MIME)

    def upload_bytes(self, parent_id: str, name: str, data: bytes,
                     mime_type: str = "application/octet-stream") -> dict[str, Any]:
        if not isinstance(data, bytes) or len(data) > MAX_CHUNK_BYTES:
            raise MemoryError("drive_upload_too_large")
        mime_type = _text(mime_type, maximum=255)
        if _MIME.fullmatch(mime_type) is None or mime_type.startswith("application/vnd.google-apps."):
            raise MemoryError("drive_invalid_upload_mime_type")
        parent_id, name = self._new_name(parent_id, name)
        document = canonical_bytes({"name": name, "mimeType": mime_type, "parents": [parent_id]})
        boundary = "memoryvault-" + secrets.token_hex(24)
        if boundary.encode("ascii") in data or boundary.encode("ascii") in document:
            raise MemoryError("drive_multipart_boundary_conflict", retryable=True)
        marker = boundary.encode("ascii")
        body = (b"--" + marker + b"\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n" + document
                + b"\r\n--" + marker + b"\r\nContent-Type: " + mime_type.encode("ascii") + b"\r\n\r\n"
                + data + b"\r\n--" + marker + b"--\r\n")
        url = UPLOAD_ROOT + "/files?" + urllib.parse.urlencode({"uploadType": "multipart", "fields": _FIELDS, "supportsAllDrives": "true"})
        try:
            _, _, raw = self._api(url, method="POST", body=body,
                headers={"Content-Type": "multipart/related; boundary=" + boundary}, statuses=(200, 201))
        except MemoryError as exc:
            if exc.code in {"drive_network_unavailable", "drive_deadline_exceeded", "drive_response_length_mismatch"}:
                raise MemoryError("drive_write_outcome_unknown") from None
            raise
        metadata = self._created(raw, parent_id=parent_id, name=name, mime_type=mime_type, size=len(data))
        if "sha256Checksum" in metadata and metadata["sha256Checksum"] != hashlib.sha256(data).hexdigest():
            raise MemoryError("drive_created_checksum_mismatch")
        if "md5Checksum" in metadata and metadata["md5Checksum"] != hashlib.md5(data, usedforsecurity=False).hexdigest():
            raise MemoryError("drive_created_checksum_mismatch")
        return metadata
