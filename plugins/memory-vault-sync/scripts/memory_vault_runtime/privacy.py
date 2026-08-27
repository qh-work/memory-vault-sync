"""Secret, local-path, and remote-document privacy enforcement."""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Mapping

from memory_vault_runtime.errors import PrivacyError


MAX_VISIBLE_TEXT_BYTES = 2 * 1024 * 1024

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "github_token",
        re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
    (
        "anthropic_api_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}"
            r"(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "openai_api_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"
            r"(?![A-Za-z0-9_-])"
        ),
    ),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{20,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("oauth_access_token", re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b")),
    ("oauth_client_secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b")),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
            r"(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "bearer_token",
        re.compile(
            r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{12,}"
        ),
    ),
    (
        "bearer_token_value",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    ),
    ("slack_token", re.compile(r"\bx(?:ox[baprs]|app)-[A-Za-z0-9-]{10,}\b")),
    ("gitlab_token", re.compile(r"\b(?:glpat|glrt|gloas)-[A-Za-z0-9_-]{20,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    (
        "stripe_secret_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "sendgrid_token",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    ),
    ("telegram_bot_token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")),
    ("digitalocean_token", re.compile(r"\bdop_v1_[0-9a-fA-F]{64}\b")),
    ("square_token", re.compile(r"\bsq0(?:atp|csp)-[A-Za-z0-9_-]{20,}\b")),
    ("cookie_header", re.compile(r"(?i)\b(?:Cookie|Set-Cookie)\s*:\s*\S+")),
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "memory_reconciliation_session_token",
        re.compile(
            r"(?i)(?:--session-token|session[_-]?token)"
            r"\s*(?:=|:|\s)\s*[\"']?[A-Za-z0-9_-]{43}"
            r"(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "memory_vault_handoff_capability",
        re.compile(
            r"(?i)(?:\[\[\s*)?memory-vault-handoff\s*:\s*"
            r"[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"
        ),
    ),
    (
        "memory_vault_routing_decision_capability",
        re.compile(r"mvrd_[A-Za-z0-9_-]{43}"),
    ),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|api[_-]?(?:key|token)|"
            r"access[_-]?token|refresh[_-]?token|oauth[_-]?token|"
            r"session[_-]?token|client[_-]?secret|secret[_-]?key|"
            r"private[_-]?key|webhook[_-]?secret)\s*[:=]\s*"
            r"[\"']?[^\s\"']{12,}"
        ),
    ),
)

ABSOLUTE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:^|[\s\"'(`])/(?:Users|home|root|tmp|var|private|Volumes|"
        r"content|mnt|etc|opt|Applications|Library|System|bin|sbin|"
        r"run|dev|proc|sys|srv|data|workspace|workspaces|project|projects|"
        r"repo|repos|build|app|usr/(?:local|bin|sbin|share|lib|include))/"
    ),
    re.compile(r"(?:^|[\s\"'(`])[A-Za-z]:[\\/]"),
    re.compile(r"(?:^|[\s\"'(`])\\\\[^\\\s]+\\[^\\\s]+"),
    re.compile(r"(?:^|[\s\"'(`])~[\\/]"),
)

REMOTE_FORBIDDEN_KEYS = {
    "local_path",
    "cwd",
    "session_id",
    "turn_id",
    "workspace_instance_id",
    "hostname",
    "username",
    "user",
    "email",
    "token",
    "password",
    "cookie",
    "credential",
    "upload_session_url",
}


def scan_text_content(
    value: str,
    label: str,
    *,
    reject_absolute_paths: bool = True,
) -> str:
    normalized = unicodedata.normalize("NFC", value)
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(normalized):
            raise PrivacyError(f"{label} contains {name}")
    if reject_absolute_paths:
        for pattern in ABSOLUTE_PATH_PATTERNS:
            if pattern.search(normalized):
                raise PrivacyError(f"{label} contains a local absolute path")
    return normalized


def scan_visible_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise PrivacyError(f"{label} must be text")
    if "\x00" in value:
        raise PrivacyError(f"{label} contains NUL")
    if len(value.encode("utf-8")) > MAX_VISIBLE_TEXT_BYTES:
        raise PrivacyError(f"{label} is too large")
    return scan_text_content(value, label)


def assert_remote_safe(value: Any, trail: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered in REMOTE_FORBIDDEN_KEYS:
                raise PrivacyError(
                    "remote document contains forbidden key: "
                    f"{'.'.join((*trail, lowered))}"
                )
            assert_remote_safe(child, (*trail, str(key)))
    elif isinstance(value, list):
        for child in value:
            assert_remote_safe(child, trail)
    elif isinstance(value, str):
        scan_visible_text(value, "remote text")
