"""Integer-only JCS metadata helpers, retained from public v0.21 (Apache-2.0).

This is the external-provider/update metadata domain, not record/v1 hashing.
There are no filesystem, network, installation or authorization side effects.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


class ProtocolValueError(ValueError):
    """A value is outside the versioned deterministic protocol domain."""

    def __init__(self, code: str, value_type: str | None = None):
        super().__init__(code)
        self.code = code
        self.value_type = value_type


def strict_json_loads(text: str) -> Any:
    """Load JSON while rejecting duplicate keys and non-finite numbers."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value is forbidden: {value}")

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(
        text,
        parse_constant=reject_constant,
        object_pairs_hook=reject_duplicate,
    )


def persisted_json_bytes(value: Any) -> bytes:
    """Encode the existing sorted, newline-terminated persisted JSON form."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def jcs_json_bytes(value: Any) -> bytes:
    """Encode integer-only RFC 8785 metadata, not the core record/v1 domain."""

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            if abs(item) > 9_007_199_254_740_991:
                raise ProtocolValueError("integer_outside_ieee754_safe_range")
            return str(item)
        if isinstance(item, float):
            raise ProtocolValueError("floating_point_forbidden")
        if isinstance(item, str):
            return json.dumps(
                item,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if isinstance(item, Mapping):
            if not all(isinstance(key, str) for key in item):
                raise ProtocolValueError("non_string_object_key")
            keys = sorted(
                item,
                key=lambda key: key.encode(
                    "utf-16be",
                    errors="surrogatepass",
                ),
            )
            return (
                "{"
                + ",".join(
                    f"{json.dumps(key, ensure_ascii=False)}:{encode(item[key])}"
                    for key in keys
                )
                + "}"
            )
        raise ProtocolValueError(
            "unsupported_value_type",
            type(item).__name__,
        )

    return encode(value).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
