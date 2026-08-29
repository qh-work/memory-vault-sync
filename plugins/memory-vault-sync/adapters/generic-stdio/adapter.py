#!/usr/bin/env python3
"""Generic local-model stdio bridge for the shared Memory Vault."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Mapping


ADAPTERS_ROOT = Path(__file__).resolve().parent.parent
if str(ADAPTERS_ROOT) not in sys.path:
    sys.path.insert(0, str(ADAPTERS_ROOT))

from adapter_common import (  # noqa: E402
    AdapterFailure,
    LifecycleAdapter,
    MAX_HOOK_INPUT_BYTES,
    generic_error,
    generic_success,
    read_bounded_json,
    require_exact_fields,
    require_limit,
    require_mapping,
    require_native_id,
    require_visible_text,
    strict_json_loads,
    write_json,
)


EVENT_SCHEMA = "memory-vault-local-host-event/v1"
ADAPTER = LifecycleAdapter("memory-vault.generic-stdio", "generic-stdio")


def translate_event(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    envelope = require_exact_fields(
        raw,
        {"schema_version", "event", "payload"},
        "invalid_event_envelope",
    )
    if envelope.get("schema_version") != EVENT_SCHEMA:
        raise AdapterFailure("unsupported_event_schema")
    event = envelope.get("event")
    if not isinstance(event, str):
        raise AdapterFailure("invalid_event")
    payload = require_mapping(envelope.get("payload"), "invalid_event_payload")

    if event == "capabilities":
        require_exact_fields(payload, set())
        return ADAPTER.capabilities()

    if event == "session.open":
        body = require_exact_fields(payload, {"native_session_id", "reason"})
        native_id = require_native_id(body.get("native_session_id"))
        reason = body.get("reason")
        if reason not in {"startup", "resume", "clear", "compact"}:
            raise AdapterFailure("invalid_session_reason")
        return ADAPTER.session_open(native_id, reason)

    if event == "turn.input":
        body = require_exact_fields(
            payload,
            {"native_session_id", "visible_user_text", "limit"},
        )
        return ADAPTER.turn_input(
            require_native_id(body.get("native_session_id")),
            require_visible_text(body.get("visible_user_text")),
            require_limit(body.get("limit")),
        )

    if event == "turn.commit":
        body = require_exact_fields(
            payload,
            {
                "native_session_id",
                "outcome",
                "visible_user_text",
                "visible_assistant_text",
            },
        )
        outcome = body.get("outcome")
        if outcome != "final":
            raise AdapterFailure("invalid_turn_outcome")
        result = ADAPTER.turn_commit(
            require_native_id(body.get("native_session_id")),
            outcome=outcome,
            visible_user_text=require_visible_text(
                body.get("visible_user_text"), nullable=True
            ),
            visible_assistant_text=require_visible_text(
                body.get("visible_assistant_text"), nullable=True
            ),
        )
        return result or {}

    if event == "turn.abort":
        body = require_exact_fields(
            payload, {"native_session_id", "reason"}
        )
        reason = body.get("reason")
        if reason not in {"cancelled", "host_error", "user_interrupt", "unknown"}:
            raise AdapterFailure("invalid_abort_reason")
        return ADAPTER.turn_abort(
            require_native_id(body.get("native_session_id")), reason
        ) or {}

    if event == "session.close":
        body = require_exact_fields(payload, {"native_session_id"})
        return ADAPTER.session_close(
            require_native_id(body.get("native_session_id"))
        ) or {}

    if event == "memory.recall":
        body = require_exact_fields(payload, {"query", "limit"})
        return ADAPTER.memory_recall(
            require_visible_text(body.get("query")),
            require_limit(body.get("limit")),
        )

    if event == "memory.remember":
        body = require_exact_fields(payload, {"proposal"})
        proposal = require_mapping(body.get("proposal"), "invalid_proposal")
        return ADAPTER.memory_remember(proposal)

    if event == "memory.status":
        require_exact_fields(payload, set())
        return ADAPTER.memory_status()

    if event == "sync.flush":
        require_exact_fields(payload, set())
        return ADAPTER.sync_flush()

    raise AdapterFailure("unsupported_event")


def process(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        return generic_success(translate_event(raw))
    except Exception:
        return generic_error()


def serve() -> int:
    while True:
        line = sys.stdin.buffer.readline(MAX_HOOK_INPUT_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_HOOK_INPUT_BYTES or not line.endswith(b"\n"):
            write_json(generic_error())
            return 0
        try:
            value = strict_json_loads(line)
            raw = require_mapping(value)
        except Exception:
            write_json(generic_error())
            continue
        write_json(process(raw))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Translate local model lifecycle events to Memory Vault stdio."
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Read and write one bounded JSON object per line until EOF.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.serve:
        return serve()
    try:
        raw = read_bounded_json()
    except Exception:
        write_json(generic_error())
        return 0
    write_json(process(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
