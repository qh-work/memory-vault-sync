#!/usr/bin/env python3
"""Claude Code hook bridge for the model-neutral Memory Vault protocol."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping


ADAPTERS_ROOT = Path(__file__).resolve().parent.parent
if str(ADAPTERS_ROOT) not in sys.path:
    sys.path.insert(0, str(ADAPTERS_ROOT))

from adapter_common import (  # noqa: E402
    AdapterFailure,
    LifecycleAdapter,
    hook_context,
    hook_noop,
    read_bounded_json,
    require_native_id,
    require_visible_text,
    write_json,
)


ADAPTER = LifecycleAdapter("memory-vault.claude-code", "claude-code")


def translate_hook(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    event = raw.get("hook_event_name")
    if not isinstance(event, str):
        raise AdapterFailure("invalid_hook_event")
    native_session_id = require_native_id(raw.get("session_id"))

    if event == "SessionStart":
        source = raw.get("source")
        if source == "fork":
            source = "resume"
        if source not in {"startup", "resume", "clear", "compact"}:
            raise AdapterFailure("invalid_session_reason")
        result = ADAPTER.session_open(native_session_id, source)
        return hook_context(event, ADAPTER._context(result))

    if event == "UserPromptSubmit":
        prompt = require_visible_text(raw.get("prompt"))
        result = ADAPTER.turn_input(native_session_id, prompt, 8)
        return hook_context(event, ADAPTER._context(result))

    if event == "Stop":
        assistant = require_visible_text(
            raw.get("last_assistant_message"), nullable=True
        )
        if assistant is not None:
            ADAPTER.turn_commit(
                native_session_id,
                outcome="final",
                visible_user_text=None,
                visible_assistant_text=assistant,
            )
        return hook_noop()

    if event == "StopFailure":
        ADAPTER.turn_abort(native_session_id, "host_error")
        return hook_noop()

    if event == "SessionEnd":
        ADAPTER.session_close(native_session_id)
        return hook_noop()

    raise AdapterFailure("unsupported_hook_event")


def main() -> int:
    try:
        output = translate_hook(read_bounded_json())
    except Exception:
        # A memory outage must not turn into a permission decision or stop the
        # host.  Deliberately emit no private diagnostic or input fragment.
        output = hook_noop()
    write_json(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
