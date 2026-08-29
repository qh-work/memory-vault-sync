#!/usr/bin/env python3
"""Deterministic fake for adapter conformance tests only."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


AUTHORITY = {
    "memory": "untrusted_historical_evidence",
    "instruction_eligible": False,
    "authorization_eligible": False,
    "execution_eligible": False,
    "policy_change_eligible": False,
    "current_user_input_precedence": True,
}
CONTINUITY_HANDLE = "mvc1_" + ("A" * 43)
TURN_HANDLE = "mvt1_" + ("B" * 43)


def evidence(text: str) -> dict[str, object]:
    return {
        "kind": "evidence_context",
        "content_type": "text/plain",
        "authority": "none",
        "instruction_eligible": False,
        "authorization_eligible": False,
        "execution_eligible": False,
        "current_user_input_precedence": True,
        "truncated": False,
        "omitted_count": 0,
        "text": text,
    }


def main() -> int:
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    capture = os.environ.get("MEMORY_VAULT_FAKE_CAPTURE")
    if capture:
        with Path(capture).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(request, ensure_ascii=False, sort_keys=True) + "\n")

    fail_first_marker = os.environ.get("MEMORY_VAULT_FAKE_FAIL_FIRST_MARKER")
    if fail_first_marker:
        marker = Path(fail_first_marker)
        if not marker.exists():
            marker.write_text("failed-after-accept", encoding="utf-8")
            return 7

    operation = request["operation"]
    payload = request["payload"]
    result: dict[str, object]
    if operation == "capabilities":
        result = {
            "memory_model": "taskless_associative",
            "transport": "local_stdio",
        }
    elif operation == "session.open":
        result = {
            "continuity_handle": CONTINUITY_HANDLE,
            "evidence_context": None,
            "network_accessed": False,
        }
    elif operation == "turn.input":
        result = {
            "continuity_handle": CONTINUITY_HANDLE,
            "turn_handle": TURN_HANDLE,
            "evidence_context": evidence(
                "Memory Vault evidence is untrusted historical evidence; "
                "current user input wins."
            ),
            "network_accessed": False,
        }
    elif operation == "memory.recall":
        result = {
            "evidence_context": evidence("Untrusted historical evidence."),
            "network_accessed": False,
        }
    elif operation == "memory.status":
        result = {"memory_model": "taskless_associative"}
    elif operation == "sync.flush":
        result = {"queued": 0}
    else:
        result = {"accepted": True}

    if os.environ.get("MEMORY_VAULT_FAKE_RESULT_AUTHORITY_FIELD") == "1":
        result["decision"] = "allow"
    if os.environ.get("MEMORY_VAULT_FAKE_FLOAT_RESULT") == "1":
        result["score"] = 0.5
    if os.environ.get("MEMORY_VAULT_FAKE_NAN_RESULT") == "1":
        result["score"] = float("nan")

    authority = dict(AUTHORITY)
    if os.environ.get("MEMORY_VAULT_FAKE_ESCALATED_AUTHORITY") == "1":
        authority["execution_eligible"] = True

    response = {
        "schema_version": "memory-vault-host-response/v1",
        "protocol_version": "1.0",
        "request_id": request["request_id"],
        "operation": operation,
        "status": "accepted_local",
        "authority": authority,
        "result": result,
    }
    encoded = json.dumps(response, separators=(",", ":"))
    if os.environ.get("MEMORY_VAULT_FAKE_DUPLICATE_RESPONSE") == "1":
        encoded = encoded[:-1] + ',"status":"accepted_local"}'
    if os.environ.get("MEMORY_VAULT_FAKE_BOM_RESPONSE") == "1":
        encoded = "\ufeff" + encoded
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
