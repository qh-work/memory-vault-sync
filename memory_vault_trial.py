"""Disposable synthetic endpoint for the hosted Memory Vault network trial.

This module never discovers an installed plugin, hook, Vault or user config.  It
creates a fresh endpoint below a marked trial directory, pins the service and
issuer from a separately supplied trust file, and sends one generated nonce.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tempfile
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from memory_vault import MemoryError, canonical_bytes, strict_json_loads
from memory_vault_agent import Agent
from memory_vault_network import NetworkClient, origin
from memory_vault_network_admin import configure_network, create_identity
from memory_vault_network_crypto import PublicKeyTrust, integer, object_fields, opaque, public_signing_key
from memory_vault_storage import atomic_write, private_directory
from memory_vault_update import read_file


TRUST_SCHEMA = "memory-vault-trial-service-trust/v1"
SERVICE_SCHEMA = "memory-vault-trial-service/v1"
ENROLLMENT_SCHEMA = "memory-vault-trial-enrollment-result/v1"
RESULT_SCHEMA = "memory-vault-synthetic-trial-result/v1"
MARKER_SCHEMA = "memory-vault-synthetic-trial-state/v1"
STATE_PREFIX = "memory-vault-synthetic-trial-"
SYNTHETIC_PREFIX = "memory-vault synthetic trial/v1 nonce="
SYNTHETIC_REPLY_PREFIX = "memory-vault synthetic trial reply/v1 nonce="
_NONCE = re.compile(r"[0-9a-f]{64}")
_RUN_CODE = re.compile(r"[A-Za-z0-9._~-]{32,128}")
_POST = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]


class TrialError(MemoryError):
    """A redaction-safe trial failure identified only by a stable code."""


def _trial_error(code: str, *, retryable: bool = False) -> TrialError:
    return TrialError(code, retryable=retryable)


def _enrollment_url(value: Any) -> str:
    if not isinstance(value, str):
        raise _trial_error("trial_service_trust_invalid")
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path != "/v1/trial/enroll" or not parsed.hostname
            or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))):
        raise _trial_error("trial_service_trust_invalid")
    return value


def select_enrollment_url(value: Any, trusted_url: str) -> str:
    """Accept the pinned endpoint or its control origin, never a new host."""
    if value == trusted_url:
        return trusted_url
    try:
        selected = origin(value)
    except Exception:
        raise _trial_error("trial_service_selection_mismatch") from None
    parsed = urlsplit(trusted_url)
    trusted_origin = parsed.scheme + "://" + parsed.netloc
    if selected != trusted_origin:
        raise _trial_error("trial_service_selection_mismatch")
    return trusted_url


def validate_service(value: Any) -> dict[str, Any]:
    service = object_fields(value, {"schema_version", "network_id", "authority_url", "relays",
                                    "issuer_public_key", "reference_peer_key_id"},
                            "trial_service_trust_invalid")
    if service["schema_version"] != SERVICE_SCHEMA:
        raise _trial_error("trial_service_trust_invalid")
    network_id = opaque(service["network_id"])
    authority_url = origin(service["authority_url"])
    relays = service["relays"]
    if (not isinstance(relays, list) or not 1 <= len(relays) <= 2
            or len(set(relays)) != len(relays)):
        raise _trial_error("trial_service_trust_invalid")
    relays = [origin(item) for item in relays]
    issuer = public_signing_key(service["issuer_public_key"])
    reference = opaque(service["reference_peer_key_id"])
    return {"schema_version": SERVICE_SCHEMA, "network_id": network_id,
            "authority_url": authority_url, "relays": relays,
            "issuer_public_key": issuer, "reference_peer_key_id": reference}


def validate_service_trust(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping) and value.get("state") == "unconfigured":
        raise _trial_error("trial_service_unconfigured")
    trust = object_fields(value, {"schema_version", "enrollment_url", "service"},
                          "trial_service_trust_invalid")
    if trust["schema_version"] != TRUST_SCHEMA:
        raise _trial_error("trial_service_trust_invalid")
    return {"schema_version": TRUST_SCHEMA,
            "enrollment_url": _enrollment_url(trust["enrollment_url"]),
            "service": validate_service(trust["service"])}


def load_service_trust(path: Path) -> dict[str, Any]:
    raw = read_file(path, maximum=32 * 1024)
    if raw is None:
        raise _trial_error("trial_service_trust_missing")
    try:
        return validate_service_trust(strict_json_loads(raw))
    except TrialError:
        raise
    except Exception:
        raise _trial_error("trial_service_trust_invalid") from None


def _new_state_root(selected: Path | None) -> Path:
    if selected is None:
        # macOS exposes /var as a symlink to /private/var. The secure storage
        # layer correctly rejects symlinked ancestors, so create the private
        # directory below the resolved system temporary parent.
        temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix=STATE_PREFIX, dir=temporary_parent)).resolve(strict=True)
    else:
        candidate = selected.expanduser().absolute()
        if candidate.name.startswith(STATE_PREFIX) is False or os.path.lexists(candidate):
            raise _trial_error("trial_state_path_unsafe")
        parent = candidate.parent
        if not parent.is_dir() or parent.is_symlink():
            raise _trial_error("trial_state_path_unsafe")
        candidate.mkdir(mode=0o700)
        root = candidate
    private_directory(root)
    atomic_write(root / ".memory-vault-synthetic-trial",
                 canonical_bytes({"schema_version": MARKER_SCHEMA, "synthetic_only": True}) + b"\n",
                 replace=False)
    return root


def _marked_trial_root(root: Path) -> bool:
    try:
        if root.is_symlink() or not root.is_dir() or not root.name.startswith(STATE_PREFIX):
            return False
        marker = root / ".memory-vault-synthetic-trial"
        info = marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return False
        value = strict_json_loads(read_file(marker, maximum=1024))
        return value == {"schema_version": MARKER_SCHEMA, "synthetic_only": True}
    except (OSError, MemoryError, TypeError, ValueError):
        return False


def cleanup_trial_state(root: Path) -> bool:
    """Remove only a directory created and marked by this trial module."""
    if not _marked_trial_root(root):
        raise _trial_error("trial_state_cleanup_refused")
    shutil.rmtree(root)
    return not os.path.lexists(root)


def _post_json(url: str, value: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        import httpx
        with httpx.Client(timeout=10, follow_redirects=False,
                          limits=httpx.Limits(max_connections=1, max_keepalive_connections=0)) as client:
            with client.stream("POST", url, content=canonical_bytes(value),
                               headers={"content-type": "application/json"}) as response:
                encoded = bytearray()
                for chunk in response.iter_bytes():
                    encoded.extend(chunk)
                    if len(encoded) > 8 * 1024 * 1024:
                        raise _trial_error("trial_enrollment_response_too_large")
                status_code = response.status_code
            body = strict_json_loads(bytes(encoded))
    except TrialError:
        raise
    except Exception:
        raise _trial_error("trial_enrollment_unavailable", retryable=True) from None
    if status_code != 200:
        if isinstance(body, Mapping) and isinstance(body.get("error"), Mapping):
            code = body["error"].get("code")
            retryable = body["error"].get("retryable")
            if isinstance(code, str) and type(retryable) is bool:
                raise _trial_error(code, retryable=retryable)
        raise _trial_error("trial_enrollment_rejected")
    if not isinstance(body, Mapping):
        raise _trial_error("trial_enrollment_invalid")
    return dict(body)


def _validate_enrollment(value: Any, pinned_service: Mapping[str, Any]) -> dict[str, Any]:
    result = object_fields(value, {"schema_version", "state", "invitation", "service", "service_proof", "expires_at"},
                           "trial_enrollment_invalid")
    if result["schema_version"] != ENROLLMENT_SCHEMA or result["state"] != "invited":
        raise _trial_error("trial_enrollment_invalid")
    signed_service = object_fields(result["service"], {
        "schema_version", "network_id", "authority_url", "relays", "issuer_public_key",
        "reference_peer_key_id", "issued_at", "expires_at", "synthetic_only", "execution_authority",
        "content_enforcement", "relay_plaintext_access",
    }, "trial_enrollment_invalid")
    static_service = validate_service({key: signed_service[key] for key in pinned_service})
    if canonical_bytes(static_service) != canonical_bytes(pinned_service):
        raise _trial_error("trial_service_pin_mismatch")
    issued_at = integer(signed_service["issued_at"], minimum=1)
    service_expires_at = integer(signed_service["expires_at"], minimum=1)
    if (issued_at > service_expires_at or signed_service["synthetic_only"] is not True
            or signed_service["execution_authority"] is not False
            or signed_service["content_enforcement"] != "endpoint-only"
            or signed_service["relay_plaintext_access"] is not False):
        raise _trial_error("trial_enrollment_invalid")
    try:
        verified = PublicKeyTrust([pinned_service["issuer_public_key"]]).verify_message(
            signed_service, result["service_proof"])
    except Exception:
        raise _trial_error("trial_service_proof_invalid") from None
    if verified != pinned_service["issuer_public_key"]["key_id"]:
        raise _trial_error("trial_service_proof_invalid")
    invitation = result["invitation"]
    if (not isinstance(invitation, Mapping) or not {"invite", "roster"} <= set(invitation)
            or set(invitation) - {"invite", "roster", "handoff"}):
        raise _trial_error("trial_enrollment_invalid")
    expires_at = integer(result["expires_at"], minimum=1)
    try:
        if (invitation["invite"]["payload"]["expires_at"] != expires_at
                or service_expires_at != expires_at):
            raise _trial_error("trial_enrollment_invalid")
    except (KeyError, TypeError):
        raise _trial_error("trial_enrollment_invalid") from None
    return {"invitation": dict(invitation), "expires_at": expires_at, "service": static_service}


def _require_ok(response: Mapping[str, Any], fallback: str) -> Mapping[str, Any]:
    if response.get("ok") is True and isinstance(response.get("result"), Mapping):
        return response["result"]
    error = response.get("error")
    if isinstance(error, Mapping) and isinstance(error.get("code"), str):
        raise _trial_error(error["code"], retryable=bool(error.get("retryable", False)))
    raise _trial_error(fallback)


def _recall_text(agent: Agent, memory_id: str) -> str:
    request: dict[str, Any] = {"op": "recall", "memory_id": memory_id}
    pieces: list[str] = []
    for _ in range(32):
        result = _require_ok(agent.handle(request), "trial_recall_failed")
        hits = result.get("hits")
        if not isinstance(hits, list):
            raise _trial_error("trial_recall_failed")
        pieces.extend(hit["text"] for hit in hits if isinstance(hit, Mapping) and isinstance(hit.get("text"), str))
        cursor = result.get("next_cursor")
        if cursor is None:
            return "".join(pieces)
        if not isinstance(cursor, str):
            raise _trial_error("trial_recall_failed")
        request = {"op": "recall", "cursor": cursor}
    raise _trial_error("trial_recall_failed")


def run_trial(*, service_trust: Mapping[str, Any], run_code: str,
              state_directory: Path | None = None, keep_state: bool = False,
              transport: Any = None, enrollment_request: _POST | None = None,
              progress_hook: Callable[[], Any] | None = None,
              timeout_seconds: int = 30) -> dict[str, Any]:
    """Run one bounded synthetic round trip and return redacted evidence."""
    trust = validate_service_trust(service_trust)
    if not isinstance(run_code, str) or _RUN_CODE.fullmatch(run_code) is None:
        raise _trial_error("trial_run_code_invalid")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise _trial_error("trial_timeout_invalid")
    root = _new_state_root(state_directory)
    cleaned = False
    try:
        endpoint = root / "endpoint"
        created = create_identity(endpoint)
        candidate = strict_json_loads(read_file(endpoint / "member-public.json", maximum=16 * 1024))
        post = enrollment_request or _post_json
        enrollment = _validate_enrollment(post(trust["enrollment_url"],
            {"run_code": run_code, "candidate": candidate}), trust["service"])
        issuer_path = root / "trusted-issuer.json"
        atomic_write(issuer_path, canonical_bytes(trust["service"]["issuer_public_key"]) + b"\n", replace=False)
        network_path = endpoint / "network.json"
        configure_network(client_config=Path(created["client_config"]),
                          encryption_key=Path(created["encryption_key"]), issuer_public=issuer_path,
                          network_id=trust["service"]["network_id"],
                          authority_url=trust["service"]["authority_url"],
                          relays=trust["service"]["relays"], output=network_path)
        agent = Agent(Path(created["client_config"]), network_path, transport=transport)
        connect = _require_ok(agent.handle({"op": "connect", "request_id": "req_trial_connect_" + secrets.token_hex(8),
                                            "invitation": enrollment["invitation"]}), "trial_connect_failed")
        if connect.get("state") != "connected" or connect.get("degraded") is not False:
            raise _trial_error("trial_connect_failed", retryable=True)
        discover = _require_ok(agent.handle({"op": "discover", "online": True}), "trial_discover_failed")
        if trust["service"]["reference_peer_key_id"] not in {
                item.get("key_id") for item in discover.get("members", []) if isinstance(item, Mapping)}:
            raise _trial_error("trial_reference_peer_missing", retryable=True)

        nonce = secrets.token_hex(32)
        text = SYNTHETIC_PREFIX + nonce
        nonce_sha256 = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        remembered = _require_ok(agent.handle({"op": "remember", "request_id": "req_trial_remember_" + nonce[:24],
                                                "kind": "fact", "text": text}), "trial_remember_failed")
        if remembered.get("state") != "accepted_local" or not isinstance(remembered.get("memory_id"), str):
            raise _trial_error("trial_remember_failed")
        send_request = {"op": "send", "request_id": "req_trial_send_" + nonce[:24],
                        "recipients": [trust["service"]["reference_peer_key_id"]],
                        "text": text, "memory_ids": [remembered["memory_id"]]}
        sent = _require_ok(agent.handle(send_request), "trial_send_failed")
        if sent.get("state") != "stored" or sent.get("stored_nodes") != sent.get("configured_nodes"):
            raise _trial_error("trial_relay_storage_unconfirmed", retryable=True)

        # Exercise the durable queue worker even though the initial online send
        # normally already has every configured relay receipt.
        with NetworkClient(network_path, transport=transport) as network:
            pumped = network.pump(maximum_messages=4, maximum_seconds=5, receive_limit=0)
        if pumped.get("remaining_outbox") != 0:
            raise _trial_error("trial_pump_incomplete", retryable=True)

        expected_reply = SYNTHETIC_REPLY_PREFIX + nonce + " source=" + sent["message_id"]
        reply = None
        deadline = time.monotonic() + timeout_seconds
        receive_attempts = 0
        while time.monotonic() < deadline:
            if progress_hook is not None:
                progress_hook()
            receive_attempts += 1
            received = _require_ok(agent.handle({"op": "receive", "limit": 4}), "trial_receive_failed")
            for message in received.get("messages", []):
                if (isinstance(message, Mapping) and message.get("sender_key_id") == trust["service"]["reference_peer_key_id"]
                        and message.get("state") == "validated_saved" and message.get("text") == expected_reply):
                    reply = message
                    break
            if reply is not None:
                break
            time.sleep(0.25)
        if reply is None:
            raise _trial_error("trial_reference_reply_timeout", retryable=True)
        retried = _require_ok(agent.handle(send_request), "trial_receipt_check_failed")
        if retried.get("endpoint_validated") is not True:
            raise _trial_error("trial_peer_validation_unconfirmed", retryable=True)
        memory_id = reply.get("text_memory_id")
        if not isinstance(memory_id, str) or _recall_text(agent, memory_id) != expected_reply:
            raise _trial_error("trial_local_recall_mismatch")

        result = {"schema_version": RESULT_SCHEMA, "ok": True, "synthetic_only": True,
                  "nonce_sha256": nonce_sha256,
                  "stages": {"keys_generated_locally": True,
                    "connect": {"connected": True, "joined_nodes": connect["joined_nodes"]},
                    "discover": {"reference_peer_found": True, "member_count": discover["member_count"]},
                    "remember": {"accepted_local": True},
                    "relay_stored": {"confirmed": True, "stored_nodes": sent["stored_nodes"]},
                    "pump": {"completed": pumped.get("state") == "completed", "remaining_outbox": 0},
                    "peer_validated_saved": {"confirmed": True},
                    "receive": {"validated_saved": True, "attempts": receive_attempts},
                    "local_recall": {"matched_synthetic_nonce": True}},
                  "privacy": {"existing_vault_accessed": False, "plugin_accessed": False,
                              "hook_accessed": False, "private_keys_uploaded": False,
                              "plaintext_visible_to_relay": False},
                  "cleanup": {"state_retained": bool(keep_state), "state_removed": False,
                              **({"retained_state_directory": str(root)} if keep_state else {})}}
    finally:
        if not keep_state:
            cleaned = cleanup_trial_state(root)
    result["cleanup"]["state_removed"] = cleaned
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a disposable synthetic Memory Vault network endpoint")
    parser.add_argument("--service", required=True,
                        help="Pinned control origin shown with the one-time run code")
    parser.add_argument("--service-trust", required=True, type=Path)
    parser.add_argument("--run-code", required=True)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--keep-state", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        # Service trust is validated before any trial state or key is created.
        trust = load_service_trust(args.service_trust)
        select_enrollment_url(args.service, trust["enrollment_url"])
        result = run_trial(service_trust=trust, run_code=args.run_code,
                           state_directory=args.state_directory, keep_state=args.keep_state,
                           timeout_seconds=args.timeout_seconds)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        code = getattr(exc, "code", "trial_unavailable")
        retryable = bool(getattr(exc, "retryable", False))
        failure = {"schema_version": RESULT_SCHEMA, "ok": False,
                   "error": {"code": code, "retryable": retryable},
                   "privacy": {"error_details_redacted": True}}
        print(json.dumps(failure, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
