"""Explicit maintenance for one independently authorized ciphertext node.

No import starts a process or acquires resources. The node's signing key is
not a member identity and has no message decryption or agent send permission.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import time
from typing import Any, Mapping, Sequence

from memory_vault import MemoryError, canonical_bytes, failure, success, write_response
from memory_vault_network import HTTPTransport
from memory_vault_network_crypto import document, document_sha256
from memory_vault_nodes import sign_node_request
from memory_vault_relay import Relay, RelayError
from memory_vault_trust import TrustError
import memory_vault_storage as storage


def refresh(relay: Relay, *, transport: Any = None, maximum_seconds: int = 10) -> Mapping[str, Any]:
    """Refresh current member and node policy without borrowing an agent key."""
    if type(maximum_seconds) is not int or not 1 <= maximum_seconds <= 60:
        raise RelayError("relay_invalid_budget")
    if relay.node_identity is None or relay.authority_url is None:
        raise RelayError("relay_node_authority_required")
    owned = transport is None
    transport = HTTPTransport() if owned else transport
    try:
        deadline = time.monotonic() + maximum_seconds
        challenge = relay.status_challenge()
        nonce = challenge["nonce"]
        now = int(time.time())
        request = sign_node_request(relay.node_identity, network_id=relay.network_id, action="refresh",
                                    request_id="req_" + secrets.token_hex(16), body={"nonce": nonce},
                                    issued_at=now, expires_at=now + 60)
        query = {"network_id": relay.network_id, "nonce": nonce, "request": request}
        if isinstance(transport, HTTPTransport):
            response = transport.request(relay.authority_url, "POST", "/v1/node-status", query, deadline=deadline)
        else:
            response = transport.request(relay.authority_url, "POST", "/v1/node-status", query)
        if time.monotonic() >= deadline:
            raise RelayError("relay_budget_exhausted", retryable=True)
        result = relay.update_status(response)
        return {**result, "node_directory_version": response["nodes"]["payload"]["version"],
                "node_directory_sha256": document_sha256(response["nodes"]),
                "node_identity": relay.node_descriptor(), "network_accessed": True,
                "agent_identity_used": False, "plaintext_keys_used": False}
    finally:
        if owned:
            transport.close()


def inspect(relay: Relay) -> Mapping[str, Any]:
    """Bounded local state/size inspection; does not open ciphertext bodies."""
    with relay._transaction() as db:
        files, size = relay._object_usage()
        messages = db.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        receipts = db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        state = relay._get(db, "draining")
        try:
            relay._node_current(db, "refresh")
            authorization = "current"
        except MemoryError as exc:
            authorization = exc.code
        return {"state": "draining" if state is not None else "serving",
                "node_identity": relay.node_descriptor(), "authorization": authorization,
                "stored_messages": messages, "stored_receipts": receipts,
                "ciphertext_files": files, "ciphertext_bytes": size,
                "orphan_files": max(0, files - messages), "limits": dict(relay.limits),
                "network_accessed": False, "source_data_deleted": False,
                "safe_to_remove": False, "migration_required": state is not None}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("operation", choices=["inspect", "refresh", "drain", "prepare-export", "transfer"])
    parser.add_argument("--maximum-seconds", type=int, default=10)
    parser.add_argument("--transfer-id", help="stable ID for an exact frozen export")
    parser.add_argument("--output", type=Path, help="new private signed snapshot file")
    parser.add_argument("--grant", type=Path, help="independently issuer-authorized directed transfer grant")
    parser.add_argument("--maximum-objects", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        relay = Relay(args.config)
        if args.operation == "refresh":
            result = refresh(relay, maximum_seconds=args.maximum_seconds)
        elif args.operation == "drain":
            refresh(relay, maximum_seconds=args.maximum_seconds)
            result = relay.drain()
        elif args.operation == "prepare-export":
            from memory_vault_node_transfer import prepare_export
            if args.transfer_id is None or args.output is None:
                raise RelayError("relay_export_id_and_output_required")
            output = storage.validate_path(args.output)
            if output.exists() or output.is_symlink():
                raise RelayError("relay_export_new_path_required")
            storage.check_private_directory(output.parent)
            deadline = time.monotonic() + args.maximum_seconds
            refresh(relay, maximum_seconds=args.maximum_seconds)
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                raise RelayError("relay_budget_exhausted", retryable=True)
            snapshot = prepare_export(relay, args.transfer_id, maximum_seconds=remaining)
            storage.atomic_write(output, canonical_bytes(snapshot) + b"\n", replace=False)
            result = {"state": "node_export_prepared", "snapshot": str(output),
                      "snapshot_sha256": document_sha256(snapshot), "source_data_deleted": False,
                      "issuer_transfer_grant_required": True, "safe_to_remove": False}
        elif args.operation == "transfer":
            from memory_vault_node_transfer import transfer
            from memory_vault_relay import _read
            if args.grant is None:
                raise RelayError("relay_transfer_grant_required")
            grant = document(_read(storage.validate_path(args.grant), 16384), maximum=16384)
            result = transfer(relay, grant, maximum_objects=args.maximum_objects,
                              maximum_seconds=args.maximum_seconds)
        else:
            result = inspect(relay)
        write_response(success(result))
        if args.operation == "transfer" and result["state"] != "exit_ready":
            return 2
        return 0
    except (MemoryError, TrustError, storage.StorageError) as exc:
        write_response(failure(exc.code, retryable=getattr(exc, "retryable", False)))
    except (OSError, ValueError, TypeError, KeyError):
        write_response(failure("relay_maintenance_unavailable"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
