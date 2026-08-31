"""One explicit, bounded native network retry/receive pass.

Importing this module starts nothing. Hosts may invoke it on their own schedule;
it creates no daemon, hook, scheduler entry, service or external-protocol adapter.
Only already configured endpoints and previously queued recipients are used.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sqlite3
from typing import Sequence

from memory_vault import MemoryError, failure, success, write_response
from memory_vault_network import NetworkClient
from memory_vault_trust import TrustError


def main(argv: Sequence[str] | None = None, *, client_config: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one bounded native outbox retry and inbox receive pass")
    parser.add_argument("--network-config", type=Path, required=True)
    parser.add_argument("--maximum-messages", type=int, default=4, help="Outbox attempts, 0..16 (default: 4)")
    parser.add_argument("--maximum-seconds", type=int, default=10,
                        help="Cooperative deadline, 1..60 seconds; in-flight OS calls are not forcibly interrupted")
    parser.add_argument("--receive-limit", type=int, default=4, help="Incoming messages, 0..4; zero disables polling")
    args = parser.parse_args(argv)
    try:
        with NetworkClient(args.network_config) as client:
            if client_config is not None and client.client_config.path != client_config.absolute():
                raise MemoryError("network_client_config_mismatch")
            result = client.pump(maximum_messages=args.maximum_messages, maximum_seconds=args.maximum_seconds,
                                 receive_limit=args.receive_limit)
        write_response(success(result))
        return 0 if result["state"] == "completed" else 2
    except (MemoryError, TrustError) as exc:
        write_response(failure(exc.code, retryable=getattr(exc, "retryable", False)))
    except (sqlite3.Error, OSError):
        write_response(failure("network_worker_storage_unavailable", retryable=True))
    except (ValueError, TypeError, KeyError):
        write_response(failure("network_worker_invalid_state"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
