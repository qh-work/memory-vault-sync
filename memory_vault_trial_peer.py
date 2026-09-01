"""Bounded synthetic reference peer for the hosted trial network.

The peer never executes message content.  It only answers the exact generated
trial nonce grammar after the received evidence has been saved and recalled by
its own endpoint.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Mapping

from memory_vault_agent import Agent
from memory_vault_network import NetworkClient
from memory_vault_trial import SYNTHETIC_PREFIX, SYNTHETIC_REPLY_PREFIX, _recall_text


_MESSAGE = re.compile(re.escape(SYNTHETIC_PREFIX) + r"([0-9a-f]{64})")


class SyntheticReferencePeer:
    def __init__(self, client_config: Path, network_config: Path, *, transport: Any = None):
        self.client_config = client_config
        self.network_config = network_config
        self.transport = transport
        self.agent = Agent(client_config, network_config, transport=transport)

    def step(self, limit: int = 4) -> dict[str, Any]:
        with NetworkClient(self.network_config, transport=self.transport) as network:
            pump = network.pump(maximum_messages=4, maximum_seconds=5, receive_limit=0)
        received = self.agent.handle({"op": "receive", "limit": limit})
        if received.get("ok") is not True:
            error = received.get("error", {})
            return {"received": 0, "replied": 0, "rejected": 0,
                    "retryable": bool(error.get("retryable", False)), "error_code": error.get("code")}
        messages = received["result"].get("messages", [])
        replied = rejected = 0
        for message in messages:
            match = _MESSAGE.fullmatch(message.get("text", "")) if isinstance(message, Mapping) else None
            memory_id = message.get("text_memory_id") if isinstance(message, Mapping) else None
            if (not isinstance(message, Mapping) or message.get("state") != "validated_saved" or match is None
                    or not isinstance(memory_id, str)
                    or _recall_text(self.agent, memory_id) != message["text"]):
                rejected += 1
                continue
            nonce = match.group(1)
            source = message["message_id"]
            response = self.agent.handle({"op": "send",
                "request_id": "req_trial_reply_" + hashlib.sha256(source.encode("ascii")).hexdigest()[:32],
                "recipients": [message["sender_key_id"]],
                "text": SYNTHETIC_REPLY_PREFIX + nonce + " source=" + source})
            if response.get("ok") is True and response["result"].get("state") in {"stored", "queued_local"}:
                replied += 1
            else:
                rejected += 1
        return {"received": len(messages), "replied": replied, "rejected": rejected,
                "retryable": (pump.get("retryable") is True
                    or any(error.get("retryable", False) for error in received["result"].get("errors", []))),
                "error_code": None}

    def serve(self, *, interval_seconds: float = 0.5, maximum_steps: int | None = None) -> dict[str, int]:
        totals = {"received": 0, "replied": 0, "rejected": 0}
        steps = 0
        while maximum_steps is None or steps < maximum_steps:
            result = self.step()
            for key in totals:
                totals[key] += result[key]
            steps += 1
            if maximum_steps is None or steps < maximum_steps:
                time.sleep(interval_seconds)
        return totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the isolated Memory Vault synthetic reference peer")
    parser.add_argument("--client-config", required=True, type=Path)
    parser.add_argument("--network-config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval-seconds", type=float, default=0.5)
    args = parser.parse_args(argv)
    peer = SyntheticReferencePeer(args.client_config, args.network_config)
    result = peer.serve(interval_seconds=args.interval_seconds, maximum_steps=1 if args.once else None)
    print(json.dumps({"ok": True, "synthetic_only": True, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
