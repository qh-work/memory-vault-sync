"""Explicit operator initialization for a finite, publicly introduced open node.

Creates new protected state only. HTTPS termination and process supervision stay
with the operator; this command neither exposes plaintext nor provisions cloud.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import sys
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_network_crypto import EncryptionIdentity, document
from memory_vault_open_control import MAX_DESCRIPTOR_BYTES, MAX_DESCRIPTOR_SECONDS, issue_node, verify_node
from memory_vault_open_transport import endpoint
from memory_vault_trust import Identity, _absolute_path, _safe_parent, _write_new_private

NODE_CONFIG = "memory-vault-open-node-config/v1"


def _read_seed(path: Path, now: int):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise MemoryError("open_invalid_seed_file")
        raw = stream.read(MAX_DESCRIPTOR_BYTES + 1)
    seed = document(raw, maximum=MAX_DESCRIPTOR_BYTES)
    checked = verify_node(seed, now=now)
    if checked["status"] != "active":
        raise MemoryError("open_seed_inactive")
    endpoint(checked["base_url"], allow_loopback=False)
    # Exact node validation excludes secrets and all unknown descriptor fields.
    return seed


def initialize_node(directory: Path, *, base_url: str, listen_port: int = 8787, seeds=()):
    directory = _absolute_path(directory)
    endpoint(base_url, allow_loopback=False)
    if type(listen_port) is not int or not 1024 <= listen_port <= 65535:
        raise MemoryError("open_invalid_listener")
    if not isinstance(seeds, (list, tuple)) or len(seeds) > 2:
        raise MemoryError("open_two_initial_introductions_maximum")
    now = int(time.time())
    introductions = [_read_seed(Path(path), now) for path in seeds]
    if len({node["payload"]["signing_key"]["key_id"] for node in introductions}) != len(introductions):
        raise MemoryError("open_duplicate_seed")
    # Validate parents without changing their permissions. mkdir is exclusive;
    # retries cannot replace another node or a partially initialized identity.
    _safe_parent(directory, create=True)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise MemoryError("open_setup_directory_exists") from None
    identity_path = directory / "signing-identity.json"
    encryption_path = directory / "encryption-identity.json"
    config_path = directory / "node-config.json"
    introduction_path = directory / "node-introduction.json"
    state_directory = directory / "state"
    signer = Identity.generate(identity_path)
    encryption = EncryptionIdentity.generate()
    encryption.save(encryption_path)
    state_directory.mkdir(mode=0o700)
    descriptor = issue_node(signer, base_url=base_url, storage_epoch="epoch_" + secrets.token_hex(32),
                            roles=["directory", "router"], revision=1,
                            issued_at=now, expires_at=now + MAX_DESCRIPTOR_SECONDS)
    # Running this initialization is the explicit operator choice to offer
    # these finite services. Ordinary profile loading never turns them on.
    config = {
        "schema_version": NODE_CONFIG,
        "identity_path": str(identity_path), "encryption_key_path": str(encryption_path),
        "state_directory": str(state_directory), "node": descriptor,
        "seeds": introductions, "allow_loopback": False,
        "listen_host": "127.0.0.1", "listen_port": listen_port,
        "index_policy": {"enabled": True, "maximum_records": 128,
                         "maximum_bytes": 2 * 1024 * 1024, "maximum_replays": 512,
                         "maximum_lease_seconds": 600},
        "contact_policy": {"enabled": True, "maximum_leases": 128,
                           "maximum_knock_items": 1024, "maximum_knock_bytes": 16 * 1024 * 1024,
                           "maximum_delivery_items": 1024, "maximum_delivery_bytes": 64 * 1024 * 1024,
                           "maximum_challenges": 128, "maximum_challenge_bytes": 1024 * 1024},
        "delivery_policy": {"enabled": True, "maximum_bytes": 64 * 1024 * 1024,
                            "maximum_items": 512, "maximum_handles": 64, "maximum_challenges": 128},
        "provider_policy": {"enabled": True, "policy": {
            "maximum_leases": 128, "maximum_facts": 512, "maximum_replays": 4096,
            "maximum_state_bytes": 64 * 1024 * 1024, "maximum_live_bytes": 64 * 1024 * 1024,
            "maximum_meta_bytes": 64 * 1024 * 1024, "maximum_requests": 65536,
            "maximum_pending": 1024, "maximum_jobs": 4096, "maximum_job_bytes": 16 * 1024 * 1024}},
    }
    _write_new_private(config_path, canonical_bytes(config) + b"\n")
    # This file alone is shareable. It contains a signed public introduction,
    # never the config, filesystem paths or either private identity document.
    _write_new_private(introduction_path, canonical_bytes(descriptor))
    command = [sys.executable, "-B", str(Path(__file__).absolute().with_name("memory_vault_open_node.py")),
               "--config", str(config_path)]
    return {
        "state": "initialized", "config_path": str(config_path),
        "public_introduction_path": str(introduction_path),
        "node_key_id": signer.key_id, "base_url": base_url,
        "public_introduction_url": base_url.rstrip("/") + "/open/v1/node",
        "introduction_expires_at": descriptor["payload"]["expires_at"],
        "start_command": shlex.join(command),
        "https_forward_to": "http://127.0.0.1:" + str(listen_port),
        "https_paths": ["/open/v1/node", "/open/v1/rpc", "/open/v1/blob"],
        "network_started": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Initialize a NEW node with finite routing, contact, delivery and provider services")
    parser.add_argument("--directory", required=True, type=Path, help="new absolute directory; existing directories are never overwritten")
    parser.add_argument("--base-url", required=True, help="your deployed public HTTPS origin")
    parser.add_argument("--listen-port", type=int, default=8787, help="local 127.0.0.1 port behind your HTTPS terminator (default: 8787)")
    parser.add_argument("--seed", type=Path, action="append", default=[], help="public signed node JSON file; repeat at most twice")
    args = parser.parse_args(argv)
    try:
        result = initialize_node(args.directory, base_url=args.base_url, listen_port=args.listen_port, seeds=args.seed)
    except (MemoryError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "open_setup_storage_unavailable")}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
