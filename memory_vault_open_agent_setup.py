"""Explicitly add an open transport to an existing signed Memory Vault client.

Only a new directory, X25519 identity and open configuration are created. The
existing ClientConfig, Vault, Ed25519 identity and trust store are read-only.
File introductions are read offline. Explicit endpoint introductions fetch and
challenge only the selected HTTPS origins. Neither path approves contact,
exports memories or starts a background process.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import sys
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_control import coordinate, sign_request, verify_node, verify_response
from memory_vault_open_setup import _read_seed
from memory_vault_open_transport import OpenHTTPTransport, endpoint
from memory_vault_storage import private_directory
from memory_vault_trust import Identity, TrustError, _absolute_path, _safe_parent, _write_new_private

CONFIG_SCHEMA = "memory-vault-open-client-config/v1"


def fetch_introductions(signer, endpoints, *, allow_loopback=False, timeout=15):
    """Fetch and challenge 1–2 explicitly selected origins and expected keys.

    No redirects, proxy credentials, private destinations or ambient trust are
    inherited. A matching signed GET alone is not a successful endpoint probe.
    """
    if not isinstance(endpoints, (list, tuple)) or not 1 <= len(endpoints) <= 2:
        raise MemoryError("open_one_or_two_introductions_required")
    checked = []
    for item in endpoints:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise MemoryError("open_invalid_seed_endpoint")
        base, key_id = item
        endpoint(base, allow_loopback=allow_loopback)
        coordinate(key_id)
        checked.append((base.rstrip("/"), key_id))
    if len({key_id for _, key_id in checked}) != len(checked):
        raise MemoryError("open_duplicate_seed")
    import math
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 15:
        raise MemoryError("open_invalid_seed_endpoint")
    transport = OpenHTTPTransport(allow_loopback=allow_loopback)
    deadline = time.monotonic() + timeout
    introductions = []
    try:
        for base, key_id in checked:
            node = transport.request_node(base, deadline=deadline).response
            initial = verify_node(node)
            if (initial["status"] != "active" or initial["base_url"] != base
                    or initial["signing_key"]["key_id"] != key_id):
                raise MemoryError("open_seed_endpoint_mismatch")
            now = int(time.time())
            request = sign_request(signer, node=node, action="hello", body={"node": None},
                request_id="open_" + secrets.token_hex(16), issued_at=now, expires_at=now + 60)
            reply = transport.request(base, request, deadline=deadline)
            response = verify_response(reply.response, request=request, node=node)
            if "error" in response["body"]:
                error = response["body"]["error"]
                raise MemoryError(error["code"], retryable=error["retryable"])
            current = response["body"]["node"]
            payload = verify_node(current)
            if (payload["status"] != "active" or payload["base_url"] != base
                    or payload["revision"] < initial["revision"]
                    or (payload["revision"] == initial["revision"] and current != node)):
                raise MemoryError("open_seed_endpoint_mismatch")
            introductions.append(current)
    finally:
        transport.close()
    return introductions


def initialize_agent(client_config: Path, directory: Path, *, seeds=(), seed_endpoints=()):
    """Reuse the exact existing client and signer; refuse existing destinations."""
    config = ClientConfig.load(_absolute_path(client_config))
    directory = _absolute_path(directory)
    if config.identity_path is None:
        raise MemoryError("network_signing_identity_required")
    signer = Identity.load(config.identity_path)
    if (not isinstance(seeds, (list, tuple)) or not isinstance(seed_endpoints, (list, tuple))
            or bool(seeds) == bool(seed_endpoints) or not 1 <= len(seeds or seed_endpoints) <= 2):
        raise MemoryError("open_one_or_two_introductions_required")

    protected = [config.path, config.vault_path, config.identity_path,
                 config.trust_path, config.state_path, config.sync_config_path]
    if config.sync_config_path is not None:
        from memory_vault_client import bound_sync_config
        sync = bound_sync_config(config)
        protected.append(sync.state_directory)
        if sync.backend["kind"] == "directory":
            protected.append(Path(sync.backend["exchange"]))
    for existing in (path for path in protected if path is not None):
        if directory == existing or directory in existing.parents or existing in directory.parents:
            raise MemoryError("network_separate_state_required")

    if directory.exists() or directory.is_symlink():
        raise MemoryError("open_setup_directory_exists")
    introductions = (fetch_introductions(signer, seed_endpoints) if seed_endpoints else
                     [_read_seed(_absolute_path(Path(path)), int(time.time())) for path in seeds])
    if len({node["payload"]["signing_key"]["key_id"] for node in introductions}) != len(introductions):
        raise MemoryError("open_duplicate_seed")

    # Parent validation does not chmod existing directories. Creation is
    # exclusive: even a failed earlier initialization is never overwritten.
    _safe_parent(directory, create=True)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise MemoryError("open_setup_directory_exists") from None
    private_directory(directory, create=False)
    encryption = EncryptionIdentity.generate()
    encryption_path = directory / "encryption-identity.json"
    encryption.save(encryption_path)
    state_directory = directory / "state"
    private_directory(state_directory)
    network_config = directory / "open-config.json"
    value = {"schema_version": CONFIG_SCHEMA, "client_config_path": str(config.path),
             "state_directory": str(state_directory),
             "encryption_key_path": str(encryption_path),
             "seeds": introductions, "allow_loopback": False}
    _write_new_private(network_config, canonical_bytes(value) + b"\n")
    return {"state": "initialized", "client_config_path": str(config.path),
            "network_config_path": str(network_config),
            "signing_key_id": signer.key_id, "encryption_key_id": encryption.key_id,
            "agent_command": [sys.executable, "-B", str(Path(__file__).absolute().with_name("memory_vault_agent.py")),
                              "--client-config", str(config.path),
                              "--network-config", str(network_config), "serve"],
            "network_accessed": bool(seed_endpoints), "seed_endpoints_verified": bool(seed_endpoints),
            "vault_modified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-config", required=True, type=Path, help="existing absolute ClientConfig path with signing identity")
    parser.add_argument("--directory", required=True, type=Path, help="NEW absolute private transport directory; never overwritten")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--seed", type=Path, action="append", help="current public signed node JSON file; one or two")
    source.add_argument("--seed-endpoint", nargs=2, action="append", metavar=("HTTPS_ORIGIN", "EXPECTED_KEY_ID"),
                        help="fetch and challenge a selected operator's current introduction; one or two")
    args = parser.parse_args(argv)
    try:
        result = initialize_agent(args.client_config, args.directory, seeds=args.seed or (),
                                  seed_endpoints=args.seed_endpoint or ())
    except (MemoryError, TrustError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "open_setup_storage_unavailable")}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
