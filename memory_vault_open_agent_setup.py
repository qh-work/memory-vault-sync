"""Explicitly add an open transport to an existing signed Memory Vault client.

Only a new directory, X25519 identity and open configuration are created. The
existing ClientConfig, Vault, Ed25519 identity and trust store are read-only.
No network, contact approval, memory export or background process is started.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from memory_vault import MemoryError, canonical_bytes
from memory_vault_client import ClientConfig
from memory_vault_network_crypto import EncryptionIdentity
from memory_vault_open_setup import _read_seed
from memory_vault_storage import private_directory
from memory_vault_trust import Identity, TrustError, _absolute_path, _safe_parent, _write_new_private

CONFIG_SCHEMA = "memory-vault-open-client-config/v1"


def initialize_agent(client_config: Path, directory: Path, *, seeds):
    """Reuse the exact existing client and signer; refuse existing destinations."""
    config = ClientConfig.load(_absolute_path(client_config))
    directory = _absolute_path(directory)
    if config.identity_path is None:
        raise MemoryError("network_signing_identity_required")
    signer = Identity.load(config.identity_path)
    if not isinstance(seeds, (list, tuple)) or not 1 <= len(seeds) <= 2:
        raise MemoryError("open_one_or_two_introductions_required")
    now = int(time.time())
    introductions = [_read_seed(_absolute_path(Path(path)), now) for path in seeds]
    if len({node["payload"]["signing_key"]["key_id"] for node in introductions}) != len(introductions):
        raise MemoryError("open_duplicate_seed")

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
            "network_accessed": False, "vault_modified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-config", required=True, type=Path, help="existing absolute ClientConfig path with signing identity")
    parser.add_argument("--directory", required=True, type=Path, help="NEW absolute private transport directory; never overwritten")
    parser.add_argument("--seed", required=True, type=Path, action="append", help="current public signed node JSON file; one or two")
    args = parser.parse_args(argv)
    try:
        result = initialize_agent(args.client_config, args.directory, seeds=args.seed)
    except (MemoryError, TrustError, OSError) as exc:
        print(json.dumps({"error": getattr(exc, "code", "open_setup_storage_unavailable")}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
