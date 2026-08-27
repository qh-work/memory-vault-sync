"""Self-contained standard-library runtime for Memory Vault Sync.

The package deliberately has no import-time filesystem or network work.
``vault_sync.py`` is the stable executable boundary; ``core`` owns command
dispatch while focused modules own protocol primitives and error categories.
"""

from __future__ import annotations

__all__ = [
    "bundle",
    "checkpoint",
    "chunks",
    "core",
    "crypto_adapter",
    "device_trust",
    "diagnostics",
    "encrypted_replication",
    "errors",
    "graph_views",
    "privacy",
    "packs",
    "protocol",
    "retrieval",
    "sharing",
    "signed_updates",
    "transport",
]
