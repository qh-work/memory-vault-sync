#!/usr/bin/env python3
"""Stable command entrypoint for the self-contained Memory Vault runtime.

Implementation code lives in ``memory_vault_runtime``.  Keeping this file
small makes lifecycle hooks and operator commands stable while internal
responsibilities can evolve independently.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from memory_vault_runtime import core as _core  # noqa: E402


VERSION = "0.20.1+codex.20260827153312"
EXPECTED_CORE = (
    SCRIPT_DIRECTORY / "memory_vault_runtime" / "core.py"
).resolve()
if Path(_core.__file__).resolve() != EXPECTED_CORE:
    raise RuntimeError("runtime core was imported from an unexpected package")
if VERSION != _core.VERSION:
    raise RuntimeError("runtime entrypoint and core versions do not match")


def main(argv: Sequence[str] | None = None) -> int:
    return _core.main(argv)


def __getattr__(name: str) -> object:
    """Keep read-only import compatibility for existing maintenance tools."""

    return getattr(_core, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_core)))


if __name__ == "__main__":
    raise SystemExit(main())
