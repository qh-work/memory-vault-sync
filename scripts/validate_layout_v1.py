#!/usr/bin/env python3
"""Stable entrypoint for repository history and memory-network validation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from memory_vault_validator import core as _core  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    return _core.main(argv)


def __getattr__(name: str) -> object:
    return getattr(_core, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_core)))


if __name__ == "__main__":
    raise SystemExit(main())
