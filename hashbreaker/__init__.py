"""DARK HashBreaker Audit Package."""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.append(_HERE)

from . import hashbreaker as _core  # noqa: E401,E402
from .hashbreaker import *  # noqa: F401,F403,E402

__version__ = "4.0.0"


def __getattr__(name: str):
    return getattr(_core, name)
