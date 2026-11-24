"""DARK API & Enterprise Core Package."""
from __future__ import annotations

import sys
from pathlib import Path

_PKG_DIR = str(Path(__file__).resolve().parent)
_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))
for _sub in (_PKG_DIR, str(_ROOT_DIR / "modules"), str(_ROOT_DIR / "webvulnx"),
             str(_ROOT_DIR / "netrecon"), str(_ROOT_DIR / "netsentry"), str(_ROOT_DIR / "hashbreaker")):
    if Path(_sub).is_dir() and _sub not in sys.path:
        sys.path.append(_sub)

__version__ = "4.0.0"
