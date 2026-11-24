"""Ensure repository root precedes tool subdirectories on sys.path during pytest."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent)
if ROOT in sys.path:
    sys.path.remove(ROOT)
sys.path.insert(0, ROOT)
