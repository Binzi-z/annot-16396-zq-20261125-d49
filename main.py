#!/usr/bin/env python3
"""Conventional alias for :mod:`run` / ``python -m permission_proof``.

Running ``python main.py`` executes the full offline verification harness.
"""

from __future__ import annotations

import sys
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))

from permission_proof.verify_all import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
