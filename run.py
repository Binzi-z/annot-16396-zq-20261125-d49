#!/usr/bin/env python3
"""One-command end-to-end verification.

Native Windows::

    python run.py

Stdlib only; exits 0 when every required check passes, 1 otherwise.
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
