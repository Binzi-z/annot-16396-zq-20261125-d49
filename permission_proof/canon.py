"""Canonical JSON encoding and SHA-256 helpers.

Every certificate / sealed envelope is hashed through the same canonical
serializer so an independent verifier reproduces byte-identical digests.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_dumps(obj: Any) -> str:
    """Return the canonical JSON text used for all digests.

    Keys are sorted, non-ASCII characters are kept verbatim and separators
    are compact.  This is deterministic across CPython runs and platforms.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_dumps(obj).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    """SHA-256 hex digest of an object / string / bytes."""
    if isinstance(obj, str):
        data = obj.encode("utf-8")
    elif isinstance(obj, (bytes, bytearray)):
        data = bytes(obj)
    else:
        data = canonical_bytes(obj)
    return hashlib.sha256(data).hexdigest()


def short_digest(obj: Any, length: int = 12) -> str:
    return sha256_hex(obj)[:length]


def fixed_sorted(items) -> list:
    """The one fixed total order used for every tie-break / report list."""
    return sorted(items)
