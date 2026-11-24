"""Append-only, water-marked multi-tenant policy log.

Facts are appended as events.  Each ``(tenant, stream)`` pair has its own
monotonic water-mark:

* stream ``auth`` covers role edges, assignments and permission rules,
* stream ``sod``  covers separation-of-duties constraints.

An event only participates in a fold when its per-key water-mark is at or
below the *effective* water-mark for that key.  This lets a late revocation be
appended while staying invisible until its water-mark is advanced, and lets a
sealed version fold the exact historical prefix forever.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Any

from .world import COLLECTIONS, WorldDef

AUTH = "auth"
SOD = "sod"


def wm_key(tenant: str, stream: str) -> str:
    return f"{tenant}:{stream}"


class PolicyLog:
    def __init__(self, topology: WorldDef | None = None) -> None:
        # Topology = slowly-changing identity data: tenants, controllers,
        # principals, resources, roles.  Water-marked collections are folded
        # from events.
        self.topology: WorldDef = deepcopy(topology) if topology else {}
        self.events: list[dict[str, Any]] = []
        self._last_wm: dict[str, int] = defaultdict(int)
        #: Effective (visible) water-mark per ``tenant:stream``.
        self.effective: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    # Appending events (does not move any effective water-mark)
    # ------------------------------------------------------------------ #
    def add(
        self,
        collection: str,
        item: dict[str, Any],
        tenant: str,
        stream: str = AUTH,
    ) -> dict[str, Any]:
        key = wm_key(tenant, stream)
        self._last_wm[key] += 1
        event = {
            "seq": len(self.events) + 1,
            "tenant": tenant,
            "stream": stream,
            "wm": self._last_wm[key],
            "op": "add",
            "collection": collection,
            "item": deepcopy(item),
        }
        self.events.append(event)
        return event

    def revoke(
        self,
        collection: str,
        fact_id: str,
        tenant: str,
        stream: str = AUTH,
    ) -> dict[str, Any]:
        key = wm_key(tenant, stream)
        self._last_wm[key] += 1
        event = {
            "seq": len(self.events) + 1,
            "tenant": tenant,
            "stream": stream,
            "wm": self._last_wm[key],
            "op": "revoke",
            "collection": collection,
            "fact_id": fact_id,
        }
        self.events.append(event)
        return event

    def latest_watermark(self, tenant: str, stream: str) -> int:
        return self._last_wm.get(wm_key(tenant, stream), 0)

    def advance(self, tenant: str, stream: str, mark: int | None = None) -> int:
        """Advance the effective water-mark; defaults to the latest event."""
        key = wm_key(tenant, stream)
        target = self._last_wm[key] if mark is None else mark
        self.effective[key] = max(self.effective.get(key, 0), target)
        return self.effective[key]

    def expose_all_latest(self) -> dict[str, int]:
        for key, mark in list(self._last_wm.items()):
            self.effective[key] = mark
        return dict(self.effective)

    def watermark_vector(self) -> dict[str, int]:
        return dict(sorted(self.effective.items()))

    # ------------------------------------------------------------------ #
    # Folding
    # ------------------------------------------------------------------ #
    def fold(self, vector: dict[str, int] | None = None) -> WorldDef:
        """Fold visible events into an effective :class:`WorldDef`."""
        frontier = dict(self.effective if vector is None else vector)
        revoked: set[tuple[str, str]] = set()
        added: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for ev in self.events:
            key = wm_key(ev["tenant"], ev["stream"])
            if ev["wm"] > frontier.get(key, 0):
                continue
            if ev["op"] == "revoke":
                revoked.add((ev["collection"], ev["fact_id"]))
            elif ev["op"] == "add":
                added[ev["collection"]].append(deepcopy(ev["item"]))

        defn: WorldDef = deepcopy(self.topology)
        for collection in COLLECTIONS:
            items = added.get(collection, [])
            defn[collection] = [
                item
                for item in items
                if (collection, str(item.get("id"))) not in revoked
            ]
        defn["watermarks"] = dict(sorted(frontier.items()))
        return defn
