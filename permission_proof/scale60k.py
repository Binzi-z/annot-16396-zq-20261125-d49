"""Deterministic 60,000-role-edge scale / incremental consistency check.

The synthetic graph is constructed with exactly :data:`TARGET_ROLE_EDGES`
unique directed role-inheritance edges arranged into :data:`COMPONENT_COUNT`
disconnected weak components (each internally a connected tree plus seeded
extra edges, so many SCC cycles appear).

One resource-side rule (``RR-TRACK``) is then changed: its target resource
moves from ``res.only_a`` to ``res.bridge``.  In the combined
role/resource graph this bridges two formerly separate components.  An
affected-component tracker applies the single changeset locally; the result is
cross-checked against a complete from-scratch BFS recomputation and an
independent DSU partition ("full consistency").
"""

from __future__ import annotations

import random
import time
from typing import Any

from .graph import (
    TrackedComponents,
    dsu_partition,
    kosaraju_scc,
    partitions_equal,
    weak_component_partition,
)

SEED = 16396
TARGET_ROLE_EDGES = 60_000
COMPONENT_COUNT = 40
ROLES_PER_COMPONENT = 400
LEAF_RESOURCE_RULES = 1_800

ROLE_A = "r00_0010"
ROLE_A_BACKUP = "r00_0011"
ROLE_B = "r01_0020"
RES_ONLY_A = "res.only_a"
RES_BRIDGE = "res.bridge"


def _role(comp: int, idx: int) -> str:
    return f"r{comp:02d}_{idx:04d}"


def generate_role_edges() -> list[tuple[str, str]]:
    rng = random.Random(SEED)
    edges: set[tuple[str, str]] = set()

    # Connected parent-lower-index tree inside each component.
    for c in range(COMPONENT_COUNT):
        for i in range(1, ROLES_PER_COMPONENT):
            parent_idx = rng.randrange(i)
            edges.add((_role(c, i), _role(c, parent_idx)))

    # Seeded intra-component extra edges until the exact target is reached.
    while len(edges) < TARGET_ROLE_EDGES:
        c = rng.randrange(COMPONENT_COUNT)
        i = rng.randrange(ROLES_PER_COMPONENT)
        j = rng.randrange(ROLES_PER_COMPONENT)
        if i == j:
            continue
        edges.add((_role(c, i), _role(c, j)))

    if len(edges) != TARGET_ROLE_EDGES:
        raise AssertionError(f"wanted exactly 60000 edges, got {len(edges)}")
    return sorted(edges)


def build_resource_rules() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Return leaf rules plus the tracked rule in v1 and v2 forms."""
    rules: list[dict[str, Any]] = []
    connectivity: list[tuple[str, str]] = []
    for t in range(LEAF_RESOURCE_RULES):
        c = t % COMPONENT_COUNT
        idx = 50 + (t % (ROLES_PER_COMPONENT - 60))
        holder = _role(c, idx)
        resource = f"res.leaf_{t:05d}"
        rules.append(
            {
                "id": f"RR-LEAF-{t:05d}",
                "side": "resource",
                "holder_type": "role",
                "holder": holder,
                "resource": resource,
                "action": "read",
                "effect": "allow",
            }
        )
        connectivity.append((holder, resource))

    backup_rule = {
        "id": "RR-BACKUP-ONLY-A",
        "side": "resource",
        "holder_type": "role",
        "holder": ROLE_A_BACKUP,
        "resource": RES_ONLY_A,
        "action": "read",
        "effect": "allow",
    }
    anchor_rule = {
        "id": "RR-BRIDGE-ANCHOR",
        "side": "resource",
        "holder_type": "role",
        "holder": ROLE_B,
        "resource": RES_BRIDGE,
        "action": "read",
        "effect": "allow",
    }
    tracked_v1 = {
        "id": "RR-TRACK",
        "side": "resource",
        "holder_type": "role",
        "holder": ROLE_A,
        "resource": RES_ONLY_A,
        "action": "read",
        "effect": "allow",
    }
    tracked_v2 = dict(tracked_v1)
    tracked_v2["resource"] = RES_BRIDGE

    for rule in (backup_rule, anchor_rule, tracked_v1):
        connectivity.append((rule["holder"], rule["resource"]))

    rules.extend([backup_rule, anchor_rule, tracked_v1])
    return rules, tracked_v1, tracked_v2


def run_scale_check() -> dict[str, Any]:
    started = time.perf_counter()
    role_edges = generate_role_edges()
    assert len(role_edges) == 60_000

    # --- Role-graph components (two independent methods) ------------------
    role_bfs = weak_component_partition(role_edges)
    role_dsu = dsu_partition(role_edges)
    role_wcc_count = len(role_bfs)
    role_wcc_consistent = partitions_equal(role_bfs, role_dsu)

    scc = kosaraju_scc(role_edges)
    cyclic_ids = scc.cyclic_component_ids(role_edges)

    # --- Combined role + resource graph at v1 ------------------------------
    all_resource_rules, tracked_v1, tracked_v2 = build_resource_rules()
    resource_connectivity = [
        (r["holder"], r["resource"]) for r in all_resource_rules
    ]
    combined_v1_edges = list(role_edges) + resource_connectivity

    full_v1 = weak_component_partition(combined_v1_edges)
    tracker = TrackedComponents.from_edges(combined_v1_edges)
    v1_tracker_matches = tracker.matches_full_recompute()
    v1_count_full = len(full_v1)
    v1_count_tracker = tracker.count

    # --- The single resource-side rule change ------------------------------
    removed = [(ROLE_A, RES_ONLY_A)]
    added = [(ROLE_A, RES_BRIDGE)]
    after_count = tracker.apply_changeset(removed_edges=removed, added_edges=added)

    combined_v2_edges = list(role_edges) + [
        e for e in resource_connectivity if e != (ROLE_A, RES_ONLY_A)
    ]
    # resource_connectivity includes tracked v1 edge (ROLE_A, ONLY_A); the
    # list comprehension above removes it; backup edge is a different pair.
    combined_v2_edges.append((ROLE_A, RES_BRIDGE))

    full_v2 = weak_component_partition(combined_v2_edges)
    dsu_v2 = dsu_partition(combined_v2_edges)
    v2_count_full = len(full_v2)
    v2_count_dsu = len(dsu_v2)
    tracker_matches_full = tracker.matches_full_recompute()
    tracker_partition_matches_bfs = partitions_equal(tracker.partition(), full_v2)
    dsu_matches_bfs = partitions_equal(dsu_v2, full_v2)

    # Role-only components must be untouched by a resource-side change.
    role_bfs_after = weak_component_partition(role_edges)
    role_components_unchanged = partitions_equal(role_bfs, role_bfs_after)

    # Sanity: the change really did merge exactly two components.
    expected_after = v1_count_full - 1

    checks = {
        "exactly_60000_role_edges": len(role_edges) == TARGET_ROLE_EDGES,
        "role_wcc_count_is_40_by_construction": role_wcc_count == COMPONENT_COUNT,
        "role_wcc_dsu_matches_bfs": role_wcc_consistent,
        "v1_tracker_matches_full": v1_tracker_matches
        and v1_count_tracker == v1_count_full,
        "v1_combined_count_is_40": v1_count_full == COMPONENT_COUNT,
        "one_change_merges_exactly_two": after_count == expected_after == v2_count_full,
        "v2_tracker_partition_matches_full_bfs": tracker_partition_matches_bfs,
        "v2_tracker_self_consistent": tracker_matches_full,
        "v2_dsu_partition_matches_bfs": dsu_matches_bfs,
        "role_components_unchanged_by_resource_change": role_components_unchanged,
    }
    ok = all(checks.values())

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    return {
        "id": "SCALE-60K-ONE-RESOURCE-CHANGE",
        "ok": ok,
        "checks": checks,
        "seed": SEED,
        "role_edge_count": len(role_edges),
        "role_node_count": COMPONENT_COUNT * ROLES_PER_COMPONENT,
        "role_weak_component_count": role_wcc_count,
        "role_scc_count": scc.count,
        "role_cyclic_scc_count": len(cyclic_ids),
        "leaf_resource_rule_count": LEAF_RESOURCE_RULES,
        "special_resource_rule_count": 3,
        "resource_rule_count": len(all_resource_rules),
        "combined_component_count_before": v1_count_full,
        "combined_component_count_after": v2_count_full,
        "tracker_count_after": after_count,
        "dsu_count_after": v2_count_dsu,
        "expected_after": expected_after,
        "role_components_unchanged": role_components_unchanged,
        "tracked_rule_change": {
            "rule_id": "RR-TRACK",
            "changed_fields": ["resource"],
            "before": tracked_v1,
            "after": tracked_v2,
            "removed_connectivity_edges": removed,
            "added_connectivity_edges": added,
        },
        "full_consistency": {
            "tracker_equals_full_bfs_after": tracker_partition_matches_bfs,
            "dsu_equals_full_bfs_after": dsu_matches_bfs,
            "incremental_matches_full": tracker_matches_full
            and tracker_partition_matches_bfs,
        },
        "elapsed_ms": elapsed_ms,
    }
