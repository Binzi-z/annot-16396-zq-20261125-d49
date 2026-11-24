"""Minimum emergency-exception selection.

Two exact procedures are provided:

* :func:`enumerate_exception_sets` — the small-scale *independent oracle*:
  walks every ``2**k`` subset and records feasibility / coverage / SoD.
* :func:`solve_min_exceptions` — minimum-cardinality search that scans
  cardinalities ascending and combinations in the fixed ID order, so the
  first feasible set is exactly the canonical tie-break winner.

Both call the same semantic :func:`evaluate_subset`, guaranteeing the
certificate means what the enumeration says; the randomized cross-check in
the test suite additionally compares the solver against the full oracle.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any

from .evaluate import evaluate_coverage, evaluate_sod_controller
from .world import World, world_with_exceptions


def sorted_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(candidates, key=lambda c: c["id"])


def evaluate_subset(
    base: World | dict[str, Any],
    candidates: list[dict[str, Any]],
    selected_ids: list[str] | tuple[str, ...] | set[str],
    requirements: list[dict[str, str]],
    principal: str,
) -> dict[str, Any]:
    """Feasibility + evidence for one chosen exception subset."""
    world = world_with_exceptions(base, candidates, selected_ids)
    coverage = evaluate_coverage(world, principal, requirements)
    sod = evaluate_sod_controller(world)

    uncovered = [
        {
            "permission": item["permission"],
            "decision": item["decision"],
            "blocking_deny_sources": item["blocking_deny_sources"],
        }
        for item in coverage["items"]
        if not item["allowed"]
    ]
    sod_violations = [c for c in sod["relevant_checks"] if c["violated"]]

    return {
        "selected": sorted(selected_ids),
        "size": len(set(selected_ids)),
        "feasible": coverage["covered"] and sod["ok"],
        "coverage_ok": coverage["covered"],
        "sod_ok": sod["ok"],
        "uncovered": uncovered,
        "sod_violations": sod_violations,
        "coverage": coverage,
        "sod": sod,
    }


def _canonical_key(selected: tuple[str, ...], rank: dict[str, int]):
    # Fixed total order: compare by fixed rank vector.  IDs are already in
    # ascending fixed order because subsets are generated from sorted IDs.
    return tuple(rank[x] for x in selected)


def enumerate_exception_sets(
    base: World | dict[str, Any],
    candidates: list[dict[str, Any]],
    requirements: list[dict[str, str]],
    principal: str,
) -> dict[str, Any]:
    """Exhaustively enumerate every exception subset (small instances)."""
    cands = sorted_candidates(candidates)
    ids = [c["id"] for c in cands]
    rank = {cid: i for i, cid in enumerate(ids)}
    k = len(ids)

    subsets: list[dict[str, Any]] = []
    feasible_sets: list[tuple[str, ...]] = []
    for mask in range(1 << k):
        selected = tuple(ids[i] for i in range(k) if mask & (1 << i))
        verdict = evaluate_subset(base, cands, selected, requirements, principal)
        row = {
            "mask": mask,
            "selected": list(selected),
            "size": len(selected),
            "feasible": verdict["feasible"],
            "coverage_ok": verdict["coverage_ok"],
            "sod_ok": verdict["sod_ok"],
            "uncovered_count": len(verdict["uncovered"]),
            "sod_violation_count": len(verdict["sod_violations"]),
        }
        subsets.append(row)
        if verdict["feasible"]:
            feasible_sets.append(selected)

    optimum_size: int | None
    canonical: tuple[str, ...] | None
    winners: list[tuple[str, ...]]
    if not feasible_sets:
        optimum_size = None
        canonical = None
        winners = []
    else:
        optimum_size = min(len(s) for s in feasible_sets)
        winners = sorted(
            (s for s in feasible_sets if len(s) == optimum_size),
            key=lambda s: _canonical_key(s, rank),
        )
        canonical = winners[0]

    return {
        "candidate_ids": ids,
        "candidate_count": k,
        "enumerated_subset_count": 1 << k,
        "feasible_count": len(feasible_sets),
        "optimum_size": optimum_size,
        "canonical_winner": list(canonical) if canonical is not None else None,
        "same_cost_winners": [list(w) for w in winners],
        "subsets": subsets,
    }


def solve_min_exceptions(
    base: World | dict[str, Any],
    candidates: list[dict[str, Any]],
    requirements: list[dict[str, str]],
    principal: str,
) -> dict[str, Any]:
    """Exact minimum-cardinality, fixed-order canonical solver.

    Scans cardinality ``0..k`` and combinations in lexicographic fixed order;
    the first feasible verdict is therefore the canonical same-cost winner.
    """
    cands = sorted_candidates(candidates)
    ids = [c["id"] for c in cands]
    k = len(ids)

    evaluated = 0
    for size in range(0, k + 1):
        for combo in combinations(range(k), size):
            selected = tuple(ids[i] for i in combo)
            evaluated += 1
            verdict = evaluate_subset(base, cands, selected, requirements, principal)
            if verdict["feasible"]:
                return {
                    "status": "feasible",
                    "chosen": list(selected),
                    "optimum_size": size,
                    "evaluated_subsets": evaluated,
                    "tie_break": "min-cardinality then lexicographic-smallest sorted fixed ID order",
                    "verdict": verdict,
                }

    # Recompute the blocking picture for the empty set to explain infeasibility.
    empty = evaluate_subset(base, cands, (), requirements, principal)
    return {
        "status": "infeasible",
        "chosen": [],
        "optimum_size": None,
        "evaluated_subsets": evaluated,
        "tie_break": "min-cardinality then lexicographic-smallest sorted fixed ID order",
        "verdict": empty,
    }


def candidate_coverage_table(
    base: World | dict[str, Any],
    candidates: list[dict[str, Any]],
    requirements: list[dict[str, str]],
    principal: str,
) -> list[dict[str, Any]]:
    """Which requirements each single candidate makes allowed (reporting)."""
    rows = []
    for cand in sorted_candidates(candidates):
        cid = cand["id"]
        verdict = evaluate_subset(base, candidates, [cid], requirements, principal)
        cov = verdict["coverage"]
        rows.append(
            {
                "id": cid,
                "alone_covers": [
                    item["permission"] for item in cov["items"] if item["allowed"]
                ],
                "alone_sod_ok": verdict["sod_ok"],
            }
        )
    return rows
