"""Canonical permission certificates and independent re-verification."""

from __future__ import annotations

import hmac
import traceback
from copy import deepcopy
from typing import Any

from . import TIE_BREAK_RULE
from .canon import sha256_hex
from .exceptions import enumerate_exception_sets, evaluate_subset, solve_min_exceptions

CERT_SCHEMA = "perm-proof/certificate/v1"


def build_certificate(
    *,
    cert_id: str,
    title: str,
    target_change: dict[str, Any],
    principal: str,
    requirements: list[dict[str, str]],
    world_def: dict[str, Any],
    candidates: list[dict[str, Any]],
    solution: dict[str, Any],
    watermark_vector: dict[str, int] | None = None,
    logical_label: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble and sign (SHA-256) a self-contained certificate body."""
    verdict = solution["verdict"]
    coverage = verdict["coverage"]
    snapshot = deepcopy(world_def)
    body: dict[str, Any] = {
        "schema": CERT_SCHEMA,
        "cert_id": cert_id,
        "title": title,
        "logical_label": logical_label,
        "target_change": target_change,
        "principal": principal,
        "requirements": requirements,
        "tie_break_rule": TIE_BREAK_RULE,
        "watermark_vector": watermark_vector or snapshot.get("watermarks", {}),
        "world_snapshot_digest": sha256_hex(snapshot),
        "world_snapshot": snapshot,
        "candidates": candidates,
        "status": solution["status"],
        "chosen_exceptions": solution["chosen"],
        "optimum_size": solution["optimum_size"],
        "evaluated_subsets_for_solver": solution.get("evaluated_subsets"),
        "coverage": coverage,
        "sod": verdict["sod"],
        "all_retained_sources": coverage["all_retained_sources"],
    }
    if extra:
        body["extra"] = extra
    body["cert_hash"] = sha256_hex({k: v for k, v in body.items() if k != "cert_hash"})
    return body


def _check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def _hash_eq(claimed: Any, actual: str) -> bool:
    """compare_digest only accepts ASCII str; treat anything else as mismatch."""
    try:
        return bool(claimed) and hmac.compare_digest(str(claimed), actual)
    except (TypeError, ValueError):
        return False


def verify_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    """Independently recompute every claim made by a certificate.

    This function is total: a malformed or tampered certificate yields
    ``valid=False`` with a failed check rather than raising.
    """
    checks: list[dict[str, Any]] = []
    enum_summary: dict[str, Any] | None = None

    if not isinstance(cert, dict):
        return {
            "valid": False,
            "cert_id": None,
            "check_count": 1,
            "passed_count": 0,
            "checks": [_check("certificate_is_object", False, f"got {type(cert)!r}")],
            "enumeration_summary": None,
        }

    claimed_hash = cert.get("cert_hash")
    hash_error: str | None = None
    try:
        recomputed_hash = sha256_hex(
            {k: v for k, v in cert.items() if k != "cert_hash"}
        )
    except Exception as exc:  # noqa: BLE001 - non-canonical / malicious JSON
        recomputed_hash = ""
        hash_error = f"canonical encoding failed: {exc!r}"
    hash_ok = hash_error is None and _hash_eq(claimed_hash, recomputed_hash)
    checks.append(
        _check("cert_hash_integrity", hash_ok, hash_error or recomputed_hash)
    )

    world_def = cert.get("world_snapshot", {})
    snapshot_error: str | None = None
    try:
        snapshot_digest = sha256_hex(world_def)
    except Exception as exc:  # noqa: BLE001
        snapshot_digest = ""
        snapshot_error = f"canonical encoding failed: {exc!r}"
    checks.append(
        _check(
            "world_snapshot_digest",
            snapshot_error is None
            and _hash_eq(cert.get("world_snapshot_digest", ""), snapshot_digest),
            snapshot_error or snapshot_digest,
        )
    )
    if snapshot_error is not None or not isinstance(world_def, dict):
        if not isinstance(world_def, dict):
            checks.append(
                _check("world_snapshot_is_object", False, f"got {type(world_def)!r}")
            )
        return {
            "valid": False,
            "cert_id": cert.get("cert_id"),
            "check_count": len(checks),
            "passed_count": sum(1 for c in checks if c["ok"]),
            "checks": checks,
            "enumeration_summary": None,
        }

    wm = cert.get("watermark_vector", {})
    checks.append(
        _check(
            "watermark_vector_matches_snapshot",
            wm == world_def.get("watermarks", {}),
            f"cert={wm} snapshot={world_def.get('watermarks', {})}",
        )
    )

    try:
        principal = cert["principal"]
        requirements = cert["requirements"]
        candidates = cert.get("candidates", [])
        chosen = list(cert.get("chosen_exceptions", []))

        # Independent semantic recomputation of the chosen set.
        verdict = evaluate_subset(world_def, candidates, chosen, requirements, principal)
        checks.append(_check("chosen_set_feasible", verdict["feasible"]))
        checks.append(_check("coverage_ok_recomputed", verdict["coverage_ok"]))
        checks.append(_check("sod_ok_recomputed", verdict["sod_ok"]))

        embedded_sources = list(cert.get("all_retained_sources", []))
        recomputed_sources = verdict["coverage"]["all_retained_sources"]
        checks.append(
            _check(
                "all_retained_sources_exact",
                embedded_sources == recomputed_sources,
                f"embedded={embedded_sources} recomputed={recomputed_sources}",
            )
        )

        embedded_cov_sources = [
            (i["permission"], i["retained_sources"])
            for i in cert.get("coverage", {}).get("items", [])
        ]
        recomputed_cov_sources = [
            (i["permission"], i["retained_sources"])
            for i in verdict["coverage"]["items"]
        ]
        checks.append(
            _check(
                "per_resource_retained_sources_exact",
                embedded_cov_sources == recomputed_cov_sources,
            )
        )

        checks.append(
            _check(
                "sod_violation_count_exact",
                cert.get("sod", {}).get("violation_count")
                == verdict["sod"]["violation_count"],
            )
        )

        # Minimum + fixed-order canonical winner via full independent enumeration.
        enum = enumerate_exception_sets(world_def, candidates, requirements, principal)
        canonical = enum["canonical_winner"] or []
        checks.append(
            _check(
                "chosen_is_canonical_minimum",
                enum["optimum_size"] == cert.get("optimum_size")
                and canonical == chosen
                and cert.get("status") == "feasible",
                f"enum_opt={enum['optimum_size']} canonical={canonical} chosen={chosen}",
            )
        )

        # The ordered solver must agree with the enumeration oracle.
        solver = solve_min_exceptions(world_def, candidates, requirements, principal)
        checks.append(
            _check(
                "solver_agrees_with_enumeration",
                solver["status"] == cert.get("status")
                and solver["chosen"] == canonical
                and solver["optimum_size"] == enum["optimum_size"],
                f"solver={solver['chosen']}",
            )
        )

        # Every critical requirement must truly be allowed.
        checks.append(
            _check(
                "all_critical_resources_allowed",
                all(i["allowed"] for i in verdict["coverage"]["items"]),
            )
        )

        enum_summary = {
            "candidate_count": enum["candidate_count"],
            "enumerated_subset_count": enum["enumerated_subset_count"],
            "feasible_count": enum["feasible_count"],
            "optimum_size": enum["optimum_size"],
            "canonical_winner": enum["canonical_winner"],
            "same_cost_winners": enum["same_cost_winners"],
        }
    except Exception:  # noqa: BLE001 - tampered / malformed certificate
        checks.append(
            _check(
                "recomputation_succeeded",
                False,
                traceback.format_exc(limit=4),
            )
        )

    valid = all(c["ok"] for c in checks)
    return {
        "valid": valid,
        "cert_id": cert.get("cert_id"),
        "check_count": len(checks),
        "passed_count": sum(1 for c in checks if c["ok"]),
        "checks": checks,
        "enumeration_summary": enum_summary,
    }
