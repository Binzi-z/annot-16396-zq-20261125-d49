"""Effective permissions (deny overrides) and controller-level SoD."""

from __future__ import annotations

from collections import deque
from typing import Any

from .canon import fixed_sorted
from .world import World, assignment_source, rule_source


# --------------------------------------------------------------------------- #
# Witness paths
# --------------------------------------------------------------------------- #
def best_inheritance_path(world: World, principal_id: str, target: str) -> list[str]:
    """Deterministic shortest assigned-role -> target inheritance path."""
    starts = fixed_sorted(world.assigned_roles(principal_id))
    if target in starts:
        return [target]
    parent: dict[str, str | None] = {s: None for s in starts}
    q: deque[str] = deque(starts)
    found = False
    while q and not found:
        u = q.popleft()
        for v in fixed_sorted(world.parents.get(u, ())):
            if v not in parent:
                parent[v] = u
                if v == target:
                    found = True
                    break
                q.append(v)
    if target not in parent:
        return []
    path: list[str] = []
    cur: str | None = target
    while cur is not None:
        path.append(cur)
        cur = parent[cur]
    path.reverse()
    return path


def _anchor_sources_for_rule(
    world: World, principal_id: str, rule: dict[str, Any]
) -> list[str]:
    if rule.get("holder_type", "role") != "role":
        return []
    holder = rule["holder"]
    out: set[str] = set()
    for asg in world.assignments_by_principal.get(principal_id, ()):  # type: ignore[arg-type]
        start = asg["role"]
        if holder in world.role_closure([start]):
            out.add(assignment_source(asg))
    return fixed_sorted(out)


# --------------------------------------------------------------------------- #
# Permission decision
# --------------------------------------------------------------------------- #
def evaluate_permission(
    world: World, principal_id: str, resource: str, action: str
) -> dict[str, Any]:
    rules, closure = world.applicable_rules(principal_id, resource, action)

    votes: list[dict[str, Any]] = []
    breakglass: list[dict[str, Any]] = []
    denies: list[dict[str, Any]] = []
    allows: list[dict[str, Any]] = []

    for rule in rules:
        src = rule_source(rule)
        is_bg = bool(rule.get("overrides_deny")) and rule.get("effect") == "allow"
        if is_bg:
            kind = "breakglass_allow"
        elif rule.get("effect") == "deny":
            kind = "policy_deny"
        else:
            kind = "allow"
        vote = {
            "rule_id": str(rule.get("id")),
            "source": src,
            "kind": kind,
            "effect": rule.get("effect", "allow"),
            "side": rule.get("side", "identity"),
            "holder_type": rule.get("holder_type", "role"),
            "holder": rule.get("holder"),
            "tenant": rule.get("tenant"),
            "via_exception": rule.get("via_exception"),
        }
        votes.append(vote)
        if kind == "breakglass_allow":
            breakglass.append(rule)
        elif kind == "policy_deny":
            denies.append(rule)
        else:
            allows.append(rule)

    # Fixed order for every reported list.
    votes.sort(key=lambda v: (v["source"], v["rule_id"]))

    if breakglass:
        decision = "allow"
        decisive_kind = "breakglass_allow_over_deny"
        effective_entitlements = breakglass + allows
        blockers: list[dict[str, Any]] = denies
    elif denies:
        decision = "deny"  # inherited / policy deny overrides all allows
        decisive_kind = "deny_overrides"
        effective_entitlements = []
        blockers = denies
    elif allows:
        decision = "allow"
        decisive_kind = "allow"
        effective_entitlements = allows
        blockers = []
    else:
        decision = "none"
        decisive_kind = "implicit_deny"
        effective_entitlements = []
        blockers = []

    entitlement_sources: set[str] = set()
    anchor_sources: set[str] = set()
    source_details: list[dict[str, Any]] = []
    for rule in effective_entitlements:
        src = rule_source(rule)
        entitlement_sources.add(src)
        anchors = _anchor_sources_for_rule(world, principal_id, rule)
        anchor_sources.update(anchors)
        path = (
            best_inheritance_path(world, principal_id, rule["holder"])
            if rule.get("holder_type", "role") == "role"
            else [principal_id]
        )
        source_details.append(
            {
                "source": src,
                "rule_id": str(rule.get("id")),
                "kind": "breakglass_allow"
                if bool(rule.get("overrides_deny"))
                else "allow",
                "side": rule.get("side", "identity"),
                "holder": rule.get("holder"),
                "inheritance_path": path,
                "anchor_sources": anchors,
            }
        )

    blocking_sources = fixed_sorted(rule_source(r) for r in blockers)
    retained = fixed_sorted(entitlement_sources | anchor_sources)
    entitlement_list = fixed_sorted(entitlement_sources)
    anchor_list = fixed_sorted(anchor_sources)

    decisive_source: str | None = None
    if decision == "allow":
        if breakglass:
            decisive_source = fixed_sorted(rule_source(r) for r in breakglass)[0]
        elif allows:
            decisive_source = fixed_sorted(rule_source(r) for r in allows)[0]
    elif decision == "deny" and denies:
        decisive_source = fixed_sorted(rule_source(r) for r in denies)[0]

    return {
        "principal": principal_id,
        "resource": resource,
        "action": action,
        "permission": f"{action}@{resource}",
        "decision": decision,
        "allowed": decision == "allow",
        "decisive_kind": decisive_kind,
        "decisive_source": decisive_source,
        "role_closure_size": len(closure),
        "entitlement_sources": entitlement_list,
        "anchor_sources": anchor_list,
        "retained_sources": retained,
        "blocking_deny_sources": blocking_sources,
        "source_details": sorted(source_details, key=lambda d: d["source"]),
        "votes": votes,
    }


def evaluate_coverage(
    world: World, principal_id: str, requirements: list[dict[str, str]]
) -> dict[str, Any]:
    items = [
        evaluate_permission(world, principal_id, req["resource"], req["action"])
        for req in requirements
    ]
    all_sources: set[str] = set()
    for item in items:
        all_sources.update(item["retained_sources"])
    return {
        "principal": principal_id,
        "covered": all(item["allowed"] for item in items),
        "requirement_count": len(items),
        "covered_count": sum(1 for i in items if i["allowed"]),
        "all_retained_sources": fixed_sorted(all_sources),
        "items": items,
    }


# --------------------------------------------------------------------------- #
# Separation of duties
# --------------------------------------------------------------------------- #
def evaluate_sod_controller(world: World) -> dict[str, Any]:
    """Controller-granularity SoD across every account a controller owns."""
    checks: list[dict[str, Any]] = []
    violations = 0
    controllers_checked = 0

    for cid in fixed_sorted(world.principals_by_controller):
        controllers_checked += 1
        roles, witness = world.controller_role_detail(cid)
        for con in world.sod:
            ra, rb = con["role_a"], con["role_b"]
            ha, hb = ra in roles, rb in roles
            if not (ha or hb):
                continue
            violated = ha and hb
            if violated:
                violations += 1
            checks.append(
                {
                    "constraint_id": con["id"],
                    "tenant": con.get("tenant"),
                    "controller": cid,
                    "role_a": ra,
                    "role_b": rb,
                    "holds_role_a": ha,
                    "holds_role_b": hb,
                    "violated": violated,
                    "witness_a": witness.get(ra, []),
                    "witness_b": witness.get(rb, []),
                }
            )

    checks.sort(key=lambda c: (c["controller"], c["constraint_id"]))
    return {
        "level": "controller",
        "ok": violations == 0,
        "violation_count": violations,
        "controllers_checked": controllers_checked,
        "constraints_defined": len(world.sod),
        "relevant_checks": checks,
    }


def evaluate_sod_principal_level(world: World) -> dict[str, Any]:
    """Naive per-account check, kept only to prove why controller aggregation matters."""
    violations: list[dict[str, str]] = []
    for pid in fixed_sorted(world.principal_by_id):
        roles = world.principal_role_closure(pid)
        for con in world.sod:
            if con["role_a"] in roles and con["role_b"] in roles:
                violations.append(
                    {
                        "principal": pid,
                        "constraint_id": con["id"],
                        "role_a": con["role_a"],
                        "role_b": con["role_b"],
                    }
                )
    return {
        "level": "principal",
        "ok": not violations,
        "violation_count": len(violations),
        "violations": violations,
    }
