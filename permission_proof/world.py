"""Effective policy world: indexes over a JSON-able *effective snapshot*.

A ``WorldDef`` is the folded, point-in-time policy state (only visible and
active facts).  Keeping it plain JSON data means the exact world used by a
certificate can be embedded and independently rebuilt by the verifier.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Any, Iterable

WorldDef = dict[str, Any]

COLLECTIONS = ("edges", "assignments", "rules", "sod")


def rule_source(rule: dict[str, Any]) -> str:
    if rule.get("source"):
        return str(rule["source"])
    return f"SRC:{rule.get('tenant', '_')}:{rule['id']}"


def assignment_source(asg: dict[str, Any]) -> str:
    if asg.get("source"):
        return str(asg["source"])
    return f"ASG:{asg.get('tenant', '_')}:{asg['id']}"


class World:
    """Read model over an effective :data:`WorldDef`."""

    def __init__(self, defn: WorldDef | None = None) -> None:
        self.defn: WorldDef = deepcopy(defn) if defn else {}
        self.tenants: list[dict[str, Any]] = list(self.defn.get("tenants", []))
        self.principals: list[dict[str, Any]] = list(self.defn.get("principals", []))
        self.roles: list[dict[str, Any]] = list(self.defn.get("roles", []))
        self.resources: list[dict[str, Any]] = list(self.defn.get("resources", []))
        self.edges: list[dict[str, Any]] = list(self.defn.get("edges", []))
        self.assignments: list[dict[str, Any]] = list(self.defn.get("assignments", []))
        self.rules: list[dict[str, Any]] = list(self.defn.get("rules", []))
        self.sod: list[dict[str, Any]] = list(self.defn.get("sod", []))

        self.principal_by_id: dict[str, dict[str, Any]] = {
            p["id"]: p for p in self.principals
        }
        self.controller_of: dict[str, str] = {}
        self.principals_by_controller: dict[str, list[str]] = defaultdict(list)
        for p in self.principals:
            pid = p["id"]
            cid = p.get("controller", pid)
            self.controller_of[pid] = cid
            self.principals_by_controller[cid].append(pid)
        for cid in self.principals_by_controller:
            self.principals_by_controller[cid].sort()

        # child role -> parent roles (child inherits parent permissions)
        self.parents: dict[str, set[str]] = defaultdict(set)
        self.directed_edges: list[tuple[str, str]] = []
        for e in self.edges:
            child, parent = e["child"], e["parent"]
            self.parents[child].add(parent)
            self.directed_edges.append((child, parent))

        self.assignments_by_principal: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for a in self.assignments:
            self.assignments_by_principal[a["principal"]].append(a)

        self.rules_by_holder_role: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.rules_by_holder_principal: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in self.rules:
            ht = r.get("holder_type", "role")
            if ht == "principal":
                self.rules_by_holder_principal[r["holder"]].append(r)
            else:
                self.rules_by_holder_role[r["holder"]].append(r)

    # ------------------------------------------------------------------ #
    # Role reachability
    # ------------------------------------------------------------------ #
    def assigned_roles(self, principal_id: str) -> set[str]:
        return {a["role"] for a in self.assignments_by_principal.get(principal_id, ())}

    def role_closure(self, start_roles: Iterable[str]) -> set[str]:
        """All roles reachable by inheritance (cycle safe)."""
        seen: set[str] = set()
        stack = list(start_roles)
        while stack:
            r = stack.pop()
            if r in seen:
                continue
            seen.add(r)
            for parent in self.parents.get(r, ()):  # type: ignore[arg-type]
                if parent not in seen:
                    stack.append(parent)
        return seen

    def principal_role_closure(self, principal_id: str) -> set[str]:
        return self.role_closure(self.assigned_roles(principal_id))

    def controller_role_detail(
        self, controller_id: str
    ) -> tuple[set[str], dict[str, list[dict[str, str]]]]:
        """Union role closure for every principal controlled by a controller.

        Returns the role set and, per role, witness rows describing which
        controlled principal / assignment grounded it.
        """
        witness: dict[str, list[dict[str, str]]] = defaultdict(list)
        roles: set[str] = set()
        for pid in self.principals_by_controller.get(controller_id, (controller_id,)):
            for asg in self.assignments_by_principal.get(pid, ()):  # direct anchors
                start = asg["role"]
                closure = self.role_closure([start])
                for r in closure:
                    roles.add(r)
                    witness[r].append(
                        {
                            "principal": pid,
                            "assignment_id": str(asg.get("id", "")),
                            "assignment_source": assignment_source(asg),
                            "start_role": start,
                        }
                    )
        return roles, witness

    # ------------------------------------------------------------------ #
    # Rule matching
    # ------------------------------------------------------------------ #
    def applicable_rules(
        self, principal_id: str, resource: str, action: str
    ) -> tuple[list[dict[str, Any]], set[str]]:
        """Return matching rules and the role closure used."""
        closure = self.principal_role_closure(principal_id)
        matches: list[dict[str, Any]] = []
        for role in closure:
            for rule in self.rules_by_holder_role.get(role, ()):  # type: ignore[arg-type]
                if _rule_matches(rule, resource, action):
                    matches.append(rule)
        for rule in self.rules_by_holder_principal.get(principal_id, ()):  # type: ignore[arg-type]
            if _rule_matches(rule, resource, action):
                matches.append(rule)
        return matches, closure

    def entitlement_root_roles(self) -> set[str]:
        """Roles that directly declare at least one permission rule.

        These are the genuine authority seeds used by cycle classification.
        Principal-held rules do not seed role-graph cycles.
        """
        seeds: set[str] = set()
        for r in self.rules:
            if r.get("holder_type", "role") == "role":
                seeds.add(r["holder"])
        for role in self.defn.get("authority_root_roles", []):
            seeds.add(role)
        return seeds

    def snapshot_digest(self) -> str:
        from .canon import sha256_hex

        return sha256_hex(self.defn)


def _rule_matches(rule: dict[str, Any], resource: str, action: str) -> bool:
    res_ok = rule.get("resource") in (resource, "*")
    act_ok = rule.get("action") in (action, "*")
    return res_ok and act_ok


def world_with_exceptions(
    base: World | WorldDef,
    candidates: list[dict[str, Any]],
    selected_ids: Iterable[str],
) -> World:
    """Return a new World with selected emergency exceptions merged in.

    Exceptions become ordinary effective assignments / rules, so coverage,
    provenance and controller SoD all traverse exactly the same code path.
    """
    defn: WorldDef = deepcopy(base.defn if isinstance(base, World) else base)
    chosen = set(selected_ids)
    by_id = {c["id"]: c for c in candidates}
    unknown = chosen - set(by_id)
    if unknown:
        # A certificate naming an unknown exception id is invalid; the
        # verifier turns this into a failed check rather than a KeyError.
        raise ValueError(f"unknown exception id(s): {sorted(unknown)}")

    new_assignments: list[dict[str, Any]] = []
    new_rules: list[dict[str, Any]] = []
    for cid in sorted(chosen):  # fixed order while materialising
        cand = by_id[cid]
        subject = cand["subject"]
        for role in cand.get("assign_roles", []):
            new_assignments.append(
                {
                    "id": f"EXC-ASG:{cid}:{role}",
                    "principal": subject,
                    "role": role,
                    "tenant": "emergency",
                    "source": cid,
                    "via_exception": cid,
                }
            )
        for perm in cand.get("grant_permissions", []):
            resource, action = perm["resource"], perm["action"]
            new_rules.append(
                {
                    "id": f"EXC-RULE:{cid}:{resource}:{action}",
                    "tenant": "emergency",
                    "side": "exception",
                    "holder_type": "principal",
                    "holder": subject,
                    "resource": resource,
                    "action": action,
                    "effect": perm.get("effect", "allow"),
                    "overrides_deny": bool(perm.get("overrides_deny", False)),
                    "source": cid,
                    "via_exception": cid,
                }
            )

    defn.setdefault("assignments", []).extend(new_assignments)
    defn.setdefault("rules", []).extend(new_rules)
    return World(defn)
