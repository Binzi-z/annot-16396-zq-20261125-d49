"""Deterministic synthetic fixtures.

Three small cases are required to be independently enumerated:

* :func:`controller_dual_role_scenario` — one controller owns two accounts
  that together hold a mutually exclusive role pair;
* :func:`inherited_deny_scenario` — an inherited deny overrides a direct
  allow and ordinary exception allows; only break-glass tier wins;
* :func:`cycle_rooted_scenario` / :func:`cycle_rootless_scenario` — a cyclic
  SCC that contains a real authority root vs a rootless loop.

:func:`build_migration_log` builds the old/new tenant coexistence story whose
late revocation changes the current minimum recommendation.
"""

from __future__ import annotations

from typing import Any

from .store import AUTH, SOD, PolicyLog

# --------------------------------------------------------------------------- #
# Scenario 1: same controller acts in two mutually exclusive roles
# --------------------------------------------------------------------------- #
def controller_dual_role_scenario() -> dict[str, Any]:
    world: dict[str, Any] = {
        "tenants": [{"id": "new", "label": "destination tenant"}],
        "controllers": [{"id": "ctrl.zhang", "label": "Zhang (accountable owner)"}],
        "principals": [
            {"id": "acct.duty", "controller": "ctrl.zhang", "team": "team.sre-new"},
            {"id": "acct.records", "controller": "ctrl.zhang", "team": "records"},
        ],
        "roles": [
            {"id": "role.requestor"},
            {"id": "role.approver"},
            {"id": "role.payops"},
        ],
        "edges": [],
        "assignments": [
            {
                "id": "ASG-RECORDS-REQUESTOR",
                "principal": "acct.records",
                "role": "role.requestor",
                "tenant": "new",
                "source": "ASG:new:records-requestor",
            }
        ],
        "rules": [
            {
                "id": "RULE-APPROVER-PAY",
                "tenant": "new",
                "holder_type": "role",
                "holder": "role.approver",
                "resource": "res.payments",
                "action": "approve",
                "effect": "allow",
                "source": "SRC:new:approver-baseline",
            },
            {
                "id": "RULE-PAYOPS-PAY",
                "tenant": "new",
                "holder_type": "role",
                "holder": "role.payops",
                "resource": "res.payments",
                "action": "approve",
                "effect": "allow",
                "source": "SRC:new:payops-baseline",
            },
        ],
        "sod": [
            {
                "id": "SOD-REQ-APP",
                "tenant": "new",
                "role_a": "role.requestor",
                "role_b": "role.approver",
            }
        ],
    }
    candidates = [
        {
            "id": "EXC-S1-10-approver-role",
            "subject": "acct.duty",
            "assign_roles": ["role.approver"],
            "why": "Grants the mutex approver role -> controller conflict.",
        },
        {
            "id": "EXC-S1-20-payops-role",
            "subject": "acct.duty",
            "assign_roles": ["role.payops"],
            "why": "Grants a non-mutex role that already permits approval.",
        },
        {
            "id": "EXC-S1-30-direct-perm",
            "subject": "acct.duty",
            "grant_permissions": [
                {"resource": "res.payments", "action": "approve", "effect": "allow"}
            ],
            "why": "Scoped direct permission; no mutex role assumed.",
        },
    ]
    return {
        "id": "S1-controller-dual-role",
        "title": "Same controller holds both sides of an SoD pair",
        "principal": "acct.duty",
        "requirements": [{"resource": "res.payments", "action": "approve"}],
        "world": world,
        "candidates": candidates,
        "expect": {
            "optimum_size": 1,
            "canonical": ["EXC-S1-20-payops-role"],
            "same_cost_winners": [
                ["EXC-S1-20-payops-role"],
                ["EXC-S1-30-direct-perm"],
            ],
            "rejected_for_sod": "EXC-S1-10-approver-role",
        },
    }


# --------------------------------------------------------------------------- #
# Scenario 2: inherited deny overrides
# --------------------------------------------------------------------------- #
def inherited_deny_scenario() -> dict[str, Any]:
    world: dict[str, Any] = {
        "tenants": [{"id": "old", "label": "legacy tenant"}],
        "controllers": [{"id": "ctrl.dbowner"}],
        "principals": [
            {"id": "acct.dbonduty", "controller": "ctrl.dbowner"},
        ],
        "roles": [{"id": "role.ops_oncall"}, {"id": "role.ops_base"}],
        "edges": [{"child": "role.ops_oncall", "parent": "role.ops_base", "tenant": "old"}],
        "assignments": [
            {
                "id": "ASG-ONDUTY-OPS",
                "principal": "acct.dbonduty",
                "role": "role.ops_oncall",
                "tenant": "old",
                "source": "ASG:old:onduty-ops",
            }
        ],
        "rules": [
            {
                "id": "RULE-ONCALL-ALLOW-DB",
                "tenant": "old",
                "holder_type": "role",
                "holder": "role.ops_oncall",
                "resource": "res.db_prod",
                "action": "read",
                "effect": "allow",
                "source": "SRC:old:oncall-allow-db",
            },
            {
                "id": "RULE-BASE-DENY-DB",
                "tenant": "old",
                "holder_type": "role",
                "holder": "role.ops_base",
                "resource": "res.db_prod",
                "action": "read",
                "effect": "deny",
                "source": "SRC:old:base-inherited-deny",
            },
        ],
        "sod": [],
    }
    candidates = [
        {
            "id": "EXC-S2-10-allow-plain",
            "subject": "acct.dbonduty",
            "grant_permissions": [
                {"resource": "res.db_prod", "action": "read", "effect": "allow"}
            ],
            "why": "Ordinary allow cannot beat the inherited deny.",
        },
        {
            "id": "EXC-S2-20-breakglass-a",
            "subject": "acct.dbonduty",
            "grant_permissions": [
                {
                    "resource": "res.db_prod",
                    "action": "read",
                    "effect": "allow",
                    "overrides_deny": True,
                }
            ],
            "why": "Break-glass tier supersedes the inherited deny.",
        },
        {
            "id": "EXC-S2-30-breakglass-b",
            "subject": "acct.dbonduty",
            "grant_permissions": [
                {
                    "resource": "res.db_prod",
                    "action": "read",
                    "effect": "allow",
                    "overrides_deny": True,
                }
            ],
            "why": "Second equal-cost break-glass option for the tie-break.",
        },
    ]
    return {
        "id": "S2-inherited-deny-override",
        "title": "Inherited deny overrides direct/exception allows",
        "principal": "acct.dbonduty",
        "requirements": [{"resource": "res.db_prod", "action": "read"}],
        "world": world,
        "candidates": candidates,
        "expect": {
            "baseline_decision": "deny",
            "baseline_decisive_kind": "deny_overrides",
            "optimum_size": 1,
            "canonical": ["EXC-S2-20-breakglass-a"],
            "same_cost_winners": [
                ["EXC-S2-20-breakglass-a"],
                ["EXC-S2-30-breakglass-b"],
            ],
            "plain_allow_subset_infeasible": ["EXC-S2-10-allow-plain"],
        },
    }


# --------------------------------------------------------------------------- #
# Scenario 3a: cycle containing a real authority root
# --------------------------------------------------------------------------- #
def cycle_rooted_scenario() -> dict[str, Any]:
    world: dict[str, Any] = {
        "tenants": [{"id": "new"}],
        "controllers": [{"id": "ctrl.c1"}],
        "principals": [{"id": "acct.ground", "controller": "ctrl.c1"}],
        "roles": [{"id": "cyc.a"}, {"id": "cyc.b"}],
        "edges": [
            {"child": "cyc.a", "parent": "cyc.b"},
            {"child": "cyc.b", "parent": "cyc.a"},
        ],
        "assignments": [
            {"id": "ASG-GROUND-A", "principal": "acct.ground", "role": "cyc.a", "tenant": "new"}
        ],
        "rules": [
            {
                "id": "RULE-LOOP-REAL",
                "tenant": "new",
                "holder_type": "role",
                "holder": "cyc.b",
                "resource": "res.loop_real",
                "action": "read",
                "effect": "allow",
                "source": "SRC:new:loop-real-root",
            }
        ],
        "sod": [],
    }
    candidates = [
        {
            "id": "EXC-S3A-10-redundant",
            "subject": "acct.ground",
            "grant_permissions": [
                {"resource": "res.loop_real", "action": "read", "effect": "allow"}
            ],
            "why": "Redundant: the grounded loop already grants access.",
        }
    ]
    return {
        "id": "S3a-cycle-real-root",
        "title": "Inheritance cycle that contains a real authority root",
        "principal": "acct.ground",
        "requirements": [{"resource": "res.loop_real", "action": "read"}],
        "world": world,
        "candidates": candidates,
        "cycle_expect": {"rootless": False, "has_real_root_inside": True},
        "expect": {"optimum_size": 0, "canonical": []},
    }


# --------------------------------------------------------------------------- #
# Scenario 3b: rootless cycle
# --------------------------------------------------------------------------- #
def cycle_rootless_scenario() -> dict[str, Any]:
    world: dict[str, Any] = {
        "tenants": [{"id": "new"}],
        "controllers": [{"id": "ctrl.c2"}],
        "principals": [{"id": "acct.ghost", "controller": "ctrl.c2"}],
        "roles": [{"id": "ghost.x"}, {"id": "ghost.y"}],
        "edges": [
            {"child": "ghost.x", "parent": "ghost.y"},
            {"child": "ghost.y", "parent": "ghost.x"},
        ],
        "assignments": [
            {"id": "ASG-GHOST-X", "principal": "acct.ghost", "role": "ghost.x", "tenant": "new"}
        ],
        "rules": [],
        "sod": [],
    }
    candidates = [
        {
            "id": "EXC-S3B-10-ghost-dup",
            "subject": "acct.ghost",
            "assign_roles": ["ghost.x"],
            "why": "Re-asserting a role in a rootless loop grants no entitlement.",
        },
        {
            "id": "EXC-S3B-20-real-grant",
            "subject": "acct.ghost",
            "grant_permissions": [
                {"resource": "res.loop_void", "action": "read", "effect": "allow"}
            ],
            "why": "A genuine scoped grant is the only real source.",
        },
    ]
    return {
        "id": "S3b-cycle-rootless",
        "title": "Rootless inheritance cycle confers no authority",
        "principal": "acct.ghost",
        "requirements": [{"resource": "res.loop_void", "action": "read"}],
        "world": world,
        "candidates": candidates,
        "cycle_expect": {"rootless": True, "has_real_root_inside": False},
        "expect": {
            "optimum_size": 1,
            "canonical": ["EXC-S3B-20-real-grant"],
        },
    }


# --------------------------------------------------------------------------- #
# Main migration: old + new tenant coexistence and a late revocation
# --------------------------------------------------------------------------- #
MIGRATION_PRINCIPAL = "acct.duty-synth"
MIGRATION_REQUIREMENTS = [
    {"resource": "res.prod-api", "action": "deploy"},
    {"resource": "res.prod-workers", "action": "restart"},
    {"resource": "res.observability", "action": "read"},
    {"resource": "res.change-window", "action": "approve"},
]


def migration_candidates() -> list[dict[str, Any]]:
    return [
        {
            "id": "EXC-M01-obs-scoped",
            "subject": MIGRATION_PRINCIPAL,
            "grant_permissions": [
                {"resource": "res.observability", "action": "read", "effect": "allow"}
            ],
        },
        {
            "id": "EXC-M02-window-bg",
            "subject": MIGRATION_PRINCIPAL,
            "grant_permissions": [
                {
                    "resource": "res.change-window",
                    "action": "approve",
                    "effect": "allow",
                    "overrides_deny": True,
                }
            ],
        },
        {
            "id": "EXC-M03-approver-role",
            "subject": MIGRATION_PRINCIPAL,
            "assign_roles": ["role.change_approver"],
            "why": "Trips controller-level requestor/approver SoD.",
        },
        {
            "id": "EXC-M04-deploy-scoped",
            "subject": MIGRATION_PRINCIPAL,
            "grant_permissions": [
                {"resource": "res.prod-api", "action": "deploy", "effect": "allow"}
            ],
        },
        {
            "id": "EXC-M05-restart-scoped",
            "subject": MIGRATION_PRINCIPAL,
            "grant_permissions": [
                {"resource": "res.prod-workers", "action": "restart", "effect": "allow"}
            ],
        },
        {
            "id": "EXC-M06-obs-bg",
            "subject": MIGRATION_PRINCIPAL,
            "grant_permissions": [
                {
                    "resource": "res.observability",
                    "action": "read",
                    "effect": "allow",
                    "overrides_deny": True,
                }
            ],
        },
        {
            "id": "EXC-M07-window-direct",
            "subject": MIGRATION_PRINCIPAL,
            "grant_permissions": [
                {"resource": "res.change-window", "action": "approve", "effect": "allow"}
            ],
        },
    ]


def build_migration_log() -> PolicyLog:
    topology: dict[str, Any] = {
        "tenants": [
            {"id": "old", "label": "legacy tenant (pre-migration policy still effective)"},
            {"id": "new", "label": "destination tenant (new team)"},
        ],
        "controllers": [
            {"id": "ctrl.sre-lead", "label": "SRE lead controlling duty and clerk accounts"}
        ],
        "principals": [
            {
                "id": MIGRATION_PRINCIPAL,
                "controller": "ctrl.sre-lead",
                "team": "team.sre-new",
                "kind": "synthetic-oncall",
            },
            {
                "id": "acct.req-clerk",
                "controller": "ctrl.sre-lead",
                "team": "change-ops",
            },
        ],
        "roles": [
            {"id": "role.sre_new"},
            {"id": "role.oncall_old"},
            {"id": "role.change_requester"},
            {"id": "role.change_approver"},
        ],
        "resources": [
            {"id": r["resource"], "critical": True, "action": r["action"]}
            for r in MIGRATION_REQUIREMENTS
        ],
    }
    log = PolicyLog(topology)

    # --- new tenant authorization chain (already migrated baseline) -------
    log.add(
        "assignments",
        {
            "id": "ASG-NEW-DUTY-SRE",
            "principal": MIGRATION_PRINCIPAL,
            "role": "role.sre_new",
            "tenant": "new",
        },
        tenant="new",
        stream=AUTH,
    )
    for rid, resource, action in [
        ("RULE-NEW-DEPLOY", "res.prod-api", "deploy"),
        ("RULE-NEW-RESTART", "res.prod-workers", "restart"),
    ]:
        log.add(
            "rules",
            {
                "id": rid,
                "tenant": "new",
                "holder_type": "role",
                "holder": "role.sre_new",
                "resource": resource,
                "action": action,
                "effect": "allow",
            },
            tenant="new",
            stream=AUTH,
        )
    log.add(
        "assignments",
        {
            "id": "ASG-CLERK-REQUESTER",
            "principal": "acct.req-clerk",
            "role": "role.change_requester",
            "tenant": "new",
        },
        tenant="new",
        stream=AUTH,
    )
    log.add(
        "rules",
        {
            "id": "RULE-NEW-APPROVER-WINDOW",
            "tenant": "new",
            "holder_type": "role",
            "holder": "role.change_approver",
            "resource": "res.change-window",
            "action": "approve",
            "effect": "allow",
        },
        tenant="new",
        stream=AUTH,
    )
    log.add(
        "sod",
        {
            "id": "SOD-CHANGE-REQ-APP",
            "tenant": "new",
            "role_a": "role.change_requester",
            "role_b": "role.change_approver",
        },
        tenant="new",
        stream=SOD,
    )

    # --- old tenant chain still effective during coexistence --------------
    log.add(
        "assignments",
        {
            "id": "ASG-OLD-DUTY-ONCALL",
            "principal": MIGRATION_PRINCIPAL,
            "role": "role.oncall_old",
            "tenant": "old",
            "source": "ASG:old:duty-oncall-standing",
        },
        tenant="old",
        stream=AUTH,
    )
    log.add(
        "rules",
        {
            "id": "RULE-OLD-OBS",
            "tenant": "old",
            "holder_type": "role",
            "holder": "role.oncall_old",
            "resource": "res.observability",
            "action": "read",
            "effect": "allow",
            "source": "SRC:old:observability-standing",
        },
        tenant="old",
        stream=AUTH,
    )

    log.expose_all_latest()
    return log


def late_revoke_old_oncall(log: PolicyLog) -> None:
    """Append the late revocation and advance only the old/auth water-mark."""
    log.revoke(
        "assignments",
        "ASG-OLD-DUTY-ONCALL",
        tenant="old",
        stream=AUTH,
    )
    log.advance("old", AUTH)
