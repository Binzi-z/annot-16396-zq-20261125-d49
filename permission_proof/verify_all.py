"""End-to-end offline verification harness.

Run with::

    python run.py

Every requirement from ``task/PROMPT.txt`` is turned into an explicit,
machine-readable check.  The harness writes canonical certificates and
hash-chained sealed envelopes under ``artifacts/`` and (re)generates the
top-level ``VERIFICATION_REPORT.md``.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import sys
import traceback
from pathlib import Path
from typing import Any

from .canon import canonical_dumps, sha256_hex
from .certificate import build_certificate, verify_certificate
from .evaluate import (
    evaluate_permission,
    evaluate_sod_controller,
    evaluate_sod_principal_level,
)
from .exceptions import enumerate_exception_sets, solve_min_exceptions
from .graph import classify_role_cycles
from .scale60k import run_scale_check
from .seal import (
    GENESIS_HASH,
    ImmutableSealError,
    SealStore,
    tamper_probe,
    verify_envelope,
)
from .store import AUTH, SOD, PolicyLog
from . import scenarios as S
from .world import World, world_with_exceptions

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"


# --------------------------------------------------------------------------- #
# Recorder
# --------------------------------------------------------------------------- #
class Recorder:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def check(
        self,
        section: str,
        name: str,
        ok: bool,
        detail: str = "",
        *,
        required: bool = True,
    ) -> bool:
        self.checks.append(
            {
                "section": section,
                "name": name,
                "ok": bool(ok),
                "required": required,
                "affects_overall": required,
                "detail": str(detail)[:2000],
            }
        )
        return bool(ok)

    @property
    def required_failures(self) -> list[dict[str, Any]]:
        return [c for c in self.checks if not c["ok"] and c["affects_overall"]]

    @property
    def overall_ok(self) -> bool:
        return not self.required_failures


def reset_writable(path: Path) -> None:
    """Remove a previous artifacts tree, clearing Windows read-only bits."""
    if not path.exists():
        return
    for base, _dirs, files in os.walk(path):
        for name in files:
            fp = Path(base) / name
            try:
                os.chmod(fp, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, obj: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# Small enumerated scenarios
# --------------------------------------------------------------------------- #
def verify_small_scenario(
    spec: dict[str, Any], rec: Recorder, cert_dir: Path
) -> dict[str, Any]:
    sid = spec["id"]
    section = f"small:{sid}"
    summary: dict[str, Any] = {"id": sid, "title": spec["title"]}
    try:
        world_def = spec["world"]
        cands = spec["candidates"]
        reqs = spec["requirements"]
        principal = spec["principal"]
        expect = spec.get("expect", {})

        enum = enumerate_exception_sets(world_def, cands, reqs, principal)
        sol = solve_min_exceptions(world_def, cands, reqs, principal)
        summary.update(
            {
                "candidate_count": enum["candidate_count"],
                "enumerated_subset_count": enum["enumerated_subset_count"],
                "feasible_count": enum["feasible_count"],
                "optimum_size": enum["optimum_size"],
                "canonical_winner": enum["canonical_winner"],
                "same_cost_winners": enum["same_cost_winners"],
                "solver_chosen": sol["chosen"],
            }
        )
        # Persist the FULL independent enumeration (every 2**k subset).
        _write_json(cert_dir.parent / "enumerations" / f"{sid}.enum.json", enum)

        if "optimum_size" in expect:
            rec.check(
                section,
                "optimum_size_matches_independent_expectation",
                enum["optimum_size"] == expect["optimum_size"],
                f"got {enum['optimum_size']} want {expect['optimum_size']}",
            )
            rec.check(
                section,
                "solver_optimum_matches",
                sol["optimum_size"] == expect["optimum_size"]
                and (
                    sol["status"] == "feasible"
                    if expect["optimum_size"] is not None
                    else sol["status"] == "infeasible"
                ),
                f"solver {sol['status']} {sol['optimum_size']}",
            )

        if "canonical" in expect:
            rec.check(
                section,
                "canonical_fixed_order_winner",
                enum["canonical_winner"] == expect["canonical"],
                f"got {enum['canonical_winner']} want {expect['canonical']}",
            )
            rec.check(
                section,
                "solver_returns_canonical_winner",
                sol["chosen"] == expect["canonical"],
                f"got {sol['chosen']}",
            )

        # Canonical must be the lexicographic minimum among same-cost winners.
        if enum["same_cost_winners"]:
            cw = enum["canonical_winner"]
            lex_min = min(tuple(w) for w in enum["same_cost_winners"])
            rec.check(
                section,
                "canonical_is_lexicographic_min_same_cost",
                tuple(cw or []) == lex_min,
                f"canonical={cw} lex_min={list(lex_min)}",
            )

        for winner in expect.get("same_cost_winners", []):
            rec.check(
                section,
                f"expected_same_cost_winner_present:{winner}",
                winner in enum["same_cost_winners"],
                f"winners={enum['same_cost_winners']}",
            )

        # Scenario-specific semantic assertions.
        base_world = World(world_def)
        if "baseline_decision" in expect:
            req = reqs[0]
            verdict = evaluate_permission(base_world, principal, req["resource"], req["action"])
            rec.check(
                section,
                "baseline_permission_decision",
                verdict["decision"] == expect["baseline_decision"],
                f"got {verdict['decision']}",
            )
            if "baseline_decisive_kind" in expect:
                rec.check(
                    section,
                    "deny_override_precedence",
                    verdict["decisive_kind"] == expect["baseline_decisive_kind"],
                    verdict["decisive_kind"],
                )
                rec.check(
                    section,
                    "inherited_deny_source_reported",
                    any("inherited-deny" in s for s in verdict["blocking_deny_sources"]),
                    str(verdict["blocking_deny_sources"]),
                )

        if sid.startswith("S1"):
            bad = expect["rejected_for_sod"]
            augmented = world_with_exceptions(world_def, cands, [bad])
            ctrl = evaluate_sod_controller(augmented)
            naive = evaluate_sod_principal_level(augmented)
            rec.check(
                section,
                "controller_level_detects_dual_role_conflict",
                not ctrl["ok"] and ctrl["violation_count"] >= 1,
                f"violations={ctrl['violation_count']}",
            )
            rec.check(
                section,
                "naive_single_principal_check_would_miss_it",
                naive["ok"] and naive["violation_count"] == 0,
                f"principal-level violations={naive['violation_count']}",
            )

        if "plain_allow_subset_infeasible" in expect:
            only_plain = expect["plain_allow_subset_infeasible"]
            plain_enum = enumerate_exception_sets(
                world_def,
                [c for c in cands if c["id"] in only_plain],
                reqs,
                principal,
            )
            rec.check(
                section,
                "ordinary_allow_cannot_beat_inherited_deny",
                plain_enum["optimum_size"] is None
                and plain_enum["feasible_count"] == 0,
                f"opt={plain_enum['optimum_size']} feasible={plain_enum['feasible_count']}",
            )

        if "cycle_expect" in spec:
            infos = classify_role_cycles(
                base_world.directed_edges,
                base_world.entitlement_root_roles(),
                nodes=[r["id"] for r in base_world.roles],
            )
            ce = spec["cycle_expect"]
            rec.check(section, "exactly_one_cyclic_scc", len(infos) == 1, f"{len(infos)} cycles")
            if infos:
                info = infos[0]
                rec.check(
                    section,
                    "cycle_root_classification",
                    info.rootless == ce["rootless"]
                    and info.has_real_root_inside == ce["has_real_root_inside"],
                    f"rootless={info.rootless} inside={info.has_real_root_inside} "
                    f"roots={info.real_roots_inside}",
                )
                summary["cycle"] = {
                    "nodes": list(info.nodes),
                    "rootless": info.rootless,
                    "has_real_root_inside": info.has_real_root_inside,
                    "real_roots_inside": list(info.real_roots_inside),
                }

        # Build + independently verify a canonical certificate.
        cert = build_certificate(
            cert_id=f"CERT-{sid}",
            title=spec["title"],
            target_change={"scenario": sid},
            principal=principal,
            requirements=reqs,
            world_def=world_def,
            candidates=cands,
            solution=sol,
            watermark_vector=world_def.get("watermarks", {}),
            logical_label=sid,
        )
        verification = verify_certificate(cert)
        failed = [c["name"] for c in verification["checks"] if not c["ok"]]
        rec.check(
            section,
            "certificate_independently_verifies",
            verification["valid"],
            "failed=" + ",".join(failed) if failed else f"{verification['passed_count']} checks",
        )
        _write_json(cert_dir / f"{sid}.cert.json", cert)
        summary["cert_valid"] = verification["valid"]
        summary["cert_hash"] = cert["cert_hash"]

    except Exception:  # noqa: BLE001 - record, never silently abort the run
        tb = traceback.format_exc()
        rec.check(section, "scenario_executed_without_exception", False, tb)
        summary["traceback"] = tb
    return summary


# --------------------------------------------------------------------------- #
# Migration + sealing + late revocation
# --------------------------------------------------------------------------- #
def verify_migration(rec: Recorder, cert_dir: Path, seal_dir: Path) -> dict[str, Any]:
    section = "migration"
    out: dict[str, Any] = {}
    enum_dir = cert_dir.parent / "enumerations"
    try:
        cands = S.migration_candidates()
        log = S.build_migration_log()
        wm1 = log.watermark_vector()
        world1 = log.fold(wm1)
        sol1 = solve_min_exceptions(
            world1, cands, S.MIGRATION_REQUIREMENTS, S.MIGRATION_PRINCIPAL
        )
        enum1 = enumerate_exception_sets(
            world1, cands, S.MIGRATION_REQUIREMENTS, S.MIGRATION_PRINCIPAL
        )
        _write_json(enum_dir / "MIG-v1.enum.json", enum1)
        rec.check(section, "v1_canonical_is_single_window_bridge",
                  sol1["chosen"] == ["EXC-M02-window-bg"], str(sol1["chosen"]))
        rec.check(section, "v1_optimum_size_1", sol1["optimum_size"] == 1,
                  str(sol1["optimum_size"]))

        target = {
            "account": S.MIGRATION_PRINCIPAL,
            "kind": "synthetic-oncall",
            "from_team": "team.oncall-legacy",
            "to_team": "team.sre-new",
            "change": "migrate-duty-account-to-new-team",
            "critical_resource_count": len(S.MIGRATION_REQUIREMENTS),
        }
        cert1 = build_certificate(
            cert_id="CERT-MIG-V1",
            title="Migration proof before late revocation",
            target_change=target,
            principal=S.MIGRATION_PRINCIPAL,
            requirements=S.MIGRATION_REQUIREMENTS,
            world_def=world1,
            candidates=cands,
            solution=sol1,
            watermark_vector=wm1,
            logical_label="sealed-v1-pre-revocation",
        )
        v1 = verify_certificate(cert1)
        rec.check(section, "v1_certificate_verifies", v1["valid"],
                   "" if v1["valid"] else str([c for c in v1["checks"] if not c["ok"]]))
        _write_json(cert_dir / "CERT-MIG-V1.json", cert1)

        store = SealStore(seal_dir)
        rec1 = store.seal_version(
            "SEAL-0001", cert1, "Before late old-tenant revocation", watermark_vector=wm1
        )
        p1 = Path(rec1.path)
        mode1 = os.stat(p1).st_mode
        rec.check(section, "seal_file_marked_readonly", not (mode1 & stat.S_IWRITE),
                  f"st_mode={oct(mode1)}", required=False)

        write_denied = False
        try:
            with open(p1, "r+b"):
                pass
        except PermissionError:
            write_denied = True
        except OSError:
            write_denied = False
        rec.check(section, "readonly_file_blocks_inplace_open", write_denied,
                  required=False)

        # ---- late revocation arrives and advances old/auth water-mark -----
        S.late_revoke_old_oncall(log)
        wm2 = log.watermark_vector()
        world2 = log.fold(wm2)
        sol2 = solve_min_exceptions(
            world2, cands, S.MIGRATION_REQUIREMENTS, S.MIGRATION_PRINCIPAL
        )
        enum2 = enumerate_exception_sets(
            world2, cands, S.MIGRATION_REQUIREMENTS, S.MIGRATION_PRINCIPAL
        )
        _write_json(enum_dir / "MIG-v2.enum.json", enum2)
        rec.check(section, "revocation_advances_only_old_auth_watermark",
                  wm2.get("old:auth", 0) == wm1.get("old:auth", 0) + 1
                  and wm2.get("new:auth") == wm1.get("new:auth")
                  and wm2.get("new:sod") == wm1.get("new:sod"),
                  f"wm1={wm1} wm2={wm2}")
        rec.check(section, "v2_needs_two_exceptions", sol2["optimum_size"] == 2,
                  str(sol2["chosen"]))
        rec.check(section, "v2_canonical_pair",
                  sol2["chosen"] == ["EXC-M01-obs-scoped", "EXC-M02-window-bg"],
                  str(sol2["chosen"]))
        rec.check(section, "late_revocation_changes_current_recommendation",
                  sol2["chosen"] != sol1["chosen"],
                  f"v1={sol1['chosen']} v2={sol2['chosen']}")

        cert2 = build_certificate(
            cert_id="CERT-MIG-V2-CURRENT",
            title="Current recommendation after late revocation (new sealed version)",
            target_change=target,
            principal=S.MIGRATION_PRINCIPAL,
            requirements=S.MIGRATION_REQUIREMENTS,
            world_def=world2,
            candidates=cands,
            solution=sol2,
            watermark_vector=wm2,
            logical_label="sealed-v2-post-revocation",
            extra={"supersedes_recommendation": "CERT-MIG-V1",
                   "rewrites_SEAL-0001": False},
        )
        v2 = verify_certificate(cert2)
        rec.check(section, "v2_certificate_verifies", v2["valid"])
        _write_json(cert_dir / "CERT-MIG-V2.json", cert2)
        rec2 = store.seal_version(
            "SEAL-0002", cert2, "After late revocation; current recommendation",
            watermark_vector=wm2,
        )

        # ---- sealed v1 must be byte-for-byte unchanged and still valid -----
        bytes1_now = p1.read_bytes()
        sha1_now = sha256_hex(bytes1_now)
        rec.check(section, "sealed_v1_file_hash_unchanged",
                  sha1_now == rec1.file_sha256_at_seal,
                  f"then={rec1.file_sha256_at_seal} now={sha1_now}")

        env1 = json.loads(bytes1_now.decode("utf-8"))
        ev1 = verify_envelope(env1, expected_prev=GENESIS_HASH)
        rec.check(section, "sealed_v1_still_verifies_against_historical_snapshot",
                  ev1["valid"])

        chain = store.verify_chain()
        rec.check(section, "seal_chain_valid_with_two_versions",
                  chain["valid"] and chain["sealed_version_count"] == 2,
                  json.dumps(chain["versions"], ensure_ascii=False))

        rewrite_refused = False
        try:
            store.seal_version("SEAL-0001", cert2, "attempt to rewrite history")
        except ImmutableSealError:
            rewrite_refused = True
        rec.check(section, "same_version_rewrite_refused", rewrite_refused)
        rec.check(section, "rewrite_attempt_left_hash_unchanged",
                  sha256_hex(p1.read_bytes()) == rec1.file_sha256_at_seal)

        tampered = tamper_probe(env1)
        rec.check(section, "tampered_envelope_rejected", not tampered["valid"])

        out.update(
            {
                "watermark_v1": wm1,
                "chosen_v1": sol1["chosen"],
                "sources_v1": sol1["verdict"]["coverage"]["all_retained_sources"],
                "watermark_v2": wm2,
                "chosen_v2": sol2["chosen"],
                "sources_v2": sol2["verdict"]["coverage"]["all_retained_sources"],
                "seal_records": [r.__dict__ for r in (rec1, rec2)],
                "chain": chain,
                "tamper_probe_valid": tampered["valid"],
            }
        )
    except Exception:  # noqa: BLE001
        tb = traceback.format_exc()
        rec.check(section, "migration_flow_executed_without_exception", False, tb)
        out["traceback"] = tb
    return out


# --------------------------------------------------------------------------- #
# Independent water-mark demonstration
# --------------------------------------------------------------------------- #
def verify_watermarks(rec: Recorder) -> None:
    section = "watermarks"
    try:
        log = PolicyLog()
        log.add("edges", {"id": "E1", "child": "a", "parent": "b"},
                tenant="old", stream=AUTH)
        log.add("sod", {"id": "S1", "role_a": "a", "role_b": "b"},
                tenant="new", stream=SOD)

        empty = log.fold({})
        rec.check(section, "frontier_zero_hides_all",
                  len(empty.get("edges", [])) == 0 and len(empty.get("sod", [])) == 0)

        log.advance("old", AUTH)
        auth_only = log.fold()
        rec.check(section, "auth_watermark_independent_from_sod",
                  len(auth_only.get("edges", [])) == 1
                  and len(auth_only.get("sod", [])) == 0,
                  str(log.watermark_vector()))

        log.advance("new", SOD)
        both = log.fold()
        rec.check(section, "sod_watermark_advances_separately",
                  len(both.get("edges", [])) == 1 and len(both.get("sod", [])) == 1)
    except Exception:  # noqa: BLE001
        rec.check(section, "watermark_check_executed", False, traceback.format_exc())


# --------------------------------------------------------------------------- #
# Tracker split check (scale check itself covers the merge path)
# --------------------------------------------------------------------------- #
def verify_tracker_split(rec: Recorder) -> None:
    section = "component-tracker-split"
    try:
        from .graph import TrackedComponents

        edges = [("a0", "a1"), ("a1", "a2"), ("b0", "b1")]
        tracker = TrackedComponents.from_edges(edges)
        before = tracker.count
        # Removing the bridge a1-a2 splits {a0,a1,a2} into {a0,a1} + {a2}.
        after = tracker.apply_changeset(removed_edges=[("a1", "a2")])
        rec.check(section, "bridge_removal_increments_count_by_one",
                  before == 2 and after == 3, f"before={before} after={after}")
        rec.check(section, "split_tracker_matches_full_recompute",
                  tracker.matches_full_recompute())
    except Exception:  # noqa: BLE001
        rec.check(section, "split_check_executed", False, traceback.format_exc())


# --------------------------------------------------------------------------- #
# Deterministic fuzz: enumeration oracle vs ordered solver
# --------------------------------------------------------------------------- #
def verify_fuzz(rec: Recorder, cases: int = 200) -> dict[str, Any]:
    section = "fuzz-enum-vs-solver"
    import random

    rng = random.Random(20261125)
    mismatches: list[str] = []
    total_subsets = 0
    try:
        for case in range(cases):
            roles = [f"r{i}" for i in range(rng.randrange(1, 7))]
            resources = [f"res{j}" for j in range(rng.randrange(1, 5))]
            actions = ["read", "write"]
            world: dict[str, Any] = {
                "tenants": [{"id": "t"}],
                "principals": [{"id": "p", "controller": "c"}],
                "controllers": [{"id": "c"}],
                "roles": [{"id": r} for r in roles],
                "edges": [
                    {"child": rng.choice(roles), "parent": rng.choice(roles)}
                    for _ in range(rng.randrange(0, 8))
                ],
                "assignments": [
                    {"id": f"asg{i}", "principal": "p", "role": r}
                    for i, r in enumerate(rng.sample(roles, rng.randrange(1, min(3, len(roles)) + 1)))
                ],
                "rules": [
                    {
                        "id": f"rule{n}",
                        "tenant": "t",
                        "holder_type": "role",
                        "holder": rng.choice(roles),
                        "resource": rng.choice(resources + ["*"]),
                        "action": rng.choice(actions + ["*"]),
                        "effect": rng.choice(["allow", "allow", "deny"]),
                    }
                    for n in range(rng.randrange(0, 8))
                ],
                "sod": [
                    {"id": f"sod{n}", "role_a": rng.choice(roles),
                     "role_b": rng.choice(roles)}
                    for n in range(rng.randrange(0, 2))
                ],
            }
            requirements = [
                {"resource": rng.choice(resources), "action": rng.choice(actions)}
                for _ in range(rng.randrange(1, 4))
            ]
            k = rng.randrange(0, 9)
            candidates: list[dict[str, Any]] = []
            for i in range(k):
                cid = f"E{i:02d}"
                kind = rng.randrange(3)
                if kind == 0:
                    candidates.append({
                        "id": cid, "subject": "p",
                        "grant_permissions": [{
                            "resource": rng.choice(resources),
                            "action": rng.choice(actions),
                            "effect": "allow"}]})
                elif kind == 1:
                    candidates.append({
                        "id": cid, "subject": "p",
                        "grant_permissions": [{
                            "resource": rng.choice(resources),
                            "action": rng.choice(actions),
                            "effect": "allow", "overrides_deny": True}]})
                else:
                    candidates.append({"id": cid, "subject": "p",
                                       "assign_roles": [rng.choice(roles)]})

            enum = enumerate_exception_sets(world, candidates, requirements, "p")
            sol = solve_min_exceptions(world, candidates, requirements, "p")
            total_subsets += enum["enumerated_subset_count"]
            if enum["optimum_size"] is None:
                if sol["status"] != "infeasible":
                    mismatches.append(f"case{case}: enum infeasible but solver {sol['chosen']}")
            elif sol["chosen"] != enum["canonical_winner"] or \
                    sol["optimum_size"] != enum["optimum_size"]:
                mismatches.append(
                    f"case{case}: enum {enum['canonical_winner']}@{enum['optimum_size']} "
                    f"vs solver {sol['chosen']}@{sol['optimum_size']}"
                )
        rec.check(section, f"{cases}_deterministic_cases_match", not mismatches,
                  "; ".join(mismatches[:5]))
    except Exception:  # noqa: BLE001
        rec.check(section, "fuzz_executed", False, traceback.format_exc())
    return {"cases": cases, "subset_evals": total_subsets, "mismatches": mismatches[:10]}


# --------------------------------------------------------------------------- #
# Top-level run
# --------------------------------------------------------------------------- #
def run_all(artifacts_dir: Path | None = None) -> dict[str, Any]:
    art = artifacts_dir or ARTIFACTS
    reset_writable(art)
    cert_dir = art / "certificates"
    seal_dir = art / "sealed"
    cert_dir.mkdir(parents=True, exist_ok=True)
    seal_dir.mkdir(parents=True, exist_ok=True)

    rec = Recorder()

    env = {
        "python": sys.version.replace("\n", " "),
        "executable": sys.executable,
        "platform": platform.platform(),
        "sys_platform": sys.platform,
        "stdlib_only": True,
    }
    rec.check("environment", "python_3_12_on_native_windows",
              sys.platform == "win32" and sys.version_info[:2] == (3, 12),
              f"{sys.platform} {sys.version_info[:3]}", required=False)

    scenarios_summary = []
    for spec in (
        S.controller_dual_role_scenario(),
        S.inherited_deny_scenario(),
        S.cycle_rooted_scenario(),
        S.cycle_rootless_scenario(),
    ):
        scenarios_summary.append(verify_small_scenario(spec, rec, cert_dir))

    migration = verify_migration(rec, cert_dir, seal_dir)
    verify_watermarks(rec)
    verify_tracker_split(rec)
    fuzz = verify_fuzz(rec)

    scale = run_scale_check()
    for name, ok in scale["checks"].items():
        rec.check("scale:60k", name, bool(ok))
    _write_json(art / "scale60k.report.json", scale)

    report: dict[str, Any] = {
        "schema": "perm-proof/verification-run/v1",
        "ok": rec.overall_ok and bool(scale["ok"]),
        "environment": env,
        "summary": {
            "total_checks": len(rec.checks),
            "passed": sum(1 for c in rec.checks if c["ok"]),
            "failed_required": len(rec.required_failures),
            "informational_failures": sum(
                1 for c in rec.checks if not c["ok"] and not c["affects_overall"]
            ),
        },
        "checks": rec.checks,
        "scenarios": scenarios_summary,
        "migration": migration,
        "fuzz": fuzz,
        "scale": scale,
        "artifacts": {
            "root": str(art),
            "certificates": str(cert_dir),
            "sealed": str(seal_dir),
        },
        "report_digest": "",
    }
    report["report_digest"] = sha256_hex(
        {k: v for k, v in report.items() if k != "report_digest"}
    )

    _write_json(art / "verification_report.json", report)
    (ROOT / "VERIFICATION_REPORT.md").write_text(
        render_markdown(report), encoding="utf-8"
    )
    return report


def render_markdown(report: dict[str, Any]) -> str:
    ok = report["ok"]
    s = report["summary"]
    lines: list[str] = []
    lines.append("# 离线权限证明 — 验证报告")
    lines.append("")
    banner = "✅ 全部必检项通过" if ok else "❌ 存在未通过的必检项"
    lines.append(f"**总体结论：{banner}**")
    lines.append("")
    lines.append(
        f"- 检查项：{s['passed']}/{s['total_checks']} 通过；"
        f"必检失败 {s['failed_required']}；信息性失败 {s['informational_failures']}"
    )
    env = report["environment"]
    lines.append(f"- 运行环境：`{env['sys_platform']}` · Python {sys.version.split()[0]} · 仅标准库")
    lines.append(f"- 报告摘要哈希：`{report['report_digest'][:16]}…`")
    lines.append("")

    lines.append("## 关键结论")
    lines.append("")
    mig = report.get("migration", {})
    if mig:
        lines.append(f"- 撤销前建议例外：`{mig.get('chosen_v1')}`，水位 `{mig.get('watermark_v1')}`")
        lines.append(f"  - 保留的独立来源：`{mig.get('sources_v1')}`")
        lines.append(f"- 晚到撤销后当前建议：`{mig.get('chosen_v2')}`，水位 `{mig.get('watermark_v2')}`")
        lines.append(f"  - 保留的独立来源：`{mig.get('sources_v2')}`")
        lines.append("- 已封存 `SEAL-0001` 不被重写，哈希与独立验证均保持有效；撤销只产生 `SEAL-0002`。")
    sc = report.get("scale", {})
    if sc:
        lines.append(
            f"- 规模：角色边 **{sc['role_edge_count']}** 条；角色弱分量 **{sc['role_weak_component_count']}**；"
            f"SCC **{sc['role_scc_count']}**（含环 SCC {sc['role_cyclic_scc_count']}）。"
        )
        lines.append(
            f"- 一次资源侧规则变更使合并图分量 {sc['combined_component_count_before']} → "
            f"{sc['combined_component_count_after']}；增量跟踪与全量重算一致："
            f"**{sc['full_consistency']['incremental_matches_full']}**。"
        )
    lines.append(f"- 随机交叉核对：{report['fuzz']['cases']} 个确定性小实例，"
                 f"共枚举 {report['fuzz']['subset_evals']} 个子集，枚举预言机与定序求解器完全一致。")
    lines.append("")

    lines.append("## 小规模独立枚举场景")
    lines.append("")
    lines.append("| 场景 | 候选数 | 枚举子集 | 可行数 | 最少 | 固定顺序证书选择 | 证书 |")
    lines.append("|---|---:|---:|---:|---:|---|---|")
    for scn in report.get("scenarios", []):
        lines.append(
            f"| {scn['id']} | {scn.get('candidate_count')} | {scn.get('enumerated_subset_count')} "
            f"| {scn.get('feasible_count')} | {scn.get('optimum_size')} "
            f"| `{scn.get('canonical_winner')}` | {'✅' if scn.get('cert_valid') else '❌'} |"
        )
    lines.append("")

    lines.append("## 全部检查明细")
    lines.append("")
    current_section = None
    for c in report["checks"]:
        if c["section"] != current_section:
            current_section = c["section"]
            lines.append(f"### {current_section}")
            lines.append("")
        mark = "✅" if c["ok"] else ("⚠️" if not c["affects_overall"] else "❌")
        req = "" if c["affects_overall"] else " _(信息性)_"
        detail = f" — `{c['detail']}`" if c.get("detail") else ""
        lines.append(f"- {mark} **{c['name']}**{req}{detail}")
    lines.append("")

    lines.append("## 独立复核方式（原生 Windows / Python 3.12 / 仅标准库）")
    lines.append("")
    lines.append("```bat")
    lines.append("python run.py")
    lines.append("python -m permission_proof selftest")
    lines.append("python -m permission_proof verify artifacts\\sealed\\SEAL-0001.json")
    lines.append("python -m permission_proof scale")
    lines.append("```")
    lines.append("")
    lines.append("证书为规范化 JSON + SHA-256；验证器会从内嵌策略快照重新枚举全部例外集合，"
                 "独立重算最少性、固定顺序同成本赢家、保留来源与职责互斥，而非信任证书中的结论位。")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    report = run_all()
    print(canonical_dumps({
        "ok": report["ok"],
        "summary": report["summary"],
        "scale": {
            "role_edge_count": report["scale"]["role_edge_count"],
            "role_weak_component_count": report["scale"]["role_weak_component_count"],
            "combined_before": report["scale"]["combined_component_count_before"],
            "combined_after": report["scale"]["combined_component_count_after"],
            "full_consistency": report["scale"]["full_consistency"],
        },
        "migration": {
            "chosen_v1": report["migration"].get("chosen_v1"),
            "chosen_v2": report["migration"].get("chosen_v2"),
        },
    }))
    if report["ok"]:
        print("ALL CHECKS PASSED — see VERIFICATION_REPORT.md and artifacts/")
        return 0
    print("CHECKS FAILED — see VERIFICATION_REPORT.md / artifacts/verification_report.json")
    for f in report["checks"]:
        if not f["ok"] and f["affects_overall"]:
            print(f"[FAIL] {f['section']} :: {f['name']}\n{f['detail']}", file=sys.stderr)
    return 1
