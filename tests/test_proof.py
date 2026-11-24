"""Stdlib unittest suite for the offline permission-proof system.

Run from the workspace root::

    python -m permission_proof selftest
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from permission_proof import scenarios as scn  # noqa: E402
from permission_proof.certificate import (  # noqa: E402
    build_certificate,
    verify_certificate,
)
from permission_proof.evaluate import (  # noqa: E402
    evaluate_permission,
    evaluate_sod_controller,
    evaluate_sod_principal_level,
)
from permission_proof.exceptions import (  # noqa: E402
    enumerate_exception_sets,
    solve_min_exceptions,
)
from permission_proof.graph import (  # noqa: E402
    DSU,
    TrackedComponents,
    classify_role_cycles,
    kosaraju_scc,
    partitions_equal,
    weak_component_partition,
)
from permission_proof.scale60k import run_scale_check  # noqa: E402
from permission_proof.seal import (  # noqa: E402
    GENESIS_HASH,
    ImmutableSealError,
    SealStore,
    tamper_probe,
    verify_envelope,
)
from permission_proof.store import AUTH, SOD, PolicyLog  # noqa: E402
from permission_proof.world import World, world_with_exceptions  # noqa: E402


def force_rmtree(path: str) -> None:
    def make_writable(func, p, _exc):  # noqa: ANN001
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable)
    else:  # pragma: no cover - target runtime is 3.12
        shutil.rmtree(path, onerror=make_writable)


class CanonicalTieBreakTests(unittest.TestCase):
    def test_s1_controller_dual_role(self):
        spec = scn.controller_dual_role_scenario()
        enum = enumerate_exception_sets(
            spec["world"], spec["candidates"], spec["requirements"], spec["principal"]
        )
        self.assertEqual(enum["optimum_size"], 1)
        self.assertEqual(enum["canonical_winner"], ["EXC-S1-20-payops-role"])
        self.assertIn(["EXC-S1-30-direct-perm"], enum["same_cost_winners"])

        augmented = world_with_exceptions(
            spec["world"], spec["candidates"], ["EXC-S1-10-approver-role"]
        )
        self.assertFalse(evaluate_sod_controller(augmented)["ok"])
        # The naive per-account view misses the same-controller conflict.
        self.assertTrue(evaluate_sod_principal_level(augmented)["ok"])

    def test_s2_inherited_deny(self):
        spec = scn.inherited_deny_scenario()
        base = World(spec["world"])
        d = evaluate_permission(base, spec["principal"], "res.db_prod", "read")
        self.assertEqual(d["decision"], "deny")
        self.assertEqual(d["decisive_kind"], "deny_overrides")
        self.assertTrue(any("inherited-deny" in s for s in d["blocking_deny_sources"]))

        plain = enumerate_exception_sets(
            spec["world"],
            [c for c in spec["candidates"] if c["id"] == "EXC-S2-10-allow-plain"],
            spec["requirements"],
            spec["principal"],
        )
        self.assertIsNone(plain["optimum_size"])
        self.assertEqual(plain["feasible_count"], 0)

        full = solve_min_exceptions(
            spec["world"], spec["candidates"], spec["requirements"], spec["principal"]
        )
        self.assertEqual(full["chosen"], ["EXC-S2-20-breakglass-a"])

    def test_s3_cycle_classification(self):
        rooted = scn.cycle_rooted_scenario()
        w = World(rooted["world"])
        infos = classify_role_cycles(
            w.directed_edges, w.entitlement_root_roles(),
            nodes=[r["id"] for r in w.roles],
        )
        self.assertEqual(len(infos), 1)
        self.assertTrue(infos[0].has_real_root_inside)
        self.assertFalse(infos[0].rootless)
        d = evaluate_permission(w, rooted["principal"], "res.loop_real", "read")
        self.assertTrue(d["allowed"])
        sol = solve_min_exceptions(
            rooted["world"], rooted["candidates"], rooted["requirements"],
            rooted["principal"],
        )
        self.assertEqual(sol["optimum_size"], 0)
        self.assertEqual(sol["chosen"], [])

        rootless = scn.cycle_rootless_scenario()
        w2 = World(rootless["world"])
        infos2 = classify_role_cycles(
            w2.directed_edges, w2.entitlement_root_roles(),
            nodes=[r["id"] for r in w2.roles],
        )
        self.assertEqual(len(infos2), 1)
        self.assertTrue(infos2[0].rootless)
        self.assertFalse(infos2[0].has_real_root_inside)
        sol2 = solve_min_exceptions(
            rootless["world"], rootless["candidates"], rootless["requirements"],
            rootless["principal"],
        )
        self.assertEqual(sol2["chosen"], ["EXC-S3B-20-real-grant"])


class GraphTests(unittest.TestCase):
    def test_scc_cycle_and_dag(self):
        res = kosaraju_scc([("a", "b"), ("b", "a"), ("b", "c")])
        comps = {frozenset(c) for c in res.components}
        self.assertIn(frozenset({"a", "b"}), comps)
        self.assertIn(frozenset({"c"}), comps)

    def test_dsu_matches_bfs(self):
        edges = [("a", "b"), ("b", "c"), ("d", "e")]
        self.assertTrue(
            partitions_equal(dsu_partition_safe(edges), weak_component_partition(edges))
        )
        d = DSU(["x"])
        self.assertEqual(d.components, 1)
        d.union("x", "y")
        self.assertEqual(d.components, 1)

    def test_tracker_merge_and_split(self):
        merge = TrackedComponents.from_edges([("a0", "a1"), ("b0", "b1")])
        self.assertEqual(merge.count, 2)
        count = merge.apply_changeset(added_edges=[("a1", "b0")])
        self.assertEqual(count, 1)
        self.assertTrue(merge.matches_full_recompute())

        split = TrackedComponents.from_edges([("a0", "a1"), ("a1", "a2"), ("b0", "b1")])
        self.assertEqual(split.count, 2)
        after = split.apply_changeset(removed_edges=[("a1", "a2")])
        self.assertEqual(after, 3)
        self.assertTrue(split.matches_full_recompute())


def dsu_partition_safe(edges):
    from permission_proof.graph import dsu_partition

    return dsu_partition(edges)


class WatermarkTests(unittest.TestCase):
    def test_independent_auth_and_sod_watermarks(self):
        log = PolicyLog()
        log.add("edges", {"id": "E1", "child": "a", "parent": "b"}, "old", AUTH)
        log.add("sod", {"id": "S1", "role_a": "a", "role_b": "b"}, "new", SOD)
        self.assertEqual(len(log.fold({}).get("edges", [])), 0)
        log.advance("old", AUTH)
        f = log.fold()
        self.assertEqual(len(f["edges"]), 1)
        self.assertEqual(len(f["sod"]), 0)
        log.advance("new", SOD)
        self.assertEqual(len(log.fold()["sod"]), 1)

    def test_late_revocation_hidden_until_watermark_advances(self):
        log = scn.build_migration_log()
        before = log.fold()
        self.assertTrue(any(a["id"] == "ASG-OLD-DUTY-ONCALL" for a in before["assignments"]))
        log.revoke("assignments", "ASG-OLD-DUTY-ONCALL", "old", AUTH)
        # Not advanced yet: the late revocation is still invisible.
        still = log.fold()
        self.assertTrue(any(a["id"] == "ASG-OLD-DUTY-ONCALL" for a in still["assignments"]))
        log.advance("old", AUTH)
        after = log.fold()
        self.assertFalse(any(a["id"] == "ASG-OLD-DUTY-ONCALL" for a in after["assignments"]))


class CertificateSealTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="permproof_test_")
        self.addCleanup(force_rmtree, self.tmp)

    def _migration_cert(self):
        log = scn.build_migration_log()
        wm = log.watermark_vector()
        world = log.fold(wm)
        cands = scn.migration_candidates()
        sol = solve_min_exceptions(
            world, cands, scn.MIGRATION_REQUIREMENTS, scn.MIGRATION_PRINCIPAL
        )
        cert = build_certificate(
            cert_id="CERT-T",
            title="t",
            target_change={},
            principal=scn.MIGRATION_PRINCIPAL,
            requirements=scn.MIGRATION_REQUIREMENTS,
            world_def=world,
            candidates=cands,
            solution=sol,
            watermark_vector=wm,
        )
        return cert

    def test_certificate_verifies_and_detects_tamper(self):
        cert = self._migration_cert()
        self.assertTrue(verify_certificate(cert)["valid"])
        mutated = json.loads(json.dumps(cert))
        mutated["chosen_exceptions"].append("EXC-M04-deploy-scoped")
        self.assertFalse(verify_certificate(mutated)["valid"])

    def test_seal_immutability_revocation_and_tamper(self):
        cert1 = self._migration_cert()
        store = SealStore(Path(self.tmp) / "sealed")
        rec1 = store.seal_version("SEAL-0001", cert1, "v1")
        p1 = Path(rec1.path)
        bytes_before = p1.read_bytes()

        with self.assertRaises(ImmutableSealError):
            store.seal_version("SEAL-0001", cert1, "rewrite")

        env1 = json.loads(bytes_before.decode("utf-8"))
        self.assertTrue(verify_envelope(env1, expected_prev=GENESIS_HASH)["valid"])
        self.assertFalse(tamper_probe(env1)["valid"])

        # A second version chains and leaves v1 bytes untouched.
        cert2 = json.loads(json.dumps(cert1))
        cert2["cert_id"] = "CERT-T2"
        from permission_proof.canon import sha256_hex

        cert2["cert_hash"] = sha256_hex(
            {k: v for k, v in cert2.items() if k != "cert_hash"}
        )
        store.seal_version("SEAL-0002", cert2, "v2")
        self.assertEqual(p1.read_bytes(), bytes_before)
        chain = store.verify_chain()
        self.assertTrue(chain["valid"])
        self.assertEqual(chain["sealed_version_count"], 2)


class ScaleTests(unittest.TestCase):
    def test_60k_consistency(self):
        rep = run_scale_check()
        self.assertEqual(rep["role_edge_count"], 60_000)
        self.assertEqual(rep["role_weak_component_count"], 40)
        self.assertEqual(rep["combined_component_count_before"], 40)
        self.assertEqual(rep["combined_component_count_after"], 39)
        self.assertTrue(rep["full_consistency"]["incremental_matches_full"])
        self.assertTrue(rep["ok"], msg=json.dumps(rep["checks"], ensure_ascii=False))


class IntegrationRunTests(unittest.TestCase):
    def test_full_run_all_in_temp_artifacts(self):
        from permission_proof.verify_all import run_all

        tmp = tempfile.mkdtemp(prefix="permproof_run_")
        self.addCleanup(force_rmtree, tmp)
        report = run_all(Path(tmp) / "artifacts")
        failed = [
            (c["section"], c["name"], c["detail"])
            for c in report["checks"]
            if not c["ok"] and c["affects_overall"]
        ]
        self.assertTrue(report["ok"], msg=json.dumps(failed, ensure_ascii=False, indent=2))
        self.assertTrue((ROOT / "VERIFICATION_REPORT.md").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
