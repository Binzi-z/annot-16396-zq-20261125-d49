"""Graph primitives for role inheritance and the combined authorization graph.

The module is deliberately dependency-free and provides two independent
component implementations (union-find and BFS) so the 60k-edge consistency
check can cross-check them.  SCCs use an iterative Kosaraju pass to avoid
Python recursion-depth / C-stack problems on deep synthetic chains.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Hashable, Iterable

Node = Hashable
Edge = tuple[Node, Node]


# --------------------------------------------------------------------------- #
# Union-find
# --------------------------------------------------------------------------- #
class DSU:
    """Disjoint-set union (weak connectivity)."""

    def __init__(self, nodes: Iterable[Node] = ()) -> None:
        self.parent: dict[Node, Node] = {}
        self.size: dict[Node, int] = {}
        self.components = 0
        for n in nodes:
            self.add(n)

    def add(self, x: Node) -> None:
        if x not in self.parent:
            self.parent[x] = x
            self.size[x] = 1
            self.components += 1

    def find(self, x: Node) -> Node:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != x:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: Node, b: Node) -> bool:
        self.add(a)
        self.add(b)
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        self.components -= 1
        return True

    def component_map(self) -> dict[Node, int]:
        root_to_label: dict[Node, int] = {}
        out: dict[Node, int] = {}
        for n in self.parent:
            r = self.find(n)
            if r not in root_to_label:
                root_to_label[r] = len(root_to_label)
            out[n] = root_to_label[r]
        return out


# --------------------------------------------------------------------------- #
# Weak components (BFS / DSU) + partition comparison
# --------------------------------------------------------------------------- #
def build_undirected_adjacency(
    edges: Iterable[Edge], nodes: Iterable[Node] | None = None
) -> dict[Node, set[Node]]:
    adj: dict[Node, set[Node]] = defaultdict(set)
    if nodes is not None:
        for n in nodes:
            adj.setdefault(n, set())
    for u, v in edges:
        adj[u].add(v)
        adj[v].add(u)
    return dict(adj)


def weak_component_partition(
    edges: Iterable[Edge], nodes: Iterable[Node] | None = None
) -> list[frozenset[Node]]:
    """Return weak connected components as canonical frozensets of nodes."""
    adj = build_undirected_adjacency(edges, nodes)
    seen: set[Node] = set()
    parts: list[frozenset[Node]] = []
    for start in adj:
        if start in seen:
            continue
        q: deque[Node] = deque([start])
        seen.add(start)
        members: set[Node] = set()
        while q:
            u = q.popleft()
            members.add(u)
            for w in adj[u]:
                if w not in seen:
                    seen.add(w)
                    q.append(w)
        parts.append(frozenset(members))
    return parts


def weak_component_count(edges: Iterable[Edge], nodes: Iterable[Node] | None = None) -> int:
    return len(weak_component_partition(edges, nodes))


def dsu_partition(
    edges: Iterable[Edge], nodes: Iterable[Node] | None = None
) -> list[frozenset[Node]]:
    dsu = DSU(nodes or ())
    materialized = list(edges)
    for u, v in materialized:
        dsu.union(u, v)
    groups: dict[Node, set[Node]] = defaultdict(set)
    for n in dsu.parent:
        groups[dsu.find(n)].add(n)
    return [frozenset(g) for g in groups.values()]


def partition_signature(partition: Iterable[frozenset[Node]]) -> frozenset[frozenset[Node]]:
    return frozenset(partition)


def partitions_equal(
    a: Iterable[frozenset[Node]], b: Iterable[frozenset[Node]]
) -> bool:
    return partition_signature(a) == partition_signature(b)


def component_maps_equal(map_a: dict[Node, Node], map_b: dict[Node, Node]) -> bool:
    """Compare two label maps up to arbitrary label naming."""

    def groups(m: dict[Node, Node]) -> frozenset[frozenset[Node]]:
        g: dict[Node, set[Node]] = defaultdict(set)
        for node, label in m.items():
            g[label].add(node)
        return frozenset(frozenset(s) for s in g.values())

    return groups(map_a) == groups(map_b)


# --------------------------------------------------------------------------- #
# Strongly connected components (iterative Kosaraju)
# --------------------------------------------------------------------------- #
@dataclass
class SCCResult:
    comp_id: dict[Node, int]
    components: list[list[Node]]

    @property
    def count(self) -> int:
        return len(self.components)

    def cyclic_component_ids(self, directed_edges: Iterable[Edge]) -> set[int]:
        """Labels of SCCs that contain a directed cycle.

        An SCC is cyclic when it has more than one node, or a single node with
        a self-loop.
        """
        self_loops = {u for u, v in directed_edges if u == v}
        cyclic: set[int] = set()
        for cid, members in enumerate(self.components):
            if len(members) > 1:
                cyclic.add(cid)
            elif members and members[0] in self_loops:
                cyclic.add(cid)
        return cyclic


def kosaraju_scc(
    directed_edges: Iterable[Edge], nodes: Iterable[Node] | None = None
) -> SCCResult:
    edges = list(directed_edges)
    adj: dict[Node, list[Node]] = defaultdict(list)
    radj: dict[Node, list[Node]] = defaultdict(list)
    all_nodes: set[Node] = set(nodes or ())
    for u, v in edges:
        adj[u].append(v)
        radj[v].append(u)
        all_nodes.add(u)
        all_nodes.add(v)

    # First pass: finishing order (iterative).
    visited: set[Node] = set()
    order: list[Node] = []
    for start in sorted(all_nodes, key=str):
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[Node, int]] = [(start, 0)]
        while stack:
            v, idx = stack[-1]
            neigh = adj.get(v, ())
            if idx < len(neigh):
                to = neigh[idx]
                stack[-1] = (v, idx + 1)
                if to not in visited:
                    visited.add(to)
                    stack.append((to, 0))
            else:
                order.append(v)
                stack.pop()

    # Second pass on the reversed graph.
    comp_id: dict[Node, int] = {}
    components: list[list[Node]] = []
    cid = 0
    for start in reversed(order):
        if start in comp_id:
            continue
        comp_id[start] = cid
        stack = [start]
        members: list[Node] = []
        while stack:
            v = stack.pop()
            members.append(v)
            for to in radj.get(v, ()):
                if to not in comp_id:
                    comp_id[to] = cid
                    stack.append(to)
        components.append(sorted(members, key=str))
        cid += 1
    return SCCResult(comp_id=comp_id, components=components)


# --------------------------------------------------------------------------- #
# Cycle root classification
# --------------------------------------------------------------------------- #
@dataclass
class CycleInfo:
    component_id: int
    nodes: tuple[Node, ...]
    has_real_root_inside: bool
    reaches_real_root: bool
    rootless: bool
    real_roots_inside: tuple[Node, ...]


def nodes_that_reach_seeds(
    directed_edges: Iterable[Edge], seeds: Iterable[Node]
) -> set[Node]:
    """All nodes from which any seed is reachable (reverse BFS)."""
    edges = list(directed_edges)
    radj: dict[Node, list[Node]] = defaultdict(list)
    for u, v in edges:
        radj[v].append(u)
    seed_set = set(seeds)
    seen: set[Node] = set(seed_set)
    stack = list(seed_set)
    while stack:
        v = stack.pop()
        for pred in radj.get(v, ()):
            if pred not in seen:
                seen.add(pred)
                stack.append(pred)
    return seen


def classify_role_cycles(
    directed_edges: Iterable[Edge],
    real_root_seeds: Iterable[Node],
    nodes: Iterable[Node] | None = None,
) -> list[CycleInfo]:
    """Classify every cyclic SCC as real-rooted or rootless.

    A "real root seed" is a role at which genuine policy authority is
    declared (an effective entitlement rule or an explicitly designated
    authority root).  A ring that contains such a seed is a ring with a real
    root; a cyclic SCC that neither contains nor reaches any seed is a
    rootless loop that confers no authority of its own.
    """
    edges = list(directed_edges)
    scc = kosaraju_scc(edges, nodes)
    cyclic_ids = scc.cyclic_component_ids(edges)
    seeds = set(real_root_seeds)
    reach_seed = nodes_that_reach_seeds(edges, seeds)

    infos: list[CycleInfo] = []
    for cid in sorted(cyclic_ids):
        members = scc.components[cid]
        inside = tuple(sorted((n for n in members if n in seeds), key=str))
        has_inside = bool(inside)
        reaches = any(n in reach_seed for n in members)
        infos.append(
            CycleInfo(
                component_id=cid,
                nodes=tuple(members),
                has_real_root_inside=has_inside,
                reaches_real_root=reaches,
                rootless=not reaches,
                real_roots_inside=inside,
            )
        )
    infos.sort(key=lambda c: tuple(map(str, c.nodes)))
    return infos


# --------------------------------------------------------------------------- #
# Affected-component tracker for a single graph/rule change
# --------------------------------------------------------------------------- #
@dataclass
class TrackedComponents:
    """Incremental weak-component state supporting one edge changeset.

    The tracker only recomputes the connected component(s) touched by a
    mutation; untouched components keep their labels.  After the change the
    result can be compared against a complete from-scratch recomputation via
    :meth:`matches_full_recompute`.
    """

    nodes: set[Node]
    adjacency: dict[Node, set[Node]] = field(default_factory=dict)
    label: dict[Node, int] = field(default_factory=dict)
    members: dict[int, set[Node]] = field(default_factory=dict)
    _next_label: int = 0

    @classmethod
    def from_edges(
        cls, edges: Iterable[Edge], nodes: Iterable[Node] | None = None
    ) -> "TrackedComponents":
        node_set: set[Node] = set(nodes or ())
        adj: dict[Node, set[Node]] = defaultdict(set)
        for n in node_set:
            adj.setdefault(n, set())
        for u, v in edges:
            node_set.add(u)
            node_set.add(v)
            adj[u].add(v)
            adj[v].add(u)
        tracker = cls(nodes=node_set, adjacency=dict(adj))
        tracker._full_relabel()
        return tracker

    def _full_relabel(self) -> None:
        # Direct BFS over the adjacency that is already the source of truth.
        seen: set[Node] = set()
        self.label = {}
        self.members = {}
        next_label = 0
        for start in self.nodes:
            if start in seen:
                continue
            seen.add(start)
            q: deque[Node] = deque([start])
            group: set[Node] = set()
            while q:
                u = q.popleft()
                group.add(u)
                self.label[u] = next_label
                for w in self.adjacency.get(u, ()):  # type: ignore[arg-type]
                    if w not in seen:
                        seen.add(w)
                        q.append(w)
            self.members[next_label] = group
            next_label += 1
        self._next_label = next_label

    @property
    def count(self) -> int:
        return len(self.members)

    def partition(self) -> list[frozenset[Node]]:
        return [frozenset(g) for g in self.members.values()]

    def apply_changeset(
        self,
        removed_edges: Iterable[Edge] = (),
        added_edges: Iterable[Edge] = (),
    ) -> int:
        """Apply one atomic edge changeset and locally recompute components.

        Returns the new component count.
        """
        removed = list(removed_edges)
        added = list(added_edges)

        # Affected old labels are the components owning every endpoint before
        # the mutation.
        affected_labels: set[int] = set()
        endpoints: set[Node] = set()
        for u, v in removed + added:
            endpoints.add(u)
            endpoints.add(v)
        for n in endpoints:
            self.nodes.add(n)
            affected_labels.add(self.label.get(n, self._next_label))

        affected_nodes: set[Node] = set()
        for lab in affected_labels:
            affected_nodes |= self.members.pop(lab, set())
        # New endpoints that had no label yet are part of the affected region.
        affected_nodes |= endpoints

        # Mutate adjacency.
        for u, v in removed:
            self.adjacency.get(u, set()).discard(v)
            self.adjacency.get(v, set()).discard(u)
        for u, v in added:
            self.adjacency.setdefault(u, set()).add(v)
            self.adjacency.setdefault(v, set()).add(u)

        # Recompute components strictly inside the affected region.  An
        # unchanged edge cannot join an affected node to an unaffected one,
        # otherwise that node would already have belonged to the affected
        # label set; hence the local BFS is exact.
        local_seen: set[Node] = set()
        for start in affected_nodes:
            if start in local_seen:
                continue
            local_seen.add(start)
            q: deque[Node] = deque([start])
            group: set[Node] = set()
            while q:
                u = q.popleft()
                group.add(u)
                for w in self.adjacency.get(u, ()):  # type: ignore[arg-type]
                    if w in affected_nodes and w not in local_seen:
                        local_seen.add(w)
                        q.append(w)
            lab = self._next_label
            self._next_label += 1
            self.members[lab] = group
            for n in group:
                self.label[n] = lab
        return self.count

    def full_partition_from_scratch(self) -> list[frozenset[Node]]:
        edges: list[Edge] = []
        seen_pairs: set[tuple[Node, Node]] = set()
        for u, neigh in self.adjacency.items():
            for v in neigh:
                key = (u, v)
                rkey = (v, u)
                if key in seen_pairs or rkey in seen_pairs:
                    continue
                seen_pairs.add(key)
                edges.append((u, v))
        return weak_component_partition(edges, nodes=self.nodes)

    def matches_full_recompute(self) -> bool:
        return partitions_equal(self.partition(), self.full_partition_from_scratch())
