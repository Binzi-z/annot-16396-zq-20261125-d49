"""Offline permission proof for the synthetic on-call account migration.

Pure Python 3.12 standard library only.  The package implements:

* water-marked, multi-tenant policy state (old/new tenant coexistence),
* role-inheritance graphs with SCC / weak-component analysis and a
  real-root vs rootless-cycle classifier,
* deny-override effective-permission evaluation with independent
  authority-source provenance,
* controller-granularity separation-of-duties (SoD) checks,
* brute-force exception-set enumeration and an exact minimum-cardinality
  solver with a fixed-order lexicographic tie-break,
* canonical, independently re-verifiable certificates,
* hash-chained write-once sealed versions that late revocations cannot
  rewrite,
* a deterministic 60,000-role-edge scale / consistency check.

Nothing in this package performs network or third-party calls.
"""

__version__ = "1.0.0"

#: Fixed tie-break rule identifier embedded in every certificate.
TIE_BREAK_RULE = "min-cardinality then lexicographic-smallest sorted fixed ID order"
