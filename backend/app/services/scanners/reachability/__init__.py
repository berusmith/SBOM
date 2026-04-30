"""
Reachability analysis package.

Public surface for vulnerability reachability classification.
The frozen interface is exactly what `__all__` re-exports below.
Internal implementation lives in submodules (python_analyzer.py today;
js_analyzer.py / java_analyzer.py added by Wave D sprint #3).
"""
# =============================================================================
# Wave-D contract (frozen at iter-1 PR-1 merge — see ledger.md D11 / D13)
# =============================================================================
#
# DO NOT modify the signatures, return-type structure, or label vocabulary
# below without first opening a WD-4 interface-evolution commit (see
# .refactor-audit/architecture.md §4.5 WD-4).  Any sprint #3 commit that
# touches these without that evolution commit MUST be rejected at review.
#
# -----------------------------------------------------------------------------
# FROZEN PUBLIC SURFACE (entire surface — additions allowed, removals/changes
# require WD-4):
#
#   scan_zip        (function)
#   classify_vulns  (function)
#   ScanResult      (dataclass shape)
#   PackagePresence (type alias shape; inner keys EXTENSIBLE — see below)
#
# -----------------------------------------------------------------------------
# Type aliases (frozen at iter-1 close):
#
#   ComponentMap = dict[str, ComponentLike]
#     where the key is component.id (str, UUID stringified) — NOT component.name,
#     NOT vuln.id.  This matches the call-site construction in
#     usecases/release/scanners.py (post-PR-1): `{c.id: c for c in components}`.
#
#   ComponentLike = duck-typed object exposing .name (str)
#     today: backend/app/models/component.py:Component ORM rows
#     Wave D MAY pass any object satisfying the .name protocol;
#     classify_vulns reads .name only.
#
# -----------------------------------------------------------------------------
# scan_zip(zip_bytes: bytes) -> ScanResult
#
#   Pre-conditions:
#     - zip_bytes is a bytes object containing a valid ZIP archive
#     - len(zip_bytes) <= MAX_ZIP_BYTES (50 MiB; declared in python_analyzer.py)
#
#   Post-conditions:
#     - Returns a ScanResult instance:
#         .presence       — PackagePresence (see below)
#         .ast_reachable  — set[str] of package names confirmed function-reachable
#                           (must be a subset of {pkg for pkg, info in presence.items()
#                            if info.get("main", False)})
#     - All package names in presence keys / ast_reachable are LOWERCASED AND
#       DOT-NORMALISED via the same `_normalise` rule used in python_analyzer
#       (caller-side comparisons MUST normalise the same way)
#
#   Raises:
#     - ValueError — when zip_bytes exceeds the size cap (zh-TW message in
#       python_analyzer)
#     - ValueError — when zip_bytes is not a valid ZIP (zh-TW message)
#     - (no other exception types; all other errors degrade silently to fewer
#        entries in ScanResult)
#
#   Wave D MAY:
#     - Add new languages to the regex/AST scan inside python_analyzer.py
#     - Add new analyzer modules (e.g. js_analyzer.py) and have integration.py
#       merge their ScanResult contributions into a single returned ScanResult
#
#   Wave D MAY NOT (without WD-4 evolution commit):
#     - Return anything other than ScanResult
#     - Add a new required parameter
#     - Raise a different exception type
#     - Loosen MAX_ZIP_BYTES (security cap; see code-principles §D2)
#
# -----------------------------------------------------------------------------
# classify_vulns(vulns, result: ScanResult, comp_map: ComponentMap)
#                                                            -> dict[str, str]
#
#   Pre-conditions:
#     - vulns: iterable of objects exposing .id (str) and .component_id (str)
#       (today: backend/app/models/vulnerability.py:Vulnerability ORM rows;
#        duck-typed equivalents are accepted)
#     - result: a ScanResult produced by scan_zip()
#     - comp_map: a ComponentMap (see Type aliases above) — keys are
#       component.id values (str); the lookup pattern is
#       `comp_map.get(vuln.component_id)` — vuln.id is NOT a valid lookup key
#
#   Post-conditions:
#     - Returns dict[str, str] mapping vuln.id -> reachability label
#     - Every label MUST be one of the FROZEN VOCABULARY (see below)
#     - Vulns whose component_id is not in comp_map MUST be assigned "unknown"
#       (NOT silently dropped — caller relies on every input vuln getting a key)
#
#   Frozen reachability label vocabulary (persisted to
#   vulnerabilities.reachability column; rendered by frontend; CSV-exported):
#
#     "function_reachable"  — AST confirmed call from an entry-point function
#     "reachable"           — package imported in main code (regex Phase 1/2)
#     "test_only"           — package only in test/script paths
#     "not_found"           — package not imported anywhere
#     "unknown"             — analyzer cannot determine (component absent from
#                              comp_map, OR language unsupported by available
#                              analyzers — Wave D's J15/J16 honesty cases)
#
#   Raises:
#     - None under normal operation; failures degrade to "unknown" labels.
#
#   Wave D MAY:
#     - Inside integration.py: dispatch to language-specific analyzers based on
#       file extensions found in the scan, then merge labels per the existing
#       precedence ("function_reachable" beats "reachable" beats "test_only"
#       beats "not_found" beats "unknown")
#     - Make new analyzer modules emit any of the 5 frozen labels
#
#   Wave D MAY NOT (without WD-4 evolution commit):
#     - Introduce a 6th label value (would break the DB column's implicit enum
#       and the frontend's rendering switch)
#     - Change parameter shape (e.g. require comp_map as list, or vulns as dict)
#     - Drop the "every input vuln gets a key" post-condition
#
#   Why 5 labels are FROZEN (not just guidance):
#     - Persisted to vulnerabilities.reachability column (no DB enum constraint;
#       this contract is the only enforcement)
#     - Rendered by frontend ReleaseDetail.jsx switch with hardcoded label arms
#     - Emitted to CSV export — downstream tools (customer pipelines) parse the
#       5 values; unknown values cause silent ingestion errors
#     Adding a 6th label = touching DB write path + frontend render + CSV
#     contract.  This is the same triple-touch as ARCH-1.003 / D.8 (the
#     cross-org 403→404 evolution); both rightly require WD-4 evolution.
#
# -----------------------------------------------------------------------------
# ScanResult (frozen dataclass shape)
#
#   @dataclass
#   class ScanResult:
#       presence:      PackagePresence  = field(default_factory=dict)
#       ast_reachable: set[str]         = field(default_factory=set)
#
#   Wave D MAY add OPTIONAL fields WITH defaults — additive only.  Example:
#     js_ast_reachable: set[str] = field(default_factory=set)
#
#   Wave D MAY NOT (without WD-4):
#     - Remove `presence` or `ast_reachable`
#     - Rename either field
#     - Change the type of either field (e.g. set→list, dict→dataclass)
#
# -----------------------------------------------------------------------------
# PackagePresence (frozen at the OUTER shape; inner keys are EXTENSIBLE)
#
#   PackagePresence = dict[str, dict[str, bool]]
#
#   Outer key:  package name (normalised: lowercase + dots-stripped)
#   Inner dict: at minimum {"main": bool, "test": bool}; analyzers MAY add
#               additional keys (e.g. "production_runtime", "build_only",
#               "test_fixture") WITHOUT WD-4 because additive keys are
#               read-side compatible — current consumers in classify_vulns
#               and scan_zip read inner keys via .get(key, False) defaults.
#
#   Verified at PR-1 merge: all consumers in python_analyzer.py use .get()
#   for inner-dict reads (see commit `c2f0335` C.0 — bracket-indexing on
#   the inner dict is FORBIDDEN going forward).  Adding a new inner key
#   does not require updating existing consumers.
#
#   Wave D MAY (no WD-4 needed):
#     - Add new inner keys with bool values
#
#   Wave D MAY NOT (without WD-4):
#     - Remove "main" or "test" from the inner shape
#     - Change the inner-value type (bool → int / Literal / etc.) for ANY key,
#       new or existing — type stability is the contract, not the key set
#     - Change package-name normalisation rules (would break key-based joins
#       across analyzer boundaries inside integration.py)
#
# -----------------------------------------------------------------------------
# WD-4 interface evolution process (when this contract genuinely needs to change):
#
#   1. Open a SEPARATE commit titled
#        "ref(arch): WD interface evolution — <one-line description>"
#      BEFORE any analyzer change that depends on the new shape.
#   2. In the same commit, update:
#        - this docstring (the contract)
#        - __all__ if exports change
#        - the consumer call site(s) — today:
#            backend/app/api/releases.py (post-PR-1: usecases/release/scanners.py)
#            backend/app/services/monitor.py (if applicable)
#        - characterization tests under
#            backend/tests/unit/test_reachability_*.py
#            backend/tests/fixtures/reachability/_runner/run_corpus.py
#            (the 39-fixture corpus must still pass after the evolution)
#   3. ONLY THEN open the analyzer change that uses the new shape.
#   4. The evolution commit gets a ledger.md entry under iter-N decisions
#      (the iter where Wave D is in flight) marking it as a deliberate
#      contract evolution per the spirit of D.8 / ARCH-1.003.
# =============================================================================

from .python_analyzer import (
    PackagePresence,
    ScanResult,
    classify_vulns,
    scan_zip,
)

__all__ = [
    "PackagePresence",
    "ScanResult",
    "classify_vulns",
    "scan_zip",
]
