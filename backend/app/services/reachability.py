"""
Reachability Phase 3 — function-level call graph (Python AST).

Phase 1: was the package imported at all?
Phase 2: only in test/script paths, or in main code?
Phase 3: does a main-code entry point actually call into the package API?

scan_zip() returns ScanResult:
  presence     — PackagePresence {pkg: {main, test}}
  ast_reachable — set of packages confirmed function-reachable by AST

classify_vulns() maps each vuln to:
  "function_reachable" — AST confirmed call from entry point
  "reachable"          — imported in main code (Phase 2 level)
  "test_only"          — only in test/script dirs
  "not_found"          — not imported anywhere
  "unknown"            — component not in comp map
"""
from __future__ import annotations

import ast
import io
import re
import zipfile
from dataclasses import dataclass, field

# ── limits ─────────────────────────────────────────────────────────────────────
MAX_ZIP_BYTES  = 50 * 1024 * 1024
MAX_FILE_BYTES = 1 * 1024 * 1024
MAX_FILES      = 5_000

# ── test-path detection ────────────────────────────────────────────────────────
_TEST_SEGMENTS = frozenset({
    "test", "tests", "spec", "specs",
    "__test__", "__tests__",
    "scripts", "script",
    "fixtures", "fixture",
    "e2e", "integration",
    "conftest",
})

# Entry-point filenames (execution roots)
_ENTRY_FILENAMES = frozenset({
    "main.py", "app.py", "wsgi.py", "asgi.py",
    "run.py", "server.py", "manage.py", "cli.py",
})

# Route decorator attribute names (Flask, FastAPI, Django-ninja, APIRouter …)
_ROUTE_ATTRS = frozenset({
    "route", "get", "post", "put", "patch", "delete",
    "head", "options", "on_event", "add_api_route",
})

# ── regex (Phase 1/2 fast path) ────────────────────────────────────────────────
_PY_IMPORT = re.compile(r"""^\s*(?:import|from)\s+([\w][\w.]*)""", re.MULTILINE)
_JS_REQUIRE = re.compile(
    r"""(?:require|from)\s*[\(\s]['"]((?:@[\w-]+/)?[\w][\w.-]*)['"]"""
)


def _normalise(name: str) -> str:
    return name.lower().split(".")[0].replace("-", "_")


def _is_test_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    parts = lower.split("/")
    for part in parts[:-1]:
        if part in _TEST_SEGMENTS:
            return True
    filename = parts[-1]
    if filename.startswith("test_") or filename.startswith("spec_"):
        return True
    stem = filename.rsplit(".", 1)[0]
    if stem.endswith((".test", ".spec")):
        return True
    return False


def _is_text_file(name: str) -> bool:
    return name.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"))


def _is_entry_file(path: str) -> bool:
    return path.lower().replace("\\", "/").split("/")[-1] in _ENTRY_FILENAMES


def _extract_packages_regex(content: str, filename: str) -> set[str]:
    """Fast regex-based import extraction (Phase 1/2)."""
    pkgs: set[str] = set()
    if filename.endswith(".py"):
        for m in _PY_IMPORT.finditer(content):
            pkg = _normalise(m.group(1))
            if pkg:
                pkgs.add(pkg)
    else:
        for m in _JS_REQUIRE.finditer(content):
            pkg = m.group(1)
            if not pkg.startswith("."):
                pkgs.add(_normalise(pkg))
    return pkgs


# ── AST analyser ───────────────────────────────────────────────────────────────

class _FileAnalyser(ast.NodeVisitor):
    """
    Single-pass AST visitor that builds:
      alias_map  : {local_name -> pkg_name}  for packages we care about
      pkg_used_in: {pkg_name -> set(func_key)}  where func_key is the
                   containing function name, or "__module__" for top-level
      call_graph : {caller_func -> set(callee_name)}  intra-file only
      entry_points: set of func names that are routes / __main__ calls
    """

    def __init__(self, target_pkgs: set[str], is_entry_file: bool) -> None:
        self.target_pkgs  = target_pkgs
        self.alias_map:   dict[str, str]        = {}
        self.pkg_used_in: dict[str, set[str]]   = {}
        self.call_graph:  dict[str, set[str]]   = {}
        self.entry_points: set[str]             = set()
        self._scope: list[str]                  = []   # function scope stack
        self._is_entry_file = is_entry_file

    # ── current scope helper ──────────────────────────────────────────────────

    def _cur(self) -> str:
        return self._scope[-1] if self._scope else "__module__"

    # ── import visitors ───────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            pkg = _normalise(alias.name)
            if pkg in self.target_pkgs:
                local = _normalise(alias.asname) if alias.asname else pkg
                self.alias_map[local] = pkg
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module:
            return
        pkg = _normalise(node.module)
        if pkg in self.target_pkgs:
            for alias in node.names:
                local = _normalise(alias.asname) if alias.asname else _normalise(alias.name)
                self.alias_map[local] = pkg
        self.generic_visit(node)

    # ── function visitors ─────────────────────────────────────────────────────

    def _enter_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._scope.append(node.name)
        self.call_graph.setdefault(node.name, set())
        # Route decorator → entry point
        for dec in node.decorator_list:
            func = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(func, ast.Attribute) and func.attr in _ROUTE_ATTRS:
                self.entry_points.add(node.name)
            elif isinstance(func, ast.Name) and func.id in _ROUTE_ATTRS:
                self.entry_points.add(node.name)
        # All functions in entry files are treated as potential entry points
        if self._is_entry_file:
            self.entry_points.add(node.name)

    def _exit_func(self) -> None:
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_func(node)
        self.generic_visit(node)
        self._exit_func()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_func(node)
        self.generic_visit(node)
        self._exit_func()

    # ── call visitor ──────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        pkg: str | None = None

        if isinstance(func, ast.Attribute):
            # alias.method()
            if isinstance(func.value, ast.Name) and func.value.id in self.alias_map:
                pkg = self.alias_map[func.value.id]
        elif isinstance(func, ast.Name):
            if func.id in self.alias_map:
                # direct call of imported name: Flask(), pytest.raises() …
                pkg = self.alias_map[func.id]
            else:
                # track intra-file call graph
                cur = self._cur()
                if cur != "__module__":
                    self.call_graph.setdefault(cur, set()).add(func.id)

        if pkg:
            ctx = self._cur()
            self.pkg_used_in.setdefault(pkg, set()).add(ctx)

        self.generic_visit(node)


def _ast_reachable_in_file(
    content: str,
    filepath: str,
    target_pkgs: set[str],
) -> set[str]:
    """
    Return subset of target_pkgs that are function-reachable in this file.
    """
    is_entry = _is_entry_file(filepath)
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return set()

    analyser = _FileAnalyser(target_pkgs, is_entry)
    analyser.visit(tree)

    confirmed: set[str] = set()
    for pkg, used_in in analyser.pkg_used_in.items():
        # Module-level usage → always reachable
        if "__module__" in used_in:
            confirmed.add(pkg)
            continue
        # Used directly in an entry-point function
        if used_in & analyser.entry_points:
            confirmed.add(pkg)
            continue
        # Entry point calls a function that uses the package (1-hop)
        for ep in analyser.entry_points:
            if analyser.call_graph.get(ep, set()) & used_in:
                confirmed.add(pkg)
                break

    return confirmed


# ── public API ─────────────────────────────────────────────────────────────────

PackagePresence = dict[str, dict[str, bool]]  # {pkg: {"main": bool, "test": bool}}


@dataclass
class ScanResult:
    presence:      PackagePresence        = field(default_factory=dict)
    ast_reachable: set[str]              = field(default_factory=set)


def scan_zip(zip_bytes: bytes) -> ScanResult:
    """
    Phase 1+2: regex import scan → presence dict.
    Phase 3:   AST scan on main Python files for packages already in presence["main"].
    Raises ValueError for bad input.
    """
    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise ValueError(f"壓縮檔超過 {MAX_ZIP_BYTES // 1024 // 1024} MB 上限")
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise ValueError("無效的 zip 檔案")

    presence: PackagePresence = {}
    main_py_files: list[tuple[str, str]] = []   # (path, content) for AST pass
    file_count = 0

    for info in zf.infolist():
        name = info.filename
        if info.is_dir() or ".." in name or name.startswith("/"):
            continue
        if file_count >= MAX_FILES:
            break
        if not _is_text_file(name):
            continue
        if info.file_size > MAX_FILE_BYTES:
            continue

        file_count += 1
        try:
            content = zf.read(name).decode("utf-8", errors="ignore")
        except Exception:
            continue

        is_test = _is_test_path(name)
        for pkg in _extract_packages_regex(content, name):
            entry = presence.setdefault(pkg, {"main": False, "test": False})
            if is_test:
                entry["test"] = True
            else:
                entry["main"] = True

        # Collect main Python files for AST phase
        if not is_test and name.endswith(".py"):
            main_py_files.append((name, content))

    zf.close()

    # Phase 3: AST analysis — only for packages found in main code
    main_pkgs = {pkg for pkg, info in presence.items() if info["main"]}
    ast_reachable: set[str] = set()
    if main_pkgs:
        for filepath, content in main_py_files:
            ast_reachable |= _ast_reachable_in_file(content, filepath, main_pkgs)

    return ScanResult(presence=presence, ast_reachable=ast_reachable)


def classify_vulns(
    vulns,
    result: ScanResult,
    comp_map: dict,
) -> dict[str, str]:
    """
    comp_map: {component_id -> component_obj}
    Returns {vuln_id -> reachability_label}
    """
    out: dict[str, str] = {}
    for v in vulns:
        comp = comp_map.get(v.component_id)
        if comp is None:
            out[v.id] = "unknown"
            continue
        pkg = _normalise(comp.name)
        info = result.presence.get(pkg)
        if info is None:
            out[v.id] = "not_found"
        elif info["main"]:
            out[v.id] = "function_reachable" if pkg in result.ast_reachable else "reachable"
        elif info["test"]:
            out[v.id] = "test_only"
        else:
            out[v.id] = "not_found"
    return out
