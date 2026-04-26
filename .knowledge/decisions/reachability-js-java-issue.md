---
status: draft (ready to file as GitHub issue)
created: 2026-04-26
target: https://github.com/berusmith/SBOM/issues/new
---

# Issue body — paste verbatim into a new GitHub issue

**Title:** Extend reachability analysis to JavaScript and Java (Phase 2/3)

---

## Context

`backend/app/services/reachability.py` currently does a three-phase
source-reachability analysis to mark each vulnerability with one of
`function_reachable` / `reachable` / `test_only` / `not_found` /
`unknown`.  This is what makes our VEX output non-trivially better than
"every CVE is open" — we can confidently say "yes the vulnerable code
is in the import graph" or "no, it only appears in tests".

**Today, only Python is fully supported:**
- **Phase 1 (regex import scan)** — works for any language
- **Phase 2 (test-path filtering)** — works for any language
- **Phase 3 (AST call graph)** — **Python only** via `ast` stdlib in
  the `_FileAnalyser` class (alias tracking, route decorator detection,
  1-hop call graph)

For JavaScript / TypeScript / Java code uploads, the analyser falls
back to import-level reachability — accurate but coarser, can't
distinguish "imported and called" from "imported but dead".

## Goal

Extend Phase 3 AST analysis to cover **JavaScript / TypeScript** and
**Java**, the two languages that account for the majority of OSS
component vulnerabilities in our customer SBOMs.

### Acceptance criteria

- [ ] JS/TS: parse `.js .jsx .ts .tsx .mjs .cjs` with alias tracking,
      route handler / framework decorator detection, 1-hop call graph
- [ ] Java: parse `.java` with import-aliasing (FQN resolution),
      annotation-based route detection (Spring `@RestController`,
      JAX-RS `@Path`), 1-hop call graph
- [ ] `classify_vulns()` returns the same five reachability labels for
      JS/Java vulns as it does for Python today
- [ ] Unit tests covering: aliased imports, dead imports (Phase 3
      should downgrade to `not_found`), test-only imports (downgrade
      to `test_only`), framework route handlers (upgrade to
      `function_reachable`)
- [ ] Performance: 10 KLOC JS project parses in ≤ 5s on a Mac Mini;
      Java ≤ 10s (slower because of more verbose AST)
- [ ] Graceful degradation: parse error on a single file logs a
      warning and continues; never crashes a SBOM upload
- [ ] Frontend: existing `reachability` column in vuln table works
      unchanged (no API contract change)

## Technical approach — JavaScript / TypeScript

**Library candidates (must be pure-Python or distributable as wheel):**

| Library | License | Notes |
|---------|---------|-------|
| `esprima-python` | BSD | Pure Python, ES6 only — TS / JSX needs preprocessing or no |
| `tree-sitter` + `tree-sitter-javascript` / `-typescript` | MIT | Compiled, but pre-built wheels for win/mac/linux. Handles JS + TS + JSX + TSX uniformly. **Recommended.** |
| `acorn` via `node` subprocess | MIT | Requires Node.js on the server — **rejected**, Mac Mini deploy script does not install Node |

**Recommended:** `tree-sitter` + `tree-sitter-javascript` +
`tree-sitter-typescript`.  Pre-built wheels exist for all three
target platforms.  Single grammar per language, query-based pattern
matching matches our Python AST traversal style.

**Things to model:**
- ES6 imports: `import { foo as bar } from 'lodash'` → alias `bar` resolves to `lodash.foo`
- CommonJS: `const { foo } = require('lodash')`
- TypeScript-specific: type-only imports (`import type { X }`) — should NOT count as runtime reachability
- Express routes: `app.get('/x', handler)` → `handler` is reachable
- React component usage in JSX `<Foo />` → `Foo` is reachable

**Out of scope for v1:**
- Dynamic `import()` — mark as `unknown`, don't try to resolve
- Webpack alias config (`@/components`) — would need to read `tsconfig.json` / `webpack.config.js` paths
- CSS-in-JS / styled-components reachability

## Technical approach — Java

**Library:** `javalang` (BSD-3, pure Python) — already on PyPI, no
build step. Sufficient for our 1-hop call graph needs.  If we hit
limits, fall back to `javaparser` via subprocess (Apache 2.0 jar) but
adds a Java runtime dependency to the deploy.

**Things to model:**
- `import a.b.c.Foo` → identifier `Foo` resolves to FQN `a.b.c.Foo`
- `import a.b.c.*` → wildcard, mark all references as ambiguous
- `static import` for static method calls
- Spring routes: `@RestController` + `@RequestMapping` / `@GetMapping`
  on a method → method is `function_reachable`
- JAX-RS routes: `@Path` + `@GET` / `@POST`
- Method calls: `obj.foo()` and `Foo.staticMethod()`

**Out of scope for v1:**
- Reflection (`Class.forName`, `Method.invoke`)
- Annotation-driven DI frameworks beyond Spring/JAX-RS
- Build-time code generation (Lombok, MapStruct generated code is in
  the AST, but we won't track which annotation generated it)

## Effort estimate

| Phase | Days | Risk |
|-------|------|------|
| `tree-sitter` setup + JS grammar prototype | 2 | low |
| JS alias tracking + call graph | 3 | medium |
| TS support (extends JS) | 1 | low |
| `javalang` setup + Java alias tracking | 2 | low |
| Java route annotation detection | 2 | medium |
| Test fixtures (10–20 small projects per language) | 2 | low |
| Performance pass + cache integration | 1 | medium |
| Documentation + integration into existing `classify_vulns` | 1 | low |
| **Total** | **~14 days (≈ 1 sprint)** | |

## Risks / unknowns

- **tree-sitter wheel size:** adds ~5 MB to the backend wheel set per
  language grammar.  Acceptable but worth checking against any
  internal artifact size policy.
- **TypeScript edge cases:** TS type narrowing, `as` casts, JSX
  pragma — Phase 3 will see these as just identifiers; not a
  correctness issue but reachability label may be slightly more
  pessimistic than reality.
- **Spring AOP / proxies:** runtime-injected aspects won't show up in
  static AST.  Document this caveat in the v1 release notes.
- **Java Lombok generated methods:** AST sees `@Data` on a class, so
  we infer the generated getter/setter exist.  But `@SneakyThrows`
  rewrites bodies — we may misclassify some method bodies as not
  calling things they actually call.

## Definition of done

- [ ] PR merged with both languages working
- [ ] Unit tests pass on Windows/macOS/Linux CI
- [ ] Smoke test: upload a real-world Express app SBOM + a real-world
      Spring Boot SBOM, eyeball-verify that `reachability` column
      shows differentiated labels (not all `unknown`)
- [ ] `CLAUDE.md` updated to mention JS/Java reachability
- [ ] `CHANGELOG.md` entry under "Unreleased > 變更"
- [ ] `docs/architecture.md` updated with the new analyser hierarchy

## Out of scope (separate issues)

- Go, Rust, Ruby, .NET reachability — file separate issues if demand
  arises
- Cross-file call graph beyond 1-hop (would multiply analysis cost)
- Type-flow / data-flow analysis (this is a different class of tool)
- Replacing the regex Phase 1 with grammar-based imports (Phase 1 is
  intentionally cheap and language-agnostic)

---

## Suggested labels

`enhancement` · `reachability` · `wave-d` · `effort: 2 weeks`

## Suggested milestone

`Wave D — Post-launch enhancements`
