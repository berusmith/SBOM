# Reachability Fixture Corpus

Ground-truth corpus for measuring the reachability analyzer
(`backend/app/services/reachability.py`) against known vulnerable / non-vulnerable
component-use patterns. Sprint #3 (Wave D issue) extends the analyzer from
Python-only to JS/TS + Java; this corpus tells us whether each new language
backend is correct.

## Layout

```
tests/fixtures/reachability/
├── README.md                         # this file
├── _schema/meta.schema.yaml          # field/enum/cross-field rules
├── _tools/
│   ├── validate_meta.py              # per-fixture meta.yaml validation
│   └── corpus_stats.py               # per-language / per-track counts
├── _runner/
│   └── run_corpus.py                 # runs analyzer, reports FP/FN
├── python/<slug>/
│   ├── meta.yaml                     # ground truth for this fixture
│   ├── requirements.txt              # vulnerable package + version
│   └── src/...  (and optionally tests/...)
├── javascript/...                    # populated in phase 2
├── typescript/...                    # populated in phase 2
└── java/...                          # populated in phase 3
```

## Phase status

| Phase | Languages | Fixture count | Status |
|-------|-----------|---------------|--------|
| 1     | Python    | 10 (P1–P10)   | ✅ landed (this commit) |
| 2     | JS / TS   | 16 (J1–J16)   | ⏳ pending |
| 3     | Java      | 13 (V1–V13)   | ⏳ pending |
| **Total** | **all** | **39**       | partial |

Phase 2 + 3 land only after the Phase 1 schema + tooling has survived a
real run (this is the "schema gate" agreed in
`.knowledge/decisions/reachability-corpus-cve-mapping.md`).

## How to run

From the repo root:

```bash
# 1. Validate every meta.yaml
python backend/tests/fixtures/reachability/_tools/validate_meta.py

# 2. Print counts (validates first; refuses to run on a broken corpus)
python backend/tests/fixtures/reachability/_tools/corpus_stats.py

# 3. Run the current analyzer against the corpus, report FP/FN
python backend/tests/fixtures/reachability/_runner/run_corpus.py
```

`run_corpus.py` exits non-zero on any FP/FN in supported languages
(today: Python only). JS/TS/Java fixtures count as `skipped` until
sprint #3 lands the analyzer extension.

## How to add a fixture

1. `mkdir backend/tests/fixtures/reachability/<lang>/<slug>/`
2. Copy a sibling fixture's `meta.yaml` and edit fields
3. Add the source under `src/` (and optionally `tests/`)
4. Run `validate_meta.py` — fixes any schema errors
5. Run `corpus_stats.py` — sanity-check the count delta
6. Run `run_corpus.py` — confirm the analyzer's verdict matches `expected_label`

## Fixture types

- `cve_reachability` — measures whether the analyzer correctly marks a
  vulnerable code path. **Counts in the headline FP/FN rate.**
- `framework_mechanism` — exercises a parser / framework edge case
  (JSX wiring, JAX-RS dispatch). **Reported in its own track** so a
  parser limitation never gets miscounted as a "missed CVE".

## Special label: `unknown_acceptable`

For inputs the analyzer genuinely cannot resolve statically (dynamic
import, reflective dispatch), the only correct answer is "I don't
know" (`unknown`). Outputting `reachable` or `not_found` here is a
**fail** — it means the analyzer is guessing rather than admitting
defeat. Reported in a third track.

## See also

- `.knowledge/decisions/reachability-corpus-cve-mapping.md` —
  full per-fixture CVE → vulnerable_symbol mapping (rev 2)
- `.knowledge/decisions/reachability-js-java-issue.md` —
  Wave D sprint spec for the JS/Java analyzer extension
