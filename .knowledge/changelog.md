# Knowledge Base Changelog

## 2026-04-24 — 第 1 輪:基礎建置 + 生產就緒強化

### 新增
- **首次建立**:`.knowledge/` 骨架(decisions/patterns/pitfalls/references)
- `index.md`:全域索引
- `decisions/0001-fastapi-dependency-upgrade.md`:依賴升級決策(已執行,結果 0 CVE)
- `decisions/0002-lifespan-migration.md`:lifespan 遷移決策(已執行)
- `patterns/inline-sqlite-migration.md`:慣用的欄位遷移寫法
- `patterns/plan-feature-gating.md`:plan 分層 gating
- `patterns/stdlib-test-suite.md`:純 stdlib 測試套件結構
- `pitfalls/windows-msstore-python-alias.md`:Windows Python 別名陷阱
- `pitfalls/powershell-npm-ps1-blocked.md`:PowerShell 執行原則攔截 npm
- `pitfalls/npm-install-child-path.md`:winget 裝完 node 後 PATH 未刷新
- `pitfalls/health-monitor-running-key.md`:/health endpoint bug(已修復)
- `references/pip-audit.md`:pip-audit 工具筆記
- `references/fastapi-lifespan.md`:FastAPI lifespan 官方用法

### 後續觀察(放入待討論池)
- `pip` 本身有 2 個 CVE(CVE-2025-8869、CVE-2026-1703,修正版 25.3 / 26.0),非 runtime 依賴,本輪不動
- npm dev-only 套件 2 個 moderate vuln(esbuild、vite),不在生產 bundle,本輪不動
