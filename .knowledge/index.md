# Knowledge Base Index

本索引為跨輪次、跨任務的永久記憶。每輪結束前強制更新。

## Decisions（ADR）
- [ADR-0001: FastAPI dependency upgrade path](decisions/0001-fastapi-dependency-upgrade.md) — 安全性升級時如何選版本
- [ADR-0002: Startup/shutdown migration to lifespan](decisions/0002-lifespan-migration.md) — 從 `@app.on_event` 遷移到 lifespan context manager

## Patterns
- [Inline SQLite column migration](patterns/inline-sqlite-migration.md) — 本專案不用 Alembic,直接在 `main.py` 以 `_add_column` 補欄位
- [Plan-based feature gating](patterns/plan-feature-gating.md) — `require_plan(feature)` FastAPI dependency 回 402
- [Pure-stdlib test suite](patterns/stdlib-test-suite.md) — `test_all.py` 用 `urllib` + `json`,無 pytest/requests

## Pitfalls
- [Windows: Microsoft Store python.exe alias](pitfalls/windows-msstore-python-alias.md) — `python` 指令預設為 Store 捷徑;需用絕對路徑或 winget 安裝
- [PowerShell: npm.ps1 blocked by ExecutionPolicy](pitfalls/powershell-npm-ps1-blocked.md) — 用 `npm.cmd` 或 bash
- [npm install: child process lacks refreshed PATH](pitfalls/npm-install-child-path.md) — esbuild postinstall 找不到 node
- [health endpoint misreport monitor.running](pitfalls/health-monitor-running-key.md) — `get_status()` 沒回 `running` key

## References
- [pip-audit](references/pip-audit.md) — Python 依賴 CVE 掃描工具
- [FastAPI lifespan docs](references/fastapi-lifespan.md) — 官方 lifespan 用法摘要

## Changelog
見 [changelog.md](changelog.md)
