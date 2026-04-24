# ADR-0001: FastAPI Dependency Upgrade Path (Security)

**情境** | 2026-04-24 pip-audit 回報 9 個 CVE,集中在 starlette / requests / python-multipart / pillow。starlette 被 fastapi 0.115.0 鎖在 `<0.39.0`,要升 starlette 就得升 fastapi。

**方案** | 單次最小升級,一次解掉全部 CVE:
| 套件 | 舊版 | 新版 | 備註 |
|------|------|------|------|
| fastapi | 0.115.0 | 0.118.0 | 放寬 starlette 上限 |
| python-multipart | 0.0.12 | 0.0.26 | 3 CVE |
| requests | 2.32.3 | 2.33.0 | 2 CVE |
| pillow | 10.4.0 | 12.2.0 | 2 CVE;需 Python 3.10+(prod 用 3.11 ✓) |
| starlette | 0.38.6 | 0.47.2 | 由 fastapi 傳遞帶入 |
| uvicorn / sqlalchemy / pydantic | 不動 | — | 無 CVE,不動以控制風險 |

**理由** |
- 一次到位,比多次小升級更容易回歸測試
- FastAPI 0.118 仍支援 `on_event`(deprecation warning,可另做 lifespan 遷移 — 見 ADR-0002)
- Pillow 12 支援 Python 3.10+;prod 為 3.11,local dev 為 3.12,都可
- 所有升版不改變 public API 簽名

**被否決的替代方案** |
- ❌ 升到 fastapi 0.120+(最新):擴大改動面,風險不必要
- ❌ 只升 requests 不升 fastapi:starlette CVE 留著
- ❌ 改用 `uv`/`poetry`:超出本輪範圍(YAGNI)

**驗收** | `test_all.py` 54/54 通過;`pip-audit` 無高風險 CVE。

**參考來源** |
- `pip-audit -r backend/requirements.txt`
- https://github.com/fastapi/fastapi/releases
- https://starlette.io/releases/

**日期** | 2026-04-24
