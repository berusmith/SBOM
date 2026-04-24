# ADR-0002: Migrate `@app.on_event` to FastAPI Lifespan

**情境** | FastAPI 自 0.109 起 deprecate `@app.on_event("startup"/"shutdown")`,Starlette 0.47+ 已全面採用 `lifespan` context manager。目前 `backend/app/main.py` 有 3 處 `@app.on_event`:
1. `_purge_expired_tokens`(startup — 清除過期 JWT 黑名單)
2. `_start_monitor`(startup — 啟動背景掃描執行緒)
3. `_stop_monitor`(shutdown — 終止掃描執行緒)

**方案** | 改用 `@asynccontextmanager` + `FastAPI(lifespan=...)`:
```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # === startup ===
    _purge_expired_tokens()
    monitor.start()
    yield
    # === shutdown ===
    monitor.stop()

app = FastAPI(title=..., lifespan=lifespan)
```

**理由** |
- 官方推薦寫法,未來 FastAPI 移除 `on_event` 時不需再改
- 單一函式、可讀性更高、例外處理更一致
- 測試時可以用 `AsyncClient` 搭配 `transport.app`;本專案用 HTTP-based `test_all.py`,不受影響

**被否決** |
- ❌ 保留 `on_event`:eventually 會壞,技術債累積
- ❌ 大改成 FastAPI 新功能(如 DI 型 lifespan hooks):YAGNI

**驗收** |
- 後端啟動無 DeprecationWarning 關於 on_event
- `/health` 仍回正確狀態
- monitor 仍運作(thread alive、可 trigger)
- `test_all.py` 54/54

**參考來源** |
- https://fastapi.tiangolo.com/advanced/events/#lifespan
- https://www.starlette.io/lifespan/

**日期** | 2026-04-24
