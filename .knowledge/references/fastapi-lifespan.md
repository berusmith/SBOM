# Reference: FastAPI Lifespan

**重點** | 取代 `@app.on_event("startup"/"shutdown")` 的官方新寫法。

**基本用法** |
```python
from contextlib import asynccontextmanager
from fastapi import FastAPI

@asynccontextmanager
async def lifespan(app: FastAPI):
    # === startup ===
    # 非同步可 await;同步函式直接呼叫
    await load_ml_model()
    _init_cache()
    yield
    # === shutdown ===
    await save_state()
    close_resources()

app = FastAPI(lifespan=lifespan)
```

**用 state 傳物件** |
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db_pool = await create_pool()
    yield
    await app.state.db_pool.close()

# 在 endpoint:
@app.get("/")
async def root(request: Request):
    pool = request.app.state.db_pool
```

**和 Starlette 的差異** | 完全相容 —FastAPI 把 lifespan 透傳給底層 Starlette。

**為什麼要遷移** |
- `@app.on_event` 自 FastAPI 0.109 起 deprecated,未來會移除
- lifespan 是單一函式,例外處理更一致
- 和 ASGI lifespan protocol 對齊,測試更好寫

**陷阱** |
- lifespan 是 **async context manager**,startup 放在 yield 前,shutdown 放在 yield 後
- 同步函式可直接呼叫(不用 await);**不要** 在 lifespan 裡開 `asyncio.create_task` 沒 cancel(會在 shutdown hang)
- 測試用 `AsyncClient(transport=ASGITransport(app=app))` 會觸發 lifespan

**本專案預計遷移的 hooks** |
1. `_purge_expired_tokens()` — 清過期 JWT 黑名單(sync)
2. `monitor.start()` — 啟動掃描執行緒
3. `monitor.stop()` — 停止掃描執行緒

**連結** | https://fastapi.tiangolo.com/advanced/events/#lifespan

**日期** | 2026-04-24
