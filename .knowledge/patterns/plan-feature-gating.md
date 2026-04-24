# Pattern: Plan-Based Feature Gating

**情境** | Starter / Standard / Professional 三層 plan,需控制功能可見度 + API 存取。

**方案** | 後端 `app/core/plan.py`:
- `FEATURE_PLAN: dict[str, str]` 映射 feature key → 最低 plan
- `require_plan(feature) -> Depends`,內部比對 org plan 等級,不足回 `402 Payment Required`
- `check_starter_limit(db, org_id, resource)` 硬上限(3 products / 10 releases),超出回 `402`
- Admin user 永遠繞過 plan 檢查

**怎麼用** |
```python
@router.post("/compliance/tisax", dependencies=[Depends(require_plan("tisax"))])
def create_tisax(...):
    ...
```

前端配合:`/api/auth/me` 回 `plan` 欄位,UI 依此灰掉不可用功能。

**理由** |
- 集中管理 feature↔plan 對應,加新功能只改 `FEATURE_PLAN` dict
- `402` 語意清楚,前端可用同一 interceptor 處理
- Admin 繞過便於內測

**參考** | `backend/app/core/plan.py`、`frontend/src/api/client.js`

**日期** | 2026-04-24
