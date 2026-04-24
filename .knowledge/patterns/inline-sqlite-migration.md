# Pattern: Inline SQLite Column Migration

**情境** | 本專案不用 Alembic,schema 變更靠啟動時 `ALTER TABLE ADD COLUMN`。

**方案** | `backend/app/main.py` 使用 `_add_column(conn, table, col, typedef)` helper,自動判斷欄位是否存在,避免重複 ALTER。

```python
if _table_exists(conn, "vulnerabilities"):
    for col, typedef in [
        ("new_field", "TEXT"),
        ("new_score", "REAL"),
    ]:
        _add_column(conn, "vulnerabilities", col, typedef)
    conn.commit()
```

**理由** |
- 單機/單檔 SQLite 部署,Alembic overkill
- 支援 Postgres 切換:`_add_column` 會把 `REAL` 轉 `DOUBLE PRECISION`、`DATETIME` 轉 `TIMESTAMP WITH TIME ZONE`
- SQLite 不支援 DROP/RENAME COLUMN,所以只加不刪;若要改欄位型別得新建表 + 複製資料

**怎麼用** |
- 新增欄位 → 在 `main.py` 對應 table 區塊加一行
- 新增 table → 不用特別處理,`Base.metadata.create_all(checkfirst=True)` 會在最後建立未存在的表
- 新增 index → 加到 `for _idx in [...]` 區塊,包 `CREATE INDEX IF NOT EXISTS`

**參考** | `backend/app/main.py` line 33-173

**日期** | 2026-04-24
