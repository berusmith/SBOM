# Pitfall: `/health` 的 `monitor.running` 永遠是 `false`

**症狀** | `GET /health` 回 `{"monitor": {"running": false, ...}}`,即使 monitor 執行緒正常跑。

**原因** | `app/main.py` 的 `health_check()`:
```python
mon_status = _mon.get_status()
return {
    ...
    "monitor": {
        "running": mon_status.get("running", False),  # ← 取不到,永遠 False
        ...
    },
}
```
但 `app/services/monitor.py` 的 `get_status()` **沒回 `"running"` key**,它回的是 `"is_scanning"`(是否正在掃描中,瞬間值)。兩者語意不同:
- `is_scanning` = 正在執行掃描的那一下(短暫)
- `running` = 排程執行緒還活著(長期)

Uptime monitor 誤以為 monitor 壞了,會一直發警報。

**解法** |
1. 在 `monitor.py` 的 `get_status()` 加 `running` 欄位,反映 scheduler thread 是否 alive
2. 或在 `health_check()` 改取 `is_scanning`(但語意不對)

優先方案 1 — monitor 自己知道自己在不在。以 `threading.enumerate()` 找 `monitor-scheduler` thread 或用模組層 `_scheduler_thread` 變數追蹤。

**預防** | API contract 改動時,所有 caller 都要同步;可考慮定義 `MonitorStatus` dataclass 或 TypedDict。

**日期** | 2026-04-24
