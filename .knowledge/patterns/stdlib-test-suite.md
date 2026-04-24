# Pattern: Pure-stdlib HTTP Test Suite

**情境** | 本專案無 pytest、無 `requests`,避免額外測試相依。

**方案** | `test_all.py` 用 `urllib.request` + `json` 寫 HTTP-level 測試:

```python
def req(method, path, body=None, tok=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    h = {"Content-Type": "application/json"}
    if tok: h["Authorization"] = "Bearer " + tok
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read()) if resp.read() else {}
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()) or {}

def chk(name, cond, detail=""):
    results.append(("PASS" if cond else "FAIL", name, detail))
```

測試格式固定:`s, d = req(...); chk("name", s == 200 and ...)`

**理由** |
- 零外部相依,CI 環境最小化
- 直接測 HTTP layer,覆蓋 auth / serialisation / status codes
- 執行快(54 個測試 < 3 秒)

**怎麼用** |
1. 啟動後端 `uvicorn app.main:app --port 9100`
2. 另一個終端 `python test_all.py`
3. 看輸出 `TOTAL: N PASS / 0 FAIL`

**限制** |
- 不適合單元測試(function-level 邏輯)
- 需要真實 DB(測試會 create/delete 物件,結尾 cleanup)
- 跨執行緒/異步行為測不到

**參考** | `test_all.py`、`test_full_verification.py`

**日期** | 2026-04-24
