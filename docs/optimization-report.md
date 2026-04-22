# SBOM Platform 系統優化報告

產出日期：2026-04-22

---

## 安全性問題

### CRITICAL — 硬編碼預設密碼
- **檔案：** `backend/app/core/config.py` 第 10-11 行
- **問題：** `ADMIN_PASSWORD = "sbom@2024"` 若環境變數未設定，系統會使用此弱密碼
- **修復：** 移除預設值；若環境變數未設定則啟動時 `raise ValueError`

### CRITICAL — 不安全的預設 SECRET_KEY
- **檔案：** `backend/app/core/config.py` 第 8 行
- **問題：** `SECRET_KEY = "change-me-in-production"` — 若未更換，任何人都可偽造 JWT token
- **修復：** 啟動時檢測預設值並拒絕啟動；或用 `secrets.token_urlsafe(32)` 自動生成

### MEDIUM — SBOM 上傳路徑穿越風險
- **檔案：** `backend/app/api/releases.py` 第 108 行
- **問題：** 檔名由使用者提供，雖有 `Path(...).name` 過濾，仍有邊緣風險
- **修復：** 改用 UUID 作為儲存檔名，原始檔名僅存 DB

### MEDIUM — migrations 中 f-string 拼接 SQL
- **檔案：** `backend/app/main.py` 第 30-48 行
- **問題：** `f"ALTER TABLE ... ADD COLUMN {col} {typedef}"` 雖目前為硬編碼，模式本身不安全
- **修復：** 使用 SQLAlchemy DDL 構件或 `text()` 明確標記

### MEDIUM — 缺少安全標頭
- **問題：** 未設定 `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`
- **修復：** 在 `main.py` 加入 middleware 統一注入安全標頭

---

## 資料庫問題

### HIGH — Vulnerability 欄位缺少索引
- **檔案：** `backend/app/models/vulnerability.py` 第 15-18 行
- **問題：** `cve_id`、`severity`、`status`、`is_kev`、`epss_score` 為頻繁查詢欄位，無索引
- **修復：** 加 `index=True`；複合索引 `(status, severity, component_id)`

### HIGH — N+1 查詢：元件搜尋
- **檔案：** `backend/app/api/search.py` 第 32-37 行
- **問題：** 迴圈中對每個 component 個別查 Release 和 Product（200 個結果 = 400+ 次查詢）
- **修復：** JOIN 查詢時加 `selectinload(Component.release)` 一次載入

### HIGH — N+1 查詢：批次 VEX 更新
- **檔案：** `backend/app/api/vulnerabilities.py`
- **問題：** `batch_update_vex` 用迴圈逐一查詢，應改用 `.in_()` 一次取回
- **修復：** `db.query(Vulnerability).filter(Vulnerability.id.in_(ids)).all()`

### HIGH — 缺少分頁：多個 .all() 端點
- **影響：** `cra.py` 事件列表、`organizations.py` 組織列表、`releases.py` 漏洞列表
- **問題：** 未加 LIMIT/OFFSET，大資料量時回應爆炸
- **修復：** 統一加 `skip`/`limit` 參數，預設 100，上限 500

### HIGH — 漏洞列表在 Python 做分頁
- **檔案：** `backend/app/api/releases.py` 第 374-415 行
- **問題：** 先 `.all()` 取回所有漏洞，再用 `result[skip:skip+limit]` 切片
- **修復：** 改為資料庫層 `.offset(skip).limit(limit)`

---

## 效能問題

### HIGH — 元件掃描序列 HTTP 呼叫
- **檔案：** `backend/app/services/vuln_scanner.py` 第 82-93 行
- **問題：** 1000 個元件 = 1000 次序列 HTTP → OSV.dev，極慢
- **修復：** 使用 `asyncio` + `httpx.AsyncClient` 並行；或 thread pool

### HIGH — NVD 服務中 `time.sleep()`
- **檔案：** `backend/app/services/nvd.py` 第 18, 32 行
- **問題：** 雖已在 background task 執行，sleep 阻塞 worker thread
- **修復：** Background task 改用 `asyncio.sleep()`；或移至獨立 thread

### MEDIUM — PDF / ZIP 在記憶體中組裝
- **檔案：** `backend/app/api/releases.py` 第 520, 807 行
- **問題：** `io.BytesIO()` 將整份 PDF/ZIP 存在記憶體後再回應
- **修復：** 使用 `StreamingResponse` + generator；大報告分批寫出

---

## 錯誤處理缺失

### MEDIUM — Webhook / Email 靜默失敗
- **檔案：** `backend/app/services/alerts.py` 第 22-51 行
- **問題：** `except Exception: pass` — webhook/email 失敗完全無聲，無 log、無重試
- **修復：** 加 `logger.error(...)`；實作指數退避重試

### MEDIUM — 例外訊息洩漏給使用者
- **檔案：** `backend/app/api/releases.py` 第 105 行
- **問題：** `detail=f"SBOM 解析失敗：{e}"` 將內部錯誤細節暴露
- **修復：** Log 完整 traceback；回應給使用者改為通用訊息

---

## 程式碼品質

### LOW — 重複 SEVERITY_ORDER 常數
- **檔案：** `backend/app/api/releases.py` 第 1004 行 & `search.py` 第 14 行
- **修復：** 移至 `backend/app/core/constants.py` 共用

### LOW — 魔術數字
- **問題：** `limit > 1000`、`50 * 1024 * 1024` 等散落各處
- **修復：** 定義命名常數於模組最上方

### LOW — 重複的 `_assert_release_org` 函式
- **問題：** 相同邏輯在多個路由重複定義
- **修復：** 移至 `core/dependencies.py`

---

## 優先行動清單

| 優先 | 項目 | 工時估計 |
|------|------|---------|
| P0 | 移除硬編碼 ADMIN_PASSWORD 預設值 | 15 分鐘 |
| P0 | 移除硬編碼 SECRET_KEY 預設值 | 15 分鐘 |
| P1 | 加 Vulnerability 欄位索引（含 migration） | 30 分鐘 |
| P1 | 修 search.py N+1 查詢 | 20 分鐘 |
| P1 | 修 vulnerabilities.py batch N+1 | 10 分鐘 |
| P2 | 漏洞列表改資料庫層分頁 | 30 分鐘 |
| P2 | vuln_scanner 序列→並行 HTTP | 1 小時 |
| P3 | Webhook/Email 加 log + 重試 | 45 分鐘 |
| P3 | 重複常數整合 | 20 分鐘 |
