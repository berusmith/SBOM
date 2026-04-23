# 下一項工作詳細計畫

**已完成（2026-04-23）**
- API Token 最小權限（read / write / admin scope）
- 首屏性能優化（路由 lazy + 依賴圖延後 fetch）
- License 風險分類 + 通知測試按鈕
- ✅ **GitHub Action + CLI 工具（完成）**
  - Day 1：Python CLI 工具（sbom upload / gate / diff）
  - Day 2：GitHub Actions composite action
  - Day 3：文檔整合 + Help 頁面

---

## 下一項：TISAX 模組（~2 週）

### 為什麼選這個
競品分析詳見 `docs/competitor-gap.md`。結論：**CI/CD 整合**是目前跟 Snyk / Anchore / Dependency-Track 落差最大、但也最便宜補上的一塊。Reachability、Sigstore、Postgres 這三塊投資回報週期太長，應放後面。

對顧問業務影響：把產品定位從「一次性 SBOM 上傳工具」升級成「開發流程基礎設施」，直接支撐年費訂閱話術。

### 範圍

#### Day 1 — `sbom-cli`（Python 單檔）
- 放在 `tools/sbom-cli/` 底下
- 三個子指令：
  - `sbom upload <sbom.json> --release <id>` → `POST /api/releases/{id}/sbom`
  - `sbom gate --release <id>` → `GET /api/releases/{id}/gate`，非 0 exit code 若未通過
  - `sbom diff --v1 <id> --v2 <id>` → `GET /api/products/{pid}/diff`
- 認證：`SBOM_API_TOKEN` 環境變數 + `SBOM_API_URL`
- 純 stdlib（urllib + json），不引入 requests，可 `pip install` 也可 `pyinstaller` 包單一 exe

#### Day 2 — GitHub Action
- 新增 `tools/sbom-action/action.yml`（composite action）
- 輸入：`sbom-file`, `release-id`, `fail-on-gate`（預設 true）
- 行為：安裝 CLI → upload → gate → 以 PR comment 輸出 Policy Gate 結果
- 附 demo workflow `tools/sbom-action/example.yml`

#### Day 3 — 文件 + 整合到 /help
- `docs/ci-integration.md`：CLI 安裝、Token 產生流程、GitHub Action 使用、Jenkins/GitLab 範例
- 在 `frontend/src/pages/Help.jsx` 加一篇「CI/CD 整合」
- 更新 CLAUDE.md 加 `tools/` 目錄章節

### 不做什麼（明確排除）
- GitLab/Jenkins plugin（只寫 shell script 範例，不做官方 plugin）
- 伺服器端變更（API 已齊備，CLI 純 client-side）
- 新 npm 套件 / 新 Python 依賴

### 驗收標準
- ✅ `pip install -e tools/sbom-cli` 可安裝
- ✅ 在本地對 localhost:9100 跑 `sbom upload` / `sbom gate` / `sbom diff` 三個指令全通
- ✅ GitHub Action 在 demo repo 的 PR 上跑通並留 comment
- ✅ Gate 失敗時 workflow fail
- ✅ 既有 39 項 `test_all.py` 無迴歸

**預計 commit 數**：3（Day 1 / Day 2 / Day 3 各一）

---

## 後續路線（依序）

| # | 項目 | 預估 | 備註 |
|---|------|------|------|
| 2 | TISAX 模組 | ~2 週 | 已有 `docs/TISAX_MODULE_PLAN.md` |
| 3 | Reachability 分析（Python/Node 先行） | ~2 月 | 差異化關鍵 |
| 4 | SBOM Sigstore 簽章驗證 | ~1 週 | CRA 稽核會被問 |
| 5 | Postgres 後端選項 | ~1 週 | 進企業客戶前必過 |
