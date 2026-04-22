# 下一項工作詳細計畫

**決定前請讀完此檔，確認無誤後回覆「同意做 [項目名]」**

---

## 三項選擇詳細對比

| 項目 | 檔案異動 | 工作內容 | 時間 | 難度 | 風險 |
|------|---------|---------|------|------|------|
| **P3-4** | 4-5 個 | API分離 + 懶加載 | 2-3h | ⭐⭐ | 低 |
| **P3-5** | 10+ 個 | 無障礙標籤 + 檢查 | 3-4h | ⭐ | 低 |
| **2.4a** | 5+ 個 | 韌體上傳 + EMBA 整合 | 5-7h | ⭐⭐⭐ | 中 |

---

## 選項 1️⃣ : P3-4 首屏性能優化

### 目標
ReleaseDetail 首頁加載時間 < 2 秒（目前 ~5秒）

### 要改什麼

#### 1. **ReleaseDetail.jsx** （主要改動）
```
目前架構:
  useEffect(() => {
    fetch 7 個 API (並行)
  }, [releaseId])
  
改為:
  - 立即 fetch: release 基本資訊 + 漏洞列表 (2 個)
  - 延遲 fetch: Policy Gate + SLA + 依賴圖 (2 個)
  - React.lazy: 依賴關係圖表 (SVG 圖表元件)
```

**改動檔案**:
- `src/pages/ReleaseDetail.jsx`
  - 新增 `React.Suspense` wrapper
  - 將依賴圖改為 lazy import: `const DependencyGraph = lazy(() => import(...))`
  - useEffect 拆成 2 階段: 初始化 + 延遲載入

**新增檔案**: 無

#### 2. **Help.jsx** （分頁）
```
目前: 24 篇文章全載入
改為: 分頁，每頁 5 篇，初加載只顯示第 1 頁
```

**改動檔案**:
- `src/pages/Help.jsx`
  - 新增 `const [page, setPage] = useState(0)`
  - SECTIONS 按分類分組
  - 底部加「上一頁 / 下一頁」按鈕

#### 3. **Releases.jsx** （圖表懶加載）
```
目前: TrendChart 元件總是渲染
改為: 使用 React.lazy，Tab 點擊時才載入
```

**改動檔案**:
- `src/pages/Releases.jsx`
  - 將 `TrendChart` 移到 lazy import

### 測試步驟
1. ✅ 編譯: `npm run build` （無錯誤）
2. ✅ 頁面加載: 開 DevTools → Network tab
   - ReleaseDetail: 初次加載 < 2s
   - Help: 初次加載 < 1s
3. ✅ 功能驗證:
   - ReleaseDetail: 依賴圖點擊後才顯示 ✓
   - Help: 分頁翻頁正常 ✓
   - Releases: 切到「漏洞趨勢」Tab 才出現圖表 ✓
4. ✅ 無迴歸: 其他頁面正常 ✓

### 驗收標準
- ✅ 沒有編譯錯誤
- ✅ ReleaseDetail 首頁 JS 執行 < 2s
- ✅ 所有 lazy 元件點擊後正常顯示
- ✅ 沒有因懶加載導致的 UI 閃爍

**預計 Commit 數**: 1 個 (feat: P3-4 首屏性能優化)

---

## 選項 2️⃣ : P3-5 無障礙改進

### 目標
Lighthouse 無障礙評分 ≥ 90

### 要改什麼

#### 1. **ARIA 標籤** （所有有圖示的按鈕）
```jsx
<button>  {/* ❌ 看不出是什麼 */}
  <Eye size={16} />
</button>

改為:

<button aria-label="顯示密碼">
  <Eye size={16} />
</button>
```

**改動檔案** (逐個):
- `PasswordInput.jsx`: aria-label="顯示/隱藏密碼"
- `ReleaseDetail.jsx`: 刪除按鈕 aria-label="刪除"
- `Login.jsx`, `Organizations.jsx`, `Users.jsx` 等: 所有圖示按鈕

#### 2. **表格無障礙** （ReleaseDetail 等表格頁面）
```html
❌ 目前:
<table>
  <tr><td>版本號</td><td>建立時間</td></tr>
  
✅ 改為:
<table>
  <caption>版本列表</caption>
  <thead>
    <tr>
      <th scope="col">版本號</th>
      <th scope="col">建立時間</th>
    </tr>
```

**改動檔案**:
- `src/pages/ReleaseDetail.jsx`: 漏洞表格
- `src/pages/Releases.jsx`: 版本表格
- `src/pages/Policies.jsx`: 違規表格
- `src/pages/Users.jsx`: 用戶表格
- 等 (4-5 個表格)

#### 3. **顏色對比檢查** （Lighthouse 檢查）
```
檢查清單:
- text-gray-500 (文字) vs white (背景) = 5.5:1 ✓
- text-red-500 (錯誤) vs white (背景) = 4.9:1 ✓
- 需調整的: text-gray-400 (灰色標籤) = 3.2:1 ❌
  → 改為 text-gray-600
```

**改動檔案**:
- 全站搜尋 `text-gray-400` 改 `text-gray-600` (約 5-10 處)

### 測試步驟
1. ✅ 編譯: `npm run build`
2. ✅ Lighthouse 檢查:
   - 開發工具 → Lighthouse → 無障礙
   - 檢查評分 ≥ 90
3. ✅ 螢幕閱讀器驗證 (macOS Voiceover / Windows NVDA):
   - 密碼切換按鈕: "顯示密碼" 可聽見 ✓
   - 表格: 欄位標題可正確標示 ✓
4. ✅ 鍵盤導航:
   - Tab 鍵能訪問所有互動元素 ✓
   - Enter 提交表單 ✓

### 驗收標準
- ✅ Lighthouse 無障礙評分 ≥ 90
- ✅ 所有圖示按鈕有 aria-label
- ✅ 所有表格有 `<caption>` 或 `aria-label` + scope 屬性
- ✅ 色彩對比 WCAG AA 標準 (4.5:1)

**預計 Commit 數**: 1 個 (feat: P3-5 無障礙改進)

---

## 選項 3️⃣ : Phase 2.4a 韌體掃描基礎

### 目標
可上傳韌體 → 自動生成 SBOM → 掃描漏洞

### 前置要求
- ✅ EMBA 框架已安裝（Linux 環境）
  - Windows: 需 WSL2 或遠端 Linux 伺服器
- ✅ 已測試 EMBA CLI: `emba -f firmware.bin -d output_dir`

### 要改什麼

#### 1. **後端 API** (3 個端點)
```python
POST /api/firmware/upload
  ├─ 接收: multipart/form-data (file: .bin/.img/.zip)
  ├─ 存儲: backend/firmware_uploads/{timestamp}_{filename}
  ├─ 觸發: 非同步呼叫 EMBA (背景 task)
  └─ 回傳: { scan_id, status: "running", created_at }

GET /api/firmware/scans
  ├─ 列出所有掃描任務
  └─ 回傳: [{ id, filename, status, progress, created_at }, ...]

GET /api/firmware/scans/{scan_id}
  ├─ 檢查掃描進度
  ├─ 若完成: 解析 EMBA JSON 輸出 → 元件清單
  └─ 回傳: { status, progress, components: [{name, version, ...}], errors }
```

**新增檔案**:
- `backend/app/api/firmware.py` (200 行)
- `backend/app/models/firmware_scan.py` (50 行)
- `backend/app/services/firmware_service.py` (150 行)

**改動檔案**:
- `backend/app/main.py`: 註冊路由
- `backend/requirements.txt`: 無需新增（EMBA 為 OS 軟體）

#### 2. **前端頁面** (1 個新頁面)
```jsx
FirmwareUpload.jsx
  ├─ 拖放上傳區域
  ├─ 檔案選擇 (.bin/.img/.zip)
  ├─ 上傳進度條
  └─ 掃描結果預覽
      ├─ EMBA 輸出摘要 (找到 N 個元件)
      ├─ 元件表格
      └─ 「匯入為 Release」按鈕
```

**新增檔案**:
- `frontend/src/pages/FirmwareUpload.jsx` (300 行)

**改動檔案**:
- `frontend/src/App.jsx`: 新增路由 `/firmware`
- `frontend/src/components/Sidebar.jsx`: 左側選單加「韌體掃描」

#### 3. **資料表**
```sql
CREATE TABLE firmware_scans (
  id VARCHAR PRIMARY KEY,
  filename VARCHAR,
  status VARCHAR (running/completed/failed),
  progress INT (0-100),
  components_count INT,
  emba_output_json TEXT,
  created_at DATETIME,
  completed_at DATETIME
);
```

**改動檔案**:
- `backend/app/main.py`: migration 區塊新增 CREATE TABLE

### 測試步驟
1. ✅ 編譯: `npm run build` + 後端啟動
2. ✅ 上傳韌體:
   - POST `/api/firmware/upload` with file
   - 檢查 scan_id 回傳 ✓
3. ✅ 檢查進度:
   - GET `/api/firmware/scans/{scan_id}` (每 5 秒)
   - 看到 progress 從 0 → 100 ✓
4. ✅ 驗證結果:
   - 掃描完成後，元件列表正確 ✓
   - 「匯入為 Release」能建立新版本 ✓
5. ✅ 無迴歸: 其他頁面正常 ✓

### 驗收標準
- ✅ 無編譯錯誤
- ✅ 能上傳韌體 (.bin/.img/.zip)
- ✅ EMBA 掃描成功完成（需 5-30 分鐘）
- ✅ SBOM 元件自動生成
- ✅ 掃描結果可匯入為版本並自動掃描漏洞

**預計 Commit 數**: 1 個 (feat: Phase 2.4a 韌體掃描基礎)

---

## 🎯 決策時間

**請確認：你要做哪一項？**

回覆格式:
```
同意做 P3-4

或

同意做 P3-5

或

同意做 Phase 2.4a
```

確認後我會立即開始計劃 → 編碼 → 測試 → Commit+Push
