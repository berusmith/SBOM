# 外部情資 API Key 申請指引

平台預設**完全不需要**任何 API key 即可運作 — OSV.dev、NVD、CISA KEV、FIRST.org EPSS、GitHub Advisory 全部允許匿名存取。但 NVD 與 GitHub 兩個來源的匿名額度偏低,在大型 SBOM(>200 個元件)或頻繁 enrichment 時可能撞到限速、漏抓資料。

申請兩把免費 key 約 **5–10 分鐘**,效果:

| 來源 | 無 key | 有 key | 速率倍數 |
|------|--------|--------|----------|
| **NVD API 2.0** | 5 req / 30s | 50 req / 30s | **10×** |
| **GitHub GHSA** | 60 req / hour | 5000 req / hour | **83×** |

兩把 key 都是完全免費、不收信用卡、無使用上限。

---

## 1. NVD API Key(漏洞描述 / CWE / CVSS v3+v4)

### 申請步驟

1. 開 <https://nvd.nist.gov/developers/request-an-api-key>
2. 填表單(只需要 email + 機構名稱 + 用途說明,中英皆可):
   - **Organization**:你的公司名(個人填 "Personal" 也接受)
   - **Email Address**:收 key 的信箱
   - **Organization Type**:選 `Private Industry` 或 `Other`
   - **Reason for Requesting an API Key**:照填即可,例如:
     > Internal SBOM management platform; querying CVE details to enrich vulnerability records for our software releases.
3. 送出後**立刻**會收到一封確認信(主旨 `NIST NVD - API Key Request`)
4. 點信中的 **Activate** 連結 → 瀏覽器顯示一串 36 字元的 UUID(就是你的 key)
5. **複製存好** — 這頁關掉後 NIST 不會再次顯示,只能重新申請

### 填到 `.env`

```bash
# backend/.env
NVD_API_KEY=12345678-aaaa-bbbb-cccc-9876543210ab
```

重啟 backend 後生效(`launchctl unload && launchctl load ~/Library/LaunchAgents/com.sbom.backend.plist`,本機開發直接 Ctrl-C 重跑 uvicorn)。

### 驗證已生效

```bash
# 上傳一個 SBOM,然後觀察 backend log:
# 無 key 時 nvd.py 每 6 秒只能打 1 個 CVE(5 req/30s)
# 有 key 時可以 2 秒 1 個(50 req/30s)
# 大型 SBOM 的 enrichment 時間從幾分鐘降到幾十秒
```

---

## 2. GitHub Personal Access Token(GHSA 情資)

### 申請步驟(2026 年新版 fine-grained tokens)

1. 開 <https://github.com/settings/personal-access-tokens/new>
   - 必須**已登入** GitHub,個人 / 組織帳號皆可
2. 填欄位:
   - **Token name**:`SBOM Platform GHSA Reader`(或任何你認得的名字)
   - **Expiration**:建議 **1 year** 或 **No expiration**(只讀公開資料,風險極低)
   - **Description**:選填,例如 `Read GHSA advisories for SBOM vulnerability enrichment`
   - **Resource owner**:選你自己(個人 token)
   - **Repository access**:**Public Repositories (read-only)** ← 預設值,維持就好
   - **Permissions**:**完全不用展開** — 預設的 `Public repositories: Read` 已足夠 GHSA API
3. 按 **Generate token**
4. 顯示的 token 字串(以 `github_pat_` 開頭,約 90 字元)**只會出現這一次**
5. **複製存好** — 關掉就再也看不到,只能重新生成

### 為什麼 fine-grained 比 classic 安全

- 只開「Public Repositories Read」,即使 token 外洩也只能讀公開資料
- 不能寫 / 不能讀私有 repo / 不能存取個人資料
- 比舊版 classic token(只能勾整個 `public_repo` scope)權限更小

如果你**已有** classic token 也可以用,但建議遷移到 fine-grained。

### 填到 `.env`

```bash
# backend/.env
GITHUB_TOKEN=github_pat_11AAAAAAA0xxxxxxxxxxxx_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

重啟 backend 生效。

### 驗證已生效

```bash
# 開 backend/app/services/ghsa.py 看,會發現 _get_headers() 加了
# Authorization: Bearer github_pat_...
# GHSA enrichment 時 X-RateLimit-Remaining 會從 60 變成 5000
```

---

## 安全注意

- **絕對不要** commit `.env` 到 git — `.gitignore` 已包含
- 部署到 Mac Mini 時,`.env` 透過 `deploy/.env.production` 模板複製到伺服器,該檔本身也是 gitignored
- 兩把 key 都是「只讀」性質,即使外洩也只能查公開漏洞情資 / 公開 repo,沒有寫入 / 帳號接管風險
- 不過仍建議:
  - GitHub token 設 **1 年到期**,定期輪換
  - NVD key 若懷疑外洩,直接到 [Manage NVD Keys](https://nvd.nist.gov/developers/start-here) 撤銷重發

---

## 常見問題

**Q: 一定要兩把都申請嗎?**
A: 不用。完全不申請 → 平台仍能比對漏洞,只是 enrichment 慢 / GHSA 偶爾撞到 60 req/h 上限。建議至少申請 NVD(免費、五分鐘、效果最明顯)。

**Q: 申請失敗 / 信沒收到?**
A: NVD 偶爾寄到垃圾郵件夾。等 30 分鐘還沒收到就重新申請。GitHub 是即時生成,不發信。

**Q: 公司資安政策不允許用個人 GitHub 帳號?**
A: 在 GitHub 開一個 service account(免費),用該帳號生 token。或用 GitHub Apps(更複雜但可審計)— 但 GHSA Read 不需要這麼正式。

**Q: 大規模部署(多客戶 SaaS)時 5000 req/h 還是不夠?**
A: GitHub 接受 GitHub Apps(installation token)更高的速率,或可申請企業合約。目前 SBOM Platform 的單實例規模 5000/h 綽綽有餘(典型 100 個 release / 天 × 平均 30 元件 = 3000 calls)。
