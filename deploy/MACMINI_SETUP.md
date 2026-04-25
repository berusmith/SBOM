# Mac Mini 部署指南

把 SBOM Platform 部署到自家 Mac Mini(macOS)。預設安裝在使用者家目錄 `$HOME/sbom/`,**無需 sudo**。

---

## 部署資訊範本

| 項目 | 範例值 | 說明 |
|------|--------|------|
| 主機名 | `mac-mini.local` | macOS Bonjour 名,系統設定 → 一般 → 共享 → 顯示 |
| SSH 用戶 | `peter` | Mac Mini 上登入用的帳號 |
| 部署根 | `/Users/peter/sbom/` | 預設 `$HOME/sbom`,可由 `SBOM_DEPLOY_DIR` 覆寫 |
| Python | 3.11 (Homebrew) | `brew install python@3.11` |
| Service | launchd user agent | `~/Library/LaunchAgents/com.sbom.backend.plist` |
| 反向代理 | nginx(Homebrew,可選) | `INSTALL_NGINX=1` 自動裝 + 設定;對外存取必裝 |
| 資料庫 | PostgreSQL 16(Homebrew,推薦) | `INSTALL_POSTGRES=1` 一鍵裝 + 建 user/DB;SQLite 仍可用 |
| 容器 / IaC SBOM 拆解 | Trivy(Homebrew,可選) | `INSTALL_TRIVY=1` brew 裝;Apache-2.0 license,無法務負擔 |
| 原始碼 / Binary SBOM 生成 | Syft(Homebrew,可選) | `INSTALL_SYFT=1` brew 裝;Apache-2.0 license,無法務負擔 |
| 韌體拆解 | EMBA(Docker,需自行決定) | `INSTALL_EMBA=1` **只印安裝指南**;GPL-3.0,本產品不打包,詳見 `NOTICE.md` §3 |

> **執行從哪邊?** 從你的開發機(Windows / Mac / Linux)用 SSH 推到 Mac Mini。或直接在 Mac Mini 本地 git pull 也行。

---

## 前置作業(在 Mac Mini 上做一次)

### 1. 開啟「遠端登入」(SSH)

系統設定 → 一般 → 共享 → 「遠端登入」打開。

把開發機的 SSH 公鑰加到 Mac Mini:

```bash
# 在開發機(Windows Git Bash 也行)
ssh-copy-id peter@mac-mini.local
# 沒有 ssh-copy-id 的話,手動把 ~/.ssh/id_*.pub 內容貼到 Mac Mini 的 ~/.ssh/authorized_keys
```

### 2. 安裝 Homebrew

```bash
# 在 Mac Mini 上(Terminal)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Apple Silicon 機器裝完後依提示加 `/opt/homebrew/bin` 到 PATH。Intel 機器是 `/usr/local/bin`。

---

## 首次部署(在開發機上跑)

```bash
# 在 SBOM 倉庫根目錄
export SBOM_DEPLOY_HOST=mac-mini.local        # Mac Mini 的 hostname / IP / Tailscale name
export SBOM_DEPLOY_USER=peter                 # Mac Mini 的 SSH 使用者(預設等於本機 whoami)
# 可選:
# export SBOM_DEPLOY_DIR=/Users/peter/sbom    # 預設 /Users/$USER/sbom
# export SBOM_SSH_KEY=/path/to/private_key    # 預設用 ssh-agent / 預設金鑰
# export SBOM_SSH_OPTS="-p 2222"              # 自訂 SSH port

bash deploy/first-deploy.sh
```

`first-deploy.sh` 會做的事:

1. 測試 SSH 連線
2. 上傳 `setup-macos.sh` / launchd plist / nginx conf / `.env.production` / `backup.sh` 到 Mac Mini 的 `~/sbom-bootstrap/`
3. 在 Mac Mini 上執行 `setup-macos.sh`(裝 Homebrew python@3.11、建目錄、建 venv、安裝 launchd plist)
4. **暫停** — 你需要 SSH 進去手動 `cp .env.production backend/.env` 並改 SECRET_KEY / ADMIN_PASSWORD
5. 接你按 Enter 後跑 `deploy.sh`(本機 build → 上傳 → 起 service)

如果想同時裝 Postgres / nginx,在 step 3 前先在 Mac Mini 上執行(用環境變數開選項):

```bash
ssh peter@mac-mini.local
cd ~/sbom-bootstrap

# 純 Python + venv + launchd
bash setup-macos.sh

# 加裝 Postgres(推薦):
INSTALL_POSTGRES=1 bash setup-macos.sh

# 全餐(Postgres + nginx):
INSTALL_POSTGRES=1 INSTALL_NGINX=1 bash setup-macos.sh

# 全餐 + 容器/IaC 拆解能力:
INSTALL_POSTGRES=1 INSTALL_NGINX=1 INSTALL_TRIVY=1 bash setup-macos.sh
```

`INSTALL_POSTGRES=1` 會自動:
1. `brew install postgresql@16` 並 `brew services start`(自動隨開機啟動)
2. 建立 role `sbom_user`(密碼自動產 32 字元隨機)
3. 建立 database `sbom`,owner = `sbom_user`
4. **印出完整 `DATABASE_URL`** — 複製到 step 4 的 `.env` 即可

可用 `PG_USER` / `PG_PASS` / `PG_DB` 環境變數覆寫預設。

---

## 拆解能力啟用 (SBOM 生成)

平台本體只負責「消費 SBOM 與管理漏洞」,實際的拆解動作由外部工具承擔。
這些工具依 license 風險不同,啟用方式也不同:

| 拆解對象 | 工具 | License | 啟用方式 |
|---------|------|---------|---------|
| 容器映像 / IaC | Trivy | Apache-2.0 ✅ | `INSTALL_TRIVY=1 bash setup-macos.sh` 自動 brew 裝 |
| 原始碼 zip → SBOM | Syft | Apache-2.0 ✅ | `INSTALL_SYFT=1 bash setup-macos.sh`;端點 `POST /api/releases/{id}/sbom-from-source` |
| Binary(.exe/.so/.dll/firmware/.jar/.whl)→ SBOM | Syft | Apache-2.0 ✅ | 同上 brew 裝;端點 `POST /api/releases/{id}/sbom-from-binary` |
| 韌體 image (.bin / .img,深度解包) | EMBA | **GPL-3.0** ⚠️ | `INSTALL_EMBA=1 bash setup-macos.sh` **只印指南**(本產品不打包,使用者自行決定是否安裝) |

**EMBA 的法務考量** (詳見 `NOTICE.md` §3):
- 本產品**從不**將 EMBA 包進任何 release artifact
- `firmware_service.py` 透過 `subprocess.run(["emba", ...])` 呼叫,屬於 arms-length 使用
- 若你選擇安裝 EMBA,GPL-3.0 義務只擴及 EMBA 本身,**不擴及本產品的程式碼**
- 預設策略:**不裝 EMBA**,容器/IaC 用 Trivy + 原始碼/binary 用客戶端 Syft 即足夠多數場景

如果你的客戶確實需要韌體拆解,推薦走 Docker EMBA 路線(`INSTALL_EMBA=1` 印的指南會說明)。

---

## 後續更新(改完 code 後常用)

```bash
SBOM_DEPLOY_HOST=mac-mini.local bash deploy/deploy.sh
```

`deploy.sh` 會本機 build 前端 → tar + ssh 上傳 backend 與 dist → 在 Mac Mini 跑 `pip install` → reload launchd agent。**Mac Mini 不需要 Node.js**(前端永遠在開發機 build)。

---

## 對外連線方式 — 三種選一

> **重要:backend 永遠只綁 `127.0.0.1:9100`**(launchd plist 寫死,基於最小暴露原則)。
> 對外存取**必須**透過下面三種方式其一:nginx 反代、Tailscale + nginx、SSH tunnel。
> **沒有「直接打 `mac-mini.local:9100`」的選項** — 那會連線拒絕。

### A. nginx 反向代理(推薦給內網/LAN 用)

`setup-macos.sh INSTALL_NGINX=1` 一次裝好 + 設定。

```bash
INSTALL_POSTGRES=1 INSTALL_NGINX=1 bash setup-macos.sh
```

之後打 `http://mac-mini.local`(80 埠 → nginx → 127.0.0.1:9100)。
`backend/.env` 的 `ALLOWED_ORIGIN` 設為 `http://mac-mini.local`(無 `:9100`)。

### B. Tailscale(跨 LAN 存取,免開公網)— 仍需 nginx

Tailscale 給 Mac Mini 一個 mesh 內的 hostname,但因 backend 只綁 127.0.0.1,
Tailscale 對端打 `mac-mini.tail-scale.ts.net:9100` 會連不到 — 還是要 nginx 在 80/443 接收。

1. Mac Mini 與用戶端都裝 Tailscale,登入同一帳號
2. `INSTALL_NGINX=1 bash setup-macos.sh`(裝 nginx)
3. `SBOM_DEPLOY_HOST=mac-mini.tail-scale.ts.net`,`.env` 的 `ALLOWED_ORIGIN` 對應
4. (可選)`tailscale cert` 拿 Let's Encrypt 走 HTTPS

**不想裝 nginx 的替代方案**:從本機跑 SSH tunnel,直接拿到 backend:
```bash
ssh -L 9100:127.0.0.1:9100 peter@mac-mini.tail-scale.ts.net
# 然後本機瀏覽器打 http://localhost:9100
```

### C. 公網 + 自有域名 + Let's Encrypt

需要:
- 域名(例如 `sbom.example.com`)
- 動態 DNS(若是浮動 IP — Cloudflare DNS / DuckDNS)
- 路由器 port forward 80/443 → Mac Mini
- nginx + certbot

先 `INSTALL_NGINX=1 bash setup-macos.sh`,然後:

```bash
brew install certbot
sudo certbot --nginx -d sbom.example.com
```

修改 `$(brew --prefix)/etc/nginx/servers/sbom.conf`,把 `server_name _` 改成你的域名,加 `listen 443 ssl;` 與 cert 路徑(certbot 通常自動加)。

`.env` 的 `ALLOWED_ORIGIN=https://sbom.example.com`。

---

## 資料庫:PostgreSQL(推薦)/ SQLite(替代)

### 為何預設 Postgres?

| 面向 | SQLite | PostgreSQL 16 |
|------|--------|----------------|
| 安裝複雜度 | 零(內建)| `brew install postgresql@16`(`INSTALL_POSTGRES=1` 一鍵)|
| 併發寫入 | WAL mode 可,但單寫者瓶頸 | MVCC 真併發 |
| RAM 占用 | ~5MB | ~50-150MB |
| 工具生態 | sqlite3 CLI | psql / pgAdmin / DBeaver / 完整 SQL 標準 |
| 備份 | `.backup`(秒級)| `pg_dump custom`(秒-分級,壓縮)|
| 適用場景 | 個人 / 1-2GB RAM 機器 | 多人 / 長期維運 / 想用 SQL 工具分析 |

對個人 Mac Mini 兩者都跑得動,但 Postgres 在維運性與工具支援上贏面大,**首推 Postgres**。SQLite 仍完整支援(改 `DATABASE_URL=sqlite:///../data/sbom.db` 即可)。

### 自動安裝(推薦)

`setup-macos.sh` 加 `INSTALL_POSTGRES=1`:

```bash
INSTALL_POSTGRES=1 bash deploy/setup-macos.sh
```

完成後會印出形如:

```
Add this to $SBOM_HOME/backend/.env:
    DATABASE_URL=postgresql+pg8000://sbom_user:Xy7K...32chars...@127.0.0.1:5432/sbom
```

整行貼到 `~/sbom/backend/.env` 取代範本的 `CHANGE_ME` 行即可。**密碼只印一次,務必當下保存**(若漏抄,在 Mac Mini 上重跑 `INSTALL_POSTGRES=1 PG_PASS=新密碼 bash setup-macos.sh` 會更新密碼)。

### 手動安裝(若你已有 Postgres)

```bash
# Mac Mini 上
brew install postgresql@16
brew services start postgresql@16

# 設 PATH(postgresql@16 是 keg-only)
echo 'export PATH="$(brew --prefix postgresql@16)/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# 建 user 與 DB
psql -d postgres -c "CREATE ROLE sbom_user WITH LOGIN PASSWORD '改成隨機強密碼';"
psql -d postgres -c "CREATE DATABASE sbom OWNER sbom_user;"
psql -d sbom -c "GRANT ALL ON SCHEMA public TO sbom_user;"

# .env 寫:
# DATABASE_URL=postgresql+pg8000://sbom_user:你的密碼@127.0.0.1:5432/sbom
```

### 從 SQLite 遷移現有資料

如果之前已有 `backend/sbom.db` 在跑、現在想換 Postgres:

```bash
# 在 Mac Mini 上(deploy/migrate-sqlite-to-postgres.py 已隨 deploy.sh 同步過去)
launchctl unload ~/Library/LaunchAgents/com.sbom.backend.plist  # 停掉 backend 才能安心遷移

# 1. 先 dry-run 看會搬多少
$SBOM_HOME/backend/venv/bin/python $SBOM_HOME/backend/../deploy/migrate-sqlite-to-postgres.py \
    --source "sqlite:///$SBOM_HOME/data/sbom.db" \
    --dest   "postgresql+pg8000://sbom_user:PASS@127.0.0.1:5432/sbom" \
    --dry-run

# 2. 確認沒問題後實跑(若 Postgres 已有資料,加 --force 會先 DELETE)
$SBOM_HOME/backend/venv/bin/python $SBOM_HOME/backend/../deploy/migrate-sqlite-to-postgres.py \
    --source "sqlite:///$SBOM_HOME/data/sbom.db" \
    --dest   "postgresql+pg8000://sbom_user:PASS@127.0.0.1:5432/sbom"

# 3. 改 .env 的 DATABASE_URL 指向 Postgres
vi $SBOM_HOME/backend/.env

# 4. 重啟 backend,驗 /health
launchctl load ~/Library/LaunchAgents/com.sbom.backend.plist
sleep 2 && curl http://127.0.0.1:9100/health
```

遷移腳本特點:
- **單一交易**:過程中任何錯誤整批 rollback,不會留下半套狀態
- **欄位交集**:source 與 dest 共有的欄位才搬(向前相容,schema 演進不會炸)
- **FK 順序**:用 `Base.metadata.sorted_tables` 自動算依賴順序
- **預設拒絕覆寫**:dest 已有資料就 fail,加 `--force` 才會 DELETE

### Postgres 互動操作

```bash
PG_BIN="$(brew --prefix postgresql@16)/bin"

# 連進去
"$PG_BIN/psql" -d sbom -U sbom_user

# 看 DB 大小
"$PG_BIN/psql" -d sbom -c "SELECT pg_size_pretty(pg_database_size('sbom'));"

# 列所有 table 與行數
"$PG_BIN/psql" -d sbom -c "
    SELECT relname, n_live_tup
    FROM pg_stat_user_tables
    ORDER BY n_live_tup DESC;
"

# 看 service 狀態
brew services list | grep postgres
```

### 切回 SQLite

把 `.env` 的 `DATABASE_URL` 改成 `sqlite:///../data/sbom.db`,重啟 backend 即可。資料會從零開始 — 若需要保留 Postgres 的資料先 dump 出來:

```bash
"$PG_BIN/pg_dump" --data-only --inserts -d sbom > /tmp/sbom-data.sql
# 之後可手動轉成 SQLite 語法導回(沒寫 reverse 遷移腳本,因為一般用不到)
```

---

## 常用維運指令(在 Mac Mini 上)

```bash
# Service 狀態
launchctl list | grep com.sbom.backend
launchctl print gui/$(id -u)/com.sbom.backend | head -30

# 重啟
launchctl kickstart -k gui/$(id -u)/com.sbom.backend

# 停 / 啟
launchctl unload ~/Library/LaunchAgents/com.sbom.backend.plist
launchctl load   ~/Library/LaunchAgents/com.sbom.backend.plist

# Log
tail -f ~/sbom/logs/backend.err.log
tail -f ~/sbom/logs/backend.out.log
log show --predicate 'process == "uvicorn"' --last 5m

# 健檢
curl http://127.0.0.1:9100/health

# 看 .env(別 cat 到分享頻道)
ls -la ~/sbom/backend/.env
```

---

## 目錄結構(Mac Mini 上)

```
~/sbom/
├── backend/             ← deploy.sh 同步自開發機
│   ├── app/
│   ├── venv/            ← Python 虛擬環境(Mac Mini 本地)
│   ├── requirements.txt
│   └── .env             ← 不進 git,手動填寫
├── frontend/
│   └── dist/            ← deploy.sh 同步自開發機 npm run build 產物
├── data/
│   ├── sbom.db          ← 僅 SQLite 模式產生(Postgres 模式不會有)
│   └── uploads/         ← 上傳的 SBOM 檔案
├── logs/
│   ├── backend.out.log
│   ├── backend.err.log
│   └── backup.log       ← cron backup 輸出
└── backups/             ← backup.sh 產出
    ├── sbom_YYYYMMDD_HHMMSS.db    ← SQLite mode
    └── sbom_YYYYMMDD_HHMMSS.dump  ← Postgres mode (pg_dump custom format)
```

---

## 自動備份(launchd 或 cron)

`backup.sh` **自動偵測 `backend/.env` 的 `DATABASE_URL`**,SQLite 走 `sqlite3 .backup`,Postgres 走 `pg_dump --format=custom`,輸出在 `~/sbom/backups/`。預設保留最近 14 天自動輪替。

最簡單用 cron(每天凌晨 2 點):

```bash
crontab -e
# 加入這行
0 2 * * * /Users/peter/sbom/deploy/backup.sh >> /Users/peter/sbom/logs/backup.log 2>&1
```

手動跑一次驗證:
```bash
bash ~/sbom/deploy/backup.sh
ls -la ~/sbom/backups/
```

環境變數覆寫:
- `SBOM_DATABASE_URL` 指定 DSN(略過讀 .env)
- `SBOM_BACKUP_DIR` 自訂輸出目錄
- `SBOM_KEEP_DAYS` 自訂保留天數

### 還原

**SQLite:**
```bash
launchctl unload ~/Library/LaunchAgents/com.sbom.backend.plist
sqlite3 ~/sbom/data/sbom.db ".restore '/path/to/sbom_20260425_020000.db'"
launchctl load   ~/Library/LaunchAgents/com.sbom.backend.plist
```

**Postgres:**
```bash
launchctl unload ~/Library/LaunchAgents/com.sbom.backend.plist
PG_BIN="$(brew --prefix postgresql@16)/bin"
"$PG_BIN/dropdb"   sbom
"$PG_BIN/createdb" -O sbom_user sbom
"$PG_BIN/pg_restore" --no-owner --no-acl -d "postgresql://sbom_user:PASS@127.0.0.1:5432/sbom" \
                     /path/to/sbom_20260425_020000.dump
launchctl load   ~/Library/LaunchAgents/com.sbom.backend.plist
```

---

## 架構圖

```
你的開發機(Windows / Mac / Linux)
    │ npm run build
    │ tar + ssh
    ▼
Mac Mini(macOS,$HOME/sbom/)
    │
    ├─ launchd(com.sbom.backend) → uvicorn :9100
    │                                  │
    │                                  └─ FastAPI(STATIC_DIR=frontend/dist 同時吐 SPA)
    │                                          │
    │                                          └─ ┬─ PostgreSQL 16(brew services,localhost:5432)← 預設
    │                                             └─ SQLite(data/sbom.db,WAL)── 替代
    │
    └─ nginx(可選,Homebrew):80/443 → 反向代理 :9100,順便靜態快取
```

---

## 常見問題

**Q: `mac-mini.local` 連不上?**
- 確認系統設定 → 一般 → 共享 → 「遠端登入」開啟
- 確認雙方在同 LAN 下,或裝了 Tailscale
- 防火牆: 系統設定 → 網路 → 防火牆 → 允許 SSH

**Q: launchd 載入失敗?**
- `launchctl print gui/$(id -u)/com.sbom.backend` 看狀態
- 看 `~/sbom/logs/backend.err.log`(可能是 .env 還沒填,或 venv 沒建好)
- plist 內 `__SBOM_HOME__` / `__PYTHON_BIN__` 沒被替換 → 重跑 `setup-macos.sh`

**Q: Apple Silicon 與 Intel 路徑不同?**
- Apple Silicon: `/opt/homebrew/...`
- Intel: `/usr/local/...`
- 兩者 launchd plist 的 `PATH` 都包含,不需手動切換

**Q: Postgres 怎麼弄?**
- 詳見上方「資料庫:PostgreSQL / SQLite」章節 — 從零部署用 `INSTALL_POSTGRES=1`,從 SQLite 搬資料用 `deploy/migrate-sqlite-to-postgres.py`

**Q: Postgres 服務沒啟動?**
- `brew services list | grep postgres` 看狀態,若 stopped 用 `brew services start postgresql@16`
- 看 log:`tail -f $(brew --prefix)/var/log/postgresql@16.log`
- 連線測試:`pg_isready -h 127.0.0.1 -p 5432`
