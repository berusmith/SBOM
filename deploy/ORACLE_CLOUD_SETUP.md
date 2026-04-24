# Oracle Cloud 部署指南

## 伺服器資訊

| 項目 | 值 |
|------|-----|
| IP | 161.33.130.101 |
| OS | Oracle Linux 9.7 |
| SSH 用戶 | `opc` |
| SSH Key | `D:\projects\SBOM\ssh-key-2026-04-21.key` |
| RAM | 1GB |
| 磁碟 | 30GB |

---

## 防火牆設定（必做，兩層都要開）

### 第一層：VCN Security List（雲端控制台）

1. Oracle Cloud Console → 左上 ≡ → Networking → Virtual Cloud Networks
2. 點你的 VCN → Security Lists → Default Security List
3. Add Ingress Rules：

| Source CIDR | Protocol | Port | 說明 |
|-------------|----------|------|------|
| `0.0.0.0/0` | TCP | `22`  | SSH |
| `0.0.0.0/0` | TCP | `80`  | HTTP |
| `0.0.0.0/0` | TCP | `443` | HTTPS（未來用）|

### 第二層：OS 防火牆（setup.sh 自動處理）

Oracle Linux 9 用 firewalld，setup.sh 會自動開放 80/443。若失敗手動執行：
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## 首次部署

```bash
# 在 D:\projects\SBOM\sbom-platform\ 目錄下執行
bash deploy/first-deploy.sh
```

流程：
1. 上傳 nginx.conf、systemd service、.env.production、setup.sh 到伺服器 `/tmp/`
2. 在伺服器執行 setup.sh（安裝 python3.11 + nginx，不安裝 Node.js）
3. 暫停等待你在伺服器上填寫 `.env`（SECRET_KEY、ADMIN_PASSWORD）
4. 本機 `npm run build` → rsync backend/ + dist/ → pip install → 啟動服務

---

## 日後更新

```bash
bash deploy/deploy.sh
```

本機 build 前端，rsync 程式碼，重啟後端。**Node.js 不需安裝在伺服器上。**

---

## 常用維運指令

```bash
# SSH 連線
ssh -i ../ssh-key-2026-04-21.key opc@161.33.130.101

# 查看後端狀態與日誌
sudo systemctl status sbom-backend
journalctl -u sbom-backend -f

# 重啟後端
sudo systemctl restart sbom-backend

# 查看 nginx 狀態
sudo systemctl status nginx
sudo nginx -t

# 記憶體 / 磁碟
free -h
df -h /

# 查看 .env
cat /var/www/sbom/.env
```

---

## 目錄結構（伺服器）

```
/var/www/sbom/
├── backend/          ← rsync 自本機 backend/
│   ├── app/
│   ├── venv/         ← Python 虛擬環境（伺服器本地）
│   ├── requirements.txt
│   └── .env          ← 不進 git，手動填寫
├── frontend/
│   └── dist/         ← rsync 自本機 npm run build 產出
└── data/
    ├── sbom.db       ← SQLite 資料庫
    └── uploads/      ← 上傳的 SBOM 檔案
```

---

## 架構說明

```
用戶瀏覽器
    ↓ HTTP :80
nginx（靜態檔 + 反向代理）
    ├── /           → frontend/dist/（React SPA）
    └── /api/*      → uvicorn :9100（FastAPI）
                         ↓
                    SQLite（data/sbom.db）
```

FastAPI 的 `STATIC_DIR` 環境變數設為 `frontend/dist`，即使直接存取 port 9100 也能回傳 SPA（備援用）。

---

## 切換 Postgres 資料庫（可選）

SQLite 適合單機、低流量場景。若客戶要求多節點、高可用或 RBAC 審計，可切換至 Postgres。

### 安裝 Postgres（Oracle Linux 9）

```bash
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

# 建立資料庫與使用者
sudo -u postgres psql <<SQL
CREATE USER sbom_user WITH PASSWORD 'your_strong_password';
CREATE DATABASE sbom_db OWNER sbom_user;
GRANT ALL PRIVILEGES ON DATABASE sbom_db TO sbom_user;
SQL
```

### 修改後端設定

編輯 `/var/www/sbom/backend/.env`：

```bash
# 將此行
DATABASE_URL=sqlite:///./sbom.db

# 改為
DATABASE_URL=postgresql://sbom_user:your_strong_password@localhost:5432/sbom_db
```

### 安裝 Postgres Python driver

```bash
cd /var/www/sbom/backend
source venv/bin/activate
pip install psycopg2-binary
```

### 重啟服務

```bash
sudo systemctl restart sbom-backend
# 首次啟動會自動建立所有 table 和 migration
```

### 從 SQLite 搬移現有資料（使用 pgloader）

```bash
# 安裝 pgloader
sudo dnf install -y pgloader

# 搬移（schema 會自動從 Postgres 已建立的 table 推斷）
pgloader sqlite:///var/www/sbom/data/sbom.db \
         postgresql://sbom_user:your_password@localhost/sbom_db

# 搬移後記得重建 sequences（UUID 主鍵不受影響）
```

> **注意**：uploads/ 目錄（SBOM 檔案）和 .env 需手動複製，不在 pgloader 範圍內。
