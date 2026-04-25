#!/usr/bin/env bash
# Mac Mini 首次安裝 — 在 Mac Mini 本機執行(不是從 Windows 跑)
#
# 用法:
#   bash deploy/setup-macos.sh                                    # 純 Python + venv + launchd
#   INSTALL_POSTGRES=1 bash deploy/setup-macos.sh                 # 加裝 PostgreSQL 16
#   INSTALL_POSTGRES=1 INSTALL_NGINX=1 bash deploy/setup-macos.sh # 全餐
#   INSTALL_TRIVY=1 bash deploy/setup-macos.sh                    # 加裝容器/IaC 掃描
#   INSTALL_SYFT=1 bash deploy/setup-macos.sh                     # 加裝原始碼/binary SBOM 生成
#
# 環境變數:
#   SBOM_HOME         部署根目錄(預設 $HOME/sbom)
#   INSTALL_POSTGRES  =1 時裝 postgresql@16 + 建 DB user 與 database
#   INSTALL_NGINX     =1 時裝 nginx(走 80/443 + TLS;LAN-only 不需要)
#   INSTALL_TRIVY     =1 時裝 Trivy(Apache-2.0 — 容器映像 / IaC SBOM 拆解)
#   INSTALL_SYFT      =1 時裝 Syft (Apache-2.0 — 原始碼 zip / binary 產 SBOM)
#   INSTALL_EMBA      =1 時"印出"EMBA 安裝指南(GPL-3.0 — 本腳本不下載也不打包)
#   PG_USER           Postgres 使用者(預設 sbom_user)
#   PG_PASS           Postgres 密碼(留空 = 自動產 32 字元隨機)
#   PG_DB             Postgres database 名(預設 sbom)
#
# 第一次跑會把 DATABASE_URL 印到終端 — 複製到 backend/.env 即可。
#
# License 邊界:
#   - Trivy / Postgres / nginx / Python : permissive license,本腳本可直接 brew install
#   - EMBA : GPL-3.0,本產品**不包進任何 release artifact**;此旗標僅印安裝引導,
#           真正的安裝動作由使用者自行決定執行,符合 arms-length subprocess 模式。
#           詳見 NOTICE.md 第 3 節。

set -euo pipefail

SBOM_HOME="${SBOM_HOME:-$HOME/sbom}"
INSTALL_POSTGRES="${INSTALL_POSTGRES:-0}"
INSTALL_NGINX="${INSTALL_NGINX:-0}"
INSTALL_TRIVY="${INSTALL_TRIVY:-0}"
INSTALL_SYFT="${INSTALL_SYFT:-0}"
INSTALL_EMBA="${INSTALL_EMBA:-0}"
PLIST_DST="$HOME/Library/LaunchAgents/com.sbom.backend.plist"

PG_USER="${PG_USER:-sbom_user}"
PG_DB="${PG_DB:-sbom}"
PG_PASS="${PG_PASS:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

echo "=== SBOM Mac Mini setup ==="
echo "  SBOM_HOME         = $SBOM_HOME"
echo "  INSTALL_POSTGRES  = $INSTALL_POSTGRES"
echo "  INSTALL_NGINX     = $INSTALL_NGINX"
echo "  INSTALL_TRIVY     = $INSTALL_TRIVY"
echo "  INSTALL_SYFT      = $INSTALL_SYFT"
echo "  INSTALL_EMBA      = $INSTALL_EMBA  (notice-only; never bundled)"
echo ""

# ── [1/8] Homebrew ────────────────────────────────────────────────────────────
if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Install from https://brew.sh first, then re-run."
    exit 1
fi
echo "[1/8] Homebrew: $(brew --prefix)"

# ── [2/8] python@3.11 ─────────────────────────────────────────────────────────
echo "[2/8] Installing python@3.11..."
brew list python@3.11 >/dev/null 2>&1 || brew install python@3.11
PYTHON_BIN="$(brew --prefix python@3.11)/bin/python3.11"
"$PYTHON_BIN" --version

# ── [3/8] PostgreSQL 16 (optional) ────────────────────────────────────────────
PG_DSN=""  # filled in if Postgres is installed
if [ "$INSTALL_POSTGRES" = "1" ]; then
    echo "[3/8] Installing postgresql@16..."
    brew list postgresql@16 >/dev/null 2>&1 || brew install postgresql@16
    PG_PREFIX="$(brew --prefix postgresql@16)"
    PG_BIN="$PG_PREFIX/bin"
    "$PG_BIN/postgres" --version

    # Start as launchd service (auto-start on login)
    if ! brew services list | grep -E "^postgresql@16\s+started" >/dev/null 2>&1; then
        brew services start postgresql@16
    fi

    # Wait for ready (up to 30s)
    echo "    waiting for Postgres to accept connections..."
    for i in $(seq 1 30); do
        if "$PG_BIN/pg_isready" -q 2>/dev/null; then
            echo "    ready after ${i}s"
            break
        fi
        sleep 1
        if [ "$i" = "30" ]; then
            echo "ERROR: Postgres failed to start within 30s. Check 'brew services list'."
            exit 1
        fi
    done
else
    echo "[3/8] Skipping PostgreSQL (INSTALL_POSTGRES=0). Backend will use SQLite."
fi

# ── [4/8] Create Postgres role + database (idempotent) ────────────────────────
if [ "$INSTALL_POSTGRES" = "1" ]; then
    echo "[4/8] Configuring Postgres role + database..."
    PG_BIN="$(brew --prefix postgresql@16)/bin"

    # Generate password if not provided
    if [ -z "$PG_PASS" ]; then
        PG_PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)"
        echo "    auto-generated random password (32 chars)"
    fi

    # Create role if missing (psql peer auth as macOS user — Homebrew default)
    "$PG_BIN/psql" -d postgres -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${PG_USER}') THEN
        CREATE ROLE ${PG_USER} WITH LOGIN PASSWORD '${PG_PASS}';
        RAISE NOTICE 'Created role ${PG_USER}';
    ELSE
        ALTER ROLE ${PG_USER} WITH PASSWORD '${PG_PASS}';
        RAISE NOTICE 'Updated password for existing role ${PG_USER}';
    END IF;
END
\$\$;
SQL

    # Create database if missing
    DB_EXISTS="$("$PG_BIN/psql" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'")"
    if [ -z "$DB_EXISTS" ]; then
        "$PG_BIN/psql" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${PG_DB} OWNER ${PG_USER};"
        echo "    created database ${PG_DB}"
    else
        echo "    database ${PG_DB} already exists"
    fi

    # Grant schema permissions (Postgres 15+ requires explicit GRANT on public schema)
    "$PG_BIN/psql" -d "${PG_DB}" -v ON_ERROR_STOP=1 -c "GRANT ALL ON SCHEMA public TO ${PG_USER};"

    PG_DSN="postgresql+psycopg2://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}"
fi

if [ "$INSTALL_NGINX" = "1" ]; then
    brew list nginx >/dev/null 2>&1 || brew install nginx
fi

# ── [5/8] Directory layout ────────────────────────────────────────────────────
echo "[5/8] Creating layout under $SBOM_HOME ..."
mkdir -p "$SBOM_HOME"/{backend,frontend/dist,data/uploads,logs,backups}

# ── [6/8] Python venv ─────────────────────────────────────────────────────────
echo "[6/8] Creating venv..."
if [ ! -d "$SBOM_HOME/backend/venv" ]; then
    "$PYTHON_BIN" -m venv "$SBOM_HOME/backend/venv"
fi
"$SBOM_HOME/backend/venv/bin/pip" install --upgrade pip --quiet
echo "venv ready (deps will be installed by deploy.sh)"

# ── [7/8] launchd plist ───────────────────────────────────────────────────────
echo "[7/8] Installing launchd agent at $PLIST_DST ..."
mkdir -p "$HOME/Library/LaunchAgents"
SRC_PLIST="$SCRIPT_DIR/com.sbom.backend.plist"
if [ ! -f "$SRC_PLIST" ]; then
    echo "ERROR: $SRC_PLIST not found. Run from repo root with deploy/com.sbom.backend.plist present."
    exit 1
fi
sed -e "s|__SBOM_HOME__|$SBOM_HOME|g" \
    -e "s|__PYTHON_BIN__|$SBOM_HOME/backend/venv/bin/uvicorn|g" \
    "$SRC_PLIST" > "$PLIST_DST"
launchctl unload "$PLIST_DST" 2>/dev/null || true

# ── [8/11] Nginx config (optional) ────────────────────────────────────────────
if [ "$INSTALL_NGINX" = "1" ]; then
    echo "[8/11] Installing nginx config..."
    NGINX_CONF_DIR="$(brew --prefix)/etc/nginx/servers"
    mkdir -p "$NGINX_CONF_DIR"
    sed -e "s|__SBOM_HOME__|$SBOM_HOME|g" \
        "$SCRIPT_DIR/nginx-sbom.conf" > "$NGINX_CONF_DIR/sbom.conf"
    brew services restart nginx || brew services start nginx
    echo "nginx config: $NGINX_CONF_DIR/sbom.conf"
else
    echo "[8/11] Skipping nginx (INSTALL_NGINX=0). Backend will be reachable on http://localhost:9100"
fi

# ── [9/11] Trivy (optional, Apache-2.0) ───────────────────────────────────────
# Trivy provides container-image and IaC scanning.  Apache-2.0 license — free
# for commercial use, no attribution surface beyond NOTICE.md.  Safe to install
# directly via brew.
if [ "$INSTALL_TRIVY" = "1" ]; then
    echo "[9/11] Installing Trivy (Apache-2.0)..."
    brew list trivy >/dev/null 2>&1 || brew install trivy
    trivy --version
    echo "    Trivy ready. Container scan: POST /api/releases/{id}/scan-image"
    echo "                IaC scan:        POST /api/releases/{id}/scan-iac"
else
    echo "[9/11] Skipping Trivy (INSTALL_TRIVY=0). To enable later:  brew install trivy"
fi

# ── [10/11] Syft (optional, Apache-2.0) ───────────────────────────────────────
# Syft (Anchore) generates CycloneDX SBOMs from source archives or single
# binaries.  Apache-2.0 license — same compliance posture as Trivy: brew
# installable, no copyleft surface, attribution covered by NOTICE.md §3.
if [ "$INSTALL_SYFT" = "1" ]; then
    echo "[10/11] Installing Syft (Apache-2.0)..."
    brew list syft >/dev/null 2>&1 || brew install syft
    syft --version
    echo "    Syft ready. Source-archive SBOM:  POST /api/releases/{id}/sbom-from-source"
    echo "               Binary SBOM:           POST /api/releases/{id}/sbom-from-binary"
else
    echo "[10/11] Skipping Syft (INSTALL_SYFT=0). To enable later:  brew install syft"
fi

# ── [11/11] EMBA notice (optional, GPL-3.0 — NEVER auto-installed) ───────────
# EMBA is GPL-3.0 firmware analysis software.  This product invokes EMBA at
# arms length via subprocess; it does NOT include EMBA binaries or sources in
# any release artifact.  This step prints installation guidance only — it does
# not download EMBA, install EMBA, or accept GPL-3.0 obligations on the user's
# behalf.  See NOTICE.md §3 for the compliance reasoning.
if [ "$INSTALL_EMBA" = "1" ]; then
    cat <<'EMBA_NOTICE'
[11/11] EMBA installation guidance (GPL-3.0):

This installer does NOT download EMBA.  EMBA is GPL-3.0 licensed firmware
analysis software maintained at:
    https://github.com/e-m-b-a/emba

EMBA is heavily Linux-dependent.  On macOS, recommended options are:

  Option A — Run EMBA in Docker (recommended on Mac Mini)
    1. Install Docker Desktop:
         https://docs.docker.com/desktop/install/mac-install/
    2. Pull the official image (you accept GPL-3.0 on the EMBA portion
       at this point, governed by EMBA's own license — not this product):
         docker pull embeddedanalyzer/emba
    3. NOTE: backend/app/services/firmware_service.py currently invokes
       `emba` directly on PATH.  Wiring up the Docker workflow requires
       a code change to firmware_service.py — open a roadmap issue if
       this matters for your deployment.

  Option B — Run EMBA on a separate Linux host
    Install EMBA per upstream README on a Linux box.  Scan firmware
    there.  Upload the resulting CycloneDX/SPDX SBOM to this platform
    via POST /api/releases/{id}/sbom — clean separation, no GPL bleed.

  Option C — Skip EMBA (default; recommended for most users)
    Use Trivy (container/IaC) plus client-side Syft (source/binary) for
    SBOM generation.  Both are Apache-2.0 with zero copyleft surface.

Compliance summary:
  - SBOM Platform NEVER redistributes EMBA in release artifacts.
  - subprocess() invocation = arms-length use; no GPL obligations propagate
    to SBOM Platform's own code under this pattern.
  - The user's choice to install EMBA is governed solely by EMBA's license.

EMBA_NOTICE
else
    echo "[11/11] Skipping EMBA notice. (Set INSTALL_EMBA=1 to read the guidance.)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=============================================================="
echo "=== Setup complete ==="
echo "=============================================================="
echo ""
echo "Next steps:"
echo "  1. Copy .env template:  cp $SCRIPT_DIR/.env.production $SBOM_HOME/backend/.env"
echo "  2. Edit .env:           vi $SBOM_HOME/backend/.env"
if [ -n "$PG_DSN" ]; then
    echo ""
    echo "     >>> Set DATABASE_URL to:"
    echo "         DATABASE_URL=$PG_DSN"
    echo ""
    echo "     (Save the password above — it won't be shown again.)"
    echo ""
    echo "     For interactive psql access, add this to your ~/.zshrc:"
    echo "         export PATH=\"$(brew --prefix postgresql@16)/bin:\$PATH\""
fi
echo "     Always change SECRET_KEY (>= 32 random bytes) and ADMIN_PASSWORD."
echo ""
echo "  3. Run deploy.sh from dev machine, or locally if working on the Mac Mini."
echo "  4. After code is in place:  launchctl load $PLIST_DST"
echo "  5. Verify:                  curl http://127.0.0.1:9100/health"
