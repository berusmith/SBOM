#!/usr/bin/env bash
# 執行方式（在 D:/projects/SBOM/ 目錄下）: bash deploy/deploy.sh
set -e

KEY="./ssh-key-2026-04-21.key"
SERVER="opc@161.33.130.101"
REMOTE="/var/www/sbom"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no"

chmod 600 "$KEY" 2>/dev/null || true

echo "=== [1/4] Build 前端（本機執行，不佔伺服器記憶體）==="
cd frontend
npm run build
cd ..

echo "=== [2/4] 同步後端程式碼 ==="
tar -czf - \
  --exclude='backend/__pycache__' \
  --exclude='backend/**/__pycache__' \
  --exclude='backend/**/*.pyc' \
  --exclude='backend/.env' \
  --exclude='backend/sbom.db' \
  --exclude='backend/sbom.db-shm' \
  --exclude='backend/sbom.db-wal' \
  --exclude='backend/uploads' \
  --exclude='backend/venv' \
  backend/ \
| $SSH "$SERVER" "mkdir -p $REMOTE && tar -xzf - -C $REMOTE"

echo "=== [3/4] 同步前端靜態檔（僅 dist/）==="
tar -czf - frontend/dist/ \
| $SSH "$SERVER" "mkdir -p $REMOTE/frontend && tar -xzf - --strip-components=1 -C $REMOTE/frontend"

echo "=== [4/4] 安裝新依賴並重啟後端 ==="
$SSH "$SERVER" bash -s << 'REMOTE_CMD'
  cd /var/www/sbom/backend
  ./venv/bin/pip install -r requirements.txt --quiet
  sudo systemctl restart sbom-backend
  sleep 2
  sudo systemctl is-active sbom-backend && echo "Backend: running" || echo "Backend: FAILED"
REMOTE_CMD

echo ""
echo "部署完成！ http://161.33.130.101"
