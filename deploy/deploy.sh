#!/usr/bin/env bash
# 本機執行：build 前端、同步檔案、重啟後端
# 執行方式（在 sbom-platform/ 目錄下）: bash deploy/deploy.sh
set -e

KEY="../ssh-key-2026-04-21.key"
SERVER="ubuntu@161.33.130.101"
REMOTE="/var/www/sbom"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no"

# Windows git bash: 確保 key 權限
chmod 600 "$KEY" 2>/dev/null || true

echo "=== [1/4] Build 前端（本機執行，不佔伺服器記憶體）==="
cd frontend
npm run build
cd ..

echo "=== [2/4] 同步後端程式碼 ==="
rsync -az --delete \
  --exclude __pycache__ \
  --exclude "*.pyc" \
  --exclude ".env" \
  --exclude "sbom.db" \
  --exclude "sbom.db-shm" \
  --exclude "sbom.db-wal" \
  --exclude "uploads/" \
  --exclude "venv/" \
  -e "ssh -i $KEY -o StrictHostKeyChecking=no" \
  backend/ "$SERVER:$REMOTE/backend/"

echo "=== [3/4] 同步前端靜態檔（僅 dist/）==="
rsync -az --delete \
  -e "ssh -i $KEY -o StrictHostKeyChecking=no" \
  frontend/dist/ "$SERVER:$REMOTE/frontend/dist/"

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
