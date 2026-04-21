#!/usr/bin/env bash
# 第一次部署用：上傳設定檔、執行 setup、首次同步
# 執行方式（在 sbom-platform/ 目錄下）: bash deploy/first-deploy.sh
set -e

KEY="../ssh-key-2026-04-21.key"
SERVER="opc@161.33.130.101"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no"

chmod 600 "$KEY" 2>/dev/null || true

echo "=== 測試 SSH 連線 ==="
$SSH "$SERVER" "echo 連線成功"

echo "=== 上傳設定檔到 /tmp ==="
scp -i "$KEY" -o StrictHostKeyChecking=no \
  deploy/nginx-sbom.conf      "$SERVER:/tmp/nginx-sbom.conf"
scp -i "$KEY" -o StrictHostKeyChecking=no \
  deploy/sbom-backend.service "$SERVER:/tmp/sbom-backend.service"
scp -i "$KEY" -o StrictHostKeyChecking=no \
  deploy/.env.production      "$SERVER:/tmp/.env.production"
scp -i "$KEY" -o StrictHostKeyChecking=no \
  deploy/setup.sh             "$SERVER:/tmp/setup.sh"

echo "=== 執行伺服器初始化（安裝 python3.11 + nginx，不安裝 Node.js）==="
$SSH "$SERVER" "bash /tmp/setup.sh"

echo ""
echo "=== 請在伺服器上填寫 .env ==="
echo "  執行: $SSH $SERVER"
echo "  然後: cp /tmp/.env.production /var/www/sbom/.env && nano /var/www/sbom/.env"
echo "  修改 SECRET_KEY 和 ADMIN_PASSWORD 後儲存"
echo ""
read -p "填寫完 .env 後按 Enter 繼續進行首次程式碼部署..."

echo "=== 執行首次程式碼部署 ==="
bash deploy/deploy.sh

echo ""
echo "=============================="
echo "首次部署完成！"
echo "開啟: http://161.33.130.101"
echo "=============================="
