#!/usr/bin/env bash
# 在 Ubuntu 伺服器上執行一次，完成初始環境建置（不需要 Node.js）
# 執行方式: bash /tmp/setup.sh
set -e

DEPLOY_DIR="/var/www/sbom"
SERVICE_USER="ubuntu"

echo "=== [1/6] 安裝系統套件 ==="
sudo apt-get update -qq
sudo apt-get install -y -q python3.11 python3.11-venv python3-pip nginx

echo "=== [2/6] 建立目錄結構 ==="
sudo mkdir -p "$DEPLOY_DIR"/{backend,frontend/dist,data/uploads}
sudo chown -R "$SERVICE_USER":"$SERVICE_USER" "$DEPLOY_DIR"

echo "=== [3/6] 建立 Python 虛擬環境 ==="
cd "$DEPLOY_DIR/backend"
python3.11 -m venv venv
./venv/bin/pip install --upgrade pip --quiet
# requirements.txt 由 deploy.sh 同步後才有，此處先跳過
echo "虛擬環境建立完成（依賴將在首次 deploy.sh 時安裝）"

echo "=== [4/6] 設定 nginx ==="
sudo cp /tmp/nginx-sbom.conf /etc/nginx/sites-available/sbom
sudo ln -sf /etc/nginx/sites-available/sbom /etc/nginx/sites-enabled/sbom
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl restart nginx

echo "=== [5/6] 設定 systemd 服務 ==="
sudo cp /tmp/sbom-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sbom-backend

echo "=== [6/6] 開放防火牆 ==="
if command -v ufw &>/dev/null; then
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw --force enable
    echo "ufw 已開放 80/443"
fi

echo ""
echo "=== 初始化完成 ==="
echo "後續步驟："
echo "  1. 填寫 .env:   cp /tmp/.env.production $DEPLOY_DIR/.env && nano $DEPLOY_DIR/.env"
echo "  2. 填完後回到本機繼續執行 first-deploy.sh"
