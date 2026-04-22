#!/usr/bin/env bash
# 在 Oracle Linux 9 伺服器上執行一次，完成初始環境建置（不需要 Node.js）
# 執行方式: bash /tmp/setup.sh
set -e

DEPLOY_DIR="/var/www/sbom"
SERVICE_USER="opc"

echo "=== [1/6] 安裝系統套件 ==="
sudo dnf install -y -q python3.11 python3.11-pip nginx

echo "=== [2/6] 建立目錄結構 ==="
sudo mkdir -p "$DEPLOY_DIR"/{backend,frontend/dist,data/uploads}
sudo chown -R "$SERVICE_USER":"$SERVICE_USER" "$DEPLOY_DIR"

echo "=== [3/6] 建立 Python 虛擬環境 ==="
cd "$DEPLOY_DIR/backend"
python3.11 -m venv venv
./venv/bin/pip install --upgrade pip --quiet
echo "虛擬環境建立完成（依賴將在 deploy.sh 時安裝）"

echo "=== [4/6] 設定 nginx ==="
sudo cp /tmp/nginx-sbom.conf /etc/nginx/conf.d/sbom.conf
# 移除預設設定避免衝突
sudo rm -f /etc/nginx/conf.d/default.conf
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl start nginx

echo "=== [5/6] 設定 systemd 服務 ==="
sudo cp /tmp/sbom-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sbom-backend

echo "=== [6/6] 開放防火牆 ==="
if command -v firewall-cmd &>/dev/null; then
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --reload
    echo "firewalld 已開放 80/443"
fi

echo ""
echo "=== 初始化完成 ==="
echo "後續步驟："
echo "  1. 填寫 .env:   cp /tmp/.env.production $DEPLOY_DIR/.env && nano $DEPLOY_DIR/.env"
echo "  2. 填完後回到本機繼續執行 first-deploy.sh"
