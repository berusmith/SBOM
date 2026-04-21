#!/usr/bin/env bash
# 在 Oracle Cloud 伺服器上執行一次，完成初始環境建置
# 執行方式: bash setup.sh
set -e

DEPLOY_DIR="/var/www/sbom"
SERVICE_USER="opc"

echo "=== [1/6] 安裝系統套件 ==="
sudo dnf install -y -q python3.11 python3.11-pip nginx

echo "=== [2/6] 建立目錄結構 ==="
sudo mkdir -p "$DEPLOY_DIR"/{backend,frontend/dist,data/uploads}
sudo chown -R "$SERVICE_USER":"$SERVICE_USER" "$DEPLOY_DIR"

echo "=== [3/6] 建立 Python 虛擬環境並安裝依賴 ==="
cd "$DEPLOY_DIR/backend"
python3.11 -m venv venv || python3.11 -m virtualenv venv
./venv/bin/pip install --upgrade pip --quiet
./venv/bin/pip install -r requirements.txt --quiet
echo "Python 依賴安裝完成"

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
# Ubuntu ufw
if command -v ufw &>/dev/null; then
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    echo "ufw 已開放 80/443"
fi
# Oracle Linux firewalld
if command -v firewall-cmd &>/dev/null; then
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --reload
    echo "firewalld 已開放 80/443"
fi

echo ""
echo "=== 初始化完成 ==="
echo "請執行以下步驟："
echo "  1. 複製並填寫 .env:  cp /tmp/.env.production $DEPLOY_DIR/.env && nano $DEPLOY_DIR/.env"
echo "  2. 啟動後端:          sudo systemctl start sbom-backend"
echo "  3. 確認狀態:          sudo systemctl status sbom-backend"
echo "  4. 查看日誌:          journalctl -u sbom-backend -f"
