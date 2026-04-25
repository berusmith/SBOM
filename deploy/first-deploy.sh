#!/usr/bin/env bash
# 首次部署到 Mac Mini —— 上傳設定檔 + 提示在 Mac Mini 上跑 setup-macos.sh + 首次同步程式碼。
#
# 前置條件:
#   1. Mac Mini 上已裝好 Homebrew(https://brew.sh)
#   2. Mac Mini 已開啟「遠端登入」(系統設定 → 一般 → 共享 → 遠端登入)
#   3. 你的 SSH 公鑰已加到 Mac Mini 的 ~/.ssh/authorized_keys
#
# 執行:
#   SBOM_DEPLOY_HOST=mac-mini.local bash deploy/first-deploy.sh
#
# 完整變數見 deploy/deploy.sh 的標頭說明。

set -euo pipefail

: "${SBOM_DEPLOY_HOST:?Set SBOM_DEPLOY_HOST (e.g. export SBOM_DEPLOY_HOST=mac-mini.local)}"
SBOM_DEPLOY_USER="${SBOM_DEPLOY_USER:-$(whoami)}"
SBOM_DEPLOY_DIR="${SBOM_DEPLOY_DIR:-/Users/$SBOM_DEPLOY_USER/sbom}"

SSH_OPTS="${SBOM_SSH_OPTS:-} -o StrictHostKeyChecking=accept-new"
if [ -n "${SBOM_SSH_KEY:-}" ]; then
    chmod 600 "$SBOM_SSH_KEY" 2>/dev/null || true
    SSH_OPTS="-i $SBOM_SSH_KEY $SSH_OPTS"
fi
SSH="ssh $SSH_OPTS $SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST"
SCP="scp $SSH_OPTS"

echo "=== [1/4] 測試 SSH 連線 ==="
$SSH "uname -a && sw_vers 2>/dev/null || true"

echo "=== [2/4] 上傳部署設定檔到 Mac Mini ~/sbom-bootstrap/ ==="
$SSH "mkdir -p ~/sbom-bootstrap"
$SCP deploy/setup-macos.sh                  "$SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:~/sbom-bootstrap/"
$SCP deploy/com.sbom.backend.plist          "$SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:~/sbom-bootstrap/"
$SCP deploy/nginx-sbom.conf                 "$SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:~/sbom-bootstrap/"
$SCP deploy/.env.production                 "$SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:~/sbom-bootstrap/"
$SCP deploy/backup.sh                       "$SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:~/sbom-bootstrap/"
$SCP deploy/migrate-sqlite-to-postgres.py   "$SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:~/sbom-bootstrap/"

echo "=== [3/4] 在 Mac Mini 上執行 setup-macos.sh ==="
echo "(若要同時裝 nginx,加 INSTALL_NGINX=1)"
$SSH "cd ~/sbom-bootstrap && bash setup-macos.sh"

echo ""
echo "=== 請在 Mac Mini 上填寫 .env ==="
echo "  $SSH"
echo "  cp ~/sbom-bootstrap/.env.production $SBOM_DEPLOY_DIR/backend/.env"
echo "  vi $SBOM_DEPLOY_DIR/backend/.env   # 修改 SECRET_KEY 與 ADMIN_PASSWORD"
echo ""
read -p "填寫完 .env 後按 Enter 繼續首次程式碼部署..."

echo "=== [4/4] 首次程式碼部署 ==="
bash deploy/deploy.sh

echo ""
echo "=============================="
echo "首次部署完成"
echo "  http://$SBOM_DEPLOY_HOST:9100/health"
echo ""
echo "ops 常用指令(在 Mac Mini 上):"
echo "  launchctl list | grep com.sbom.backend          # 確認 agent 載入"
echo "  launchctl kickstart -k gui/\$(id -u)/com.sbom.backend  # 重啟"
echo "  tail -f $SBOM_DEPLOY_DIR/logs/backend.err.log   # 看 log"
echo "=============================="
