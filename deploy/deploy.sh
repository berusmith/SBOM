#!/usr/bin/env bash
# 從本機(Windows/macOS/Linux)推送到 Mac Mini。
#
# 必要環境變數:
#   SBOM_DEPLOY_HOST   Mac Mini 的主機名或 IP(例如 mac-mini.local 或 100.x.x.x [Tailscale])
#
# 可選環境變數:
#   SBOM_DEPLOY_USER   SSH 使用者(預設 = 本機 whoami)
#   SBOM_DEPLOY_DIR    Mac Mini 上的部署根(預設 /Users/$SBOM_DEPLOY_USER/sbom)
#   SBOM_SSH_KEY       SSH 私鑰路徑(預設用 ssh-agent / ~/.ssh/id_*)
#   SBOM_SSH_OPTS      其他 ssh 參數(例如 "-p 2222")
#
# 範例:
#   SBOM_DEPLOY_HOST=mac-mini.local bash deploy/deploy.sh
#   SBOM_DEPLOY_HOST=100.64.1.42 SBOM_DEPLOY_USER=peter bash deploy/deploy.sh

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

echo "=== Deploy → $SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST:$SBOM_DEPLOY_DIR ==="

echo "=== [1/4] Build frontend (locally — Mac Mini 不需要 Node.js) ==="
( cd frontend && npm run build )

echo "=== [2/4] Sync backend code (tar pipeline — 不需 rsync,Windows Git Bash 可用) ==="
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
| $SSH "mkdir -p '$SBOM_DEPLOY_DIR' && tar -xzf - -C '$SBOM_DEPLOY_DIR'"

echo "=== [3/4] Sync frontend dist ==="
tar -czf - frontend/dist/ \
| $SSH "mkdir -p '$SBOM_DEPLOY_DIR/frontend' && tar -xzf - --strip-components=1 -C '$SBOM_DEPLOY_DIR/frontend'"

echo "=== [4/4] Install deps + reload launchd agent ==="
$SSH bash -s -- "$SBOM_DEPLOY_DIR" << 'REMOTE'
set -e
SBOM_HOME="$1"
PLIST="$HOME/Library/LaunchAgents/com.sbom.backend.plist"

cd "$SBOM_HOME/backend"
./venv/bin/pip install -r requirements.txt --quiet

if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    sleep 2
    if curl -fsS http://127.0.0.1:9100/health >/dev/null 2>&1; then
        echo "Backend: running"
    else
        echo "Backend: FAILED — check $SBOM_HOME/logs/backend.err.log"
        exit 1
    fi
else
    echo "WARN: $PLIST 不存在 — 請先在 Mac Mini 上跑 deploy/setup-macos.sh"
    exit 1
fi
REMOTE

echo ""
echo "Deploy complete. Backend listens on 127.0.0.1:9100 only — never exposed"
echo "to the network directly. Reach it via one of:"
echo "  http://$SBOM_DEPLOY_HOST       (with nginx — INSTALL_NGINX=1 in setup-macos.sh)"
echo "  http://localhost:9100          (SSH tunnel: ssh -L 9100:127.0.0.1:9100 $SBOM_DEPLOY_USER@$SBOM_DEPLOY_HOST)"
echo "  http://$SBOM_DEPLOY_HOST:9100  (Tailscale: only works when peer is on tailnet)"
