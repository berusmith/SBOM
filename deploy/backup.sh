#!/usr/bin/env bash
# 自動偵測 backend/.env 的 DATABASE_URL,SQLite 走 .backup,Postgres 走 pg_dump custom format。
# 保留最近 KEEP_DAYS 天(預設 14)。
#
# Usage:
#   bash deploy/backup.sh
#
# Schedule (macOS, cron 例):
#   crontab -e
#   0 2 * * * /Users/<you>/sbom/deploy/backup.sh >> /Users/<you>/sbom/logs/backup.log 2>&1
#
# 環境變數覆寫:
#   SBOM_HOME            部署根(預設 $HOME/sbom)
#   SBOM_DATABASE_URL    直接指定 DSN(略過讀 .env)
#   SBOM_BACKUP_DIR      備份輸出目錄(預設 $SBOM_HOME/backups)
#   SBOM_KEEP_DAYS       保留天數(預設 14)
#
# 還原(SQLite):
#   sqlite3 path/to/sbom.db ".restore '/path/to/backup.db'"
#
# 還原(Postgres):
#   pg_restore --clean --if-exists -d postgresql://user:pass@host/db /path/to/backup.dump

set -euo pipefail

SBOM_HOME="${SBOM_HOME:-$HOME/sbom}"
BACKUP_DIR="${SBOM_BACKUP_DIR:-$SBOM_HOME/backups}"
KEEP_DAYS="${SBOM_KEEP_DAYS:-14}"
ENV_FILE="$SBOM_HOME/backend/.env"

# Resolve DATABASE_URL: env var wins, then .env file
if [ -z "${SBOM_DATABASE_URL:-}" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: $ENV_FILE not found and SBOM_DATABASE_URL not set"
        exit 1
    fi
    DATABASE_URL="$(grep -E '^DATABASE_URL=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
else
    DATABASE_URL="$SBOM_DATABASE_URL"
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: DATABASE_URL is empty"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
TS_LOG="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

case "$DATABASE_URL" in
    sqlite*)
        # ── SQLite ──────────────────────────────────────────────────────
        # Strip sqlite:/// prefix; resolve relative paths against $SBOM_HOME/backend
        DB_PATH="${DATABASE_URL#sqlite:///}"
        DB_PATH="${DB_PATH#sqlite:////}"
        case "$DB_PATH" in
            /*) ;;  # absolute, keep as-is
            *) DB_PATH="$SBOM_HOME/backend/$DB_PATH" ;;
        esac

        if [ ! -f "$DB_PATH" ]; then
            echo "[$TS_LOG] ERROR: SQLite DB not found at $DB_PATH"
            exit 1
        fi

        DEST="$BACKUP_DIR/sbom_${TIMESTAMP}.db"
        sqlite3 "$DB_PATH" ".backup '$DEST'"
        SIZE="$(du -sh "$DEST" | cut -f1)"
        echo "[$TS_LOG] SQLite backup OK: $DEST ($SIZE)"

        # Rotate
        find "$BACKUP_DIR" -name "sbom_*.db" -mtime +${KEEP_DAYS} -delete
        REMAINING="$(find "$BACKUP_DIR" -name "sbom_*.db" | wc -l | tr -d ' ')"
        echo "[$TS_LOG] Retained $REMAINING SQLite backup(s)"
        ;;

    postgresql*|postgres*)
        # ── Postgres ────────────────────────────────────────────────────
        # pg_dump understands SQLAlchemy URLs only after stripping the +driver part.
        PG_URL="$(echo "$DATABASE_URL" | sed -E 's|^(postgres(ql)?)\+[a-z0-9]+://|\1://|')"

        # Locate pg_dump (Homebrew postgresql@16 is keg-only)
        if command -v pg_dump >/dev/null 2>&1; then
            PG_DUMP="pg_dump"
        elif command -v brew >/dev/null 2>&1 && brew --prefix postgresql@16 >/dev/null 2>&1; then
            PG_DUMP="$(brew --prefix postgresql@16)/bin/pg_dump"
        else
            echo "[$TS_LOG] ERROR: pg_dump not found. Install postgresql@16 or add to PATH."
            exit 1
        fi

        DEST="$BACKUP_DIR/sbom_${TIMESTAMP}.dump"
        # --format=custom  → compressed binary, readable by pg_restore
        # --no-owner/--no-acl → restorable into a different user/role
        "$PG_DUMP" --format=custom --no-owner --no-acl --file="$DEST" "$PG_URL"
        SIZE="$(du -sh "$DEST" | cut -f1)"
        echo "[$TS_LOG] Postgres backup OK: $DEST ($SIZE)"

        # Rotate
        find "$BACKUP_DIR" -name "sbom_*.dump" -mtime +${KEEP_DAYS} -delete
        REMAINING="$(find "$BACKUP_DIR" -name "sbom_*.dump" | wc -l | tr -d ' ')"
        echo "[$TS_LOG] Retained $REMAINING Postgres backup(s)"
        ;;

    *)
        echo "[$TS_LOG] ERROR: Unsupported DATABASE_URL scheme: ${DATABASE_URL%%:*}"
        exit 1
        ;;
esac
